package mdsig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

type CandidateKey struct {
	Alg    string
	Key    []byte
	Source string
}

type ResolveResult struct {
	Keys     []CandidateKey
	Warnings []string
}

const (
	KindNetwork     = "network"
	KindNotFound    = "not-found"
	KindUnsupported = "unsupported"
	KindOffline     = "offline"
	KindMalformed   = "malformed"
)

type ResolutionError struct {
	Kind string
	Msg  string
}

func (e *ResolutionError) Error() string { return e.Msg }

func resErr(kind, format string, a ...any) error {
	return &ResolutionError{Kind: kind, Msg: fmt.Sprintf(format, a...)}
}

type TofuStore interface {
	Get(signer string) (string, bool)
	Set(signer, pubkey string) error
}

type MemoryTofuStore struct{ m map[string]string }

func (s *MemoryTofuStore) Get(k string) (string, bool) { v, ok := s.m[k]; return v, ok }

func (s *MemoryTofuStore) Set(k, v string) error {
	if s.m == nil {
		s.m = map[string]string{}
	}
	s.m[k] = v
	return nil
}

type ResolveOptions struct {
	HTTPClient   *http.Client
	LookupTXT    func(ctx context.Context, name string) ([]string, error)
	DoHEndpoints []string
	Offline      bool
	TofuStore    TofuStore
	// SPEC 4.4: replace a stored binding instead of failing with key-changed
	AcceptNewTofuKey bool
	// PGPKeyring returns the local certificate for fpr, or nil when the keyring has none
	PGPKeyring func(ctx context.Context, fpr string) ([]byte, error)
	// PGPClient fetches WKD and keyserver URLs; nil means SafeHTTPClient
	PGPClient *http.Client
	// SPEC 4.3: chosen by the verifier, never taken from the block; empty means DefaultKeyserver
	Keyserver string
}

type Resolver interface {
	Resolve(ctx context.Context, fields map[string]string, opts *ResolveOptions) (ResolveResult, error)
}

type ResolverFunc func(ctx context.Context, fields map[string]string, opts *ResolveOptions) (ResolveResult, error)

func (f ResolverFunc) Resolve(ctx context.Context, fields map[string]string, opts *ResolveOptions) (ResolveResult, error) {
	return f(ctx, fields, opts)
}

var defaultDoH = []string{"https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"}

func DefaultResolvers() map[string]Resolver {
	return map[string]Resolver{
		"dns":         ResolverFunc(resolveDNS),
		"git-hosting": ResolverFunc(resolveGitHosting),
		"tofu":        ResolverFunc(resolveTofu),
		"pgp":         ResolverFunc(resolvePGP),
	}
}

func algOf(f map[string]string) string {
	if a, ok := f["alg"]; ok {
		return a
	}
	return "ed25519"
}

func keyTypeFor(alg string) string {
	switch alg {
	case "ed25519":
		return "ed25519"
	case "webauthn-es256":
		return "es256"
	case "openpgp":
		return "openpgp"
	}
	return ""
}

func keyTypeOf(f map[string]string) string {
	if k := keyTypeFor(algOf(f)); k != "" {
		return k
	}
	return algOf(f)
}

// as in the TS core, an es256 point is only checked when the key is used
func decodePublicKey(keyType string, b []byte) ([]byte, error) {
	switch keyType {
	case "ed25519":
		return rawEd25519PublicKey(b)
	case "es256":
		return es256SPKI(b)
	}
	return nil, fmt.Errorf("unsupported key type %q", keyType)
}

func httpClient(o *ResolveOptions) *http.Client {
	if o != nil && o.HTTPClient != nil {
		return o.HTTPClient
	}
	return SafeHTTPClient(15 * time.Second)
}

func parseDNSRecord(txt string) (k, p string, ok bool) {
	tags := map[string]string{}
	for _, part := range strings.Split(txt, ";") {
		i := strings.IndexByte(part, '=')
		if i < 0 {
			continue
		}
		tags[strings.TrimFunc(part[:i], isJSSpace)] = strings.TrimFunc(part[i+1:], isJSSpace)
	}
	if tags["v"] != "mdsig1" || tags["p"] == "" {
		return "", "", false
	}
	k = tags["k"]
	if k == "" {
		k = "ed25519"
	}
	return k, tags["p"], true
}

func DNSName(fields map[string]string) string {
	domain := strings.TrimSuffix(strings.ToLower(fields["signer"]), ".")
	if sel := fields["selector"]; sel != "" {
		return sel + "._mdsig." + domain
	}
	return "_mdsig." + domain
}

func joinTXT(data string) string {
	re := regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)
	parts := re.FindAllStringSubmatch(data, -1)
	if parts == nil {
		return data
	}
	unesc := regexp.MustCompile(`\\(.)`)
	var b strings.Builder
	for _, p := range parts {
		b.WriteString(unesc.ReplaceAllString(p[1], "$1"))
	}
	return b.String()
}

func lookupTXT(ctx context.Context, name string, o *ResolveOptions) ([]string, error) {
	lookup := o.LookupTXT
	if lookup == nil {
		lookup = net.DefaultResolver.LookupTXT
	}
	recs, err := lookup(ctx, name)
	if err == nil {
		return recs, nil
	}
	var de *net.DNSError
	// NXDOMAIN is final; other resolver errors fall back to DoH
	if errors.As(err, &de) && de.IsNotFound {
		return nil, nil
	}
	sysErr := err
	eps := o.DoHEndpoints
	if eps == nil {
		eps = defaultDoH
	}
	lastErr := sysErr
	for _, ep := range eps {
		r, err := dohTXT(ctx, ep, name, o)
		if err == nil {
			return r, nil
		}
		lastErr = err
	}
	return nil, resErr(KindNetwork, "DNS lookup for %s failed: %v", name, lastErr)
}

func dohTXT(ctx context.Context, ep, name string, o *ResolveOptions) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep+"?name="+url.QueryEscape(name)+"&type=TXT", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	res, err := httpClient(o).Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, fmt.Errorf("HTTP %d", res.StatusCode)
	}
	var j struct {
		Status int
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		}
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&j); err != nil {
		return nil, err
	}
	if j.Status == 3 {
		return nil, nil
	}
	if j.Status != 0 {
		return nil, fmt.Errorf("DNS status %d", j.Status)
	}
	var out []string
	for _, a := range j.Answer {
		if a.Type == 16 {
			out = append(out, joinTXT(a.Data))
		}
	}
	return out, nil
}

func resolveDNS(ctx context.Context, fields map[string]string, o *ResolveOptions) (ResolveResult, error) {
	if o.Offline {
		return ResolveResult{}, resErr(KindOffline, "offline mode")
	}
	name := DNSName(fields)
	records, err := lookupTXT(ctx, name, o)
	if err != nil {
		return ResolveResult{}, err
	}
	return DNSKeysFromRecords(fields, name, records)
}

func DNSKeysFromRecords(fields map[string]string, name string, records []string) (ResolveResult, error) {
	var keys []CandidateKey
	kt := keyTypeOf(fields)
	for _, r := range records {
		k, p, ok := parseDNSRecord(r)
		if !ok || k != kt {
			continue
		}
		b, err := fromBase64(p)
		if err != nil {
			continue
		}
		key, err := decodePublicKey(k, b)
		if err != nil {
			continue
		}
		keys = append(keys, CandidateKey{Alg: k, Key: key, Source: "DNS TXT " + name})
	}
	if len(keys) == 0 {
		return ResolveResult{}, resErr(KindNotFound, "no v=mdsig1 k=%s TXT record at %s", kt, name)
	}
	return ResolveResult{Keys: keys, Warnings: []string{"key resolved from current DNS; it may differ from the key at signing time"}}, nil
}

func keysURL(signer string) string { return "https://" + signer + ".keys" }

// SPEC 4.2: the host is a domain name of two or more labels, never an IP address
var gitSignerRe = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z](?:[a-z0-9-]*[a-z0-9])?/[A-Za-z0-9._-]+$`)

func isValidGitHostingSigner(s string) bool { return gitSignerRe.MatchString(s) }

func FetchKeysFile(ctx context.Context, signer string, o *ResolveOptions) (string, error) {
	u := keysURL(signer)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", resErr(KindNetwork, "fetching %s failed: %v", u, err)
	}
	res, err := httpClient(o).Do(req)
	if err != nil {
		return "", resErr(KindNetwork, "fetching %s failed: %v", u, err)
	}
	defer res.Body.Close()
	if res.StatusCode == 404 {
		return "", resErr(KindNotFound, "%s: 404 Not Found", u)
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return "", resErr(KindNetwork, "fetching %s failed: HTTP %d", u, res.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return "", resErr(KindNetwork, "fetching %s failed: %v", u, err)
	}
	return string(b), nil
}

func resolveGitHosting(ctx context.Context, fields map[string]string, o *ResolveOptions) (ResolveResult, error) {
	if o.Offline {
		return ResolveResult{}, resErr(KindOffline, "offline mode")
	}
	signer := fields["signer"]
	if !gitSignerRe.MatchString(signer) {
		return ResolveResult{}, resErr(KindMalformed, "invalid git-hosting signer %q", signer)
	}
	text, err := FetchKeysFile(ctx, signer, o)
	if err != nil {
		return ResolveResult{}, err
	}
	return GitHostingKeysFromText(fields, keysURL(signer), text)
}

func GitHostingKeysFromText(fields map[string]string, source, text string) (ResolveResult, error) {
	if algOf(fields) != "ed25519" {
		return ResolveResult{}, resErr(KindUnsupported, "alg %s is not supported for git-hosting", algOf(fields))
	}
	var keys []CandidateKey
	fp, hasFp := fields["key_fp"]
	for _, k := range ParseSSHPublicKeys(text) {
		if k.Type != "ssh-ed25519" || k.Key == nil {
			continue
		}
		kfp := SSHFingerprint(k.Key)
		if hasFp && fp != "" && kfp != fp {
			continue
		}
		keys = append(keys, CandidateKey{Alg: "ed25519", Key: k.Key, Source: fmt.Sprintf("%s (%s)", source, kfp)})
	}
	if len(keys) == 0 {
		if hasFp && fp != "" {
			return ResolveResult{}, resErr(KindNotFound, "no ssh-ed25519 key with fingerprint %s at %s", fp, source)
		}
		return ResolveResult{}, resErr(KindNotFound, "no ssh-ed25519 keys at %s", source)
	}
	return ResolveResult{Keys: keys, Warnings: []string{"key list reflects the account's current keys, not the keys at signing time"}}, nil
}

func resolveTofu(_ context.Context, fields map[string]string, o *ResolveOptions) (ResolveResult, error) {
	pk, ok := fields["pubkey"]
	if !ok || pk == "" {
		return ResolveResult{}, resErr(KindNotFound, `tofu block has no "pubkey"`)
	}
	i := strings.IndexByte(pk, ':')
	var kalg string
	if i >= 0 {
		kalg = pk[:i]
	} else {
		kalg = pk[:len(pk)-1]
	}
	if i < 0 || kalg != keyTypeOf(fields) {
		return ResolveResult{}, resErr(KindMalformed, "pubkey key type %s does not match alg %s", jsonString(kalg), jsonString(algOf(fields)))
	}
	b, err := fromBase64(pk[i+1:])
	if err != nil {
		return ResolveResult{}, resErr(KindMalformed, "invalid pubkey: %v", err)
	}
	key, err := decodePublicKey(kalg, b)
	if err != nil {
		return ResolveResult{}, resErr(KindMalformed, "invalid pubkey: %v", err)
	}
	warnings := []string{"tofu: the key is embedded in the document; this proves integrity, not identity"}
	return ResolveResult{Keys: []CandidateKey{{Alg: kalg, Key: key, Source: "embedded pubkey"}}, Warnings: warnings}, nil
}

// SPEC 4.3: keyring, then WKD, then the keyserver; candidate "keys" are whole certificates
func resolvePGP(ctx context.Context, fields map[string]string, o *ResolveOptions) (ResolveResult, error) {
	fpr := fields["fpr"]
	if o.Keyserver != "" && !IsValidRevocationURL(o.Keyserver) {
		return ResolveResult{}, resErr(KindUnsupported, "keyserver must be an https:// URL")
	}
	r := lookupPgpKey(ctx, fpr, fields["signer"], o.Keyserver, o)
	tried := describeAttempts(r.attempts)
	if r.cert == nil {
		kind := KindNotFound
		if slices.ContainsFunc(r.attempts, func(a pgpAttempt) bool { return a.Result == "error" }) {
			kind = KindNetwork
			if o.Offline {
				kind = KindOffline
			}
		}
		return ResolveResult{}, resErr(kind, "no OpenPGP key %s found (%s)", fpr, tried)
	}
	var warnings []string
	if len(r.attempts) > 1 {
		warnings = append(warnings, "pgp key lookup: "+tried)
	}
	if r.source != "keyring" {
		from := "the keyserver"
		if r.source == "wkd" {
			from = "WKD"
		}
		warnings = append(warnings, "pgp: the certificate is the current one from "+from+", not the one at signing time")
	}
	source := r.source
	if r.url != "" {
		source += " " + r.url
	}
	return ResolveResult{Keys: []CandidateKey{{Alg: "openpgp", Key: r.cert, Source: source}}, Warnings: warnings}, nil
}
