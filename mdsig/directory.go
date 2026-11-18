package mdsig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// ------------------------------------------------------------------ lookup (SPEC 4.7)

func DefaultKeyDirectories() []string { return []string{"https://keys.mdsig.dev"} }

var keyDirectoryRe = regexp.MustCompile(`^https://[^\s/?#]+(?:/[^\s?#]*)?$`)

func IsValidKeyDirectory(u string) bool { return keyDirectoryRe.MatchString(u) }

func directoryKeyURL(directory, email string) string {
	sum := sha256.Sum256([]byte(email))
	return strings.TrimRight(directory, "/") + "/v1/keys/" + hex.EncodeToString(sum[:])
}

func parseDNSTags(txt string) map[string]string {
	tags := map[string]string{}
	for _, part := range strings.Split(txt, ";") {
		i := strings.IndexByte(part, '=')
		if i < 0 {
			continue
		}
		tags[strings.TrimFunc(part[:i], isJSSpace)] = strings.TrimFunc(part[i+1:], isJSSpace)
	}
	return tags
}

func directoriesFromRecords(records []string) []string {
	var dirs []string
	seen := map[string]bool{}
	for _, r := range records {
		tags := parseDNSTags(r)
		d := tags["dir"]
		if tags["v"] != "mdsig1" || !IsValidKeyDirectory(d) {
			continue
		}
		d = strings.TrimRight(d, "/")
		if !seen[d] {
			seen[d] = true
			dirs = append(dirs, d)
		}
	}
	return dirs
}

type directoryEntry struct {
	Type string
	Key  []byte
}

// nil entries with a nil error: the response describes another address (SPEC 4.7: no key)
func parseDirectoryResponse(body []byte, email string) ([]directoryEntry, error) {
	if !utf8.Valid(body) {
		return nil, errors.New("the response is not UTF-8")
	}
	var o map[string]any
	if err := json.Unmarshal(body, &o); err != nil || o == nil {
		return nil, errors.New("the response is not a JSON object")
	}
	if e, _ := o["email"].(string); e != email {
		return nil, nil
	}
	var out []directoryEntry
	list, _ := o["keys"].([]any)
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		t, ok1 := m["type"].(string)
		k, ok2 := m["key"].(string)
		if !ok1 || !ok2 {
			continue
		}
		b, err := fromBase64(k)
		if err != nil {
			continue
		}
		out = append(out, directoryEntry{Type: t, Key: b})
	}
	return out, nil
}

const maxDirectoryBytes = 64 << 10

func resolveDirectory(ctx context.Context, fields map[string]string, o *ResolveOptions) (ResolveResult, error) {
	if o.Offline {
		return ResolveResult{}, resErr(KindOffline, "offline mode")
	}
	email := fields["signer"]
	domain := email[strings.LastIndexByte(email, '@')+1:]
	records, err := lookupTXT(ctx, "_mdsig."+domain, o)
	if err != nil {
		return ResolveResult{}, err
	}
	named := directoriesFromRecords(records)
	if len(named) > 1 {
		return ResolveResult{}, resErr(KindNotFound, "_mdsig.%s names %d different key directories", domain, len(named))
	}
	list, via := named, "named by _mdsig."+domain
	if len(named) == 0 {
		via = "trusted list"
		base := o.KeyDirectories
		if base == nil {
			base = DefaultKeyDirectories()
		}
		list = nil
		seen := map[string]bool{}
		for _, d := range base {
			if !IsValidKeyDirectory(d) {
				return ResolveResult{}, resErr(KindUnsupported, "key directory must be an https:// URL, got %q", d)
			}
			d = strings.TrimRight(d, "/")
			if !seen[d] {
				seen[d] = true
				list = append(list, d)
			}
		}
	}
	kt := keyTypeOf(fields)
	var failed []string
	for _, dir := range list {
		body, err := FetchResource(ctx, httpClient(o), directoryKeyURL(dir, email), maxDirectoryBytes)
		if err != nil {
			var hs *httpStatusError
			if !errors.As(err, &hs) || hs.Status != http.StatusNotFound {
				failed = append(failed, dir+": "+err.Error())
			}
			continue
		}
		entries, err := parseDirectoryResponse(body, email)
		if err != nil {
			failed = append(failed, dir+": "+err.Error())
			continue
		}
		var keys []CandidateKey
		for _, e := range entries {
			if e.Type != kt {
				continue
			}
			key, err := decodePublicKey(kt, e.Key)
			if err != nil {
				continue
			}
			keys = append(keys, CandidateKey{Alg: kt, Key: key, Source: fmt.Sprintf("key directory %s (%s)", dir, via)})
		}
		if len(keys) > 0 {
			return ResolveResult{Keys: keys, Warnings: []string{"key resolved from the current key directory; it may differ from the key at signing time"}}, nil
		}
	}
	if len(failed) > 0 {
		return ResolveResult{}, resErr(KindNetwork, "key directory lookup failed (%s)", strings.Join(failed, "; "))
	}
	return ResolveResult{}, resErr(KindNotFound, "no %s key for %s in %s", kt, email, strings.Join(list, ", "))
}

// ------------------------------------------------------------------ registration (the keys.mdsig.dev API; not part of the format)

const keydirProofPrefix = "md-signature/keydir/v1"

// the proof binds the challenge to the address and the key; the same bytes as registrationMessage in the TS core
func registrationMessage(challenge, email, keyType, key string) []byte {
	return []byte(keydirProofPrefix + "\n" + challenge + "\n" + email + "\n" + keyType + ":" + key)
}

func postDirectory(ctx context.Context, client *http.Client, url string, body any) (map[string]any, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, maxDirectoryBytes))
	var j map[string]any
	_ = json.Unmarshal(raw, &j)
	if res.StatusCode < 200 || res.StatusCode > 299 {
		if msg, _ := j["error"].(string); msg != "" {
			return nil, errors.New(msg)
		}
		return nil, fmt.Errorf("HTTP %d", res.StatusCode)
	}
	return j, nil
}

// RegisterKey asks the directory to publish signer's key for email; it is published after the owner opens the link in the confirmation email.
func RegisterKey(ctx context.Context, client *http.Client, directory, email string, signer Signer, label string) error {
	if !IsValidKeyDirectory(directory) {
		return fmt.Errorf("key directory must be an https:// URL, got %q", directory)
	}
	if client == nil {
		client = SafeHTTPClient(30 * time.Second)
	}
	email = strings.ToLower(email)
	if !emailRe.MatchString(email) {
		return fmt.Errorf("not an email address: %q", email)
	}
	base := strings.TrimRight(directory, "/")
	c, err := postDirectory(ctx, client, base+"/v1/challenges", map[string]any{})
	if err != nil {
		return err
	}
	challenge, _ := c["challenge"].(string)
	if challenge == "" {
		return errors.New("the directory returned no challenge")
	}
	key := toBase64(signer.PublicKey())
	sig, err := signer.Sign(registrationMessage(challenge, email, "ed25519", key))
	if err != nil {
		return err
	}
	req := map[string]any{"email": email, "type": "ed25519", "key": key, "challenge": challenge, "proof": map[string]any{"type": "ed25519", "sig": toBase64(sig)}}
	if label != "" {
		req["label"] = label
	}
	_, err = postDirectory(ctx, client, base+"/v1/registrations", req)
	return err
}

// RequestKeyRemoval asks the directory to remove email's keys (or only key when given); it sends a confirmation email.
func RequestKeyRemoval(ctx context.Context, client *http.Client, directory, email, key string) error {
	if !IsValidKeyDirectory(directory) {
		return fmt.Errorf("key directory must be an https:// URL, got %q", directory)
	}
	if client == nil {
		client = SafeHTTPClient(30 * time.Second)
	}
	body := map[string]any{"email": strings.ToLower(email)}
	if key != "" {
		body["key"] = key
	}
	_, err := postDirectory(ctx, client, strings.TrimRight(directory, "/")+"/v1/removals", body)
	return err
}

// RegistrationDirectory is where a key for email is registered: the domain's dir= if it names exactly one, otherwise fallback.
func RegistrationDirectory(ctx context.Context, email, fallback string, o *ResolveOptions) string {
	if o == nil {
		o = &ResolveOptions{}
	}
	domain := email[strings.LastIndexByte(email, '@')+1:]
	if records, err := lookupTXT(ctx, "_mdsig."+domain, o); err == nil {
		if named := directoriesFromRecords(records); len(named) == 1 {
			return named[0]
		}
	}
	return fallback
}
