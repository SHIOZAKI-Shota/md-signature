package mdsig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	StatusValid       = "valid"
	StatusInvalid     = "invalid"
	StatusMalformed   = "malformed"
	StatusUnresolved  = "unresolved"
	StatusUnsupported = "unsupported"
)

const (
	RevocationNotRevoked = "not-revoked"
	RevocationRevoked    = "revoked"
	RevocationNotChecked = "not-checked"
)

type RevocationCheck struct {
	Status string
	Detail string
	// set when the list was wanted but could not be used; the block is then unresolved
	Failure string
}

const (
	TofuKnown    = "known"
	TofuNew      = "new"
	TofuReplaced = "replaced"
)

type TofuInfo struct {
	Status      string
	Fingerprint string
}

// SPEC 4.6: T(k), the earliest genTime + accuracy of a valid tsa block after this one
type BlockTime struct {
	At         string
	Block      int
	GenTime    string
	AccuracyMs int64
	Signer     string
}

type BlockResult struct {
	Index        int
	Line         int
	Status       string
	Code         string
	Message      string
	Fields       map[string]string
	HashOk       *bool
	ComputedHash string
	Partial      []string
	KeySource    string
	// SPEC 4.4: whether a tofu key matched the stored binding, was seen for the first time, or replaced it
	Tofu       *TofuInfo
	WebAuthn   *WebAuthnInfo
	PGP        *PGPInfo
	Resources  []ResourceResult
	Revocation *RevocationCheck
	// a tsa block: the check of its own token
	TSA      *TSACheck
	Time     *BlockTime
	Warnings []string
}

type VerifyResult struct {
	OK         bool
	Signatures []*BlockResult
	Agreement  Agreement
	Warnings   []string
	Error      string
}

type VerifyOptions struct {
	ResolveOptions
	ResourceCheckOptions
	Resolvers map[string]Resolver
	// SkipTSA leaves T(k) out (SPEC 4.6); tsa blocks are still checked
	SkipTSA bool
	TSA     TSAVerifyOptions
	// TSAVerifier replaces the built-in token check of tsa blocks; the token's imprint is hash(data)
	TSAVerifier  func(ctx context.Context, token string, data []byte, hash string) TSACheck
	NoRevocation bool
	Now          time.Time

	skipAgreement bool
	// SPEC 5.10: signed lists (revocation lists, rosters) fetched during one call, by URL
	signedListCache map[string]*loadedList
	pendingTofu     map[string]string
}

var supportedAlgs = map[string]bool{"ed25519": true, "webauthn-es256": true, "openpgp": true}

var webAuthnKeys = []string{"rp_id", "webauthn_authenticator_data", "webauthn_client_data"}

var revocationURLRe = regexp.MustCompile(`^https://\S+$`)

func IsValidRevocationURL(u string) bool {
	return revocationURLRe.MatchString(u) && jsNonSpace(u)
}

// SPEC 4.6: a tsa block carries no signer key, so only these fields mean something in it
var tsaBlockKeys = map[string]bool{"v": true, "method": true, "signer": true, "ts": true, "alg": true, "hash": true, "sig": true, "reason": true}

// SPEC 4.5: methods whose block may carry a snapshot of the public key
var keySnapshotMethods = map[string]bool{"dns": true, "git-hosting": true, "directory": true}

var knownMethods = map[string]bool{"dns": true, "git-hosting": true, "tofu": true, "pgp": true, "directory": true, "tsa": true}

func validateSemantics(f map[string]string) string {
	// SPEC 4.6: method tsa and alg rfc3161 only go together
	isTsa := f["method"] == "tsa"
	if isTsa != (f["alg"] == "rfc3161") {
		if isTsa {
			return "method tsa requires alg rfc3161"
		}
		return "alg rfc3161 requires method tsa"
	}
	// SPEC 3.4: signers are compared exactly, so they must already be in canonical form
	if knownMethods[f["method"]] {
		if se := CheckSignerID(f["method"], f["signer"]); se != "" {
			return se
		}
	}
	if isTsa {
		extra := ""
		for k := range f {
			if !tsaBlockKeys[k] && !strings.HasPrefix(k, "x_") && (extra == "" || fieldRank(k) < fieldRank(extra)) {
				extra = k
			}
		}
		if extra != "" {
			return fmt.Sprintf("field %q is not allowed with method tsa", extra)
		}
		return ""
	}
	if sel, ok := f["selector"]; ok && (f["method"] != "dns" || !isSelector(sel)) {
		if f["method"] != "dns" {
			return "selector is only allowed with method dns"
		}
		return `selector must be lower-case LDH labels and must not start with "_"`
	}
	if role, ok := f["role"]; ok && !isRole(role) {
		return "role must be one word: [a-z0-9][a-z0-9._-]*"
	}
	if dn, ok := f["display_name"]; ok {
		if e := checkDisplayNameLength(dn); e != "" {
			return e
		}
	}
	// an unknown method is reported as unsupported later, not as a misplaced pubkey
	if _, ok := f["pubkey"]; ok && f["method"] == "pgp" {
		return "pubkey is not allowed with method pgp"
	}
	if pk, ok := f["pubkey"]; ok && (f["method"] == "tofu" || keySnapshotMethods[f["method"]]) {
		kalg, _, found := strings.Cut(pk, ":")
		if !found {
			kalg = ""
		}
		// an unknown alg is reported as unsupported later
		if want := keyTypeFor(f["alg"]); want != "" && kalg != want {
			return fmt.Sprintf("pubkey key type %q does not match alg %q", kalg, f["alg"])
		}
	}
	if v, ok := f["expires"]; ok && !IsValidTimestamp(v) {
		return fmt.Sprintf("expires %q is not a valid YYYY-MM-DDTHH:MM:SSZ date-time", v)
	}
	if v, ok := f["revocation_url"]; ok && !IsValidRevocationURL(v) {
		return "revocation_url must be an https:// URL"
	}
	if v, ok := f["scope"]; ok {
		if _, ok := ParseScope(v); !ok {
			return "scope must list one section id per line, each id unique"
		}
	}
	if v, ok := f["require"]; ok {
		if p := ParseRequire(v, 0); len(p.Errors) > 0 {
			return strings.Join(p.Errors, "; ")
		}
	}
	if v, ok := f["resources"]; ok {
		if _, errs, _ := parseResources(v); len(errs) > 0 {
			return strings.Join(errs, "; ")
		}
	}
	// SPEC 4.3: method pgp and alg openpgp only go together
	isPgp := f["method"] == "pgp"
	if isPgp != (f["alg"] == "openpgp") {
		if isPgp {
			return "method pgp requires alg openpgp"
		}
		return "alg openpgp requires method pgp"
	}
	if isPgp && !fprRe.MatchString(f["fpr"]) {
		return "pgp requires fpr: 40 or 64 upper-case hex digits"
	}
	isWebAuthn := f["alg"] == "webauthn-es256"
	for _, k := range webAuthnKeys {
		_, has := f[k]
		if isWebAuthn && !has {
			return fmt.Sprintf("alg webauthn-es256 requires %q", k)
		}
		if !isWebAuthn && has {
			return fmt.Sprintf("%q is only allowed with alg webauthn-es256", k)
		}
	}
	if isWebAuthn && !isRPID(f["rp_id"]) {
		return "rp_id must be a lower-case domain name"
	}
	return ""
}

// the order of the fields in a parsed block, which JS object iteration follows; unknown x_ keys come last
func fieldRank(k string) int {
	if i := slices.Index(fieldOrder, k); i >= 0 {
		return i
	}
	return len(fieldOrder)
}

var (
	legacyVersionRe   = regexp.MustCompile(`^0\.0\.[0-9]+$`)
	legacyResourcesRe = regexp.MustCompile(`(?m)^ *sha256:[0-9a-f]{64} `)
)

// advice for blocks written in an older format; verdicts do not change (CLI_SPEC, hints)
func legacyHints(block *ParsedBlock) []string {
	f := block.Fields
	var out []string
	if v, ok := f["v"]; ok && legacyVersionRe.MatchString(v) {
		out = append(out, fmt.Sprintf("format %s is not supported by format 0.1 verifiers; verify this document with mdsig v0.0.5", v))
	}
	_, hasToken := f["tsa_token"]
	_, hasURL := f["tsa_url"]
	if hasToken || hasURL {
		out = append(out, "tsa_token and tsa_url were removed in format 0.1; a timestamp is a separate tsa block (mdsig timestamp)")
	}
	if v, ok := f["scope"]; ok && (strings.Contains(v, "section:") || strings.Contains(v, ",")) {
		out = append(out, `scope lists one section id per line without "section:" (format 0.1)`)
	}
	if v, ok := f["resources"]; ok && legacyResourcesRe.MatchString(v) {
		out = append(out, `resources lines are "<ref> hash=sha256:<hex>" (format 0.1)`)
	}
	if v, ok := f["require"]; ok {
		out = append(out, ParseRequire(v, 0).Hints...)
	}
	if strings.Contains(block.Raw, "\t") {
		out = append(out, "tabs are not allowed in a signature block; use spaces")
	}
	var hints []string
	for _, h := range out {
		if !slices.Contains(hints, "hint: "+h) {
			hints = append(hints, "hint: "+h)
		}
	}
	return hints
}

func ComputeBlockHash(text string, block *ParsedBlock, hashAlg string) (computed string, partial []string, scopeErr *ScopeError) {
	slice := text[:block.Start]
	var input []byte
	if scope, ok := block.Fields["scope"]; ok {
		in, ids, se := scopedHashInput(slice, scope)
		if se != nil {
			return "", nil, se
		}
		input, partial = []byte(in), ids
	} else {
		input = []byte(normalizeDocument(slice))
	}
	return hashAlg + ":" + toHex(digestBytes(hashAlg, input)), partial, nil
}

// --- signed lists (SPEC 5.10)

type loadedList struct {
	ok  bool
	err string
	// fetched, but not a signed document with nothing after its last block
	untrusted  string
	body       string
	signatures []*BlockResult
}

func loadList(ctx context.Context, url string, opts *VerifyOptions) *loadedList {
	if l, ok := opts.signedListCache[url]; ok {
		return l
	}
	l := fetchAndVerifyList(ctx, url, opts)
	if opts.signedListCache != nil {
		opts.signedListCache[url] = l
	}
	return l
}

func fetchAndVerifyList(ctx context.Context, url string, opts *VerifyOptions) *loadedList {
	b, err := FetchResource(ctx, opts.FetchClient, url, maxSignedListBytes)
	if err == nil && !utf8.Valid(b) {
		err = errors.New("the list is not valid UTF-8")
	}
	if err != nil {
		return &loadedList{err: fmt.Sprintf("could not fetch %s: %s", url, err.Error())}
	}
	// TextDecoder strips a leading BOM
	text := strings.TrimPrefix(string(b), bom)
	inner := *opts
	// SPEC 5.10: no revocation, no resources, no agreement, so a list never leads to another list
	inner.NoRevocation = true
	inner.FetchResources = false
	inner.LoadResource = nil
	inner.TofuStore = nil
	inner.skipAgreement = true
	r := VerifyDocument(ctx, text, &inner)
	if r.Error != "" {
		return &loadedList{ok: true, untrusted: "the list does not verify: " + r.Error}
	}
	return &loadedList{ok: true, body: ParseDocument(text).Body, signatures: r.Signatures}
}

// SPEC 5.10: trusted only with a valid unscoped block from the expected issuer
func trustedList(ctx context.Context, url, listType string, isIssuer func(*BlockResult) bool, opts *VerifyOptions) (map[string]bool, string, string) {
	l := loadList(ctx, url, opts)
	if !l.ok {
		return nil, KindNetwork, l.err
	}
	if l.untrusted != "" {
		return nil, KindNotFound, url + ": " + l.untrusted
	}
	if !slices.ContainsFunc(l.signatures, func(s *BlockResult) bool {
		_, scoped := s.Fields["scope"]
		return s.Status == StatusValid && !scoped && isIssuer(s)
	}) {
		return nil, KindNotFound, url + " is not signed by the expected issuer"
	}
	entries, e := parseSignedList(l.body, listType)
	if e != "" {
		return nil, KindNotFound, url + ": " + e
	}
	set := map[string]bool{}
	for _, x := range entries {
		set[x] = true
	}
	return set, "", ""
}

// SPEC 5.9: computed from the payload, because sig bytes can be changed without the key
func RevocationID(fields map[string]string) string {
	sum := sha256.Sum256(SignedPayload(fields))
	return toHex(sum[:])
}

func checkRevocation(ctx context.Context, f map[string]string, opts *VerifyOptions) *RevocationCheck {
	url := f["revocation_url"]
	if opts.Offline {
		return &RevocationCheck{Status: RevocationNotChecked, Detail: "revocation list not fetched (offline)"}
	}
	if opts.NoRevocation {
		return &RevocationCheck{Status: RevocationNotChecked, Detail: "revocation check disabled"}
	}
	// SPEC 5.9: same method:signer; tofu ids are self-asserted, so also the same key
	entries, failure, e := trustedList(ctx, url, signedListRevocation, func(s *BlockResult) bool {
		if s.Fields["method"] != f["method"] || s.Fields["signer"] != f["signer"] {
			return false
		}
		pk, has := s.Fields["pubkey"]
		return f["method"] != "tofu" || (has && pk != "" && sameKeyValue(pk, f["pubkey"]))
	}, opts)
	if entries == nil {
		return &RevocationCheck{Status: RevocationNotChecked, Detail: e, Failure: failure}
	}
	id := RevocationID(f)
	if entries[id] {
		return &RevocationCheck{Status: RevocationRevoked, Detail: "sha256:" + id + " is on the signer's revocation list"}
	}
	return &RevocationCheck{Status: RevocationNotRevoked}
}

// --- rosters (SPEC 5.8 member_of)

// SPEC 5.8.10: 8 https roster URLs and 256 lookups (URL fetches and DNS queries together)
const (
	maxRosters       = 8
	maxRosterQueries = 256
)

func lookupMemberships(ctx context.Context, queries []membershipQuery, opts *VerifyOptions, warnings *[]string) map[membershipQuery]string {
	out := map[membershipQuery]string{}
	var rosters []string
	for _, q := range queries {
		if !slices.Contains(rosters, q.roster) {
			rosters = append(rosters, q.roster)
		}
	}
	if opts.Offline {
		for _, q := range queries {
			out[q] = MembershipUnavailable
		}
		if len(queries) > 0 {
			*warnings = append(*warnings, "member_of: rosters not consulted (offline)")
		}
		return out
	}
	httpsRosters, lookups := 0, 0
	for _, r := range rosters {
		if strings.HasPrefix(r, "https:") {
			httpsRosters++
		}
	}
	lookups = httpsRosters
	for _, q := range queries {
		if strings.HasPrefix(q.roster, "dns:") {
			lookups++
		}
	}
	if httpsRosters > maxRosters || lookups > maxRosterQueries {
		*warnings = append(*warnings, fmt.Sprintf("member_of: %d roster URLs and %d lookups exceed the limits (%d URLs, %d lookups)", httpsRosters, lookups, maxRosters, maxRosterQueries))
		for _, q := range queries {
			out[q] = MembershipUnavailable
		}
		return out
	}
	for _, roster := range rosters {
		ref, _ := parseRosterRef(roster)
		var ids []string
		for _, q := range queries {
			if q.roster == roster {
				ids = append(ids, q.id)
			}
		}
		if !ref.https {
			for _, id := range ids {
				out[membershipQuery{roster, id}] = lookupDNSMember(ctx, id, ref.domain, &opts.ResolveOptions)
			}
			continue
		}
		// SPEC 5.8.8: the issuer is the host of the URL as written, not of a redirect target
		entries, _, e := trustedList(ctx, ref.url, signedListMembers, func(s *BlockResult) bool {
			return s.Fields["method"] == "dns" && s.Fields["signer"] == ref.host
		}, opts)
		if entries == nil {
			*warnings = append(*warnings, fmt.Sprintf("member_of: roster %s cannot be used: %s", roster, e))
		}
		for _, id := range ids {
			switch {
			case entries == nil:
				out[membershipQuery{roster, id}] = MembershipUnavailable
			case entries[id]:
				out[membershipQuery{roster, id}] = MembershipMember
			default:
				out[membershipQuery{roster, id}] = MembershipNotMember
			}
		}
	}
	return out
}

func verifyBlock(ctx context.Context, text string, block *ParsedBlock, opts *VerifyOptions) *BlockResult {
	if opts == nil {
		opts = &VerifyOptions{}
	}
	f := block.Fields
	r := &BlockResult{Index: block.Index, Line: block.Line, Status: StatusValid, Fields: f, Warnings: []string{}}
	fail := func(status, code, msg string) *BlockResult {
		if status == StatusMalformed || status == StatusUnsupported {
			r.Warnings = append(r.Warnings, legacyHints(block)...)
		}
		r.Status, r.Code, r.Message = status, code, msg
		return r
	}

	// SPEC 5.4 step 1: an unknown version comes first, so fields added by later formats read as "unsupported", not "malformed"
	if v, ok := f["v"]; ok && !slices.Contains(block.Errors, `duplicate key "v"`) && !supportedVersions[v] {
		return fail(StatusUnsupported, "unsupported-version", fmt.Sprintf("unsupported version %q", v))
	}
	if len(block.UnknownKeys) > 0 {
		return fail(StatusMalformed, "unknown-field", strings.Join(block.Errors, "; "))
	}
	if len(block.Errors) > 0 {
		return fail(StatusMalformed, "malformed", strings.Join(block.Errors, "; "))
	}
	if !tsRe.MatchString(f["ts"]) {
		r.Warnings = append(r.Warnings, fmt.Sprintf("ts %q is not in YYYY-MM-DDTHH:MM:SSZ form", f["ts"]))
	}
	if sem := validateSemantics(f); sem != "" {
		return fail(StatusMalformed, "malformed", sem)
	}
	// SPEC 5.7: a resource hash prefix this version does not define
	if v, ok := f["resources"]; ok {
		if _, _, uh := parseResources(v); uh != "" {
			return fail(StatusUnsupported, "unsupported-hash", fmt.Sprintf("unsupported resource hash %q", uh))
		}
	}

	h := f["hash"]
	hi := strings.IndexByte(h, ':')
	if hi < 0 || !IsSupportedHash(h[:hi]) {
		return fail(StatusUnsupported, "unsupported-hash", fmt.Sprintf("unsupported hash %q", h))
	}
	computed, partial, se := ComputeBlockHash(text, block, h[:hi])
	if se != nil {
		if se.Code == "malformed" {
			return fail(StatusMalformed, se.Code, se.Msg)
		}
		return fail(StatusInvalid, se.Code, se.Msg)
	}
	r.Partial = partial
	r.ComputedHash = computed
	ok := r.ComputedHash == strings.ToLower(h) && h == strings.ToLower(h)
	r.HashOk = &ok
	if !ok {
		if partial != nil {
			return fail(StatusInvalid, "hash-mismatch", "a signed section was modified after this signature")
		}
		return fail(StatusInvalid, "hash-mismatch", "document content was modified after this signature")
	}

	// SPEC 4.6: a tsa block is checked against its token; there is no key to resolve
	if f["method"] == "tsa" {
		return verifyTsaBlock(ctx, r, f, h[:hi], opts, fail)
	}

	alg := f["alg"]
	if !supportedAlgs[alg] {
		return fail(StatusUnsupported, "unsupported-alg", fmt.Sprintf("unsupported alg %q", alg))
	}
	sigText := UnfoldBinary(f["sig"])
	if !strings.HasPrefix(sigText, "base64:") {
		return fail(StatusMalformed, "malformed", `sig must start with "base64:"`)
	}
	sig, err := fromBase64(sigText[7:])
	if err != nil {
		return fail(StatusMalformed, "malformed", "sig is not valid base64")
	}

	if alg == "openpgp" {
		if pre := CheckPGPSignaturePacket(sig, f["fpr"]); !pre.OK {
			return fail(pre.Status, pre.Code, pre.Message)
		}
	}

	payload := SignedPayload(f)
	var wa *webAuthnCheck
	if alg == "webauthn-es256" {
		c := checkWebAuthnData(f, payload)
		if c.info != nil {
			r.WebAuthn = c.info
		}
		if !c.ok {
			if c.code == "malformed" {
				return fail(StatusMalformed, c.code, c.msg)
			}
			return fail(StatusInvalid, c.code, c.msg)
		}
		wa = &c
		if c.info.RPID == "localhost" {
			r.Warnings = append(r.Warnings, "webauthn: rp_id is localhost (development signature)")
		}
	}
	// ed25519 and webauthn-es256
	findKey := func(cands []CandidateKey) (*CandidateKey, error) {
		for i := range cands {
			if wa != nil {
				good, err := verifyWebAuthnSignature(cands[i].Key, sig, wa.authData, wa.clientData)
				if err != nil {
					return nil, err
				}
				if good {
					return &cands[i], nil
				}
			} else if ed25519Verify(cands[i].Key, sig, payload) {
				return &cands[i], nil
			}
		}
		return nil, nil
	}

	// SPEC 4.5: a key snapshot is checked first, so a bad signature is invalid even when the published key cannot be reached
	var snapshot *CandidateKey
	if _, ok := f["pubkey"]; ok && keySnapshotMethods[f["method"]] {
		s, msg := keySnapshot(f, alg)
		if msg != "" {
			return fail(StatusMalformed, "malformed", msg)
		}
		m, err := findKey([]CandidateKey{*s})
		if err != nil {
			return fail(StatusMalformed, "malformed", err.Error())
		}
		if m == nil {
			return fail(StatusInvalid, "bad-signature", "signature does not verify with the embedded key")
		}
		snapshot = s
	}

	resolver := opts.Resolvers[f["method"]]
	if resolver == nil {
		resolver = DefaultResolvers()[f["method"]]
	}
	if resolver == nil {
		return fail(StatusUnsupported, "unsupported-method", fmt.Sprintf("unknown method %q", f["method"]))
	}
	var keys []CandidateKey
	notPublished := ""
	res, err := resolver.Resolve(ctx, f, &opts.ResolveOptions)
	if err != nil {
		var re *ResolutionError
		switch {
		case !errors.As(err, &re):
			return fail(StatusUnresolved, "network", err.Error())
		case re.Kind == KindUnsupported:
			return fail(StatusUnsupported, "unsupported-method", re.Msg)
		case re.Kind == KindMalformed:
			return fail(StatusMalformed, "malformed", re.Msg)
		case re.Kind == KindNotFound && snapshot != nil:
			notPublished = re.Msg
		default:
			return fail(StatusUnresolved, re.Kind, re.Msg)
		}
	} else {
		for _, k := range res.Keys {
			if k.Alg == keyTypeFor(alg) {
				keys = append(keys, k)
			}
		}
		r.Warnings = append(r.Warnings, res.Warnings...)
	}
	if snapshot != nil {
		i := slices.IndexFunc(keys, func(k CandidateKey) bool { return bytes.Equal(k.Key, snapshot.Key) })
		if i >= 0 {
			keys = keys[i : i+1]
		} else {
			if notPublished == "" {
				notPublished = f["signer"] + " does not publish the embedded key now"
			}
			keys = []CandidateKey{*snapshot}
		}
	}

	var matched *CandidateKey
	if alg == "openpgp" {
		now := opts.Now
		if now.IsZero() {
			now = time.Now()
		}
		certs := make([]pgpCertSource, len(keys))
		for i, k := range keys {
			certs[i] = pgpCertSource{bytes: k.Key, source: strings.SplitN(k.Source, " ", 2)[0]}
		}
		chk := verifyPgpSignature(sig, f, payload, certs, now.Unix())
		r.PGP = chk.info
		if chk.status != StatusValid {
			return fail(chk.status, chk.code, chk.message)
		}
		r.Warnings = append(r.Warnings, chk.warnings...)
		for i := range keys {
			if strings.HasPrefix(keys[i].Source, chk.info.KeySource) {
				matched = &keys[i]
				break
			}
		}
		if matched == nil && len(keys) > 0 {
			matched = &keys[0]
		}
	} else {
		m, err := findKey(keys)
		if err != nil {
			return fail(StatusMalformed, "malformed", err.Error())
		}
		matched = m
	}
	if matched == nil {
		if snapshot != nil {
			return fail(StatusInvalid, "bad-signature", "signature does not verify with the embedded key")
		}
		return fail(StatusInvalid, "bad-signature", "signature does not verify with the signer's key(s)")
	}
	r.KeySource = matched.Source

	// SPEC 4.4: a stored tofu binding must match, and is only written once the whole block verified
	tofuStatus := ""
	if pk, ok := f["pubkey"]; ok && f["method"] == "tofu" && opts.TofuStore != nil {
		// SPEC 4.4: an unconfirmed key from an earlier block of this document counts as recorded for the blocks after it
		prev, unconfirmed := opts.pendingTofu[f["signer"]]
		known := unconfirmed
		if !unconfirmed {
			prev, known = opts.TofuStore.Get(f["signer"])
		}
		if known && prev != pk && !opts.AcceptNewTofuKey {
			from := "the stored one"
			if unconfirmed {
				from = "the one in an earlier signature"
			}
			return fail(StatusInvalid, "key-changed", fmt.Sprintf("tofu: the key for signer %q differs from %s (%s)", f["signer"], from, prev))
		}
		switch {
		case !known || (unconfirmed && prev == pk):
			tofuStatus = TofuNew
		case prev == pk:
			tofuStatus = TofuKnown
		default:
			tofuStatus = TofuReplaced
		}
	}

	if exp := f["expires"]; exp != "" {
		now := opts.Now
		if now.IsZero() {
			now = time.Now()
		}
		if t, err := time.Parse(tsLayout, exp); err == nil && now.UnixMilli() > t.UnixMilli() {
			return fail(StatusInvalid, "expired", "signature expired at "+exp)
		}
	}

	if v := f["resources"]; v != "" {
		entries, _, _ := parseResources(v)
		r.Resources = checkResources(ctx, entries, &opts.ResourceCheckOptions)
		firstWith := func(status string) *ResourceResult {
			for i := range r.Resources {
				if r.Resources[i].Status == status {
					return &r.Resources[i]
				}
			}
			return nil
		}
		if bad := firstWith(ResourceMismatch); bad != nil {
			return fail(StatusInvalid, "resource-mismatch", fmt.Sprintf("resource %s does not match its hash", bad.Ref))
		}
		if missing := firstWith(ResourceMissing); missing != nil {
			return fail(StatusInvalid, "resource-missing", fmt.Sprintf("resource %s is missing", missing.Ref))
		}
		if un := firstWith(ResourceUnreachable); un != nil {
			return fail(StatusUnresolved, "network", fmt.Sprintf("resource %s could not be fetched: %s", un.Ref, un.Detail))
		}
		var unchecked []string
		for _, x := range r.Resources {
			if x.Status == ResourceNotChecked {
				unchecked = append(unchecked, x.Ref)
			}
		}
		if len(unchecked) > 0 {
			r.Warnings = append(r.Warnings, fmt.Sprintf("%d resource(s) not checked: %s", len(unchecked), strings.Join(unchecked, ", ")))
		}
	}

	if f["revocation_url"] != "" {
		r.Revocation = checkRevocation(ctx, f, opts)
		if r.Revocation.Status == RevocationRevoked {
			return fail(StatusInvalid, "revoked", fmt.Sprintf("signature was revoked by its signer (%s)", f["revocation_url"]))
		}
		// SPEC 5.9 step 4: blocking the fetch must not hide a revocation
		if r.Revocation.Failure != "" {
			return fail(StatusUnresolved, r.Revocation.Failure, "revocation list could not be checked: "+r.Revocation.Detail)
		}
		if r.Revocation.Status == RevocationNotChecked {
			r.Warnings = append(r.Warnings, "revocation not checked: "+r.Revocation.Detail)
		}
	}

	if r.Partial != nil {
		r.Warnings = append(r.Warnings, "partial signature: covers only section(s) "+strings.Join(r.Partial, ", "))
	}
	// SPEC 4.5: the signature holds with the embedded key, but nobody vouches for that key now; VerifyDocument adds T(k)
	if notPublished != "" {
		return fail(StatusUnresolved, "key-not-published", fmt.Sprintf("the signature verifies with the embedded key, which %s does not publish now (%s)", f["signer"], notPublished))
	}
	if tofuStatus != "" {
		r.Tofu = &TofuInfo{Status: tofuStatus, Fingerprint: KeyFingerprint(f["pubkey"])}
		if tofuStatus == TofuNew && opts.ConfirmNewTofuKeys {
			opts.pendingTofu[f["signer"]] = f["pubkey"]
		} else if tofuStatus != TofuKnown {
			if err := opts.TofuStore.Set(f["signer"], f["pubkey"]); err != nil {
				r.Warnings = append(r.Warnings, "tofu: could not record key: "+err.Error())
			}
		}
	}
	return r
}

func keySnapshot(f map[string]string, alg string) (*CandidateKey, string) {
	pk := f["pubkey"]
	kalg, b64, ok := strings.Cut(pk, ":")
	if !ok || kalg != keyTypeFor(alg) {
		if !ok {
			kalg = ""
		}
		return nil, fmt.Sprintf("pubkey key type %q does not match alg %q", kalg, alg)
	}
	raw, err := fromBase64(b64)
	if err != nil {
		return nil, "invalid pubkey: " + err.Error()
	}
	key, err := decodePublicKey(kalg, raw)
	if err != nil {
		return nil, "invalid pubkey: " + err.Error()
	}
	// SPEC 4.2: key_fp names a key, so it has to name this one
	if fp, has := f["key_fp"]; has && f["method"] == "git-hosting" && kalg == "ed25519" && SSHFingerprint(key) != fp {
		return nil, "key_fp does not match the embedded pubkey"
	}
	return &CandidateKey{Alg: kalg, Key: key, Source: "embedded pubkey"}, ""
}

func verifyTsaBlock(ctx context.Context, r *BlockResult, f map[string]string, hashAlg string, opts *VerifyOptions, fail func(status, code, msg string) *BlockResult) *BlockResult {
	token := UnfoldBinary(f["sig"])
	if _, err := DecodePrefixedBinary(token); err != nil {
		return fail(StatusMalformed, "malformed", "sig is not a timestamp token: "+err.Error())
	}
	payload := SignedPayload(f)
	// SPEC 4.6: the token's imprint is the digest of the signed payload, with the block's hash algorithm
	var c TSACheck
	if opts.TSAVerifier != nil {
		c = opts.TSAVerifier(ctx, token, payload, hashAlg)
	} else {
		c = checkTimestampOver(token, digestBytes(hashAlg, payload), hashAlg, &opts.TSA, "message imprint does not match "+strings.ToUpper(hashAlg)+"(payload)")
	}
	// SPEC 4.6: a time is evidence only when the token was verified
	if !c.Verified {
		c.GenTime, c.AccuracyMs = "", 0
	}
	r.TSA = &c
	if c.Status == TSAMismatch {
		return fail(StatusInvalid, "bad-signature", "timestamp token does not cover this block: "+c.Detail)
	}
	if c.Status == TSAError || !c.Verified {
		// a token whose imprint matched but whose TSA cannot be trusted is unresolved, like a key that was not found
		if strings.HasPrefix(c.Detail, "imprint matched") || c.Status == TSAOK {
			return fail(StatusUnresolved, KindNotFound, "timestamp could not be verified: "+c.Detail)
		}
		// an outside verifier that fails says nothing about the token
		if opts.TSAVerifier != nil {
			return fail(StatusUnresolved, KindNetwork, "timestamp could not be verified: "+c.Detail)
		}
		return fail(StatusInvalid, "bad-signature", "timestamp token is unusable: "+c.Detail)
	}
	r.KeySource = "TSA " + c.Signer
	return r
}

// --- T(k) (SPEC 4.6)

var genTimeMsRe = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z$`)

// milliseconds since the epoch; a fraction finer than 1 ms is rounded up, so the bound stays an upper bound
func genTimeMs(genTime string) (int64, bool) {
	m := genTimeMsRe.FindStringSubmatch(genTime)
	if m == nil {
		return 0, false
	}
	base, err := time.Parse("2006-01-02T15:04:05", m[1])
	if err != nil {
		return 0, false
	}
	frac := m[2]
	ms := int64(0)
	for i := 0; i < 3; i++ {
		ms *= 10
		if i < len(frac) {
			ms += int64(frac[i] - '0')
		}
	}
	if len(frac) > 3 && strings.Trim(frac[3:], "0") != "" {
		ms++
	}
	return base.UnixMilli() + ms, true
}

func formatTimeMs(ms int64) string {
	s := time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z")
	if strings.HasSuffix(s, ".000Z") {
		return strings.TrimSuffix(s, ".000Z") + "Z"
	}
	return s
}

func blockTimes(sigs []*BlockResult) {
	for _, k := range sigs {
		var best *BlockTime
		var bestMs int64
		for _, j := range sigs {
			if j.Index <= k.Index || j.Fields["method"] != "tsa" || j.Status != StatusValid || j.TSA == nil || !j.TSA.Verified || j.TSA.GenTime == "" {
				continue
			}
			g, ok := genTimeMs(j.TSA.GenTime)
			if !ok {
				continue
			}
			t := g + j.TSA.AccuracyMs
			if best == nil || t < bestMs {
				bestMs = t
				best = &BlockTime{At: formatTimeMs(t), Block: j.Index, GenTime: j.TSA.GenTime, AccuracyMs: j.TSA.AccuracyMs, Signer: j.TSA.Signer}
			}
		}
		k.Time = best
	}
}

// SPEC 5.2: every block hashes the document from the start, so the chain length is bounded
const MaxChainBlocks = 256

func VerifyDocument(ctx context.Context, text string, opts *VerifyOptions) *VerifyResult {
	if opts == nil {
		opts = &VerifyOptions{}
	}
	doc := ParseDocument(text)
	res := &VerifyResult{Signatures: []*BlockResult{}, Warnings: []string{}, Agreement: emptyAgreement()}
	if len(doc.Chain) > MaxChainBlocks {
		res.Error = fmt.Sprintf("too many signature blocks (%d; the limit is %d)", len(doc.Chain), MaxChainBlocks)
		return res
	}
	if len(doc.Chain) == 0 {
		if doc.StrayMarker {
			res.Error = fmt.Sprintf("unsigned content after the last signature (signature block at line %d is followed by other text)", doc.StrayMarkerLine)
		} else {
			res.Error = "no signatures found"
		}
		return res
	}
	if doc.StrayMarker {
		res.Warnings = append(res.Warnings, fmt.Sprintf("line %d: an md-signature marker inside the body is treated as document content, not as a signature", doc.StrayMarkerLine))
	}
	// SPEC 5.5: a renderer shows every block of such a document as code
	if doc.UnclosedFence {
		res.Warnings = append(res.Warnings, "the body ends inside an open code fence, so Markdown renderers show the signature blocks as code")
	}
	_, _, markerWarnings := FindSignatureMarker(doc.Body)
	res.Warnings = append(res.Warnings, markerWarnings...)
	o := *opts
	if o.signedListCache == nil {
		o.signedListCache = map[string]*loadedList{}
	}
	o.pendingTofu = map[string]string{}
	for _, b := range doc.Chain {
		res.Signatures = append(res.Signatures, verifyBlock(ctx, doc.Text, b, &o))
	}
	if !o.SkipTSA {
		blockTimes(res.Signatures)
	}
	for _, s := range res.Signatures {
		if s.Code == "key-not-published" && s.Time != nil {
			s.Message += fmt.Sprintf("; the signature existed at %s (TSA, block #%d)", s.Time.At, s.Time.Block)
		}
	}
	if !opts.skipAgreement {
		blocks := make([]agreementBlock, len(res.Signatures))
		for i, s := range res.Signatures {
			blocks[i] = agreementBlock{Index: s.Index, Status: s.Status, Code: s.Code, Fields: s.Fields, UserVerified: s.WebAuthn != nil && s.WebAuthn.UserVerified}
		}
		memberships := lookupMemberships(ctx, membershipQueries(blocks), &o, &res.Warnings)
		res.Agreement = evaluateAgreement(blocks, func(roster, id string) string {
			if m, ok := memberships[membershipQuery{roster, id}]; ok {
				return m
			}
			return MembershipUnavailable
		})
	}
	res.OK = agreementOK(res)
	return res
}

// SPEC 5.4, 5.8.9: a violated, undetermined, or unsupported agreement is not a success
func agreementOK(r *VerifyResult) bool {
	if r.Error != "" {
		return false
	}
	for _, s := range r.Signatures {
		if s.Status != StatusValid {
			return false
		}
	}
	switch r.Agreement.Status {
	case AgreementViolated, AgreementUndetermined, AgreementUnsupported:
		return false
	}
	return true
}
