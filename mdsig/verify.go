package mdsig

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
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
	WebAuthn     *WebAuthnInfo
	PGP          *PGPInfo
	Resources    []ResourceResult
	Revocation   *RevocationCheck
	TSA          *TSACheck
	Warnings     []string
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
	Resolvers    map[string]Resolver
	SkipTSA      bool
	TSA          TSAVerifyOptions
	NoRevocation bool
	Now          time.Time

	skipAgreement   bool
	revocationCache map[string]*revocationList
}

var supportedAlgs = map[string]bool{"ed25519": true, "webauthn-es256": true, "openpgp": true}

var webAuthnKeys = []string{"rp_id", "webauthn_authenticator_data", "webauthn_client_data"}

var revocationURLRe = regexp.MustCompile(`^https://\S+$`)

func IsValidRevocationURL(u string) bool {
	return revocationURLRe.MatchString(u) && jsNonSpace(u)
}

func validateSemantics(f map[string]string) string {
	if v, ok := f["expires"]; ok && !IsValidTimestamp(v) {
		return fmt.Sprintf("expires %s is not a valid YYYY-MM-DDTHH:MM:SSZ date-time", jsonString(v))
	}
	if v, ok := f["revocation_url"]; ok && !IsValidRevocationURL(v) {
		return "revocation_url must be an https:// URL"
	}
	if v, ok := f["require"]; ok {
		if _, errs := ParseRequire(v, 0, f["v"]); len(errs) > 0 {
			return strings.Join(errs, "; ")
		}
	}
	if v, ok := f["resources"]; ok {
		if _, errs := parseResources(v); len(errs) > 0 {
			return strings.Join(errs, "; ")
		}
	}
	// SPEC 4.3: method pgp and alg openpgp only go together
	isPgp := f["method"] == "pgp"
	if isPgp != (algOf(f) == "openpgp") {
		if isPgp {
			return "method pgp requires alg openpgp"
		}
		return "alg openpgp requires method pgp"
	}
	if isPgp {
		if !fprRe.MatchString(f["fpr"]) {
			return "pgp requires fpr: 40 or 64 upper-case hex digits"
		}
		if !emailRe.MatchString(f["signer"]) {
			return "pgp signer must be a lower-case email address"
		}
	}
	if f["method"] == "git-hosting" && !isValidGitHostingSigner(f["signer"]) {
		return "git-hosting signer must be <host>/<username> with a domain name as host"
	}
	isWebAuthn := algOf(f) == "webauthn-es256"
	for _, k := range webAuthnKeys {
		_, has := f[k]
		if isWebAuthn && !has {
			return fmt.Sprintf("alg webauthn-es256 requires %q", k)
		}
		if !isWebAuthn && has {
			return fmt.Sprintf("%q is only allowed with alg webauthn-es256", k)
		}
	}
	return ""
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

type revocationList struct {
	ok      bool
	signers []revocationSigner
	revoked map[string]bool
	err     string
}

type revocationSigner struct {
	method, signer, pubkey string
	hasPubkey              bool
}

// SPEC 5.9: computed from the payload, because sig bytes can be changed without the key
func RevocationID(fields map[string]string) string {
	sum := sha256.Sum256(SignedPayload(fields))
	return toHex(sum[:])
}

var revokedLineRe = regexp.MustCompile(`^revoked: sha256:([0-9a-f]{64})[ \t]*$`)

func loadRevocationList(ctx context.Context, url string, opts *VerifyOptions) *revocationList {
	b, err := FetchResource(ctx, opts.FetchClient, url, maxRevocationListBytes)
	if err == nil && !utf8.Valid(b) {
		err = errors.New("the list is not valid UTF-8")
	}
	if err != nil {
		return &revocationList{err: "could not fetch revocation list: " + err.Error()}
	}
	// TextDecoder strips a leading BOM
	text := strings.TrimPrefix(string(b), bom)
	inner := *opts
	// SPEC 5.9: the list is verified without revocation, resources or require
	inner.NoRevocation = true
	inner.FetchResources = false
	inner.LoadResource = nil
	inner.revocationCache = nil
	inner.TofuStore = nil
	inner.skipAgreement = true
	r := VerifyDocument(ctx, text, &inner)
	if !r.OK {
		msg := r.Error
		if msg == "" {
			msg = "invalid"
			for _, s := range r.Signatures {
				if s.Status != StatusValid {
					if s.Message != "" {
						msg = s.Message
					}
					break
				}
			}
		}
		return &revocationList{err: "revocation list does not verify: " + msg}
	}
	revoked := map[string]bool{}
	// JS /^...$/gm splits on any ECMAScript line terminator
	for _, line := range strings.FieldsFunc(ParseDocument(text).Body, isJSLineTerminator) {
		if m := revokedLineRe.FindStringSubmatch(line); m != nil {
			revoked[m[1]] = true
		}
	}
	list := &revocationList{ok: true, revoked: revoked}
	for _, s := range r.Signatures {
		pk, has := s.Fields["pubkey"]
		list.signers = append(list.signers, revocationSigner{method: s.Fields["method"], signer: s.Fields["signer"], pubkey: pk, hasPubkey: has})
	}
	return list
}

func checkRevocation(ctx context.Context, f map[string]string, opts *VerifyOptions) *RevocationCheck {
	url := f["revocation_url"]
	if opts.Offline {
		return &RevocationCheck{Status: RevocationNotChecked, Detail: "revocation list not fetched (offline)"}
	}
	if opts.NoRevocation {
		return &RevocationCheck{Status: RevocationNotChecked, Detail: "revocation check disabled"}
	}
	cache := opts.revocationCache
	if cache == nil {
		cache = map[string]*revocationList{}
	}
	list, ok := cache[url]
	if !ok {
		list = loadRevocationList(ctx, url, opts)
		cache[url] = list
	}
	if !list.ok {
		return &RevocationCheck{Status: RevocationNotChecked, Detail: list.err, Failure: KindNetwork}
	}
	trusted := false
	for _, s := range list.signers {
		pk, has := f["pubkey"]
		// SPEC 5.9: tofu ids are self-asserted, so the list must come from the same pubkey
		pubkeyOK := f["method"] != "tofu" || (s.hasPubkey == has && s.pubkey == pk)
		if s.method == f["method"] && sameSigner(f["method"], s.signer, f["signer"]) && pubkeyOK {
			trusted = true
			break
		}
	}
	if !trusted {
		return &RevocationCheck{Status: RevocationNotChecked, Detail: "revocation list is not signed by this signer", Failure: KindNotFound}
	}
	id := RevocationID(f)
	if list.revoked[id] {
		return &RevocationCheck{Status: RevocationRevoked, Detail: "sha256:" + id + " is on the signer's revocation list"}
	}
	return &RevocationCheck{Status: RevocationNotRevoked}
}

func verifyBlock(ctx context.Context, text string, block *ParsedBlock, opts *VerifyOptions) *BlockResult {
	if opts == nil {
		opts = &VerifyOptions{}
	}
	f := block.Fields
	r := &BlockResult{Index: block.Index, Line: block.Line, Status: StatusValid, Fields: f, Warnings: []string{}}
	fail := func(status, code, msg string) *BlockResult {
		r.Status, r.Code, r.Message = status, code, msg
		return r
	}

	if len(block.UnknownKeys) > 0 {
		return fail(StatusMalformed, "unknown-field", strings.Join(block.Errors, "; "))
	}
	if len(block.Errors) > 0 {
		return fail(StatusMalformed, "malformed", strings.Join(block.Errors, "; "))
	}
	if !supportedVersions[f["v"]] {
		return fail(StatusUnsupported, "unsupported-version", fmt.Sprintf("unsupported version %q", f["v"]))
	}
	if !tsRe.MatchString(f["ts"]) {
		r.Warnings = append(r.Warnings, fmt.Sprintf("ts %q is not in YYYY-MM-DDTHH:MM:SSZ form", f["ts"]))
	}
	if sem := validateSemantics(f); sem != "" {
		return fail(StatusMalformed, "malformed", sem)
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

	alg := algOf(f)
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

	resolver := opts.Resolvers[f["method"]]
	if resolver == nil {
		resolver = DefaultResolvers()[f["method"]]
	}
	if resolver == nil {
		return fail(StatusUnsupported, "unsupported-method", fmt.Sprintf("unknown method %q", f["method"]))
	}
	res, err := resolver.Resolve(ctx, f, &opts.ResolveOptions)
	if err != nil {
		var re *ResolutionError
		if errors.As(err, &re) {
			if re.Kind == KindUnsupported {
				return fail(StatusUnsupported, "unsupported-method", re.Msg)
			}
			if re.Kind == KindMalformed {
				return fail(StatusMalformed, "malformed", re.Msg)
			}
			return fail(StatusUnresolved, re.Kind, re.Msg)
		}
		return fail(StatusUnresolved, "network", err.Error())
	}
	var keys []CandidateKey
	for _, k := range res.Keys {
		if k.Alg == keyTypeFor(alg) {
			keys = append(keys, k)
		}
	}
	r.Warnings = append(r.Warnings, res.Warnings...)

	payload := SignedPayload(f)
	var matched *CandidateKey
	if alg == "webauthn-es256" {
		wa := checkWebAuthnData(f, payload)
		if wa.info != nil {
			r.WebAuthn = wa.info
		}
		if !wa.ok {
			if wa.code == "malformed" {
				return fail(StatusMalformed, wa.code, wa.msg)
			}
			return fail(StatusInvalid, wa.code, wa.msg)
		}
		for i := range keys {
			good, err := verifyWebAuthnSignature(keys[i].Key, sig, wa.authData, wa.clientData)
			if err != nil {
				return fail(StatusMalformed, "malformed", err.Error())
			}
			if good {
				matched = &keys[i]
				break
			}
		}
		if wa.info.RPID == "localhost" {
			r.Warnings = append(r.Warnings, "webauthn: rp_id is localhost (development signature)")
		}
	} else if alg == "openpgp" {
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
		for i := range keys {
			if ed25519Verify(keys[i].Key, sig, payload) {
				matched = &keys[i]
				break
			}
		}
	}
	if matched == nil {
		return fail(StatusInvalid, "bad-signature", "signature does not verify with the signer's key(s)")
	}
	r.KeySource = matched.Source

	// SPEC 4.4: a stored tofu binding must match, and is only written for a signature that verified
	if pk, ok := f["pubkey"]; ok && f["method"] == "tofu" && opts.TofuStore != nil {
		prev, known := opts.TofuStore.Get(f["signer"])
		if known && prev != pk && !opts.AcceptNewTofuKey {
			return fail(StatusInvalid, "key-changed", fmt.Sprintf("tofu: the key for signer %q differs from the stored one (%s)", f["signer"], prev))
		}
		if !known || prev != pk {
			if err := opts.TofuStore.Set(f["signer"], pk); err != nil {
				r.Warnings = append(r.Warnings, "tofu: could not record key: "+err.Error())
			}
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
		entries, _ := parseResources(v)
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
		// SPEC 5.9 step 5: blocking the fetch must not hide a revocation
		if r.Revocation.Failure != "" {
			return fail(StatusUnresolved, r.Revocation.Failure, "revocation list could not be checked: "+r.Revocation.Detail)
		}
		if r.Revocation.Status == RevocationNotChecked {
			r.Warnings = append(r.Warnings, "revocation not checked: "+r.Revocation.Detail)
		}
	}

	if tok := f["tsa_token"]; tok != "" && !opts.SkipTSA {
		c := CheckTSAToken(UnfoldBinary(tok), sig, &opts.TSA)
		r.TSA = &c
		if c.Status == TSAMismatch {
			return fail(StatusInvalid, "bad-signature", "timestamp token does not match this signature: "+c.Detail)
		}
		if c.Status == TSAError {
			r.Warnings = append(r.Warnings, "timestamp could not be checked: "+c.Detail)
		}
	}
	if r.Partial != nil {
		r.Warnings = append(r.Warnings, "partial signature: covers only section(s) "+strings.Join(r.Partial, ", "))
	}
	return r
}

// SPEC 5.2: every block hashes the document from the start, so the chain length is bounded
const MaxChainBlocks = 256

func VerifyDocument(ctx context.Context, text string, opts *VerifyOptions) *VerifyResult {
	if opts == nil {
		opts = &VerifyOptions{}
	}
	doc := ParseDocument(text)
	none := Agreement{Status: AgreementNone, Required: []Requirement{}, Missing: []MissingRequirement{}, Violations: []OrderViolation{}}
	res := &VerifyResult{Signatures: []*BlockResult{}, Warnings: []string{}, Agreement: none}
	if len(doc.Chain) == 0 {
		if doc.StrayMarker {
			res.Error = fmt.Sprintf("unsigned content after the last signature (signature block at line %d is followed by other text)", doc.StrayMarkerLine)
		} else {
			res.Error = "no signatures found"
		}
		return res
	}
	if len(doc.Chain) > MaxChainBlocks {
		res.Error = fmt.Sprintf("too many signature blocks (%d; the limit is %d)", len(doc.Chain), MaxChainBlocks)
		return res
	}
	if doc.StrayMarker {
		res.Warnings = append(res.Warnings, fmt.Sprintf("line %d: an md-signature marker inside the body is treated as document content, not as a signature", doc.StrayMarkerLine))
	}
	o := *opts
	if o.revocationCache == nil {
		o.revocationCache = map[string]*revocationList{}
	}
	res.OK = true
	for _, b := range doc.Chain {
		br := verifyBlock(ctx, doc.Text, b, &o)
		res.Signatures = append(res.Signatures, br)
		if br.Status != StatusValid {
			res.OK = false
		}
	}
	if !opts.skipAgreement {
		blocks := make([]agreementBlock, len(res.Signatures))
		for i, s := range res.Signatures {
			blocks[i] = agreementBlock{Index: s.Index, Valid: s.Status == StatusValid, Declares: s.Status == StatusValid || s.Status == StatusUnresolved, Fields: s.Fields}
		}
		res.Agreement = evaluateAgreement(blocks)
		// SPEC 5.8: an order violation under "order strict" fails the document
		if res.Agreement.Status == AgreementViolated {
			res.OK = false
		}
	}
	return res
}
