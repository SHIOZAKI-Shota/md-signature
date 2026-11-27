package mdsig

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

type SignOptions struct {
	Signer    Signer
	WebAuthn  WebAuthnSigner
	PGP       PGPSigner
	Method    string
	SignerID  string
	Selector  string
	KeyFP     string
	OmitKeyFP bool
	// SPEC 3.3: self-declared name for the signature table; the Nickname enforcement rules are applied
	DisplayName string
	Role        string
	Reason      string
	TS          string
	Expires     string
	Scope       []string
	// one line each; "order mode=…" and "step [any=m]" lines included (SPEC 5.8)
	Require       []string
	Resources     []ResourceItem
	RevocationURL string
	Extra         map[string]string
	// SPEC 4.6: appends a tsa block after the signature block
	TSAURL string
	TSA    TSAVerifyOptions
	// dns and git-hosting: also write the public key (SPEC 4.5), so the signature stays checkable after the key is gone
	EmbedKey bool
	// directory blocks carry the key snapshot unless this is set (SPEC 4.7)
	OmitKeySnapshot bool
	// passkeys: "required" or "preferred"; empty means "required" when a require line asks for user_verified
	UserVerification string
	HTTPClient       *http.Client
	Force            bool
	Now              func() time.Time
}

type SignResult struct {
	Text     string
	Block    string
	Fields   map[string]string
	Previous int
	TSABlock string
}

type SignError struct{ Msg string }

func (e *SignError) Error() string { return e.Msg }

type ValueError struct{ Msg string }

func (e *ValueError) Error() string { return e.Msg }

// SPEC 5.1: generators refuse documents that are not valid UTF-8
var errNotUTF8 = &SignError{Msg: "the document is not valid UTF-8"}

// SigningKey is the public half of a signer: enough to build the payload when the signature is made elsewhere
type SigningKey struct {
	Alg       string // ed25519, webauthn-es256, or openpgp
	PublicKey []byte // Ed25519 key, or the passkey's SPKI
	RPID      string // webauthn-es256
	Fpr       string // openpgp
	Emails    []string
}

type PreparedSignature struct {
	Fields  map[string]string
	Payload []byte
	// SPEC 6.1: the WebAuthn challenge, SHA-256(payload)
	Challenge []byte
	// passkeys: what to ask the authenticator for (CLI_SPEC 8.2 user_verification)
	UserVerification string
	text             string
	opts             SignOptions
	key              SigningKey
	previous         int
}

func SignDocument(ctx context.Context, text string, o SignOptions) (*SignResult, error) {
	if !utf8.ValidString(text) {
		return nil, errNotUTF8
	}
	var key SigningKey
	switch {
	case o.PGP != nil:
		key = SigningKey{Alg: "openpgp", Fpr: o.PGP.Fpr(), Emails: o.PGP.Emails()}
	case o.WebAuthn != nil:
		key = SigningKey{Alg: "webauthn-es256", PublicKey: o.WebAuthn.PublicKeySPKI(), RPID: o.WebAuthn.RPID()}
	case o.Signer != nil:
		key = SigningKey{Alg: "ed25519", PublicKey: o.Signer.PublicKey()}
	default:
		if o.Method == "pgp" {
			return nil, &ValueError{Msg: "method pgp needs an OpenPGP key"}
		}
		return nil, errors.New("no signer")
	}
	p, err := PrepareSignature(text, key, o)
	if err != nil {
		return nil, err
	}
	switch key.Alg {
	case "webauthn-es256":
		a, err := o.WebAuthn.GetAssertion(p.Challenge, p.UserVerification)
		if err != nil {
			return nil, err
		}
		if p.UserVerification == UserVerificationRequired && !assertionUserVerified(a) {
			return nil, &SignError{Msg: "user verification was required, but the authenticator did not verify the user"}
		}
		return p.complete(ctx, a.Signature, a)
	case "openpgp":
		sig, err := o.PGP.Sign(p.Payload)
		if err != nil {
			return nil, err
		}
		return p.complete(ctx, sig, nil)
	default:
		sig, err := o.Signer.Sign(p.Payload)
		if err != nil {
			return nil, err
		}
		return p.complete(ctx, sig, nil)
	}
}

// Finish checks an Ed25519 signature, or a WebAuthn assertion (a, with sig nil), against the key and appends the block; OpenPGP signatures are not checked
func (p *PreparedSignature) Finish(ctx context.Context, sig []byte, a *WebAuthnAssertion) (*SignResult, error) {
	switch p.key.Alg {
	case "webauthn-es256":
		if a == nil {
			return nil, &SignError{Msg: "a passkey signature needs the whole WebAuthn assertion"}
		}
		f := maps.Clone(p.Fields)
		f["webauthn_authenticator_data"] = toBase64(a.AuthenticatorData)
		f["webauthn_client_data"] = toBase64(a.ClientDataJSON)
		if chk := checkWebAuthnData(f, p.Payload); !chk.ok {
			return nil, &SignError{Msg: "the WebAuthn assertion does not verify for this payload and key: " + chk.msg}
		}
		if ok, err := verifyWebAuthnSignature(p.key.PublicKey, a.Signature, a.AuthenticatorData, a.ClientDataJSON); err != nil || !ok {
			return nil, &SignError{Msg: "the WebAuthn assertion does not verify for this payload and key"}
		}
		// CLI_SPEC 8.5: a tool that asked for user verification refuses an assertion without it
		if p.UserVerification == UserVerificationRequired && !assertionUserVerified(a) {
			return nil, &SignError{Msg: "user verification was required, but the assertion does not have the UV flag"}
		}
		return p.complete(ctx, a.Signature, a)
	case "ed25519":
		if len(p.key.PublicKey) != ed25519.PublicKeySize || !ed25519.Verify(p.key.PublicKey, p.Payload, sig) {
			return nil, &SignError{Msg: "the signature does not verify for this payload and key"}
		}
	}
	return p.complete(ctx, sig, nil)
}

func (p *PreparedSignature) complete(ctx context.Context, sig []byte, a *WebAuthnAssertion) (*SignResult, error) {
	fields := maps.Clone(p.Fields)
	if a != nil {
		fields["webauthn_authenticator_data"] = toBase64(a.AuthenticatorData)
		fields["webauthn_client_data"] = toBase64(a.ClientDataJSON)
	}
	fields["sig"] = "base64:" + toBase64(sig)
	r, err := appendBlock(p.text, p.previous, fields)
	if err != nil || p.opts.TSAURL == "" {
		return r, err
	}
	t, err := TimestampDocument(ctx, r.Text, TimestampOptions{TSAURL: p.opts.TSAURL, TS: fields["ts"], HTTPClient: p.opts.HTTPClient, TSA: p.opts.TSA})
	if err != nil {
		return nil, err
	}
	r.Text, r.TSABlock = t.Text, t.Block
	return r, nil
}

// SPEC 5.8.7: a passkey signer that some require line asks for with user_verified
func wantsUserVerification(chain []*ParsedBlock, method, signer string) bool {
	me := map[string]string{"method": method, "signer": signer}
	for _, b := range chain {
		if b.Fields["require"] == "" {
			continue
		}
		p := ParseRequire(b.Fields["require"], b.Index)
		if len(p.Errors) > 0 {
			continue
		}
		self := b.Fields["method"] == method && b.Fields["signer"] == signer
		for _, r := range p.Requirements {
			if r.Attributes.UserVerified && targetMatches(r, me) && !(r.Pattern && self) {
				return true
			}
		}
	}
	return false
}

// PrepareSignature builds the block for key without signing; o.Signer, o.WebAuthn, and o.PGP are ignored
func PrepareSignature(text string, key SigningKey, o SignOptions) (*PreparedSignature, error) {
	if !utf8.ValidString(text) {
		return nil, errNotUTF8
	}
	doc := ParseDocument(text)
	if len(doc.Chain) == 0 && doc.StrayMarker && !o.Force {
		return nil, &SignError{Msg: fmt.Sprintf("line %d: found an md-signature block that is followed by unsigned content. "+
			"Co-signing would endorse text the earlier signer never signed. Use force to sign the whole file as a new document.", doc.StrayMarkerLine)}
	}
	// SPEC 5.5: every appended block would render as code
	if doc.UnclosedFence {
		return nil, &SignError{Msg: "the body ends inside an open code fence; close the fence before signing, or every signature block would be shown as code"}
	}
	if !o.Force {
		for _, b := range doc.Chain {
			if len(b.Errors) > 0 {
				return nil, &SignError{Msg: fmt.Sprintf("existing signature #%d is malformed: %s", b.Index, strings.Join(b.Errors, "; "))}
			}
		}
	}

	ts := o.TS
	if ts == "" {
		now := time.Now
		if o.Now != nil {
			now = o.Now
		}
		ts = NowTS(now())
	}
	if !tsRe.MatchString(ts) {
		return nil, &ValueError{Msg: fmt.Sprintf("ts must be YYYY-MM-DDTHH:MM:SSZ, got %q", ts)}
	}
	if o.Expires != "" && !IsValidTimestamp(o.Expires) {
		return nil, &ValueError{Msg: fmt.Sprintf("expires must be YYYY-MM-DDTHH:MM:SSZ, got %q", o.Expires)}
	}
	if o.RevocationURL != "" && !IsValidRevocationURL(o.RevocationURL) {
		return nil, &ValueError{Msg: "revocation URL must be https://"}
	}
	for k := range o.Extra {
		if !isExtensionKey(k) {
			return nil, &ValueError{Msg: fmt.Sprintf("extra field %q must start with \"x_\"", k)}
		}
	}

	alg := key.Alg
	if alg != "ed25519" && alg != "webauthn-es256" && alg != "openpgp" {
		return nil, &ValueError{Msg: fmt.Sprintf("unsupported key algorithm %q", alg)}
	}
	isPgp := alg == "openpgp"
	isWebAuthn := alg == "webauthn-es256"
	if isPgp != (o.Method == "pgp") {
		if isPgp {
			return nil, &ValueError{Msg: "an OpenPGP key can only sign with method pgp"}
		}
		return nil, &ValueError{Msg: "method pgp needs an OpenPGP key"}
	}
	pub := key.PublicKey
	if o.Method == "git-hosting" && isWebAuthn {
		return nil, &ValueError{Msg: "git-hosting supports only Ed25519 SSH keys; use tofu or dns for passkeys"}
	}
	signerID := CanonicalSignerInput(o.Method, o.SignerID)
	if se := CheckSignerID(o.Method, signerID); se != "" {
		return nil, &ValueError{Msg: fmt.Sprintf("%s, got %q", se, o.SignerID)}
	}
	fields := map[string]string{"v": SpecVersion, "method": o.Method, "signer": signerID}
	if o.Selector != "" {
		if o.Method != "dns" {
			return nil, &ValueError{Msg: "selector is only used with method dns"}
		}
		if !isSelector(o.Selector) {
			return nil, &ValueError{Msg: fmt.Sprintf(`selector must be lower-case LDH labels and must not start with "_", got %q`, o.Selector)}
		}
		fields["selector"] = o.Selector
	}
	if o.Method == "git-hosting" && !o.OmitKeyFP {
		if o.KeyFP != "" {
			fields["key_fp"] = o.KeyFP
		} else {
			fields["key_fp"] = SSHFingerprint(pub)
		}
	}
	// SPEC 4.7: directory blocks should carry a snapshot, so it is on unless turned off
	embedKey := o.EmbedKey || (o.Method == "directory" && !o.OmitKeySnapshot)
	if o.EmbedKey && o.Method != "dns" && o.Method != "git-hosting" && o.Method != "directory" {
		return nil, &ValueError{Msg: "EmbedKey works with dns, git-hosting, and directory, not " + o.Method}
	}
	if o.Method == "tofu" || embedKey {
		kt := "ed25519"
		if isWebAuthn {
			kt = "es256"
		}
		fields["pubkey"] = kt + ":" + toBase64(pub)
	}
	if isPgp {
		if emails := key.Emails; len(emails) > 0 && !slices.Contains(emails, signerID) {
			return nil, &ValueError{Msg: fmt.Sprintf("the OpenPGP key has no user ID with <%s> (has: %s)", signerID, strings.Join(emails, ", "))}
		}
		fields["fpr"] = key.Fpr
	}
	if isWebAuthn {
		fields["rp_id"] = key.RPID
	}
	for k, v := range o.Extra {
		fields[k] = v
	}
	if o.DisplayName != "" {
		name, err := displayNameInput(o.DisplayName)
		if err != nil {
			return nil, &ValueError{Msg: err.Error()}
		}
		fields["display_name"] = name
	}
	if o.Role != "" {
		if !isRole(o.Role) {
			return nil, &ValueError{Msg: fmt.Sprintf("role must be one word ([a-z0-9][a-z0-9._-]*), got %q", o.Role)}
		}
		fields["role"] = o.Role
	}
	if o.Reason != "" {
		fields["reason"] = o.Reason
	}
	fields["ts"] = ts
	if o.Expires != "" {
		fields["expires"] = o.Expires
	}
	if len(o.Scope) > 0 {
		sc, ok := FormatScope(o.Scope)
		if !ok {
			return nil, &ValueError{Msg: fmt.Sprintf("invalid section id in scope %q (use [a-z0-9-]+)", strings.Join(o.Scope, ","))}
		}
		fields["scope"] = sc
	}
	if len(o.Require) > 0 {
		fields["require"] = strings.Join(o.Require, "\n")
		p := ParseRequire(fields["require"], 0)
		problems := append(append([]string{}, p.Errors...), p.Unsupported...)
		if p.OverLimit != "" {
			problems = append(problems, p.OverLimit)
		}
		problems = append(problems, p.Hints...)
		if len(problems) > 0 {
			return nil, &ValueError{Msg: strings.Join(problems, "; ")}
		}
	}
	if len(o.Resources) > 0 {
		v, err := formatResources(o.Resources)
		if err != nil {
			return nil, &ValueError{Msg: "resources: " + err.Error()}
		}
		fields["resources"] = v
	}
	if o.RevocationURL != "" {
		fields["revocation_url"] = o.RevocationURL
	}
	fields["alg"] = alg

	if sc, ok := fields["scope"]; ok {
		in, _, se := scopedHashInput(normalizeNewlines(text), sc)
		if se != nil {
			return nil, &ValueError{Msg: se.Msg}
		}
		sum := sha256.Sum256([]byte(in))
		fields["hash"] = "sha256:" + toHex(sum[:])
	} else {
		fields["hash"] = normalizedHash(text)
	}

	for _, k := range orderedKeys(fields) {
		if e := validateKey(k); e != "" {
			return nil, &ValueError{Msg: e}
		}
		if e := validateValue(fields[k], listKeys[k]); e != "" {
			return nil, &ValueError{Msg: k + ": " + e}
		}
	}

	uv := o.UserVerification
	if uv == "" {
		uv = UserVerificationPreferred
		if isWebAuthn && wantsUserVerification(doc.Chain, o.Method, signerID) {
			uv = UserVerificationRequired
		}
	}
	payload := SignedPayload(fields)
	challenge := sha256.Sum256(payload)
	return &PreparedSignature{Fields: fields, Payload: payload, Challenge: challenge[:], UserVerification: uv, text: text, opts: o, key: key, previous: len(doc.Chain)}, nil
}

func appendBlock(text string, previous int, fields map[string]string) (*SignResult, error) {
	block, err := serializeBlock(fields)
	if err != nil {
		return nil, &ValueError{Msg: err.Error()}
	}
	eol := "\n"
	if strings.Contains(text, "\r\n") {
		eol = "\r\n"
	}
	trimmed := strings.TrimRight(text, "\r\n \t")
	// SPEC 7: blank line before the first block only
	sep := eol + eol
	if previous > 0 {
		sep = eol
	}
	out := trimmed + sep + strings.ReplaceAll(block, "\n", eol) + eol
	return &SignResult{Text: out, Block: block, Fields: fields, Previous: previous}, nil
}

type TimestampOptions struct {
	TSAURL string
	// "sha512" for a renewal that must outlive SHA-256 (SPEC 4.6); "" means sha256
	Hash       string
	TS         string
	Reason     string
	HTTPClient *http.Client
	TSA        TSAVerifyOptions
}

// TimestampDocument appends a tsa block: a timestamp over everything before it, earlier tokens included (SPEC 4.6).
func TimestampDocument(ctx context.Context, text string, o TimestampOptions) (*SignResult, error) {
	if !utf8.ValidString(text) {
		return nil, errNotUTF8
	}
	doc := ParseDocument(text)
	if len(doc.Chain) == 0 {
		if doc.StrayMarker {
			return nil, &SignError{Msg: fmt.Sprintf("line %d: a signature block is followed by unsigned content", doc.StrayMarkerLine)}
		}
		return nil, &SignError{Msg: "the document has no signature to timestamp"}
	}
	for _, b := range doc.Chain {
		if len(b.Errors) > 0 {
			return nil, &SignError{Msg: fmt.Sprintf("existing signature #%d is malformed: %s", b.Index, strings.Join(b.Errors, "; "))}
		}
	}
	tsaURL := o.TSAURL
	if tsaURL == "" {
		tsaURL = DefaultTSAURL
	}
	if !tsaURLRe.MatchString(tsaURL) || strings.Contains(tsaURL, "*") {
		return nil, &ValueError{Msg: fmt.Sprintf("TSA URL must be http(s)://, got %q", tsaURL)}
	}
	hashAlg := o.Hash
	if hashAlg == "" {
		hashAlg = "sha256"
	}
	if hashAlg != "sha256" && hashAlg != "sha512" {
		return nil, &ValueError{Msg: fmt.Sprintf("hash must be sha256 or sha512, got %q", hashAlg)}
	}
	ts := o.TS
	if ts == "" {
		ts = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	}
	if !tsRe.MatchString(ts) {
		return nil, &ValueError{Msg: fmt.Sprintf("ts must be YYYY-MM-DDTHH:MM:SSZ, got %q", ts)}
	}
	fields := map[string]string{"v": SpecVersion, "method": "tsa", "signer": tsaURL, "ts": ts, "alg": "rfc3161"}
	if o.Reason != "" {
		fields["reason"] = o.Reason
	}
	fields["hash"] = hashAlg + ":" + toHex(digestBytes(hashAlg, []byte(normalizeDocument(text))))
	for k, v := range fields {
		if e := ValidateValue(v); e != "" {
			return nil, &ValueError{Msg: k + ": " + e}
		}
	}
	tok, err := requestTimestampOver(ctx, digestBytes(hashAlg, SignedPayload(fields)), hashAlg, tsaURL, o.HTTPClient, &o.TSA)
	if err != nil {
		return nil, fmt.Errorf("timestamp request to %s failed: %w", tsaURL, err)
	}
	fields["sig"] = tok
	return appendBlock(text, len(doc.Chain), fields)
}
