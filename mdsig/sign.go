package mdsig

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

type SignOptions struct {
	Signer        Signer
	WebAuthn      WebAuthnSigner
	PGP           PGPSigner
	Method        string
	SignerID      string
	Selector      string
	KeyFP         string
	OmitKeyFP     bool
	Role          string
	Reason        string
	TS            string
	Expires       string
	Scope         []string
	Require       []string
	Resources     []ResourceItem
	RevocationURL string
	Extra         map[string]string
	TSAURL        string
	TSA           TSAVerifyOptions
	// dns and git-hosting: also write the public key (SPEC 4.5), so the signature stays checkable after the key is gone
	EmbedKey   bool
	HTTPClient *http.Client
	Force      bool
	Now        func() time.Time
}

type SignResult struct {
	Text     string
	Block    string
	Fields   map[string]string
	Previous int
}

type SignError struct{ Msg string }

func (e *SignError) Error() string { return e.Msg }

type ValueError struct{ Msg string }

func (e *ValueError) Error() string { return e.Msg }

// SPEC 5.1: generators refuse documents that are not valid UTF-8
var errNotUTF8 = &SignError{Msg: "the document is not valid UTF-8"}

func SignDocument(ctx context.Context, text string, o SignOptions) (*SignResult, error) {
	if !utf8.ValidString(text) {
		return nil, errNotUTF8
	}
	doc := ParseDocument(text)
	if len(doc.Chain) == 0 && doc.StrayMarker && !o.Force {
		return nil, &SignError{Msg: fmt.Sprintf("line %d: found an md-signature block that is followed by unsigned content. "+
			"Co-signing would endorse text the earlier signer never signed. Use force to sign the whole file as a new document.", doc.StrayMarkerLine)}
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

	isPgp := o.PGP != nil
	isWebAuthn := !isPgp && o.WebAuthn != nil
	if isPgp != (o.Method == "pgp") {
		if isPgp {
			return nil, &ValueError{Msg: "an OpenPGP key can only sign with method pgp"}
		}
		return nil, &ValueError{Msg: "method pgp needs an OpenPGP key"}
	}
	alg := "ed25519"
	var pub []byte
	if isPgp {
		alg = "openpgp"
	} else if isWebAuthn {
		alg = "webauthn-es256"
		pub = o.WebAuthn.PublicKeySPKI()
	} else {
		if o.Signer == nil {
			return nil, errors.New("no signer")
		}
		pub = o.Signer.PublicKey()
	}
	fields := map[string]string{"v": SpecVersion, "method": o.Method, "signer": o.SignerID}
	switch o.Method {
	case "dns":
		fields["signer"] = strings.TrimSuffix(strings.ToLower(o.SignerID), ".")
		if o.Selector != "" {
			fields["selector"] = o.Selector
		}
	case "git-hosting":
		if isWebAuthn {
			return nil, &ValueError{Msg: "git-hosting supports only Ed25519 SSH keys; use tofu or dns for passkeys"}
		}
		if !isValidGitHostingSigner(o.SignerID) {
			return nil, &ValueError{Msg: fmt.Sprintf("git-hosting signer must be <host>/<username> with a domain name as host, got %q", o.SignerID)}
		}
		if !o.OmitKeyFP {
			if o.KeyFP != "" {
				fields["key_fp"] = o.KeyFP
			} else {
				fields["key_fp"] = SSHFingerprint(pub)
			}
		}
	}
	if o.EmbedKey && o.Method != "dns" && o.Method != "git-hosting" {
		return nil, &ValueError{Msg: "EmbedKey works with dns and git-hosting, not " + o.Method}
	}
	if o.Method == "tofu" || o.EmbedKey {
		kt := "ed25519"
		if isWebAuthn {
			kt = "es256"
		}
		fields["pubkey"] = kt + ":" + toBase64(pub)
	}
	if isPgp {
		email := strings.ToLower(o.SignerID)
		if !emailRe.MatchString(email) {
			return nil, &ValueError{Msg: fmt.Sprintf("pgp signer must be an email address, got %q", o.SignerID)}
		}
		if emails := o.PGP.Emails(); len(emails) > 0 && !slices.Contains(emails, email) {
			return nil, &ValueError{Msg: fmt.Sprintf("the OpenPGP key has no user ID with <%s> (has: %s)", email, strings.Join(emails, ", "))}
		}
		fields["signer"] = email
		fields["fpr"] = o.PGP.Fpr()
	}
	if isWebAuthn {
		fields["rp_id"] = o.WebAuthn.RPID()
	}
	for k, v := range o.Extra {
		fields[k] = v
	}
	if o.Role != "" {
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
		if _, errs := ParseRequire(fields["require"], 0, SpecVersion); len(errs) > 0 {
			return nil, &ValueError{Msg: strings.Join(errs, "; ")}
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
		if e := validateValue(fields[k], k == "require" || k == "resources"); e != "" {
			return nil, &ValueError{Msg: k + ": " + e}
		}
	}

	if o.TSAURL != "" {
		if e := ValidateValue(o.TSAURL); e != "" {
			return nil, &ValueError{Msg: "tsa_url: " + e}
		}
	}

	payload := SignedPayload(fields)
	var sig []byte
	if isWebAuthn {
		challenge := sha256.Sum256(payload)
		a, err := o.WebAuthn.GetAssertion(challenge[:])
		if err != nil {
			return nil, err
		}
		sig = a.Signature
		fields["webauthn_authenticator_data"] = toBase64(a.AuthenticatorData)
		fields["webauthn_client_data"] = toBase64(a.ClientDataJSON)
	} else if isPgp {
		var err error
		if sig, err = o.PGP.Sign(payload); err != nil {
			return nil, err
		}
	} else {
		var err error
		sig, err = o.Signer.Sign(payload)
		if err != nil {
			return nil, err
		}
	}
	fields["sig"] = "base64:" + toBase64(sig)
	if o.TSAURL != "" {
		tok, err := RequestTimestamp(ctx, sig, o.TSAURL, o.HTTPClient, &o.TSA)
		if err != nil {
			return nil, fmt.Errorf("timestamp request to %s failed: %w", o.TSAURL, err)
		}
		fields["tsa_url"] = o.TSAURL
		fields["tsa_token"] = tok
	}

	return appendBlock(text, len(doc.Chain), fields)
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

var tsaURLRe = regexp.MustCompile(`^https?://\S+$`)

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
	if !tsaURLRe.MatchString(tsaURL) {
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
