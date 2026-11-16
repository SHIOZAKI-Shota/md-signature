package mdsig

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
)

type SignOptions struct {
	Signer        Signer
	WebAuthn      WebAuthnSigner
	Pgp           PgpSigner
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
	HTTPClient    *http.Client
	Force         bool
	Now           func() time.Time
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

func SignDocument(ctx context.Context, text string, o SignOptions) (*SignResult, error) {
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
	if !TSRe.MatchString(ts) {
		return nil, &ValueError{Msg: fmt.Sprintf("ts must be YYYY-MM-DDTHH:MM:SSZ, got %q", ts)}
	}
	if o.Expires != "" && !IsValidTimestamp(o.Expires) {
		return nil, &ValueError{Msg: fmt.Sprintf("expires must be YYYY-MM-DDTHH:MM:SSZ, got %q", o.Expires)}
	}
	if o.RevocationURL != "" && !IsValidRevocationURL(o.RevocationURL) {
		return nil, &ValueError{Msg: "revocation URL must be https://"}
	}
	for k := range o.Extra {
		if !IsExtensionKey(k) {
			return nil, &ValueError{Msg: fmt.Sprintf("extra field %q must start with \"x_\"", k)}
		}
	}

	isPgp := o.Pgp != nil
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
			return nil, &ValueError{Msg: "git-hosting supports only ed25519 SSH keys; use tofu or dns for passkeys"}
		}
		if !IsValidGitHostingSigner(o.SignerID) {
			return nil, &ValueError{Msg: fmt.Sprintf("git-hosting signer must be <host>/<username> with a domain name as host, got %q", o.SignerID)}
		}
		if !o.OmitKeyFP {
			if o.KeyFP != "" {
				fields["key_fp"] = o.KeyFP
			} else {
				fields["key_fp"] = SSHFingerprint(pub)
			}
		}
	case "tofu":
		kt := "ed25519"
		if isWebAuthn {
			kt = "es256"
		}
		fields["pubkey"] = kt + ":" + ToBase64(pub)
	}
	if isPgp {
		email := strings.ToLower(o.SignerID)
		if !EmailRe.MatchString(email) {
			return nil, &ValueError{Msg: fmt.Sprintf("pgp signer must be an email address, got %q", o.SignerID)}
		}
		if emails := o.Pgp.Emails(); len(emails) > 0 && !slices.Contains(emails, email) {
			return nil, &ValueError{Msg: fmt.Sprintf("the OpenPGP key has no user ID with <%s> (has: %s)", email, strings.Join(emails, ", "))}
		}
		fields["signer"] = email
		fields["fpr"] = o.Pgp.Fpr()
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
		if _, errs := ParseRequire(fields["require"], 0); len(errs) > 0 {
			return nil, &ValueError{Msg: strings.Join(errs, "; ")}
		}
	}
	if len(o.Resources) > 0 {
		v, err := FormatResources(o.Resources)
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
		in, _, se := ScopedHashInput(NormalizeNewlines(text), sc)
		if se != nil {
			return nil, &ValueError{Msg: se.Msg}
		}
		sum := sha256.Sum256([]byte(in))
		fields["hash"] = "sha256:" + ToHex(sum[:])
	} else {
		fields["hash"] = NormalizedHash(text)
	}

	for _, k := range orderedKeys(fields) {
		if e := ValidateKey(k); e != "" {
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
		fields["webauthn_authenticator_data"] = ToBase64(a.AuthenticatorData)
		fields["webauthn_client_data"] = ToBase64(a.ClientDataJSON)
	} else if isPgp {
		var err error
		if sig, err = o.Pgp.Sign(payload); err != nil {
			return nil, err
		}
	} else {
		var err error
		sig, err = o.Signer.Sign(payload)
		if err != nil {
			return nil, err
		}
	}
	fields["sig"] = "base64:" + ToBase64(sig)
	if o.TSAURL != "" {
		tok, err := RequestTimestampWith(ctx, sig, o.TSAURL, o.HTTPClient, &o.TSA)
		if err != nil {
			return nil, fmt.Errorf("timestamp request to %s failed: %w", o.TSAURL, err)
		}
		fields["tsa_url"] = o.TSAURL
		fields["tsa_token"] = tok
	}

	block, err := SerializeBlock(fields)
	if err != nil {
		return nil, &ValueError{Msg: err.Error()}
	}
	eol := "\n"
	if strings.Contains(text, "\r\n") {
		eol = "\r\n"
	}
	trimmed := strings.TrimRight(text, "\r\n \t")
	sep := eol + eol
	if len(doc.Chain) > 0 {
		sep = eol
	}
	out := trimmed + sep + strings.ReplaceAll(block, "\n", eol) + eol
	return &SignResult{Text: out, Block: block, Fields: fields, Previous: len(doc.Chain)}, nil
}
