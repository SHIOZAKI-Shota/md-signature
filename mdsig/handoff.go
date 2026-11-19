package mdsig

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

// --- CLI_SPEC 8: passkey signatures through a signing page

const HandoffVersion = "1"

var handoffMethods = map[string]bool{"tofu": true, "dns": true, "directory": true}

type HandoffError struct {
	Code string // cancelled, invalid-request, unsupported, or bad-response
	Msg  string
}

func (e *HandoffError) Error() string { return e.Msg }

func IsSigningPageURL(u string) bool {
	p, err := url.Parse(u)
	return err == nil && p.Scheme == "https" && p.Hostname() != "" && p.User == nil
}

var handoffSchemeRe = regexp.MustCompile(`^[a-z][a-z0-9+.-]*$`)

// CLI_SPEC 8.4: a non-http(s) scheme or a loopback address, so a web site cannot collect signatures through the page
func IsHandoffReturnURL(u string) bool {
	p, err := url.Parse(u)
	if err != nil {
		return false
	}
	if p.Scheme != "http" && p.Scheme != "https" {
		return handoffSchemeRe.MatchString(p.Scheme)
	}
	host := p.Hostname()
	return p.Scheme == "http" && (host == "127.0.0.1" || host == "::1") && p.Port() != "" && p.User == nil
}

// CLI_SPEC 8.5: the RP ID is the page's host or a parent domain of it
func RPIDFitsPage(page, rpID string) bool {
	p, err := url.Parse(page)
	if err != nil || rpID == "" {
		return false
	}
	host, rp := strings.ToLower(p.Hostname()), strings.ToLower(rpID)
	return host == rp || strings.HasSuffix(host, "."+rp)
}

type HandoffRequest struct {
	URL   string
	State string
}

type HandoffRequestOptions struct {
	Op         string // key or sign
	ReturnURL  string
	Payload    []byte
	Credential string
	Name       string
	State      string
}

func CreateHandoffRequest(page string, o HandoffRequestOptions) (*HandoffRequest, error) {
	if !IsSigningPageURL(page) {
		return nil, &HandoffError{"invalid-request", "the signing page must be an https:// URL"}
	}
	if !IsHandoffReturnURL(o.ReturnURL) {
		return nil, &HandoffError{"invalid-request", "the return URL must use its own scheme or a loopback address"}
	}
	if o.Op != "key" && o.Op != "sign" {
		return nil, &HandoffError{"invalid-request", "op must be key or sign"}
	}
	if o.Op == "sign" && len(o.Payload) == 0 {
		return nil, &HandoffError{"invalid-request", "op=sign needs a payload"}
	}
	state := o.State
	if state == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		state = toBase64URL(b)
	}
	u, _ := url.Parse(page)
	q := u.Query()
	q.Set("v", HandoffVersion)
	q.Set("op", o.Op)
	q.Set("return", o.ReturnURL)
	q.Set("state", state)
	if o.Op == "sign" {
		q.Set("payload", toBase64URL(o.Payload))
	}
	if o.Credential != "" {
		q.Set("credential", o.Credential)
	}
	if o.Name != "" {
		q.Set("name", o.Name)
	}
	u.RawQuery = q.Encode()
	return &HandoffRequest{URL: u.String(), State: state}, nil
}

type HandoffResponse struct {
	State      string
	Error      string // cancelled, invalid-request, or unsupported; empty on success
	RPID       string // op=key
	Key        []byte
	Credential string
	Assertion  *WebAuthnAssertion // op=sign
}

var b64uRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func b64u(v string) []byte {
	if !b64uRe.MatchString(v) {
		return nil
	}
	b, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return nil
	}
	return b
}

// nil when the URL is not a version 1 answer; the caller matches State against its pending requests (CLI_SPEC 8.5)
func ParseHandoffResponse(answer, op string) *HandoffResponse {
	u, err := url.Parse(answer)
	if err != nil {
		return nil
	}
	q := u.Query()
	state := q.Get("state")
	if q.Get("v") != HandoffVersion || state == "" {
		return nil
	}
	if q.Has("error") {
		e := q.Get("error")
		if e != "cancelled" && e != "unsupported" {
			e = "invalid-request"
		}
		return &HandoffResponse{State: state, Error: e}
	}
	if op == "key" {
		key, cred := b64u(q.Get("key")), q.Get("credential")
		if q.Get("rp_id") == "" || key == nil || b64u(cred) == nil {
			return nil
		}
		return &HandoffResponse{State: state, RPID: q.Get("rp_id"), Key: key, Credential: cred}
	}
	ad, cd, sig := b64u(q.Get("authenticator_data")), b64u(q.Get("client_data")), b64u(q.Get("sig"))
	if ad == nil || cd == nil || sig == nil {
		return nil
	}
	return &HandoffResponse{State: state, Assertion: &WebAuthnAssertion{Signature: sig, AuthenticatorData: ad, ClientDataJSON: cd}}
}

// HandoffTransport opens the request in the user's browser and returns the answer URL for that state
type HandoffTransport func(ctx context.Context, req *HandoffRequest) (string, error)

func handoffExchange(ctx context.Context, page string, t HandoffTransport, o HandoffRequestOptions) (*HandoffResponse, error) {
	req, err := CreateHandoffRequest(page, o)
	if err != nil {
		return nil, err
	}
	answer, err := t(ctx, req)
	if err != nil {
		return nil, err
	}
	res := ParseHandoffResponse(answer, o.Op)
	// security: an answer is accepted only for the state of this request (CLI_SPEC 8.5)
	if res == nil || res.State != req.State {
		return nil, &HandoffError{"bad-response", "the signing page did not answer this request"}
	}
	if res.Error != "" {
		return nil, &HandoffError{res.Error, "the signing page answered " + res.Error}
	}
	return res, nil
}

type HandoffPasskey struct {
	Page       string
	RPID       string
	Key        []byte
	Credential string
}

func ConnectPasskeyViaPage(ctx context.Context, page, returnURL string, t HandoffTransport) (*HandoffPasskey, error) {
	res, err := handoffExchange(ctx, page, t, HandoffRequestOptions{Op: "key", ReturnURL: returnURL})
	if err != nil {
		return nil, err
	}
	if !RPIDFitsPage(page, res.RPID) {
		return nil, &HandoffError{"bad-response", fmt.Sprintf("the passkey's RP ID %s does not belong to the signing page", res.RPID)}
	}
	return &HandoffPasskey{Page: page, RPID: res.RPID, Key: res.Key, Credential: res.Credential}, nil
}

// SignViaPage signs text with a passkey through its signing page; o.Signer, o.WebAuthn, and o.PGP are ignored
func SignViaPage(ctx context.Context, text string, pk *HandoffPasskey, returnURL, name string, t HandoffTransport, o SignOptions) (*SignResult, error) {
	if !handoffMethods[o.Method] {
		return nil, &HandoffError{"invalid-request", "passkeys sign with method tofu, dns, or directory, not " + o.Method}
	}
	p, err := PrepareSignature(text, SigningKey{Alg: "webauthn-es256", PublicKey: pk.Key, RPID: pk.RPID}, o)
	if err != nil {
		return nil, err
	}
	res, err := handoffExchange(ctx, pk.Page, t, HandoffRequestOptions{Op: "sign", ReturnURL: returnURL, Payload: p.Payload, Credential: pk.Credential, Name: name})
	if err != nil {
		return nil, err
	}
	if res.Assertion == nil {
		return nil, &HandoffError{"bad-response", "the signing page answered with the wrong operation"}
	}
	return p.Finish(ctx, nil, res.Assertion)
}

// --- signing page side (CLI_SPEC 8.3)

func ParseSignedPayload(payload []byte) map[string]string {
	if !utf8.Valid(payload) {
		return nil
	}
	lines := strings.Split(string(payload), "\n")
	if lines[0] != payloadDomain {
		return nil
	}
	fields := map[string]string{}
	last := ""
	for _, line := range lines[1:] {
		if strings.HasPrefix(line, "  ") && last != "" {
			fields[last] += "\n" + line[2:]
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || k == "" {
			return nil
		}
		if _, dup := fields[k]; dup {
			return nil
		}
		fields[k], last = v, k
	}
	// only the canonical encoding is accepted, so what is shown is exactly what is signed
	if !bytes.Equal(SignedPayload(fields), payload) {
		return nil
	}
	return fields
}

type PageRequest struct {
	OK         bool
	Error      string // invalid-request or unsupported
	Message    string
	Op         string
	ReturnURL  string // empty when the return URL itself is refused: the page must not redirect
	State      string
	Payload    []byte
	Fields     map[string]string
	Credential string
	Name       string
}

var stateRe = regexp.MustCompile(`^[A-Za-z0-9_-]{22,}$`)

func CheckHandoffRequest(request, rpID string) *PageRequest {
	u, err := url.Parse(request)
	if err != nil {
		return &PageRequest{Error: "invalid-request", Message: "not a URL"}
	}
	q := u.Query()
	ret, state := q.Get("return"), q.Get("state")
	// security: a request with another return URL is refused without redirecting (CLI_SPEC 8.4)
	if !IsHandoffReturnURL(ret) {
		return &PageRequest{Error: "invalid-request", Message: "the return URL must use its own scheme or a loopback address"}
	}
	fail := func(code, msg string) *PageRequest {
		return &PageRequest{Error: code, Message: msg, ReturnURL: ret, State: state}
	}
	if !stateRe.MatchString(state) {
		return fail("invalid-request", "state must be at least 128 bits of base64url")
	}
	if q.Get("v") != HandoffVersion {
		return fail("unsupported", "unsupported version "+q.Get("v"))
	}
	op := q.Get("op")
	if op == "key" {
		return &PageRequest{OK: true, Op: op, ReturnURL: ret, State: state}
	}
	if op != "sign" {
		return fail("invalid-request", "unknown op "+op)
	}
	payload := b64u(q.Get("payload"))
	fields := ParseSignedPayload(payload)
	if payload == nil || fields == nil {
		return fail("invalid-request", "the payload is not an md-signature payload")
	}
	if fields["alg"] != "webauthn-es256" {
		return fail("unsupported", "alg "+fields["alg"]+" is not webauthn-es256")
	}
	if !handoffMethods[fields["method"]] {
		return fail("unsupported", "method "+fields["method"]+" cannot be signed with a passkey")
	}
	if fields["rp_id"] != rpID {
		return fail("invalid-request", fmt.Sprintf("rp_id %s is not %s", fields["rp_id"], rpID))
	}
	return &PageRequest{OK: true, Op: op, ReturnURL: ret, State: state, Payload: payload, Fields: fields, Credential: q.Get("credential"), Name: q.Get("name")}
}

// CLI_SPEC 8.3 check 3: a payload that names a key must name the passkey in use
func PayloadMatchesKey(fields map[string]string, publicKey []byte) bool {
	pk, ok := fields["pubkey"]
	return !ok || pk == "es256:"+toBase64(publicKey)
}

type HandoffAnswer struct {
	Error      string
	RPID       string
	Key        []byte
	Credential string
	Assertion  *WebAuthnAssertion
}

func HandoffResponseURL(returnURL, state string, a HandoffAnswer) (string, error) {
	if !IsHandoffReturnURL(returnURL) {
		return "", &HandoffError{"invalid-request", "the return URL must use its own scheme or a loopback address"}
	}
	u, _ := url.Parse(returnURL)
	q := u.Query()
	q.Set("v", HandoffVersion)
	q.Set("state", state)
	switch {
	case a.Error != "":
		q.Set("error", a.Error)
	case a.Assertion != nil:
		q.Set("authenticator_data", toBase64URL(a.Assertion.AuthenticatorData))
		q.Set("client_data", toBase64URL(a.Assertion.ClientDataJSON))
		q.Set("sig", toBase64URL(a.Assertion.Signature))
	default:
		q.Set("rp_id", a.RPID)
		q.Set("key", toBase64URL(a.Key))
		q.Set("credential", a.Credential)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
