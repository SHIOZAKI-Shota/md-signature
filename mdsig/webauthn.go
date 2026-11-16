package mdsig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"unicode/utf8"
)

func toBase64URL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// strict DER: no long-form lengths, no non-minimal or negative INTEGERs, at most 33 bytes each
func derToP1363(der []byte) ([]byte, error) {
	fail := func(m string) ([]byte, error) { return nil, errors.New("malformed DER signature: " + m) }
	if len(der) < 8 || der[0] != 0x30 {
		return fail("not a SEQUENCE")
	}
	if der[1]&0x80 != 0 {
		return fail("long-form length not expected")
	}
	if int(der[1]) != len(der)-2 {
		return fail("length mismatch")
	}
	o := 2
	out := make([]byte, 64)
	for k := 0; k < 2; k++ {
		if o >= len(der) || der[o] != 0x02 {
			return fail("INTEGER expected")
		}
		// JS reads undefined past the end, which fails the range check
		if o+1 >= len(der) {
			return fail("integer length out of range")
		}
		n := int(der[o+1])
		if n < 1 || n > 33 {
			return fail("integer length out of range")
		}
		if o+2+n > len(der) {
			return fail("truncated")
		}
		v := der[o+2 : o+2+n]
		if v[0]&0x80 != 0 {
			return fail("negative integer")
		}
		if n > 1 && v[0] == 0 && v[1]&0x80 == 0 {
			return fail("non-minimal integer")
		}
		if v[0] == 0 {
			v = v[1:]
		}
		if len(v) > 32 {
			return fail("integer longer than 32 bytes")
		}
		copy(out[k*32+(32-len(v)):], v)
		o += 2 + n
	}
	if o != len(der) {
		return fail("trailing bytes")
	}
	return out, nil
}

func p1363ToDER(sig []byte) ([]byte, error) {
	if len(sig) != 64 {
		return nil, errors.New("P-256 signature must be 64 bytes")
	}
	integer := func(b []byte) []byte {
		i := 0
		for i < len(b)-1 && b[i] == 0 {
			i++
		}
		v := b[i:]
		if v[0]&0x80 != 0 {
			v = append([]byte{0}, v...)
		}
		return append([]byte{0x02, byte(len(v))}, v...)
	}
	body := append(integer(sig[:32]), integer(sig[32:])...)
	return append([]byte{0x30, byte(len(body))}, body...), nil
}

var spkiP256Prefix = []byte{0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00}

func es256SPKI(b []byte) ([]byte, error) {
	if len(b) == 91 && bytes.Equal(b[:26], spkiP256Prefix) {
		return b, nil
	}
	if len(b) == 65 && b[0] == 0x04 {
		return append(append([]byte{}, spkiP256Prefix...), b...), nil
	}
	return nil, fmt.Errorf("not a P-256 public key (length %d)", len(b))
}

func parseES256(key []byte) (*ecdsa.PublicKey, error) {
	spki, err := es256SPKI(key)
	if err != nil {
		return nil, err
	}
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, err
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA key")
	}
	return ec, nil
}

type WebAuthnInfo struct {
	RPID         string
	Origin       string
	UserVerified bool
}

type webAuthnCheck struct {
	ok         bool
	code, msg  string
	info       *WebAuthnInfo
	authData   []byte
	clientData []byte
}

// approximates WHATWG URL parsing for the origin check
func jsHostname(origin string) (host, scheme string, ok bool) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Opaque != "" {
		return "", "", false
	}
	scheme = strings.ToLower(u.Scheme) + ":"
	if (scheme == "http:" || scheme == "https:") && u.Host == "" {
		return "", "", false
	}
	return strings.ToLower(u.Hostname()), scheme, true
}

func checkWebAuthnData(fields map[string]string, payload []byte) webAuthnCheck {
	rpID := fields["rp_id"]
	authData, err1 := fromBase64(fields["webauthn_authenticator_data"])
	clientData, err2 := fromBase64(fields["webauthn_client_data"])
	if err1 != nil || err2 != nil {
		return webAuthnCheck{code: "malformed", msg: "webauthn fields are not valid base64"}
	}
	// TextDecoder strips one leading BOM before JSON.parse
	cdText := bytes.TrimPrefix(clientData, []byte(bom))
	var parsed any
	if !utf8.Valid(cdText) || json.Unmarshal(cdText, &parsed) != nil {
		return webAuthnCheck{code: "malformed", msg: "clientDataJSON is not valid JSON"}
	}
	cd, isObject := parsed.(map[string]any)
	if !isObject {
		return webAuthnCheck{code: "malformed", msg: "clientDataJSON is not a JSON object"}
	}
	origin, _ := cd["origin"].(string)
	info := &WebAuthnInfo{RPID: rpID, Origin: origin, UserVerified: len(authData) > 32 && authData[32]&0x04 != 0}
	bad := func(code, msg string) webAuthnCheck { return webAuthnCheck{code: code, msg: msg, info: info} }
	if t, _ := cd["type"].(string); t != "webauthn.get" {
		return bad("bad-signature", fmt.Sprintf("clientDataJSON type is %s, expected \"webauthn.get\"", jsJSON(cd["type"])))
	}
	sum := sha256.Sum256(payload)
	if ch, ok := cd["challenge"].(string); !ok || ch != toBase64URL(sum[:]) {
		return bad("bad-signature", "challenge does not match the signed payload")
	}
	host, scheme, ok := jsHostname(origin)
	if !ok {
		return bad("bad-signature", fmt.Sprintf("invalid origin %s", jsonString(origin)))
	}
	if host != rpID && !strings.HasSuffix(host, "."+rpID) {
		return bad("bad-signature", fmt.Sprintf("origin %s does not belong to rp_id %s", origin, rpID))
	}
	if scheme != "https:" && host != "localhost" {
		return bad("bad-signature", fmt.Sprintf("origin %s is not https", origin))
	}
	if len(authData) < 37 {
		return bad("malformed", "authenticatorData is too short")
	}
	rpHash := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(authData[:32], rpHash[:]) {
		return bad("bad-signature", "authenticatorData rpIdHash does not match rp_id")
	}
	if authData[32]&0x01 == 0 {
		return bad("bad-signature", "User Present flag is not set")
	}
	return webAuthnCheck{ok: true, info: info, authData: authData, clientData: clientData}
}

func jsJSON(v any) string {
	if v == nil {
		return "undefined"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "undefined"
	}
	return string(b)
}

func verifyWebAuthnSignature(key, derSig, authData, clientData []byte) (bool, error) {
	rs, err := derToP1363(derSig)
	if err != nil {
		return false, err
	}
	pub, err := parseES256(key)
	if err != nil {
		return false, err
	}
	cdHash := sha256.Sum256(clientData)
	signed := append(append([]byte{}, authData...), cdHash[:]...)
	digest := sha256.Sum256(signed)
	r := new(big.Int).SetBytes(rs[:32])
	s := new(big.Int).SetBytes(rs[32:])
	return ecdsa.Verify(pub, digest[:], r, s), nil
}

type WebAuthnAssertion struct {
	Signature         []byte
	AuthenticatorData []byte
	ClientDataJSON    []byte
}

type WebAuthnSigner interface {
	PublicKeySPKI() []byte
	RPID() string
	GetAssertion(challenge []byte) (*WebAuthnAssertion, error)
}
