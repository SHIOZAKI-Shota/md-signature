package mdsig

import (
	"context"
	"crypto/sha1"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

const DefaultKeyserver = "https://keys.openpgp.org"

const maxPgpKeyBytes = 1024 * 1024

var (
	FprRe   = regexp.MustCompile(`^(?:[0-9A-F]{40}|[0-9A-F]{64})$`)
	EmailRe = regexp.MustCompile("^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\\.[a-z0-9-]+)+$")
)

// --- WKD (draft-koch-openpgp-webkey-service)

const zb32 = "ybndrfg8ejkmcpqxot1uwisza345h769"

func zbase32(b []byte) string {
	var out strings.Builder
	buf, n := 0, 0
	for _, x := range b {
		buf = (buf<<8 | int(x)) & 0xffff
		n += 8
		for n >= 5 {
			out.WriteByte(zb32[(buf>>(n-5))&31])
			n -= 5
		}
	}
	if n > 0 {
		out.WriteByte(zb32[(buf<<(5-n))&31])
	}
	return out.String()
}

// encodeURIComponent of the TS core
func jsEncodeURIComponent(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte("-_.!~*'()", c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// WKD mandates SHA-1 of the lower-cased local part; this is addressing, not a signature hash
func WKDURLs(email string) (advanced, direct string) {
	at := strings.LastIndexByte(email, '@')
	local, domain := email, ""
	if at >= 0 {
		local, domain = email[:at], strings.ToLower(email[at+1:])
	}
	sum := sha1.Sum([]byte(strings.ToLower(local)))
	h := zbase32(sum[:])
	l := jsEncodeURIComponent(local)
	return "https://openpgpkey." + domain + "/.well-known/openpgpkey/" + domain + "/hu/" + h + "?l=" + l,
		"https://" + domain + "/.well-known/openpgpkey/hu/" + h + "?l=" + l
}

func HKPURL(keyserver, fpr string) string {
	return strings.TrimRight(keyserver, "/") + "/pks/lookup?op=get&options=mr&search=0x" + fpr
}

// --- lookup (SPEC 4.3)

type PgpAttempt struct {
	Source string // keyring, wkd, keyserver
	URL    string
	Result string // found, absent, error
	Detail string
}

type pgpLookupResult struct {
	cert     []byte
	source   string
	url      string
	attempts []PgpAttempt
}

func containsKey(b []byte, fpr string) bool {
	certs, err := parseCerts(b)
	if err != nil {
		return false
	}
	for _, c := range certs {
		if c.primary.fprHex() == fpr || slices.ContainsFunc(c.subkeys, func(s *pgpSubkey) bool { return s.key.fprHex() == fpr }) {
			return true
		}
	}
	return false
}

func lookupPgpKey(ctx context.Context, fpr, email, keyserver string, o *ResolveOptions) pgpLookupResult {
	var attempts []PgpAttempt
	if o.PgpKeyring != nil {
		b, err := o.PgpKeyring(ctx, fpr)
		switch {
		case err != nil:
			attempts = append(attempts, PgpAttempt{Source: "keyring", Result: "error", Detail: err.Error()})
		case b != nil && containsKey(b, fpr):
			return pgpLookupResult{cert: b, source: "keyring", attempts: append(attempts, PgpAttempt{Source: "keyring", Result: "found"})}
		default:
			attempts = append(attempts, PgpAttempt{Source: "keyring", Result: "absent"})
		}
	}
	if o.Offline {
		return pgpLookupResult{attempts: append(attempts, PgpAttempt{Source: "wkd", Result: "error", Detail: "offline"})}
	}
	client := o.PgpClient
	if client == nil {
		client = SafeHTTPClient(30 * time.Second)
	}
	try := func(source, u string) (PgpAttempt, []byte) {
		b, err := FetchResource(ctx, client, u, maxPgpKeyBytes)
		if err != nil {
			var hs *HTTPStatusError
			if errors.As(err, &hs) && hs.Status == 404 {
				return PgpAttempt{Source: source, URL: u, Result: "absent", Detail: "404"}, nil
			}
			return PgpAttempt{Source: source, URL: u, Result: "error", Detail: err.Error()}, nil
		}
		if containsKey(b, fpr) {
			return PgpAttempt{Source: source, URL: u, Result: "found"}, b
		}
		return PgpAttempt{Source: source, URL: u, Result: "absent", Detail: "response has no key with this fingerprint"}, nil
	}

	advanced, direct := WKDURLs(email)
	a, b := try("wkd", advanced)
	// WKD: the direct method is used when the advanced host does not answer
	if a.Result == "error" {
		d, db := try("wkd", direct)
		if d.Result == "error" {
			d.Detail = "advanced: " + a.Detail + "; direct: " + d.Detail
		}
		a, b = d, db
	}
	attempts = append(attempts, a)
	if b != nil {
		return pgpLookupResult{cert: b, source: "wkd", url: a.URL, attempts: attempts}
	}
	if keyserver == "" {
		keyserver = DefaultKeyserver
	}
	ks, kb := try("keyserver", HKPURL(keyserver, fpr))
	attempts = append(attempts, ks)
	if kb != nil {
		return pgpLookupResult{cert: kb, source: "keyserver", url: ks.URL, attempts: attempts}
	}
	return pgpLookupResult{attempts: attempts}
}

func DescribeAttempts(attempts []PgpAttempt) string {
	parts := make([]string, len(attempts))
	for i, a := range attempts {
		label := "keyserver"
		switch {
		case a.Source == "keyring":
			label = "keyring"
		case a.Source == "wkd":
			label = "WKD"
		case a.URL != "":
			if u, err := url.Parse(a.URL); err == nil {
				// WHATWG URL host: lower-cased, default port dropped
				label = strings.TrimSuffix(strings.ToLower(u.Host), ":443")
			}
		}
		result := "unreachable"
		switch {
		case a.Result == "found":
			result = "found"
		case a.Result == "absent":
			result = "no key"
		case a.Detail == "offline":
			result = "skipped (offline)"
		}
		parts[i] = label + ": " + result
	}
	return strings.Join(parts, "; ")
}

// --- document signature (SPEC 6.2)

type PgpInfo struct {
	Fpr       string
	UID       string
	KeyAlg    string
	KeySource string
	Created   string
}

type PgpPacketCheck struct {
	OK      bool
	Status  string
	Code    string
	Message string
	Created string
}

func CheckPgpSignaturePacket(sigBytes []byte, fpr string) PgpPacketCheck {
	bad := func(format string, a ...any) PgpPacketCheck {
		return PgpPacketCheck{Status: StatusInvalid, Code: "bad-signature", Message: fmt.Sprintf(format, a...)}
	}
	sig, err := readSignaturePacket(sigBytes)
	if err != nil {
		return bad("%s", err.Error())
	}
	if sig.typ != sigBinary {
		return bad("OpenPGP signature type 0x%02x is not 0x00 (binary document)", sig.typ)
	}
	if !pgpDocumentHashes[sig.hashAlgo] {
		return bad("OpenPGP signature hash algorithm %d is not SHA-256, SHA-384 or SHA-512", sig.hashAlgo)
	}
	created, ok := sig.created()
	if !ok {
		return bad("OpenPGP signature has no hashed creation time")
	}
	var issuer []byte
	hasIssuer := false
	for _, s := range sig.hashed {
		if s.typ == subIssuerFp {
			issuer, hasIssuer = s.data, true
			break
		}
	}
	if !hasIssuer || len(issuer) < 2 {
		return bad("OpenPGP signature has no hashed issuer fingerprint")
	}
	if got := strings.ToUpper(ToHex(issuer[1:])); got != fpr {
		return bad("OpenPGP signature issuer %s does not match fpr", got)
	}
	if crit, has := sig.unknownCritical(); has {
		return bad("OpenPGP signature has an unknown critical subpacket %d", crit)
	}
	if !slices.Contains([]int{1, 19, 22, 27}, sig.pubAlgo) {
		return PgpPacketCheck{Status: StatusUnsupported, Code: "unsupported-alg", Message: fmt.Sprintf("OpenPGP public-key algorithm %d is not supported", sig.pubAlgo)}
	}
	if sig.lib == nil {
		return bad("OpenPGP signature packet is malformed: %s", sig.libErr.Error())
	}
	return PgpPacketCheck{OK: true, Created: isoSeconds(created)}
}

type pgpCertSource struct {
	bytes  []byte
	source string
}

type pgpSigCheck struct {
	status, code, message string
	info                  *PgpInfo
	warnings              []string
}

func verifyPgpSignature(sigBytes []byte, f map[string]string, payload []byte, certs []pgpCertSource, now int64) pgpSigCheck {
	fpr := f["fpr"]
	pre := CheckPgpSignaturePacket(sigBytes, fpr)
	if !pre.OK {
		return pgpSigCheck{status: pre.Status, code: pre.Code, message: pre.Message, info: &PgpInfo{Fpr: fpr}}
	}
	sig, _ := readSignaturePacket(sigBytes)
	var firstFail *pgpCertCheck
	for _, c := range certs {
		parsed, err := parseCerts(c.bytes)
		if err != nil {
			continue
		}
		for _, cert := range parsed {
			chk := checkCert(cert, fpr, f["signer"], now)
			if !chk.ok {
				if chk.code == "revoked" {
					return pgpSigCheck{status: StatusInvalid, code: "revoked", message: chk.message, info: &PgpInfo{Fpr: fpr}}
				}
				if !strings.HasPrefix(chk.message, "certificate has no key") && (firstFail == nil || firstFail.code == "not-found") {
					firstFail = &chk
				}
				continue
			}
			info := &PgpInfo{Fpr: fpr, UID: chk.uid, KeyAlg: chk.key.algName(), KeySource: c.source, Created: pre.Created}
			if sig.pubAlgo != chk.key.algo || sig.version != chk.key.version {
				return pgpSigCheck{status: StatusInvalid, code: "bad-signature", message: "OpenPGP signature version or algorithm does not match the key", info: info}
			}
			if !verifyRaw(chk.key, sig, subjectBytes(payload)) {
				return pgpSigCheck{status: StatusInvalid, code: "bad-signature", message: "OpenPGP signature does not verify with the signer's key", info: info}
			}
			return pgpSigCheck{status: StatusValid, info: info, warnings: chk.warnings}
		}
	}
	if firstFail != nil && firstFail.code == "unsupported-alg" {
		return pgpSigCheck{status: StatusUnsupported, code: "unsupported-alg", message: firstFail.message, info: &PgpInfo{Fpr: fpr}}
	}
	msg := "no certificate with key " + fpr
	if firstFail != nil {
		msg = firstFail.message
	}
	return pgpSigCheck{status: StatusUnresolved, code: "not-found", message: msg, info: &PgpInfo{Fpr: fpr}}
}
