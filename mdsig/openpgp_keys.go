package mdsig

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// --- keys (parsed by go-crypto)

type pgpKey struct {
	version     int
	tag         int
	created     int64
	algo        int
	kind        string // rsa, ecdsa, ed25519, other
	bits        int
	name        string
	fingerprint []byte
	keyID       []byte
	pub         *packet.PublicKey
	// secret-key packets only; raw is the packet, re-read for every unlock so that no decrypted key stays here
	priv *packet.PrivateKey
	raw  []byte
}

var pgpAlgoNames = map[int]string{1: "rsa", 2: "rsa-encrypt", 3: "rsa-sign", 16: "elgamal", 17: "dsa", 18: "ecdh", 19: "ecdsa", 22: "eddsa-legacy", 25: "x25519", 26: "x448", 27: "ed25519", 28: "ed448"}

func classifyKey(k *pgpKey) {
	k.kind = "other"
	k.name = pgpAlgoNames[k.algo]
	if k.name == "" {
		k.name = fmt.Sprintf("algorithm %d", k.algo)
	}
	switch k.algo {
	case 1:
		if n, err := k.pub.BitLength(); err == nil {
			k.kind, k.bits = "rsa", int(n)
		}
	case 19:
		if c, err := k.pub.Curve(); err == nil && c == packet.CurveNistP256 {
			k.kind = "ecdsa"
		} else {
			k.name = "ecdsa (curve not supported)"
		}
	case 22:
		if c, err := k.pub.Curve(); err == nil && c == packet.Curve25519 {
			k.kind = "ed25519"
		} else {
			k.name = "eddsa (curve not supported)"
		}
	case 27:
		k.kind = "ed25519"
	}
}

func parseKeyPacket(tag int, body []byte) (*pgpKey, error) {
	raw := encodePacket(tag, body)
	p, err := packet.Read(bytes.NewReader(raw))
	if err != nil {
		return nil, &PgpError{Msg: err.Error()}
	}
	k := &pgpKey{tag: tag}
	switch v := p.(type) {
	case *packet.PrivateKey:
		k.pub, k.priv, k.raw = &v.PublicKey, v, raw
	case *packet.PublicKey:
		k.pub = v
	default:
		return nil, &PgpError{Msg: "not a key packet"}
	}
	if k.pub.Version != 4 && k.pub.Version != 6 {
		return nil, &PgpError{Msg: fmt.Sprintf("unsupported key version %d", k.pub.Version)}
	}
	// the fingerprint must be over the bytes that were read: go-crypto hashes its own re-encoding of the key
	var canon bytes.Buffer
	if err := k.pub.SerializeForHash(&canon); err != nil {
		return nil, &PgpError{Msg: err.Error()}
	}
	prefix := 3
	if k.pub.Version == 6 {
		prefix = 5
	}
	if canon.Len() < prefix || !bytes.HasPrefix(body, canon.Bytes()[prefix:]) {
		return nil, &PgpError{Msg: "key packet is not in canonical form"}
	}
	k.version = k.pub.Version
	k.created = k.pub.CreationTime.Unix()
	k.algo = int(k.pub.PubKeyAlgo)
	k.fingerprint = k.pub.Fingerprint
	k.keyID = binary.BigEndian.AppendUint64(nil, k.pub.KeyId)
	classifyKey(k)
	return k, nil
}

func (k *pgpKey) hasSecret() bool { return k.priv != nil }

func (k *pgpKey) fprHex() string { return strings.ToUpper(ToHex(k.fingerprint)) }

func (k *pgpKey) algName() string {
	switch k.kind {
	case "rsa":
		return fmt.Sprintf("rsa%d", k.bits)
	case "ecdsa":
		return "ecdsa-p256"
	case "ed25519":
		return "ed25519"
	default:
		return k.name
	}
}

// SPEC 6.2 condition 5
func (k *pgpKey) signingAlgSupported() bool {
	return (k.kind == "rsa" && k.bits >= 2048) || k.kind == "ecdsa" || k.kind == "ed25519"
}

// --- certificates (RFC 9580 Section 10.1)

type pgpUID struct {
	uid  string
	raw  []byte
	sigs []*pgpSignature
}

type pgpSubkey struct {
	key  *pgpKey
	sigs []*pgpSignature
}

type pgpCert struct {
	primary *pgpKey
	direct  []*pgpSignature
	uids    []*pgpUID
	subkeys []*pgpSubkey
}

func parseCerts(input []byte) ([]*pgpCert, error) {
	certs, _, err := parseCertsDetail(input)
	return certs, err
}

// also returns why secret-key packets were refused, so that a damaged key file is not reported as "no key"
func parseCertsDetail(input []byte) ([]*pgpCert, []error, error) {
	blocks, err := toPacketBytes(input)
	if err != nil {
		return nil, nil, err
	}
	var certs []*pgpCert
	var refused []error
	for _, block := range blocks {
		packets, err := readPackets(block)
		if err != nil {
			return nil, nil, err
		}
		var cur *pgpCert
		var sigs *[]*pgpSignature
		for _, p := range packets {
			if p.tag == pgpTagPublicKey || p.tag == pgpTagSecretKey {
				k, err := parseKeyPacket(p.tag, p.body)
				if err != nil {
					if p.tag == pgpTagSecretKey {
						refused = append(refused, err)
					}
					cur, sigs = nil, nil
					continue
				}
				cur = &pgpCert{primary: k}
				certs = append(certs, cur)
				sigs = &cur.direct
				continue
			}
			if cur == nil {
				continue
			}
			switch p.tag {
			case pgpTagUserID:
				u := &pgpUID{uid: decodeUTF8Lossy(p.body), raw: p.body}
				cur.uids = append(cur.uids, u)
				sigs = &u.sigs
			case pgpTagUserAttribute:
				sigs = &[]*pgpSignature{}
			case pgpTagPublicSubkey, pgpTagSecretSubkey:
				k, err := parseKeyPacket(p.tag, p.body)
				if err != nil {
					if p.tag == pgpTagSecretSubkey {
						refused = append(refused, err)
					}
					sigs = &[]*pgpSignature{}
					continue
				}
				s := &pgpSubkey{key: k}
				cur.subkeys = append(cur.subkeys, s)
				sigs = &s.sigs
			case pgpTagSignature:
				if sigs == nil {
					continue
				}
				if s, err := parseSignature(p.body); err == nil {
					*sigs = append(*sigs, s)
				}
			}
		}
	}
	return certs, refused, nil
}

var (
	uidEmailRe  = regexp.MustCompile(`<([^<>` + jsSpaceClass + `]+@[^<>` + jsSpaceClass + `]+)>`)
	bareEmailRe = regexp.MustCompile(`^[^` + jsSpaceClass + `@<>]+@[^` + jsSpaceClass + `@<>]+$`)
)

func emailOf(uid string) string {
	if m := uidEmailRe.FindStringSubmatch(uid); m != nil {
		return strings.ToLower(m[1])
	}
	if t := strings.TrimFunc(uid, isJSSpace); bareEmailRe.MatchString(t) {
		return strings.ToLower(t)
	}
	return ""
}

func newestValid(sigs []*pgpSignature, types []int, issuer *pgpKey, subject pgpSubject, now int64) *pgpSignature {
	var best *pgpSignature
	for _, s := range sigs {
		if !slices.Contains(types, s.typ) || !selfSigUsable(s, issuer, now) {
			continue
		}
		if best != nil {
			bc, _ := best.created()
			sc, _ := s.created()
			if bc >= sc {
				continue
			}
		}
		if verifyRaw(issuer, s, subject) {
			best = s
		}
	}
	return best
}

func anyValid(sigs []*pgpSignature, typ int, issuer *pgpKey, subject pgpSubject, now int64) bool {
	for _, s := range sigs {
		if s.typ == typ && selfSigUsable(s, issuer, now) && verifyRaw(issuer, s, subject) {
			return true
		}
	}
	return false
}

type pgpCertCheck struct {
	ok       bool
	key      *pgpKey
	uid      string
	emails   []string
	warnings []string
	code     string // not-found, revoked, unsupported-alg
	message  string
}

func certFail(code, format string, a ...any) pgpCertCheck {
	return pgpCertCheck{code: code, message: fmt.Sprintf(format, a...)}
}

var certTypes = []int{0x10, 0x11, 0x12, 0x13}

type pgpValidUID struct {
	uid string
	sig *pgpSignature
}

func validUIDs(c *pgpCert, now int64) []pgpValidUID {
	var out []pgpValidUID
	for _, u := range c.uids {
		newest := newestValid(u.sigs, append(slices.Clone(certTypes), sigCertRevocation), c.primary, subjectUID(c.primary, u.raw), now)
		if newest != nil && newest.typ != sigCertRevocation {
			out = append(out, pgpValidUID{uid: u.uid, sig: newest})
		}
	}
	return out
}

func uniqueEmails(uids []string) []string {
	out := []string{}
	for _, u := range uids {
		if e := emailOf(u); e != "" && !slices.Contains(out, e) {
			out = append(out, e)
		}
	}
	return out
}

func isoSeconds(t int64) string { return time.Unix(t, 0).UTC().Format(tsLayout) }

// SPEC 4.3 key validation; an empty email skips the user ID condition (own secret keys)
func checkCert(c *pgpCert, fpr, email string, now int64) pgpCertCheck {
	p := c.primary
	want := strings.ToUpper(fpr)
	var sub *pgpSubkey
	for _, s := range c.subkeys {
		if s.key.fprHex() == want {
			sub = s
			break
		}
	}
	if p.fprHex() != want && sub == nil {
		return certFail("not-found", "certificate has no key %s", want)
	}
	if p.kind == "other" {
		return certFail("unsupported-alg", "primary key algorithm %s is not supported", p.name)
	}
	pp := subjectKeys(p)
	var warnings []string

	if anyValid(c.direct, sigKeyRevocation, p, pp, now) {
		return certFail("revoked", "OpenPGP key %s has been revoked", p.fprHex())
	}

	uids := validUIDs(c, now)
	names := make([]string, len(uids))
	for i, u := range uids {
		names[i] = u.uid
	}
	emails := uniqueEmails(names)
	var matched *pgpValidUID
	for i := range uids {
		if email == "" || emailOf(uids[i].uid) == strings.ToLower(email) {
			matched = &uids[i]
			break
		}
	}
	if email != "" && matched == nil {
		return certFail("not-found", "no valid user ID with <%s> on key %s", email, p.fprHex())
	}

	direct := newestValid(c.direct, []int{sigDirectKey}, p, pp, now)
	// RFC 9580 5.2.3.10: a version 6 key is not used without a valid direct key signature
	if p.version == 6 && direct == nil {
		return certFail("not-found", "version 6 key %s has no valid direct key signature", p.fprHex())
	}
	var primaryUID *pgpValidUID
	for i := range uids {
		if slices.ContainsFunc(uids[i].sig.hashed, func(s pgpSubpacket) bool { return s.typ == subPrimaryUID && len(s.data) > 0 && s.data[0] != 0 }) {
			primaryUID = &uids[i]
			break
		}
	}
	if primaryUID == nil && len(uids) > 0 {
		primaryUID = &uids[0]
	}
	primaryAttrs := direct
	if _, has := keyFlagsOf(direct); !has && primaryUID != nil {
		primaryAttrs = primaryUID.sig
	}
	expired := func(k *pgpKey, sig *pgpSignature) {
		if sig == nil {
			return
		}
		if e := sig.keyExpiry(); e != 0 && k.created+e <= now {
			warnings = append(warnings, fmt.Sprintf("OpenPGP key %s expired on %s", k.fprHex(), isoSeconds(k.created+e)))
		}
	}
	expired(p, primaryAttrs)

	key := p
	if sub != nil {
		both := subjectKeys(p, sub.key)
		if anyValid(sub.sigs, sigSubkeyRevocation, p, both, now) {
			return certFail("revoked", "OpenPGP subkey %s has been revoked", want)
		}
		binding := newestValid(sub.sigs, []int{sigSubkeyBinding}, p, both, now)
		if binding == nil {
			return certFail("not-found", "subkey %s has no valid binding signature", want)
		}
		if f, _ := binding.keyFlags(); f&0x02 == 0 {
			return certFail("not-found", "subkey %s is not marked for signing", want)
		}
		back := false
		for _, e := range binding.embeddedSignatures() {
			if e.typ == sigPrimaryBinding && selfSigUsable(e, sub.key, now) && verifyRaw(sub.key, e, both) {
				back = true
			}
		}
		if !back {
			return certFail("not-found", "signing subkey %s has no valid primary key binding signature", want)
		}
		expired(sub.key, binding)
		key = sub.key
	} else if f, has := keyFlagsOf(primaryAttrs); has && f&0x02 == 0 {
		return certFail("not-found", "key %s is not marked for signing", want)
	}
	if !key.signingAlgSupported() {
		return certFail("unsupported-alg", "OpenPGP key algorithm %s is not supported", key.algName())
	}
	r := pgpCertCheck{ok: true, key: key, emails: emails, warnings: warnings}
	if matched != nil {
		r.uid = matched.uid
	}
	return r
}

func keyFlagsOf(s *pgpSignature) (int, bool) {
	if s == nil {
		return 0, false
	}
	return s.keyFlags()
}

type PgpPublicKeyInfo struct {
	Fpr     string
	KeyAlg  string
	Version int
	UIDs    []string
	Subkeys []PgpSubkeyInfo
}

type PgpSubkeyInfo struct {
	Fpr    string
	KeyAlg string
}

func ReadPgpPublicKey(input []byte, now time.Time) ([]PgpPublicKeyInfo, error) {
	certs, err := parseCerts(input)
	if err != nil {
		return nil, err
	}
	out := []PgpPublicKeyInfo{}
	for _, c := range certs {
		info := PgpPublicKeyInfo{Fpr: c.primary.fprHex(), KeyAlg: c.primary.algName(), Version: c.primary.version, UIDs: []string{}, Subkeys: []PgpSubkeyInfo{}}
		for _, u := range validUIDs(c, now.Unix()) {
			info.UIDs = append(info.UIDs, u.uid)
		}
		for _, s := range c.subkeys {
			info.Subkeys = append(info.Subkeys, PgpSubkeyInfo{Fpr: s.key.fprHex(), KeyAlg: s.key.algName()})
		}
		out = append(out, info)
	}
	return out, nil
}

type PgpKeyInfo struct {
	Fpr        string
	PrimaryFpr string
	KeyAlg     string
	UIDs       []string
	Emails     []string
}

// CheckPgpKey applies the SPEC 4.3 rules (without the user ID condition) to the key fpr in a certificate.
func CheckPgpKey(cert []byte, fpr string, now time.Time) (*PgpKeyInfo, error) {
	certs, err := parseCerts(cert)
	if err != nil {
		return nil, err
	}
	msg := fmt.Sprintf("certificate has no key %s", strings.ToUpper(fpr))
	for _, c := range certs {
		chk := checkCert(c, fpr, "", now.Unix())
		if !chk.ok {
			if chk.code != "not-found" || !strings.HasPrefix(chk.message, "certificate has no key") {
				msg = chk.message
			}
			continue
		}
		var uids []string
		for _, u := range validUIDs(c, now.Unix()) {
			uids = append(uids, u.uid)
		}
		return &PgpKeyInfo{Fpr: chk.key.fprHex(), PrimaryFpr: c.primary.fprHex(), KeyAlg: chk.key.algName(), UIDs: uids, Emails: chk.emails}, nil
	}
	return nil, &PgpError{Msg: msg}
}
