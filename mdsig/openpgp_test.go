package mdsig

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

// --- RFC 9580 Appendix A

const pgpA1 = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEU/NfCxYJKwYBBAHaRw8BAQdAPwmJlL3ZFu1AUxl5NOSofIBzOhKA1i+AEJku
Q+47JAY=
-----END PGP PUBLIC KEY BLOCK-----`

const pgpA2 = `-----BEGIN PGP SIGNATURE-----

iF4EABYIAAYFAlX5X5UACgkQjP3hIZeWWpr2IgD/VvkMypjiECY3vZg/2xbBMd/S
ftgr9N3lYG4NdWrtM2YBANCcT6EVJ/A44PV/IgHYLy6iyQMyZfps60iehUuuYbQE
-----END PGP SIGNATURE-----`

const pgpA3 = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf
GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy
KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw
gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE
QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn
+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh
BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8
j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805
I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==
-----END PGP PUBLIC KEY BLOCK-----`

const pgpA4 = `-----BEGIN PGP PRIVATE KEY BLOCK-----

xUsGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laMAGXKB
exK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditlsLfCsQYfGwoAAABCBYJjh3/jAwsJ
BwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lwgyU2kCcUmKfvBXbAf6rh
RYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaEQsiPlR4zxP/TP7mhfVEe
7XWPxtnMUMtf15OyA51YBMdLBmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/
LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24wpsG
GBsKAAAALAWCY4d/4wKbDCIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJAAAAAAQBIKbpGG2dWTX8j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDE
M0g12vYxoWM8Y81W+bHBw805I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUr
k0mXubZvyl4GBg==
-----END PGP PRIVATE KEY BLOCK-----`

const pgpA6Sig = `-----BEGIN PGP SIGNATURE-----

wpgGARsKAAAAKQWCY5ijYyIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJAAAAAGk2IHZJX1AhiJD39eLuPBgiUU9wUA9VHYblySHkBONKU/usJ9BvuAqo
/FvLFuGWMbKAdA+epq7V4HOtAPlBWmU8QOd6aud+aSunHQaaEJ+iTFjP2OMW0KBr
NK2ay45cX1IVAQ==
-----END PGP SIGNATURE-----`

var pgpNow = time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)

func mustDearmor(t *testing.T, s string) []byte {
	t.Helper()
	b, err := dearmor(s)
	if err != nil || len(b) != 1 {
		t.Fatalf("dearmor: %v (%d blocks)", err, len(b))
	}
	return b[0]
}

func mustCert(t *testing.T, s string) *pgpCert {
	t.Helper()
	certs, err := parseCerts([]byte(s))
	if err != nil || len(certs) == 0 {
		t.Fatalf("parseCerts: %v", err)
	}
	return certs[0]
}

func mustSigPacket(t *testing.T, b []byte) *pgpSignature {
	t.Helper()
	s, err := readSignaturePacket(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func a1Key(t *testing.T) *pgpKey {
	t.Helper()
	packets, err := readPackets(mustDearmor(t, pgpA1))
	if err != nil {
		t.Fatal(err)
	}
	k, err := parseKeyPacket(packets[0].tag, packets[0].body)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestPgpA1KeyPacketAndFingerprint(t *testing.T) {
	packets, err := readPackets(mustDearmor(t, pgpA1))
	if err != nil {
		t.Fatal(err)
	}
	if got := ToHex(packets[0].body); got != "0453f35f0b16092b06010401da470f010107403f098994bdd916ed4053197934e4a87c80733a1280d62f8010992e43ee3b2406" {
		t.Fatal(got)
	}
	k := a1Key(t)
	if k.fprHex() != "C959BDBAFA32A2F89A153B678CFDE12197965A9A" || k.kind != "ed25519" {
		t.Fatal(k.fprHex(), k.kind)
	}
}

func TestPgpA2Verify(t *testing.T) {
	k := a1Key(t)
	sig := mustSigPacket(t, mustDearmor(t, pgpA2))
	if sig.version != 4 {
		t.Fatal(sig.version)
	}
	if !verifyRaw(k, sig, subjectBytes([]byte("OpenPGP"))) || verifyRaw(k, sig, subjectBytes([]byte("OpenPGq"))) {
		t.Fatal("verifyRaw")
	}
}

func TestPgpA2FailsDocumentRules(t *testing.T) {
	if CheckPgpSignaturePacket(mustDearmor(t, pgpA2), "C959BDBAFA32A2F89A153B678CFDE12197965A9A").OK {
		t.Fatal("A.2 has no issuer fingerprint subpacket")
	}
}

func TestPgpA3V6Certificate(t *testing.T) {
	c := mustCert(t, pgpA3)
	const primary = "CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9"
	const sub = "12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885"
	if c.primary.fprHex() != primary || c.subkeys[0].key.fprHex() != sub {
		t.Fatal(c.primary.fprHex(), c.subkeys[0].key.fprHex())
	}
	if chk := checkCert(c, primary, "", pgpNow.Unix()); !chk.ok {
		t.Fatal(chk.message)
	}
	if checkCert(c, sub, "", pgpNow.Unix()).ok {
		t.Fatal("X25519 subkey must not sign")
	}
	if checkCert(c, primary, "alice@example.org", pgpNow.Unix()).ok {
		t.Fatal("no user ID to bind")
	}
}

const groceryText = "What we need from the grocery store:\r\n\r\n- tofu\r\n- vegetables\r\n- noodles\r\n"

func TestPgpA6V6Signature(t *testing.T) {
	c := mustCert(t, pgpA3)
	sig := mustSigPacket(t, mustDearmor(t, pgpA6Sig))
	if sig.version != 6 || sig.lib == nil {
		t.Fatal(sig.version, sig.libErr)
	}
	if !verifyRaw(c.primary, sig, subjectBytes([]byte(groceryText))) || verifyRaw(c.primary, sig, subjectBytes([]byte(strings.Replace(groceryText, "tofu", "tempeh", 1)))) {
		t.Fatal("verifyRaw")
	}
}

func TestPgpA4V6SecretKeySigns(t *testing.T) {
	info, err := ReadPgpSecretKey([]byte(pgpA4), pgpNow)
	if err != nil {
		t.Fatal(err)
	}
	if info.Fpr != "CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9" || info.Protected {
		t.Fatal(info.Fpr, info.Protected)
	}
	signer, err := UnlockPgpSecretKey(info, nil, PgpUnlockOptions{})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("md-signature/v1\nalg=openpgp")
	pkt, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	signer.Dispose()
	if _, err := signer.Sign(payload); err == nil {
		t.Fatal("disposed signer signed")
	}
	sig := mustSigPacket(t, pkt)
	if sig.version != 6 || !verifyRaw(mustCert(t, pgpA3).primary, sig, subjectBytes(payload)) {
		t.Fatal("v6 signature does not verify")
	}
	if !CheckPgpSignaturePacket(pkt, info.Fpr).OK {
		t.Fatal("SPEC 6.2 check")
	}
}

func TestPgpWKD(t *testing.T) {
	adv, direct := WKDURLs("Joe.Doe@Example.ORG")
	if direct != "https://example.org/.well-known/openpgpkey/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe" {
		t.Fatal(direct)
	}
	if adv != "https://openpgpkey.example.org/.well-known/openpgpkey/example.org/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe" {
		t.Fatal(adv)
	}
	if zbase32([]byte{0xf0}) != "6y" {
		t.Fatal(zbase32([]byte{0xf0}))
	}
}

// --- lookup outcome (SPEC 4.3)

func clientFunc(f func(*http.Request) (*http.Response, error)) *http.Client {
	return &http.Client{Transport: roundTripFunc(f)}
}

func TestPgpNotFoundOnlyWhenAllAbsent(t *testing.T) {
	c := clientFunc(func(r *http.Request) (*http.Response, error) { return respond(r, 404, nil), nil })
	r := VerifyDocument(context.Background(), readExample(t, "valid-pgp-v6.md"), &VerifyOptions{ResolveOptions: ResolveOptions{PgpClient: c}})
	if s := r.Signatures[0]; s.Status != StatusUnresolved || s.Code != "not-found" {
		t.Fatal(s.Status, s.Code, s.Message)
	}
}

func TestPgpNetworkWhenASourceIsUnreachable(t *testing.T) {
	c := clientFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "keys.openpgp.org" {
			return respond(r, 404, nil), nil
		}
		return nil, errors.New("connection refused")
	})
	r := VerifyDocument(context.Background(), readExample(t, "valid-pgp-v6.md"), &VerifyOptions{ResolveOptions: ResolveOptions{PgpClient: c}})
	s := r.Signatures[0]
	if s.Code != "network" || !strings.Contains(s.Message, "WKD: unreachable; keys.openpgp.org: no key") {
		t.Fatal(s.Code, s.Message)
	}
}

func TestPgpKeyringFirstAndOffline(t *testing.T) {
	cert := []byte(readExample(t, "pgp/erin.pub.asc"))
	now, _ := time.Parse(time.RFC3339, "2026-12-01T00:00:00Z")
	keyring := func(context.Context, string) ([]byte, error) { return cert, nil }
	r := VerifyDocument(context.Background(), readExample(t, "valid-pgp-v6.md"), &VerifyOptions{ResolveOptions: ResolveOptions{Offline: true, PgpKeyring: keyring}, Now: now})
	if s := r.Signatures[0]; s.Status != StatusValid || s.Pgp == nil || s.Pgp.KeySource != "keyring" {
		t.Fatal(s.Status, s.Code, s.Message)
	}
	off := VerifyDocument(context.Background(), readExample(t, "valid-pgp-v6.md"), &VerifyOptions{ResolveOptions: ResolveOptions{Offline: true}})
	if off.Signatures[0].Code != "offline" {
		t.Fatal(off.Signatures[0].Code)
	}
	absent := func(context.Context, string) ([]byte, error) { return nil, nil }
	off = VerifyDocument(context.Background(), readExample(t, "valid-pgp-v6.md"), &VerifyOptions{ResolveOptions: ResolveOptions{Offline: true, PgpKeyring: absent}})
	if s := off.Signatures[0]; s.Code != "offline" || !strings.Contains(s.Message, "keyring: no key; WKD: skipped (offline)") {
		t.Fatal(s.Code, s.Message)
	}
}

func TestPgpSignChecksEmailsAndRecordsFpr(t *testing.T) {
	info, err := ReadPgpSecretKey([]byte(readExample(t, "pgp/frank.sec.asc")), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnlockPgpSecretKey(info, nil, PgpUnlockOptions{}); err == nil || !strings.Contains(err.Error(), "passphrase is required") {
		t.Fatal(err)
	}
	if _, err := UnlockPgpSecretKey(info, []byte("wrong"), PgpUnlockOptions{}); err == nil || err.Error() != "wrong passphrase" {
		t.Fatal(err)
	}
	signer, err := UnlockPgpSecretKey(info, []byte("test"), PgpUnlockOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Dispose()
	ctx := context.Background()
	if _, err := SignDocument(ctx, "# x\n", SignOptions{Pgp: signer, Method: "pgp", SignerID: "someone@example.org"}); err == nil || !strings.Contains(err.Error(), "no user ID") {
		t.Fatal(err)
	}
	if _, err := SignDocument(ctx, "# x\n", SignOptions{Pgp: signer, Method: "tofu", SignerID: "frank@example.org"}); err == nil || !strings.Contains(err.Error(), "only sign with method pgp") {
		t.Fatal(err)
	}
	out, err := SignDocument(ctx, "# x\n", SignOptions{Pgp: signer, Method: "pgp", SignerID: "Frank@Example.org"})
	if err != nil {
		t.Fatal(err)
	}
	f := out.Fields
	if f["signer"] != "frank@example.org" || f["fpr"] != info.Fpr || f["alg"] != "openpgp" {
		t.Fatal(f)
	}
	cert := []byte(readExample(t, "pgp/frank.pub.asc"))
	r := VerifyDocument(ctx, out.Text, &VerifyOptions{ResolveOptions: ResolveOptions{Offline: true, PgpKeyring: func(context.Context, string) ([]byte, error) { return cert, nil }}})
	if s := r.Signatures[0]; s.Status != StatusValid {
		t.Fatal(s.Status, s.Code, s.Message)
	}
}

// --- cross-implementation (deterministic algorithms)

func TestPgpCrossImplementation(t *testing.T) {
	for _, tc := range []struct{ file, secret, email, pass string }{
		{"valid-pgp-ed25519.md", "pgp/dave.sec.asc", "dave@example.org", ""},
		{"valid-pgp-rsa.md", "pgp/frank.sec.asc", "frank@example.org", "test"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			want := readExample(t, tc.file)
			b := ParseDocument(want).Chain[0]
			created, ok := mustSigPacket(t, mustBase64(t, UnfoldBinary(b.Fields["sig"])[7:])).created()
			if !ok {
				t.Fatal("no creation time")
			}
			info, err := ReadPgpSecretKey([]byte(readExample(t, tc.secret)), pgpNow)
			if err != nil {
				t.Fatal(err)
			}
			var pass []byte
			if tc.pass != "" {
				pass = []byte(tc.pass)
			}
			signer, err := UnlockPgpSecretKey(info, pass, PgpUnlockOptions{Now: func() time.Time { return time.Unix(created, 0) }})
			if err != nil {
				t.Fatal(err)
			}
			defer signer.Dispose()
			out, err := SignDocument(context.Background(), testBody, SignOptions{Pgp: signer, Method: "pgp", SignerID: tc.email, Role: "author", TS: "2026-11-16T09:00:00Z"})
			if err != nil {
				t.Fatal(err)
			}
			if out.Text != want {
				t.Fatalf("Go output differs from examples/%s\n--- go ---\n%s", tc.file, out.Text)
			}
		})
	}
}

func mustBase64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := FromBase64(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPgpSecretKeyErrors(t *testing.T) {
	if _, err := ReadPgpSecretKey([]byte(pgpA3), pgpNow); err == nil || err.Error() != "no OpenPGP secret key found" {
		t.Fatal(err)
	}
	if _, err := ReadPgpSecretKey([]byte("not a key"), pgpNow); err == nil || err.Error() != "no OpenPGP armored block found" {
		t.Fatal(err)
	}
}

// --- rules kept on top of go-crypto

func TestPgpRulesOnTopOfLibrary(t *testing.T) {
	info, err := ReadPgpSecretKey([]byte(readExample(t, "pgp/dave.sec.asc")), pgpNow)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := UnlockPgpSecretKey(info, nil, PgpUnlockOptions{Now: func() time.Time { return pgpNow.Add(-time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("md-signature/v1\nalg=openpgp")
	pkt, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	certs := []pgpCertSource{{bytes: []byte(readExample(t, "pgp/dave.pub.asc")), source: "keyring"}}
	fields := map[string]string{"fpr": info.Fpr, "signer": "dave@example.org"}
	check := func(p []byte) pgpSigCheck { return verifyPgpSignature(p, fields, payload, certs, pgpNow.Unix()) }
	if c := check(pkt); c.status != StatusValid {
		t.Fatal(c.status, c.message)
	}

	packets, err := readPackets(pkt)
	if err != nil || len(packets) != 1 {
		t.Fatal(err)
	}
	body := packets[0].body
	sig := mustSigPacket(t, pkt)
	tag := len(sig.header) + 2 + int(body[len(sig.header)])<<8 + int(body[len(sig.header)+1])

	prefix := slices.Clone(body)
	prefix[tag] ^= 0xff
	if c := check(encodePacket(pgpTagSignature, prefix)); c.status != StatusInvalid || c.code != "bad-signature" {
		t.Errorf("wrong two-octet hash prefix on a v4 signature: %s %s", c.status, c.message)
	}
	if lib := mustSigPacket(t, encodePacket(pgpTagSignature, prefix)).lib; lib == nil {
		t.Error("go-crypto should still read this packet; the check is ours")
	}

	trailing := append(slices.Clone(body), 0)
	if c := check(encodePacket(pgpTagSignature, trailing)); c.status != StatusInvalid || !strings.Contains(c.message, "trailing data") {
		t.Errorf("trailing byte in the signature packet: %s %s", c.status, c.message)
	}

	two := append(slices.Clone(pkt), pkt...)
	if c := check(two); c.status != StatusInvalid || !strings.Contains(c.message, "exactly one") {
		t.Errorf("two packets: %s %s", c.status, c.message)
	}
}

func TestPgpIssuerFingerprintMustBeHashed(t *testing.T) {
	const fpr = "C959BDBAFA32A2F89A153B678CFDE12197965A9A"
	packets, err := readPackets(mustDearmor(t, pgpA2))
	if err != nil {
		t.Fatal(err)
	}
	body := packets[0].body
	sig := mustSigPacket(t, mustDearmor(t, pgpA2))
	at := len(sig.header)
	oldLen := int(body[at])<<8 | int(body[at+1])
	fp, _ := FromHex(fpr)
	sub := encodeSubpacket(subIssuerFp, concatBytes([]byte{4}, fp))
	moved := concatBytes(body[:at], u16be(oldLen+len(sub)), body[at+2:at+2+oldLen], sub, body[at+2+oldLen:])
	pkt := encodePacket(pgpTagSignature, moved)
	got := mustSigPacket(t, pkt)
	if got.lib == nil || strings.ToUpper(ToHex(got.lib.IssuerFingerprint)) != fpr {
		t.Fatal("go-crypto should take the issuer fingerprint from the unhashed area", got.libErr)
	}
	if c := CheckPgpSignaturePacket(pkt, fpr); c.OK || !strings.Contains(c.Message, "no hashed issuer fingerprint") {
		t.Fatalf("unhashed issuer fingerprint accepted: %+v", c)
	}
}

func TestPgpKeyPacketMustBeCanonical(t *testing.T) {
	const fpr = "1E79CDA3F204FEF40DE7B7DDC1E564DE2D9677BAB5E768574CA08AB07B092777"
	cert := mustDearmor(t, readExample(t, "pgp/erin.pub.asc"))
	if !containsKey(cert, fpr) {
		t.Fatal("erin's certificate")
	}
	bent := slices.Clone(cert)
	bent[11] = 0x7d
	if containsKey(bent, fpr) {
		t.Fatal("a key packet with a wrong material length kept its fingerprint")
	}
}

func TestPgpDamagedSecretKeyIsRefused(t *testing.T) {
	raw := mustDearmor(t, readExample(t, "pgp/dave.sec.asc"))
	packets, err := readPackets(raw)
	if err != nil {
		t.Fatal(err)
	}
	damaged := slices.Clone(raw)
	damaged[2+len(packets[0].body)-5] ^= 0x01
	if _, err := ReadPgpSecretKey(damaged, pgpNow); err == nil || !strings.Contains(err.Error(), "cannot read the OpenPGP secret key") {
		t.Fatalf("secret scalar that does not match the public key: %v", err)
	}
}
