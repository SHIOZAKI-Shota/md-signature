package mdsig

import (
	"context"
	"strings"
	"testing"
)

const testBody = "# Service Agreement\n\n" +
	"This agreement is made between **Example Corp** (\"Provider\") and **Alice** (\"Client\").\n\n" +
	"1. The Provider will deliver the service described in Appendix A.\n" +
	"2. The Client will pay the fees listed in Appendix B within 30 days.\n\n" +
	"| Item | Fee |\n| --- | --- |\n| Setup | 1,000 USD |\n| Monthly | 200 USD |\n\n" +
	"日本語の本文も UTF-8 でそのまま署名されます。\n"

const (
	aliceSeed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	bobSeed   = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
)

func mustSigner(t *testing.T, hexSeed string) KeySigner {
	t.Helper()
	seed, err := fromHex(hexSeed)
	if err != nil {
		t.Fatal(err)
	}
	s, err := SignerFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func signTofu(t *testing.T, text string) *SignResult {
	t.Helper()
	r, err := SignDocument(context.Background(), text, SignOptions{
		Signer: mustSigner(t, bobSeed), Method: "tofu", SignerID: "bob@laptop", Role: "author", TS: "2026-11-16T09:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func offline() *VerifyOptions { return &VerifyOptions{ResolveOptions: ResolveOptions{Offline: true}} }

func TestNormalizeDocument(t *testing.T) {
	cases := map[string]string{
		"":                       "\n",
		"a":                      "a\n",
		bom + "a\r\nb\rc":        "a\nb\nc\n",
		"a\n\n \t\n":             "a\n",
		"a \t":                   "a\n",
		"  a\n":                  "  a\n",
		"a\r\r\n":                "a\n",
		"x" + bom:                "x" + bom + "\n",
		bom + bom + "a":          bom + "a\n",
		"line1\r\n\r\nline2\r\n": "line1\n\nline2\n",
	}
	for in, want := range cases {
		if got := normalizeDocument(in); got != want {
			t.Errorf("NormalizeDocument(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSignedPayload(t *testing.T) {
	f := map[string]string{
		"v": "0.0.1", "method": "git-hosting", "signer": "github.com/alice", "role": "author", "reason": "Initial draft",
		"ts": "2026-11-16T09:00:00Z", "alg": "ed25519", "hash": "sha256:3a0d", "sig": "base64:xx",
		"tsa_url": "http://ts.ssl.com", "tsa_token": "gzip+base64:yy", "zz_extra": "1", "a_b": "2",
	}
	want := "md-signature/v1\na_b=2\nalg=ed25519\nhash=sha256:3a0d\nmethod=git-hosting\nreason=Initial draft\nrole=author\nsigner=github.com/alice\nts=2026-11-16T09:00:00Z\nv=0.0.1\nzz_extra=1"
	if got := string(SignedPayload(f)); got != want {
		t.Errorf("payload:\n%s\nwant:\n%s", got, want)
	}
}

func TestFoldingRoundTrip(t *testing.T) {
	long := "base64:" + strings.Repeat("ABCD", 40)
	fields := map[string]string{"v": "0.0.1", "method": "tofu", "signer": "x", "ts": "2026-11-16T09:00:00Z", "hash": "sha256:00", "sig": long, "tsa_token": "base64:" + strings.Repeat("Q", 200), "x_custom": "c", "role": "r"}
	block, err := serializeBlock(fields)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(block, "\n")
	for _, l := range lines {
		if strings.HasPrefix(l, "  ") && len(l) > 78 {
			t.Errorf("continuation line too long: %d", len(l))
		}
	}
	if !strings.Contains(block, "sig: |\n  base64:") {
		t.Errorf("sig not folded:\n%s", block)
	}
	if strings.Index(block, "x_custom:") < strings.Index(block, "ts:") || strings.Index(block, "x_custom:") > strings.Index(block, "hash:") {
		t.Errorf("bad order:\n%s", block)
	}
	got, errs, _ := parseFields(lines[1 : len(lines)-1])
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	for k, v := range fields {
		g := got[k]
		if binaryKeys[k] {
			if !strings.Contains(g, "\n") {
				t.Errorf("%s: folded value should keep its line breaks: %q", k, g)
			}
			g = UnfoldBinary(g)
		}
		if g != v {
			t.Errorf("%s: got %q want %q", k, g, v)
		}
	}
	fields["sig"] = "base64:AAAA"
	block, _ = serializeBlock(fields)
	if !strings.Contains(block, "\nsig: base64:AAAA\n") {
		t.Errorf("short sig folded:\n%s", block)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	r := signTofu(t, testBody)
	v := VerifyDocument(context.Background(), r.Text, offline())
	if !v.OK || len(v.Signatures) != 1 || v.Signatures[0].Status != StatusValid {
		t.Fatalf("not ok: %+v %+v", v, v.Signatures[0])
	}
	alice := mustSigner(t, aliceSeed)
	r2, err := SignDocument(context.Background(), r.Text, SignOptions{Signer: alice, Method: "tofu", SignerID: "alice", TS: "2026-11-16T10:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if r2.Previous != 1 || !strings.Contains(r2.Text, "-->\n<!-- md-signature\n") {
		t.Fatalf("co-sign layout wrong:\n%s", r2.Text)
	}
	v = VerifyDocument(context.Background(), r2.Text, offline())
	if !v.OK || len(v.Signatures) != 2 {
		t.Fatalf("cosign not ok: %+v", v)
	}
}

func TestTamper(t *testing.T) {
	signed := signTofu(t, testBody).Text
	cases := []struct {
		name, text, status, code string
	}{
		{"body", strings.Replace(signed, "1,000 USD", "100 USD", 1), StatusInvalid, "hash-mismatch"},
		{"role", strings.Replace(signed, "role: author", "role: approver", 1), StatusInvalid, "bad-signature"},
		{"ts", strings.Replace(signed, "ts: 2026-11-16T09:00:00Z", "ts: 2026-11-16T09:00:01Z", 1), StatusInvalid, "bad-signature"},
		{"added field", strings.Replace(signed, "role: author\n", "role: author\nnote: hi\n", 1), StatusMalformed, "unknown-field"},
		{"added x_ field", strings.Replace(signed, "role: author\n", "role: author\nx_note: hi\n", 1), StatusInvalid, "bad-signature"},
		{"dup key", strings.Replace(signed, "role: author\n", "role: author\nrole: author\n", 1), StatusMalformed, "malformed"},
		{"version", strings.Replace(signed, "v: 0.0.2", "v: 0.0.3", 1), StatusUnsupported, "unsupported-version"},
		{"alg", strings.Replace(signed, "alg: ed25519", "alg: ml-dsa-65", 1), StatusUnsupported, "unsupported-alg"},
		{"method", strings.Replace(signed, "method: tofu", "method: foo", 1), StatusUnsupported, "unsupported-method"},
		{"dashdash", strings.Replace(signed, "role: author", "role: au--thor", 1), StatusMalformed, "malformed"},
		{"blank line", strings.Replace(signed, "role: author\n", "role: author\n\n", 1), "", ""},
	}
	for _, c := range cases {
		v := VerifyDocument(context.Background(), c.text, offline())
		if v.OK {
			t.Errorf("%s: expected failure", c.name)
			continue
		}
		if c.status == "" {
			if len(v.Signatures) != 0 {
				t.Errorf("%s: expected no chain, got %d", c.name, len(v.Signatures))
			}
			continue
		}
		s := v.Signatures[0]
		if s.Status != c.status || s.Code != c.code {
			t.Errorf("%s: got %s:%s (%s), want %s:%s", c.name, s.Status, s.Code, s.Message, c.status, c.code)
		}
	}
	for _, ok := range []string{signed + "\n\n  \n", strings.ReplaceAll(signed, "\n", "\r\n"), bom + signed} {
		if v := VerifyDocument(context.Background(), ok, offline()); !v.OK {
			t.Errorf("benign change rejected: %+v", v.Signatures[0])
		}
	}
	v := VerifyDocument(context.Background(), signed+"\nP.S.\n", offline())
	if v.OK || !strings.Contains(v.Error, "unsigned content") {
		t.Errorf("trailer: %+v", v)
	}
	if _, err := SignDocument(context.Background(), signed+"\nP.S.\n", SignOptions{Signer: mustSigner(t, bobSeed), Method: "tofu", SignerID: "b"}); err == nil {
		t.Error("signing over unsigned trailer should be refused")
	}
	if _, err := SignDocument(context.Background(), signed+"\nP.S.\n", SignOptions{Signer: mustSigner(t, bobSeed), Method: "tofu", SignerID: "b", Force: true}); err != nil {
		t.Errorf("force: %v", err)
	}
}

func TestFencedExampleIsNotStray(t *testing.T) {
	body := "# Doc\n\n```markdown\n<!-- md-signature\nv: 0.0.1\n-->\n```\n\nMore text.\n"
	d := ParseDocument(body)
	if d.StrayMarker || len(d.Chain) != 0 {
		t.Fatalf("fenced example: %+v", d)
	}
	r := signTofu(t, body)
	if v := VerifyDocument(context.Background(), r.Text, offline()); !v.OK || len(v.Warnings) != 0 {
		t.Fatalf("%+v", v)
	}
	unfenced := "# Doc\n\n<!-- md-signature\nv: 0.0.1\n-->\n\nMore text.\n"
	if d := ParseDocument(unfenced); !d.StrayMarker || d.StrayMarkerLine != 3 {
		t.Fatalf("unfenced: %+v", d)
	}
}

func TestCRLFPreserved(t *testing.T) {
	crlf := strings.ReplaceAll(testBody, "\n", "\r\n")
	r := signTofu(t, crlf)
	if strings.Count(r.Text, "\n") != strings.Count(r.Text, "\r\n") {
		t.Fatal("bare LF in CRLF output")
	}
	if !strings.HasSuffix(r.Text, "-->\r\n") || !strings.Contains(r.Text, "。\r\n\r\n<!-- md-signature\r\n") {
		t.Fatalf("CRLF layout wrong: %q", r.Text[len(r.Text)-40:])
	}
	lf := signTofu(t, testBody)
	if r.Fields["hash"] != lf.Fields["hash"] || r.Fields["sig"] != lf.Fields["sig"] {
		t.Fatal("CRLF and LF should produce the same signature")
	}
	if v := VerifyDocument(context.Background(), r.Text, offline()); !v.OK {
		t.Fatal("CRLF doc does not verify")
	}
}

func TestRejectBadValues(t *testing.T) {
	for _, bad := range []string{"a--b", "a\nb", "a\tb", " lead", "trail ", "x\x7f"} {
		_, err := SignDocument(context.Background(), testBody, SignOptions{Signer: mustSigner(t, bobSeed), Method: "tofu", SignerID: "b", Reason: bad})
		if _, ok := err.(*ValueError); !ok {
			t.Errorf("reason %q: got %v, want ValueError", bad, err)
		}
	}
}

func TestDNSSignerLowercased(t *testing.T) {
	r, err := SignDocument(context.Background(), testBody, SignOptions{Signer: mustSigner(t, aliceSeed), Method: "dns", SignerID: "Example.COM.", Selector: "2026", TS: "2026-11-16T09:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Fields["signer"] != "example.com" || r.Fields["selector"] != "2026" {
		t.Fatalf("%v", r.Fields)
	}
	if !strings.Contains(r.Block, "signer: example.com\nselector: 2026\n") {
		t.Fatal(r.Block)
	}
}

func TestGitHostingKeyFP(t *testing.T) {
	s := mustSigner(t, aliceSeed)
	r, err := SignDocument(context.Background(), testBody, SignOptions{Signer: s, Method: "git-hosting", SignerID: "github.com/alice", TS: "2026-11-16T09:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Fields["key_fp"] != "SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8" {
		t.Fatal(r.Fields["key_fp"])
	}
	other := mustSigner(t, bobSeed)
	keysFile := FormatSSHPublicKey(other.PublicKey(), "x") + "\n" + FormatSSHPublicKey(s.PublicKey(), "alice")
	res := map[string]Resolver{"git-hosting": ResolverFunc(func(_ context.Context, f map[string]string, _ *ResolveOptions) (ResolveResult, error) {
		return GitHostingKeysFromText(f, "test", keysFile)
	})}
	v := VerifyDocument(context.Background(), r.Text, &VerifyOptions{Resolvers: res})
	if !v.OK || !strings.Contains(v.Signatures[0].KeySource, "SHA256:bbXpu") {
		t.Fatalf("%+v", v.Signatures[0])
	}
	v = VerifyDocument(context.Background(), r.Text, offline())
	if v.Signatures[0].Status != StatusUnresolved || v.Signatures[0].Code != "offline" || !*v.Signatures[0].HashOk {
		t.Fatalf("%+v", v.Signatures[0])
	}
}

func TestBase64(t *testing.T) {
	for in, ok := range map[string]bool{"AAAA": true, "AA": true, "AA==": true, "A A\nA A": true, "A": false, "AA===": false, "A=A": false, "AA-_": false} {
		_, err := fromBase64(in)
		if (err == nil) != ok {
			t.Errorf("FromBase64(%q) err=%v", in, err)
		}
	}
}

func TestTSARequestDER(t *testing.T) {
	imprint := make([]byte, 32)
	der, err := buildTimeStampReq(imprint, []byte{0, 0x80, 1}, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	want := "303e0201013031300d060960864801650304020105000420" + strings.Repeat("00", 32) + "0203008001" + "0101ff"
	if got := toHex(der); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestTofuBadPubkeyIsMalformed(t *testing.T) {
	signed := signTofu(t, testBody)
	pk := signed.Fields["pubkey"]
	for name, bad := range map[string]string{
		"alg prefix": "x25519:" + strings.TrimPrefix(pk, "ed25519:"),
		"no prefix":  strings.TrimPrefix(pk, "ed25519:"),
		"bad base64": "ed25519:!!!!",
		"bad length": "ed25519:AAAA",
	} {
		text := strings.Replace(signed.Text, "pubkey: "+pk, "pubkey: "+bad, 1)
		v := VerifyDocument(context.Background(), text, offline())
		s := v.Signatures[0]
		if v.OK || s.Status != StatusMalformed || s.Code != "malformed" {
			t.Errorf("%s: got %s:%s (%s), want malformed:malformed", name, s.Status, s.Code, s.Message)
		}
	}
}
