package mdsig

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testdata fixtures come from the TS core: node mdsig/testdata/gen-ts-fixtures.mjs
const exampleComSeed = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"

func readTestdata(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

func TestCrossImplFeatureBlock(t *testing.T) {
	in := readTestdata(t, "features-input.md")
	want := readTestdata(t, "features-ts.md")
	r, err := SignDocument(context.Background(), in, SignOptions{
		Signer: mustSigner(t, bobSeed), Method: "tofu", SignerID: "bob@laptop", DisplayName: "Bob Example", Role: "author", Reason: "Scoped draft", TS: "2026-11-16T09:00:00Z",
		Scope: []string{"terms", "fees"}, Expires: "2027-11-16T00:00:00Z",
		Require: []string{"order mode=guide", "step", "  dns:example.com role=approver", "  git-hosting:github.com/alice", "step any=1", "  tofu:carol@passkey role=witness", "  dns:*.example.com member_of=dns:example.com"},
		Resources: []ResourceItem{
			{Ref: "./img/diagram.png", Bytes: []byte("PNG-BYTES\n")},
			{Ref: "https://example.com/chart.png", Bytes: []byte("REMOTE")},
		},
		RevocationURL: "https://example.com/.well-known/mdsig-revoked.md",
		Extra:         map[string]string{"x_ref": "PO-123", "x_dept": "legal"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.Text != want {
		t.Fatalf("Go output differs from the TS fixture\n--- go ---\n%s\n--- ts ---\n%s", r.Text, want)
	}
	v := VerifyDocument(context.Background(), want, &VerifyOptions{NoRevocation: true, ResourceCheckOptions: ResourceCheckOptions{
		LoadResource: func(ref string) ([]byte, error) { return []byte("PNG-BYTES\n"), nil },
	}})
	if !v.OK || v.Agreement.Status != AgreementPending || len(v.Agreement.Missing) != 4 {
		t.Fatalf("%+v %+v", v, v.Signatures[0])
	}
}

func TestCrossImplRequirePayload(t *testing.T) {
	want := readTestdata(t, "require-payload-ts.txt")
	got := string(SignedPayload(map[string]string{
		"v": "0.1", "require": "dns:a.com role=approver\ngit-hosting:github.com/b\nv=9", "x_note": "n",
		"sig": "base64:AA", "webauthn_client_data": "AA",
	}))
	if got != want {
		t.Fatalf("payload differs\n--- go ---\n%q\n--- ts ---\n%q", got, want)
	}
}

func TestCrossImplExampleVectors(t *testing.T) {
	ctx := context.Background()
	bob := mustSigner(t, bobSeed)
	alice := mustSigner(t, aliceSeed)
	ex := mustSigner(t, exampleComSeed)
	sign := func(text string, o SignOptions) *SignResult {
		t.Helper()
		r, err := SignDocument(ctx, text, o)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	check := func(name, got string) {
		t.Helper()
		if want := readExample(t, name); got != want {
			t.Errorf("%s differs\n--- go ---\n%s\n--- ts ---\n%s", name, got, want)
		}
	}
	const ts = "2026-11-16T09:00:00Z"
	join := func(lines ...string) string { return strings.Join(lines, "\n") }

	diagram := []byte("<svg xmlns='http://www.w3.org/2000/svg'><text>diagram v1</text></svg>\n")
	res := sign(join(testBody, "![Diagram](./assets/diagram.svg)", "", "![Remote chart](https://example.com/chart.png)", ""), SignOptions{
		Signer: bob, Method: "tofu", SignerID: "bob@laptop", Role: "author", TS: ts,
		Resources: []ResourceItem{{Ref: "./assets/diagram.svg", Bytes: diagram}, {Ref: "https://example.com/chart.png", Bytes: []byte("not fetched by default")}},
	})
	check("valid-resources.md", res.Text)
	csvSigned := []byte("milestone,amount\ndesign,4000\nlaunch,6000\n")
	check("tampered-resource.md", sign(join(testBody, "See [the data](./assets/chart.csv).", ""), SignOptions{
		Signer: bob, Method: "tofu", SignerID: "bob@laptop", TS: ts, Resources: []ResourceItem{{Ref: "./assets/chart.csv", Bytes: csvSigned}},
	}).Text)
	check("missing-resource.md", sign(testBody, SignOptions{
		Signer: bob, Method: "tofu", SignerID: "bob@laptop", TS: ts, Resources: []ResourceItem{{Ref: "./assets/missing.png", Bytes: []byte("gone")}},
	}).Text)

	scopedBody := join("# Statement of Work", "", "<!-- mdsig:section terms -->", "## Terms", "Payment within 30 days of each milestone.",
		"<!-- /mdsig:section -->", "", "## Progress notes (editable)", "Kick-off scheduled.", "", "<!-- mdsig:section fees -->",
		"| Milestone | Amount |", "| --- | --- |", "| Launch | 6,000 USD |", "<!-- /mdsig:section -->", "")
	scoped := sign(scopedBody, SignOptions{Signer: bob, Method: "tofu", SignerID: "bob@laptop", Role: "author", TS: ts, Scope: []string{"terms", "fees"}})
	check("valid-scoped-edited.md", strings.Replace(scoped.Text, "Kick-off scheduled.", "Kick-off done. Design review on 2026-11-20.", 1))
	check("tampered-scoped.md", strings.Replace(scoped.Text, "6,000 USD", "60,000 USD", 1))

	req := sign(testBody, SignOptions{Signer: alice, Method: "git-hosting", SignerID: "github.com/alice", Role: "author", TS: ts, Require: []string{"dns:example.com role=approver"}})
	check("pending-require.md", req.Text)
	check("complete-require.md", sign(req.Text, SignOptions{Signer: ex, Method: "dns", SignerID: "example.com", Selector: "2026", Role: "approver", TS: "2026-11-16T09:46:00Z"}).Text)

	check("expired.md", sign(testBody, SignOptions{Signer: bob, Method: "tofu", SignerID: "bob@laptop", TS: ts, Expires: "2026-11-30T00:00:00Z"}).Text)

	const revURL = "https://example.com/.well-known/mdsig-revoked.md"
	check("not-revoked.md", sign(testBody, SignOptions{Signer: ex, Method: "dns", SignerID: "example.com", Selector: "2026", TS: ts, RevocationURL: revURL, Reason: "Still valid"}).Text)
	revBad := sign(testBody, SignOptions{Signer: ex, Method: "dns", SignerID: "example.com", Selector: "2026", TS: ts, RevocationURL: revURL, Reason: "Withdrawn later"})
	check("revoked.md", revBad.Text)
	id := RevocationID(revBad.Fields)
	check("revocation/example.com.md", sign(join("# example.com revoked signatures", "", "```mdsig-list", "type: revocation", "revoked: sha256:"+id, "```", ""), SignOptions{
		Signer: ex, Method: "dns", SignerID: "example.com", Selector: "2026", TS: "2026-11-25T00:00:00Z", RevocationURL: revURL,
	}).Text)
}

func TestWriteGoVectors(t *testing.T) {
	dir := os.Getenv("MDSIG_WRITE_GO_VECTORS")
	if dir == "" {
		t.Skip("MDSIG_WRITE_GO_VECTORS not set")
	}
	write := func(name, text string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	auth := newSoftAuth(t, rp, "", 0x05)
	write("go-webauthn.md", mustSign(t, testBody, SignOptions{WebAuthn: auth, Method: "tofu", SignerID: "carol@passkey", Role: "approver", TS: fTS}).Text)
	local := newSoftAuth(t, "localhost", "http://localhost:8765", 0x01)
	write("go-webauthn-localhost.md", mustSign(t, testBody, SignOptions{WebAuthn: local, Method: "tofu", SignerID: "dev", TS: fTS}).Text)
	in := readTestdata(t, "features-input.md")
	s := mustSign(t, in, SignOptions{Signer: mustSigner(t, bobSeed), Method: "tofu", SignerID: "bob@laptop", TS: fTS, Scope: []string{"terms"},
		Require: []string{"tofu:alice role=approver"}, Resources: []ResourceItem{{Ref: "./img/diagram.png", Bytes: []byte("PNG-BYTES\n")}},
		Expires: "2027-11-16T00:00:00Z", Extra: map[string]string{"x_ref": "PO-1"}})
	s2 := mustSign(t, strings.Replace(s.Text, "Notes (editable).", "Notes edited later.", 1), SignOptions{Signer: mustSigner(t, aliceSeed), Method: "tofu", SignerID: "alice", Role: "approver", TS: fTS})
	write("go-features.md", s2.Text)
}
