package cli

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyPgpExitCodes(t *testing.T) {
	cases := map[string]int{
		"valid-pgp-ed25519.md":     exitOK,
		"valid-pgp-v6.md":          exitOK,
		"valid-pgp-gpg.md":         exitOK,
		"tampered-pgp.md":          exitFail,
		"malformed-pgp-alg.md":     exitFail,
		"pgp-revoked-key.md":       exitFail,
		"pgp-wrong-uid.md":         exitNetwork,
		"pgp-subkey-no-backsig.md": exitNetwork,
		"pgp-v6-no-direct-key.md":  exitNetwork,
	}
	for file, want := range cases {
		isolate(t)
		o := examplesOptions(t)
		o.quiet = true
		if got := exitCode(runVerify(o, []string{ex(file)})); got != want {
			t.Errorf("%s: exit %d, want %d", file, got, want)
		}
	}
}

func TestVerifyPgpOutput(t *testing.T) {
	out, _ := isolate(t)
	o := examplesOptions(t)
	o.json = true
	if err := runVerify(o, []string{ex("valid-pgp-gpg.md"), ex("valid-single.md")}); err != nil {
		t.Fatal(err)
	}
	var res struct {
		Files []struct {
			Signatures []map[string]json.RawMessage `json:"signatures"`
		} `json:"files"`
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	var pgp map[string]*string
	if err := json.Unmarshal(res.Files[0].Signatures[0]["pgp"], &pgp); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{"fpr": "275E2B9A1BC461282279D5335E7F0C0F098A2BC1", "uid": "Frank Test <frank@example.org>", "key_alg": "rsa2048", "key_source": "keyserver", "created": "2026-11-16T09:00:00Z"} {
		if pgp[k] == nil || *pgp[k] != want {
			t.Errorf("pgp.%s = %v, want %s", k, pgp[k], want)
		}
	}
	if string(res.Files[1].Signatures[0]["pgp"]) != "null" {
		t.Errorf("pgp for tofu: %s", res.Files[1].Signatures[0]["pgp"])
	}

	out.Reset()
	o = examplesOptions(t)
	_ = runVerify(o, []string{ex("valid-pgp-ed25519.md")})
	for _, want := range []string{
		"OpenPGP DC169A0E529FF31AB87FC0B8EF37BA0F059AD959  Dave Test <dave@example.org>  (key from WKD https://example.org/.well-known/openpgpkey/hu/",
		"OpenPGP signature time: 2026-11-16T09:00:00Z (claimed by the signer, not a TSA time)",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s", want, out.String())
		}
	}
}

func TestVerifyPgpKeyring(t *testing.T) {
	isolate(t)
	cert, err := os.ReadFile(ex("pgp/erin.pub.asc"))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	o := &verifyOptions{quiet: true, offline: true, pgpKeyring: func(context.Context, string) ([]byte, error) { calls++; return cert, nil }}
	o.now = examplesOptions(t).now
	if c := exitCode(runVerify(o, []string{ex("valid-pgp-v6.md")})); c != exitOK || calls != 1 {
		t.Errorf("keyring: exit %d, calls %d", c, calls)
	}
	o.noKeyring = true
	if c := exitCode(runVerify(o, []string{ex("valid-pgp-v6.md")})); c != exitNetwork || calls != 1 {
		t.Errorf("--no-keyring --offline: exit %d, calls %d", c, calls)
	}
}

func TestSignPgpKeyFile(t *testing.T) {
	_, errb := isolate(t)
	dir := t.TempDir()
	doc := filepath.Join(dir, "doc.md")
	if err := os.WriteFile(doc, []byte("# Doc\n\nBody.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	frank := ex("pgp/frank.sec.asc")
	t.Setenv("MDSIG_PGP_PASSPHRASE", "wrong")
	if c := exitCode(runSign(&signOptions{method: "pgp", pgpKey: frank}, doc)); c != exitIO {
		t.Errorf("wrong passphrase: %d", c)
	}
	t.Setenv("MDSIG_PGP_PASSPHRASE", "test")
	if c := exitCode(runSign(&signOptions{method: "pgp", pgpKey: frank, signer: "other@example.org"}, doc)); c != exitUsage {
		t.Errorf("foreign email: %d", c)
	}
	if err := runSign(&signOptions{method: "pgp", pgpKey: frank, role: "author"}, doc); err != nil {
		t.Fatal(err, errb.String())
	}
	b, _ := os.ReadFile(doc)
	for _, want := range []string{"signer: frank@example.org\n", "fpr: 275E2B9A1BC461282279D5335E7F0C0F098A2BC1\n", "alg: openpgp\n"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %q:\n%s", want, b)
		}
	}
	cert, _ := os.ReadFile(ex("pgp/frank.pub.asc"))
	o := &verifyOptions{quiet: true, offline: true, pgpKeyring: func(context.Context, string) ([]byte, error) { return cert, nil }}
	if c := exitCode(runVerify(o, []string{doc})); c != exitOK {
		t.Errorf("verify: %d", c)
	}

	for _, bad := range []*signOptions{
		{method: "tofu", signer: "x", localUser: "a"},
		{method: "pgp", pgpKey: frank, localUser: "a"},
		{method: "pgp", pgpKey: frank, keyPath: "k"},
	} {
		if c := exitCode(runSign(bad, doc)); c != exitUsage {
			t.Errorf("%+v: %d", bad, c)
		}
	}
	if c := exitCode(runSign(&signOptions{method: "pgp", pgpKey: filepath.Join(dir, "none.asc")}, doc)); c != exitIO {
		t.Errorf("missing key file: %d", c)
	}
}

func TestSignPgpWithoutGpg(t *testing.T) {
	isolate(t)
	old := gpgProgram
	gpgProgram = "mdsig-no-such-gpg"
	t.Cleanup(func() { gpgProgram = old })
	doc := filepath.Join(t.TempDir(), "doc.md")
	_ = os.WriteFile(doc, []byte("# Doc\n"), 0o644)
	if c := exitCode(runSign(&signOptions{method: "pgp", signer: "a@example.org"}, doc)); c != exitUsage {
		t.Errorf("no gpg: %d", c)
	}
	if gpgKeyring() != nil {
		t.Error("keyring hook without gpg")
	}
}

func TestParseGpgSecretKeys(t *testing.T) {
	out := strings.Join([]string{
		"sec:u:255:22:AAAA:1700000000:::u:::cSC:::+:::ed25519:::0:",
		"fpr:::::::::1111111111111111111111111111111111111111:",
		"grp:::::::::0000:",
		`uid:u::::1700000000::H::Alice \x3a Test <alice@example.org>::::::::::0:`,
		"uid:r::::1700000000::H::Old <old@example.org>::::::::::0:",
		"ssb:u:256:19:BBBB:1700000100::::::s:::+:::nistp256::",
		"fpr:::::::::2222222222222222222222222222222222222222:",
		"ssb:u:256:22:CCCC:1700000200::::::s:::#:::ed25519::",
		"fpr:::::::::3333333333333333333333333333333333333333:",
		"sec:u:3072:1:DDDD:1600000000:::u:::scSC:::+::::::0:",
		"fpr:::::::::4444444444444444444444444444444444444444:",
		"uid:u::::1600000000::H::Bob <bob@example.org>::::::::::0:",
		"",
	}, "\r\n")
	keys := parseGpgSecretKeys(out)
	if len(keys) != 2 {
		t.Fatal(len(keys))
	}
	if keys[0].fpr != "1111111111111111111111111111111111111111" || keys[0].signingFpr() != "2222222222222222222222222222222222222222" {
		t.Error(keys[0].fpr, keys[0].signingFpr())
	}
	if len(keys[0].uids) != 1 || keys[0].uids[0] != "Alice : Test <alice@example.org>" {
		t.Error(keys[0].uids)
	}
	if keys[1].signingFpr() != "4444444444444444444444444444444444444444" {
		t.Error(keys[1].signingFpr())
	}
}

func TestRevokePgp(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	p := func(n string) string { return filepath.Join(dir, n) }
	dave := ex("pgp/dave.sec.asc")
	const revURL = "https://example.org/.well-known/mdsig-revoked.md"
	src, err := os.ReadFile(ex("pgp-revoked.md"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p("doc.md"), src, 0o644); err != nil {
		t.Fatal(err)
	}
	verifyWith := func(file, list string) int {
		o := examplesOptions(t)
		o.quiet = true
		base := o.fetchClient
		o.fetchClient = serveClient(func(u string) ([]byte, bool) {
			if u == revURL {
				return []byte(list), true
			}
			resp, err := base.Get(u)
			if err != nil {
				return nil, false
			}
			defer resp.Body.Close()
			b, err := io.ReadAll(resp.Body)
			return b, err == nil
		})
		return exitCode(runVerify(o, []string{file}))
	}
	readList := func() string {
		b, err := os.ReadFile(p("rev.md"))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	if err := runRevoke(&revokeOptions{list: p("rev.md"), method: "pgp", pgpKey: dave}, p("doc.md")); err != nil {
		t.Fatal(err)
	}
	list := readList()
	if !strings.Contains(list, "signer: dave@example.org") || strings.Contains(list, "keyserver:") || strings.Count(list, "revoked: sha256:") != 1 {
		t.Fatalf("list:\n%s", list)
	}
	if c := verifyWith(p("doc.md"), list); c != exitFail {
		t.Errorf("revoked doc: %d", c)
	}

	if c := exitCode(runRevoke(&revokeOptions{list: p("rev3.md"), method: "tofu", signer: "x", pgpKey: dave}, p("doc.md"))); c != exitUsage {
		t.Errorf("--pgp-key with tofu: %d", c)
	}
}
