package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mdsig.dev/internal/i18n"
	"mdsig.dev/mdsig"
)

var examplesDir = filepath.Join("..", "..", "examples")

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func serveClient(serve func(url string) ([]byte, bool)) *http.Client {
	return &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		b, ok := serve(r.URL.String())
		if !ok {
			return nil, fmt.Errorf("network disabled in tests: %s", r.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(b)), ContentLength: int64(len(b)), Header: http.Header{}, Request: r}, nil
	})}
}

func isolate(t *testing.T) (*bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	var out, errb bytes.Buffer
	oldOut, oldErr := stdout, stderr
	stdout, stderr = &out, &errb
	i18n.Set(i18n.EN)
	t.Cleanup(func() { stdout, stderr = oldOut, oldErr })
	return &out, &errb
}

func examplesOptions(t *testing.T) *verifyOptions {
	t.Helper()
	var keys struct {
		GitHosting map[string]struct {
			KeysFile string `json:"keys_file"`
		} `json:"git-hosting"`
		DNS map[string]struct {
			TXT string `json:"txt"`
		} `json:"dns"`
		DNSRecords map[string]json.RawMessage `json:"dns_records"`
		Now        string                     `json:"now"`
		Fetch      map[string]string          `json:"fetch"`
	}
	b, err := os.ReadFile(filepath.Join(examplesDir, "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &keys); err != nil {
		t.Fatal(err)
	}
	now, _ := time.Parse(time.RFC3339, keys.Now)
	return &verifyOptions{
		now:       now,
		noKeyring: true,
		resolvers: map[string]mdsig.Resolver{
			"git-hosting": mdsig.ResolverFunc(func(_ context.Context, f map[string]string, _ *mdsig.ResolveOptions) (mdsig.ResolveResult, error) {
				return mdsig.GitHostingKeysFromText(f, "keys.json", keys.GitHosting[f["signer"]].KeysFile)
			}),
			"dns": mdsig.ResolverFunc(func(_ context.Context, f map[string]string, _ *mdsig.ResolveOptions) (mdsig.ResolveResult, error) {
				return mdsig.DNSKeysFromRecords(f, mdsig.DNSName(f), []string{keys.DNS[mdsig.DNSName(f)].TXT})
			}),
		},
		lookupTXT: func(_ context.Context, name string) ([]string, error) {
			raw, ok := keys.DNSRecords[name]
			if !ok {
				return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
			}
			var recs []string
			if json.Unmarshal(raw, &recs) != nil {
				return nil, &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
			}
			return recs, nil
		},
		dohEndpoints: []string{},
		fetchClient: serveClient(func(u string) ([]byte, bool) {
			f, ok := keys.Fetch[u]
			if !ok {
				return nil, false
			}
			b, err := os.ReadFile(filepath.Join(examplesDir, filepath.FromSlash(f)))
			return b, err == nil
		}),
	}
}

func exitCode(err error) int {
	if err == nil {
		return exitOK
	}
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	return -1
}

func ex(name string) string { return filepath.Join(examplesDir, name) }

func TestSeverity(t *testing.T) {
	order := []int{exitOK, exitPending, exitNetwork, exitIO, exitFail}
	for i := range order {
		for j := range order {
			want := order[max(i, j)]
			if got := worse(order[i], order[j]); got != want {
				t.Errorf("worse(%d,%d) = %d, want %d", order[i], order[j], got, want)
			}
		}
	}
}

func TestVerifyExitCodes(t *testing.T) {
	cases := map[string]int{
		"pending-require.md":               exitPending,
		"complete-require.md":              exitOK,
		"require-serial-complete.md":       exitOK,
		"require-serial-pending.md":        exitPending,
		"require-serial-guide.md":          exitOK,
		"require-serial-strict.md":         exitFail,
		"require-any-pending.md":           exitPending,
		"require-any-complete.md":          exitOK,
		"malformed-require-steps.md":       exitFail,
		"agent-accepted.md":                exitPending,
		"agent-approved.md":                exitOK,
		"require-member-dns.md":            exitOK,
		"require-member-unreachable.md":    exitNetwork,
		"require-declarer-unresolved.md":   exitNetwork,
		"unsupported-require-attribute.md": exitFail,
		"unsupported-version-v004.md":      exitFail,
		"revoked.md":                       exitFail,
		"not-revoked.md":                   exitOK,
		"unknown-field.md":                 exitFail,
		"valid-resources.md":               exitOK,
		"tampered-resource.md":             exitFail,
		"valid-scoped-edited.md":           exitOK,
		"expired.md":                       exitFail,
		"valid-webauthn.md":                exitOK,
	}
	for file, want := range cases {
		isolate(t)
		o := examplesOptions(t)
		o.quiet = true
		if got := exitCode(runVerify(o, []string{ex(file)})); got != want {
			t.Errorf("%s: exit %d, want %d", file, got, want)
		}
	}
	isolate(t)
	o := examplesOptions(t)
	o.quiet = true
	if got := exitCode(runVerify(o, []string{ex("valid-single.md"), ex("pending-require.md")})); got != exitPending {
		t.Errorf("0+5: %d", got)
	}
	if got := exitCode(runVerify(o, []string{ex("pending-require.md"), ex("no-such-file.md")})); got != exitIO {
		t.Errorf("5+4: %d", got)
	}
	if got := exitCode(runVerify(o, []string{ex("no-such-file.md"), ex("tampered.md")})); got != exitFail {
		t.Errorf("4+1: %d", got)
	}
	o = &verifyOptions{quiet: true, offline: true}
	if got := exitCode(runVerify(o, []string{ex("pending-require.md")})); got != exitNetwork {
		t.Errorf("offline pending: %d", got)
	}
	if got := exitCode(runVerify(o, []string{ex("complete-require.md")})); got != exitNetwork {
		t.Errorf("offline complete-require: %d", got)
	}
}

func TestVerifyJSON(t *testing.T) {
	out, _ := isolate(t)
	o := examplesOptions(t)
	o.json = true
	err := runVerify(o, []string{ex("valid-resources.md"), ex("pending-require.md"), ex("valid-scoped-edited.md"), ex("valid-webauthn.md"), ex("not-revoked.md")})
	if exitCode(err) != exitPending {
		t.Fatal(err)
	}
	var res struct {
		Files []map[string]json.RawMessage `json:"files"`
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err, out.String())
	}
	sig := func(i int) map[string]json.RawMessage {
		var sigs []map[string]json.RawMessage
		_ = json.Unmarshal(res.Files[i]["signatures"], &sigs)
		return sigs[0]
	}
	want := []string{"index", "line", "status", "code", "message", "fields", "display_name", "hash_ok", "partial", "key_source", "tofu", "webauthn", "pgp", "resources", "revocation", "tsa", "warnings"}
	for _, k := range want {
		if _, ok := sig(0)[k]; !ok {
			t.Errorf("signature JSON lacks %q", k)
		}
	}
	for _, k := range []string{"file", "ok", "error", "warnings", "agreement", "signatures"} {
		if _, ok := res.Files[0][k]; !ok {
			t.Errorf("file JSON lacks %q", k)
		}
	}
	check := func(got json.RawMessage, want string) {
		t.Helper()
		var a, b any
		_ = json.Unmarshal(got, &a)
		_ = json.Unmarshal([]byte(want), &b)
		ga, _ := json.Marshal(a)
		gb, _ := json.Marshal(b)
		if !bytes.Equal(ga, gb) {
			t.Errorf("got %s\nwant %s", ga, gb)
		}
	}
	check(sig(0)["resources"], `[{"ref":"assets/diagram.svg","status":"ok","detail":null},{"ref":"https://example.com/chart.png","status":"not-checked","detail":"remote resources are fetched only on request"}]`)
	check(sig(0)["partial"], `null`)
	check(res.Files[1]["ok"], `true`)
	req := `{"declared_by":1,"step":1,"any":null,"line":1,"method":"dns","signer":"example.com","pattern":false,"attributes":{"role":"approver"}}`
	check(res.Files[1]["agreement"], `{"status":"pending","required":[`+req+`],"missing":[{"declared_by":1,"step":1,"any":null,"line":1,"method":"dns","signer":"example.com","pattern":false,"attributes":{"role":"approver"},"need":1,"rejected":[]}],"violations":[],"next":[{"declared_by":1,"step":1,"need":1,"candidates":[`+req+`],"later":[]}],"satisfied":[],"declarations":[{"declared_by":1,"order":"pending","status":"pending","detail":null,"steps":[{"step":1,"any":null,"need":1,"count":0,"complete":false,"blocked_by":null,"lines":[{"line":1,"blocks":[]}]}]}]}`)
	check(res.Files[0]["agreement"], `{"status":"none","required":[],"missing":[],"violations":[],"next":[],"satisfied":[],"declarations":[]}`)
	check(sig(2)["partial"], `{"sections":["terms","fees"]}`)
	check(sig(3)["webauthn"], `{"rp_id":"mdsig.dev","origin":"https://mdsig.dev","user_verified":true,"backup_eligible":false,"backed_up":false}`)
	check(sig(4)["revocation"], `{"status":"not-revoked","detail":null}`)
}

func TestHumanOutputRequireSteps(t *testing.T) {
	out, _ := isolate(t)
	o := examplesOptions(t)
	_ = runVerify(o, []string{ex("require-serial-pending.md"), ex("require-serial-guide.md"), ex("require-serial-strict.md"), ex("require-any-pending.md"), ex("require-member-unreachable.md")})
	s := out.String()
	for _, want := range []string{
		"Agreement: pending\n    next: step 2 needs 1 more\n      tofu:bob@laptop role=reviewer",
		"not counted: #2 tofu:bob@laptop (early: signed before step 1 was complete)",
		"! order not followed: #2 tofu:bob@laptop role=reviewer signed for step 2 before step 1 was complete",
		"Agreement: violated (#2 tofu:bob@laptop role=reviewer signed for step 2 before step 1 was complete)",
		"next: step 1 needs 1 more (any 2 of 3)\n      tofu:carol@laptop\n      tofu:dave@laptop",
		"Agreement: undetermined (a roster cannot be obtained)",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
}

func TestHumanOutput(t *testing.T) {
	out, _ := isolate(t)
	o := examplesOptions(t)
	_ = runVerify(o, []string{ex("valid-resources.md"), ex("pending-require.md"), ex("valid-scoped-edited.md"), ex("valid-webauthn.md"), ex("valid-display-name.md"), ex("valid-cosigned.md")})
	s := out.String()
	for _, want := range []string{
		"resources: ✓ assets/diagram.svg  - https://example.com/chart.png (not checked)",
		"Agreement: pending\n    next: step 1 needs 1 more\n      dns:example.com role=approver",
		"partial: terms, fees",
		"passkey (rp_id mdsig.dev, user verified)",
		"\"Bob Example (営業部)\" (declared)",
		"⏱ by ",
		"#3 tsa       http://ts.ssl.com    TSA ",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
}

func TestRenderAndExplain(t *testing.T) {
	out, _ := isolate(t)
	o := &renderOptions{verifyOptions: *examplesOptions(t)}
	if c := exitCode(runRender(o, ex("table-marker.md"))); c != exitPending {
		t.Fatalf("render exit %d", c)
	}
	page := out.String()
	for _, want := range []string{"<table class=\"mdsig-signatures\">", "class=\"mdsig-unsigned\"", "<header class=\"mdsig-summary ok\">"} {
		if !strings.Contains(page, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Count(page, "<article class=\"mdsig-body\">") != 2 || strings.Index(page, "mdsig-table") > strings.LastIndex(page, "mdsig-body") {
		t.Errorf("the table is not placed at the marker:\n%s", page)
	}
	if strings.Contains(page, "<script") {
		t.Error("script in the page")
	}
	out.Reset()
	if err := runRequireExplain("step\n  dns:example.com role=approver\nstep any=2\n  dns:*.example.com member_of=dns:example.com", false); err != nil {
		t.Fatal(err)
	}
	if want := "order: pending (signatures before their turn are not counted)\nstep 1: all of\n  dns:example.com with role approver\nstep 2: any 2 different signers of\n  any subdomain of example.com (not example.com itself), on the DNS roster of example.com, not the declaring signer\n"; out.String() != want {
		t.Errorf("explain:\n%s", out.String())
	}
	if c := exitCode(runRequireExplain("dns:Example.com role=approver", false)); c != exitUsage {
		t.Errorf("explain bad value: %d", c)
	}
	if c := exitCode(runRequireExplain("dns:example.com x_budget=1", false)); c != exitOK {
		t.Errorf("explain unknown attribute: %d", c)
	}
	out.Reset()
	if err := runRequireExplain("step any=1\n  tofu:bob\n  dns:a.example", true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"any": 1`) || !strings.Contains(out.String(), `tofu:bob has no pubkey=`) {
		t.Errorf("explain json:\n%s", out.String())
	}
}

func TestMemberRecord(t *testing.T) {
	out, _ := isolate(t)
	if err := runMemberRecord("dns:A.example.com", "corp.example", false, nil); err != nil {
		t.Fatal(err)
	}
	if want := "zyjnbt5iuukqrpbqryna3zkgv3n5zpgouvyzfud5cx2odbzcbrdq._member._mdsig.corp.example. IN TXT \"v=mdsig1; m=dns:a.example.com\"\n"; out.String() != want {
		t.Errorf("got %q", out.String())
	}
	for _, bad := range [][2]string{{"dns:*.example.com", "corp.example"}, {"dns:a.example.com", "Corp.example"}, {"nocolon", "corp.example"}, {"tofu:a b", "corp.example"}} {
		if c := exitCode(runMemberRecord(bad[0], bad[1], false, nil)); c != exitUsage {
			t.Errorf("%v: %d", bad, c)
		}
	}
	o := examplesOptions(t)
	ro := &mdsig.ResolveOptions{LookupTXT: o.lookupTXT, DoHEndpoints: []string{}}
	for id, want := range map[string]int{"dns:a.example.com": exitOK, "dns:b.example.com": exitFail, "dns:someone.example": exitFail} {
		if c := exitCode(runMemberRecord(id, "corp.example", true, ro)); c != want {
			t.Errorf("%s: %d, want %d", id, c, want)
		}
	}
	if c := exitCode(runMemberRecord("dns:a.example.com", "broken.example", true, ro)); c != exitNetwork {
		t.Errorf("SERVFAIL: %d", c)
	}
}

func TestExtensionFlags(t *testing.T) {
	now := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	ok := func(o *signOptions) *signExtensions {
		t.Helper()
		e, err := parseExtensionFlags(o, now)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	if e := ok(&signOptions{expires: "30d"}); e.expires != "2026-12-16T09:00:00Z" {
		t.Error(e.expires)
	}
	if e := ok(&signOptions{expires: "12h"}); e.expires != "2026-11-16T21:00:00Z" {
		t.Error(e.expires)
	}
	if e := ok(&signOptions{require: []string{"order mode=guide", "step", "dns:a.com role=approver", "  step any=1", "tofu:b", "tofu:c"}}); strings.Join(e.require, "|") != "order mode=guide|step|  dns:a.com role=approver|step any=1|  tofu:b|  tofu:c" {
		t.Error(e.require)
	}
	if e := ok(&signOptions{expires: "2027-01-01T00:00:00Z", scope: []string{"terms, fees", "notes"}}); e.expires != "2027-01-01T00:00:00Z" || strings.Join(e.scope, ",") != "terms,fees,notes" {
		t.Error(e)
	}
	if e := ok(&signOptions{resources: []string{"./assets/meeting notes.txt"}}); e == nil || encodeLocalRef(trimDotSlash("./assets/meeting notes.txt")) != "assets/meeting%20notes.txt" {
		t.Error("percent-encoding")
	}
	for _, bad := range []*signOptions{
		{expires: "tomorrow"}, {expires: "0d"}, {expires: "2027-02-30T00:00:00Z"}, {expires: "30m"},
		{scope: []string{"Terms"}}, {scope: []string{"a,a"}}, {scope: []string{","}}, {scope: []string{"section:terms"}},
		{require: []string{"nope"}}, {require: []string{"dns:a.com approver"}}, {require: []string{"dns:a-->b"}},
		{require: []string{"step"}}, {require: []string{"step 2", "dns:a.com"}}, {require: []string{"dns:a.com", "order mode=strict"}}, {require: []string{"step any=2", "dns:a.com"}},
		{require: []string{"order mode=strict", "dns:*"}}, {require: []string{"dns:a.com x_budget=1"}},
		{resources: []string{"../x.png"}}, {resources: []string{"/etc/passwd"}}, {resources: []string{"http://example.com/x"}},
		{revocationURL: "http://example.com/r.md"}, {revocationURL: "https://example.com/a b"},
	} {
		if _, err := parseExtensionFlags(bad, now); exitCode(err) != exitUsage {
			t.Errorf("%+v: %v", bad, err)
		}
	}
}

func TestSignRevokeFlow(t *testing.T) {
	_, errb := isolate(t)
	dir := t.TempDir()
	write := func(name, s string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	p := func(name string) string { return filepath.Join(dir, name) }
	for _, k := range []string{"alice", "bob"} {
		if err := runKeygen(&keygenOptions{out: p(k)}); err != nil {
			t.Fatal(err)
		}
	}
	write("doc.md", "# SOW\n\n<!-- mdsig:section terms -->\nPay in 30 days.\n<!-- /mdsig:section -->\n\nNotes.\n\n![a](img/a.png)\n")
	_ = os.MkdirAll(p("img"), 0o755)
	write("img/a.png", "PNG")
	write("data.csv", "x,1\n")

	revURL := "https://lists.example/alice.md"
	sign := &signOptions{method: "tofu", signer: "alice@laptop", keyPath: p("alice"), scope: []string{"terms"}, require: []string{"tofu:bob@laptop role=approver"},
		resources: []string{"data.csv"}, autoResources: true, expires: "30d", revocationURL: revURL}
	if err := runSign(sign, p("doc.md")); err != nil {
		t.Fatal(err, errb.String())
	}
	signed, _ := os.ReadFile(p("doc.md"))
	for _, want := range []string{"scope: terms\n", "require: tofu:bob@laptop role=approver\n", " data.csv hash=sha256:", " img/a.png hash=sha256:", "revocation_url: " + revURL + "\n", "expires: "} {
		if !strings.Contains(string(signed), want) {
			t.Errorf("missing %q:\n%s", want, signed)
		}
	}
	if c := exitCode(runSign(&signOptions{method: "tofu", signer: "x", keyPath: p("alice"), resources: []string{"nope.png"}}, p("doc.md"))); c != exitIO {
		t.Errorf("missing resource: %d", c)
	}
	if c := exitCode(runSign(&signOptions{method: "tofu", signer: "x", keyPath: p("alice"), scope: []string{"nope"}}, p("doc.md"))); c != exitUsage {
		t.Errorf("unknown section: %d", c)
	}

	list := ""
	vo := func() *verifyOptions {
		return &verifyOptions{quiet: true, fetchClient: serveClient(func(u string) ([]byte, bool) {
			if u != revURL || list == "" {
				return nil, false
			}
			return []byte(list), true
		})}
	}
	unpublished := func() *verifyOptions {
		o := vo()
		o.noRevocation = true
		return o
	}
	if c := exitCode(runVerify(vo(), []string{p("doc.md")})); c != exitNetwork {
		t.Fatalf("list not published yet: %d", c)
	}
	if c := exitCode(runVerify(unpublished(), []string{p("doc.md")})); c != exitPending {
		t.Fatalf("pending: %d", c)
	}
	if err := runSign(&signOptions{method: "tofu", signer: "bob@laptop", keyPath: p("bob"), role: "approver"}, p("doc.md")); err != nil {
		t.Fatal(err)
	}
	if c := exitCode(runVerify(unpublished(), []string{p("doc.md")})); c != exitOK {
		t.Fatalf("complete: %d", c)
	}

	if c := exitCode(runRevoke(&revokeOptions{list: p("rev.md"), method: "tofu", signer: "alice@laptop", keyPath: p("bob")}, p("doc.md"))); c != exitUsage {
		t.Errorf("wrong key: %d", c)
	}
	if _, err := os.Stat(p("rev.md")); err == nil {
		t.Error("list written despite the wrong key")
	}
	errb.Reset()
	if err := runRevoke(&revokeOptions{list: p("rev.md"), method: "tofu", signer: "alice@laptop", keyPath: p("alice")}, p("doc.md")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errb.String(), revURL) {
		t.Errorf("publish URL not printed: %s", errb.String())
	}
	b, _ := os.ReadFile(p("rev.md"))
	list = string(b)
	if strings.Contains(list, "revocation_url") || strings.Count(list, "revoked: sha256:") != 1 {
		t.Fatalf("list:\n%s", list)
	}
	if err := runRevoke(&revokeOptions{list: p("rev.md"), method: "tofu", signer: "alice@laptop", keyPath: p("alice"), index: 1}, p("doc.md")); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(p("rev.md"))
	list = string(b)
	if strings.Count(list, "revoked: sha256:") != 1 || len(mdsig.ParseDocument(list).Chain) != 1 {
		t.Fatalf("list:\n%s", list)
	}
	if c := exitCode(runVerify(vo(), []string{p("doc.md")})); c != exitFail {
		t.Fatalf("revoked: %d", c)
	}
	o := vo()
	o.noRevocation = true
	if c := exitCode(runVerify(o, []string{p("doc.md")})); c != exitOK {
		t.Fatalf("--no-revocation: %d", c)
	}
	if c := exitCode(runRevoke(&revokeOptions{list: p("rev.md"), method: "tofu", signer: "alice@laptop", keyPath: p("alice"), index: 2}, p("doc.md"))); c != exitUsage {
		t.Errorf("index of other signer: %d", c)
	}
}

func TestTimestampRejectsInvalidUTF8(t *testing.T) {
	isolate(t)
	p := filepath.Join(t.TempDir(), "bad.md")
	if err := os.WriteFile(p, []byte("# x\xff\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var ee *exitError
	if err := runTimestamp(&timestampOptions{tsa: "http://127.0.0.1:1/", hash: "sha256"}, p); !errors.As(err, &ee) || ee.code != exitFail {
		t.Fatalf("got %v", err)
	}
}

func TestRenderBodyParts(t *testing.T) {
	marker := func(body string) int {
		_, off, _ := mdsig.FindSignatureMarker(body)
		return off
	}
	body := "See [annex][1].\n\n<!-- mdsig:signatures -->\n\nAfter.\n\n[1]: https://example.com/annex\n"
	parts, err := bodyParts(body, marker(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 2 || !strings.Contains(parts[0], `<a href="https://example.com/annex">annex</a>`) || strings.Contains(parts[0], "raw HTML") || !strings.Contains(parts[1], "After.") {
		t.Errorf("reference across the marker: %q", parts)
	}
	body = "<div>\nArticle 2.\n<!-- mdsig:signatures -->\nArticle 3.\n</div>\n\nTail.\n"
	parts, _ = bodyParts(body, marker(body))
	if len(parts) != 2 || strings.Contains(parts[1], "Article 3.") || strings.TrimSpace(parts[1]) != "<p>Tail.</p>" {
		t.Errorf("marker inside an HTML block: %q", parts)
	}
	parts, _ = bodyParts("Only.\n", -1)
	if len(parts) != 1 {
		t.Errorf("no marker: %q", parts)
	}
}
