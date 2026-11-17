package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
		Now   string            `json:"now"`
		Fetch map[string]string `json:"fetch"`
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
		"pending-require.md":         exitPending,
		"complete-require.md":        exitOK,
		"require-serial-complete.md": exitOK,
		"require-serial-pending.md":  exitPending,
		"require-serial-guide.md":    exitOK,
		"require-serial-strict.md":   exitFail,
		"require-any-pending.md":     exitPending,
		"require-any-complete.md":    exitOK,
		"malformed-require-steps.md": exitFail,
		"mixed-versions.md":          exitOK,
		"revoked.md":                 exitFail,
		"not-revoked.md":             exitOK,
		"unknown-field.md":           exitFail,
		"valid-resources.md":         exitOK,
		"tampered-resource.md":       exitFail,
		"valid-scoped-edited.md":     exitOK,
		"expired.md":                 exitFail,
		"valid-webauthn.md":          exitOK,
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
	want := []string{"index", "line", "status", "code", "message", "fields", "hash_ok", "partial", "key_source", "webauthn", "resources", "revocation", "tsa", "warnings"}
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
	check(sig(0)["resources"], `[{"ref":"./assets/diagram.svg","status":"ok","detail":null},{"ref":"https://example.com/chart.png","status":"not-checked","detail":"remote resources are fetched only on request"}]`)
	check(sig(0)["partial"], `null`)
	check(res.Files[1]["ok"], `true`)
	check(res.Files[1]["agreement"], `{"status":"pending","required":[{"method":"dns","signer":"example.com","role":"approver","declared_by":1,"step":1,"any":1}],"missing":[{"method":"dns","signer":"example.com","role":"approver","declared_by":1,"step":1,"any":1,"need":1}],"violations":[]}`)
	check(res.Files[0]["agreement"], `{"status":"none","required":[],"missing":[],"violations":[]}`)
	check(sig(2)["partial"], `{"sections":["terms","fees"]}`)
	check(sig(3)["webauthn"], `{"rp_id":"mdsig.dev","origin":"https://mdsig.dev","user_verified":true}`)
	check(sig(4)["revocation"], `{"status":"not-revoked","detail":null}`)
}

func TestHumanOutputRequireSteps(t *testing.T) {
	out, _ := isolate(t)
	o := examplesOptions(t)
	_ = runVerify(o, []string{ex("require-serial-pending.md"), ex("require-serial-guide.md"), ex("require-serial-strict.md"), ex("require-any-pending.md")})
	s := out.String()
	for _, want := range []string{
		"Agreement: pending (step 2 needs 1 more of: tofu:bob@laptop reviewer [signed before the previous step, sign again])",
		"! order not followed: #2 tofu:bob@laptop reviewer signed for step 2 before step 1 was complete",
		"Agreement: violated (#2 tofu:bob@laptop reviewer signed for step 2 before step 1 was complete)",
		"Agreement: pending (step 1 needs 1 more of: tofu:carol@laptop, tofu:dave@laptop)",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
}

func TestHumanOutput(t *testing.T) {
	out, _ := isolate(t)
	o := examplesOptions(t)
	_ = runVerify(o, []string{ex("valid-resources.md"), ex("pending-require.md"), ex("valid-scoped-edited.md"), ex("valid-webauthn.md")})
	s := out.String()
	for _, want := range []string{
		"resources: ✓ ./assets/diagram.svg  - https://example.com/chart.png (not checked)",
		"Agreement: pending (missing dns:example.com approver)",
		"partial: terms, fees",
		"passkey (rp_id mdsig.dev)",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
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
	if _, err := parseExtensionFlags(&signOptions{require: []string{"order guide", "step 1", "dns:a.com approver", "step 2 any 1", "tofu:b", "tofu:c"}}, now); err != nil {
		t.Error(err)
	}
	if e := ok(&signOptions{expires: "2027-01-01T00:00:00Z", scope: "terms, section:fees"}); e.expires != "2027-01-01T00:00:00Z" || strings.Join(e.scope, ",") != "terms,fees" {
		t.Error(e)
	}
	for _, bad := range []*signOptions{
		{expires: "tomorrow"}, {expires: "0d"}, {expires: "2027-02-30T00:00:00Z"}, {expires: "30m"},
		{scope: "Terms"}, {scope: "a,a"}, {scope: ","},
		{require: []string{"nope"}}, {require: []string{"dns:a.com approver extra"}}, {require: []string{"dns:a--b"}},
		{require: []string{"step 1"}}, {require: []string{"step 2", "dns:a.com"}}, {require: []string{"dns:a.com", "order strict"}}, {require: []string{"step 1 any 2", "dns:a.com"}},
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
	sign := &signOptions{method: "tofu", signer: "alice@laptop", keyPath: p("alice"), scope: "terms", require: []string{"tofu:bob@laptop approver"},
		resources: []string{"data.csv"}, autoResources: true, expires: "30d", revocationURL: revURL}
	if err := runSign(sign, p("doc.md")); err != nil {
		t.Fatal(err, errb.String())
	}
	signed, _ := os.ReadFile(p("doc.md"))
	for _, want := range []string{"scope: section:terms\n", "require: tofu:bob@laptop approver\n", " data.csv\n", " img/a.png\n", "revocation_url: " + revURL + "\n", "expires: "} {
		if !strings.Contains(string(signed), want) {
			t.Errorf("missing %q:\n%s", want, signed)
		}
	}
	if c := exitCode(runSign(&signOptions{method: "tofu", signer: "x", keyPath: p("alice"), resources: []string{"nope.png"}}, p("doc.md"))); c != exitIO {
		t.Errorf("missing resource: %d", c)
	}
	if c := exitCode(runSign(&signOptions{method: "tofu", signer: "x", keyPath: p("alice"), scope: "nope"}, p("doc.md"))); c != exitUsage {
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
