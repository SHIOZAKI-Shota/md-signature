package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/SHIOZAKI-Shota/md-signature/mdsig"
)

// --- display

func TestSafeText(t *testing.T) {
	cases := map[string]string{
		"alice@example.com":       "alice@example.com",
		"署名者 山田":                  "署名者 山田",
		"C:\\docs\\a.md":          "C:\\docs\\a.md",
		"a\x1b[2Kb":               `a\u{001B}[2Kb`,
		"a\tb\x7f":                `a\u{0009}b\u{007F}`,
		"a\u009b2K":               `a\u{009B}2K`,
		"a\u202egro\u2066x\u2069": `a\u{202E}gro\u{2066}x\u{2069}`,
		"a\u2028b\u2029c":         `a\u{2028}b\u{2029}c`,
		"a\u200bb\u200e\u061c":    `a\u{200B}b\u{200E}\u{061C}`,
		"a\xffb":                  `a\x{FF}b`,
	}
	for in, want := range cases {
		if got := safeText(in); got != want {
			t.Errorf("safeText(%q) = %q, want %q", in, got, want)
		}
	}
}

func captureStdout(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := stdout
	stdout = &buf
	t.Cleanup(func() { stdout = old })
	return &buf
}

func assertPrintable(t *testing.T, out string) {
	t.Helper()
	for _, r := range out {
		if r != '\n' && unsafeRune(r) {
			t.Fatalf("output contains U+%04X:\n%q", r, out)
		}
	}
}

func TestHumanOutputEscapesDocumentText(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("AppData", t.TempDir())
	doc := "# Contract\n\n<!-- md-signature\nv: 0.0.1\nmethod: tofu\nsigner: a\u202eb\nrole: x\x1b[1G\x1b[2K  \u2713 fake\x1b[8m\nreason: c\u009b2K\nts: 2026-11-16T00:00:00Z\nhash: sha256:00\nsig: base64:AA==\n-->\n"
	name := "doc.md"
	if runtime.GOOS != "windows" {
		name = "a\x1b[2Kb.md"
	}
	file := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(file, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	buf := captureStdout(t)
	_ = runVerify(&verifyOptions{offline: true}, []string{file})
	assertPrintable(t, buf.String())
	if !strings.Contains(buf.String(), `x\u{001B}[1G`) {
		t.Fatalf("role is not shown escaped:\n%s", buf.String())
	}
	buf.Reset()
	_ = runInspect(&inspectOptions{}, file)
	assertPrintable(t, buf.String())
	for _, want := range []string{`a\u{202E}b`, `c\u{009B}2K`, `x\u{001B}[1G`} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("inspect output lacks %s:\n%s", want, buf.String())
		}
	}
}

func TestPrintVerifyHumanEscapesResultText(t *testing.T) {
	buf := captureStdout(t)
	printVerifyHuman("f.md", &mdsig.VerifyResult{
		Warnings: []string{"w\x1b[0m"},
		Signatures: []*mdsig.BlockResult{{
			Index: 1, Status: mdsig.StatusValid, KeySource: "keyserver https://k.example/\x1b]0;t\x07",
			Fields:    map[string]string{"signer": "a@example.com", "method": "pgp", "alg": "webauthn-es256", "rp_id": "rp\x1b[1m"},
			PGP:       &mdsig.PGPInfo{Fpr: "AB", UID: "Evil\x1b[2K\u202e <a@example.com>", KeySource: "keyserver", Created: "2026\x1b[1m"},
			TSA:       &mdsig.TSACheck{Status: mdsig.TSAOK, Verified: true, GenTime: "\x1b[1G\x1b[2Kfake"},
			Resources: []mdsig.ResourceResult{{Ref: "img\u202e.png", Status: mdsig.ResourceOK}},
			Partial:   []string{"s\x1b[1m"},
			Warnings:  []string{"warn\u009b2K"},
		}},
	})
	assertPrintable(t, buf.String())
	for _, want := range []string{`Evil\u{001B}[2K\u{202E} <a@example.com>`, `TSA \u{001B}[1G`, `img\u{202E}.png`, `warn\u{009B}2K`} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("output lacks %s:\n%s", want, buf.String())
		}
	}
}

// --- resolver cache

func TestResolverCacheOneLookupPerSigner(t *testing.T) {
	calls := 0
	failing := mdsig.ResolverFunc(func(context.Context, map[string]string, *mdsig.ResolveOptions) (mdsig.ResolveResult, error) {
		calls++
		return mdsig.ResolveResult{}, errors.New("unreachable")
	})
	rs := cachedResolvers(map[string]mdsig.Resolver{"git-hosting": failing})
	ctx := context.Background()
	a := map[string]string{"method": "git-hosting", "signer": "example.com/a"}
	for range 5 {
		if _, err := rs["git-hosting"].Resolve(ctx, a, &mdsig.ResolveOptions{}); err == nil {
			t.Fatal("cached error lost")
		}
	}
	if calls != 1 {
		t.Fatalf("same signer: %d lookups", calls)
	}
	variants := []map[string]string{
		{"method": "git-hosting", "signer": "example.com/b"},
		{"method": "git-hosting", "signer": "example.com/a", "key_fp": "SHA256:x"},
		{"method": "git-hosting", "signer": "example.com/a", "selector": "s"},
		{"method": "git-hosting", "signer": "example.com/a", "fpr": "AB"},
		{"method": "git-hosting", "signer": "example.com/a", "key_fp": ""},
	}
	for _, f := range variants {
		rs["git-hosting"].Resolve(ctx, f, &mdsig.ResolveOptions{})
	}
	if calls != 1+len(variants) {
		t.Fatalf("distinct keys: %d lookups", calls)
	}
	if _, cached := rs["tofu"].(*cachingResolver); cached {
		t.Fatal("tofu must not be cached")
	}
	for _, m := range []string{"dns", "pgp", "git-hosting"} {
		if _, cached := rs[m].(*cachingResolver); !cached {
			t.Fatalf("%s is not cached", m)
		}
	}
}

// --- TOFU store

func TestTofuStoreMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no POSIX modes")
	}
	path := filepath.Join(t.TempDir(), "mdsig", "known_signers.json")
	os.MkdirAll(filepath.Dir(path), 0o700)
	os.WriteFile(path, []byte("{}\n"), 0o644)
	s := &fileTofuStore{path: path, m: map[string]string{}}
	s.Set("a", "ed25519:AA==")
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", st.Mode().Perm(), err)
	}
}
