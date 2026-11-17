package i18n

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestDetect(t *testing.T) {
	for _, k := range []string{"MDSIG_LANG", "LC_ALL", "LC_MESSAGES", "LANG"} {
		t.Setenv(k, "")
	}
	t.Setenv("LANG", "ja_JP.UTF-8")
	if Detect("") != JA {
		t.Error("LANG=ja_JP.UTF-8 should give ja")
	}
	t.Setenv("LC_ALL", "C")
	if Detect("") != EN {
		t.Error("LC_ALL=C takes precedence and gives en")
	}
	t.Setenv("MDSIG_LANG", "ja")
	if Detect("") != JA {
		t.Error("MDSIG_LANG wins over locale vars")
	}
	if Detect("en") != EN {
		t.Error("--lang wins")
	}
	if _, ok := Parse("fr"); ok {
		t.Error("fr is unsupported")
	}
}

func TestCatalogsComplete(t *testing.T) {
	for k := range en {
		if _, ok := ja[k]; !ok {
			t.Errorf("ja is missing %q", k)
		}
	}
	for k := range ja {
		if _, ok := en[k]; !ok {
			t.Errorf("en is missing %q", k)
		}
	}
	Set(JA)
	defer Set(EN)
	if got := T("sign.done", "a.md", 2, "tofu", "bob"); got != "a.md に署名しました（署名 #2、tofu bob）" {
		t.Error(got)
	}
}

func TestCodeLabels(t *testing.T) {
	codes := map[string]bool{}
	for _, c := range []string{"malformed", "unknown-field", "hash-mismatch", "bad-signature", "scope-missing", "resource-mismatch", "resource-missing", "expired", "revoked", "key-changed", "key-not-published", "unsupported-version", "unsupported-alg", "unsupported-hash", "unsupported-method", "network", "not-found", "offline"} {
		codes[c] = true
	}
	files, err := filepath.Glob("../../mdsig/*.go")
	if err != nil || len(files) == 0 {
		t.Fatal("mdsig sources not found", err)
	}
	re := regexp.MustCompile(`fail\(Status\w+, "([a-z-]+)"|[Cc]ode: +"([a-z-]+)"`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			codes[m[1]+m[2]] = true
		}
	}
	for c := range codes {
		if _, ok := en["code."+c]; !ok {
			t.Errorf("en has no label for code %q", c)
		}
		if _, ok := ja["code."+c]; !ok {
			t.Errorf("ja has no label for code %q", c)
		}
	}
}
