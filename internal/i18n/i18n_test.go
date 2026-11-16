package i18n

import "testing"

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
