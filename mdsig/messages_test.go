package mdsig

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var japaneseRe = regexp.MustCompile(`[\p{Hiragana}\p{Katakana}\p{Han}]`)

func assertLocalized(t *testing.T, en, where string) {
	t.Helper()
	ja := LocalizeMessage(en, "ja")
	if ja == en {
		t.Errorf("%s: no pattern for %q", where, en)
		return
	}
	for _, part := range strings.Split(ja, "；") {
		if !japaneseRe.MatchString(part) {
			t.Errorf("%s: %q -> %q", where, en, ja)
			return
		}
	}
}

func TestLocalizeMessageCatalog(t *testing.T) {
	var raw []struct{ En, Ja string }
	if err := json.Unmarshal(messagesJA, &raw); err != nil {
		t.Fatal(err)
	}
	for _, e := range raw {
		if !strings.HasPrefix(e.En, "^") || !strings.HasSuffix(e.En, "$") {
			t.Errorf("pattern is not anchored: %s", e.En)
		}
		if _, err := regexp.Compile(e.En); err != nil {
			t.Errorf("%s: %v", e.En, err)
		}
	}
	gen, err := os.ReadFile(filepath.Join("..", "packages", "core", "src", "messages-ja.ts"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range raw {
		var b strings.Builder
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		if err := enc.Encode([]string{e.En, e.Ja}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(gen), strings.Replace(strings.TrimSpace(b.String()), `","`, `", "`, 1)) {
			t.Errorf("packages/core/src/messages-ja.ts is out of date (run npm run build:messages): %s", e.En)
			break
		}
	}
	if LocalizeMessage("document content was modified after this signature", "en") != "document content was modified after this signature" {
		t.Error("en changed the text")
	}
	if got := LocalizeMessage("something the library never says", "ja"); got != "something the library never says" {
		t.Errorf("unknown text changed: %q", got)
	}
	if got, want := LocalizeMessage(`unknown field "foo" (extension fields must start with "x_"); missing required field "sig"`, "ja"), `不明なフィールド "foo"（拡張フィールドは "x_" で開始しなければならない）；必須フィールド "sig" がない`; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestLocalizeMessageExamples(t *testing.T) {
	var expected map[string]json.RawMessage
	if err := json.Unmarshal([]byte(readExample(t, "expected.json")), &expected); err != nil {
		t.Fatal(err)
	}
	for file := range expected {
		t.Run(file, func(t *testing.T) {
			r := VerifyDocument(context.Background(), readExample(t, file), examplesVerifyOptions(t))
			check := func(m, where string) {
				if m != "" {
					assertLocalized(t, m, where)
				}
			}
			check(r.Error, "error")
			for _, w := range r.Warnings {
				check(w, "warning")
			}
			for _, s := range r.Signatures {
				where := fmt.Sprintf("#%d", s.Index)
				check(s.Message, where+" message")
				for _, w := range s.Warnings {
					check(w, where+" warning")
				}
				for _, x := range s.Resources {
					if x.Status != ResourceMismatch {
						check(x.Detail, where+" resource")
					}
				}
				if s.Revocation != nil {
					check(s.Revocation.Detail, where+" revocation")
				}
				if s.TSA != nil {
					check(s.TSA.Detail, where+" tsa")
				}
			}
			for _, d := range r.Agreement.Declarations {
				check(d.Detail, fmt.Sprintf("declaration #%d", d.DeclaredBy))
			}
		})
	}
}

func TestExplainRequireJapaneseMessages(t *testing.T) {
	for _, v := range []string{"step\n  dns:example.com author", "order pending\nstep\n  dns:example.com", "step any=3\n  dns:a.example\n  dns:b.example", "step\n  ssh:alice"} {
		e := ExplainRequire(v, "ja")
		for _, m := range append(append(append(append([]string{}, e.Errors...), e.Unsupported...), e.Hints...), e.Warnings...) {
			if !japaneseRe.MatchString(m) {
				t.Errorf("%q: %q", v, m)
			}
		}
	}
}
