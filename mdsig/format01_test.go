package mdsig

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode"
)

// --- grammar (SPEC 3.2)

func TestGrammarContinuationAndTrailingSpaces(t *testing.T) {
	f, errs, _ := parseFields([]string{"v: 0.1", "require: |", "  step", "    dns:a.example", "x_note: a", "method: tofu", "signer: a", "ts: x", "alg: ed25519", "hash: h", "sig: s"})
	if len(errs) != 0 || f["require"] != "step\n  dns:a.example" {
		t.Fatalf("%q %v", f["require"], errs)
	}
	if !strings.Contains(string(SignedPayload(map[string]string{"require": f["require"]})), "require=step\n    dns:a.example") {
		t.Error("payload indentation")
	}
	for _, lines := range [][]string{{"require: |", "  dns:a.example  "}, {"reason: a "}} {
		if _, errs, _ := parseFields(lines); !strings.Contains(strings.Join(errs, ";"), "trailing spaces") {
			t.Errorf("%q: %v", lines, errs)
		}
	}
}

func TestGrammarFormatCharactersAndAlg(t *testing.T) {
	for _, ch := range []string{"\u200b", "\u200d", "\U000e0041", "\ufeff", "\u2029", "\ufffe", "\ufdd0", "\U0001fffe"} {
		if _, errs, _ := parseFields([]string{"reason: a" + ch + "b"}); !strings.Contains(strings.Join(errs, ";"), "must not contain") {
			t.Errorf("%q accepted", ch)
		}
	}
	if _, errs, _ := parseFields([]string{"v: 0.1", "method: tofu", "signer: a", "ts: x", "hash: h", "sig: s"}); !slices.Contains(errs, `missing required field "alg"`) {
		t.Error(errs)
	}
}

func TestForbiddenRunesMatchUnicode15(t *testing.T) {
	if unicode.Version != "15.0.0" {
		t.Skipf("Go's tables are Unicode %s", unicode.Version)
	}
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xd800 && r <= 0xdfff {
			continue
		}
		want := unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) || (r >= 0xfdd0 && r <= 0xfdef) || r&0xfffe == 0xfffe
		if isForbiddenRune(r) != want {
			t.Errorf("U+%04X: table %v, unicode %v", r, isForbiddenRune(r), want)
		}
	}
}

func TestRoleAndDisplayName(t *testing.T) {
	a := mustSigner(t, seedA)
	for _, role := range []string{"Approver", "chief approver"} {
		if _, err := SignDocument(context.Background(), fDoc, SignOptions{Signer: a, Method: "tofu", SignerID: "a", Role: role}); err == nil || !strings.Contains(err.Error(), "one word") {
			t.Errorf("%q: %v", role, err)
		}
	}
	ok := mustSign(t, fDoc, SignOptions{Signer: a, Method: "tofu", SignerID: "a", TS: fTS, Role: "legal.reviewer", DisplayName: "Alice Example"})
	if !strings.Contains(ok.Block, "\ndisplay_name: Alice Example\nrole: legal.reviewer\n") {
		t.Fatal(ok.Block)
	}
	if e := checkDisplayName("佐藤 花子"); e != "" {
		t.Error(e)
	}
	for v, want := range map[string]string{"Ａｌｉｃｅ": "NFKC", "a  b": "consecutive", "a\u3000b": "U+0020", strings.Repeat("x", 65): "64"} {
		if e := checkDisplayName(v); !strings.Contains(e, want) {
			t.Errorf("%q: %q", v, e)
		}
	}
	if n := mustSign(t, fDoc, SignOptions{Signer: a, Method: "tofu", SignerID: "a", TS: fTS, DisplayName: "  Ａlice   Example "}).Fields["display_name"]; n != "Alice Example" {
		t.Error(n)
	}
	long := strings.Replace(ok.Text, "display_name: Alice Example", "display_name: "+strings.Repeat("x", 65), 1)
	if s := verify(long, nil).Signatures[0]; s.Status != StatusMalformed {
		t.Error(s.Status)
	}
}

// --- identifiers (SPEC 3.4)

func TestIdentifierSyntax(t *testing.T) {
	for _, d := range []string{"example.com", "a-b.example.co.jp", "xn--fsqu00a.example", "1.2.3.example"} {
		if !isLdhDomain(d) {
			t.Errorf("%s rejected", d)
		}
	}
	for _, d := range []string{"Example.com", "example.com.", "localhost", "127.0.0.1", "2130706433", "example.123", "-a.example", "a-.example", "a_b.example", "a..example", strings.Repeat("a", 64) + ".example", strings.Repeat("a.", 127) + "com"} {
		if isLdhDomain(d) {
			t.Errorf("%s accepted", d)
		}
	}
	for e, want := range map[string]bool{"alice@mail.example": true, "ユーザ@mail.example": true, "Alice@mail.example": false, "alice@Mail.example": false,
		"al*ce@mail.example": false, "alice@localhost": false, "@mail.example": false, "a..b@mail.example": false, ".a@mail.example": false} {
		if isEmailID(e) != want {
			t.Errorf("%s: %v", e, !want)
		}
	}
	for id, ok := range map[[2]string]bool{{"git-hosting", "github.com/alice"}: true, {"git-hosting", "github.com/Alice"}: false, {"git-hosting", "github.com/.x_y-z"}: true,
		{"tofu", "bob*"}: false, {"tofu", "Bob@Laptop"}: true, {"tofu", "Bob Laptop"}: false} {
		if (CheckSignerID(id[0], id[1]) == "") != ok {
			t.Errorf("%v: %q", id, CheckSignerID(id[0], id[1]))
		}
	}
}

func TestIdentifierGeneratorsAndExactComparison(t *testing.T) {
	a := mustSigner(t, seedA)
	s := mustSign(t, fDoc, SignOptions{Signer: a, Method: "dns", SignerID: "Example.COM.", Selector: "2026", TS: fTS})
	if s.Fields["signer"] != "example.com" {
		t.Fatal(s.Fields["signer"])
	}
	o := &VerifyOptions{Resolvers: map[string]Resolver{"dns": fixedKeys(map[string][]byte{"example.com": a.PublicKey()}, "ed25519")}}
	if !verify(s.Text, o).OK {
		t.Error("canonical signer")
	}
	if st := verify(strings.Replace(s.Text, "signer: example.com", "signer: EXAMPLE.com", 1), o).Signatures[0].Status; st != StatusMalformed {
		t.Error(st)
	}
	if _, err := SignDocument(context.Background(), fDoc, SignOptions{Signer: a, Method: "dns", SignerID: "example.com", Selector: "_member"}); err == nil || !strings.Contains(err.Error(), `must not start with "_"`) {
		t.Error(err)
	}
	if g := mustSign(t, fDoc, SignOptions{Signer: a, Method: "git-hosting", SignerID: "GitHub.com/Alice", TS: fTS}); g.Fields["signer"] != "github.com/alice" {
		t.Error(g.Fields["signer"])
	}
	if _, err := SignDocument(context.Background(), fDoc, SignOptions{Signer: a, Method: "tofu", SignerID: "any*one"}); err == nil || !strings.Contains(err.Error(), `"*"`) {
		t.Error(err)
	}
}

func TestSameKeyValueRawAndSPKI(t *testing.T) {
	a := mustSigner(t, seedA)
	spki := append([]byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}, a.PublicKey()...)
	if !sameKeyValue("ed25519:"+toBase64(a.PublicKey()), "ed25519:"+toBase64(spki)) {
		t.Error("raw and SPKI differ")
	}
	if sameKeyValue("ed25519:"+toBase64(a.PublicKey()), "es256:"+toBase64(a.PublicKey())) {
		t.Error("key types ignored")
	}
}

// --- list lines (SPEC 3.5), scope, resources

func TestListLines(t *testing.T) {
	kinds := map[string]string{"role": listAttrValue, "member_of": listAttrValue, "user_verified": listAttrFlag}
	l, e := parseListLine("  dns:a.example role=x member_of=https://e.example/?a=b user_verified", kinds)
	if l == nil || l.indent != 2 {
		t.Fatal(e)
	}
	if m, _ := l.get("member_of"); m.value != "https://e.example/?a=b" {
		t.Error(m)
	}
	if u, _ := l.get("user_verified"); !u.flag {
		t.Error(u)
	}
	for raw, want := range map[string]string{"dns:a.example  role=x": "exactly one space", "dns:a.example role=": "empty value", "dns:a.example role=x role=y": "twice",
		"dns:a.example role": "needs a value", "dns:a.example user_verified=yes": "takes no value"} {
		if _, e := parseListLine(raw, kinds); !strings.Contains(e, want) {
			t.Errorf("%q: %q", raw, e)
		}
	}
	if l, _ := parseListLine("dns:a.example x_new=1", nil); !reflect.DeepEqual(l.unknown, []string{"x_new"}) {
		t.Error(l.unknown)
	}
	if l, _ := parseListLine("a=b c=d", map[string]string{"c": listAttrValue}); l.target != "a=b" {
		t.Error(l.target)
	}
}

func TestScopeLines(t *testing.T) {
	if ids, ok := ParseScope("terms\n  fees"); !ok || !reflect.DeepEqual(ids, []string{"terms", "fees"}) {
		t.Error(ids)
	}
	for _, bad := range []string{"section:terms,section:fees", "terms\nterms"} {
		if _, ok := ParseScope(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
	a := mustSigner(t, seedA)
	doc := "<!-- mdsig:section terms -->\nT\n<!-- /mdsig:section -->\n<!-- mdsig:section fees -->\nF\n<!-- /mdsig:section -->\n"
	s := mustSign(t, doc, SignOptions{Signer: a, Method: "tofu", SignerID: "a", TS: fTS, Scope: []string{"terms", "fees"}})
	if !strings.Contains(s.Block, "scope: |\n  terms\n  fees\n") {
		t.Fatal(s.Block)
	}
	old := verify(strings.Replace(s.Text, "scope: |\n  terms\n  fees\n", "scope: section:terms,section:fees\n", 1), nil).Signatures[0]
	if old.Status != StatusMalformed || !slices.ContainsFunc(old.Warnings, func(w string) bool { return strings.Contains(w, "one section id per line") }) {
		t.Errorf("%s %v", old.Status, old.Warnings)
	}
}

func TestLocalRefDecoding(t *testing.T) {
	for ref, want := range map[string]string{"assets/meeting%20notes.txt": "assets/meeting notes.txt", "img/%E5%9B%B3.png": "img/図.png", "img/図.png": "img/図.png"} {
		if p, e := decodeLocalRef(ref); p != want || e != "" {
			t.Errorf("%s: %q %q", ref, p, e)
		}
	}
	for _, bad := range []string{"..%2Fsecret", "a%2fb", "a%5Cb", "a%00b", "a/%2E%2E/b", "a//b", "a/./b", "a/", "%zz", "a%ff", "a b", "a#b", "/abs", "./a.png", "C:/x.png", "c%3A/x.png"} {
		if _, e := decodeLocalRef(bad); e == "" {
			t.Errorf("%s accepted", bad)
		}
	}
	h0, h1 := strings.Repeat("0", 64), strings.Repeat("1", 64)
	entries, errs, _ := parseResources("a.png hash=sha256:" + h0 + "\nhttps://e.example/x?y=1&z=2 hash=sha256:" + h1)
	if len(errs) != 0 || entries[0].Path != "a.png" || entries[0].Remote || !entries[1].Remote || entries[1].Ref != "https://e.example/x?y=1&z=2" {
		t.Errorf("%+v %v", entries, errs)
	}
	for v, want := range map[string]string{"sha256:" + h0 + " a.png": "invalid attribute", "a.png hash=sha256:" + h0 + " size=3": "unknown attribute", "a.png hash=sha256:" + strings.Repeat("A", 64): "lowercase"} {
		if _, errs, _ := parseResources(v); !strings.Contains(strings.Join(errs, ";"), want) {
			t.Errorf("%q: %v", v, errs)
		}
	}
	if _, _, uh := parseResources("a.png hash=sha512:" + strings.Repeat("0", 128)); uh != "sha512:"+strings.Repeat("0", 128) {
		t.Error(uh)
	}
}

// --- code fences (SPEC 5.5)

func TestFenceScan(t *testing.T) {
	var got [][2]bool
	for _, l := range linesWithFence("````\n```\n~~~~\n````\nafter") {
		got = append(got, [2]bool{l.InFence, l.Close})
	}
	if !reflect.DeepEqual(got, [][2]bool{{true, false}, {true, false}, {true, false}, {true, true}, {false, false}}) {
		t.Error(got)
	}
	if l := linesWithFence("```mdsig-list  \n```")[0]; l.Info != "mdsig-list" {
		t.Error(l.Info)
	}
	for text, want := range map[string]bool{"a\n```\nb\n": true, "a\n```\nb\n```\n": false, "    ```\n```js\n": true, "``` not `a` fence\n": false, "~~~ `ok` for tildes\n": true} {
		if endsInOpenFence(text) != want {
			t.Errorf("%q", text)
		}
	}
	if _, err := SignDocument(context.Background(), "# a\n\n```\ncode\n", SignOptions{Signer: mustSigner(t, seedA), Method: "tofu", SignerID: "a"}); err == nil || !strings.Contains(err.Error(), "open code fence") {
		t.Error(err)
	}
	if !ParseDocument("a\n```\nb\n\n<!-- md-signature\n-->\n").UnclosedFence {
		t.Error("unclosed fence not reported")
	}
}

// --- require parsing (SPEC 5.8)

func TestRequireParsing(t *testing.T) {
	ok := ParseRequire("order mode=guide\nstep\n  dns:a.example role=approver\nstep any=2\n  dns:*.example.com member_of=dns:corp.example user_verified\n  directory:*@mail.example member_of=https://example.com/m.md\n  tofu:bob pubkey=ed25519:11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo= user_verified", 0)
	if len(ok.Errors)+len(ok.Unsupported) != 0 || ok.Spec.Order != OrderGuide || len(ok.Spec.Steps) != 2 || ok.Spec.Steps[1].Any != 2 || len(ok.Spec.Steps[1].Lines) != 3 {
		t.Fatalf("%+v", ok)
	}
	if a := ok.Requirements[1].Attributes; a != (RequirementAttributes{UserVerified: true, MemberOf: "dns:corp.example"}) {
		t.Error(a)
	}
	for v, want := range map[string]string{
		"pgp:a@b.example user_verified":                "only allowed on dns, directory, and tofu",
		"tofu:bob user_verified":                       "needs pubkey=",
		"dns:a.example pubkey=ed25519:AAAA":            "only allowed on tofu",
		"tofu:bob pubkey=ed25519:AAAA":                 "pubkey=",
		"dns:a.example role=Approver":                  "role must match",
		"dns:a.example\nstep\n  dns:b.example":         `before the first "step"`,
		"step\nstep\n  dns:a.example":                  "step 1 has no requirement",
		"step any=3\n  dns:a.example\n  dns:b.example": "any=3 of 2",
		"dns:a.example\ndns:a.example role=x":          "appears twice",
		"order mode=strict\ndns:*":                     "strict cannot be used with pattern",
		"order mode=fast\ndns:a.example":               "order mode=",
		"tsa:https://t.example":                        "cannot be required",
		"dns:Example.com":                              "lower-case domain",
		"step any=2\n  dns:a.example\n  dns:a.example": "any=2 of 1 different signers",
		"tofu:bob member_of=dns:corp.example":          "not allowed on tofu",
	} {
		if e := strings.Join(ParseRequire(v, 0).Errors, "; "); !strings.Contains(e, want) {
			t.Errorf("%q: %q", v, e)
		}
	}
	for _, pat := range []string{"dns:a*.example", "dns:*example.com", "tofu:*", "git-hosting:github.com/*", "directory:*.mail.example", "dns:*.localhost"} {
		if len(ParseRequire(pat, 0).Errors) == 0 {
			t.Errorf("%s accepted", pat)
		}
	}
	for _, url := range []string{"http://e.example/m", "https://u@e.example/m", "https://e.example:8443/m", "https://e.example/m#f", "https://192.0.2.1/m", "dns:Corp.example"} {
		if e := strings.Join(ParseRequire("dns:*.example.com member_of="+url, 0).Errors, ""); !strings.Contains(e, "member_of must be") {
			t.Errorf("%s: %q", url, e)
		}
	}
	if len(ParseRequire("step any=5\n  dns:*.example.com", 0).Errors) != 0 {
		t.Error("any above the line count with a pattern")
	}
	if _, ok := parseRosterRef("https://e.example:443/m"); !ok {
		t.Error("port 443")
	}
	if un := ParseRequire("dns:a.example x_budget=100\nfoo:bar", 0); len(un.Errors) != 0 || len(un.Unsupported) != 2 {
		t.Errorf("%+v", un)
	}
	var many, steps []string
	for i := range 65 {
		many = append(many, "tofu:p"+string(rune('a'+i%26))+strings.Repeat("x", i))
	}
	for i := range 17 {
		steps = append(steps, "step", "  tofu:p"+strings.Repeat("x", i))
	}
	if ParseRequire(strings.Join(many, "\n"), 0).OverLimit == "" || ParseRequire(strings.Join(steps, "\n"), 0).OverLimit == "" {
		t.Error("limits")
	}
	h := strings.Join(ParseRequire("order strict\nstep 1\ndns:example.com approver\nstep 2 any 2\ntofu:a\ntofu:b", 0).Hints, "\n")
	for _, want := range []string{"order mode=strict", `"step"`, "role=approver", "step any=2"} {
		if !strings.Contains(h, want) {
			t.Errorf("hint %q missing in %s", want, h)
		}
	}
}

// --- matching (SPEC 5.8, Appendix C)

func declBlock(require string, signer ...string) agreementBlock {
	s := "example.com"
	if len(signer) > 0 {
		s = signer[0]
	}
	return agreementBlock{Index: 1, Status: StatusValid, Fields: map[string]string{"method": "dns", "signer": s, "require": require}}
}

func dnsBlock(index int, signer string, extra map[string]string, status ...string) agreementBlock {
	f := map[string]string{"method": "dns", "signer": signer}
	for k, v := range extra {
		f[k] = v
	}
	b := agreementBlock{Index: index, Status: StatusValid, Fields: f}
	if len(status) > 0 {
		b.Status = status[0]
	}
	if len(status) > 1 {
		b.Code = status[1]
	}
	return b
}

func satisfied(a Agreement) [][2]int {
	out := [][2]int{}
	for _, s := range a.Satisfied {
		out = append(out, [2]int{s.Line, s.Index})
	}
	return out
}

func TestMatchingCanonicalAssignment(t *testing.T) {
	a := evaluateAgreement([]agreementBlock{declBlock("dns:*.example.com\ndns:a.example.com"), dnsBlock(2, "a.example.com", nil), dnsBlock(3, "b.example.com", nil)}, nil)
	if a.Status != AgreementComplete || !reflect.DeepEqual(satisfied(a), [][2]int{{1, 3}, {2, 2}}) {
		t.Errorf("first-fit: %s %v", a.Status, satisfied(a))
	}
	role := map[string]string{"role": "x"}
	b := evaluateAgreement([]agreementBlock{declBlock("dns:*.example.com role=x\ndns:*.example.com"), dnsBlock(2, "a.example.com", role), dnsBlock(3, "b.example.com", role)}, nil)
	if b.Status != AgreementComplete || !reflect.DeepEqual(satisfied(b), [][2]int{{1, 3}, {2, 2}}) {
		t.Errorf("Kuhn order: %s %v", b.Status, satisfied(b))
	}
}

func TestMatchingAnyAndReuse(t *testing.T) {
	a := evaluateAgreement([]agreementBlock{declBlock("step any=2\n  dns:*.example.com"), dnsBlock(2, "a.example.com", nil), dnsBlock(3, "a.example.com", nil), dnsBlock(4, "b.example.com", nil), dnsBlock(5, "c.example.com", nil)}, nil)
	if a.Status != AgreementComplete || !reflect.DeepEqual(satisfied(a), [][2]int{{2, 2}, {2, 4}}) {
		t.Errorf("%s %v", a.Status, satisfied(a))
	}
	one := evaluateAgreement([]agreementBlock{declBlock("step any=2\n  dns:*.example.com"), dnsBlock(2, "a.example.com", nil), dnsBlock(3, "a.example.com", nil)}, nil)
	if one.Status != AgreementPending || one.Missing[0].Need != 1 || one.Next[0].Need != 1 {
		t.Errorf("%+v", one)
	}
	r := "step\n  dns:a.example.com\nstep\n  dns:a.example.com role=final"
	final := map[string]string{"role": "final"}
	p := evaluateAgreement([]agreementBlock{declBlock(r), dnsBlock(2, "a.example.com", final)}, nil)
	if p.Status != AgreementPending || len(p.Missing) != 1 || p.Missing[0].Step != 2 || !reflect.DeepEqual(p.Missing[0].Rejected, []Rejection{{2, RejectBlocked}}) {
		t.Errorf("%+v", p.Missing)
	}
	c := evaluateAgreement([]agreementBlock{declBlock(r), dnsBlock(2, "a.example.com", final), dnsBlock(3, "a.example.com", final)}, nil)
	if c.Status != AgreementComplete || c.Satisfied[0].Index != 2 || c.Satisfied[1].Index != 3 {
		t.Errorf("%+v", c.Satisfied)
	}
}

func TestMatchingPatternsAndSelf(t *testing.T) {
	sub := evaluateAgreement([]agreementBlock{declBlock("dns:*.example.com"), dnsBlock(2, "example.com", nil), dnsBlock(3, "badexample.com", nil), dnsBlock(4, "x.y.example.com", nil)}, nil)
	if !reflect.DeepEqual(satisfied(sub), [][2]int{{1, 4}}) {
		t.Error(satisfied(sub))
	}
	self := evaluateAgreement([]agreementBlock{declBlock("dns:*.example.com", "a.example.com"), dnsBlock(2, "a.example.com", nil)}, nil)
	if !reflect.DeepEqual(self.Missing[0].Rejected, []Rejection{{2, RejectSelf}}) {
		t.Error(self.Missing[0].Rejected)
	}
	mail := evaluateAgreement([]agreementBlock{
		declBlock("directory:*@mail.example"),
		{Index: 2, Status: StatusValid, Fields: map[string]string{"method": "directory", "signer": "x@sub.mail.example"}},
		{Index: 3, Status: StatusValid, Fields: map[string]string{"method": "directory", "signer": "y@mail.example"}},
	}, nil)
	if !reflect.DeepEqual(satisfied(mail), [][2]int{{1, 3}}) {
		t.Error(satisfied(mail))
	}
}

func TestMatchingRejectedAndUndetermined(t *testing.T) {
	oracle := func(_, id string) string {
		switch id {
		case "dns:m.example.com":
			return MembershipMember
		case "dns:u.example.com":
			return MembershipUnavailable
		}
		return MembershipNotMember
	}
	a := evaluateAgreement([]agreementBlock{declBlock("dns:*.example.com member_of=dns:corp.example"), dnsBlock(2, "n.example.com", nil),
		dnsBlock(3, "s.example.com", map[string]string{"scope": "terms"}), dnsBlock(4, "v.example.com", nil, StatusInvalid, "bad-signature")}, oracle)
	if a.Status != AgreementPending || !reflect.DeepEqual(a.Missing[0].Rejected, []Rejection{{2, RejectNotMember}, {3, RejectScoped}, {4, RejectNotValid}}) {
		t.Errorf("%s %v", a.Status, a.Missing[0].Rejected)
	}
	for blocks, want := range map[*[]agreementBlock]string{
		{declBlock("dns:*.example.com member_of=dns:corp.example"), dnsBlock(2, "u.example.com", nil)}:      AgreementUndetermined,
		{declBlock("dns:a.example.com"), dnsBlock(2, "a.example.com", nil, StatusUnresolved, KindNetwork)}:  AgreementUndetermined,
		{declBlock("dns:a.example.com"), dnsBlock(2, "a.example.com", nil, StatusUnresolved, KindNotFound)}: AgreementPending,
		{declBlock("dns:a.example.com"), dnsBlock(2, "a.example.com", nil, StatusInvalid, "bad-signature")}: AgreementPending,
	} {
		if got := evaluateAgreement(*blocks, oracle).Status; got != want {
			t.Errorf("%v: %s, want %s", *blocks, got, want)
		}
	}
	wa := map[string]string{"alg": "webauthn-es256"}
	no, yes := dnsBlock(2, "a.example.com", wa), dnsBlock(3, "a.example.com", wa)
	yes.UserVerified = true
	uv := evaluateAgreement([]agreementBlock{declBlock("dns:a.example.com user_verified"), no, yes}, nil)
	if uv.Status != AgreementComplete || uv.Satisfied[0].Index != 3 {
		t.Errorf("%+v", uv)
	}
}

func TestMatchingOrder(t *testing.T) {
	p := evaluateAgreement([]agreementBlock{declBlock("step\n  dns:a.example.com\nstep\n  dns:b.example.com"), dnsBlock(2, "b.example.com", nil)}, nil)
	if len(p.Missing) != 2 || p.Missing[1].BlockedBy != 1 || !reflect.DeepEqual(p.Missing[1].Rejected, []Rejection{{2, RejectEarly}}) || p.Next[0].Step != 1 || p.Next[0].Later[0].Step != 2 {
		t.Errorf("%+v", p)
	}
	g := evaluateAgreement([]agreementBlock{declBlock("order mode=guide\nstep\n  dns:a.example.com\nstep\n  dns:*.example.com"), dnsBlock(2, "c.example.com", nil), dnsBlock(3, "a.example.com", nil)}, nil)
	if g.Status != AgreementComplete || len(g.Violations) != 0 {
		t.Errorf("%+v", g)
	}
	gn := evaluateAgreement([]agreementBlock{declBlock("order mode=guide\nstep\n  dns:a.example.com\nstep\n  dns:c.example.com"), dnsBlock(2, "c.example.com", nil), dnsBlock(3, "a.example.com", nil)}, nil)
	if len(gn.Violations) != 1 || gn.Violations[0].Index != 2 || gn.Violations[0].Step != 2 {
		t.Errorf("%+v", gn.Violations)
	}
	st := evaluateAgreement([]agreementBlock{declBlock("order mode=strict\nstep\n  dns:a.example.com\nstep\n  dns:b.example.com\nstep\n  dns:c.example.com"),
		dnsBlock(2, "b.example.com", nil), dnsBlock(3, "c.example.com", nil), dnsBlock(4, "a.example.com", nil)}, nil)
	if st.Status != AgreementViolated || len(st.Violations) != 2 || st.Violations[0].Index != 2 || st.Violations[1].Index != 3 || st.Violations[1].Step != 3 {
		t.Errorf("%+v", st.Violations)
	}
	never := evaluateAgreement([]agreementBlock{declBlock("order mode=strict\nstep\n  dns:a.example.com\nstep\n  dns:b.example.com"), dnsBlock(2, "b.example.com", nil)}, nil)
	if never.Status != AgreementViolated || len(never.Violations) != 1 || len(never.Next) != 1 {
		t.Errorf("%+v", never)
	}
}

func TestUnsupportedAttributeKeepsSignatureValid(t *testing.T) {
	a := mustSigner(t, seedA)
	if _, err := SignDocument(context.Background(), fDoc, SignOptions{Signer: a, Method: "tofu", SignerID: "a", Require: []string{"tofu:b x_budget=1"}}); err == nil || !strings.Contains(err.Error(), "unknown attribute") {
		t.Fatal(err)
	}
	f := map[string]string{"v": "0.1", "method": "tofu", "signer": "a", "pubkey": "ed25519:" + toBase64(a.PublicKey()), "ts": fTS, "require": "tofu:b x_budget=1", "alg": "ed25519", "hash": normalizedHash(fDoc)}
	sig, _ := a.Sign(SignedPayload(f))
	f["sig"] = "base64:" + toBase64(sig)
	block, err := serializeBlock(f)
	if err != nil {
		t.Fatal(err)
	}
	v := verify(fDoc+"\n"+block+"\n", nil)
	if v.Signatures[0].Status != StatusValid || v.Agreement.Status != AgreementUnsupported || v.OK {
		t.Errorf("%s %s %v", v.Signatures[0].Status, v.Agreement.Status, v.OK)
	}
}

// --- signed lists and rosters (SPEC 5.10, 5.8.8)

func TestSignedListParsing(t *testing.T) {
	list := func(lines ...string) string {
		return strings.Join(append(append([]string{"# L", "", "```mdsig-list"}, lines...), "```", ""), "\n")
	}
	if e, err := parseSignedList(list("type: members", "member: dns:a.example.com", "member: tofu:bob"), signedListMembers); err != "" || !reflect.DeepEqual(e, []string{"dns:a.example.com", "tofu:bob"}) {
		t.Error(e, err)
	}
	for body, typ := range map[string]string{
		list("type: members"): signedListRevocation, list("type: members", "member: dns:A.example.com"): signedListMembers,
		list("type: members", "member: dns:*.example.com"): signedListMembers, list("type: members", ""): signedListMembers,
		list("type: revocation", "revoked: sha256:"+strings.Repeat("A", 64)): signedListRevocation, "no list\n": signedListMembers,
		list("type: members") + list("type: members"): signedListMembers, "```mdsig-list\ntype: members\n": signedListMembers,
	} {
		if _, err := parseSignedList(body, typ); err == "" {
			t.Errorf("%q accepted", body)
		}
	}
	if _, err := parseSignedList("~~~mdsig-list\ntype: members\n~~~\n", signedListMembers); err != "" {
		t.Error(err)
	}
	lines := []string{"type: revocation"}
	for i := range 100_000 {
		lines = append(lines, fmt.Sprintf("revoked: sha256:%064x", i))
	}
	if e, err := parseSignedList(list(lines...), signedListRevocation); err != "" || len(e) != 100_000 {
		t.Errorf("%d %s", len(e), err)
	}
}

func TestMemberRecords(t *testing.T) {
	if got := base32LowerNoPad.EncodeToString([]byte("foobar")); got != "mzxw6ytboi" {
		t.Error(got)
	}
	name, err := MemberRecordName("dns:a.example.com", "corp.example")
	if err != nil || len(strings.SplitN(name, ".", 2)[0]) != 52 || !strings.HasSuffix(name, "._member._mdsig.corp.example") {
		t.Fatal(name, err)
	}
	if _, err := MemberRecordName("dns:a.example.com", "Corp.example"); err == nil {
		t.Error("upper-case domain accepted")
	}
	lookup := func(records map[string][]string, servfail bool) *ResolveOptions {
		return &ResolveOptions{DoHEndpoints: []string{}, LookupTXT: func(_ context.Context, n string) ([]string, error) {
			if servfail {
				return nil, &net.DNSError{Err: "server misbehaving", Name: n, IsTemporary: true}
			}
			r, ok := records[n]
			if !ok {
				return nil, &net.DNSError{Err: "no such host", Name: n, IsNotFound: true}
			}
			return r, nil
		}}
	}
	ctx := context.Background()
	for o, want := range map[*ResolveOptions]string{
		lookup(map[string][]string{name: {"v=mdsig1; m=dns:a.example.com"}}, false): MembershipMember,
		lookup(map[string][]string{name: {"v=mdsig1; m=dns:other.example"}}, false): MembershipNotMember,
		lookup(map[string][]string{name: {}}, false):                                MembershipNotMember,
		lookup(nil, false): MembershipNotMember,
		lookup(nil, true):  MembershipUnavailable,
		{Offline: true}:    MembershipUnavailable,
	} {
		if got := CheckMemberRecord(ctx, "dns:a.example.com", "corp.example", o); got != want {
			t.Errorf("%s, want %s", got, want)
		}
	}
}

func TestHTTPSRosterThroughVerify(t *testing.T) {
	a := mustSigner(t, seedA)
	b, _ := SignerFromSeed(bytesOf(32, 9))
	resolvers := map[string]Resolver{"dns": fixedKeys(map[string][]byte{"example.com": a.PublicKey(), "x.example.com": b.PublicKey()}, "ed25519")}
	roster := mustSign(t, "# Members\n\n```mdsig-list\ntype: members\nmember: dns:x.example.com\n```\n", SignOptions{Signer: a, Method: "dns", SignerID: "example.com", TS: fTS}).Text
	stub := &fetchStub{fn: func(r *http.Request) (int, []byte, error) {
		if r.URL.String() != "https://example.com/m.md" {
			t.Errorf("fetched %s", r.URL)
		}
		return 200, []byte(roster), nil
	}}
	d := mustSign(t, fDoc, SignOptions{Signer: a, Method: "dns", SignerID: "example.com", TS: fTS,
		Require: []string{"dns:*.example.com member_of=https://example.com/m.md", "dns:*.example.com member_of=https://example.com/m.md role=x"}})
	s := mustSign(t, d.Text, SignOptions{Signer: b, Method: "dns", SignerID: "x.example.com", TS: fTS})
	o := &VerifyOptions{Resolvers: resolvers, ResourceCheckOptions: ResourceCheckOptions{FetchClient: stub.client()}}
	v := verify(s.Text, o)
	if v.Agreement.Status != AgreementPending || stub.calls != 1 || len(v.Agreement.Satisfied) != 1 || v.Agreement.Satisfied[0].Index != 2 {
		t.Errorf("%s calls=%d %+v", v.Agreement.Status, stub.calls, v.Agreement.Satisfied)
	}
	o.Offline = true
	off := verify(s.Text, o)
	if off.Agreement.Status != AgreementUndetermined || !strings.Contains(off.Agreement.Declarations[0].Detail, "roster") {
		t.Errorf("%+v", off.Agreement.Declarations)
	}
}

// --- signature table (SPEC 5.11, 9.5)

func TestSignatureTable(t *testing.T) {
	if l, _, _ := FindSignatureMarker("a\n<!-- mdsig:signatures -->\n"); l != 2 {
		t.Error(l)
	}
	if l, _, w := FindSignatureMarker("```\n<!-- mdsig:signatures -->\n```\n<!-- mdsig:signatures -->\n<!-- mdsig:signatures -->\n"); l != 4 || len(w) != 2 {
		t.Error(l, w)
	}
	a := mustSigner(t, seedA)
	s := mustSign(t, "# PO\n\n<!-- mdsig:signatures -->\n", SignOptions{Signer: a, Method: "tofu", SignerID: "seller", DisplayName: "<b>Seller</b> & Co", Role: "seller", TS: fTS, Require: []string{"tofu:buyer role=buyer"}})
	rows := SignatureTable(verify(s.Text, nil))
	if len(rows) != 2 || rows[0].Number != 1 || rows[0].Signer != "seller" || rows[0].Status != StatusValid || rows[1].Number != 0 || rows[1].Signer != "buyer" || rows[1].Status != "unsigned" || rows[1].Role != "buyer" {
		t.Fatalf("%+v", rows)
	}
	ja := RenderSignatureTableHTML(rows, "ja")
	if !strings.Contains(ja, "&lt;b&gt;Seller&lt;/b&gt; &amp; Co") || strings.Contains(ja, "<b>") || !strings.Contains(ja, "未署名") {
		t.Error(ja)
	}
	if !strings.Contains(RenderSignatureTableHTML(rows, "en"), "Unsigned") {
		t.Error("en labels")
	}
}

// --- ExplainRequire (CLI_SPEC 3.11)

func TestExplainRequire(t *testing.T) {
	ja := ExplainRequire("step\n  dns:example.com role=approver\nstep any=2\n  dns:*.example.com member_of=dns:corp.example\n  tofu:bob", "ja")
	for _, want := range []string{"段階 1：次のすべて\n  dns:example.com（役割 approver）", "段階 2：次のうち異なる2者", "example.com のサブドメインのいずれか", "corp.example の DNS 名簿に掲載"} {
		if !strings.Contains(ja.Text, want) {
			t.Errorf("%q missing in %s", want, ja.Text)
		}
	}
	if !ja.OK || !strings.Contains(strings.Join(ja.Warnings, ""), "この名前を名乗る誰でも満たせる") {
		t.Error(ja.Warnings)
	}
	en := ExplainRequire("step\n  dns:example.com role=approver\nstep any=2\n  dns:*.example.com member_of=dns:example.com", "en")
	if en.Text != "order: pending (signatures before their turn are not counted)\nstep 1: all of\n  dns:example.com with role approver\nstep 2: any 2 different signers of\n  any subdomain of example.com (not example.com itself), on the DNS roster of example.com, not the declaring signer" {
		t.Error(en.Text)
	}
	if w := ExplainRequire("step\ndns:a.example\n  step\n  dns:b.example", "en").Warnings; !strings.Contains(strings.Join(w, ""), "indentation") {
		t.Error(w)
	}
	strict := ExplainRequire("order mode=strict\ndns:a.example user_verified", "en")
	if !strings.Contains(strict.Text, "order: strict") || !strings.Contains(strict.Text, "user verification") {
		t.Error(strict.Text)
	}
	bad := ExplainRequire("dns:example.com approver", "en")
	if bad.OK || !strings.Contains(strings.Join(bad.Hints, ""), "role=approver") {
		t.Errorf("%+v", bad)
	}
}

// --- passkeys and user_verified (SPEC 5.8.7, 6.1, CLI_SPEC 8)

func TestUserVerifiedPasskeys(t *testing.T) {
	uvAuth := newSoftAuth(t, rp, "", 0x05|0x08|0x10)
	upAuth := newSoftAuth(t, rp, "", 0x01)
	a := mustSigner(t, seedA)
	declare := func(auth *softAuth) string {
		return mustSign(t, fDoc, SignOptions{Signer: a, Method: "tofu", SignerID: "a", TS: fTS, Require: []string{"tofu:carol pubkey=es256:" + toBase64(auth.PublicKeySPKI()) + " user_verified"}}).Text
	}
	ok := mustSign(t, declare(uvAuth), SignOptions{WebAuthn: uvAuth, Method: "tofu", SignerID: "carol", TS: fTS})
	if uvAuth.asked != UserVerificationRequired {
		t.Error(uvAuth.asked)
	}
	v := verify(ok.Text, nil)
	if w := v.Signatures[1].WebAuthn; v.Agreement.Status != AgreementComplete || !w.UserVerified || !w.BackupEligible || !w.BackedUp {
		t.Errorf("%s %+v", v.Agreement.Status, w)
	}
	if _, err := SignDocument(context.Background(), declare(upAuth), SignOptions{WebAuthn: upAuth, Method: "tofu", SignerID: "carol", TS: fTS}); err == nil || !strings.Contains(err.Error(), "user verification was required") {
		t.Error(err)
	}
	p, err := PrepareSignature(declare(upAuth), SigningKey{Alg: "webauthn-es256", PublicKey: upAuth.PublicKeySPKI(), RPID: rp}, SignOptions{Method: "tofu", SignerID: "carol", TS: fTS})
	if err != nil || p.UserVerification != UserVerificationRequired {
		t.Fatal(err, p.UserVerification)
	}
	as, _ := upAuth.GetAssertion(p.Challenge, p.UserVerification)
	if _, err := p.Finish(context.Background(), nil, as); err == nil || !strings.Contains(err.Error(), "UV flag") {
		t.Error(err)
	}
	req, err := CreateHandoffRequest("https://mdsig.dev/sign/", HandoffRequestOptions{Op: "sign", ReturnURL: "mdsig-app:cb", Payload: p.Payload, UserVerification: UserVerificationRequired})
	if err != nil || !strings.Contains(req.URL, "user_verification=required") {
		t.Fatal(err, req)
	}
	if page := CheckHandoffRequest(req.URL, rp); !page.OK || page.UserVerification != UserVerificationRequired {
		t.Errorf("%+v", page)
	}
}

func TestWebAuthnCrossOriginRefused(t *testing.T) {
	x := newSoftAuth(t, rp, "", 0x05)
	x.overrideClientData = func(cd map[string]any) map[string]any { cd["crossOrigin"] = true; return cd }
	s := verify(mustSign(t, fDoc, SignOptions{WebAuthn: x, Method: "tofu", SignerID: "x", TS: fTS}).Text, nil).Signatures[0]
	if s.Code != "bad-signature" || !strings.Contains(s.Message, "crossOrigin") {
		t.Errorf("%+v", s)
	}
}

// --- T(k) (SPEC 4.6)

func TestBlockTimeRounding(t *testing.T) {
	for g, want := range map[string]int64{"2026-11-16T09:00:00Z": 1794819600000, "2026-11-16T09:00:00.5Z": 1794819600500, "2026-11-16T09:00:00.1234Z": 1794819600124, "2026-11-16T09:00:00.1230Z": 1794819600123} {
		if ms, ok := genTimeMs(g); !ok || ms != want {
			t.Errorf("%s: %d", g, ms)
		}
	}
	if formatTimeMs(1794819600000) != "2026-11-16T09:00:00Z" || formatTimeMs(1794819600124) != "2026-11-16T09:00:00.124Z" {
		t.Error(formatTimeMs(1794819600124))
	}
}

func TestOutsideTSAVerifier(t *testing.T) {
	text := readExample(t, "valid-tsa-block.md")
	last := ParseDocument(text).Chain[len(ParseDocument(text).Chain)-1]
	var gotData []byte
	var gotHash string
	o := &VerifyOptions{ResolveOptions: ResolveOptions{Offline: true}, TSAVerifier: func(_ context.Context, token string, data []byte, hash string) TSACheck {
		gotData, gotHash = data, hash
		return TSACheck{Status: TSAOK, Verified: true, GenTime: "2026-11-16T09:00:00.5Z", AccuracyMs: 1000, Signer: "Outside TSA"}
	}}
	v := verify(text, o)
	s := v.Signatures[len(v.Signatures)-1]
	if s.Status != StatusValid || string(gotData) != string(SignedPayload(last.Fields)) || gotHash != "sha256" {
		t.Fatalf("%+v %q", s, gotHash)
	}
	if tm := v.Signatures[0].Time; tm == nil || tm.At != "2026-11-16T09:00:01.500Z" || tm.Block != s.Index {
		t.Errorf("%+v", tm)
	}
	o.TSAVerifier = func(context.Context, string, []byte, string) TSACheck {
		return TSACheck{Status: TSAError, Detail: "server down", GenTime: "2026-11-16T09:00:00Z"}
	}
	v = verify(text, o)
	if s := v.Signatures[len(v.Signatures)-1]; s.Status != StatusUnresolved || s.Code != KindNetwork || s.TSA.GenTime != "" || v.Signatures[0].Time != nil {
		t.Errorf("%+v %+v", s, s.TSA)
	}
}
