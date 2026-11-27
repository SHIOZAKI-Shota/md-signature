package mdsig

import (
	"fmt"
	"strings"
)

// --- require explanation (CLI_SPEC 3.11)

type RequireExplanation struct {
	OK          bool
	Text        string
	Errors      []string
	Unsupported []string
	// advice that does not make the value invalid (tofu lines without pubkey=, indentation, older syntax)
	Warnings []string
	Hints    []string
}

func explainTarget(r Requirement, ja bool) string {
	s := r.Signer
	switch {
	case !r.Pattern:
		return r.Method + ":" + s
	case s == "*":
		if ja {
			return r.Method + " 方式の任意の署名者"
		}
		return "any " + r.Method + " signer"
	case strings.HasPrefix(s, "*."):
		d := s[2:]
		if ja {
			return fmt.Sprintf("%s のサブドメインのいずれか（%s 自体を除く）", d, d)
		}
		return fmt.Sprintf("any subdomain of %s (not %s itself)", d, d)
	}
	d := s[2:]
	if ja {
		return fmt.Sprintf("%s のメールアドレスのいずれか（%s 方式、サブドメインを除く）", d, r.Method)
	}
	return fmt.Sprintf("any %s address at %s (not its subdomains)", r.Method, d)
}

func explainLine(r Requirement, ja bool) string {
	a := r.Attributes
	var parts []string
	if a.MemberOf != "" {
		ref, ok := parseRosterRef(a.MemberOf)
		switch {
		case ok && !ref.https && ja:
			parts = append(parts, ref.domain+" の DNS 名簿に掲載")
		case ok && !ref.https:
			parts = append(parts, "on the DNS roster of "+ref.domain)
		case ja:
			parts = append(parts, "名簿 "+a.MemberOf+" に掲載")
		default:
			parts = append(parts, "on the roster at "+a.MemberOf)
		}
	}
	if a.UserVerified {
		if ja {
			parts = append(parts, "パスキーの利用者確認（UV）あり")
		} else {
			parts = append(parts, "with passkey user verification")
		}
	}
	if a.Pubkey != "" {
		short := a.Pubkey
		if len(short) > 20 {
			short = short[:20]
		}
		if ja {
			parts = append(parts, "鍵 "+short+"… に限定")
		} else {
			parts = append(parts, "with key "+short+"…")
		}
	}
	if r.Pattern {
		if ja {
			parts = append(parts, "宣言者自身を除く")
		} else {
			parts = append(parts, "not the declaring signer")
		}
	}
	head := explainTarget(r, ja)
	if a.Role != "" {
		if ja {
			head += "（役割 " + a.Role + "）"
		} else {
			head += " with role " + a.Role
		}
	}
	if len(parts) == 0 {
		return head
	}
	if ja {
		return head + "、" + strings.Join(parts, "、")
	}
	return head + ", " + strings.Join(parts, ", ")
}

var orderText = map[bool]map[string]string{
	true: {
		OrderPending: "順序：pending（順番より前の署名は数えない）",
		OrderGuide:   "順序：guide（順番より前の署名も数え、順序違反として報告する）",
		OrderStrict:  "順序：strict（順番より前の署名があると、合意は違反として失敗する）",
	},
	false: {
		OrderPending: "order: pending (signatures before their turn are not counted)",
		OrderGuide:   "order: guide (signatures before their turn are counted and reported)",
		OrderStrict:  "order: strict (a signature before its turn makes the agreement violated)",
	},
}

func ExplainRequire(value, lang string) RequireExplanation {
	p := ParseRequire(value, 0)
	ja := lang == "ja"
	lines := []string{orderText[ja][p.Spec.Order]}
	for _, s := range p.Spec.Steps {
		var head string
		switch {
		case s.Any != 0 && ja:
			head = fmt.Sprintf("段階 %d：次のうち異なる%d者", s.Step, s.Any)
		case s.Any != 0:
			head = fmt.Sprintf("step %d: any %d different signers of", s.Step, s.Any)
		case ja:
			head = fmt.Sprintf("段階 %d：次のすべて", s.Step)
		default:
			head = fmt.Sprintf("step %d: all of", s.Step)
		}
		lines = append(lines, head)
		for _, r := range s.Lines {
			lines = append(lines, "  "+explainLine(r, ja))
		}
	}
	warnings := []string{}
	for _, r := range p.Requirements {
		// SPEC 5.8.2: verifiers warn that a tofu line without pubkey= can be met by anyone using the name
		if r.Method == "tofu" && r.Attributes.Pubkey == "" {
			if ja {
				warnings = append(warnings, fmt.Sprintf("%d行目：tofu:%s に pubkey= がないため、この名前を名乗る誰でも満たせる", r.Line, r.Signer))
			} else {
				warnings = append(warnings, fmt.Sprintf("line %d: tofu:%s has no pubkey=, so anyone using that name can meet it", r.Line, r.Signer))
			}
		}
	}
	// indentation carries no structure (SPEC 3.5), but a requirement indented no deeper than its step line is likely a mistake
	raws := strings.Split(value, "\n")
	indent := func(l string) int { return len(l) - len(strings.TrimLeft(l, " ")) }
	anyIndented := false
	for _, x := range raws {
		if indent(x) > 0 {
			anyIndented = true
		}
	}
	stepIndent := -1
	for i, l := range raws {
		t := strings.TrimLeftFunc(l, isJSSpace)
		if t == "step" || strings.HasPrefix(t, "step ") {
			stepIndent = indent(l)
		} else if stepIndent >= 0 && !strings.HasPrefix(t, "order ") && anyIndented && indent(l) <= stepIndent {
			if ja {
				warnings = append(warnings, fmt.Sprintf("%d行目：字下げが段階の構造と一致しない", i+1))
			} else {
				warnings = append(warnings, fmt.Sprintf("line %d: the indentation does not match the step structure", i+1))
			}
		}
	}
	loc := func(list []string) []string {
		out := make([]string, 0, len(list))
		for _, m := range list {
			out = append(out, LocalizeMessage(m, lang))
		}
		return out
	}
	return RequireExplanation{OK: len(p.Errors) == 0 && len(p.Unsupported) == 0, Text: strings.Join(lines, "\n"), Errors: loc(p.Errors),
		Unsupported: loc(p.Unsupported), Warnings: warnings, Hints: loc(p.Hints)}
}
