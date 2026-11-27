package mdsig

import (
	"fmt"
	"regexp"
	"strings"
)

// --- Signature table (SPEC 5.11, 9.5, CLI_SPEC 3.10): built from the blocks, never written into the body

const SignatureMarker = "<!-- mdsig:signatures -->"

var signatureMarkerRe = regexp.MustCompile(`^<!-- mdsig:signatures -->[ \t]*$`)

// SPEC 5.11: one marker per body, outside code fences; later and fenced ones only warn (line 0: none)
func FindSignatureMarker(body string) (line, offset int, warnings []string) {
	warnings = []string{}
	for _, l := range linesWithFence(body) {
		if !signatureMarkerRe.MatchString(l.Line) {
			continue
		}
		switch {
		case l.InFence:
			warnings = append(warnings, fmt.Sprintf("line %d: %s inside a code fence is ignored", l.Index+1, SignatureMarker))
		case line != 0:
			warnings = append(warnings, fmt.Sprintf("line %d: only the first %s is used; this one is ignored", l.Index+1, SignatureMarker))
		default:
			line, offset = l.Index+1, l.Offset
		}
	}
	return line, offset, warnings
}

type SignatureRow struct {
	// block number; 0 for a row that is still to be signed
	Number int
	// self-declared; always shown together with Signer
	DisplayName string
	Method      string
	Signer      string
	// how the identity was checked: the key source of a verified block
	KeySource string
	Role      string
	TS        string
	// T(k) (SPEC 4.6)
	Time string
	// nil when the row is not a passkey signature (or, unsigned, does not ask for user verification)
	UserVerified *bool
	// block status, or "unsigned"
	Status  string
	Code    string
	Partial []string
	// unsigned rows: the requirement this row stands for
	DeclaredBy int
	Step       int
	Need       int
	Pattern    bool
	Attributes RequirementAttributes
}

func unsignedRow(r Requirement, need int) SignatureRow {
	row := SignatureRow{Method: r.Method, Signer: r.Signer, Role: r.Attributes.Role, Status: "unsigned",
		DeclaredBy: r.DeclaredBy, Step: r.Step, Need: need, Pattern: r.Pattern, Attributes: r.Attributes}
	if r.Attributes.UserVerified {
		f := false
		row.UserVerified = &f
	}
	return row
}

// SignatureTable lists the signature blocks (tsa blocks left out) and, from Agreement.Next, the rows still to be signed.
func SignatureTable(r *VerifyResult) []SignatureRow {
	rows := []SignatureRow{}
	for _, s := range r.Signatures {
		if s.Fields["method"] == "tsa" {
			continue
		}
		row := SignatureRow{Number: s.Index, DisplayName: s.Fields["display_name"], Method: s.Fields["method"], Signer: s.Fields["signer"],
			Role: s.Fields["role"], TS: s.Fields["ts"], Status: s.Status, Code: s.Code, Partial: s.Partial}
		if s.Status == StatusValid {
			row.KeySource = s.KeySource
		}
		if s.Time != nil {
			row.Time = s.Time.At
		}
		if s.Fields["alg"] == "webauthn-es256" {
			uv := s.Status == StatusValid && s.WebAuthn != nil && s.WebAuthn.UserVerified
			row.UserVerified = &uv
		}
		rows = append(rows, row)
	}
	// CLI_SPEC 3.10: unsigned rows come from next
	for _, n := range r.Agreement.Next {
		for _, c := range n.Candidates {
			rows = append(rows, unsignedRow(c, n.Need))
		}
		for _, l := range n.Later {
			for _, c := range l.Lines {
				rows = append(rows, unsignedRow(c, l.Need))
			}
		}
	}
	return rows
}

type tableLabels struct {
	caption  string
	head     []string
	status   map[string]string
	yes, no  string
	partial  string
	any      func(n int) string
	declared string
	step     func(n, need int) string
}

var signatureTableLabels = map[string]tableLabels{
	"ja": {
		caption:  "署名欄",
		head:     []string{"番号", "表示名（申告）", "署名者", "身元の確認", "役割", "申告時刻", "時刻証明", "利用者確認", "状態"},
		status:   map[string]string{"valid": "有効", "invalid": "無効", "malformed": "形式不正", "unresolved": "未確認", "unsupported": "未対応", "unsigned": "未署名"},
		yes:      "あり",
		no:       "なし",
		partial:  "部分",
		any:      func(n int) string { return fmt.Sprintf("いずれか %d者", n) },
		declared: "（申告）",
		step:     func(n, need int) string { return fmt.Sprintf("段階 %d、あと %d者", n, need) },
	},
	"en": {
		caption:  "Signatures",
		head:     []string{"No.", "Display name (declared)", "Signer", "Identity check", "Role", "Declared time", "Timestamp", "User verified", "Status"},
		status:   map[string]string{"valid": "Valid", "invalid": "Invalid", "malformed": "Malformed", "unresolved": "Unresolved", "unsupported": "Unsupported", "unsigned": "Unsigned"},
		yes:      "Yes",
		no:       "No",
		partial:  "partial",
		any:      func(n int) string { return fmt.Sprintf("any %d", n) },
		declared: " (declared)",
		step:     func(n, need int) string { return fmt.Sprintf("step %d, %d more", n, need) },
	},
}

var htmlEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")

func attributeWords(a RequirementAttributes) []string {
	var out []string
	if a.Role != "" {
		out = append(out, "role="+a.Role)
	}
	if a.Pubkey != "" {
		out = append(out, "pubkey="+a.Pubkey)
	}
	if a.UserVerified {
		out = append(out, "user_verified")
	}
	if a.MemberOf != "" {
		out = append(out, "member_of="+a.MemberOf)
	}
	return out
}

// security: every cell is escaped and nothing comes from the body; render it outside the sanitized body DOM (SPEC 9.5)
func RenderSignatureTableHTML(rows []SignatureRow, lang string) string {
	L, ok := signatureTableLabels[lang]
	if !ok {
		L = signatureTableLabels["en"]
	}
	cell := func(v string, null bool) string {
		if null {
			return "<td></td>"
		}
		return "<td>" + htmlEscaper.Replace(v) + "</td>"
	}
	var b strings.Builder
	b.WriteString(`<table class="mdsig-signatures"><caption>` + htmlEscaper.Replace(L.caption) + "</caption><thead><tr>")
	for _, h := range L.head {
		b.WriteString("<th>" + htmlEscaper.Replace(h) + "</th>")
	}
	b.WriteString("</tr></thead><tbody>")
	for _, r := range rows {
		status := r.Status
		if s, ok := L.status[r.Status]; ok {
			status = s
		}
		if r.Partial != nil {
			status += fmt.Sprintf(" (%s: %s)", L.partial, strings.Join(r.Partial, ", "))
		}
		if r.Code != "" && r.Status != StatusValid {
			status += " [" + r.Code + "]"
		}
		unsigned := r.Status == "unsigned"
		signer := r.Method + ":" + r.Signer
		if unsigned {
			if w := attributeWords(r.Attributes); len(w) > 0 {
				signer += " " + strings.Join(w, " ")
			}
			if r.Pattern && r.Need != 0 {
				signer += " (" + L.any(r.Need) + ")"
			}
		}
		number := fmt.Sprintf("#%d", r.Number)
		if r.Number == 0 {
			number = L.step(r.Step, r.Need)
		}
		uv := ""
		if r.UserVerified != nil {
			uv = L.no
			if *r.UserVerified {
				uv = L.yes
			}
		}
		b.WriteString(`<tr class="mdsig-` + htmlEscaper.Replace(r.Status) + `">`)
		b.WriteString(cell(number, false))
		b.WriteString(cell(r.DisplayName+L.declared, r.DisplayName == ""))
		b.WriteString(cell(signer, false))
		b.WriteString(cell(r.KeySource, r.KeySource == ""))
		b.WriteString(cell(r.Role, r.Role == ""))
		b.WriteString(cell(r.TS, r.TS == ""))
		b.WriteString(cell(r.Time, r.Time == ""))
		b.WriteString(cell(uv, r.UserVerified == nil))
		b.WriteString(cell(status, false))
		b.WriteString("</tr>")
	}
	b.WriteString("</tbody></table>")
	return b.String()
}

// JSONSignatureRow is one row of the signature table in the snake_case form of examples/expected.json
type JSONSignatureRow struct {
	Number       *int            `json:"number"`
	DisplayName  *string         `json:"display_name"`
	Method       string          `json:"method"`
	Signer       string          `json:"signer"`
	KeySource    *string         `json:"key_source"`
	Role         *string         `json:"role"`
	TS           *string         `json:"ts"`
	Time         *string         `json:"time"`
	UserVerified *bool           `json:"user_verified"`
	Status       string          `json:"status"`
	Code         *string         `json:"code"`
	Partial      []string        `json:"partial"`
	DeclaredBy   *int            `json:"declared_by,omitempty"`
	Step         *int            `json:"step,omitempty"`
	Need         *int            `json:"need,omitempty"`
	Pattern      *bool           `json:"pattern,omitempty"`
	Attributes   *JSONAttributes `json:"attributes,omitempty"`
}

func SignatureTableToJSON(rows []SignatureRow) []JSONSignatureRow {
	out := []JSONSignatureRow{}
	for _, r := range rows {
		j := JSONSignatureRow{DisplayName: strPtr(r.DisplayName), Method: r.Method, Signer: r.Signer, KeySource: strPtr(r.KeySource), Role: strPtr(r.Role),
			TS: strPtr(r.TS), Time: strPtr(r.Time), UserVerified: r.UserVerified, Status: r.Status, Code: strPtr(r.Code), Partial: r.Partial}
		if r.Number != 0 {
			n := r.Number
			j.Number = &n
		}
		if r.Status == "unsigned" {
			d, s, n, p, a := r.DeclaredBy, r.Step, r.Need, r.Pattern, JSONAttributes(r.Attributes)
			j.DeclaredBy, j.Step, j.Need, j.Pattern, j.Attributes = &d, &s, &n, &p, &a
		}
		out = append(out, j)
	}
	return out
}
