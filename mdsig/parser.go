package mdsig

import (
	"encoding/json"
	"fmt"
	"strings"
)

type ParsedBlock struct {
	Index       int
	Start       int
	End         int
	Line        int
	Raw         string
	Fields      map[string]string
	Errors      []string
	UnknownKeys []string
}

type ParsedDocument struct {
	Text            string
	Body            string
	Chain           []*ParsedBlock
	StrayMarker     bool
	StrayMarkerLine int
	// SPEC 5.5: the body ends inside an open code fence, so a renderer shows every block as code
	UnclosedFence bool
}

var requiredKeys = []string{"v", "method", "signer", "ts", "alg", "hash", "sig"}

func isBlank(l string) bool { return strings.Trim(l, " \t") == "" }
func isOpen(l string) bool  { return strings.TrimRight(l, " \t") == openLine }
func isClose(l string) bool { return strings.TrimRight(l, " \t") == closeLine }

// a value with U+2028 or U+2029 is still read as one line, and then rejected by rule 4
func matchFieldLine(l string) (key, value string, ok bool) {
	if l == "" || l[0] < 'a' || l[0] > 'z' {
		return "", "", false
	}
	i := 1
	for i < len(l) && (l[i] >= 'a' && l[i] <= 'z' || l[i] >= '0' && l[i] <= '9' || l[i] == '_') {
		i++
	}
	if !strings.HasPrefix(l[i:], ": ") {
		return "", "", false
	}
	return l[:i], l[i+2:], true
}

// SPEC 3.2: cont-line = 2SP *SP vchar ...; spaces after the first two belong to the value
func matchContLine(l string) (string, bool) {
	if !strings.HasPrefix(l, "  ") || strings.TrimLeft(l, " ") == "" {
		return "", false
	}
	return l[2:], true
}

func isFieldish(l string) bool {
	if _, _, ok := matchFieldLine(l); ok {
		return true
	}
	_, ok := matchContLine(l)
	return ok
}

func jsonString(s string) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSuffix(b.String(), "\n")
}

func parseFields(lines []string) (map[string]string, []string, []string) {
	fields := map[string]string{}
	var errs, unknown []string
	i := 0
	for i < len(lines) {
		line := lines[i]
		key, value, ok := matchFieldLine(line)
		if !ok {
			errs = append(errs, fmt.Sprintf("line %d: expected \"key: value\", got %s", i+1, jsonString(line)))
			i++
			continue
		}
		i++
		folded := false
		if value == "|" {
			folded = true
			var parts []string
			for i < len(lines) {
				c, ok := matchContLine(lines[i])
				if !ok {
					break
				}
				parts = append(parts, c)
				i++
			}
			if len(parts) == 0 {
				errs = append(errs, key+": folded value has no continuation lines")
			}
			value = strings.Join(parts, "\n")
		}
		if _, dup := fields[key]; dup {
			errs = append(errs, fmt.Sprintf("duplicate key %q", key))
			continue
		}
		if !knownKeys[key] && !isExtensionKey(key) {
			unknown = append(unknown, key)
			errs = append(errs, fmt.Sprintf("unknown field %q (extension fields must start with \"x_\")", key))
		}
		if !folded || value != "" {
			if ve := validateValue(value, folded); ve != "" {
				errs = append(errs, key+": "+ve)
			}
		}
		fields[key] = value
	}
	for _, k := range requiredKeys {
		if _, ok := fields[k]; !ok {
			errs = append(errs, fmt.Sprintf("missing required field %q", k))
		}
	}
	return fields, errs, unknown
}

func ParseDocument(input string) *ParsedDocument {
	text := normalizeNewlines(input)
	lines := strings.Split(text, "\n")
	offsets := make([]int, len(lines))
	o := 0
	for k, l := range lines {
		offsets[k] = o
		o += len(l) + 1
	}

	var found []*ParsedBlock
	i := len(lines) - 1
	for {
		for i >= 0 && isBlank(lines[i]) {
			i--
		}
		if i < 0 || !isClose(lines[i]) {
			break
		}
		j := i - 1
		for j >= 0 && !isOpen(lines[j]) && isFieldish(lines[j]) {
			j--
		}
		if j < 0 || !isOpen(lines[j]) {
			break
		}
		fields, errs, unknown := parseFields(lines[j+1 : i])
		start := offsets[j]
		end := offsets[i] + len(lines[i])
		found = append(found, &ParsedBlock{Start: start, End: end, Line: j + 1, Raw: text[start:end], Fields: fields, Errors: errs, UnknownKeys: unknown})
		i = j - 1
	}
	chain := make([]*ParsedBlock, len(found))
	for k := range found {
		b := found[len(found)-1-k]
		b.Index = k + 1
		chain[k] = b
	}
	bodyEnd := len(text)
	if len(chain) > 0 {
		bodyEnd = chain[0].Start
	}
	body := text[:bodyEnd]

	stray := 0
	for _, fl := range linesWithFence(body) {
		if !fl.InFence && isOpen(fl.Line) {
			stray = fl.Index + 1
		}
	}
	return &ParsedDocument{Text: text, Body: body, Chain: chain, StrayMarker: stray != 0, StrayMarkerLine: stray, UnclosedFence: endsInOpenFence(body)}
}

type fenceLine struct {
	Line          string
	Index, Offset int
	InFence       bool
	// set on the opening line of a fence: its info string, trimmed
	Info   string
	IsOpen bool
	Close  bool
}

// SPEC 5.5: a line scan, not a full CommonMark parse; a fence closes with the same character at least as many times
func linesWithFence(text string) []fenceLine {
	var out []fenceLine
	fence := ""
	offset := 0
	for k, l := range strings.Split(text, "\n") {
		if fence == "" {
			if f, info, ok := fenceOpen(l); ok {
				fence = f
				out = append(out, fenceLine{Line: l, Index: k, Offset: offset, InFence: true, Info: info, IsOpen: true})
			} else {
				out = append(out, fenceLine{Line: l, Index: k, Offset: offset})
			}
		} else {
			closes := fenceCloses(l, fence)
			if closes {
				fence = ""
			}
			out = append(out, fenceLine{Line: l, Index: k, Offset: offset, InFence: true, Close: closes})
		}
		offset += len(l) + 1
	}
	return out
}

func endsInOpenFence(text string) bool {
	fence := ""
	for _, l := range strings.Split(text, "\n") {
		if fence == "" {
			if f, _, ok := fenceOpen(l); ok {
				fence = f
			}
		} else if fenceCloses(l, fence) {
			fence = ""
		}
	}
	return fence != ""
}

func fenceRun(l string) (int, string) {
	i := 0
	for i < len(l) && i < 3 && l[i] == ' ' {
		i++
	}
	if i >= len(l) || (l[i] != '`' && l[i] != '~') {
		return 0, ""
	}
	c := l[i]
	j := i
	for j < len(l) && l[j] == c {
		j++
	}
	if j-i < 3 {
		return 0, ""
	}
	return j, l[i:j]
}

// SPEC 5.5 (CommonMark 4.5): a backtick fence's info string cannot contain a backtick
func fenceOpen(l string) (fence, info string, ok bool) {
	j, f := fenceRun(l)
	if f == "" || (f[0] == '`' && strings.Contains(l[j:], "`")) {
		return "", "", false
	}
	return f, strings.TrimFunc(l[j:], isJSSpace), true
}

func fenceCloses(l, fence string) bool {
	j, f := fenceRun(l)
	return f != "" && f[0] == fence[0] && len(f) >= len(fence) && strings.Trim(l[j:], " \t") == ""
}
