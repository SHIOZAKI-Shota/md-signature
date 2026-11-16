package mdsig

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
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
}

var RequiredKeys = []string{"v", "method", "signer", "ts", "hash", "sig"}

func isBlank(l string) bool { return strings.Trim(l, " \t") == "" }
func isOpen(l string) bool  { return strings.TrimRight(l, " \t") == OpenLine }
func isClose(l string) bool { return strings.TrimRight(l, " \t") == CloseLine }

func noLineTerminator(s string) bool {
	return !strings.ContainsFunc(s, isJSLineTerminator)
}

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
	value = l[i+2:]
	if !noLineTerminator(value) {
		return "", "", false
	}
	return l[:i], value, true
}

func matchContLine(l string) (string, bool) {
	if !strings.HasPrefix(l, "  ") || len(l) < 3 {
		return "", false
	}
	rest := l[2:]
	r, _ := utf8.DecodeRuneInString(rest)
	if isJSSpace(r) || !noLineTerminator(rest) {
		return "", false
	}
	return rest, true
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

func ParseFields(lines []string) (map[string]string, []string, []string) {
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
				parts = append(parts, strings.TrimRight(c, " \t"))
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
		if !knownKeys[key] && !IsExtensionKey(key) {
			unknown = append(unknown, key)
			errs = append(errs, fmt.Sprintf("unknown field %q (extension fields must start with \"x_\")", key))
		}
		if ve := validateValue(value, folded); ve != "" {
			errs = append(errs, key+": "+ve)
		}
		fields[key] = value
	}
	for _, k := range RequiredKeys {
		if _, ok := fields[k]; !ok {
			errs = append(errs, fmt.Sprintf("missing required field %q", k))
		}
	}
	return fields, errs, unknown
}

func ParseDocument(input string) *ParsedDocument {
	text := NormalizeNewlines(input)
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
		fields, errs, unknown := ParseFields(lines[j+1 : i])
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
	fence := ""
	for k, l := range strings.Split(body, "\n") {
		if f := fenceOpen(l); f != "" {
			if fence == "" {
				fence = f
			} else if f[0] == fence[0] && len(f) >= len(fence) && isFenceClose(l) {
				fence = ""
			}
			continue
		}
		if fence == "" && isOpen(l) {
			stray = k + 1
		}
	}
	return &ParsedDocument{Text: text, Body: body, Chain: chain, StrayMarker: stray != 0, StrayMarkerLine: stray}
}

type FenceLine struct {
	Line          string
	Index, Offset int
	InFence       bool
}

func LinesWithFence(text string) []FenceLine {
	var out []FenceLine
	fence := ""
	offset := 0
	for k, l := range strings.Split(text, "\n") {
		inFence := fence != ""
		if f := fenceOpen(l); f != "" {
			if fence == "" {
				fence = f
			} else if f[0] == fence[0] && len(f) >= len(fence) && isFenceClose(l) {
				fence = ""
			}
			inFence = true
		}
		out = append(out, FenceLine{Line: l, Index: k, Offset: offset, InFence: inFence})
		offset += len(l) + 1
	}
	return out
}

func fenceOpen(l string) string {
	i := 0
	for i < len(l) && i < 3 && l[i] == ' ' {
		i++
	}
	if i >= len(l) || (l[i] != '`' && l[i] != '~') {
		return ""
	}
	c := l[i]
	j := i
	for j < len(l) && l[j] == c {
		j++
	}
	if j-i < 3 {
		return ""
	}
	return l[i:j]
}

func isFenceClose(l string) bool {
	i := 0
	for i < len(l) && i < 3 && l[i] == ' ' {
		i++
	}
	j := i
	for j < len(l) && (l[j] == '`' || l[j] == '~') {
		j++
	}
	if j == i {
		return false
	}
	return strings.Trim(l[j:], " \t") == ""
}
