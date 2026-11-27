package mdsig

import (
	"fmt"
	"regexp"
	"strings"
)

// --- List-form lines (SPEC 3.5): target *(SP attr), attr = name ["=" value]

const (
	listAttrValue = "value"
	listAttrFlag  = "flag"
)

type listAttr struct {
	name  string
	value string
	flag  bool
}

type listLine struct {
	indent int
	target string
	attrs  []listAttr
	// attribute names the caller does not know; the caller decides whether that is malformed or unsupported
	unknown []string
}

func (l *listLine) get(name string) (listAttr, bool) {
	for _, a := range l.attrs {
		if a.name == name {
			return a, true
		}
	}
	return listAttr{}, false
}

var attrNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

func parseListLine(raw string, known map[string]string) (*listLine, string) {
	text := strings.TrimLeft(raw, " ")
	indent := len(raw) - len(text)
	if text == "" {
		return nil, "empty line"
	}
	parts := strings.Split(text, " ")
	// SPEC 3.5: exactly one SP between items
	for _, p := range parts {
		if p == "" {
			return nil, "items must be separated by exactly one space: " + jsonString(raw)
		}
	}
	// SPEC 3.5: the first item is always the target and may contain "="
	l := &listLine{indent: indent, target: parts[0]}
	for _, p := range parts[1:] {
		name, value, hasValue := strings.Cut(p, "=")
		if !attrNameRe.MatchString(name) {
			return nil, "invalid attribute " + jsonString(p)
		}
		if _, dup := l.get(name); dup {
			return nil, fmt.Sprintf("attribute %q appears twice", name)
		}
		if hasValue && value == "" {
			return nil, fmt.Sprintf("attribute %q has an empty value", name)
		}
		kind := known[name]
		if kind == listAttrValue && !hasValue {
			return nil, fmt.Sprintf("attribute %q needs a value", name)
		}
		if kind == listAttrFlag && hasValue {
			return nil, fmt.Sprintf("attribute %q takes no value", name)
		}
		if kind == "" {
			l.unknown = append(l.unknown, name)
		}
		l.attrs = append(l.attrs, listAttr{name: name, value: value, flag: !hasValue})
	}
	return l, ""
}
