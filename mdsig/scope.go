package mdsig

import (
	"fmt"
	"regexp"
	"strings"
)

type Section struct {
	ID         string
	Start, End int
	Line       int
}

var (
	sectionBeginRe  = regexp.MustCompile(`^<!-- mdsig:section ([a-z0-9-]+) -->[ \t]*$`)
	sectionEndRe    = regexp.MustCompile(`^<!-- /mdsig:section -->[ \t]*$`)
	sectionLookLike = regexp.MustCompile(`^<!-- /?mdsig:section`)
	sectionIDRe     = regexp.MustCompile(`^[a-z0-9-]+$`)
)

func looksLikeMarker(line string) bool {
	loc := sectionLookLike.FindStringIndex(line)
	if loc == nil {
		return false
	}
	if loc[1] < len(line) {
		c := line[loc[1]]
		if c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			return false
		}
	}
	return true
}

func FindSections(text string) (map[string]Section, []string) {
	sections := map[string]Section{}
	var errs []string
	var open *Section
	for _, fl := range linesWithFence(text) {
		line := fl.Line
		if fl.InFence || !looksLikeMarker(line) {
			continue
		}
		if b := sectionBeginRe.FindStringSubmatch(line); b != nil {
			if open != nil {
				errs = append(errs, fmt.Sprintf("line %d: section %s starts inside section %s (nesting is not allowed)", fl.Index+1, jsonString(b[1]), jsonString(open.ID)))
				continue
			}
			if _, dup := sections[b[1]]; dup {
				errs = append(errs, fmt.Sprintf("line %d: section id %s is used twice", fl.Index+1, jsonString(b[1])))
			}
			open = &Section{ID: b[1], Start: fl.Offset, Line: fl.Index + 1}
			continue
		}
		if sectionEndRe.MatchString(line) {
			if open == nil {
				errs = append(errs, fmt.Sprintf("line %d: end marker without a matching begin marker", fl.Index+1))
				continue
			}
			if _, dup := sections[open.ID]; !dup {
				sections[open.ID] = Section{ID: open.ID, Start: open.Start, End: fl.Offset + len(line), Line: open.Line}
			}
			open = nil
			continue
		}
		errs = append(errs, fmt.Sprintf("line %d: malformed section marker %s", fl.Index+1, jsonString(line)))
	}
	if open != nil {
		errs = append(errs, fmt.Sprintf("line %d: section %s is never closed", open.Line, jsonString(open.ID)))
	}
	return sections, errs
}

// SPEC 5.6: one section id per line, leading spaces ignored, ids unique
func ParseScope(value string) ([]string, bool) {
	var ids []string
	seen := map[string]bool{}
	for _, raw := range strings.Split(value, "\n") {
		l, _ := parseListLine(raw, nil)
		if l == nil || len(l.attrs) > 0 || !sectionIDRe.MatchString(l.target) || seen[l.target] {
			return nil, false
		}
		seen[l.target] = true
		ids = append(ids, l.target)
	}
	return ids, true
}

func FormatScope(ids []string) (string, bool) {
	for _, id := range ids {
		if !sectionIDRe.MatchString(id) {
			return "", false
		}
	}
	return strings.Join(ids, "\n"), true
}

type ScopeError struct {
	Code, Msg string
}

func (e *ScopeError) Error() string { return e.Msg }

func scopedHashInput(slice, scope string) (string, []string, *ScopeError) {
	ids, ok := ParseScope(scope)
	if !ok {
		return "", nil, &ScopeError{Code: "malformed", Msg: fmt.Sprintf("invalid scope %s (expected one section id per line, each id unique)", jsonString(scope))}
	}
	sections, errs := FindSections(slice)
	if len(errs) > 0 {
		return "", nil, &ScopeError{Code: "malformed", Msg: "section markers: " + strings.Join(errs, "; ")}
	}
	var b strings.Builder
	for _, id := range ids {
		s, ok := sections[id]
		if !ok {
			return "", nil, &ScopeError{Code: "scope-missing", Msg: fmt.Sprintf("section %s not found", jsonString(id))}
		}
		b.WriteString(normalizeDocument(slice[s.Start:s.End]))
	}
	return b.String(), ids, nil
}
