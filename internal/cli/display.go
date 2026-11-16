package cli

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// --- terminal-safe text

func unsafeRune(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029
}

// document-controlled text must not reach the terminal with escape sequences, bidi overrides or invisible characters
func safeText(s string) string {
	if utf8.ValidString(s) && !strings.ContainsFunc(s, unsafeRune) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x{%02X}`, s[i])
		case unsafeRune(r):
			fmt.Fprintf(&b, `\u{%04X}`, r)
		default:
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}

func safeLines(s string) []string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = safeText(l)
	}
	return lines
}

func safeAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = safeText(s)
	}
	return out
}
