package mdsig

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

const (
	// must match packages/core canonical.ts; SPEC 3.3: other versions are unsupported (SPEC 5.4 step 1)
	SpecVersion   = "0.1"
	payloadDomain = "md-signature/v1"
	openLine      = "<!-- md-signature"
	closeLine     = "-->"
	foldWidth     = 76
)

const bom = string(rune(0xFEFF))

var supportedVersions = map[string]bool{SpecVersion: true}

var unsignedKeys = map[string]bool{"sig": true, "webauthn_authenticator_data": true, "webauthn_client_data": true}

var fieldOrder = []string{
	"v", "method", "signer", "selector", "key_fp", "fpr", "pubkey", "rp_id",
	"display_name", "role", "reason", "ts", "expires", "scope", "require", "resources", "revocation_url",
	"alg", "hash", "sig", "webauthn_authenticator_data", "webauthn_client_data",
}

// SPEC 3.5: values of these fields are lists, one item per line
var listKeys = map[string]bool{"scope": true, "require": true, "resources": true}

var knownKeys = func() map[string]bool {
	m := map[string]bool{}
	for _, k := range fieldOrder {
		m[k] = true
	}
	return m
}()

func isKnownKey(key string) bool { return knownKeys[key] }

func isExtensionKey(key string) bool { return strings.HasPrefix(key, "x_") }

var binaryKeys = map[string]bool{"sig": true, "webauthn_authenticator_data": true, "webauthn_client_data": true}

var tsRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)

var keyRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

func normalizeNewlines(text string) string {
	text = strings.TrimPrefix(text, bom)
	text = strings.ReplaceAll(text, "\r\n", "\n")
	return strings.ReplaceAll(text, "\r", "\n")
}

func normalizeDocument(text string) string {
	return strings.TrimRight(normalizeNewlines(text), "\n \t") + "\n"
}

func normalizedHash(text string) string {
	sum := sha256.Sum256([]byte(normalizeDocument(text)))
	return "sha256:" + toHex(sum[:])
}

func SignedPayload(fields map[string]string) []byte {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		if !unsignedKeys[k] {
			keys = append(keys, k)
		}
	}
	// byte-wise, same as JS < for ASCII keys
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(payloadDomain)
	b.WriteString("\n")
	for i, k := range keys {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(strings.ReplaceAll(fields[k], "\n", "\n  "))
	}
	return []byte(b.String())
}

const msgControl = "value must not contain control characters, format characters, line breaks, or noncharacters"

// SPEC 3.2 rule 3: CommonMark HTML block type 2 ends at "-->"; WHATWG comments also end at "--!>"; "<!--" opens a nested comment
var forbiddenSequences = []string{"-->", "--!>", "<!--"}

// SPEC 3.2 rule 4: Cc, Cf, Zl, Zp of Unicode 15.0.0, pinned to the same table as canonical.ts whatever Go's Unicode version
var forbiddenRanges = [][2]rune{
	{0x0000, 0x001f}, {0x007f, 0x009f}, {0x00ad, 0x00ad}, {0x0600, 0x0605}, {0x061c, 0x061c}, {0x06dd, 0x06dd},
	{0x070f, 0x070f}, {0x0890, 0x0891}, {0x08e2, 0x08e2}, {0x180e, 0x180e}, {0x200b, 0x200f}, {0x2028, 0x202e},
	{0x2060, 0x2064}, {0x2066, 0x206f}, {0xd800, 0xdfff}, {0xfeff, 0xfeff}, {0xfff9, 0xfffb}, {0x110bd, 0x110bd},
	{0x110cd, 0x110cd}, {0x13430, 0x1343f}, {0x1bca0, 0x1bca3}, {0x1d173, 0x1d17a}, {0xe0001, 0xe0001}, {0xe0020, 0xe007f},
}

func isForbiddenRune(r rune) bool {
	for _, g := range forbiddenRanges {
		if r >= g[0] && r <= g[1] {
			return true
		}
	}
	// noncharacters
	return (r >= 0xfdd0 && r <= 0xfdef) || r&0xfffe == 0xfffe
}

func validateLine(value string) string {
	if value == "" {
		return "value is empty"
	}
	for _, seq := range forbiddenSequences {
		if strings.Contains(value, seq) {
			return fmt.Sprintf("value must not contain %q", seq)
		}
	}
	if strings.ContainsFunc(value, isForbiddenRune) {
		return msgControl
	}
	if strings.HasSuffix(value, " ") {
		return "value must not have trailing spaces"
	}
	return ""
}

func ValidateValue(value string) string { return validateValue(value, false) }

// a folded line keeps its leading spaces (SPEC 3.2 cont-line); a single-line value may not start with one
func validateValue(value string, allowMultiline bool) string {
	if strings.Contains(value, "\n") {
		if !allowMultiline {
			return msgControl
		}
		for _, line := range strings.Split(value, "\n") {
			if strings.TrimLeft(line, " ") == "" {
				return "a folded line must not be empty"
			}
			if e := validateLine(line); e != "" {
				return e
			}
		}
		return ""
	}
	if strings.HasPrefix(value, " ") && !allowMultiline {
		return "value must not have leading spaces"
	}
	if allowMultiline && strings.TrimLeft(value, " ") == "" {
		return "a folded line must not be empty"
	}
	return validateLine(value)
}

func validateKey(key string) string {
	if keyRe.MatchString(key) {
		return ""
	}
	return fmt.Sprintf("invalid key %q", key)
}

// mirrors canonical.ts: x_*/unknown keys go before alg, or after revocation_url if there is no alg
func orderedKeys(fields map[string]string) []string {
	var known []string
	for _, k := range fieldOrder {
		if _, ok := fields[k]; ok {
			known = append(known, k)
		}
	}
	var extra []string
	for k := range fields {
		if !knownKeys[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	at := slices.Index(known, "alg")
	if at < 0 {
		rev := slices.Index(fieldOrder, "revocation_url")
		at = slices.IndexFunc(known, func(k string) bool { return slices.Index(fieldOrder, k) > rev })
	}
	if at < 0 {
		at = len(known)
	}
	out := append([]string{}, known[:at]...)
	out = append(out, extra...)
	return append(out, known[at:]...)
}

func serializeBlock(fields map[string]string) (string, error) {
	lines := []string{openLine}
	for _, k := range orderedKeys(fields) {
		v := fields[k]
		if e := validateKey(k); e != "" {
			return "", errors.New(e)
		}
		folded := strings.Contains(v, "\n") || strings.HasPrefix(v, " ")
		if e := validateValue(v, folded); e != "" {
			return "", fmt.Errorf("%s: %s", k, e)
		}
		switch {
		case folded:
			lines = append(lines, k+": |")
			for _, l := range strings.Split(v, "\n") {
				lines = append(lines, "  "+l)
			}
		case binaryKeys[k] && utf16Len(v) > foldWidth:
			lines = append(lines, k+": |")
			for _, part := range chunkUTF16(v, foldWidth) {
				lines = append(lines, "  "+part)
			}
		default:
			lines = append(lines, k+": "+v)
		}
	}
	lines = append(lines, closeLine)
	return strings.Join(lines, "\n"), nil
}

// JS string length (UTF-16 code units)
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}

func chunkUTF16(s string, width int) []string {
	var out []string
	var cur strings.Builder
	n := 0
	for _, r := range s {
		w := 1
		if r >= 0x10000 {
			w = 2
		}
		if n+w > width && n > 0 {
			out = append(out, cur.String())
			cur.Reset()
			n = 0
		}
		cur.WriteRune(r)
		n += w
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// must round-trip, so 2026-02-30 and 24:00:00 are rejected
func IsValidTimestamp(s string) bool {
	if !tsRe.MatchString(s) {
		return false
	}
	t, err := time.Parse(tsLayout, s)
	return err == nil && t.UTC().Format(tsLayout) == s
}

const tsLayout = "2006-01-02T15:04:05Z"

func UnfoldBinary(v string) string {
	return strings.Map(func(r rune) rune {
		if isJSSpace(r) {
			return -1
		}
		return r
	}, v)
}

func NowTS(t time.Time) string {
	return t.UTC().Format(tsLayout)
}
