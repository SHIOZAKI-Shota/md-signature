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

// SPEC 3.2: verifiers accept every format version listed here; generators write SpecVersion (must match packages/core canonical.ts)
var supportedVersions = map[string]bool{"0.0.1": true, "0.0.2": true, "0.0.4": true}

const (
	// must match packages/core canonical.ts
	SpecVersion   = "0.0.4"
	payloadDomain = "md-signature/v1"
	openLine      = "<!-- md-signature"
	closeLine     = "-->"
	foldWidth     = 76
)

const bom = string(rune(0xFEFF))

var unsignedKeys = map[string]bool{"sig": true, "tsa_url": true, "tsa_token": true, "webauthn_authenticator_data": true, "webauthn_client_data": true}

var fieldOrder = []string{
	"v", "method", "signer", "selector", "key_fp", "fpr", "pubkey", "rp_id",
	"role", "reason", "ts", "expires", "scope", "require", "resources", "revocation_url",
	"alg", "hash", "sig", "webauthn_authenticator_data", "webauthn_client_data", "tsa_url", "tsa_token",
}

var knownKeys = func() map[string]bool {
	m := map[string]bool{}
	for _, k := range fieldOrder {
		m[k] = true
	}
	return m
}()

func isKnownKey(key string) bool { return knownKeys[key] }

func isExtensionKey(key string) bool { return strings.HasPrefix(key, "x_") }

var binaryKeys = map[string]bool{"sig": true, "tsa_token": true, "webauthn_authenticator_data": true, "webauthn_client_data": true}

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

const msgControl = "value must not contain control characters or line breaks"

// SPEC 3.2 rule 4: C0, DEL, C1, line separators, bidi controls
func isForbiddenRune(r rune) bool {
	return r <= 0x1f || (r >= 0x7f && r <= 0x9f) || r == 0x2028 || r == 0x2029 || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)
}

func validateLine(value string) string {
	if value == "" {
		return "value is empty"
	}
	if strings.Contains(value, "--") {
		return `value must not contain "--"`
	}
	for _, r := range value {
		if isForbiddenRune(r) {
			return msgControl
		}
	}
	if strings.TrimFunc(value, isJSSpace) != value {
		return "value must not have leading or trailing whitespace"
	}
	return ""
}

func ValidateValue(value string) string { return validateValue(value, false) }

func validateValueMultiline(value string) string { return validateValue(value, true) }

func validateValue(value string, allowMultiline bool) string {
	if strings.Contains(value, "\n") {
		if !allowMultiline {
			return msgControl
		}
		for _, line := range strings.Split(value, "\n") {
			if e := validateLine(line); e != "" {
				return e
			}
		}
		return ""
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
		if e := validateValueMultiline(v); e != "" {
			return "", fmt.Errorf("%s: %s", k, e)
		}
		switch {
		case strings.Contains(v, "\n"):
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
