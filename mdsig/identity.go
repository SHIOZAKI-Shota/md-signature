package mdsig

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// --- Identifier syntax (SPEC 3.4): checked as written, compared byte for byte

var (
	ldhLabelRe  = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	allDigitsRe = regexp.MustCompile(`^[0-9]+$`)
	// SPEC 3.4: RFC 5322 dot-atom-text with RFC 6531 UTF-8, no ASCII upper case; "*" is reserved for patterns
	emailLocalRe = regexp.MustCompile("^(?:[a-z0-9!#$%&'+\\-/=?^_\x60{|}~]|[^\\x00-\\x7f])+(?:\\.(?:[a-z0-9!#$%&'+\\-/=?^_\x60{|}~]|[^\\x00-\\x7f])+)*$")
	gitUserRe    = regexp.MustCompile(`^[a-z0-9._-]+$`)
	// SPEC 4.1: one label of [a-z0-9_-], 1-63 octets, not starting with "_" (reserved for _member)
	selectorRe = regexp.MustCompile(`^[a-z0-9-][a-z0-9_-]{0,62}$`)
	roleRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	tsaURLRe   = regexp.MustCompile(`^https?://\S+$`)
)

// SPEC 3.4: RFC 1123 / RFC 5890 A-label syntax, lower case, two or more labels, no trailing dot, last label not all digits
func isLdhDomain(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if !ldhLabelRe.MatchString(l) {
			return false
		}
	}
	return !allDigitsRe.MatchString(labels[len(labels)-1])
}

func isEmailID(s string) bool {
	at := strings.LastIndexByte(s, '@')
	if at <= 0 {
		return false
	}
	return utf8.ValidString(s) && emailLocalRe.MatchString(s[:at]) && isLdhDomain(s[at+1:])
}

func isGitHostingID(s string) bool {
	i := strings.IndexByte(s, '/')
	return i > 0 && isLdhDomain(s[:i]) && gitUserRe.MatchString(s[i+1:])
}

func isSelector(s string) bool { return selectorRe.MatchString(s) }

// SPEC 6.1: rp_id is a domain; "localhost" is kept for development passkeys
func isRPID(s string) bool { return s == "localhost" || isLdhDomain(s) }

func isRole(s string) bool { return roleRe.MatchString(s) }

func CheckSignerID(method, signer string) string {
	if strings.Contains(signer, "*") {
		return `signer must not contain "*"`
	}
	switch method {
	case "dns":
		if !isLdhDomain(signer) {
			return "dns signer must be a lower-case domain name (LDH labels, no trailing dot)"
		}
	case "git-hosting":
		if !isGitHostingID(signer) {
			return "git-hosting signer must be <host>/<username> in lower case with a domain name as host"
		}
	case "pgp", "directory":
		if !isEmailID(signer) {
			return method + " signer must be a lower-case email address with a domain name"
		}
	case "tofu":
		if strings.Contains(signer, " ") {
			return "tofu signer must not contain spaces"
		}
	case "tsa":
		if !tsaURLRe.MatchString(signer) || !jsNonSpace(signer) {
			return "tsa signer must be the http(s) URL of the time-stamping authority"
		}
	}
	return ""
}

func asciiLower(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 32
		}
		return r
	}, s)
}

func CanonicalSignerInput(method, signer string) string {
	switch method {
	case "dns":
		return strings.TrimSuffix(asciiLower(signer), ".")
	case "git-hosting", "pgp", "directory":
		return asciiLower(signer)
	}
	return signer
}

// SPEC 3.4: keys compare as decoded bytes, so raw and SPKI spellings of one key are equal
func decodeKeyValue(value string) (string, []byte, bool) {
	i := strings.IndexByte(value, ':')
	if i <= 0 {
		return "", nil, false
	}
	raw, err := fromBase64(value[i+1:])
	if err != nil {
		return "", nil, false
	}
	key, err := decodePublicKey(value[:i], raw)
	if err != nil {
		return "", nil, false
	}
	return value[:i], key, true
}

func sameKeyValue(a, b string) bool {
	ta, ka, ok1 := decodeKeyValue(a)
	tb, kb, ok2 := decodeKeyValue(b)
	return ok1 && ok2 && ta == tb && bytes.Equal(ka, kb)
}

// --- display_name (SPEC 3.3): RFC 8266 Nickname, simplified

// SPEC 3.3: verifiers check only the length
func checkDisplayNameLength(v string) string {
	if utf8.RuneCountInString(v) > 64 {
		return "display_name is longer than 64 code points"
	}
	return ""
}

// generators: the value must be unchanged by the Nickname enforcement rules
func checkDisplayName(v string) string {
	if e := checkDisplayNameLength(v); e != "" {
		return e
	}
	if strings.ContainsFunc(v, func(r rune) bool { return r != ' ' && unicode.Is(unicode.Zs, r) }) {
		return "display_name must use U+0020 for spaces"
	}
	if v != norm.NFKC.String(v) {
		return "display_name must be in Unicode NFKC form"
	}
	if strings.Contains(v, "  ") {
		return "display_name must not contain consecutive spaces"
	}
	return ""
}

var multiSpaceRe = regexp.MustCompile(` {2,}`)

// RFC 8266 enforcement without the FreeformClass repertoire check: spaces to U+0020, trim, collapse, NFKC
func nicknameEnforce(v string) string {
	v = strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Zs, r) {
			return ' '
		}
		return r
	}, v)
	v = multiSpaceRe.ReplaceAllString(strings.TrimFunc(v, isJSSpace), " ")
	return norm.NFKC.String(v)
}

func displayNameInput(v string) (string, error) {
	name := nicknameEnforce(v)
	if e := checkDisplayName(name); e != "" {
		return "", fmt.Errorf("%s", e)
	}
	return name, nil
}
