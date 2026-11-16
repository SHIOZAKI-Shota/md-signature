package i18n

import (
	"fmt"
	"os"
	"strings"
)

type Lang string

const (
	EN Lang = "en"
	JA Lang = "ja"
)

var current = EN

func Set(l Lang) { current = l }

func Current() Lang { return current }

func Parse(code string) (Lang, bool) {
	c := strings.ToLower(strings.TrimSpace(code))
	if i := strings.IndexAny(c, "_-.@"); i >= 0 {
		c = c[:i]
	}
	switch c {
	case "ja":
		return JA, true
	case "en":
		return EN, true
	}
	return EN, false
}

// CLI_SPEC 7: an unsupported value yields English instead of trying the next source
func Detect(flag string) Lang {
	if flag != "" {
		l, _ := Parse(flag)
		return l
	}
	if v := os.Getenv("MDSIG_LANG"); v != "" {
		l, _ := Parse(v)
		return l
	}
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(k); v != "" {
			l, _ := Parse(v)
			return l
		}
	}
	if v := systemUILanguage(); v != "" {
		l, _ := Parse(v)
		return l
	}
	return EN
}

func T(key string, args ...any) string {
	msg, ok := catalogs[current][key]
	if !ok {
		msg, ok = catalogs[EN][key]
	}
	if !ok {
		msg = key
	}
	if len(args) == 0 {
		return msg
	}
	return fmt.Sprintf(msg, args...)
}

func N(key string, n int, args ...any) string {
	k := key + ".other"
	if n == 1 {
		k = key + ".one"
	}
	return T(k, args...)
}

var catalogs = map[Lang]map[string]string{EN: en, JA: ja}
