package mdsig

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"strconv"
	"sync"
)

// --- localized messages

//go:embed messages_ja.json
var messagesJA []byte

type messageEntry struct {
	re *regexp.Regexp
	ja string
}

const maxMessageDepth = 8

var (
	messageOnce        sync.Once
	messageCatalog     []messageEntry
	messagePlaceholder = regexp.MustCompile(`\{(\d+)(:msg)?\}`)
)

func loadMessageCatalog() {
	var raw []struct {
		En string `json:"en"`
		Ja string `json:"ja"`
	}
	if err := json.Unmarshal(messagesJA, &raw); err != nil {
		panic("mdsig: messages_ja.json: " + err.Error())
	}
	for _, e := range raw {
		messageCatalog = append(messageCatalog, messageEntry{re: regexp.MustCompile(e.En), ja: e.Ja})
	}
}

func LocalizeMessage(text, lang string) string {
	if lang != "ja" {
		return text
	}
	messageOnce.Do(loadMessageCatalog)
	return localizeMessage(text, 0)
}

func localizeMessage(text string, depth int) string {
	if depth > maxMessageDepth {
		return text
	}
	for _, e := range messageCatalog {
		m := e.re.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		return messagePlaceholder.ReplaceAllStringFunc(e.ja, func(p string) string {
			sub := messagePlaceholder.FindStringSubmatch(p)
			n, _ := strconv.Atoi(sub[1])
			g := ""
			if n < len(m) {
				g = m[n]
			}
			if sub[2] != "" {
				return localizeMessage(g, depth+1)
			}
			return g
		})
	}
	return text
}
