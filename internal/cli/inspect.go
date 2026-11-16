package cli

import (
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/SHIOZAKI-Shota/md-signature/internal/i18n"
	"github.com/SHIOZAKI-Shota/md-signature/mdsig"
)

type inspectOptions struct{ json bool }

func newInspectCmd() *cobra.Command {
	o := &inspectOptions{}
	c := &cobra.Command{
		Use:   "inspect <file>",
		Short: "Print the signature chain and all fields (no network)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInspect(o, args[0])
		},
	}
	c.Flags().BoolVar(&o.json, "json", false, "print JSON to stdout")
	return c
}

type jsonBlock struct {
	Index        int               `json:"index"`
	Line         int               `json:"line"`
	Fields       map[string]string `json:"fields"`
	Errors       []string          `json:"errors"`
	HashOK       *bool             `json:"hash_ok"`
	ComputedHash *string           `json:"computed_hash"`
}

type jsonInspect struct {
	File            string      `json:"file"`
	BodyLines       int         `json:"body_lines"`
	StrayMarkerLine *int        `json:"stray_marker_line"`
	Warnings        []string    `json:"warnings"`
	Blocks          []jsonBlock `json:"signatures"`
}

func blockHash(doc *mdsig.ParsedDocument, b *mdsig.ParsedBlock) (computed string, ok *bool) {
	h, present := b.Fields["hash"]
	i := strings.IndexByte(h, ':')
	if !present || i < 0 || !mdsig.IsSupportedHash(h[:i]) {
		return "", nil
	}
	computed, _, se := mdsig.ComputeBlockHash(doc.Text, b, h[:i])
	if se != nil {
		return "", nil
	}
	match := computed == h
	return computed, &match
}

func runInspect(o *inspectOptions, file string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return exitf(exitIO, "%v", err)
	}
	if !utf8.Valid(data) {
		return exitf(exitFail, "%s", i18n.T("file.not_utf8", file))
	}
	doc := mdsig.ParseDocument(string(data))
	res := jsonInspect{File: file, BodyLines: strings.Count(doc.Body, "\n"), Warnings: []string{}, Blocks: []jsonBlock{}}
	if len(doc.Chain) == 0 {
		res.BodyLines = strings.Count(strings.TrimRight(doc.Body, "\n"), "\n") + 1
	}
	if doc.StrayMarker {
		l := doc.StrayMarkerLine
		res.StrayMarkerLine = &l
		if len(doc.Chain) == 0 {
			res.Warnings = append(res.Warnings, fmt.Sprintf("unsigned content after the last signature (signature block at line %d is followed by other text)", l))
		} else {
			res.Warnings = append(res.Warnings, fmt.Sprintf("line %d: an md-signature marker inside the body is treated as document content, not as a signature", l))
		}
	}
	for _, b := range doc.Chain {
		jb := jsonBlock{Index: b.Index, Line: b.Line, Fields: b.Fields, Errors: b.Errors}
		if jb.Errors == nil {
			jb.Errors = []string{}
		}
		computed, ok := blockHash(doc, b)
		jb.ComputedHash, jb.HashOK = strPtr(computed), ok
		res.Blocks = append(res.Blocks, jb)
	}
	if o.json {
		if err := writeJSON(res); err != nil {
			return exitf(exitIO, "%v", err)
		}
		return nil
	}

	w := stdout
	fmt.Fprintln(w, safeText(file))
	if len(doc.Chain) == 0 {
		fmt.Fprintf(w, "  %s\n", i18n.T("inspect.no_signatures"))
	} else {
		fmt.Fprintf(w, "  %s\n", i18n.N("inspect.summary", len(doc.Chain), len(doc.Chain), res.BodyLines))
	}
	for _, wn := range res.Warnings {
		fmt.Fprintf(w, "  ! %s\n", safeText(wn))
	}
	for _, jb := range res.Blocks {
		fmt.Fprintf(w, "\n  #%d  (%s)\n", jb.Index, i18n.T("inspect.line", jb.Line))
		switch {
		case jb.HashOK == nil:
			fmt.Fprintf(w, "    %s %s\n", mark("?"), i18n.T("inspect.hash_unchecked"))
		case *jb.HashOK:
			fmt.Fprintf(w, "    %s %s\n", mark("ok"), i18n.T("inspect.hash_ok"))
		default:
			fmt.Fprintf(w, "    %s %s\n", mark("x"), i18n.T("inspect.hash_bad", safeText(*jb.ComputedHash)))
		}
		for _, e := range jb.Errors {
			fmt.Fprintf(w, "    %s %s\n", mark("x"), safeText(e))
		}
		b := doc.Chain[jb.Index-1]
		width := 0
		keys := fieldKeysInBlockOrder(b)
		for _, k := range keys {
			width = max(width, len(k))
		}
		for _, k := range keys {
			v := strings.Join(safeLines(jb.Fields[k]), "\n      "+strings.Repeat(" ", width+1))
			fmt.Fprintf(w, "    %s  %s\n", pad(k+":", width+1), v)
		}
	}
	return nil
}

func fieldKeysInBlockOrder(b *mdsig.ParsedBlock) []string {
	var keys []string
	seen := map[string]bool{}
	for _, l := range strings.Split(b.Raw, "\n") {
		i := strings.Index(l, ": ")
		if i <= 0 || strings.HasPrefix(l, " ") {
			continue
		}
		k := l[:i]
		if _, ok := b.Fields[k]; ok && !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	return keys
}
