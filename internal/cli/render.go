package cli

import (
	"bytes"
	"context"
	"fmt"
	"html"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"

	"mdsig.dev/internal/i18n"
	"mdsig.dev/mdsig"
)

// --- render (CLI_SPEC 3.10)

type renderOptions struct {
	verifyOptions
	out string
}

func newRenderCmd() *cobra.Command {
	o := &renderOptions{}
	c := &cobra.Command{
		Use:   "render <file>",
		Short: "Verify a document and write its body and signature table as HTML",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRender(o, args[0])
		},
	}
	f := c.Flags()
	f.StringVarP(&o.out, "out", "o", "", "output HTML file (default: stdout)")
	f.BoolVar(&o.offline, "offline", false, "do not use the network")
	f.BoolVar(&o.fetchResources, "fetch-resources", false, "fetch https:// resources and check their hashes")
	f.BoolVar(&o.noRevocation, "no-revocation", false, "do not fetch revocation lists")
	f.StringVar(&o.keyserver, "keyserver", "", "pgp only: https:// keyserver to look keys up on")
	f.StringArrayVar(&o.keyDirectories, "key-directory", nil, "directory only: also trust this https:// key directory for this run (repeatable)")
	f.StringArrayVar(&o.tsaRoots, "tsa-root", nil, "also trust this root certificate when checking a timestamp token (repeatable)")
	return c
}

// markdown without raw HTML: scripts, event attributes, form elements, and style attributes never reach the output (CLI_SPEC 3.10 rule 2)
var renderMarkdown = goldmark.New(goldmark.WithExtensions(extension.GFM))

func markdownHTML(src string) (string, error) {
	var b bytes.Buffer
	if err := renderMarkdown.Convert([]byte(src), &b); err != nil {
		return "", err
	}
	return b.String(), nil
}

func runRender(o *renderOptions, file string) error {
	// the page is not terminal output, so --lang applies even when stdout is not a TTY (CLI_SPEC 7)
	lang := i18n.Detect(langFlag)
	env, err := newVerifyEnv(&o.verifyOptions)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return exitf(exitIO, "%v", err)
	}
	if !utf8.Valid(data) {
		return exitf(exitFail, "%s", i18n.T("file.not_utf8", file))
	}
	r := mdsig.VerifyDocument(context.Background(), string(data), env.options(file))
	_ = env.store.save()
	code := fileExitCode(r)
	page, err := renderPage(file, string(data), r, lang)
	if err != nil {
		return exitf(exitFail, "%v", err)
	}
	if o.out == "" {
		if _, err := fmt.Fprint(stdout, page); err != nil {
			return exitf(exitIO, "%v", err)
		}
	} else if err := os.WriteFile(o.out, []byte(page), 0o644); err != nil {
		return exitf(exitIO, "%v", err)
	}
	if code != exitOK {
		return &exitError{code: code}
	}
	return nil
}

const renderStyle = `body{font-family:system-ui,sans-serif;max-width:52rem;margin:2rem auto;padding:0 1rem;line-height:1.6;color:#1b1b1b;background:#fff}
.mdsig-summary{border:1px solid #c8c8c8;border-radius:6px;padding:.75rem 1rem;margin-bottom:1.5rem;background:#f6f6f6}
.mdsig-summary.ok{border-color:#2e7d32}.mdsig-summary.fail{border-color:#c62828}
table{border-collapse:collapse;margin:1rem 0}th,td{border:1px solid #c8c8c8;padding:.25rem .5rem;text-align:left;vertical-align:top}
.mdsig-signatures caption{text-align:left;font-weight:bold}.mdsig-unsigned td{color:#666;font-style:italic;background:#fafafa}
pre{overflow:auto;background:#f6f6f6;padding:.5rem}
@media (prefers-color-scheme:dark){body{color:#e8e8e8;background:#161616}.mdsig-summary,pre{background:#222}.mdsig-unsigned td{background:#1d1d1d;color:#aaa}}`

func renderPage(file, text string, r *mdsig.VerifyResult, lang i18n.Lang) (string, error) {
	prev := i18n.Current()
	i18n.Set(lang)
	defer i18n.Set(prev)
	doc := mdsig.ParseDocument(text)
	body := doc.Body
	if len(doc.Chain) == 0 {
		body = doc.Text
	}
	table := mdsig.RenderSignatureTableHTML(mdsig.SignatureTable(r), string(lang))
	// CLI_SPEC 3.10 rule 3: the table is never part of the DOM the body is rendered into
	var parts []string
	if line, offset, _ := mdsig.FindSignatureMarker(body); line != 0 {
		end := strings.IndexByte(body[offset:], '\n')
		rest := ""
		if end >= 0 {
			rest = body[offset+end+1:]
		}
		parts = []string{body[:offset], rest}
	} else {
		parts = []string{body}
	}
	var b strings.Builder
	b.WriteString("<!doctype html>\n<html lang=\"" + string(lang) + "\">\n<head>\n<meta charset=\"utf-8\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	b.WriteString("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src https: data:\">\n")
	b.WriteString("<title>" + html.EscapeString(file) + "</title>\n<style>" + renderStyle + "</style>\n</head>\n<body>\n")
	ok := fileExitCode(r) == exitOK || fileExitCode(r) == exitPending
	class := "fail"
	if ok {
		class = "ok"
	}
	b.WriteString("<header class=\"mdsig-summary " + class + "\">\n<p><strong>" + html.EscapeString(file) + "</strong></p>\n")
	b.WriteString("<p>" + html.EscapeString(summaryLine(r)) + "</p>\n")
	if r.Agreement.Status != mdsig.AgreementNone {
		b.WriteString("<p>" + html.EscapeString(i18n.T("render.agreement", i18n.T("agreement."+r.Agreement.Status))) + "</p>\n")
	}
	b.WriteString("</header>\n")
	for i, p := range parts {
		h, err := markdownHTML(p)
		if err != nil {
			return "", err
		}
		b.WriteString("<article class=\"mdsig-body\">\n" + h + "</article>\n")
		if i == 0 && len(parts) == 2 {
			b.WriteString("<section class=\"mdsig-table\">\n" + table + "\n</section>\n")
		}
	}
	if len(parts) == 1 {
		b.WriteString("<section class=\"mdsig-table\">\n" + table + "\n</section>\n")
	}
	b.WriteString("</body>\n</html>\n")
	return b.String(), nil
}

func summaryLine(r *mdsig.VerifyResult) string {
	total, bad, unresolved := len(r.Signatures), 0, 0
	for _, s := range r.Signatures {
		switch s.Status {
		case mdsig.StatusValid:
		case mdsig.StatusUnresolved:
			unresolved++
		default:
			bad++
		}
	}
	switch {
	case r.Error != "":
		return i18n.T("verify.not_verified", r.Error)
	case bad > 0:
		return i18n.T("verify.not_verified", i18n.N("verify.n_failed", bad, bad, total))
	case unresolved > 0:
		return i18n.N("verify.n_unresolved", unresolved, unresolved, total)
	}
	return i18n.N("verify.verified", total, total)
}
