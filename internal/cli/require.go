package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"mdsig.dev/internal/i18n"
	"mdsig.dev/mdsig"
)

// --- require explain (CLI_SPEC 3.11)

func newRequireCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "require",
		Short: "Work with require values",
		Args:  cobra.NoArgs,
	}
	var asJSON bool
	explain := &cobra.Command{
		Use:   "explain <value>",
		Short: "Check a require value and explain it in prose (- reads it from stdin)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRequireExplain(args[0], asJSON)
		},
	}
	explain.Flags().BoolVar(&asJSON, "json", false, "print the parsed value as JSON")
	c.AddCommand(explain)
	return c
}

var stdin io.Reader = os.Stdin

type jsonExplainLine struct {
	Line       int                  `json:"line"`
	Method     string               `json:"method"`
	Signer     string               `json:"signer"`
	Pattern    bool                 `json:"pattern"`
	Attributes mdsig.JSONAttributes `json:"attributes"`
}

type jsonExplainStep struct {
	Step  int               `json:"step"`
	Any   *int              `json:"any"`
	Lines []jsonExplainLine `json:"lines"`
}

func runRequireExplain(value string, asJSON bool) error {
	if value == "-" {
		b, err := io.ReadAll(io.LimitReader(stdin, 1<<20))
		if err != nil {
			return exitf(exitIO, "%v", err)
		}
		value = strings.TrimRight(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	}
	lang := string(i18n.Current())
	e := mdsig.ExplainRequire(value, lang)
	if len(e.Errors) > 0 {
		for _, m := range append(e.Errors, e.Hints...) {
			fmt.Fprintln(stderr, "mdsig: "+safeText(m))
		}
		return &exitError{code: exitUsage}
	}
	warnings := append(append(append([]string{}, e.Unsupported...), e.Warnings...), e.Hints...)
	if asJSON {
		// JSON output is always English (CLI_SPEC 5)
		en := mdsig.ExplainRequire(value, "en")
		p := mdsig.ParseRequire(value, 0)
		steps := []jsonExplainStep{}
		for _, s := range p.Spec.Steps {
			js := jsonExplainStep{Step: s.Step, Lines: []jsonExplainLine{}}
			if s.Any != 0 {
				n := s.Any
				js.Any = &n
			}
			for _, l := range s.Lines {
				js.Lines = append(js.Lines, jsonExplainLine{Line: l.Line, Method: l.Method, Signer: l.Signer, Pattern: l.Pattern, Attributes: mdsig.JSONAttributes(l.Attributes)})
			}
			steps = append(steps, js)
		}
		warnings = append(append(append([]string{}, en.Unsupported...), en.Warnings...), en.Hints...)
		if err := writeJSON(map[string]any{"order": p.Spec.Order, "steps": steps, "warnings": warnings}); err != nil {
			return exitf(exitIO, "%v", err)
		}
		return nil
	}
	for _, l := range strings.Split(e.Text, "\n") {
		fmt.Fprintln(stdout, safeText(l))
	}
	for _, w := range warnings {
		fmt.Fprintln(stderr, "! "+safeText(w))
	}
	return nil
}

// --- member-record (CLI_SPEC 3.12)

var memberMethodRe = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

func newMemberRecordCmd() *cobra.Command {
	var check bool
	c := &cobra.Command{
		Use:   "member-record <method:signer> <domain>",
		Short: "Print the TXT record that lists a signer on a DNS roster",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMemberRecord(args[0], args[1], check, nil)
		},
	}
	c.Flags().BoolVar(&check, "check", false, "look the record up with the system resolver and report membership")
	return c
}

func runMemberRecord(id, domain string, check bool, ro *mdsig.ResolveOptions) error {
	method, signer, ok := strings.Cut(id, ":")
	if !ok || !memberMethodRe.MatchString(method) || method == "tsa" || signer == "" {
		return exitf(exitUsage, "%s", i18n.T("member.bad_id", id))
	}
	signer = mdsig.CanonicalSignerInput(method, signer)
	if e := mdsig.CheckSignerID(method, signer); e != "" {
		return exitf(exitUsage, "%s: %s", i18n.T("member.bad_id", id), localize(e))
	}
	id = method + ":" + signer
	name, err := mdsig.MemberRecordName(id, domain)
	if err != nil {
		return exitf(exitUsage, "%v", err)
	}
	if e := mdsig.ValidateValue(mdsig.MemberRecordValue(id)); e != "" {
		return exitf(exitUsage, "%s: %s", i18n.T("member.bad_id", id), localize(e))
	}
	fmt.Fprintf(stdout, "%s. IN TXT \"%s\"\n", name, safeText(mdsig.MemberRecordValue(id)))
	if !check {
		return nil
	}
	if ro == nil {
		ro = &mdsig.ResolveOptions{HTTPClient: mdsig.SafeHTTPClient(15 * time.Second)}
	}
	switch mdsig.CheckMemberRecord(context.Background(), id, domain, ro) {
	case mdsig.MembershipMember:
		fmt.Fprintln(stdout, i18n.T("member.member", id, domain))
		return nil
	case mdsig.MembershipNotMember:
		fmt.Fprintln(stdout, i18n.T("member.not_member", id, domain))
		return &exitError{code: exitFail}
	}
	fmt.Fprintln(stdout, i18n.T("member.undetermined", id, domain))
	return &exitError{code: exitNetwork}
}
