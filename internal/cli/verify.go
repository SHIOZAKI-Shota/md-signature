package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"mdsig.dev/internal/i18n"
	"mdsig.dev/mdsig"
)

type verifyOptions struct {
	json, quiet, offline         bool
	fetchResources, noRevocation bool
	noKeyring                    bool
	pgpKeyring                   func(ctx context.Context, fpr string) ([]byte, error)
	resolvers                    map[string]mdsig.Resolver
	fetchClient                  *http.Client
	now                          time.Time
	keyserver                    string
	tsaRoots                     []string
	acceptNewKey                 bool
}

func newVerifyCmd() *cobra.Command {
	o := &verifyOptions{}
	c := &cobra.Command{
		Use:   "verify <file>...",
		Short: "Verify every signature in each file's chain",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerify(o, args)
		},
	}
	c.Flags().BoolVar(&o.json, "json", false, "print a JSON result to stdout")
	c.Flags().BoolVarP(&o.quiet, "quiet", "q", false, "no output; exit code only")
	c.Flags().BoolVar(&o.offline, "offline", false, "do not use the network (tofu, pgp from the local keyring, and tsa blocks can still be checked)")
	c.Flags().BoolVar(&o.fetchResources, "fetch-resources", false, "fetch https:// resources and check their hashes (tells the server the document is being verified)")
	c.Flags().BoolVar(&o.noRevocation, "no-revocation", false, "do not fetch revocation lists")
	c.Flags().BoolVar(&o.noKeyring, "no-keyring", false, "pgp only: do not look in the local gpg keyring (WKD and keyserver only)")
	c.Flags().BoolVar(&o.acceptNewKey, "accept-new-key", false, "tofu only: accept a key that differs from the stored one and replace the stored binding")
	c.Flags().StringArrayVar(&o.tsaRoots, "tsa-root", nil, "also trust this root certificate when checking a timestamp token (PEM or DER file; repeatable)")
	c.Flags().StringVar(&o.keyserver, "keyserver", "", "pgp only: https:// keyserver to look keys up on (default "+mdsig.DefaultKeyserver+"); use one that confirms email addresses")
	return c
}

func httpClientWithTimeout(d time.Duration) *http.Client { return &http.Client{Timeout: d} }

type jsonFile struct {
	File string `json:"file"`
	mdsig.JSONResult
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func writeJSON(v any) error {
	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func fileExitCode(r *mdsig.VerifyResult) int {
	if r.Error != "" {
		return exitFail
	}
	code := exitOK
	for _, s := range r.Signatures {
		switch {
		case s.Status == mdsig.StatusValid:
		case s.Status == mdsig.StatusUnresolved:
			code = worse(code, exitNetwork)
		default:
			return exitFail
		}
	}
	// SPEC 5.8: a violated "order strict" is a failure; pending is not
	if r.Agreement.Status == mdsig.AgreementViolated {
		return exitFail
	}
	if code == exitOK && r.Agreement.Status == mdsig.AgreementPending {
		code = exitPending
	}
	return code
}

// --- TOFU store ---

type fileTofuStore struct {
	path  string
	m     map[string]string
	dirty bool
}

func openTofuStore() *fileTofuStore {
	s := &fileTofuStore{m: map[string]string{}}
	dir, err := os.UserConfigDir()
	if err != nil {
		return s
	}
	s.path = filepath.Join(dir, "mdsig", "known_signers.json")
	if b, err := os.ReadFile(s.path); err == nil {
		_ = json.Unmarshal(b, &s.m)
		if s.m == nil {
			s.m = map[string]string{}
		}
	}
	return s
}

func (s *fileTofuStore) Get(k string) (string, bool) { v, ok := s.m[k]; return v, ok }

func (s *fileTofuStore) Set(k, v string) error {
	s.m[k] = v
	s.dirty = true
	return nil
}

func (s *fileTofuStore) save() error {
	if !s.dirty || s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s.m, "", "  ")
	if err := writeAtomic(s.path, append(b, '\n')); err != nil {
		return err
	}
	// writeAtomic keeps the mode of an existing file, which older versions created 0644
	return os.Chmod(s.path, 0o600)
}

// --- verify ---

func runVerify(o *verifyOptions, files []string) error {
	ctx := context.Background()
	tsaRoots, err := mdsig.LoadTSARoots(o.tsaRoots)
	if err != nil {
		return exitf(exitUsage, "%s", i18n.T("tsa.bad_root", err))
	}
	if o.keyserver != "" && !mdsig.IsValidRevocationURL(o.keyserver) {
		return exitf(exitUsage, "%s", i18n.T("verify.bad_keyserver", o.keyserver))
	}
	store := openTofuStore()
	var keyring func(ctx context.Context, fpr string) ([]byte, error)
	if !o.noKeyring {
		keyring = o.pgpKeyring
		if keyring == nil {
			keyring = gpgKeyring()
		}
	}
	fetchClient := o.fetchClient
	if fetchClient == nil {
		fetchClient = mdsig.SafeHTTPClient(30 * time.Second)
	}
	// SSRF: git-hosting hosts and DoH go through the same dial-time address check as other fetches
	resolveClient := o.fetchClient
	if resolveClient == nil {
		resolveClient = mdsig.SafeHTTPClient(15 * time.Second)
	}
	resolvers := cachedResolvers(o.resolvers)
	exit := exitOK
	var out []jsonFile
	for _, file := range files {
		vo := &mdsig.VerifyOptions{
			ResolveOptions: mdsig.ResolveOptions{
				Offline: o.offline, TofuStore: store, AcceptNewTofuKey: o.acceptNewKey, HTTPClient: resolveClient,
				PGPKeyring: keyring, PGPClient: fetchClient, Keyserver: o.keyserver,
			},
			ResourceCheckOptions: mdsig.ResourceCheckOptions{
				LoadResource:   mdsig.DirResourceLoader(filepath.Dir(file)),
				FetchResources: o.fetchResources && !o.offline,
				FetchClient:    fetchClient,
			},
			Resolvers:    resolvers,
			TSA:          mdsig.TSAVerifyOptions{ExtraRoots: tsaRoots},
			NoRevocation: o.noRevocation,
			Now:          o.now,
		}
		jf := jsonFile{File: file, JSONResult: mdsig.ToJSON(nil)}
		data, err := os.ReadFile(file)
		var code int
		switch {
		case err != nil:
			code = exitIO
			jf.Error = strPtr(err.Error())
			if !o.quiet && !o.json {
				fmt.Fprintf(stdout, "%s\n  %s %s\n", safeText(file), mark("x"), safeText(err.Error()))
			}
		case !utf8.Valid(data):
			code = exitFail
			jf.Error = strPtr("file is not valid UTF-8")
			if !o.quiet && !o.json {
				fmt.Fprintf(stdout, "%s\n  %s %s\n", safeText(file), mark("x"), i18n.T("file.not_utf8", safeText(file)))
			}
		default:
			r := mdsig.VerifyDocument(ctx, string(data), vo)
			code = fileExitCode(r)
			jf.JSONResult = mdsig.ToJSON(r)
			if !o.quiet && !o.json {
				printVerifyHuman(file, r)
			}
		}
		exit = worse(exit, code)
		out = append(out, jf)
	}
	if err := store.save(); err != nil && !o.quiet && !o.json {
		fmt.Fprintln(stderr, "mdsig: "+i18n.T("verify.tofu_save_failed", err))
	}
	if o.json && !o.quiet {
		if err := writeJSON(map[string]any{"files": out}); err != nil {
			return exitf(exitIO, "%v", err)
		}
	}
	if exit != exitOK {
		return &exitError{code: exit}
	}
	return nil
}

func mark(kind string) string {
	switch kind {
	case "ok":
		return "✓"
	case "x":
		return "✗"
	case "?":
		return "?"
	case "-":
		return "-"
	}
	return " "
}

func pad(s string, n int) string {
	if w := utf8.RuneCountInString(s); w < n {
		return s + strings.Repeat(" ", n-w)
	}
	return s
}

func humanHiddenWarning(w string) bool {
	return strings.HasPrefix(w, "partial signature: ") || strings.Contains(w, " resource(s) not checked: ")
}

func resourceMark(status string) string {
	switch status {
	case mdsig.ResourceOK:
		return mark("ok")
	case mdsig.ResourceNotChecked:
		return mark("-")
	case mdsig.ResourceUnreachable:
		return mark("?")
	}
	return mark("x")
}

func printVerifyHuman(file string, r *mdsig.VerifyResult) {
	w := stdout
	fmt.Fprintln(w, safeText(file))
	for _, s := range r.Signatures {
		f := s.Fields
		sym := mark("x")
		switch {
		case s.Status == mdsig.StatusValid:
			sym = mark("ok")
		case s.Status == mdsig.StatusUnresolved && s.Code == mdsig.KindOffline:
			sym = mark("-")
		case s.Status == mdsig.StatusUnresolved:
			sym = mark("?")
		}
		role := safeText(f["role"])
		if role == "" {
			role = "-"
		}
		line := fmt.Sprintf("  %s #%d %s %s %s  %s", sym, s.Index, pad(role, 9), pad(safeText(f["signer"]), 20), pad(safeText(f["ts"]), 20), safeText(f["method"]))
		if rp, ok := f["rp_id"]; ok && f["alg"] == "webauthn-es256" {
			line += "  " + i18n.T("verify.passkey", safeText(rp))
		}
		if s.TSA != nil && s.TSA.Verified {
			line += "  ⏱ TSA " + safeText(s.TSA.GenTime) + " (" + safeText(s.TSA.Signer) + ")"
		}
		fmt.Fprintln(w, strings.TrimRight(line, " "))
		if s.Status != mdsig.StatusValid {
			fmt.Fprintf(w, "      %s\n", describeFailure(s))
		}
		if s.PGP != nil {
			printPgpHuman(w, s)
		}
		if s.Partial != nil {
			fmt.Fprintf(w, "      %s\n", i18n.T("verify.partial", strings.Join(safeAll(s.Partial), ", ")))
		}
		if len(s.Resources) > 0 {
			parts := make([]string, 0, len(s.Resources))
			for _, res := range s.Resources {
				p := resourceMark(res.Status) + " " + safeText(res.Ref)
				if res.Status != mdsig.ResourceOK {
					p += " (" + i18n.T("resource."+res.Status) + ")"
				}
				parts = append(parts, p)
			}
			fmt.Fprintf(w, "      %s %s\n", i18n.T("verify.resources"), strings.Join(parts, "  "))
		}
		if s.Revocation != nil && s.Revocation.Status == mdsig.RevocationNotRevoked {
			fmt.Fprintf(w, "      %s\n", i18n.T("verify.not_revoked"))
		}
		if s.TSA != nil && s.TSA.Verified {
			fmt.Fprintf(w, "      %s\n", i18n.T("verify.tsa_note"))
		}
		for _, wn := range s.Warnings {
			if !humanHiddenWarning(wn) {
				fmt.Fprintf(w, "      ! %s\n", safeText(wn))
			}
		}
	}
	for _, wn := range r.Warnings {
		fmt.Fprintf(w, "  ! %s\n", safeText(wn))
	}
	total := len(r.Signatures)
	offline, failed, unresolved := 0, 0, 0
	for _, s := range r.Signatures {
		switch {
		case s.Status == mdsig.StatusValid:
		case s.Status == mdsig.StatusUnresolved && s.Code == mdsig.KindOffline:
			offline++
		case s.Status == mdsig.StatusUnresolved:
			unresolved++
		default:
			failed++
		}
	}
	switch {
	case r.Error != "":
		msg := safeText(r.Error)
		if strings.HasPrefix(msg, "unsigned content") {
			msg = i18n.T("verify.unsigned_content")
		} else if msg == "no signatures found" {
			msg = i18n.T("verify.no_signatures")
		}
		fmt.Fprintf(w, "  %s %s\n", mark("x"), i18n.T("verify.not_verified", msg))
	case failed > 0:
		fmt.Fprintf(w, "  %s\n", i18n.T("verify.not_verified", i18n.N("verify.n_failed", failed, failed, total)))
	case unresolved > 0:
		fmt.Fprintf(w, "  %s\n", i18n.N("verify.n_unresolved", unresolved, unresolved, total))
	case offline > 0:
		fmt.Fprintf(w, "  %s\n", i18n.N("verify.offline_summary", offline, offline, total-offline))
	default:
		fmt.Fprintf(w, "  %s\n", i18n.N("verify.verified", total, total))
	}
	switch r.Agreement.Status {
	case mdsig.AgreementComplete:
		fmt.Fprintf(w, "  %s\n", i18n.T("verify.agreement_complete"))
	case mdsig.AgreementPending:
		fmt.Fprintf(w, "  %s\n", i18n.T("verify.agreement_pending", describeMissing(r.Agreement)))
	case mdsig.AgreementViolated:
		fmt.Fprintf(w, "  %s\n", i18n.T("verify.agreement_violated", describeViolations(r.Agreement.Violations)))
	}
	if r.Agreement.Status != mdsig.AgreementViolated && len(r.Agreement.Violations) > 0 {
		fmt.Fprintf(w, "  ! %s\n", i18n.T("verify.order_not_followed", describeViolations(r.Agreement.Violations)))
	}
}

// a declaration with one step that needs everyone reads as a plain list, as before steps existed
func describeMissing(a mdsig.Agreement) string {
	stepsOf := map[int]int{}
	for _, r := range a.Required {
		stepsOf[r.DeclaredBy] = max(stepsOf[r.DeclaredBy], r.Step)
	}
	type group struct {
		declaredBy, step, need, blockedBy int
		names                             []string
		plain                             bool
	}
	var groups []*group
	for _, m := range a.Missing {
		g := (*group)(nil)
		if n := len(groups); n > 0 && groups[n-1].declaredBy == m.DeclaredBy && groups[n-1].step == m.Step {
			g = groups[n-1]
		} else {
			g = &group{declaredBy: m.DeclaredBy, step: m.Step, need: m.Need, blockedBy: m.BlockedBy, plain: stepsOf[m.DeclaredBy] == 1}
			groups = append(groups, g)
		}
		name := safeText(m.String())
		if m.Early {
			name += i18n.T("verify.agreement_early")
		}
		g.names = append(g.names, name)
		g.plain = g.plain && m.Need == len(g.names) && m.Any == m.Need
	}
	parts := make([]string, 0, len(groups))
	for _, g := range groups {
		list := strings.Join(g.names, ", ")
		if g.plain && g.need == len(g.names) {
			parts = append(parts, i18n.T("verify.agreement_missing", list))
			continue
		}
		s := i18n.T("verify.agreement_step", g.step, g.need, list)
		if g.blockedBy > 0 {
			s += i18n.T("verify.agreement_after", g.blockedBy)
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, "; ")
}

func describeViolations(vs []mdsig.OrderViolation) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = i18n.T("verify.order_violation", v.Index, safeText(mdsig.Requirement{Method: v.Method, Signer: v.Signer, Role: v.Role}.String()), v.Step, v.Step-1)
	}
	return strings.Join(parts, ", ")
}

func describeFailure(s *mdsig.BlockResult) string {
	label := i18n.T("code." + s.Code)
	if s.Code == mdsig.KindOffline {
		return label
	}
	if s.Message == "" {
		return label
	}
	return label + ": " + safeText(s.Message)
}

// SPEC 6.2: the packet creation time is the signer's claim and is shown apart from ts and the TSA time
func printPgpHuman(w io.Writer, s *mdsig.BlockResult) {
	p := s.PGP
	line := "OpenPGP " + safeText(p.Fpr)
	if p.UID != "" {
		line += "  " + safeText(p.UID)
	}
	if p.KeySource != "" {
		src := i18n.T("pgp.source." + p.KeySource)
		if _, u, ok := strings.Cut(s.KeySource, " "); ok {
			src += " " + safeText(u)
		}
		line += "  (" + i18n.T("verify.pgp_key_from", src) + ")"
	}
	fmt.Fprintf(w, "      %s\n", line)
	if p.Created != "" {
		fmt.Fprintf(w, "      %s\n", i18n.T("verify.pgp_created", safeText(p.Created)))
	}
}
