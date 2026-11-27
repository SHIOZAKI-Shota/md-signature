package cli

import (
	"context"
	"crypto/x509"
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
	keyDirectories               []string
	tsaRoots                     []string
	acceptNewKey                 bool
	lookupTXT                    func(ctx context.Context, name string) ([]string, error)
	dohEndpoints                 []string
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
	c.Flags().StringArrayVar(&o.keyDirectories, "key-directory", nil, "directory only: also trust this https:// key directory for this run (repeatable; see mdsig directory trust)")
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
	return mdsig.DocumentVerdict(r).ExitCode
}

// --- TOFU store ---

type fileTofuStore struct {
	path    string
	m       map[string]string
	changed map[string]string
}

func knownSignersPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "mdsig", "known_signers.json")
}

func readKnownSigners(path string) map[string]string {
	m := map[string]string{}
	if path == "" {
		return m
	}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &m)
		if m == nil {
			m = map[string]string{}
		}
	}
	return m
}

// CLI_SPEC 3.9: atomic, owner-only, and reread just before writing so other tools' records survive
func updateKnownSigners(path string, update func(map[string]string)) error {
	if path == "" {
		return fmt.Errorf("no configuration directory")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	m := readKnownSigners(path)
	update(m)
	b, _ := json.MarshalIndent(m, "", "  ")
	return writeAtomicMode(path, append(b, '\n'), 0o600)
}

func openTofuStore() *fileTofuStore {
	path := knownSignersPath()
	return &fileTofuStore{path: path, m: readKnownSigners(path)}
}

func (s *fileTofuStore) Get(k string) (string, bool) { v, ok := s.m[k]; return v, ok }

func (s *fileTofuStore) Set(k, v string) error {
	s.m[k] = v
	if s.changed == nil {
		s.changed = map[string]string{}
	}
	s.changed[k] = v
	return nil
}

func (s *fileTofuStore) save() error {
	if len(s.changed) == 0 || s.path == "" {
		return nil
	}
	return updateKnownSigners(s.path, func(m map[string]string) {
		for k, v := range s.changed {
			m[k] = v
		}
	})
}

// --- verify ---

type verifyEnv struct {
	o                          *verifyOptions
	store                      *fileTofuStore
	keyring                    func(ctx context.Context, fpr string) ([]byte, error)
	fetchClient, resolveClient *http.Client
	resolvers                  map[string]mdsig.Resolver
	tsaRoots                   []*x509.Certificate
	keyDirs                    []string
}

func newVerifyEnv(o *verifyOptions) (*verifyEnv, error) {
	tsaRoots, err := mdsig.LoadTSARoots(o.tsaRoots)
	if err != nil {
		return nil, exitf(exitUsage, "%s", i18n.T("tsa.bad_root", err))
	}
	if o.keyserver != "" && !mdsig.IsValidRevocationURL(o.keyserver) {
		return nil, exitf(exitUsage, "%s", i18n.T("verify.bad_keyserver", o.keyserver))
	}
	keyDirs, err := trustedDirectories(o.keyDirectories)
	if err != nil {
		return nil, err
	}
	e := &verifyEnv{o: o, store: openTofuStore(), tsaRoots: tsaRoots, keyDirs: keyDirs, resolvers: cachedResolvers(o.resolvers)}
	if !o.noKeyring {
		e.keyring = o.pgpKeyring
		if e.keyring == nil {
			e.keyring = gpgKeyring()
		}
	}
	e.fetchClient = o.fetchClient
	if e.fetchClient == nil {
		e.fetchClient = mdsig.SafeHTTPClient(30 * time.Second)
	}
	// SSRF: git-hosting hosts and DoH go through the same dial-time address check as other fetches
	e.resolveClient = o.fetchClient
	if e.resolveClient == nil {
		e.resolveClient = mdsig.SafeHTTPClient(15 * time.Second)
	}
	return e, nil
}

func (e *verifyEnv) options(file string) *mdsig.VerifyOptions {
	o := e.o
	vo := &mdsig.VerifyOptions{
		ResolveOptions: mdsig.ResolveOptions{
			Offline: o.offline, TofuStore: e.store, AcceptNewTofuKey: o.acceptNewKey, HTTPClient: e.resolveClient,
			PGPKeyring: e.keyring, PGPClient: e.fetchClient, Keyserver: o.keyserver, KeyDirectories: e.keyDirs,
			LookupTXT: o.lookupTXT, DoHEndpoints: o.dohEndpoints,
		},
		ResourceCheckOptions: mdsig.ResourceCheckOptions{
			LoadResource:   mdsig.DirResourceLoader(filepath.Dir(file)),
			FetchResources: o.fetchResources && !o.offline,
			FetchClient:    e.fetchClient,
		},
		Resolvers:    e.resolvers,
		TSA:          mdsig.TSAVerifyOptions{ExtraRoots: e.tsaRoots},
		NoRevocation: o.noRevocation,
		Now:          o.now,
	}
	return vo
}

func runVerify(o *verifyOptions, files []string) error {
	ctx := context.Background()
	env, err := newVerifyEnv(o)
	if err != nil {
		return err
	}
	store := env.store
	exit := exitOK
	var out []jsonFile
	for _, file := range files {
		vo := env.options(file)
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
		var line string
		if f["method"] == "tsa" {
			line = fmt.Sprintf("  %s #%d %s %s", sym, s.Index, pad("tsa", 9), pad(safeText(f["signer"]), 20))
			if s.TSA != nil && s.TSA.Verified {
				line += " TSA " + safeText(s.TSA.GenTime) + accuracyText(s.TSA.AccuracyMs) + " (" + safeText(s.TSA.Signer) + ")"
			} else {
				line += " " + safeText(f["ts"])
			}
		} else {
			role := safeText(f["role"])
			if role == "" {
				role = "-"
			}
			line = fmt.Sprintf("  %s #%d %s %s %s  %s", sym, s.Index, pad(role, 9), pad(safeText(f["signer"]), 20), pad(safeText(f["ts"]), 20), safeText(f["method"]))
			// CLI_SPEC 3.2: a display name is the signer's claim and follows the verified identity
			if dn := f["display_name"]; dn != "" {
				line += "  \"" + safeText(dn) + "\"" + i18n.T("verify.declared")
			}
			if rp, ok := f["rp_id"]; ok && f["alg"] == "webauthn-es256" {
				line += "  " + passkeyText(rp, s.WebAuthn)
			}
			if s.Time != nil {
				line += "  " + i18n.T("verify.time", safeText(s.Time.At), s.Time.Block)
			}
		}
		fmt.Fprintln(w, strings.TrimRight(line, " "))
		if s.Status != mdsig.StatusValid {
			fmt.Fprintf(w, "      %s\n", describeFailure(s))
		}
		if s.PGP != nil {
			printPgpHuman(w, s)
		}
		if s.Tofu != nil && s.Tofu.Status != mdsig.TofuKnown {
			fmt.Fprintf(w, "      %s\n", i18n.T("verify.tofu_"+s.Tofu.Status, s.Tofu.Fingerprint))
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
		for _, wn := range s.Warnings {
			if !humanHiddenWarning(wn) {
				fmt.Fprintf(w, "      ! %s\n", safeText(localize(wn)))
			}
		}
	}
	for _, wn := range r.Warnings {
		fmt.Fprintf(w, "  ! %s\n", safeText(localize(wn)))
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
		} else {
			msg = safeText(localize(r.Error))
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
	printAgreementHuman(w, r.Agreement)
}

func accuracyText(ms int64) string {
	switch {
	case ms == 0:
		return ""
	case ms%1000 == 0:
		return fmt.Sprintf(" ±%ds", ms/1000)
	}
	return fmt.Sprintf(" ±%dms", ms)
}

func passkeyText(rpID string, w *mdsig.WebAuthnInfo) string {
	parts := []string{"rp_id " + safeText(rpID)}
	if w != nil && w.UserVerified {
		parts = append(parts, i18n.T("verify.passkey_uv"))
	}
	if w != nil && w.BackedUp {
		parts = append(parts, i18n.T("verify.passkey_synced"))
	}
	return i18n.T("verify.passkey", strings.Join(parts, i18n.T("list.sep")))
}

// CLI_SPEC 3.2: the content of next, indented by the structure of the steps, and the blocks that were not counted
func printAgreementHuman(w io.Writer, a mdsig.Agreement) {
	if a.Status == mdsig.AgreementNone {
		return
	}
	detail := func(status string) string {
		var parts []string
		for _, d := range a.Declarations {
			if d.Status == status && d.Detail != "" {
				parts = append(parts, safeText(localize(d.Detail)))
			}
		}
		return strings.Join(parts, "; ")
	}
	switch a.Status {
	case mdsig.AgreementViolated:
		fmt.Fprintf(w, "  %s\n", i18n.T("verify.agreement_violated", describeViolations(a, mdsig.OrderStrict)))
	case mdsig.AgreementUndetermined, mdsig.AgreementUnsupported:
		fmt.Fprintf(w, "  %s\n", i18n.T("verify.agreement_"+a.Status, detail(a.Status)))
	default:
		fmt.Fprintf(w, "  %s\n", i18n.T("verify.agreement_"+a.Status))
	}
	stepSize := func(declaredBy, step int) int {
		n := 0
		for _, r := range a.Required {
			if r.DeclaredBy == declaredBy && r.Step == step {
				n++
			}
		}
		return n
	}
	for _, n := range a.Next {
		head := i18n.T("verify.next", n.Step, n.Need)
		if len(n.Candidates) > 0 && n.Candidates[0].Any != 0 {
			head += i18n.T("verify.next_any", n.Candidates[0].Any, stepSize(n.DeclaredBy, n.Step))
		}
		fmt.Fprintf(w, "    %s\n", head)
		for _, c := range n.Candidates {
			fmt.Fprintf(w, "      %s\n", safeText(c.String()))
		}
		for _, l := range n.Later {
			if l.Need == 0 && len(l.Lines) == 0 {
				continue
			}
			fmt.Fprintf(w, "    %s\n", i18n.T("verify.next_later", l.Step, l.Need))
			for _, c := range l.Lines {
				fmt.Fprintf(w, "      %s\n", safeText(c.String()))
			}
		}
	}
	seen := map[string]bool{}
	for _, m := range a.Missing {
		for _, x := range m.Rejected {
			key := fmt.Sprintf("%d %s %s", x.Index, x.Reason, m.Method+":"+m.Signer)
			if seen[key] {
				continue
			}
			seen[key] = true
			reason := i18n.T("reject." + x.Reason)
			if x.Reason == mdsig.RejectEarly && m.Step > 1 {
				reason = i18n.T("reject.early_step", m.Step-1)
			}
			fmt.Fprintf(w, "    %s\n", i18n.T("verify.not_counted", x.Index, safeText(m.Method+":"+m.Signer), reason))
		}
	}
	if a.Status != mdsig.AgreementViolated {
		if v := describeViolations(a, mdsig.OrderGuide); v != "" {
			fmt.Fprintf(w, "  ! %s\n", i18n.T("verify.order_not_followed", v))
		}
	}
}

func describeViolations(a mdsig.Agreement, order string) string {
	var parts []string
	for _, v := range a.Violations {
		if v.Order != order {
			continue
		}
		target := v.Method + ":" + v.Signer
		for _, r := range a.Required {
			if r.DeclaredBy == v.DeclaredBy && r.Line == v.Line {
				target = mdsig.Requirement{Method: v.Method, Signer: v.Signer, Attributes: r.Attributes}.String()
			}
		}
		parts = append(parts, i18n.T("verify.order_violation", v.Index, safeText(target), v.Step, v.Step-1))
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
	return label + ": " + safeText(localize(s.Message))
}

// human output only; --json stays English (CLI_SPEC 5)
func localize(msg string) string {
	return mdsig.LocalizeMessage(msg, string(i18n.Current()))
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
