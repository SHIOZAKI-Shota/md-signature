package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"mdsig.dev/internal/i18n"
	"mdsig.dev/mdsig"
)

// set at release via -ldflags -X (see .goreleaser.yaml); go install builds take it from the module version
var Version = ""

func init() {
	if Version != "" {
		return
	}
	Version = "dev"
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		Version = strings.TrimPrefix(bi.Main.Version, "v")
	}
}

const (
	exitOK       = 0
	exitFail     = 1
	exitUsage    = 2
	exitNetwork  = 3
	exitIO       = 4
	exitPending  = 5
	exitCanceled = 130
)

type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

func exitf(code int, format string, a ...any) error {
	return &exitError{code: code, msg: fmt.Sprintf(format, a...)}
}

// CLI_SPEC 4: with several files the most severe code wins: 1 > 4 > 3 > 5 > 0
func severity(code int) int {
	switch code {
	case exitFail:
		return 5
	case exitIO:
		return 4
	case exitNetwork:
		return 3
	case exitPending:
		return 2
	case exitOK:
		return 0
	}
	return 6
}

func worse(a, b int) int {
	if severity(b) > severity(a) {
		return b
	}
	return a
}

var (
	stdout io.Writer = os.Stdout
	stderr io.Writer = os.Stderr
)

func isTTY(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }

func stdoutIsTTY() bool { return isTTY(os.Stdout) }

func interactiveTTY() bool { return isTTY(os.Stdin) && isTTY(os.Stdout) }

var langFlag string

func Execute() int {
	root := newRootCmd()
	err := root.Execute()
	if err == nil {
		return exitOK
	}
	var ee *exitError
	if errors.As(err, &ee) {
		if ee.msg != "" {
			fmt.Fprintln(stderr, "mdsig: "+ee.msg)
		}
		return ee.code
	}
	fmt.Fprintln(stderr, "mdsig: "+err.Error())
	fmt.Fprintln(stderr, "Run 'mdsig --help' for usage.")
	return exitUsage
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "mdsig",
		Short: "Embedded, append-only signatures for Markdown documents",
		Long:  "mdsig signs and verifies md-signature blocks embedded in Markdown files.\nRun without arguments on a terminal for an interactive menu.",
		// the release and the signature format have separate version numbers
		Version:       Version + " (format " + mdsig.SpecVersion + ")",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return setupLanguage()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if !interactiveTTY() {
				cmd.SetOut(stderr)
				_ = cmd.Usage()
				return &exitError{code: exitUsage}
			}
			return runLauncher()
		},
	}
	root.PersistentFlags().StringVar(&langFlag, "lang", "", "UI language: en or ja")
	root.SetFlagErrorFunc(func(c *cobra.Command, err error) error { return err })
	root.AddCommand(newSignCmd(), newVerifyCmd(), newInspectCmd(), newKeygenCmd(), newRevokeCmd(), newServeCmd(), newTimestampCmd(), newDirectoryCmd())
	root.CompletionOptions.DisableDefaultCmd = true
	return root
}

func setupLanguage() error {
	if langFlag != "" {
		if _, ok := i18n.Parse(langFlag); !ok {
			return exitf(exitUsage, "unsupported --lang %q (supported: en, ja)", langFlag)
		}
	}
	l := i18n.Detect(langFlag)
	// CLI_SPEC 7: non-TTY output is always English
	if !stdoutIsTTY() {
		l = i18n.EN
	}
	i18n.Set(l)
	return nil
}

// --- interactive launcher ---

func runForm(fields ...huh.Field) error {
	err := huh.NewForm(huh.NewGroup(fields...)).Run()
	if errors.Is(err, huh.ErrUserAborted) {
		return &exitError{code: exitCanceled}
	}
	return err
}

// huh clears a finished form from the terminal, so answers are re-printed
func answered(title, value string) {
	if value == "" {
		value = "-"
	}
	fmt.Fprintf(stderr, "? %s\n  ❯ %s\n\n", title, value)
}

func runLauncher() error {
	fmt.Fprintf(stderr, "\n  %s\n\n", i18n.T("launcher.header", Version))
	var action string
	if err := runForm(huh.NewSelect[string]().
		Title(i18n.T("launcher.action")).
		Description(i18n.T("launcher.action.desc")).
		Options(
			huh.NewOption(i18n.T("launcher.action.sign"), "sign"),
			huh.NewOption(i18n.T("launcher.action.verify"), "verify"),
			huh.NewOption(i18n.T("launcher.action.inspect"), "inspect"),
			huh.NewOption(i18n.T("launcher.action.keygen"), "keygen"),
		).Value(&action)); err != nil {
		return err
	}
	answered(i18n.T("launcher.action"), i18n.T("launcher.action."+action))
	switch action {
	case "sign":
		return launchSign()
	case "verify", "inspect":
		file, err := chooseFile(action == "verify" || action == "inspect")
		if err != nil {
			return err
		}
		var runErr error
		if action == "verify" {
			runErr = runVerify(&verifyOptions{}, []string{file})
		} else {
			runErr = runInspect(&inspectOptions{}, file)
		}
		printNextTime([]string{action, file})
		return runErr
	case "keygen":
		return launchKeygen()
	}
	return nil
}

func printNextTime(argv []string) {
	quoted := make([]string, len(argv))
	for i, a := range argv {
		quoted[i] = shellQuote(a)
	}
	fmt.Fprintf(stderr, "\n%s\n  $ mdsig %s\n", i18n.T("launcher.next_time"), strings.Join(quoted, " "))
}

var safeArg = regexp.MustCompile(`^[A-Za-z0-9@%+=:,./_-]+$`)

func shellQuote(s string) string {
	if safeArg.MatchString(s) {
		return s
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`, "`", "\\`")
	return `"` + r.Replace(s) + `"`
}

func findMarkdown(dir string) []string {
	var out []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		depth := 0
		if rel != "." {
			depth = strings.Count(filepath.ToSlash(rel), "/") + 1
		}
		if d.IsDir() {
			if rel != "." && (d.Name() == "node_modules" || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			if depth >= 3 {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.EqualFold(filepath.Ext(p), ".md") {
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(out)
	return out
}

const typePath = "\x00type"

func chooseFile(showCosign bool) (string, error) {
	files := findMarkdown(".")
	var opts []huh.Option[string]
	for _, f := range files {
		label := f
		if showCosign {
			if b, err := os.ReadFile(f); err == nil {
				if n := len(mdsig.ParseDocument(string(b)).Chain); n > 0 {
					label += "  " + i18n.N("launcher.existing", n, n)
				}
			}
		}
		opts = append(opts, huh.NewOption(label, f))
	}
	opts = append(opts, huh.NewOption(i18n.T("launcher.type_path"), typePath))
	var file string
	if err := runForm(huh.NewSelect[string]().Title(i18n.T("launcher.file")).Description(i18n.T("launcher.file.desc")).Options(opts...).Height(min(len(opts)+3, 16)).Value(&file)); err != nil {
		return "", err
	}
	if file == typePath {
		file = ""
		if err := runForm(huh.NewInput().Title(i18n.T("launcher.path")).Prompt("> ").Value(&file).Validate(nonEmpty)); err != nil {
			return "", err
		}
	}
	file = strings.TrimSpace(file)
	answered(i18n.T("launcher.file"), file)
	return file, nil
}

func nonEmpty(s string) error {
	if strings.TrimSpace(s) == "" {
		return errors.New(i18n.T("launcher.required"))
	}
	return nil
}

func optionalValue(s string) error {
	if s == "" {
		return nil
	}
	if e := mdsig.ValidateValue(s); e != "" {
		return errors.New(e)
	}
	return nil
}

func launchSign() error {
	file, err := chooseFile(true)
	if err != nil {
		return err
	}
	o := &signOptions{method: "git-hosting", interactive: true}
	if err := runForm(huh.NewSelect[string]().Title(i18n.T("launcher.method")).Options(
		huh.NewOption(i18n.T("launcher.method.git-hosting"), "git-hosting"),
		huh.NewOption(i18n.T("launcher.method.dns"), "dns"),
		huh.NewOption(i18n.T("launcher.method.tofu"), "tofu"),
		huh.NewOption(i18n.T("launcher.method.pgp"), "pgp"),
		huh.NewOption(i18n.T("launcher.method.directory"), "directory"),
	).Value(&o.method)); err != nil {
		return err
	}
	answered(i18n.T("launcher.method"), i18n.T("launcher.method."+o.method))
	if o.method == "pgp" {
		if err := launchPgpKey(o); err != nil {
			return err
		}
	} else if err := askSigner(o); err != nil {
		return err
	}
	if o.method == "dns" {
		if err := runForm(huh.NewInput().Title(i18n.T("launcher.selector")).Prompt("> ").Value(&o.selector).Validate(optionalValue)); err != nil {
			return err
		}
		answered(i18n.T("launcher.selector"), o.selector)
	}
	var role string
	if err := runForm(huh.NewSelect[string]().Title(i18n.T("launcher.role")).Options(
		huh.NewOption(i18n.T("launcher.role.author"), "author"),
		huh.NewOption(i18n.T("launcher.role.reviewer"), "reviewer"),
		huh.NewOption(i18n.T("launcher.role.approver"), "approver"),
		huh.NewOption(i18n.T("launcher.role.witness"), "witness"),
		huh.NewOption(i18n.T("launcher.role.other"), typePath),
		huh.NewOption(i18n.T("launcher.role.skip"), ""),
	).Value(&role)); err != nil {
		return err
	}
	if role == typePath {
		role = ""
		if err := runForm(huh.NewInput().Title(i18n.T("launcher.role")).Prompt("> ").Value(&role).Validate(optionalValue)); err != nil {
			return err
		}
	}
	o.role = strings.TrimSpace(role)
	answered(i18n.T("launcher.role"), o.role)
	if err := runForm(huh.NewInput().Title(i18n.T("launcher.reason")).Prompt("> ").Value(&o.reason).Validate(optionalValue)); err != nil {
		return err
	}
	answered(i18n.T("launcher.reason"), o.reason)
	var useTSA bool
	if err := runForm(huh.NewSelect[bool]().Title(i18n.T("launcher.tsa")).Options(
		huh.NewOption(i18n.T("launcher.tsa.no"), false),
		huh.NewOption(i18n.T("launcher.tsa.yes", mdsig.DefaultTSAURL), true),
	).Value(&useTSA)); err != nil {
		return err
	}
	if useTSA {
		o.tsa = mdsig.DefaultTSAURL
		answered(i18n.T("launcher.tsa"), i18n.T("launcher.tsa.yes", mdsig.DefaultTSAURL))
	} else {
		answered(i18n.T("launcher.tsa"), i18n.T("launcher.tsa.no"))
	}
	runErr := runSign(o, file)
	argv := []string{"sign", file, "-m", o.method, "-s", o.signer}
	if o.selector != "" {
		argv = append(argv, "--selector", o.selector)
	}
	if o.keyPath != "" {
		argv = append(argv, "-k", o.keyPath)
	}
	if o.localUser != "" {
		argv = append(argv, "-u", o.localUser)
	}
	if o.pgpKey != "" {
		argv = append(argv, "--pgp-key", o.pgpKey)
	}
	if o.role != "" {
		argv = append(argv, "-r", o.role)
	}
	if o.reason != "" {
		argv = append(argv, "--reason", o.reason)
	}
	if o.tsa != "" {
		argv = append(argv, "--tsa")
	}
	if runErr == nil {
		printNextTime(argv)
	}
	return runErr
}

func launchKeygen() error {
	o := &keygenOptions{out: "./mdsig_ed25519"}
	if err := runForm(
		huh.NewInput().Title(i18n.T("launcher.keygen.out")).Value(&o.out).Validate(nonEmpty),
		huh.NewInput().Title(i18n.T("launcher.keygen.domain")).Value(&o.domain),
		huh.NewInput().Title(i18n.T("launcher.selector")).Value(&o.selector),
	); err != nil {
		return err
	}
	o.out, o.domain, o.selector = strings.TrimSpace(o.out), strings.TrimSpace(o.domain), strings.TrimSpace(o.selector)
	runErr := runKeygen(o)
	argv := []string{"keygen", "-o", o.out}
	if o.domain != "" {
		argv = append(argv, "-d", o.domain)
	}
	if o.selector != "" {
		argv = append(argv, "--selector", o.selector)
	}
	if runErr == nil {
		printNextTime(argv)
	}
	return runErr
}

func askSigner(o *signOptions) error {
	placeholder := map[string]string{"git-hosting": "github.com/alice", "dns": "example.com", "tofu": "bob@laptop"}[o.method]
	if err := runForm(huh.NewInput().Title(i18n.T("launcher.signer")).Prompt("> ").Placeholder(placeholder).Value(&o.signer).Validate(func(s string) error {
		if err := nonEmpty(s); err != nil {
			return err
		}
		return optionalValue(strings.TrimSpace(s))
	})); err != nil {
		return err
	}
	o.signer = strings.TrimSpace(o.signer)
	answered(i18n.T("launcher.signer"), o.signer)
	return nil
}
