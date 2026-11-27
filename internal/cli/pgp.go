package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/huh"
	"golang.org/x/term"

	"mdsig.dev/internal/i18n"
	"mdsig.dev/mdsig"
)

// --- gpg

var gpgProgram = "gpg"

func gpgPath() (string, bool) {
	p, err := exec.LookPath(gpgProgram)
	return p, err == nil
}

func runGpg(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	p, ok := gpgPath()
	if !ok {
		return nil, exec.ErrNotFound
	}
	var out, errb bytes.Buffer
	c := exec.CommandContext(ctx, p, args...)
	c.Env = gpgEnv(p)
	if stdin != nil {
		c.Stdin = bytes.NewReader(stdin)
	}
	c.Stdout, c.Stderr = &out, &errb
	if err := c.Run(); err != nil {
		if msg := strings.TrimSpace(errb.String()); msg != "" {
			return nil, fmt.Errorf("%w: %s", err, msg)
		}
		return nil, err
	}
	return out.Bytes(), nil
}

var (
	gpgEnvOnce sync.Once
	gpgEnvVal  []string
	winPathRe  = regexp.MustCompile(`^([A-Za-z]):[\\/]`)
	msysHomeRe = regexp.MustCompile(`(?m)^Home: /`)
)

// Git for Windows ships an MSYS gpg that reads GNUPGHOME as a POSIX path (/c/...); Gpg4win and Unix gpg take native paths
func gpgEnv(p string) []string {
	gpgEnvOnce.Do(func() {
		home := os.Getenv("GNUPGHOME")
		if runtime.GOOS != "windows" || !winPathRe.MatchString(home) {
			return
		}
		c := exec.Command(p, "--version")
		c.Env = slices.DeleteFunc(os.Environ(), func(e string) bool { return strings.HasPrefix(strings.ToUpper(e), "GNUPGHOME=") })
		out, err := c.Output()
		if err != nil || !msysHomeRe.Match(out) {
			return
		}
		posix := winPathRe.ReplaceAllStringFunc(home, func(m string) string { return "/" + strings.ToLower(m[:1]) + "/" })
		gpgEnvVal = append(c.Env, "GNUPGHOME="+strings.ReplaceAll(posix, `\`, "/"))
	})
	return gpgEnvVal
}

// CLI_SPEC 3.2: the local keyring is the first source; nil when gpg is unavailable
func gpgKeyring() func(ctx context.Context, fpr string) ([]byte, error) {
	if _, ok := gpgPath(); !ok {
		return nil
	}
	return func(ctx context.Context, fpr string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		b, err := runGpg(ctx, nil, "--batch", "--export", "--", fpr)
		if err != nil {
			return nil, err
		}
		if len(b) == 0 {
			return nil, nil
		}
		return b, nil
	}
}

type gpgSubkey struct {
	fpr      string
	created  int64
	usable   bool
	validity string
}

type gpgSecretKey struct {
	fpr     string
	uids    []string
	primary gpgSubkey
	subkeys []gpgSubkey
}

var colonEscape = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)

func unescapeColon(s string) string {
	return colonEscape.ReplaceAllStringFunc(s, func(m string) string {
		v, _ := strconv.ParseUint(m[2:], 16, 8)
		return string([]byte{byte(v)})
	})
}

// parses `gpg --list-secret-keys --with-colons` (doc/DETAILS in GnuPG)
func parseGpgSecretKeys(out string) []*gpgSecretKey {
	var keys []*gpgSecretKey
	var cur *gpgSecretKey
	var last *gpgSubkey
	for _, line := range strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n") {
		f := strings.Split(line, ":")
		for len(f) < 15 {
			f = append(f, "")
		}
		switch f[0] {
		case "sec", "ssb":
			created, _ := strconv.ParseInt(f[5], 10, 64)
			k := gpgSubkey{created: created, validity: f[1]}
			// field 12: own capabilities in lower case; field 15 "#" marks a stub without the secret
			k.usable = strings.Contains(f[11], "s") && !strings.ContainsAny(f[1], "rei") && f[14] != "#"
			if f[0] == "sec" {
				cur = &gpgSecretKey{primary: k}
				keys = append(keys, cur)
				last = &cur.primary
			} else if cur != nil {
				cur.subkeys = append(cur.subkeys, k)
				last = &cur.subkeys[len(cur.subkeys)-1]
			}
		case "fpr":
			if last != nil && last.fpr == "" {
				last.fpr = strings.ToUpper(f[9])
				if cur != nil && last == &cur.primary {
					cur.fpr = last.fpr
				}
			}
		case "uid":
			if cur != nil && !strings.ContainsAny(f[1], "rei") {
				cur.uids = append(cur.uids, unescapeColon(f[9]))
			}
		}
		if f[0] != "fpr" && f[0] != "grp" && f[0] != "sec" && f[0] != "ssb" {
			last = nil
		}
	}
	return keys
}

// gpg signs with the newest usable signing subkey, else the primary key
func (k *gpgSecretKey) signingFpr() string {
	subs := slices.Clone(k.subkeys)
	slices.SortStableFunc(subs, func(a, b gpgSubkey) int { return int(b.created - a.created) })
	for _, s := range subs {
		if s.usable {
			return s.fpr
		}
	}
	if k.primary.usable {
		return k.primary.fpr
	}
	return ""
}

func listGpgSecretKeys(ctx context.Context, id string) ([]*gpgSecretKey, error) {
	args := []string{"--batch", "--with-colons", "--fixed-list-mode", "--list-secret-keys"}
	if id != "" {
		args = append(args, "--", id)
	}
	out, err := runGpg(ctx, nil, args...)
	if err != nil {
		return nil, err
	}
	return parseGpgSecretKeys(string(out)), nil
}

type gpgSigner struct {
	fpr, localUser string
	emails         []string
}

func (s *gpgSigner) Fpr() string      { return s.fpr }
func (s *gpgSigner) Emails() []string { return s.emails }

// CLI_SPEC 3.1.2: gpg's output must pass the SPEC 6.2 checks and come from the key fpr names
func (s *gpgSigner) Sign(payload []byte) ([]byte, error) {
	p, _ := gpgPath()
	args := []string{"--detach-sign", "--digest-algo", "SHA256"}
	if s.localUser != "" {
		args = append(args, "--local-user", s.localUser)
	}
	var out bytes.Buffer
	c := exec.Command(p, args...)
	c.Env = gpgEnv(p)
	c.Stdin, c.Stdout, c.Stderr = bytes.NewReader(payload), &out, os.Stderr
	if err := c.Run(); err != nil {
		return nil, &mdsig.ValueError{Msg: i18n.T("sign.gpg_failed", err)}
	}
	sig := out.Bytes()
	// an `armor` line in gpg.conf makes gpg write ASCII armor
	if len(sig) > 0 && sig[0]&0x80 == 0 {
		if blocks, err := mdsig.Dearmor(string(sig)); err == nil && len(blocks) == 1 {
			sig = blocks[0]
		}
	}
	if chk := mdsig.CheckPGPSignaturePacket(sig, s.fpr); !chk.OK {
		return nil, &mdsig.ValueError{Msg: i18n.T("sign.gpg_bad_output", localize(chk.Message), s.fpr)}
	}
	return sig, nil
}

// --- key selection

type pgpKeyChoice struct {
	fpr    string
	keyAlg string
	emails []string
	file   *mdsig.PGPSecretKeyInfo
}

func loadPgpKey(ctx context.Context, o *signOptions, now time.Time) (*pgpKeyChoice, error) {
	if o.pgpKey != "" {
		data, err := os.ReadFile(o.pgpKey)
		if err != nil {
			return nil, exitf(exitIO, "%v", err)
		}
		info, err := mdsig.ReadPGPSecretKey(data, now)
		if err != nil {
			return nil, exitf(exitIO, "%s: %v", o.pgpKey, err)
		}
		return &pgpKeyChoice{fpr: info.Fpr, keyAlg: info.KeyAlg, emails: info.Emails, file: info}, nil
	}
	if _, ok := gpgPath(); !ok {
		return nil, exitf(exitUsage, "%s", i18n.T("sign.gpg_not_found"))
	}
	id := strings.TrimSuffix(o.localUser, "!")
	keys, err := listGpgSecretKeys(ctx, id)
	if err != nil || len(keys) == 0 {
		return nil, exitf(exitUsage, "%s", i18n.T("sign.gpg_no_secret_key", gpgKeyLabel(o)))
	}
	var key *gpgSecretKey
	fpr := ""
	if strings.HasSuffix(o.localUser, "!") {
		want := strings.ToUpper(strings.TrimPrefix(id, "0x"))
		for _, k := range keys {
			for _, s := range append([]gpgSubkey{k.primary}, k.subkeys...) {
				if s.fpr == want && s.usable {
					key, fpr = k, s.fpr
				}
			}
		}
	} else {
		for _, k := range keys {
			if f := k.signingFpr(); f != "" {
				key, fpr = k, f
				break
			}
		}
	}
	if key == nil {
		return nil, exitf(exitUsage, "%s", i18n.T("sign.gpg_no_signing_key", gpgKeyLabel(o)))
	}
	cert, err := runGpg(ctx, nil, "--batch", "--export", "--", key.fpr)
	if err != nil || len(cert) == 0 {
		return nil, exitf(exitUsage, "%s", i18n.T("sign.gpg_export_failed", key.fpr, err))
	}
	info, err := mdsig.CheckPGPKey(cert, fpr, now)
	if err != nil {
		return nil, exitf(exitUsage, "%s: %v", fpr, err)
	}
	return &pgpKeyChoice{fpr: fpr, keyAlg: info.KeyAlg, emails: info.Emails}, nil
}

func pgpPassphrase(path string) ([]byte, error) {
	if isTTY(os.Stdin) {
		fmt.Fprint(stderr, i18n.T("sign.passphrase", path))
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(stderr)
		return pw, err
	}
	if v, ok := os.LookupEnv("MDSIG_PGP_PASSPHRASE"); ok {
		return []byte(v), nil
	}
	return nil, errors.New(i18n.T("sign.pgp_passphrase_needed", path))
}

// returns the signer and a function that drops the secret key material
func (c *pgpKeyChoice) signer(o *signOptions) (mdsig.PGPSigner, func(), error) {
	if c.file == nil {
		return &gpgSigner{fpr: c.fpr, localUser: o.localUser, emails: c.emails}, func() {}, nil
	}
	var pass []byte
	if c.file.Protected {
		p, err := pgpPassphrase(o.pgpKey)
		if err != nil {
			return nil, nil, exitf(exitIO, "%v", err)
		}
		if p == nil {
			p = []byte{}
		}
		pass = p
	}
	s, err := mdsig.UnlockPGPSecretKey(c.file, pass, mdsig.PGPUnlockOptions{})
	clear(pass)
	if err != nil {
		return nil, nil, exitf(exitIO, "%s: %v", o.pgpKey, err)
	}
	return s, s.Dispose, nil
}

// CLI_SPEC 3.1.2: without --signer the email comes from the key's valid user IDs
func choosePgpEmail(o *signOptions, emails []string) (string, error) {
	switch {
	case len(emails) == 1:
		return emails[0], nil
	case len(emails) == 0:
		return "", exitf(exitUsage, "%s", i18n.T("sign.pgp_no_email"))
	case !o.interactive || !interactiveTTY():
		return "", exitf(exitUsage, "%s", i18n.T("sign.pgp_many_emails", strings.Join(emails, ", ")))
	}
	var opts []huh.Option[string]
	for _, e := range emails {
		opts = append(opts, huh.NewOption(e, e))
	}
	choice := emails[0]
	if err := runForm(huh.NewSelect[string]().Title(i18n.T("launcher.pgp_email")).Options(opts...).Value(&choice)); err != nil {
		return "", err
	}
	answered(i18n.T("launcher.pgp_email"), choice)
	return choice, nil
}

// --- launcher

const pgpKeyFileChoice = "\x00file"

func launchPgpKey(o *signOptions) error {
	ctx := context.Background()
	var opts []huh.Option[string]
	labels := map[string]string{}
	if _, ok := gpgPath(); ok {
		if keys, err := listGpgSecretKeys(ctx, ""); err == nil {
			for _, k := range keys {
				if k.signingFpr() == "" {
					continue
				}
				label := k.fpr
				if len(k.uids) > 0 {
					label += "  " + k.uids[0]
				}
				labels[k.fpr] = label
				opts = append(opts, huh.NewOption(label, k.fpr))
			}
		}
	}
	opts = append(opts, huh.NewOption(i18n.T("launcher.pgp_key_file"), pgpKeyFileChoice))
	choice := pgpKeyFileChoice
	if err := runForm(huh.NewSelect[string]().Title(i18n.T("launcher.pgp_key")).Options(opts...).Value(&choice)); err != nil {
		return err
	}
	if choice == pgpKeyFileChoice {
		answered(i18n.T("launcher.pgp_key"), i18n.T("launcher.pgp_key_file"))
		if err := runForm(huh.NewInput().Title(i18n.T("launcher.pgp_key_path")).Prompt("> ").Value(&o.pgpKey).Validate(nonEmpty)); err != nil {
			return err
		}
		o.pgpKey = strings.TrimSpace(o.pgpKey)
		answered(i18n.T("launcher.pgp_key_path"), o.pgpKey)
	} else {
		o.localUser = choice
		answered(i18n.T("launcher.pgp_key"), labels[choice])
	}
	c, err := loadPgpKey(ctx, o, time.Now())
	if err != nil {
		return err
	}
	o.signer, err = choosePgpEmail(o, c.emails)
	if err != nil {
		return err
	}
	if len(c.emails) == 1 {
		answered(i18n.T("launcher.pgp_email"), o.signer)
	}
	return nil
}

func gpgKeyLabel(o *signOptions) string {
	if o.localUser == "" {
		return i18n.T("sign.gpg_default_key")
	}
	return o.localUser
}
