package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"mdsig.dev/internal/i18n"
	"mdsig.dev/internal/sshkeys"
	"mdsig.dev/mdsig"
)

type signOptions struct {
	method, signer, keyPath, selector, role, reason, tsa string
	toStdout, force                                      bool
	scope, expires, revocationURL                        string
	require, resources                                   []string
	autoResources                                        bool
	interactive                                          bool
	localUser, pgpKey                                    string
	tsaRoots                                             []string
	embedKey, noEmbedKey                                 bool
}

var urlArg = regexp.MustCompile(`^https?://`)

func newSignCmd() *cobra.Command {
	o := &signOptions{}
	c := &cobra.Command{
		Use:   "sign <file>",
		Short: "Sign a Markdown file (co-signs if it already has signatures)",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			// pflag treats the URL in "--tsa URL" as a positional arg because the value is optional
			if len(args) == 2 {
				if !cmd.Flags().Changed("tsa") || o.tsa != mdsig.DefaultTSAURL {
					return exitf(exitUsage, "sign takes exactly one file")
				}
				switch {
				case urlArg.MatchString(args[0]) && !urlArg.MatchString(args[1]):
					o.tsa, args = args[0], args[1:]
				case urlArg.MatchString(args[1]):
					o.tsa, args = args[1], args[:1]
				default:
					return exitf(exitUsage, "sign takes exactly one file")
				}
			}
			return runSign(o, args[0])
		},
	}
	f := c.Flags()
	f.StringVarP(&o.method, "method", "m", "git-hosting", "git-hosting, dns, tofu, pgp, or directory")
	f.StringVarP(&o.signer, "signer", "s", "", "signer ID: github.com/alice, example.com, bob@laptop, alice@example.com, ... (required; pgp: defaults to the key's email)")
	f.StringVarP(&o.keyPath, "key", "k", "", "OpenSSH Ed25519 private key file (default: ssh-agent, then ~/.ssh/id_ed25519)")
	f.StringVar(&o.selector, "selector", "", "dns only: DNS selector")
	f.StringVarP(&o.localUser, "local-user", "u", "", "pgp only: key for gpg to sign with (fingerprint or user ID; default: gpg's default key)")
	f.StringVar(&o.pgpKey, "pgp-key", "", "pgp only: ASCII-armored OpenPGP secret key file to sign with directly instead of gpg")
	f.StringVarP(&o.role, "role", "r", "", "author, reviewer, approver, witness, or any value")
	f.StringVar(&o.reason, "reason", "", "free-text reason")
	f.StringVar(&o.tsa, "tsa", "", "request an RFC 3161 timestamp (default URL "+mdsig.DefaultTSAURL+"; use --tsa=URL for another TSA)")
	f.Lookup("tsa").NoOptDefVal = mdsig.DefaultTSAURL
	f.StringArrayVar(&o.tsaRoots, "tsa-root", nil, "also trust this root certificate when checking a timestamp token (PEM or DER file; repeatable)")
	f.BoolVar(&o.toStdout, "stdout", false, "write the signed document to stdout instead of changing the file")
	f.BoolVar(&o.embedKey, "embed-key", false, "dns and git-hosting only: also write the public key into the block, so the signature can still be checked after the key is removed (directory does this by default)")
	f.BoolVar(&o.noEmbedKey, "no-embed-key", false, "directory only: do not write the public key into the block")
	f.BoolVar(&o.force, "force", false, "sign the whole file as a new document even if a signature block is followed by unsigned content")
	f.StringVar(&o.scope, "scope", "", "sign only these sections, comma-separated: --scope terms,fees")
	f.StringArrayVar(&o.require, "require", nil, "one `line` of the require value (repeatable, kept in order): <method>:<signer>[ <role>], step <n>[ any <m>], or order pending|guide|strict")
	f.StringArrayVar(&o.resources, "resource", nil, "bind a file (relative to the document) or https:// URL by its SHA-256 (repeatable)")
	f.BoolVar(&o.autoResources, "auto-resources", false, "also bind every local image referenced by ![..](..) or <img src> outside code fences")
	f.StringVar(&o.expires, "expires", "", "expiry: YYYY-MM-DDTHH:MM:SSZ, or a duration from now such as 30d or 12h")
	f.StringVar(&o.revocationURL, "revocation-url", "", "https:// URL of the signer's revocation list")
	return c
}

func runSign(o *signOptions, file string) error {
	switch o.method {
	case "git-hosting", "dns", "tofu", "pgp", "directory":
	default:
		return exitf(exitUsage, "%s", i18n.T("sign.bad_method", o.method))
	}
	isPgp := o.method == "pgp"
	if o.signer == "" && !isPgp {
		return exitf(exitUsage, "%s", i18n.T("sign.signer_required"))
	}
	tsaRoots, rootErr := mdsig.LoadTSARoots(o.tsaRoots)
	if rootErr != nil {
		return exitf(exitUsage, "%s", i18n.T("tsa.bad_root", rootErr))
	}
	if len(tsaRoots) > 0 && o.tsa == "" {
		return exitf(exitUsage, "%s", i18n.T("sign.tsa_root_needs_tsa"))
	}
	if o.embedKey && o.method != "dns" && o.method != "git-hosting" && o.method != "directory" {
		return exitf(exitUsage, "%s", i18n.T("sign.embed_key_method", o.method))
	}
	if o.noEmbedKey && o.method != "directory" {
		return exitf(exitUsage, "%s", i18n.T("sign.no_embed_key_method", o.method))
	}
	if o.selector != "" && o.method != "dns" {
		return exitf(exitUsage, "%s", i18n.T("sign.selector_dns_only"))
	}
	if err := checkPgpFlags(o); err != nil {
		return err
	}
	// validate before any passphrase prompt or agent access
	for k, v := range map[string]string{"signer": o.signer, "selector": o.selector, "role": o.role, "reason": o.reason, "tsa_url": o.tsa} {
		if v == "" {
			continue
		}
		if e := mdsig.ValidateValue(v); e != "" {
			return exitf(exitUsage, "%s: %s", k, e)
		}
	}

	ext, err := parseExtensionFlags(o, time.Now())
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
	text := string(data)

	ctx := context.Background()
	refs := append([]string{}, o.resources...)
	if o.autoResources {
		refs = append(refs, mdsig.FindLocalImages(mdsig.ParseDocument(text).Body)...)
	}
	items, err := loadSignResources(ctx, filepath.Dir(file), refs)
	if err != nil {
		return err
	}

	var signer mdsig.Signer
	var pgpSigner mdsig.PGPSigner
	if isPgp {
		key, err := loadPgpKey(ctx, o, time.Now())
		if err != nil {
			return err
		}
		if o.signer == "" {
			if o.signer, err = choosePgpEmail(o, key.emails); err != nil {
				return err
			}
		}
		ps, dispose, err := key.signer(o)
		if err != nil {
			return err
		}
		defer dispose()
		pgpSigner = ps
	} else if signer, err = discoverSigner(ctx, o); err != nil {
		return err
	}

	res, err := mdsig.SignDocument(ctx, text, mdsig.SignOptions{
		Signer: signer, PGP: pgpSigner, Method: o.method, SignerID: o.signer, Selector: o.selector,
		Role: o.role, Reason: o.reason, TSAURL: o.tsa, TSA: mdsig.TSAVerifyOptions{ExtraRoots: tsaRoots}, Force: o.force,
		Scope: ext.scope, Require: o.require, Expires: ext.expires, RevocationURL: o.revocationURL, Resources: items,
		HTTPClient: httpClientWithTimeout(30 * time.Second), EmbedKey: o.embedKey, OmitKeySnapshot: o.noEmbedKey,
	})
	if err != nil {
		var ve *mdsig.ValueError
		var se *mdsig.SignError
		switch {
		case errors.As(err, &ve):
			return exitf(exitUsage, "%s", ve.Msg)
		case errors.As(err, &se):
			return exitf(exitFail, "%s", se.Msg)
		case o.tsa != "":
			return exitf(exitNetwork, "%v", err)
		default:
			return exitf(exitFail, "%v", err)
		}
	}

	if o.toStdout {
		if _, err := fmt.Fprint(stdout, res.Text); err != nil {
			return exitf(exitIO, "%v", err)
		}
	} else if err := writeAtomic(file, []byte(res.Text)); err != nil {
		return exitf(exitIO, "%v", err)
	}
	if o.method == "directory" {
		warnIfUnpublished(ctx, res.Fields, signer.PublicKey())
	}
	if o.interactive {
		fmt.Fprintln(stderr, i18n.T("launcher.signed", file))
	} else {
		fmt.Fprintln(stderr, i18n.T("sign.done", file, res.Previous+1, o.method, res.Fields["signer"]))
	}
	return nil
}

type signExtensions struct {
	scope   []string
	expires string
}

var durationArg = regexp.MustCompile(`^([0-9]+)([dh])$`)

func parseExtensionFlags(o *signOptions, now time.Time) (*signExtensions, error) {
	ext := &signExtensions{}
	if o.scope != "" {
		for _, id := range strings.Split(o.scope, ",") {
			id = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(id), "section:"))
			ext.scope = append(ext.scope, id)
		}
		sc, ok := mdsig.FormatScope(ext.scope)
		if !ok {
			return nil, exitf(exitUsage, "%s", i18n.T("sign.bad_scope", o.scope))
		}
		if _, ok := mdsig.ParseScope(sc); !ok {
			return nil, exitf(exitUsage, "%s", i18n.T("sign.bad_scope", o.scope))
		}
	}
	for _, r := range o.require {
		if e := mdsig.ValidateValue(r); e != "" {
			return nil, exitf(exitUsage, "require: %s", e)
		}
	}
	// each --require is one line; "step" lines only make sense together with the lines after them
	if len(o.require) > 0 {
		if _, errs := mdsig.ParseRequire(strings.Join(o.require, "\n"), 0, mdsig.SpecVersion); len(errs) > 0 {
			return nil, exitf(exitUsage, "%s", strings.Join(errs, "; "))
		}
	}
	for _, ref := range o.resources {
		if e := mdsig.ValidateValue(ref); e != "" {
			return nil, exitf(exitUsage, "resource: %s", e)
		}
		if e := mdsig.ValidateResourceRef(ref); e != "" {
			return nil, exitf(exitUsage, "resource: %s", e)
		}
	}
	if o.expires != "" {
		switch m := durationArg.FindStringSubmatch(o.expires); {
		case m != nil:
			n, err := strconv.Atoi(m[1])
			if err != nil || n <= 0 || n > 100000 {
				return nil, exitf(exitUsage, "%s", i18n.T("sign.bad_expires", o.expires))
			}
			unit := 24 * time.Hour
			if m[2] == "h" {
				unit = time.Hour
			}
			ext.expires = mdsig.NowTS(now.Add(time.Duration(n) * unit))
		case mdsig.IsValidTimestamp(o.expires):
			ext.expires = o.expires
		default:
			return nil, exitf(exitUsage, "%s", i18n.T("sign.bad_expires", o.expires))
		}
	}
	if o.revocationURL != "" && (!mdsig.IsValidRevocationURL(o.revocationURL) || mdsig.ValidateValue(o.revocationURL) != "") {
		return nil, exitf(exitUsage, "%s", i18n.T("sign.bad_revocation_url", o.revocationURL))
	}
	return ext, nil
}

func loadSignResources(ctx context.Context, dir string, refs []string) ([]mdsig.ResourceItem, error) {
	var items []mdsig.ResourceItem
	seen := map[string]bool{}
	client := mdsig.SafeHTTPClient(60 * time.Second)
	load := mdsig.DirResourceLoader(dir)
	for _, ref := range refs {
		if seen[ref] {
			continue
		}
		seen[ref] = true
		var b []byte
		var err error
		if strings.HasPrefix(strings.ToLower(ref), "https://") {
			b, err = mdsig.FetchResource(ctx, client, ref, mdsig.MaxResourceBytes)
			if err != nil {
				return nil, exitf(exitNetwork, "%s", i18n.T("sign.resource_fetch_failed", ref, err))
			}
		} else {
			b, err = load(ref)
			if err != nil {
				return nil, exitf(exitIO, "%s: %v", ref, err)
			}
			if b == nil {
				return nil, exitf(exitIO, "%s", i18n.T("sign.resource_missing", ref, filepath.Join(dir, filepath.FromSlash(ref))))
			}
		}
		items = append(items, mdsig.ResourceItem{Ref: ref, Bytes: b})
	}
	return items, nil
}

func writeAtomic(path string, data []byte) error {
	mode := fs.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".mdsig-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	_ = os.Chmod(name, mode)
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

func passphraseSource(path string) func() ([]byte, error) {
	return func() ([]byte, error) {
		if isTTY(os.Stdin) {
			fmt.Fprint(stderr, i18n.T("sign.passphrase", path))
			pw, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(stderr)
			return pw, err
		}
		if v, ok := os.LookupEnv("MDSIG_PASSPHRASE"); ok {
			return []byte(v), nil
		}
		return nil, errors.New(i18n.T("sign.passphrase_needed", path))
	}
}

func loadKeyFile(path string) (mdsig.Signer, error) {
	s, err := sshkeys.LoadPrivateKeyFile(path, passphraseSource(path))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
			return nil, exitf(exitIO, "%v", err)
		}
		return nil, exitf(exitIO, "%s: %v", path, err)
	}
	return s, nil
}

func discoverSigner(ctx context.Context, o *signOptions) (mdsig.Signer, error) {
	if o.keyPath != "" {
		return loadKeyFile(o.keyPath)
	}
	if s := agentSigner(ctx, o); s != nil {
		return s, nil
	}
	p, err := sshkeys.DefaultKeyPath()
	if err != nil {
		return nil, exitf(exitIO, "%v", err)
	}
	if _, err := os.Stat(p); err != nil {
		return nil, exitf(exitIO, "%s", i18n.T("sign.no_key", p))
	}
	return loadKeyFile(p)
}

func agentSigner(ctx context.Context, o *signOptions) mdsig.Signer {
	ag, closer, err := sshkeys.OpenAgent()
	if err != nil || ag == nil {
		return nil
	}
	// the agent connection stays open for signing; the process exits afterwards
	_ = closer
	keys, err := sshkeys.ListEd25519(ag)
	if err != nil || len(keys) == 0 {
		return nil
	}
	if len(keys) == 1 {
		return keys[0]
	}
	candidates := keys
	if o.method == "git-hosting" {
		var ro mdsig.ResolveOptions
		ro.HTTPClient = mdsig.SafeHTTPClient(10 * time.Second)
		if text, err := mdsig.FetchKeysFile(ctx, o.signer, &ro); err == nil {
			published := map[string]bool{}
			for _, k := range mdsig.ParseSSHPublicKeys(text) {
				if k.Key != nil {
					published[mdsig.SSHFingerprint(k.Key)] = true
				}
			}
			var matching []sshkeys.AgentKey
			for _, k := range keys {
				if published[k.Fingerprint()] {
					matching = append(matching, k)
				}
			}
			if len(matching) > 0 {
				candidates = matching
			}
		}
	}
	if len(candidates) == 1 || !o.interactive || !interactiveTTY() {
		return candidates[0]
	}
	var opts []huh.Option[int]
	for i, k := range candidates {
		opts = append(opts, huh.NewOption(strings.TrimSpace(k.Fingerprint()+"  "+k.Comment), i))
	}
	choice := 0
	if err := runForm(huh.NewSelect[int]().Title(i18n.T("sign.choose_agent_key")).Options(opts...).Value(&choice)); err != nil {
		return candidates[0]
	}
	return candidates[choice]
}

func checkPgpFlags(o *signOptions) error {
	if o.method != "pgp" {
		for flag, v := range map[string]string{"--local-user": o.localUser, "--pgp-key": o.pgpKey} {
			if v != "" {
				return exitf(exitUsage, "%s", i18n.T("sign.pgp_only", flag))
			}
		}
		return nil
	}
	if o.keyPath != "" {
		return exitf(exitUsage, "%s", i18n.T("sign.key_not_pgp"))
	}
	if o.localUser != "" && o.pgpKey != "" {
		return exitf(exitUsage, "%s", i18n.T("sign.pgp_key_and_local_user"))
	}
	return nil
}
