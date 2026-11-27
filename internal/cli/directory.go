package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"mdsig.dev/internal/i18n"
	"mdsig.dev/mdsig"
)

// --- trusted key directories (SPEC 4.7: chosen by the verifier) ---

type directoryStore struct {
	path string
	list []string
}

func openDirectoryStore() *directoryStore {
	s := &directoryStore{}
	dir, err := os.UserConfigDir()
	if err != nil {
		return s
	}
	s.path = filepath.Join(dir, "mdsig", "key_directories.json")
	if b, err := os.ReadFile(s.path); err == nil {
		_ = json.Unmarshal(b, &s.list)
	}
	return s
}

func (s *directoryStore) save() error {
	if s.path == "" {
		return fmt.Errorf("no configuration directory")
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	if s.list == nil {
		s.list = []string{}
	}
	b, _ := json.MarshalIndent(s.list, "", "  ")
	return writeAtomic(s.path, append(b, '\n'))
}

// the default list, then the stored ones, then --key-directory
func trustedDirectories(extra []string) ([]string, error) {
	var out []string
	for _, d := range append(append(mdsig.DefaultKeyDirectories(), openDirectoryStore().list...), extra...) {
		if !mdsig.IsValidKeyDirectory(d) {
			return nil, exitf(exitUsage, "%s", i18n.T("directory.bad_url", d))
		}
		d = strings.TrimRight(d, "/")
		if !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	return out, nil
}

// --- mdsig directory ---

func newDirectoryCmd() *cobra.Command {
	c := &cobra.Command{Use: "directory", Short: "Manage key directories (SPEC 4.7)"}
	trust := &cobra.Command{Use: "trust", Short: "Key directories this verifier trusts"}
	trust.AddCommand(
		&cobra.Command{
			Use: "add <url>", Short: "Trust another key directory", Args: cobra.ExactArgs(1),
			RunE: func(_ *cobra.Command, args []string) error { return runTrust("add", args[0]) },
		},
		&cobra.Command{
			Use: "remove <url>", Short: "Stop trusting a key directory", Args: cobra.ExactArgs(1),
			RunE: func(_ *cobra.Command, args []string) error { return runTrust("remove", args[0]) },
		},
		&cobra.Command{
			Use: "list", Short: "Print the trusted key directories", Args: cobra.NoArgs,
			RunE: func(_ *cobra.Command, _ []string) error { return runTrust("list", "") },
		},
	)
	var email, directory, keyPath, label string
	register := &cobra.Command{
		Use:   "register",
		Short: "Publish your Ed25519 key for an email address (confirmed by email)",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runRegister(email, directory, keyPath, label)
		},
	}
	register.Flags().StringVar(&email, "email", "", "the email address to publish the key for (required)")
	register.Flags().StringVar(&directory, "directory", "", "key directory to register with (default: the one the address's domain names in _mdsig, otherwise "+mdsig.DefaultKeyDirectories()[0]+")")
	register.Flags().StringVarP(&keyPath, "key", "k", "", "OpenSSH Ed25519 private key file (default: ssh-agent, then ~/.ssh/id_ed25519)")
	register.Flags().StringVar(&label, "label", "", "a name for the key, sent to the directory (whether it is shown depends on the directory)")
	var removeEmail, removeDirectory, removeKey, removeWith string
	remove := &cobra.Command{
		Use:   "remove",
		Short: "Ask a key directory to remove your keys (confirmed by email, or at once with --with-key)",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if removeWith != "" {
				if removeKey != "" {
					return exitf(exitUsage, "%s", i18n.T("directory.with_key_and_key"))
				}
				return runRemoveWithKey(removeEmail, removeDirectory, strings.TrimPrefix(removeWith, discoverKey))
			}
			return runRemoveKey(removeEmail, removeDirectory, removeKey)
		},
	}
	remove.Flags().StringVar(&removeEmail, "email", "", "the email address whose keys to remove (required)")
	remove.Flags().StringVar(&removeDirectory, "directory", "", "key directory (default: as for register)")
	remove.Flags().StringVar(&removeKey, "key", "", "remove only this public key (base64); default: every key for the address")
	remove.Flags().StringVar(&removeWith, "with-key", "", "remove the key you sign with at once, without a confirmation email (--with-key alone: ssh-agent, then ~/.ssh/id_ed25519; --with-key=<file>: that OpenSSH private key)")
	remove.Flags().Lookup("with-key").NoOptDefVal = discoverKey
	c.AddCommand(trust, register, remove)
	return c
}

func runTrust(action, url string) error {
	s := openDirectoryStore()
	url = strings.TrimRight(url, "/")
	switch action {
	case "list":
		for _, d := range mdsig.DefaultKeyDirectories() {
			fmt.Fprintln(stdout, d+"  "+i18n.T("directory.default"))
		}
		for _, d := range s.list {
			fmt.Fprintln(stdout, safeText(d))
		}
		return nil
	case "add":
		if !mdsig.IsValidKeyDirectory(url) {
			return exitf(exitUsage, "%s", i18n.T("directory.bad_url", url))
		}
		if slices.Contains(mdsig.DefaultKeyDirectories(), url) || slices.Contains(s.list, url) {
			fmt.Fprintln(stderr, i18n.T("directory.already", safeText(url)))
			return nil
		}
		s.list = append(s.list, url)
	case "remove":
		i := slices.Index(s.list, url)
		if i < 0 {
			return exitf(exitUsage, "%s", i18n.T("directory.not_trusted", safeText(url)))
		}
		s.list = slices.Delete(s.list, i, i+1)
	}
	if err := s.save(); err != nil {
		return exitf(exitIO, "%v", err)
	}
	fmt.Fprintln(stderr, i18n.T(map[string]string{"add": "directory.added", "remove": "directory.removed"}[action], safeText(url)))
	return nil
}

func registrationTarget(ctx context.Context, email, directory string) (string, error) {
	if directory != "" {
		if !mdsig.IsValidKeyDirectory(directory) {
			return "", exitf(exitUsage, "%s", i18n.T("directory.bad_url", directory))
		}
		return directory, nil
	}
	return mdsig.RegistrationDirectory(ctx, email, mdsig.DefaultKeyDirectories()[0], &mdsig.ResolveOptions{HTTPClient: mdsig.SafeHTTPClient(15 * time.Second)}), nil
}

func runRegister(email, directory, keyPath, label string) error {
	if email == "" {
		return exitf(exitUsage, "%s", i18n.T("directory.email_required"))
	}
	ctx := context.Background()
	dir, err := registrationTarget(ctx, strings.ToLower(email), directory)
	if err != nil {
		return err
	}
	signer, err := discoverSigner(ctx, &signOptions{keyPath: keyPath})
	if err != nil {
		return err
	}
	if err := mdsig.RegisterKey(ctx, mdsig.SafeHTTPClient(30*time.Second), dir, email, signer, label); err != nil {
		return exitf(exitNetwork, "%s", i18n.T("directory.request_failed", safeText(dir), err))
	}
	fmt.Fprintln(stderr, i18n.T("directory.registered", safeText(strings.ToLower(email)), safeText(dir)))
	return nil
}

func runRemoveKey(email, directory, key string) error {
	if email == "" {
		return exitf(exitUsage, "%s", i18n.T("directory.email_required"))
	}
	ctx := context.Background()
	dir, err := registrationTarget(ctx, strings.ToLower(email), directory)
	if err != nil {
		return err
	}
	if err := mdsig.RequestKeyRemoval(ctx, mdsig.SafeHTTPClient(30*time.Second), dir, email, key); err != nil {
		return exitf(exitNetwork, "%s", i18n.T("directory.request_failed", safeText(dir), err))
	}
	fmt.Fprintln(stderr, i18n.T("directory.removal_sent", safeText(strings.ToLower(email)), safeText(dir)))
	return nil
}

// --with-key given without a file
const discoverKey = "\x00discover"

func runRemoveWithKey(email, directory, keyPath string) error {
	if email == "" {
		return exitf(exitUsage, "%s", i18n.T("directory.email_required"))
	}
	ctx := context.Background()
	dir, err := registrationTarget(ctx, strings.ToLower(email), directory)
	if err != nil {
		return err
	}
	signer, err := discoverSigner(ctx, &signOptions{keyPath: keyPath})
	if err != nil {
		return err
	}
	if err := mdsig.RemoveKeyWithProof(ctx, mdsig.SafeHTTPClient(30*time.Second), dir, email, signer); err != nil {
		return exitf(exitNetwork, "%s", i18n.T("directory.request_failed", safeText(dir), err))
	}
	fp := mdsig.KeyFingerprint("ed25519:" + base64.StdEncoding.EncodeToString(signer.PublicKey()))
	fmt.Fprintln(stderr, i18n.T("directory.removed_now", fp, safeText(strings.ToLower(email)), safeText(dir)))
	return nil
}

// after signing with method directory: warn when verifiers using the default rules would not find the key
func warnIfUnpublished(ctx context.Context, fields map[string]string, pub []byte) {
	dirs, err := trustedDirectories(nil)
	if err != nil {
		return
	}
	res, err := mdsig.DefaultResolvers()["directory"].Resolve(ctx, fields, &mdsig.ResolveOptions{HTTPClient: mdsig.SafeHTTPClient(15 * time.Second), KeyDirectories: dirs})
	if err == nil {
		for _, k := range res.Keys {
			if bytes.Equal(k.Key, pub) {
				return
			}
		}
		err = fmt.Errorf("%s", i18n.T("directory.other_key"))
	}
	fmt.Fprintln(stderr, i18n.T("sign.directory_unpublished", safeText(fields["signer"]), err))
}
