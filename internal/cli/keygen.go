package cli

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/spf13/cobra"

	"github.com/SHIOZAKI-Shota/md-signature/internal/i18n"
	"github.com/SHIOZAKI-Shota/md-signature/internal/sshkeys"
	"github.com/SHIOZAKI-Shota/md-signature/mdsig"
)

type keygenOptions struct{ out, domain, selector string }

func newKeygenCmd() *cobra.Command {
	o := &keygenOptions{}
	c := &cobra.Command{
		Use:   "keygen",
		Short: "Generate an Ed25519 key pair (OpenSSH format)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeygen(o)
		},
	}
	c.Flags().StringVarP(&o.out, "out", "o", "./mdsig_ed25519", "write <prefix> (private key, mode 0600) and <prefix>.pub")
	c.Flags().StringVarP(&o.domain, "domain", "d", "", "also print the DNS TXT record for this domain")
	c.Flags().StringVar(&o.selector, "selector", "", "selector for the DNS record name")
	return c
}

func runKeygen(o *keygenOptions) error {
	if o.out == "" {
		return exitf(exitUsage, "--out must not be empty")
	}
	domain := strings.TrimSuffix(strings.ToLower(o.domain), ".")
	if o.selector != "" && domain == "" {
		return exitf(exitUsage, "%s", i18n.T("keygen.selector_needs_domain"))
	}
	for k, v := range map[string]string{"domain": domain, "selector": o.selector} {
		if v == "" {
			continue
		}
		if e := mdsig.ValidateValue(v); e != "" || strings.ContainsAny(v, " ;\"") {
			return exitf(exitUsage, "invalid %s %q", k, v)
		}
	}
	pub, err := sshkeys.GenerateKeyPair(o.out, "mdsig")
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return exitf(exitIO, "%s", i18n.T("keygen.exists", err))
		}
		return exitf(exitIO, "%v", err)
	}
	b64 := base64.StdEncoding.EncodeToString(pub)
	w := stdout
	fmt.Fprintf(w, "%s %s\n", pad(i18n.T("keygen.private"), 12), o.out)
	fmt.Fprintf(w, "%s %s\n", pad(i18n.T("keygen.public"), 12), o.out+".pub")
	if domain != "" {
		name := "_mdsig." + domain + "."
		if o.selector != "" {
			name = o.selector + "." + name
		}
		fmt.Fprintf(w, "\n%s\n  %s IN TXT \"v=mdsig1; k=ed25519; p=%s\"\n", i18n.T("keygen.dns"), name, b64)
	}
	fmt.Fprintf(w, "\n%s\n  ed25519:%s\n", i18n.T("keygen.tofu"), b64)
	fmt.Fprintf(w, "\n%s\n  %s\n", i18n.T("keygen.fingerprint"), mdsig.SSHFingerprint(pub))
	return nil
}
