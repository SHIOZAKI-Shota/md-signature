package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"mdsig.dev/internal/i18n"
	"mdsig.dev/mdsig"
)

type revokeOptions struct {
	list                              string
	method, signer, keyPath, selector string
	localUser, pgpKey                 string
	index                             int
}

func newRevokeCmd() *cobra.Command {
	o := &revokeOptions{}
	c := &cobra.Command{
		Use:   "revoke <file> --list <list.md>",
		Short: "Add your signatures in a file to your revocation list and sign the list",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRevoke(o, args[0])
		},
	}
	f := c.Flags()
	f.StringVar(&o.list, "list", "", "the revocation list file (created if it does not exist; required)")
	f.StringVarP(&o.method, "method", "m", "git-hosting", "git-hosting, dns, tofu, or pgp")
	f.StringVarP(&o.signer, "signer", "s", "", "signer id whose signatures are revoked (required; pgp: defaults to the key's email)")
	f.StringVarP(&o.keyPath, "key", "k", "", "OpenSSH Ed25519 private key file (default: ssh-agent, then ~/.ssh/id_ed25519)")
	f.StringVar(&o.selector, "selector", "", "DNS selector (dns only)")
	f.StringVarP(&o.localUser, "local-user", "u", "", "pgp only: key for gpg to sign the list with (fingerprint or user ID; default: gpg's default key)")
	f.StringVar(&o.pgpKey, "pgp-key", "", "pgp only: ASCII-armored OpenPGP secret key file to sign the list with directly instead of gpg")
	f.IntVar(&o.index, "index", 0, "revoke only signature #n of <file> (default: every signature by the signer)")
	_ = c.MarkFlagRequired("list")
	return c
}

var revokedLine = regexp.MustCompile(`(?m)^revoked: sha256:([0-9a-f]{64})[ \t]*$`)

func sameRevokeSigner(method, a, b string) bool {
	if method == "dns" {
		return strings.TrimSuffix(strings.ToLower(a), ".") == strings.TrimSuffix(strings.ToLower(b), ".")
	}
	return a == b
}

func readTextFile(path string) (text string, ok bool, err error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, exitf(exitIO, "%v", err)
	}
	if !utf8.Valid(b) {
		return "", false, exitf(exitFail, "%s", i18n.T("file.not_utf8", path))
	}
	return string(b), true, nil
}

func runRevoke(o *revokeOptions, file string) error {
	switch o.method {
	case "git-hosting", "dns", "tofu", "pgp":
	default:
		return exitf(exitUsage, "%s", i18n.T("sign.bad_method", o.method))
	}
	isPgp := o.method == "pgp"
	if o.signer == "" && !isPgp {
		return exitf(exitUsage, "%s", i18n.T("sign.signer_required"))
	}
	so := &signOptions{method: o.method, signer: o.signer, keyPath: o.keyPath, selector: o.selector, localUser: o.localUser, pgpKey: o.pgpKey}
	if err := checkPgpFlags(so); err != nil {
		return err
	}
	if o.list == "" {
		return exitf(exitUsage, "%s", i18n.T("revoke.list_required"))
	}
	if o.selector != "" && o.method != "dns" {
		return exitf(exitUsage, "%s", i18n.T("sign.selector_dns_only"))
	}
	for k, v := range map[string]string{"signer": o.signer, "selector": o.selector} {
		if v != "" {
			if e := mdsig.ValidateValue(v); e != "" {
				return exitf(exitUsage, "%s: %s", k, e)
			}
		}
	}

	text, ok, err := readTextFile(file)
	if err != nil {
		return err
	}
	if !ok {
		return exitf(exitIO, "%s", i18n.T("revoke.no_file", file))
	}
	doc := mdsig.ParseDocument(text)

	ctx := context.Background()
	var pgpKey *pgpKeyChoice
	if isPgp {
		if pgpKey, err = loadPgpKey(ctx, so, time.Now()); err != nil {
			return err
		}
		if o.signer == "" {
			if o.signer, err = choosePgpEmail(so, pgpKey.emails); err != nil {
				return err
			}
			so.signer = o.signer
		}
	}
	if o.index < 0 || o.index > len(doc.Chain) {
		return exitf(exitUsage, "%s", i18n.T("revoke.bad_index", o.index, len(doc.Chain)))
	}

	var ids, urls []string
	var indexes []string
	var keyHints []map[string]string
	seenURL := map[string]bool{}
	for _, b := range doc.Chain {
		if o.index != 0 && b.Index != o.index {
			continue
		}
		mine := b.Fields["method"] == o.method && sameRevokeSigner(o.method, b.Fields["signer"], o.signer)
		if !mine {
			if o.index != 0 {
				return exitf(exitUsage, "%s", i18n.T("revoke.not_yours", o.index, safeText(b.Fields["method"]), safeText(b.Fields["signer"])))
			}
			continue
		}
		ids = append(ids, mdsig.RevocationID(b.Fields))
		indexes = append(indexes, fmt.Sprintf("#%d", b.Index))
		keyHints = append(keyHints, b.Fields)
		if u := b.Fields["revocation_url"]; u != "" && !seenURL[u] {
			seenURL[u] = true
			urls = append(urls, u)
		}
	}
	if len(ids) == 0 {
		return exitf(exitFail, "%s", i18n.T("revoke.none", file, o.method, o.signer))
	}

	listText, exists, err := readTextFile(o.list)
	if err != nil {
		return err
	}
	var body string
	if exists {
		body = strings.TrimRight(mdsig.ParseDocument(listText).Body, "\n \t")
	}
	if strings.TrimSpace(body) == "" {
		body = "# Revoked md-signature signatures: " + o.signer
	}
	present := map[string]bool{}
	for _, m := range revokedLine.FindAllStringSubmatch(body, -1) {
		present[m[1]] = true
	}
	added := 0
	var newLines []string
	for _, id := range ids {
		if present[id] {
			continue
		}
		present[id] = true
		newLines = append(newLines, "revoked: sha256:"+id)
		added++
	}
	if len(newLines) > 0 {
		sep := "\n"
		if !revokedLine.MatchString(body) {
			sep = "\n\n"
		}
		body += sep + strings.Join(newLines, "\n")
	}
	body += "\n"

	if isPgp {
		return signPgpRevocation(o, so, pgpKey, file, body, keyHints, indexes, urls, added)
	}
	signer, err := discoverSigner(ctx, so)
	if err != nil {
		return err
	}
	pub := signer.PublicKey()
	// SPEC 5.9: tofu lists are trusted only with the same pubkey, git-hosting/dns by method + signer
	for _, f := range keyHints {
		if o.method == "tofu" && f["pubkey"] != "ed25519:"+base64.StdEncoding.EncodeToString(pub) {
			return exitf(exitUsage, "%s", i18n.T("revoke.tofu_key_mismatch", f["pubkey"]))
		}
	}
	for _, f := range keyHints {
		if o.method == "git-hosting" && f["key_fp"] != "" && f["key_fp"] != mdsig.SSHFingerprint(pub) {
			fmt.Fprintln(stderr, "mdsig: "+i18n.T("revoke.key_mismatch", f["key_fp"]))
			break
		}
	}

	// SPEC 5.9: a revocation list must not carry its own revocation_url
	res, err := mdsig.SignDocument(ctx, body, mdsig.SignOptions{Signer: signer, Method: o.method, SignerID: o.signer, Selector: o.selector})
	if err != nil {
		var ve *mdsig.ValueError
		var se *mdsig.SignError
		switch {
		case errors.As(err, &ve):
			return exitf(exitUsage, "%s", ve.Msg)
		case errors.As(err, &se):
			return exitf(exitFail, "%s", se.Msg)
		default:
			return exitf(exitFail, "%v", err)
		}
	}
	return finishRevoke(o, file, res.Text, indexes, urls, added)
}

func signPgpRevocation(o *revokeOptions, so *signOptions, key *pgpKeyChoice, file, body string, keyHints []map[string]string, indexes, urls []string, added int) error {
	for _, f := range keyHints {
		if f["fpr"] != key.fpr {
			fmt.Fprintln(stderr, "mdsig: "+i18n.T("revoke.pgp_key_mismatch", f["fpr"]))
			break
		}
	}

	ps, dispose, err := key.signer(so)
	if err != nil {
		return err
	}
	defer dispose()
	res, err := mdsig.SignDocument(context.Background(), body, mdsig.SignOptions{PGP: ps, Method: "pgp", SignerID: o.signer})
	if err != nil {
		var ve *mdsig.ValueError
		var se *mdsig.SignError
		switch {
		case errors.As(err, &ve):
			return exitf(exitUsage, "%s", ve.Msg)
		case errors.As(err, &se):
			return exitf(exitFail, "%s", se.Msg)
		default:
			return exitf(exitFail, "%v", err)
		}
	}
	return finishRevoke(o, file, res.Text, indexes, urls, added)
}

func finishRevoke(o *revokeOptions, file, list string, indexes, urls []string, added int) error {
	if err := writeAtomic(o.list, []byte(list)); err != nil {
		return exitf(exitIO, "%v", err)
	}

	fmt.Fprintln(stderr, i18n.T("revoke.done", strings.Join(indexes, ", "), file, o.list, added))
	if len(urls) == 0 {
		fmt.Fprintln(stderr, "mdsig: "+i18n.T("revoke.no_url"))
	} else {
		fmt.Fprintln(stderr, i18n.T("revoke.publish"))
		for _, u := range urls {
			fmt.Fprintln(stderr, "  "+u)
		}
	}
	return nil
}
