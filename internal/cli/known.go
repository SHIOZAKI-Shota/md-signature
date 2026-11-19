package cli

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"mdsig.dev/internal/i18n"
	"mdsig.dev/mdsig"
)

// --- mdsig known (CLI_SPEC 3.9) ---

type knownSigner struct {
	Signer      string `json:"signer"`
	Key         string `json:"key"`
	Fingerprint string `json:"fingerprint"`
}

func newKnownCmd() *cobra.Command {
	c := &cobra.Command{Use: "known", Short: "Manage stored tofu keys (SPEC 4.4)"}
	var asJSON bool
	list := &cobra.Command{
		Use: "list", Short: "Print stored signers and key fingerprints", Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error { return runKnownList(asJSON) },
	}
	list.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	remove := &cobra.Command{
		Use: "remove <signer>", Short: "Forget the stored key of a signer", Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error { return runKnownRemove(args[0]) },
	}
	c.AddCommand(list, remove)
	return c
}

func knownList() []knownSigner {
	m := readKnownSigners(knownSignersPath())
	out := make([]knownSigner, 0, len(m))
	for s, k := range m {
		out = append(out, knownSigner{Signer: s, Key: k, Fingerprint: mdsig.KeyFingerprint(k)})
	}
	slices.SortFunc(out, func(a, b knownSigner) int { return strings.Compare(a.Signer, b.Signer) })
	return out
}

func runKnownList(asJSON bool) error {
	list := knownList()
	if asJSON {
		b, _ := json.MarshalIndent(list, "", "  ")
		stdout.Write(append(b, '\n'))
		return nil
	}
	if len(list) == 0 {
		fmt.Fprintln(stderr, i18n.T("known.none"))
		return nil
	}
	for _, k := range list {
		fmt.Fprintln(stdout, safeText(k.Signer)+"  "+k.Fingerprint)
	}
	return nil
}

func runKnownRemove(signer string) error {
	path := knownSignersPath()
	if _, ok := readKnownSigners(path)[signer]; !ok {
		return exitf(exitUsage, "%s", i18n.T("known.not_found", safeText(signer)))
	}
	if err := updateKnownSigners(path, func(m map[string]string) { delete(m, signer) }); err != nil {
		return exitf(exitIO, "%v", err)
	}
	fmt.Fprintln(stderr, i18n.T("known.removed", safeText(signer)))
	return nil
}
