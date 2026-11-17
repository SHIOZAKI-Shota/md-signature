package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"mdsig.dev/internal/i18n"
	"mdsig.dev/mdsig"
)

type timestampOptions struct {
	tsa      string
	hash     string
	reason   string
	tsaRoots []string
	toStdout bool
}

func newTimestampCmd() *cobra.Command {
	o := &timestampOptions{}
	c := &cobra.Command{
		Use:   "timestamp <file>",
		Short: "Append a timestamp block over the whole file, earlier timestamps included (SPEC 4.6)",
		Args:  cobra.ExactArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error { return runTimestamp(o, args[0]) },
	}
	f := c.Flags()
	f.StringVar(&o.tsa, "tsa", mdsig.DefaultTSAURL, "URL of the RFC 3161 time-stamping authority")
	f.StringVar(&o.hash, "hash", "sha256", "imprint and block hash: sha256, or sha512 for a renewal that must outlive SHA-256")
	f.StringVar(&o.reason, "reason", "", "free-text reason")
	f.StringArrayVar(&o.tsaRoots, "tsa-root", nil, "also trust this root certificate when checking the TSA's response (PEM or DER file; repeatable)")
	f.BoolVar(&o.toStdout, "stdout", false, "write the result to stdout instead of changing the file")
	return c
}

func runTimestamp(o *timestampOptions, file string) error {
	if o.hash != "sha256" && o.hash != "sha512" {
		return exitf(exitUsage, "%s", i18n.T("timestamp.bad_hash", o.hash))
	}
	roots, err := mdsig.LoadTSARoots(o.tsaRoots)
	if err != nil {
		return exitf(exitUsage, "%s", i18n.T("tsa.bad_root", err))
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return exitf(exitIO, "%v", err)
	}
	res, err := mdsig.TimestampDocument(context.Background(), string(data), mdsig.TimestampOptions{
		TSAURL: o.tsa, Hash: o.hash, Reason: o.reason, TSA: mdsig.TSAVerifyOptions{ExtraRoots: roots},
		HTTPClient: httpClientWithTimeout(30 * time.Second),
	})
	if err != nil {
		var ve *mdsig.ValueError
		var se *mdsig.SignError
		switch {
		case errors.As(err, &ve):
			return exitf(exitUsage, "%s", ve.Msg)
		case errors.As(err, &se):
			return exitf(exitFail, "%s", se.Msg)
		default:
			return exitf(exitNetwork, "%v", err)
		}
	}
	if o.toStdout {
		if _, err := fmt.Fprint(stdout, res.Text); err != nil {
			return exitf(exitIO, "%v", err)
		}
	} else if err := writeAtomic(file, []byte(res.Text)); err != nil {
		return exitf(exitIO, "%v", err)
	}
	fmt.Fprintln(stderr, i18n.T("timestamp.done", file, res.Previous+1, o.tsa))
	return nil
}
