package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"mdsig.dev/internal/i18n"
	"mdsig.dev/mdsig"
	"mdsig.dev/mdsig/server"
)

const defaultListen = "127.0.0.1:8787"

type serveOptions struct {
	listen                                string
	allowOrigins, tsaRoots                []string
	offline, fetchResources, noRevocation bool
	keyserver                             string
	keyDirectories                        []string

	// tests: receives the bound address, and a context that stops the server
	ready func(addr string)
	ctx   context.Context
}

func newServeCmd() *cobra.Command {
	o := &serveOptions{}
	c := &cobra.Command{
		Use:   "serve",
		Short: "Verify documents over HTTP (POST /v1/verify, POST /v1/tsa)",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, args []string) error { return runServe(o) },
	}
	f := c.Flags()
	f.StringVar(&o.listen, "listen", defaultListen, "address to listen on (host:port)")
	f.StringArrayVar(&o.allowOrigins, "allow-origin", nil, "web origin that may call the API from a browser, for example https://example.org (repeatable)")
	f.BoolVar(&o.offline, "offline", false, "do not use the network")
	f.BoolVar(&o.fetchResources, "fetch-resources", false, "fetch https:// resources and check their hashes")
	f.BoolVar(&o.noRevocation, "no-revocation", false, "do not fetch revocation lists")
	f.StringVar(&o.keyserver, "keyserver", "", "pgp only: https:// keyserver to look keys up on (default "+mdsig.DefaultKeyserver+")")
	f.StringArrayVar(&o.keyDirectories, "key-directory", nil, "directory only: also trust this https:// key directory (repeatable; see mdsig directory trust)")
	f.StringArrayVar(&o.tsaRoots, "tsa-root", nil, "also trust this root certificate when checking a timestamp token (PEM or DER file; repeatable)")
	return c
}

func validOrigin(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.Scheme+"://"+u.Host == s
}

func runServe(o *serveOptions) error {
	tsaRoots, err := mdsig.LoadTSARoots(o.tsaRoots)
	if err != nil {
		return exitf(exitUsage, "%s", i18n.T("tsa.bad_root", err))
	}
	if o.keyserver != "" && !mdsig.IsValidRevocationURL(o.keyserver) {
		return exitf(exitUsage, "%s", i18n.T("verify.bad_keyserver", o.keyserver))
	}
	keyDirs, err := trustedDirectories(o.keyDirectories)
	if err != nil {
		return err
	}
	for _, origin := range o.allowOrigins {
		if !validOrigin(origin) {
			return exitf(exitUsage, "%s", i18n.T("serve.bad_origin", origin))
		}
	}
	ln, err := net.Listen("tcp", o.listen)
	if err != nil {
		return exitf(exitIO, "%s", i18n.T("serve.listen_failed", o.listen, err))
	}
	srv := &http.Server{
		Handler: server.NewHandler(server.Options{
			Version: Version, AllowOrigins: o.allowOrigins,
			Offline: o.offline, FetchResources: o.fetchResources, NoRevocation: o.noRevocation, Keyserver: o.keyserver, KeyDirectories: keyDirs,
			TSA: mdsig.TSAVerifyOptions{ExtraRoots: tsaRoots},
		}),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      server.DefaultRequestTimeout + 10*time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	addr := ln.Addr().String()
	fmt.Fprintln(stderr, "mdsig: "+i18n.T("serve.listening", addr))
	if host, _, _ := net.SplitHostPort(addr); !net.ParseIP(host).IsLoopback() {
		fmt.Fprintln(stderr, "mdsig: "+i18n.T("serve.not_loopback"))
	}
	if o.ready != nil {
		o.ready(addr)
	}
	ctx := o.ctx
	if ctx == nil {
		var stop context.CancelFunc
		ctx, stop = signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			return exitf(exitIO, "%v", err)
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}
	return nil
}
