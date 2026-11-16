package mdsig

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"os/exec"
	"sync"
	"time"
)

// --- TSA trust anchors (macOS)

const appleRootKeychain = "/System/Library/Keychains/SystemRootCertificates.keychain"

// Go verifies the system pool through Security.framework with the TLS server policy, which rejects every TSA certificate; the roots are read into an ordinary pool instead
var tsaSystemRoots = sync.OnceValues(func() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if f := os.Getenv("SSL_CERT_FILE"); f != "" {
		pem, err := os.ReadFile(f)
		if err != nil || !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("SSL_CERT_FILE has no usable certificates")
		}
		return pool, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pem, err := exec.CommandContext(ctx, "/usr/bin/security", "find-certificate", "-a", "-p", appleRootKeychain).Output()
	if err != nil || !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("could not read the macOS root certificates")
	}
	return pool, nil
})
