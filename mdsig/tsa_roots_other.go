//go:build !darwin

package mdsig

import "crypto/x509"

// --- TSA trust anchors

func tsaSystemRoots() (*x509.CertPool, error) { return x509.SystemCertPool() }
