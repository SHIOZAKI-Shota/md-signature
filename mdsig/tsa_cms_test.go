package mdsig

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// --- fixed trust anchor for the example token

func sslcomRoots(t *testing.T) *x509.CertPool {
	t.Helper()
	pem, err := os.ReadFile(filepath.Join("testdata", "sslcom-root-rsa.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("no certificate in testdata/sslcom-root-rsa.pem")
	}
	return pool
}

func exampleToken(t *testing.T) (token string, sig []byte) {
	t.Helper()
	b := ParseDocument(readExample(t, "valid-cosigned.md")).Chain[1]
	sig, err := FromBase64(UnfoldBinary(b.Fields["sig"])[7:])
	if err != nil {
		t.Fatal(err)
	}
	return UnfoldBinary(b.Fields["tsa_token"]), sig
}

func wantTSAError(t *testing.T, name string, c TSACheck, substr string) {
	t.Helper()
	if c.Status != TSAError || c.Verified || c.GenTime != "" || c.Signer != "" || !strings.Contains(c.Detail, substr) {
		t.Errorf("%s: %+v, want error containing %q", name, c, substr)
	}
}

func TestTSARealTokenVerifies(t *testing.T) {
	token, sig := exampleToken(t)
	c := CheckTSATokenWith(token, sig, &TSAVerifyOptions{Roots: sslcomRoots(t)})
	if c.Status != TSAOk || !c.Verified || c.Signer != "SSL.com Timestamping Unit 2026 E1" || !TSRe.MatchString(c.GenTime) {
		t.Fatalf("%+v", c)
	}
	if c.Detail != "imprint matched; TSA signature verified (SSL.com Timestamping Unit 2026 E1)" {
		t.Errorf("detail = %q", c.Detail)
	}
}

func TestTSARealTokenRejected(t *testing.T) {
	token, sig := exampleToken(t)
	roots := &TSAVerifyOptions{Roots: sslcomRoots(t)}
	wantTSAError(t, "empty pool", CheckTSATokenWith(token, sig, &TSAVerifyOptions{Roots: x509.NewCertPool()}), "does not chain to a trusted root")

	other := append([]byte{}, sig...)
	other[0] ^= 1
	if c := CheckTSATokenWith(token, other, roots); c.Status != TSAMismatch || c.GenTime != "" || c.Verified {
		t.Errorf("other imprint: %+v", c)
	}

	raw, err := DecodePrefixedBinary(token)
	if err != nil {
		t.Fatal(err)
	}
	info, err := ParseTimeStampResp(raw)
	if err != nil {
		t.Fatal(err)
	}
	at := bytes.Index(raw, info.eContent)
	serial, _ := FromHex(info.Serial)
	inSerial := at + bytes.Index(info.eContent, serial) + len(serial) - 1
	mutate := func(i int) string {
		b := append([]byte{}, raw...)
		b[i] ^= 0x01
		return "base64:" + ToBase64(b)
	}
	wantTSAError(t, "eContent byte", CheckTSATokenWith(mutate(inSerial), sig, roots), "message-digest does not match")
	wantTSAError(t, "signature byte", CheckTSATokenWith(mutate(len(raw)-1), sig, roots), "signature does not verify")
}

// --- a TSA built in the test

type testTSA struct {
	caCert, cert *x509.Certificate
	key          crypto.Signer
	roots        *x509.CertPool
}

func newTestTSA(t *testing.T, eku []x509.ExtKeyUsage, useRSA bool) *testTSA {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test TSA Root"},
		NotBefore: notBefore, NotAfter: notBefore.AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	var key crypto.Signer
	if useRSA {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test TSA Unit", Organization: []string{"Test Org"}},
		NotBefore: notBefore, NotAfter: notBefore.AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: eku,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, key.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	return &testTSA{caCert: caCert, cert: cert, key: key, roots: roots}
}

type tokenSpec struct {
	digestOID     asn1.ObjectIdentifier
	pss           bool
	noSigningCert bool
	wrongESSHash  bool
	twoSigners    bool
	nonce         []byte
	genTime       string
	status        int
}

func tlv(tag byte, parts ...[]byte) []byte {
	body := bytes.Join(parts, nil)
	return append(derHeader(tag, len(body)), body...)
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (ts *testTSA) response(t *testing.T, imprint []byte, spec tokenSpec) []byte {
	t.Helper()
	if spec.digestOID == nil {
		spec.digestOID = oidSHA256
	}
	if spec.genTime == "" {
		spec.genTime = "20260601120000Z"
	}
	null := []byte{0x05, 0x00}
	tstParts := [][]byte{
		tlv(0x02, []byte{1}),
		mustMarshal(t, asn1.ObjectIdentifier{1, 2, 3, 4}),
		tlv(0x30, tlv(0x30, mustMarshal(t, oidSHA256), null), tlv(0x04, imprint)),
		tlv(0x02, []byte{0x5a, 0x17}),
		tlv(0x18, []byte(spec.genTime)),
	}
	if spec.nonce != nil {
		tstParts = append(tstParts, mustMarshal(t, new(big.Int).SetBytes(spec.nonce)))
	}
	tst := tlv(0x30, tstParts...)
	digest := sha256.Sum256(tst)

	attr := func(oid asn1.ObjectIdentifier, value []byte) []byte {
		return tlv(0x30, mustMarshal(t, oid), tlv(0x31, value))
	}
	attrs := [][]byte{
		attr(oidAttrContentType, mustMarshal(t, oidTSTInfo)),
		attr(oidAttrMessageDgst, tlv(0x04, digest[:])),
	}
	if !spec.noSigningCert {
		certHash := sha256.Sum256(ts.cert.Raw)
		if spec.wrongESSHash {
			certHash[0] ^= 1
		}
		attrs = append(attrs, attr(oidAttrSigningCert2, tlv(0x30, tlv(0x30, tlv(0x30, tlv(0x04, certHash[:]))))))
	}
	slices.SortFunc(attrs, bytes.Compare)
	toSign := sha256.Sum256(tlv(0x31, attrs...))

	var sigAlg, sig []byte
	var err error
	switch k := ts.key.(type) {
	case *rsa.PrivateKey:
		if spec.pss {
			sig, err = rsa.SignPSS(rand.Reader, k, crypto.SHA256, toSign[:], &rsa.PSSOptions{SaltLength: 32})
			sha := pkix.AlgorithmIdentifier{Algorithm: oidSHA256}
			params := mustMarshal(t, rsaPSSParams{
				Hash:       sha,
				MGF:        pkix.AlgorithmIdentifier{Algorithm: oidMGF1, Parameters: asn1.RawValue{FullBytes: mustMarshal(t, sha)}},
				SaltLength: 32,
			})
			sigAlg = tlv(0x30, mustMarshal(t, oidRSAPSS), params)
		} else {
			sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, toSign[:])
			sigAlg = tlv(0x30, mustMarshal(t, oidRSAEncryption), null)
		}
	default:
		sig, err = ts.key.Sign(rand.Reader, toSign[:], crypto.SHA256)
		sigAlg = tlv(0x30, mustMarshal(t, oidECDSAWithSHA256))
	}
	if err != nil {
		t.Fatal(err)
	}
	digestAlg := tlv(0x30, mustMarshal(t, spec.digestOID))
	signerInfo := tlv(0x30,
		tlv(0x02, []byte{1}),
		tlv(0x30, ts.cert.RawIssuer, mustMarshal(t, ts.cert.SerialNumber)),
		digestAlg,
		tlv(0xa0, attrs...),
		sigAlg,
		tlv(0x04, sig),
	)
	signerInfos := [][]byte{signerInfo}
	if spec.twoSigners {
		signerInfos = append(signerInfos, signerInfo)
	}
	signedData := tlv(0x30,
		tlv(0x02, []byte{3}),
		tlv(0x31, digestAlg),
		tlv(0x30, mustMarshal(t, oidTSTInfo), tlv(0xa0, tlv(0x04, tst))),
		tlv(0xa0, ts.cert.Raw),
		tlv(0x31, signerInfos...),
	)
	token := tlv(0x30, mustMarshal(t, oidSignedData), tlv(0xa0, signedData))
	return tlv(0x30, tlv(0x30, tlv(0x02, []byte{byte(spec.status)})), token)
}

func (ts *testTSA) check(t *testing.T, sig []byte, spec tokenSpec, o *TSAVerifyOptions) TSACheck {
	t.Helper()
	sum := sha256.Sum256(sig)
	return CheckTSATokenWith("base64:"+ToBase64(ts.response(t, sum[:], spec)), sig, o)
}

var timeStamping = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}

func TestTSASyntheticTokens(t *testing.T) {
	sig := bytes.Repeat([]byte{7}, 64)
	ec := newTestTSA(t, timeStamping, false)
	trusted := &TSAVerifyOptions{Roots: ec.roots}

	ok := ec.check(t, sig, tokenSpec{}, trusted)
	if ok.Status != TSAOk || !ok.Verified || ok.Signer != "Test TSA Unit" || ok.GenTime != "2026-06-01T12:00:00Z" {
		t.Fatalf("ecdsa: %+v", ok)
	}

	wantTSAError(t, "own CA not in the pool", ec.check(t, sig, tokenSpec{}, &TSAVerifyOptions{Roots: sslcomRoots(t)}), "does not chain to a trusted root")
	wantTSAError(t, "SHA-1 digest", ec.check(t, sig, tokenSpec{digestOID: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}}, trusted), "digest algorithm 1.3.14.3.2.26 is not")
	wantTSAError(t, "MD5 digest", ec.check(t, sig, tokenSpec{digestOID: asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}}, trusted), "digest algorithm")
	wantTSAError(t, "no signing-certificate", ec.check(t, sig, tokenSpec{noSigningCert: true}, trusted), "no signing-certificate attribute")
	wantTSAError(t, "wrong ESSCertIDv2", ec.check(t, sig, tokenSpec{wrongESSHash: true}, trusted), "does not match the TSA certificate")
	wantTSAError(t, "two SignerInfos", ec.check(t, sig, tokenSpec{twoSigners: true}, trusted), "want exactly 1")
	wantTSAError(t, "certificate not yet valid at genTime", ec.check(t, sig, tokenSpec{genTime: "20250601120000Z"}, trusted), "was not valid at the token's time")
	wantTSAError(t, "certificate expired at genTime", ec.check(t, sig, tokenSpec{genTime: "20280601120000Z"}, trusted), "was not valid at the token's time")
	wantTSAError(t, "status rejection", ec.check(t, sig, tokenSpec{status: 2}, trusted), "not granted")

	skip := ec.check(t, sig, tokenSpec{}, &TSAVerifyOptions{Roots: x509.NewCertPool(), skipChain: true})
	if skip.Status != TSAOk || !skip.Verified {
		t.Errorf("skipChain: %+v", skip)
	}

	for name, eku := range map[string][]x509.ExtKeyUsage{"no EKU": nil, "serverAuth EKU": {x509.ExtKeyUsageServerAuth}} {
		bad := newTestTSA(t, eku, false)
		wantTSAError(t, name, bad.check(t, sig, tokenSpec{}, &TSAVerifyOptions{Roots: bad.roots}), "lacks the timeStamping extended key usage")
	}

	rs := newTestTSA(t, timeStamping, true)
	for name, spec := range map[string]tokenSpec{"rsa pkcs1": {}, "rsa pss": {pss: true}} {
		if c := rs.check(t, sig, spec, &TSAVerifyOptions{Roots: rs.roots}); c.Status != TSAOk || !c.Verified {
			t.Errorf("%s: %+v", name, c)
		}
	}
}

func TestTSASyntheticTamper(t *testing.T) {
	sig := bytes.Repeat([]byte{7}, 64)
	ts := newTestTSA(t, timeStamping, false)
	trusted := &TSAVerifyOptions{Roots: ts.roots}
	sum := sha256.Sum256(sig)
	resp := ts.response(t, sum[:], tokenSpec{})
	flip := func(i int) TSACheck {
		b := append([]byte{}, resp...)
		b[i] ^= 0x01
		return CheckTSATokenWith("base64:"+ToBase64(b), sig, trusted)
	}
	wantTSAError(t, "genTime digit", flip(bytes.Index(resp, []byte("20260601120000Z"))+13), "message-digest does not match")
	wantTSAError(t, "signature", flip(len(resp)-1), "")
	other := newTestTSA(t, timeStamping, false)
	wantTSAError(t, "signed by another TSA with the same names", CheckTSATokenWith("base64:"+ToBase64(other.response(t, sum[:], tokenSpec{})), sig, trusted), "does not chain to a trusted root")
}

// --- generator

func tsaServer(t *testing.T, ts *testTSA, nonceOf func(sent []byte) []byte) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req timeStampReq
		if _, err := asn1.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		w.Write(ts.response(t, req.MessageImprint.HashedMessage, tokenSpec{nonce: nonceOf(req.Nonce.Bytes())}))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRequestTimestampVerifiesResponse(t *testing.T) {
	sig := bytes.Repeat([]byte{9}, 64)
	ts := newTestTSA(t, timeStamping, false)
	trusted := &TSAVerifyOptions{Roots: ts.roots}
	ctx := context.Background()
	echo := func(sent []byte) []byte { return sent }

	tok, err := RequestTimestampWith(ctx, sig, tsaServer(t, ts, echo).URL, nil, trusted)
	if err != nil {
		t.Fatal(err)
	}
	if c := CheckTSATokenWith(tok, sig, trusted); c.Status != TSAOk || !c.Verified {
		t.Fatalf("round trip: %+v", c)
	}

	cases := map[string]struct {
		nonce func([]byte) []byte
		opts  *TSAVerifyOptions
		want  string
	}{
		"untrusted TSA": {echo, &TSAVerifyOptions{Roots: x509.NewCertPool()}, "does not chain to a trusted root"},
		"other nonce":   {func(sent []byte) []byte { return append([]byte{1}, sent...) }, trusted, "nonce does not match"},
		"no nonce":      {func([]byte) []byte { return nil }, trusted, "nonce does not match"},
	}
	for name, c := range cases {
		if _, err := RequestTimestampWith(ctx, sig, tsaServer(t, ts, c.nonce).URL, nil, c.opts); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestTSAExtraRoots(t *testing.T) {
	sig := bytes.Repeat([]byte{7}, 64)
	ec := newTestTSA(t, timeStamping, false)
	other := newTestTSA(t, timeStamping, false)

	added := ec.check(t, sig, tokenSpec{}, &TSAVerifyOptions{Roots: other.roots, ExtraRoots: []*x509.Certificate{ec.caCert}})
	if added.Status != TSAOk || !added.Verified {
		t.Fatalf("extra root not used: %+v", added)
	}
	wantTSAError(t, "caller's pool unchanged", ec.check(t, sig, tokenSpec{}, &TSAVerifyOptions{Roots: other.roots}), "does not chain to a trusted root")
	wantTSAError(t, "unrelated extra root", ec.check(t, sig, tokenSpec{}, &TSAVerifyOptions{Roots: x509.NewCertPool(), ExtraRoots: []*x509.Certificate{other.caCert}}), "does not chain to a trusted root")

	old := tsaDefaultRoots
	tsaDefaultRoots = func() (*x509.CertPool, error) { return x509.NewCertPool(), nil }
	defer func() { tsaDefaultRoots = old }()
	if c := ec.check(t, sig, tokenSpec{}, &TSAVerifyOptions{ExtraRoots: []*x509.Certificate{ec.caCert}}); !c.Verified {
		t.Errorf("extra root on top of the system pool: %+v", c)
	}
}

func TestLoadTSARoots(t *testing.T) {
	a := newTestTSA(t, timeStamping, false)
	b := newTestTSA(t, timeStamping, false)
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	pemOf := func(c *x509.Certificate) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	bundle := write("bundle.pem", append(pemOf(a.caCert), pemOf(b.caCert)...))
	der := write("root.der", a.caCert.Raw)

	got, err := LoadTSARoots([]string{bundle, der})
	if err != nil || len(got) != 3 || !got[1].Equal(b.caCert) || !got[2].Equal(a.caCert) {
		t.Fatalf("got %d certificates, err %v", len(got), err)
	}
	for name, p := range map[string]string{
		"text":    write("junk.pem", []byte("hello")),
		"key":     write("key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})),
		"missing": filepath.Join(dir, "nope.pem"),
		"large":   write("large.der", make([]byte, maxTSARootFileBytes+1)),
	} {
		if _, err := LoadTSARoots([]string{p}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
