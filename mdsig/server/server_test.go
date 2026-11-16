package server

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mdsig.dev/mdsig"
)

func tofuDoc(t *testing.T, seedByte byte, signer string) string {
	t.Helper()
	s, err := mdsig.SignerFromSeed(bytes.Repeat([]byte{seedByte}, 32))
	if err != nil {
		t.Fatal(err)
	}
	r, err := mdsig.SignDocument(context.Background(), "# Doc\n", mdsig.SignOptions{Signer: s, Method: "tofu", SignerID: signer})
	if err != nil {
		t.Fatal(err)
	}
	return r.Text
}

func call(t *testing.T, h http.Handler, method, path, contentType, origin, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func verifyBody(doc string) string {
	b, _ := json.Marshal(map[string]string{"document": doc})
	return string(b)
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) mdsig.JSONResult {
	t.Helper()
	var out mdsig.JSONResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("%v: %s", err, rec.Body.String())
	}
	return out
}

// --- verify

func TestVerifyEndpoint(t *testing.T) {
	h := NewHandler(Options{Offline: true})
	rec := call(t, h, "POST", "/v1/verify", "application/json", "", verifyBody(tofuDoc(t, 1, "alice")))
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	out := decode(t, rec)
	if !out.OK || len(out.Signatures) != 1 || out.Signatures[0].Status != mdsig.StatusValid || out.Signatures[0].Fields["signer"] != "alice" {
		t.Fatalf("%s", rec.Body.String())
	}
	for _, key := range []string{`"ok"`, `"error"`, `"warnings"`, `"agreement"`, `"signatures"`, `"hash_ok"`, `"key_source"`, `"tsa"`} {
		if !strings.Contains(rec.Body.String(), key) {
			t.Errorf("response has no %s", key)
		}
	}

	tampered := strings.Replace(tofuDoc(t, 1, "alice"), "# Doc", "# Dog", 1)
	if out := decode(t, call(t, h, "POST", "/v1/verify", "application/json", "", verifyBody(tampered))); out.OK || out.Signatures[0].Status != mdsig.StatusInvalid {
		t.Errorf("tampered document: %+v", out)
	}
	if out := decode(t, call(t, h, "POST", "/v1/verify", "application/json; charset=utf-8", "", verifyBody("# plain\n"))); out.OK || out.Error == nil {
		t.Errorf("unsigned document: %+v", out)
	}
}

func TestVerifyKeepsNoStateBetweenRequests(t *testing.T) {
	h := NewHandler(Options{Offline: true})
	for _, seed := range []byte{1, 2} {
		out := decode(t, call(t, h, "POST", "/v1/verify", "application/json", "", verifyBody(tofuDoc(t, seed, "alice"))))
		if !out.OK {
			t.Fatalf("seed %d: a TOFU binding from an earlier request was used: %+v", seed, out.Signatures[0])
		}
	}
}

// --- request rules

func TestRequestRules(t *testing.T) {
	h := NewHandler(Options{Offline: true, AllowOrigins: []string{"https://app.example"}, MaxBodyBytes: 2048})
	doc := verifyBody(tofuDoc(t, 1, "alice"))
	cases := []struct {
		name, method, path, ct, origin, body string
		want                                 int
	}{
		{"ok without origin", "POST", "/v1/verify", "application/json", "", doc, 200},
		{"allowed origin", "POST", "/v1/verify", "application/json", "https://app.example", doc, 200},
		{"other origin", "POST", "/v1/verify", "application/json", "https://evil.example", doc, 403},
		{"null origin", "POST", "/v1/verify", "application/json", "null", doc, 403},
		{"form content type", "POST", "/v1/verify", "text/plain", "", doc, 415},
		{"no content type", "POST", "/v1/verify", "", "", doc, 415},
		{"GET verify", "GET", "/v1/verify", "", "", "", 405},
		{"POST health", "POST", "/v1/health", "application/json", "", "{}", 405},
		{"unknown path", "POST", "/v2/verify", "application/json", "", doc, 404},
		{"not JSON", "POST", "/v1/verify", "application/json", "", "document=x", 400},
		{"no document", "POST", "/v1/verify", "application/json", "", `{"doc":"x"}`, 400},
		{"too large", "POST", "/v1/verify", "application/json", "", verifyBody(strings.Repeat("a", 4096)), 413},
		{"tsa without fields", "POST", "/v1/tsa", "application/json", "", `{"tsa_token":"base64:AA=="}`, 400},
		{"tsa bad sig", "POST", "/v1/tsa", "application/json", "", `{"tsa_token":"base64:AA==","sig":"***"}`, 400},
	}
	for _, c := range cases {
		rec := call(t, h, c.method, c.path, c.ct, c.origin, c.body)
		if rec.Code != c.want {
			t.Errorf("%s: status %d, want %d (%s)", c.name, rec.Code, c.want, strings.TrimSpace(rec.Body.String()))
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); (got != "") != (c.origin == "https://app.example") {
			t.Errorf("%s: Access-Control-Allow-Origin %q", c.name, got)
		}
	}

	pre := call(t, h, "OPTIONS", "/v1/verify", "", "https://app.example", "")
	if pre.Code != 204 || pre.Header().Get("Access-Control-Allow-Origin") != "https://app.example" || !strings.Contains(pre.Header().Get("Access-Control-Allow-Headers"), "Content-Type") {
		t.Errorf("preflight: %d %v", pre.Code, pre.Header())
	}
	if rec := call(t, h, "OPTIONS", "/v1/verify", "", "https://evil.example", ""); rec.Code != 403 {
		t.Errorf("preflight from another origin: %d", rec.Code)
	}
	health := call(t, NewHandler(Options{Version: "9.9.9"}), "GET", "/v1/health", "", "", "")
	if health.Code != 200 || !strings.Contains(health.Body.String(), `"version":"9.9.9"`) || !strings.Contains(health.Body.String(), `"api":"v1"`) {
		t.Errorf("health: %d %s", health.Code, health.Body.String())
	}
}

type blockingResolver struct{ entered, release chan struct{} }

func (b blockingResolver) Resolve(ctx context.Context, _ map[string]string, _ *mdsig.ResolveOptions) (mdsig.ResolveResult, error) {
	b.entered <- struct{}{}
	<-b.release
	return mdsig.ResolveResult{}, context.Canceled
}

func TestBusy(t *testing.T) {
	br := blockingResolver{entered: make(chan struct{}), release: make(chan struct{})}
	h := NewHandler(Options{MaxConcurrent: 1, Resolvers: map[string]mdsig.Resolver{"tofu": br}})
	doc := verifyBody(tofuDoc(t, 1, "alice"))
	done := make(chan int)
	go func() { done <- call(t, h, "POST", "/v1/verify", "application/json", "", doc).Code }()
	<-br.entered
	if rec := call(t, h, "POST", "/v1/verify", "application/json", "", doc); rec.Code != 503 || rec.Header().Get("Retry-After") == "" {
		t.Errorf("second request while the first runs: %d", rec.Code)
	}
	close(br.release)
	if code := <-done; code != 200 {
		t.Errorf("first request: %d", code)
	}
}

// --- tsa

func TestTSAEndpoint(t *testing.T) {
	text, err := os.ReadFile(filepath.Join("..", "..", "examples", "valid-cosigned.md"))
	if err != nil {
		t.Fatal(err)
	}
	var token string
	var sig []byte
	for _, b := range mdsig.ParseDocument(string(text)).Chain {
		if tok := b.Fields["tsa_token"]; tok != "" {
			token = tok
			if sig, err = mdsig.DecodePrefixedBinary(mdsig.UnfoldBinary(b.Fields["sig"])); err != nil {
				t.Fatal(err)
			}
		}
	}
	if token == "" {
		t.Skip("examples were generated without a TSA")
	}
	pem, err := os.ReadFile(filepath.Join("..", "testdata", "sslcom-root-rsa.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	post := func(h http.Handler, sig []byte) mdsig.JSONTSA {
		body, _ := json.Marshal(map[string]string{"tsa_token": token, "sig": base64.StdEncoding.EncodeToString(sig)})
		rec := call(t, h, "POST", "/v1/tsa", "application/json", "", string(body))
		var out mdsig.JSONTSA
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
		return out
	}
	ok := post(NewHandler(Options{TSA: mdsig.TSAVerifyOptions{Roots: roots}}), sig)
	if ok.Status != mdsig.TSAOK || !ok.Verified || ok.GenTime == nil || ok.Signer == nil {
		t.Errorf("trusted root: %+v", ok)
	}
	if none := post(NewHandler(Options{TSA: mdsig.TSAVerifyOptions{Roots: x509.NewCertPool()}}), sig); none.Verified || none.GenTime != nil {
		t.Errorf("no roots: %+v", none)
	}
	if other := post(NewHandler(Options{TSA: mdsig.TSAVerifyOptions{Roots: roots}}), []byte("another signature")); other.Status != mdsig.TSAMismatch {
		t.Errorf("another signature: %+v", other)
	}
}
