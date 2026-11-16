package mdsig

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	seedA  = aliceSeed
	seedB  = exampleComSeed
	fTS    = "2026-11-16T09:00:00Z"
	fDoc   = "# Contract\n\nThe parties agree.\n"
	revURL = "https://example.com/.well-known/mdsig-revoked.md"
)

func fixedKeys(m map[string][]byte, alg string) Resolver {
	return ResolverFunc(func(_ context.Context, f map[string]string, _ *ResolveOptions) (ResolveResult, error) {
		k, ok := m[f["signer"]]
		if !ok {
			return ResolveResult{}, errors.New("unknown")
		}
		return ResolveResult{Keys: []CandidateKey{{Alg: alg, Key: k, Source: "test"}}}, nil
	})
}

func mustSign(t *testing.T, text string, o SignOptions) *SignResult {
	t.Helper()
	r, err := SignDocument(context.Background(), text, o)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func verify(text string, o *VerifyOptions) *VerifyResult {
	return VerifyDocument(context.Background(), text, o)
}

func dump(v *VerifyResult) string {
	b, _ := json.MarshalIndent(v, "", " ")
	return string(b)
}

// --- unknown fields ---

func TestUnknownFieldsAndExtensions(t *testing.T) {
	a := mustSigner(t, seedA)
	s := mustSign(t, fDoc, SignOptions{Signer: a, Method: "tofu", SignerID: "a", TS: fTS, Extra: map[string]string{"x_ref": "PO-1"}})
	if !verify(s.Text, nil).OK {
		t.Fatal("x_ field should verify")
	}
	unknown := strings.Replace(s.Text, "x_ref: PO-1", "x_ref: PO-1\npriority: high", 1)
	v := verify(unknown, nil)
	if v.Signatures[0].Status != StatusMalformed || v.Signatures[0].Code != "unknown-field" {
		t.Fatalf("%+v", v.Signatures[0])
	}
	if v := verify(strings.Replace(s.Text, "x_ref: PO-1", "x_ref: PO-2", 1), nil); v.Signatures[0].Code != "bad-signature" {
		t.Fatalf("%+v", v.Signatures[0])
	}
	_, err := SignDocument(context.Background(), fDoc, SignOptions{Signer: a, Method: "tofu", SignerID: "a", Extra: map[string]string{"ref": "x"}})
	if err == nil || !strings.Contains(err.Error(), `must start with "x_"`) {
		t.Fatal(err)
	}
}

func TestPayloadEscapesLF(t *testing.T) {
	p := string(SignedPayload(map[string]string{"require": "dns:a.com\ndns:b.com", "v": "0.0.1"}))
	if p != "md-signature/v1\nrequire=dns:a.com\n  dns:b.com\nv=0.0.1" {
		t.Fatalf("%q", p)
	}
	q := string(SignedPayload(map[string]string{"require": "dns:a.com\nv=9"}))
	if !strings.Contains(q, "\n  v=9") {
		t.Fatalf("%q", q)
	}
	if strings.Contains(string(SignedPayload(map[string]string{"webauthn_client_data": "x", "webauthn_authenticator_data": "y", "v": "1"})), "webauthn") {
		t.Fatal("webauthn fields must not be in the payload")
	}
}

func TestFoldedValuesJoinWithLF(t *testing.T) {
	f, errs, _ := ParseFields([]string{"require: |", "  dns:a.com", "  dns:b.com  ", "v: 0.0.1"})
	if f["require"] != "dns:a.com\ndns:b.com" {
		t.Fatalf("%q %v", f["require"], errs)
	}
	_, errs, _ = ParseFields([]string{"reason: |", "  a--b"})
	if !strings.Contains(strings.Join(errs, ";"), `"--"`) {
		t.Fatal(errs)
	}
}

// --- resources ---

type fetchStub struct {
	calls int
	fn    func(r *http.Request) (int, []byte, error)
}

func (s *fetchStub) client() *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		s.calls++
		st, body, err := s.fn(r)
		if err != nil {
			return nil, err
		}
		return respond(r, st, body), nil
	})}
}

func staticFetch(status int, body []byte) *fetchStub {
	return &fetchStub{fn: func(*http.Request) (int, []byte, error) { return status, body, nil }}
}

func TestResources(t *testing.T) {
	a := mustSigner(t, seedA)
	png := []byte("PNG-BYTES")
	remote := []byte("REMOTE-CHART")
	s := mustSign(t, fDoc, SignOptions{Signer: a, Method: "tofu", SignerID: "a", TS: fTS,
		Resources: []ResourceItem{{Ref: "./diagram.png", Bytes: png}, {Ref: "https://example.com/chart.png", Bytes: remote}}})
	if !regexp.MustCompile(`resources: \|\n {2}sha256:[0-9a-f]{64} \./diagram\.png\n {2}sha256:[0-9a-f]{64} https://example\.com/chart\.png`).MatchString(s.Block) {
		t.Fatal(s.Block)
	}
	files := map[string][]byte{"./diagram.png": png}
	load := func(ref string) ([]byte, error) { return files[ref], nil }
	stub := staticFetch(200, remote)
	opts := func(fetch bool, c *http.Client) *VerifyOptions {
		return &VerifyOptions{ResourceCheckOptions: ResourceCheckOptions{LoadResource: load, FetchResources: fetch, FetchClient: c}}
	}
	statuses := func(v *VerifyResult) []string {
		var out []string
		for _, r := range v.Signatures[0].Resources {
			out = append(out, r.Status)
		}
		return out
	}

	v1 := verify(s.Text, opts(false, stub.client()))
	if !v1.OK || !reflect.DeepEqual(statuses(v1), []string{"ok", "not-checked"}) || stub.calls != 0 {
		t.Fatalf("default: %v calls=%d %s", statuses(v1), stub.calls, dump(v1))
	}
	v2 := verify(s.Text, opts(true, stub.client()))
	if !reflect.DeepEqual(statuses(v2), []string{"ok", "ok"}) || stub.calls != 1 {
		t.Fatalf("fetch: %v", statuses(v2))
	}
	files["./diagram.png"] = []byte("EVIL")
	if c := verify(s.Text, opts(false, nil)).Signatures[0].Code; c != "resource-mismatch" {
		t.Fatal(c)
	}
	delete(files, "./diagram.png")
	if c := verify(s.Text, opts(false, nil)).Signatures[0].Code; c != "resource-missing" {
		t.Fatal(c)
	}
	files["./diagram.png"] = png
	if c := verify(s.Text, opts(true, staticFetch(200, []byte("CHANGED")).client())).Signatures[0].Code; c != "resource-mismatch" {
		t.Fatal(c)
	}
	if st := verify(s.Text, opts(true, staticFetch(404, nil).client())).Signatures[0]; st.Status != StatusUnresolved || st.Code != "network" {
		t.Fatalf("%+v", st)
	}
	if v := verify(s.Text, &VerifyOptions{}); !v.OK || v.Signatures[0].Resources[0].Status != ResourceNotChecked {
		t.Fatal(dump(v))
	}
	for _, ref := range []string{"/etc/passwd", "../secret.png", "C:/x.png", "http://example.com/a.png", `a\b.png`, "a/../../b"} {
		_, err := SignDocument(context.Background(), fDoc, SignOptions{Signer: a, Method: "tofu", SignerID: "a", Resources: []ResourceItem{{Ref: ref, Bytes: png}}})
		if err == nil || !strings.Contains(err.Error(), "resources") {
			t.Errorf("%s: %v", ref, err)
		}
	}
}

func TestResourcesOverTLS(t *testing.T) {
	body := []byte("CHART-BYTES")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/chart.png":
			_, _ = w.Write(body)
		case "/big":
			_, _ = w.Write(make([]byte, 2048))
		case "/redirect-http":
			http.Redirect(w, r, "http://example.com/x", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	a := mustSigner(t, seedA)
	s := mustSign(t, fDoc, SignOptions{Signer: a, Method: "tofu", SignerID: "a", TS: fTS,
		Resources: []ResourceItem{{Ref: srv.URL + "/chart.png", Bytes: body}}})
	ok := verify(s.Text, &VerifyOptions{ResourceCheckOptions: ResourceCheckOptions{FetchResources: true, FetchClient: srv.Client()}})
	if !ok.OK || ok.Signatures[0].Resources[0].Status != ResourceOK {
		t.Fatal(dump(ok))
	}
	ref := verify(s.Text, &VerifyOptions{ResourceCheckOptions: ResourceCheckOptions{FetchResources: true}})
	r0 := ref.Signatures[0]
	if r0.Status != StatusUnresolved || r0.Resources[0].Status != ResourceUnreachable || !strings.Contains(r0.Resources[0].Detail, "refusing") {
		t.Fatal(dump(ref))
	}
	if _, err := FetchResource(context.Background(), srv.Client(), srv.URL+"/big", 1024); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatal(err)
	}
	if _, err := FetchResource(context.Background(), SafeHTTPClient(5*time.Second), srv.URL+"/chart.png", 0); !errors.Is(err, ErrForbiddenAddress) {
		t.Fatal(err)
	}
	if _, err := FetchResource(context.Background(), nil, "http://example.com/a", 0); err == nil {
		t.Fatal("http must be refused")
	}
	c := SafeHTTPClient(5 * time.Second)
	c.Transport = srv.Client().Transport // bypass the dial check to test the redirect policy only
	if _, err := FetchResource(context.Background(), c, srv.URL+"/redirect-http", 0); err == nil || !strings.Contains(err.Error(), "non-https") {
		t.Fatal(err)
	}
}

func TestForbiddenIPs(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "0.0.0.0", "100.64.0.1"} {
		if err := safeDialControl("tcp", s+":443", nil); err == nil && !strings.Contains(s, ":") {
			t.Errorf("%s allowed", s)
		}
	}
	for _, s := range []string{"[::1]:443", "[fe80::1]:443", "[::ffff:10.0.0.1]:443"} {
		if err := safeDialControl("tcp", s, nil); err == nil {
			t.Errorf("%s allowed", s)
		}
	}
	for _, s := range []string{"93.184.216.34:443", "[2606:2800:220:1::1]:443"} {
		if err := safeDialControl("tcp", s, nil); err != nil {
			t.Errorf("%s refused: %v", s, err)
		}
	}
}

func TestFindLocalImages(t *testing.T) {
	md := "![a](./a.png)\n<img src=\"img/b.jpg\">\n![r](https://x.com/r.png)\n```\n![c](./c.png)\n```\n![d](../d.png)\n"
	if got := FindLocalImages(md); !reflect.DeepEqual(got, []string{"./a.png", "img/b.jpg"}) {
		t.Fatal(got)
	}
	if got := FindLocalImages("![t](<x y.png> \"title\") ![u](./u.png \"T\") ![a](./a.png) <IMG SRC='i.gif'> ![h](#frag) ![m](mailto:x)"); !reflect.DeepEqual(got, []string{"./u.png", "./a.png", "i.gif"}) {
		t.Fatal(got)
	}
}

// --- require ---

func TestRequire(t *testing.T) {
	a := mustSigner(t, seedA)
	b := mustSigner(t, seedB)
	o := &VerifyOptions{Resolvers: map[string]Resolver{"dns": fixedKeys(map[string][]byte{"example.com": b.PublicKey()}, "ed25519")}}
	s1 := mustSign(t, fDoc, SignOptions{Signer: a, Method: "tofu", SignerID: "alice", Role: "author", TS: fTS,
		Require: []string{"dns:example.com approver", Requirement{Method: "tofu", Signer: "carol"}.String()}})
	v1 := verify(s1.Text, o)
	if !v1.OK || v1.Agreement.Status != AgreementPending || len(v1.Agreement.Missing) != 2 {
		t.Fatal(dump(v1))
	}
	s2bad := mustSign(t, s1.Text, SignOptions{Signer: b, Method: "dns", SignerID: "Example.com", Role: "witness", TS: fTS})
	if n := len(verify(s2bad.Text, o).Agreement.Missing); n != 2 {
		t.Fatalf("wrong role satisfied a requirement: %d", n)
	}
	s2 := mustSign(t, s1.Text, SignOptions{Signer: b, Method: "dns", SignerID: "Example.com", Role: "approver", TS: fTS})
	if n := len(verify(s2.Text, o).Agreement.Missing); n != 1 {
		t.Fatal(n)
	}
	c, _ := SignerFromSeed(bytesOf(32, 3))
	s3 := mustSign(t, s2.Text, SignOptions{Signer: c, Method: "tofu", SignerID: "carol", TS: fTS})
	if st := verify(s3.Text, o).Agreement.Status; st != AgreementComplete {
		t.Fatal(st)
	}
	broken := strings.Replace(s3.Text, "signer: carol", "signer: carol\nx_t: 1", 1)
	if v := verify(broken, o); v.OK || v.Agreement.Status != AgreementPending {
		t.Fatal(dump(v))
	}
	if st := verify(mustSign(t, fDoc, SignOptions{Signer: a, Method: "tofu", SignerID: "x", TS: fTS}).Text, nil).Agreement.Status; st != AgreementNone {
		t.Fatal(st)
	}
	if _, err := SignDocument(context.Background(), fDoc, SignOptions{Signer: a, Method: "tofu", SignerID: "x", Require: []string{"not a requirement"}}); err == nil || !strings.Contains(err.Error(), "require") {
		t.Fatal(err)
	}
}

func bytesOf(n int, v byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = v
	}
	return b
}

func TestExpires(t *testing.T) {
	a := mustSigner(t, seedA)
	s := mustSign(t, fDoc, SignOptions{Signer: a, Method: "tofu", SignerID: "a", TS: fTS, Expires: "2027-01-01T00:00:00Z"})
	at := func(ts string) *VerifyResult {
		now, _ := time.Parse(time.RFC3339, ts)
		return verify(s.Text, &VerifyOptions{Now: now})
	}
	if !at("2026-12-31T23:59:59Z").OK || !at("2027-01-01T00:00:00Z").OK {
		t.Fatal("not yet expired")
	}
	if c := at("2027-01-01T00:00:01Z").Signatures[0].Code; c != "expired" {
		t.Fatal(c)
	}
	if _, err := SignDocument(context.Background(), fDoc, SignOptions{Signer: a, Method: "tofu", SignerID: "a", Expires: "tomorrow"}); err == nil || !strings.Contains(err.Error(), "expires") {
		t.Fatal(err)
	}
	for _, good := range []string{"2026-02-28T23:59:59Z", "2028-02-29T00:00:00Z", "0000-01-01T00:00:00Z"} {
		if !IsValidTimestamp(good) {
			t.Error(good)
		}
	}
	for _, bad := range []string{"2026-02-30T00:00:00Z", "2026-02-32T00:00:00Z", "2026-13-01T00:00:00Z", "2026-11-16T24:00:00Z", "2026-01-01T23:59:60Z", "2026-00-01T00:00:00Z", "2026-1-01T00:00:00Z"} {
		if IsValidTimestamp(bad) {
			t.Error(bad)
		}
	}
}

func TestHardening(t *testing.T) {
	auth := newSoftAuth(t, rp, "", 0x05)
	wa := mustSign(t, fDoc, SignOptions{WebAuthn: auth, Method: "tofu", SignerID: "x", TS: fTS})
	cdLine := regexp.MustCompile(`webauthn_client_data: (\|\n(  .*\n)+|.*\n)`)
	for _, v := range []string{"bnVsbA==", "WzFd", "MQ=="} {
		r := verify(cdLine.ReplaceAllString(wa.Text, "webauthn_client_data: "+v+"\n"), nil).Signatures[0]
		if r.Status != StatusMalformed || r.Code != "malformed" || r.Message != "clientDataJSON is not a JSON object" {
			t.Errorf("%s: %+v", v, r)
		}
	}

	a := mustSigner(t, seedA)
	s := mustSign(t, fDoc, SignOptions{Signer: a, Method: "tofu", SignerID: "a", TS: fTS, Resources: []ResourceItem{{Ref: "./x.png", Bytes: []byte("x")}}})
	v := verify(s.Text, &VerifyOptions{ResourceCheckOptions: ResourceCheckOptions{LoadResource: func(string) ([]byte, error) { return nil, errors.New("EACCES") }}})
	if v.Signatures[0].Code != "resource-missing" || v.Signatures[0].Resources[0].Detail != "could not be read: EACCES" {
		t.Fatal(dump(v))
	}

	for _, bad := range []string{"2026-02-30T00:00:00Z", "2026-11-16T24:00:00Z", "2026-13-01T00:00:00Z"} {
		if _, err := SignDocument(context.Background(), fDoc, SignOptions{Signer: a, Method: "tofu", SignerID: "a", Expires: bad}); err == nil || !strings.Contains(err.Error(), "expires") {
			t.Errorf("%s: %v", bad, err)
		}
		ok := mustSign(t, fDoc, SignOptions{Signer: a, Method: "tofu", SignerID: "a", TS: fTS, Expires: "2030-01-01T00:00:00Z"})
		r := verify(strings.Replace(ok.Text, "expires: 2030-01-01T00:00:00Z", "expires: "+bad, 1), nil).Signatures[0]
		if r.Status != StatusMalformed || !strings.Contains(r.Message, "is not a valid YYYY-MM-DDTHH:MM:SSZ date-time") {
			t.Errorf("%s: %+v", bad, r)
		}
	}

	req := mustSign(t, fDoc, SignOptions{Signer: a, Method: "dns", SignerID: "example.com", TS: fTS, Require: []string{"tofu:bob"}})
	off := verify(req.Text, &VerifyOptions{ResolveOptions: ResolveOptions{Offline: true}})
	if off.Signatures[0].Status != StatusUnresolved || off.Agreement.Status != AgreementPending {
		t.Fatal(dump(off))
	}
	b := mustSigner(t, seedB)
	declared := mustSign(t, fDoc, SignOptions{Signer: a, Method: "tofu", SignerID: "a", TS: fTS, Require: []string{"dns:example.com"}})
	cos := mustSign(t, declared.Text, SignOptions{Signer: b, Method: "dns", SignerID: "example.com", TS: fTS})
	if v := verify(cos.Text, &VerifyOptions{ResolveOptions: ResolveOptions{Offline: true}}); v.Agreement.Status != AgreementPending {
		t.Fatal(dump(v))
	}

	if !SameSigner("dns", "Example.COM.", "example.com") || SameSigner("tofu", "Bob", "bob") {
		t.Fatal("SameSigner")
	}
	rv := mustSign(t, fDoc, SignOptions{Signer: a, Method: "tofu", SignerID: "a", TS: fTS, RevocationURL: revURL})
	if d := verify(rv.Text, &VerifyOptions{NoRevocation: true}).Signatures[0].Revocation.Detail; d != "revocation check disabled" {
		t.Error(d)
	}
	if d := verify(rv.Text, &VerifyOptions{ResolveOptions: ResolveOptions{Offline: true}}).Signatures[0].Revocation.Detail; d != "revocation list not fetched (offline)" {
		t.Error(d)
	}
	dnsDoc := mustSign(t, fDoc, SignOptions{Signer: a, Method: "dns", SignerID: "example.com", TS: fTS, RevocationURL: revURL})
	id := RevocationID(dnsDoc.Fields)
	resolvers := map[string]Resolver{"dns": ResolverFunc(func(_ context.Context, f map[string]string, _ *ResolveOptions) (ResolveResult, error) {
		return ResolveResult{Keys: []CandidateKey{{Alg: "ed25519", Key: a.PublicKey(), Source: "test"}}}, nil
	})}
	stub := staticFetch(200, []byte(dnsListWithSigner(t, a, id, "Example.COM.")))
	o := &VerifyOptions{Resolvers: resolvers, ResourceCheckOptions: ResourceCheckOptions{FetchClient: stub.client()}}
	if c := verify(dnsDoc.Text, o).Signatures[0].Code; c != "revoked" {
		t.Fatal(c)
	}
}

func dnsListWithSigner(t *testing.T, s KeySigner, id, signer string) string {
	t.Helper()
	body := "revoked: sha256:" + id + "\n"
	fields := map[string]string{"v": SpecVersion, "method": "dns", "signer": signer, "ts": fTS, "alg": "ed25519", "hash": NormalizedHash(body)}
	sig, _ := s.Sign(SignedPayload(fields))
	fields["sig"] = "base64:" + ToBase64(sig)
	block, err := SerializeBlock(fields)
	if err != nil {
		t.Fatal(err)
	}
	return body + "\n" + block + "\n"
}

// --- revocation ---

func TestRevocation(t *testing.T) {
	a := mustSigner(t, seedA)
	b := mustSigner(t, seedB)
	resolvers := map[string]Resolver{"dns": fixedKeys(map[string][]byte{"example.com": a.PublicKey(), "evil.com": b.PublicKey()}, "ed25519")}
	doc := mustSign(t, fDoc, SignOptions{Signer: a, Method: "dns", SignerID: "example.com", TS: fTS, RevocationURL: revURL})
	id := RevocationID(doc.Fields)

	listText := ""
	stub := &fetchStub{fn: func(r *http.Request) (int, []byte, error) {
		if r.URL.String() != revURL {
			t.Errorf("unexpected fetch %s", r.URL)
		}
		return 200, []byte(listText), nil
	}}
	makeList := func(signer Signer, signerID string, ids ...string) string {
		var lines []string
		for _, i := range ids {
			lines = append(lines, "revoked: sha256:"+i)
		}
		return mustSign(t, "# Revoked\n\n"+strings.Join(lines, "\n")+"\n", SignOptions{Signer: signer, Method: "dns", SignerID: signerID, TS: fTS, RevocationURL: revURL}).Text
	}
	opts := func() *VerifyOptions {
		return &VerifyOptions{Resolvers: resolvers, ResourceCheckOptions: ResourceCheckOptions{FetchClient: stub.client()}}
	}

	listText = makeList(a, "example.com")
	v0 := verify(doc.Text, opts())
	if !v0.OK || v0.Signatures[0].Revocation.Status != RevocationNotRevoked || stub.calls != 1 {
		t.Fatalf("calls=%d %s", stub.calls, dump(v0))
	}

	listText = makeList(a, "example.com", id)
	if c := verify(doc.Text, opts()).Signatures[0].Code; c != "revoked" {
		t.Fatal(c)
	}
	stub.calls = 0
	twice := mustSign(t, doc.Text, SignOptions{Signer: a, Method: "dns", SignerID: "example.com", TS: fTS, RevocationURL: revURL})
	listText = makeList(a, "example.com")
	if v := verify(twice.Text, opts()); !v.OK || stub.calls != 1 {
		t.Fatalf("calls=%d %s", stub.calls, dump(v))
	}

	listText = makeList(b, "evil.com", id)
	v2 := verify(doc.Text, opts())
	if v2.OK || v2.Signatures[0].Status != StatusUnresolved || v2.Signatures[0].Code != KindNotFound || v2.Signatures[0].Revocation.Status != RevocationNotChecked {
		t.Fatal(dump(v2))
	}
	listText = strings.Replace(makeList(a, "example.com", id), "# Revoked", "# Revoked!", 1)
	if v := verify(doc.Text, opts()); v.OK || v.Signatures[0].Status != StatusUnresolved || v.Signatures[0].Code != KindNetwork {
		t.Fatal(dump(v))
	}

	stub.calls = 0
	o := opts()
	o.Offline = true
	v3 := verify(doc.Text, o)
	if v3.Signatures[0].Status != StatusValid || v3.Signatures[0].Revocation.Status != RevocationNotChecked {
		t.Fatal(dump(v3))
	}
	o = opts()
	o.NoRevocation = true
	if v := verify(doc.Text, o); v.Signatures[0].Revocation.Status != RevocationNotChecked || stub.calls != 0 {
		t.Fatal(dump(v))
	}

	td := mustSign(t, fDoc, SignOptions{Signer: a, Method: "tofu", SignerID: "bob", TS: fTS, RevocationURL: revURL})
	tid := RevocationID(td.Fields)
	listText = mustSign(t, "revoked: sha256:"+tid+"\n", SignOptions{Signer: b, Method: "tofu", SignerID: "bob", TS: fTS}).Text
	if v := verify(td.Text, opts()); v.OK || v.Signatures[0].Code != KindNotFound {
		t.Fatal(dump(v))
	}
	listText = mustSign(t, "revoked: sha256:"+tid+"\n", SignOptions{Signer: a, Method: "tofu", SignerID: "bob", TS: fTS}).Text
	if c := verify(td.Text, opts()).Signatures[0].Code; c != "revoked" {
		t.Fatal(c)
	}
}

// --- scope ---

const scopedDoc = `# Agreement

<!-- mdsig:section terms -->
## Terms
Payment within 30 days.
<!-- /mdsig:section -->

## Notes (editable)
Draft notes.

<!-- mdsig:section fees -->
| Fee | 100 |
<!-- /mdsig:section -->
`

func TestScope(t *testing.T) {
	a := mustSigner(t, seedA)
	s := mustSign(t, scopedDoc, SignOptions{Signer: a, Method: "tofu", SignerID: "a", TS: fTS, Scope: []string{"terms", "fees"}})
	v0 := verify(s.Text, nil)
	if !v0.OK || !reflect.DeepEqual(v0.Signatures[0].Partial, []string{"terms", "fees"}) {
		t.Fatal(dump(v0))
	}
	if !strings.Contains(strings.Join(v0.Signatures[0].Warnings, ";"), "partial") {
		t.Fatal(v0.Signatures[0].Warnings)
	}
	if !verify(strings.Replace(s.Text, "Draft notes.", "Final notes, edited later.", 1), nil).OK {
		t.Fatal("editing outside the sections must keep the signature valid")
	}
	for _, c := range [][2]string{{"30 days", "90 days"}, {"| Fee | 100 |", "| Fee | 1000 |"}} {
		if code := verify(strings.Replace(s.Text, c[0], c[1], 1), nil).Signatures[0].Code; code != "hash-mismatch" {
			t.Errorf("%s: %s", c[1], code)
		}
	}
	shifted := strings.Replace(s.Text, "Payment within 30 days.\n<!-- /mdsig:section -->", "<!-- /mdsig:section -->\nPayment within 30 days.", 1)
	if verify(shifted, nil).OK {
		t.Fatal("boundary shift must fail")
	}
	removed := strings.Replace(s.Text, "<!-- mdsig:section fees -->\n| Fee | 100 |\n<!-- /mdsig:section -->\n", "", 1)
	if r := verify(removed, nil).Signatures[0]; r.Status != StatusInvalid || r.Code != "scope-missing" {
		t.Fatalf("%+v", r)
	}
	unclosed := strings.Replace(s.Text, "| Fee | 100 |\n<!-- /mdsig:section -->", "| Fee | 100 |", 1)
	if r := verify(unclosed, nil).Signatures[0]; r.Status != StatusMalformed || !strings.Contains(r.Message, "never closed") {
		t.Fatalf("%+v", r)
	}
	_, err := SignDocument(context.Background(), "<!-- mdsig:section a -->\n<!-- mdsig:section b -->\n<!-- /mdsig:section -->\n", SignOptions{Signer: a, Method: "tofu", SignerID: "a", Scope: []string{"a"}})
	if err == nil || !strings.Contains(err.Error(), "nesting") {
		t.Fatal(err)
	}
	_, err = SignDocument(context.Background(), scopedDoc, SignOptions{Signer: a, Method: "tofu", SignerID: "a", Scope: []string{"nope"}})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatal(err)
	}
	_, err = SignDocument(context.Background(), scopedDoc, SignOptions{Signer: a, Method: "tofu", SignerID: "a", Scope: []string{"Bad_ID"}})
	if _, ok := err.(*ValueError); !ok {
		t.Fatal(err)
	}
	if _, ok := ParseScope("section:a,section:a"); ok {
		t.Fatal("duplicate ids must be rejected")
	}
	b := mustSigner(t, seedB)
	s2 := mustSign(t, s.Text, SignOptions{Signer: b, Method: "tofu", SignerID: "b", TS: fTS})
	v2 := verify(strings.Replace(s2.Text, "Draft notes.", "Edited.", 1), nil)
	if v2.Signatures[0].Status != StatusValid || v2.Signatures[1].Status != StatusInvalid {
		t.Fatal(dump(v2))
	}
}

func TestScopeMarkersInFencesIgnored(t *testing.T) {
	a := mustSigner(t, seedA)
	doc := "```\n<!-- mdsig:section x -->\n```\n<!-- mdsig:section real -->\nA\n<!-- /mdsig:section -->\n"
	s := mustSign(t, doc, SignOptions{Signer: a, Method: "tofu", SignerID: "a", TS: fTS, Scope: []string{"real"}})
	if !verify(s.Text, nil).OK {
		t.Fatal("fenced marker should be ignored")
	}
	_, errs := FindSections("<!-- mdsig:section x -->\n<!-- /mdsig:section -->\n<!-- mdsig:sectionfoo -->\n<!-- mdsig:section-y -->\n<!-- /mdsig:section -->\n")
	if len(errs) != 2 {
		t.Fatal(errs)
	}
}

// --- WebAuthn ---

func TestDERConversion(t *testing.T) {
	for i := 0; i < 200; i++ {
		rs := make([]byte, 64)
		_, _ = rand.Read(rs)
		if i%3 == 0 {
			rs[0] = 0
		}
		if i%5 == 0 {
			rs[32] = 0x80
		}
		der, err := P1363ToDER(rs)
		if err != nil {
			t.Fatal(err)
		}
		back, err := DERToP1363(der)
		if err != nil || !reflect.DeepEqual(back, rs) {
			t.Fatalf("%x -> %x (%v)", rs, back, err)
		}
	}
	good, _ := P1363ToDER(bytesOf(64, 1))
	expectErr := func(b []byte, sub string) {
		t.Helper()
		_, err := DERToP1363(b)
		if err == nil || !strings.Contains(err.Error(), sub) {
			t.Errorf("%x: %v (want %q)", b, err, sub)
		}
	}
	expectErr(good[:len(good)-1], "length mismatch")
	expectErr(append(append([]byte{}, good...), 0), "length mismatch")
	fat := append([]byte{0x30, 0x26, 0x02, 0x22, 0, 0}, bytesOf(32, 1)...)
	fat = append(fat, 0x02, 0x00)
	expectErr(fat, "integer length out of range")
	expectErr([]byte{0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}, "SEQUENCE")
	expectErr([]byte{0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}, "long-form")
	expectErr([]byte{0x30, 0x06, 0x02, 0x01, 0x81, 0x02, 0x01, 0x01}, "negative")
	expectErr([]byte{0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01}, "non-minimal")
	expectErr([]byte{0x30, 0x06, 0x04, 0x01, 0x01, 0x02, 0x01, 0x01}, "INTEGER expected")
	expectErr([]byte{0x30, 0x06, 0x02, 0x05, 0x01, 0x02, 0x01, 0x01}, "truncated")
	expectErr([]byte{0x30, 0x08, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00}, "trailing bytes")
	long33 := append([]byte{0x30, 0x26, 0x02, 0x21, 0x01}, bytesOf(32, 1)...)
	long33 = append(long33, 0x02, 0x01, 0x01)
	expectErr(long33, "longer than 32 bytes")
	ok := append([]byte{0x30, 0x44, 0x02, 0x1f}, bytesOf(31, 0x7f)...)
	ok = append(ok, 0x02, 0x21, 0x00)
	ok = append(ok, bytesOf(32, 0xff)...)
	if rs, err := DERToP1363(ok); err != nil || rs[0] != 0 || rs[1] != 0x7f || rs[63] != 0xff {
		t.Fatalf("%x %v", rs, err)
	}
}

type softAuth struct {
	key                *ecdsa.PrivateKey
	rpID, origin       string
	flags              byte
	counter            int
	overrideClientData func(map[string]any) map[string]any
}

func newSoftAuth(t *testing.T, rpID, origin string, flags byte) *softAuth {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if origin == "" {
		origin = "https://" + rpID
	}
	return &softAuth{key: k, rpID: rpID, origin: origin, flags: flags}
}

func (a *softAuth) PublicKeySPKI() []byte {
	b, _ := x509.MarshalPKIXPublicKey(&a.key.PublicKey)
	return b
}

func (a *softAuth) RPID() string { return a.rpID }

func (a *softAuth) GetAssertion(challenge []byte) (*WebAuthnAssertion, error) {
	cd := map[string]any{"type": "webauthn.get", "challenge": ToBase64URL(challenge), "origin": a.origin, "crossOrigin": false}
	if a.overrideClientData != nil {
		cd = a.overrideClientData(cd)
	}
	clientData, _ := json.Marshal(cd)
	a.counter++
	rpHash := sha256.Sum256([]byte(a.rpID))
	authData := append(rpHash[:], a.flags, 0, 0, byte(a.counter>>8), byte(a.counter))
	cdHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authData...), cdHash[:]...))
	r, s, err := ecdsa.Sign(rand.Reader, a.key, digest[:])
	if err != nil {
		return nil, err
	}
	rs := make([]byte, 64)
	r.FillBytes(rs[:32])
	s.FillBytes(rs[32:])
	der, err := P1363ToDER(rs)
	if err != nil {
		return nil, err
	}
	return &WebAuthnAssertion{Signature: der, AuthenticatorData: authData, ClientDataJSON: clientData}, nil
}

const rp = "shiozaki-shota.github.io"

func TestWebAuthn(t *testing.T) {
	auth := newSoftAuth(t, rp, "", 0x05)
	s := mustSign(t, fDoc, SignOptions{WebAuthn: auth, Method: "tofu", SignerID: "carol@passkey", Role: "approver", TS: fTS})
	for _, re := range []string{`pubkey: es256:`, `rp_id: shiozaki-shota\.github\.io`, `alg: webauthn-es256`} {
		if !regexp.MustCompile(re).MatchString(s.Block) {
			t.Fatalf("%s missing:\n%s", re, s.Block)
		}
	}
	v := verify(s.Text, nil)
	if !v.OK || v.Signatures[0].WebAuthn == nil || v.Signatures[0].WebAuthn.RPID != rp || v.Signatures[0].WebAuthn.Origin != "https://"+rp {
		t.Fatal(dump(v))
	}
	code := func(text string) *BlockResult { return verify(text, nil).Signatures[0] }
	if c := code(strings.Replace(s.Text, "agree", "disagree", 1)).Code; c != "hash-mismatch" {
		t.Fatal(c)
	}
	if c := code(strings.Replace(s.Text, "role: approver", "role: author", 1)).Code; c != "bad-signature" {
		t.Fatal(c)
	}
	if c := code(strings.Replace(s.Text, "rp_id: "+rp, "rp_id: evil.example", 1)).Code; c != "bad-signature" {
		t.Fatal(c)
	}

	other := newSoftAuth(t, "evil.example", "https://"+rp, 0x05)
	forged := &rpOverride{softAuth: other, rp: rp}
	r2 := code(mustSign(t, fDoc, SignOptions{WebAuthn: forged, Method: "tofu", SignerID: "x", TS: fTS}).Text)
	if r2.Code != "bad-signature" || !strings.Contains(r2.Message, "rpIdHash") {
		t.Fatalf("%+v", r2)
	}
	wrongOrigin := newSoftAuth(t, rp, "https://evil.example", 0x05)
	if r := code(mustSign(t, fDoc, SignOptions{WebAuthn: wrongOrigin, Method: "tofu", SignerID: "x", TS: fTS}).Text); !strings.Contains(r.Message, "origin") {
		t.Fatalf("%+v", r)
	}
	sub := newSoftAuth(t, "github.io", "https://shiozaki-shota.github.io", 0x05)
	if r := code(mustSign(t, fDoc, SignOptions{WebAuthn: sub, Method: "tofu", SignerID: "x", TS: fTS}).Text); r.Status != StatusValid {
		t.Fatalf("%+v", r)
	}
	plainHTTP := newSoftAuth(t, rp, "http://"+rp, 0x05)
	if r := code(mustSign(t, fDoc, SignOptions{WebAuthn: plainHTTP, Method: "tofu", SignerID: "x", TS: fTS}).Text); !strings.Contains(r.Message, "not https") {
		t.Fatalf("%+v", r)
	}
	wrongType := newSoftAuth(t, rp, "", 0x05)
	wrongType.overrideClientData = func(cd map[string]any) map[string]any { cd["type"] = "webauthn.create"; return cd }
	if r := code(mustSign(t, fDoc, SignOptions{WebAuthn: wrongType, Method: "tofu", SignerID: "x", TS: fTS}).Text); r.Code != "bad-signature" || !strings.Contains(r.Message, "webauthn.create") {
		t.Fatalf("%+v", r)
	}
	local := newSoftAuth(t, "localhost", "http://localhost:8765", 0x05)
	v5 := verify(mustSign(t, fDoc, SignOptions{WebAuthn: local, Method: "tofu", SignerID: "dev", TS: fTS}).Text, nil)
	if !v5.OK || !strings.Contains(strings.Join(v5.Signatures[0].Warnings, ";"), "localhost") {
		t.Fatal(dump(v5))
	}
	noUp := newSoftAuth(t, rp, "", 0x04)
	if r := code(mustSign(t, fDoc, SignOptions{WebAuthn: noUp, Method: "tofu", SignerID: "x", TS: fTS}).Text); !strings.Contains(r.Message, "User Present") {
		t.Fatalf("%+v", r)
	}
	if !v.Signatures[0].WebAuthn.UserVerified {
		t.Fatal("UV flag (0x04) should be reported")
	}
	sigLine := regexp.MustCompile(`(?s)sig: \|\n  [^\n]+\n  [^\n]+\n|sig: [^\n]+\n`)
	bad := sigLine.ReplaceAllString(s.Text, "sig: base64:MAYCAQECAQ==\n")
	if r := code(bad); r.Status != StatusMalformed {
		t.Fatalf("%+v", r)
	}
	a := mustSigner(t, seedA)
	plain := mustSign(t, fDoc, SignOptions{Signer: a, Method: "tofu", SignerID: "a", TS: fTS})
	if r := code(strings.Replace(plain.Text, "alg: ed25519", "rp_id: x.com\nalg: ed25519", 1)); r.Status != StatusMalformed {
		t.Fatalf("%+v", r)
	}
	if r := code(strings.Replace(s.Text, "pubkey: es256:", "pubkey: ed25519:", 1)); r.Status != StatusMalformed {
		t.Fatalf("%+v", r)
	}
	if _, err := SignDocument(context.Background(), fDoc, SignOptions{WebAuthn: auth, Method: "git-hosting", SignerID: "github.com/a"}); err == nil || !strings.Contains(err.Error(), "git-hosting") {
		t.Fatal(err)
	}
}

type rpOverride struct {
	*softAuth
	rp string
}

func (r *rpOverride) RPID() string { return r.rp }

func TestWebAuthnViaDNS(t *testing.T) {
	auth := newSoftAuth(t, rp, "", 0x05)
	p := ToBase64(auth.PublicKeySPKI())
	o := &VerifyOptions{ResolveOptions: ResolveOptions{LookupTXT: func(_ context.Context, name string) ([]string, error) {
		if name != "_mdsig.example.com" {
			t.Errorf("lookup %s", name)
		}
		return []string{"v=mdsig1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=", "v=mdsig1; k=es256; p=" + p}, nil
	}}}
	s := mustSign(t, fDoc, SignOptions{WebAuthn: auth, Method: "dns", SignerID: "example.com", TS: fTS})
	if v := verify(s.Text, o); !v.OK {
		t.Fatal(dump(v))
	}
	pt := auth.PublicKeySPKI()[26:]
	o.LookupTXT = func(context.Context, string) ([]string, error) {
		return []string{"v=mdsig1; k=es256; p=" + ToBase64(pt)}, nil
	}
	if v := verify(s.Text, o); !v.OK {
		t.Fatal(dump(v))
	}
}

func TestAllFeaturesRoundTrip(t *testing.T) {
	a := mustSigner(t, seedA)
	s := mustSign(t, scopedDoc, SignOptions{Signer: a, Method: "tofu", SignerID: "a", TS: fTS, Scope: []string{"terms"}, Expires: "2030-01-01T00:00:00Z",
		Require: []string{"tofu:b"}, Resources: []ResourceItem{{Ref: "./x.png", Bytes: []byte("x")}}, RevocationURL: "https://example.com/r.md", Extra: map[string]string{"x_ref": "PO-9"}})
	block := ParseDocument(s.Text).Chain[0]
	if len(block.Errors) != 0 {
		t.Fatal(block.Errors)
	}
	var order []string
	for _, l := range strings.Split(s.Block, "\n") {
		if l == OpenLine || l == CloseLine || strings.HasPrefix(l, "  ") {
			continue
		}
		order = append(order, strings.SplitN(l, ":", 2)[0])
	}
	want := []string{"v", "method", "signer", "pubkey", "ts", "expires", "scope", "require", "resources", "revocation_url", "x_ref", "alg", "hash", "sig"}
	if !reflect.DeepEqual(order, want) {
		t.Fatal(order)
	}
}
