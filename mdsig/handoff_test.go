package mdsig

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/url"
	"strings"
	"testing"
)

// --- helpers

const (
	hoPage   = "https://keys.example.org/sign"
	hoReturn = "mdsig+test://handoff"
)

func hoPageTransport(t *testing.T, auth *softAuth, tamper func(*url.URL), refuse string) HandoffTransport {
	return func(_ context.Context, req *HandoffRequest) (string, error) {
		r := CheckHandoffRequest(req.URL, "keys.example.org")
		if !r.OK {
			t.Fatalf("page refused: %s", r.Message)
		}
		var a HandoffAnswer
		switch {
		case refuse != "":
			a = HandoffAnswer{Error: refuse}
		case r.Op == "key":
			a = HandoffAnswer{RPID: "keys.example.org", Key: auth.PublicKeySPKI(), Credential: "Y3JlZA"}
		default:
			if !PayloadMatchesKey(r.Fields, auth.PublicKeySPKI()) {
				t.Fatal("payload names another key")
			}
			sum := sha256.Sum256(r.Payload)
			as, err := auth.GetAssertion(sum[:], r.UserVerification)
			if err != nil {
				return "", err
			}
			a = HandoffAnswer{Assertion: as}
		}
		out, err := HandoffResponseURL(r.ReturnURL, r.State, a)
		if err != nil {
			return "", err
		}
		u, _ := url.Parse(out)
		if tamper != nil {
			tamper(u)
		}
		return u.String(), nil
	}
}

// --- two-phase signing

func TestPrepareSignatureMatchesSignDocument(t *testing.T) {
	s := mustSigner(t, aliceSeed)
	o := SignOptions{Method: "tofu", SignerID: "a", TS: "2026-11-16T09:00:00Z"}
	direct, err := SignDocument(context.Background(), testBody, SignOptions{Signer: s, Method: o.Method, SignerID: o.SignerID, TS: o.TS})
	if err != nil {
		t.Fatal(err)
	}
	p, err := PrepareSignature(testBody, SigningKey{Alg: "ed25519", PublicKey: s.PublicKey()}, o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Finish(context.Background(), make([]byte, 64), nil); err == nil {
		t.Fatal("a wrong signature was accepted")
	}
	sig, _ := s.Sign(p.Payload)
	done, err := p.Finish(context.Background(), sig, nil)
	if err != nil || done.Text != direct.Text {
		t.Fatalf("finish: %v\n%s\n---\n%s", err, done.Text, direct.Text)
	}
}

// --- handoff

func TestHandoffURLs(t *testing.T) {
	for u, want := range map[string]bool{
		"mdsig+fountain-pen://handoff": true, "http://127.0.0.1:8123/cb": true, "http://[::1]:8123/cb": true,
		"https://evil.example/cb": false, "http://localhost:8123/cb": false, "http://127.0.0.1/cb": false,
	} {
		if IsHandoffReturnURL(u) != want {
			t.Errorf("%s: want %v", u, want)
		}
	}
	if !RPIDFitsPage(hoPage, "example.org") || RPIDFitsPage(hoPage, "ys.example.org") {
		t.Error("RPIDFitsPage")
	}
	if _, err := CreateHandoffRequest("http://keys.example.org/sign", HandoffRequestOptions{Op: "key", ReturnURL: hoReturn}); err == nil {
		t.Error("http page accepted")
	}
	if ParseSignedPayload([]byte("md-signature/v1\nb=1\na=2")) != nil {
		t.Error("non-canonical payload accepted")
	}
	if f := ParseSignedPayload([]byte("md-signature/v1\na=x\n  y\nb=1")); f["a"] != "x\ny" || f["b"] != "1" {
		t.Errorf("payload: %v", f)
	}
}

func TestHandoffSignAndVerify(t *testing.T) {
	ctx := context.Background()
	auth := newSoftAuth(t, "keys.example.org", "", 0x05)
	pk, err := ConnectPasskeyViaPage(ctx, hoPage, hoReturn, hoPageTransport(t, auth, nil, ""))
	if err != nil {
		t.Fatal(err)
	}
	r, err := SignViaPage(ctx, testBody, pk, hoReturn, "contract.md", hoPageTransport(t, auth, nil, ""), SignOptions{Method: "tofu", SignerID: "alice", TS: "2026-11-16T09:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if v := VerifyDocument(ctx, r.Text, offline()); !v.OK {
		t.Fatalf("verify: %+v", v.Signatures[0])
	}
	o := SignOptions{Method: "tofu", SignerID: "alice", TS: "2026-11-16T09:00:00Z"}
	flip := func(u *url.URL) {
		q := u.Query()
		s := q.Get("sig")
		if strings.HasSuffix(s, "AA") {
			s = s[:len(s)-2] + "AB"
		} else {
			s = s[:len(s)-2] + "AA"
		}
		q.Set("sig", s)
		u.RawQuery = q.Encode()
	}
	if _, err := SignViaPage(ctx, testBody, pk, hoReturn, "", hoPageTransport(t, auth, flip, ""), o); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("tampered: %v", err)
	}
	other := func(u *url.URL) {
		q := u.Query()
		q.Set("state", strings.Repeat("x", 22))
		u.RawQuery = q.Encode()
	}
	var he *HandoffError
	if _, err := SignViaPage(ctx, testBody, pk, hoReturn, "", hoPageTransport(t, auth, other, ""), o); !errors.As(err, &he) || he.Code != "bad-response" {
		t.Errorf("other state: %v", err)
	}
	if _, err := SignViaPage(ctx, testBody, pk, hoReturn, "", hoPageTransport(t, auth, nil, "cancelled"), o); !errors.As(err, &he) || he.Code != "cancelled" {
		t.Errorf("refused: %v", err)
	}
	if _, err := ConnectPasskeyViaPage(ctx, "https://other.example/sign", hoReturn, hoPageTransport(t, auth, nil, "")); err == nil {
		t.Error("RP ID of another host accepted")
	}
}

func TestHandoffPageRefusesBadRequests(t *testing.T) {
	s := mustSigner(t, aliceSeed)
	p, _ := PrepareSignature(testBody, SigningKey{Alg: "ed25519", PublicKey: s.PublicKey()}, SignOptions{Method: "tofu", SignerID: "a", TS: "2026-11-16T09:00:00Z"})
	req, err := CreateHandoffRequest(hoPage, HandoffRequestOptions{Op: "sign", ReturnURL: hoReturn, Payload: p.Payload})
	if err != nil {
		t.Fatal(err)
	}
	if CheckHandoffRequest(req.URL, "keys.example.org").OK {
		t.Error("an ed25519 payload was accepted")
	}
	u, _ := url.Parse(req.URL)
	q := u.Query()
	q.Set("return", "https://evil.example/")
	u.RawQuery = q.Encode()
	if r := CheckHandoffRequest(u.String(), "keys.example.org"); r.OK || r.ReturnURL != "" {
		t.Errorf("evil return: %+v", r)
	}
}
