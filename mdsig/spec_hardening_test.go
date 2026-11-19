package mdsig

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestTofuBindingStoredOnlyAfterVerification(t *testing.T) {
	store := &MemoryTofuStore{}
	signed := signTofu(t, testBody)
	signer := signed.Fields["signer"]
	forged := strings.Replace(signed.Text, "signer: "+signer, "signer: someone-else", 1)
	v := VerifyDocument(context.Background(), forged, &VerifyOptions{ResolveOptions: ResolveOptions{Offline: true, TofuStore: store}})
	if v.Signatures[0].Code != "bad-signature" {
		t.Fatalf("forged: %+v", v.Signatures[0])
	}
	if _, ok := store.Get("someone-else"); ok {
		t.Error("binding stored for a signature that did not verify")
	}
	v = VerifyDocument(context.Background(), signed.Text, &VerifyOptions{ResolveOptions: ResolveOptions{Offline: true, TofuStore: store}})
	if !v.OK {
		t.Fatalf("valid: %+v", v.Signatures[0])
	}
	if pk, ok := store.Get(signer); !ok || pk != signed.Fields["pubkey"] {
		t.Error("binding not stored for a valid signature")
	}
	if !hasWarning(v.Signatures[0].Warnings, "seen for the first time") {
		t.Errorf("first-seen warning missing: %v", v.Signatures[0].Warnings)
	}
	v = VerifyDocument(context.Background(), signed.Text, &VerifyOptions{ResolveOptions: ResolveOptions{Offline: true, TofuStore: store}})
	if hasWarning(v.Signatures[0].Warnings, "seen for the first time") {
		t.Errorf("known key reported as new: %v", v.Signatures[0].Warnings)
	}

	expired, err := SignDocument(context.Background(), testBody, SignOptions{
		Signer: mustSigner(t, bobSeed), Method: "tofu", SignerID: "late", TS: "2026-11-16T09:00:00Z", Expires: "2027-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	opts := &VerifyOptions{ResolveOptions: ResolveOptions{Offline: true, TofuStore: store}, Now: time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC)}
	if v := VerifyDocument(context.Background(), expired.Text, opts); v.Signatures[0].Code != "expired" {
		t.Fatalf("expired: %+v", v.Signatures[0])
	}
	if _, ok := store.Get("late"); ok {
		t.Error("binding stored for an expired signature")
	}
}

func hasWarning(ws []string, s string) bool {
	for _, w := range ws {
		if strings.Contains(w, s) {
			return true
		}
	}
	return false
}

func TestTSATokenBounds(t *testing.T) {
	bomb := CheckTSAToken("gzip+base64:"+toBase64(gzipBytes(make([]byte, 8<<20))), make([]byte, 64), nil)
	if bomb.Status != TSAError || !strings.Contains(bomb.Detail, "larger than") {
		t.Errorf("bomb: %+v", bomb)
	}
	deep := make([]byte, 100)
	for i := 0; i < 50; i++ {
		deep[2*i], deep[2*i+1] = 0x30, byte(98-2*i)
	}
	nested := CheckTSAToken("base64:"+toBase64(deep), make([]byte, 64), nil)
	if nested.Status != TSAError || !strings.Contains(nested.Detail, "nested too deeply") {
		t.Errorf("nested: %+v", nested)
	}
}

func TestGitHostingSignerHost(t *testing.T) {
	for _, s := range []string{"127.0.0.1/a", "localhost/a", "2130706433/a", "[::1]/a", "github.com./a", "-x.com/a"} {
		if isValidGitHostingSigner(s) {
			t.Errorf("%q accepted", s)
		}
	}
	for _, s := range []string{"github.com/alice", "git.example.co.jp/bob_1", "GitLab.com/x"} {
		if !isValidGitHostingSigner(s) {
			t.Errorf("%q rejected", s)
		}
	}
}

func TestForbiddenRunesInValues(t *testing.T) {
	for _, r := range []rune{0x1b, 0x7f, 0x9b, 0x2028, 0x2029, 0x202e, 0x2066} {
		if validateLine("a"+string(r)+"b") == "" {
			t.Errorf("U+%04X accepted", r)
		}
	}
	if validateLine("日本語 ok") != "" {
		t.Error("ordinary text rejected")
	}
}
