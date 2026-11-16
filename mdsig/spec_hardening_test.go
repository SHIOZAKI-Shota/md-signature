package mdsig

import (
	"context"
	"strings"
	"testing"
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
}

func TestTSATokenBounds(t *testing.T) {
	bomb := CheckTSAToken("gzip+base64:"+ToBase64(Gzip(make([]byte, 8<<20))), make([]byte, 64))
	if bomb.Status != TSAError || !strings.Contains(bomb.Detail, "larger than") {
		t.Errorf("bomb: %+v", bomb)
	}
	deep := make([]byte, 100)
	for i := 0; i < 50; i++ {
		deep[2*i], deep[2*i+1] = 0x30, byte(98-2*i)
	}
	nested := CheckTSAToken("base64:"+ToBase64(deep), make([]byte, 64))
	if nested.Status != TSAError || !strings.Contains(nested.Detail, "nested too deeply") {
		t.Errorf("nested: %+v", nested)
	}
}

func TestGitHostingSignerHost(t *testing.T) {
	for _, s := range []string{"127.0.0.1/a", "localhost/a", "2130706433/a", "[::1]/a", "github.com./a", "-x.com/a"} {
		if IsValidGitHostingSigner(s) {
			t.Errorf("%q accepted", s)
		}
	}
	for _, s := range []string{"github.com/alice", "git.example.co.jp/bob_1", "GitLab.com/x"} {
		if !IsValidGitHostingSigner(s) {
			t.Errorf("%q rejected", s)
		}
	}
}

func TestForbiddenRunesInValues(t *testing.T) {
	for _, r := range []rune{0x1b, 0x7f, 0x9b, 0x2028, 0x2029, 0x202e, 0x2066} {
		if ValidateLine("a"+string(r)+"b") == "" {
			t.Errorf("U+%04X accepted", r)
		}
	}
	if ValidateLine("日本語 ok") != "" {
		t.Error("ordinary text rejected")
	}
}
