package sshkeys

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/SHIOZAKI-Shota/md-signature/mdsig"
)

func testKey(t *testing.T) ed25519.PrivateKey {
	seed, _ := mdsig.FromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	return ed25519.NewKeyFromSeed(seed)
}

func TestAgentSignatureIsRawEd25519(t *testing.T) {
	priv := testKey(t)
	kr := agent.NewKeyring()
	if err := kr.Add(agent.AddedKey{PrivateKey: priv, Comment: "test"}); err != nil {
		t.Fatal(err)
	}
	keys, err := ListEd25519(kr)
	if err != nil || len(keys) != 1 {
		t.Fatalf("keys=%v err=%v", keys, err)
	}
	ak := keys[0]
	pub := priv.Public().(ed25519.PublicKey)
	if !bytes.Equal(ak.PublicKey(), pub) {
		t.Fatal("agent public key mismatch")
	}

	res, err := mdsig.SignDocument(context.Background(), "# Hello\n", mdsig.SignOptions{
		Signer: ak, Method: "git-hosting", SignerID: "github.com/alice", TS: "2026-11-16T09:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := mdsig.FromBase64(strings.TrimPrefix(res.Fields["sig"], "base64:"))
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("sig is %d bytes, want 64", len(sig))
	}
	if !ed25519.Verify(pub, mdsig.SignedPayload(res.Fields), sig) {
		t.Fatal("agent signature does not verify with crypto/ed25519 over the payload")
	}
	if !bytes.Equal(sig, ed25519.Sign(priv, mdsig.SignedPayload(res.Fields))) {
		t.Fatal("agent signature differs from a raw-key signature")
	}
	keysFile := mdsig.FormatSSHPublicKey(pub, "alice")
	v := mdsig.VerifyDocument(context.Background(), res.Text, &mdsig.VerifyOptions{Resolvers: map[string]mdsig.Resolver{
		"git-hosting": mdsig.ResolverFunc(func(_ context.Context, f map[string]string, _ *mdsig.ResolveOptions) (mdsig.ResolveResult, error) {
			return mdsig.GitHostingKeysFromText(f, "test", keysFile)
		}),
	}})
	if !v.OK {
		t.Fatalf("%+v", v.Signatures[0])
	}
}

func TestKeyPairRoundTripAndPassphrase(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "k")
	priv := testKey(t)
	if err := WriteKeyPair(prefix, "c", priv); err != nil {
		t.Fatal(err)
	}
	if err := WriteKeyPair(prefix, "c", priv); err == nil {
		t.Fatal("overwrote existing key")
	}
	s, err := LoadPrivateKeyFile(prefix, nil)
	if err != nil || !bytes.Equal(s.Key, priv) {
		t.Fatalf("load: %v", err)
	}
	pubLine, _ := os.ReadFile(prefix + ".pub")
	if !strings.HasPrefix(string(pubLine), "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea") {
		t.Fatalf("pub line: %s", pubLine)
	}

	blk, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "c", []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	enc := filepath.Join(dir, "enc")
	if err := os.WriteFile(enc, pemEncode(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKeyFile(enc, nil); err != ErrPassphraseNeeded {
		t.Fatalf("want ErrPassphraseNeeded, got %v", err)
	}
	if _, err := LoadPrivateKeyFile(enc, func() ([]byte, error) { return []byte("bad"), nil }); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	s, err = LoadPrivateKeyFile(enc, func() ([]byte, error) { return []byte("pw"), nil })
	if err != nil || !bytes.Equal(s.Key, priv) {
		t.Fatalf("encrypted load: %v", err)
	}
}

func pemEncode(b *pem.Block) []byte { return pem.EncodeToMemory(b) }
