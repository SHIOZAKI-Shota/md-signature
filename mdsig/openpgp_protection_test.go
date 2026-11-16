package mdsig

import (
	"bytes"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/go-crypto/openpgp/s2k"
)

func TestPgpSecretKeyArgon2AEAD(t *testing.T) {
	all, err := Dearmor(readExample(t, "pgp/dave.sec.asc"))
	if err != nil || len(all) != 1 {
		t.Fatalf("dearmor: %v", err)
	}
	blocks := all[0]
	p, err := packet.NewReader(bytes.NewReader(blocks)).Next()
	if err != nil {
		t.Fatal(err)
	}
	sk, ok := p.(*packet.PrivateKey)
	if !ok {
		t.Fatalf("first packet is %T", p)
	}
	cfg := &packet.Config{
		S2KConfig:  &s2k.Config{S2KMode: s2k.Argon2S2K, Argon2Config: &s2k.Argon2Config{NumberOfPasses: 1, DegreeOfParallelism: 1, Memory: 16}},
		AEADConfig: &packet.AEADConfig{},
	}
	if err := sk.EncryptWithConfig([]byte("hunter2"), cfg); err != nil {
		t.Fatal(err)
	}
	var protected bytes.Buffer
	if err := sk.Serialize(&protected); err != nil {
		t.Fatal(err)
	}
	rest := blocks[len(blocks)-restAfterFirstPacket(t, blocks):]
	now := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	info, err := ReadPgpSecretKey(append(protected.Bytes(), rest...), now)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Protected {
		t.Fatal("key is not reported as protected")
	}
	if _, err := UnlockPgpSecretKey(info, []byte("wrong"), PgpUnlockOptions{}); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	signer, err := UnlockPgpSecretKey(info, []byte("hunter2"), PgpUnlockOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if sig, err := signer.Sign([]byte("payload")); err != nil || len(sig) == 0 {
		t.Fatalf("sign: %v", err)
	}
}

func restAfterFirstPacket(t *testing.T, b []byte) int {
	t.Helper()
	r := bytes.NewReader(b)
	if _, err := packet.NewReader(r).Next(); err != nil {
		t.Fatal(err)
	}
	return r.Len()
}
