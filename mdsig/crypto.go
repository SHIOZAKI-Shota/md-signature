package mdsig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strings"
)

type Signer interface {
	PublicKey() ed25519.PublicKey
	Sign(data []byte) ([]byte, error)
}

type KeySigner struct{ Key ed25519.PrivateKey }

func (s KeySigner) PublicKey() ed25519.PublicKey { return s.Key.Public().(ed25519.PublicKey) }

func (s KeySigner) Sign(data []byte) ([]byte, error) { return ed25519.Sign(s.Key, data), nil }

func SignerFromSeed(seed []byte) (KeySigner, error) {
	if len(seed) != ed25519.SeedSize {
		return KeySigner{}, errors.New("Ed25519 seed must be 32 bytes")
	}
	return KeySigner{Key: ed25519.NewKeyFromSeed(seed)}, nil
}

var spkiEd25519Prefix = []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}

func RawEd25519PublicKey(b []byte) ([]byte, error) {
	if len(b) == 32 {
		return b, nil
	}
	if len(b) == 44 && bytes.Equal(b[:12], spkiEd25519Prefix) {
		return b[12:], nil
	}
	return nil, fmt.Errorf("not an Ed25519 public key (length %d)", len(b))
}

func Ed25519Verify(publicKey, sig, data []byte) bool {
	if len(sig) != ed25519.SignatureSize {
		return false
	}
	pk, err := RawEd25519PublicKey(publicKey)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pk), data, sig)
}

func IsSupportedHash(alg string) bool { return alg == "sha256" || alg == "sha512" }

func Digest(alg string, data []byte) []byte {
	var h hash.Hash
	if alg == "sha512" {
		h = sha512.New()
	} else {
		h = sha256.New()
	}
	h.Write(data)
	return h.Sum(nil)
}

func sshString(b []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
	return append(out, b...)
}

func SSHEd25519Blob(publicKey []byte) []byte {
	return append(sshString([]byte("ssh-ed25519")), sshString(publicKey)...)
}

func FormatSSHPublicKey(publicKey []byte, comment string) string {
	s := "ssh-ed25519 " + ToBase64(SSHEd25519Blob(publicKey))
	if comment != "" {
		s += " " + comment
	}
	return s
}

func SSHFingerprint(publicKey []byte) string {
	sum := sha256.Sum256(SSHEd25519Blob(publicKey))
	return "SHA256:" + ToBase64Unpadded(sum[:])
}

type SSHPublicKey struct {
	Type    string
	Key     []byte
	Blob    []byte
	Comment string
}

type sshReader struct {
	b []byte
	o int
}

func (r *sshReader) u32() (uint32, error) {
	if r.o+4 > len(r.b) {
		return 0, errors.New("truncated SSH data")
	}
	v := binary.BigEndian.Uint32(r.b[r.o:])
	r.o += 4
	return v, nil
}

func (r *sshReader) bytes() ([]byte, error) {
	n, err := r.u32()
	if err != nil {
		return nil, err
	}
	if uint64(r.o)+uint64(n) > uint64(len(r.b)) {
		return nil, errors.New("truncated SSH data")
	}
	v := r.b[r.o : r.o+int(n)]
	r.o += int(n)
	return v, nil
}

func ParseSSHPublicKeys(text string) []SSHPublicKey {
	var out []SSHPublicKey
	for _, line := range strings.Split(text, "\n") {
		t := strings.TrimFunc(strings.TrimSuffix(line, "\r"), isJSSpace)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		parts := strings.FieldsFunc(t, isJSSpace)
		if len(parts) < 2 {
			continue
		}
		blob, err := FromBase64(parts[1])
		if err != nil {
			continue
		}
		r := &sshReader{b: blob}
		typ, err := r.bytes()
		if err != nil || string(typ) != parts[0] {
			continue
		}
		e := SSHPublicKey{Type: string(typ), Blob: blob, Comment: strings.Join(parts[2:], " ")}
		if e.Type == "ssh-ed25519" {
			k, err := r.bytes()
			if err != nil {
				continue
			}
			e.Key = k
		}
		out = append(out, e)
	}
	return out
}
