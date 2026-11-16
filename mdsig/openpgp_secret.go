package mdsig

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	gcecdsa "github.com/ProtonMail/go-crypto/openpgp/ecdsa"
	gced25519 "github.com/ProtonMail/go-crypto/openpgp/ed25519"
	gceddsa "github.com/ProtonMail/go-crypto/openpgp/eddsa"
	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// --- secret key material (S2K, unwrapping and the private-key operation are go-crypto's)

const pgpStubMessage = "the secret key is not in this file (stub for a smartcard or offline key); sign with gpg instead"

func decryptSecret(k *pgpKey, passphrase []byte) (*packet.PrivateKey, error) {
	p, err := packet.Read(bytes.NewReader(k.raw))
	priv, ok := p.(*packet.PrivateKey)
	if err != nil || !ok {
		return nil, &PGPError{Msg: "not an OpenPGP secret key"}
	}
	if priv.Dummy() {
		return nil, &PGPError{Msg: pgpStubMessage}
	}
	if !priv.Encrypted {
		return priv, nil
	}
	if passphrase == nil {
		return nil, &PGPError{Msg: "this OpenPGP key is protected; a passphrase is required"}
	}
	if err := priv.Decrypt(passphrase); err != nil {
		var unsupported pgperrors.UnsupportedError
		var invalidKey pgperrors.KeyInvalidError
		if errors.As(err, &unsupported) || errors.As(err, &invalidKey) {
			return nil, &PGPError{Msg: err.Error()}
		}
		// go-crypto reports a failed integrity check of the unwrapped key as a structural or AEAD error
		return nil, &PGPError{Msg: "wrong passphrase"}
	}
	return priv, nil
}

func importSigning(k *pgpKey, priv *packet.PrivateKey) (*pgpSigningKey, error) {
	invalid := &PGPError{Msg: fmt.Sprintf("invalid %s secret key", k.algName())}
	switch k.kind {
	case "rsa":
		key, ok := priv.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, invalid
		}
		return &pgpSigningKey{key: k, sign: func(h crypto.Hash, digest []byte) ([]byte, error) {
			s, err := rsa.SignPKCS1v15(nil, key, h, digest)
			if err != nil {
				return nil, err
			}
			return encodeMpi(s), nil
		}}, nil
	case "ecdsa":
		key, ok := priv.PrivateKey.(*gcecdsa.PrivateKey)
		if !ok {
			return nil, invalid
		}
		return &pgpSigningKey{key: k, sign: func(_ crypto.Hash, digest []byte) ([]byte, error) {
			rr, ss, err := gcecdsa.Sign(rand.Reader, key, digest)
			if err != nil {
				return nil, err
			}
			return concatBytes(encodeMpi(rr.Bytes()), encodeMpi(ss.Bytes())), nil
		}}, nil
	case "ed25519":
		// OpenPGP EdDSA signs the digest, not the hashed data itself
		if k.algo == 27 {
			key, ok := priv.PrivateKey.(*gced25519.PrivateKey)
			if !ok {
				return nil, invalid
			}
			return &pgpSigningKey{key: k, sign: func(_ crypto.Hash, digest []byte) ([]byte, error) {
				return gced25519.Sign(key, digest)
			}}, nil
		}
		key, ok := priv.PrivateKey.(*gceddsa.PrivateKey)
		if !ok {
			return nil, invalid
		}
		return &pgpSigningKey{key: k, sign: func(_ crypto.Hash, digest []byte) ([]byte, error) {
			r, s, err := gceddsa.Sign(key, digest)
			if err != nil {
				return nil, err
			}
			return concatBytes(encodeMpi(r), encodeMpi(s)), nil
		}}, nil
	}
	return nil, &PGPError{Msg: fmt.Sprintf("OpenPGP key algorithm %s cannot sign here", k.algName())}
}

// --- public API

type PGPSecretKeyInfo struct {
	Fpr        string
	PrimaryFpr string
	KeyAlg     string
	Version    int
	UIDs       []string
	Emails     []string
	Protected  bool
	key        *pgpKey
}

func ReadPGPSecretKey(input []byte, now time.Time) (*PGPSecretKeyInfo, error) {
	all, refused, err := parseCertsDetail(input)
	if err != nil {
		return nil, err
	}
	var certs []*pgpCert
	for _, c := range all {
		if c.primary.hasSecret() || slices.ContainsFunc(c.subkeys, func(s *pgpSubkey) bool { return s.key.hasSecret() }) {
			certs = append(certs, c)
		}
	}
	if len(certs) == 0 {
		if len(refused) > 0 {
			return nil, &PGPError{Msg: "cannot read the OpenPGP secret key: " + refused[0].Error()}
		}
		return nil, &PGPError{Msg: "no OpenPGP secret key found"}
	}
	var errs []string
	for _, c := range certs {
		var candidates []*pgpKey
		for _, s := range c.subkeys {
			candidates = append(candidates, s.key)
		}
		slices.SortStableFunc(candidates, func(a, b *pgpKey) int { return int(b.created - a.created) })
		candidates = append(candidates, c.primary)
		for _, k := range candidates {
			if !k.hasSecret() || k.priv.Dummy() {
				continue
			}
			chk := checkCert(c, k.fprHex(), "", now.Unix())
			if !chk.ok {
				errs = append(errs, chk.message)
				continue
			}
			var uids []string
			for _, u := range validUIDs(c, now.Unix()) {
				uids = append(uids, u.uid)
			}
			return &PGPSecretKeyInfo{
				Fpr: k.fprHex(), PrimaryFpr: c.primary.fprHex(), KeyAlg: k.algName(), Version: k.version,
				UIDs: uids, Emails: uniqueEmails(uids), Protected: k.priv.Encrypted, key: k,
			}, nil
		}
	}
	msg := "no usable signing key in this secret key file"
	for _, e := range refused {
		errs = append(errs, e.Error())
	}
	if len(errs) > 0 {
		msg += " (" + strings.Join(errs, "; ") + ")"
	}
	return nil, &PGPError{Msg: msg}
}

type PGPSigner interface {
	Fpr() string
	Emails() []string
	// returns one binary OpenPGP signature packet over the payload (SPEC 6.2)
	Sign(payload []byte) ([]byte, error)
}

type PGPKeySigner struct {
	fpr, keyAlg string
	uids        []string
	emails      []string
	hashAlgo    int
	now         func() time.Time
	mu          sync.Mutex
	sk          *pgpSigningKey
}

type PGPUnlockOptions struct {
	Hash string // sha256 (default), sha384, sha512
	Now  func() time.Time
}

// UnlockPGPSecretKey decrypts the key; a nil passphrase means none was given.
func UnlockPGPSecretKey(info *PGPSecretKeyInfo, passphrase []byte, o PGPUnlockOptions) (*PGPKeySigner, error) {
	hashAlgo := map[string]int{"": pgpHashSHA256, "sha256": pgpHashSHA256, "sha384": pgpHashSHA384, "sha512": pgpHashSHA512}[o.Hash]
	if hashAlgo == 0 {
		return nil, &PGPError{Msg: fmt.Sprintf("unsupported hash %q", o.Hash)}
	}
	priv, err := decryptSecret(info.key, passphrase)
	if err != nil {
		return nil, err
	}
	sk, err := importSigning(info.key, priv)
	if err != nil {
		return nil, err
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	return &PGPKeySigner{fpr: info.Fpr, keyAlg: info.KeyAlg, uids: info.UIDs, emails: info.Emails, hashAlgo: hashAlgo, now: now, sk: sk}, nil
}

func (s *PGPKeySigner) Fpr() string      { return s.fpr }
func (s *PGPKeySigner) KeyAlg() string   { return s.keyAlg }
func (s *PGPKeySigner) UIDs() []string   { return s.uids }
func (s *PGPKeySigner) Emails() []string { return s.emails }

func (s *PGPKeySigner) Sign(payload []byte) ([]byte, error) {
	s.mu.Lock()
	sk := s.sk
	s.mu.Unlock()
	if sk == nil {
		return nil, &PGPError{Msg: "this signer has been disposed"}
	}
	body, err := createSignature(sk, sigBinary, payload, pgpSigOptions{hashAlgo: s.hashAlgo, created: s.now().Unix()})
	if err != nil {
		return nil, err
	}
	out := encodePacket(pgpTagSignature, body)
	// the packet is assembled here (SPEC vectors fix its layout), so it is checked with go-crypto before it leaves
	if sig, err := readSignaturePacket(out); err != nil || !verifyRaw(sk.key, sig, subjectBytes(payload)) {
		return nil, &PGPError{Msg: "the signature just created does not verify"}
	}
	return out, nil
}

func (s *PGPKeySigner) Dispose() {
	s.mu.Lock()
	s.sk = nil
	s.mu.Unlock()
}
