package sshkeys

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/SHIOZAKI-Shota/md-signature/mdsig"
)

var ErrPassphraseNeeded = errors.New("the key file is passphrase-protected")

func LoadPrivateKeyFile(path string, passphrase func() ([]byte, error)) (mdsig.KeySigner, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return mdsig.KeySigner{}, err
	}
	return ParsePrivateKey(data, passphrase)
}

func ParsePrivateKey(data []byte, passphrase func() ([]byte, error)) (mdsig.KeySigner, error) {
	raw, err := ssh.ParseRawPrivateKey(data)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		if passphrase == nil {
			return mdsig.KeySigner{}, ErrPassphraseNeeded
		}
		pw, perr := passphrase()
		if perr != nil {
			return mdsig.KeySigner{}, perr
		}
		raw, err = ssh.ParseRawPrivateKeyWithPassphrase(data, pw)
		if errors.Is(err, x509.IncorrectPasswordError) {
			return mdsig.KeySigner{}, errors.New("incorrect passphrase")
		}
	}
	if err != nil {
		return mdsig.KeySigner{}, err
	}
	switch k := raw.(type) {
	case ed25519.PrivateKey:
		return mdsig.KeySigner{Key: k}, nil
	case *ed25519.PrivateKey:
		return mdsig.KeySigner{Key: *k}, nil
	default:
		return mdsig.KeySigner{}, fmt.Errorf("unsupported key type %T: md-signature 0.0.1 needs an Ed25519 key", raw)
	}
}

func DefaultKeyPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ssh", "id_ed25519"), nil
}

type AgentKey struct {
	Agent   agent.Agent
	Key     *agent.Key
	Comment string
}

func (a AgentKey) PublicKey() ed25519.PublicKey {
	pk, err := ssh.ParsePublicKey(a.Key.Blob)
	if err != nil {
		return nil
	}
	if cpk, ok := pk.(ssh.CryptoPublicKey); ok {
		if ek, ok := cpk.CryptoPublicKey().(ed25519.PublicKey); ok {
			return ek
		}
	}
	return nil
}

// SPEC 4.2: for ssh-ed25519 the agent returns the raw Ed25519 signature in sig.Blob
func (a AgentKey) Sign(data []byte) ([]byte, error) {
	sig, err := a.Agent.Sign(a.Key, data)
	if err != nil {
		return nil, fmt.Errorf("ssh-agent: %w", err)
	}
	if sig.Format != ssh.KeyAlgoED25519 || len(sig.Blob) != ed25519.SignatureSize {
		return nil, fmt.Errorf("ssh-agent returned an unexpected %s signature", sig.Format)
	}
	return sig.Blob, nil
}

func (a AgentKey) Fingerprint() string { return mdsig.SSHFingerprint(a.PublicKey()) }

func OpenAgent() (agent.Agent, io.Closer, error) {
	conn, err := dialAgent()
	if err != nil || conn == nil {
		return nil, nil, err
	}
	return agent.NewClient(conn), conn, nil
}

func ListEd25519(ag agent.Agent) ([]AgentKey, error) {
	keys, err := ag.List()
	if err != nil {
		return nil, err
	}
	var out []AgentKey
	for _, k := range keys {
		if k.Format != ssh.KeyAlgoED25519 {
			continue
		}
		ak := AgentKey{Agent: ag, Key: k, Comment: k.Comment}
		if ak.PublicKey() != nil {
			out = append(out, ak)
		}
	}
	return out, nil
}

func dialUnix(path string) (net.Conn, error) { return net.Dial("unix", path) }

func GenerateKeyPair(prefix, comment string) (ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return pub, WriteKeyPair(prefix, comment, priv)
}

func WriteKeyPair(prefix, comment string, priv ed25519.PrivateKey) error {
	pubPath := prefix + ".pub"
	for _, p := range []string{prefix, pubPath} {
		if _, err := os.Lstat(p); err == nil {
			return &os.PathError{Op: "create", Path: p, Err: os.ErrExist}
		}
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return err
	}
	if err := writeExclusive(prefix, pem.EncodeToMemory(block), 0o600); err != nil {
		return err
	}
	line := mdsig.FormatSSHPublicKey(priv.Public().(ed25519.PublicKey), comment) + "\n"
	if err := writeExclusive(pubPath, []byte(line), 0o644); err != nil {
		_ = os.Remove(prefix)
		return err
	}
	return nil
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	return f.Close()
}
