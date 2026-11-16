package mdsig

import (
	"bytes"
	"crypto"
	"crypto/rand"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

const (
	pgpHashSHA1   = 2
	pgpHashSHA256 = 8
	pgpHashSHA384 = 9
	pgpHashSHA512 = 10
)

var pgpHashes = map[int]crypto.Hash{2: crypto.SHA1, 8: crypto.SHA256, 9: crypto.SHA384, 10: crypto.SHA512}

// RFC 9580 Table 23: v6 signature salt sizes
var pgpSaltSize = map[int]int{8: 16, 9: 24, 10: 32}

var pgpDocumentHashes = map[int]bool{8: true, 9: true, 10: true}

// RFC 9580 9.5: SHA-1 self-signatures are tolerated only if made before 2023-02-01
const pgpSHA1Cutoff = 1675209600

const (
	sigBinary           = 0x00
	sigCertPositive     = 0x13
	sigSubkeyBinding    = 0x18
	sigPrimaryBinding   = 0x19
	sigDirectKey        = 0x1f
	sigKeyRevocation    = 0x20
	sigSubkeyRevocation = 0x28
	sigCertRevocation   = 0x30
)

const (
	subCreated     = 2
	subSigExpiry   = 3
	subKeyExpiry   = 9
	subIssuerKeyID = 16
	subPrimaryUID  = 25
	subKeyFlags    = 27
	subEmbedded    = 32
	subIssuerFp    = 33
)

// subpackets whose meaning is understood well enough to honour a critical bit
var pgpUnderstood = map[int]bool{2: true, 3: true, 4: true, 9: true, 11: true, 16: true, 21: true, 22: true, 23: true, 24: true, 25: true, 26: true, 27: true, 28: true, 29: true, 30: true, 31: true, 32: true, 33: true, 34: true, 35: true, 37: true, 39: true}

type pgpSignature struct {
	version  int
	typ      int
	pubAlgo  int
	hashAlgo int
	header   []byte
	hashed   []pgpSubpacket
	unhashed []pgpSubpacket
	left16   []byte
	raw      []byte
	// the same packet as go-crypto reads it; nil (with libErr) when it refuses the packet
	lib    *packet.Signature
	libErr error
}

// the structure is read here so that the SPEC 6.2 rules see the exact subpacket areas; all cryptography goes through lib
func parseSignature(body []byte) (sig *pgpSignature, err error) {
	defer catchPgp(&err)
	r := &pgpReader{b: body}
	version := r.u8()
	if version != 4 && version != 6 {
		pgpFail(fmt.Sprintf("unsupported signature version %d", version))
	}
	start := r.o - 1
	s := &pgpSignature{version: version, typ: r.u8(), pubAlgo: r.u8(), hashAlgo: r.u8(), raw: body}
	areaLen := func() int64 {
		if version == 4 {
			return int64(r.u16())
		}
		return r.u32()
	}
	harea := r.bytes(areaLen())
	s.header = body[start:r.o]
	uarea := r.bytes(areaLen())
	s.left16 = r.bytes(2)
	s.hashed = readSubpackets(harea)
	s.unhashed = readSubpackets(uarea)

	in := bytes.NewReader(encodePacket(pgpTagSignature, body))
	p, perr := packet.Read(in)
	lib, ok := p.(*packet.Signature)
	switch {
	case perr != nil:
		s.libErr = perr
	case !ok:
		s.libErr = &PGPError{Msg: "not a signature packet"}
	case in.Len() != 0:
		s.libErr = &PGPError{Msg: "trailing data in signature packet"}
	case !bytes.HasPrefix(lib.HashSuffix, s.header):
		// both readers must agree on the bytes that are hashed
		s.libErr = &PGPError{Msg: "signature packet is read inconsistently"}
	default:
		s.lib = lib
	}
	return s, nil
}

func (s *pgpSignature) sub(typ int, hashedOnly bool) []byte {
	for _, p := range s.hashed {
		if p.typ == typ {
			return p.data
		}
	}
	if !hashedOnly {
		for _, p := range s.unhashed {
			if p.typ == typ {
				return p.data
			}
		}
	}
	return nil
}

func (s *pgpSignature) created() (int64, bool) {
	d := s.sub(subCreated, true)
	if len(d) != 4 {
		return 0, false
	}
	return int64(binary.BigEndian.Uint32(d)), true
}

func (s *pgpSignature) issuerFp() []byte {
	d := s.sub(subIssuerFp, s.version == 4)
	if len(d) > 1 {
		return d[1:]
	}
	return nil
}

func (s *pgpSignature) keyFlags() (int, bool) {
	d := s.sub(subKeyFlags, true)
	if len(d) == 0 {
		return 0, false
	}
	return int(d[0]), true
}

func (s *pgpSignature) keyExpiry() int64 {
	d := s.sub(subKeyExpiry, true)
	if len(d) != 4 {
		return 0
	}
	return int64(binary.BigEndian.Uint32(d))
}

func (s *pgpSignature) unknownCritical() (int, bool) {
	for _, area := range [][]pgpSubpacket{s.hashed, s.unhashed} {
		for _, p := range area {
			if p.critical && !pgpUnderstood[p.typ] {
				return p.typ, true
			}
		}
	}
	return 0, false
}

func (s *pgpSignature) embeddedSignatures() []*pgpSignature {
	var out []*pgpSignature
	for _, area := range [][]pgpSubpacket{s.hashed, s.unhashed} {
		for _, p := range area {
			if p.typ != subEmbedded {
				continue
			}
			if e, err := parseSignature(p.data); err == nil {
				out = append(out, e)
			}
		}
	}
	return out
}

// --- verification (go-crypto does the hashing and the public-key operation)

type pgpSubject func(w io.Writer)

func subjectBytes(b []byte) pgpSubject { return func(w io.Writer) { w.Write(b) } }

func subjectKeys(keys ...*pgpKey) pgpSubject {
	return func(w io.Writer) {
		for _, k := range keys {
			_ = k.pub.SerializeForHash(w)
		}
	}
}

// RFC 9580 5.2.4: a user ID is hashed as 0xB4, a four-octet length and the user ID
func subjectUID(k *pgpKey, uid []byte) pgpSubject {
	return func(w io.Writer) {
		_ = k.pub.SerializeForHash(w)
		w.Write(concatBytes([]byte{0xb4}, u32be(int64(len(uid))), uid))
	}
}

func verifyRaw(key *pgpKey, sig *pgpSignature, subject pgpSubject) bool {
	if sig.lib == nil || sig.pubAlgo != key.algo || sig.version != key.version {
		return false
	}
	h, err := sig.lib.PrepareVerify()
	if err != nil {
		return false
	}
	subject(h)
	if key.pub.VerifySignature(h, sig.lib) != nil {
		return false
	}
	// go-crypto compares the two-octet hash prefix only for v6; SPEC 6.2 signatures keep it for v4 as well
	return bytes.Equal(h.Sum(nil)[:2], sig.left16)
}

// every rule a self-signature must satisfy apart from the cryptographic check
func selfSigUsable(sig *pgpSignature, issuer *pgpKey, now int64) bool {
	if _, bad := sig.unknownCritical(); bad {
		return false
	}
	created, ok := sig.created()
	if !ok {
		return false
	}
	if sig.hashAlgo == pgpHashSHA1 {
		if created >= pgpSHA1Cutoff {
			return false
		}
	} else if !pgpDocumentHashes[sig.hashAlgo] {
		return false
	}
	if exp := sig.sub(subSigExpiry, true); len(exp) == 4 {
		if e := int64(binary.BigEndian.Uint32(exp)); e != 0 && created+e <= now {
			return false
		}
	}
	if fp := sig.issuerFp(); fp != nil && !bytes.Equal(fp, issuer.fingerprint) {
		return false
	}
	return true
}

// --- signature creation

type pgpSigningKey struct {
	key *pgpKey
	// returns the algorithm-specific signature material, already encoded (MPIs or raw)
	sign func(h crypto.Hash, digest []byte) ([]byte, error)
}

type pgpSigOptions struct {
	hashAlgo int
	created  int64
	hashed   [][]byte
	salt     []byte
}

func createSignature(sk *pgpSigningKey, typ int, subject []byte, o pgpSigOptions) ([]byte, error) {
	key := sk.key
	hashAlgo := o.hashAlgo
	if hashAlgo == 0 {
		hashAlgo = pgpHashSHA256
	}
	h, ok := pgpHashes[hashAlgo]
	if !ok {
		return nil, &PGPError{Msg: fmt.Sprintf("unsupported hash %d", hashAlgo)}
	}
	created := o.created
	if created == 0 {
		created = time.Now().Unix()
	}
	area := concatBytes(encodeSubpacket(subCreated, u32be(created)), encodeSubpacket(subIssuerFp, concatBytes([]byte{byte(key.version)}, key.fingerprint)))
	for _, x := range o.hashed {
		area = append(area, x...)
	}
	v := key.version
	areaLen := u16be(len(area))
	if v == 6 {
		areaLen = u32be(int64(len(area)))
	}
	header := concatBytes([]byte{byte(v), byte(typ), byte(key.algo), byte(hashAlgo)}, areaLen, area)
	salt := []byte{}
	if v == 6 {
		salt = o.salt
		if salt == nil {
			size, ok := pgpSaltSize[hashAlgo]
			if !ok {
				size = 16
			}
			salt = make([]byte, size)
			if _, err := rand.Read(salt); err != nil {
				return nil, err
			}
		}
	}
	data := concatBytes(salt, subject, header, []byte{byte(v), 0xff}, u32be(int64(len(header))))
	hw := h.New()
	hw.Write(data)
	digest := hw.Sum(nil)
	material, err := sk.sign(h, digest)
	if err != nil {
		return nil, err
	}
	var unhashed []byte
	if v == 4 {
		unhashed = encodeSubpacket(subIssuerKeyID, key.keyID)
	}
	unhashedLen := u16be(len(unhashed))
	saltField := []byte{}
	if v == 6 {
		unhashedLen = u32be(int64(len(unhashed)))
		saltField = concatBytes([]byte{byte(len(salt))}, salt)
	}
	return concatBytes(header, unhashedLen, unhashed, digest[:2], saltField, material), nil
}

func readSignaturePacket(b []byte) (*pgpSignature, error) {
	packets, err := readPackets(b)
	if err != nil {
		return nil, err
	}
	if len(packets) != 1 || packets[0].tag != pgpTagSignature {
		return nil, &PGPError{Msg: "sig must contain exactly one OpenPGP signature packet"}
	}
	return parseSignature(packets[0].body)
}
