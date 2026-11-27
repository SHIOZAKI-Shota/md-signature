package mdsig

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"slices"
	"time"
)

// --- RFC 5652 SignedData as used by RFC 3161

var (
	oidSignedData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidAttrContentType  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMessageDgst  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttrSigningCert  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	oidAttrSigningCert2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	oidSHA384           = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512           = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidRSAEncryption    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidRSAPSS           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidMGF1             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	oidSHA256WithRSA    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidECPublicKey      = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidECDSAWithSHA256  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

type cmsContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// encoding/asn1 ignores "optional" on a RawValue, so optional implicit fields are structs holding RawContent
type cmsRaw struct {
	Raw asn1.RawContent
}

type cmsEncapContent struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,optional,tag:0"`
}

type cmsSignerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        cmsRaw `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      cmsRaw `asn1:"optional,tag:1"`
}

type cmsSignedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo cmsEncapContent
	Certificates     cmsRaw          `asn1:"optional,tag:0"`
	CRLs             cmsRaw          `asn1:"optional,tag:1"`
	SignerInfos      []cmsSignerInfo `asn1:"set"`
}

type cmsAttribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

type cmsIssuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type rsaPSSParams struct {
	Hash       pkix.AlgorithmIdentifier `asn1:"explicit,optional,tag:0"`
	MGF        pkix.AlgorithmIdentifier `asn1:"explicit,optional,tag:1"`
	SaltLength int                      `asn1:"explicit,optional,default:20,tag:2"`
}

// SHA-1 and MD5 are rejected for both the content digest and the signature
func cmsHash(oid asn1.ObjectIdentifier) (crypto.Hash, bool) {
	switch {
	case oid.Equal(oidSHA256):
		return crypto.SHA256, true
	case oid.Equal(oidSHA384):
		return crypto.SHA384, true
	case oid.Equal(oidSHA512):
		return crypto.SHA512, true
	}
	return 0, false
}

func hashSum(h crypto.Hash, data []byte) []byte {
	switch h {
	case crypto.SHA384:
		s := sha512.Sum384(data)
		return s[:]
	case crypto.SHA512:
		s := sha512.Sum512(data)
		return s[:]
	}
	s := sha256.Sum256(data)
	return s[:]
}

type TSAVerifyOptions struct {
	// Roots are the trust anchors for the TSA certificate; nil means the system pool
	Roots *x509.CertPool
	// ExtraRoots are trusted in addition to Roots or, without it, to the system pool
	ExtraRoots []*x509.Certificate
	// CheckTSAToken only: the token's imprint is Hash(data), "sha256" (the default) or "sha512"
	Hash string

	// tests only: accept a TSA certificate without building a chain to Roots
	skipChain bool
}

const maxTSARootFileBytes = 1 << 20

// LoadTSARoots reads certificates from PEM (one or more) or DER files
func LoadTSARoots(paths []string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		b, err := io.ReadAll(io.LimitReader(f, maxTSARootFileBytes+1))
		f.Close()
		if err != nil {
			return nil, err
		}
		if len(b) > maxTSARootFileBytes {
			return nil, fmt.Errorf("%s: larger than %d bytes", p, maxTSARootFileBytes)
		}
		n := len(out)
		if bytes.Contains(b, []byte("-----BEGIN")) {
			for rest := b; ; {
				var blk *pem.Block
				if blk, rest = pem.Decode(rest); blk == nil {
					break
				}
				if blk.Type != "CERTIFICATE" {
					continue
				}
				c, err := x509.ParseCertificate(blk.Bytes)
				if err != nil {
					return nil, fmt.Errorf("%s: %v", p, err)
				}
				out = append(out, c)
			}
		} else if c, err := x509.ParseCertificate(b); err == nil {
			out = append(out, c)
		}
		if len(out) == n {
			return nil, fmt.Errorf("%s: no certificate found (PEM or DER expected)", p)
		}
	}
	return out, nil
}

// swapped by tests that must not depend on the machine's trust store
var tsaDefaultRoots = func() (*x509.CertPool, error) { return tsaSystemRoots() }

func splitDER(content []byte) ([][]byte, error) {
	var out [][]byte
	for len(content) > 0 {
		var rv asn1.RawValue
		rest, err := asn1.Unmarshal(content, &rv)
		if err != nil {
			return nil, err
		}
		out = append(out, rv.FullBytes)
		content = rest
	}
	return out, nil
}

func derHeader(tag byte, n int) []byte {
	if n < 128 {
		return []byte{tag, byte(n)}
	}
	var l []byte
	for ; n > 0; n >>= 8 {
		l = append([]byte{byte(n)}, l...)
	}
	return append([]byte{tag, 0x80 | byte(len(l))}, l...)
}

// RFC 5652 5.4: the signature covers the DER SET OF (tag 0x31, elements sorted), not the [0] IMPLICIT encoding
func signedAttrsDER(raw []byte) ([]byte, []cmsAttribute, error) {
	var outer asn1.RawValue
	if rest, err := asn1.Unmarshal(raw, &outer); err != nil || len(rest) != 0 {
		return nil, nil, errors.New("signed attributes are not valid DER")
	}
	elems, err := splitDER(outer.Bytes)
	if err != nil {
		return nil, nil, errors.New("signed attributes are not valid DER")
	}
	attrs := make([]cmsAttribute, len(elems))
	for i, e := range elems {
		if rest, err := asn1.Unmarshal(e, &attrs[i]); err != nil || len(rest) != 0 {
			return nil, nil, errors.New("signed attribute is not valid DER")
		}
		if slices.ContainsFunc(attrs[:i], func(a cmsAttribute) bool { return a.Type.Equal(attrs[i].Type) }) {
			return nil, nil, fmt.Errorf("signed attribute %s appears twice", attrs[i].Type)
		}
	}
	slices.SortFunc(elems, bytes.Compare)
	body := bytes.Join(elems, nil)
	return append(derHeader(0x31, len(body)), body...), attrs, nil
}

func attrValue(attrs []cmsAttribute, oid asn1.ObjectIdentifier) ([]byte, bool, error) {
	for _, a := range attrs {
		if !a.Type.Equal(oid) {
			continue
		}
		vals, err := splitDER(a.Values.Bytes)
		if err != nil || a.Values.Tag != asn1.TagSet || len(vals) != 1 {
			return nil, true, fmt.Errorf("signed attribute %s must have exactly one value", oid)
		}
		return vals[0], true, nil
	}
	return nil, false, nil
}

func findSignerCert(sid asn1.RawValue, certs []*x509.Certificate) *x509.Certificate {
	if sid.Class == asn1.ClassContextSpecific && sid.Tag == 0 {
		for _, c := range certs {
			if len(c.SubjectKeyId) > 0 && bytes.Equal(c.SubjectKeyId, sid.Bytes) {
				return c
			}
		}
		return nil
	}
	var ias cmsIssuerAndSerial
	if rest, err := asn1.Unmarshal(sid.FullBytes, &ias); err != nil || len(rest) != 0 || ias.Serial == nil {
		return nil
	}
	for _, c := range certs {
		if bytes.Equal(c.RawIssuer, ias.Issuer.FullBytes) && c.SerialNumber.Cmp(ias.Serial) == 0 {
			return c
		}
	}
	return nil
}

// RFC 3161 2.4.2 / RFC 5816: the first ESSCertID(v2) names the certificate that signed the token
func checkSigningCertAttr(attrs []cmsAttribute, cert *x509.Certificate) error {
	v2, has2, err := attrValue(attrs, oidAttrSigningCert2)
	if err != nil {
		return err
	}
	v1, has1, err := attrValue(attrs, oidAttrSigningCert)
	if err != nil {
		return err
	}
	if !has1 && !has2 {
		return errors.New("no signing-certificate attribute")
	}
	first := func(v []byte) (*der, error) {
		n, _, err := parseDer(v, 0)
		if err != nil {
			return nil, err
		}
		id := n.child(0).child(0)
		if id == nil || id.tag != 0x30 {
			return nil, errors.New("signing-certificate attribute is malformed")
		}
		return id, nil
	}
	if has2 {
		id, err := first(v2)
		if err != nil {
			return err
		}
		h, hashNode := crypto.SHA256, id.child(0)
		if hashNode != nil && hashNode.tag == 0x30 {
			var alg pkix.AlgorithmIdentifier
			if _, err := asn1.Unmarshal(hashNode.raw, &alg); err != nil {
				return errors.New("signing-certificate attribute is malformed")
			}
			var ok bool
			if h, ok = cmsHash(alg.Algorithm); !ok {
				return fmt.Errorf("signing-certificate hash %s is not supported", alg.Algorithm)
			}
			hashNode = id.child(1)
		}
		if hashNode == nil || hashNode.tag != 0x04 || !bytes.Equal(hashNode.content, hashSum(h, cert.Raw)) {
			return errors.New("signing-certificate attribute does not match the TSA certificate")
		}
	}
	if has1 {
		id, err := first(v1)
		if err != nil {
			return err
		}
		// ESSCertID is defined with SHA-1; it only binds the certificate that the signature already names
		sum := sha1.Sum(cert.Raw)
		if h := id.child(0); h == nil || h.tag != 0x04 || !bytes.Equal(h.content, sum[:]) {
			return errors.New("signing-certificate attribute does not match the TSA certificate")
		}
	}
	return nil
}

func verifyCMSSignature(cert *x509.Certificate, alg pkix.AlgorithmIdentifier, digestHash crypto.Hash, signed, sig []byte) error {
	h := digestHash
	oid := alg.Algorithm
	named := func(want crypto.Hash) { h = want }
	switch {
	case oid.Equal(oidSHA256WithRSA), oid.Equal(oidECDSAWithSHA256):
		named(crypto.SHA256)
	case oid.Equal(oidSHA384WithRSA), oid.Equal(oidECDSAWithSHA384):
		named(crypto.SHA384)
	case oid.Equal(oidSHA512WithRSA), oid.Equal(oidECDSAWithSHA512):
		named(crypto.SHA512)
	}
	switch {
	case oid.Equal(oidRSAEncryption), oid.Equal(oidSHA256WithRSA), oid.Equal(oidSHA384WithRSA), oid.Equal(oidSHA512WithRSA):
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("signature algorithm is RSA but the TSA certificate key is not")
		}
		if pub.N.BitLen() < 2048 {
			return errors.New("TSA RSA key is shorter than 2048 bits")
		}
		if rsa.VerifyPKCS1v15(pub, h, hashSum(h, signed), sig) != nil {
			return errors.New("signature does not verify with the TSA certificate")
		}
		return nil
	case oid.Equal(oidRSAPSS):
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("signature algorithm is RSA-PSS but the TSA certificate key is not")
		}
		if pub.N.BitLen() < 2048 {
			return errors.New("TSA RSA key is shorter than 2048 bits")
		}
		var p rsaPSSParams
		if rest, err := asn1.Unmarshal(alg.Parameters.FullBytes, &p); err != nil || len(rest) != 0 {
			return errors.New("RSA-PSS parameters are malformed")
		}
		ph, ok := cmsHash(p.Hash.Algorithm)
		if !ok {
			return errors.New("RSA-PSS hash is not SHA-256, SHA-384, or SHA-512")
		}
		var mgfHash pkix.AlgorithmIdentifier
		if !p.MGF.Algorithm.Equal(oidMGF1) {
			return errors.New("RSA-PSS mask generation function is not MGF1")
		}
		if _, err := asn1.Unmarshal(p.MGF.Parameters.FullBytes, &mgfHash); err != nil || !mgfHash.Algorithm.Equal(p.Hash.Algorithm) {
			return errors.New("RSA-PSS MGF1 hash differs from the message hash")
		}
		if rsa.VerifyPSS(pub, ph, hashSum(ph, signed), sig, &rsa.PSSOptions{SaltLength: p.SaltLength, Hash: ph}) != nil {
			return errors.New("signature does not verify with the TSA certificate")
		}
		return nil
	case oid.Equal(oidECPublicKey), oid.Equal(oidECDSAWithSHA256), oid.Equal(oidECDSAWithSHA384), oid.Equal(oidECDSAWithSHA512):
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("signature algorithm is ECDSA but the TSA certificate key is not")
		}
		if !ecdsa.VerifyASN1(pub, hashSum(h, signed), sig) {
			return errors.New("signature does not verify with the TSA certificate")
		}
		return nil
	}
	return fmt.Errorf("signature algorithm %s is not supported", oid)
}

func certDisplayName(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	if len(c.Subject.Organization) > 0 {
		return c.Subject.Organization[0]
	}
	return c.Subject.String()
}

// verifies the token's CMS signature and certificate chain; returns the authenticated eContent and the TSA certificate
func verifyTSASignedData(token []byte, genTime time.Time, o *TSAVerifyOptions) ([]byte, *x509.Certificate, error) {
	if o == nil {
		o = &TSAVerifyOptions{}
	}
	var ci cmsContentInfo
	if rest, err := asn1.Unmarshal(token, &ci); err != nil || len(rest) != 0 {
		return nil, nil, errors.New("token is not DER-encoded CMS")
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, nil, errors.New("token is not CMS SignedData")
	}
	var sd cmsSignedData
	if rest, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil || len(rest) != 0 {
		return nil, nil, errors.New("SignedData is not valid DER")
	}
	if !sd.EncapContentInfo.EContentType.Equal(oidTSTInfo) {
		return nil, nil, errors.New("content type is not id-ct-TSTInfo")
	}
	eContent := sd.EncapContentInfo.EContent
	if len(eContent) == 0 {
		return nil, nil, errors.New("eContent is missing")
	}
	if len(sd.SignerInfos) != 1 {
		return nil, nil, fmt.Errorf("token has %d SignerInfos, want exactly 1", len(sd.SignerInfos))
	}
	si := sd.SignerInfos[0]

	var certs []*x509.Certificate
	if len(sd.Certificates.Raw) > 0 {
		var set asn1.RawValue
		if _, err := asn1.Unmarshal(sd.Certificates.Raw, &set); err != nil {
			return nil, nil, errors.New("certificates are not valid DER")
		}
		elems, err := splitDER(set.Bytes)
		if err != nil {
			return nil, nil, errors.New("certificates are not valid DER")
		}
		for _, e := range elems {
			// other CertificateChoices (attribute certificates) are skipped
			if c, err := x509.ParseCertificate(e); err == nil {
				certs = append(certs, c)
			}
		}
	}
	cert := findSignerCert(si.SID, certs)
	if cert == nil {
		return nil, nil, errors.New("TSA certificate is not included in the token")
	}

	digestHash, ok := cmsHash(si.DigestAlgorithm.Algorithm)
	if !ok {
		return nil, nil, fmt.Errorf("digest algorithm %s is not SHA-256, SHA-384, or SHA-512", si.DigestAlgorithm.Algorithm)
	}
	// RFC 3161 2.4.2 requires the signing-certificate attribute, so a token without signed attributes is rejected
	if len(si.SignedAttrs.Raw) == 0 {
		return nil, nil, errors.New("token has no signed attributes")
	}
	signed, attrs, err := signedAttrsDER(si.SignedAttrs.Raw)
	if err != nil {
		return nil, nil, err
	}
	ct, has, err := attrValue(attrs, oidAttrContentType)
	if err != nil {
		return nil, nil, err
	}
	var ctOID asn1.ObjectIdentifier
	if !has {
		return nil, nil, errors.New("signed attributes have no content-type")
	}
	if _, err := asn1.Unmarshal(ct, &ctOID); err != nil || !ctOID.Equal(oidTSTInfo) {
		return nil, nil, errors.New("signed content-type is not id-ct-TSTInfo")
	}
	md, has, err := attrValue(attrs, oidAttrMessageDgst)
	if err != nil {
		return nil, nil, err
	}
	var digest []byte
	if !has {
		return nil, nil, errors.New("signed attributes have no message-digest")
	}
	if _, err := asn1.Unmarshal(md, &digest); err != nil || !bytes.Equal(digest, hashSum(digestHash, eContent)) {
		return nil, nil, errors.New("message-digest does not match the TSTInfo")
	}
	if err := checkSigningCertAttr(attrs, cert); err != nil {
		return nil, nil, err
	}
	if err := verifyCMSSignature(cert, si.SignatureAlgorithm, digestHash, signed, si.Signature); err != nil {
		return nil, nil, err
	}

	if !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageTimeStamping) {
		return nil, nil, errors.New("TSA certificate lacks the timeStamping extended key usage")
	}
	if genTime.Before(cert.NotBefore) || genTime.After(cert.NotAfter) {
		return nil, nil, errors.New("TSA certificate was not valid at the token's time")
	}
	if !o.skipChain {
		roots := o.Roots
		if roots == nil {
			sys, err := tsaDefaultRoots()
			if err != nil {
				return nil, nil, fmt.Errorf("system root certificates are not available: %v", err)
			}
			roots = sys
		}
		if len(o.ExtraRoots) > 0 {
			roots = roots.Clone()
			for _, c := range o.ExtraRoots {
				roots.AddCert(c)
			}
		}
		inter := x509.NewCertPool()
		for _, c := range certs {
			if c != cert {
				inter.AddCert(c)
			}
		}
		// a timestamp stays valid after the TSA certificate expires, so the chain is checked at genTime
		_, err := cert.Verify(x509.VerifyOptions{
			Roots: roots, Intermediates: inter, CurrentTime: genTime,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		})
		if err != nil {
			return nil, nil, fmt.Errorf("TSA certificate does not chain to a trusted root: %v", err)
		}
	}
	return eContent, cert, nil
}
