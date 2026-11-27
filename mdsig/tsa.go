package mdsig

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const DefaultTSAURL = "http://ts.ssl.com"

var (
	oidSHA256  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidTSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
)

// mirrors the TS tiny DER parser so both accept the same tokens
type der struct {
	tag      byte
	content  []byte
	raw      []byte
	children []*der
}

// a real TimeStampResp nests about 10 levels
const maxDerDepth = 32

func parseDer(b []byte, offset int) (*der, int, error) {
	return parseDerAt(b, offset, 0)
}

func parseDerAt(b []byte, offset, depth int) (*der, int, error) {
	if depth > maxDerDepth {
		return nil, 0, errors.New("DER: nested too deeply")
	}
	if offset+2 > len(b) {
		return nil, 0, errors.New("DER: truncated")
	}
	tag := b[offset]
	if tag&0x1f == 0x1f {
		return nil, 0, errors.New("DER: multi-byte tags not supported")
	}
	l := int(b[offset+1])
	hdr := 2
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 {
			return nil, 0, errors.New("DER: bad length")
		}
		l = 0
		for i := 0; i < n; i++ {
			if offset+2+i >= len(b) {
				return nil, 0, errors.New("DER: truncated")
			}
			l = l*256 + int(b[offset+2+i])
		}
		hdr += n
	}
	start := offset + hdr
	end := start + l
	if end > len(b) || end < start {
		return nil, 0, errors.New("DER: length exceeds data")
	}
	node := &der{tag: tag, content: b[start:end], raw: b[offset:end]}
	if tag&0x20 != 0 {
		o := 0
		for o < len(node.content) {
			c, next, err := parseDerAt(node.content, o, depth+1)
			if err != nil {
				return nil, 0, err
			}
			node.children = append(node.children, c)
			o = next
		}
	}
	return node, end, nil
}

func (d *der) child(i int) *der {
	if d == nil || i >= len(d.children) {
		return nil
	}
	return d.children[i]
}

type tstInfo struct {
	Status  int
	HashOID string
	Imprint []byte
	GenTime string
	Policy  string
	Serial  string
	// Nonce is the content of the INTEGER, nil when the token has none
	Nonce []byte
	// TSTInfo accuracy in milliseconds, rounded up; 0 when absent (SPEC 4.6)
	AccuracyMs int64

	token    []byte
	eContent []byte
}

func oidToString(c []byte) string {
	if len(c) == 0 {
		return ""
	}
	parts := []string{strconv.Itoa(int(c[0]) / 40), strconv.Itoa(int(c[0]) % 40)}
	v := 0
	for _, x := range c[1:] {
		v = v*128 + int(x&0x7f)
		if x&0x80 == 0 {
			parts = append(parts, strconv.Itoa(v))
			v = 0
		}
	}
	return strings.Join(parts, ".")
}

var genTimeRe = regexp.MustCompile(`^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z$`)

func parseGeneralizedTime(s string) (string, error) {
	m := genTimeRe.FindStringSubmatch(s)
	if m == nil {
		return "", errors.New("timestamp token: genTime is not a GeneralizedTime")
	}
	return fmt.Sprintf("%s-%s-%sT%s:%s:%s%sZ", m[1], m[2], m[3], m[4], m[5], m[6], m[7]), nil
}

func derUint(b []byte) int64 {
	var v int64
	for _, x := range b {
		v = v*256 + int64(x)
	}
	return v
}

// Accuracy ::= SEQUENCE { seconds INTEGER OPTIONAL, millis [0] INTEGER OPTIONAL, micros [1] INTEGER OPTIONAL }
func accuracyMs(acc *der) int64 {
	var us int64
	for _, c := range acc.children {
		switch c.tag {
		case 0x02:
			us += derUint(c.content) * 1_000_000
		case 0x80:
			us += derUint(c.content) * 1000
		case 0x81:
			us += derUint(c.content)
		}
	}
	return (us + 999) / 1000
}

func parseTimeStampResp(b []byte) (*tstInfo, error) {
	root, _, err := parseDer(b, 0)
	if err != nil {
		return nil, err
	}
	status := 0
	var token *der
	if c0 := root.child(0); c0 != nil && c0.tag == 0x30 {
		status = 2
		if s := c0.child(0); s != nil && len(s.content) > 0 {
			status = int(s.content[0])
		}
		token = root.child(1)
		if token == nil {
			return nil, fmt.Errorf("TSA response has no token (status %d)", status)
		}
	} else {
		token = root
	}
	signedData := token.child(1).child(0)
	if signedData == nil || signedData.children == nil {
		return nil, errors.New("timestamp token: SignedData not found")
	}
	encap := signedData.child(2)
	eType := encap.child(0)
	wantType, _ := asn1.Marshal(oidTSTInfo)
	if eType == nil || !bytes.Equal(eType.content, wantType[2:]) {
		return nil, errors.New("timestamp token: content is not TSTInfo")
	}
	octets := encap.child(1).child(0)
	if octets == nil {
		return nil, errors.New("timestamp token: eContent missing")
	}
	tst, _, err := parseDer(octets.content, 0)
	if err != nil {
		return nil, err
	}
	policy, mi, serial, gen := tst.child(1), tst.child(2), tst.child(3), tst.child(4)
	if policy == nil || mi == nil || serial == nil || gen == nil {
		return nil, errors.New("timestamp token: malformed TSTInfo")
	}
	genTime, err := parseGeneralizedTime(string(gen.content))
	if err != nil {
		return nil, err
	}
	info := &tstInfo{
		Status:   status,
		GenTime:  genTime,
		Policy:   oidToString(policy.content),
		Serial:   toHex(serial.content),
		token:    token.raw,
		eContent: octets.content,
	}
	// after genTime: accuracy (SEQUENCE), ordering (BOOLEAN), nonce (INTEGER), tsa [0], extensions [1]
	for _, c := range tst.children[5:] {
		if c.tag == 0x02 {
			info.Nonce = c.content
			break
		}
	}
	for _, c := range tst.children[5:] {
		if c.tag == 0x30 {
			info.AccuracyMs = accuracyMs(c)
			break
		}
	}
	if alg := mi.child(0).child(0); alg != nil {
		info.HashOID = oidToString(alg.content)
	}
	if h := mi.child(1); h != nil {
		info.Imprint = h.content
	}
	return info, nil
}

const (
	TSAOK       = "ok"
	TSAMismatch = "mismatch"
	TSAError    = "error"
)

type TSACheck struct {
	Status string
	// GenTime is set only when Verified is true, so an unauthenticated time is never shown as evidence
	GenTime string
	// set with GenTime
	AccuracyMs int64
	Detail     string
	Verified   bool
	Signer     string
}

// the imprint is H(data), H = o.Hash (sha256 when empty), as the HTTP API (CLI_SPEC 3.6) and VerifyOptions.TSAVerifier need
func CheckTSAToken(tsaToken string, data []byte, o *TSAVerifyOptions) TSACheck {
	h := "sha256"
	if o != nil && o.Hash != "" {
		h = o.Hash
	}
	return checkTimestampOver(tsaToken, digestBytes(h, data), h, o, "message imprint does not match "+strings.ToUpper(h)+"(data)")
}

// a token over an imprint the caller computed, for example the payload of a tsa block (SPEC 4.6)
func checkTimestampOver(token string, imprint []byte, hashAlg string, o *TSAVerifyOptions, mismatchDetail string) TSACheck {
	b, err := DecodePrefixedBinary(token)
	if err != nil {
		return TSACheck{Status: TSAError, Detail: err.Error()}
	}
	info, cert, err := verifyTimeStampResp(b, imprint, o, hashAlg)
	var ie *tsaImprintError
	switch {
	case errors.As(err, &ie):
		return TSACheck{Status: TSAMismatch, Detail: mismatchDetail}
	case err != nil && info != nil:
		return TSACheck{Status: TSAError, Detail: "imprint matched; TSA signature not verified: " + err.Error()}
	case err != nil:
		return TSACheck{Status: TSAError, Detail: err.Error()}
	}
	signer := certDisplayName(cert)
	return TSACheck{Status: TSAOK, GenTime: info.GenTime, AccuracyMs: info.AccuracyMs, Verified: true, Signer: signer, Detail: "imprint matched; TSA signature verified (" + signer + ")"}
}

type tsaImprintError struct{}

func (*tsaImprintError) Error() string { return "timestamp token is for a different imprint" }

// info is non-nil once the imprint matched, also when the CMS check then fails
func imprintOID(hashAlg string) asn1.ObjectIdentifier {
	if hashAlg == "sha512" {
		return oidSHA512
	}
	return oidSHA256
}

func verifyTimeStampResp(resp, imprint []byte, o *TSAVerifyOptions, hashAlg string) (*tstInfo, *x509.Certificate, error) {
	info, err := parseTimeStampResp(resp)
	if err != nil {
		return nil, nil, err
	}
	if info.Status != 0 && info.Status != 1 {
		return nil, nil, fmt.Errorf("TSA status %d (not granted)", info.Status)
	}
	if info.HashOID != imprintOID(hashAlg).String() {
		return nil, nil, errors.New("unsupported imprint hash " + info.HashOID)
	}
	if !bytes.Equal(imprint, info.Imprint) {
		return nil, nil, &tsaImprintError{}
	}
	genTime, err := time.Parse(time.RFC3339Nano, info.GenTime)
	if err != nil {
		return info, nil, errors.New("genTime is not a valid date")
	}
	eContent, cert, err := verifyTSASignedData(info.token, genTime, o)
	if err != nil {
		return info, nil, err
	}
	// the fields above were read by the lenient parser; they count only if they come from the signed bytes
	if !bytes.Equal(eContent, info.eContent) {
		return info, nil, errors.New("TSTInfo is encoded ambiguously")
	}
	return info, cert, nil
}

type messageImprint struct {
	HashAlgorithm struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue
	}
	HashedMessage []byte
}

type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	Nonce          *big.Int
	CertReq        bool
}

func buildTimeStampReq(imprint []byte, nonce []byte, hashAlg string) ([]byte, error) {
	if nonce == nil {
		nonce = make([]byte, 8)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
	}
	var r timeStampReq
	r.Version = 1
	r.MessageImprint.HashAlgorithm.Algorithm = imprintOID(hashAlg)
	r.MessageImprint.HashAlgorithm.Parameters = asn1.NullRawValue
	r.MessageImprint.HashedMessage = imprint
	r.Nonce = new(big.Int).SetBytes(nonce)
	r.CertReq = true
	return asn1.Marshal(r)
}

// RequestTimestamp asks a TSA for a token over SHA-256(data) and verifies the response; client and o may be nil
func RequestTimestamp(ctx context.Context, data []byte, tsaURL string, client *http.Client, o *TSAVerifyOptions) (string, error) {
	sum := sha256.Sum256(data)
	return requestTimestampOver(ctx, sum[:], "sha256", tsaURL, client, o)
}

func requestTimestampOver(ctx context.Context, imprint []byte, hashAlg, tsaURL string, client *http.Client, o *TSAVerifyOptions) (string, error) {
	if tsaURL == "" {
		tsaURL = DefaultTSAURL
	}
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	reqDer, err := buildTimeStampReq(imprint, nonce, hashAlg)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tsaURL, bytes.NewReader(reqDer))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/timestamp-query")
	if client == nil {
		client = http.DefaultClient
	}
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return "", fmt.Errorf("TSA HTTP %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, MaxDecodedBytes+1))
	if err != nil {
		return "", err
	}
	// a larger token could not be decoded again by a verifier
	if len(body) > MaxDecodedBytes {
		return "", fmt.Errorf("TSA response is larger than %d bytes", MaxDecodedBytes)
	}
	info, _, err := verifyTimeStampResp(body, imprint, o, hashAlg)
	if err != nil {
		return "", fmt.Errorf("TSA response rejected: %w", err)
	}
	// RFC 3161 2.4.2: the nonce binds the response to this request (no replay of an older token)
	if len(info.Nonce) == 0 || new(big.Int).SetBytes(info.Nonce).Cmp(new(big.Int).SetBytes(nonce)) != 0 || info.Nonce[0]&0x80 != 0 {
		return "", errors.New("TSA response rejected: nonce does not match the request")
	}
	return "gzip+base64:" + toBase64(gzipBytes(body)), nil
}
