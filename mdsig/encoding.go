package mdsig

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ECMAScript WhiteSpace + LineTerminator, as used by \s and trim() in the TS core
func isJSSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

// characters not matched by . in a JS regexp
func isJSLineTerminator(r rune) bool {
	return r == '\n' || r == '\r' || r == 0x2028 || r == 0x2029
}

func toBase64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func toBase64Unpadded(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }

// lenient like the TS core: whitespace removed, missing padding added
func fromBase64(s string) ([]byte, error) {
	clean := strings.Map(func(r rune) rune {
		if isJSSpace(r) {
			return -1
		}
		return r
	}, s)
	body := strings.TrimRight(clean, "=")
	if len(clean)-len(body) > 2 {
		return nil, errors.New("invalid base64")
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/') {
			return nil, errors.New("invalid base64")
		}
	}
	padded := clean + strings.Repeat("=", (4-len(clean)%4)%4)
	out, err := base64.StdEncoding.DecodeString(padded)
	if err != nil {
		return nil, errors.New("invalid base64")
	}
	return out, nil
}

func toHex(b []byte) string { return hex.EncodeToString(b) }

func fromHex(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, errors.New("invalid hex")
	}
	return b, nil
}

func gzipBytes(data []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(data)
	_ = w.Close()
	return buf.Bytes()
}

// SPEC 5.5: the value is unsigned, so the decompressed size is capped
const MaxDecodedBytes = 1024 * 1024

func gunzipBytes(data []byte, maxBytes int64) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	b, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("decompressed data is larger than %d bytes", maxBytes)
	}
	return b, nil
}

// zstd+base64: is recognized but unsupported, as in the TS core
func DecodePrefixedBinary(v string) ([]byte, error) {
	i := strings.IndexByte(v, ':')
	if i < 0 {
		return nil, errors.New("missing encoding prefix")
	}
	prefix, body := v[:i], v[i+1:]
	switch prefix {
	case "base64":
		return fromBase64(body)
	case "gzip+base64":
		b, err := fromBase64(body)
		if err != nil {
			return nil, err
		}
		return gunzipBytes(b, MaxDecodedBytes)
	case "zstd+base64":
		return nil, errors.New("zstd+base64 is not supported by this implementation")
	default:
		return nil, fmt.Errorf("unknown encoding prefix: %s", prefix)
	}
}
