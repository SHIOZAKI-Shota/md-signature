package mdsig

import (
	"encoding/binary"
	"math/bits"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	pgpTagSignature     = 2
	pgpTagSecretKey     = 5
	pgpTagPublicKey     = 6
	pgpTagSecretSubkey  = 7
	pgpTagUserID        = 13
	pgpTagPublicSubkey  = 14
	pgpTagUserAttribute = 17
)

type PGPError struct{ Msg string }

func (e *PGPError) Error() string { return e.Msg }

func pgpFail(msg string) { panic(&PGPError{Msg: msg}) }

// parsers below panic with *PgpError like the TS core throws; catchPgp turns that back into an error
func catchPgp(err *error) {
	if v := recover(); v != nil {
		e, ok := v.(*PGPError)
		if !ok {
			panic(v)
		}
		*err = e
	}
}

type pgpReader struct {
	b []byte
	o int
}

func (r *pgpReader) left() int { return len(r.b) - r.o }

func (r *pgpReader) u8() int {
	if r.o >= len(r.b) {
		pgpFail("truncated OpenPGP data")
	}
	r.o++
	return int(r.b[r.o-1])
}

func (r *pgpReader) u16() int { return r.u8()<<8 | r.u8() }

func (r *pgpReader) u32() int64 {
	return int64(r.u8())<<24 | int64(r.u8())<<16 | int64(r.u8())<<8 | int64(r.u8())
}

func (r *pgpReader) bytes(n int64) []byte {
	if n < 0 || int64(r.o)+n > int64(len(r.b)) {
		pgpFail("truncated OpenPGP data")
	}
	v := r.b[r.o : r.o+int(n)]
	r.o += int(n)
	return v
}

func u16be(n int) []byte { return []byte{byte(n >> 8), byte(n)} }

func u32be(n int64) []byte { return binary.BigEndian.AppendUint32(nil, uint32(n)) }

func concatBytes(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func stripLeadingZeros(b []byte) []byte {
	i := 0
	for i < len(b) && b[i] == 0 {
		i++
	}
	return b[i:]
}

func encodeMpi(b []byte) []byte {
	v := stripLeadingZeros(b)
	n := 0
	if len(v) > 0 {
		n = (len(v)-1)*8 + bits.Len8(v[0])
	}
	return concatBytes(u16be(n), v)
}

// --- packet framing (RFC 9580 Section 4.2)

type pgpPacket struct {
	tag  int
	body []byte
}

func readNewLength(r *pgpReader) (int64, bool) {
	a := r.u8()
	switch {
	case a < 192:
		return int64(a), false
	case a < 224:
		return int64((a-192)<<8+r.u8()) + 192, false
	case a == 255:
		return r.u32(), false
	}
	return 1 << (a & 0x1f), true
}

func readPackets(data []byte) (out []pgpPacket, err error) {
	defer catchPgp(&err)
	r := &pgpReader{b: data}
	for r.left() > 0 {
		h := r.u8()
		if h&0x80 == 0 {
			pgpFail("not an OpenPGP packet")
		}
		var tag int
		var body []byte
		if h&0x40 != 0 {
			tag = h & 0x3f
			n, partial := readNewLength(r)
			body = r.bytes(n)
			if partial {
				body = append([]byte{}, body...)
			}
			for partial {
				n, partial = readNewLength(r)
				body = append(body, r.bytes(n)...)
			}
		} else {
			tag = (h >> 2) & 0x0f
			var n int64
			switch h & 3 {
			case 0:
				n = int64(r.u8())
			case 1:
				n = int64(r.u16())
			case 2:
				n = r.u32()
			default:
				n = int64(r.left())
			}
			body = r.bytes(n)
		}
		out = append(out, pgpPacket{tag: tag, body: body})
	}
	return out, nil
}

func subpacketLength(n int) []byte {
	switch {
	case n < 192:
		return []byte{byte(n)}
	case n < 8384:
		return []byte{byte((n-192)>>8 + 192), byte(n - 192)}
	}
	return concatBytes([]byte{255}, u32be(int64(n)))
}

func encodePacket(tag int, body []byte) []byte {
	return concatBytes([]byte{byte(0xc0 | tag)}, subpacketLength(len(body)), body)
}

// --- subpackets (RFC 9580 Section 5.2.3.7)

type pgpSubpacket struct {
	typ      int
	critical bool
	data     []byte
}

func readSubpackets(area []byte) []pgpSubpacket {
	r := &pgpReader{b: area}
	var out []pgpSubpacket
	for r.left() > 0 {
		a := r.u8()
		var n int64
		switch {
		case a < 192:
			n = int64(a)
		case a < 255:
			n = int64((a-192)<<8+r.u8()) + 192
		default:
			n = r.u32()
		}
		if n < 1 {
			pgpFail("empty signature subpacket")
		}
		t := r.u8()
		out = append(out, pgpSubpacket{typ: t & 0x7f, critical: t&0x80 != 0, data: r.bytes(n - 1)})
	}
	return out
}

func encodeSubpacket(typ int, data []byte) []byte {
	return concatBytes(subpacketLength(len(data)+1), []byte{byte(typ)}, data)
}

// --- ASCII armor (RFC 9580 Section 6)

var (
	armorRe       = regexp.MustCompile(`-----BEGIN PGP [A-Z ,0-9/]+-----\r?\n([\s\S]*?)-----END PGP [A-Z ,0-9/]+-----`)
	armorHeaderRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*: `)
	crlfSplitRe   = regexp.MustCompile(`\r?\n`)
)

// RFC 9580 6.1: the CRC24 footer is optional and is not checked; the signatures carry the integrity.
func dearmor(text string) ([][]byte, error) {
	var out [][]byte
	for _, m := range armorRe.FindAllStringSubmatch(text, -1) {
		lines := crlfSplitRe.Split(m[1], -1)
		i := 0
		for i < len(lines) && strings.TrimFunc(lines[i], isJSSpace) != "" && armorHeaderRe.MatchString(lines[i]) {
			i++
		}
		var b64 strings.Builder
		for ; i < len(lines); i++ {
			l := strings.TrimFunc(lines[i], isJSSpace)
			if strings.HasPrefix(l, "=") && utf16Len(l) == 5 {
				break
			}
			b64.WriteString(l)
		}
		b, err := fromBase64(b64.String())
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// accepts armored text, binary packets, or binary bytes that happen to be armored text
func toPacketBytes(input []byte) ([][]byte, error) {
	if len(input) > 0 && input[0]&0x80 != 0 {
		return [][]byte{input}, nil
	}
	blocks, err := dearmor(decodeUTF8Lossy(input))
	if err != nil {
		return nil, err
	}
	if len(blocks) == 0 {
		return nil, &PGPError{Msg: "no OpenPGP armored block found"}
	}
	return blocks, nil
}

// TextDecoder parity: each maximal ill-formed subsequence becomes one U+FFFD (WHATWG Encoding)
func decodeUTF8Lossy(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var sb strings.Builder
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if r != utf8.RuneError || size > 1 {
			sb.WriteRune(r)
			i += size
			continue
		}
		sb.WriteRune(utf8.RuneError)
		i += maximalSubpart(b[i:])
	}
	return sb.String()
}

func maximalSubpart(b []byte) int {
	c := b[0]
	var need int
	lo, hi := byte(0x80), byte(0xbf)
	switch {
	case c >= 0xc2 && c <= 0xdf:
		need = 1
	case c >= 0xe0 && c <= 0xef:
		need = 2
		if c == 0xe0 {
			lo = 0xa0
		} else if c == 0xed {
			hi = 0x9f
		}
	case c >= 0xf0 && c <= 0xf4:
		need = 3
		if c == 0xf0 {
			lo = 0x90
		} else if c == 0xf4 {
			hi = 0x8f
		}
	default:
		return 1
	}
	n := 1
	for k := 0; k < need && n < len(b); k++ {
		x := b[n]
		if x < lo || x > hi {
			break
		}
		lo, hi = 0x80, 0xbf
		n++
	}
	return n
}

func Dearmor(text string) ([][]byte, error) { return dearmor(text) }
