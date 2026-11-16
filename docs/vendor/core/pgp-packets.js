import { concat, fromBase64, toBase64 } from "./encoding.js";
export const TAG = { signature: 2, secretKey: 5, publicKey: 6, secretSubkey: 7, userId: 13, publicSubkey: 14, userAttribute: 17 };
export class PgpError extends Error {
}
export class Reader {
    o = 0;
    b;
    constructor(b) {
        this.b = b;
    }
    get left() {
        return this.b.length - this.o;
    }
    u8() {
        if (this.o >= this.b.length)
            throw new PgpError("truncated OpenPGP data");
        return this.b[this.o++];
    }
    u16() {
        return (this.u8() << 8) | this.u8();
    }
    u32() {
        return ((this.u8() << 24) | (this.u8() << 16) | (this.u8() << 8) | this.u8()) >>> 0;
    }
    bytes(n) {
        if (n < 0 || this.o + n > this.b.length)
            throw new PgpError("truncated OpenPGP data");
        const v = this.b.subarray(this.o, this.o + n);
        this.o += n;
        return v;
    }
    rest() {
        return this.bytes(this.left);
    }
    mpi() {
        const bits = this.u16();
        return this.bytes((bits + 7) >> 3);
    }
}
export function u16be(n) {
    return new Uint8Array([(n >>> 8) & 255, n & 255]);
}
export function u32be(n) {
    return new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
}
export function stripLeadingZeros(b) {
    let i = 0;
    while (i < b.length && b[i] === 0)
        i++;
    return b.subarray(i);
}
export function encodeMpi(b) {
    const v = stripLeadingZeros(b);
    const bits = v.length ? (v.length - 1) * 8 + (32 - Math.clz32(v[0])) : 0;
    return concat(u16be(bits), v);
}
export function leftPad(b, n) {
    const v = stripLeadingZeros(b);
    if (v.length > n)
        return null;
    const out = new Uint8Array(n);
    out.set(v, n - v.length);
    return out;
}
// --- packet framing (RFC 9580 Section 4.2)
function readNewLength(r) {
    const a = r.u8();
    if (a < 192)
        return { len: a, partial: false };
    if (a < 224)
        return { len: ((a - 192) << 8) + r.u8() + 192, partial: false };
    if (a === 255)
        return { len: r.u32(), partial: false };
    return { len: 1 << (a & 0x1f), partial: true };
}
export function readPackets(data) {
    const r = new Reader(data);
    const out = [];
    while (r.left > 0) {
        const h = r.u8();
        if (!(h & 0x80))
            throw new PgpError("not an OpenPGP packet");
        let tag;
        let body;
        if (h & 0x40) {
            tag = h & 0x3f;
            let { len, partial } = readNewLength(r);
            const parts = [r.bytes(len)];
            while (partial) {
                ({ len, partial } = readNewLength(r));
                parts.push(r.bytes(len));
            }
            body = parts.length === 1 ? parts[0] : concat(...parts);
        }
        else {
            tag = (h >> 2) & 0x0f;
            const lt = h & 3;
            const len = lt === 0 ? r.u8() : lt === 1 ? r.u16() : lt === 2 ? r.u32() : r.left;
            body = r.bytes(len);
        }
        out.push({ tag, body });
    }
    return out;
}
export function encodePacket(tag, body) {
    const n = body.length;
    const len = n < 192 ? new Uint8Array([n]) : n < 8384 ? new Uint8Array([((n - 192) >> 8) + 192, (n - 192) & 255]) : concat(new Uint8Array([255]), u32be(n));
    return concat(new Uint8Array([0xc0 | tag]), len, body);
}
export function readSubpackets(area) {
    const r = new Reader(area);
    const out = [];
    while (r.left > 0) {
        const a = r.u8();
        const len = a < 192 ? a : a < 255 ? ((a - 192) << 8) + r.u8() + 192 : r.u32();
        if (len < 1)
            throw new PgpError("empty signature subpacket");
        const t = r.u8();
        out.push({ type: t & 0x7f, critical: (t & 0x80) !== 0, data: r.bytes(len - 1) });
    }
    return out;
}
export function encodeSubpacket(type, data, critical = false) {
    const n = data.length + 1;
    const len = n < 192 ? new Uint8Array([n]) : n < 8384 ? new Uint8Array([((n - 192) >> 8) + 192, (n - 192) & 255]) : concat(new Uint8Array([255]), u32be(n));
    return concat(len, new Uint8Array([critical ? type | 0x80 : type]), data);
}
// --- ASCII armor (RFC 9580 Section 6)
// RFC 9580 6.1: the CRC24 footer is optional and is not checked; the signatures carry the integrity.
export function dearmor(text) {
    const out = [];
    const re = /-----BEGIN PGP [A-Z ,0-9/]+-----\r?\n([\s\S]*?)-----END PGP [A-Z ,0-9/]+-----/g;
    for (const m of text.matchAll(re)) {
        const lines = m[1].split(/\r?\n/);
        let i = 0;
        while (i < lines.length && lines[i].trim() !== "" && /^[A-Za-z][A-Za-z0-9-]*: /.test(lines[i]))
            i++;
        const b64 = [];
        for (; i < lines.length; i++) {
            const l = lines[i].trim();
            if (l.startsWith("=") && l.length === 5)
                break;
            b64.push(l);
        }
        out.push(fromBase64(b64.join("")));
    }
    return out;
}
function crc24(data) {
    let crc = 0xb704ce;
    for (const b of data) {
        crc ^= b << 16;
        for (let i = 0; i < 8; i++) {
            crc <<= 1;
            if (crc & 0x1000000)
                crc ^= 0x1864cfb;
        }
    }
    return crc & 0xffffff;
}
export function armor(type, data) {
    const c = crc24(data);
    const body = toBase64(data).replace(/(.{64})/g, "$1\n").trimEnd();
    return `-----BEGIN PGP ${type}-----\n\n${body}\n=${toBase64(new Uint8Array([c >> 16, (c >> 8) & 255, c & 255]))}\n-----END PGP ${type}-----\n`;
}
// Accepts armored text, binary packets, or binary bytes that happen to be armored text.
export function toPacketBytes(input) {
    if (typeof input !== "string") {
        if (input.length && input[0] & 0x80)
            return [input];
        input = new TextDecoder().decode(input);
    }
    const blocks = dearmor(input);
    if (!blocks.length)
        throw new PgpError("no OpenPGP armored block found");
    return blocks;
}
