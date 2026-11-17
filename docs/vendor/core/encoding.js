const enc = new TextEncoder();
export function utf8(s) {
    return enc.encode(s);
}
// ignoreBOM keeps a leading U+FEFF so normalization can strip it
export function fromUtf8(b) {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(b);
}
export function toBase64(b) {
    let s = "";
    for (let i = 0; i < b.length; i += 0x8000) {
        s += String.fromCharCode(...b.subarray(i, i + 0x8000));
    }
    return btoa(s);
}
export function fromBase64(s) {
    const clean = s.replace(/[\s]/g, "");
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean))
        throw new Error("invalid base64");
    const padded = clean + "=".repeat((4 - (clean.length % 4)) % 4);
    const bin = atob(padded);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++)
        out[i] = bin.charCodeAt(i);
    return out;
}
export function toBase64Unpadded(b) {
    return toBase64(b).replace(/=+$/, "");
}
export function toHex(b) {
    let s = "";
    for (const x of b)
        s += x.toString(16).padStart(2, "0");
    return s;
}
export function fromHex(s) {
    if (s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s))
        throw new Error("invalid hex");
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; i++)
        out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
    return out;
}
export function concat(...parts) {
    const n = parts.reduce((a, p) => a + p.length, 0);
    const out = new Uint8Array(n);
    let o = 0;
    for (const p of parts) {
        out.set(p, o);
        o += p.length;
    }
    return out;
}
export function bytesEqual(a, b) {
    if (a.length !== b.length)
        return false;
    for (let i = 0; i < a.length; i++)
        if (a[i] !== b[i])
            return false;
    return true;
}
async function pipe(data, stream, maxBytes = Infinity) {
    const writer = stream.writable.getWriter();
    writer.write(data).catch(() => { });
    writer.close().catch(() => { });
    const chunks = [];
    const reader = stream.readable.getReader();
    let total = 0;
    for (;;) {
        const { done, value } = await reader.read();
        if (done)
            break;
        total += value.length;
        if (total > maxBytes) {
            await reader.cancel();
            throw new Error(`decompressed data is larger than ${maxBytes} bytes`);
        }
        chunks.push(value);
    }
    return concat(...chunks);
}
export function gzip(data) {
    return pipe(data, new CompressionStream("gzip"));
}
export function gunzip(data, maxBytes = Infinity) {
    return pipe(data, new DecompressionStream("gzip"), maxBytes);
}
// SPEC 5.5: the value is unsigned, so the decompressed size is capped
export const MAX_DECODED_BYTES = 1024 * 1024;
export async function decodePrefixedBinary(v, maxBytes = MAX_DECODED_BYTES) {
    const i = v.indexOf(":");
    if (i < 0)
        throw new Error("missing encoding prefix");
    const prefix = v.slice(0, i);
    const body = v.slice(i + 1);
    switch (prefix) {
        case "base64":
            return fromBase64(body);
        case "gzip+base64":
            return gunzip(fromBase64(body), maxBytes);
        case "zstd+base64":
            throw new Error("zstd+base64 is not supported by this implementation");
        default:
            throw new Error(`unknown encoding prefix: ${prefix}`);
    }
}
