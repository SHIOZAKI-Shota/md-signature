const enc = new TextEncoder();

export function utf8(s: string): Uint8Array {
  return enc.encode(s);
}

// ignoreBOM keeps a leading U+FEFF so normalization can strip it
export function fromUtf8(b: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(b);
}

export function toBase64(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i += 0x8000) {
    s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

export function fromBase64(s: string): Uint8Array {
  const clean = s.replace(/[\s]/g, "");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean)) throw new Error("invalid base64");
  const padded = clean + "=".repeat((4 - (clean.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function toBase64Unpadded(b: Uint8Array): string {
  return toBase64(b).replace(/=+$/, "");
}

export function toHex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

export function fromHex(s: string): Uint8Array {
  if (s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) throw new Error("invalid hex");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const n = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

async function pipe(data: Uint8Array, stream: { readable: ReadableStream<Uint8Array>; writable: WritableStream<BufferSource> }, maxBytes = Infinity): Promise<Uint8Array> {
  const writer = stream.writable.getWriter();
  writer.write(data as BufferSource).catch(() => {});
  writer.close().catch(() => {});
  const chunks: Uint8Array[] = [];
  const reader = stream.readable.getReader();
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error(`decompressed data is larger than ${maxBytes} bytes`);
    }
    chunks.push(value);
  }
  return concat(...chunks);
}

export function gzip(data: Uint8Array): Promise<Uint8Array> {
  return pipe(data, new CompressionStream("gzip") as never);
}

export function gunzip(data: Uint8Array, maxBytes = Infinity): Promise<Uint8Array> {
  return pipe(data, new DecompressionStream("gzip") as never, maxBytes);
}

// SPEC 4.6: the value is unsigned, so the decompressed size is capped
export const MAX_DECODED_BYTES = 1024 * 1024;

export async function decodePrefixedBinary(v: string, maxBytes = MAX_DECODED_BYTES): Promise<Uint8Array> {
  const i = v.indexOf(":");
  if (i < 0) throw new Error("missing encoding prefix");
  const prefix = v.slice(0, i);
  const body = v.slice(i + 1);
  switch (prefix) {
    case "base64":
      return fromBase64(body);
    case "gzip+base64":
      return gunzip(fromBase64(body), maxBytes);
    default:
      throw new Error(`unknown encoding prefix: ${prefix}`);
  }
}
