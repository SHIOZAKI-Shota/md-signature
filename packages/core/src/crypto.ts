import { concat, fromBase64, toBase64, toBase64Unpadded, utf8, bytesEqual } from "./encoding.ts";

const subtle = globalThis.crypto.subtle;

// DER headers for Ed25519 (OID 1.3.101.112): PKCS#8 + 32-byte seed, SPKI + 32-byte key
export const PKCS8_ED25519_PREFIX =new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);
const SPKI_ED25519_PREFIX = new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);

export type HashAlg = "sha256" | "sha512";

export function isSupportedHash(alg: string): alg is HashAlg {
  return alg === "sha256" || alg === "sha512";
}

export async function digest(alg: HashAlg, data: Uint8Array): Promise<Uint8Array> {
  const name = alg === "sha256" ? "SHA-256" : "SHA-512";
  return new Uint8Array(await subtle.digest(name, data as BufferSource));
}

export const sha256 = (data: Uint8Array) => digest("sha256", data);

export interface Signer {
  alg: "ed25519";
  publicKey: Uint8Array;
  sign(data: Uint8Array): Promise<Uint8Array>;
}

export function rawEd25519PublicKey(b: Uint8Array): Uint8Array {
  if (b.length === 32) return b;
  if (b.length === 44 && bytesEqual(b.subarray(0, 12), SPKI_ED25519_PREFIX)) return b.subarray(12);
  throw new Error(`not an Ed25519 public key (length ${b.length})`);
}

export async function ed25519Verify(publicKey: Uint8Array, signature: Uint8Array, data: Uint8Array): Promise<boolean> {
  if (signature.length !== 64) return false;
  const key = await subtle.importKey("raw", rawEd25519PublicKey(publicKey) as BufferSource, { name: "Ed25519" }, false, ["verify"]);
  return subtle.verify({ name: "Ed25519" }, key, signature as BufferSource, data as BufferSource);
}

export async function signerFromSeed(seed: Uint8Array): Promise<Signer> {
  if (seed.length !== 32) throw new Error("Ed25519 seed must be 32 bytes");
  const pkcs8 = concat(PKCS8_ED25519_PREFIX, seed);
  const key = await subtle.importKey("pkcs8", pkcs8 as BufferSource, { name: "Ed25519" }, true, ["sign"]);
  // a PKCS#8 import exposes no public key; recover it from the JWK
  const jwk = await subtle.exportKey("jwk", key);
  const publicKey = fromBase64(jwk.x!.replace(/-/g, "+").replace(/_/g, "/"));
  return {
    alg: "ed25519",
    publicKey,
    sign: async (data) => new Uint8Array(await subtle.sign({ name: "Ed25519" }, key, data as BufferSource)),
  };
}

export interface GeneratedKey {
  seed: Uint8Array;
  publicKey: Uint8Array;
  signer: Signer;
}

export async function generateEd25519(): Promise<GeneratedKey> {
  const seed = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const signer = await signerFromSeed(seed);
  return { seed, publicKey: signer.publicKey, signer };
}

// --- OpenSSH formats

class SshReader {
  private o = 0;
  private b: Uint8Array;
  constructor(b: Uint8Array) {
    this.b = b;
  }
  u32(): number {
    if (this.o + 4 > this.b.length) throw new Error("truncated SSH data");
    const v = ((this.b[this.o]! << 24) | (this.b[this.o + 1]! << 16) | (this.b[this.o + 2]! << 8) | this.b[this.o + 3]!) >>> 0;
    this.o += 4;
    return v;
  }
  bytes(): Uint8Array {
    const n = this.u32();
    if (this.o + n > this.b.length) throw new Error("truncated SSH data");
    const v = this.b.subarray(this.o, this.o + n);
    this.o += n;
    return v;
  }
  str(): string {
    return new TextDecoder().decode(this.bytes());
  }
  raw(n: number): Uint8Array {
    const v = this.b.subarray(this.o, this.o + n);
    this.o += n;
    return v;
  }
}

function sshString(b: Uint8Array): Uint8Array {
  const n = b.length;
  return concat(new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]), b);
}

export function sshEd25519Blob(publicKey: Uint8Array): Uint8Array {
  return concat(sshString(utf8("ssh-ed25519")), sshString(rawEd25519PublicKey(publicKey)));
}

export function formatSshPublicKey(publicKey: Uint8Array, comment = ""): string {
  return `ssh-ed25519 ${toBase64(sshEd25519Blob(publicKey))}${comment ? " " + comment : ""}`;
}

export async function sshFingerprint(publicKey: Uint8Array): Promise<string> {
  return "SHA256:" + toBase64Unpadded(await sha256(sshEd25519Blob(publicKey)));
}

export interface SshPublicKey {
  type: string;
  key?: Uint8Array;
  blob: Uint8Array;
  comment: string;
}

export function parseSshPublicKeys(text: string): SshPublicKey[] {
  const out: SshPublicKey[] = [];
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const parts = t.split(/\s+/);
    if (parts.length < 2) continue;
    try {
      const blob = fromBase64(parts[1]!);
      const r = new SshReader(blob);
      const type = r.str();
      if (type !== parts[0]) continue;
      const entry: SshPublicKey = { type, blob, comment: parts.slice(2).join(" ") };
      if (type === "ssh-ed25519") entry.key = r.bytes();
      out.push(entry);
    } catch {
    }
  }
  return out;
}

export function parseOpenSshPrivateKey(pem: string): { seed: Uint8Array; publicKey: Uint8Array; comment: string } {
  const m = pem.match(/-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]+?)-----END OPENSSH PRIVATE KEY-----/);
  if (!m) throw new Error("not an OpenSSH private key");
  const data = fromBase64(m[1]!);
  const magic = utf8("openssh-key-v1\0");
  if (!bytesEqual(data.subarray(0, magic.length), magic)) throw new Error("bad OpenSSH key magic");
  const r = new SshReader(data.subarray(magic.length));
  const cipher = r.str();
  r.str(); // kdfname
  r.bytes(); // kdfoptions
  if (cipher !== "none") throw new Error("encrypted OpenSSH keys are not supported here; decrypt first or use an ssh-agent");
  if (r.u32() !== 1) throw new Error("multiple keys in one file are not supported");
  r.bytes(); // public key blob
  const priv = new SshReader(r.bytes());
  if (priv.u32() !== priv.u32()) throw new Error("OpenSSH key checkint mismatch");
  const type = priv.str();
  if (type !== "ssh-ed25519") throw new Error(`unsupported key type: ${type}`);
  const publicKey = priv.bytes();
  const sk = priv.bytes();
  const comment = priv.str();
  return { seed: sk.subarray(0, 32), publicKey, comment };
}

export function formatOpenSshPrivateKey(seed: Uint8Array, publicKey: Uint8Array, comment = ""): string {
  const blob = sshEd25519Blob(publicKey);
  const check = globalThis.crypto.getRandomValues(new Uint8Array(4));
  let privSection = concat(
    check,
    check,
    sshString(utf8("ssh-ed25519")),
    sshString(publicKey),
    sshString(concat(seed, publicKey)),
    sshString(utf8(comment)),
  );
  const pad: number[] = [];
  for (let i = 1; (privSection.length + pad.length) % 8 !== 0; i++) pad.push(i);
  privSection = concat(privSection, new Uint8Array(pad));
  const body = concat(
    utf8("openssh-key-v1\0"),
    sshString(utf8("none")),
    sshString(utf8("none")),
    sshString(new Uint8Array(0)),
    new Uint8Array([0, 0, 0, 1]),
    sshString(blob),
    sshString(privSection),
  );
  const b64 = toBase64(body).replace(/(.{70})/g, "$1\n").trimEnd();
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${b64}\n-----END OPENSSH PRIVATE KEY-----\n`;
}
