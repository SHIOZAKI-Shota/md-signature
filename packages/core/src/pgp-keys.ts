import { bytesEqual, concat, fromHex, toHex } from "./encoding.ts";
import { PgpError, Reader, TAG, readPackets, toPacketBytes, u16be, u32be } from "./pgp-packets.ts";
import {
  SIG,
  embeddedSignatures,
  keyPrefix,
  parseSignature,
  selfSigUsable,
  sigCreated,
  sigKeyExpiry,
  sigKeyFlags,
  uidPrefix,
  verifyRaw,
  type PgpSignature,
} from "./pgp-sig.ts";

const subtle = globalThis.crypto.subtle;

const OID_P256 = fromHex("2a8648ce3d030107");
const OID_ED25519 = fromHex("2b06010401da470f01");

export type KeyMaterial =
  | { kind: "rsa"; n: Uint8Array; e: Uint8Array; bits: number }
  | { kind: "ecdsa"; point: Uint8Array }
  | { kind: "ed25519"; pub: Uint8Array }
  | { kind: "other"; name: string };

export interface PgpKey {
  version: 4 | 6;
  tag: number;
  created: number;
  algo: number;
  material: KeyMaterial;
  publicBody: Uint8Array;
  // secret-key packets only: the bytes after the public part
  secretPart?: Uint8Array;
  fingerprint: Uint8Array;
  keyId: Uint8Array;
}

const ALGO_NAMES: Record<number, string> = { 1: "rsa", 2: "rsa-encrypt", 3: "rsa-sign", 16: "elgamal", 17: "dsa", 18: "ecdh", 19: "ecdsa", 22: "eddsa-legacy", 25: "x25519", 26: "x448", 27: "ed25519", 28: "ed448" };

function bitLength(b: Uint8Array): number {
  let i = 0;
  while (i < b.length && b[i] === 0) i++;
  return i === b.length ? 0 : (b.length - i - 1) * 8 + (32 - Math.clz32(b[i]!));
}

function readMaterial(r: Reader, algo: number): KeyMaterial {
  switch (algo) {
    case 1:
    case 2:
    case 3: {
      const n = r.mpi();
      const e = r.mpi();
      return algo === 1 ? { kind: "rsa", n, e, bits: bitLength(n) } : { kind: "other", name: ALGO_NAMES[algo]! };
    }
    case 16:
      r.mpi(), r.mpi(), r.mpi();
      return { kind: "other", name: "elgamal" };
    case 17:
      r.mpi(), r.mpi(), r.mpi(), r.mpi();
      return { kind: "other", name: "dsa" };
    case 18:
    case 19:
    case 22: {
      const oid = r.bytes(r.u8());
      const point = r.mpi();
      if (algo === 18) {
        r.bytes(r.u8());
        return { kind: "other", name: "ecdh" };
      }
      if (algo === 19) return bytesEqual(oid, OID_P256) && point.length === 65 && point[0] === 4 ? { kind: "ecdsa", point } : { kind: "other", name: "ecdsa (curve not supported)" };
      return bytesEqual(oid, OID_ED25519) && point.length === 33 && point[0] === 0x40 ? { kind: "ed25519", pub: point.subarray(1) } : { kind: "other", name: "eddsa (curve not supported)" };
    }
    case 25:
      r.bytes(32);
      return { kind: "other", name: "x25519" };
    case 26:
      r.bytes(56);
      return { kind: "other", name: "x448" };
    case 27:
      return { kind: "ed25519", pub: r.bytes(32) };
    case 28:
      r.bytes(57);
      return { kind: "other", name: "ed448" };
    default:
      throw new PgpError(`unknown public-key algorithm ${algo}`);
  }
}

export async function parseKeyPacket(tag: number, body: Uint8Array): Promise<PgpKey> {
  const r = new Reader(body);
  const version = r.u8();
  if (version !== 4 && version !== 6) throw new PgpError(`unsupported key version ${version}`);
  const created = r.u32();
  const algo = r.u8();
  let material: KeyMaterial;
  if (version === 6) {
    const len = r.u32();
    const mr = new Reader(r.bytes(len));
    material = readMaterial(mr, algo);
  } else {
    material = readMaterial(r, algo);
  }
  const publicBody = body.subarray(0, r.o);
  const prefix = version === 4 ? concat(new Uint8Array([0x99]), u16be(publicBody.length), publicBody) : concat(new Uint8Array([0x9b]), u32be(publicBody.length), publicBody);
  const fingerprint = new Uint8Array(await subtle.digest(version === 4 ? "SHA-1" : "SHA-256", prefix as BufferSource));
  const keyId = version === 4 ? fingerprint.subarray(12) : fingerprint.subarray(0, 8);
  const key: PgpKey = { version, tag, created, algo, material, publicBody, fingerprint, keyId };
  if (tag === TAG.secretKey || tag === TAG.secretSubkey) key.secretPart = body.subarray(r.o);
  return key;
}

export function fprHex(key: PgpKey): string {
  return toHex(key.fingerprint).toUpperCase();
}

export function keyAlgName(key: PgpKey): string {
  const m = key.material;
  if (m.kind === "rsa") return `rsa${m.bits}`;
  if (m.kind === "ecdsa") return "ecdsa-p256";
  if (m.kind === "ed25519") return "ed25519";
  return m.name;
}

// SPEC 6.2 condition 5
export function signingAlgSupported(key: PgpKey): boolean {
  const m = key.material;
  return (m.kind === "rsa" && m.bits >= 2048) || m.kind === "ecdsa" || m.kind === "ed25519";
}

// --- certificates (RFC 9580 Section 10.1)

export interface PgpCert {
  primary: PgpKey;
  direct: PgpSignature[];
  uids: { uid: string; raw: Uint8Array; sigs: PgpSignature[] }[];
  subkeys: { key: PgpKey; sigs: PgpSignature[] }[];
}

export async function parseCerts(input: string | Uint8Array): Promise<PgpCert[]> {
  const certs: PgpCert[] = [];
  for (const block of toPacketBytes(input)) {
    let cur: PgpCert | null = null;
    let sigs: PgpSignature[] | null = null;
    for (const p of readPackets(block)) {
      if (p.tag === TAG.publicKey || p.tag === TAG.secretKey) {
        try {
          cur = { primary: await parseKeyPacket(p.tag, p.body), direct: [], uids: [], subkeys: [] };
          certs.push(cur);
          sigs = cur.direct;
        } catch {
          cur = null;
          sigs = null;
        }
        continue;
      }
      if (!cur) continue;
      if (p.tag === TAG.userId) {
        const e = { uid: new TextDecoder().decode(p.body), raw: p.body, sigs: [] as PgpSignature[] };
        cur.uids.push(e);
        sigs = e.sigs;
      } else if (p.tag === TAG.userAttribute) {
        sigs = [];
      } else if (p.tag === TAG.publicSubkey || p.tag === TAG.secretSubkey) {
        try {
          const e = { key: await parseKeyPacket(p.tag, p.body), sigs: [] as PgpSignature[] };
          cur.subkeys.push(e);
          sigs = e.sigs;
        } catch {
          sigs = [];
        }
      } else if (p.tag === TAG.signature && sigs) {
        try {
          sigs.push(parseSignature(p.body));
        } catch {
        }
      }
    }
  }
  return certs;
}

export function emailOf(uid: string): string | undefined {
  const m = /<([^<>\s]+@[^<>\s]+)>/.exec(uid);
  if (m) return m[1]!.toLowerCase();
  const t = uid.trim();
  return /^[^\s@<>]+@[^\s@<>]+$/.test(t) ? t.toLowerCase() : undefined;
}

async function newestValid(sigs: PgpSignature[], types: number[], issuer: PgpKey, subject: Uint8Array, now: number): Promise<PgpSignature | undefined> {
  let best: PgpSignature | undefined;
  for (const s of sigs) {
    if (!types.includes(s.type) || !selfSigUsable(s, issuer, now)) continue;
    if (best && sigCreated(best)! >= sigCreated(s)!) continue;
    if (await verifyRaw(issuer, s, subject)) best = s;
  }
  return best;
}

async function anyValid(sigs: PgpSignature[], type: number, issuer: PgpKey, subject: Uint8Array, now: number): Promise<boolean> {
  for (const s of sigs) if (s.type === type && selfSigUsable(s, issuer, now) && (await verifyRaw(issuer, s, subject))) return true;
  return false;
}

export type CertCheck =
  | { ok: true; key: PgpKey; uid?: string; emails: string[]; warnings: string[] }
  | { ok: false; code: "not-found" | "revoked" | "unsupported-alg"; message: string };

const CERT_TYPES = [0x10, 0x11, 0x12, 0x13];

export async function validUids(cert: PgpCert, now: number): Promise<{ uid: string; sig: PgpSignature }[]> {
  const p = cert.primary;
  const pp = keyPrefix(p);
  const out: { uid: string; sig: PgpSignature }[] = [];
  for (const u of cert.uids) {
    const newest = await newestValid(u.sigs, [...CERT_TYPES, SIG.certRevocation], p, concat(pp, uidPrefix(u.raw)), now);
    if (newest && newest.type !== SIG.certRevocation) out.push({ uid: u.uid, sig: newest });
  }
  return out;
}

// SPEC 4.3 key validation; `email` undefined skips the user ID condition (own secret keys).
export async function checkCert(cert: PgpCert, fpr: string, email: string | undefined, now: number): Promise<CertCheck> {
  const p = cert.primary;
  const want = fpr.toUpperCase();
  const sub = cert.subkeys.find((s) => fprHex(s.key) === want);
  if (fprHex(p) !== want && !sub) return { ok: false, code: "not-found", message: `certificate has no key ${want}` };
  if (p.material.kind === "other") return { ok: false, code: "unsupported-alg", message: `primary key algorithm ${p.material.name} is not supported` };
  const pp = keyPrefix(p);
  const warnings: string[] = [];

  if (await anyValid(cert.direct, SIG.keyRevocation, p, pp, now)) return { ok: false, code: "revoked", message: `OpenPGP key ${fprHex(p)} has been revoked` };

  const uids = await validUids(cert, now);
  const emails = [...new Set(uids.map((u) => emailOf(u.uid)).filter((e): e is string => !!e))];
  const matched = email === undefined ? uids[0] : uids.find((u) => emailOf(u.uid) === email.toLowerCase());
  if (email !== undefined && !matched) return { ok: false, code: "not-found", message: `no valid user ID with <${email}> on key ${fprHex(p)}` };

  const direct = await newestValid(cert.direct, [SIG.directKey], p, pp, now);
  // RFC 9580 5.2.3.10: a version 6 key is not used without a valid direct key signature
  if (p.version === 6 && !direct) return { ok: false, code: "not-found", message: `version 6 key ${fprHex(p)} has no valid direct key signature` };
  const primaryUid = uids.find((u) => u.sig.hashed.some((s) => s.type === 25 && s.data[0])) ?? uids[0];
  const primaryAttrs = direct && sigKeyFlags(direct) !== undefined ? direct : primaryUid?.sig ?? direct;
  const expired = (key: PgpKey, sig?: PgpSignature) => {
    const e = sig && sigKeyExpiry(sig);
    if (e && key.created + e <= now) warnings.push(`OpenPGP key ${fprHex(key)} expired on ${new Date((key.created + e) * 1000).toISOString().replace(/\.\d+Z$/, "Z")}`);
  };
  expired(p, primaryAttrs);

  let key = p;
  if (sub) {
    const both = concat(pp, keyPrefix(sub.key));
    if (await anyValid(sub.sigs, SIG.subkeyRevocation, p, both, now)) return { ok: false, code: "revoked", message: `OpenPGP subkey ${want} has been revoked` };
    const binding = await newestValid(sub.sigs, [SIG.subkeyBinding], p, both, now);
    if (!binding) return { ok: false, code: "not-found", message: `subkey ${want} has no valid binding signature` };
    if (!((sigKeyFlags(binding) ?? 0) & 0x02)) return { ok: false, code: "not-found", message: `subkey ${want} is not marked for signing` };
    let back = false;
    for (const e of embeddedSignatures(binding)) {
      if (e.type === SIG.primaryBinding && selfSigUsable(e, sub.key, now) && (await verifyRaw(sub.key, e, both))) back = true;
    }
    if (!back) return { ok: false, code: "not-found", message: `signing subkey ${want} has no valid primary key binding signature` };
    expired(sub.key, binding);
    key = sub.key;
  } else {
    const flags = primaryAttrs ? sigKeyFlags(primaryAttrs) : undefined;
    if (flags !== undefined && !(flags & 0x02)) return { ok: false, code: "not-found", message: `key ${want} is not marked for signing` };
  }
  if (!signingAlgSupported(key)) return { ok: false, code: "unsupported-alg", message: `OpenPGP key algorithm ${keyAlgName(key)} is not supported` };
  return { ok: true, key, uid: matched?.uid, emails, warnings };
}

export interface PgpPublicKeyInfo {
  fpr: string;
  keyAlg: string;
  version: 4 | 6;
  uids: string[];
  subkeys: { fpr: string; keyAlg: string }[];
}

export async function readPgpPublicKey(input: string | Uint8Array, now = Math.floor(Date.now() / 1000)): Promise<PgpPublicKeyInfo[]> {
  const out: PgpPublicKeyInfo[] = [];
  for (const c of await parseCerts(input)) {
    out.push({
      fpr: fprHex(c.primary),
      keyAlg: keyAlgName(c.primary),
      version: c.primary.version,
      uids: (await validUids(c, now)).map((u) => u.uid),
      subkeys: c.subkeys.map((s) => ({ fpr: fprHex(s.key), keyAlg: keyAlgName(s.key) })),
    });
  }
  return out;
}
