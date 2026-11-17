import { bytesEqual, concat, fromBase64 } from "./encoding.ts";
import { parseDer, type Der } from "./der.ts";

// --- OIDs

export function oidString(content: Uint8Array): string {
  if (!content.length) return "";
  const parts: number[] = [];
  let v = 0;
  let first = true;
  for (const x of content) {
    v = v * 128 + (x & 0x7f);
    if (x & 0x80) continue;
    if (first) {
      const a = v < 40 ? 0 : v < 80 ? 1 : 2;
      parts.push(a, v - a * 40);
      first = false;
    } else parts.push(v);
    v = 0;
  }
  return parts.join(".");
}

export const OID = {
  sha256: "2.16.840.1.101.3.4.2.1",
  sha384: "2.16.840.1.101.3.4.2.2",
  sha512: "2.16.840.1.101.3.4.2.3",
  rsaEncryption: "1.2.840.113549.1.1.1",
  rsaPss: "1.2.840.113549.1.1.10",
  mgf1: "1.2.840.113549.1.1.8",
  sha256WithRsa: "1.2.840.113549.1.1.11",
  sha384WithRsa: "1.2.840.113549.1.1.12",
  sha512WithRsa: "1.2.840.113549.1.1.13",
  ecPublicKey: "1.2.840.10045.2.1",
  ecdsaSha256: "1.2.840.10045.4.3.2",
  ecdsaSha384: "1.2.840.10045.4.3.3",
  ecdsaSha512: "1.2.840.10045.4.3.4",
  basicConstraints: "2.5.29.19",
  keyUsage: "2.5.29.15",
  extKeyUsage: "2.5.29.37",
  subjectKeyId: "2.5.29.14",
  nameConstraints: "2.5.29.30",
  ekuTimeStamping: "1.3.6.1.5.5.7.3.8",
  ekuAny: "2.5.29.37.0",
} as const;

export type ShaName = "SHA-256" | "SHA-384" | "SHA-512";

// SHA-1 and MD5 are rejected for digests and signatures
export function shaName(oid: string): ShaName | undefined {
  return ({ [OID.sha256]: "SHA-256", [OID.sha384]: "SHA-384", [OID.sha512]: "SHA-512" } as Record<string, ShaName>)[oid];
}

export async function shaDigest(h: ShaName | "SHA-1", data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await globalThis.crypto.subtle.digest(h, data as BufferSource));
}

const CURVES: Record<string, { name: string; size: number }> = {
  "1.2.840.10045.3.1.7": { name: "P-256", size: 32 },
  "1.3.132.0.34": { name: "P-384", size: 48 },
  "1.3.132.0.35": { name: "P-521", size: 66 },
};

// extensions this verifier processes or may safely ignore when critical (policies are not evaluated)
const CRITICAL_OK = new Set<string>([OID.basicConstraints, OID.keyUsage, OID.extKeyUsage, "2.5.29.17", "2.5.29.32", "2.5.29.36", "2.5.29.54"]);

// --- certificate

export interface AlgId {
  oid: string;
  params?: Der;
}

export interface X509Cert {
  raw: Uint8Array;
  tbs: Uint8Array;
  sigAlg: AlgId;
  signature: Uint8Array;
  serial: Uint8Array;
  issuerRaw: Uint8Array;
  subjectRaw: Uint8Array;
  notBefore: number;
  notAfter: number;
  spki: Uint8Array;
  keyAlg: AlgId;
  rsaBits?: number;
  hasBasicConstraints: boolean;
  isCA: boolean;
  pathLen?: number;
  keyUsage?: number;
  eku?: string[];
  subjectKeyId?: Uint8Array;
  hasNameConstraints: boolean;
  unknownCritical?: string;
  name: string;
}

function algId(n: Der | undefined): AlgId {
  const o = n?.children?.[0];
  if (!n || n.tag !== 0x30 || !o || o.tag !== 0x06) throw new Error("X.509: malformed AlgorithmIdentifier");
  return { oid: oidString(o.content), params: n.children![1] };
}

export { algId as parseAlgId };

function parseTime(n: Der | undefined): number {
  const s = n ? new TextDecoder().decode(n.content) : "";
  let m: RegExpExecArray | null;
  let year: number;
  if (n?.tag === 0x17 && (m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s))) year = Number(m[1]) + (Number(m[1]) < 50 ? 2000 : 1900);
  else if (n?.tag === 0x18 && (m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s))) year = Number(m[1]);
  else throw new Error("X.509: malformed validity time");
  const [mo, d, h, mi, sec] = m.slice(2).map(Number) as [number, number, number, number, number];
  const t = Date.UTC(year, mo - 1, d, h, mi, sec);
  if (Number.isNaN(t)) throw new Error("X.509: malformed validity time");
  return t;
}

function nameString(n: Der): string {
  const dec = (v: Der) => {
    if (v.tag === 0x1e) {
      let s = "";
      for (let i = 0; i + 1 < v.content.length; i += 2) s += String.fromCharCode(v.content[i]! * 256 + v.content[i + 1]!);
      return s;
    }
    if (v.tag === 0x14) return Array.from(v.content, (x) => String.fromCharCode(x)).join("");
    return new TextDecoder().decode(v.content);
  };
  let cn = "";
  let org = "";
  for (const rdn of n.children ?? []) {
    for (const atv of rdn.children ?? []) {
      const o = atv.children?.[0];
      const v = atv.children?.[1];
      if (!o || !v) continue;
      const id = oidString(o.content);
      if (id === "2.5.4.3") cn = dec(v);
      if (id === "2.5.4.10" && !org) org = dec(v);
    }
  }
  return cn || org || "(unnamed)";
}

function unsignedInt(n: Der | undefined, what: string): Uint8Array {
  if (!n || n.tag !== 0x02 || !n.content.length) throw new Error(`X.509: malformed ${what}`);
  let b = n.content;
  while (b.length > 1 && b[0] === 0) b = b.subarray(1);
  return b;
}

export function parseCertificate(der: Uint8Array): X509Cert {
  const { node: root, next } = parseDer(der);
  if (next !== der.length) throw new Error("X.509: trailing bytes after the certificate");
  const [tbs, outerAlg, sigBits] = root.children ?? [];
  if (root.tag !== 0x30 || !tbs?.children || !outerAlg || !sigBits || sigBits.tag !== 0x03 || sigBits.content[0] !== 0) throw new Error("X.509: malformed certificate");
  const f = [...tbs.children];
  if (f[0]?.tag === 0xa0) f.shift();
  const [serial, innerAlg, issuer, validity, subject, spki, ...rest] = f;
  if (!innerAlg || !issuer || !validity || !subject || !spki?.children) throw new Error("X.509: malformed TBSCertificate");
  // RFC 5280 4.1.1.2: both algorithm fields must be the same
  if (!bytesEqual(innerAlg.bytes, outerAlg.bytes)) throw new Error("X.509: signature algorithm fields differ");
  const keyBits = spki.children[1];
  if (!keyBits || keyBits.tag !== 0x03 || keyBits.content[0] !== 0) throw new Error("X.509: malformed SubjectPublicKeyInfo");
  const keyAlg = algId(spki.children[0]);

  const c: X509Cert = {
    raw: root.bytes,
    tbs: tbs.bytes,
    sigAlg: algId(outerAlg),
    signature: sigBits.content.subarray(1),
    serial: unsignedInt(serial, "serial number"),
    issuerRaw: issuer.bytes,
    subjectRaw: subject.bytes,
    notBefore: parseTime(validity.children?.[0]),
    notAfter: parseTime(validity.children?.[1]),
    spki: spki.bytes,
    keyAlg,
    hasBasicConstraints: false,
    isCA: false,
    hasNameConstraints: false,
    name: nameString(subject),
  };
  if (keyAlg.oid === OID.rsaEncryption || keyAlg.oid === OID.rsaPss) {
    const n = parseDer(keyBits.content.subarray(1)).node.children?.[0];
    const mod = unsignedInt(n, "RSA modulus");
    c.rsaBits = (mod.length - 1) * 8 + (32 - Math.clz32(mod[0]!));
  }

  const exts = rest.find((n) => n.tag === 0xa3)?.children?.[0]?.children ?? [];
  const seen = new Set<string>();
  for (const e of exts) {
    const k = e.children ?? [];
    const id = k[0]?.tag === 0x06 ? oidString(k[0].content) : "";
    const critical = k.length === 3 && k[1]!.tag === 0x01 && k[1]!.content[0] !== 0;
    const value = k[k.length - 1];
    if (!id || !value || value.tag !== 0x04 || k.length < 2 || k.length > 3) throw new Error("X.509: malformed extension");
    if (seen.has(id)) throw new Error(`X.509: extension ${id} appears twice`);
    seen.add(id);
    if (critical && !CRITICAL_OK.has(id) && id !== OID.nameConstraints) c.unknownCritical ??= id;
    if (id === OID.nameConstraints) c.hasNameConstraints = true;
    if (id !== OID.basicConstraints && id !== OID.keyUsage && id !== OID.extKeyUsage && id !== OID.subjectKeyId) continue;
    const v = parseDer(value.content).node;
    if (id === OID.basicConstraints) {
      c.hasBasicConstraints = true;
      const kids = v.children ?? [];
      c.isCA = kids[0]?.tag === 0x01 && kids[0].content[0] !== 0;
      const pl = kids.find((n) => n.tag === 0x02);
      if (pl) {
        if (pl.content.length > 2 || pl.content[0]! & 0x80) throw new Error("X.509: malformed pathLenConstraint");
        c.pathLen = pl.content.reduce((a, x) => a * 256 + x, 0);
      }
    } else if (id === OID.keyUsage) {
      if (v.tag !== 0x03 || v.content.length < 2) throw new Error("X.509: malformed keyUsage");
      c.keyUsage = v.content[1]!;
    } else if (id === OID.extKeyUsage) {
      c.eku = (v.children ?? []).map((n) => oidString(n.content));
    } else if (v.tag === 0x04) c.subjectKeyId = v.content;
  }
  return c;
}

export function pemToDer(input: Uint8Array | string): Uint8Array[] {
  if (typeof input !== "string") return [input];
  const out: Uint8Array[] = [];
  for (const m of input.matchAll(/-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----/g)) out.push(fromBase64(m[1]!.replace(/\s+/g, "")));
  if (!out.length) throw new Error("no PEM certificate found");
  return out;
}

// --- signatures

function ecdsaP1363(der: Uint8Array, size: number): Uint8Array {
  const { node, next } = parseDer(der);
  const ints = node.children ?? [];
  if (node.tag !== 0x30 || next !== der.length || ints.length !== 2) throw new Error("malformed ECDSA signature");
  const out = new Uint8Array(size * 2);
  ints.forEach((n, k) => {
    if (n.tag !== 0x02 || !n.content.length || n.content[0]! & 0x80) throw new Error("malformed ECDSA signature");
    let v = n.content;
    while (v.length > 1 && v[0] === 0) v = v.subarray(1);
    if (v.length > size) throw new Error("malformed ECDSA signature");
    out.set(v, k * size + (size - v.length));
  });
  return out;
}

function pssParams(p: Der | undefined): { hash: ShaName; saltLength: number } {
  let hash: ShaName | undefined;
  let mgfHash: string | undefined;
  let saltLength = 20;
  for (const n of p?.children ?? []) {
    const inner = n.children?.[0];
    if (n.tag === 0xa0) hash = shaName(algId(inner).oid);
    else if (n.tag === 0xa1) {
      const mgf = algId(inner);
      if (mgf.oid !== OID.mgf1) throw new Error("RSA-PSS mask generation function is not MGF1");
      mgfHash = algId(mgf.params).oid;
    } else if (n.tag === 0xa2) {
      if (!inner || inner.tag !== 0x02 || inner.content.length > 2) throw new Error("RSA-PSS parameters are malformed");
      saltLength = inner.content.reduce((a, x) => a * 256 + x, 0);
    }
  }
  if (!hash) throw new Error("RSA-PSS hash is not SHA-256, SHA-384, or SHA-512");
  if (!mgfHash || shaName(mgfHash) !== hash) throw new Error("RSA-PSS MGF1 hash differs from the message hash");
  return { hash, saltLength };
}

// fallbackHash is used when the algorithm names only the key type (CMS rsaEncryption / id-ecPublicKey)
export async function verifyWithCert(cert: X509Cert, alg: AlgId, fallbackHash: ShaName | undefined, data: Uint8Array, sig: Uint8Array): Promise<boolean> {
  const subtle = globalThis.crypto.subtle;
  const named: Record<string, ShaName> = {
    [OID.sha256WithRsa]: "SHA-256",
    [OID.sha384WithRsa]: "SHA-384",
    [OID.sha512WithRsa]: "SHA-512",
    [OID.ecdsaSha256]: "SHA-256",
    [OID.ecdsaSha384]: "SHA-384",
    [OID.ecdsaSha512]: "SHA-512",
  };
  const hash = named[alg.oid] ?? fallbackHash;
  const isRsa = alg.oid === OID.rsaEncryption || alg.oid === OID.sha256WithRsa || alg.oid === OID.sha384WithRsa || alg.oid === OID.sha512WithRsa;
  const isPss = alg.oid === OID.rsaPss;
  const isEc = alg.oid === OID.ecPublicKey || alg.oid === OID.ecdsaSha256 || alg.oid === OID.ecdsaSha384 || alg.oid === OID.ecdsaSha512;
  if (!isRsa && !isPss && !isEc) throw new Error(`signature algorithm ${alg.oid} is not supported`);

  if (isRsa || isPss) {
    if (cert.keyAlg.oid !== OID.rsaEncryption && !(isPss && cert.keyAlg.oid === OID.rsaPss)) throw new Error("signature algorithm is RSA but the certificate key is not");
    if ((cert.rsaBits ?? 0) < 2048) throw new Error("RSA key is shorter than 2048 bits");
    if (isPss) {
      const p = pssParams(alg.params);
      const key = await subtle.importKey("spki", cert.spki as BufferSource, { name: "RSA-PSS", hash: p.hash }, false, ["verify"]);
      return subtle.verify({ name: "RSA-PSS", saltLength: p.saltLength }, key, sig as BufferSource, data as BufferSource);
    }
    if (!hash) throw new Error("signature hash is not SHA-256, SHA-384, or SHA-512");
    const key = await subtle.importKey("spki", cert.spki as BufferSource, { name: "RSASSA-PKCS1-v1_5", hash }, false, ["verify"]);
    return subtle.verify("RSASSA-PKCS1-v1_5", key, sig as BufferSource, data as BufferSource);
  }
  if (cert.keyAlg.oid !== OID.ecPublicKey) throw new Error("signature algorithm is ECDSA but the certificate key is not");
  if (!hash) throw new Error("signature hash is not SHA-256, SHA-384, or SHA-512");
  const curve = cert.keyAlg.params?.tag === 0x06 ? CURVES[oidString(cert.keyAlg.params.content)] : undefined;
  if (!curve) throw new Error("elliptic curve is not P-256, P-384, or P-521");
  let raw: Uint8Array;
  try {
    raw = ecdsaP1363(sig, curve.size);
  } catch {
    return false;
  }
  const key = await subtle.importKey("spki", cert.spki as BufferSource, { name: "ECDSA", namedCurve: curve.name }, false, ["verify"]);
  return subtle.verify({ name: "ECDSA", hash }, key, raw as BufferSource, data as BufferSource);
}

// --- path validation (RFC 5280 6.1, without policies, name constraints and revocation)

const MAX_PATH = 8;
const MAX_SIGNATURE_CHECKS = 32;

function usableFor(c: X509Cert, eku: string): boolean {
  return !c.eku || c.eku.includes(eku) || c.eku.includes(OID.ekuAny);
}

function issuerProblem(c: X509Cert, below: number, at: number, eku: string, anchor: boolean): string | undefined {
  if (at < c.notBefore || at > c.notAfter) return `"${c.name}" was not valid at that time`;
  if (c.unknownCritical) return `"${c.name}" has an unsupported critical extension ${c.unknownCritical}`;
  if (c.hasNameConstraints) return `"${c.name}" has name constraints, which are not supported`;
  // a version 1 trust anchor has no basicConstraints; anything else that signs must be a CA
  if (anchor ? c.hasBasicConstraints && !c.isCA : !c.isCA) return `"${c.name}" is not a CA certificate`;
  if (c.keyUsage !== undefined && !(c.keyUsage & 0x04)) return `"${c.name}" may not sign certificates`;
  if (c.pathLen !== undefined && below > c.pathLen) return `"${c.name}" allows a shorter path`;
  if (!usableFor(c, eku)) return `"${c.name}" is not usable for this purpose`;
  return undefined;
}

export interface PathOptions {
  roots: X509Cert[];
  intermediates: X509Cert[];
  // unix milliseconds
  at: number;
  eku: string;
}

export async function buildPath(leaf: X509Cert, o: PathOptions): Promise<X509Cert[]> {
  if (leaf.unknownCritical) throw new Error(`"${leaf.name}" has an unsupported critical extension ${leaf.unknownCritical}`);
  if (o.roots.some((r) => bytesEqual(r.raw, leaf.raw))) return [leaf];
  let budget = MAX_SIGNATURE_CHECKS;
  let reason = "";
  const signs = async (issuer: X509Cert, child: X509Cert): Promise<boolean> => {
    if (budget-- <= 0) throw new Error("too many candidate certificates");
    try {
      return await verifyWithCert(issuer, child.sigAlg, undefined, child.tbs, child.signature);
    } catch (e) {
      reason ||= (e as Error).message;
      return false;
    }
  };
  const walk = async (path: X509Cert[]): Promise<X509Cert[] | undefined> => {
    const child = path[path.length - 1]!;
    const below = path.length - 1;
    for (const r of o.roots) {
      if (!bytesEqual(r.subjectRaw, child.issuerRaw)) continue;
      const p = issuerProblem(r, below, o.at, o.eku, true);
      if (p) {
        reason ||= p;
        continue;
      }
      if (await signs(r, child)) return [...path, r];
    }
    if (path.length >= MAX_PATH) return undefined;
    for (const c of o.intermediates) {
      if (!bytesEqual(c.subjectRaw, child.issuerRaw) || path.some((x) => bytesEqual(x.raw, c.raw))) continue;
      const p = issuerProblem(c, below, o.at, o.eku, false);
      if (p) {
        reason ||= p;
        continue;
      }
      if (!(await signs(c, child))) continue;
      const done = await walk([...path, c]);
      if (done) return done;
    }
    return undefined;
  };
  const found = await walk([leaf]);
  if (!found) throw new Error(reason || `no trusted root issued "${leaf.name}" or its issuers`);
  return found;
}

export function derSet(elems: Uint8Array[]): Uint8Array {
  const sorted = [...elems].sort((a, b) => {
    for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i]! - b[i]!;
    return a.length - b.length;
  });
  const body = concat(...sorted);
  const len: number[] = [];
  for (let n = body.length; n > 0; n = Math.floor(n / 256)) len.unshift(n & 0xff);
  return concat(new Uint8Array(body.length < 0x80 ? [0x31, body.length] : [0x31, 0x80 | len.length, ...len]), body);
}
