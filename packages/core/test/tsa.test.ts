import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DEFAULT_TSA_ROOTS, checkTsaToken, concat, p1363ToDer, readTsaRoots, requestTimestamp, sha256, signDocument, signerFromSeed, timestampDocument, toBase64, toHex, utf8, verifyDocument } from "../src/index.ts";
import { genTimeMs, formatTimeMs, parseDocument, toJsonResult } from "../src/index.ts";
import { exampleOptions } from "./harness.ts";
import { parseDer } from "../src/der.ts";
import { derSet, parseCertificate } from "../src/x509.ts";

// --- DER builders

const len = (n: number) => {
  if (n < 0x80) return new Uint8Array([n]);
  const out: number[] = [];
  for (; n > 0; n = Math.floor(n / 256)) out.unshift(n & 0xff);
  return new Uint8Array([0x80 | out.length, ...out]);
};
const tlv = (tag: number, ...c: Uint8Array[]) => {
  const body = concat(...c);
  return concat(new Uint8Array([tag]), len(body.length), body);
};
const seq = (...c: Uint8Array[]) => tlv(0x30, ...c);
const set = (...c: Uint8Array[]) => tlv(0x31, ...c);
const octets = (b: Uint8Array) => tlv(0x04, b);
const int = (n: number | Uint8Array) => {
  let b = typeof n === "number" ? new Uint8Array(n < 256 ? [n] : [n >> 8, n & 0xff]) : n;
  if (b[0]! & 0x80) b = concat(new Uint8Array([0]), b);
  return tlv(0x02, b);
};
const oid = (s: string) => {
  const p = s.split(".").map(Number);
  const out = [p[0]! * 40 + p[1]!];
  for (const v of p.slice(2)) {
    const chunk = [v & 0x7f];
    for (let x = Math.floor(v / 128); x > 0; x = Math.floor(x / 128)) chunk.unshift((x & 0x7f) | 0x80);
    out.push(...chunk);
  }
  return tlv(0x06, new Uint8Array(out));
};
const NULL = new Uint8Array([0x05, 0x00]);
const TRUE = new Uint8Array([0x01, 0x01, 0xff]);
const name = (cn: string) => seq(set(seq(oid("2.5.4.3"), tlv(0x0c, utf8(cn)))));
const utcTime = (d: Date) => tlv(0x17, utf8(d.toISOString().replace(/[-:T]/g, "").slice(2, 14) + "Z"));
const genTimeDer = (d: Date) => tlv(0x18, utf8(d.toISOString().replace(/[-:T]/g, "").slice(0, 14) + "Z"));

const SHA256 = seq(oid("2.16.840.1.101.3.4.2.1"), NULL);
const SHA1 = seq(oid("1.3.14.3.2.26"), NULL);
const ECDSA_SHA256 = seq(oid("1.2.840.10045.4.3.2"));
const RSA_SHA256 = seq(oid("1.2.840.113549.1.1.11"), NULL);
const TSTINFO = "1.2.840.113549.1.9.16.1.4";
const EKU_TS = "1.3.6.1.5.5.7.3.8";

// --- test PKI

interface Key {
  spki: Uint8Array;
  alg: Uint8Array;
  sign(data: Uint8Array): Promise<Uint8Array>;
}

async function ecKey(): Promise<Key> {
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  return {
    spki: new Uint8Array(await crypto.subtle.exportKey("spki", kp.publicKey)),
    alg: ECDSA_SHA256,
    sign: async (d) => p1363ToDer(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, d as BufferSource))),
  };
}

async function rsaKey(bits: number): Promise<Key> {
  const kp = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: bits, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  return {
    spki: new Uint8Array(await crypto.subtle.exportKey("spki", kp.publicKey)),
    alg: RSA_SHA256,
    sign: async (d) => new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, d as BufferSource)),
  };
}

interface CertSpec {
  cn: string;
  key: Key;
  issuerCn?: string;
  issuerKey?: Key;
  ca?: boolean;
  pathLen?: number;
  keyUsage?: number;
  eku?: string[];
  notBefore?: Date;
  notAfter?: Date;
  extra?: Uint8Array[];
  noExtensions?: boolean;
}

let serialCounter = 1;
const ext = (id: string, critical: boolean, value: Uint8Array) => seq(oid(id), ...(critical ? [TRUE] : []), octets(value));

async function cert(s: CertSpec): Promise<Uint8Array> {
  const exts: Uint8Array[] = [];
  if (s.ca !== undefined) exts.push(ext("2.5.29.19", true, seq(...(s.ca ? [TRUE] : []), ...(s.pathLen !== undefined ? [int(s.pathLen)] : []))));
  if (s.keyUsage !== undefined) exts.push(ext("2.5.29.15", true, tlv(0x03, new Uint8Array([0, s.keyUsage]))));
  if (s.eku) exts.push(ext("2.5.29.37", true, seq(...s.eku.map(oid))));
  exts.push(...(s.extra ?? []));
  const signer = s.issuerKey ?? s.key;
  const tbs = seq(
    tlv(0xa0, int(2)),
    int(serialCounter++),
    signer.alg,
    name(s.issuerCn ?? s.cn),
    seq(utcTime(s.notBefore ?? new Date("2026-01-01T00:00:00Z")), utcTime(s.notAfter ?? new Date("2036-01-01T00:00:00Z"))),
    name(s.cn),
    s.key.spki,
    ...(s.noExtensions ? [] : [tlv(0xa3, seq(...exts))]),
  );
  return seq(tbs, signer.alg, tlv(0x03, new Uint8Array([0]), await signer.sign(tbs)));
}

interface TokenSpec {
  leaf: Uint8Array;
  key: Key;
  chain?: Uint8Array[];
  sig: Uint8Array;
  genTime?: Date;
  accuracy?: Uint8Array;
  nonce?: Uint8Array;
  digestAlg?: Uint8Array;
  signingCert?: "v2" | "v1" | "none" | "wrong";
  noSignedAttrs?: boolean;
  twoSigners?: boolean;
  mutateTst?: (tst: Uint8Array) => Uint8Array;
  sidBySki?: Uint8Array;
  // a token over this imprint instead of SHA-256(sig)
  imprint?: { hashAlgId: Uint8Array; value: Uint8Array };
}

async function token(s: TokenSpec): Promise<string> {
  const mi = s.imprint ? seq(s.imprint.hashAlgId, octets(s.imprint.value)) : seq(SHA256, octets(await sha256(s.sig)));
  const tst = seq(int(1), oid("1.2.3.4"), mi, int(7), genTimeDer(s.genTime ?? new Date("2026-11-16T10:00:00Z")), ...(s.accuracy ? [s.accuracy] : []), ...(s.nonce ? [int(s.nonce)] : []));
  const c = parseCertificate(s.leaf);
  const attrs = [seq(oid("1.2.840.113549.1.9.3"), set(oid(TSTINFO))), seq(oid("1.2.840.113549.1.9.4"), set(octets(await sha256(tst))))];
  const mode = s.signingCert ?? "v2";
  const hashed = mode === "wrong" ? s.key.spki : s.leaf;
  if (mode === "v2" || mode === "wrong") attrs.push(seq(oid("1.2.840.113549.1.9.16.2.47"), set(seq(seq(seq(octets(await sha256(hashed))))))));
  if (mode === "v1") attrs.push(seq(oid("1.2.840.113549.1.9.16.2.12"), set(seq(seq(seq(octets(new Uint8Array(await crypto.subtle.digest("SHA-1", s.leaf as BufferSource)))))))));
  const signedSet = derSet(attrs);
  const body = parseDer(signedSet).node.content;
  const sid = s.sidBySki ? tlv(0x80, s.sidBySki) : seq(c.issuerRaw, int(c.serial));
  const info = seq(
    int(1),
    sid,
    s.digestAlg ?? SHA256,
    ...(s.noSignedAttrs ? [] : [tlv(0xa0, body)]),
    s.key.alg,
    octets(await s.key.sign(s.noSignedAttrs ? tst : signedSet)),
  );
  const eContent = s.mutateTst ? s.mutateTst(tst) : tst;
  const sd = seq(int(3), set(SHA256), seq(oid(TSTINFO), tlv(0xa0, octets(eContent))), tlv(0xa0, s.leaf, ...(s.chain ?? [])), set(info, ...(s.twoSigners ? [info] : [])));
  const resp = seq(seq(int(0)), seq(oid("1.2.840.113549.1.7.2"), tlv(0xa0, sd)));
  return "base64:" + toBase64(resp);
}

const SIG = new Uint8Array(64).fill(7);

async function pki() {
  const rootKey = await ecKey();
  const caKey = await ecKey();
  const leafKey = await ecKey();
  const root = await cert({ cn: "Test Root", key: rootKey, ca: true, keyUsage: 0x06 });
  const ca = await cert({ cn: "Test TSA CA", key: caKey, issuerCn: "Test Root", issuerKey: rootKey, ca: true, pathLen: 0, keyUsage: 0x06 });
  const leaf = await cert({ cn: "Test TSA", key: leafKey, issuerCn: "Test TSA CA", issuerKey: caKey, ca: false, keyUsage: 0x80, eku: [EKU_TS] });
  return { rootKey, caKey, leafKey, root, ca, leaf };
}

const errors = async (tok: string, roots: Uint8Array[], re: RegExp) => {
  const r = await checkTsaToken(tok, SIG, { roots });
  assert.equal(r.status, "error", r.detail);
  assert.equal(r.verified, false);
  assert.equal(r.genTime, undefined);
  assert.match(r.detail, re);
};

// --- chain and signature

test("tsa: a token chaining to a given root is verified", async () => {
  const p = await pki();
  const tok = await token({ leaf: p.leaf, key: p.leafKey, chain: [p.ca], sig: SIG });
  const r = await checkTsaToken(tok, SIG, { roots: [p.root] });
  assert.deepEqual({ status: r.status, verified: r.verified, genTime: r.genTime, signer: r.signer }, { status: "ok", verified: true, genTime: "2026-11-16T10:00:00Z", signer: "Test TSA" });

  const pem = `-----BEGIN CERTIFICATE-----\n${toBase64(p.root)}\n-----END CERTIFICATE-----\n`;
  assert.equal((await checkTsaToken(tok, SIG, { roots: [pem] })).verified, true);
  const v1 = await token({ leaf: p.leaf, key: p.leafKey, chain: [p.ca], sig: SIG, signingCert: "v1" });
  assert.equal((await checkTsaToken(v1, SIG, { roots: [p.root] })).verified, true);
});

test("tsa: the same token is not verified without its root", async () => {
  const p = await pki();
  const tok = await token({ leaf: p.leaf, key: p.leafKey, chain: [p.ca], sig: SIG });
  await errors(tok, [], /does not chain to a trusted root/);
  const other = await pki();
  await errors(tok, [other.root], /does not chain to a trusted root/);
  const def = await checkTsaToken(tok, SIG);
  assert.equal(def.verified, false);
  assert.match(def.detail, /does not chain to a trusted root/);
  await errors(await token({ leaf: p.leaf, key: p.leafKey, chain: [p.ca, p.root], sig: SIG }), [other.root], /does not chain/);
});

test("tsa: extra roots are added to the built-in or the given roots", async () => {
  const p = await pki();
  const other = await pki();
  const tok = await token({ leaf: p.leaf, key: p.leafKey, chain: [p.ca], sig: SIG });
  const pem = (der: Uint8Array) => `-----BEGIN CERTIFICATE-----\n${toBase64(der)}\n-----END CERTIFICATE-----\n`;
  assert.equal((await checkTsaToken(tok, SIG, { extraRoots: [p.root] })).verified, true);
  assert.equal((await checkTsaToken(tok, SIG, { roots: [other.root], extraRoots: [pem(other.ca) + pem(p.root)] })).verified, true);
  assert.equal((await checkTsaToken(tok, SIG, { roots: [], extraRoots: [other.root] })).verified, false);

  const listed = await readTsaRoots(pem(other.ca) + pem(p.root));
  assert.deepEqual(listed.map((r) => r.name), ["Test TSA CA", "Test Root"]);
  assert.equal(listed[1]!.sha256, toHex(await sha256(p.root)));
  assert.equal(listed[1]!.notAfter, "2036-01-01");
  await assert.rejects(readTsaRoots("not a certificate"));

  const bad = await checkTsaToken(tok, SIG, { extraRoots: ["not a certificate"] });
  assert.equal(bad.verified, false);
  assert.match(bad.detail, /extraTsaRoots\[0\] is not a certificate/);
});

test("tsa: imprint for another signature is a mismatch", async () => {
  const p = await pki();
  const tok = await token({ leaf: p.leaf, key: p.leafKey, chain: [p.ca], sig: new Uint8Array(64).fill(8) });
  const r = await checkTsaToken(tok, SIG, { roots: [p.root] });
  assert.equal(r.status, "mismatch");
  assert.equal(r.genTime, undefined);
});

test("tsa: a changed TSTInfo or a foreign signature is rejected", async () => {
  const p = await pki();
  const later = (tst: Uint8Array) => {
    const out = tst.slice();
    const at = out.findIndex((x, i) => x === 0x18 && out[i + 1] === 15);
    out[at + 5] = 0x37;
    return out;
  };
  await errors(await token({ leaf: p.leaf, key: p.leafKey, chain: [p.ca], sig: SIG, mutateTst: later }), [p.root], /message-digest does not match/);
  const mallory = await ecKey();
  await errors(await token({ leaf: p.leaf, key: mallory, chain: [p.ca], sig: SIG }), [p.root], /signature does not verify/);
});

test("tsa: CMS structure rules", async () => {
  const p = await pki();
  const base = { leaf: p.leaf, key: p.leafKey, chain: [p.ca], sig: SIG };
  await errors(await token({ ...base, noSignedAttrs: true }), [p.root], /no signed attributes/);
  await errors(await token({ ...base, twoSigners: true }), [p.root], /2 SignerInfos/);
  await errors(await token({ ...base, signingCert: "none" }), [p.root], /no signing-certificate attribute/);
  await errors(await token({ ...base, signingCert: "wrong" }), [p.root], /does not match the TSA certificate/);
  await errors(await token({ ...base, digestAlg: SHA1 }), [p.root], /digest algorithm 1\.3\.14\.3\.2\.26/);
  await errors(await token({ ...base, sidBySki: new Uint8Array(20) }), [p.root], /not included in the token/);
});

test("tsa: certificate rules", async () => {
  const p = await pki();
  const leafOf = (o: Partial<CertSpec>, issuerKey = p.caKey, issuerCn = "Test TSA CA") => cert({ cn: "Test TSA", key: p.leafKey, issuerCn, issuerKey, ca: false, eku: [EKU_TS], ...o });
  const tok = (leaf: Uint8Array, chain = [p.ca], genTime?: Date) => token({ leaf, key: p.leafKey, chain, sig: SIG, genTime });

  await errors(await tok(await leafOf({ eku: ["1.3.6.1.5.5.7.3.1"] })), [p.root], /lacks the timeStamping/);
  await errors(await tok(await leafOf({ eku: undefined })), [p.root], /lacks the timeStamping/);
  await errors(await tok(p.leaf, [p.ca], new Date("2037-01-01T00:00:00Z")), [p.root], /not valid at the token's time/);
  await errors(await tok(await leafOf({ extra: [ext("1.2.3.4.5", true, NULL)] })), [p.root], /unsupported critical extension 1\.2\.3\.4\.5/);

  const endKey = await ecKey();
  const end = await cert({ cn: "End Entity", key: endKey, issuerCn: "Test TSA CA", issuerKey: p.caKey, ca: false, eku: [EKU_TS] });
  await errors(await tok(await leafOf({}, endKey, "End Entity"), [end, p.ca]), [p.root], /not a CA certificate/);

  const subKey = await ecKey();
  const sub = await cert({ cn: "Sub CA", key: subKey, issuerCn: "Test TSA CA", issuerKey: p.caKey, ca: true });
  await errors(await tok(await leafOf({}, subKey, "Sub CA"), [sub, p.ca]), [p.root], /allows a shorter path/);

  const expiredCa = await cert({ cn: "Test TSA CA", key: p.caKey, issuerCn: "Test Root", issuerKey: p.rootKey, ca: true, notAfter: new Date("2026-06-01T00:00:00Z") });
  await errors(await tok(p.leaf, [expiredCa]), [p.root], /was not valid at that time/);
  const noSignCa = await cert({ cn: "Test TSA CA", key: p.caKey, issuerCn: "Test Root", issuerKey: p.rootKey, ca: true, keyUsage: 0x80 });
  await errors(await tok(p.leaf, [noSignCa]), [p.root], /may not sign certificates/);
  const tlsCa = await cert({ cn: "Test TSA CA", key: p.caKey, issuerCn: "Test Root", issuerKey: p.rootKey, ca: true, eku: ["1.3.6.1.5.5.7.3.1"] });
  await errors(await tok(p.leaf, [tlsCa]), [p.root], /not usable for this purpose/);
  const constrained = await cert({ cn: "Test TSA CA", key: p.caKey, issuerCn: "Test Root", issuerKey: p.rootKey, ca: true, extra: [ext("2.5.29.30", true, seq())] });
  await errors(await tok(p.leaf, [constrained]), [p.root], /name constraints/);
  const fakeCa = await cert({ cn: "Test TSA CA", key: p.caKey, issuerCn: "Test Root", issuerKey: await ecKey(), ca: true });
  await errors(await tok(p.leaf, [fakeCa]), [p.root], /does not chain/);
});

test("tsa: RSA certificates verify, short RSA keys do not", async () => {
  const rootKey = await rsaKey(2048);
  const root = await cert({ cn: "RSA Root", key: rootKey, ca: true });
  const leafKey = await rsaKey(2048);
  const leaf = await cert({ cn: "RSA TSA", key: leafKey, issuerCn: "RSA Root", issuerKey: rootKey, ca: false, eku: [EKU_TS] });
  assert.equal((await checkTsaToken(await token({ leaf, key: leafKey, sig: SIG }), SIG, { roots: [root] })).verified, true);

  const weakKey = await rsaKey(1024);
  const weak = await cert({ cn: "Weak TSA", key: weakKey, issuerCn: "RSA Root", issuerKey: rootKey, ca: false, eku: [EKU_TS] });
  await errors(await token({ leaf: weak, key: weakKey, sig: SIG }), [root], /shorter than 2048 bits/);
});

test("tsa: a self-signed TSA certificate is trusted only as a root", async () => {
  const key = await ecKey();
  const self = await cert({ cn: "Self TSA", key, ca: false, eku: [EKU_TS] });
  const tok = await token({ leaf: self, key, sig: SIG });
  await errors(tok, [], /does not chain/);
  assert.equal((await checkTsaToken(tok, SIG, { roots: [self] })).verified, true);
});

// --- real token and built-in roots

test("tsa: built-in roots are self-issued, unexpired and match their fingerprints", async () => {
  assert.ok(DEFAULT_TSA_ROOTS.length >= 5);
  for (const r of DEFAULT_TSA_ROOTS) {
    const c = parseCertificate(r.der);
    assert.deepEqual(c.issuerRaw, c.subjectRaw, r.name);
    assert.equal(toHex(await sha256(r.der)), r.sha256, r.name);
    assert.ok(c.notAfter > Date.parse("2027-01-01T00:00:00Z"), r.name);
  }
});

test("tsa: the example token verifies with the built-in roots and not with an empty set", async () => {
  const text = readFileSync(new URL("../../../examples/valid-cosigned.md", import.meta.url), "utf8");
  if (!/^method: tsa$/m.test(text)) return;
  const o = exampleOptions();
  const ok = await verifyDocument(text, o);
  const tsa = ok.signatures[2]!.tsa!;
  assert.equal(tsa.verified, true, tsa.detail);
  assert.match(tsa.signer!, /SSL.com/);
  assert.ok(tsa.genTime);
  assert.equal(ok.signatures[1]!.time!.block, 3);

  const extra = await verifyDocument(text, { ...o, extraTsaRoots: [DEFAULT_TSA_ROOTS[0]!.der] });
  assert.equal(extra.signatures[2]!.tsa!.verified, true);

  const none = await verifyDocument(text, { ...o, tsaRoots: [] });
  const s = none.signatures[2]!;
  assert.deepEqual([s.status, s.code], ["unresolved", "not-found"]);
  assert.equal(s.tsa!.verified, false);
  assert.equal(s.tsa!.genTime, undefined);
  assert.equal(none.signatures[1]!.time, undefined);
});

// --- requesting

test("tsa: requestTimestamp verifies the response and its nonce", async () => {
  const p = await pki();
  const reqNonce = (init: RequestInit) => {
    const kids = parseDer(new Uint8Array(init.body as ArrayBuffer)).node.children!;
    return kids.find((n, i) => i > 1 && n.tag === 0x02)!.content;
  };
  const respond = (make: (nonce: Uint8Array) => Promise<string>) =>
    (async (_url: string, init: RequestInit) => {
      const b64 = (await make(reqNonce(init))).slice("base64:".length);
      return new Response(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)));
    }) as unknown as typeof globalThis.fetch;
  const base = { leaf: p.leaf, key: p.leafKey, chain: [p.ca], sig: SIG };

  const tok = await requestTimestamp(SIG, "https://tsa.test/", respond((nonce) => token({ ...base, nonce })), { roots: [p.root] });
  assert.equal((await checkTsaToken(tok, SIG, { roots: [p.root] })).verified, true);

  await assert.rejects(requestTimestamp(SIG, "https://tsa.test/", respond(() => token({ ...base, nonce: new Uint8Array([1, 2, 3]) })), { roots: [p.root] }), /nonce does not match/);
  await assert.rejects(requestTimestamp(SIG, "https://tsa.test/", respond(() => token(base)), { roots: [p.root] }), /nonce does not match/);
  await assert.rejects(requestTimestamp(SIG, "https://tsa.test/", respond((nonce) => token({ ...base, nonce })), { roots: [] }), /TSA response rejected: .*does not chain/);
  await assert.rejects(requestTimestamp(SIG, "https://tsa.test/", respond((nonce) => token({ ...base, nonce, sig: new Uint8Array(64) }))), /TSA response rejected: .*different imprint/);
});

// --- tsa blocks (SPEC 4.6)

test("tsa block: a timestamp over everything before it, renewable with sha512", async () => {
  const p = await pki();
  // a TSA that answers any request: it echoes the request's hash algorithm, imprint and nonce
  const tsa = (async (_url: string, init: RequestInit) => {
    const req = parseDer(new Uint8Array(init.body as ArrayBuffer)).node.children!;
    const mi = req[1]!;
    const nonce = req.find((n, i) => i > 1 && n.tag === 0x02)!.content;
    const b64 = (await token({ leaf: p.leaf, key: p.leafKey, chain: [p.ca], sig: SIG, nonce, imprint: { hashAlgId: mi.children![0]!.bytes, value: mi.children![1]!.content } })).slice(7);
    return new Response(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)));
  }) as unknown as typeof globalThis.fetch;
  const roots = { tsaRoots: [p.root] };
  const signed = (await signDocument("# Doc\n", { signer: await signerFromSeed(new Uint8Array(32).fill(1)), method: "tofu", signerId: "alice", ts: "2026-11-16T09:00:00Z" })).text;
  const t1 = (await timestampDocument(signed, { tsaUrl: "https://tsa.test/", fetch: tsa, ts: "2026-11-16T09:30:00Z", ...roots })).text;
  assert.match(t1, /\nmethod: tsa\nsigner: https:\/\/tsa\.test\/\nts: 2026-11-16T09:30:00Z\nalg: rfc3161\nhash: sha256:/);
  const v1 = await verifyDocument(t1, { offline: true, ...roots });
  assert.equal(v1.ok, true, JSON.stringify(v1.signatures[1]));
  assert.deepEqual([v1.signatures[1]!.status, v1.signatures[1]!.tsa!.verified, v1.signatures[1]!.tsa!.signer], ["valid", true, "Test TSA"]);
  assert.equal(v1.agreement.status, "none");

  const t2 = (await timestampDocument(t1, { tsaUrl: "https://tsa.test/", fetch: tsa, hash: "sha512", ...roots })).text;
  const v2 = await verifyDocument(t2, { offline: true, ...roots });
  assert.deepEqual(v2.signatures.map((s) => s.status), ["valid", "valid", "valid"]);
  assert.match(v2.signatures[2]!.fields.hash!, /^sha512:[0-9a-f]{128}$/);

  // the renewal covers the first token: changing it breaks the second block
  const firstSig = /method: tsa[\s\S]*?sig: \|\n {2}gzip\+base64:(\S)/.exec(t2)!;
  const swapped = t2.replace(firstSig[0], firstSig[0].slice(0, -1) + (firstSig[1] === "A" ? "B" : "A"));
  assert.deepEqual((await verifyDocument(swapped, { offline: true, ...roots })).signatures.slice(1).map((s) => s.code ?? s.status), ["malformed", "hash-mismatch"]);

  const untrusted = await verifyDocument(t1, { offline: true, tsaRoots: [] });
  assert.deepEqual([untrusted.ok, untrusted.signatures[1]!.status, untrusted.signatures[1]!.code], [false, "unresolved", "not-found"]);
  assert.equal(untrusted.signatures[1]!.tsa!.genTime, undefined);
  const edited = await verifyDocument(t1.replace("# Doc", "# Dog"), { offline: true, ...roots });
  assert.deepEqual(edited.signatures.map((s) => s.code), ["hash-mismatch", "hash-mismatch"]);

  const block = (from: string, to: string) => verifyDocument(t1.replace(from, to), { offline: true, ...roots }).then((r) => r.signatures[1]!);
  assert.match((await block("alg: rfc3161\n", "alg: rfc3161\nrole: witness\n")).message!, /"role" is not allowed with method tsa/);
  assert.match((await block("alg: rfc3161\n", "alg: ed25519\n")).message!, /method tsa requires alg rfc3161/);
  assert.equal((await block("ts: 2026-11-16T09:30:00Z\n", "ts: 2026-11-16T09:31:00Z\n")).code, "bad-signature");
});

test("tsa block: never satisfies require, cannot be required", async () => {
  const p = await pki();
  const tsa = (async (_url: string, init: RequestInit) => {
    const req = parseDer(new Uint8Array(init.body as ArrayBuffer)).node.children!;
    const mi = req[1]!;
    const nonce = req.find((n, i) => i > 1 && n.tag === 0x02)!.content;
    const b64 = (await token({ leaf: p.leaf, key: p.leafKey, chain: [p.ca], sig: SIG, nonce, imprint: { hashAlgId: mi.children![0]!.bytes, value: mi.children![1]!.content } })).slice(7);
    return new Response(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)));
  }) as unknown as typeof globalThis.fetch;
  const a = await signerFromSeed(new Uint8Array(32).fill(1));
  await assert.rejects(signDocument("# Doc\n", { signer: a, method: "tofu", signerId: "alice", require: ["tsa:https://tsa.test/"] }), /cannot be required/);
  const declared = (await signDocument("# Doc\n", { signer: a, method: "tofu", signerId: "alice", require: ["tofu:bob"] })).text;
  const stamped = (await timestampDocument(declared, { tsaUrl: "https://tsa.test/", fetch: tsa, tsaRoots: [p.root] })).text;
  assert.equal((await verifyDocument(stamped, { offline: true, tsaRoots: [p.root] })).agreement.status, "pending");
  await assert.rejects(timestampDocument("# no signature\n", { fetch: tsa }), /no signature to timestamp/);
});

test("tsa: signDocument with tsaUrl appends a tsa block; T(k) is the earliest genTime + accuracy after k", async () => {
  const p = await pki();
  let next: { genTime: Date; accuracy?: Uint8Array } = { genTime: new Date("2026-11-16T10:00:00Z") };
  const tsa = (async (_url: string, init: RequestInit) => {
    const req = parseDer(new Uint8Array(init.body as ArrayBuffer)).node.children!;
    const mi = req[1]!;
    const nonce = req.find((n, i) => i > 1 && n.tag === 0x02)!.content;
    const b64 = (await token({ leaf: p.leaf, key: p.leafKey, chain: [p.ca], sig: SIG, nonce, ...next, imprint: { hashAlgId: mi.children![0]!.bytes, value: mi.children![1]!.content } })).slice(7);
    return new Response(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)));
  }) as unknown as typeof globalThis.fetch;
  const roots = { tsaRoots: [p.root] };
  const a = await signerFromSeed(new Uint8Array(32).fill(1));
  next = { genTime: new Date("2026-11-16T10:00:00Z"), accuracy: seq(int(2), tlv(0x80, new Uint8Array([0x01, 0xf4]))) };
  const s1 = await signDocument("# Doc\n", { signer: a, method: "tofu", signerId: "alice", ts: "2026-11-16T09:00:00Z", tsaUrl: "https://tsa.test/", fetch: tsa, ...roots });
  assert.ok(s1.tsaBlock);
  assert.equal(parseDocument(s1.text).chain.length, 2);
  next = { genTime: new Date("2026-11-16T09:59:00Z") };
  const s2 = await timestampDocument(s1.text, { tsaUrl: "https://tsa.test/", fetch: tsa, ...roots });
  const v = await verifyDocument(s2.text, { offline: true, ...roots });
  assert.deepEqual(v.signatures.map((x) => x.status), ["valid", "valid", "valid"]);
  assert.equal(v.signatures[1]!.tsa!.accuracyMs, 2500);
  assert.deepEqual([v.signatures[0]!.time!.at, v.signatures[0]!.time!.block], ["2026-11-16T09:59:00Z", 3]);
  assert.deepEqual([v.signatures[1]!.time!.at, v.signatures[1]!.time!.block], ["2026-11-16T09:59:00Z", 3]);
  assert.equal(v.signatures[2]!.time, undefined);
  const j = toJsonResult(v);
  assert.deepEqual([j.signatures[0]!.tsa!.time, j.signatures[0]!.tsa!.block, j.signatures[0]!.tsa!.verified], ["2026-11-16T09:59:00Z", 3, true]);
  const only = await verifyDocument(s1.text, { offline: true, ...roots });
  assert.equal(only.signatures[0]!.time!.at, "2026-11-16T10:00:02.500Z");
  assert.equal(genTimeMs("2026-11-16T10:00:00.0001Z"), Date.parse("2026-11-16T10:00:00.001Z"));
  assert.equal(formatTimeMs(Date.parse("2026-11-16T10:00:00Z")), "2026-11-16T10:00:00Z");
});
