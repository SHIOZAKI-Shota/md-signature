import { test } from "node:test";
import assert from "node:assert/strict";
import {
  signDocument,
  verifyDocument,
  signerFromSeed,
  normalizeDocument,
  parseDocument,
  signedPayload,
  serializeBlock,
  parseFields,
  fromHex,
  toBase64,
  formatSshPublicKey,
  formatOpenSshPrivateKey,
  parseOpenSshPrivateKey,
  sshFingerprint,
  parseSshPublicKeys,
  joinTxt,
  parseDnsRecord,
  buildTimeStampReq,
  parseDer,
  MemoryTofuStore,
  unfoldBinary,
  type Resolver,
} from "../src/index.ts";

const SEED_A = fromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
const SEED_B = fromHex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
const TS = "2026-11-16T09:00:00Z";
const DOC = "# Contract\n\nThe parties agree.\n";

test("RFC 8032 test vector 1 public key", async () => {
  const s = await signerFromSeed(SEED_A);
  assert.equal(Buffer.from(s.publicKey).toString("hex"), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
});

test("normalization: CRLF, CR, BOM and trailing whitespace", () => {
  assert.equal(normalizeDocument("\ufeffa\r\nb\rc\n\n  \t\n"), "a\nb\nc\n");
  assert.equal(normalizeDocument("a"), "a\n");
  assert.equal(normalizeDocument(""), "\n");
  assert.notEqual(normalizeDocument("a  \nb"), normalizeDocument("a\nb"));
});

test("payload is sorted, excludes sig and webauthn data, and has domain prefix", () => {
  const p = new TextDecoder().decode(signedPayload({ v: "0.1", sig: "x", webauthn_client_data: "c", webauthn_authenticator_data: "d", b: "2", a: "1" }));
  assert.equal(p, "md-signature/v1\na=1\nb=2\nv=0.1");
});

test("tofu sign + verify", async () => {
  const signer = await signerFromSeed(SEED_A);
  const r = await signDocument(DOC, { signer, method: "tofu", signerId: "alice@laptop", role: "author", ts: TS });
  assert.match(r.text, /^# Contract\n\nThe parties agree.\n\n<!-- md-signature\nv: 0.1\nmethod: tofu\n/);
  const v = await verifyDocument(r.text, { offline: true });
  assert.equal(v.ok, true, JSON.stringify(v));
  assert.equal(v.signatures[0]!.status, "valid");
});

test("signatures are deterministic (Ed25519)", async () => {
  const signer = await signerFromSeed(SEED_A);
  const a = await signDocument(DOC, { signer, method: "tofu", signerId: "a", ts: TS });
  const b = await signDocument(DOC, { signer, method: "tofu", signerId: "a", ts: TS });
  assert.equal(a.text, b.text);
});

const fixedKeys =
  (map: Record<string, Uint8Array>): Resolver =>
  async (f) => {
    const key = map[f.signer!];
    if (!key) throw new Error("unknown");
    return { keys: [{ alg: "ed25519", key, source: "test" }], warnings: [] };
  };

test("multi-party co-signing builds a valid chain", async () => {
  const a = await signerFromSeed(SEED_A);
  const b = await signerFromSeed(SEED_B);
  const resolvers = { dns: fixedKeys({ "example.com": b.publicKey }) };
  const s1 = await signDocument(DOC, { signer: a, method: "tofu", signerId: "alice", role: "author", ts: TS });
  const s2 = await signDocument(s1.text, { signer: b, method: "dns", signerId: "Example.COM", selector: "2026", role: "approver", ts: TS });
  assert.equal(s2.previous, 1);
  assert.equal(s2.fields.signer, "example.com");
  assert.match(s2.text, /-->\n<!-- md-signature\n/);
  const v = await verifyDocument(s2.text, { resolvers });
  assert.equal(v.ok, true, JSON.stringify(v, null, 1));
  assert.equal(v.signatures.length, 2);
});

test("tamper detection: body, metadata, earlier block, trailing content", async () => {
  const a = await signerFromSeed(SEED_A);
  const b = await signerFromSeed(SEED_B);
  const resolvers = { dns: fixedKeys({ "example.com": b.publicKey }) };
  const s1 = await signDocument(DOC, { signer: a, method: "tofu", signerId: "alice", role: "author", ts: TS });
  const s2 = await signDocument(s1.text, { signer: b, method: "dns", signerId: "example.com", ts: TS });

  const v1 = await verifyDocument(s2.text.replace("agree", "disagree"), { resolvers });
  assert.equal(v1.ok, false);
  assert.deepEqual(v1.signatures.map((s) => s.code), ["hash-mismatch", "hash-mismatch"]);

  const v2 = await verifyDocument(s2.text.replace("role: author", "role: approver"), { resolvers });
  assert.deepEqual(v2.signatures.map((s) => s.code), ["bad-signature", "hash-mismatch"]);

  const v3 = await verifyDocument(s2.text.replace(`ts: ${TS}\nalg: ed25519\nhash: sha256:${s2.fields.hash!.slice(7)}`, `ts: 2027-01-01T00:00:00Z\nalg: ed25519\nhash: ${s2.fields.hash}`), { resolvers });
  assert.deepEqual(v3.signatures.map((s) => s.status), ["valid", "invalid"]);

  const v4 = await verifyDocument(s2.text + "\nP.S. extra clause\n", { resolvers });
  assert.equal(v4.ok, false);
  assert.match(v4.error!, /unsigned content after the last signature/);
  await assert.rejects(signDocument(s2.text + "\nextra\n", { signer: a, method: "tofu", signerId: "x", ts: TS }), /unsigned content/);

  const v5 = await verifyDocument(s2.text, { resolvers: { dns: fixedKeys({ "example.com": a.publicKey }) } });
  assert.deepEqual(v5.signatures.map((s) => s.code), [undefined, "bad-signature"]);
});

test("CRLF documents verify and keep CRLF; converting line endings keeps signatures valid", async () => {
  const a = await signerFromSeed(SEED_A);
  const crlf = DOC.replace(/\n/g, "\r\n");
  const s = await signDocument(crlf, { signer: a, method: "tofu", signerId: "alice", ts: TS });
  assert.ok(!/[^\r]\n/.test(s.text), "output must be pure CRLF");
  assert.equal((await verifyDocument(s.text)).ok, true);
  assert.equal((await verifyDocument(s.text.replace(/\r\n/g, "\n"))).ok, true);
  assert.equal((await verifyDocument("\ufeff" + s.text + "\r\n\r\n")).ok, true);
  const lf = await signDocument(DOC, { signer: a, method: "tofu", signerId: "alice", ts: TS });
  assert.equal(lf.fields.hash, s.fields.hash);
});

test("example blocks inside code fences are body content", async () => {
  const a = await signerFromSeed(SEED_A);
  const doc = "# Spec\n\n```markdown\n<!-- md-signature\nv: 0.0.1\n-->\n```\n\nMore text.\n";
  const p = parseDocument(doc);
  assert.equal(p.chain.length, 0);
  assert.equal(p.strayMarker, false);
  const s = await signDocument(doc, { signer: a, method: "tofu", signerId: "a", ts: TS });
  assert.equal((await verifyDocument(s.text)).ok, true);
});

test("parser rejects blank lines, duplicates, comment delimiters", async () => {
  assert.match(parseFields(["v: 1", "v: 2"]).errors.join(), /duplicate/);
  assert.doesNotMatch(parseFields(["reason: a -- b"]).errors.join(), /--/);
  for (const v of ["a --> b", "a --!> b", "a <!-- b"]) assert.match(parseFields([`reason: ${v}`]).errors.join(), /must not contain/, v);
  const a = await signerFromSeed(SEED_A);
  await assert.rejects(signDocument(DOC, { signer: a, method: "tofu", signerId: "a", reason: "x --> y", ts: TS }), /-->/);
  assert.equal((await verifyDocument((await signDocument(DOC, { signer: a, method: "tofu", signerId: "a", reason: "x -- y", ts: TS })).text)).ok, true);
  await assert.rejects(signDocument(DOC, { signer: a, method: "tofu", signerId: "a", reason: "line\nbreak", ts: TS }), /control/);
  const s = await signDocument(DOC, { signer: a, method: "tofu", signerId: "a", ts: TS });
  const broken = s.text.replace("method: tofu\n", "method: tofu\n\n");
  const v = await verifyDocument(broken);
  assert.equal(v.ok, false);
});

test("folded values round-trip", async () => {
  const long = "base64:" + "A".repeat(200);
  const block = serializeBlock({ v: "0.1", method: "tofu", signer: "a", ts: TS, alg: "ed25519", hash: "sha256:00", sig: long });
  assert.match(block, /sig: \|\n {2}base64:A/);
  const p = parseDocument("x\n\n" + block + "\n");
  assert.equal(unfoldBinary(p.chain[0]!.fields.sig!), long);
  assert.ok(p.chain[0]!.fields.sig!.includes("\n"), "folded value keeps LF");
  assert.deepEqual(p.chain[0]!.errors, []);
});

test("unknown fields are signed", async () => {
  const a = await signerFromSeed(SEED_A);
  const s = await signDocument(DOC, { signer: a, method: "tofu", signerId: "a", ts: TS, extra: { x_ref: "PO-123" } });
  assert.equal((await verifyDocument(s.text)).ok, true);
  assert.equal((await verifyDocument(s.text.replace("PO-123", "PO-999"))).ok, false);
});

test("tofu store: a changed key is invalid until it is accepted", async () => {
  const store = new MemoryTofuStore();
  const a = await signerFromSeed(SEED_A);
  const b = await signerFromSeed(SEED_B);
  const s1 = await signDocument(DOC, { signer: a, method: "tofu", signerId: "same", ts: TS });
  const s2 = await signDocument(DOC, { signer: b, method: "tofu", signerId: "same", ts: TS });
  await verifyDocument(s1.text, { tofuStore: store });
  const v = await verifyDocument(s2.text, { tofuStore: store });
  assert.equal(v.ok, false);
  assert.equal(v.signatures[0]!.code, "key-changed");
  assert.equal((await verifyDocument(s1.text, { tofuStore: store })).ok, true);
  assert.equal((await verifyDocument(s2.text, { tofuStore: store, acceptNewTofuKey: true })).ok, true);
  assert.equal((await verifyDocument(s1.text, { tofuStore: store })).signatures[0]!.code, "key-changed");
});

test("SSH key formats and fingerprints", async () => {
  const a = await signerFromSeed(SEED_A);
  const line = formatSshPublicKey(a.publicKey, "alice");
  const parsed = parseSshPublicKeys(`ssh-rsa AAAAB3NzaC1yc2E bogus\n${line}\n`);
  assert.equal(parsed.length, 2);
  assert.equal(parsed[1]!.type, "ssh-ed25519");
  assert.deepEqual(parsed[1]!.key, a.publicKey);
  assert.match(await sshFingerprint(a.publicKey), /^SHA256:[A-Za-z0-9+/]{43}$/);
  const pem = formatOpenSshPrivateKey(SEED_A, a.publicKey, "alice");
  const back = parseOpenSshPrivateKey(pem);
  assert.deepEqual(back.seed, SEED_A);
  assert.equal(back.comment, "alice");
});

test("git-hosting resolver with mocked fetch, key_fp filtering", async () => {
  const a = await signerFromSeed(SEED_A);
  const b = await signerFromSeed(SEED_B);
  const keys = `${formatSshPublicKey(b.publicKey)}\n${formatSshPublicKey(a.publicKey)}\n`;
  const fetch = (async (url: string) => {
    assert.equal(url, "https://github.com/alice.keys");
    return new Response(keys);
  }) as typeof globalThis.fetch;
  const s = await signDocument(DOC, { signer: a, method: "git-hosting", signerId: "github.com/alice", ts: TS });
  assert.equal(s.fields.key_fp, await sshFingerprint(a.publicKey));
  const v = await verifyDocument(s.text, { fetch });
  assert.equal(v.ok, true, JSON.stringify(v));
  const off = await verifyDocument(s.text, { offline: true });
  assert.equal(off.signatures[0]!.status, "unresolved");
});

test("dns resolver with mocked DoH, split TXT strings", async () => {
  const b = await signerFromSeed(SEED_B);
  const p = toBase64(b.publicKey);
  const data = `"v=mdsig1; k=ed25519; " "p=${p}"`;
  assert.equal(joinTxt(data), `v=mdsig1; k=ed25519; p=${p}`);
  assert.deepEqual(parseDnsRecord(joinTxt(data)), { k: "ed25519", p });
  let calls = 0;
  const fetch = (async (url: string) => {
    calls++;
    if (url.startsWith("https://cloudflare-dns.com")) return new Response("down", { status: 503 });
    assert.match(url, /name=2026\._mdsig\.example\.com&type=TXT/);
    return Response.json({ Status: 0, Answer: [{ type: 16, data: '"v=spf1 -all"' }, { type: 16, data }] });
  }) as typeof globalThis.fetch;
  const s = await signDocument(DOC, { signer: b, method: "dns", signerId: "example.com", selector: "2026", ts: TS });
  const v = await verifyDocument(s.text, { fetch });
  assert.equal(v.ok, true, JSON.stringify(v));
  assert.equal(calls, 2);
});

test("TimeStampReq DER structure", () => {
  const req = buildTimeStampReq(new Uint8Array(32).fill(7), new Uint8Array([1, 2, 3]));
  const n = parseDer(req).node;
  assert.equal(n.tag, 0x30);
  assert.equal(n.children!.length, 4);
  assert.equal(n.children![1]!.children![1]!.content.length, 32);
});

test("broken tofu pubkey is malformed, not a network error", async () => {
  const a = await signerFromSeed(SEED_A);
  const s = await signDocument(DOC, { signer: a, method: "tofu", signerId: "a", ts: TS });
  const broken = s.text.replace(/pubkey: ed25519:\S+/, "pubkey: ed25519:AAAA");
  const v = await verifyDocument(broken);
  assert.equal(v.signatures[0]!.status, "malformed");
  const wrongAlg = await verifyDocument(s.text.replace("pubkey: ed25519:", "pubkey: ml-dsa-65:"));
  assert.equal(wrongAlg.signatures[0]!.status, "malformed");
});
