import { readFileSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  signDocument,
  timestampDocument,
  verifyDocument,
  signerFromSeed,
  fromHex,
  utf8,
  sha256,
  toHex,
  signedPayload,
  parseDocument,
  derToP1363,
  p1363ToDer,
  createSoftwareAuthenticator,
  findLocalImages,
  revocationId,
  serializeBlock,
  checkTsaToken,
  gzip,
  toBase64,
  fromBase64,
  MemoryTofuStore,
  sshFingerprint,
  ResolutionError,
  type Resolver,
} from "../src/index.ts";

const SEED_A = fromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
const SEED_B = fromHex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
const TS = "2026-11-16T09:00:00Z";
const DOC = "# Contract\n\nThe parties agree.\n";

const fixedKeys =
  (map: Record<string, Uint8Array>, alg = "ed25519"): Resolver =>
  async (f) => {
    const key = map[f.signer!];
    if (!key) throw new Error("unknown");
    return { keys: [{ alg, key, source: "test" }], warnings: [] };
  };

// --- UTF-8
test("generators refuse text that has no UTF-8 encoding", async () => {
  const a = await signerFromSeed(SEED_A);
  await assert.rejects(signDocument("# a\n\uD800\n", { signer: a, method: "tofu", signerId: "a", ts: TS }), /not valid UTF-8/);
  await assert.rejects(timestampDocument("# a\n\uDC00\n", { tsaUrl: "https://tsa.test/" }), /not valid UTF-8/);
  await signDocument("# a \u{1F600}\n", { signer: a, method: "tofu", signerId: "a", ts: TS });
});

// --- Fields
test("unknown fields are malformed; x_ fields are allowed and signed", async () => {
  const a = await signerFromSeed(SEED_A);
  const s = await signDocument(DOC, { signer: a, method: "tofu", signerId: "a", ts: TS, extra: { x_ref: "PO-1" } });
  assert.equal((await verifyDocument(s.text)).ok, true);
  const unknown = s.text.replace("x_ref: PO-1", "x_ref: PO-1\npriority: high");
  const v = await verifyDocument(unknown);
  assert.equal(v.signatures[0]!.status, "malformed");
  assert.equal(v.signatures[0]!.code, "unknown-field");
  await assert.rejects(signDocument(DOC, { signer: a, method: "tofu", signerId: "a", extra: { ref: "x" } }), /must start with "x_"/);
});

test("payload escapes LF in folded values so lines cannot forge fields", () => {
  const p = new TextDecoder().decode(signedPayload({ require: "dns:a.com\ndns:b.com", v: "0.0.1" }));
  assert.equal(p, "md-signature/v1\nrequire=dns:a.com\n  dns:b.com\nv=0.0.1");
  const q = new TextDecoder().decode(signedPayload({ require: "dns:a.com\nv=9" }));
  assert.ok(q.includes("\n  v=9"));
});

// --- Resources
test("resources: local files and remote URLs", async () => {
  const a = await signerFromSeed(SEED_A);
  const png = utf8("PNG-BYTES");
  const remote = utf8("REMOTE-CHART");
  const s = await signDocument(DOC, {
    signer: a, method: "tofu", signerId: "a", ts: TS,
    resources: [{ ref: "./diagram.png", bytes: png }, { ref: "https://example.com/chart.png", bytes: remote }],
  });
  assert.match(s.block, /resources: \|\n {2}sha256:[0-9a-f]{64} \.\/diagram\.png\n {2}sha256:[0-9a-f]{64} https:\/\/example\.com\/chart\.png/);
  const files: Record<string, Uint8Array> = { "./diagram.png": png };
  const loadResource = async (ref: string) => files[ref] ?? null;
  let fetched = 0;
  const fetch = (async () => {
    fetched++;
    return new Response(remote as BodyInit);
  }) as typeof globalThis.fetch;

  const v1 = await verifyDocument(s.text, { loadResource, fetch });
  assert.equal(v1.ok, true, JSON.stringify(v1, null, 1));
  assert.deepEqual(v1.signatures[0]!.resources!.map((r) => r.status), ["ok", "not-checked"]);
  assert.equal(fetched, 0);
  const v2 = await verifyDocument(s.text, { loadResource, fetch, fetchResources: true });
  assert.deepEqual(v2.signatures[0]!.resources!.map((r) => r.status), ["ok", "ok"]);
  files["./diagram.png"] = utf8("EVIL");
  const v3 = await verifyDocument(s.text, { loadResource, fetch });
  assert.equal(v3.signatures[0]!.code, "resource-mismatch");
  delete files["./diagram.png"];
  assert.equal((await verifyDocument(s.text, { loadResource })).signatures[0]!.code, "resource-missing");
  files["./diagram.png"] = png;
  const evilFetch = (async () => new Response("CHANGED")) as typeof globalThis.fetch;
  assert.equal((await verifyDocument(s.text, { loadResource, fetch: evilFetch, fetchResources: true })).signatures[0]!.code, "resource-mismatch");
  const deadFetch = (async () => new Response("", { status: 404 })) as typeof globalThis.fetch;
  assert.equal((await verifyDocument(s.text, { loadResource, fetch: deadFetch, fetchResources: true })).signatures[0]!.status, "unresolved");
  for (const ref of ["/etc/passwd", "../secret.png", "C:/x.png", "http://example.com/a.png", "a\\b.png"]) {
    await assert.rejects(signDocument(DOC, { signer: a, method: "tofu", signerId: "a", resources: [{ ref, bytes: png }] }), /resources/, ref);
  }
});

test("findLocalImages lists local images outside code fences", () => {
  const md = "![a](./a.png)\n<img src=\"img/b.jpg\">\n![r](https://x.com/r.png)\n```\n![c](./c.png)\n```\n![d](../d.png)\n";
  assert.deepEqual(findLocalImages(md), ["./a.png", "img/b.jpg"]);
});

// --- Require
test("require: pending until the required parties co-sign", async () => {
  const a = await signerFromSeed(SEED_A);
  const b = await signerFromSeed(SEED_B);
  const resolvers = { dns: fixedKeys({ "example.com": b.publicKey }) };
  const s1 = await signDocument(DOC, {
    signer: a, method: "tofu", signerId: "alice", role: "author", ts: TS,
    require: ["dns:example.com approver", { method: "tofu", signer: "carol" }],
  });
  const v1 = await verifyDocument(s1.text, { resolvers });
  assert.equal(v1.ok, true);
  assert.equal(v1.agreement.status, "pending");
  assert.equal(v1.agreement.missing.length, 2);
  const s2bad = await signDocument(s1.text, { signer: b, method: "dns", signerId: "Example.com", role: "witness", ts: TS });
  assert.equal((await verifyDocument(s2bad.text, { resolvers })).agreement.missing.length, 2);
  const s2 = await signDocument(s1.text, { signer: b, method: "dns", signerId: "Example.com", role: "approver", ts: TS });
  assert.equal((await verifyDocument(s2.text, { resolvers })).agreement.missing.length, 1);
  const c = await signerFromSeed(new Uint8Array(32).fill(3));
  const s3 = await signDocument(s2.text, { signer: c, method: "tofu", signerId: "carol", ts: TS });
  const v3 = await verifyDocument(s3.text, { resolvers });
  assert.equal(v3.agreement.status, "complete");
  assert.equal((await verifyDocument((await signDocument(DOC, { signer: a, method: "tofu", signerId: "x", ts: TS })).text)).agreement.status, "none");
  await assert.rejects(signDocument(DOC, { signer: a, method: "tofu", signerId: "x", require: ["not a requirement"] }), /require/);
});

test("require: steps run in order, any M counts distinct signers", async () => {
  const keys = await Promise.all([1, 2, 3, 4].map((n) => signerFromSeed(new Uint8Array(32).fill(n))));
  const [a, b, c, d] = keys as [Awaited<ReturnType<typeof signerFromSeed>>, Awaited<ReturnType<typeof signerFromSeed>>, Awaited<ReturnType<typeof signerFromSeed>>, Awaited<ReturnType<typeof signerFromSeed>>];
  const sign = (text: string, signer: typeof a, id: string, extra: object = {}) => signDocument(text, { signer, method: "tofu", signerId: id, ts: TS, ...extra }).then((r) => r.text);
  const agree = async (text: string) => (await verifyDocument(text, { offline: true })).agreement;
  const steps = (order?: string) => [...(order ? [`order ${order}`] : []), "step 1", "tofu:bob", "step 2 any 2", "tofu:carol", "tofu:dave", "tofu:erin"];

  const decl = await sign(DOC, a, "alice", { require: steps() });
  const pending1 = await agree(decl);
  assert.equal(pending1.status, "pending");
  assert.deepEqual(pending1.missing.map((m) => [m.signer, m.step, m.need, m.blockedBy ?? 0]), [["bob", 1, 1, 0], ["carol", 2, 2, 1], ["dave", 2, 2, 1], ["erin", 2, 2, 1]]);
  assert.deepEqual(pending1.required.map((r) => [r.signer, r.step, r.any]), [["bob", 1, 1], ["carol", 2, 2], ["dave", 2, 2], ["erin", 2, 2]]);

  const inOrder = await sign(await sign(await sign(decl, b, "bob"), c, "carol"), d, "dave");
  assert.equal((await agree(inOrder)).status, "complete");
  const sameTwice = await sign(await sign(await sign(decl, b, "bob"), c, "carol"), c, "carol");
  const st = await agree(sameTwice);
  assert.equal(st.status, "pending");
  assert.deepEqual([...new Set(st.missing.map((m) => m.need))], [1]);

  const early = await sign(await sign(decl, c, "carol"), b, "bob");
  const pe = await agree(early);
  assert.equal(pe.status, "pending");
  assert.equal(pe.missing.find((m) => m.signer === "carol")!.early, true);
  assert.equal((await agree(await sign(await sign(early, c, "carol"), d, "dave"))).status, "complete");

  for (const [order, status] of [["guide", "complete"], ["strict", "violated"]] as const) {
    const t = await sign(await sign(await sign(await sign(DOC, a, "alice", { require: steps(order) }), c, "carol"), b, "bob"), d, "dave");
    const v = await verifyDocument(t, { offline: true });
    assert.equal(v.agreement.status, status, order);
    assert.deepEqual(v.agreement.violations.map((x) => [x.index, x.step, x.order]), [[2, 2, order]]);
    assert.equal(v.ok, order === "guide");
  }

  // a scoped block never satisfies, also inside a step
  const scopedDoc = "# Deal\n\n<!-- mdsig:section terms -->\nTerms.\n<!-- /mdsig:section -->\n";
  const sdecl = await sign(scopedDoc, a, "alice", { require: ["step 1", "tofu:bob"] });
  assert.equal((await agree(await sign(sdecl, b, "bob", { scope: ["terms"] }))).status, "pending");

  await assert.rejects(sign(DOC, a, "x", { require: ["step 1 any 3", "tofu:bob", "tofu:carol"] }), /any 3 of 2/);
  await assert.rejects(sign(DOC, a, "x", { require: ["step 2", "tofu:bob"] }), /expected "step 1"/);
  await assert.rejects(sign(DOC, a, "x", { require: ["tofu:bob", "order strict"] }), /first line/);
  await assert.rejects(sign(DOC, a, "x", { require: ["tofu:bob", "tofu:bob"] }), /appears twice/);
});

test("key snapshot: embedded key verifies, published key decides valid or key-not-published", async () => {
  const a = await signerFromSeed(SEED_A);
  const b = await signerFromSeed(SEED_B);
  const resolverWith = (keys: Uint8Array[] | "missing" | "offline"): Record<string, Resolver> => {
    const r: Resolver = async () => {
      if (keys === "missing") throw new ResolutionError("no TXT record", "not-found");
      if (keys === "offline") throw new ResolutionError("DoH unreachable", "network");
      return { keys: keys.map((key) => ({ alg: "ed25519", key, source: "test" })), warnings: [] };
    };
    return { dns: r, "git-hosting": r };
  };
  const dnsDoc = (await signDocument(DOC, { signer: a, method: "dns", signerId: "example.com", ts: TS, embedKey: true })).text;
  assert.match(dnsDoc, /\npubkey: ed25519:/);
  const check = async (text: string, keys: Parameters<typeof resolverWith>[0]) => {
    const s = (await verifyDocument(text, { resolvers: resolverWith(keys) })).signatures[0]!;
    return [s.status, s.code ?? null];
  };
  assert.deepEqual(await check(dnsDoc, [b.publicKey, a.publicKey]), ["valid", null]);
  assert.deepEqual(await check(dnsDoc, [b.publicKey]), ["unresolved", "key-not-published"]);
  assert.deepEqual(await check(dnsDoc, "missing"), ["unresolved", "key-not-published"]);
  assert.deepEqual(await check(dnsDoc, "offline"), ["unresolved", "network"]);
  // the snapshot is signed: swapping it breaks the signature, even with the network down
  const swapped = dnsDoc.replace(/pubkey: ed25519:\S+/, `pubkey: ed25519:${toBase64(b.publicKey)}`);
  assert.deepEqual(await check(swapped, "offline"), ["invalid", "bad-signature"]);
  assert.deepEqual(await check(dnsDoc.replace("# Contract", "# Contrast"), [a.publicKey]), ["invalid", "hash-mismatch"]);

  const gh = (await signDocument(DOC, { signer: a, method: "git-hosting", signerId: "github.com/alice", ts: TS, embedKey: true })).text;
  assert.deepEqual(await check(gh, [a.publicKey]), ["valid", null]);
  assert.deepEqual(await check(gh, "missing"), ["unresolved", "key-not-published"]);
  const otherFp = await sshFingerprint(b.publicKey);
  assert.match((await verifyDocument(gh.replace(/key_fp: \S+/, `key_fp: ${otherFp}`), { resolvers: resolverWith([a.publicKey]) })).signatures[0]!.message!, /key_fp does not match the embedded pubkey/);

  await assert.rejects(signDocument(DOC, { signer: a, method: "tofu", signerId: "x", embedKey: true }), /embedKey works with dns and git-hosting/);
  const plain = (await signDocument(DOC, { signer: a, method: "dns", signerId: "example.com", ts: TS })).text;
  assert.doesNotMatch(plain, /pubkey:/);
  assert.deepEqual(await check(plain, "missing"), ["unresolved", "not-found"]);
});

test("require: format 0.0.1 blocks keep their rules", async () => {
  const text = (name: string) => readFileSync(new URL(`../../../examples/${name}`, import.meta.url), "utf8");
  const keys = JSON.parse(text("keys.json"));
  const dns: Record<string, string> = Object.fromEntries(Object.entries(keys.dns as Record<string, { txt: string }>).map(([k, v]) => [k, v.txt]));
  const fetch = (async (url: string) => {
    const n = new URL(url).searchParams.get("name")!;
    return new Response(JSON.stringify({ Status: 0, Answer: dns[n] ? [{ type: 16, data: `"${dns[n]}"` }] : [] }));
  }) as typeof globalThis.fetch;
  const mixed = await verifyDocument(text("mixed-versions.md"), { fetch, now: new Date(keys.now), tofuStore: new MemoryTofuStore() });
  assert.deepEqual(mixed.signatures.map((s) => [s.fields.v, s.status]), [["0.0.1", "valid"], ["0.0.2", "valid"]]);
  assert.equal(mixed.agreement.status, "complete");
  const bad = await verifyDocument(text("malformed-require-step-v001.md"), { offline: true });
  assert.match(bad.signatures[0]!.message!, /need format 0\.0\.2/);
  const future = text("legacy-v001.md").replace("v: 0.0.1", "v: 0.0.3");
  assert.equal((await verifyDocument(future, { offline: true })).signatures[0]!.code, "unsupported-version");
});

test("version: an unknown version is reported before unknown fields", async () => {
  const signed = (await signDocument(DOC, { signer: await signerFromSeed(SEED_A), method: "tofu", signerId: "alice", ts: TS })).text;
  const code = async (t: string) => (await verifyDocument(t, { offline: true })).signatures[0]!;
  const later = await code(signed.replace("v: 0.0.2\n", "v: 0.0.3\nnew_field: 1\n"));
  assert.deepEqual([later.status, later.code], ["unsupported", "unsupported-version"]);
  const known = await code(signed.replace("v: 0.0.2\n", "v: 0.0.2\nnew_field: 1\n"));
  assert.deepEqual([known.status, known.code], ["malformed", "unknown-field"]);
  const twice = await code(signed.replace("v: 0.0.2\n", "v: 0.0.3\nv: 0.0.4\n"));
  assert.deepEqual([twice.status, twice.code], ["malformed", "malformed"]);
  const missing = await code(signed.replace("v: 0.0.2\n", ""));
  assert.deepEqual([missing.status, missing.code], ["malformed", "malformed"]);
});

// --- Expires
test("expires", async () => {
  const a = await signerFromSeed(SEED_A);
  const s = await signDocument(DOC, { signer: a, method: "tofu", signerId: "a", ts: TS, expires: "2027-01-01T00:00:00Z" });
  assert.equal((await verifyDocument(s.text, { now: new Date("2026-12-31T23:59:59Z") })).ok, true);
  const v = await verifyDocument(s.text, { now: new Date("2027-01-01T00:00:01Z") });
  assert.equal(v.signatures[0]!.code, "expired");
  await assert.rejects(signDocument(DOC, { signer: a, method: "tofu", signerId: "a", expires: "tomorrow" }), /expires/);
});

// --- Revocation
test("revocation lists: revoke, ignore lists by other signers, no recursion", async () => {
  const a = await signerFromSeed(SEED_A);
  const b = await signerFromSeed(SEED_B);
  const URL_ = "https://example.com/.well-known/mdsig-revoked.md";
  const resolvers = { dns: fixedKeys({ "example.com": a.publicKey, "evil.com": b.publicKey }) };
  const doc = await signDocument(DOC, { signer: a, method: "dns", signerId: "example.com", ts: TS, revocationUrl: URL_ });
  const id = await revocationId(doc.fields);

  let listText = "";
  let calls = 0;
  const fetch = (async (u: string) => {
    calls++;
    assert.equal(u, URL_);
    return new Response(listText);
  }) as typeof globalThis.fetch;

  const makeList = async (signer = a, signerId = "example.com", ids: string[] = []) =>
    (await signDocument(`# Revoked\n\n${ids.map((i) => `revoked: sha256:${i}`).join("\n")}\n`, { signer, method: "dns", signerId, ts: TS, revocationUrl: URL_ })).text;

  listText = await makeList(a, "example.com", []);
  const v0 = await verifyDocument(doc.text, { resolvers, fetch });
  assert.equal(v0.ok, true, JSON.stringify(v0, null, 1));
  assert.equal(v0.signatures[0]!.revocation!.status, "not-revoked");
  assert.equal(calls, 1, "list fetched once, no recursion");

  listText = await makeList(a, "example.com", [id]);
  const v1 = await verifyDocument(doc.text, { resolvers, fetch });
  assert.equal(v1.signatures[0]!.code, "revoked");

  listText = await makeList(b, "evil.com", [id]);
  const v2 = await verifyDocument(doc.text, { resolvers, fetch });
  assert.equal(v2.ok, false);
  assert.deepEqual([v2.signatures[0]!.status, v2.signatures[0]!.code], ["unresolved", "not-found"]);
  assert.equal(v2.signatures[0]!.revocation!.status, "not-checked");

  const v3 = await verifyDocument(doc.text, { resolvers, offline: true, fetch });
  assert.equal(v3.signatures[0]!.status, "valid");
  assert.equal(v3.signatures[0]!.revocation!.status, "not-checked");
  const v4 = await verifyDocument(doc.text, { resolvers, fetch, checkRevocation: false });
  assert.equal(v4.signatures[0]!.revocation!.status, "not-checked");
});

// --- Scope
const SCOPED = `# Agreement

<!-- mdsig:section terms -->
## Terms
Payment within 30 days.
<!-- /mdsig:section -->

## Notes (editable)
Draft notes.

<!-- mdsig:section fees -->
| Fee | 100 |
<!-- /mdsig:section -->
`;

test("scope: unsigned parts are editable, signed sections are not", async () => {
  const a = await signerFromSeed(SEED_A);
  const s = await signDocument(SCOPED, { signer: a, method: "tofu", signerId: "a", ts: TS, scope: ["terms", "fees"] });
  const v0 = await verifyDocument(s.text);
  assert.equal(v0.ok, true, JSON.stringify(v0, null, 1));
  assert.deepEqual(v0.signatures[0]!.partial, { sections: ["terms", "fees"] });
  assert.ok(v0.signatures[0]!.warnings.some((w) => w.includes("partial")));

  assert.equal((await verifyDocument(s.text.replace("Draft notes.", "Final notes, edited later."))).ok, true);
  assert.equal((await verifyDocument(s.text.replace("30 days", "90 days"))).signatures[0]!.code, "hash-mismatch");
  assert.equal((await verifyDocument(s.text.replace("| Fee | 100 |", "| Fee | 1000 |"))).signatures[0]!.code, "hash-mismatch");
  const shifted = s.text.replace("Payment within 30 days.\n<!-- /mdsig:section -->", "<!-- /mdsig:section -->\nPayment within 30 days.");
  assert.equal((await verifyDocument(shifted)).ok, false);
  const removed = s.text.replace("<!-- mdsig:section fees -->\n| Fee | 100 |\n<!-- /mdsig:section -->\n", "");
  assert.equal((await verifyDocument(removed)).signatures[0]!.code, "scope-missing");
  const unclosed = s.text.replace("| Fee | 100 |\n<!-- /mdsig:section -->", "| Fee | 100 |");
  const vu = await verifyDocument(unclosed);
  assert.equal(vu.signatures[0]!.status, "malformed");
  assert.match(vu.signatures[0]!.message!, /never closed/);
  await assert.rejects(signDocument("<!-- mdsig:section a -->\n<!-- mdsig:section b -->\n<!-- /mdsig:section -->\n", { signer: a, method: "tofu", signerId: "a", scope: ["a"] }), /nesting/);
  await assert.rejects(signDocument(SCOPED, { signer: a, method: "tofu", signerId: "a", scope: ["nope"] }), /not found/);
  const b = await signerFromSeed(SEED_B);
  const s2 = await signDocument(s.text, { signer: b, method: "tofu", signerId: "b", ts: TS });
  const v2 = await verifyDocument(s2.text.replace("Draft notes.", "Edited."));
  assert.deepEqual(v2.signatures.map((x) => x.status), ["valid", "invalid"]);
});

test("scope: markers inside code fences are ignored", async () => {
  const a = await signerFromSeed(SEED_A);
  const doc = "```\n<!-- mdsig:section x -->\n```\n<!-- mdsig:section real -->\nA\n<!-- /mdsig:section -->\n";
  const s = await signDocument(doc, { signer: a, method: "tofu", signerId: "a", ts: TS, scope: ["real"] });
  assert.equal((await verifyDocument(s.text)).ok, true);
});

// --- WebAuthn
test("DER <-> P1363 conversion, including short and long integers", () => {
  for (let i = 0; i < 200; i++) {
    const rs = globalThis.crypto.getRandomValues(new Uint8Array(64));
    if (i % 3 === 0) rs[0] = 0;
    if (i % 5 === 0) rs[32] = 0x80;
    assert.deepEqual(derToP1363(p1363ToDer(rs)), rs);
  }
  const good = p1363ToDer(new Uint8Array(64).fill(1));
  assert.throws(() => derToP1363(good.subarray(0, good.length - 1)), /length mismatch/);
  assert.throws(() => derToP1363(new Uint8Array([...good, 0])), /length mismatch/);
  const fat = new Uint8Array([0x30, 0x26, 0x02, 0x22, 0, 0, ...new Uint8Array(32).fill(1), 0x02, 0x00]);
  assert.throws(() => derToP1363(fat));
  assert.throws(() => derToP1363(new Uint8Array([0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01])), /SEQUENCE/);
});

test("webauthn-es256: valid, challenge mismatch, rpId mismatch, origin mismatch", async () => {
  const auth = await createSoftwareAuthenticator("mdsig.dev");
  const s = await signDocument(DOC, { signer: auth, method: "tofu", signerId: "carol@passkey", role: "approver", ts: TS });
  assert.match(s.block, /pubkey: es256:/);
  assert.match(s.block, /rp_id: mdsig\.dev/);
  assert.match(s.block, /alg: webauthn-es256/);
  const v = await verifyDocument(s.text);
  assert.equal(v.ok, true, JSON.stringify(v, null, 1));
  assert.equal(v.signatures[0]!.webauthn!.rpId, "mdsig.dev");

  assert.equal((await verifyDocument(s.text.replace("agree", "disagree"))).signatures[0]!.code, "hash-mismatch");
  assert.equal((await verifyDocument(s.text.replace("role: approver", "role: author"))).signatures[0]!.code, "bad-signature");
  assert.equal((await verifyDocument(s.text.replace("rp_id: mdsig.dev", "rp_id: evil.example"))).signatures[0]!.code, "bad-signature");

  const other = await createSoftwareAuthenticator("evil.example", "https://mdsig.dev");
  const forged = { ...other, rpId: "mdsig.dev" };
  const s2 = await signDocument(DOC, { signer: forged, method: "tofu", signerId: "x", ts: TS });
  const v2 = await verifyDocument(s2.text);
  assert.equal(v2.signatures[0]!.code, "bad-signature");
  assert.match(v2.signatures[0]!.message!, /rpIdHash/);

  const wrongOrigin = await createSoftwareAuthenticator("mdsig.dev", "https://evil.example");
  const s3 = await signDocument(DOC, { signer: wrongOrigin, method: "tofu", signerId: "x", ts: TS });
  assert.match((await verifyDocument(s3.text)).signatures[0]!.message!, /origin/);

  const wrongType = await createSoftwareAuthenticator("mdsig.dev");
  wrongType.overrideClientData = (cd) => ({ ...cd, type: "webauthn.create" });
  const s4 = await signDocument(DOC, { signer: wrongType, method: "tofu", signerId: "x", ts: TS });
  assert.equal((await verifyDocument(s4.text)).signatures[0]!.code, "bad-signature");

  const local = await createSoftwareAuthenticator("localhost", "http://localhost:8765");
  const s5 = await signDocument(DOC, { signer: local, method: "tofu", signerId: "dev", ts: TS });
  const v5 = await verifyDocument(s5.text);
  assert.equal(v5.ok, true);
  assert.ok(v5.signatures[0]!.warnings.some((w) => w.includes("localhost")));

  const noUp = await createSoftwareAuthenticator("mdsig.dev", undefined, 0x04);
  const s6 = await signDocument(DOC, { signer: noUp, method: "tofu", signerId: "x", ts: TS });
  assert.match((await verifyDocument(s6.text)).signatures[0]!.message!, /User Present/);

  const a = await signerFromSeed(SEED_A);
  const plain = await signDocument(DOC, { signer: a, method: "tofu", signerId: "a", ts: TS });
  const bogus = plain.text.replace("alg: ed25519", "rp_id: x.com\nalg: ed25519");
  assert.equal((await verifyDocument(bogus)).signatures[0]!.status, "malformed");
  await assert.rejects(signDocument(DOC, { signer: auth, method: "git-hosting", signerId: "github.com/a" }), /git-hosting/);
});

test("webauthn-es256 via dns (k=es256)", async () => {
  const auth = await createSoftwareAuthenticator("mdsig.dev");
  const p = btoa(String.fromCharCode(...auth.publicKey));
  const fetch = (async () => Response.json({ Status: 0, Answer: [{ type: 16, data: `"v=mdsig1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="` }, { type: 16, data: `"v=mdsig1; k=es256; p=${p}"` }] })) as typeof globalThis.fetch;
  const s = await signDocument(DOC, { signer: auth, method: "dns", signerId: "example.com", ts: TS });
  const v = await verifyDocument(s.text, { fetch });
  assert.equal(v.ok, true, JSON.stringify(v, null, 1));
});

test("all features together round-trip through the parser", async () => {
  const a = await signerFromSeed(SEED_A);
  const s = await signDocument(SCOPED, {
    signer: a, method: "tofu", signerId: "a", ts: TS, scope: ["terms"], expires: "2030-01-01T00:00:00Z",
    require: ["tofu:b"], resources: [{ ref: "./x.png", bytes: utf8("x") }], revocationUrl: "https://example.com/r.md", extra: { x_ref: "PO-9" },
  });
  const block = parseDocument(s.text).chain[0]!;
  assert.deepEqual(block.errors, []);
  const order = s.block.split("\n").slice(1, -1).filter((l) => !l.startsWith("  ")).map((l) => l.split(":")[0]);
  assert.deepEqual(order, ["v", "method", "signer", "pubkey", "ts", "expires", "scope", "require", "resources", "revocation_url", "x_ref", "alg", "hash", "sig"]);
});

test("hardening: null clientData, unreadable resource, dns trailing dot, invalid expires, offline require", async () => {
  const auth = await createSoftwareAuthenticator("mdsig.dev");
  const wa = await signDocument(DOC, { signer: auth, method: "tofu", signerId: "x", ts: TS });
  const nulled = wa.text.replace(/webauthn_client_data: (\|\n(  .*\n)+|.*\n)/, "webauthn_client_data: bnVsbA==\n");
  assert.equal((await verifyDocument(nulled)).signatures[0]!.status, "malformed");

  const a = await signerFromSeed(SEED_A);
  const s = await signDocument(DOC, { signer: a, method: "tofu", signerId: "a", ts: TS, resources: [{ ref: "./x.png", bytes: utf8("x") }] });
  const v = await verifyDocument(s.text, { loadResource: async () => { throw new Error("EACCES"); } });
  assert.equal(v.signatures[0]!.code, "resource-missing");
  assert.match(v.signatures[0]!.resources![0]!.detail!, /EACCES/);

  for (const bad of ["2026-02-30T00:00:00Z", "2026-11-16T24:00:00Z", "2026-13-01T00:00:00Z"]) {
    await assert.rejects(signDocument(DOC, { signer: a, method: "tofu", signerId: "a", expires: bad }), /expires/, bad);
    const ok = await signDocument(DOC, { signer: a, method: "tofu", signerId: "a", ts: TS, expires: "2030-01-01T00:00:00Z" });
    const r = await verifyDocument(ok.text.replace("expires: 2030-01-01T00:00:00Z", `expires: ${bad}`));
    assert.equal(r.signatures[0]!.status, "malformed", bad);
  }

  const req = await signDocument(DOC, { signer: a, method: "dns", signerId: "example.com", ts: TS, require: ["tofu:bob"] });
  const off = await verifyDocument(req.text, { offline: true });
  assert.equal(off.signatures[0]!.status, "unresolved");
  assert.equal(off.agreement.status, "pending");
});

test("revocation survives a signature re-encoded without the key (ECDSA s -> n - s)", async () => {
  const auth = await createSoftwareAuthenticator("example.com");
  const URL_ = "https://example.com/revoked.md";
  const base = { signer: auth, method: "tofu" as const, signerId: "carol@passkey", ts: TS };
  const doc = await signDocument(DOC, { ...base, revocationUrl: URL_ });
  const list = (await signDocument(`# Revoked\n\nrevoked: sha256:${await revocationId(doc.fields)}\n`, base)).text;
  const fetch = (async () => new Response(list)) as typeof globalThis.fetch;
  assert.equal((await verifyDocument(doc.text, { fetch })).signatures[0]!.code, "revoked");

  const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  const rs = derToP1363(fromBase64(doc.fields.sig!.slice(7)));
  const s2 = (N - BigInt("0x" + toHex(rs.subarray(32)))).toString(16).padStart(64, "0");
  const flipped = new Uint8Array([...rs.subarray(0, 32), ...fromHex(s2)]);
  const b = parseDocument(doc.text).chain[0]!;
  const text = doc.text.slice(0, b.start) + serializeBlock({ ...b.fields, sig: "base64:" + toBase64(p1363ToDer(flipped)) }) + "\n";
  const v = await verifyDocument(text, { fetch });
  assert.equal(v.signatures[0]!.code, "revoked", JSON.stringify(v, null, 1));
});

test("tofu binding is stored only after the signature verifies, and never from a revocation list", async () => {
  const a = await signerFromSeed(SEED_A);
  const b = await signerFromSeed(SEED_B);
  const store = new MemoryTofuStore();
  const forged = (await signDocument(DOC, { signer: a, method: "tofu", signerId: "alice", ts: TS })).text.replace("signer: alice", "signer: bob");
  assert.equal((await verifyDocument(forged, { tofuStore: store })).signatures[0]!.code, "bad-signature");
  assert.equal(store.get("bob"), undefined);

  const URL_ = "https://example.com/revoked.md";
  const list = (await signDocument("# Revoked\n", { signer: b, method: "tofu", signerId: "ceo", ts: TS })).text;
  const fetch = (async () => new Response(list)) as typeof globalThis.fetch;
  const doc = await signDocument(DOC, { signer: a, method: "tofu", signerId: "alice", ts: TS, revocationUrl: URL_ });
  assert.equal((await verifyDocument(doc.text, { tofuStore: store, fetch })).signatures[0]!.status, "unresolved");
  assert.equal(store.get("ceo"), undefined);
  assert.ok(store.get("alice"));
});

test("tsa_token: decompression and DER nesting are bounded", async () => {
  const bomb = await checkTsaToken("gzip+base64:" + toBase64(await gzip(new Uint8Array(8 * 1024 * 1024))), new Uint8Array(64));
  assert.equal(bomb.status, "error");
  assert.match(bomb.detail, /larger than/);
  const deep = new Uint8Array(100);
  for (let i = 0; i < 50; i++) deep.set([0x30, 98 - 2 * i], 2 * i);
  const nested = await checkTsaToken("base64:" + toBase64(deep), new Uint8Array(64));
  assert.equal(nested.status, "error");
  assert.match(nested.detail, /nested too deeply/);
});

test("git-hosting signer host must be a domain name", async () => {
  const a = await signerFromSeed(SEED_A);
  for (const id of ["127.0.0.1/alice", "localhost/alice", "2130706433/alice", "[::1]/alice"]) {
    await assert.rejects(signDocument(DOC, { signer: a, method: "git-hosting", signerId: id, ts: TS }), /domain name/);
  }
  const ok = await signDocument(DOC, { signer: a, method: "git-hosting", signerId: "github.com/alice", ts: TS });
  const v = await verifyDocument(ok.text.replace("github.com/alice", "10.0.0.1/alice"), { offline: true });
  assert.equal(v.signatures[0]!.status, "malformed");
});

test("values with C1, line-separator, or bidi control characters are malformed", async () => {
  const a = await signerFromSeed(SEED_A);
  for (const ch of ["\u009b", "\u2028", "\u202e", "\u2066"]) {
    await assert.rejects(signDocument(DOC, { signer: a, method: "tofu", signerId: "a", ts: TS, reason: `x${ch}y` }), /control characters/);
  }
});

test("a chain longer than the limit is a failure", async () => {
  const a = await signerFromSeed(SEED_A);
  const s = await signDocument(DOC, { signer: a, method: "tofu", signerId: "a", ts: TS });
  const block = parseDocument(s.text).chain[0]!.raw + "\n";
  const v = await verifyDocument(DOC + "\n" + block.repeat(257));
  assert.equal(v.ok, false);
  assert.match(v.error ?? "", /too many signature blocks/);
});
