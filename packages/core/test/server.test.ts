import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  compareResults,
  createVerifyHandler,
  fromHex,
  parseDocument,
  publicHostFetch,
  remoteTsaVerifier,
  remoteVerify,
  signDocument,
  signerFromSeed,
  toJsonResult,
  verifyDocument,
  MemoryTofuStore,
  type JsonResult,
  type VerifyHandlerOptions,
} from "../src/index.ts";

const SEED_A = fromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
const SEED_B = fromHex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
const BASE = "https://verify.test";

const tofuDoc = async (seed: Uint8Array, signer = "alice") => (await signDocument("# Doc\n", { signer: await signerFromSeed(seed), method: "tofu", signerId: signer })).text;
const viaHandler = (o: VerifyHandlerOptions = {}) => {
  const handler = createVerifyHandler(o);
  return ((url: string, init?: RequestInit) => handler(new Request(url, init))) as typeof fetch;
};
const call = (handler: (r: Request) => Promise<Response>, method: string, path: string, headers: Record<string, string>, body?: string) => handler(new Request(BASE + path, { method, headers, body }));
const JSON_CT = { "content-type": "application/json" };

// --- verify

test("server: /v1/verify answers in the CLI JSON shape", async () => {
  const doc = await tofuDoc(SEED_A);
  const r = await remoteVerify(BASE, doc, { fetch: viaHandler({ verify: { offline: true } }) });
  assert.equal(r.ok, true);
  assert.equal(r.error, null);
  assert.deepEqual(Object.keys(r), ["ok", "error", "warnings", "agreement", "signatures"]);
  assert.deepEqual(Object.keys(r.signatures[0]!), ["index", "line", "status", "code", "message", "fields", "hash_ok", "partial", "key_source", "webauthn", "pgp", "resources", "revocation", "tsa", "warnings"]);
  assert.equal(r.signatures[0]!.status, "valid");
  assert.equal(r.signatures[0]!.fields.signer, "alice");

  const tampered = await remoteVerify(BASE, doc.replace("# Doc", "# Dog"), { fetch: viaHandler({ verify: { offline: true } }) });
  assert.equal(tampered.ok, false);
  assert.equal(tampered.signatures[0]!.code, "hash-mismatch");
  const unsigned = await remoteVerify(BASE, "# plain\n", { fetch: viaHandler() });
  assert.equal(unsigned.ok, false);
  assert.equal(typeof unsigned.error, "string");
});

test("server: no TOFU binding survives a request", async () => {
  const fetch = viaHandler({ verify: { offline: true } });
  assert.equal((await remoteVerify(BASE, await tofuDoc(SEED_A), { fetch })).ok, true);
  assert.equal((await remoteVerify(BASE, await tofuDoc(SEED_B), { fetch })).ok, true);
});

// --- request rules

test("server: origin, method, content type and size rules", async () => {
  const h = createVerifyHandler({ verify: { offline: true }, allowOrigins: ["https://app.example"], maxBodyBytes: 2048 });
  const doc = JSON.stringify({ document: await tofuDoc(SEED_A) });
  const cases: [string, string, string, Record<string, string>, string | undefined, number][] = [
    ["ok without origin", "POST", "/v1/verify", JSON_CT, doc, 200],
    ["allowed origin", "POST", "/v1/verify", { ...JSON_CT, origin: "https://app.example" }, doc, 200],
    ["other origin", "POST", "/v1/verify", { ...JSON_CT, origin: "https://evil.example" }, doc, 403],
    ["null origin", "POST", "/v1/verify", { ...JSON_CT, origin: "null" }, doc, 403],
    ["text content type", "POST", "/v1/verify", { "content-type": "text/plain" }, doc, 415],
    ["GET verify", "GET", "/v1/verify", {}, undefined, 405],
    ["POST health", "POST", "/v1/health", JSON_CT, "{}", 405],
    ["unknown path", "POST", "/v2/verify", JSON_CT, doc, 404],
    ["not JSON", "POST", "/v1/verify", JSON_CT, "document=x", 400],
    ["no document", "POST", "/v1/verify", JSON_CT, '{"doc":"x"}', 400],
    ["too large", "POST", "/v1/verify", JSON_CT, JSON.stringify({ document: "a".repeat(4096) }), 413],
    ["tsa without sig", "POST", "/v1/tsa", JSON_CT, '{"tsa_token":"base64:AA=="}', 400],
    ["tsa bad sig", "POST", "/v1/tsa", JSON_CT, '{"tsa_token":"base64:AA==","sig":"***"}', 400],
  ];
  for (const [name, method, path, headers, body, want] of cases) {
    const res = await call(h, method, path, headers, body);
    assert.equal(res.status, want, name);
    assert.equal(res.headers.get("access-control-allow-origin") !== null, headers.origin === "https://app.example", name);
  }
  const pre = await call(h, "OPTIONS", "/v1/verify", { origin: "https://app.example" });
  assert.equal(pre.status, 204);
  assert.equal(pre.headers.get("access-control-allow-origin"), "https://app.example");
  assert.match(pre.headers.get("access-control-allow-headers")!, /Content-Type/);
  assert.equal((await call(h, "OPTIONS", "/v1/verify", { origin: "https://evil.example" })).status, 403);
  const health = await (await call(createVerifyHandler({ version: "9.9.9" }), "GET", "/v1/health", {})).json();
  assert.deepEqual(health, { name: "@md-signature/core", version: "9.9.9", api: "v1" });
});

test("server: refuses work beyond maxConcurrent", async () => {
  let release!: () => void;
  let seen!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  const entered = new Promise<void>((r) => (seen = r));
  const h = createVerifyHandler({ maxConcurrent: 1, verify: { resolvers: { tofu: async () => (seen(), await gate, { keys: [], warnings: [] }) } } });
  const doc = JSON.stringify({ document: await tofuDoc(SEED_A) });
  const first = call(h, "POST", "/v1/verify", JSON_CT, doc);
  await entered;
  const second = await call(h, "POST", "/v1/verify", JSON_CT, doc);
  assert.equal(second.status, 503);
  assert.equal(second.headers.get("retry-after"), "1");
  release();
  assert.equal((await first).status, 200);
});

// --- outbound requests

test("server: outbound requests to private or internal hosts are refused", async () => {
  const seen: string[] = [];
  const inner = (async (url: URL | string) => {
    const u = String(url);
    seen.push(u);
    if (u === "https://hop.example.org/a") return new Response(null, { status: 302, headers: { location: "https://127.0.0.1/secret" } });
    if (u === "https://hop.example.org/b") return new Response(null, { status: 302, headers: { location: "https://ok.example.org/final" } });
    return new Response("body");
  }) as typeof fetch;
  const f = publicHostFetch(inner);
  for (const url of ["https://127.0.0.1/x", "https://localhost/x", "https://[::1]/x", "https://2130706433/x", "https://0x7f.1/x", "https://intranet/x", "https://db.internal/x", "https://printer.local/x", "file:///etc/passwd"]) {
    await assert.rejects(f(url), /refused/, url);
  }
  assert.deepEqual(seen, []);
  await assert.rejects(f("https://hop.example.org/a"), /refused request to 127\.0\.0\.1/);
  assert.equal(await (await f("https://hop.example.org/b")).text(), "body");
  assert.deepEqual(seen, ["https://hop.example.org/a", "https://hop.example.org/b", "https://ok.example.org/final"]);

  const doc = (await signDocument("# Doc\n", { signer: await signerFromSeed(SEED_A), method: "tofu", signerId: "alice", revocationUrl: "https://rev.internal/list.md" })).text;
  seen.length = 0;
  const r = await remoteVerify(BASE, doc, { fetch: viaHandler({ verify: { fetch: inner } }) });
  assert.equal(r.signatures[0]!.status, "unresolved");
  assert.deepEqual(seen, []);
});

// --- TSA through the server, and comparing both sides

const example = () => readFileSync(new URL("../../../examples/valid-cosigned.md", import.meta.url), "utf8");
const exampleDns = () => {
  const keys = JSON.parse(readFileSync(new URL("../../../examples/keys.json", import.meta.url), "utf8"));
  const dns: Record<string, string> = Object.fromEntries(Object.entries(keys.dns as Record<string, { txt: string }>).map(([k, v]) => [k, v.txt]));
  const fetch = (async (url: string) => {
    const n = new URL(url).searchParams.get("name")!;
    return new Response(JSON.stringify({ Status: 0, Answer: dns[n] ? [{ type: 16, data: `"${dns[n]}"` }] : [] }));
  }) as typeof globalThis.fetch;
  return { fetch, now: new Date(keys.now) };
};

test("server: tsaVerifier sends the token check to the server", async () => {
  const text = example();
  if (!/^tsa_token:/m.test(text)) return;
  const { fetch, now } = exampleDns();
  const trusting = remoteTsaVerifier(BASE, { fetch: viaHandler() });
  const strict = remoteTsaVerifier(BASE, { fetch: viaHandler({ verify: { tsaRoots: [] } }) });

  const local = await verifyDocument(text, { fetch, now, tsaRoots: [], tsaVerifier: trusting });
  const tsa = local.signatures.find((s) => s.tsa)!.tsa!;
  assert.equal(tsa.verified, true, tsa.detail);
  assert.match(tsa.signer!, /SSL\.com/);
  assert.ok(tsa.genTime);

  const refused = (await verifyDocument(text, { fetch, now, tsaVerifier: strict })).signatures.find((s) => s.tsa)!;
  assert.equal(refused.status, "valid");
  assert.equal(refused.tsa!.verified, false);
  assert.equal(refused.tsa!.genTime, undefined);

  const down = remoteTsaVerifier(BASE, { fetch: (async () => new Response("oops", { status: 502 })) as typeof globalThis.fetch });
  const unreachable = (await verifyDocument(text, { fetch, now, tsaVerifier: down })).signatures.find((s) => s.tsa)!;
  assert.equal(unreachable.status, "valid");
  assert.equal(unreachable.tsa!.status, "error");
  assert.match(unreachable.tsa!.detail, /verification server/);

  const lying = async () => ({ status: "error" as const, verified: false, genTime: "2019-01-01T00:00:00Z", detail: "x" });
  assert.equal((await verifyDocument(text, { fetch, now, tsaVerifier: lying })).signatures.find((s) => s.tsa)!.tsa!.genTime, undefined);
});

test("server: compareResults reports where two verifications differ", async () => {
  const text = example();
  if (!/^tsa_token:/m.test(text)) return;
  const { fetch, now } = exampleDns();
  const local = await verifyDocument(text, { fetch, now });
  const same = compareResults(local, toJsonResult(await verifyDocument(text, { fetch, now })));
  assert.deepEqual({ agree: same.agree, tsaAgree: same.tsaAgree, n: same.blocks.length }, { agree: true, tsaAgree: true, n: 2 });

  const noRoots = compareResults(local, toJsonResult(await verifyDocument(text, { fetch, now, tsaRoots: [] })));
  assert.equal(noRoots.agree, true);
  assert.equal(noRoots.tsaAgree, false);
  const tsBlock = noRoots.blocks.find((b) => b.local!.tsaVerified !== null)!;
  assert.deepEqual([tsBlock.local!.tsaVerified, tsBlock.remote!.tsaVerified, tsBlock.tsaAgree], [true, false, false]);

  const offline: JsonResult = toJsonResult(await verifyDocument(text, { offline: true, now, tofuStore: new MemoryTofuStore() }));
  const differs = compareResults(toJsonResult(local), offline);
  assert.equal(differs.agree, false);
  assert.ok(differs.blocks.some((b) => !b.agree && b.local!.status === "valid" && b.remote!.status === "unresolved"));

  const shorter: JsonResult = { ...toJsonResult(local), signatures: toJsonResult(local).signatures.slice(0, 1) };
  const missing = compareResults(local, shorter);
  assert.equal(missing.agree, false);
  assert.equal(missing.blocks[1]!.remote, null);
  assert.equal(parseDocument(text).chain.length, 2);
});
