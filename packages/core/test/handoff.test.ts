import { test } from "node:test";
import assert from "node:assert/strict";
import {
  checkHandoffRequest,
  connectPasskeyViaPage,
  createHandoffRequest,
  createSoftwareAuthenticator,
  toBase64,
  fromHex,
  handoffResponseUrl,
  HandoffError,
  isHandoffReturnUrl,
  parseHandoffResponse,
  parseSignedPayload,
  payloadMatchesKey,
  prepareSignature,
  rpIdFitsPage,
  signDocument,
  signedPayload,
  signerFromSeed,
  signViaPage,
  utf8,
  verifyDocument,
  type HandoffTransport,
} from "../src/index.ts";

// --- helpers

const DOC = "# Contract\n\nPay 100.\n";
const TS = "2026-11-16T09:00:00Z";
const PAGE = "https://keys.example.org/sign";
const RETURN = "mdsig+test://handoff";
const SEED = fromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");

const AUTH = await createSoftwareAuthenticator("keys.example.org");

async function signingPage(o: { tamper?: (u: URL) => void; refuse?: "cancelled" } = {}): Promise<HandoffTransport> {
  const auth = AUTH;
  return async (req) => {
    const r = checkHandoffRequest(req.url, "keys.example.org");
    assert.ok(r.ok, !r.ok ? r.message : "");
    if (o.refuse) return handoffResponseUrl(r.returnUrl, r.state, { error: o.refuse });
    let out: string;
    if (r.op === "key") out = handoffResponseUrl(r.returnUrl, r.state, { rpId: "keys.example.org", key: auth.publicKey, credential: "Y3JlZA" });
    else {
      assert.ok(payloadMatchesKey(r.fields, auth.publicKey));
      const challenge = new Uint8Array(await crypto.subtle.digest("SHA-256", r.payload as BufferSource));
      out = handoffResponseUrl(r.returnUrl, r.state, await auth.getAssertion(challenge));
    }
    const u = new URL(out);
    o.tamper?.(u);
    return u.toString();
  };
}

// --- two-phase signing

test("prepareSignature + finish gives the same block as signDocument", async () => {
  const signer = await signerFromSeed(SEED);
  const direct = await signDocument(DOC, { signer, method: "tofu", signerId: "a", ts: TS });
  const p = await prepareSignature(DOC, { signer: { alg: "ed25519", publicKey: signer.publicKey }, method: "tofu", signerId: "a", ts: TS });
  assert.deepEqual(p.payload, signedPayload(p.fields));
  const done = await p.finish(await signer.sign(p.payload));
  assert.equal(done.text, direct.text);
  await assert.rejects(p.finish(new Uint8Array(64)), /does not verify/);
});

// --- handoff

test("return URLs are a custom scheme or a loopback address", () => {
  assert.ok(isHandoffReturnUrl("mdsig+fountain-pen://handoff"));
  assert.ok(isHandoffReturnUrl("http://127.0.0.1:8123/cb"));
  assert.ok(isHandoffReturnUrl("http://[::1]:8123/cb"));
  assert.ok(!isHandoffReturnUrl("https://evil.example/cb"));
  assert.ok(!isHandoffReturnUrl("http://localhost:8123/cb"));
  assert.ok(!isHandoffReturnUrl("http://127.0.0.1/cb"));
  assert.ok(rpIdFitsPage(PAGE, "example.org"));
  assert.ok(!rpIdFitsPage(PAGE, "ys.example.org"));
  assert.throws(() => createHandoffRequest("http://keys.example.org/sign", { op: "key", returnUrl: RETURN }), HandoffError);
  assert.throws(() => createHandoffRequest(PAGE, { op: "key", returnUrl: "https://evil.example/" }), HandoffError);
});

test("a passkey connects and signs through the page; the block verifies", async () => {
  const transport = await signingPage();
  const passkey = await connectPasskeyViaPage(PAGE, { returnUrl: RETURN, transport });
  assert.equal(passkey.rpId, "keys.example.org");
  const r = await signViaPage(DOC, { method: "dns", signerId: "example.org", ts: TS, embedKey: true, passkey, returnUrl: RETURN, transport, name: "contract.md" });
  assert.equal(r.fields.rp_id, "keys.example.org");
  assert.equal(r.fields.alg, "webauthn-es256");
  const t = await signViaPage(DOC, { method: "tofu", signerId: "alice", ts: TS, passkey, returnUrl: RETURN, transport });
  assert.equal((await verifyDocument(t.text, { offline: true })).signatures[0]!.status, "valid");
});

test("tampered answers, other states, and refusals are rejected", async () => {
  const passkey = await connectPasskeyViaPage(PAGE, { returnUrl: RETURN, transport: await signingPage() });
  const o = { method: "tofu" as const, signerId: "alice", ts: TS, passkey, returnUrl: RETURN };
  const flip = await signingPage({
    tamper: (u) => {
      const s = u.searchParams.get("sig")!;
      u.searchParams.set("sig", s.slice(0, -2) + (s.endsWith("AA") ? "AB" : "AA"));
    },
  });
  await assert.rejects(signViaPage(DOC, { ...o, transport: flip }), /does not verify/);
  await assert.rejects(signViaPage(DOC, { ...o, transport: await signingPage({ tamper: (u) => u.searchParams.set("state", "x".repeat(22)) }) }), (e) => e instanceof HandoffError && e.code === "bad-response");
  await assert.rejects(signViaPage(DOC, { ...o, transport: await signingPage({ refuse: "cancelled" }) }), (e) => e instanceof HandoffError && e.code === "cancelled");
  await assert.rejects(signViaPage(DOC, { ...o, method: "git-hosting" as never, transport: await signingPage() }), HandoffError);
  await assert.rejects(connectPasskeyViaPage("https://other.example/sign", { returnUrl: RETURN, transport: await signingPage() }), /RP ID/);
});

test("the signing page refuses bad requests", async () => {
  const signer = await signerFromSeed(SEED);
  const p = await prepareSignature(DOC, { signer: { alg: "ed25519", publicKey: signer.publicKey }, method: "tofu", signerId: "a", ts: TS });
  const ed = createHandoffRequest(PAGE, { op: "sign", returnUrl: RETURN, payload: p.payload });
  assert.equal(checkHandoffRequest(ed.url, "keys.example.org").ok, false);
  const bad = new URL(ed.url);
  bad.searchParams.set("return", "https://evil.example/");
  const r = checkHandoffRequest(bad.toString(), "keys.example.org");
  assert.ok(!r.ok && r.returnUrl === undefined);
  const wa = await prepareSignature(DOC, { signer: { alg: "webauthn-es256", publicKey: new Uint8Array(91), rpId: "other.example" }, method: "tofu", signerId: "a", ts: TS });
  const other = checkHandoffRequest(createHandoffRequest(PAGE, { op: "sign", returnUrl: RETURN, payload: wa.payload }).url, "keys.example.org");
  assert.ok(!other.ok && /rp_id/.test(other.message));
  assert.equal(parseSignedPayload(utf8("md-signature/v1\nb=1\na=2")), null);
  assert.deepEqual(parseSignedPayload(utf8("md-signature/v1\na=x\n  y\nb=1")), { a: "x\ny", b: "1" });
  assert.equal(parseHandoffResponse("mdsig+test://handoff?v=2&state=abc", "key"), null);
});

test("payloadMatchesKey compares decoded key bytes (SPEC 3.4)", async () => {
  const a = await createSoftwareAuthenticator("mdsig.dev");
  const b = await createSoftwareAuthenticator("mdsig.dev");
  const raw = a.publicKey.slice(-65);
  assert.ok(payloadMatchesKey({ pubkey: "es256:" + toBase64(raw) }, a.publicKey));
  assert.ok(payloadMatchesKey({ pubkey: "es256:" + toBase64(a.publicKey) }, raw));
  assert.ok(!payloadMatchesKey({ pubkey: "es256:" + toBase64(b.publicKey) }, a.publicKey));
  assert.ok(!payloadMatchesKey({ pubkey: "ed25519:" + toBase64(raw) }, a.publicKey));
  assert.ok(payloadMatchesKey({}, a.publicKey));
});
