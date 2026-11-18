import { test } from "node:test";
import assert from "node:assert/strict";
import {
  signDocument,
  verifyDocument,
  signerFromSeed,
  fromHex,
  sha256,
  toHex,
  toBase64,
  createSoftwareAuthenticator,
  registrationMessage,
  createRegistration,
  verifyRegistration,
  directoryKeyUrl,
  directoriesFromRecords,
  resolveDirectory,
  ResolutionError,
} from "../src/index.ts";

const SEED = fromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
const TS = "2026-11-16T09:00:00Z";
const DOC = "# Contract\n\nThe parties agree.\n";

// --- registration proofs
test("the registration message is the bytes the Go CLI signs", async () => {
  const m = registrationMessage("Y2hhbGxlbmdl", "alice@mail.example", "ed25519", "PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=");
  assert.equal(toHex(await sha256(m)), "8d2281f7f7b6e585130540359012a38d638193afb414b2fbd5169881d1dbaf67");
  assert.equal(await directoryKeyUrl("https://keys.mdsig.dev/", "alice@mail.example"), "https://keys.mdsig.dev/v1/keys/e29f4fb165e275d7e0fbbb5f7891bf1d1a69070aebb661cfdc3b3231f923967a");
});

test("registration proofs verify for Ed25519 keys and passkeys, and bind the address and key", async () => {
  const ed = await signerFromSeed(SEED);
  const r1 = await createRegistration("c1", "alice@mail.example", ed, "laptop");
  assert.equal(await verifyRegistration(r1), true);
  assert.equal(await verifyRegistration({ ...r1, email: "bob@mail.example" }), false);
  assert.equal(await verifyRegistration({ ...r1, challenge: "c2" }), false);
  const pk = await createSoftwareAuthenticator("mdsig.dev");
  const r2 = await createRegistration("c1", "carol@mail.example", pk);
  assert.equal(r2.type, "es256");
  assert.equal(await verifyRegistration(r2), true);
  assert.equal(await verifyRegistration({ ...r2, key: toBase64(ed.publicKey) }), false);
  assert.equal(await verifyRegistration({ ...r2, proof: { ...r2.proof, rp_id: "evil.example" } as typeof r2.proof }), false);
});

// --- lookup
test("dir= values: https only, duplicates collapse, conflicts stay distinct", () => {
  assert.deepEqual(directoriesFromRecords(["v=mdsig1; k=ed25519; p=AAAA", "v=mdsig1; dir=https://keys.example.com/"]), ["https://keys.example.com"]);
  assert.deepEqual(directoriesFromRecords(["v=mdsig1; dir=http://keys.example.com", "v=spf1 dir=https://x.example"]), []);
  assert.equal(directoriesFromRecords(["v=mdsig1; dir=https://a.example", "v=mdsig1; dir=https://b.example"]).length, 2);
});

function directoryFetch(responses: Record<string, unknown | number>, txt: Record<string, string[]> = {}): typeof fetch {
  return (async (url: string) => {
    if (url.startsWith("https://cloudflare-dns.com/dns-query?")) {
      const name = new URL(url).searchParams.get("name")!;
      const r = txt[name];
      return Response.json(r ? { Status: 0, Answer: r.map((d) => ({ type: 16, data: JSON.stringify(d) })) } : { Status: 3 });
    }
    const v = responses[url];
    if (v === undefined) throw new TypeError("network down");
    if (typeof v === "number") return new Response("", { status: v });
    return Response.json(v);
  }) as typeof fetch;
}

test("a response for another address counts as no key; extra directories are tried in order", async () => {
  const ed = await signerFromSeed(SEED);
  const email = "alice@mail.example";
  const entry = { type: "ed25519", key: toBase64(ed.publicKey) };
  const f = directoryFetch({
    [await directoryKeyUrl("https://keys.mdsig.dev", email)]: { email: "mallory@mail.example", keys: [entry] },
    [await directoryKeyUrl("https://keys.other.example", email)]: { email, verified: "email", keys: [entry] },
  });
  const r = await resolveDirectory({ signer: email, alg: "ed25519" }, { fetch: f, extraKeyDirectories: ["https://keys.other.example"] });
  assert.equal(r.keys.length, 1);
  assert.match(r.keys[0]!.source, /keys\.other\.example \(trusted list\)/);
  await assert.rejects(resolveDirectory({ signer: email, alg: "ed25519" }, { fetch: f }), (e: unknown) => e instanceof ResolutionError && e.kind === "not-found");
  await assert.rejects(resolveDirectory({ signer: email, alg: "ed25519" }, { fetch: f, keyDirectories: ["http://insecure.example"] }), (e: unknown) => e instanceof ResolutionError && e.kind === "unsupported");
});

test("an unreachable directory is a network error, not not-found; offline does not ask", async () => {
  const email = "alice@mail.example";
  const f = directoryFetch({});
  await assert.rejects(resolveDirectory({ signer: email, alg: "ed25519" }, { fetch: f }), (e: unknown) => e instanceof ResolutionError && e.kind === "network");
  await assert.rejects(resolveDirectory({ signer: email, alg: "ed25519" }, { fetch: f, offline: true }), (e: unknown) => e instanceof ResolutionError && e.kind === "offline");
});

test("directory signatures: snapshot by default, signer lower-cased, offline gives a bad signature only when it is bad", async () => {
  const ed = await signerFromSeed(SEED);
  const s = await signDocument(DOC, { signer: ed, method: "directory", signerId: "Alice@Mail.Example", ts: TS });
  assert.equal(s.fields.signer, "alice@mail.example");
  assert.equal(s.fields.pubkey, `ed25519:${toBase64(ed.publicKey)}`);
  const plain = await signDocument(DOC, { signer: ed, method: "directory", signerId: "alice@mail.example", ts: TS, embedKey: false });
  assert.equal(plain.fields.pubkey, undefined);
  await assert.rejects(signDocument(DOC, { signer: ed, method: "directory", signerId: "not-an-email", ts: TS }), /email address/);
  const off = await verifyDocument(s.text, { offline: true });
  assert.equal(off.signatures[0]!.status, "unresolved");
  const bad = await verifyDocument(s.text.replace(/sig: \|\n(?:  .*\n)+/, `sig: |\n  base64:${toBase64(new Uint8Array(64))}\n`), { offline: true });
  assert.equal(bad.signatures[0]!.code, "bad-signature");
});
