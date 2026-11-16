import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { verifyDocument, parseSshPublicKeys, parseDnsRecord, fromBase64, decodePublicKey, type Resolver } from "../src/index.ts";

const dir = new URL("../../../examples/", import.meta.url);
const read = (n: string) => readFileSync(new URL(n, dir), "utf8");
const keys = JSON.parse(read("keys.json"));

interface Expected {
  ok: boolean;
  signatures: string[];
  error?: string;
  tsa?: (string | null)[];
  agreement?: string;
  partial?: (string[] | null)[];
  resources?: string[][];
  revocation?: string[];
  pgp?: { keySource: string; keyAlg: string }[];
}
const expected: Record<string, Expected> = JSON.parse(read("expected.json"));

const resolvers: Record<string, Resolver> = {
  "git-hosting": async (f) => ({
    keys: parseSshPublicKeys(keys["git-hosting"][f.signer!].keys_file).map((k) => ({ alg: "ed25519", key: k.key!, source: "keys.json" })),
    warnings: [],
  }),
  dns: async (f) => {
    const rec = parseDnsRecord(keys.dns[`${f.selector}._mdsig.${f.signer}`].txt)!;
    return { keys: [{ alg: rec.k, key: decodePublicKey(rec.k, fromBase64(rec.p)), source: "keys.json" }], warnings: [] };
  },
};

const fetch = (async (url: string) => {
  const file = keys.fetch?.[url];
  if (!file) throw new TypeError(`network disabled in tests: ${url}`);
  return new Response(read(file));
}) as typeof globalThis.fetch;

const loadResource = async (ref: string) => {
  const u = new URL(ref, dir);
  return existsSync(u) ? new Uint8Array(readFileSync(u)) : null;
};

for (const [file, exp] of Object.entries(expected)) {
  test(`example ${file}`, async () => {
    const r = await verifyDocument(read(file), { resolvers, fetch, loadResource, now: new Date(keys.now) });
    assert.equal(r.ok, exp.ok, JSON.stringify(r, null, 1));
    assert.deepEqual(
      r.signatures.map((s) => (s.status === "valid" ? "valid" : `${s.status}:${s.code}`)),
      exp.signatures,
    );
    if (exp.error === "unsigned-content") assert.match(r.error ?? "", /unsigned content/);
    if (exp.tsa) assert.deepEqual(r.signatures.map((s) => s.tsa?.status ?? null), exp.tsa);
    assert.equal(r.agreement.status, exp.agreement ?? "none");
    if (exp.partial) assert.deepEqual(r.signatures.map((s) => s.partial?.sections ?? null), exp.partial);
    if (exp.resources) assert.deepEqual(r.signatures.map((s) => s.resources?.map((x) => x.status) ?? []), exp.resources);
    if (exp.revocation) assert.deepEqual(r.signatures.map((s) => s.revocation?.status ?? null), exp.revocation);
    if (exp.pgp) assert.deepEqual(r.signatures.map((s) => ({ keySource: s.pgp?.keySource, keyAlg: s.pgp?.keyAlg })), exp.pgp);
  });
}
