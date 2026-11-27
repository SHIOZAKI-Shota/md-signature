import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyDocument, toJsonResult, signatureTable, signatureTableToJson, findSignatureMarker, parseDocument, documentVerdict } from "../src/index.ts";
import { exampleOptions, readExample } from "./harness.ts";

interface Expected {
  ok: boolean;
  signatures: string[];
  error?: string;
  tsa?: (string | null)[];
  agreement: string;
  partial?: (string[] | null)[];
  resources?: string[][];
  revocation?: string[];
  pgp?: { keySource: string; keyAlg: string }[];
  warnings?: string[];
  agreement_json: unknown;
  table: unknown;
  times: (string | null)[];
  marker: number | null;
  verdict: string;
}
const expected: Record<string, Expected> = JSON.parse(readExample("expected.json"));

for (const [file, exp] of Object.entries(expected)) {
  test(`example ${file}`, async () => {
    const text = readExample(file);
    const r = await verifyDocument(text, exampleOptions());
    assert.equal(r.ok, exp.ok, JSON.stringify(r, null, 1));
    assert.deepEqual(
      r.signatures.map((s) => (s.status === "valid" ? "valid" : `${s.status}:${s.code}`)),
      exp.signatures,
    );
    if (exp.error === "unsigned-content") assert.match(r.error ?? "", /unsigned content/);
    if (exp.tsa) assert.deepEqual(r.signatures.map((s) => s.tsa?.status ?? null), exp.tsa);
    assert.equal(r.agreement.status, exp.agreement);
    if (exp.partial) assert.deepEqual(r.signatures.map((s) => s.partial?.sections ?? null), exp.partial);
    if (exp.resources) assert.deepEqual(r.signatures.map((s) => s.resources?.map((x) => x.status) ?? []), exp.resources);
    if (exp.revocation) assert.deepEqual(r.signatures.map((s) => s.revocation?.status ?? null), exp.revocation);
    if (exp.pgp) assert.deepEqual(r.signatures.map((s) => ({ keySource: s.pgp?.keySource, keyAlg: s.pgp?.keyAlg })), exp.pgp);
    for (const w of exp.warnings ?? []) assert.ok(r.warnings.includes(w), w);
    assert.deepEqual(toJsonResult(r).agreement, exp.agreement_json);
    assert.deepEqual(signatureTableToJson(signatureTable(r)), exp.table);
    assert.deepEqual(r.signatures.map((s) => s.time?.at ?? null), exp.times);
    assert.equal(findSignatureMarker(parseDocument(text).body).line ?? null, exp.marker);
    assert.equal(documentVerdict(r).kind, exp.verdict);
  });
}
