import { test } from "node:test";
import assert from "node:assert/strict";
import { parseRequire, serializeRequire, documentVerdict, verifyDocument, checkSignInput } from "../src/index.ts";
import { exampleOptions, readExample } from "./harness.ts";

// --- serializeRequire

const shape = (v: string) => {
  const p = parseRequire(v, 0);
  assert.deepEqual([p.errors, p.unsupported, p.hints], [[], [], []], v);
  return { order: p.spec.order, steps: p.spec.steps.map((s) => ({ any: s.any, lines: s.lines.map((l) => ({ method: l.method, signer: l.signer, attributes: l.attributes })) })) };
};

test("serializeRequire round-trips parseRequire", () => {
  for (const v of [
    "dns:example.com role=approver",
    "dns:example.com\ngit-hosting:github.com/alice role=reviewer",
    "order mode=strict\nstep\n  dns:example.com role=seller\nstep\n  tofu:bob@laptop",
    "step\n  dns:a.example.com role=buyer\nstep any=2\n  dns:*.example.com role=witness\n  tofu:bob@laptop role=witness",
    "order mode=guide\ndirectory:*@example.com user_verified member_of=dns:example.com",
    "tofu:carol user_verified pubkey=ed25519:11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
  ]) {
    const s = shape(v);
    assert.equal(serializeRequire(s), v);
    assert.deepEqual(shape(serializeRequire(parseRequire(v, 0).spec)), s);
  }
});

test("serializeRequire drops empty steps and writes headers only when needed", () => {
  assert.equal(serializeRequire({ steps: [{ lines: [] }, { lines: [{ method: "dns", signer: "example.com" }] }] }), "dns:example.com");
  assert.equal(serializeRequire({ order: "pending", steps: [{ any: 1, lines: [{ method: "dns", signer: "*" }] }] }), "step any=1\n  dns:*");
  assert.equal(serializeRequire({ steps: [] }), "");
});

// --- documentVerdict

test("documentVerdict follows the CLI exit codes", async () => {
  const cases: [string, string, number][] = [
    ["valid-single.md", "valid", 0],
    ["pending-require.md", "pending", 5],
    ["tampered.md", "failed", 1],
    ["require-declarer-unresolved.md", "unresolved", 3],
  ];
  for (const [file, kind, exitCode] of cases) assert.deepEqual(documentVerdict(await verifyDocument(readExample(file), exampleOptions())), { kind, exitCode }, file);
  assert.deepEqual(documentVerdict(await verifyDocument("# no signature\n")), { kind: "unsigned", exitCode: 1 });
  const offline = await verifyDocument(readExample("valid-cosigned.md"), { ...exampleOptions(), offline: true, checkTsa: false });
  assert.equal(documentVerdict(offline).kind, offline.signatures.every((s) => s.status === "valid") ? "valid" : "offline");
});

// --- checkSignInput

test("checkSignInput canonicalizes the signer and checks each field", () => {
  const c = checkSignInput({ method: "dns", signer: " Example.COM ", displayName: "  Example Corp ", require: "dns:example.com role=approver" });
  assert.equal(c.signer, "example.com");
  assert.equal(c.signerError, null);
  assert.equal(c.displayName, "Example Corp");
  assert.equal(c.displayNameError, null);
  assert.equal(c.require?.ok, true);
  assert.equal(c.require?.spec?.steps[0]?.lines[0]?.attributes.role, "approver");
  assert.ok(c.require?.explanation);
  assert.deepEqual(checkSignInput({ method: "tofu", signer: "" }), { signer: "", signerError: null, displayName: null, displayNameError: null, require: null });
});

test("checkSignInput reports problems in the requested language", () => {
  const bad = checkSignInput({ method: "dns", signer: "exa mple.com", displayName: "x".repeat(65), require: "dns:example.com approver" }, "ja");
  assert.ok(bad.signerError && /[\u3040-\u30ff\u4e00-\u9fff]/.test(bad.signerError), bad.signerError ?? "");
  assert.ok(bad.displayNameError && /[\u3040-\u30ff\u4e00-\u9fff]/.test(bad.displayNameError), bad.displayNameError ?? "");
  assert.equal(bad.require?.ok, false);
  assert.equal(bad.require?.spec, null);
  assert.ok(bad.require!.errors.length > 0);
  for (const e of bad.require!.errors) assert.match(e, /[\u3040-\u30ff\u4e00-\u9fff]/);
  const warn = checkSignInput({ method: "dns", signer: "example.com", require: "tofu:carol" });
  assert.equal(warn.require?.ok, true);
  assert.ok(warn.require!.warnings.length > 0);
});
