import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { verifyDocument, localizeMessage, parseRequire, explainRequire, checkSignerId, checkDisplayName, type VerifyResult } from "../src/index.ts";
import { MESSAGES_JA } from "../src/messages-ja.ts";
import { checkCatalog, renderMessagesModule } from "../scripts/messages-module.ts";
import { exampleOptions, readExample } from "./harness.ts";

const catalogJson = readFileSync(new URL("../../../mdsig/messages_ja.json", import.meta.url), "utf8");
const JA_RE = /[぀-ヿ一-鿿]/;

function assertJa(en: string, where: string): void {
  const ja = localizeMessage(en, "ja");
  assert.notEqual(ja, en, `${where}: no pattern for ${JSON.stringify(en)}`);
  for (const part of ja.split("；")) assert.match(part, JA_RE, `${where}: ${JSON.stringify(en)} -> ${JSON.stringify(ja)}`);
}

function messagesOf(r: VerifyResult): [string, string][] {
  const out: [string, string][] = [];
  if (r.error) out.push(["error", r.error]);
  for (const w of r.warnings) out.push(["warning", w]);
  for (const s of r.signatures) {
    if (s.message) out.push([`#${s.index} message`, s.message]);
    for (const w of s.warnings) out.push([`#${s.index} warning`, w]);
    for (const x of s.resources ?? []) if (x.detail && x.status !== "mismatch") out.push([`#${s.index} resource`, x.detail]);
    if (s.revocation?.detail) out.push([`#${s.index} revocation`, s.revocation.detail]);
    if (s.tsa?.detail) out.push([`#${s.index} tsa`, s.tsa.detail]);
  }
  for (const d of r.agreement.declarations) if (d.detail) out.push([`declaration #${d.declaredBy}`, d.detail]);
  return out;
}

// --- catalog

test("messages: catalog entries are anchored and compile", () => {
  const entries = checkCatalog(JSON.parse(catalogJson));
  assert.ok(entries.length > 200);
  for (const e of entries) {
    assert.ok(e.en.startsWith("^") && e.en.endsWith("$"), e.en);
    assert.doesNotThrow(() => new RegExp(e.en), e.en);
    assert.doesNotMatch(e.en, /\(\?<|\\[1-9]/, `${e.en}: lookbehind, named groups, and backreferences are not RE2`);
    assert.doesNotMatch(e.ja, /—/, e.ja);
  }
});

test("messages: src/messages-ja.ts is generated from mdsig/messages_ja.json (npm run build:messages)", () => {
  assert.equal(readFileSync(new URL("../src/messages-ja.ts", import.meta.url), "utf8"), renderMessagesModule(catalogJson));
  assert.equal(MESSAGES_JA.length, JSON.parse(catalogJson).length);
});

test("messages: en and unknown text are returned unchanged", () => {
  assert.equal(localizeMessage("document content was modified after this signature", "en"), "document content was modified after this signature");
  assert.equal(localizeMessage("something the library never says", "ja"), "something the library never says");
  assert.equal(localizeMessage("document content was modified after this signature", "ja"), "文書の内容がこの署名の後に変更されている");
});

test("messages: nested and joined messages are localized part by part", () => {
  assert.equal(
    localizeMessage('unknown field "foo" (extension fields must start with "x_"); missing required field "sig"', "ja"),
    '不明なフィールド "foo"（拡張フィールドは "x_" で開始しなければならない）；必須フィールド "sig" がない',
  );
  assert.equal(localizeMessage("revocation list could not be checked: https://example.com/r.md is not signed by the expected issuer", "ja"), "撤回リストを確認できない：https://example.com/r.md は想定する発行者の署名を持たない");
  assert.equal(localizeMessage("hint: require line 2: write the role as \"role=author\" (format 0.1)", "ja"), "ヒント：require 2行目：役割は \"role=author\" と記述する（形式 0.1）");
  assertJa("pgp key lookup: keyring: no key; WKD: unreachable; keys.openpgp.org: found", "pgp lookup");
});

// --- vectors

const expected: Record<string, unknown> = JSON.parse(readExample("expected.json"));
for (const file of Object.keys(expected)) {
  test(`messages: example ${file}`, async () => {
    const r = await verifyDocument(readExample(file), exampleOptions());
    for (const [where, m] of messagesOf(r)) assertJa(m, `${file} ${where}`);
  });
}

// --- require, identities, display names

const BAD_REQUIRE = [
  "step\n\tdns:example.com",
  "order pending\nstep\n  dns:example.com",
  "step\n  dns:example.com\norder mode=guide",
  "order mode=sometimes\nstep\n  dns:example.com",
  "order mode=guide x=1\nstep\n  dns:example.com",
  "step 1\n  dns:example.com",
  "step any=0\n  dns:example.com",
  "step\n  example.com",
  "step\n  tsa:https://tsa.example",
  "step\n  dns:example.com author",
  "step\n  ssh:alice",
  "step\n  dns:Example.com",
  "step\n  dns:example.com role=Author",
  "step\n  dns:example.com pubkey=ed25519:AAAA",
  "step\n  tofu:bob pubkey=rsa:AAAA",
  "step\n  git-hosting:github.com/alice user_verified",
  "step\n  tofu:bob user_verified",
  "step\n  tofu:bob member_of=dns:example.com",
  "step\n  dns:example.com member_of=http://example.com/r.md",
  "step\n  dns:example.com  role=author",
  "step\n  dns:example.com role=a role=b",
  "step\n  dns:example.com role=",
  "step\n  dns:example.com user_verified=yes",
  "step\n  dns:example.com member_of",
  "step",
  "step any=3\n  dns:a.example\n  dns:b.example",
  "step\n  dns:a.example\n  dns:a.example",
  "order mode=strict\nstep\n  dns:*",
  "step\n  tofu:*",
  "step\n  dns:*example.com",
  "step\n  directory:*@Example.com",
  "",
];

test("messages: parseRequire errors, unsupported lines, and hints", () => {
  let n = 0;
  for (const v of BAD_REQUIRE) {
    const p = parseRequire(v);
    const all = [...p.errors, ...p.unsupported, ...p.hints, ...(p.overLimit ? [p.overLimit] : [])];
    assert.ok(all.length, `no message for ${JSON.stringify(v)}`);
    for (const m of all) assertJa(m, `require ${JSON.stringify(v)}`);
    n += all.length;
  }
  assert.ok(n >= BAD_REQUIRE.length);
  const many = "step\n" + Array.from({ length: 70 }, (_, i) => `  dns:a${i}.example`).join("\n");
  assertJa(parseRequire(many).overLimit!, "over limit");
  const steps = Array.from({ length: 17 }, (_, i) => `step\n  dns:a${i}.example`).join("\n");
  assertJa(parseRequire(steps).overLimit!, "over limit");
});

test("messages: explainRequire(value, 'ja') localizes errors, unsupported lines, warnings, and hints", () => {
  for (const v of BAD_REQUIRE) {
    const e = explainRequire(v, "ja");
    for (const m of [...e.errors, ...e.unsupported, ...e.warnings, ...e.hints]) assert.match(m, JA_RE, `${JSON.stringify(v)}: ${m}`);
    const en = explainRequire(v, "en");
    assert.deepEqual(e.errors, en.errors.map((m) => localizeMessage(m, "ja")));
  }
  const w = explainRequire("step\n  tofu:bob\nstep\ndns:example.com", "ja");
  assert.ok(w.warnings.length >= 2);
  for (const m of w.warnings) assert.match(m, JA_RE);
});

test("messages: checkSignerId and checkDisplayName errors", () => {
  const cases: [string, string][] = [
    ["dns", "Example.com"],
    ["dns", "*.example.com"],
    ["git-hosting", "github.com"],
    ["pgp", "Alice@example.com"],
    ["directory", "alice"],
    ["tofu", "bob laptop"],
    ["tsa", "tsa.example"],
  ];
  for (const [method, signer] of cases) {
    const e = checkSignerId(method, signer);
    assert.ok(e, `${method}:${signer}`);
    assertJa(e, `${method}:${signer}`);
  }
  for (const name of ["a".repeat(65), "a　b", "ｱ", "a  b"]) {
    const e = checkDisplayName(name);
    assert.ok(e, name);
    assertJa(e, `display_name ${JSON.stringify(name)}`);
  }
});
