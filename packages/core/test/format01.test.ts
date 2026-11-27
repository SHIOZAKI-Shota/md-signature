import { test } from "node:test";
import assert from "node:assert/strict";
import {
  signDocument,
  verifyDocument,
  signerFromSeed,
  fromHex,
  toBase64,
  parseDocument,
  parseFields,
  parseRequire,
  parseListLine,
  parseScope,
  parseSignedList,
  parseRosterRef,
  evaluateAgreement,
  isLdhDomain,
  isEmailId,
  checkSignerId,
  checkDisplayName,
  sameKeyValue,
  decodeLocalRef,
  parseResources,
  linesWithFence,
  endsInOpenFence,
  memberRecordName,
  base32LowerNoPad,
  lookupDnsMember,
  findSignatureMarker,
  signatureTable,
  renderSignatureTableHtml,
  explainRequire,
  createSoftwareAuthenticator,
  prepareSignature,
  checkHandoffRequest,
  createHandoffRequest,
  serializeBlock,
  signedPayload,
  sha256,
  utf8,
  type AgreementBlock,
  type MembershipOracle,
  type Resolver,
} from "../src/index.ts";

const SEED_A = fromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
const TS = "2026-11-16T09:00:00Z";
const DOC = "# Contract\n\nThe parties agree.\n";

const fixedKeys = (map: Record<string, Uint8Array>): Resolver => async (f) => {
  const key = map[f.signer!];
  if (!key) throw new Error("unknown");
  return { keys: [{ alg: "ed25519", key, source: "test" }], warnings: [] };
};

// --- grammar (SPEC 3.2)

test("grammar: continuation lines keep extra leading spaces; trailing spaces are malformed", () => {
  const p = parseFields(["v: 0.1", "require: |", "  step", "    dns:a.example", "x_note: a", "method: tofu", "signer: a", "ts: x", "alg: ed25519", "hash: h", "sig: s"]);
  assert.deepEqual(p.errors, []);
  assert.equal(p.fields.require, "step\n  dns:a.example");
  assert.match(new TextDecoder().decode(signedPayload({ require: p.fields.require! })), /require=step\n {4}dns:a\.example/);
  assert.match(parseFields(["require: |", "  dns:a.example  "]).errors.join(), /trailing spaces/);
  assert.match(parseFields(["reason: a "]).errors.join(), /trailing spaces/);
});

test("grammar: Cf, Zl, Zp, and noncharacters are rejected; alg is required", () => {
  for (const ch of ["\u200b", "\u200d", "\u{e0041}", "\ufeff", "\u2029", "\ufffe", "\ufdd0", "\u{1fffe}"]) {
    assert.match(parseFields([`reason: a${ch}b`]).errors.join(), /must not contain/, JSON.stringify(ch));
  }
  assert.match(parseFields(["v: 0.1", "method: tofu", "signer: a", "ts: x", "hash: h", "sig: s"]).errors.join(), /missing required field "alg"/);
});

test("grammar: role is one word; display_name follows the Nickname rules", async () => {
  const a = await signerFromSeed(SEED_A);
  await assert.rejects(signDocument(DOC, { signer: a, method: "tofu", signerId: "a", role: "Approver" }), /one word/);
  await assert.rejects(signDocument(DOC, { signer: a, method: "tofu", signerId: "a", role: "chief approver" }), /one word/);
  const ok = await signDocument(DOC, { signer: a, method: "tofu", signerId: "a", ts: TS, role: "legal.reviewer", displayName: "Alice Example" });
  assert.match(ok.block, /\ndisplay_name: Alice Example\nrole: legal\.reviewer\n/);
  assert.equal(checkDisplayName("佐藤 花子"), null);
  assert.match(checkDisplayName("Ａｌｉｃｅ")!, /NFKC/);
  assert.match(checkDisplayName("a  b")!, /consecutive/);
  assert.match(checkDisplayName("a\u3000b")!, /U\+0020/);
  assert.match(checkDisplayName("x".repeat(65))!, /64/);
  const v = await verifyDocument(ok.text.replace("display_name: Alice Example", `display_name: ${"x".repeat(65)}`));
  assert.equal((await signDocument(DOC, { signer: a, method: "tofu", signerId: "a", ts: TS, displayName: "  Ａlice   Example " })).fields.display_name, "Alice Example");
  assert.equal(v.signatures[0]!.status, "malformed");
});

// --- identifiers (SPEC 3.4)

test("identifiers: ldh-domain syntax", () => {
  for (const d of ["example.com", "a-b.example.co.jp", "xn--fsqu00a.example", "1.2.3.example"]) assert.ok(isLdhDomain(d), d);
  for (const d of ["Example.com", "example.com.", "localhost", "127.0.0.1", "2130706433", "example.123", "-a.example", "a-.example", "a_b.example", "a..example", `${"a".repeat(64)}.example`, `${"a.".repeat(127)}com`]) assert.ok(!isLdhDomain(d), d);
  assert.ok(isEmailId("alice@mail.example"));
  for (const e of ["Alice@mail.example", "alice@Mail.example", "al*ce@mail.example", "alice@localhost", "@mail.example"]) assert.ok(!isEmailId(e), e);
  assert.equal(checkSignerId("git-hosting", "github.com/alice"), null);
  assert.ok(checkSignerId("git-hosting", "github.com/Alice"));
  assert.ok(checkSignerId("tofu", "bob*"));
  assert.equal(checkSignerId("tofu", "Bob@Laptop"), null);
  assert.ok(checkSignerId("tofu", "Bob Laptop"));
  assert.ok(isEmailId("ユーザ@mail.example"));
  assert.ok(!isEmailId("a..b@mail.example"));
  assert.ok(!isEmailId(".a@mail.example"));
  assert.equal(checkSignerId("git-hosting", "github.com/.x_y-z"), null);
});

test("identifiers: generators lower-case ASCII; verifiers compare exactly", async () => {
  const a = await signerFromSeed(SEED_A);
  const s = await signDocument(DOC, { signer: a, method: "dns", signerId: "Example.COM.", selector: "2026", ts: TS });
  assert.equal(s.fields.signer, "example.com");
  const resolvers = { dns: fixedKeys({ "example.com": a.publicKey }) };
  assert.equal((await verifyDocument(s.text, { resolvers })).ok, true);
  assert.equal((await verifyDocument(s.text.replace("signer: example.com", "signer: EXAMPLE.com"), { resolvers })).signatures[0]!.status, "malformed");
  await assert.rejects(signDocument(DOC, { signer: a, method: "dns", signerId: "example.com", selector: "_member" }), /must not start with "_"/);
  const g = await signDocument(DOC, { signer: a, method: "git-hosting", signerId: "GitHub.com/Alice", ts: TS });
  assert.equal(g.fields.signer, "github.com/alice");
  await assert.rejects(signDocument(DOC, { signer: a, method: "tofu", signerId: "any*one" }), /"\*"/);
});

test("identifiers: pubkey= compares decoded key bytes (raw and SPKI)", async () => {
  const a = await signerFromSeed(SEED_A);
  const spki = new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, ...a.publicKey]);
  assert.ok(sameKeyValue(`ed25519:${toBase64(a.publicKey)}`, `ed25519:${toBase64(spki)}`));
  assert.ok(!sameKeyValue(`ed25519:${toBase64(a.publicKey)}`, `es256:${toBase64(a.publicKey)}`));
});

// --- list lines (SPEC 3.5), scope, resources

test("list lines: one space, attributes split at the first =, no empty values or duplicates", () => {
  const ok = parseListLine("  dns:a.example role=x member_of=https://e.example/?a=b user_verified", { role: "value", member_of: "value", user_verified: "flag" });
  assert.equal(ok.line!.indent, 2);
  assert.equal(ok.line!.attrs.get("member_of"), "https://e.example/?a=b");
  assert.equal(ok.line!.attrs.get("user_verified"), true);
  assert.match(parseListLine("dns:a.example  role=x", { role: "value" }).error!, /exactly one space/);
  assert.match(parseListLine("dns:a.example role=", { role: "value" }).error!, /empty value/);
  assert.match(parseListLine("dns:a.example role=x role=y", { role: "value" }).error!, /twice/);
  assert.match(parseListLine("dns:a.example role", { role: "value" }).error!, /needs a value/);
  assert.match(parseListLine("dns:a.example user_verified=yes", { user_verified: "flag" }).error!, /takes no value/);
  assert.deepEqual(parseListLine("dns:a.example x_new=1", {}).line!.unknown, ["x_new"]);
});

test("scope: one id per line; the old comma form is malformed with a hint", async () => {
  assert.deepEqual(parseScope("terms\n  fees"), ["terms", "fees"]);
  assert.equal(parseScope("section:terms,section:fees"), null);
  assert.equal(parseScope("terms\nterms"), null);
  const a = await signerFromSeed(SEED_A);
  const doc = "<!-- mdsig:section terms -->\nT\n<!-- /mdsig:section -->\n<!-- mdsig:section fees -->\nF\n<!-- /mdsig:section -->\n";
  const s = await signDocument(doc, { signer: a, method: "tofu", signerId: "a", ts: TS, scope: ["terms", "fees"] });
  assert.match(s.block, /scope: \|\n {2}terms\n {2}fees\n/);
  const old = await verifyDocument(s.text.replace("scope: |\n  terms\n  fees\n", "scope: section:terms,section:fees\n"));
  assert.equal(old.signatures[0]!.status, "malformed");
  assert.ok(old.signatures[0]!.warnings.some((w) => /one section id per line/.test(w)));
});

test("resources: percent-decoding rules for local references", () => {
  assert.deepEqual(decodeLocalRef("assets/meeting%20notes.txt"), { path: "assets/meeting notes.txt" });
  assert.deepEqual(decodeLocalRef("img/%E5%9B%B3.png"), { path: "img/図.png" });
  assert.deepEqual(decodeLocalRef("img/図.png"), { path: "img/図.png" });
  for (const bad of ["..%2Fsecret", "a%2fb", "a%5Cb", "a%00b", "a/%2E%2E/b", "a//b", "a/./b", "a/", "%zz", "a%ff", "a b", "a#b", "/abs", "./a.png", "C:/x.png", "c%3A/x.png"]) assert.ok("error" in decodeLocalRef(bad), bad);
  const p = parseResources("a.png hash=sha256:" + "0".repeat(64) + "\nhttps://e.example/x hash=sha256:" + "1".repeat(64));
  assert.deepEqual(p.errors, []);
  assert.deepEqual(p.entries.map((e) => [e.ref, e.remote, e.path]), [["a.png", false, "a.png"], ["https://e.example/x", true, undefined]]);
  const q = parseResources("https://e.example/x?y=1&z=2 hash=sha256:" + "1".repeat(64));
  assert.deepEqual([q.errors, q.entries[0]!.ref], [[], "https://e.example/x?y=1&z=2"]);
  assert.equal(parseListLine("a=b c=d", { c: "value" }).line!.target, "a=b");
  assert.match(parseResources("sha256:" + "0".repeat(64) + " a.png").errors.join(), /invalid attribute/);
  assert.match(parseResources("a.png hash=sha256:" + "0".repeat(64) + " size=3").errors.join(), /unknown attribute/);
  assert.match(parseResources("a.png hash=sha256:" + "A".repeat(64)).errors.join(), /lowercase/);
  assert.equal(parseResources("a.png hash=sha512:" + "0".repeat(128)).unsupportedHash, "sha512:" + "0".repeat(128));
});

// --- code fences (SPEC 5.5)

test("fences: a shorter or different fence does not close; generators refuse an open fence", async () => {
  const lines = [...linesWithFence("````\n```\n~~~~\n````\nafter")];
  assert.deepEqual(lines.map((l) => [l.inFence, l.close ?? false]), [[true, false], [true, false], [true, false], [true, true], [false, false]]);
  assert.equal([...linesWithFence("```mdsig-list  \n```")][0]!.info, "mdsig-list");
  assert.ok(endsInOpenFence("a\n```\nb\n"));
  assert.ok(!endsInOpenFence("a\n```\nb\n```\n"));
  assert.ok(endsInOpenFence("    ```\n```js\n"));
  assert.ok(!endsInOpenFence("``` not `a` fence\n"));
  assert.ok(endsInOpenFence("~~~ `ok` for tildes\n"));
  const a = await signerFromSeed(SEED_A);
  await assert.rejects(signDocument("# a\n\n```\ncode\n", { signer: a, method: "tofu", signerId: "a" }), /open code fence/);
});

// --- require parsing (SPEC 5.8)

test("require: ABNF, attributes, and where they may appear", () => {
  const ok = parseRequire("order mode=guide\nstep\n  dns:a.example role=approver\nstep any=2\n  dns:*.example.com member_of=dns:corp.example user_verified\n  directory:*@mail.example member_of=https://example.com/m.md\n  tofu:bob pubkey=ed25519:11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo= user_verified");
  assert.deepEqual([ok.errors, ok.unsupported], [[], []]);
  assert.equal(ok.spec.order, "guide");
  assert.deepEqual(ok.spec.steps.map((s) => [s.any, s.lines.length]), [[null, 1], [2, 3]]);
  assert.deepEqual(ok.requirements[1]!.attributes, { user_verified: true, member_of: "dns:corp.example" });
  const err = (v: string, re: RegExp) => assert.match(parseRequire(v).errors.join("; "), re, v);
  err("pgp:a@b.example user_verified", /only allowed on dns, directory, and tofu/);
  err("tofu:bob user_verified", /needs pubkey=/);
  err("dns:a.example pubkey=ed25519:AAAA", /only allowed on tofu/);
  err("tofu:bob pubkey=ed25519:AAAA", /pubkey=/);
  err("dns:a.example role=Approver", /role must match/);
  err("dns:a.example\nstep\n  dns:b.example", /before the first "step"/);
  err("step\nstep\n  dns:a.example", /step 1 has no requirement/);
  err("step any=3\n  dns:a.example\n  dns:b.example", /any=3 of 2/);
  err("dns:a.example\ndns:a.example role=x", /appears twice/);
  err("order mode=strict\ndns:*", /strict cannot be used with pattern/);
  err("order mode=fast\ndns:a.example", /order mode=/);
  err("tsa:https://t.example", /cannot be required/);
  err("dns:Example.com", /lower-case domain/);
  for (const pat of ["dns:a*.example", "dns:*example.com", "tofu:*", "git-hosting:github.com/*", "directory:*.mail.example", "dns:*.localhost"]) err(pat, /patterns|tofu has no|domain/);
  assert.deepEqual(parseRequire("step any=5\n  dns:*.example.com").errors, []);
  err("step any=2\n  dns:a.example\n  dns:a.example", /any=2 of 1 different signers/);
  err("tofu:bob member_of=dns:corp.example", /not allowed on tofu/);
  for (const url of ["http://e.example/m", "https://u@e.example/m", "https://e.example:8443/m", "https://e.example/m#f", "https://192.0.2.1/m", "dns:Corp.example"]) err(`dns:*.example.com member_of=${url}`, /member_of must be/);
  assert.ok(parseRosterRef("https://e.example:443/m"));
  const un = parseRequire("dns:a.example x_budget=100\nfoo:bar");
  assert.deepEqual([un.errors, un.unsupported.length], [[], 2]);
  assert.ok(parseRequire(Array.from({ length: 65 }, (_, i) => `tofu:p${i}`).join("\n")).overLimit);
  assert.ok(parseRequire(Array.from({ length: 17 }, (_, i) => `step\n  tofu:p${i}`).join("\n")).overLimit);
});

test("require: hints for the format 0.0.x syntax", () => {
  const p = parseRequire("order strict\nstep 1\ndns:example.com approver\nstep 2 any 2\ntofu:a\ntofu:b");
  const h = p.hints.join("\n");
  assert.match(h, /order mode=strict/);
  assert.match(h, /"step"/);
  assert.match(h, /role=approver/);
  assert.match(h, /step any=2/);
});

// --- matching (SPEC 5.8)

const decl = (require: string, signer = "example.com"): AgreementBlock => ({ index: 1, status: "valid", fields: { method: "dns", signer, require } });
const blk = (index: number, signer: string, extra: Record<string, string> = {}, status = "valid", code?: string): AgreementBlock => ({ index, status, ...(code ? { code } : {}), fields: { method: "dns", signer, ...extra } });

test("matching: first-fit would fail where a matching completes", () => {
  const a = evaluateAgreement([decl("dns:*.example.com\ndns:a.example.com"), blk(2, "a.example.com"), blk(3, "b.example.com")]);
  assert.equal(a.status, "complete");
  assert.deepEqual(a.satisfied.map((s) => [s.line, s.index]), [[1, 3], [2, 2]]);
});

test("matching: with two maximum matchings, the canonical Kuhn order is reported", () => {
  const a = evaluateAgreement([decl("dns:*.example.com role=x\ndns:*.example.com"), blk(2, "a.example.com", { role: "x" }), blk(3, "b.example.com", { role: "x" })]);
  assert.equal(a.status, "complete");
  assert.deepEqual(a.satisfied.map((s) => [s.line, s.index]), [[1, 3], [2, 2]]);
});

test("matching: any=m counts distinct signers, pattern lines take many, completion is the earliest position", () => {
  const a = evaluateAgreement([decl("step any=2\n  dns:*.example.com"), blk(2, "a.example.com"), blk(3, "a.example.com"), blk(4, "b.example.com"), blk(5, "c.example.com")]);
  assert.equal(a.status, "complete");
  assert.deepEqual(a.satisfied.map((s) => s.index), [2, 4]);
  const one = evaluateAgreement([decl("step any=2\n  dns:*.example.com"), blk(2, "a.example.com"), blk(3, "a.example.com")]);
  assert.equal(one.status, "pending");
  assert.deepEqual([one.missing[0]!.need, one.next[0]!.need], [1, 1]);
});

test("matching: a block used in one step is not reused; the same signer may fill a later step with another block", () => {
  const r = "step\n  dns:a.example.com\nstep\n  dns:a.example.com role=final";
  const one = evaluateAgreement([decl(r), blk(2, "a.example.com", { role: "final" })]);
  assert.equal(one.status, "pending");
  assert.deepEqual(one.missing.map((m) => [m.step, m.rejected]), [[2, [{ index: 2, reason: "blocked" }]]]);
  const two = evaluateAgreement([decl(r), blk(2, "a.example.com", { role: "final" }), blk(3, "a.example.com", { role: "final" })]);
  assert.equal(two.status, "complete");
  assert.deepEqual(two.satisfied.map((s) => [s.step, s.index]), [[1, 2], [2, 3]]);
});

test("matching: patterns respect label boundaries and exclude the declarer", () => {
  const sub = evaluateAgreement([decl("dns:*.example.com"), blk(2, "example.com"), blk(3, "badexample.com"), blk(4, "x.y.example.com")]);
  assert.deepEqual(sub.satisfied.map((s) => s.index), [4]);
  const self = evaluateAgreement([decl("dns:*.example.com", "a.example.com"), blk(2, "a.example.com")]);
  assert.deepEqual(self.missing[0]!.rejected, [{ index: 2, reason: "self" }]);
  const mail: AgreementBlock[] = [
    { index: 1, status: "valid", fields: { method: "dns", signer: "example.com", require: "directory:*@mail.example" } },
    { index: 2, status: "valid", fields: { method: "directory", signer: "x@sub.mail.example" } },
    { index: 3, status: "valid", fields: { method: "directory", signer: "y@mail.example" } },
  ];
  assert.deepEqual(evaluateAgreement(mail).satisfied.map((s) => s.index), [3]);
});

test("matching: rejected reasons and undetermined", () => {
  const oracle: MembershipOracle = (_r, id) => (id === "dns:m.example.com" ? "member" : id === "dns:u.example.com" ? "unavailable" : "not-member");
  const a = evaluateAgreement(
    [
      decl("dns:*.example.com member_of=dns:corp.example"),
      blk(2, "n.example.com"),
      blk(3, "s.example.com", { scope: "terms" }),
      blk(4, "v.example.com", {}, "invalid", "bad-signature"),
    ],
    oracle,
  );
  assert.equal(a.status, "pending");
  assert.deepEqual(a.missing[0]!.rejected, [{ index: 2, reason: "not-member" }, { index: 3, reason: "scoped" }, { index: 4, reason: "not-valid" }]);
  assert.equal(evaluateAgreement([decl("dns:*.example.com member_of=dns:corp.example"), blk(2, "u.example.com")], oracle).status, "undetermined");
  assert.equal(evaluateAgreement([decl("dns:a.example.com"), blk(2, "a.example.com", {}, "unresolved", "network")]).status, "undetermined");
  assert.equal(evaluateAgreement([decl("dns:a.example.com"), blk(2, "a.example.com", {}, "unresolved", "not-found")]).status, "pending");
  assert.equal(evaluateAgreement([decl("dns:a.example.com"), blk(2, "a.example.com", {}, "invalid", "bad-signature")]).status, "pending");
  const uv = evaluateAgreement([decl("dns:a.example.com user_verified"), { ...blk(2, "a.example.com", { alg: "webauthn-es256" }), userVerified: false }, { ...blk(3, "a.example.com", { alg: "webauthn-es256" }), userVerified: true }]);
  assert.equal(uv.status, "complete");
  assert.deepEqual(uv.satisfied.map((s) => s.index), [3]);
});

test("matching: pending blocks later steps; guide ignores early pattern-only signatures", () => {
  const p = evaluateAgreement([decl("step\n  dns:a.example.com\nstep\n  dns:b.example.com"), blk(2, "b.example.com")]);
  assert.deepEqual(p.missing.map((m) => [m.step, m.blockedBy ?? 0, m.rejected]), [[1, 0, []], [2, 1, [{ index: 2, reason: "early" }]]]);
  assert.deepEqual([p.next[0]!.step, p.next[0]!.later.map((l) => l.step)], [1, [2]]);
  const g = evaluateAgreement([decl("order mode=guide\nstep\n  dns:a.example.com\nstep\n  dns:*.example.com"), blk(2, "c.example.com"), blk(3, "a.example.com")]);
  assert.equal(g.status, "complete");
  assert.deepEqual(g.violations, []);
  const gn = evaluateAgreement([decl("order mode=guide\nstep\n  dns:a.example.com\nstep\n  dns:c.example.com"), blk(2, "c.example.com"), blk(3, "a.example.com")]);
  assert.deepEqual(gn.violations.map((v) => [v.index, v.step]), [[2, 2]]);
  const st = evaluateAgreement([decl("order mode=strict\nstep\n  dns:a.example.com\nstep\n  dns:b.example.com\nstep\n  dns:c.example.com"), blk(2, "b.example.com"), blk(3, "c.example.com"), blk(4, "a.example.com")]);
  assert.equal(st.status, "violated");
  assert.deepEqual(st.violations.map((v) => [v.index, v.step]), [[2, 2], [3, 3]]);
  const never = evaluateAgreement([decl("order mode=strict\nstep\n  dns:a.example.com\nstep\n  dns:b.example.com"), blk(2, "b.example.com")]);
  assert.deepEqual([never.status, never.violations.map((v) => v.index), never.next.length], ["violated", [2], 1]);
});

test("agreement: unsupported attributes leave the signature valid", async () => {
  const a = await signerFromSeed(SEED_A);
  await assert.rejects(signDocument(DOC, { signer: a, method: "tofu", signerId: "a", require: ["tofu:b x_budget=1"] }), /unknown attribute/);
  const fields: Record<string, string> = { v: "0.1", method: "tofu", signer: "a", pubkey: `ed25519:${toBase64(a.publicKey)}`, ts: TS, require: "tofu:b x_budget=1", alg: "ed25519" };
  fields.hash = "sha256:" + Array.from(await sha256(utf8(DOC)), (x) => x.toString(16).padStart(2, "0")).join("");
  fields.sig = "base64:" + toBase64(await a.sign(signedPayload(fields)));
  const v = await verifyDocument(DOC + "\n" + serializeBlock(fields) + "\n");
  assert.equal(v.signatures[0]!.status, "valid");
  assert.equal(v.agreement.status, "unsupported");
  assert.equal(v.ok, false);
});

// --- signed lists and rosters (SPEC 5.10, 5.8)

test("signed lists: exactly one closed fence of the right type, every line valid", () => {
  const list = (lines: string[]) => ["# L", "", "```mdsig-list", ...lines, "```", ""].join("\n");
  assert.deepEqual(parseSignedList(list(["type: members", "member: dns:a.example.com", "member: tofu:bob"]), "members"), { ok: true, entries: ["dns:a.example.com", "tofu:bob"] });
  assert.equal(parseSignedList(list(["type: members"]), "revocation").ok, false);
  assert.equal(parseSignedList(list(["type: members", "member: dns:A.example.com"]), "members").ok, false);
  assert.equal(parseSignedList(list(["type: members", "member: dns:*.example.com"]), "members").ok, false);
  assert.equal(parseSignedList(list(["type: members", ""]), "members").ok, false);
  assert.equal(parseSignedList(list(["type: revocation", "revoked: sha256:" + "A".repeat(64)]), "revocation").ok, false);
  assert.equal(parseSignedList("no list\n", "members").ok, false);
  assert.equal(parseSignedList(list(["type: members"]) + list(["type: members"]), "members").ok, false);
  assert.equal(parseSignedList("```mdsig-list\ntype: members\n", "members").ok, false);
  assert.equal(parseSignedList("~~~mdsig-list\ntype: members\n~~~\n", "members").ok, true);
  const big = parseSignedList(list(["type: revocation", ...Array.from({ length: 100_000 }, (_, i) => `revoked: sha256:${i.toString(16).padStart(64, "0")}`)]), "revocation");
  assert.equal(big.ok && big.entries.length, 100_000);
});

test("rosters: member record names, and m= must match", async () => {
  assert.equal(base32LowerNoPad(utf8("foobar")), "mzxw6ytboi");
  const name = await memberRecordName("dns:a.example.com", "corp.example");
  assert.match(name, /^[a-z2-7]{52}\._member\._mdsig\.corp\.example$/);
  await assert.rejects(memberRecordName("dns:a.example.com", "Corp.example"));
  const answer = (records: Record<string, unknown>) => (async (url: string) => {
    const n = new URL(url).searchParams.get("name")!;
    const r = records[n];
    if (r === "SERVFAIL") return Response.json({ Status: 2 });
    return Response.json(r ? { Status: 0, Answer: (r as string[]).map((d) => ({ type: 16, data: JSON.stringify(d) })) } : { Status: 3 });
  }) as typeof globalThis.fetch;
  const opts = (records: Record<string, unknown>) => ({ fetch: answer(records), dohEndpoints: ["https://doh.test/q"] });
  assert.equal(await lookupDnsMember("dns:a.example.com", "corp.example", opts({ [name]: ["v=mdsig1; m=dns:a.example.com"] })), "member");
  assert.equal(await lookupDnsMember("dns:a.example.com", "corp.example", opts({ [name]: ["v=mdsig1; m=dns:other.example"] })), "not-member");
  assert.equal(await lookupDnsMember("dns:a.example.com", "corp.example", opts({ [name]: [] })), "not-member");
  assert.equal(await lookupDnsMember("dns:a.example.com", "corp.example", opts({})), "not-member");
  assert.equal(await lookupDnsMember("dns:a.example.com", "corp.example", opts({ [name]: "SERVFAIL" })), "unavailable");
  assert.equal(await lookupDnsMember("dns:a.example.com", "corp.example", { ...opts({}), offline: true }), "unavailable");
});

test("rosters: https roster through verifyDocument, trusted only from dns:<host>", async () => {
  const a = await signerFromSeed(SEED_A);
  const b = await signerFromSeed(new Uint8Array(32).fill(9));
  const resolvers = { dns: fixedKeys({ "example.com": a.publicKey, "x.example.com": b.publicKey }) };
  const roster = (await signDocument(["# Members", "", "```mdsig-list", "type: members", "member: dns:x.example.com", "```", ""].join("\n"), { signer: a, method: "dns", signerId: "example.com", ts: TS })).text;
  let calls = 0;
  const fetch = (async (url: string) => {
    calls++;
    assert.equal(url, "https://example.com/m.md");
    return new Response(roster);
  }) as typeof globalThis.fetch;
  const d = await signDocument(DOC, { signer: a, method: "dns", signerId: "example.com", ts: TS, require: ["dns:*.example.com member_of=https://example.com/m.md", "dns:*.example.com member_of=https://example.com/m.md role=x"] });
  const s = await signDocument(d.text, { signer: b, method: "dns", signerId: "x.example.com", ts: TS });
  const v = await verifyDocument(s.text, { resolvers, fetch });
  assert.equal(v.agreement.status, "pending");
  assert.equal(calls, 1, "one fetch per URL per call");
  assert.deepEqual(v.agreement.satisfied.map((x) => x.index), [2]);
  const off = await verifyDocument(s.text, { resolvers, fetch, offline: true });
  assert.equal(off.agreement.status, "undetermined");
  assert.match(off.agreement.declarations[0]!.detail!, /roster/);
});

// --- signature table (SPEC 9.5)

test("signature table: marker rules, rows, and escaped HTML", async () => {
  assert.deepEqual(findSignatureMarker("a\n<!-- mdsig:signatures -->\n").line, 2);
  const m = findSignatureMarker("```\n<!-- mdsig:signatures -->\n```\n<!-- mdsig:signatures -->\n<!-- mdsig:signatures -->\n");
  assert.equal(m.line, 4);
  assert.equal(m.warnings.length, 2);
  const a = await signerFromSeed(SEED_A);
  const s = await signDocument("# PO\n\n<!-- mdsig:signatures -->\n", { signer: a, method: "tofu", signerId: "seller", displayName: "<b>Seller</b> & Co", role: "seller", ts: TS, require: ["tofu:buyer role=buyer"] });
  const v = await verifyDocument(s.text);
  const rows = signatureTable(v);
  assert.deepEqual(rows.map((r) => [r.number, r.signer, r.status, r.role]), [[1, "seller", "valid", "seller"], [null, "buyer", "unsigned", "buyer"]]);
  const html = renderSignatureTableHtml(rows, "ja");
  assert.ok(html.includes("&lt;b&gt;Seller&lt;/b&gt; &amp; Co"));
  assert.ok(!html.includes("<b>"));
  assert.match(html, /未署名/);
  assert.match(renderSignatureTableHtml(rows, "en"), /Unsigned/);
});

// --- explainRequire

test("explainRequire: steps, patterns, and attributes in plain language", () => {
  const ja = explainRequire("step\n  dns:example.com role=approver\nstep any=2\n  dns:*.example.com member_of=dns:corp.example\n  tofu:bob", "ja");
  assert.equal(ja.ok, true);
  assert.match(ja.text, /段階 1：次のすべて\n  dns:example\.com（役割 approver）/);
  assert.match(ja.text, /段階 2：次のうち異なる2者/);
  assert.match(ja.text, /example\.com のサブドメインのいずれか/);
  assert.match(ja.text, /corp\.example の DNS 名簿に掲載/);
  assert.match(ja.warnings.join(), /この名前を名乗る誰でも満たせる/);
  const sample = explainRequire("step\n  dns:example.com role=approver\nstep any=2\n  dns:*.example.com member_of=dns:example.com", "en");
  assert.equal(sample.text, "order: pending (signatures before their turn are not counted)\nstep 1: all of\n  dns:example.com with role approver\nstep 2: any 2 different signers of\n  any subdomain of example.com (not example.com itself), on the DNS roster of example.com, not the declaring signer");
  assert.match(explainRequire("step\ndns:a.example\n  step\n  dns:b.example").warnings.join(), /indentation/);
  const en = explainRequire("order mode=strict\ndns:a.example user_verified", "en");
  assert.match(en.text, /order: strict/);
  assert.match(en.text, /user verification/);
  const bad = explainRequire("dns:example.com approver", "en");
  assert.equal(bad.ok, false);
  assert.match(bad.hints.join(), /role=approver/);
});

// --- passkeys and user_verified (SPEC 5.8, 6.1, CLI_SPEC 8)

test("passkeys: a user_verified requirement asks for UV and refuses an assertion without it", async () => {
  const uv = await createSoftwareAuthenticator("mdsig.dev", "https://mdsig.dev", 0x05 | 0x08 | 0x10);
  const up = await createSoftwareAuthenticator("mdsig.dev", "https://mdsig.dev", 0x01);
  const a = await signerFromSeed(SEED_A);
  const d = (pk: Uint8Array) => signDocument(DOC, { signer: a, method: "tofu", signerId: "a", ts: TS, require: [`tofu:carol pubkey=es256:${toBase64(pk)} user_verified`] });
  let asked: string | undefined;
  const spy = { ...uv, getAssertion: (c: Uint8Array, o?: { userVerification?: "required" | "preferred" }) => ((asked = o?.userVerification), uv.getAssertion(c)) };
  const ok = await signDocument((await d(uv.publicKey)).text, { signer: spy, method: "tofu", signerId: "carol", ts: TS });
  assert.equal(asked, "required");
  const v = await verifyDocument(ok.text);
  assert.equal(v.agreement.status, "complete");
  assert.deepEqual([v.signatures[1]!.webauthn!.userVerified, v.signatures[1]!.webauthn!.backupEligible, v.signatures[1]!.webauthn!.backedUp], [true, true, true]);
  await assert.rejects(signDocument((await d(up.publicKey)).text, { signer: up, method: "tofu", signerId: "carol", ts: TS }), /user verification was required/);

  const prepared = await prepareSignature((await d(up.publicKey)).text, { signer: { alg: "webauthn-es256", publicKey: up.publicKey, rpId: "mdsig.dev" }, method: "tofu", signerId: "carol", ts: TS });
  assert.equal(prepared.userVerification, "required");
  await assert.rejects(prepared.finish(await up.getAssertion(prepared.challenge)), /UV flag/);
  const req = createHandoffRequest("https://mdsig.dev/sign/", { op: "sign", returnUrl: "mdsig-app:cb", payload: prepared.payload, userVerification: "required" });
  assert.match(req.url, /user_verification=required/);
  const page = checkHandoffRequest(req.url, "mdsig.dev");
  assert.ok(page.ok && page.op === "sign" && page.userVerification === "required");
});

test("webauthn: crossOrigin true is refused", async () => {
  const x = await createSoftwareAuthenticator("mdsig.dev");
  x.overrideClientData = (cd) => ({ ...cd, crossOrigin: true });
  const s = await signDocument(DOC, { signer: x, method: "tofu", signerId: "x", ts: TS });
  const v = await verifyDocument(s.text);
  assert.equal(v.signatures[0]!.code, "bad-signature");
  assert.match(v.signatures[0]!.message!, /crossOrigin/);
});

test("parseDocument reports an unclosed fence before the chain", async () => {
  assert.equal(parseDocument("a\n```\nb\n\n<!-- md-signature\n-->\n").unclosedFence, true);
});
