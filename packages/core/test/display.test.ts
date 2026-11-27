import { test } from "node:test";
import assert from "node:assert/strict";
import { HIDDEN_CHARACTER_RE, documentLayout, describeRequirement, findHiddenCharacters, parseDocument, parseRequire } from "../src/index.ts";
import { readExample } from "./harness.ts";

// --- findHiddenCharacters

const contexts = (s: string) => findHiddenCharacters(s).map((h) => [h.codePoint, h.context]);

test("hidden characters outside an emoji or a joining script are reported", () => {
  assert.deepEqual(contexts("a\u{E0041}\u{E0042}b"), [["U+E0041", null], ["U+E0042", null]]);
  assert.deepEqual(contexts("pay‍pal"), [["U+200D", null]]);
  assert.deepEqual(contexts("a ‌ b"), [["U+200C", null]]);
  assert.deepEqual(contexts("م‍‍م"), [["U+200D", null], ["U+200D", null]]);
  assert.deepEqual(contexts("‍start"), [["U+200D", null]]);
  assert.deepEqual(contexts("soft­hyphen ‮bidi ﻿bom ㅤfiller"), [["U+00AD", null], ["U+202E", null], ["U+FEFF", null], ["U+3164", null]]);
  assert.deepEqual(contexts("️ at the start"), [["U+FE0F", null]]);
  assert.deepEqual(contexts("\u{E0001}"), [["U+E0001", null]]);
  assert.deepEqual(contexts("﷐\u{10FFFF}"), [["U+FDD0", null], ["U+10FFFF", null]]);
});

test("hidden characters that are part of something visible carry their context", () => {
  assert.deepEqual(contexts("👨‍👩‍👧"), [["U+200D", "emoji-sequence"], ["U+200D", "emoji-sequence"]]);
  assert.deepEqual(contexts("👍🏽‍❤️"), [["U+200D", "emoji-sequence"], ["U+FE0F", "variation"]]);
  const england = "🏴\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}";
  assert.ok(findHiddenCharacters(england).every((h) => h.context === "emoji-tag"));
  assert.ok(findHiddenCharacters("🏴\u{E0067}\u{E0062}x").every((h) => h.context === null));
  assert.deepEqual(contexts("می‌خواهم"), [["U+200C", "joiner"]]);
  assert.deepEqual(contexts("क्‍ष"), [["U+200D", "joiner"]]);
  assert.deepEqual(contexts("م‌क"), [["U+200C", null]]);
});

test("tab, line feed, and carriage return are not hidden characters", () => {
  assert.deepEqual(findHiddenCharacters("a\tb\r\nc\n"), []);
  assert.ok(!new RegExp(HIDDEN_CHARACTER_RE.source, "u").test("\t"));
});

test("positions are lines and UTF-16 columns", () => {
  const [h] = findHiddenCharacters("first\n😀x​y");
  assert.deepEqual({ index: h!.index, line: h!.line, column: h!.column }, { index: 9, line: 2, column: 4 });
});

// --- documentLayout

test("documentLayout gives block spans and coverage", () => {
  const l = documentLayout(readExample("valid-cosigned.md"));
  assert.deepEqual([l.blocks[0]!.from, l.blocks[0]!.to, l.blocks[1]!.from], [15, 28, 29]);
  assert.ok(l.coverage[0]!.ranges[0]!.to < 15);
  assert.deepEqual(l.coverage[1]!.ranges, [{ from: 1, to: 28 }]);
  assert.equal(l.blocks.length, parseDocument(readExample("valid-cosigned.md")).chain.length);
});

test("documentLayout reports sections and unsigned text", () => {
  assert.deepEqual(documentLayout(readExample("valid-scoped-edited.md")).coverage[0], { index: 1, ranges: [{ from: 3, to: 6 }, { from: 11, to: 15 }], sections: ["terms", "fees"] });
  const t = documentLayout(readExample("unsigned-trailer.md"));
  assert.equal(t.blocks.length, 0);
  assert.deepEqual(t.tail, { from: 30, to: 30 });
});

// --- describeRequirement

test("describeRequirement describes one line in either language", () => {
  const [r] = parseRequire("dns:*.example.com role=witness member_of=dns:example.com", 0).requirements;
  assert.equal(describeRequirement(r!), "any subdomain of example.com (not example.com itself) with role witness, on the DNS roster of example.com, not the declaring signer");
  assert.match(describeRequirement(r!, "ja"), /^example\.com のサブドメインのいずれか/);
  assert.equal(describeRequirement({ method: "dns", signer: "example.com", pattern: false, attributes: {} }), "dns:example.com");
});
