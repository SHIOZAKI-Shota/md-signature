// Regenerates the TS fixtures in this directory: node mdsig/testdata/gen-ts-fixtures.mjs
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { signDocument, signerFromSeed, fromHex, utf8, signedPayload } from "../../packages/core/src/index.ts";

const out = fileURLToPath(new URL("./", import.meta.url));
const bob = await signerFromSeed(fromHex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"));
const NL = String.fromCharCode(10);
const doc = [
  "# Statement of Work",
  "",
  "<!-- mdsig:section terms -->",
  "## Terms",
  "Payment within 30 days.",
  "<!-- /mdsig:section -->",
  "",
  "Notes (editable).",
  "",
  "![Diagram](./img/diagram.png)",
  "",
  "<!-- mdsig:section fees -->",
  "| Fee | 100 |",
  "<!-- /mdsig:section -->",
  "",
].join(NL);
writeFileSync(out + "features-input.md", doc);
const s = await signDocument(doc, {
  signer: bob, method: "tofu", signerId: "bob@laptop", displayName: "Bob Example", role: "author", reason: "Scoped draft", ts: "2026-11-16T09:00:00Z",
  scope: ["terms", "fees"], expires: "2027-11-16T00:00:00Z",
  require: ["order mode=guide", "step", "  dns:example.com role=approver", "  git-hosting:github.com/alice", "step any=1", "  tofu:carol@passkey role=witness", "  dns:*.example.com member_of=dns:example.com"],
  resources: [{ ref: "./img/diagram.png", bytes: utf8("PNG-BYTES" + NL) }, { ref: "https://example.com/chart.png", bytes: utf8("REMOTE") }],
  revocationUrl: "https://example.com/.well-known/mdsig-revoked.md",
  extra: { x_ref: "PO-123", x_dept: "legal" },
});
writeFileSync(out + "features-ts.md", s.text);
const p = signedPayload({ v: "0.1", require: "dns:a.com role=approver" + NL + "git-hosting:github.com/b" + NL + "v=9", x_note: "n", sig: "base64:AA", webauthn_client_data: "AA" });
writeFileSync(out + "require-payload-ts.txt", p);
console.log("wrote", out);
