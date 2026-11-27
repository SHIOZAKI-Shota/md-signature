import { writeFileSync, mkdirSync, readFileSync, existsSync, rmSync } from "node:fs";
import { readPgpSecretKey, unlockPgpSecretKey, armor, hkpUrl, wkdUrls, type PgpSigner } from "../src/index.ts";
import { HASH } from "../src/pgp-sig.ts";
import { ed25519Key, p256Key, buildCert, signerOf, gpgSigner } from "./pgp-build.ts";
import {
  signDocument, signerFromSeed, timestampDocument, fromHex, fromBase64, toBase64, formatSshPublicKey, sshFingerprint, sha256, utf8, createSoftwareAuthenticator,
  directoryKeyUrl, parseDocument, revocationId, serializeBlock, signedPayload, unfoldBinary, normalizedBytes, toHex, memberRecordName, memberRecordValue,
  verifyDocument, toJsonResult, signatureTable, signatureTableToJson, findSignatureMarker, type Signer,
} from "../src/index.ts";

const out = new URL("../../../examples/", import.meta.url);
mkdirSync(out, { recursive: true });
const written: string[] = [];
const w = (name: string, text: string | Uint8Array) => {
  writeFileSync(new URL(name, out), text);
  written.push(name);
};
for (const old of ["legacy-v001.md", "mixed-versions.md", "malformed-require-step-v001.md"]) rmSync(new URL(old, out), { force: true });

// RFC 8032 7.1 test seeds: public, never use for real signatures
const ALICE = fromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
const EXAMPLE_COM = fromHex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
const BOB = fromHex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");

const args = process.argv.slice(2);
const tsaUrl = args.includes("--no-tsa") ? undefined : (args[args.indexOf("--tsa") + 1] ?? "http://ts.ssl.com");

const alice = await signerFromSeed(ALICE);
const ex = await signerFromSeed(EXAMPLE_COM);
const bob = await signerFromSeed(BOB);
const NL = "\n";
const labelSeed = async (label: string) => sha256(utf8(`md-signature public test key: ${label}`));

// SPEC 5.10: a signed list is one ```mdsig-list fence in the body
const signedList = (title: string, type: "revocation" | "members", entries: string[]) =>
  [title, "", "```mdsig-list", `type: ${type}`, ...entries, "```", ""].join(NL);

const body = `# Service Agreement

This agreement is made between **Example Corp** ("Provider") and **Alice** ("Client").

1. The Provider will deliver the service described in Appendix A.
2. The Client will pay the fees listed in Appendix B within 30 days.

| Item | Fee |
| --- | --- |
| Setup | 1,000 USD |
| Monthly | 200 USD |

日本語の本文も UTF-8 でそのまま署名されます。
`;

// dns test signers: selector 2026 each; keys.json lists them under "dns"
const dnsKeys: Record<string, { seed: Uint8Array; signer: Signer; extra?: string }> = {};
async function dnsSigner(domain: string, seed?: Uint8Array, extra?: string) {
  const s = seed ?? (await labelSeed(`dns ${domain}`));
  dnsKeys[domain] = { seed: s, signer: await signerFromSeed(s), ...(extra ? { extra } : {}) };
  return dnsKeys[domain]!.signer;
}
await dnsSigner("example.com", EXAMPLE_COM);
await dnsSigner("tagged.example", EXAMPLE_COM, "x=future; ");
const aSub = await dnsSigner("a.example.com");
const bSub = await dnsSigner("b.example.com");
const badEx = await dnsSigner("badexample.com");
const agent = await dnsSigner("agent.example");
const idn = await dnsSigner("xn--fsqu00a.example");
const TS0 = "2026-11-16T09:00:00Z";
const dnsSign = (text: string, signer: Signer, domain: string, extra: Partial<Parameters<typeof signDocument>[1]> = {}) =>
  signDocument(text, { signer, method: "dns", signerId: domain, selector: "2026", ts: TS0, ...extra });

const single = await signDocument(body, { signer: bob, method: "tofu", signerId: "bob@laptop", role: "author", reason: "Initial draft", ts: TS0 });
w("valid-single.md", single.text);

const c1 = await signDocument(body, { signer: alice, method: "git-hosting", signerId: "github.com/alice", role: "author", reason: "Initial draft", ts: TS0 });
// SPEC 4.6: --tsa appends a tsa block after the signature block
const c2 = await signDocument(c1.text, { signer: ex, method: "dns", signerId: "example.com", selector: "2026", role: "approver", reason: "Final approval", ts: "2026-11-16T09:46:00Z", tsaUrl });
w("valid-cosigned.md", c2.text);

const crlf = await signDocument(body.replace(/\n/g, "\r\n"), { signer: bob, method: "tofu", signerId: "bob@laptop", role: "author", ts: TS0 });
w("valid-crlf.md", crlf.text);
w("tampered.md", single.text.replace("1,000 USD", "100 USD"));
w("tampered-metadata.md", single.text.replace("role: author", "role: approver"));
w("unsigned-trailer.md", single.text + NL + "P.S. The Client also agrees to pay 5,000 USD." + NL);

// --- grammar and identifiers (SPEC 3.2, 3.4)
w("valid-double-hyphen.md", (await signDocument(body, { signer: bob, method: "tofu", signerId: "bob@laptop", reason: "Fees -- see Appendix B", ts: TS0 })).text);
w("malformed-value-comment-close.md", single.text.replace("reason: Initial draft", "reason: Initial draft --> visible"));
w("malformed-signer-uppercase.md", (await dnsSign(body, ex, "example.com")).text.replace("signer: example.com", "signer: Example.com"));
w("malformed-signer-star.md", single.text.replace("signer: bob@laptop", "signer: bob*@laptop"));
w("valid-xn-signer.md", (await dnsSign(body, idn, "xn--fsqu00a.example", { role: "approver" })).text);
w("valid-display-name.md", (await signDocument(body, { signer: bob, method: "tofu", signerId: "bob@laptop", displayName: "Bob Example (営業部)", role: "author", ts: TS0 })).text);
// SPEC 3.3: verifiers check only the length (64 code points), before the signature
w("malformed-display-name.md", single.text.replace("role: author", `display_name: ${"名".repeat(65)}\nrole: author`));
w("malformed-zero-width.md", single.text.replace("reason: Initial draft", "reason: Initial\u200bdraft"));
w("malformed-trailing-space-folded.md", (await signDocument(body, { signer: bob, method: "tofu", signerId: "bob@laptop", ts: TS0, require: ["step", "tofu:carol@laptop", "step", "tofu:dave@laptop"] })).text.replace("  tofu:carol@laptop\n", "  tofu:carol@laptop \n"));

// SPEC 3.6: generators refuse a body that ends inside a fence, so this vector is assembled by hand
{
  const fenced = body + NL + "```text" + NL + "an example that is never closed" + NL;
  const fields: Record<string, string> = { v: "0.1", method: "tofu", signer: "bob@laptop", pubkey: `ed25519:${toBase64(bob.publicKey)}`, ts: TS0, alg: "ed25519", hash: `sha256:${toHex(await sha256(normalizedBytes(fenced)))}` };
  fields.sig = "base64:" + toBase64(await bob.sign(signedPayload(fields)));
  w("unclosed-fence.md", fenced.replace(/\n+$/, "") + NL + NL + serializeBlock(fields) + NL);
}

// --- Extension vectors
const NOW = "2026-12-01T00:00:00Z";
mkdirSync(new URL("assets/", out), { recursive: true });
mkdirSync(new URL("revocation/", out), { recursive: true });
mkdirSync(new URL("lists/", out), { recursive: true });

const diagram = utf8(["<svg xmlns='http://www.w3.org/2000/svg'><text>diagram v1</text></svg>", ""].join(NL));
const csvSigned = utf8(["milestone,amount", "design,4000", "launch,6000", ""].join(NL));
const csvOnDisk = utf8(["milestone,amount", "design,4000", "launch,60000", ""].join(NL)); // swapped after signing
const notes = utf8("notes with a space in the file name\n");
w("assets/diagram.svg", diagram);
w("assets/chart.csv", csvOnDisk);
w("assets/meeting notes.txt", notes);

const resBody = [body, "![Diagram](./assets/diagram.svg)", "", "![Remote chart](https://example.com/chart.png)", ""].join(NL);
const res = await signDocument(resBody, {
  signer: bob, method: "tofu", signerId: "bob@laptop", role: "author", ts: TS0,
  resources: [{ ref: "./assets/diagram.svg", bytes: diagram }, { ref: "https://example.com/chart.png", bytes: utf8("not fetched by default") }],
});
w("valid-resources.md", res.text);
// SPEC 3.5: the target is the first item and may contain "=", so a URL with a query string is a valid reference
const QUERY_URL = "https://example.com/report?id=118&format=csv";
w("valid-resource-query.md", (await signDocument([body, `[Report](${QUERY_URL})`, ""].join(NL), {
  signer: bob, method: "tofu", signerId: "bob@laptop", ts: TS0, resources: [{ ref: QUERY_URL, bytes: utf8("id,amount\n118,1200\n") }],
})).text);
const resT = await signDocument([body, "See [the data](./assets/chart.csv).", ""].join(NL), {
  signer: bob, method: "tofu", signerId: "bob@laptop", ts: TS0, resources: [{ ref: "./assets/chart.csv", bytes: csvSigned }],
});
w("tampered-resource.md", resT.text);
const resM = await signDocument(body, { signer: bob, method: "tofu", signerId: "bob@laptop", ts: TS0, resources: [{ ref: "./assets/missing.png", bytes: utf8("gone") }] });
w("missing-resource.md", resM.text);
// SPEC 5.7: percent-decoding; %20 is a space, an encoded "/" after ".." is refused
const resP = await signDocument(body, { signer: bob, method: "tofu", signerId: "bob@laptop", ts: TS0, resources: [{ ref: "assets/meeting%20notes.txt", bytes: notes }] });
w("valid-resource-percent.md", resP.text);
w("malformed-resource-percent.md", resP.text.replace("assets/meeting%20notes.txt hash=", "assets/..%2F..%2Fsecret.txt hash="));

const scopedBody = [
  "# Statement of Work",
  "",
  "<!-- mdsig:section terms -->",
  "## Terms",
  "Payment within 30 days of each milestone.",
  "<!-- /mdsig:section -->",
  "",
  "## Progress notes (editable)",
  "Kick-off scheduled.",
  "",
  "<!-- mdsig:section fees -->",
  "| Milestone | Amount |",
  "| --- | --- |",
  "| Launch | 6,000 USD |",
  "<!-- /mdsig:section -->",
  "",
].join(NL);
const scoped = await signDocument(scopedBody, { signer: bob, method: "tofu", signerId: "bob@laptop", role: "author", ts: TS0, scope: ["terms", "fees"] });
w("valid-scoped-edited.md", scoped.text.replace("Kick-off scheduled.", "Kick-off done. Design review on 2026-11-20."));
w("tampered-scoped.md", scoped.text.replace("6,000 USD", "60,000 USD"));
w("malformed-unclosed-section.md", scoped.text.replace("| Launch | 6,000 USD |" + NL + "<!-- /mdsig:section -->", "| Launch | 6,000 USD |"));

// --- require (SPEC 5.8)
const declare = (lines: string[], text = body) => signDocument(text, { signer: alice, method: "git-hosting", signerId: "github.com/alice", role: "author", ts: TS0, require: lines });
const req = await declare(["dns:example.com role=approver"]);
w("pending-require.md", req.text);
const reqDone = await dnsSign(req.text, ex, "example.com", { role: "approver", ts: "2026-11-16T09:46:00Z" });
w("complete-require.md", reqDone.text);
// SPEC 5.8: a scoped block copied from another document does not satisfy the requirement
const scopedEx = await dnsSign(scopedBody, ex, "example.com", { role: "approver", ts: "2026-11-16T09:46:00Z", scope: ["terms"] });
const reqScoped = await declare(["dns:example.com role=approver"], ["# Purchase order", "", "example.com pays 1,000,000 USD.", "", scopedBody].join(NL));
w("pending-require-scoped.md", reqScoped.text + parseDocument(scopedEx.text).chain[0]!.raw + NL);

const SERIAL = ["step", "  dns:example.com role=approver", "step", "  tofu:bob@laptop role=reviewer"];
const approve = (text: string, ts: string) => dnsSign(text, ex, "example.com", { role: "approver", ts });
const review = (text: string, ts: string) => signDocument(text, { signer: bob, method: "tofu", signerId: "bob@laptop", role: "reviewer", ts });
const inOrder = await declare(SERIAL);
w("require-serial-complete.md", (await review((await approve(inOrder.text, "2026-11-16T09:30:00Z")).text, "2026-11-16T09:40:00Z")).text);
w("require-serial-pending.md", (await approve((await review(inOrder.text, "2026-11-16T09:20:00Z")).text, "2026-11-16T09:30:00Z")).text);
for (const [order, name] of [["guide", "require-serial-guide.md"], ["strict", "require-serial-strict.md"]] as const) {
  const d = await declare([`order mode=${order}`, ...SERIAL]);
  w(name, (await approve((await review(d.text, "2026-11-16T09:20:00Z")).text, "2026-11-16T09:30:00Z")).text);
}
// tofu signers with their own names: a tofu key proves integrity only, so any test key will do
const ANY = ["step any=2", "  tofu:bob@laptop", "  tofu:carol@laptop", "  tofu:dave@laptop"];
const anyDecl = await declare(ANY);
const anyOne = await signDocument(anyDecl.text, { signer: bob, method: "tofu", signerId: "bob@laptop", ts: "2026-11-16T09:20:00Z" });
w("require-any-pending.md", anyOne.text);
w("require-any-complete.md", (await signDocument(anyOne.text, { signer: ex, method: "tofu", signerId: "dave@laptop", ts: "2026-11-16T09:30:00Z" })).text);
// SPEC 5.8: checked before the signature, so the edit gives malformed rather than bad-signature
w("malformed-require-steps.md", anyDecl.text.replace("step any=2", "step any=4"));
w("malformed-require-strict-pattern.md", (await declare(["order mode=strict", "dns:example.com role=approver"])).text.replace("dns:example.com role=approver", "dns:*.example.com role=approver"));
// SPEC 5.8: an attribute this version does not define leaves the block valid and the agreement unsupported; generators refuse it, so assembled by hand
{
  const fields: Record<string, string> = { v: "0.1", method: "tofu", signer: "bob@laptop", pubkey: `ed25519:${toBase64(bob.publicKey)}`, role: "author", ts: TS0, require: "dns:example.com role=approver x_budget=100", alg: "ed25519", hash: `sha256:${toHex(await sha256(normalizedBytes(body)))}` };
  fields.sig = "base64:" + toBase64(await bob.sign(signedPayload(fields)));
  w("unsupported-require-attribute.md", body + NL + serializeBlock(fields) + NL);
}

// SPEC 5.8.3: label boundaries and self-exclusion
const exDecl = (lines: string[]) => dnsSign(body, ex, "example.com", { role: "author", require: lines });
const sub = await exDecl(["dns:*.example.com role=approver"]);
w("require-pattern-subdomain.md", (await dnsSign(sub.text, aSub, "a.example.com", { role: "approver", ts: "2026-11-16T09:30:00Z" })).text);
w("require-pattern-boundary.md", (await dnsSign(sub.text, badEx, "badexample.com", { role: "approver", ts: "2026-11-16T09:30:00Z" })).text);
{
  const d = await dnsSign(body, aSub, "a.example.com", { role: "author", require: ["dns:*.example.com"] });
  w("require-pattern-self.md", (await dnsSign(d.text, aSub, "a.example.com", { ts: "2026-11-16T09:30:00Z" })).text);
}
// SPEC 5.8: a first-fit choice puts a.example.com on the pattern line and leaves line 2 empty; the matching completes
{
  const d = await exDecl(["dns:*.example.com", "dns:a.example.com"]);
  const s1 = await dnsSign(d.text, aSub, "a.example.com", { ts: "2026-11-16T09:20:00Z" });
  w("require-greedy-vs-matching.md", (await dnsSign(s1.text, bSub, "b.example.com", { ts: "2026-11-16T09:30:00Z" })).text);
}
// two maximum matchings; the canonical Kuhn order decides which is reported
{
  const d = await exDecl(["dns:*.example.com", "dns:*.example.com"]);
  const s1 = await dnsSign(d.text, aSub, "a.example.com", { ts: "2026-11-16T09:20:00Z" });
  w("require-canonical-assignment.md", (await dnsSign(s1.text, bSub, "b.example.com", { ts: "2026-11-16T09:30:00Z" })).text);
}

// SPEC 5.8.7: user_verified and pubkey=
const passkeyUv = await createSoftwareAuthenticator("mdsig.dev", "https://mdsig.dev", 0x05);
const passkeyUp = await createSoftwareAuthenticator("mdsig.dev", "https://mdsig.dev", 0x01);
for (const [pk, name] of [[passkeyUv, "require-user-verified-complete.md"], [passkeyUp, "require-user-verified-pending.md"]] as const) {
  const d = await declare([`tofu:carol@passkey pubkey=es256:${toBase64(pk.publicKey)} user_verified role=approver`]);
  // the UP-only authenticator cannot satisfy user_verified, so the automatic "required" is turned off to produce the vector
  w(name, (await signDocument(d.text, { signer: pk, method: "tofu", signerId: "carol@passkey", role: "approver", ts: "2026-11-16T09:30:00Z", ...(pk === passkeyUp ? { userVerification: "preferred" as const } : {}) })).text);
}
{
  const d = await declare([`tofu:bob@laptop pubkey=ed25519:${toBase64(ex.publicKey)}`]);
  w("require-tofu-key-mismatch.md", (await signDocument(d.text, { signer: bob, method: "tofu", signerId: "bob@laptop", ts: "2026-11-16T09:30:00Z" })).text);
}

// --- rosters (SPEC 5.8 member_of, 5.10)
const listFetch: Record<string, string> = {};
const ROSTER = "https://example.com/members.md";
const rosterDoc = async (file: string, text: string, extra: Partial<Parameters<typeof signDocument>[1]> = {}) => {
  w(`lists/${file}`, (await dnsSign(text, ex, "example.com", { ts: "2026-11-01T00:00:00Z", ...extra })).text);
};
await rosterDoc("members.md", signedList("# example.com members", "members", ["dns:a.example.com", "directory:alice@mail.example"].map((m) => `member: ${m}`)));
listFetch[ROSTER] = "lists/members.md";
await rosterDoc("wrong-type.md", signedList("# example.com members", "revocation", []));
listFetch["https://example.com/wrong-type.md"] = "lists/wrong-type.md";
await rosterDoc("bad-line.md", signedList("# example.com members", "members", ["member: dns:a.example.com", "member: dns:B.example.com"]));
listFetch["https://example.com/bad-line.md"] = "lists/bad-line.md";
await rosterDoc("two-fences.md", signedList("# example.com members", "members", ["member: dns:a.example.com"]) + NL + signedList("## more", "members", ["member: dns:b.example.com"]));
listFetch["https://example.com/two-fences.md"] = "lists/two-fences.md";
{
  const t = ["# example.com members", "", "<!-- mdsig:section list -->", ...signedList("", "members", ["member: dns:a.example.com"]).split(NL).slice(2, -1), "<!-- /mdsig:section -->", ""].join(NL);
  await rosterDoc("scoped-issuer.md", t, { scope: ["list"] });
  listFetch["https://example.com/scoped-issuer.md"] = "lists/scoped-issuer.md";
}
// signed by b.example.com, not by the URL's host
w("lists/other-issuer.md", (await dnsSign(signedList("# members", "members", ["member: dns:a.example.com"]), bSub, "b.example.com", { ts: "2026-11-01T00:00:00Z" })).text);
listFetch["https://example.com/other-issuer.md"] = "lists/other-issuer.md";

const memberDecl = (roster: string) => exDecl([`dns:*.example.com member_of=${roster}`]);
const memberSign = async (roster: string, signer: Signer, domain: string) => (await dnsSign((await memberDecl(roster)).text, signer, domain, { ts: "2026-11-16T09:30:00Z" })).text;
w("require-member-https.md", await memberSign(ROSTER, aSub, "a.example.com"));
w("require-member-https-not-member.md", await memberSign(ROSTER, bSub, "b.example.com"));
w("require-member-unreachable.md", await memberSign("https://roster.example.net/members.md", aSub, "a.example.com"));
for (const f of ["wrong-type", "bad-line", "two-fences", "scoped-issuer", "other-issuer"]) w(`roster-${f}.md`, await memberSign(`https://example.com/${f}.md`, aSub, "a.example.com"));

const dnsRecords: Record<string, string[] | "SERVFAIL"> = {};
dnsRecords[await memberRecordName("dns:a.example.com", "corp.example")] = [memberRecordValue("dns:a.example.com")];
// a wildcard record answers every name; m= names someone else, so it never makes a member
dnsRecords[await memberRecordName("dns:b.example.com", "corp.example")] = [memberRecordValue("dns:someone.example")];
dnsRecords[await memberRecordName("dns:a.example.com", "broken.example")] = "SERVFAIL";
w("require-member-dns.md", await memberSign("dns:corp.example", aSub, "a.example.com"));
w("require-member-dns-wildcard.md", await memberSign("dns:corp.example", bSub, "b.example.com"));
w("require-member-dns-servfail.md", await memberSign("dns:broken.example", aSub, "a.example.com"));

// --- signature table (SPEC 9.5) and agent commerce (AGENT_COMMERCE)
{
  const t = ["# Purchase order 2026-118", "", "<!-- mdsig:signatures -->", "", "Quantity: 40 units. Price: 1,200 USD.", "", "```markdown", "<!-- mdsig:signatures -->", "```", "", "<!-- mdsig:signatures -->", ""].join(NL);
  const s1 = await dnsSign(t, ex, "example.com", { displayName: "Example Corp", role: "seller", require: ["step", "  dns:a.example.com role=buyer", "step any=2", "  dns:*.example.com role=witness", "  tofu:bob@laptop role=witness"] });
  const s2 = await dnsSign(s1.text, aSub, "a.example.com", { displayName: "A Division", role: "buyer", ts: "2026-11-16T09:30:00Z" });
  w("table-marker.md", s2.text);
}
const AGENT_TERMS = [
  "# Data access terms (offer 7f3c)",
  "",
  "Provider: example.com. Counterparty: the agent that accepts below.",
  "",
  "- Price: 0.002 USD per request, settled by x402.",
  "- Rate limit: 10 requests per second.",
  "- The provider confirms each acceptance before access starts.",
  "",
  "<!-- mdsig:signatures -->",
  "",
].join(NL);
const terms = await dnsSign(AGENT_TERMS, ex, "example.com", { displayName: "Example Data", role: "offer", require: ["step", "  dns:* role=accept", "step", "  dns:example.com role=confirm"] });
w("agent-terms.md", terms.text);
const accepted = await dnsSign(terms.text, agent, "agent.example", { displayName: "Buyer Agent", role: "accept", ts: "2026-11-16T09:10:00Z" });
w("agent-accepted.md", accepted.text);
w("agent-approved.md", (await dnsSign(accepted.text, ex, "example.com", { role: "confirm", ts: "2026-11-16T09:12:00Z" })).text);

// --- key snapshots (SPEC 4.5) and tsa blocks (SPEC 4.6)
w("valid-key-snapshot.md", (await dnsSign(body, ex, "example.com", { role: "approver", embedKey: true })).text);
// github.com/alice publishes only alice's key, so a snapshot of another key is not vouched for
w("key-not-published.md", (await signDocument(body, { signer: ex, method: "git-hosting", signerId: "github.com/alice", role: "author", ts: TS0, embedKey: true })).text);
if (tsaUrl) {
  const stamped = await timestampDocument(single.text, { tsaUrl, ts: "2026-11-16T09:30:00Z" });
  w("valid-tsa-block.md", stamped.text);
  w("valid-tsa-renewal.md", (await timestampDocument(stamped.text, { tsaUrl, hash: "sha512", ts: "2026-11-16T09:40:00Z", reason: "renewal" })).text);
  w("tampered-tsa-block.md", stamped.text.replace("1,000 USD", "100 USD"));
}

// SPEC 5.4 step 1: a later format with a field this version does not know is "unsupported", not "malformed"
w("unsupported-version-new-field.md", single.text.replace("v: 0.1\n", "v: 9.9.9\n").replace("role: author\n", "role: author\nwitness_policy: any\n"));
w("unsupported-version-v004.md", single.text.replace("v: 0.1\n", "v: 0.0.4\n"));
w("malformed-duplicate-version.md", single.text.replace("v: 0.1\n", "v: 0.1\nv: 9.9.9\n"));
w("malformed-missing-alg.md", single.text.replace("alg: ed25519\n", ""));

const exp = await signDocument(body, { signer: bob, method: "tofu", signerId: "bob@laptop", ts: TS0, expires: "2026-11-30T00:00:00Z" });
w("expired.md", exp.text);

const REV_URL = "https://example.com/.well-known/mdsig-revoked.md";
const revOk = await dnsSign(body, ex, "example.com", { revocationUrl: REV_URL, reason: "Still valid" });
const revBad = await dnsSign(body, ex, "example.com", { revocationUrl: REV_URL, reason: "Withdrawn later" });
w("not-revoked.md", revOk.text);
w("revoked.md", revBad.text);
// SPEC 5.10: the list's own revocation_url must not be followed
const list = await dnsSign(signedList("# example.com revoked signatures", "revocation", [`revoked: sha256:${await revocationId(revBad.fields)}`]), ex, "example.com", { ts: "2026-11-25T00:00:00Z", revocationUrl: REV_URL });
w("revocation/example.com.md", list.text);

w("unknown-field.md", single.text.replace("role: author", "role: author" + NL + "priority: high"));
// SPEC 3.2 rule 4: U+202E (right-to-left override) in a value
w("malformed-bidi-control.md", single.text.replace("role: author", "role: \u202eauthor"));
// SPEC 4.2: the host of a git-hosting signer is never an IP address
w("malformed-git-hosting-ip.md", single.text.replace("method: tofu", "method: git-hosting").replace("signer: bob@laptop", "signer: 127.0.0.1/bob").replace(/pubkey: .*\n/, ""));

const passkey = await createSoftwareAuthenticator("mdsig.dev");
const wa = await signDocument(body, { signer: passkey, method: "tofu", signerId: "carol@passkey", role: "approver", ts: TS0 });
w("valid-webauthn.md", wa.text);
w("tampered-webauthn.md", wa.text.replace("role: approver", "role: witness"));

// --- OpenPGP vectors (SPEC 4.3, 6.2)
// --- OpenPGP vectors (SPEC 4.3, 6.2)
mkdirSync(new URL("pgp/", out), { recursive: true });
const PGP_CREATED = 1767225600; // 2026-01-01T00:00:00Z
// RFC 8032 7.1 "TEST 1024" and "TEST SHA(abc)" seeds
const DAVE = fromHex("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5");
const ERIN = fromHex("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42");
// fixed public P-256 test key, generated once for these vectors
const GRACE_P256 = { d: "L947bY-adulkQqPF942Ozg9e3qDmqrkV31lHgD1xNv4", x: "_kH32lKm-2n4pJvJUk-6LuqYkw74vhN8PJScK7-BZmQ", y: "NcMGHgjQaL5nU6rP9BLOg0ATCwJRT537cwsxOyHbx9o" };

// packet creation time = ts, so regenerated vectors are identical apart from random salts and nonces
const PGP_SIGNED = Date.parse("2026-11-16T09:00:00Z") / 1000;
const pgpFetch: Record<string, string> = {};
const pgpKeys: Record<string, unknown> = {};
const ks = (fpr: string, file: string) => (pgpFetch[hkpUrl("https://keys.openpgp.org", fpr)] = file);
async function pgpCert(name: string, spec: Parameters<typeof buildCert>[0]) {
  const c = await buildCert(spec);
  w(`pgp/${name}.pub.asc`, armor("PUBLIC KEY BLOCK", c.pub));
  w(`pgp/${name}.sec.asc`, armor("PRIVATE KEY BLOCK", c.sec));
}
const pgpDoc = (signer: PgpSigner, signerId: string, extra: Partial<Parameters<typeof signDocument>[1]> = {}) =>
  signDocument(body, { signer, method: "pgp", signerId, role: "author", ts: "2026-11-16T09:00:00Z", ...extra });

const dave = await ed25519Key(DAVE, PGP_CREATED, 4);
await pgpCert("dave", { primary: dave, uid: "Dave Test <dave@example.org>", primaryFlags: 0x03, created: PGP_CREATED });
const daveSigner = signerOf(dave, ["dave@example.org"], undefined, PGP_SIGNED);
pgpFetch[(await wkdUrls("dave@example.org")).direct] = "pgp/dave.pub.asc";
ks(daveSigner.fpr, "pgp/dave.pub.asc");
const pd = await pgpDoc(daveSigner, "dave@example.org");
w("valid-pgp-ed25519.md", pd.text);
w("tampered-pgp.md", pd.text.replace("role: author", "role: approver"));
w("malformed-pgp-alg.md", pd.text.replace("alg: openpgp", "alg: ed25519"));
w("pgp-wrong-uid.md", (await pgpDoc({ ...daveSigner, emails: [] }, "mallory@example.org")).text);

const PGP_REV_URL = "https://example.org/.well-known/mdsig-revoked.md";
const pgpRevoked = await pgpDoc(daveSigner, "dave@example.org", { revocationUrl: PGP_REV_URL, reason: "Withdrawn later" });
w("pgp-revoked.md", pgpRevoked.text);
// SPEC 5.9: dropping the unhashed subpackets changes the sig bytes but not the revocation id
{
  const b = parseDocument(pgpRevoked.text).chain[0]!;
  const pkt = fromBase64(unfoldBinary(b.fields.sig!).slice(7));
  const sigBody = pkt.subarray(2);
  const uoff = 6 + ((sigBody[4]! << 8) | sigBody[5]!);
  const ulen = (sigBody[uoff]! << 8) | sigBody[uoff + 1]!;
  const stripped = new Uint8Array([...sigBody.subarray(0, uoff), 0, 0, ...sigBody.subarray(uoff + 2 + ulen)]);
  const sig = "base64:" + toBase64(new Uint8Array([0xc2, stripped.length, ...stripped]));
  w("pgp-revoked-malleated.md", pgpRevoked.text.slice(0, b.start) + serializeBlock({ ...b.fields, sig }) + NL);
}
const revokedLine = async (r: { fields: Record<string, string> }) => `revoked: sha256:${await revocationId(r.fields)}`;
const daveList = await signDocument(signedList("# dave@example.org revoked signatures", "revocation", [await revokedLine(pgpRevoked)]), {
  signer: daveSigner, method: "pgp", signerId: "dave@example.org", ts: "2026-11-25T00:00:00Z",
});
w("revocation/dave.md", daveList.text);
const mallory = await ed25519Key(await labelSeed("mallory"), PGP_CREATED, 4);
await pgpCert("mallory", { primary: mallory, uid: "Not Dave <dave@example.org>", primaryFlags: 0x03, created: PGP_CREATED });
const mallorySigner = signerOf(mallory, ["dave@example.org"], undefined, PGP_SIGNED);
// SPEC 4.3: a block cannot name its keyserver; mallory claims dave's address with a key the verifier's keyserver does not have
const malloryDoc = await pgpDoc(mallorySigner, "dave@example.org");
w("pgp-keyserver-field.md", malloryDoc.text.replace(`fpr: ${mallorySigner.fpr}`, `fpr: ${mallorySigner.fpr}` + NL + "keyserver: https://keys.example.net"));
pgpFetch[PGP_REV_URL] = "revocation/dave.md";

const erin = await ed25519Key(ERIN, PGP_CREATED, 6);
await pgpCert("erin", { primary: erin, uid: "Erin Test <erin@example.org>", primaryFlags: 0x03, created: PGP_CREATED });
const erinSigner = signerOf(erin, ["erin@example.org"], undefined, PGP_SIGNED);
ks(erinSigner.fpr, "pgp/erin.pub.asc");
w("valid-pgp-v6.md", (await pgpDoc(erinSigner, "erin@example.org")).text);
// the packet's issuer fingerprint (dave) differs from the block's fpr (erin)
w("pgp-fpr-mismatch.md", (await pgpDoc({ ...daveSigner, fpr: erinSigner.fpr, emails: [] }, "erin@example.org")).text);
w("pgp-sha1.md", (await pgpDoc(signerOf(dave, ["dave@example.org"], HASH.sha1, PGP_SIGNED), "dave@example.org")).text);

const graceSub = await p256Key(GRACE_P256, PGP_CREATED, true);
await pgpCert("grace", {
  primary: await ed25519Key(await labelSeed("grace"), PGP_CREATED, 4), uid: "Grace Test <grace@example.org>", primaryFlags: 0x01,
  subkeys: [{ k: graceSub, flags: 0x02, backsig: true }], created: PGP_CREATED,
});
const graceSigner = signerOf(graceSub, ["grace@example.org"], undefined, PGP_SIGNED);
ks(graceSigner.fpr, "pgp/grace.pub.asc");
w("valid-pgp-p256-subkey.md", (await pgpDoc(graceSigner, "grace@example.org", { role: "approver" })).text);

const henry = await ed25519Key(await labelSeed("henry"), PGP_CREATED, 4);
await pgpCert("henry", { primary: henry, uid: "Henry Test <henry@example.org>", primaryFlags: 0x03, revoked: true, created: PGP_CREATED });
const henrySigner = signerOf(henry, ["henry@example.org"], undefined, PGP_SIGNED);
ks(henrySigner.fpr, "pgp/henry.pub.asc");
w("pgp-revoked-key.md", (await pgpDoc(henrySigner, "henry@example.org")).text);

const ivanSub = await ed25519Key(await labelSeed("ivan-sub"), PGP_CREATED, 4, true);
await pgpCert("ivan", {
  primary: await ed25519Key(await labelSeed("ivan"), PGP_CREATED, 4), uid: "Ivan Test <ivan@example.org>", primaryFlags: 0x01,
  subkeys: [{ k: ivanSub, flags: 0x0c, backsig: true }], created: PGP_CREATED,
});
const ivanSigner = signerOf(ivanSub, ["ivan@example.org"], undefined, PGP_SIGNED);
ks(ivanSigner.fpr, "pgp/ivan.pub.asc");
w("pgp-subkey-not-signing.md", (await pgpDoc(ivanSigner, "ivan@example.org")).text);

const judySub = await ed25519Key(await labelSeed("judy-sub"), PGP_CREATED, 4, true);
await pgpCert("judy", {
  primary: await ed25519Key(await labelSeed("judy"), PGP_CREATED, 4), uid: "Judy Test <judy@example.org>", primaryFlags: 0x01,
  subkeys: [{ k: judySub, flags: 0x02, backsig: false }], created: PGP_CREATED,
});
const judySigner = signerOf(judySub, ["judy@example.org"], undefined, PGP_SIGNED);
ks(judySigner.fpr, "pgp/judy.pub.asc");
w("pgp-subkey-no-backsig.md", (await pgpDoc(judySigner, "judy@example.org")).text);

// kate: version 6 key whose certificate lacks the direct key signature (RFC 9580 5.2.3.10)
const kate = await ed25519Key(await labelSeed("kate"), PGP_CREATED, 6);
await pgpCert("kate", { primary: kate, uid: "Kate Test <kate@example.org>", primaryFlags: 0x03, noDirectKey: true, created: PGP_CREATED });
const kateSigner = signerOf(kate, ["kate@example.org"], undefined, PGP_SIGNED);
ks(kateSigner.fpr, "pgp/kate.pub.asc");
w("pgp-v6-no-direct-key.md", (await pgpDoc(kateSigner, "kate@example.org")).text);

// frank: RSA-2048 made by gpg 2.4 and committed with passphrase "test"
const frankFile = new URL("pgp/frank.sec.asc", out);
const frankInfo = await readPgpSecretKey(readFileSync(frankFile, "utf8"), Date.parse(NOW) / 1000);
const frankSigner = await unlockPgpSecretKey(frankInfo, "test", { created: PGP_SIGNED });
ks(frankInfo.fpr, "pgp/frank.pub.asc");
w("valid-pgp-rsa.md", (await pgpDoc(frankSigner, "frank@example.org")).text);
frankSigner.dispose();
// the same key signing through gpg itself; kept from the previous run when gpg is not installed
const viaGpg = gpgSigner(frankFile, frankInfo, "20261116T090000!");
if (viaGpg) w("valid-pgp-gpg.md", (await pgpDoc(viaGpg, "frank@example.org", { reason: "Signed by gpg (detached signature)" })).text);
else console.warn("gpg not found: keeping the existing valid-pgp-gpg.md");

const pgpExpected = {
  "valid-pgp-ed25519.md": { ok: true, signatures: ["valid"], pgp: [{ keySource: "wkd", keyAlg: "ed25519" }] },
  "valid-pgp-v6.md": { ok: true, signatures: ["valid"], pgp: [{ keySource: "keyserver", keyAlg: "ed25519" }] },
  "valid-pgp-p256-subkey.md": { ok: true, signatures: ["valid"], pgp: [{ keySource: "keyserver", keyAlg: "ecdsa-p256" }] },
  "valid-pgp-rsa.md": { ok: true, signatures: ["valid"], pgp: [{ keySource: "keyserver", keyAlg: "rsa2048" }] },
  ...(viaGpg || existsSync(new URL("valid-pgp-gpg.md", out)) ? { "valid-pgp-gpg.md": { ok: true, signatures: ["valid"], pgp: [{ keySource: "keyserver", keyAlg: "rsa2048" }] } } : {}),
  "tampered-pgp.md": { ok: false, signatures: ["invalid:bad-signature"] },
  "malformed-pgp-alg.md": { ok: false, signatures: ["malformed:malformed"] },
  "pgp-wrong-uid.md": { ok: false, signatures: ["unresolved:not-found"] },
  "pgp-fpr-mismatch.md": { ok: false, signatures: ["invalid:bad-signature"] },
  "pgp-sha1.md": { ok: false, signatures: ["invalid:bad-signature"] },
  "pgp-revoked-key.md": { ok: false, signatures: ["invalid:revoked"] },
  "pgp-subkey-not-signing.md": { ok: false, signatures: ["unresolved:not-found"] },
  "pgp-subkey-no-backsig.md": { ok: false, signatures: ["unresolved:not-found"] },
  "pgp-v6-no-direct-key.md": { ok: false, signatures: ["unresolved:not-found"] },
  "pgp-revoked.md": { ok: false, signatures: ["invalid:revoked"] },
  "pgp-revoked-malleated.md": { ok: false, signatures: ["invalid:revoked"] },
  "pgp-keyserver-field.md": { ok: false, signatures: ["malformed:unknown-field"] },
};
Object.assign(pgpKeys, {
  "dave@example.org": { fpr: daveSigner.fpr, version: 4, seed_hex: toHexStr(DAVE), cert: "pgp/dave.pub.asc", secret: "pgp/dave.sec.asc", lookup: "WKD (direct)" },
  "erin@example.org": { fpr: erinSigner.fpr, version: 6, seed_hex: toHexStr(ERIN), cert: "pgp/erin.pub.asc", secret: "pgp/erin.sec.asc" },
  "frank@example.org": { fpr: frankInfo.fpr, version: 4, cert: "pgp/frank.pub.asc", secret: "pgp/frank.sec.asc", passphrase: "test" },
  "grace@example.org": { fpr: graceSigner.fpr, version: 4, cert: "pgp/grace.pub.asc", secret: "pgp/grace.sec.asc", note: "ECDSA P-256 signing subkey" },
  "henry@example.org": { fpr: henrySigner.fpr, version: 4, cert: "pgp/henry.pub.asc", note: "revoked key" },
  "ivan@example.org": { fpr: ivanSigner.fpr, version: 4, cert: "pgp/ivan.pub.asc", note: "subkey without the signing flag" },
  "mallory (dave@example.org)": { fpr: mallorySigner.fpr, version: 4, cert: "pgp/mallory.pub.asc", secret: "pgp/mallory.sec.asc", note: "claims dave's address; signs pgp-keyserver-field.md" },
  "judy@example.org": { fpr: judySigner.fpr, version: 4, cert: "pgp/judy.pub.asc", note: "signing subkey without a primary key binding signature" },
  "kate@example.org": { fpr: kateSigner.fpr, version: 6, cert: "pgp/kate.pub.asc", note: "version 6 key without a direct key signature" },
});

// --- key directories (SPEC 4.7)
mkdirSync(new URL("directory/", out), { recursive: true });
const KEYS_MDSIG = "https://keys.mdsig.dev";
const dirFetch: Record<string, string> = {};
const dirTxt: Record<string, string[]> = {};
const dirKeys: Record<string, unknown> = {};
async function publish(directory: string, email: string, entries: { type: string; key: Uint8Array }[], file: string) {
  const json = { email, verified: "email", keys: entries.map((e) => ({ type: e.type, key: toBase64(e.key), added: "2026-11-01T00:00:00Z" })) };
  w(`directory/${file}.json`, JSON.stringify(json, null, 2) + NL);
  dirFetch[await directoryKeyUrl(directory, email)] = `directory/${file}.json`;
}
const absent = async (directory: string, email: string) => (dirFetch[await directoryKeyUrl(directory, email)] = "404");
const dirDoc = (signer: Signer | Awaited<ReturnType<typeof createSoftwareAuthenticator>>, signerId: string, extra: Partial<Parameters<typeof signDocument>[1]> = {}) =>
  signDocument(body, { signer, method: "directory", signerId, role: "author", ts: "2026-11-16T09:00:00Z", ...extra });

const dirAlice = await signerFromSeed(await labelSeed("directory alice"));
await publish(KEYS_MDSIG, "alice@mail.example", [{ type: "ed25519", key: dirAlice.publicKey }], "alice");
const dirValid = await dirDoc(dirAlice, "alice@mail.example", { embedKey: false });
w("directory-valid.md", dirValid.text);
w("directory-snapshot.md", (await dirDoc(dirAlice, "alice@mail.example")).text);
w("malformed-directory-signer.md", dirValid.text.replace("signer: alice@mail.example", "signer: Alice@mail.example"));

const dirPasskey = await createSoftwareAuthenticator("mdsig.dev");
await publish(KEYS_MDSIG, "carol@mail.example", [{ type: "es256", key: dirPasskey.publicKey }], "carol");
w("directory-passkey.md", (await dirDoc(dirPasskey, "carol@mail.example", { role: "approver" })).text);

// the directory lists alice's key for dave, so dave's own embedded key is not vouched for
const dirDave = await signerFromSeed(await labelSeed("directory dave"));
await publish(KEYS_MDSIG, "dave@mail.example", [{ type: "ed25519", key: dirAlice.publicKey }], "dave");
w("directory-key-not-published.md", (await dirDoc(dirDave, "dave@mail.example")).text);

await absent(KEYS_MDSIG, "erin@mail.example");
w("directory-not-found.md", (await dirDoc(dirDave, "erin@mail.example", { embedKey: false })).text);

// corp.example names its own directory, so keys.mdsig.dev is never asked
const dirFrank = await signerFromSeed(await labelSeed("directory frank"));
dirTxt["_mdsig.corp.example"] = ["v=mdsig1; dir=https://keys.corp.example"];
await publish("https://keys.corp.example", "frank@corp.example", [{ type: "ed25519", key: dirFrank.publicKey }], "frank");
w("directory-domain-delegated.md", (await dirDoc(dirFrank, "frank@corp.example", { embedKey: false })).text);

dirTxt["_mdsig.multi.example"] = ["v=mdsig1; dir=https://keys.one.example", "v=mdsig1; dir=https://keys.two.example"];
w("directory-conflicting-dir.md", (await dirDoc(dirFrank, "grace@multi.example", { embedKey: false })).text);
// SPEC 5.8.5: the declaring block cannot be checked (its directory is unreachable), so the agreement is undetermined although the approval is there
{
  const d = await dirDoc(dirFrank, "zoe@mail.example", { embedKey: false, require: ["dns:example.com role=approver"] });
  w("require-declarer-unresolved.md", (await dnsSign(d.text, ex, "example.com", { role: "approver", ts: "2026-11-16T09:30:00Z" })).text);
}

// SPEC 4.1: a key record with unknown tags (here dir= and x=) still works for dns
w("dns-unknown-tag.md", (await signDocument(body, { signer: ex, method: "dns", signerId: "tagged.example", selector: "2026", role: "approver", ts: "2026-11-16T09:00:00Z" })).text);

Object.assign(dirKeys, {
  "alice@mail.example": { seed_hex: toHexStr(await labelSeed("directory alice")), directory: KEYS_MDSIG },
  "carol@mail.example": { note: "software passkey, rp_id mdsig.dev", directory: KEYS_MDSIG },
  "dave@mail.example": { seed_hex: toHexStr(await labelSeed("directory dave")), directory: KEYS_MDSIG, note: "the directory lists alice's key" },
  "erin@mail.example": { directory: KEYS_MDSIG, note: "no key (HTTP 404)" },
  "frank@corp.example": { seed_hex: toHexStr(await labelSeed("directory frank")), directory: "https://keys.corp.example", note: "named by _mdsig.corp.example" },
  "grace@multi.example": { note: "_mdsig.multi.example names two directories" },
});

const dnsEntries: Record<string, { seed_hex: string; txt: string }> = {};
for (const [domain, k] of Object.entries(dnsKeys)) dnsEntries[`2026._mdsig.${domain}`] = { seed_hex: toHexStr(k.seed), txt: `v=mdsig1; k=ed25519; ${k.extra ?? ""}p=${toBase64(k.signer.publicKey)}${domain === "tagged.example" ? "; dir=https://keys.example.org" : ""}` };

const keys = {
  _comment:
    "PUBLIC TEST KEYS from RFC 8032 Section 7.1 and SHA-256 of fixed labels. Never use them for real signatures. Verifiers under test must resolve these signers to these keys instead of using the network: " +
    "dns signers from `dns` (name <selector>._mdsig.<signer>), git-hosting signers from `git-hosting`; use `now` as the current time; serve the URLs in `fetch` from the listed files (\"404\" means an HTTP 404 response, URLs not listed fail as network errors); " +
    "answer DNS TXT queries (DoH) from `dns_records`: a list of TXT strings is the answer ([] is NODATA), \"SERVFAIL\" is a server failure, and names not listed are NXDOMAIN; resolve relative resources against this directory.",
  "git-hosting": {
    "github.com/alice": { seed_hex: toHexStr(ALICE), keys_file: formatSshPublicKey(alice.publicKey, "alice@example"), key_fp: await sshFingerprint(alice.publicKey) },
  },
  dns: dnsEntries,
  directory: dirKeys,
  dns_records: { ...dirTxt, ...dnsRecords },
  tofu: {
    "bob@laptop": { seed_hex: toHexStr(BOB), pubkey: `ed25519:${toBase64(bob.publicKey)}` },
  },
  pgp: pgpKeys,
  now: NOW,
  fetch: { [REV_URL]: "revocation/example.com.md", ...listFetch, ...pgpFetch, ...dirFetch },
};
w("keys.json", JSON.stringify(keys, null, 2) + NL);

// hand-written verdicts; agreement details and table rows are recorded from this implementation for the other one to match
const expected: Record<string, { ok: boolean; signatures: string[]; error?: string; tsa?: (string | null)[]; agreement?: string; partial?: (string[] | null)[]; resources?: string[][]; revocation?: string[]; pgp?: { keySource: string; keyAlg: string }[]; warnings?: string[] }> = {
  "valid-single.md": { ok: true, signatures: ["valid"] },
  "valid-cosigned.md": tsaUrl ? { ok: true, signatures: ["valid", "valid", "valid"], tsa: [null, null, "ok"] } : { ok: true, signatures: ["valid", "valid"] },
  "valid-crlf.md": { ok: true, signatures: ["valid"] },
  "tampered.md": { ok: false, signatures: ["invalid:hash-mismatch"] },
  "tampered-metadata.md": { ok: false, signatures: ["invalid:bad-signature"] },
  "unsigned-trailer.md": { ok: false, signatures: [], error: "unsigned-content" },
  "valid-double-hyphen.md": { ok: true, signatures: ["valid"] },
  "malformed-value-comment-close.md": { ok: false, signatures: ["malformed:malformed"] },
  "malformed-signer-uppercase.md": { ok: false, signatures: ["malformed:malformed"] },
  "malformed-signer-star.md": { ok: false, signatures: ["malformed:malformed"] },
  "valid-xn-signer.md": { ok: true, signatures: ["valid"] },
  "valid-display-name.md": { ok: true, signatures: ["valid"] },
  "malformed-display-name.md": { ok: false, signatures: ["malformed:malformed"] },
  "malformed-zero-width.md": { ok: false, signatures: ["malformed:malformed"] },
  "malformed-trailing-space-folded.md": { ok: false, signatures: ["malformed:malformed"] },
  "unclosed-fence.md": { ok: true, signatures: ["valid"], warnings: ["the body ends inside an open code fence, so Markdown renderers show the signature blocks as code"] },
  "valid-resources.md": { ok: true, signatures: ["valid"], resources: [["ok", "not-checked"]] },
  "valid-resource-query.md": { ok: true, signatures: ["valid"], resources: [["not-checked"]] },
  "require-declarer-unresolved.md": { ok: false, signatures: ["unresolved:network", "valid"], agreement: "undetermined" },
  "tampered-resource.md": { ok: false, signatures: ["invalid:resource-mismatch"] },
  "missing-resource.md": { ok: false, signatures: ["invalid:resource-missing"] },
  "valid-resource-percent.md": { ok: true, signatures: ["valid"], resources: [["ok"]] },
  "malformed-resource-percent.md": { ok: false, signatures: ["malformed:malformed"] },
  "valid-scoped-edited.md": { ok: true, signatures: ["valid"], partial: [["terms", "fees"]] },
  "tampered-scoped.md": { ok: false, signatures: ["invalid:hash-mismatch"] },
  "malformed-unclosed-section.md": { ok: false, signatures: ["malformed:malformed"] },
  "pending-require.md": { ok: true, signatures: ["valid"], agreement: "pending" },
  "complete-require.md": { ok: true, signatures: ["valid", "valid"], agreement: "complete" },
  "pending-require-scoped.md": { ok: true, signatures: ["valid", "valid"], agreement: "pending", partial: [null, ["terms"]] },
  "require-serial-complete.md": { ok: true, signatures: ["valid", "valid", "valid"], agreement: "complete" },
  "require-serial-pending.md": { ok: true, signatures: ["valid", "valid", "valid"], agreement: "pending" },
  "require-serial-guide.md": { ok: true, signatures: ["valid", "valid", "valid"], agreement: "complete" },
  "require-serial-strict.md": { ok: false, signatures: ["valid", "valid", "valid"], agreement: "violated" },
  "require-any-pending.md": { ok: true, signatures: ["valid", "valid"], agreement: "pending" },
  "require-any-complete.md": { ok: true, signatures: ["valid", "valid", "valid"], agreement: "complete" },
  "malformed-require-steps.md": { ok: false, signatures: ["malformed:malformed"] },
  "malformed-require-strict-pattern.md": { ok: false, signatures: ["malformed:malformed"] },
  "unsupported-require-attribute.md": { ok: false, signatures: ["valid"], agreement: "unsupported" },
  "require-pattern-subdomain.md": { ok: true, signatures: ["valid", "valid"], agreement: "complete" },
  "require-pattern-boundary.md": { ok: true, signatures: ["valid", "valid"], agreement: "pending" },
  "require-pattern-self.md": { ok: true, signatures: ["valid", "valid"], agreement: "pending" },
  "require-greedy-vs-matching.md": { ok: true, signatures: ["valid", "valid", "valid"], agreement: "complete" },
  "require-canonical-assignment.md": { ok: true, signatures: ["valid", "valid", "valid"], agreement: "complete" },
  "require-user-verified-complete.md": { ok: true, signatures: ["valid", "valid"], agreement: "complete" },
  "require-user-verified-pending.md": { ok: true, signatures: ["valid", "valid"], agreement: "pending" },
  "require-tofu-key-mismatch.md": { ok: true, signatures: ["valid", "valid"], agreement: "pending" },
  "require-member-https.md": { ok: true, signatures: ["valid", "valid"], agreement: "complete" },
  "require-member-https-not-member.md": { ok: true, signatures: ["valid", "valid"], agreement: "pending" },
  "require-member-unreachable.md": { ok: false, signatures: ["valid", "valid"], agreement: "undetermined" },
  "roster-wrong-type.md": { ok: false, signatures: ["valid", "valid"], agreement: "undetermined" },
  "roster-bad-line.md": { ok: false, signatures: ["valid", "valid"], agreement: "undetermined" },
  "roster-two-fences.md": { ok: false, signatures: ["valid", "valid"], agreement: "undetermined" },
  "roster-scoped-issuer.md": { ok: false, signatures: ["valid", "valid"], agreement: "undetermined" },
  "roster-other-issuer.md": { ok: false, signatures: ["valid", "valid"], agreement: "undetermined" },
  "require-member-dns.md": { ok: true, signatures: ["valid", "valid"], agreement: "complete" },
  "require-member-dns-wildcard.md": { ok: true, signatures: ["valid", "valid"], agreement: "pending" },
  "require-member-dns-servfail.md": { ok: false, signatures: ["valid", "valid"], agreement: "undetermined" },
  "table-marker.md": { ok: true, signatures: ["valid", "valid"], agreement: "pending" },
  "agent-terms.md": { ok: true, signatures: ["valid"], agreement: "pending" },
  "agent-accepted.md": { ok: true, signatures: ["valid", "valid"], agreement: "pending" },
  "agent-approved.md": { ok: true, signatures: ["valid", "valid", "valid"], agreement: "complete" },
  "unsupported-version-new-field.md": { ok: false, signatures: ["unsupported:unsupported-version"] },
  "unsupported-version-v004.md": { ok: false, signatures: ["unsupported:unsupported-version"] },
  "malformed-missing-alg.md": { ok: false, signatures: ["malformed:malformed"] },
  "valid-key-snapshot.md": { ok: true, signatures: ["valid"] },
  "key-not-published.md": { ok: false, signatures: ["unresolved:key-not-published"] },
  ...(tsaUrl
    ? {
        "valid-tsa-block.md": { ok: true, signatures: ["valid", "valid"], tsa: [null, "ok"] },
        "valid-tsa-renewal.md": { ok: true, signatures: ["valid", "valid", "valid"], tsa: [null, "ok", "ok"] },
        "tampered-tsa-block.md": { ok: false, signatures: ["invalid:hash-mismatch", "invalid:hash-mismatch"] },
      }
    : {}),
  "malformed-duplicate-version.md": { ok: false, signatures: ["malformed:malformed"] },
  "expired.md": { ok: false, signatures: ["invalid:expired"] },
  "not-revoked.md": { ok: true, signatures: ["valid"], revocation: ["not-revoked"] },
  "revoked.md": { ok: false, signatures: ["invalid:revoked"] },
  "unknown-field.md": { ok: false, signatures: ["malformed:unknown-field"] },
  "malformed-bidi-control.md": { ok: false, signatures: ["malformed:malformed"] },
  "malformed-git-hosting-ip.md": { ok: false, signatures: ["malformed:malformed"] },
  "valid-webauthn.md": { ok: true, signatures: ["valid"] },
  "tampered-webauthn.md": { ok: false, signatures: ["invalid:bad-signature"] },
  "directory-valid.md": { ok: true, signatures: ["valid"] },
  "directory-snapshot.md": { ok: true, signatures: ["valid"] },
  "directory-passkey.md": { ok: true, signatures: ["valid"] },
  "directory-key-not-published.md": { ok: false, signatures: ["unresolved:key-not-published"] },
  "directory-not-found.md": { ok: false, signatures: ["unresolved:not-found"] },
  "directory-domain-delegated.md": { ok: true, signatures: ["valid"] },
  "directory-conflicting-dir.md": { ok: false, signatures: ["unresolved:not-found"] },
  "malformed-directory-signer.md": { ok: false, signatures: ["malformed:malformed"] },
  "dns-unknown-tag.md": { ok: true, signatures: ["valid"] },
  ...pgpExpected,
};

// the second half of the expectations: what this implementation reports, for the Go port to match
const { exampleOptions } = await import("../test/harness.ts");
const full: Record<string, unknown> = {};
for (const [file, e] of Object.entries(expected)) {
  const r = await verifyDocument(readFileSync(new URL(file, out), "utf8"), exampleOptions());
  const j = toJsonResult(r);
  const got = r.signatures.map((s) => (s.status === "valid" ? "valid" : `${s.status}:${s.code}`));
  if (JSON.stringify(got) !== JSON.stringify(e.signatures) || r.ok !== e.ok || (e.agreement ?? "none") !== r.agreement.status) {
    console.error(`MISMATCH ${file}: ok=${r.ok} ${JSON.stringify(got)} agreement=${r.agreement.status}`, JSON.stringify(j.agreement), r.signatures.map((s) => s.message));
  }
  full[file] = {
    ...e,
    agreement: e.agreement ?? "none",
    agreement_json: j.agreement,
    table: signatureTableToJson(signatureTable(r)),
    times: r.signatures.map((s) => s.time?.at ?? null),
    marker: findSignatureMarker(parseDocument(readFileSync(new URL(file, out), "utf8")).body).line ?? null,
  };
}
w("expected.json", JSON.stringify(full, null, 2) + NL);
console.log("wrote examples to", out.pathname, tsaUrl ? `(TSA: ${tsaUrl})` : "(no TSA)");

function toHexStr(b: Uint8Array) {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}
