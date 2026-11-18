import { writeFileSync, mkdirSync, readFileSync, existsSync } from "node:fs";
import { readPgpSecretKey, unlockPgpSecretKey, armor, hkpUrl, wkdUrls, type PgpSigner } from "../src/index.ts";
import { HASH } from "../src/pgp-sig.ts";
import { ed25519Key, p256Key, buildCert, signerOf, gpgSigner } from "./pgp-build.ts";
import { signDocument, signerFromSeed, timestampDocument, fromHex, fromBase64, toBase64, formatSshPublicKey, sshFingerprint, sha256, utf8, createSoftwareAuthenticator, directoryKeyUrl, parseDocument, revocationId, serializeBlock, signedPayload, unfoldBinary, type Signer } from "../src/index.ts";

const out = new URL("../../../examples/", import.meta.url);
mkdirSync(out, { recursive: true });
const w = (name: string, text: string | Uint8Array) => writeFileSync(new URL(name, out), text);

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

const single = await signDocument(body, { signer: bob, method: "tofu", signerId: "bob@laptop", role: "author", reason: "Initial draft", ts: "2026-11-16T09:00:00Z" });
w("valid-single.md", single.text);

const c1 = await signDocument(body, { signer: alice, method: "git-hosting", signerId: "github.com/alice", role: "author", reason: "Initial draft", ts: "2026-11-16T09:00:00Z" });
const c2 = await signDocument(c1.text, { signer: ex, method: "dns", signerId: "example.com", selector: "2026", role: "approver", reason: "Final approval", ts: "2026-11-16T09:46:00Z", tsaUrl });
w("valid-cosigned.md", c2.text);

const crlf = await signDocument(body.replace(/\n/g, "\r\n"), { signer: bob, method: "tofu", signerId: "bob@laptop", role: "author", ts: "2026-11-16T09:00:00Z" });
w("valid-crlf.md", crlf.text);

w("tampered.md", single.text.replace("1,000 USD", "100 USD"));

w("tampered-metadata.md", single.text.replace("role: author", "role: approver"));

w("unsigned-trailer.md", single.text + NL + "P.S. The Client also agrees to pay 5,000 USD." + NL);

// --- Extension vectors
const NOW = "2026-12-01T00:00:00Z";
mkdirSync(new URL("assets/", out), { recursive: true });
mkdirSync(new URL("revocation/", out), { recursive: true });

const diagram = utf8(["<svg xmlns='http://www.w3.org/2000/svg'><text>diagram v1</text></svg>", ""].join(NL));
const csvSigned = utf8(["milestone,amount", "design,4000", "launch,6000", ""].join(NL));
const csvOnDisk = utf8(["milestone,amount", "design,4000", "launch,60000", ""].join(NL)); // swapped after signing
w("assets/diagram.svg", diagram);
w("assets/chart.csv", csvOnDisk);

const resBody = [body, "![Diagram](./assets/diagram.svg)", "", "![Remote chart](https://example.com/chart.png)", ""].join(NL);
const res = await signDocument(resBody, {
  signer: bob, method: "tofu", signerId: "bob@laptop", role: "author", ts: "2026-11-16T09:00:00Z",
  resources: [{ ref: "./assets/diagram.svg", bytes: diagram }, { ref: "https://example.com/chart.png", bytes: utf8("not fetched by default") }],
});
w("valid-resources.md", res.text);
const resT = await signDocument([body, "See [the data](./assets/chart.csv).", ""].join(NL), {
  signer: bob, method: "tofu", signerId: "bob@laptop", ts: "2026-11-16T09:00:00Z", resources: [{ ref: "./assets/chart.csv", bytes: csvSigned }],
});
w("tampered-resource.md", resT.text);
const resM = await signDocument(body, { signer: bob, method: "tofu", signerId: "bob@laptop", ts: "2026-11-16T09:00:00Z", resources: [{ ref: "./assets/missing.png", bytes: utf8("gone") }] });
w("missing-resource.md", resM.text);

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
const scoped = await signDocument(scopedBody, { signer: bob, method: "tofu", signerId: "bob@laptop", role: "author", ts: "2026-11-16T09:00:00Z", scope: ["terms", "fees"] });
w("valid-scoped-edited.md", scoped.text.replace("Kick-off scheduled.", "Kick-off done. Design review on 2026-11-20."));
w("tampered-scoped.md", scoped.text.replace("6,000 USD", "60,000 USD"));
w("malformed-unclosed-section.md", scoped.text.replace("| Launch | 6,000 USD |" + NL + "<!-- /mdsig:section -->", "| Launch | 6,000 USD |"));

const req = await signDocument(body, { signer: alice, method: "git-hosting", signerId: "github.com/alice", role: "author", ts: "2026-11-16T09:00:00Z", require: ["dns:example.com approver"] });
w("pending-require.md", req.text);
const reqDone = await signDocument(req.text, { signer: ex, method: "dns", signerId: "example.com", selector: "2026", role: "approver", ts: "2026-11-16T09:46:00Z" });
w("complete-require.md", reqDone.text);
// SPEC 5.8: a scoped block copied from another document does not satisfy the requirement
const scopedEx = await signDocument(scopedBody, { signer: ex, method: "dns", signerId: "example.com", selector: "2026", role: "approver", ts: "2026-11-16T09:46:00Z", scope: ["terms"] });
const reqScoped = await signDocument(["# Purchase order", "", "example.com pays 1,000,000 USD.", "", scopedBody].join(NL), {
  signer: alice, method: "git-hosting", signerId: "github.com/alice", role: "author", ts: "2026-11-16T09:00:00Z", require: ["dns:example.com approver"],
});
w("pending-require-scoped.md", reqScoped.text + parseDocument(scopedEx.text).chain[0]!.raw + NL);

// --- require with steps and thresholds (SPEC 5.8, format 0.0.2)
const SERIAL = ["step 1", "dns:example.com approver", "step 2", "tofu:bob@laptop reviewer"];
const declare = (lines: string[]) => signDocument(body, { signer: alice, method: "git-hosting", signerId: "github.com/alice", role: "author", ts: "2026-11-16T09:00:00Z", require: lines });
const approve = (text: string, ts: string) => signDocument(text, { signer: ex, method: "dns", signerId: "example.com", selector: "2026", role: "approver", ts });
const review = (text: string, ts: string) => signDocument(text, { signer: bob, method: "tofu", signerId: "bob@laptop", role: "reviewer", ts });
const inOrder = await declare(SERIAL);
w("require-serial-complete.md", (await review((await approve(inOrder.text, "2026-11-16T09:30:00Z")).text, "2026-11-16T09:40:00Z")).text);
w("require-serial-pending.md", (await approve((await review(inOrder.text, "2026-11-16T09:20:00Z")).text, "2026-11-16T09:30:00Z")).text);
for (const [order, name] of [["guide", "require-serial-guide.md"], ["strict", "require-serial-strict.md"]] as const) {
  const d = await declare([`order ${order}`, ...SERIAL]);
  w(name, (await approve((await review(d.text, "2026-11-16T09:20:00Z")).text, "2026-11-16T09:30:00Z")).text);
}
// tofu signers with their own names: a tofu key proves integrity only, so any test key will do
const ANY = ["step 1 any 2", "tofu:bob@laptop", "tofu:carol@laptop", "tofu:dave@laptop"];
const anyDecl = await declare(ANY);
const anyOne = await signDocument(anyDecl.text, { signer: bob, method: "tofu", signerId: "bob@laptop", ts: "2026-11-16T09:20:00Z" });
w("require-any-pending.md", anyOne.text);
w("require-any-complete.md", (await signDocument(anyOne.text, { signer: ex, method: "tofu", signerId: "dave@laptop", ts: "2026-11-16T09:30:00Z" })).text);
// SPEC 5.8: checked before the signature, so the edit gives malformed rather than bad-signature
w("malformed-require-steps.md", anyDecl.text.replace("step 1 any 2", "step 1 any 4"));

// format 0.0.1 blocks are still verified; this re-signs a block under the old version string
async function signAsV001(text: string, signer: Signer, o: Parameters<typeof signDocument>[1]) {
  const r = await signDocument(text, o);
  const fields: Record<string, string> = { ...r.fields, v: "0.0.1" };
  delete fields.sig;
  fields.sig = "base64:" + toBase64(await signer.sign(signedPayload(fields)));
  return r.text.slice(0, r.text.length - r.block.length - 1) + serializeBlock(fields) + NL;
}
const legacy = await signAsV001(body, bob, { signer: bob, method: "tofu", signerId: "bob@laptop", role: "author", ts: "2026-11-16T09:00:00Z", require: ["dns:example.com approver"] });
w("legacy-v001.md", legacy);
w("mixed-versions.md", (await approve(legacy, "2026-11-16T09:46:00Z")).text);
w("malformed-require-step-v001.md", await signAsV001(body, bob, { signer: bob, method: "tofu", signerId: "bob@laptop", ts: "2026-11-16T09:00:00Z", require: ["step 1", "dns:example.com approver"] }));

// --- key snapshots (SPEC 3.3) and tsa blocks (SPEC 4.6)
w("valid-key-snapshot.md", (await signDocument(body, { signer: ex, method: "dns", signerId: "example.com", selector: "2026", role: "approver", ts: "2026-11-16T09:00:00Z", embedKey: true })).text);
// github.com/alice publishes only alice's key, so a snapshot of another key is not vouched for
w("key-not-published.md", (await signDocument(body, { signer: ex, method: "git-hosting", signerId: "github.com/alice", role: "author", ts: "2026-11-16T09:00:00Z", embedKey: true })).text);
if (tsaUrl) {
  const stamped = await timestampDocument(single.text, { tsaUrl, ts: "2026-11-16T09:30:00Z" });
  w("valid-tsa-block.md", stamped.text);
  w("valid-tsa-renewal.md", (await timestampDocument(stamped.text, { tsaUrl, hash: "sha512", ts: "2026-11-16T09:40:00Z", reason: "renewal" })).text);
  w("tampered-tsa-block.md", stamped.text.replace("1,000 USD", "100 USD"));
}

// SPEC 5.4 step 1: a later format with a field this version does not know is "unsupported", not "malformed"
w("unsupported-version-new-field.md", single.text.replace("v: 0.0.2\n", "v: 0.0.3\n").replace("role: author\n", "role: author\nwitness_policy: any\n"));
w("malformed-duplicate-version.md", single.text.replace("v: 0.0.2\n", "v: 0.0.2\nv: 0.0.3\n"));

const exp = await signDocument(body, { signer: bob, method: "tofu", signerId: "bob@laptop", ts: "2026-11-16T09:00:00Z", expires: "2026-11-30T00:00:00Z" });
w("expired.md", exp.text);

const REV_URL = "https://example.com/.well-known/mdsig-revoked.md";
const revOk = await signDocument(body, { signer: ex, method: "dns", signerId: "example.com", selector: "2026", ts: "2026-11-16T09:00:00Z", revocationUrl: REV_URL, reason: "Still valid" });
const revBad = await signDocument(body, { signer: ex, method: "dns", signerId: "example.com", selector: "2026", ts: "2026-11-16T09:00:00Z", revocationUrl: REV_URL, reason: "Withdrawn later" });
w("not-revoked.md", revOk.text);
w("revoked.md", revBad.text);
// SPEC 5.9: the list's own revocation_url must not be followed
const list = await signDocument(["# example.com revoked signatures", "", `revoked: sha256:${await revocationId(revBad.fields)}`, ""].join(NL), {
  signer: ex, method: "dns", signerId: "example.com", selector: "2026", ts: "2026-11-25T00:00:00Z", revocationUrl: REV_URL,
});
w("revocation/example.com.md", list.text);

w("unknown-field.md", single.text.replace("role: author", "role: author" + NL + "priority: high"));
// SPEC 3.2 rule 4: U+202E (right-to-left override) in a value
w("malformed-bidi-control.md", single.text.replace("role: author", "role: \u202eauthor"));
// SPEC 4.2: the host of a git-hosting signer is never an IP address
w("malformed-git-hosting-ip.md", single.text.replace("method: tofu", "method: git-hosting").replace("signer: bob@laptop", "signer: 127.0.0.1/bob").replace(/pubkey: .*\n/, ""));

const passkey = await createSoftwareAuthenticator("mdsig.dev");
const wa = await signDocument(body, { signer: passkey, method: "tofu", signerId: "carol@passkey", role: "approver", ts: "2026-11-16T09:00:00Z" });
w("valid-webauthn.md", wa.text);
w("tampered-webauthn.md", wa.text.replace("role: approver", "role: witness"));

// --- OpenPGP vectors (SPEC 4.3, 6.2)
mkdirSync(new URL("pgp/", out), { recursive: true });
const PGP_CREATED = 1767225600; // 2026-01-01T00:00:00Z
const labelSeed = async (label: string) => sha256(utf8(`md-signature public test key: ${label}`));
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
const daveList = await signDocument(["# dave@example.org revoked signatures", "", await revokedLine(pgpRevoked), ""].join(NL), {
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

const keys = {
  _comment:
    "PUBLIC TEST KEYS from RFC 8032 Section 7.1. Never use them for real signatures. Verifiers under test must resolve these signers to these keys instead of using the network, " +
    "use `now` as the current time, serve the URLs in `fetch` from the listed files (\"404\" means an HTTP 404 response), answer TXT lookups from `txt` (absent names do not exist), and resolve relative resources against this directory.",
  "git-hosting": {
    "github.com/alice": { seed_hex: toHexStr(ALICE), keys_file: formatSshPublicKey(alice.publicKey, "alice@example"), key_fp: await sshFingerprint(alice.publicKey) },
  },
  dns: {
    "2026._mdsig.example.com": { seed_hex: toHexStr(EXAMPLE_COM), txt: `v=mdsig1; k=ed25519; p=${toBase64(ex.publicKey)}` },
    "2026._mdsig.tagged.example": { seed_hex: toHexStr(EXAMPLE_COM), txt: `v=mdsig1; k=ed25519; x=future; p=${toBase64(ex.publicKey)}; dir=https://keys.example.org` },
  },
  directory: dirKeys,
  txt: dirTxt,
  tofu: {
    "bob@laptop": { seed_hex: toHexStr(BOB), pubkey: `ed25519:${toBase64(bob.publicKey)}` },
  },
  pgp: pgpKeys,
  now: NOW,
  fetch: { [REV_URL]: "revocation/example.com.md", ...pgpFetch, ...dirFetch },
};
w("keys.json", JSON.stringify(keys, null, 2) + NL);

const expected = {
  "valid-single.md": { ok: true, signatures: ["valid"] },
  "valid-cosigned.md": { ok: true, signatures: ["valid", "valid"], tsa: tsaUrl ? [null, "ok"] : undefined },
  "valid-crlf.md": { ok: true, signatures: ["valid"] },
  "tampered.md": { ok: false, signatures: ["invalid:hash-mismatch"] },
  "tampered-metadata.md": { ok: false, signatures: ["invalid:bad-signature"] },
  "unsigned-trailer.md": { ok: false, signatures: [], error: "unsigned-content" },
  "valid-resources.md": { ok: true, signatures: ["valid"], resources: [["ok", "not-checked"]] },
  "tampered-resource.md": { ok: false, signatures: ["invalid:resource-mismatch"] },
  "missing-resource.md": { ok: false, signatures: ["invalid:resource-missing"] },
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
  "legacy-v001.md": { ok: true, signatures: ["valid"], agreement: "pending" },
  "mixed-versions.md": { ok: true, signatures: ["valid", "valid"], agreement: "complete" },
  "malformed-require-step-v001.md": { ok: false, signatures: ["malformed:malformed"] },
  "unsupported-version-new-field.md": { ok: false, signatures: ["unsupported:unsupported-version"] },
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
w("expected.json", JSON.stringify(expected, null, 2) + NL);
console.log("wrote examples to", out.pathname, tsaUrl ? `(TSA: ${tsaUrl})` : "(no TSA)");

function toHexStr(b: Uint8Array) {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}
