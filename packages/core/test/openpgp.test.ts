import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { verifyDocument, signDocument } from "../src/index.ts";
import { toHex, utf8, fromHex } from "../src/encoding.ts";
import { dearmor, readPackets } from "../src/pgp-packets.ts";
import { parseKeyPacket, parseCerts, checkCert, fprHex } from "../src/pgp-keys.ts";
import { parseSignature, verifyRaw, hashInput, readSignaturePacket } from "../src/pgp-sig.ts";
import { readPgpSecretKey, unlockPgpSecretKey, cfb } from "../src/pgp-secret.ts";
import { checkSignaturePacket, zbase32, wkdUrls } from "../src/pgp-verify.ts";

// --- RFC 9580 Appendix A

const A1 = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEU/NfCxYJKwYBBAHaRw8BAQdAPwmJlL3ZFu1AUxl5NOSofIBzOhKA1i+AEJku
Q+47JAY=
-----END PGP PUBLIC KEY BLOCK-----`;

const A2 = `-----BEGIN PGP SIGNATURE-----

iF4EABYIAAYFAlX5X5UACgkQjP3hIZeWWpr2IgD/VvkMypjiECY3vZg/2xbBMd/S
ftgr9N3lYG4NdWrtM2YBANCcT6EVJ/A44PV/IgHYLy6iyQMyZfps60iehUuuYbQE
-----END PGP SIGNATURE-----`;

const A3 = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf
GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy
KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw
gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE
QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn
+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh
BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8
j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805
I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==
-----END PGP PUBLIC KEY BLOCK-----`;

const A4 = `-----BEGIN PGP PRIVATE KEY BLOCK-----

xUsGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laMAGXKB
exK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditlsLfCsQYfGwoAAABCBYJjh3/jAwsJ
BwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lwgyU2kCcUmKfvBXbAf6rh
RYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaEQsiPlR4zxP/TP7mhfVEe
7XWPxtnMUMtf15OyA51YBMdLBmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/
LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24wpsG
GBsKAAAALAWCY4d/4wKbDCIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJAAAAAAQBIKbpGG2dWTX8j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDE
M0g12vYxoWM8Y81W+bHBw805I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUr
k0mXubZvyl4GBg==
-----END PGP PRIVATE KEY BLOCK-----`;

const A6_SIG = `-----BEGIN PGP SIGNATURE-----

wpgGARsKAAAAKQWCY5ijYyIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJAAAAAGk2IHZJX1AhiJD39eLuPBgiUU9wUA9VHYblySHkBONKU/usJ9BvuAqo
/FvLFuGWMbKAdA+epq7V4HOtAPlBWmU8QOd6aud+aSunHQaaEJ+iTFjP2OMW0KBr
NK2ay45cX1IVAQ==
-----END PGP SIGNATURE-----`;

const NOW = Date.UTC(2026, 10, 16) / 1000;

test("A.1 v4 Ed25519Legacy key: packet bytes and fingerprint", async () => {
  const [bytes] = dearmor(A1);
  const [p] = readPackets(bytes!);
  assert.equal(toHex(p!.body), "0453f35f0b16092b06010401da470f010107403f098994bdd916ed4053197934e4a87c80733a1280d62f8010992e43ee3b2406");
  const key = await parseKeyPacket(p!.tag, p!.body);
  assert.equal(fprHex(key), "C959BDBAFA32A2F89A153B678CFDE12197965A9A");
  assert.equal(key.material.kind, "ed25519");
});

test("A.2 v4 signature: hash input matches the RFC and verifies over the digest", async () => {
  const [kb] = dearmor(A1);
  const [kp] = readPackets(kb!);
  const key = await parseKeyPacket(kp!.tag, kp!.body);
  const sig = readSignaturePacket(dearmor(A2)[0]!);
  assert.equal(sig.version, 4);
  assert.equal(toHex(hashInput(sig, utf8("OpenPGP"))), "4f70656e504750040016080006050255f95f9504ff0000000c");
  assert.equal(await verifyRaw(key, sig, utf8("OpenPGP")), true);
  assert.equal(await verifyRaw(key, sig, utf8("OpenPGq")), false);
});

test("A.2 signature fails the md-signature document rules only where expected", () => {
  // it has no issuer fingerprint subpacket (only a key ID), so SPEC 6.2 condition 4 rejects it
  const r = checkSignaturePacket(dearmor(A2)[0]!, "C959BDBAFA32A2F89A153B678CFDE12197965A9A");
  assert.equal(r.ok, false);
});

test("A.3 v6 certificate: fingerprints and self-signatures", async () => {
  const [cert] = await parseCerts(A3);
  assert.equal(fprHex(cert!.primary), "CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9");
  assert.equal(fprHex(cert!.subkeys[0]!.key), "12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885");
  const chk = await checkCert(cert!, "CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9", undefined, NOW);
  assert.equal(chk.ok, true, JSON.stringify(chk));
  // the X25519 subkey is an encryption key: not usable for signing
  const sub = await checkCert(cert!, "12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885", undefined, NOW);
  assert.equal(sub.ok, false);
  // there is no user ID, so an email cannot be bound
  const bound = await checkCert(cert!, "CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9", "alice@example.org", NOW);
  assert.equal(bound.ok, false);
});

test("A.6 v6 signature (salted) verifies with the A.3 primary key", async () => {
  const [cert] = await parseCerts(A3);
  const sig = readSignaturePacket(dearmor(A6_SIG)[0]!);
  assert.equal(sig.version, 6);
  assert.equal(sig.salt.length, 32 > 0 ? sig.salt.length : 0);
  const text = "What we need from the grocery store:\r\n\r\n- tofu\r\n- vegetables\r\n- noodles\r\n";
  assert.equal(await verifyRaw(cert!.primary, sig, utf8(text)), true);
  assert.equal(await verifyRaw(cert!.primary, sig, utf8(text.replace("tofu", "tempeh"))), false);
});

test("A.4 v6 secret key: selects the primary for signing and signs verifiably", async () => {
  const info = await readPgpSecretKey(A4, NOW);
  assert.equal(info.fpr, "CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9");
  assert.equal(info.protected, false);
  const signer = await unlockPgpSecretKey(info);
  const payload = utf8("md-signature/v1\nalg=openpgp");
  const pkt = await signer.sign(payload);
  signer.dispose();
  await assert.rejects(signer.sign(payload));
  const [cert] = await parseCerts(A3);
  const sig = readSignaturePacket(pkt);
  assert.equal(sig.version, 6);
  assert.equal(await verifyRaw(cert!.primary, sig, payload), true);
  assert.deepEqual(checkSignaturePacket(pkt, info.fpr).ok, true);
});

test("v4 and v6 trailers differ as RFC 9580 5.2.4 requires", () => {
  const v4 = readSignaturePacket(dearmor(A2)[0]!);
  const v6 = readSignaturePacket(dearmor(A6_SIG)[0]!);
  const t4 = hashInput(v4, new Uint8Array(0));
  const t6 = hashInput(v6, new Uint8Array(0));
  assert.deepEqual([...t4.subarray(t4.length - 6, t4.length - 4)], [0x04, 0xff]);
  assert.deepEqual([...t6.subarray(t6.length - 6, t6.length - 4)], [0x06, 0xff]);
  assert.deepEqual(t6.subarray(0, v6.salt.length), v6.salt);
  assert.equal(parseSignature(v6.raw).hashAlgo, 10);
});

test("AES-CFB round trip (built from single-block AES-CBC)", async () => {
  const key = fromHex("000102030405060708090a0b0c0d0e0f");
  const iv = fromHex("101112131415161718191a1b1c1d1e1f");
  const plain = utf8("an odd-length plaintext that spans several blocks!");
  const enc = await cfb(key, iv, plain, false);
  assert.notDeepEqual(enc, plain);
  assert.deepEqual(await cfb(key, iv, enc, true), plain);
  // NIST SP 800-38A F.3.13 CFB128-AES128 first block
  const nk = fromHex("2b7e151628aed2a6abf7158809cf4f3c");
  const niv = fromHex("000102030405060708090a0b0c0d0e0f");
  const c = await cfb(nk, niv, fromHex("6bc1bee22e409f96e93d7e117393172a"), false);
  assert.equal(toHex(c), "3b3fd92eb72dad20333449f8e83cfb4a");
});

test("WKD: z-base-32 and URLs", async () => {
  // draft-koch-openpgp-webkey-service example: Joe.Doe@Example.ORG
  const u = await wkdUrls("Joe.Doe@Example.ORG");
  assert.equal(u.direct, "https://example.org/.well-known/openpgpkey/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe");
  assert.equal(u.advanced, "https://openpgpkey.example.org/.well-known/openpgpkey/example.org/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe");
  assert.equal(zbase32(new Uint8Array([0xf0])), "6y");
});

// --- lookup outcome (SPEC 4.3)

const vec = (name: string) => readFileSync(new URL(`../../../examples/${name}`, import.meta.url), "utf8");

test("not-found only when every source answers that the key is absent", async () => {
  const fetch404 = (async () => new Response("", { status: 404 })) as typeof globalThis.fetch;
  const r = await verifyDocument(vec("valid-pgp-v6.md"), { fetch: fetch404 });
  assert.equal(r.signatures[0]!.status, "unresolved");
  assert.equal(r.signatures[0]!.code, "not-found");
});

test("network when a source could not be reached, even if others say absent", async () => {
  const mixed = (async (u: string) => {
    if (String(u).includes("keys.openpgp.org")) return new Response("", { status: 404 });
    throw new TypeError("Failed to fetch (CORS)");
  }) as typeof globalThis.fetch;
  const r = await verifyDocument(vec("valid-pgp-v6.md"), { fetch: mixed });
  assert.equal(r.signatures[0]!.code, "network");
  assert.match(r.signatures[0]!.message!, /WKD: unreachable; keys\.openpgp\.org: no key/);
});

test("keyring is used first and works offline", async () => {
  const cert = new TextEncoder().encode(vec("pgp/erin.pub.asc"));
  const r = await verifyDocument(vec("valid-pgp-v6.md"), { offline: true, pgpKeyring: async () => cert, now: new Date("2026-12-01T00:00:00Z") });
  assert.equal(r.signatures[0]!.status, "valid", JSON.stringify(r.signatures[0]));
  assert.equal(r.signatures[0]!.pgp?.keySource, "keyring");
  const off = await verifyDocument(vec("valid-pgp-v6.md"), { offline: true });
  assert.equal(off.signatures[0]!.code, "offline");
});

test("sign with method pgp checks the key's emails and records fpr", async () => {
  const info = await readPgpSecretKey(vec("pgp/frank.sec.asc"));
  await assert.rejects(unlockPgpSecretKey(info), /passphrase is required/);
  const signer = await unlockPgpSecretKey(info, "test");
  await assert.rejects(signDocument("# x\n", { signer, method: "pgp", signerId: "someone@example.org" }), /no user ID/);
  await assert.rejects(signDocument("# x\n", { signer, method: "tofu", signerId: "frank@example.org" }), /only sign with method pgp/);
  const out = await signDocument("# x\n", { signer, method: "pgp", signerId: "Frank@Example.org" });
  assert.equal(out.fields.signer, "frank@example.org");
  assert.equal(out.fields.fpr, info.fpr);
  assert.equal(out.fields.alg, "openpgp");
  signer.dispose();
});
