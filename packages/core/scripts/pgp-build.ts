// Builds deterministic OpenPGP test certificates for examples/ and tests. Not part of the core API.
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { concat, fromBase64, utf8 } from "../src/encoding.ts";
import { signerFromSeed } from "../src/crypto.ts";
import { encodeMpi, encodePacket, encodeSubpacket, armor, u32be, TAG } from "../src/pgp-packets.ts";
import { parseKeyPacket, type PgpKey } from "../src/pgp-keys.ts";
import { SIG, createSignature, keyPrefix, uidPrefix, signaturePacket, type PgpSigningKey } from "../src/pgp-sig.ts";
import { signingKeyFromSecret, type PgpSigner } from "../src/pgp-secret.ts";

const OID_ED25519 = [0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01];
const OID_P256 = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const b64u = (s: string) => fromBase64(s.replace(/-/g, "+").replace(/_/g, "/"));

export interface BuiltKey {
  key: PgpKey;
  sk: PgpSigningKey;
  secretBody: Uint8Array;
}

function checksum(b: Uint8Array): Uint8Array {
  let s = 0;
  for (const x of b) s = (s + x) & 0xffff;
  return new Uint8Array([s >> 8, s & 255]);
}

async function finish(tag: number, pub: Uint8Array, secretMaterial: Uint8Array, version: 4 | 6): Promise<BuiltKey> {
  const secretBody = concat(pub, new Uint8Array([0]), secretMaterial, version === 4 ? checksum(secretMaterial) : new Uint8Array(0));
  const key = await parseKeyPacket(tag, pub);
  return { key, sk: await signingKeyFromSecret(key, secretMaterial), secretBody };
}

export async function ed25519Key(seed: Uint8Array, created: number, version: 4 | 6, subkey = false): Promise<BuiltKey> {
  const pub = (await signerFromSeed(seed)).publicKey;
  const tag = subkey ? TAG.publicSubkey : TAG.publicKey;
  if (version === 6) return finish(tag, concat(new Uint8Array([6]), u32be(created), new Uint8Array([27]), u32be(32), pub), seed, 6);
  const body = concat(new Uint8Array([4]), u32be(created), new Uint8Array([22, OID_ED25519.length, ...OID_ED25519]), encodeMpi(concat(new Uint8Array([0x40]), pub)));
  return finish(tag, body, encodeMpi(seed), 4);
}

export async function p256Key(jwk: { d: string; x: string; y: string }, created: number, subkey = false): Promise<BuiltKey> {
  const point = concat(new Uint8Array([4]), b64u(jwk.x), b64u(jwk.y));
  const body = concat(new Uint8Array([4]), u32be(created), new Uint8Array([19, OID_P256.length, ...OID_P256]), encodeMpi(point));
  return finish(subkey ? TAG.publicSubkey : TAG.publicKey, body, encodeMpi(b64u(jwk.d)), 4);
}

export interface CertSpec {
  primary: BuiltKey;
  uid: string;
  primaryFlags: number;
  subkeys?: { k: BuiltKey; flags: number; backsig: boolean }[];
  revoked?: boolean;
  // version 6 only: leave out the direct key signature that RFC 9580 requires
  noDirectKey?: boolean;
  created: number;
}

export async function buildCert(spec: CertSpec): Promise<{ pub: Uint8Array; sec: Uint8Array }> {
  const p = spec.primary;
  const pp = keyPrefix(p.key);
  const uid = utf8(spec.uid);
  const o = { created: spec.created };
  const flags = (f: number) => encodeSubpacket(27, new Uint8Array([f]));
  const cert = signaturePacket(await createSignature(p.sk, SIG.certPositive, concat(pp, uidPrefix(uid)), { ...o, hashed: [flags(spec.primaryFlags)] }));
  const pubParts: Uint8Array[] = [encodePacket(TAG.publicKey, p.key.publicBody)];
  const secParts: Uint8Array[] = [encodePacket(TAG.secretKey, p.secretBody)];
  if (spec.revoked) {
    const rev = signaturePacket(await createSignature(p.sk, SIG.keyRevocation, pp, { ...o, hashed: [encodeSubpacket(29, concat(new Uint8Array([2]), utf8("test key marked compromised")))] }));
    pubParts.push(rev);
    secParts.push(rev);
  }
  if (p.key.version === 6 && !spec.noDirectKey) {
    const direct = signaturePacket(await createSignature(p.sk, SIG.directKey, pp, { ...o, hashed: [flags(spec.primaryFlags)] }));
    pubParts.push(direct);
    secParts.push(direct);
  }
  for (const parts of [pubParts, secParts]) parts.push(encodePacket(TAG.userId, uid), cert);
  for (const s of spec.subkeys ?? []) {
    const both = concat(pp, keyPrefix(s.k.key));
    const hashed = [flags(s.flags)];
    if (s.backsig) hashed.push(encodeSubpacket(32, await createSignature(s.k.sk, SIG.primaryBinding, both, o)));
    const binding = signaturePacket(await createSignature(p.sk, SIG.subkeyBinding, both, { ...o, hashed }));
    pubParts.push(encodePacket(TAG.publicSubkey, s.k.key.publicBody), binding);
    secParts.push(encodePacket(TAG.secretSubkey, s.k.secretBody), binding);
  }
  return { pub: concat(...pubParts), sec: concat(...secParts) };
}

export function signerOf(k: BuiltKey, emails: string[], hashAlgo?: number, created?: number): PgpSigner {
  return {
    alg: "openpgp",
    fpr: Array.from(k.key.fingerprint, (b) => b.toString(16).padStart(2, "0")).join("").toUpperCase(),
    keyAlg: k.key.material.kind,
    uids: emails,
    emails,
    sign: async (payload) => signaturePacket(await createSignature(k.sk, SIG.binary, payload, { hashAlgo, created })),
    dispose() {},
  };
}

// Signs through a real gpg with the given (passphrase "test") secret key file; null if gpg is missing.
export function gpgSigner(secretFile: URL, info: { fpr: string; keyAlg: string; uids: string[]; emails: string[] }, fakedTime?: string): PgpSigner | null {
  let version: string;
  try {
    version = execFileSync("gpg", ["--version"]).toString();
  } catch {
    return null;
  }
  // MSYS gpg (Git for Windows) wants /c/... paths
  const msys = process.platform === "win32" && /Home: \//.test(version);
  const gp = (p: string) => (msys ? p.replace(/^([A-Za-z]):[\\/]/, (_, d: string) => `/${d.toLowerCase()}/`).replace(/\\/g, "/") : p);
  return {
    alg: "openpgp",
    ...info,
    sign: async (payload) => {
      const home = mkdtempSync(join(tmpdir(), "mdsig-gpg-"));
      chmodSync(home, 0o700);
      writeFileSync(join(home, "gpg-agent.conf"), "allow-loopback-pinentry\n");
      const env = { ...process.env, GNUPGHOME: gp(home) };
      const run = (args: string[], input?: Uint8Array) =>
        execFileSync("gpg", ["--batch", "--pinentry-mode", "loopback", "--passphrase", "test", ...args], { env, input, stdio: ["pipe", "pipe", "pipe"] });
      try {
        run(["--import", gp(fileURLToPath(secretFile))]);
        return new Uint8Array(run([...(fakedTime ? ["--faked-system-time", fakedTime] : []), "--detach-sign", "--digest-algo", "SHA256", "-u", info.fpr], payload));
      } finally {
        try {
          execFileSync("gpgconf", ["--kill", "gpg-agent"], { env });
        } catch {}
        rmSync(home, { recursive: true, force: true });
      }
    },
    dispose() {},
  };
}

export { armor };
