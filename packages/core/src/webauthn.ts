import { sha256 } from "./crypto.ts";
import { bytesEqual, concat, fromBase64, toBase64, utf8 } from "./encoding.ts";

const subtle = globalThis.crypto.subtle;

export const toBase64Url = (b: Uint8Array) => toBase64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
export const fromBase64Url = (s: string) => fromBase64(s.replace(/-/g, "+").replace(/_/g, "/"));

// --- ECDSA encodings

// WebAuthn returns DER signatures; WebCrypto ECDSA verifies raw r||s
export function derToP1363(der: Uint8Array): Uint8Array {
  const fail = (m: string): never => {
    throw new Error(`malformed DER signature: ${m}`);
  };
  if (der.length < 8 || der[0] !== 0x30) fail("not a SEQUENCE");
  if (der[1]! & 0x80) fail("long-form length not expected");
  if (der[1]! !== der.length - 2) fail("length mismatch");
  let o = 2;
  const out = new Uint8Array(64);
  for (let k = 0; k < 2; k++) {
    if (der[o] !== 0x02) fail("INTEGER expected");
    const len = der[o + 1]!;
    if (len < 1 || len > 33) fail("integer length out of range");
    let v = der.subarray(o + 2, o + 2 + len);
    if (v.length !== len) fail("truncated");
    if (v[0]! & 0x80) fail("negative integer");
    if (len > 1 && v[0] === 0 && !(v[1]! & 0x80)) fail("non-minimal integer");
    if (v[0] === 0) v = v.subarray(1);
    if (v.length > 32) fail("integer longer than 32 bytes");
    out.set(v, k * 32 + (32 - v.length));
    o += 2 + len;
  }
  if (o !== der.length) fail("trailing bytes");
  return out;
}

export function p1363ToDer(sig: Uint8Array): Uint8Array {
  if (sig.length !== 64) throw new Error("P-256 signature must be 64 bytes");
  const int = (b: Uint8Array) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    let v = b.subarray(i);
    if (v[0]! & 0x80) v = concat(new Uint8Array([0]), v);
    return concat(new Uint8Array([0x02, v.length]), v);
  };
  const body = concat(int(sig.subarray(0, 32)), int(sig.subarray(32)));
  return concat(new Uint8Array([0x30, body.length]), body);
}

// --- Keys

// DER SPKI header for P-256 (id-ecPublicKey, prime256v1); the 65-byte point follows
const SPKI_P256_PREFIX = new Uint8Array([0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00]);

export function es256Spki(b: Uint8Array): Uint8Array {
  if (b.length === 91 && bytesEqual(b.subarray(0, 26), SPKI_P256_PREFIX)) return b;
  if (b.length === 65 && b[0] === 0x04) return concat(SPKI_P256_PREFIX, b);
  throw new Error(`not a P-256 public key (length ${b.length})`);
}

async function importEs256(key: Uint8Array): Promise<CryptoKey> {
  return subtle.importKey("spki", es256Spki(key) as BufferSource, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
}

// --- Verification

export interface WebAuthnInfo {
  rpId: string;
  origin: string;
  // SPEC 5.8.7: UP (bit 0) and UV (bit 2) both set
  userVerified: boolean;
  // BE (bit 3) and BS (bit 4): the credential may be, or is, synced
  backupEligible: boolean;
  backedUp: boolean;
}

export type WebAuthnCheck = { ok: true; info: WebAuthnInfo } | { ok: false; code: "malformed" | "bad-signature"; message: string; info?: WebAuthnInfo };

// SPEC 6.1 checks 1-3; check 4 (the signature) is verifyWebAuthnSignature
export async function checkWebAuthnData(fields: Record<string, string>, payload: Uint8Array): Promise<WebAuthnCheck & { authData?: Uint8Array; clientData?: Uint8Array }> {
  const rpId = fields.rp_id!;
  let authData: Uint8Array, clientData: Uint8Array;
  try {
    authData = fromBase64(fields.webauthn_authenticator_data!);
    clientData = fromBase64(fields.webauthn_client_data!);
  } catch {
    return { ok: false, code: "malformed", message: "WebAuthn fields are not valid base64" };
  }
  let cd: { type?: unknown; challenge?: unknown; origin?: unknown; crossOrigin?: unknown };
  try {
    cd = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(clientData));
  } catch {
    return { ok: false, code: "malformed", message: "clientDataJSON is not valid JSON" };
  }
  if (cd === null || typeof cd !== "object" || Array.isArray(cd)) return { ok: false, code: "malformed", message: "clientDataJSON is not a JSON object" };
  const origin = typeof cd.origin === "string" ? cd.origin : "";
  // authenticatorData = rpIdHash(32) | flags (UP 0x01, UV 0x04) | signCount(4)
  const flags = authData.length > 32 ? authData[32]! : 0;
  const info: WebAuthnInfo = { rpId, origin, userVerified: (flags & 0x05) === 0x05, backupEligible: (flags & 0x08) !== 0, backedUp: (flags & 0x10) !== 0 };
  if (cd.type !== "webauthn.get") return { ok: false, code: "bad-signature", message: `clientDataJSON type is ${JSON.stringify(cd.type)}, expected "webauthn.get"`, info };
  if (cd.challenge !== toBase64Url(await sha256(payload))) return { ok: false, code: "bad-signature", message: "challenge does not match the signed payload", info };
  // SPEC 6.1: an assertion made inside a cross-origin iframe is refused
  if (cd.crossOrigin === true) return { ok: false, code: "bad-signature", message: "clientDataJSON crossOrigin is true", info };
  let host: string, scheme: string;
  try {
    const u = new URL(origin);
    host = u.hostname;
    scheme = u.protocol;
  } catch {
    return { ok: false, code: "bad-signature", message: `invalid origin ${JSON.stringify(origin)}`, info };
  }
  if (host !== rpId && !host.endsWith("." + rpId)) return { ok: false, code: "bad-signature", message: `origin ${origin} does not belong to rp_id ${rpId}`, info };
  if (scheme !== "https:" && host !== "localhost") return { ok: false, code: "bad-signature", message: `origin ${origin} is not https`, info };
  if (authData.length < 37) return { ok: false, code: "malformed", message: "authenticatorData is too short", info };
  if (!bytesEqual(authData.subarray(0, 32), await sha256(utf8(rpId)))) return { ok: false, code: "bad-signature", message: "authenticatorData rpIdHash does not match rp_id", info };
  if (!(authData[32]! & 0x01)) return { ok: false, code: "bad-signature", message: "User Present flag is not set", info };
  return { ok: true, info, authData, clientData };
}

export async function verifyWebAuthnSignature(key: Uint8Array, derSig: Uint8Array, authData: Uint8Array, clientData: Uint8Array): Promise<boolean> {
  const rs = derToP1363(derSig);
  const signed = concat(authData, await sha256(clientData));
  return subtle.verify({ name: "ECDSA", hash: "SHA-256" }, await importEs256(key), rs as BufferSource, signed as BufferSource);
}

// --- Signing

export interface WebAuthnAssertion {
  signature: Uint8Array;
  authenticatorData: Uint8Array;
  clientDataJSON: Uint8Array;
}

export interface WebAuthnSigner {
  alg: "webauthn-es256";
  publicKey: Uint8Array;
  rpId: string;
  getAssertion(challenge: Uint8Array, o?: AssertionOptions): Promise<WebAuthnAssertion>;
}

export interface AssertionOptions {
  // "required" when a require line asks for user_verified (SPEC 5.8)
  userVerification?: "required" | "preferred";
}

export const assertionUserVerified = (a: WebAuthnAssertion) => a.authenticatorData.length > 32 && (a.authenticatorData[32]! & 0x05) === 0x05;

// test-only software authenticator; never use for real signatures
export async function createSoftwareAuthenticator(rpId: string, origin = `https://${rpId}`, flags = 0x05): Promise<WebAuthnSigner & { overrideClientData?: (cd: Record<string, unknown>) => Record<string, unknown> }> {
  const kp = (await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const publicKey = new Uint8Array(await subtle.exportKey("spki", kp.publicKey));
  let counter = 0;
  const self: WebAuthnSigner & { overrideClientData?: (cd: Record<string, unknown>) => Record<string, unknown> } = {
    alg: "webauthn-es256",
    publicKey,
    rpId,
    async getAssertion(challenge) {
      let cd: Record<string, unknown> = { type: "webauthn.get", challenge: toBase64Url(challenge), origin, crossOrigin: false };
      if (self.overrideClientData) cd = self.overrideClientData(cd);
      const clientDataJSON = utf8(JSON.stringify(cd));
      counter++;
      const authenticatorData = concat(await sha256(utf8(rpId)), new Uint8Array([flags, 0, 0, (counter >> 8) & 255, counter & 255]));
      const rs = new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, concat(authenticatorData, await sha256(clientDataJSON)) as BufferSource));
      return { signature: p1363ToDer(rs), authenticatorData, clientDataJSON };
    },
  };
  return self;
}

export async function registerPasskey(rpId: string, userName: string, rpName = "md-signature"): Promise<{ publicKey: Uint8Array; credentialId: Uint8Array }> {
  const cred = (await navigator.credentials.create({
    publicKey: {
      rp: { id: rpId, name: rpName },
      user: { id: globalThis.crypto.getRandomValues(new Uint8Array(16)), name: userName, displayName: userName },
      challenge: globalThis.crypto.getRandomValues(new Uint8Array(32)),
      // COSE alg -7 = ES256
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
      attestation: "none",
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("passkey registration was canceled");
  const resp = cred.response as AuthenticatorAttestationResponse;
  const spki = resp.getPublicKey?.();
  if (!spki) throw new Error("this browser does not expose the passkey public key (getPublicKey)");
  if (resp.getPublicKeyAlgorithm?.() !== -7) throw new Error("the authenticator did not create an ES256 key");
  return { publicKey: new Uint8Array(spki), credentialId: new Uint8Array(cred.rawId) };
}

export function passkeySigner(rpId: string, publicKey: Uint8Array, credentialId?: Uint8Array, defaults: AssertionOptions = {}): WebAuthnSigner {
  return {
    alg: "webauthn-es256",
    publicKey: es256Spki(publicKey),
    rpId,
    async getAssertion(challenge, o = {}) {
      const cred = (await navigator.credentials.get({
        publicKey: {
          rpId,
          challenge: challenge as BufferSource,
          userVerification: o.userVerification ?? defaults.userVerification ?? "preferred",
          ...(credentialId ? { allowCredentials: [{ type: "public-key", id: credentialId as BufferSource }] } : {}),
        },
      })) as PublicKeyCredential | null;
      if (!cred) throw new Error("passkey signing was canceled");
      const r = cred.response as AuthenticatorAssertionResponse;
      return {
        signature: new Uint8Array(r.signature),
        authenticatorData: new Uint8Array(r.authenticatorData),
        clientDataJSON: new Uint8Array(r.clientDataJSON),
      };
    },
  };
}
