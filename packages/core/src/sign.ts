import { SPEC_VERSION, TS_RE, isValidTimestamp, normalizeNewlines, normalizedBytes, nowTs, serializeBlock, signedPayload, validateValue } from "./canonical.ts";
import { digest, sha256, sshFingerprint, type HashAlg, type Signer } from "./crypto.ts";
import { GIT_HOSTING_SIGNER_RE } from "./resolvers.ts";
import { toBase64, toHex, utf8 } from "./encoding.ts";
import { parseDocument } from "./parser.ts";
import { DEFAULT_TSA_URL, requestTimestamp, requestTimestampOver, type TsaRootInput } from "./tsa.ts";
import { scopedHashInput } from "./scope.ts";
import { formatResources } from "./resources.ts";
import { formatRequirement, parseRequire, type Requirement } from "./agreement.ts";
import type { WebAuthnSigner } from "./webauthn.ts";
import type { PgpSigner } from "./pgp-secret.ts";
import { EMAIL_RE } from "./pgp-verify.ts";

export type Method = "dns" | "git-hosting" | "tofu" | "pgp";

export interface SignOptions {
  signer: Signer | WebAuthnSigner | PgpSigner;
  method: Method;
  signerId: string;
  selector?: string;
  keyFp?: string | false;
  role?: string;
  reason?: string;
  ts?: string;
  expires?: string;
  scope?: string[];
  // one line each; "order …" and "step …" lines are passed as strings (SPEC 5.8)
  require?: (Pick<Requirement, "method" | "signer" | "role"> | string)[];
  resources?: { ref: string; bytes: Uint8Array }[];
  revocationUrl?: string;
  extra?: Record<string, string>;
  tsaUrl?: string;
  tsaRoots?: TsaRootInput[];
  extraTsaRoots?: TsaRootInput[];
  // dns and git-hosting: also write the public key (SPEC 4.5), so the signature stays checkable after the key is gone
  embedKey?: boolean;
  fetch?: typeof fetch;
  force?: boolean;
}

export interface SignResult {
  text: string;
  block: string;
  fields: Record<string, string>;
  previous: number;
}

export class SignError extends Error {}

export async function signDocument(text: string, o: SignOptions): Promise<SignResult> {
  const doc = parseDocument(text);
  if (doc.chain.length === 0 && doc.strayMarker && !o.force) {
    throw new SignError(
      `line ${doc.strayMarkerLine}: found an md-signature block that is followed by unsigned content. ` +
        "Co-signing would endorse text the earlier signer never signed. Use force to sign the whole file as a new document.",
    );
  }
  const malformed = doc.chain.find((b) => b.errors.length);
  if (malformed && !o.force) throw new SignError(`existing signature #${malformed.index} is malformed: ${malformed.errors.join("; ")}`);

  const ts = o.ts ?? nowTs();
  if (!TS_RE.test(ts)) throw new SignError(`ts must be YYYY-MM-DDTHH:MM:SSZ, got "${ts}"`);
  if (o.expires !== undefined && !isValidTimestamp(o.expires)) throw new SignError(`expires must be YYYY-MM-DDTHH:MM:SSZ, got "${o.expires}"`);
  if (o.revocationUrl !== undefined && !/^https:\/\/\S+$/.test(o.revocationUrl)) throw new SignError("revocation URL must be https://");
  for (const k of Object.keys(o.extra ?? {})) if (!k.startsWith("x_")) throw new SignError(`extra field "${k}" must start with "x_"`);

  const isWebAuthn = o.signer.alg === "webauthn-es256";
  const isPgp = o.signer.alg === "openpgp";
  if (isPgp !== (o.method === "pgp")) throw new SignError(isPgp ? "an OpenPGP key can only sign with method pgp" : "method pgp needs an OpenPGP key");
  const fields: Record<string, string> = { v: SPEC_VERSION, method: o.method, signer: o.signerId };
  if (o.method === "dns") {
    fields.signer = o.signerId.toLowerCase().replace(/\.$/, "");
    if (o.selector) fields.selector = o.selector;
  }
  if (o.method === "git-hosting") {
    if (isWebAuthn) throw new SignError("git-hosting supports only ed25519 SSH keys; use tofu or dns for passkeys");
    if (!GIT_HOSTING_SIGNER_RE.test(o.signerId)) throw new SignError(`git-hosting signer must be <host>/<username> with a domain name as host, got "${o.signerId}"`);
    if (o.keyFp !== false) fields.key_fp = o.keyFp ?? (await sshFingerprint((o.signer as Signer).publicKey));
  }
  if (o.embedKey && o.method !== "dns" && o.method !== "git-hosting") throw new SignError(`embedKey works with dns and git-hosting, not ${o.method}`);
  if (o.method === "tofu" || o.embedKey) fields.pubkey = `${isWebAuthn ? "es256" : "ed25519"}:${toBase64((o.signer as Signer | WebAuthnSigner).publicKey)}`;
  if (isPgp) {
    const pgp = o.signer as PgpSigner;
    const email = o.signerId.toLowerCase();
    if (!EMAIL_RE.test(email)) throw new SignError(`pgp signer must be an email address, got "${o.signerId}"`);
    if (pgp.emails.length && !pgp.emails.includes(email)) throw new SignError(`the OpenPGP key has no user ID with <${email}> (has: ${pgp.emails.join(", ")})`);
    fields.signer = email;
    fields.fpr = pgp.fpr;
  }
  if (isWebAuthn) fields.rp_id = (o.signer as WebAuthnSigner).rpId;
  Object.assign(fields, o.extra ?? {});
  if (o.role) fields.role = o.role;
  if (o.reason) fields.reason = o.reason;
  fields.ts = ts;
  if (o.expires) fields.expires = o.expires;
  if (o.scope?.length) fields.scope = o.scope.map((id) => `section:${id}`).join(",");
  if (o.require?.length) {
    fields.require = o.require.map((r) => (typeof r === "string" ? r : formatRequirement(r))).join("\n");
    const { errors } = parseRequire(fields.require, 0, SPEC_VERSION);
    if (errors.length) throw new SignError(errors.join("; "));
  }
  if (o.resources?.length) {
    try {
      fields.resources = await formatResources(o.resources);
    } catch (e) {
      throw new SignError(`resources: ${(e as Error).message}`);
    }
  }
  if (o.revocationUrl) fields.revocation_url = o.revocationUrl;
  fields.alg = o.signer.alg;

  if (fields.scope) {
    const sc = scopedHashInput(normalizeNewlines(text), fields.scope);
    if (!sc.ok) throw new SignError(sc.message);
    fields.hash = "sha256:" + toHex(await sha256(utf8(sc.input)));
  } else {
    fields.hash = "sha256:" + toHex(await sha256(normalizedBytes(text)));
  }

  for (const [k, v] of Object.entries(fields)) {
    const e = validateValue(v, k === "require" || k === "resources");
    if (e) throw new SignError(`${k}: ${e}`);
  }

  const payload = signedPayload(fields);
  let sig: Uint8Array;
  if (isWebAuthn) {
    // SPEC 6.1: the WebAuthn challenge is SHA-256(payload)
    const a = await (o.signer as WebAuthnSigner).getAssertion(await sha256(payload));
    sig = a.signature;
    fields.webauthn_authenticator_data = toBase64(a.authenticatorData);
    fields.webauthn_client_data = toBase64(a.clientDataJSON);
  } else {
    sig = await (o.signer as Signer | PgpSigner).sign(payload);
  }
  fields.sig = "base64:" + toBase64(sig);
  if (o.tsaUrl) {
    fields.tsa_url = o.tsaUrl;
    fields.tsa_token = await requestTimestamp(sig, o.tsaUrl, o.fetch, { roots: o.tsaRoots, extraRoots: o.extraTsaRoots });
  }

  return appendBlock(text, doc.chain.length, fields);
}

function appendBlock(text: string, previous: number, fields: Record<string, string>): SignResult {
  const block = serializeBlock(fields);
  const eol = /\r\n/.test(text) ? "\r\n" : "\n";
  const trimmed = text.replace(/[\r\n \t]+$/, "");
  // SPEC 7: blank line before the first block only
  const sep = previous ? eol : eol + eol;
  const out = trimmed + sep + block.replace(/\n/g, eol) + eol;
  return { text: out, block, fields, previous };
}

export interface TimestampOptions {
  tsaUrl?: string;
  // sha512 for a renewal that must outlive SHA-256 (SPEC 4.6)
  hash?: HashAlg;
  ts?: string;
  reason?: string;
  fetch?: typeof fetch;
  tsaRoots?: TsaRootInput[];
  extraTsaRoots?: TsaRootInput[];
}

// SPEC 4.6: appends a tsa block, a timestamp over everything before it, earlier tokens included
export async function timestampDocument(text: string, o: TimestampOptions = {}): Promise<SignResult> {
  const doc = parseDocument(text);
  if (doc.chain.length === 0) throw new SignError(doc.strayMarker ? `line ${doc.strayMarkerLine}: a signature block is followed by unsigned content` : "the document has no signature to timestamp");
  const malformed = doc.chain.find((b) => b.errors.length);
  if (malformed) throw new SignError(`existing signature #${malformed.index} is malformed: ${malformed.errors.join("; ")}`);
  const tsaUrl = o.tsaUrl ?? DEFAULT_TSA_URL;
  if (!/^https?:\/\/\S+$/.test(tsaUrl)) throw new SignError(`TSA URL must be http(s)://, got "${tsaUrl}"`);
  const hashAlg = o.hash ?? "sha256";
  const ts = o.ts ?? nowTs();
  if (!TS_RE.test(ts)) throw new SignError(`ts must be YYYY-MM-DDTHH:MM:SSZ, got "${ts}"`);
  const fields: Record<string, string> = { v: SPEC_VERSION, method: "tsa", signer: tsaUrl, ts };
  if (o.reason) fields.reason = o.reason;
  fields.alg = "rfc3161";
  fields.hash = `${hashAlg}:${toHex(await digest(hashAlg, normalizedBytes(text)))}`;
  for (const [k, v] of Object.entries(fields)) {
    const e = validateValue(v, false);
    if (e) throw new SignError(`${k}: ${e}`);
  }
  const imprint = await digest(hashAlg, signedPayload(fields));
  fields.sig = await requestTimestampOver(imprint, hashAlg, tsaUrl, o.fetch, { roots: o.tsaRoots, extraRoots: o.extraTsaRoots });
  return appendBlock(text, doc.chain.length, fields);
}
