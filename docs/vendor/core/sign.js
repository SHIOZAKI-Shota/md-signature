import { SPEC_VERSION, TS_RE, isValidTimestamp, normalizeNewlines, normalizedBytes, nowTs, serializeBlock, signedPayload, validateValue } from "./canonical.js";
import { digest, ed25519Verify, sha256, sshFingerprint } from "./crypto.js";
import { GIT_HOSTING_SIGNER_RE } from "./resolvers.js";
import { toBase64, toHex, utf8 } from "./encoding.js";
import { parseDocument } from "./parser.js";
import { DEFAULT_TSA_URL, requestTimestamp, requestTimestampOver } from "./tsa.js";
import { scopedHashInput } from "./scope.js";
import { formatResources } from "./resources.js";
import { formatRequirement, parseRequire } from "./agreement.js";
import { checkWebAuthnData, verifyWebAuthnSignature } from "./webauthn.js";
import { EMAIL_RE } from "./pgp-verify.js";
export class SignError extends Error {
}
// SPEC 5.1: generators refuse documents that are not valid UTF-8; a lone surrogate has no UTF-8 encoding.
const LONE_SURROGATE_RE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
function assertUtf8(text) {
    if (LONE_SURROGATE_RE.test(text))
        throw new SignError("the document is not valid UTF-8");
}
export async function signDocument(text, o) {
    const p = await prepare(text, o);
    if (o.signer.alg === "webauthn-es256") {
        // SPEC 6.1: the WebAuthn challenge is SHA-256(payload)
        const a = await o.signer.getAssertion(p.challenge);
        return complete(text, o, p, a.signature, a);
    }
    return complete(text, o, p, await o.signer.sign(p.payload));
}
export async function prepareSignature(text, o) {
    const p = await prepare(text, o);
    return {
        fields: { ...p.fields },
        payload: p.payload,
        challenge: p.challenge,
        async finish(input) {
            const key = o.signer;
            if (key.alg === "webauthn-es256") {
                if (input instanceof Uint8Array)
                    throw new SignError("a passkey signature needs the whole WebAuthn assertion");
                const f = { ...p.fields, webauthn_authenticator_data: toBase64(input.authenticatorData), webauthn_client_data: toBase64(input.clientDataJSON) };
                const check = await checkWebAuthnData(f, p.payload);
                if (!check.ok || !(await verifyWebAuthnSignature(key.publicKey, input.signature, input.authenticatorData, input.clientDataJSON)))
                    throw new SignError("the WebAuthn assertion does not verify for this payload and key");
                return complete(text, o, p, input.signature, input);
            }
            if (!(input instanceof Uint8Array))
                throw new SignError(`a ${key.alg} signature is a byte string`);
            if (key.alg === "ed25519" && !(await ed25519Verify(key.publicKey, input, p.payload)))
                throw new SignError("the signature does not verify for this payload and key");
            return complete(text, o, p, input);
        },
    };
}
async function complete(text, o, p, sig, a) {
    const fields = { ...p.fields };
    if (a) {
        fields.webauthn_authenticator_data = toBase64(a.authenticatorData);
        fields.webauthn_client_data = toBase64(a.clientDataJSON);
    }
    fields.sig = "base64:" + toBase64(sig);
    if (o.tsaUrl) {
        fields.tsa_url = o.tsaUrl;
        fields.tsa_token = await requestTimestamp(sig, o.tsaUrl, o.fetch, { roots: o.tsaRoots, extraRoots: o.extraTsaRoots });
    }
    return appendBlock(text, p.previous, fields);
}
async function prepare(text, o) {
    assertUtf8(text);
    const doc = parseDocument(text);
    if (doc.chain.length === 0 && doc.strayMarker && !o.force) {
        throw new SignError(`line ${doc.strayMarkerLine}: found an md-signature block that is followed by unsigned content. ` +
            "Co-signing would endorse text the earlier signer never signed. Use force to sign the whole file as a new document.");
    }
    const malformed = doc.chain.find((b) => b.errors.length);
    if (malformed && !o.force)
        throw new SignError(`existing signature #${malformed.index} is malformed: ${malformed.errors.join("; ")}`);
    const ts = o.ts ?? nowTs();
    if (!TS_RE.test(ts))
        throw new SignError(`ts must be YYYY-MM-DDTHH:MM:SSZ, got "${ts}"`);
    if (o.expires !== undefined && !isValidTimestamp(o.expires))
        throw new SignError(`expires must be YYYY-MM-DDTHH:MM:SSZ, got "${o.expires}"`);
    if (o.revocationUrl !== undefined && !/^https:\/\/\S+$/.test(o.revocationUrl))
        throw new SignError("revocation URL must be https://");
    for (const k of Object.keys(o.extra ?? {}))
        if (!k.startsWith("x_"))
            throw new SignError(`extra field "${k}" must start with "x_"`);
    const isWebAuthn = o.signer.alg === "webauthn-es256";
    const isPgp = o.signer.alg === "openpgp";
    if (isPgp !== (o.method === "pgp"))
        throw new SignError(isPgp ? "an OpenPGP key can only sign with method pgp" : "method pgp needs an OpenPGP key");
    const fields = { v: SPEC_VERSION, method: o.method, signer: o.signerId };
    if (o.method === "dns") {
        fields.signer = o.signerId.toLowerCase().replace(/\.$/, "");
        if (o.selector)
            fields.selector = o.selector;
    }
    if (o.method === "git-hosting") {
        if (isWebAuthn)
            throw new SignError("git-hosting supports only Ed25519 SSH keys; use tofu or dns for passkeys");
        if (!GIT_HOSTING_SIGNER_RE.test(o.signerId))
            throw new SignError(`git-hosting signer must be <host>/<username> with a domain name as host, got "${o.signerId}"`);
        if (o.keyFp !== false)
            fields.key_fp = o.keyFp ?? (await sshFingerprint(o.signer.publicKey));
    }
    if (o.method === "directory") {
        fields.signer = o.signerId.toLowerCase();
        if (!EMAIL_RE.test(fields.signer))
            throw new SignError(`directory signer must be an email address, got "${o.signerId}"`);
    }
    // SPEC 4.7: directory blocks should carry a snapshot, so it is on unless turned off
    const embedKey = o.embedKey ?? o.method === "directory";
    if (embedKey && o.method !== "dns" && o.method !== "git-hosting" && o.method !== "directory")
        throw new SignError(`embedKey works with dns, git-hosting, and directory, not ${o.method}`);
    if (o.method === "tofu" || embedKey)
        fields.pubkey = `${isWebAuthn ? "es256" : "ed25519"}:${toBase64(o.signer.publicKey)}`;
    if (isPgp) {
        const pgp = o.signer;
        const email = o.signerId.toLowerCase();
        if (!EMAIL_RE.test(email))
            throw new SignError(`pgp signer must be an email address, got "${o.signerId}"`);
        if (pgp.emails.length && !pgp.emails.includes(email))
            throw new SignError(`the OpenPGP key has no user ID with <${email}> (has: ${pgp.emails.join(", ")})`);
        fields.signer = email;
        fields.fpr = pgp.fpr;
    }
    if (isWebAuthn)
        fields.rp_id = o.signer.rpId;
    Object.assign(fields, o.extra ?? {});
    if (o.role)
        fields.role = o.role;
    if (o.reason)
        fields.reason = o.reason;
    fields.ts = ts;
    if (o.expires)
        fields.expires = o.expires;
    if (o.scope?.length)
        fields.scope = o.scope.map((id) => `section:${id}`).join(",");
    if (o.require?.length) {
        fields.require = o.require.map((r) => (typeof r === "string" ? r : formatRequirement(r))).join("\n");
        const { errors } = parseRequire(fields.require, 0, SPEC_VERSION);
        if (errors.length)
            throw new SignError(errors.join("; "));
    }
    if (o.resources?.length) {
        try {
            fields.resources = await formatResources(o.resources);
        }
        catch (e) {
            throw new SignError(`resources: ${e.message}`);
        }
    }
    if (o.revocationUrl)
        fields.revocation_url = o.revocationUrl;
    fields.alg = o.signer.alg;
    if (fields.scope) {
        const sc = scopedHashInput(normalizeNewlines(text), fields.scope);
        if (!sc.ok)
            throw new SignError(sc.message);
        fields.hash = "sha256:" + toHex(await sha256(utf8(sc.input)));
    }
    else {
        fields.hash = "sha256:" + toHex(await sha256(normalizedBytes(text)));
    }
    for (const [k, v] of Object.entries(fields)) {
        const e = validateValue(v, k === "require" || k === "resources");
        if (e)
            throw new SignError(`${k}: ${e}`);
    }
    const payload = signedPayload(fields);
    return { fields, payload, challenge: await sha256(payload), previous: doc.chain.length };
}
function appendBlock(text, previous, fields) {
    const block = serializeBlock(fields);
    const eol = /\r\n/.test(text) ? "\r\n" : "\n";
    const trimmed = text.replace(/[\r\n \t]+$/, "");
    // SPEC 7: blank line before the first block only
    const sep = previous ? eol : eol + eol;
    const out = trimmed + sep + block.replace(/\n/g, eol) + eol;
    return { text: out, block, fields, previous };
}
// SPEC 4.6: appends a tsa block, a timestamp over everything before it, earlier tokens included
export async function timestampDocument(text, o = {}) {
    assertUtf8(text);
    const doc = parseDocument(text);
    if (doc.chain.length === 0)
        throw new SignError(doc.strayMarker ? `line ${doc.strayMarkerLine}: a signature block is followed by unsigned content` : "the document has no signature to timestamp");
    const malformed = doc.chain.find((b) => b.errors.length);
    if (malformed)
        throw new SignError(`existing signature #${malformed.index} is malformed: ${malformed.errors.join("; ")}`);
    const tsaUrl = o.tsaUrl ?? DEFAULT_TSA_URL;
    if (!/^https?:\/\/\S+$/.test(tsaUrl))
        throw new SignError(`TSA URL must be http(s)://, got "${tsaUrl}"`);
    const hashAlg = o.hash ?? "sha256";
    const ts = o.ts ?? nowTs();
    if (!TS_RE.test(ts))
        throw new SignError(`ts must be YYYY-MM-DDTHH:MM:SSZ, got "${ts}"`);
    const fields = { v: SPEC_VERSION, method: "tsa", signer: tsaUrl, ts };
    if (o.reason)
        fields.reason = o.reason;
    fields.alg = "rfc3161";
    fields.hash = `${hashAlg}:${toHex(await digest(hashAlg, normalizedBytes(text)))}`;
    for (const [k, v] of Object.entries(fields)) {
        const e = validateValue(v, false);
        if (e)
            throw new SignError(`${k}: ${e}`);
    }
    const imprint = await digest(hashAlg, signedPayload(fields));
    fields.sig = await requestTimestampOver(imprint, hashAlg, tsaUrl, o.fetch, { roots: o.tsaRoots, extraRoots: o.extraTsaRoots });
    return appendBlock(text, doc.chain.length, fields);
}
