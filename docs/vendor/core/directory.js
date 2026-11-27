import { fromBase64, toBase64, toHex, utf8 } from "./encoding.js";
import { ed25519Verify, sha256 } from "./crypto.js";
import { checkWebAuthnData, verifyWebAuthnSignature } from "./webauthn.js";
// --- Lookup (SPEC 4.7)
export const DEFAULT_KEY_DIRECTORIES = ["https://keys.mdsig.dev"];
const HTTPS_URL_RE = /^https:\/\/[^\s/?#]+(?:\/[^\s?#]*)?$/;
export function isKeyDirectoryUrl(url) {
    return HTTPS_URL_RE.test(url);
}
export async function directoryKeyUrl(directory, email) {
    return `${directory.replace(/\/+$/, "")}/v1/keys/${toHex(await sha256(utf8(email)))}`;
}
// SPEC 4.1: tag-list records; unknown tags are ignored
export function parseDnsTags(txt) {
    const tags = {};
    for (const part of txt.split(";")) {
        const i = part.indexOf("=");
        if (i < 0)
            continue;
        tags[part.slice(0, i).trim()] = part.slice(i + 1).trim();
    }
    return tags;
}
// distinct https dir= values of the v=mdsig1 records at _mdsig.<domain>
export function directoriesFromRecords(records) {
    const dirs = new Set();
    for (const r of records) {
        const tags = parseDnsTags(r);
        if (tags.v === "mdsig1" && tags.dir && isKeyDirectoryUrl(tags.dir))
            dirs.add(tags.dir.replace(/\/+$/, ""));
    }
    return [...dirs];
}
// null when the response does not describe this email (SPEC 4.7: treated as "no key")
export function parseDirectoryResponse(bytes, email) {
    const j = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    if (j === null || typeof j !== "object" || Array.isArray(j))
        throw new Error("the response is not a JSON object");
    const o = j;
    if (o.email !== email)
        return null;
    const keys = [];
    for (const k of Array.isArray(o.keys) ? o.keys : []) {
        if (k === null || typeof k !== "object")
            continue;
        const { type, key, added } = k;
        if (typeof type !== "string" || typeof key !== "string")
            continue;
        try {
            keys.push({ type, key: fromBase64(key), ...(typeof added === "string" ? { added } : {}) });
        }
        catch {
        }
    }
    return { email, verified: typeof o.verified === "string" ? o.verified : "", keys };
}
// --- Registration (the keys.mdsig.dev API; not part of the format)
export const KEYDIR_PROOF_PREFIX = "md-signature/keydir/v1";
export function directoryKeyType(signer) {
    return signer.alg === "ed25519" ? "ed25519" : "es256";
}
// The proof binds the challenge to the address and the key, so it cannot be replayed for another pair.
export function registrationMessage(challenge, email, type, key) {
    return utf8(`${KEYDIR_PROOF_PREFIX}\n${challenge}\n${email}\n${type}:${key}`);
}
export async function createRegistration(challenge, email, signer, label) {
    const type = directoryKeyType(signer);
    const key = toBase64(signer.publicKey);
    const msg = registrationMessage(challenge, email, type, key);
    let proof;
    if (signer.alg === "ed25519") {
        proof = { type: "ed25519", sig: toBase64(await signer.sign(msg)) };
    }
    else {
        const a = await signer.getAssertion(await sha256(msg));
        proof = { type: "webauthn", rp_id: signer.rpId, authenticator_data: toBase64(a.authenticatorData), client_data: toBase64(a.clientDataJSON), sig: toBase64(a.signature) };
    }
    return { email, type, key, challenge, proof, ...(label ? { label } : {}) };
}
export async function verifyRegistration(r) {
    let key;
    try {
        key = fromBase64(r.key);
    }
    catch {
        return false;
    }
    const msg = registrationMessage(r.challenge, r.email, r.type, r.key);
    const p = r.proof;
    try {
        if (r.type === "ed25519" && p.type === "ed25519")
            return await ed25519Verify(key, fromBase64(p.sig), msg);
        if (r.type === "es256" && p.type === "webauthn") {
            const check = await checkWebAuthnData({ rp_id: p.rp_id, webauthn_authenticator_data: p.authenticator_data, webauthn_client_data: p.client_data }, msg);
            return check.ok && (await verifyWebAuthnSignature(key, fromBase64(p.sig), check.authData, check.clientData));
        }
    }
    catch {
        return false;
    }
    return false;
}
async function postJson(url, body, f) {
    const res = await f(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    const text = await res.text();
    let j = null;
    try {
        j = text ? JSON.parse(text) : null;
    }
    catch {
    }
    if (!res.ok)
        throw new Error(j?.error ?? `HTTP ${res.status}`);
    return j;
}
export async function requestDirectoryChallenge(directory, f = globalThis.fetch) {
    const j = (await postJson(`${directory.replace(/\/+$/, "")}/v1/challenges`, {}, f));
    if (typeof j?.challenge !== "string")
        throw new Error("the directory returned no challenge");
    return j.challenge;
}
// sends the request; the key is published after the owner opens the link in the confirmation email
export async function registerWithDirectory(directory, email, signer, o = {}) {
    const f = o.fetch ?? globalThis.fetch;
    const challenge = await requestDirectoryChallenge(directory, f);
    await postJson(`${directory.replace(/\/+$/, "")}/v1/registrations`, await createRegistration(challenge, email, signer, o.label), f);
}
// --- Removal with the key itself: no confirmation email, only the key that signs is removed
export const KEYDIR_REMOVAL_PREFIX = "md-signature/keydir/remove/v1";
// a different prefix from registrationMessage, so a registration proof cannot remove a key
export function removalMessage(challenge, email) {
    return utf8(`${KEYDIR_REMOVAL_PREFIX}\n${challenge}\n${email}`);
}
export async function createRemoval(challenge, email, signer) {
    const msg = removalMessage(challenge, email);
    const key = "publicKey" in signer ? toBase64(signer.publicKey) : undefined;
    let proof;
    if (signer.alg === "ed25519") {
        proof = { type: "ed25519", sig: toBase64(await signer.sign(msg)) };
    }
    else {
        const a = await signer.getAssertion(await sha256(msg));
        proof = { type: "webauthn", rp_id: signer.rpId, authenticator_data: toBase64(a.authenticatorData), client_data: toBase64(a.clientDataJSON), sig: toBase64(a.signature) };
    }
    return { email, challenge, proof, ...(key ? { key } : {}) };
}
// the directory tries each key registered for the address and removes the one this returns true for
export async function verifyRemoval(r, candidate) {
    let key;
    try {
        key = fromBase64(candidate.key);
    }
    catch {
        return false;
    }
    const msg = removalMessage(r.challenge, r.email);
    const p = r.proof;
    try {
        if (candidate.type === "ed25519" && p.type === "ed25519")
            return await ed25519Verify(key, fromBase64(p.sig), msg);
        if (candidate.type === "es256" && p.type === "webauthn") {
            const check = await checkWebAuthnData({ rp_id: p.rp_id, webauthn_authenticator_data: p.authenticator_data, webauthn_client_data: p.client_data }, msg);
            return check.ok && (await verifyWebAuthnSignature(key, fromBase64(p.sig), check.authData, check.clientData));
        }
    }
    catch {
        return false;
    }
    return false;
}
// removes the signing key at once; returns the directory's answer
export async function removeWithKey(directory, email, signer, o = {}) {
    const f = o.fetch ?? globalThis.fetch;
    const challenge = await requestDirectoryChallenge(directory, f);
    return postJson(`${directory.replace(/\/+$/, "")}/v1/removals`, await createRemoval(challenge, email, signer), f);
}
export async function requestDirectoryRemoval(directory, email, o = {}) {
    await postJson(`${directory.replace(/\/+$/, "")}/v1/removals`, { email, ...(o.key ? { key: o.key } : {}) }, o.fetch ?? globalThis.fetch);
}
