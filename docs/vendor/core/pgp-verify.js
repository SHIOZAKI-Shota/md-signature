import { toHex, utf8 } from "./encoding.js";
import { fetchResource } from "./resources.js";
import { checkCert, fprHex, keyAlgName, parseCerts } from "./pgp-keys.js";
import { DOCUMENT_HASHES, SIG, readSignaturePacket, sigCreated, unknownCritical, verifyRaw } from "./pgp-sig.js";
export const DEFAULT_KEYSERVER = "https://keys.openpgp.org";
const MAX_KEY_BYTES = 1024 * 1024;
export const FPR_RE = /^(?:[0-9A-F]{40}|[0-9A-F]{64})$/;
export const EMAIL_RE = /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+$/;
// --- WKD (draft-koch-openpgp-webkey-service)
const ZB32 = "ybndrfg8ejkmcpqxot1uwisza345h769";
export function zbase32(b) {
    let out = "";
    let buf = 0;
    let bits = 0;
    for (const x of b) {
        buf = (buf << 8) | x;
        bits += 8;
        while (bits >= 5) {
            out += ZB32[(buf >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    if (bits > 0)
        out += ZB32[(buf << (5 - bits)) & 31];
    return out;
}
// WKD mandates SHA-1 of the lower-cased local part; this is addressing, not a signature hash.
export async function wkdUrls(email) {
    const at = email.lastIndexOf("@");
    const local = email.slice(0, at);
    const domain = email.slice(at + 1).toLowerCase();
    const hash = zbase32(new Uint8Array(await globalThis.crypto.subtle.digest("SHA-1", utf8(local.toLowerCase()))));
    const l = encodeURIComponent(local);
    return {
        advanced: `https://openpgpkey.${domain}/.well-known/openpgpkey/${domain}/hu/${hash}?l=${l}`,
        direct: `https://${domain}/.well-known/openpgpkey/hu/${hash}?l=${l}`,
    };
}
export function hkpUrl(keyserver, fpr) {
    return `${keyserver.replace(/\/+$/, "")}/pks/lookup?op=get&options=mr&search=0x${fpr}`;
}
class HttpStatus extends Error {
    status;
    constructor(status) {
        super(`HTTP ${status}`);
        this.status = status;
    }
}
async function get(url, f) {
    try {
        return await fetchResource(url, f, MAX_KEY_BYTES);
    }
    catch (e) {
        const m = /^HTTP (\d+)$/.exec(e.message);
        throw m ? new HttpStatus(Number(m[1])) : e;
    }
}
async function containsKey(bytes, fpr) {
    try {
        const certs = await parseCerts(bytes);
        return certs.some((c) => fprHex(c.primary) === fpr || c.subkeys.some((s) => fprHex(s.key) === fpr));
    }
    catch {
        return false;
    }
}
export async function lookupPgpKey(fpr, email, keyserver, o) {
    const attempts = [];
    const done = (cert, source, url) => ({ cert, source, url, attempts });
    if (o.pgpKeyring) {
        try {
            const b = await o.pgpKeyring(fpr);
            if (b && (await containsKey(b, fpr))) {
                attempts.push({ source: "keyring", result: "found" });
                return done(b, "keyring");
            }
            attempts.push({ source: "keyring", result: "absent" });
        }
        catch (e) {
            attempts.push({ source: "keyring", result: "error", detail: e.message });
        }
    }
    if (o.offline) {
        attempts.push({ source: "wkd", result: "error", detail: "offline" });
        return { attempts };
    }
    const f = o.fetch ?? globalThis.fetch;
    const tryUrl = async (source, url) => {
        try {
            const bytes = await get(url, f);
            return (await containsKey(bytes, fpr)) ? { source, url, result: "found", bytes } : { source, url, result: "absent", detail: "response has no key with this fingerprint" };
        }
        catch (e) {
            if (e instanceof HttpStatus && e.status === 404)
                return { source, url, result: "absent", detail: "404" };
            // a CORS refusal in a browser surfaces here as a TypeError
            return { source, url, result: "error", detail: e.message };
        }
    };
    const wkd = await wkdUrls(email);
    let a = await tryUrl("wkd", wkd.advanced);
    // WKD: the direct method is used when the advanced host does not answer
    if (a.result === "error") {
        const d = await tryUrl("wkd", wkd.direct);
        a = d.result === "error" ? { ...d, detail: `advanced: ${a.detail}; direct: ${d.detail}` } : d;
    }
    attempts.push({ source: a.source, url: a.url, result: a.result, detail: a.detail });
    if (a.bytes)
        return done(a.bytes, "wkd", a.url);
    const ks = await tryUrl("keyserver", hkpUrl(keyserver ?? DEFAULT_KEYSERVER, fpr));
    attempts.push({ source: ks.source, url: ks.url, result: ks.result, detail: ks.detail });
    if (ks.bytes)
        return done(ks.bytes, "keyserver", ks.url);
    return { attempts };
}
export function describeAttempts(attempts) {
    const label = (a) => (a.source === "keyring" ? "keyring" : a.source === "wkd" ? "WKD" : a.url ? new URL(a.url).host : "keyserver");
    const result = (a) => (a.result === "found" ? "found" : a.result === "absent" ? "no key" : a.detail === "offline" ? "skipped (offline)" : "unreachable");
    return attempts.map((a) => `${label(a)}: ${result(a)}`).join("; ");
}
const iso = (t) => new Date(t * 1000).toISOString().replace(/\.\d+Z$/, "Z");
export function checkSignaturePacket(sigBytes, fpr) {
    let sig;
    try {
        sig = readSignaturePacket(sigBytes);
    }
    catch (e) {
        return { ok: false, status: "invalid", code: "bad-signature", message: e.message };
    }
    const bad = (message) => ({ ok: false, status: "invalid", code: "bad-signature", message });
    if (sig.type !== SIG.binary)
        return bad(`OpenPGP signature type 0x${sig.type.toString(16).padStart(2, "0")} is not 0x00 (binary document)`);
    if (!DOCUMENT_HASHES.has(sig.hashAlgo))
        return bad(`OpenPGP signature hash algorithm ${sig.hashAlgo} is not SHA-256, SHA-384 or SHA-512`);
    const created = sigCreated(sig);
    if (created === undefined)
        return bad("OpenPGP signature has no hashed creation time");
    const issuer = sig.hashed.find((s) => s.type === 33)?.data;
    if (!issuer || issuer.length < 2)
        return bad("OpenPGP signature has no hashed issuer fingerprint");
    if (toHex(issuer.subarray(1)).toUpperCase() !== fpr)
        return bad(`OpenPGP signature issuer ${toHex(issuer.subarray(1)).toUpperCase()} does not match fpr`);
    const crit = unknownCritical(sig);
    if (crit !== undefined)
        return bad(`OpenPGP signature has an unknown critical subpacket ${crit}`);
    if (![1, 19, 22, 27].includes(sig.pubAlgo))
        return { ok: false, status: "unsupported", code: "unsupported-alg", message: `OpenPGP public-key algorithm ${sig.pubAlgo} is not supported` };
    return { ok: true, created: iso(created) };
}
export async function verifyPgpSignature(sigBytes, fields, payload, certs, now) {
    const fpr = fields.fpr;
    const pre = checkSignaturePacket(sigBytes, fpr);
    if (!pre.ok)
        return { status: pre.status, code: pre.code, message: pre.message, info: { fpr } };
    const sig = readSignaturePacket(sigBytes);
    let firstFail;
    for (const c of certs) {
        let parsed;
        try {
            parsed = await parseCerts(c.bytes);
        }
        catch {
            continue;
        }
        for (const cert of parsed) {
            const chk = await checkCert(cert, fpr, fields.signer, now);
            if (!chk.ok) {
                if (chk.code === "revoked")
                    return { status: "invalid", code: "revoked", message: chk.message, info: { fpr } };
                if (!chk.message.startsWith("certificate has no key") && (!firstFail || firstFail.ok || firstFail.code === "not-found"))
                    firstFail = chk;
                continue;
            }
            const info = { fpr, uid: chk.uid, keyAlg: keyAlgName(chk.key), keySource: c.source, created: pre.created };
            if (sig.pubAlgo !== chk.key.algo || sig.version !== chk.key.version) {
                return { status: "invalid", code: "bad-signature", message: "OpenPGP signature version or algorithm does not match the key", info };
            }
            if (!(await verifyRaw(chk.key, sig, payload)))
                return { status: "invalid", code: "bad-signature", message: "OpenPGP signature does not verify with the signer's key", info };
            return { status: "valid", info, warnings: chk.warnings };
        }
    }
    if (firstFail && !firstFail.ok && firstFail.code === "unsupported-alg")
        return { status: "unsupported", code: "unsupported-alg", message: firstFail.message, info: { fpr } };
    return { status: "unresolved", code: "not-found", message: firstFail && !firstFail.ok ? firstFail.message : `no certificate with key ${fpr}`, info: { fpr } };
}
