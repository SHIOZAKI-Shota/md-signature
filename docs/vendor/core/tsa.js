import { MAX_DECODED_BYTES, bytesEqual, concat, decodePrefixedBinary, gzip, toBase64 } from "./encoding.js";
import { sha256 } from "./crypto.js";
import { parseDer } from "./der.js";
import { verifyTsaSignedData } from "./tsa-cms.js";
export { parseDer };
// --- DER encoding
function derLen(n) {
    if (n < 0x80)
        return new Uint8Array([n]);
    const out = [];
    while (n > 0) {
        out.unshift(n & 0xff);
        n = Math.floor(n / 256);
    }
    return new Uint8Array([0x80 | out.length, ...out]);
}
const tlv = (tag, content) => concat(new Uint8Array([tag]), derLen(content.length), content);
const seq = (...items) => tlv(0x30, concat(...items));
function derInt(bytes) {
    let b = bytes;
    while (b.length > 1 && b[0] === 0 && (b[1] & 0x80) === 0)
        b = b.subarray(1);
    if (b[0] & 0x80)
        b = concat(new Uint8Array([0]), b);
    return tlv(0x02, b);
}
// OID 2.16.840.1.101.3.4.2.1 (sha256)
const OID_SHA256 = new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
// OID 1.2.840.113549.1.9.16.1.4 (id-ct-TSTInfo)
const OID_TSTINFO = new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x04]);
export function buildTimeStampReq(imprint, nonce) {
    const n = nonce ?? globalThis.crypto.getRandomValues(new Uint8Array(8));
    return seq(derInt(new Uint8Array([1])), seq(seq(OID_SHA256, new Uint8Array([0x05, 0x00])), tlv(0x04, imprint)), derInt(n), new Uint8Array([0x01, 0x01, 0xff]));
}
function oidToString(content) {
    const parts = [];
    const first = content[0];
    parts.push(Math.floor(first / 40), first % 40);
    let v = 0;
    for (let i = 1; i < content.length; i++) {
        v = v * 128 + (content[i] & 0x7f);
        if (!(content[i] & 0x80)) {
            parts.push(v);
            v = 0;
        }
    }
    return parts.join(".");
}
function parseGeneralizedTime(s) {
    const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z$/.exec(s);
    if (!m)
        throw new Error("TSA token: genTime is not a GeneralizedTime");
    return `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${m[7] ?? ""}Z`;
}
export function parseTimeStampResp(der) {
    const root = parseDer(der).node;
    let status = 0;
    let token;
    // TimeStampResp = { PKIStatusInfo, ContentInfo }, or a bare ContentInfo
    const c0 = root.children?.[0];
    if (c0 && c0.tag === 0x30) {
        status = c0.children?.[0]?.content[0] ?? 2;
        const t = root.children?.[1];
        if (!t)
            throw new Error(`TSA response has no token (status ${status})`);
        token = t;
    }
    else {
        token = root;
    }
    // ContentInfo = { OID, [0] SignedData }; SignedData[2] = encapContentInfo
    const signedData = token.children?.[1]?.children?.[0];
    if (!signedData?.children)
        throw new Error("TSA token: SignedData not found");
    const encap = signedData.children[2];
    const eType = encap?.children?.[0];
    if (!eType || !bytesEqual(eType.content, OID_TSTINFO.subarray(0))) {
        throw new Error("TSA token: content is not TSTInfo");
    }
    const octets = encap.children?.[1]?.children?.[0];
    if (!octets)
        throw new Error("TSA token: eContent missing");
    const tst = parseDer(octets.content).node;
    // TSTInfo = { version, policy, messageImprint, serialNumber, genTime, accuracy?, ordering?, nonce?, ... }
    const [, policy, mi, serial, gen, ...opt] = tst.children ?? [];
    if (!policy || !mi || !serial || !gen)
        throw new Error("TSA token: malformed TSTInfo");
    const alg = mi.children?.[0]?.children?.[0];
    const hashed = mi.children?.[1];
    return {
        status,
        hashOid: alg ? oidToString(alg.content) : "",
        imprint: hashed?.content ?? new Uint8Array(),
        genTime: parseGeneralizedTime(new TextDecoder().decode(gen.content)),
        policy: oidToString(policy.content),
        serial: Array.from(serial.content, (x) => x.toString(16).padStart(2, "0")).join(""),
        nonce: opt.find((n) => n.tag === 0x02)?.content,
        token: token.bytes,
        eContent: octets.content,
    };
}
class ImprintError extends Error {
}
// info is set once the imprint matched, also when the CMS check then fails
async function verifyTimeStampResp(der, imprint, o) {
    const info = parseTimeStampResp(der);
    // PKIStatus 0 = granted, 1 = grantedWithMods
    if (info.status !== 0 && info.status !== 1)
        throw new Error(`TSA status ${info.status} (not granted)`);
    if (info.hashOid !== "2.16.840.1.101.3.4.2.1")
        throw new Error(`unsupported imprint hash ${info.hashOid}`);
    if (!bytesEqual(imprint, info.imprint))
        throw new ImprintError("TSA token is for a different imprint");
    const genTime = Date.parse(info.genTime);
    if (Number.isNaN(genTime))
        return { info, error: "genTime is not a valid date" };
    try {
        const { eContent, cert } = await verifyTsaSignedData(info.token, genTime, o);
        // the fields above count only if they come from the signed bytes
        if (!bytesEqual(eContent, info.eContent))
            return { info, error: "TSTInfo is encoded ambiguously" };
        return { info, signer: cert.name };
    }
    catch (e) {
        return { info, error: e.message };
    }
}
export async function checkTsaToken(tsaToken, sigBytes, o = {}) {
    try {
        const der = await decodePrefixedBinary(tsaToken);
        const r = await verifyTimeStampResp(der, await sha256(sigBytes), o);
        if (r.error !== undefined)
            return { status: "error", verified: false, detail: `imprint matched; TSA signature not verified: ${r.error}` };
        return { status: "ok", verified: true, genTime: r.info.genTime, signer: r.signer, detail: `imprint matched; TSA signature verified (${r.signer})` };
    }
    catch (e) {
        if (e instanceof ImprintError)
            return { status: "mismatch", verified: false, detail: "message imprint does not match SHA-256(sig)" };
        return { status: "error", verified: false, detail: e.message };
    }
}
export const DEFAULT_TSA_URL = "http://ts.ssl.com";
function sameNonce(a, b) {
    const strip = (v) => {
        let x = v;
        while (x.length > 1 && x[0] === 0)
            x = x.subarray(1);
        return x;
    };
    return !!a && a.length > 0 && !(a[0] & 0x80) && bytesEqual(strip(a), strip(b));
}
// most TSAs send no CORS headers, so this usually fails in browsers
export async function requestTimestamp(sigBytes, tsaUrl = DEFAULT_TSA_URL, fetchFn = globalThis.fetch, o = {}) {
    // SPEC 5.5: the imprint is SHA-256 of the raw signature bytes
    const imprint = await sha256(sigBytes);
    const nonce = globalThis.crypto.getRandomValues(new Uint8Array(8));
    const res = await fetchFn(tsaUrl, {
        method: "POST",
        headers: { "Content-Type": "application/timestamp-query" },
        body: buildTimeStampReq(imprint, nonce),
    });
    if (!res.ok)
        throw new Error(`TSA HTTP ${res.status}`);
    const der = new Uint8Array(await res.arrayBuffer());
    // a larger token could not be decoded again by a verifier
    if (der.length > MAX_DECODED_BYTES)
        throw new Error(`TSA response is larger than ${MAX_DECODED_BYTES} bytes`);
    let r;
    try {
        r = await verifyTimeStampResp(der, imprint, o);
    }
    catch (e) {
        throw new Error(`TSA response rejected: ${e.message}`);
    }
    if (r.error !== undefined)
        throw new Error(`TSA response rejected: ${r.error}`);
    // RFC 3161 2.4.2: the nonce binds the response to this request (no replay of an older token)
    if (!sameNonce(r.info.nonce, nonce))
        throw new Error("TSA response rejected: nonce does not match the request");
    return "gzip+base64:" + toBase64(await gzip(der));
}
export { readTsaRoots } from "./tsa-cms.js";
export { DEFAULT_TSA_ROOTS } from "./tsa-roots.js";
