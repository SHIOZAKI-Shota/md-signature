import { concat, bytesEqual, toBase64 } from "./encoding.js";
import { ed25519Verify } from "./crypto.js";
import { PgpError, Reader, encodePacket, encodeSubpacket, leftPad, readPackets, readSubpackets, u16be, u32be, TAG } from "./pgp-packets.js";
const subtle = globalThis.crypto.subtle;
export const HASH = { sha1: 2, sha256: 8, sha384: 9, sha512: 10 };
const HASH_NAMES = { 2: "SHA-1", 8: "SHA-256", 9: "SHA-384", 10: "SHA-512" };
// RFC 9580 Table 23: v6 signature salt sizes
const SALT_SIZE = { 8: 16, 9: 24, 10: 32 };
export const DOCUMENT_HASHES = new Set([8, 9, 10]);
// RFC 9580 9.5: SHA-1 self-signatures are tolerated only if made before 2023-02-01
const SHA1_CUTOFF = 1675209600;
export const SIG = { binary: 0x00, text: 0x01, certGeneric: 0x10, certPositive: 0x13, subkeyBinding: 0x18, primaryBinding: 0x19, directKey: 0x1f, keyRevocation: 0x20, subkeyRevocation: 0x28, certRevocation: 0x30 };
export const SUB = { created: 2, sigExpiry: 3, keyExpiry: 9, issuerKeyId: 16, primaryUid: 25, keyFlags: 27, embedded: 32, issuerFp: 33 };
// Subpackets whose meaning this implementation understands well enough to honour a critical bit.
const UNDERSTOOD = new Set([2, 3, 4, 9, 11, 16, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 37, 39]);
export function hashName(id) {
    return HASH_NAMES[id];
}
export function parseSignature(body) {
    const r = new Reader(body);
    const version = r.u8();
    if (version !== 4 && version !== 6)
        throw new PgpError(`unsupported signature version ${version}`);
    const start = r.o - 1;
    const type = r.u8();
    const pubAlgo = r.u8();
    const hashAlgo = r.u8();
    const hlen = version === 4 ? r.u16() : r.u32();
    const harea = r.bytes(hlen);
    const header = body.subarray(start, r.o);
    const ulen = version === 4 ? r.u16() : r.u32();
    const uarea = r.bytes(ulen);
    const left16 = r.bytes(2);
    let salt = new Uint8Array(0);
    if (version === 6) {
        salt = r.bytes(r.u8());
        if (salt.length !== SALT_SIZE[hashAlgo])
            throw new PgpError("v6 signature salt has the wrong size for its hash");
    }
    let material;
    if (pubAlgo === 1)
        material = [r.mpi()];
    else if (pubAlgo === 19 || pubAlgo === 22)
        material = [r.mpi(), r.mpi()];
    else if (pubAlgo === 27)
        material = [r.bytes(64)];
    else
        material = [r.rest()];
    if (r.left)
        throw new PgpError("trailing data in signature packet");
    return { version, type, pubAlgo, hashAlgo, header, hashed: readSubpackets(harea), unhashed: readSubpackets(uarea), left16, salt, material, raw: body };
}
export function sub(sig, type, hashedOnly = true) {
    return (sig.hashed.find((s) => s.type === type) ?? (hashedOnly ? undefined : sig.unhashed.find((s) => s.type === type)))?.data;
}
const u32 = (b) => ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
export function sigCreated(sig) {
    const d = sub(sig, SUB.created);
    return d?.length === 4 ? u32(d) : undefined;
}
export function sigIssuerFp(sig) {
    const d = sub(sig, SUB.issuerFp, sig.version === 4);
    return d && d.length > 1 ? d.subarray(1) : undefined;
}
export function sigKeyFlags(sig) {
    const d = sub(sig, SUB.keyFlags);
    return d?.length ? d[0] : undefined;
}
export function sigKeyExpiry(sig) {
    const d = sub(sig, SUB.keyExpiry);
    return d?.length === 4 ? u32(d) : undefined;
}
export function unknownCritical(sig) {
    return [...sig.hashed, ...sig.unhashed].find((s) => s.critical && !UNDERSTOOD.has(s.type))?.type;
}
export function embeddedSignatures(sig) {
    const out = [];
    for (const s of [...sig.hashed, ...sig.unhashed]) {
        if (s.type !== SUB.embedded)
            continue;
        try {
            out.push(parseSignature(s.data));
        }
        catch {
        }
    }
    return out;
}
// RFC 9580 5.2.4: salt (v6) || subject || hashed header || version 0xFF u32(header length)
export function hashInput(sig, subject) {
    return concat(sig.salt, subject, sig.header, new Uint8Array([sig.version, 0xff]), u32be(sig.header.length));
}
export function keyPrefix(key) {
    return key.version === 4 ? concat(new Uint8Array([0x99]), u16be(key.publicBody.length), key.publicBody) : concat(new Uint8Array([0x9b]), u32be(key.publicBody.length), key.publicBody);
}
export function uidPrefix(uid) {
    return concat(new Uint8Array([0xb4]), u32be(uid.length), uid);
}
const b64url = (b) => toBase64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
export async function verifyRaw(key, sig, subject) {
    if (sig.pubAlgo !== key.algo || sig.version !== key.version)
        return false;
    const name = HASH_NAMES[sig.hashAlgo];
    if (!name)
        return false;
    const data = hashInput(sig, subject);
    const digest = new Uint8Array(await subtle.digest(name, data));
    if (!bytesEqual(digest.subarray(0, 2), sig.left16))
        return false;
    const m = key.material;
    try {
        if (m.kind === "rsa") {
            const n = m.n;
            const s = leftPad(sig.material[0], n.length);
            if (!s)
                return false;
            const k = await subtle.importKey("jwk", { kty: "RSA", n: b64url(n), e: b64url(m.e), ext: true }, { name: "RSASSA-PKCS1-v1_5", hash: name }, false, ["verify"]);
            return await subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, k, s, data);
        }
        if (m.kind === "ecdsa") {
            const r = leftPad(sig.material[0], 32);
            const s = leftPad(sig.material[1], 32);
            if (!r || !s)
                return false;
            const k = await subtle.importKey("raw", m.point, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
            return await subtle.verify({ name: "ECDSA", hash: name }, k, concat(r, s), data);
        }
        if (m.kind === "ed25519") {
            // OpenPGP EdDSA signs the digest, not the hashed data itself
            let rs;
            if (sig.pubAlgo === 27)
                rs = sig.material[0];
            else {
                const r = leftPad(sig.material[0], 32);
                const s = leftPad(sig.material[1], 32);
                rs = r && s ? concat(r, s) : null;
            }
            return rs ? await ed25519Verify(m.pub, rs, digest) : false;
        }
    }
    catch {
        return false;
    }
    return false;
}
// Checks every rule a self-signature must satisfy apart from the cryptographic check.
export function selfSigUsable(sig, issuer, now) {
    if (unknownCritical(sig) !== undefined)
        return false;
    const created = sigCreated(sig);
    if (created === undefined)
        return false;
    if (sig.hashAlgo === HASH.sha1 ? created >= SHA1_CUTOFF : !DOCUMENT_HASHES.has(sig.hashAlgo))
        return false;
    const exp = sub(sig, SUB.sigExpiry);
    if (exp?.length === 4 && u32(exp) !== 0 && created + u32(exp) <= now)
        return false;
    const fp = sigIssuerFp(sig);
    if (fp && !bytesEqual(fp, issuer.fingerprint))
        return false;
    return true;
}
export async function createSignature(signer, type, subject, o = {}) {
    const key = signer.key;
    const hashAlgo = o.hashAlgo ?? HASH.sha256;
    const name = HASH_NAMES[hashAlgo];
    if (!name)
        throw new PgpError(`unsupported hash ${hashAlgo}`);
    const created = o.created ?? Math.floor(Date.now() / 1000);
    const area = concat(encodeSubpacket(SUB.created, u32be(created)), encodeSubpacket(SUB.issuerFp, concat(new Uint8Array([key.version]), key.fingerprint)), ...(o.hashed ?? []));
    const v = key.version;
    const header = concat(new Uint8Array([v, type, key.algo, hashAlgo]), v === 4 ? u16be(area.length) : u32be(area.length), area);
    const salt = v === 6 ? (o.salt ?? globalThis.crypto.getRandomValues(new Uint8Array(SALT_SIZE[hashAlgo] ?? 16))) : new Uint8Array(0);
    const data = concat(salt, subject, header, new Uint8Array([v, 0xff]), u32be(header.length));
    const digest = new Uint8Array(await subtle.digest(name, data));
    const material = await signer.sign(name, data, digest);
    const unhashed = concat(...(v === 4 ? [encodeSubpacket(SUB.issuerKeyId, key.keyId)] : []), ...(o.unhashed ?? []));
    return concat(header, v === 4 ? u16be(unhashed.length) : u32be(unhashed.length), unhashed, digest.subarray(0, 2), v === 6 ? concat(new Uint8Array([salt.length]), salt) : new Uint8Array(0), material);
}
export function signaturePacket(body) {
    return encodePacket(TAG.signature, body);
}
export function readSignaturePacket(bytes) {
    const packets = readPackets(bytes);
    if (packets.length !== 1 || packets[0].tag !== TAG.signature)
        throw new PgpError("sig must contain exactly one OpenPGP signature packet");
    return parseSignature(packets[0].body);
}
