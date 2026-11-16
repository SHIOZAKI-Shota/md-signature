import { concat, bytesEqual, toBase64 } from "./encoding.js";
import { PKCS8_ED25519_PREFIX } from "./crypto.js";
import { PgpError, Reader, encodeMpi, encodePacket, leftPad, stripLeadingZeros, TAG } from "./pgp-packets.js";
import { checkCert, emailOf, fprHex, keyAlgName, parseCerts, validUids } from "./pgp-keys.js";
import { HASH, SIG, createSignature } from "./pgp-sig.js";
const subtle = globalThis.crypto.subtle;
const b64url = (b) => toBase64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const S2K_HASH = { 2: "SHA-1", 8: "SHA-256", 9: "SHA-384", 10: "SHA-512" };
const AES_KEY_BYTES = { 7: 16, 8: 24, 9: 32 };
function readS2k(r) {
    const type = r.u8();
    if (type === 4)
        throw new PgpError("Argon2-protected OpenPGP keys are not supported in 0.0.1; export the key with an iterated+salted S2K (gpg default)");
    if (type === 101)
        throw new PgpError("the secret key is not in this file (stub for a smartcard or offline key); sign with gpg instead");
    if (type !== 0 && type !== 1 && type !== 3)
        throw new PgpError(`unsupported S2K type ${type}`);
    const hash = r.u8();
    const salt = type === 0 ? new Uint8Array(0) : r.bytes(8);
    const c = type === 3 ? r.u8() : 0;
    return { type, hash, salt, count: type === 3 ? (16 + (c & 15)) << ((c >> 4) + 6) : 0 };
}
async function deriveKey(s2k, pass, len) {
    const name = S2K_HASH[s2k.hash];
    if (!name)
        throw new PgpError(`unsupported S2K hash ${s2k.hash}`);
    const unit = concat(s2k.salt, pass);
    let input = unit;
    if (s2k.type === 3 && s2k.count > unit.length) {
        input = new Uint8Array(s2k.count);
        for (let o = 0; o < s2k.count; o += unit.length)
            input.set(unit.subarray(0, Math.min(unit.length, s2k.count - o)), o);
    }
    const parts = [];
    let have = 0;
    for (let i = 0; have < len; i++) {
        const d = new Uint8Array(await subtle.digest(name, concat(new Uint8Array(i), input)));
        parts.push(d);
        have += d.length;
    }
    if (input !== unit)
        input.fill(0);
    unit.fill(0);
    const out = concat(...parts).slice(0, len);
    for (const p of parts)
        p.fill(0);
    return out;
}
// Web Crypto has no CFB mode. One AES-CBC block with a zero IV is the raw block cipher,
// which is all CFB needs.
async function aesBlockFn(key) {
    const k = await subtle.importKey("raw", key, { name: "AES-CBC" }, false, ["encrypt"]);
    const iv = new Uint8Array(16);
    return async (block) => new Uint8Array(await subtle.encrypt({ name: "AES-CBC", iv }, k, block)).slice(0, 16);
}
export async function cfb(key, iv, data, decrypt) {
    const E = await aesBlockFn(key);
    const out = new Uint8Array(data.length);
    let prev = iv;
    for (let o = 0; o < data.length; o += 16) {
        const ks = await E(prev);
        const chunk = data.subarray(o, o + 16);
        for (let i = 0; i < chunk.length; i++)
            out[o + i] = chunk[i] ^ ks[i];
        prev = (decrypt ? data : out).slice(o, o + 16);
    }
    return out;
}
function readSecretParams(key) {
    const r = new Reader(key.secretPart);
    const usage = r.u8();
    if (usage === 0)
        return { usage, data: r.rest() };
    if (usage === 253)
        throw new PgpError("AEAD-protected OpenPGP keys are not supported in 0.0.1; export the key with gpg (AES + iterated S2K)");
    if (usage !== 254 && usage !== 255)
        throw new PgpError(`unsupported secret key protection ${usage}`);
    if (key.version === 6)
        r.u8();
    const cipher = r.u8();
    if (key.version === 6)
        r.u8();
    const s2k = readS2k(r);
    if (!AES_KEY_BYTES[cipher])
        throw new PgpError(`secret key cipher ${cipher} is not supported (AES only)`);
    return { usage, cipher, s2k, iv: r.bytes(16), data: r.rest() };
}
export function secretIsProtected(key) {
    return key.secretPart !== undefined && key.secretPart[0] !== 0;
}
async function decryptSecret(key, passphrase) {
    const p = readSecretParams(key);
    if (p.usage === 0) {
        // v4 appends a two-octet checksum; v6 does not
        return key.version === 4 ? p.data.slice(0, p.data.length - 2) : p.data.slice();
    }
    if (passphrase === undefined)
        throw new PgpError("this OpenPGP key is protected; a passphrase is required");
    const pass = new TextEncoder().encode(passphrase);
    const k = await deriveKey(p.s2k, pass, AES_KEY_BYTES[p.cipher]);
    pass.fill(0);
    const plain = await cfb(k, p.iv, p.data, true);
    k.fill(0);
    if (p.usage === 254) {
        const body = plain.subarray(0, plain.length - 20);
        const check = new Uint8Array(await subtle.digest("SHA-1", body));
        // RFC 9580 5.5.3: SHA-1 here is an integrity check of the decrypted key, not a signature hash
        const ok = bytesEqual(check, plain.subarray(plain.length - 20));
        check.fill(0);
        if (!ok) {
            plain.fill(0);
            throw new PgpError("wrong passphrase");
        }
        const out = body.slice();
        plain.fill(0);
        return out;
    }
    let sum = 0;
    const body = plain.subarray(0, plain.length - 2);
    for (const b of body)
        sum = (sum + b) & 0xffff;
    if (sum !== ((plain[plain.length - 2] << 8) | plain[plain.length - 1])) {
        plain.fill(0);
        throw new PgpError("wrong passphrase");
    }
    const out = body.slice();
    plain.fill(0);
    return out;
}
async function importSigning(key, material) {
    const r = new Reader(material);
    const m = key.material;
    if (m.kind === "rsa") {
        const d = r.mpi();
        const p = r.mpi();
        const q = r.mpi();
        const u = r.mpi();
        // OpenPGP stores u = p^-1 mod q; naming JWK p := q and q := p makes JWK qi equal to u.
        const big = (b) => BigInt("0x" + (Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("") || "0"));
        const toBytes = (n) => {
            let h = n.toString(16);
            if (h.length % 2)
                h = "0" + h;
            return Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16));
        };
        const D = big(d);
        const P = big(q);
        const Q = big(p);
        const jwk = {
            kty: "RSA", n: b64url(stripLeadingZeros(m.n)), e: b64url(stripLeadingZeros(m.e)), d: b64url(toBytes(D)),
            p: b64url(toBytes(P)), q: b64url(toBytes(Q)), dp: b64url(toBytes(D % (P - 1n))), dq: b64url(toBytes(D % (Q - 1n))), qi: b64url(stripLeadingZeros(u)),
        };
        const keys = new Map();
        const get = async (hash) => {
            if (!keys.has(hash))
                keys.set(hash, await subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash }, false, ["sign"]));
            return keys.get(hash);
        };
        await get("SHA-256");
        return {
            key,
            sign: async (hash, data) => encodeMpi(new Uint8Array(await subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, await get(hash), data))),
        };
    }
    if (m.kind === "ecdsa") {
        const d = leftPad(r.mpi(), 32);
        if (!d)
            throw new PgpError("invalid ECDSA secret key");
        const ck = await subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: b64url(m.point.subarray(1, 33)), y: b64url(m.point.subarray(33)), d: b64url(d) }, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
        d.fill(0);
        return {
            key,
            sign: async (hash, data) => {
                const rs = new Uint8Array(await subtle.sign({ name: "ECDSA", hash }, ck, data));
                return concat(encodeMpi(rs.subarray(0, 32)), encodeMpi(rs.subarray(32)));
            },
        };
    }
    if (m.kind === "ed25519") {
        const seed = key.algo === 27 ? r.bytes(32).slice() : leftPad(r.mpi(), 32);
        if (!seed)
            throw new PgpError("invalid Ed25519 secret key");
        const pkcs8 = concat(PKCS8_ED25519_PREFIX, seed);
        const ck = await subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
        seed.fill(0);
        pkcs8.fill(0);
        return {
            key,
            sign: async (_hash, _data, digest) => {
                const rs = new Uint8Array(await subtle.sign({ name: "Ed25519" }, ck, digest));
                return key.algo === 27 ? rs : concat(encodeMpi(rs.subarray(0, 32)), encodeMpi(rs.subarray(32)));
            },
        };
    }
    throw new PgpError(`OpenPGP key algorithm ${keyAlgName(key)} cannot sign here`);
}
export async function signingKeyFromSecret(key, material) {
    return importSigning(key, material);
}
export async function readPgpSecretKey(input, now = Math.floor(Date.now() / 1000)) {
    const certs = (await parseCerts(input)).filter((c) => c.primary.secretPart !== undefined || c.subkeys.some((s) => s.key.secretPart !== undefined));
    if (!certs.length)
        throw new PgpError("no OpenPGP secret key found");
    const errors = [];
    for (const cert of certs) {
        const candidates = [...cert.subkeys.map((s) => s.key).sort((a, b) => b.created - a.created), cert.primary].filter((k) => k.secretPart !== undefined && !isStub(k));
        for (const k of candidates) {
            const chk = await checkCert(cert, fprHex(k), undefined, now);
            if (!chk.ok) {
                errors.push(chk.message);
                continue;
            }
            const uids = (await validUids(cert, now)).map((u) => u.uid);
            return {
                fpr: fprHex(k),
                primaryFpr: fprHex(cert.primary),
                keyAlg: keyAlgName(k),
                version: k.version,
                uids,
                emails: [...new Set(uids.map(emailOf).filter((e) => !!e))],
                protected: secretIsProtected(k),
                cert,
                key: k,
            };
        }
    }
    throw new PgpError(`no usable signing key in this secret key file${errors.length ? ` (${errors.join("; ")})` : ""}`);
}
function isStub(k) {
    try {
        readSecretParams(k);
        return false;
    }
    catch (e) {
        return /stub/.test(e.message);
    }
}
export async function unlockPgpSecretKey(info, passphrase, o = {}) {
    const material = await decryptSecret(info.key, passphrase);
    let sk;
    try {
        sk = await importSigning(info.key, material);
    }
    finally {
        material.fill(0);
    }
    return {
        alg: "openpgp",
        fpr: info.fpr,
        keyAlg: info.keyAlg,
        uids: info.uids,
        emails: info.emails,
        sign: async (payload) => {
            if (!sk)
                throw new PgpError("this signer has been disposed");
            return encodePacket(TAG.signature, await createSignature(sk, SIG.binary, payload, { hashAlgo: HASH[o.hash ?? "sha256"], created: o.created }));
        },
        dispose: () => {
            sk = null;
        },
    };
}
