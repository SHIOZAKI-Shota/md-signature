import { concat, fromBase64, toBase64, toBase64Unpadded, utf8, bytesEqual } from "./encoding.js";
const subtle = globalThis.crypto.subtle;
// DER headers for Ed25519 (OID 1.3.101.112): PKCS#8 + 32-byte seed, SPKI + 32-byte key
export const PKCS8_ED25519_PREFIX = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);
const SPKI_ED25519_PREFIX = new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
export function isSupportedHash(alg) {
    return alg === "sha256" || alg === "sha512";
}
export async function digest(alg, data) {
    const name = alg === "sha256" ? "SHA-256" : "SHA-512";
    return new Uint8Array(await subtle.digest(name, data));
}
export const sha256 = (data) => digest("sha256", data);
export function rawEd25519PublicKey(b) {
    if (b.length === 32)
        return b;
    if (b.length === 44 && bytesEqual(b.subarray(0, 12), SPKI_ED25519_PREFIX))
        return b.subarray(12);
    throw new Error(`not an Ed25519 public key (length ${b.length})`);
}
export async function ed25519Verify(publicKey, signature, data) {
    if (signature.length !== 64)
        return false;
    const key = await subtle.importKey("raw", rawEd25519PublicKey(publicKey), { name: "Ed25519" }, false, ["verify"]);
    return subtle.verify({ name: "Ed25519" }, key, signature, data);
}
export async function signerFromSeed(seed) {
    if (seed.length !== 32)
        throw new Error("Ed25519 seed must be 32 bytes");
    const pkcs8 = concat(PKCS8_ED25519_PREFIX, seed);
    const key = await subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"]);
    // a PKCS#8 import exposes no public key; recover it from the JWK
    const jwk = await subtle.exportKey("jwk", key);
    const publicKey = fromBase64(jwk.x.replace(/-/g, "+").replace(/_/g, "/"));
    return {
        alg: "ed25519",
        publicKey,
        sign: async (data) => new Uint8Array(await subtle.sign({ name: "Ed25519" }, key, data)),
    };
}
export async function generateEd25519() {
    const seed = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const signer = await signerFromSeed(seed);
    return { seed, publicKey: signer.publicKey, signer };
}
// --- OpenSSH formats
class SshReader {
    o = 0;
    b;
    constructor(b) {
        this.b = b;
    }
    u32() {
        if (this.o + 4 > this.b.length)
            throw new Error("truncated SSH data");
        const v = ((this.b[this.o] << 24) | (this.b[this.o + 1] << 16) | (this.b[this.o + 2] << 8) | this.b[this.o + 3]) >>> 0;
        this.o += 4;
        return v;
    }
    bytes() {
        const n = this.u32();
        if (this.o + n > this.b.length)
            throw new Error("truncated SSH data");
        const v = this.b.subarray(this.o, this.o + n);
        this.o += n;
        return v;
    }
    str() {
        return new TextDecoder().decode(this.bytes());
    }
    raw(n) {
        const v = this.b.subarray(this.o, this.o + n);
        this.o += n;
        return v;
    }
}
function sshString(b) {
    const n = b.length;
    return concat(new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]), b);
}
export function sshEd25519Blob(publicKey) {
    return concat(sshString(utf8("ssh-ed25519")), sshString(rawEd25519PublicKey(publicKey)));
}
export function formatSshPublicKey(publicKey, comment = "") {
    return `ssh-ed25519 ${toBase64(sshEd25519Blob(publicKey))}${comment ? " " + comment : ""}`;
}
export async function sshFingerprint(publicKey) {
    return "SHA256:" + toBase64Unpadded(await sha256(sshEd25519Blob(publicKey)));
}
// CLI_SPEC 3.9: OpenSSH form for a 32-byte ed25519 key, otherwise SHA-256 of the decoded pubkey bytes
export async function keyFingerprint(pubkey) {
    const i = pubkey.indexOf(":");
    const bytes = fromBase64(pubkey.slice(i + 1));
    if (pubkey.slice(0, i) === "ed25519" && bytes.length === 32)
        return sshFingerprint(bytes);
    return "SHA256:" + toBase64Unpadded(await sha256(bytes));
}
export function parseSshPublicKeys(text) {
    const out = [];
    for (const line of text.split(/\r?\n/)) {
        const t = line.trim();
        if (!t || t.startsWith("#"))
            continue;
        const parts = t.split(/\s+/);
        if (parts.length < 2)
            continue;
        try {
            const blob = fromBase64(parts[1]);
            const r = new SshReader(blob);
            const type = r.str();
            if (type !== parts[0])
                continue;
            const entry = { type, blob, comment: parts.slice(2).join(" ") };
            if (type === "ssh-ed25519")
                entry.key = r.bytes();
            out.push(entry);
        }
        catch {
        }
    }
    return out;
}
export function parseOpenSshPrivateKey(pem) {
    const m = pem.match(/-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]+?)-----END OPENSSH PRIVATE KEY-----/);
    if (!m)
        throw new Error("not an OpenSSH private key");
    const data = fromBase64(m[1]);
    const magic = utf8("openssh-key-v1\0");
    if (!bytesEqual(data.subarray(0, magic.length), magic))
        throw new Error("bad OpenSSH key magic");
    const r = new SshReader(data.subarray(magic.length));
    const cipher = r.str();
    r.str(); // kdfname
    r.bytes(); // kdfoptions
    if (cipher !== "none")
        throw new Error("encrypted OpenSSH keys are not supported here; decrypt first or use an ssh-agent");
    if (r.u32() !== 1)
        throw new Error("multiple keys in one file are not supported");
    r.bytes(); // public key blob
    const priv = new SshReader(r.bytes());
    if (priv.u32() !== priv.u32())
        throw new Error("OpenSSH key checkint mismatch");
    const type = priv.str();
    if (type !== "ssh-ed25519")
        throw new Error(`unsupported key type: ${type}`);
    const publicKey = priv.bytes();
    const sk = priv.bytes();
    const comment = priv.str();
    return { seed: sk.subarray(0, 32), publicKey, comment };
}
export function formatOpenSshPrivateKey(seed, publicKey, comment = "") {
    const blob = sshEd25519Blob(publicKey);
    const check = globalThis.crypto.getRandomValues(new Uint8Array(4));
    let privSection = concat(check, check, sshString(utf8("ssh-ed25519")), sshString(publicKey), sshString(concat(seed, publicKey)), sshString(utf8(comment)));
    const pad = [];
    for (let i = 1; (privSection.length + pad.length) % 8 !== 0; i++)
        pad.push(i);
    privSection = concat(privSection, new Uint8Array(pad));
    const body = concat(utf8("openssh-key-v1\0"), sshString(utf8("none")), sshString(utf8("none")), sshString(new Uint8Array(0)), new Uint8Array([0, 0, 0, 1]), sshString(blob), sshString(privSection));
    const b64 = toBase64(body).replace(/(.{70})/g, "$1\n").trimEnd();
    return `-----BEGIN OPENSSH PRIVATE KEY-----\n${b64}\n-----END OPENSSH PRIVATE KEY-----\n`;
}
