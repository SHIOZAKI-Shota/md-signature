import { fromBase64 } from "./encoding.js";
import { isGitHostingId } from "./identity.js";
import { rawEd25519PublicKey, sshFingerprint, parseSshPublicKeys } from "./crypto.js";
import { es256Spki } from "./webauthn.js";
import { describeAttempts, lookupPgpKey } from "./pgp-verify.js";
import { fetchResource } from "./resources.js";
import { DEFAULT_KEY_DIRECTORIES, directoriesFromRecords, directoryKeyUrl, isKeyDirectoryUrl, parseDirectoryResponse } from "./directory.js";
export function keyTypeFor(alg) {
    return { ed25519: "ed25519", "webauthn-es256": "es256", openpgp: "openpgp" }[alg];
}
export function decodePublicKey(keyType, b) {
    if (keyType === "ed25519")
        return rawEd25519PublicKey(b);
    if (keyType === "es256")
        return es256Spki(b);
    throw new Error(`unsupported key type "${keyType}"`);
}
export class ResolutionError extends Error {
    kind;
    constructor(message, kind) {
        super(message);
        this.kind = kind;
    }
}
export class MemoryTofuStore {
    m = new Map();
    get(s) {
        return this.m.get(s);
    }
    set(s, p) {
        this.m.set(s, p);
    }
}
export const DEFAULT_DOH = ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"];
export function parseDnsRecord(txt) {
    const tags = {};
    for (const part of txt.split(";")) {
        const i = part.indexOf("=");
        if (i < 0)
            continue;
        tags[part.slice(0, i).trim()] = part.slice(i + 1).trim();
    }
    if (tags.v !== "mdsig1" || !tags.p)
        return null;
    return { k: tags.k || "ed25519", p: tags.p };
}
export function dnsName(fields) {
    const domain = fields.signer;
    return fields.selector ? `${fields.selector}._mdsig.${domain}` : `_mdsig.${domain}`;
}
export async function dohTxt(name, opts = {}) {
    const f = opts.fetch ?? globalThis.fetch;
    let lastErr;
    for (const ep of opts.dohEndpoints ?? DEFAULT_DOH) {
        try {
            const res = await f(`${ep}?name=${encodeURIComponent(name)}&type=TXT`, { headers: { Accept: "application/dns-json" } });
            if (!res.ok)
                throw new Error(`HTTP ${res.status}`);
            const j = (await res.json());
            if (j.Status === 3)
                return []; // NXDOMAIN
            if (j.Status !== 0)
                throw new Error(`DNS status ${j.Status}`);
            return (j.Answer ?? []).filter((a) => a.type === 16).map((a) => joinTxt(a.data)); // type 16 = TXT
        }
        catch (e) {
            lastErr = e;
        }
    }
    throw new ResolutionError(`DNS lookup for ${name} failed: ${lastErr?.message}`, "network");
}
// DoH JSON returns TXT data as quoted, possibly split strings
export function joinTxt(data) {
    const parts = data.match(/"((?:[^"\\]|\\.)*)"/g);
    if (!parts)
        return data;
    return parts.map((p) => p.slice(1, -1).replace(/\\(.)/g, "$1")).join("");
}
const alg = (f) => f.alg ?? "";
const keyType = (f) => keyTypeFor(alg(f)) ?? alg(f);
export const resolveDns = async (fields, opts) => {
    if (opts.offline)
        throw new ResolutionError("offline mode", "offline");
    const name = dnsName(fields);
    const records = await dohTxt(name, opts);
    const keys = [];
    for (const r of records) {
        const rec = parseDnsRecord(r);
        if (!rec || rec.k !== keyType(fields))
            continue;
        try {
            keys.push({ alg: rec.k, key: decodePublicKey(rec.k, fromBase64(rec.p)), source: `DNS TXT ${name}` });
        }
        catch {
        }
    }
    if (!keys.length)
        throw new ResolutionError(`no v=mdsig1 k=${keyType(fields)} TXT record at ${name}`, "not-found");
    return {
        keys,
        warnings: ["key resolved from current DNS; it may differ from the key at signing time"],
    };
};
// SPEC 4.2, 3.4: lower-case domain host and user name; isGitHostingId adds the length and all-digit checks
export const GIT_HOSTING_SIGNER_RE = /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\/[a-z0-9][a-z0-9._-]*$/;
export function keysUrl(signer) {
    return `https://${signer}.keys`;
}
export const resolveGitHosting = async (fields, opts) => {
    if (opts.offline)
        throw new ResolutionError("offline mode", "offline");
    const signer = fields.signer;
    if (!isGitHostingId(signer))
        throw new ResolutionError(`invalid git-hosting signer "${signer}"`, "malformed");
    const f = opts.fetch ?? globalThis.fetch;
    const url = keysUrl(signer);
    let text;
    try {
        const res = await f(url);
        if (res.status === 404)
            throw new ResolutionError(`${url}: 404 Not Found`, "not-found");
        if (!res.ok)
            throw new Error(`HTTP ${res.status}`);
        text = await res.text();
    }
    catch (e) {
        if (e instanceof ResolutionError)
            throw e;
        // github.com/<user>.keys sends no CORS headers; in browsers fall back to the REST API, which does.
        const gh = /^github\.com\/(.+)$/i.exec(signer);
        if (!gh)
            throw new ResolutionError(`fetching ${url} failed: ${e.message}`, "network");
        try {
            const res = await f(`https://api.github.com/users/${gh[1]}/keys`, { headers: { Accept: "application/vnd.github+json" } });
            if (res.status === 404)
                throw new ResolutionError(`${url}: 404 Not Found`, "not-found");
            if (!res.ok)
                throw new Error(`HTTP ${res.status}`);
            text = (await res.json()).map((k) => k.key).join("\n");
        }
        catch (e2) {
            if (e2 instanceof ResolutionError)
                throw e2;
            throw new ResolutionError(`fetching ${url} failed: ${e.message}`, "network");
        }
    }
    if (alg(fields) !== "ed25519")
        throw new ResolutionError(`alg ${alg(fields)} is not supported for git-hosting`, "unsupported");
    const keys = [];
    for (const k of parseSshPublicKeys(text)) {
        if (k.type !== "ssh-ed25519" || !k.key)
            continue;
        if (fields.key_fp && (await sshFingerprint(k.key)) !== fields.key_fp)
            continue;
        keys.push({ alg: "ed25519", key: k.key, source: `${url} (${await sshFingerprint(k.key)})` });
    }
    if (!keys.length) {
        throw new ResolutionError(fields.key_fp ? `no ssh-ed25519 key with fingerprint ${fields.key_fp} at ${url}` : `no ssh-ed25519 keys at ${url}`, "not-found");
    }
    return { keys, warnings: ["key list reflects the account's current keys, not the keys at signing time"] };
};
export const resolveTofu = async (fields, opts) => {
    const pk = fields.pubkey;
    if (!pk)
        throw new ResolutionError('tofu block has no "pubkey"', "not-found");
    const i = pk.indexOf(":");
    const kalg = pk.slice(0, i);
    if (i < 0 || kalg !== keyType(fields))
        throw new ResolutionError(`pubkey key type "${kalg}" does not match alg "${alg(fields)}"`, "malformed");
    let key;
    try {
        key = decodePublicKey(kalg, fromBase64(pk.slice(i + 1)));
    }
    catch (e) {
        throw new ResolutionError(`invalid pubkey: ${e.message}`, "malformed");
    }
    // the stored binding is checked and updated by verifyBlock, after the signature has verified
    const warnings = ["tofu: the key is embedded in the document; this proves integrity, not identity"];
    return { keys: [{ alg: kalg, key, source: "embedded pubkey" }], warnings };
};
// SPEC 4.3: keyring, then WKD, then the keyserver; candidate "keys" are whole certificates
export const resolvePgp = async (fields, opts) => {
    const fpr = fields.fpr;
    if (opts.keyserver !== undefined && !/^https:\/\/\S+$/.test(opts.keyserver))
        throw new ResolutionError("keyserver must be an https:// URL", "unsupported");
    const r = await lookupPgpKey(fpr, fields.signer, opts.keyserver, opts);
    const tried = describeAttempts(r.attempts);
    if (!r.cert) {
        const kind = r.attempts.some((a) => a.result === "error") ? (opts.offline ? "offline" : "network") : "not-found";
        throw new ResolutionError(`no OpenPGP key ${fpr} found (${tried})`, kind);
    }
    const warnings = r.attempts.length > 1 ? [`pgp key lookup: ${tried}`] : [];
    if (r.source !== "keyring")
        warnings.push("pgp: the certificate is the current one from " + (r.source === "wkd" ? "WKD" : "the keyserver") + ", not the one at signing time");
    return { keys: [{ alg: "openpgp", key: r.cert, source: `${r.source}${r.url ? " " + r.url : ""}` }], warnings };
};
const MAX_DIRECTORY_BYTES = 64 * 1024;
// SPEC 4.7: the domain's dir= if exactly one, otherwise the verifier's trusted list
export const resolveDirectory = async (fields, opts) => {
    if (opts.offline)
        throw new ResolutionError("offline mode", "offline");
    const email = fields.signer;
    const domain = email.slice(email.lastIndexOf("@") + 1);
    const named = directoriesFromRecords(await dohTxt(`_mdsig.${domain}`, opts));
    if (named.length > 1)
        throw new ResolutionError(`_mdsig.${domain} names ${named.length} different key directories`, "not-found");
    let list;
    if (named.length === 1) {
        list = named;
    }
    else {
        list = [...new Set([...(opts.keyDirectories ?? DEFAULT_KEY_DIRECTORIES), ...(opts.extraKeyDirectories ?? [])].map((d) => d.replace(/\/+$/, "")))];
        const bad = list.find((d) => !isKeyDirectoryUrl(d));
        if (bad)
            throw new ResolutionError(`key directory must be an https:// URL, got "${bad}"`, "unsupported");
    }
    const via = named.length === 1 ? `named by _mdsig.${domain}` : "trusted list";
    const f = opts.fetch ?? globalThis.fetch;
    const kt = keyType(fields);
    const failed = [];
    for (const dir of list) {
        let bytes;
        try {
            bytes = await fetchResource(await directoryKeyUrl(dir, email), f, MAX_DIRECTORY_BYTES);
        }
        catch (e) {
            if (e.message !== "HTTP 404")
                failed.push(`${dir}: ${e.message}`);
            continue;
        }
        let res;
        try {
            res = parseDirectoryResponse(bytes, email);
        }
        catch (e) {
            failed.push(`${dir}: ${e.message}`);
            continue;
        }
        const keys = [];
        for (const k of res?.keys ?? []) {
            if (k.type !== kt)
                continue;
            try {
                keys.push({ alg: kt, key: decodePublicKey(kt, k.key), source: `key directory ${dir} (${via})` });
            }
            catch {
            }
        }
        if (keys.length)
            return { keys, warnings: ["key resolved from the current key directory; it may differ from the key at signing time"] };
    }
    if (failed.length)
        throw new ResolutionError(`key directory lookup failed (${failed.join("; ")})`, "network");
    throw new ResolutionError(`no ${kt} key for ${email} in ${list.join(", ")}`, "not-found");
};
export const DEFAULT_RESOLVERS = {
    dns: resolveDns,
    "git-hosting": resolveGitHosting,
    tofu: resolveTofu,
    pgp: resolvePgp,
    directory: resolveDirectory,
};
