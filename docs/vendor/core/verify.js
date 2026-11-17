import { SUPPORTED_VERSIONS, TS_RE, isValidTimestamp, normalizedBytes, signedPayload, unfoldBinary } from "./canonical.js";
import { digest, ed25519Verify, isSupportedHash, sha256 } from "./crypto.js";
import { fromBase64, toHex, utf8 } from "./encoding.js";
import { parseDocument } from "./parser.js";
import { DEFAULT_RESOLVERS, GIT_HOSTING_SIGNER_RE, ResolutionError, keyTypeFor } from "./resolvers.js";
import { checkTsaToken } from "./tsa.js";
import { scopedHashInput } from "./scope.js";
import { checkResources, parseResources, fetchResource } from "./resources.js";
import { evaluateAgreement, parseRequire, sameSigner } from "./agreement.js";
import { checkWebAuthnData, verifyWebAuthnSignature } from "./webauthn.js";
import { EMAIL_RE, FPR_RE, checkSignaturePacket, verifyPgpSignature } from "./pgp-verify.js";
const SUPPORTED_ALGS = new Set(["ed25519", "webauthn-es256", "openpgp"]);
const WEBAUTHN_KEYS = ["rp_id", "webauthn_authenticator_data", "webauthn_client_data"];
function validateSemantics(f) {
    if (f.expires !== undefined && !isValidTimestamp(f.expires))
        return `expires "${f.expires}" is not a valid YYYY-MM-DDTHH:MM:SSZ date-time`;
    if (f.revocation_url !== undefined && !/^https:\/\/\S+$/.test(f.revocation_url))
        return "revocation_url must be an https:// URL";
    if (f.require !== undefined) {
        const { errors } = parseRequire(f.require, 0, f.v);
        if (errors.length)
            return errors.join("; ");
    }
    if (f.resources !== undefined) {
        const { errors } = parseResources(f.resources);
        if (errors.length)
            return errors.join("; ");
    }
    // SPEC 4.3: method pgp and alg openpgp only go together
    const isPgp = f.method === "pgp";
    if (isPgp !== ((f.alg ?? "ed25519") === "openpgp"))
        return isPgp ? "method pgp requires alg openpgp" : "alg openpgp requires method pgp";
    if (isPgp) {
        if (!f.fpr || !FPR_RE.test(f.fpr))
            return "pgp requires fpr: 40 or 64 upper-case hex digits";
        if (!EMAIL_RE.test(f.signer))
            return "pgp signer must be a lower-case email address";
    }
    if (f.method === "git-hosting" && !GIT_HOSTING_SIGNER_RE.test(f.signer))
        return "git-hosting signer must be <host>/<username> with a domain name as host";
    const isWebAuthn = (f.alg ?? "ed25519") === "webauthn-es256";
    for (const k of WEBAUTHN_KEYS) {
        if (isWebAuthn && f[k] === undefined)
            return `alg webauthn-es256 requires "${k}"`;
        if (!isWebAuthn && f[k] !== undefined)
            return `"${k}" is only allowed with alg webauthn-es256`;
    }
    return null;
}
async function loadRevocationList(url, opts) {
    let text;
    try {
        text = new TextDecoder("utf-8", { fatal: true }).decode(await fetchResource(url, opts.fetch ?? globalThis.fetch, 5 * 1024 * 1024));
    }
    catch (e) {
        return { ok: false, signers: [], revoked: new Set(), error: `could not fetch revocation list: ${e.message}` };
    }
    // SPEC 5.9 step 3: no recursion, no remote resources, no require evaluation.
    const r = await verifyDocument(text, { ...opts, checkRevocation: false, fetchResources: false, loadResource: undefined, revocationCache: undefined, tofuStore: undefined, skipAgreement: true });
    if (!r.ok)
        return { ok: false, signers: [], revoked: new Set(), error: `revocation list does not verify: ${r.error ?? r.signatures.find((s) => s.status !== "valid")?.message ?? "invalid"}` };
    const revoked = new Set();
    const body = parseDocument(text).body;
    for (const m of body.matchAll(/^revoked: sha256:([0-9a-f]{64})[ \t]*$/gm))
        revoked.add(m[1]);
    return {
        ok: true,
        signers: r.signatures.map((s) => ({ method: s.fields.method, signer: s.fields.signer, pubkey: s.fields.pubkey })),
        revoked,
    };
}
// SPEC 5.9: computed from the payload, because sig bytes can be changed without the key
export async function revocationId(fields) {
    return toHex(await sha256(signedPayload(fields)));
}
async function checkRevocation(f, opts) {
    const url = f.revocation_url;
    if (opts.offline)
        return { status: "not-checked", detail: "revocation list not fetched (offline)" };
    if (opts.checkRevocation === false)
        return { status: "not-checked", detail: "revocation check disabled" };
    const cache = opts.revocationCache ?? new Map();
    if (!cache.has(url))
        cache.set(url, loadRevocationList(url, opts));
    const list = await cache.get(url);
    if (!list.ok)
        return { status: "not-checked", detail: list.error, failure: "network" };
    // SPEC 5.9: tofu ids are self-asserted, so the list must come from the same pubkey
    const trusted = list.signers.some((s) => s.method === f.method &&
        sameSigner(f.method, s.signer, f.signer) &&
        (f.method !== "tofu" || s.pubkey === f.pubkey));
    if (!trusted)
        return { status: "not-checked", detail: "revocation list is not signed by this signer", failure: "not-found" };
    const id = await revocationId(f);
    return list.revoked.has(id) ? { status: "revoked", detail: `sha256:${id} is on the signer's revocation list` } : { status: "not-revoked" };
}
export async function verifyBlock(text, block, opts = {}) {
    const f = block.fields;
    const r = { index: block.index, line: block.line, status: "valid", fields: f, warnings: [] };
    const fail = (status, code, message) => Object.assign(r, { status, code, message });
    if (block.unknownKeys?.length)
        return fail("malformed", "unknown-field", block.errors.join("; "));
    if (block.errors.length)
        return fail("malformed", "malformed", block.errors.join("; "));
    if (!SUPPORTED_VERSIONS.has(f.v))
        return fail("unsupported", "unsupported-version", `unsupported version "${f.v}"`);
    if (!TS_RE.test(f.ts))
        r.warnings.push(`ts "${f.ts}" is not in YYYY-MM-DDTHH:MM:SSZ form`);
    const sem = validateSemantics(f);
    if (sem)
        return fail("malformed", "malformed", sem);
    // 1. document hash
    const hi = f.hash.indexOf(":");
    const hashAlg = f.hash.slice(0, hi);
    if (hi < 0 || !isSupportedHash(hashAlg))
        return fail("unsupported", "unsupported-hash", `unsupported hash "${f.hash}"`);
    const slice = text.slice(0, block.start);
    let input;
    if (f.scope !== undefined) {
        const sc = scopedHashInput(slice, f.scope);
        if (!sc.ok)
            return fail(sc.code === "malformed" ? "malformed" : "invalid", sc.code, sc.message);
        input = utf8(sc.input);
        r.partial = { sections: sc.ids };
    }
    else {
        input = normalizedBytes(slice);
    }
    r.computedHash = `${hashAlg}:${toHex(await digest(hashAlg, input))}`;
    // SPEC 5.3: uppercase hex is rejected, not normalised
    r.hashOk = r.computedHash === f.hash.toLowerCase() && f.hash === f.hash.toLowerCase();
    if (!r.hashOk)
        return fail("invalid", "hash-mismatch", r.partial ? "a signed section was modified after this signature" : "document content was modified after this signature");
    // 2. alg and sig encoding
    const alg = f.alg ?? "ed25519";
    if (!SUPPORTED_ALGS.has(alg))
        return fail("unsupported", "unsupported-alg", `unsupported alg "${alg}"`);
    const sigText = unfoldBinary(f.sig);
    if (!sigText.startsWith("base64:"))
        return fail("malformed", "malformed", 'sig must start with "base64:"');
    let sig;
    try {
        sig = fromBase64(sigText.slice(7));
    }
    catch {
        return fail("malformed", "malformed", "sig is not valid base64");
    }
    if (alg === "openpgp") {
        const pre = checkSignaturePacket(sig, f.fpr);
        if (!pre.ok)
            return fail(pre.status, pre.code, pre.message);
    }
    // 3. resolve keys
    const resolver = (opts.resolvers ?? {})[f.method] ?? DEFAULT_RESOLVERS[f.method];
    if (!resolver)
        return fail("unsupported", "unsupported-method", `unknown method "${f.method}"`);
    let keys;
    try {
        const res = await resolver(f, opts);
        keys = res.keys.filter((k) => k.alg === keyTypeFor(alg));
        r.warnings.push(...res.warnings);
    }
    catch (e) {
        if (e instanceof ResolutionError) {
            if (e.kind === "unsupported")
                return fail("unsupported", "unsupported-method", e.message);
            if (e.kind === "malformed")
                return fail("malformed", "malformed", e.message);
            return fail("unresolved", e.kind, e.message);
        }
        return fail("unresolved", "network", e.message);
    }
    // 4. signature
    const payload = signedPayload(f);
    let matched;
    if (alg === "webauthn-es256") {
        const wa = await checkWebAuthnData(f, payload);
        if (wa.info)
            r.webauthn = wa.info;
        if (!wa.ok)
            return fail(wa.code === "malformed" ? "malformed" : "invalid", wa.code, wa.message);
        try {
            for (const k of keys) {
                if (await verifyWebAuthnSignature(k.key, sig, wa.authData, wa.clientData)) {
                    matched = k;
                    break;
                }
            }
        }
        catch (e) {
            return fail("malformed", "malformed", e.message);
        }
        if (wa.info.rpId === "localhost")
            r.warnings.push("webauthn: rp_id is localhost (development signature)");
    }
    else if (alg === "openpgp") {
        const now = Math.floor((opts.now ?? new Date()).getTime() / 1000);
        const certs = keys.map((k) => ({ bytes: k.key, source: k.source.split(" ")[0] }));
        const chk = await verifyPgpSignature(sig, f, payload, certs, now);
        if (chk.info)
            r.pgp = chk.info;
        if (chk.status !== "valid")
            return fail(chk.status, chk.code, chk.message);
        r.warnings.push(...chk.warnings);
        matched = keys.find((k) => k.source.startsWith(chk.info.keySource)) ?? keys[0];
    }
    else {
        for (const k of keys) {
            if (await ed25519Verify(k.key, sig, payload)) {
                matched = k;
                break;
            }
        }
    }
    if (!matched)
        return fail("invalid", "bad-signature", "signature does not verify with the signer's key(s)");
    r.key = { source: matched.source };
    // SPEC 4.4: a stored tofu binding must match, and is only written for a signature that verified
    if (f.method === "tofu" && f.pubkey && opts.tofuStore) {
        const prev = await opts.tofuStore.get(f.signer);
        if (prev !== undefined && prev !== f.pubkey && !opts.acceptNewTofuKey)
            return fail("invalid", "key-changed", `tofu: the key for signer "${f.signer}" differs from the stored one (${prev})`);
        if (prev !== f.pubkey)
            await opts.tofuStore.set(f.signer, f.pubkey);
    }
    // 5. expiry
    if (f.expires && (opts.now ?? new Date()).getTime() > Date.parse(f.expires))
        return fail("invalid", "expired", `signature expired at ${f.expires}`);
    // 6. resources
    if (f.resources) {
        r.resources = await checkResources(parseResources(f.resources).entries, opts);
        const bad = r.resources.find((x) => x.status === "mismatch");
        if (bad)
            return fail("invalid", "resource-mismatch", `resource ${bad.ref} does not match its hash`);
        const missing = r.resources.find((x) => x.status === "missing");
        if (missing)
            return fail("invalid", "resource-missing", `resource ${missing.ref} is missing`);
        const unreachable = r.resources.find((x) => x.status === "unreachable");
        if (unreachable)
            return fail("unresolved", "network", `resource ${unreachable.ref} could not be fetched: ${unreachable.detail}`);
        const unchecked = r.resources.filter((x) => x.status === "not-checked");
        if (unchecked.length)
            r.warnings.push(`${unchecked.length} resource(s) not checked: ${unchecked.map((x) => x.ref).join(", ")}`);
    }
    // 7. revocation
    if (f.revocation_url) {
        r.revocation = await checkRevocation(f, opts);
        if (r.revocation.status === "revoked")
            return fail("invalid", "revoked", `signature was revoked by its signer (${f.revocation_url})`);
        // SPEC 5.9 step 5: blocking the fetch must not hide a revocation
        if (r.revocation.failure)
            return fail("unresolved", r.revocation.failure, `revocation list could not be checked: ${r.revocation.detail}`);
        if (r.revocation.status === "not-checked")
            r.warnings.push(`revocation not checked: ${r.revocation.detail}`);
    }
    // 8. timestamp
    if (f.tsa_token && opts.checkTsa !== false) {
        const tsaOpts = { roots: opts.tsaRoots, extraRoots: opts.extraTsaRoots };
        try {
            r.tsa = await (opts.tsaVerifier ?? checkTsaToken)(unfoldBinary(f.tsa_token), sig, tsaOpts);
        }
        catch (e) {
            r.tsa = { status: "error", verified: false, detail: e.message };
        }
        // SPEC 5.5: a time is evidence only when the token was verified
        if (!r.tsa.verified)
            delete r.tsa.genTime;
        if (r.tsa.status === "mismatch")
            return fail("invalid", "bad-signature", `timestamp token does not match this signature: ${r.tsa.detail}`);
        if (r.tsa.status === "error")
            r.warnings.push(`timestamp could not be checked: ${r.tsa.detail}`);
    }
    if (r.partial)
        r.warnings.push(`partial signature: covers only section(s) ${r.partial.sections.join(", ")}`);
    return r;
}
// SPEC 5.2: every block hashes the document from the start, so the chain length is bounded
export const MAX_CHAIN_BLOCKS = 256;
export async function verifyDocument(text, opts = {}) {
    const doc = parseDocument(text);
    const warnings = [];
    const none = { status: "none", required: [], missing: [], violations: [] };
    if (doc.chain.length > MAX_CHAIN_BLOCKS)
        return { ok: false, signatures: [], agreement: none, warnings, error: `too many signature blocks (${doc.chain.length}; the limit is ${MAX_CHAIN_BLOCKS})` };
    if (doc.chain.length === 0) {
        return {
            ok: false,
            signatures: [],
            agreement: none,
            warnings,
            error: doc.strayMarker
                ? `unsigned content after the last signature (signature block at line ${doc.strayMarkerLine} is followed by other text)`
                : "no signatures found",
        };
    }
    if (doc.strayMarker)
        warnings.push(`line ${doc.strayMarkerLine}: an md-signature marker inside the body is treated as document content, not as a signature`);
    const o = { ...opts, revocationCache: opts.revocationCache ?? new Map() };
    const signatures = [];
    for (const b of doc.chain)
        signatures.push(await verifyBlock(doc.text, b, o));
    const agreement = opts.skipAgreement
        ? none
        : evaluateAgreement(signatures.map((s) => ({ index: s.index, valid: s.status === "valid", declares: s.status === "valid" || s.status === "unresolved", fields: s.fields })));
    // SPEC 5.8: an order violation under "order strict" fails the document
    return { ok: signatures.every((s) => s.status === "valid") && agreement.status !== "violated", signatures, agreement, warnings };
}
