import { SUPPORTED_VERSIONS, TS_RE, isValidTimestamp, normalizedBytes, signedPayload, unfoldBinary } from "./canonical.js";
import { digest, ed25519Verify, isSupportedHash, keyFingerprint, sha256, sshFingerprint } from "./crypto.js";
import { bytesEqual, decodePrefixedBinary, fromBase64, toHex, utf8 } from "./encoding.js";
import { parseDocument } from "./parser.js";
import { DEFAULT_RESOLVERS, ResolutionError, decodePublicKey, keyTypeFor } from "./resolvers.js";
import { checkTimestampOver } from "./tsa.js";
import { parseScope, scopedHashInput } from "./scope.js";
import { checkResources, parseResources } from "./resources.js";
import { evaluateAgreement, membershipQueries, parseRequire, parseRosterRef } from "./agreement.js";
import { checkWebAuthnData, verifyWebAuthnSignature } from "./webauthn.js";
import { FPR_RE, checkSignaturePacket, verifyPgpSignature } from "./pgp-verify.js";
import { ROLE_RE, checkDisplayNameLength, checkSignerId, isRpId, isSelector, sameKeyValue } from "./identity.js";
import { fetchSignedList, lookupDnsMember, parseSignedList } from "./signed-list.js";
import { findSignatureMarker } from "./signature-table.js";
const SUPPORTED_ALGS = new Set(["ed25519", "webauthn-es256", "openpgp"]);
const WEBAUTHN_KEYS = ["rp_id", "webauthn_authenticator_data", "webauthn_client_data"];
// SPEC 4.6: a tsa block carries no signer key, so only these fields mean something in it
const TSA_BLOCK_KEYS = new Set(["v", "method", "signer", "ts", "alg", "hash", "sig", "reason"]);
// SPEC 4.5: methods whose block may carry a snapshot of the public key
const KEY_SNAPSHOT_METHODS = new Set(["dns", "git-hosting", "directory"]);
const KNOWN_METHODS = new Set(["dns", "git-hosting", "tofu", "pgp", "directory", "tsa"]);
function validateSemantics(f) {
    // SPEC 4.6: method tsa and alg rfc3161 only go together
    const isTsa = f.method === "tsa";
    if (isTsa !== (f.alg === "rfc3161"))
        return isTsa ? "method tsa requires alg rfc3161" : "alg rfc3161 requires method tsa";
    // SPEC 3.4: signers are compared exactly, so they must already be in canonical form
    if (KNOWN_METHODS.has(f.method)) {
        const se = checkSignerId(f.method, f.signer);
        if (se)
            return se;
    }
    if (isTsa) {
        const extra = Object.keys(f).find((k) => !TSA_BLOCK_KEYS.has(k) && !k.startsWith("x_"));
        if (extra)
            return `field "${extra}" is not allowed with method tsa`;
        return null;
    }
    if (f.selector !== undefined && (f.method !== "dns" || !isSelector(f.selector)))
        return f.method !== "dns" ? "selector is only allowed with method dns" : "selector must be lower-case LDH labels and must not start with \"_\"";
    if (f.role !== undefined && !ROLE_RE.test(f.role))
        return "role must be one word: [a-z0-9][a-z0-9._-]*";
    if (f.display_name !== undefined) {
        const e = checkDisplayNameLength(f.display_name);
        if (e)
            return e;
    }
    // an unknown method is reported as unsupported later, not as a misplaced pubkey
    if (f.pubkey !== undefined && f.method === "pgp")
        return "pubkey is not allowed with method pgp";
    if (f.pubkey !== undefined && (f.method === "tofu" || KEY_SNAPSHOT_METHODS.has(f.method))) {
        const kalg = f.pubkey.includes(":") ? f.pubkey.slice(0, f.pubkey.indexOf(":")) : "";
        const want = keyTypeFor(f.alg);
        // an unknown alg is reported as unsupported later
        if (want && kalg !== want)
            return `pubkey key type "${kalg}" does not match alg "${f.alg}"`;
    }
    if (f.expires !== undefined && !isValidTimestamp(f.expires))
        return `expires "${f.expires}" is not a valid YYYY-MM-DDTHH:MM:SSZ date-time`;
    if (f.revocation_url !== undefined && !/^https:\/\/\S+$/.test(f.revocation_url))
        return "revocation_url must be an https:// URL";
    if (f.scope !== undefined && !parseScope(f.scope))
        return "scope must list one section id per line, each id unique";
    if (f.require !== undefined) {
        const { errors } = parseRequire(f.require, 0);
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
    if (isPgp !== (f.alg === "openpgp"))
        return isPgp ? "method pgp requires alg openpgp" : "alg openpgp requires method pgp";
    if (isPgp && (!f.fpr || !FPR_RE.test(f.fpr)))
        return "pgp requires fpr: 40 or 64 upper-case hex digits";
    const isWebAuthn = f.alg === "webauthn-es256";
    for (const k of WEBAUTHN_KEYS) {
        if (isWebAuthn && f[k] === undefined)
            return `alg webauthn-es256 requires "${k}"`;
        if (!isWebAuthn && f[k] !== undefined)
            return `"${k}" is only allowed with alg webauthn-es256`;
    }
    if (isWebAuthn && !isRpId(f.rp_id))
        return "rp_id must be a lower-case domain name";
    return null;
}
// advice for blocks written in an older format; verdicts do not change (CLI_SPEC, hints)
export function legacyHints(block) {
    const f = block.fields;
    const out = [];
    if (f.v !== undefined && /^0\.0\.[0-9]+$/.test(f.v))
        out.push(`format ${f.v} is not supported by format 0.1 verifiers; verify this document with mdsig v0.0.5`);
    if (f.tsa_token !== undefined || f.tsa_url !== undefined)
        out.push("tsa_token and tsa_url were removed in format 0.1; a timestamp is a separate tsa block (mdsig timestamp)");
    if (f.scope !== undefined && /section:|,/.test(f.scope))
        out.push('scope lists one section id per line without "section:" (format 0.1)');
    if (f.resources !== undefined && /^ *sha256:[0-9a-f]{64} /m.test(f.resources))
        out.push('resources lines are "<ref> hash=sha256:<hex>" (format 0.1)');
    if (f.require !== undefined)
        out.push(...parseRequire(f.require).hints);
    if (block.raw.includes("\t"))
        out.push("tabs are not allowed in a signature block; use spaces");
    return [...new Set(out)].map((h) => `hint: ${h}`);
}
// --- signed lists (SPEC 5.10)
async function loadList(url, opts) {
    const cache = opts.signedListCache ?? new Map();
    let p = cache.get(url);
    if (!p) {
        p = (async () => {
            const fetched = await fetchSignedList(url, opts.fetch ?? globalThis.fetch, new Map());
            if (!fetched.ok)
                return { ok: false, error: fetched.error };
            // SPEC 5.10: no revocation, no resources, no agreement, so a list never leads to another list
            const r = await verifyDocument(fetched.text, { ...opts, checkRevocation: false, fetchResources: false, loadResource: undefined, tofuStore: undefined, skipAgreement: true });
            if (r.error)
                return { ok: true, untrusted: `the list does not verify: ${r.error}` };
            return { ok: true, body: parseDocument(fetched.text).body, signatures: r.signatures };
        })();
        cache.set(url, p);
    }
    return p;
}
// SPEC 5.10: trusted only with a valid unscoped block from the expected issuer
async function trustedList(url, type, isIssuer, opts) {
    const l = await loadList(url, opts);
    if (!l.ok)
        return { ok: false, failure: "network", error: l.error };
    if (l.untrusted)
        return { ok: false, failure: "not-found", error: `${url}: ${l.untrusted}` };
    if (!l.signatures.some((s) => s.status === "valid" && s.fields.scope === undefined && isIssuer(s)))
        return { ok: false, failure: "not-found", error: `${url} is not signed by the expected issuer` };
    const p = parseSignedList(l.body, type);
    if (!p.ok)
        return { ok: false, failure: "not-found", error: `${url}: ${p.error}` };
    return { ok: true, entries: new Set(p.entries) };
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
    // SPEC 5.9: same method:signer; tofu ids are self-asserted, so also the same key
    const list = await trustedList(url, "revocation", (s) => s.fields.method === f.method && s.fields.signer === f.signer && (f.method !== "tofu" || (!!s.fields.pubkey && sameKeyValue(s.fields.pubkey, f.pubkey ?? ""))), opts);
    if (!list.ok)
        return { status: "not-checked", detail: list.error, failure: list.failure };
    const id = await revocationId(f);
    return list.entries.has(id) ? { status: "revoked", detail: `sha256:${id} is on the signer's revocation list` } : { status: "not-revoked" };
}
// --- rosters (SPEC 5.8 member_of)
export const MAX_ROSTERS = 8;
export const MAX_ROSTER_QUERIES = 256;
async function lookupMemberships(queries, opts, warnings) {
    const out = new Map();
    const key = (roster, id) => `${roster}\n${id}`;
    const rosters = [...new Set(queries.map((q) => q.roster))];
    if (opts.offline) {
        for (const q of queries)
            out.set(key(q.roster, q.id), "unavailable");
        if (queries.length)
            warnings.push("member_of: rosters not consulted (offline)");
        return out;
    }
    // SPEC 5.8.10: 8 https roster URLs and 256 lookups (URL fetches and DNS queries together); beyond that the agreement is undetermined
    const httpsRosters = rosters.filter((r) => r.startsWith("https:")).length;
    const lookups = httpsRosters + queries.filter((q) => q.roster.startsWith("dns:")).length;
    if (httpsRosters > MAX_ROSTERS || lookups > MAX_ROSTER_QUERIES) {
        warnings.push(`member_of: ${httpsRosters} roster URLs and ${lookups} lookups exceed the limits (${MAX_ROSTERS} URLs, ${MAX_ROSTER_QUERIES} lookups)`);
        for (const q of queries)
            out.set(key(q.roster, q.id), "unavailable");
        return out;
    }
    for (const roster of rosters) {
        const ref = parseRosterRef(roster);
        const ids = queries.filter((q) => q.roster === roster).map((q) => q.id);
        if (ref.kind === "dns") {
            for (const id of ids)
                out.set(key(roster, id), await lookupDnsMember(id, ref.domain, opts));
            continue;
        }
        // SPEC 5.8.8: the issuer is the host of the URL as written, not of a redirect target
        const list = await trustedList(ref.url, "members", (s) => s.fields.method === "dns" && s.fields.signer === ref.host, opts);
        if (!list.ok)
            warnings.push(`member_of: roster ${roster} cannot be used: ${list.error}`);
        for (const id of ids)
            out.set(key(roster, id), list.ok ? (list.entries.has(id) ? "member" : "not-member") : "unavailable");
    }
    return out;
}
// --- blocks
export async function verifyBlock(text, block, opts = {}) {
    const f = block.fields;
    const r = { index: block.index, line: block.line, status: "valid", fields: f, warnings: [] };
    const fail = (status, code, message) => {
        if (status === "malformed" || status === "unsupported")
            r.warnings.push(...legacyHints(block));
        return Object.assign(r, { status, code, message });
    };
    // SPEC 5.4 step 1: an unknown version comes first, so fields added by later formats read as "unsupported", not "malformed"
    if (f.v !== undefined && !block.errors.includes(`duplicate key "v"`) && !SUPPORTED_VERSIONS.has(f.v))
        return fail("unsupported", "unsupported-version", `unsupported version "${f.v}"`);
    if (block.unknownKeys?.length)
        return fail("malformed", "unknown-field", block.errors.join("; "));
    if (block.errors.length)
        return fail("malformed", "malformed", block.errors.join("; "));
    if (!TS_RE.test(f.ts))
        r.warnings.push(`ts "${f.ts}" is not in YYYY-MM-DDTHH:MM:SSZ form`);
    const sem = validateSemantics(f);
    if (sem)
        return fail("malformed", "malformed", sem);
    // SPEC 5.7: a resource hash prefix this version does not define
    const resHash = f.resources !== undefined ? parseResources(f.resources).unsupportedHash : undefined;
    if (resHash)
        return fail("unsupported", "unsupported-hash", `unsupported resource hash "${resHash}"`);
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
    // SPEC 5.3: uppercase hex is rejected, not normalized
    r.hashOk = r.computedHash === f.hash.toLowerCase() && f.hash === f.hash.toLowerCase();
    if (!r.hashOk)
        return fail("invalid", "hash-mismatch", r.partial ? "a signed section was modified after this signature" : "document content was modified after this signature");
    // SPEC 4.6: a tsa block is checked against its token; there is no key to resolve
    if (f.method === "tsa")
        return verifyTsaBlock(r, f, hashAlg, opts, fail);
    // 2. alg and sig encoding
    const alg = f.alg;
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
    const payload = signedPayload(f);
    let webauthnData;
    if (alg === "webauthn-es256") {
        const wa = await checkWebAuthnData(f, payload);
        if (wa.info)
            r.webauthn = wa.info;
        if (!wa.ok)
            return fail(wa.code === "malformed" ? "malformed" : "invalid", wa.code, wa.message);
        webauthnData = { authData: wa.authData, clientData: wa.clientData };
        if (wa.info.rpId === "localhost")
            r.warnings.push("webauthn: rp_id is localhost (development signature)");
    }
    // ed25519 and webauthn-es256; a string is a malformed signature
    const findKey = async (cands) => {
        try {
            for (const k of cands) {
                if (webauthnData ? await verifyWebAuthnSignature(k.key, sig, webauthnData.authData, webauthnData.clientData) : await ed25519Verify(k.key, sig, payload))
                    return k;
            }
        }
        catch (e) {
            return e.message;
        }
        return undefined;
    };
    // SPEC 4.5: a key snapshot is checked first, so a bad signature is invalid even when the published key cannot be reached
    let snapshot;
    if (f.pubkey !== undefined && KEY_SNAPSHOT_METHODS.has(f.method)) {
        const s = await keySnapshot(f, alg);
        if (typeof s === "string")
            return fail("malformed", "malformed", s);
        const m = await findKey([s]);
        if (typeof m === "string")
            return fail("malformed", "malformed", m);
        if (!m)
            return fail("invalid", "bad-signature", "signature does not verify with the embedded key");
        snapshot = s;
    }
    // 3. resolve keys
    const resolver = (opts.resolvers ?? {})[f.method] ?? DEFAULT_RESOLVERS[f.method];
    if (!resolver)
        return fail("unsupported", "unsupported-method", `unknown method "${f.method}"`);
    let keys = [];
    let notPublished;
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
            if (e.kind === "not-found" && snapshot)
                notPublished = e.message;
            else
                return fail("unresolved", e.kind, e.message);
        }
        else
            return fail("unresolved", "network", e.message);
    }
    if (snapshot) {
        const published = keys.find((k) => bytesEqual(k.key, snapshot.key));
        if (published)
            keys = [published];
        else {
            notPublished ??= `${f.signer} does not publish the embedded key now`;
            keys = [snapshot];
        }
    }
    // 4. signature
    let matched;
    if (alg === "openpgp") {
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
        const m = await findKey(keys);
        if (typeof m === "string")
            return fail("malformed", "malformed", m);
        matched = m;
    }
    if (!matched)
        return fail("invalid", "bad-signature", snapshot ? "signature does not verify with the embedded key" : "signature does not verify with the signer's key(s)");
    r.key = { source: matched.source };
    // SPEC 4.4: a stored tofu binding must match, and is only written once the whole block verified
    let tofuStatus;
    const pending = PENDING_TOFU.get(opts);
    if (f.method === "tofu" && f.pubkey && opts.tofuStore) {
        // SPEC 4.4: an unconfirmed key from an earlier block of this document counts as recorded for the blocks after it
        const unconfirmed = pending?.get(f.signer);
        const prev = unconfirmed ?? (await opts.tofuStore.get(f.signer));
        if (prev !== undefined && prev !== f.pubkey && !opts.acceptNewTofuKey)
            return fail("invalid", "key-changed", `tofu: the key for signer "${f.signer}" differs from the ${unconfirmed ? "one in an earlier signature" : "stored one"} (${prev})`);
        tofuStatus = prev === undefined || (unconfirmed !== undefined && unconfirmed === f.pubkey) ? "new" : prev === f.pubkey ? "known" : "replaced";
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
        // SPEC 5.9 step 4: blocking the fetch must not hide a revocation
        if (r.revocation.failure)
            return fail("unresolved", r.revocation.failure, `revocation list could not be checked: ${r.revocation.detail}`);
        if (r.revocation.status === "not-checked")
            r.warnings.push(`revocation not checked: ${r.revocation.detail}`);
    }
    if (r.partial)
        r.warnings.push(`partial signature: covers only section(s) ${r.partial.sections.join(", ")}`);
    // SPEC 4.5: the signature holds with the embedded key, but nobody vouches for that key now; verifyDocument adds T(k)
    if (notPublished)
        return fail("unresolved", "key-not-published", `the signature verifies with the embedded key, which ${f.signer} does not publish now (${notPublished})`);
    if (tofuStatus) {
        r.tofu = { status: tofuStatus, fingerprint: await keyFingerprint(f.pubkey) };
        if (tofuStatus === "new" && opts.confirmNewTofuKeys)
            pending?.set(f.signer, f.pubkey);
        else if (tofuStatus !== "known")
            await opts.tofuStore.set(f.signer, f.pubkey);
    }
    return r;
}
async function keySnapshot(f, alg) {
    const pk = f.pubkey;
    const i = pk.indexOf(":");
    const kalg = i < 0 ? "" : pk.slice(0, i);
    if (kalg !== keyTypeFor(alg))
        return `pubkey key type "${kalg}" does not match alg "${alg}"`;
    let key;
    try {
        key = decodePublicKey(kalg, fromBase64(pk.slice(i + 1)));
    }
    catch (e) {
        return `invalid pubkey: ${e.message}`;
    }
    // SPEC 4.2: key_fp names a key, so it has to name this one
    if (f.method === "git-hosting" && f.key_fp !== undefined && kalg === "ed25519" && (await sshFingerprint(key)) !== f.key_fp)
        return "key_fp does not match the embedded pubkey";
    return { alg: kalg, key, source: "embedded pubkey" };
}
async function verifyTsaBlock(r, f, hashAlg, opts, fail) {
    let token;
    try {
        await decodePrefixedBinary(unfoldBinary(f.sig));
        token = unfoldBinary(f.sig);
    }
    catch (e) {
        return fail("malformed", "malformed", `sig is not a timestamp token: ${e.message}`);
    }
    const tsaOpts = { roots: opts.tsaRoots, extraRoots: opts.extraTsaRoots };
    const payload = signedPayload(f);
    // SPEC 4.6: the token's imprint is the digest of the signed payload, with the block's hash algorithm
    try {
        r.tsa = opts.tsaVerifier
            ? await opts.tsaVerifier(token, payload, { ...tsaOpts, hash: hashAlg })
            : await checkTimestampOver(token, await digest(hashAlg, payload), hashAlg, tsaOpts, `message imprint does not match ${hashAlg.toUpperCase()}(payload)`);
    }
    catch (e) {
        r.tsa = { status: "error", verified: false, detail: e.message };
    }
    // SPEC 4.6: a time is evidence only when the token was verified
    if (!r.tsa.verified) {
        delete r.tsa.genTime;
        delete r.tsa.accuracyMs;
    }
    if (r.tsa.status === "mismatch")
        return fail("invalid", "bad-signature", `timestamp token does not cover this block: ${r.tsa.detail}`);
    if (r.tsa.status === "error" || !r.tsa.verified) {
        // a token whose imprint matched but whose TSA cannot be trusted is unresolved, like a key that was not found
        if (r.tsa.detail.startsWith("imprint matched") || r.tsa.status === "ok")
            return fail("unresolved", "not-found", `timestamp could not be verified: ${r.tsa.detail}`);
        // an outside verifier that fails says nothing about the token
        if (opts.tsaVerifier)
            return fail("unresolved", "network", `timestamp could not be verified: ${r.tsa.detail}`);
        return fail("invalid", "bad-signature", `timestamp token is unusable: ${r.tsa.detail}`);
    }
    r.key = { source: `TSA ${r.tsa.signer}` };
    return r;
}
// --- T(k) (SPEC 4.6)
// milliseconds since the epoch; a fraction finer than 1 ms is rounded up, so the bound stays an upper bound
export function genTimeMs(genTime) {
    const m = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z$/.exec(genTime);
    if (!m)
        return NaN;
    const base = Date.parse(m[1] + "Z");
    const frac = m[2] ?? "";
    const ms = Number((frac + "000").slice(0, 3));
    const rest = /[1-9]/.test(frac.slice(3)) ? 1 : 0;
    return base + ms + rest;
}
export function formatTimeMs(ms) {
    const s = new Date(ms).toISOString();
    return s.endsWith(".000Z") ? s.replace(/\.000Z$/, "Z") : s;
}
function blockTimes(sigs) {
    for (const k of sigs) {
        let best;
        let bestMs = Infinity;
        for (const j of sigs) {
            if (j.index <= k.index || j.fields.method !== "tsa" || j.status !== "valid" || !j.tsa?.verified || !j.tsa.genTime)
                continue;
            const t = genTimeMs(j.tsa.genTime) + (j.tsa.accuracyMs ?? 0);
            if (t < bestMs) {
                bestMs = t;
                best = { at: formatTimeMs(t), block: j.index, genTime: j.tsa.genTime, accuracyMs: j.tsa.accuracyMs ?? 0, ...(j.tsa.signer ? { signer: j.tsa.signer } : {}) };
            }
        }
        if (best)
            k.time = best;
    }
}
// SPEC 5.2: every block hashes the document from the start, so the chain length is bounded
export const MAX_CHAIN_BLOCKS = 256;
const PENDING_TOFU = new WeakMap();
export async function verifyDocument(text, opts = {}) {
    const doc = parseDocument(text);
    const warnings = [];
    const none = { status: "none", required: [], missing: [], violations: [], next: [], satisfied: [], declarations: [] };
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
    // SPEC 5.5: a renderer shows every block of such a document as code
    if (doc.unclosedFence)
        warnings.push("the body ends inside an open code fence, so Markdown renderers show the signature blocks as code");
    warnings.push(...findSignatureMarker(doc.body).warnings);
    const o = { ...opts, signedListCache: opts.signedListCache ?? new Map() };
    if (o.tofuStore && o.confirmNewTofuKeys)
        PENDING_TOFU.set(o, new Map());
    const signatures = [];
    for (const b of doc.chain)
        signatures.push(await verifyBlock(doc.text, b, o));
    if (o.checkTsa !== false)
        blockTimes(signatures);
    for (const s of signatures) {
        if (s.code === "key-not-published" && s.time)
            s.message += `; the signature existed at ${s.time.at} (TSA, block #${s.time.block})`;
    }
    let agreement = none;
    if (!opts.skipAgreement) {
        const blocks = signatures.map((s) => ({ index: s.index, status: s.status, code: s.code, fields: s.fields, userVerified: s.webauthn?.userVerified }));
        const memberships = await lookupMemberships(membershipQueries(blocks), o, warnings);
        agreement = evaluateAgreement(blocks, (roster, id) => memberships.get(`${roster}\n${id}`) ?? "unavailable");
    }
    // SPEC 5.4, 5.8.9: a violated, undetermined, or unsupported agreement is not a success
    const ok = signatures.every((s) => s.status === "valid") && !["violated", "undetermined", "unsupported"].includes(agreement.status);
    return { ok, signatures, agreement, warnings };
}
