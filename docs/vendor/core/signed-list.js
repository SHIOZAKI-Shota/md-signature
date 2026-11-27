import { sha256 } from "./crypto.js";
import { utf8 } from "./encoding.js";
import { checkSignerId, isLdhDomain } from "./identity.js";
import { linesWithFence } from "./parser.js";
import { fetchResource } from "./resources.js";
import { ResolutionError, dohTxt } from "./resolvers.js";
import { parseDnsTags } from "./directory.js";
export const SIGNED_LIST_INFO = "mdsig-list";
export const MAX_SIGNED_LIST_BYTES = 10 * 1024 * 1024;
const ENTRY_RE = {
    revocation: /^revoked: sha256:([0-9a-f]{64})$/,
    members: /^member: (\S+)$/,
};
function memberIdOk(id) {
    const c = id.indexOf(":");
    if (c <= 0)
        return false;
    const method = id.slice(0, c);
    if (!/^[a-z][a-z0-9-]*$/.test(method) || method === "tsa")
        return false;
    return checkSignerId(method, id.slice(c + 1)) === null && id.slice(c + 1) !== "";
}
// the entries, or why the list cannot be trusted
export function parseSignedList(body, type) {
    const fences = [];
    let current = null;
    for (const l of linesWithFence(body)) {
        if (l.info !== undefined) {
            current = l.info === SIGNED_LIST_INFO ? { lines: [], closed: false } : null;
            if (current)
                fences.push(current);
            continue;
        }
        if (!current)
            continue;
        if (l.close) {
            current.closed = true;
            current = null;
            continue;
        }
        current.lines.push(l.line);
    }
    if (fences.length !== 1)
        return { ok: false, error: `expected exactly one \`\`\`${SIGNED_LIST_INFO} fence, found ${fences.length}` };
    if (!fences[0].closed)
        return { ok: false, error: `the ${SIGNED_LIST_INFO} fence is not closed` };
    const [first, ...rest] = fences[0].lines;
    if (first !== `type: ${type}`)
        return { ok: false, error: `the list is not "type: ${type}"` };
    const entries = [];
    for (const [i, line] of rest.entries()) {
        const m = ENTRY_RE[type].exec(line);
        if (!m || (type === "members" && !memberIdOk(m[1])))
            return { ok: false, error: `line ${i + 2} of the list is not a valid entry: ${JSON.stringify(line)}` };
        entries.push(m[1]);
    }
    return { ok: true, entries };
}
// SPEC 5.10: https only, 10 MB, cached by URL for one verification call
export function fetchSignedList(url, f, cache) {
    let p = cache.get(url);
    if (!p) {
        p = (async () => {
            try {
                return { ok: true, text: new TextDecoder("utf-8", { fatal: true }).decode(await fetchResource(url, f, MAX_SIGNED_LIST_BYTES)) };
            }
            catch (e) {
                return { ok: false, error: `could not fetch ${url}: ${e.message}` };
            }
        })();
        cache.set(url, p);
    }
    return p;
}
// --- DNS rosters (SPEC 5.8): <label>._member._mdsig.<domain> TXT "v=mdsig1; m=<method:signer>"
const B32 = "abcdefghijklmnopqrstuvwxyz234567";
export function base32LowerNoPad(b) {
    let out = "";
    let bits = 0;
    let acc = 0;
    for (const x of b) {
        acc = (acc << 8) | x;
        bits += 8;
        while (bits >= 5) {
            out += B32[(acc >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    if (bits > 0)
        out += B32[(acc << (5 - bits)) & 31];
    return out;
}
export const MEMBER_LABEL_PREFIX = "md-signature/member/v1";
export async function memberRecordName(id, domain) {
    if (!isLdhDomain(domain))
        throw new Error(`"${domain}" is not a lower-case domain name`);
    const label = base32LowerNoPad(await sha256(utf8(`${MEMBER_LABEL_PREFIX}\n${id}`)));
    return `${label}._member._mdsig.${domain}`;
}
export function memberRecordValue(id) {
    return `v=mdsig1; m=${id}`;
}
// NXDOMAIN, NODATA and records for another m are "not-member"; any other failure is "unavailable"
export async function lookupDnsMember(id, domain, opts) {
    if (opts.offline)
        return "unavailable";
    let records;
    try {
        records = await dohTxt(await memberRecordName(id, domain), opts);
    }
    catch (e) {
        if (e instanceof ResolutionError || e instanceof Error)
            return "unavailable";
        throw e;
    }
    // security: m must name the signer, so wildcard records and synthesized answers never make a member
    return records.some((r) => {
        const t = parseDnsTags(r);
        return t.v === "mdsig1" && t.m === id;
    })
        ? "member"
        : "not-member";
}
