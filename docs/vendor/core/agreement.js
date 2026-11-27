import { ROLE_RE, checkSignerId, decodeKeyValue, isLdhDomain, sameKeyValue } from "./identity.js";
import { parseListLine } from "./listline.js";
export const REQUIRE_METHODS = new Set(["dns", "git-hosting", "tofu", "pgp", "directory"]);
// SPEC 5.8.10: minimum limits every verifier supports
export const MAX_REQUIRE_LINES = 64;
export const MAX_REQUIRE_STEPS = 16;
const REQ_ATTRS = { role: "value", user_verified: "flag", member_of: "value", pubkey: "value" };
const ATTR_ORDER = ["role", "user_verified", "member_of", "pubkey"];
const METHOD_RE = /^[a-z][a-z0-9-]*$/;
const COUNT_RE = /^[1-9][0-9]{0,3}$/;
const USER_VERIFIED_METHODS = new Set(["dns", "directory", "tofu"]);
export function formatRequirement(r) {
    const a = { ...(r.role ? { role: r.role } : {}), ...(r.attributes ?? {}) };
    const parts = [`${r.method}:${r.signer}`];
    for (const k of ATTR_ORDER) {
        const v = a[k];
        if (v === undefined)
            continue;
        parts.push(v === true ? k : `${k}=${v}`);
    }
    return parts.join(" ");
}
// SPEC 5.8.8: https URL without userinfo, fragment, or a port other than 443; the host is an ldh-domain
export function parseRosterRef(v) {
    if (v.startsWith("dns:")) {
        const domain = v.slice(4);
        return isLdhDomain(domain) ? { kind: "dns", domain } : null;
    }
    const m = /^https:\/\/([^/?#@:]*)(?::([0-9]*))?([/?][^#]*)?$/.exec(v);
    if (!m || !isLdhDomain(m[1]))
        return null;
    if (m[2] !== undefined && m[2] !== "443")
        return null;
    return { kind: "https", url: v, host: m[1] };
}
function checkPattern(method, signer) {
    if (signer === "*")
        return method === "tofu" ? "tofu has no patterns" : null;
    if (method === "dns" && signer.startsWith("*.") && isLdhDomain(signer.slice(2)))
        return null;
    if ((method === "directory" || method === "pgp") && signer.startsWith("*@") && isLdhDomain(signer.slice(2)))
        return null;
    return `"${method}:${signer}" is not one of the patterns dns:*, dns:*.<domain>, directory:*, directory:*@<domain>, pgp:*, pgp:*@<domain>, git-hosting:*`;
}
export function parseRequire(value, declaredBy = 0) {
    const errors = [];
    const unsupported = [];
    const hints = [];
    const raws = value.split("\n");
    let order = "pending";
    const steps = [];
    let implicit;
    raws.forEach((raw, i) => {
        const lineNo = i + 1;
        const text = raw.replace(/^ +/, "");
        const word = text.split(" ")[0];
        if (raw.includes("\t"))
            hints.push(`require line ${lineNo}: tabs are not allowed; indent with spaces`);
        if (word === "order") {
            if (/^order (pending|guide|strict)$/.test(text))
                hints.push(`require line ${lineNo}: write "order mode=${text.slice(6)}" (format 0.1)`);
            if (i !== 0)
                return void errors.push(`require line ${lineNo}: "order" must be the first line`);
            const { line, error } = parseListLine(raw, { mode: "value" });
            if (!line)
                return void errors.push(`require line ${lineNo}: ${error}`);
            if (line.unknown.length)
                return void unsupported.push(`require line ${lineNo}: unknown attribute "${line.unknown[0]}"`);
            const mode = line.attrs.get("mode");
            if (mode !== "pending" && mode !== "guide" && mode !== "strict")
                return void errors.push(`require line ${lineNo}: expected "order mode=pending|guide|strict"`);
            order = mode;
            return;
        }
        if (word === "step") {
            const legacy = /^step [1-9][0-9]*(?: any ([1-9][0-9]*))?$/.exec(text);
            if (legacy)
                hints.push(`require line ${lineNo}: write "step${legacy[1] ? ` any=${legacy[1]}` : ""}"; steps are numbered by their position (format 0.1)`);
            if (implicit)
                return void errors.push(`require line ${lineNo}: a requirement line cannot come before the first "step" line`);
            const { line, error } = parseListLine(raw, { any: "value" });
            if (!line)
                return void errors.push(`require line ${lineNo}: ${error}`);
            if (line.unknown.length)
                return void unsupported.push(`require line ${lineNo}: unknown attribute "${line.unknown[0]}"`);
            const any = line.attrs.get("any");
            if (any !== undefined && !COUNT_RE.test(String(any)))
                return void errors.push(`require line ${lineNo}: any= needs a count from 1 to 9999`);
            steps.push({ step: steps.length + 1, any: any === undefined ? null : Number(any), lines: [] });
            return;
        }
        const { line, error } = parseListLine(raw, REQ_ATTRS);
        if (!line)
            return void errors.push(`require line ${lineNo}: ${error}`);
        const target = steps[steps.length - 1] ?? (implicit ??= { step: 1, any: null, lines: [] });
        const c = line.target.indexOf(":");
        const method = c > 0 ? line.target.slice(0, c) : "";
        const signer = c > 0 ? line.target.slice(c + 1) : "";
        if (!METHOD_RE.test(method) || !signer)
            return void errors.push(`require line ${lineNo}: expected "<method>:<signer> [attribute ...]", got ${JSON.stringify(raw)}`);
        if (method === "tsa")
            return void errors.push(`require line ${lineNo}: a tsa block cannot be required`);
        if (line.unknown.length) {
            if (line.unknown.length === 1 && line.attrs.size === 1 && ROLE_RE.test(line.unknown[0]))
                hints.push(`require line ${lineNo}: write the role as "role=${line.unknown[0]}" (format 0.1)`);
            return void unsupported.push(`require line ${lineNo}: unknown attribute "${line.unknown[0]}"`);
        }
        if (!REQUIRE_METHODS.has(method))
            return void unsupported.push(`require line ${lineNo}: unknown method "${method}"`);
        const pattern = signer.includes("*");
        const se = pattern ? checkPattern(method, signer) : checkSignerId(method, signer);
        if (se)
            return void errors.push(`require line ${lineNo}: ${se}`);
        const attributes = {};
        const role = line.attrs.get("role");
        if (role !== undefined) {
            if (!ROLE_RE.test(String(role)))
                return void errors.push(`require line ${lineNo}: role must match [a-z0-9][a-z0-9._-]*`);
            attributes.role = String(role);
        }
        const pubkey = line.attrs.get("pubkey");
        if (pubkey !== undefined) {
            if (method !== "tofu")
                return void errors.push(`require line ${lineNo}: pubkey= is only allowed on tofu lines`);
            const k = decodeKeyValue(String(pubkey));
            if (!k || (k.type !== "ed25519" && k.type !== "es256"))
                return void errors.push(`require line ${lineNo}: pubkey= must be ed25519:<base64> or es256:<base64>`);
            attributes.pubkey = String(pubkey);
        }
        if (line.attrs.has("user_verified")) {
            if (!USER_VERIFIED_METHODS.has(method))
                return void errors.push(`require line ${lineNo}: user_verified is only allowed on dns, directory, and tofu lines`);
            // SPEC 5.8.2: anyone can make a tofu key, so the key has to be pinned
            if (method === "tofu" && !attributes.pubkey)
                return void errors.push(`require line ${lineNo}: user_verified on a tofu line needs pubkey=`);
            attributes.user_verified = true;
        }
        const member = line.attrs.get("member_of");
        if (member !== undefined) {
            if (method === "tofu")
                return void errors.push(`require line ${lineNo}: member_of is not allowed on tofu lines`);
            if (!parseRosterRef(String(member)))
                return void errors.push(`require line ${lineNo}: member_of must be an https URL (no userinfo, fragment, or port other than 443) or dns:<domain>`);
            attributes.member_of = String(member);
        }
        target.lines.push({ method, signer, pattern, attributes, declaredBy, step: target.step, any: target.any, line: lineNo });
    });
    if (implicit)
        steps.push(implicit);
    if (!steps.length && !errors.length && !unsupported.length)
        errors.push("require: no requirement lines");
    for (const s of steps) {
        if (!s.lines.length) {
            if (!unsupported.length)
                errors.push(`require: step ${s.step} has no requirement`);
            continue;
        }
        const hasPattern = s.lines.some((l) => l.pattern);
        const named = new Set(s.lines.map((l) => `${l.method}:${l.signer}`)).size;
        // SPEC 5.8.1 rule 6: m distinct signers must be possible
        if (s.any !== null && !hasPattern && s.any > named)
            errors.push(`require: step ${s.step} asks for any=${s.any} of ${named} different signers`);
        if (s.any === null) {
            // SPEC 5.8.1 rule 7: one signer counts once per step, so two lines only it can fill can never both be met
            const seen = new Set();
            for (const l of s.lines) {
                if (l.pattern)
                    continue;
                const id = `${l.method}:${l.signer}`;
                if (seen.has(id))
                    errors.push(`require: ${id} appears twice in step ${s.step}, which has no any=`);
                seen.add(id);
            }
        }
    }
    // SPEC 5.8.6: anyone can append a block, so under strict a pattern line would let a stranger cause a violation
    if (order === "strict" && steps.some((s) => s.lines.some((l) => l.pattern)))
        errors.push("require: order mode=strict cannot be used with pattern lines");
    const overLimit = raws.length > MAX_REQUIRE_LINES ? `require has ${raws.length} lines (verifiers need to support only ${MAX_REQUIRE_LINES})` : steps.length > MAX_REQUIRE_STEPS ? `require has ${steps.length} steps (verifiers need to support only ${MAX_REQUIRE_STEPS})` : undefined;
    return { spec: { order, steps }, requirements: steps.flatMap((s) => s.lines), errors, unsupported, ...(overLimit ? { overLimit } : {}), hints };
}
const idOf = (f) => `${f.method}:${f.signer}`;
export function targetMatches(r, f) {
    if (f.method !== r.method)
        return false;
    const s = f.signer ?? "";
    if (!r.pattern)
        return s === r.signer;
    if (r.signer === "*")
        return true;
    // SPEC 5.8.3: label boundaries; "*." excludes the domain itself, "*@" excludes subdomains
    if (r.signer.startsWith("*."))
        return s.endsWith(r.signer.slice(1));
    if (r.signer.startsWith("*@"))
        return s.slice(s.lastIndexOf("@")) === r.signer.slice(1);
    return false;
}
// first failing attribute, or null; "role" means the block does not name this line at all
function attributeFailure(r, b, oracle) {
    const a = r.attributes;
    if (a.role !== undefined && b.fields.role !== a.role)
        return "role";
    if (a.pubkey !== undefined && !(b.fields.pubkey !== undefined && sameKeyValue(a.pubkey, b.fields.pubkey)))
        return "key-mismatch";
    if (a.user_verified && !(b.fields.alg === "webauthn-es256" && b.userVerified))
        return "not-user-verified";
    if (a.member_of !== undefined) {
        const m = oracle(a.member_of, idOf(b.fields));
        if (m === "not-member")
            return "not-member";
        if (m === "unavailable")
            return "roster-unavailable";
    }
    return null;
}
const cap = (s, l) => (s.any !== null && l.pattern ? Infinity : 1);
// SPEC Appendix C assign(): edges signer -> line represented by the earliest qualifying block; augmenting paths in canonical order
function matchStep(step, eligible, qualifies) {
    const lines = step.lines;
    const need = step.any ?? lines.length;
    const order = [];
    const rep = new Map();
    const namedEdge = new Set();
    for (const b of eligible) {
        const id = idOf(b.fields);
        if (!rep.has(id)) {
            rep.set(id, lines.map(() => undefined));
            order.push(id);
        }
        const r = rep.get(id);
        lines.forEach((l, j) => {
            if (r[j] === undefined && qualifies(b, l)) {
                r[j] = b.index;
                if (!l.pattern)
                    namedEdge.add(id);
            }
        });
    }
    const assign = (limit) => {
        const owner = lines.map(() => []);
        const lineOf = new Map();
        const augment = (x, seen) => {
            const r = rep.get(x);
            for (let j = 0; j < lines.length; j++) {
                if (r[j] === undefined || r[j] > limit || seen.has(j))
                    continue;
                seen.add(j);
                if (owner[j].length < cap(step, lines[j])) {
                    owner[j].push(x);
                    lineOf.set(x, j);
                    return true;
                }
                for (const y of [...owner[j]]) {
                    if (augment(y, seen)) {
                        owner[j] = owner[j].filter((z) => z !== y).concat(x);
                        lineOf.set(x, j);
                        return true;
                    }
                }
            }
            return false;
        };
        for (const x of order) {
            if (lineOf.size === need)
                break;
            if (rep.get(x).some((p) => p !== undefined && p <= limit))
                augment(x, new Set());
        }
        return lineOf;
    };
    const positions = [...new Set(eligible.map((b) => b.index))].sort((a, b) => a - b);
    let k;
    let final = new Map();
    for (const p of positions) {
        final = assign(p);
        if (final.size === need) {
            k = p;
            break;
        }
    }
    if (k === undefined)
        final = assign(Infinity);
    const assigned = [...final].map(([signer, j]) => ({ signer, line: lines[j], block: rep.get(signer)[j] }));
    assigned.sort((a, b) => a.line.line - b.line.line || a.block - b.block);
    return { ...(k !== undefined ? { k } : {}), assigned, size: final.size, need, namedEdge };
}
const UNDETERMINED_CODES = new Set(["network", "offline"]);
// SPEC 5.8.5, 5.8.6 and Appendix C evaluate()
function evaluateDeclaration(decl, parsed, blocks, oracle) {
    const spec = parsed.spec;
    const d = decl.index;
    const declId = idOf(decl.fields);
    const later = blocks.filter((b) => b.index > d).sort((a, b) => a.index - b.index);
    const used = new Set();
    const missing = [];
    const violations = [];
    const satisfied = [];
    const outcomes = [];
    let prev = d;
    let firstIncomplete;
    const causes = new Set();
    const qualifies = (b, l) => targetMatches(l, b.fields) && !(l.pattern && idOf(b.fields) === declId) && attributeFailure(l, b, oracle) === null;
    // SPEC 5.8.9: the first reason that applies, in this order
    const rejectReason = (b, l, usedBefore, start) => {
        if (b.status !== "valid")
            return "not-valid";
        if (b.fields.scope !== undefined)
            return "scoped";
        if (l.pattern && idOf(b.fields) === declId)
            return "self";
        const f = attributeFailure(l, b, oracle);
        if (f === "role")
            return null;
        if (f)
            return f;
        if (usedBefore.has(b.index))
            return "blocked";
        if (b.index <= start)
            return "early";
        return null;
    };
    for (const s of spec.steps) {
        const start = spec.order === "pending" ? prev : d;
        const eligible = start === Infinity ? [] : later.filter((b) => b.status === "valid" && b.fields.scope === undefined && b.fields.method !== "tsa" && b.index > start && !used.has(b.index));
        const out = matchStep(s, eligible, qualifies);
        outcomes.push(out);
        const done = out.k === undefined ? Infinity : spec.order === "pending" ? out.k : Math.max(out.k, prev);
        const usedBefore = new Set(used);
        for (const a of out.assigned) {
            satisfied.push({ declaredBy: d, step: s.step, line: a.line.line, index: a.block });
            used.add(a.block);
            // SPEC 5.8.6: guide does not report a signer whose edges go only to pattern lines
            if (s.step > 1 && spec.order !== "pending" && a.block < prev && !(spec.order === "guide" && !out.namedEdge.has(a.signer))) {
                violations.push({ declaredBy: d, step: s.step, line: a.line.line, index: a.block, method: a.line.method, signer: later.find((b) => b.index === a.block).fields.signer, order: spec.order });
            }
        }
        if (out.k === undefined) {
            firstIncomplete ??= s.step;
            const assignedSigners = new Set(out.assigned.map((a) => a.signer));
            const filled = new Set(out.assigned.map((a) => a.line));
            for (const l of s.lines) {
                if (filled.has(l) && cap(s, l) !== Infinity)
                    continue;
                const rejected = [];
                for (const b of later) {
                    if (assignedSigners.has(idOf(b.fields)) || !targetMatches(l, b.fields))
                        continue;
                    const reason = rejectReason(b, l, usedBefore, start);
                    if (!reason)
                        continue;
                    rejected.push({ index: b.index, reason });
                    if (reason === "roster-unavailable")
                        causes.add("a roster cannot be obtained");
                    if (reason === "not-valid" && b.status === "unresolved" && UNDETERMINED_CODES.has(b.code ?? ""))
                        causes.add(b.code === "offline" ? "offline" : "network failure");
                }
                const blockedBy = firstIncomplete !== s.step && spec.order !== "guide" ? firstIncomplete : undefined;
                missing.push({ ...l, need: out.need - out.size, ...(blockedBy ? { blockedBy } : {}), rejected });
            }
        }
        prev = done;
    }
    const complete = outcomes.every((o) => o.k !== undefined);
    let status;
    if (spec.order === "strict" && violations.length)
        status = "violated";
    else if (decl.status === "unresolved" && UNDETERMINED_CODES.has(decl.code ?? "")) {
        status = "undetermined";
        causes.add(`the declaring block was not checked (${decl.code})`);
    }
    else if (complete)
        status = "complete";
    else
        status = causes.size ? "undetermined" : "pending";
    let next;
    if (!complete) {
        const idx = firstIncomplete - 1;
        const linesOf = (k) => missing.filter((m) => m.step === k + 1).map(stripMissing);
        const left = (o) => (o.k !== undefined ? 0 : o.need - o.size);
        next = {
            declaredBy: d,
            step: idx + 1,
            need: left(outcomes[idx]),
            candidates: linesOf(idx),
            later: spec.steps.slice(idx + 1).map((s, j) => ({ step: s.step, need: left(outcomes[idx + 1 + j]), lines: linesOf(idx + 1 + j) })),
        };
    }
    return { status, missing, violations, satisfied, next, detail: status === "undetermined" ? [...causes].join("; ") : undefined };
}
const stripMissing = (m) => {
    const { need: _n, blockedBy: _b, rejected: _r, ...r } = m;
    return r;
};
const RANK = { complete: 0, pending: 1, undetermined: 2, unsupported: 3, violated: 4 };
// valid and unresolved blocks declare requirements, so an unchecked chain is never complete
export function evaluateAgreement(blocks, oracle = () => "unavailable") {
    const a = { status: "none", required: [], missing: [], violations: [], next: [], satisfied: [], declarations: [] };
    let worst;
    for (const b of blocks) {
        if ((b.status !== "valid" && b.status !== "unresolved") || !b.fields.require)
            continue;
        const parsed = parseRequire(b.fields.require, b.index);
        if (parsed.errors.length)
            continue;
        a.required.push(...parsed.requirements);
        let status;
        let detail;
        if (parsed.unsupported.length) {
            status = "unsupported";
            detail = parsed.unsupported.join("; ");
        }
        else if (parsed.overLimit) {
            status = "undetermined";
            detail = parsed.overLimit;
        }
        else {
            const r = evaluateDeclaration(b, parsed, blocks, oracle);
            status = r.status;
            detail = r.detail;
            a.missing.push(...r.missing);
            a.violations.push(...r.violations);
            a.satisfied.push(...r.satisfied);
            if (r.next)
                a.next.push(r.next);
        }
        a.declarations.push({ declaredBy: b.index, order: parsed.spec.order, status, ...(detail ? { detail } : {}) });
        if (worst === undefined || RANK[status] > RANK[worst])
            worst = status;
    }
    if (worst)
        a.status = worst;
    return a;
}
// --- member_of candidates (SPEC 5.8): the (roster, signer) pairs a verifier has to look up
export function membershipQueries(blocks) {
    const out = new Map();
    for (const d of blocks) {
        if ((d.status !== "valid" && d.status !== "unresolved") || !d.fields.require)
            continue;
        const parsed = parseRequire(d.fields.require, d.index);
        if (parsed.errors.length || parsed.unsupported.length || parsed.overLimit)
            continue;
        for (const r of parsed.requirements) {
            if (!r.attributes.member_of)
                continue;
            for (const b of blocks) {
                if (b.index <= d.index || b.status !== "valid" || b.fields.scope !== undefined || !targetMatches(r, b.fields))
                    continue;
                const id = idOf(b.fields);
                out.set(`${r.attributes.member_of}\n${id}`, { roster: r.attributes.member_of, id });
            }
        }
    }
    return [...out.values()];
}
