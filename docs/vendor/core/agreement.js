const LINE_RE = /^([a-z][a-z0-9-]*):(\S+)(?: (\S+))?$/;
export function parseRequire(value, declaredBy = 0) {
    const requirements = [];
    const errors = [];
    for (const line of value.split("\n")) {
        const m = LINE_RE.exec(line);
        if (!m) {
            errors.push(`require: expected "<method>:<signer> [role]", got ${JSON.stringify(line)}`);
            continue;
        }
        requirements.push({ method: m[1], signer: m[2], ...(m[3] ? { role: m[3] } : {}), declaredBy });
    }
    return { requirements, errors };
}
export const formatRequirement = (r) => `${r.method}:${r.signer}${r.role ? " " + r.role : ""}`;
// SPEC 5.8/5.9: dns names are case-insensitive, trailing dot ignored
export function sameSigner(method, a, b) {
    return method === "dns" ? a.toLowerCase().replace(/\.$/, "") === b.toLowerCase().replace(/\.$/, "") : a === b;
}
// unresolved blocks still declare requirements, so an unchecked chain is never complete
// SPEC 5.8: a block with scope does not cover the declaring block, so it never satisfies
export function evaluateAgreement(blocks) {
    const required = [];
    for (const b of blocks) {
        if (!(b.declares ?? b.valid) || !b.fields.require)
            continue;
        required.push(...parseRequire(b.fields.require, b.index).requirements);
    }
    if (!required.length)
        return { status: "none", required, missing: [] };
    const missing = required.filter((r) => !blocks.some((b) => b.valid && b.fields.scope === undefined && b.index > r.declaredBy && b.fields.method === r.method && sameSigner(r.method, b.fields.signer ?? "", r.signer) && (!r.role || b.fields.role === r.role)));
    return { status: missing.length ? "pending" : "complete", required, missing };
}
