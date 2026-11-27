const str = (s) => (s ? s : null);
export function tsaToJson(c) {
    return { status: c.status, verified: c.verified, signer: str(c.signer), gen_time: str(c.genTime), detail: c.detail };
}
export function tsaFromJson(j) {
    const c = { status: j.status, verified: j.verified === true, detail: String(j.detail ?? "") };
    if (j.signer)
        c.signer = j.signer;
    // SPEC 4.6: a time is reported only for a verified token, whatever the other side sent
    if (c.verified && j.gen_time)
        c.genTime = j.gen_time;
    return c;
}
export function requirementToJson(r) {
    return { declared_by: r.declaredBy, step: r.step, any: r.any, line: r.line, method: r.method, signer: r.signer, pattern: r.pattern, attributes: { ...r.attributes } };
}
function missingRequirement(r) {
    const out = { ...requirementToJson(r), need: r.need, rejected: r.rejected.map((x) => ({ index: x.index, reason: x.reason })) };
    if (r.blockedBy)
        out.blocked_by = r.blockedBy;
    return out;
}
function violation(v) {
    return { declared_by: v.declaredBy, step: v.step, line: v.line, index: v.index, method: v.method, signer: v.signer, order: v.order };
}
function next(n) {
    return { declared_by: n.declaredBy, step: n.step, need: n.need, candidates: n.candidates.map(requirementToJson), later: n.later.map((l) => ({ step: l.step, need: l.need, lines: l.lines.map(requirementToJson) })) };
}
export function agreementToJson(a) {
    return {
        status: a.status,
        required: a.required.map(requirementToJson),
        missing: a.missing.map(missingRequirement),
        violations: a.violations.map(violation),
        next: a.next.map(next),
        satisfied: a.satisfied.map((s) => ({ declared_by: s.declaredBy, step: s.step, line: s.line, index: s.index })),
        declarations: a.declarations.map((d) => ({ declared_by: d.declaredBy, order: d.order, status: d.status, detail: d.detail ?? null })),
    };
}
function tsaOf(s) {
    const t = s.time;
    if (s.tsa)
        return { ...tsaToJson(s.tsa), time: t?.at ?? null, block: t?.block ?? null };
    // SPEC 4.6: a signature block reports T(k) from the tsa blocks after it
    if (!t)
        return null;
    return { status: "ok", verified: true, signer: str(t.signer), gen_time: t.genTime, detail: `covered by tsa block #${t.block}`, time: t.at, block: t.block };
}
function signature(s) {
    return {
        index: s.index,
        line: s.line,
        status: s.status,
        code: str(s.code),
        message: str(s.message),
        fields: s.fields ?? {},
        display_name: str(s.fields?.display_name),
        hash_ok: s.hashOk ?? null,
        partial: s.partial ? { sections: s.partial.sections } : null,
        key_source: str(s.key?.source),
        tofu: s.tofu ? { status: s.tofu.status, fingerprint: s.tofu.fingerprint } : null,
        webauthn: s.webauthn ? { rp_id: s.webauthn.rpId, origin: s.webauthn.origin, user_verified: s.webauthn.userVerified, backup_eligible: s.webauthn.backupEligible, backed_up: s.webauthn.backedUp } : null,
        pgp: s.pgp ? { fpr: s.pgp.fpr ?? "", uid: str(s.pgp.uid), key_alg: str(s.pgp.keyAlg), key_source: str(s.pgp.keySource), created: str(s.pgp.created) } : null,
        resources: s.resources ? s.resources.map((r) => ({ ref: r.ref, status: r.status, detail: str(r.detail) })) : null,
        revocation: s.revocation ? { status: s.revocation.status, detail: str(s.revocation.detail) } : null,
        tsa: tsaOf(s),
        warnings: s.warnings ?? [],
    };
}
// ok is false on an error, a block that is not valid, or an agreement that is violated, undetermined, or unsupported (CLI_SPEC 4)
export function toJsonResult(r) {
    return {
        ok: !r.error && r.signatures.every((s) => s.status === "valid") && !["violated", "undetermined", "unsupported"].includes(r.agreement.status),
        error: str(r.error),
        warnings: r.warnings,
        agreement: agreementToJson(r.agreement),
        signatures: r.signatures.map(signature),
    };
}
