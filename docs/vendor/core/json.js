const str = (s) => (s ? s : null);
export function tsaToJson(c) {
    return { status: c.status, verified: c.verified, signer: str(c.signer), gen_time: str(c.genTime), detail: c.detail };
}
export function tsaFromJson(j) {
    const c = { status: j.status, verified: j.verified === true, detail: String(j.detail ?? "") };
    if (j.signer)
        c.signer = j.signer;
    // SPEC 5.5: a time is reported only for a verified token, whatever the other side sent
    if (c.verified && j.gen_time)
        c.genTime = j.gen_time;
    return c;
}
function requirement(r) {
    const out = { method: r.method, signer: r.signer, declared_by: r.declaredBy };
    if (r.role)
        out.role = r.role;
    return out;
}
function agreement(a) {
    return { status: a.status, required: a.required.map(requirement), missing: a.missing.map(requirement) };
}
function signature(s) {
    return {
        index: s.index,
        line: s.line,
        status: s.status,
        code: str(s.code),
        message: str(s.message),
        fields: s.fields ?? {},
        hash_ok: s.hashOk ?? null,
        partial: s.partial ? { sections: s.partial.sections } : null,
        key_source: str(s.key?.source),
        webauthn: s.webauthn ? { rp_id: s.webauthn.rpId, origin: s.webauthn.origin, user_verified: s.webauthn.userVerified } : null,
        pgp: s.pgp ? { fpr: s.pgp.fpr ?? "", uid: str(s.pgp.uid), key_alg: str(s.pgp.keyAlg), key_source: str(s.pgp.keySource), created: str(s.pgp.created) } : null,
        resources: s.resources ? s.resources.map((r) => ({ ref: r.ref, status: r.status, detail: str(r.detail) })) : null,
        revocation: s.revocation ? { status: s.revocation.status, detail: str(s.revocation.detail) } : null,
        tsa: s.tsa ? tsaToJson(s.tsa) : null,
        warnings: s.warnings ?? [],
    };
}
// ok is true when there is no error and every signature is valid (a pending agreement is still ok, CLI_SPEC 4)
export function toJsonResult(r) {
    return {
        ok: !r.error && r.signatures.every((s) => s.status === "valid"),
        error: str(r.error),
        warnings: r.warnings,
        agreement: agreement(r.agreement),
        signatures: r.signatures.map(signature),
    };
}
