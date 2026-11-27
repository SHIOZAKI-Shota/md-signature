import type { Agreement, MissingRequirement, NextStep, OrderViolation, Requirement, RequirementAttributes } from "./agreement.ts";
import type { TsaCheck } from "./tsa.ts";
import type { BlockResult, VerifyResult } from "./verify.ts";

// --- JSON schema (CLI_SPEC 5): the shape `mdsig verify --json` prints per file, without "file"

export interface JsonTsa {
  status: "ok" | "mismatch" | "error";
  verified: boolean;
  signer: string | null;
  gen_time: string | null;
  detail: string;
  // SPEC 4.6: T(k) and the tsa block it comes from; on a signature block these describe the time evidence
  time?: string | null;
  block?: number | null;
}

export interface JsonRequirement {
  declared_by: number;
  step: number;
  any: number | null;
  line: number;
  method: string;
  signer: string;
  pattern: boolean;
  attributes: RequirementAttributes;
}

export interface JsonMissingRequirement extends JsonRequirement {
  need: number;
  blocked_by?: number;
  rejected: { index: number; reason: string }[];
}

export interface JsonOrderViolation {
  declared_by: number;
  step: number;
  line: number;
  index: number;
  method: string;
  signer: string;
  order: string;
}

export interface JsonNext {
  declared_by: number;
  step: number;
  need: number;
  candidates: JsonRequirement[];
  later: { step: number; need: number; lines: JsonRequirement[] }[];
}

export interface JsonAgreement {
  status: string;
  required: JsonRequirement[];
  missing: JsonMissingRequirement[];
  violations: JsonOrderViolation[];
  next: JsonNext[];
  satisfied: { declared_by: number; step: number; line: number; index: number }[];
  declarations: {
    declared_by: number;
    order: string;
    status: string;
    detail: string | null;
    steps: { step: number; any: number | null; need: number; count: number; complete: boolean; blocked_by: number | null; lines: { line: number; blocks: number[] }[] }[];
  }[];
}

export interface JsonSignature {
  index: number;
  line: number;
  status: string;
  code: string | null;
  message: string | null;
  fields: Record<string, string>;
  display_name: string | null;
  hash_ok: boolean | null;
  partial: { sections: string[] } | null;
  key_source: string | null;
  tofu: { status: "known" | "new" | "replaced"; fingerprint: string } | null;
  webauthn: { rp_id: string; origin: string; user_verified: boolean; backup_eligible: boolean; backed_up: boolean } | null;
  pgp: { fpr: string; uid: string | null; key_alg: string | null; key_source: string | null; created: string | null } | null;
  resources: { ref: string; status: string; detail: string | null }[] | null;
  revocation: { status: string; detail: string | null } | null;
  tsa: JsonTsa | null;
  warnings: string[];
}

export interface JsonResult {
  ok: boolean;
  error: string | null;
  warnings: string[];
  agreement: JsonAgreement;
  signatures: JsonSignature[];
}

const str = (s: string | undefined): string | null => (s ? s : null);

export function tsaToJson(c: TsaCheck): JsonTsa {
  return { status: c.status, verified: c.verified, signer: str(c.signer), gen_time: str(c.genTime), detail: c.detail };
}

export function tsaFromJson(j: JsonTsa): TsaCheck {
  const c: TsaCheck = { status: j.status, verified: j.verified === true, detail: String(j.detail ?? "") };
  if (j.signer) c.signer = j.signer;
  // SPEC 4.6: a time is reported only for a verified token, whatever the other side sent
  if (c.verified && j.gen_time) c.genTime = j.gen_time;
  return c;
}

export function requirementToJson(r: Requirement): JsonRequirement {
  return { declared_by: r.declaredBy, step: r.step, any: r.any, line: r.line, method: r.method, signer: r.signer, pattern: r.pattern, attributes: { ...r.attributes } };
}

function missingRequirement(r: MissingRequirement): JsonMissingRequirement {
  const out: JsonMissingRequirement = { ...requirementToJson(r), need: r.need, rejected: r.rejected.map((x) => ({ index: x.index, reason: x.reason })) };
  if (r.blockedBy) out.blocked_by = r.blockedBy;
  return out;
}

function violation(v: OrderViolation): JsonOrderViolation {
  return { declared_by: v.declaredBy, step: v.step, line: v.line, index: v.index, method: v.method, signer: v.signer, order: v.order };
}

function next(n: NextStep): JsonNext {
  return { declared_by: n.declaredBy, step: n.step, need: n.need, candidates: n.candidates.map(requirementToJson), later: n.later.map((l) => ({ step: l.step, need: l.need, lines: l.lines.map(requirementToJson) })) };
}

export function agreementToJson(a: Agreement): JsonAgreement {
  return {
    status: a.status,
    required: a.required.map(requirementToJson),
    missing: a.missing.map(missingRequirement),
    violations: a.violations.map(violation),
    next: a.next.map(next),
    satisfied: a.satisfied.map((s) => ({ declared_by: s.declaredBy, step: s.step, line: s.line, index: s.index })),
    declarations: a.declarations.map((d) => ({
      declared_by: d.declaredBy,
      order: d.order,
      status: d.status,
      detail: d.detail ?? null,
      steps: d.steps.map((s) => ({ step: s.step, any: s.any, need: s.need, count: s.count, complete: s.complete, blocked_by: s.blockedBy ?? null, lines: s.lines.map((l) => ({ line: l.line, blocks: [...l.blocks] })) })),
    })),
  };
}

function tsaOf(s: BlockResult): JsonTsa | null {
  const t = s.time;
  if (s.tsa) return { ...tsaToJson(s.tsa), time: t?.at ?? null, block: t?.block ?? null };
  // SPEC 4.6: a signature block reports T(k) from the tsa blocks after it
  if (!t) return null;
  return { status: "ok", verified: true, signer: str(t.signer), gen_time: t.genTime, detail: `covered by tsa block #${t.block}`, time: t.at, block: t.block };
}

function signature(s: BlockResult): JsonSignature {
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
export function toJsonResult(r: VerifyResult): JsonResult {
  return {
    ok: !r.error && r.signatures.every((s) => s.status === "valid") && !["violated", "undetermined", "unsupported"].includes(r.agreement.status),
    error: str(r.error),
    warnings: r.warnings,
    agreement: agreementToJson(r.agreement),
    signatures: r.signatures.map(signature),
  };
}
