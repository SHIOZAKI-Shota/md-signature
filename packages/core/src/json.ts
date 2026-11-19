import type { Agreement, MissingRequirement, OrderViolation, Requirement } from "./agreement.ts";
import type { TsaCheck } from "./tsa.ts";
import type { BlockResult, VerifyResult } from "./verify.ts";

// --- JSON schema (CLI_SPEC 5): the shape `mdsig verify --json` prints per file, without "file"

export interface JsonTsa {
  status: "ok" | "mismatch" | "error";
  verified: boolean;
  signer: string | null;
  gen_time: string | null;
  detail: string;
}

export interface JsonRequirement {
  method: string;
  signer: string;
  role?: string;
  declared_by: number;
  step: number;
  any: number;
}

export interface JsonMissingRequirement extends JsonRequirement {
  need: number;
  blocked_by?: number;
  early?: boolean;
}

export interface JsonOrderViolation {
  declared_by: number;
  step: number;
  index: number;
  method: string;
  signer: string;
  role?: string;
  order: string;
}

export interface JsonSignature {
  index: number;
  line: number;
  status: string;
  code: string | null;
  message: string | null;
  fields: Record<string, string>;
  hash_ok: boolean | null;
  partial: { sections: string[] } | null;
  key_source: string | null;
  tofu: { status: "known" | "new" | "replaced"; fingerprint: string } | null;
  webauthn: { rp_id: string; origin: string; user_verified: boolean } | null;
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
  agreement: { status: string; required: JsonRequirement[]; missing: JsonMissingRequirement[]; violations: JsonOrderViolation[] };
  signatures: JsonSignature[];
}

const str = (s: string | undefined): string | null => (s ? s : null);

export function tsaToJson(c: TsaCheck): JsonTsa {
  return { status: c.status, verified: c.verified, signer: str(c.signer), gen_time: str(c.genTime), detail: c.detail };
}

export function tsaFromJson(j: JsonTsa): TsaCheck {
  const c: TsaCheck = { status: j.status, verified: j.verified === true, detail: String(j.detail ?? "") };
  if (j.signer) c.signer = j.signer;
  // SPEC 5.5: a time is reported only for a verified token, whatever the other side sent
  if (c.verified && j.gen_time) c.genTime = j.gen_time;
  return c;
}

function requirement(r: Requirement): JsonRequirement {
  const out: JsonRequirement = { method: r.method, signer: r.signer, declared_by: r.declaredBy, step: r.step, any: r.any };
  if (r.role) out.role = r.role;
  return out;
}

function missingRequirement(r: MissingRequirement): JsonMissingRequirement {
  const out: JsonMissingRequirement = { ...requirement(r), need: r.need };
  if (r.blockedBy) out.blocked_by = r.blockedBy;
  if (r.early) out.early = true;
  return out;
}

function violation(v: OrderViolation): JsonOrderViolation {
  const out: JsonOrderViolation = { declared_by: v.declaredBy, step: v.step, index: v.index, method: v.method, signer: v.signer, order: v.order };
  if (v.role) out.role = v.role;
  return out;
}

function agreement(a: Agreement): JsonResult["agreement"] {
  return { status: a.status, required: a.required.map(requirement), missing: a.missing.map(missingRequirement), violations: a.violations.map(violation) };
}

function signature(s: BlockResult): JsonSignature {
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
    tofu: s.tofu ? { status: s.tofu.status, fingerprint: s.tofu.fingerprint } : null,
    webauthn: s.webauthn ? { rp_id: s.webauthn.rpId, origin: s.webauthn.origin, user_verified: s.webauthn.userVerified } : null,
    pgp: s.pgp ? { fpr: s.pgp.fpr ?? "", uid: str(s.pgp.uid), key_alg: str(s.pgp.keyAlg), key_source: str(s.pgp.keySource), created: str(s.pgp.created) } : null,
    resources: s.resources ? s.resources.map((r) => ({ ref: r.ref, status: r.status, detail: str(r.detail) })) : null,
    revocation: s.revocation ? { status: s.revocation.status, detail: str(s.revocation.detail) } : null,
    tsa: s.tsa ? tsaToJson(s.tsa) : null,
    warnings: s.warnings ?? [],
  };
}

// ok is true when there is no error, every signature is valid and the agreement is not violated (a pending agreement is still ok, CLI_SPEC 4)
export function toJsonResult(r: VerifyResult): JsonResult {
  return {
    ok: !r.error && r.signatures.every((s) => s.status === "valid") && r.agreement.status !== "violated",
    error: str(r.error),
    warnings: r.warnings,
    agreement: agreement(r.agreement),
    signatures: r.signatures.map(signature),
  };
}
