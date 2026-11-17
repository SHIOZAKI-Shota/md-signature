export type OrderMode = "pending" | "guide" | "strict";

export interface Requirement {
  method: string;
  signer: string;
  role?: string;
  declaredBy: number;
  // SPEC 5.8: 1 when the value has no step lines
  step: number;
  // how many members of the step must sign
  any: number;
}

export interface MissingRequirement extends Requirement {
  // signatures still needed in this step
  need: number;
  // an earlier step that has to complete first
  blockedBy?: number;
  // this signer signed before the previous step was complete, so that signature does not count
  early?: true;
}

export interface OrderViolation {
  declaredBy: number;
  step: number;
  index: number;
  method: string;
  signer: string;
  role?: string;
  order: "guide" | "strict";
}

export interface Agreement {
  status: "none" | "complete" | "pending" | "violated";
  required: Requirement[];
  missing: MissingRequirement[];
  violations: OrderViolation[];
}

export interface RequireStep {
  step: number;
  any: number;
  members: Requirement[];
}

export interface RequireSpec {
  order: OrderMode;
  steps: RequireStep[];
  // format 0.0.1 keeps its rules: duplicates allowed, one signature may satisfy several lines
  legacy: boolean;
}

const LINE_RE = /^([a-z][a-z0-9-]*):(\S+)(?: (\S+))?$/;
const ORDER_RE = /^order (pending|guide|strict)$/;
const STEP_RE = /^step ([1-9][0-9]{0,3})(?: any ([1-9][0-9]{0,3}))?$/;
// SPEC 5.8: step and order lines exist from format 0.0.2 on
const STEPS_SINCE = "0.0.2";

export const formatRequirement = (r: Pick<Requirement, "method" | "signer" | "role">) => `${r.method}:${r.signer}${r.role ? " " + r.role : ""}`;

// SPEC 5.8/5.9: dns names are case-insensitive, trailing dot ignored
export function sameSigner(method: string, a: string, b: string): boolean {
  return method === "dns" ? a.toLowerCase().replace(/\.$/, "") === b.toLowerCase().replace(/\.$/, "") : a === b;
}

const sameRequirement = (a: Pick<Requirement, "method" | "signer" | "role">, b: Pick<Requirement, "method" | "signer" | "role">) =>
  a.method === b.method && sameSigner(a.method, a.signer, b.signer) && (a.role ?? "") === (b.role ?? "");

export function parseRequire(value: string, declaredBy = 0, version = STEPS_SINCE): { requirements: Requirement[]; spec: RequireSpec; errors: string[] } {
  const errors: string[] = [];
  const lines = value.split("\n");
  let order: OrderMode = "pending";
  const steps: RequireStep[] = [];
  let implicit: RequireStep | undefined;
  const allowSteps = version !== "0.0.1";
  lines.forEach((line, i) => {
    const o = ORDER_RE.exec(line);
    const s = STEP_RE.exec(line);
    if (o || s || /^(order|step)( |$)/.test(line)) {
      if (!allowSteps) return void errors.push(`require: "step" and "order" lines need format ${STEPS_SINCE}, got ${JSON.stringify(line)}`);
      if (o) {
        if (i !== 0) errors.push(`require: "order" must be the first line`);
        else order = o[1] as OrderMode;
        return;
      }
      if (!s) return void errors.push(`require: expected "order pending|guide|strict" or "step <n> [any <m>]", got ${JSON.stringify(line)}`);
      if (implicit) return void errors.push(`require: "step" lines must come before every requirement`);
      const n = Number(s[1]);
      if (n !== steps.length + 1) return void errors.push(`require: expected "step ${steps.length + 1}", got ${JSON.stringify(line)}`);
      steps.push({ step: n, any: s[2] ? Number(s[2]) : 0, members: [] });
      return;
    }
    const m = LINE_RE.exec(line);
    if (!m) return void errors.push(`require: expected "<method>:<signer> [role]", got ${JSON.stringify(line)}`);
    let target = steps[steps.length - 1];
    if (!target) target = implicit ??= { step: 1, any: 0, members: [] };
    if (allowSteps && m[1] === "tsa") return void errors.push(`require: a tsa block cannot be required, got ${JSON.stringify(line)}`);
    const r: Requirement = { method: m[1]!, signer: m[2]!, ...(m[3] ? { role: m[3] } : {}), declaredBy, step: target.step, any: 0 };
    if (allowSteps && target.members.some((x) => sameRequirement(x, r))) return void errors.push(`require: ${formatRequirement(r)} appears twice in step ${target.step}`);
    target.members.push(r);
  });
  if (implicit) steps.push(implicit);
  for (const s of steps) {
    if (!s.members.length) errors.push(`require: step ${s.step} has no requirement`);
    if (!s.any) s.any = s.members.length;
    else if (s.any > s.members.length) errors.push(`require: step ${s.step} asks for any ${s.any} of ${s.members.length}`);
    for (const r of s.members) r.any = s.any;
  }
  return { requirements: steps.flatMap((s) => s.members), spec: { order, steps, legacy: !allowSteps }, errors };
}

interface AgreementBlock {
  index: number;
  valid: boolean;
  declares?: boolean;
  fields: Record<string, string>;
}

const matches = (r: Requirement, b: AgreementBlock) =>
  b.fields.method === r.method && sameSigner(r.method, b.fields.signer ?? "", r.signer) && (!r.role || b.fields.role === r.role);

function evaluateDeclaration(declarer: number, spec: RequireSpec, blocks: AgreementBlock[]): { status: "complete" | "pending" | "violated"; missing: MissingRequirement[]; violations: OrderViolation[] } {
  // SPEC 5.8: a block with scope does not cover the declaring block, and a tsa block has no signer, so neither satisfies
  const later = blocks.filter((b) => b.valid && b.fields.scope === undefined && b.fields.method !== "tsa" && b.index > declarer).sort((a, b) => a.index - b.index);
  if (spec.legacy) {
    const missing = spec.steps[0]!.members.filter((r) => !later.some((b) => matches(r, b))).map((r) => ({ ...r, need: 1 }));
    return { status: missing.length ? "pending" : "complete", missing, violations: [] };
  }
  const used = new Set<number>();
  const missing: MissingRequirement[] = [];
  const violations: OrderViolation[] = [];
  const ordered = spec.order === "pending";
  // completion position of the previous step; undefined when it is not complete
  let prevDone: number | undefined = declarer;
  let firstIncomplete: number | undefined;
  for (const s of spec.steps) {
    const inOrder = (b: AgreementBlock) => prevDone !== undefined && b.index > prevDone;
    const early = later.filter((b) => !used.has(b.index) && !inOrder(b) && s.members.some((r) => matches(r, b)));
    if (s.step > 1 && spec.order !== "pending") {
      for (const b of early) {
        const r = s.members.find((x) => matches(x, b))!;
        violations.push({ declaredBy: declarer, step: s.step, index: b.index, method: r.method, signer: r.signer, ...(r.role ? { role: r.role } : {}), order: spec.order });
      }
    }
    const done = new Set<Requirement>();
    let completedAt: number | undefined;
    for (const b of later) {
      if (done.size === s.any) break;
      if (used.has(b.index) || (ordered && !inOrder(b))) continue;
      const r = s.members.find((x) => !done.has(x) && matches(x, b));
      if (!r) continue;
      done.add(r);
      used.add(b.index);
      if (done.size === s.any) completedAt = b.index;
    }
    if (completedAt === undefined) {
      firstIncomplete ??= s.step;
      const blockedBy = firstIncomplete !== s.step && spec.order !== "guide" ? firstIncomplete : undefined;
      for (const r of s.members) {
        if (done.has(r)) continue;
        const signedEarly = s.step > 1 && early.some((b) => matches(r, b));
        missing.push({ ...r, need: s.any - done.size, ...(blockedBy ? { blockedBy } : {}), ...(signedEarly ? { early: true as const } : {}) });
      }
    }
    prevDone = completedAt !== undefined && (prevDone !== undefined || !ordered) ? Math.max(completedAt, prevDone ?? completedAt) : undefined;
  }
  const status = spec.order === "strict" && violations.length ? "violated" : missing.length ? "pending" : "complete";
  return { status, missing, violations };
}

// unresolved blocks still declare requirements, so an unchecked chain is never complete
export function evaluateAgreement(blocks: AgreementBlock[]): Agreement {
  const required: Requirement[] = [];
  const missing: MissingRequirement[] = [];
  const violations: OrderViolation[] = [];
  let violated = false;
  for (const b of blocks) {
    if (!(b.declares ?? b.valid) || !b.fields.require) continue;
    const { requirements, spec, errors } = parseRequire(b.fields.require, b.index, b.fields.v);
    if (errors.length) continue;
    required.push(...requirements);
    const r = evaluateDeclaration(b.index, spec, blocks);
    missing.push(...r.missing);
    violations.push(...r.violations);
    if (r.status === "violated") violated = true;
  }
  if (!required.length) return { status: "none", required, missing: [], violations: [] };
  return { status: violated ? "violated" : missing.length ? "pending" : "complete", required, missing, violations };
}
