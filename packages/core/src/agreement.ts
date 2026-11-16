export interface Requirement {
  method: string;
  signer: string;
  role?: string;
  declaredBy: number;
}

export interface Agreement {
  status: "none" | "complete" | "pending";
  required: Requirement[];
  missing: Requirement[];
}

const LINE_RE = /^([a-z][a-z0-9-]*):(\S+)(?: (\S+))?$/;

export function parseRequire(value: string, declaredBy = 0): { requirements: Requirement[]; errors: string[] } {
  const requirements: Requirement[] = [];
  const errors: string[] = [];
  for (const line of value.split("\n")) {
    const m = LINE_RE.exec(line);
    if (!m) {
      errors.push(`require: expected "<method>:<signer> [role]", got ${JSON.stringify(line)}`);
      continue;
    }
    requirements.push({ method: m[1]!, signer: m[2]!, ...(m[3] ? { role: m[3] } : {}), declaredBy });
  }
  return { requirements, errors };
}

export const formatRequirement = (r: Pick<Requirement, "method" | "signer" | "role">) => `${r.method}:${r.signer}${r.role ? " " + r.role : ""}`;

// SPEC 5.8/5.9: dns names are case-insensitive, trailing dot ignored
export function sameSigner(method: string, a: string, b: string): boolean {
  return method === "dns" ? a.toLowerCase().replace(/\.$/, "") === b.toLowerCase().replace(/\.$/, "") : a === b;
}

// unresolved blocks still declare requirements, so an unchecked chain is never complete
// SPEC 5.8: a block with scope does not cover the declaring block, so it never satisfies
export function evaluateAgreement(blocks: { index: number; valid: boolean; declares?: boolean; fields: Record<string, string> }[]): Agreement {
  const required: Requirement[] = [];
  for (const b of blocks) {
    if (!(b.declares ?? b.valid) || !b.fields.require) continue;
    required.push(...parseRequire(b.fields.require, b.index).requirements);
  }
  if (!required.length) return { status: "none", required, missing: [] };
  const missing = required.filter(
    (r) =>
      !blocks.some(
        (b) => b.valid && b.fields.scope === undefined && b.index > r.declaredBy && b.fields.method === r.method && sameSigner(r.method, b.fields.signer ?? "", r.signer) && (!r.role || b.fields.role === r.role),
      ),
  );
  return { status: missing.length ? "pending" : "complete", required, missing };
}
