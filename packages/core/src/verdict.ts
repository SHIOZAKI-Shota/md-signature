import type { VerifyResult } from "./verify.ts";

// --- document verdict (CLI_SPEC 4)

export type VerdictKind = "valid" | "pending" | "undetermined" | "unresolved" | "offline" | "violated" | "unsupported" | "failed" | "broken" | "unsigned";

export interface Verdict {
  kind: VerdictKind;
  exitCode: 0 | 1 | 3 | 5;
}

export function documentVerdict(r: VerifyResult): Verdict {
  // "no signatures found" is the error verifyDocument gives for a document without a chain
  if (r.error) return { kind: r.error === "no signatures found" ? "unsigned" : "broken", exitCode: 1 };
  if (r.signatures.some((s) => s.status !== "valid" && s.status !== "unresolved")) return { kind: "failed", exitCode: 1 };
  // CLI_SPEC 4: violated and unsupported fail; undetermined is like an unchecked block; pending is not a failure
  if (r.agreement.status === "violated" || r.agreement.status === "unsupported") return { kind: r.agreement.status, exitCode: 1 };
  const unresolved = r.signatures.filter((s) => s.status === "unresolved");
  if (unresolved.length) return { kind: unresolved.every((s) => s.code === "offline") ? "offline" : "unresolved", exitCode: 3 };
  if (r.agreement.status === "undetermined") return { kind: "undetermined", exitCode: 3 };
  if (r.agreement.status === "pending") return { kind: "pending", exitCode: 5 };
  return { kind: "valid", exitCode: 0 };
}
