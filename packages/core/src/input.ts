import { parseRequire, type RequireSpec } from "./agreement.ts";
import { explainRequire } from "./explain.ts";
import { canonicalSignerInput, checkDisplayName, checkSignerId, nicknameEnforce } from "./identity.ts";
import { localizeMessage, type Lang } from "./messages.ts";

// --- signing-form input

export interface SignInput {
  method: string;
  signer: string;
  displayName?: string;
  require?: string;
}

export interface SignInputCheck {
  signer: string;
  signerError: string | null;
  displayName: string | null;
  displayNameError: string | null;
  require: {
    spec: RequireSpec | null;
    explanation: string;
    errors: string[];
    warnings: string[];
    ok: boolean;
  } | null;
}

export function checkSignInput(input: SignInput, lang: Lang = "en"): SignInputCheck {
  const raw = input.signer.trim();
  const signer = raw ? canonicalSignerInput(input.method, raw) : "";
  const se = signer ? checkSignerId(input.method, signer) : null;
  const dn = input.displayName?.trim() ? nicknameEnforce(input.displayName.trim()) : null;
  const de = dn !== null ? checkDisplayName(dn) : null;
  let require: SignInputCheck["require"] = null;
  const value = input.require?.trim();
  if (value) {
    const x = explainRequire(value, lang);
    require = {
      spec: x.ok ? parseRequire(value, 0).spec : null,
      explanation: x.ok ? x.text : "",
      errors: [...x.errors, ...x.unsupported, ...x.hints],
      warnings: x.warnings,
      ok: x.ok,
    };
  }
  return {
    signer,
    signerError: se && localizeMessage(se, lang),
    displayName: dn,
    displayNameError: de && localizeMessage(de, lang),
    require,
  };
}
