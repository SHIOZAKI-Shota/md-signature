import { parseRequire } from "./agreement.js";
import { explainRequire } from "./explain.js";
import { canonicalSignerInput, checkDisplayName, checkSignerId, nicknameEnforce } from "./identity.js";
import { localizeMessage } from "./messages.js";
export function checkSignInput(input, lang = "en") {
    const raw = input.signer.trim();
    const signer = raw ? canonicalSignerInput(input.method, raw) : "";
    const se = signer ? checkSignerId(input.method, signer) : null;
    const dn = input.displayName?.trim() ? nicknameEnforce(input.displayName.trim()) : null;
    const de = dn !== null ? checkDisplayName(dn) : null;
    let require = null;
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
