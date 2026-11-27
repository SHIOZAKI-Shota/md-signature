import { fromBase64 } from "./encoding.js";
import { decodePublicKey } from "./resolvers.js";
// --- Identifier syntax (SPEC 3.4): checked as written, compared byte for byte
const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
// SPEC 3.4: RFC 1123 / RFC 5890 A-label syntax, lower case, two or more labels, no trailing dot, last label not all digits
export function isLdhDomain(s) {
    if (s.length === 0 || s.length > 253)
        return false;
    const labels = s.split(".");
    if (labels.length < 2)
        return false;
    if (!labels.every((l) => LABEL_RE.test(l)))
        return false;
    return !/^[0-9]+$/.test(labels[labels.length - 1]);
}
// SPEC 3.4: RFC 5322 dot-atom-text with RFC 6531 UTF-8, no ASCII upper case; "*" is reserved for patterns
const LOCAL_RE = /^(?:[a-z0-9!#$%&'+\-/=?^_`{|}~]|[^\x00-\x7f])+(?:\.(?:[a-z0-9!#$%&'+\-/=?^_`{|}~]|[^\x00-\x7f])+)*$/u;
export function isEmailId(s) {
    const at = s.lastIndexOf("@");
    if (at <= 0)
        return false;
    return LOCAL_RE.test(s.slice(0, at)) && isLdhDomain(s.slice(at + 1));
}
const GIT_USER_RE = /^[a-z0-9._-]+$/;
export function isGitHostingId(s) {
    const i = s.indexOf("/");
    return i > 0 && isLdhDomain(s.slice(0, i)) && GIT_USER_RE.test(s.slice(i + 1));
}
// SPEC 4.1: one label of [a-z0-9_-], 1-63 octets, not starting with "_" (reserved for _member)
const SELECTOR_RE = /^[a-z0-9-][a-z0-9_-]{0,62}$/;
export function isSelector(s) {
    return SELECTOR_RE.test(s);
}
// SPEC 6.1: rp_id is a domain; "localhost" is kept for development passkeys
export function isRpId(s) {
    return s === "localhost" || isLdhDomain(s);
}
export const ROLE_RE = /^[a-z0-9][a-z0-9._-]*$/;
export function checkSignerId(method, signer) {
    if (signer.includes("*"))
        return `signer must not contain "*"`;
    switch (method) {
        case "dns":
            return isLdhDomain(signer) ? null : "dns signer must be a lower-case domain name (LDH labels, no trailing dot)";
        case "git-hosting":
            return isGitHostingId(signer) ? null : "git-hosting signer must be <host>/<username> in lower case with a domain name as host";
        case "pgp":
        case "directory":
            return isEmailId(signer) ? null : `${method} signer must be a lower-case email address with a domain name`;
        case "tofu":
            return signer.includes(" ") ? "tofu signer must not contain spaces" : null;
        case "tsa":
            return /^https?:\/\/\S+$/.test(signer) ? null : "tsa signer must be the http(s) URL of the time-stamping authority";
        default:
            return null;
    }
}
const asciiLower = (s) => s.replace(/[A-Z]+/g, (m) => m.toLowerCase());
export function canonicalSignerInput(method, signer) {
    switch (method) {
        case "dns":
            return asciiLower(signer).replace(/\.$/, "");
        case "git-hosting":
        case "pgp":
        case "directory":
            return asciiLower(signer);
        default:
            return signer;
    }
}
// SPEC 3.4: keys compare as decoded bytes, so raw and SPKI spellings of one key are equal
export function decodeKeyValue(value) {
    const i = value.indexOf(":");
    if (i <= 0)
        return null;
    const type = value.slice(0, i);
    try {
        return { type, key: decodePublicKey(type, fromBase64(value.slice(i + 1))) };
    }
    catch {
        return null;
    }
}
export function sameKeyValue(a, b) {
    const x = decodeKeyValue(a);
    const y = decodeKeyValue(b);
    if (!x || !y || x.type !== y.type || x.key.length !== y.key.length)
        return false;
    return x.key.every((v, i) => v === y.key[i]);
}
// --- display_name (SPEC 3.3): RFC 8266 Nickname, simplified
const ZS_NON_ASCII_RE = /[\p{Zs}]/u;
// SPEC 3.3: verifiers check only the length
export function checkDisplayNameLength(v) {
    return [...v].length > 64 ? "display_name is longer than 64 code points" : null;
}
// generators: the value must be unchanged by the Nickname enforcement rules
export function checkDisplayName(v) {
    const len = checkDisplayNameLength(v);
    if (len)
        return len;
    if ([...v].some((c) => c !== " " && ZS_NON_ASCII_RE.test(c)))
        return "display_name must use U+0020 for spaces";
    if (v !== v.normalize("NFKC"))
        return "display_name must be in Unicode NFKC form";
    if (v.includes("  "))
        return "display_name must not contain consecutive spaces";
    return null;
}
// RFC 8266 enforcement without the FreeformClass repertoire check: spaces to U+0020, trim, collapse, NFKC
export function nicknameEnforce(v) {
    return v.replace(/\p{Zs}/gu, " ").trim().replace(/ {2,}/g, " ").normalize("NFKC");
}
