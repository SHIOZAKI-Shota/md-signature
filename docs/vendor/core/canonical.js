import { utf8 } from "./encoding.js";
export const SPEC_VERSION = "0.0.2";
// SPEC 3.2: verifiers accept every format version listed here; generators write SPEC_VERSION
export const SUPPORTED_VERSIONS = new Set(["0.0.1", "0.0.2"]);
export const PAYLOAD_DOMAIN = "md-signature/v1";
export const OPEN_LINE = "<!-- md-signature";
export const CLOSE_LINE = "-->";
export const UNSIGNED_KEYS = new Set(["sig", "tsa_url", "tsa_token", "webauthn_authenticator_data", "webauthn_client_data"]);
const ORDER = [
    "v", "method", "signer", "selector", "key_fp", "fpr", "pubkey", "rp_id",
    "role", "reason", "ts", "expires", "scope", "require", "resources", "revocation_url",
    "alg", "hash", "sig", "webauthn_authenticator_data", "webauthn_client_data", "tsa_url", "tsa_token",
];
export const KNOWN_KEYS = new Set(ORDER);
export const isExtensionKey = (k) => k.startsWith("x_");
export function normalizeNewlines(text) {
    if (text.charCodeAt(0) === 0xfeff)
        text = text.slice(1);
    return text.replace(/\r\n?/g, "\n");
}
export function normalizeDocument(text) {
    return normalizeNewlines(text).replace(/[\n \t]+$/, "") + "\n";
}
export function normalizedBytes(text) {
    return utf8(normalizeDocument(text));
}
// SPEC 5.3: LF inside a value becomes LF + 2 spaces
export function signedPayload(fields) {
    const keys = Object.keys(fields)
        .filter((k) => !UNSIGNED_KEYS.has(k))
        .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const lines = keys.map((k) => `${k}=${fields[k].replace(/\n/g, "\n  ")}`);
    return utf8(PAYLOAD_DOMAIN + "\n" + lines.join("\n"));
}
const KEY_RE = /^[a-z][a-z0-9_]*$/;
// eslint-disable-next-line no-control-regex
// SPEC 3.2 rule 4: C0, DEL, C1, line separators, bidi controls
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/;
export function validateLine(value) {
    if (value.length === 0)
        return "value is empty";
    if (value.includes("--"))
        return 'value must not contain "--"';
    if (CONTROL_RE.test(value))
        return "value must not contain control characters or line breaks";
    if (value !== value.trim())
        return "value must not have leading or trailing whitespace";
    return null;
}
export function validateValue(value, allowMultiline = false) {
    if (value.includes("\n")) {
        if (!allowMultiline)
            return "value must not contain control characters or line breaks";
        for (const line of value.split("\n")) {
            const e = validateLine(line);
            if (e)
                return e;
        }
        return null;
    }
    return validateLine(value);
}
export function validateKey(key) {
    return KEY_RE.test(key) ? null : `invalid key "${key}"`;
}
// SPEC 3.2 rule 6: x_* keys go, sorted, just before alg
function orderedKeys(fields) {
    const known = ORDER.filter((k) => k in fields);
    const extra = Object.keys(fields)
        .filter((k) => !KNOWN_KEYS.has(k))
        .sort();
    const at = known.indexOf("alg") >= 0 ? known.indexOf("alg") : known.findIndex((k) => ORDER.indexOf(k) > ORDER.indexOf("revocation_url"));
    const pos = at < 0 ? known.length : at;
    return [...known.slice(0, pos), ...extra, ...known.slice(pos)];
}
// SPEC 3.2 rule 7: long binary values are folded
const FOLD_WIDTH = 76;
export const BINARY_KEYS = new Set(["sig", "tsa_token", "webauthn_authenticator_data", "webauthn_client_data"]);
export function serializeBlock(fields) {
    const lines = [OPEN_LINE];
    for (const k of orderedKeys(fields)) {
        const v = fields[k];
        const ke = validateKey(k);
        if (ke)
            throw new Error(ke);
        const ve = validateValue(v, true);
        if (ve)
            throw new Error(`${k}: ${ve}`);
        if (v.includes("\n")) {
            lines.push(`${k}: |`);
            for (const l of v.split("\n"))
                lines.push("  " + l);
        }
        else if (BINARY_KEYS.has(k) && v.length > FOLD_WIDTH) {
            lines.push(`${k}: |`);
            for (let i = 0; i < v.length; i += FOLD_WIDTH)
                lines.push("  " + v.slice(i, i + FOLD_WIDTH));
        }
        else {
            lines.push(`${k}: ${v}`);
        }
    }
    lines.push(CLOSE_LINE);
    return lines.join("\n");
}
export function nowTs(d = new Date()) {
    return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}
export const TS_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
// round-trip rejects Feb 30, 24:00:00 and leap seconds
export function isValidTimestamp(s) {
    if (!TS_RE.test(s))
        return false;
    const t = Date.parse(s);
    return !Number.isNaN(t) && new Date(t).toISOString().replace(/\.\d{3}Z$/, "Z") === s;
}
export const unfoldBinary = (v) => v.replace(/\s+/g, "");
