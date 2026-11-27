import { utf8 } from "./encoding.ts";
import { CONTROL_RE, hasNoncharacter } from "./charclass.ts";

export const SPEC_VERSION = "0.1";
// SPEC 3.3: the version changes only with incompatible changes; other versions are unsupported (SPEC 5.4 step 1)
export const SUPPORTED_VERSIONS: ReadonlySet<string> = new Set([SPEC_VERSION]);
export const PAYLOAD_DOMAIN = "md-signature/v1";
export const OPEN_LINE = "<!-- md-signature";
export const CLOSE_LINE = "-->";

export const UNSIGNED_KEYS: ReadonlySet<string> = new Set(["sig", "webauthn_authenticator_data", "webauthn_client_data"]);

const ORDER = [
  "v", "method", "signer", "selector", "key_fp", "fpr", "pubkey", "rp_id",
  "display_name", "role", "reason", "ts", "expires", "scope", "require", "resources", "revocation_url",
  "alg", "hash", "sig", "webauthn_authenticator_data", "webauthn_client_data",
];

export const KNOWN_KEYS: ReadonlySet<string> = new Set(ORDER);

// SPEC 3.5: values of these fields are lists, one item per line
export const LIST_KEYS: ReadonlySet<string> = new Set(["scope", "require", "resources"]);

export const isExtensionKey = (k: string) => k.startsWith("x_");

export function normalizeNewlines(text: string): string {
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  return text.replace(/\r\n?/g, "\n");
}

export function normalizeDocument(text: string): string {
  return normalizeNewlines(text).replace(/[\n \t]+$/, "") + "\n";
}

export function normalizedBytes(text: string): Uint8Array {
  return utf8(normalizeDocument(text));
}

// SPEC 5.3: LF inside a value becomes LF + 2 spaces
export function signedPayload(fields: Record<string, string>): Uint8Array {
  const keys = Object.keys(fields)
    .filter((k) => !UNSIGNED_KEYS.has(k))
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const lines = keys.map((k) => `${k}=${fields[k]!.replace(/\n/g, "\n  ")}`);
  return utf8(PAYLOAD_DOMAIN + "\n" + lines.join("\n"));
}

const KEY_RE = /^[a-z][a-z0-9_]*$/;
// SPEC 3.2 rule 3: CommonMark HTML block type 2 ends at "-->"; WHATWG comments also end at "--!>"; "<!--" opens a nested comment
const FORBIDDEN_SEQUENCES = ["-->", "--!>", "<!--"];

export function validateLine(value: string): string | null {
  if (value.length === 0) return "value is empty";
  const seq = FORBIDDEN_SEQUENCES.find((s) => value.includes(s));
  if (seq) return `value must not contain "${seq}"`;
  if (CONTROL_RE.test(value) || hasNoncharacter(value)) return "value must not contain control characters, format characters, line breaks, or noncharacters";
  if (value.endsWith(" ")) return "value must not have trailing spaces";
  return null;
}

// a folded line keeps its leading spaces (SPEC 3.2 cont-line); a single-line value may not start with one
export function validateValue(value: string, allowMultiline = false): string | null {
  if (value.includes("\n")) {
    if (!allowMultiline) return "value must not contain control characters, format characters, line breaks, or noncharacters";
    for (const line of value.split("\n")) {
      if (!line.replace(/^ +/, "")) return "a folded line must not be empty";
      const e = validateLine(line);
      if (e) return e;
    }
    return null;
  }
  if (value.startsWith(" ") && !allowMultiline) return "value must not have leading spaces";
  if (allowMultiline && !value.replace(/^ +/, "")) return "a folded line must not be empty";
  return validateLine(value);
}

export function validateKey(key: string): string | null {
  return KEY_RE.test(key) ? null : `invalid key "${key}"`;
}

// SPEC 3.2 rule 6: x_* keys go, sorted, just before alg
function orderedKeys(fields: Record<string, string>): string[] {
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
export const BINARY_KEYS: ReadonlySet<string> = new Set(["sig", "webauthn_authenticator_data", "webauthn_client_data"]);

export function serializeBlock(fields: Record<string, string>): string {
  const lines = [OPEN_LINE];
  for (const k of orderedKeys(fields)) {
    const v = fields[k]!;
    const ke = validateKey(k);
    if (ke) throw new Error(ke);
    const folded = v.includes("\n") || v.startsWith(" ");
    const ve = validateValue(v, folded);
    if (ve) throw new Error(`${k}: ${ve}`);
    if (folded) {
      lines.push(`${k}: |`);
      for (const l of v.split("\n")) lines.push("  " + l);
    } else if (BINARY_KEYS.has(k) && v.length > FOLD_WIDTH) {
      lines.push(`${k}: |`);
      for (let i = 0; i < v.length; i += FOLD_WIDTH) lines.push("  " + v.slice(i, i + FOLD_WIDTH));
    } else {
      lines.push(`${k}: ${v}`);
    }
  }
  lines.push(CLOSE_LINE);
  return lines.join("\n");
}

export function nowTs(d = new Date()): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

export const TS_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

// round-trip rejects Feb 30, 24:00:00 and leap seconds
export function isValidTimestamp(s: string): boolean {
  if (!TS_RE.test(s)) return false;
  const t = Date.parse(s);
  return !Number.isNaN(t) && new Date(t).toISOString().replace(/\.\d{3}Z$/, "Z") === s;
}

export const unfoldBinary = (v: string) => v.replace(/\s+/g, "");
