import { sha256 } from "./crypto.ts";
import { concat, toHex } from "./encoding.ts";
import { parseListLine } from "./listline.ts";
import { linesWithFence } from "./parser.ts";

export interface ResourceEntry {
  hash: string;
  // as written in the block
  ref: string;
  remote: boolean;
  // local references: the percent-decoded path handed to loadResource
  path?: string;
}

export interface ResourceResult {
  ref: string;
  status: "ok" | "mismatch" | "missing" | "unreachable" | "not-checked";
  detail?: string;
}

const HASH_RE = /^sha256:([0-9a-f]{64})$/;
// RFC 3986 pchar and "/" for local references; non-ASCII is allowed and taken as UTF-8
const LOCAL_CHAR_RE = /^(?:[A-Za-z0-9\-._~!$&'()*+,;=:@/]|%[0-9A-Fa-f]{2}|[^\x00-\x7f])*$/;

// SPEC 5.7: percent-decoding of a local reference, or an error message
export function decodeLocalRef(ref: string): { path: string } | { error: string } {
  if (!LOCAL_CHAR_RE.test(ref)) return { error: `"${ref}": characters outside RFC 3986 must be percent-encoded` };
  // security: an encoded separator or NUL would change the path after the checks below
  if (/%2f|%5c|%00/i.test(ref)) return { error: `"${ref}": %2F, %5C, and %00 are not allowed` };
  let path: string;
  try {
    const bytes: number[] = [];
    for (let i = 0; i < ref.length; ) {
      if (ref[i] === "%") {
        bytes.push(parseInt(ref.slice(i + 1, i + 3), 16));
        i += 3;
      } else {
        const cp = ref.codePointAt(i)!;
        const ch = String.fromCodePoint(cp);
        for (const b of new TextEncoder().encode(ch)) bytes.push(b);
        i += ch.length;
      }
    }
    path = new TextDecoder("utf-8", { fatal: true }).decode(new Uint8Array(bytes));
  } catch {
    return { error: `"${ref}": the decoded path is not valid UTF-8` };
  }
  if (path.startsWith("/") || /^[A-Za-z]:/.test(path) || path.includes("\\")) return { error: `"${ref}": absolute paths, drive letters, and "\\" are not allowed` };
  // security: ":" names an alternate data stream on Windows (file.txt:hidden)
  if (path.includes(":")) return { error: `"${ref}": ":" is not allowed in a local path` };
  // SPEC 5.7: ".", "..", and empty segments are checked after decoding
  if (path.split("/").some((seg) => seg === "" || seg === "." || seg === "..")) return { error: `"${ref}": ".", "..", and empty path segments are not allowed` };
  return { path };
}

export function validateResourceRef(ref: string): string | null {
  if (/^https:\/\/[^/\s]+/.test(ref)) return null;
  if (/^[a-z][a-z0-9+.-]*:/i.test(ref) && !/^[A-Za-z]:/.test(ref)) return `"${ref}": only https:// URLs and relative paths are allowed`;
  const d = decodeLocalRef(ref);
  return "error" in d ? d.error : null;
}

// SPEC 5.7: each line is "<ref> hash=sha256:<hex>"; another hash prefix is unsupported, not malformed
export function parseResources(value: string): { entries: ResourceEntry[]; errors: string[]; unsupportedHash?: string } {
  const entries: ResourceEntry[] = [];
  const errors: string[] = [];
  let unsupportedHash: string | undefined;
  for (const raw of value.split("\n")) {
    const { line, error } = parseListLine(raw, { hash: "value" });
    if (!line) {
      errors.push(`resources: ${error}`);
      continue;
    }
    if (line.unknown.length) {
      errors.push(`resources: unknown attribute "${line.unknown[0]}"`);
      continue;
    }
    const hv = line.attrs.get("hash");
    if (typeof hv !== "string") {
      errors.push(`resources: expected "<ref> hash=sha256:<hex>", got ${JSON.stringify(raw)}`);
      continue;
    }
    const pm = /^([a-z0-9-]+):/.exec(hv);
    if (pm && pm[1] !== "sha256") {
      unsupportedHash ??= hv;
      continue;
    }
    const h = HASH_RE.exec(hv);
    if (!h) {
      errors.push(`resources: expected "<ref> hash=sha256:<lowercase hex>", got ${JSON.stringify(raw)}`);
      continue;
    }
    const ref = line.target;
    const e = validateResourceRef(ref);
    if (e) {
      errors.push(`resources: ${e}`);
      continue;
    }
    const remote = /^https:\/\//.test(ref);
    const local = remote ? undefined : decodeLocalRef(ref);
    entries.push({ hash: h[1]!, ref, remote, ...(local && "path" in local ? { path: local.path } : {}) });
  }
  return { entries, errors, ...(unsupportedHash ? { unsupportedHash } : {}) };
}

// SPEC 5.7: generators drop a leading "./", because a "." segment is malformed
export const stripDotSlash = (ref: string) => ref.replace(/^(?:\.\/)+/, "");

export async function formatResources(items: { ref: string; bytes: Uint8Array }[]): Promise<string> {
  const lines: string[] = [];
  for (const it of items) {
    const ref = stripDotSlash(it.ref);
    const e = validateResourceRef(ref);
    if (e) throw new Error(e);
    lines.push(`${ref} hash=sha256:${toHex(await sha256(it.bytes))}`);
  }
  return lines.join("\n");
}

export const MAX_RESOURCE_BYTES = 50 * 1024 * 1024;

export async function fetchResource(url: string, fetchFn: typeof fetch = globalThis.fetch, maxBytes = MAX_RESOURCE_BYTES): Promise<Uint8Array> {
  if (!/^https:\/\//i.test(url)) throw new Error("only https:// URLs are fetched");
  const res = await fetchFn(url, { redirect: "follow" });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  if (res.url && !/^https:\/\//i.test(res.url)) throw new Error("redirected to a non-https URL");
  const len = Number(res.headers.get("content-length") ?? "0");
  if (len > maxBytes) throw new Error(`larger than ${maxBytes} bytes`);
  if (!res.body) return new Uint8Array(await res.arrayBuffer());
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error(`larger than ${maxBytes} bytes`);
    }
    chunks.push(value);
  }
  return concat(...chunks);
}

export interface ResourceCheckOptions {
  // receives the percent-decoded path of a local reference
  loadResource?: (path: string) => Promise<Uint8Array | null>;
  fetchResources?: boolean;
  fetch?: typeof fetch;
  maxResourceBytes?: number;
}

export async function checkResources(entries: ResourceEntry[], o: ResourceCheckOptions): Promise<ResourceResult[]> {
  const out: ResourceResult[] = [];
  for (const e of entries) {
    let bytes: Uint8Array | null;
    if (e.remote) {
      // SPEC 9.8: remote resources are fetched only on request
      if (!o.fetchResources) {
        out.push({ ref: e.ref, status: "not-checked", detail: "remote resources are fetched only on request" });
        continue;
      }
      try {
        bytes = await fetchResource(e.ref, o.fetch ?? globalThis.fetch, o.maxResourceBytes);
      } catch (err) {
        out.push({ ref: e.ref, status: "unreachable", detail: (err as Error).message });
        continue;
      }
    } else {
      if (!o.loadResource) {
        out.push({ ref: e.ref, status: "not-checked", detail: "the document's directory is not available" });
        continue;
      }
      try {
        bytes = await o.loadResource(e.path ?? e.ref);
      } catch (err) {
        out.push({ ref: e.ref, status: "missing", detail: `could not be read: ${(err as Error).message}` });
        continue;
      }
      if (!bytes) {
        out.push({ ref: e.ref, status: "missing" });
        continue;
      }
    }
    const got = toHex(await sha256(bytes));
    out.push(got === e.hash ? { ref: e.ref, status: "ok" } : { ref: e.ref, status: "mismatch", detail: `sha256:${got}` });
  }
  return out;
}

export function findLocalImages(markdown: string): string[] {
  const refs = new Set<string>();
  for (const { line, inFence } of linesWithFence(markdown)) {
    if (inFence) continue;
    for (const m of line.matchAll(/!\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)/g)) refs.add(m[1]!);
    for (const m of line.matchAll(/<img\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi)) refs.add(m[1]!);
  }
  return [...new Set([...refs].map(stripDotSlash))].filter((r) => !/^[a-z][a-z0-9+.-]*:/i.test(r) && !r.startsWith("#") && validateResourceRef(r) === null);
}
