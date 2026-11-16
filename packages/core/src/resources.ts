import { sha256 } from "./crypto.ts";
import { concat, toHex } from "./encoding.ts";
import { linesWithFence } from "./parser.ts";

export interface ResourceEntry {
  hash: string;
  ref: string;
  remote: boolean;
}

export interface ResourceResult {
  ref: string;
  status: "ok" | "mismatch" | "missing" | "unreachable" | "not-checked";
  detail?: string;
}

const LINE_RE = /^sha256:([0-9a-f]{64}) (.+)$/;

export function validateResourceRef(ref: string): string | null {
  if (/^https:\/\/[^/\s]+/i.test(ref)) return null;
  if (/^[a-z][a-z0-9+.-]*:/i.test(ref)) return `"${ref}": only https:// URLs and relative paths are allowed`;
  if (ref.startsWith("/")) return `"${ref}": absolute paths are not allowed`;
  if (ref.includes("\\")) return `"${ref}": use "/" as the path separator`;
  if (ref.split("/").some((seg) => seg === "..")) return `"${ref}": ".." is not allowed`;
  return null;
}

export function parseResources(value: string): { entries: ResourceEntry[]; errors: string[] } {
  const entries: ResourceEntry[] = [];
  const errors: string[] = [];
  for (const line of value.split("\n")) {
    const m = LINE_RE.exec(line);
    if (!m) {
      errors.push(`resources: expected "sha256:<hex> <ref>", got ${JSON.stringify(line)}`);
      continue;
    }
    const ref = m[2]!;
    const e = validateResourceRef(ref);
    if (e) errors.push(`resources: ${e}`);
    entries.push({ hash: m[1]!, ref, remote: /^https:\/\//i.test(ref) });
  }
  return { entries, errors };
}

export async function formatResources(items: { ref: string; bytes: Uint8Array }[]): Promise<string> {
  const lines: string[] = [];
  for (const it of items) {
    const e = validateResourceRef(it.ref);
    if (e) throw new Error(e);
    lines.push(`sha256:${toHex(await sha256(it.bytes))} ${it.ref}`);
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
  loadResource?: (ref: string) => Promise<Uint8Array | null>;
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
        bytes = await o.loadResource(e.ref);
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
  return [...refs].filter((r) => !/^[a-z][a-z0-9+.-]*:/i.test(r) && !r.startsWith("#") && validateResourceRef(r) === null);
}
