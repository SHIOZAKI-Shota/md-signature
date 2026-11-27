import { normalizeDocument } from "./canonical.ts";
import { linesWithFence } from "./parser.ts";
import { parseListLine } from "./listline.ts";

export interface Section {
  id: string;
  start: number;
  end: number;
  line: number;
}

const BEGIN = /^<!-- mdsig:section ([a-z0-9-]+) -->[ \t]*$/;
const END = /^<!-- \/mdsig:section -->[ \t]*$/;
const LOOKS_LIKE_MARKER = /^<!-- \/?mdsig:section\b/;
const ID_RE = /^[a-z0-9-]+$/;

export function findSections(text: string): { sections: Map<string, Section>; errors: string[] } {
  const sections = new Map<string, Section>();
  const errors: string[] = [];
  let open: { id: string; start: number; line: number } | null = null;
  for (const { line, index, offset, inFence } of linesWithFence(text)) {
    if (inFence || !LOOKS_LIKE_MARKER.test(line)) continue;
    const b = BEGIN.exec(line);
    if (b) {
      if (open) {
        errors.push(`line ${index + 1}: section "${b[1]}" starts inside section "${open.id}" (nesting is not allowed)`);
        continue;
      }
      if (sections.has(b[1]!)) errors.push(`line ${index + 1}: section id "${b[1]}" is used twice`);
      open = { id: b[1]!, start: offset, line: index + 1 };
      continue;
    }
    if (END.test(line)) {
      if (!open) {
        errors.push(`line ${index + 1}: end marker without a matching begin marker`);
        continue;
      }
      if (!sections.has(open.id)) sections.set(open.id, { id: open.id, start: open.start, end: offset + line.length, line: open.line });
      open = null;
      continue;
    }
    errors.push(`line ${index + 1}: malformed section marker ${JSON.stringify(line)}`);
  }
  if (open) errors.push(`line ${open.line}: section "${open.id}" is never closed`);
  return { sections, errors };
}

// SPEC 5.6: one section id per line, leading spaces ignored, ids unique
export function parseScope(value: string): string[] | null {
  const ids: string[] = [];
  for (const raw of value.split("\n")) {
    const { line } = parseListLine(raw, {});
    if (!line || line.attrs.size || !ID_RE.test(line.target)) return null;
    ids.push(line.target);
  }
  return new Set(ids).size === ids.length ? ids : null;
}

export type ScopeInput =
  | { ok: true; input: string; ids: string[] }
  | { ok: false; code: "malformed" | "scope-missing"; message: string };

// SPEC 5.6: hash input = normalized sections concatenated in scope order
export function scopedHashInput(slice: string, scope: string): ScopeInput {
  const ids = parseScope(scope);
  if (!ids) return { ok: false, code: "malformed", message: `invalid scope "${scope}" (expected one section id per line, each id unique)` };
  const { sections, errors } = findSections(slice);
  if (errors.length) return { ok: false, code: "malformed", message: `section markers: ${errors.join("; ")}` };
  let input = "";
  for (const id of ids) {
    const s = sections.get(id);
    if (!s) return { ok: false, code: "scope-missing", message: `section "${id}" not found` };
    input += normalizeDocument(slice.slice(s.start, s.end));
  }
  return { ok: true, input, ids };
}
