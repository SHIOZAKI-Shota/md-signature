import { normalizeDocument } from "./canonical.js";
import { linesWithFence } from "./parser.js";
const BEGIN = /^<!-- mdsig:section ([a-z0-9-]+) -->[ \t]*$/;
const END = /^<!-- \/mdsig:section -->[ \t]*$/;
const LOOKS_LIKE_MARKER = /^<!-- \/?mdsig:section\b/;
const SCOPE_RE = /^section:[a-z0-9-]+(,section:[a-z0-9-]+)*$/;
export function findSections(text) {
    const sections = new Map();
    const errors = [];
    let open = null;
    for (const { line, index, offset, inFence } of linesWithFence(text)) {
        if (inFence || !LOOKS_LIKE_MARKER.test(line))
            continue;
        const b = BEGIN.exec(line);
        if (b) {
            if (open) {
                errors.push(`line ${index + 1}: section "${b[1]}" starts inside section "${open.id}" (nesting is not allowed)`);
                continue;
            }
            if (sections.has(b[1]))
                errors.push(`line ${index + 1}: section id "${b[1]}" is used twice`);
            open = { id: b[1], start: offset, line: index + 1 };
            continue;
        }
        if (END.test(line)) {
            if (!open) {
                errors.push(`line ${index + 1}: end marker without a matching begin marker`);
                continue;
            }
            if (!sections.has(open.id))
                sections.set(open.id, { id: open.id, start: open.start, end: offset + line.length, line: open.line });
            open = null;
            continue;
        }
        errors.push(`line ${index + 1}: malformed section marker ${JSON.stringify(line)}`);
    }
    if (open)
        errors.push(`line ${open.line}: section "${open.id}" is never closed`);
    return { sections, errors };
}
export function parseScope(value) {
    if (!SCOPE_RE.test(value))
        return null;
    const ids = value.split(",").map((s) => s.slice("section:".length));
    return new Set(ids).size === ids.length ? ids : null;
}
// SPEC 5.6: hash input = normalised sections concatenated in scope order
export function scopedHashInput(slice, scope) {
    const ids = parseScope(scope);
    if (!ids)
        return { ok: false, code: "malformed", message: `invalid scope "${scope}" (expected section:<id>[,section:<id>...] with unique ids)` };
    const { sections, errors } = findSections(slice);
    if (errors.length)
        return { ok: false, code: "malformed", message: `section markers: ${errors.join("; ")}` };
    let input = "";
    for (const id of ids) {
        const s = sections.get(id);
        if (!s)
            return { ok: false, code: "scope-missing", message: `section "${id}" not found` };
        input += normalizeDocument(slice.slice(s.start, s.end));
    }
    return { ok: true, input, ids };
}
