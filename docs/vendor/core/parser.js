import { CLOSE_LINE, KNOWN_KEYS, OPEN_LINE, isExtensionKey, normalizeNewlines, validateValue } from "./canonical.js";
const FIELD_LINE = /^([a-z][a-z0-9_]*): (.*)$/;
const CONT_LINE = /^ {2}(\S.*)$/;
const isBlank = (l) => /^[ \t]*$/.test(l);
const isOpen = (l) => l.replace(/[ \t]+$/, "") === OPEN_LINE;
const isClose = (l) => l.replace(/[ \t]+$/, "") === CLOSE_LINE;
const isFieldish = (l) => FIELD_LINE.test(l) || CONT_LINE.test(l);
export const REQUIRED_KEYS = ["v", "method", "signer", "ts", "hash", "sig"];
export function parseFields(lines) {
    const fields = Object.create(null);
    const errors = [];
    const unknownKeys = [];
    let i = 0;
    while (i < lines.length) {
        const line = lines[i];
        const m = FIELD_LINE.exec(line);
        if (!m) {
            errors.push(`line ${i + 1}: expected "key: value", got ${JSON.stringify(line)}`);
            i++;
            continue;
        }
        const key = m[1];
        let value = m[2];
        i++;
        let folded = false;
        if (value === "|") {
            folded = true;
            const parts = [];
            while (i < lines.length) {
                const c = CONT_LINE.exec(lines[i]);
                if (!c)
                    break;
                parts.push(c[1].replace(/[ \t]+$/, ""));
                i++;
            }
            if (parts.length === 0)
                errors.push(`${key}: folded value has no continuation lines`);
            value = parts.join("\n"); // SPEC 3.2 rule 7: lines are joined by LF
        }
        if (key in fields) {
            errors.push(`duplicate key "${key}"`);
            continue;
        }
        if (!KNOWN_KEYS.has(key) && !isExtensionKey(key)) {
            unknownKeys.push(key);
            errors.push(`unknown field "${key}" (extension fields must start with "x_")`);
        }
        const ve = validateValue(value, folded);
        if (ve)
            errors.push(`${key}: ${ve}`);
        fields[key] = value;
    }
    for (const k of REQUIRED_KEYS)
        if (!(k in fields))
            errors.push(`missing required field "${k}"`);
    return { fields: { ...fields }, errors, unknownKeys };
}
export function* linesWithFence(text) {
    let fence = null;
    let offset = 0;
    const lines = text.split("\n");
    for (let k = 0; k < lines.length; k++) {
        const l = lines[k];
        const fm = /^ {0,3}(`{3,}|~{3,})/.exec(l);
        let inFence = fence !== null;
        if (fm) {
            if (fence === null)
                fence = fm[1];
            else if (fm[1][0] === fence[0] && fm[1].length >= fence.length && /^ {0,3}[`~]+[ \t]*$/.test(l))
                fence = null;
            inFence = true;
        }
        yield { line: l, index: k, offset, inFence };
        offset += l.length + 1;
    }
}
export function parseDocument(input) {
    const text = normalizeNewlines(input);
    const lines = text.split("\n");
    const offsets = [];
    {
        let o = 0;
        for (const l of lines) {
            offsets.push(o);
            o += l.length + 1;
        }
    }
    // SPEC 5.2: the chain is the run of blocks at the end, scanned backwards
    const found = [];
    let i = lines.length - 1;
    for (;;) {
        while (i >= 0 && isBlank(lines[i]))
            i--;
        if (i < 0 || !isClose(lines[i]))
            break;
        let j = i - 1;
        while (j >= 0 && !isOpen(lines[j]) && isFieldish(lines[j]))
            j--;
        if (j < 0 || !isOpen(lines[j]))
            break;
        const { fields, errors, unknownKeys } = parseFields(lines.slice(j + 1, i));
        const start = offsets[j];
        const end = offsets[i] + lines[i].length;
        found.push({ start, end, line: j + 1, raw: text.slice(start, end), fields, errors, unknownKeys });
        i = j - 1;
    }
    found.reverse();
    const chain = found.map((b, k) => ({ ...b, index: k + 1 }));
    const bodyEnd = chain.length ? chain[0].start : text.length;
    const body = text.slice(0, bodyEnd);
    // markers inside code fences are examples, not stray
    let strayMarkerLine;
    for (const { line, index, inFence } of linesWithFence(body)) {
        if (!inFence && isOpen(line))
            strayMarkerLine = index + 1;
    }
    return { text, body, chain, strayMarker: strayMarkerLine !== undefined, strayMarkerLine };
}
