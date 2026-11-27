import { CLOSE_LINE, KNOWN_KEYS, OPEN_LINE, isExtensionKey, normalizeNewlines, validateValue } from "./canonical.js";
// the s flag: a value with U+2028 or U+2029 is still read as one line, and then rejected by rule 4
const FIELD_LINE = /^([a-z][a-z0-9_]*): (.*)$/s;
// SPEC 3.2: cont-line = 2SP *SP vchar ...; spaces after the first two belong to the value
const CONT_LINE = /^ {2}(?= *[^ ])(.*)$/s;
const isBlank = (l) => /^[ \t]*$/.test(l);
const isOpen = (l) => l.replace(/[ \t]+$/, "") === OPEN_LINE;
const isClose = (l) => l.replace(/[ \t]+$/, "") === CLOSE_LINE;
const isFieldish = (l) => FIELD_LINE.test(l) || CONT_LINE.test(l);
export const REQUIRED_KEYS = ["v", "method", "signer", "ts", "alg", "hash", "sig"];
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
                parts.push(c[1]);
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
        if (!folded || value !== "") {
            const ve = validateValue(value, folded);
            if (ve)
                errors.push(`${key}: ${ve}`);
        }
        fields[key] = value;
    }
    for (const k of REQUIRED_KEYS)
        if (!(k in fields))
            errors.push(`missing required field "${k}"`);
    return { fields: { ...fields }, errors, unknownKeys };
}
const FENCE_OPEN = /^ {0,3}(`{3,}|~{3,})(.*)$/;
const FENCE_CLOSE = /^ {0,3}(`{3,}|~{3,})[ \t]*$/;
// SPEC 5.5 (CommonMark 4.5): a backtick fence's info string cannot contain a backtick
function fenceOpen(l) {
    const m = FENCE_OPEN.exec(l);
    return m && m[1][0] === "`" && m[2].includes("`") ? null : m;
}
// SPEC 5.5: a line scan, not a full CommonMark parse; a fence closes with the same character at least as many times
export function* linesWithFence(text) {
    let fence = null;
    let offset = 0;
    const lines = text.split("\n");
    for (let k = 0; k < lines.length; k++) {
        const l = lines[k];
        if (fence === null) {
            const open = fenceOpen(l);
            if (open) {
                fence = open[1];
                yield { line: l, index: k, offset, inFence: true, info: open[2].trim() };
            }
            else {
                yield { line: l, index: k, offset, inFence: false };
            }
        }
        else {
            const close = FENCE_CLOSE.exec(l);
            const closes = !!close && close[1][0] === fence[0] && close[1].length >= fence.length;
            if (closes)
                fence = null;
            yield { line: l, index: k, offset, inFence: true, ...(closes ? { close: true } : {}) };
        }
        offset += l.length + 1;
    }
}
export function endsInOpenFence(text) {
    let fence = null;
    for (const l of text.split("\n")) {
        if (fence === null) {
            const open = fenceOpen(l);
            if (open)
                fence = open[1];
        }
        else {
            const close = FENCE_CLOSE.exec(l);
            if (close && close[1][0] === fence[0] && close[1].length >= fence.length)
                fence = null;
        }
    }
    return fence !== null;
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
    return { text, body, chain, strayMarker: strayMarkerLine !== undefined, strayMarkerLine, unclosedFence: endsInOpenFence(body) };
}
