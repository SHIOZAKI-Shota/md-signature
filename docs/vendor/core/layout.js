import { parseDocument } from "./parser.js";
import { findSections, parseScope } from "./scope.js";
function lineAt(text, offset) {
    let n = 1;
    for (let i = 0; i < offset && i < text.length; i++)
        if (text.charCodeAt(i) === 10)
            n++;
    return n;
}
function lastContentLine(lines, from, to) {
    let l = to;
    while (l >= from && /^[ \t]*$/.test(lines[l - 1] ?? ""))
        l--;
    return l;
}
export function documentLayout(input) {
    const doc = parseDocument(input);
    const text = doc.text;
    const lines = text.split("\n");
    const lineCount = text.endsWith("\n") ? lines.length - 1 : lines.length;
    const blocks = doc.chain.map((b) => ({ index: b.index, from: b.line, to: lineAt(text, b.end - 1) }));
    const coverage = doc.chain.map((b) => {
        const before = b.line - 1;
        const sections = b.fields.scope ? parseScope(b.fields.scope) : null;
        if (sections) {
            const slice = text.slice(0, b.start);
            const found = findSections(slice).sections;
            const ranges = [];
            for (const id of sections) {
                const s = found.get(id);
                if (s)
                    ranges.push({ from: s.line, to: s.line + (slice.slice(s.start, s.end).match(/\n/g)?.length ?? 0) });
            }
            return { index: b.index, ranges, sections };
        }
        const to = lastContentLine(lines, 1, before);
        return { index: b.index, ranges: to >= 1 ? [{ from: 1, to }] : [], sections: null };
    });
    const first = doc.chain[0];
    const bodyTo = lastContentLine(lines, 1, first ? first.line - 1 : lineCount);
    let tail = null;
    let strayLine = null;
    let strayBlock = null;
    if (doc.strayMarker && doc.strayMarkerLine) {
        if (doc.chain.length === 0) {
            let close = doc.strayMarkerLine;
            while (close <= lineCount && (lines[close - 1] ?? "").replace(/[ \t]+$/, "") !== "-->")
                close++;
            let from = close + 1;
            while (from <= lineCount && /^[ \t]*$/.test(lines[from - 1] ?? ""))
                from++;
            const to = lastContentLine(lines, from, lineCount);
            tail = to >= from ? { from, to } : { from: doc.strayMarkerLine, to: lineCount };
            if (close <= lineCount)
                strayBlock = { from: doc.strayMarkerLine, to: close };
        }
        else {
            strayLine = doc.strayMarkerLine;
        }
    }
    return { lineCount, body: bodyTo >= 1 ? { from: 1, to: bodyTo } : null, blocks, coverage, tail, strayLine, strayBlock };
}
