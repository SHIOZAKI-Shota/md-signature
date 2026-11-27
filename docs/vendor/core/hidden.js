import { CONTROL_RE } from "./charclass.js";
// --- hidden characters (SPEC 9.5)
// SPEC 3.2 rule 4 without tab, LF and CR, noncharacters, and Default_Ignorable characters outside Cf (pinned like rule 4)
const RULE4 = CONTROL_RE.source.replace("\\u0000-\\u001f", "\\u0000-\\u0008\\u000b\\u000c\\u000e-\\u001f").replace(/^\[/, "").replace(/\]$/, "");
const NONCHARACTERS = "\\ufdd0-\\ufdef\\ufffe\\uffff" + Array.from({ length: 16 }, (_, i) => `\\u{${(i + 1).toString(16)}fffe}\\u{${(i + 1).toString(16)}ffff}`).join("");
const IGNORABLE = "\\u034f\\u115f\\u1160\\u17b4\\u17b5\\u180b-\\u180f\\u3164\\ufe00-\\ufe0f\\uffa0\\u{e0100}-\\u{e01ef}";
export const HIDDEN_CHARACTER_RE = new RegExp(`[${RULE4}${NONCHARACTERS}${IGNORABLE}]`, "gu");
const ZWNJ = 0x200c;
const ZWJ = 0x200d;
const BLACK_FLAG = 0x1f3f4;
const PICTOGRAPHIC = /^\p{Extended_Pictographic}$/u;
const LETTER = /^[\p{L}\p{M}]$/u;
const JOINING_SCRIPTS = ["Arabic", "Syriac", "Nko", "Mongolian", "Devanagari", "Bengali", "Gurmukhi", "Gujarati", "Oriya", "Tamil", "Telugu", "Kannada", "Malayalam", "Sinhala", "Myanmar", "Khmer", "Tibetan", "Thaana"].map((s) => new RegExp(`^\\p{sc=${s}}$`, "u"));
const isTag = (cp) => cp >= 0xe0020 && cp <= 0xe007e;
const isVariation = (cp) => (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef);
const isSkinTone = (cp) => cp >= 0x1f3fb && cp <= 0x1f3ff;
const ch = (cp) => (cp === undefined ? "" : String.fromCodePoint(cp));
const ONE = new RegExp(`^${HIDDEN_CHARACTER_RE.source}$`, "u");
const hidden = (cp) => ONE.test(String.fromCodePoint(cp));
function context(cps, i) {
    const cp = cps[i];
    const prev = cps[i - 1];
    const next = cps[i + 1];
    if (cp === ZWJ) {
        let p = i - 1;
        while (p >= 0 && (cps[p] === 0xfe0f || isSkinTone(cps[p])))
            p--;
        if (PICTOGRAPHIC.test(ch(cps[p])) && PICTOGRAPHIC.test(ch(next)))
            return "emoji-sequence";
    }
    if (cp === ZWJ || cp === ZWNJ) {
        const a = ch(prev);
        const b = ch(next);
        if (LETTER.test(a) && LETTER.test(b) && JOINING_SCRIPTS.some((re) => re.test(a) && re.test(b)))
            return "joiner";
        return null;
    }
    if (isTag(cp) || cp === 0xe007f) {
        let p = i - 1;
        while (p >= 0 && isTag(cps[p]))
            p--;
        if (cps[p] !== BLACK_FLAG)
            return null;
        let n = i;
        while (n < cps.length && isTag(cps[n]))
            n++;
        return cps[n] === 0xe007f ? "emoji-tag" : null;
    }
    if (isVariation(cp))
        return prev !== undefined && !/^\s$/u.test(ch(prev)) && !hidden(prev) ? "variation" : null;
    return null;
}
export function findHiddenCharacters(text) {
    const out = [];
    let line = 1;
    let lineStart = 0;
    let index = 0;
    const cps = Array.from(text, (c) => c.codePointAt(0));
    cps.forEach((cp, i) => {
        const s = String.fromCodePoint(cp);
        if (hidden(cp))
            out.push({ index, line, column: index - lineStart + 1, codePoint: `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`, context: context(cps, i) });
        index += s.length;
        if (cp === 10) {
            line++;
            lineStart = index;
        }
    });
    return out;
}
