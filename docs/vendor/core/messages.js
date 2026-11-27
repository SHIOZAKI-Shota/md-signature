import { MESSAGES_JA } from "./messages-ja.js";
const MAX_DEPTH = 8;
const PLACEHOLDER_RE = /\{(\d+)(:msg)?\}/g;
let compiled;
function catalog() {
    compiled ??= MESSAGES_JA.map(([en, ja]) => ({ re: new RegExp(en), ja }));
    return compiled;
}
function localize(text, depth) {
    if (depth > MAX_DEPTH)
        return text;
    for (const { re, ja } of catalog()) {
        const m = re.exec(text);
        if (!m)
            continue;
        return ja.replace(PLACEHOLDER_RE, (_, n, msg) => {
            const g = m[Number(n)] ?? "";
            return msg ? localize(g, depth + 1) : g;
        });
    }
    return text;
}
export function localizeMessage(text, lang) {
    return lang === "ja" ? localize(text, 0) : text;
}
