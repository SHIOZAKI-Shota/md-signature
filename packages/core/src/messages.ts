import { MESSAGES_JA } from "./messages-ja.ts";

// --- localized messages

export type Lang = "ja" | "en";

const MAX_DEPTH = 8;
const PLACEHOLDER_RE = /\{(\d+)(:msg)?\}/g;
let compiled: { re: RegExp; ja: string }[] | undefined;

function catalog(): { re: RegExp; ja: string }[] {
  compiled ??= MESSAGES_JA.map(([en, ja]) => ({ re: new RegExp(en), ja }));
  return compiled;
}

function localize(text: string, depth: number): string {
  if (depth > MAX_DEPTH) return text;
  for (const { re, ja } of catalog()) {
    const m = re.exec(text);
    if (!m) continue;
    return ja.replace(PLACEHOLDER_RE, (_, n: string, msg: string | undefined) => {
      const g = m[Number(n)] ?? "";
      return msg ? localize(g, depth + 1) : g;
    });
  }
  return text;
}

export function localizeMessage(text: string, lang: Lang): string {
  return lang === "ja" ? localize(text, 0) : text;
}
