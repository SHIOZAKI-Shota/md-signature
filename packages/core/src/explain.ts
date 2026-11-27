import { parseRequire, parseRosterRef, type Requirement } from "./agreement.ts";
import { localizeMessage, type Lang } from "./messages.ts";

// --- require explanation (CLI_SPEC 3.11)

export interface RequireExplanation {
  ok: boolean;
  text: string;
  errors: string[];
  unsupported: string[];
  // advice that does not make the value invalid (tofu lines without pubkey=, indentation, older syntax)
  warnings: string[];
  hints: string[];
}

type RequirementLine = Pick<Requirement, "method" | "signer" | "pattern" | "attributes">;

function target(r: RequirementLine, lang: Lang): string {
  const s = r.signer;
  const ja = lang === "ja";
  if (!r.pattern) return `${r.method}:${s}`;
  if (s === "*") return ja ? `${r.method} 方式の任意の署名者` : `any ${r.method} signer`;
  if (s.startsWith("*.")) return ja ? `${s.slice(2)} のサブドメインのいずれか（${s.slice(2)} 自体を除く）` : `any subdomain of ${s.slice(2)} (not ${s.slice(2)} itself)`;
  return ja ? `${s.slice(2)} のメールアドレスのいずれか（${r.method} 方式、サブドメインを除く）` : `any ${r.method} address at ${s.slice(2)} (not its subdomains)`;
}

export function describeRequirement(r: RequirementLine, lang: Lang = "en"): string {
  const a = r.attributes;
  const ja = lang === "ja";
  const parts: string[] = [];
  if (a.member_of) {
    const ref = parseRosterRef(a.member_of);
    parts.push(ref?.kind === "dns" ? (ja ? `${ref.domain} の DNS 名簿に掲載` : `on the DNS roster of ${ref.domain}`) : ja ? `名簿 ${a.member_of} に掲載` : `on the roster at ${a.member_of}`);
  }
  if (a.user_verified) parts.push(ja ? "パスキーの利用者確認（UV）あり" : "with passkey user verification");
  if (a.pubkey) parts.push(ja ? `鍵 ${a.pubkey.slice(0, 20)}… に限定` : `with key ${a.pubkey.slice(0, 20)}…`);
  if (r.pattern) parts.push(ja ? "宣言者自身を除く" : "not the declaring signer");
  const head = target(r, lang) + (a.role ? (ja ? `（役割 ${a.role}）` : ` with role ${a.role}`) : "");
  return parts.length ? head + (ja ? "、" : ", ") + parts.join(ja ? "、" : ", ") : head;
}

const ORDER_TEXT = {
  ja: {
    pending: "順序：pending（順番より前の署名は数えない）",
    guide: "順序：guide（順番より前の署名も数え、順序違反として報告する）",
    strict: "順序：strict（順番より前の署名があると、合意は違反として失敗する）",
  },
  en: {
    pending: "order: pending (signatures before their turn are not counted)",
    guide: "order: guide (signatures before their turn are counted and reported)",
    strict: "order: strict (a signature before its turn makes the agreement violated)",
  },
};

export function explainRequire(value: string, lang: Lang = "en"): RequireExplanation {
  const p = parseRequire(value);
  const ja = lang === "ja";
  const lines: string[] = [ORDER_TEXT[lang][p.spec.order]];
  for (const s of p.spec.steps) {
    const head = s.any !== null ? (ja ? `段階 ${s.step}：次のうち異なる${s.any}者` : `step ${s.step}: any ${s.any} different signers of`) : ja ? `段階 ${s.step}：次のすべて` : `step ${s.step}: all of`;
    lines.push(head);
    for (const r of s.lines) lines.push(`  ${describeRequirement(r, lang)}`);
  }
  const warnings: string[] = [];
  for (const r of p.requirements) {
    // SPEC 5.8.2: verifiers warn that a tofu line without pubkey= can be met by anyone using the name
    if (r.method === "tofu" && !r.attributes.pubkey) warnings.push(ja ? `${r.line}行目：tofu:${r.signer} に pubkey= がないため、この名前を名乗る誰でも満たせる` : `line ${r.line}: tofu:${r.signer} has no pubkey=, so anyone using that name can meet it`);
  }
  // indentation carries no structure (SPEC 3.5), but a requirement indented no deeper than its step line is likely a mistake
  const raws = value.split("\n");
  const indent = (l: string) => l.length - l.replace(/^ +/, "").length;
  let stepIndent: number | undefined;
  raws.forEach((l, i) => {
    const t = l.trimStart();
    if (t === "step" || t.startsWith("step ")) stepIndent = indent(l);
    else if (stepIndent !== undefined && !t.startsWith("order ") && raws.some((x) => indent(x) > 0) && indent(l) <= stepIndent) {
      warnings.push(ja ? `${i + 1}行目：字下げが段階の構造と一致しない` : `line ${i + 1}: the indentation does not match the step structure`);
    }
  });
  const loc = (list: string[]) => list.map((m) => localizeMessage(m, lang));
  return { ok: !p.errors.length && !p.unsupported.length, text: lines.join("\n"), errors: loc(p.errors), unsupported: loc(p.unsupported), warnings, hints: loc(p.hints) };
}
