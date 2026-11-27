import { linesWithFence } from "./parser.js";
// --- Signature table (SPEC 5.11, 9.5, CLI_SPEC 3.10): built from the blocks, never written into the body
export const SIGNATURE_MARKER = "<!-- mdsig:signatures -->";
const MARKER_RE = /^<!-- mdsig:signatures -->[ \t]*$/;
// SPEC 5.11: one marker per body, outside code fences; later ones and fenced ones are ignored with a warning
export function findSignatureMarker(body) {
    let found;
    const warnings = [];
    for (const l of linesWithFence(body)) {
        if (!MARKER_RE.test(l.line))
            continue;
        if (l.inFence)
            warnings.push(`line ${l.index + 1}: ${SIGNATURE_MARKER} inside a code fence is ignored`);
        else if (found)
            warnings.push(`line ${l.index + 1}: only the first ${SIGNATURE_MARKER} is used; this one is ignored`);
        else
            found = { line: l.index + 1, offset: l.offset };
    }
    return { ...(found ?? {}), warnings };
}
function unsignedRow(r, need) {
    return {
        number: null,
        displayName: null,
        method: r.method,
        signer: r.signer,
        keySource: null,
        role: r.attributes.role ?? null,
        ts: null,
        time: null,
        userVerified: r.attributes.user_verified ? false : null,
        status: "unsigned",
        code: null,
        partial: null,
        declaredBy: r.declaredBy,
        step: r.step,
        need,
        pattern: r.pattern,
        attributes: { ...r.attributes },
    };
}
export function signatureTable(result) {
    const rows = [];
    for (const s of result.signatures) {
        if (s.fields.method === "tsa")
            continue;
        rows.push({
            number: s.index,
            displayName: s.fields.display_name ?? null,
            method: s.fields.method ?? "",
            signer: s.fields.signer ?? "",
            keySource: s.status === "valid" ? (s.key?.source ?? null) : null,
            role: s.fields.role ?? null,
            ts: s.fields.ts ?? null,
            time: s.time?.at ?? null,
            userVerified: s.fields.alg === "webauthn-es256" ? (s.status === "valid" && !!s.webauthn?.userVerified) : null,
            status: s.status,
            code: s.code ?? null,
            partial: s.partial?.sections ?? null,
        });
    }
    // CLI_SPEC 3.10: unsigned rows come from next
    for (const n of result.agreement.next) {
        for (const r of n.candidates)
            rows.push(unsignedRow(r, n.need));
        for (const l of n.later)
            for (const r of l.lines)
                rows.push(unsignedRow(r, l.need));
    }
    return rows;
}
const LABELS = {
    ja: {
        caption: "署名欄",
        head: ["番号", "表示名（申告）", "署名者", "身元の確認", "役割", "申告時刻", "時刻証明", "利用者確認", "状態"],
        status: { valid: "有効", invalid: "無効", malformed: "形式不正", unresolved: "未確認", unsupported: "未対応", unsigned: "未署名" },
        yes: "あり",
        no: "なし",
        partial: "部分",
        any: (n) => `いずれか ${n}者`,
        declared: "（申告）",
        step: (n, need) => `段階 ${n}、あと ${need}者`,
    },
    en: {
        caption: "Signatures",
        head: ["No.", "Display name (declared)", "Signer", "Identity check", "Role", "Declared time", "Timestamp", "User verified", "Status"],
        status: { valid: "Valid", invalid: "Invalid", malformed: "Malformed", unresolved: "Unresolved", unsupported: "Unsupported", unsigned: "Unsigned" },
        yes: "Yes",
        no: "No",
        partial: "partial",
        any: (n) => `any ${n}`,
        declared: " (declared)",
        step: (n, need) => `step ${n}, ${need} more`,
    },
};
const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
// security: every cell is escaped and nothing comes from the body; render it outside the sanitized body DOM (SPEC 9.5)
export function renderSignatureTableHtml(rows, lang = "en") {
    const L = LABELS[lang];
    const cell = (v) => `<td>${v === null ? "" : esc(v)}</td>`;
    const body = rows.map((r) => {
        const status = (L.status[r.status] ?? r.status) + (r.partial ? ` (${L.partial}: ${r.partial.join(", ")})` : "") + (r.code && r.status !== "valid" ? ` [${r.code}]` : "");
        const attrs = Object.entries(r.attributes ?? {}).map(([k, v]) => (v === true ? k : `${k}=${v}`));
        const signer = [`${r.method}:${r.signer}`, ...(r.status === "unsigned" ? attrs : [])].join(" ") + (r.status === "unsigned" && r.pattern && r.need ? ` (${L.any(r.need)})` : "");
        return (`<tr class="mdsig-${esc(r.status)}">` +
            cell(r.number === null ? L.step(r.step ?? 0, r.need ?? 0) : `#${r.number}`) +
            cell(r.displayName === null ? null : r.displayName + L.declared) +
            cell(signer) +
            cell(r.keySource) +
            cell(r.role) +
            cell(r.ts) +
            cell(r.time) +
            cell(r.userVerified === null ? null : r.userVerified ? L.yes : L.no) +
            cell(status) +
            "</tr>");
    });
    return `<table class="mdsig-signatures"><caption>${esc(L.caption)}</caption><thead><tr>${L.head.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${body.join("")}</tbody></table>`;
}
// snake_case rows, as in the JSON of CLI_SPEC 5 and examples/expected.json
export function signatureTableToJson(rows) {
    return rows.map((r) => ({
        number: r.number,
        display_name: r.displayName,
        method: r.method,
        signer: r.signer,
        key_source: r.keySource,
        role: r.role,
        ts: r.ts,
        time: r.time,
        user_verified: r.userVerified,
        status: r.status,
        code: r.code,
        partial: r.partial,
        ...(r.status === "unsigned" ? { declared_by: r.declaredBy, step: r.step, need: r.need, pattern: r.pattern, attributes: r.attributes } : {}),
    }));
}
