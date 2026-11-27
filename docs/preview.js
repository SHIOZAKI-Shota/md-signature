import { t, onLangChange } from "./i18n.js";
import { parseDocument, findSignatureMarker, signatureTable } from "./vendor/core/index.js";

const editor = document.getElementById("editor");
const panel = document.getElementById("panel-preview");
const out = document.getElementById("preview");
const note = document.getElementById("preview-note");

// Document content must not style, name or script anything outside its own text: no CSS, no ids or classes, no form controls.
const SANITIZE = {
  USE_PROFILES: { html: true },
  ALLOW_DATA_ATTR: false,
  ALLOW_ARIA_ATTR: false,
  FORBID_TAGS: ["style", "form", "input", "button", "select", "textarea", "label", "option", "optgroup", "fieldset", "legend", "datalist", "output", "meter", "progress", "dialog", "template", "audio", "video", "source", "track", "picture", "map", "area"],
  FORBID_ATTR: ["style", "class", "id", "name", "for", "hidden", "role", "tabindex", "slot", "usemap", "popover", "popovertarget", "popovertargetaction", "color", "bgcolor", "background", "face", "srcset", "sizes", "download", "contenteditable", "draggable", "inert"],
  RETURN_DOM_FRAGMENT: true,
};

let md = null;
function renderer() {
  // Task-list boxes are drawn as text because form controls are not allowed in the preview.
  md ??= new window.marked.Marked({ gfm: true, renderer: { checkbox: ({ checked }) => (checked ? "\u2611" : "\u2610") } });
  return md;
}

let last = null;
// the latest verification result from app.js; the table is drawn only when it belongs to the text on screen
let verified = null;
document.addEventListener("mdsig:verified", (e) => {
  verified = e.detail;
  render(true);
});

function renderPart(m, tokens, links, offset) {
  // The part and each block wrapper (with its source line, used by scroll-sync.js) are created after sanitising, so content cannot forge them.
  const part = document.createElement("article");
  part.className = "md-preview";
  let line = offset;
  for (const tok of tokens) {
    const start = line;
    line += (tok.raw.match(/\n/g) || []).length;
    if (tok.type === "space") continue;
    const one = [tok];
    one.links = links;
    const blk = document.createElement("div");
    blk.className = "md-blk";
    blk.dataset.line = String(start);
    blk.append(window.DOMPurify.sanitize(m.parser(one), SANITIZE));
    part.append(blk);
  }
  return part;
}

// ------------------------------------------------------------------ signature table
const host = (u) => {
  try {
    return new URL(u).host;
  } catch {
    return u;
  }
};
// the core reports key sources as English text; known kinds get a label, anything else is shown as it is
function keySourceText(src, method) {
  if (!src) return "";
  let m;
  if (src === "embedded pubkey") return t(method === "tofu" ? "tbl.src.tofu" : "tbl.src.snapshot");
  if ((m = /^DNS TXT (\S+)$/.exec(src))) return t("tbl.src.dns", { name: m[1] });
  if ((m = /^test TXT (\S+)$/.exec(src))) return t("tbl.src.test", { name: m[1] });
  if ((m = /^test key (\S+)/.exec(src))) return t("tbl.src.test", { name: m[1] });
  if ((m = /^key directory (\S+) \((.*)\)$/.exec(src))) return t(m[2] === "trusted list" ? "tbl.src.dir-trusted" : "tbl.src.dir-named", { dir: host(m[1]) });
  if (src === "keyring") return t("tbl.src.keyring");
  if ((m = /^(wkd|keyserver)(?: (\S+))?$/.exec(src))) return t(`tbl.src.${m[1]}`, { host: m[2] ? host(m[2]) : "" });
  if ((m = /^(https:\/\/\S+) \((SHA256:\S+)\)$/.exec(src))) return t("tbl.src.git", { host: host(m[1]), fp: m[2] });
  if ((m = /^TSA (.*)$/.exec(src))) return t("tbl.src.tsa", { name: m[1] });
  return src;
}

const STATUS = new Set(["valid", "invalid", "malformed", "unresolved", "unsupported", "unsigned"]);
const ATTR_ORDER = ["role", "user_verified", "member_of", "pubkey"];

function cellEl(...parts) {
  const td = document.createElement("td");
  for (const p of parts) if (p != null && p !== "") td.append(p);
  return td;
}
function span(cls, text, title) {
  const e = document.createElement("span");
  if (cls) e.className = cls;
  e.textContent = text;
  if (title) e.title = title;
  return e;
}
// "2026-11-27T04:56:05Z" breaks after the date
const timeCell = (v) => (v ? cellEl(span("tbl-date", v.slice(0, 10)), span("tbl-time", v.slice(10))) : cellEl());

function attrChips(attrs) {
  return Object.entries(attrs ?? {})
    .sort(([x], [y]) => (ATTR_ORDER.indexOf(x) + 1 || 99) - (ATTR_ORDER.indexOf(y) + 1 || 99))
    .map(([k, v]) => {
      if (k === "role") return span("tbl-chip", t("tbl.attr.role", { role: v }));
      if (k === "user_verified") return span("tbl-chip", t("tbl.attr.uv"));
      if (k === "member_of") return span("tbl-chip", t("tbl.attr.member", { roster: String(v).replace(/^https:\/\//, "") }), String(v));
      if (k === "pubkey") {
        const s = String(v);
        const i = s.indexOf(":");
        const b = s.slice(i + 1);
        return span("tbl-chip", `pubkey=${s.slice(0, i + 1)}${b.length > 12 ? b.slice(0, 4) + "…" + b.slice(-4) : b}`, s);
      }
      return span("tbl-chip", v === true ? k : `${k}=${v}`);
    });
}

function tableEl(rows) {
  const table = document.createElement("table");
  table.className = "sig-rows";
  const cap = document.createElement("caption");
  cap.textContent = t("tbl.caption");
  const head = document.createElement("tr");
  // columns with nothing in any row (no tsa block, no passkey, no display name) are left out to keep the table narrow
  const has = { name: rows.some((r) => r.displayName), time: rows.some((r) => r.time), uv: rows.some((r) => r.userVerified !== null) };
  const cols = ["no", "name", "signer", "source", "role", "ts", "time", "uv", "status"].filter((k) => has[k] ?? true);
  for (const k of cols) {
    const th = document.createElement("th");
    th.scope = "col";
    th.textContent = t(`tbl.h.${k}`);
    th.className = `c-${k}`;
    head.append(th);
  }
  const thead = document.createElement("thead");
  thead.append(head);
  const tbody = document.createElement("tbody");
  for (const r of rows) {
    const tr = document.createElement("tr");
    tr.className = `is-${STATUS.has(r.status) ? r.status : "other"}`;
    const unsigned = r.status === "unsigned";
    const no = unsigned ? t("tbl.step", { step: r.step ?? 0, need: r.need ?? 0 }) : `#${r.number}`;
    // break opportunities after ":", "@", "/" and "." instead of inside a name
    const id = span("tbl-id", "");
    for (const part of `${r.method}:${r.signer}`.split(/(?<=[:@/.])/)) id.append(part, document.createElement("wbr"));
    const signer = cellEl(id);
    if (unsigned) {
      // the role has its own column
      const chips = attrChips(Object.fromEntries(Object.entries(r.attributes ?? {}).filter(([k]) => k !== "role")));
      if (r.pattern && r.need) chips.push(span("tbl-chip", t("tbl.any", { n: r.need })));
      if (chips.length) signer.append(document.createElement("br"), ...chips);
    }
    let status = STATUS.has(r.status) ? t(`tbl.st.${r.status}`) : r.status;
    if (r.partial) status += t("tbl.partial", { sections: r.partial.join(", ") });
    if (r.code && r.status !== "valid" && !unsigned) status += ` (${r.code})`;
    const cells = {
      no: () => cellEl(no),
      name: () => cellEl(r.displayName ? r.displayName + t("tbl.declared") : ""),
      signer: () => signer,
      source: () => cellEl(unsigned ? "" : keySourceText(r.keySource, r.method)),
      role: () => cellEl(r.role ?? ""),
      ts: () => timeCell(r.ts),
      time: () => timeCell(r.time),
      uv: () => cellEl(r.userVerified === null ? "" : t(r.userVerified ? "tbl.yes" : "tbl.no")),
      status: () => cellEl(status),
    };
    tr.append(
      ...cols.map((k) => {
        const td = cells[k]();
        td.className = `c-${k}`;
        return td;
      }),
    );
    tbody.append(tr);
  }
  table.append(cap, thead, tbody);
  return table;
}

// SPEC 5.11, 9.5: the table sits between separately rendered parts of the body, outside any sanitized content
function signatureSection(text) {
  const sec = document.createElement("section");
  sec.className = "sig-table";
  sec.setAttribute("aria-label", t("pv.table"));
  const head = document.createElement("p");
  head.className = "sig-table-note";
  head.textContent = t("pv.tableNote");
  const wrap = document.createElement("div");
  wrap.className = "sig-table-wrap";
  if (verified && verified.text === text) wrap.append(tableEl(signatureTable(verified.result)));
  else wrap.textContent = t("pv.tablePending");
  sec.append(head, wrap);
  return sec;
}

function render(force = false) {
  if (!panel || panel.hidden) return;
  const text = editor.value;
  if (!force && text === last) return;
  last = text;
  const norm = text.replace(/\r\n?/g, "\n");
  const doc = parseDocument(norm);
  const n = doc.chain.length;
  note.textContent = n ? t("pv.note", { n }) : t("pv.noteNone");
  note.classList.toggle("has-sigs", n > 0);
  const { marked, DOMPurify } = window;
  if (!marked || !DOMPurify) {
    out.textContent = t("pv.unavailable");
    return;
  }
  const m = renderer();
  const marker = n ? findSignatureMarker(doc.body).line : undefined;
  // SPEC 9.5, CLI_SPEC 3.10: lex once; the table goes after the top-level block holding the marker
  const tokens = m.lexer(norm);
  let cut = -1;
  let cutLine = 0;
  if (marker) {
    let line = 0;
    tokens.forEach((tok, i) => {
      const start = line;
      line += (tok.raw.match(/\n/g) || []).length;
      if (tok.type !== "space" && start <= marker - 1) {
        cut = i;
        cutLine = line;
      }
    });
  }
  const before = cut >= 0 ? tokens.slice(0, cut + 1) : tokens;
  if (cut >= 0 && before[cut].type === "html" && before[cut].raw.trim() === "<!-- mdsig:signatures -->") before.pop();
  const nodes = [renderPart(m, before, tokens.links, 0)];
  if (n) nodes.push(signatureSection(text));
  if (cut >= 0) nodes.push(renderPart(m, tokens.slice(cut + 1), tokens.links, cutLine));
  out.replaceChildren(...nodes);
  out.dispatchEvent(new Event("rendered"));
  for (const a of out.querySelectorAll(".md-preview a[href]")) {
    a.target = "_blank";
    a.rel = "noopener noreferrer";
  }
}

if (panel) new MutationObserver(() => render(true)).observe(panel, { attributes: true, attributeFilter: ["hidden"] });
editor.addEventListener("input", () => render());
setInterval(() => render(), 400);
onLangChange(() => render(true));
