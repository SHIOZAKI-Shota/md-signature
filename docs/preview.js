import { t, onLangChange } from "./i18n.js";
import { parseDocument } from "./vendor/core/index.js";

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

function render(force = false) {
  if (!panel || panel.hidden) return;
  const text = editor.value;
  if (!force && text === last) return;
  last = text;
  const n = parseDocument(text).chain.length;
  note.textContent = n ? t("pv.note", { n }) : t("pv.noteNone");
  note.classList.toggle("has-sigs", n > 0);
  const { marked, DOMPurify } = window;
  if (!marked || !DOMPurify) {
    out.textContent = t("pv.unavailable");
    return;
  }
  const m = renderer();
  const tokens = m.lexer(text.replace(/\r\n?/g, "\n"));
  let line = 0;
  const blocks = [];
  for (const tok of tokens) {
    const start = line;
    line += (tok.raw.match(/\n/g) || []).length;
    if (tok.type === "space") continue;
    const one = [tok];
    one.links = tokens.links;
    // The wrapper and its source line (used by scroll-sync.js) are added after sanitising, so content cannot forge them.
    const blk = document.createElement("div");
    blk.className = "md-blk";
    blk.dataset.line = String(start);
    blk.append(DOMPurify.sanitize(m.parser(one), SANITIZE));
    blocks.push(blk);
  }
  out.replaceChildren(...blocks);
  out.dispatchEvent(new Event("rendered"));
  for (const a of out.querySelectorAll("a[href]")) {
    a.target = "_blank";
    a.rel = "noopener noreferrer";
  }
}

if (panel) new MutationObserver(() => render(true)).observe(panel, { attributes: true, attributeFilter: ["hidden"] });
editor.addEventListener("input", () => render());
setInterval(() => render(), 400);
onLangChange(() => render(true));
