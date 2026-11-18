// ------------------------------------------------------------------ editor-style code blocks
// <pre data-lang="ts" data-file="verify.ts"> gets a file tab, line numbers and token colours.

const STR = String.raw`"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|` + "`(?:\\\\.|[^`\\\\])*`";
const RULES = {
  ts: [
    ["c", String.raw`\/\/.*$`],
    ["s", STR],
    ["k", String.raw`\b(?:import|from|export|default|const|let|var|await|async|function|return|for|of|in|if|else|new|true|false|null|undefined|typeof)\b`],
    ["n", String.raw`\b\d+(?:\.\d+)?\b`],
    ["f", String.raw`\b[A-Za-z_$][\w$]*(?=\()`],
  ],
  go: [
    ["c", String.raw`\/\/.*$`],
    ["s", String.raw`"(?:\\.|[^"\\])*"|` + "`[^`]*`"],
    ["k", String.raw`\b(?:import|package|func|return|for|range|if|else|nil|true|false|var|const|type|struct|defer|go|map)\b`],
    ["n", String.raw`\b\d+(?:\.\d+)?\b`],
    ["f", String.raw`\b[A-Za-z_][\w]*(?=\()`],
  ],
  yaml: [
    ["c", String.raw`(?:^|\s)#.*$`],
    ["p", String.raw`^\s*(?:-\s+)?[\w.-]+(?=:)|(?<=[{,]\s*)[\w.-]+(?=:)`],
    ["s", String.raw`"(?:\\.|[^"\\])*"|'[^']*'`],
    ["k", String.raw`\b(?:true|false|null)\b`],
  ],
};
RULES.html = [["t", String.raw`<\/?[a-z][\w-]*|\/?>`], ["a", String.raw`\b[a-z-]+(?==)`], ...RULES.ts];

const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

function highlightLine(line, rules) {
  const re = new RegExp(rules.map(([name, src]) => `(?<${name}>${src})`).join("|"), "gm");
  let out = "";
  let last = 0;
  for (const m of line.matchAll(re)) {
    if (!m[0]) continue;
    const name = Object.keys(m.groups).find((k) => m.groups[k] !== undefined);
    out += esc(line.slice(last, m.index)) + `<span class="tk-${name}">${esc(m[0])}</span>`;
    last = m.index + m[0].length;
  }
  return out + esc(line.slice(last));
}

export function decorateCode(root = document) {
  for (const pre of root.querySelectorAll("pre[data-lang]:not([data-decorated])")) {
    const rules = RULES[pre.dataset.lang];
    if (!rules) continue;
    const code = pre.querySelector("code") ?? pre;
    const lines = code.textContent.replace(/\n$/, "").split("\n");
    code.innerHTML = lines.map((l) => `<span class="ln">${highlightLine(l, rules)}</span>`).join("\n");
    pre.dataset.decorated = "";
    const win = document.createElement("div");
    win.className = "code-win";
    const tab = document.createElement("div");
    tab.className = "code-tab";
    const name = document.createElement("span");
    name.textContent = pre.dataset.file || pre.dataset.lang;
    tab.append(name);
    pre.replaceWith(win);
    win.append(tab, pre);
  }
}
