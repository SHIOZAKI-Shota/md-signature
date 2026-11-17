import { registerStrings, applyStatic, getLang, setLang, onLangChange, t } from "./i18n.js";
import STATIC from "./strings-static.js";

registerStrings(STATIC);

export function initChrome(extraStrings = []) {
  for (const s of extraStrings) registerStrings(s);
  applyStatic();
  syncLang();
  window.lucide?.createIcons({ attrs: { "stroke-width": 1.75, width: 18, height: 18 } });
  onLangChange(syncLang);
  for (const b of document.querySelectorAll(".lang-switch [data-lang]")) b.addEventListener("click", () => setLang(b.dataset.lang));
  initTheme();
}

function syncLang() {
  const root = document.documentElement;
  if (!root.hasAttribute("data-own-title")) document.title = t(root.dataset.titleKey || "meta.title");
  for (const b of document.querySelectorAll(".lang-switch [data-lang]")) b.setAttribute("aria-pressed", String(b.dataset.lang === getLang()));
  labelCells();
}

// Narrow screens stack table rows; each cell shows its column header through data-label.
function labelCells() {
  for (const table of document.querySelectorAll("table[data-cell-labels]")) {
    const heads = [...table.querySelectorAll("thead th")].map((th) => th.textContent.trim());
    for (const tr of table.querySelectorAll("tbody tr")) {
      [...tr.children].forEach((cell, i) => {
        if (cell.tagName === "TD") cell.dataset.label = heads[i] ?? "";
      });
    }
  }
}

// ------------------------------------------------------------------ color scheme
const KEY = "mdsig-color-scheme";

function initTheme() {
  const meta = document.querySelector('meta[name="color-scheme"]');
  const toggle = document.getElementById("theme-toggle");
  if (!meta || !toggle) return;
  const systemDark = matchMedia("(prefers-color-scheme: dark)");
  const stored = () => {
    try {
      return localStorage.getItem(KEY);
    } catch {
      return null;
    }
  };
  const rendered = () => {
    const s = meta.content;
    return s === "dark" || s === "light" ? s : systemDark.matches ? "dark" : "light";
  };
  toggle.addEventListener("click", () => {
    const target = rendered() === "dark" ? "light" : "dark";
    const system = systemDark.matches ? "dark" : "light";
    try {
      if (target === system) localStorage.removeItem(KEY);
      else localStorage.setItem(KEY, target);
    } catch {}
    meta.content = target === system ? "light dark" : target;
  });
  addEventListener("storage", (e) => {
    if (e.key === KEY) meta.content = stored() || "light dark";
  });
}
