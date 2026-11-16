export const LANGS = ["ja", "en"];
const STORE_KEY = "mdsig-lang";
const dict = { ja: Object.create(null), en: Object.create(null) };
const listeners = new Set();

function detect() {
  try {
    const q = new URLSearchParams(location.search).get("lang");
    if (LANGS.includes(q)) return q;
  } catch {}
  try {
    const saved = localStorage.getItem(STORE_KEY);
    if (LANGS.includes(saved)) return saved;
  } catch {}
  return "ja";
}

let lang = detect();

export const getLang = () => lang;

export function registerStrings(strings) {
  for (const l of LANGS) Object.assign(dict[l], strings[l] || {});
}

export function t(key, vars) {
  const s = dict[lang][key] ?? dict.en[key] ?? dict.ja[key] ?? key;
  return vars ? s.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m)) : s;
}

export function onLangChange(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

const has = (key) => key in dict[lang] || key in dict.en || key in dict.ja;

// Rendered document content is untrusted: i18n markers inside it are never applied, and an unknown key never becomes markup.
const USER_CONTENT = ".md-preview";
const I18N_ATTRS = new Set(["title", "aria-label", "placeholder", "alt", "href"]);
const SAFE_HREF = /^(https:\/\/|\.{1,2}\/|\/(?!\/)|#)/;

export function applyStatic(root = document) {
  const own = (sel) => [...root.querySelectorAll(sel)].filter((el) => !el.closest(USER_CONTENT));
  for (const el of own("[data-i18n]")) if (has(el.dataset.i18n)) el.textContent = t(el.dataset.i18n);
  for (const el of own("[data-i18n-html]")) if (has(el.dataset.i18nHtml)) el.innerHTML = t(el.dataset.i18nHtml);
  for (const el of own("[data-i18n-attr]")) {
    for (const pair of el.dataset.i18nAttr.split(";")) {
      const [attr, key] = pair.split(":").map((s) => s.trim());
      if (!I18N_ATTRS.has(attr) || !key || !has(key)) continue;
      const value = t(key);
      if (attr === "href" && !SAFE_HREF.test(value)) continue;
      el.setAttribute(attr, value);
    }
  }
}

export function setLang(next) {
  if (!LANGS.includes(next) || next === lang) return;
  lang = next;
  try {
    localStorage.setItem(STORE_KEY, next);
  } catch {}
  document.documentElement.lang = next;
  applyStatic();
  for (const fn of listeners) fn(next);
}

document.documentElement.lang = lang;
