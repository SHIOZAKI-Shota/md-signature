import { t } from "./i18n.js";
import GUIDE from "./strings-guide.js";
import { EXAMPLES } from "./examples.js";
import { initChrome } from "./site-common.js";

initChrome([GUIDE]);

// ------------------------------------------------------------------ sticky header
const header = document.querySelector(".site-header");
if (header) {
  const root = document.documentElement;
  new ResizeObserver(() => root.style.setProperty("--header-h", header.offsetHeight + "px")).observe(header);
}

// ------------------------------------------------------------------ slide dots
// IntersectionObserver because Chrome misreports :target-current with a fixed nav.
const dots = [...document.querySelectorAll(".slide-nav a")];
const targetFor = new Map();
const io = new IntersectionObserver(
  (entries) => {
    for (const e of entries) {
      if (!e.isIntersecting) continue;
      const id = targetFor.get(e.target);
      for (const a of dots) {
        if (a.getAttribute("href") === "#" + id) a.setAttribute("aria-current", "true");
        else a.removeAttribute("aria-current");
      }
    }
  },
  { rootMargin: "-50% 0px -50% 0px", threshold: 0 },
);
for (const a of dots) {
  const id = a.getAttribute("href").slice(1);
  const el = document.getElementById(id);
  if (el) {
    targetFor.set(el, id);
    io.observe(el);
  }
}

// ------------------------------------------------------------------ hero texture
const texture = document.querySelector(".hero-texture");
if (texture) {
  const { ja, en } = EXAMPLES.basic.text;
  const sources = [ja, en, ja, en];
  for (let i = 0; i < 4; i++) {
    const pre = document.createElement("pre");
    const lines = sources[i].split("\n");
    const k = (i * 9) % lines.length;
    pre.textContent = [...lines.slice(k), ...lines.slice(0, k)].join("\n");
    texture.append(pre);
  }
}

// ------------------------------------------------------------------ get started
for (const term of document.querySelectorAll("[data-term]")) {
  const tabButtons = [...term.querySelectorAll('.term-tabs [role="tab"]')];
  const choose = (btn) => {
    for (const b of tabButtons) {
      const on = b === btn;
      b.setAttribute("aria-selected", String(on));
      b.tabIndex = on ? 0 : -1;
      const pane = document.getElementById(b.getAttribute("aria-controls"));
      if (pane) pane.hidden = !on;
    }
  };
  tabButtons.forEach((b, i) => {
    b.addEventListener("click", () => choose(b));
    b.addEventListener("keydown", (e) => {
      const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
      if (!d) return;
      const next = tabButtons[(i + d + tabButtons.length) % tabButtons.length];
      choose(next);
      next.focus();
    });
  });
}

document.addEventListener("click", async (e) => {
  const btn = e.target.closest(".tcopy");
  if (!btn || btn.closest(".md-preview")) return;
  let text;
  if (btn.dataset.copyId) {
    text = document.getElementById(btn.dataset.copyId)?.textContent ?? "";
  } else {
    const code = btn.closest(".tblock")?.querySelector("code");
    if (!code) return;
    text = btn.hasAttribute("data-copy-all") ? code.textContent : [...code.querySelectorAll(".cmd")].map((c) => c.textContent).join("\n");
  }
  try {
    await navigator.clipboard.writeText(text);
    btn.classList.add("done");
    btn.setAttribute("aria-label", t("start.copied"));
    btn.title = t("start.copied");
    setTimeout(() => {
      btn.classList.remove("done");
      btn.setAttribute("aria-label", t("kg.copy"));
      btn.title = t("kg.copy");
    }, 1400);
  } catch {}
});
