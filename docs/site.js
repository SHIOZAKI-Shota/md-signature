import { t } from "./i18n.js";
import GUIDE from "./strings-guide.js";
import DOCS from "./strings-docs.js";
import { EXAMPLES } from "./examples.js";
import { initChrome } from "./site-common.js";
import { decorateCode } from "./code-view.js";

// ------------------------------------------------------------------ moved sections
// The top page used to hold the playground and the guide; old links land on their new pages.
if (document.documentElement.dataset.page === "top") {
  const moved = {
    playground: "playground/",
    "spec-block": "docs/format/#block",
    "spec-chain": "docs/format/#chain",
    "spec-payload": "docs/format/#payload",
    "spec-keys": "docs/keys/",
    "spec-verify": "docs/verify/",
    "spec-ext": "docs/fields/",
    start: "start/",
  };
  const target = moved[location.hash.slice(1)] ?? (new URLSearchParams(location.search).has("example") ? "playground/" : null);
  if (target) location.replace(target.startsWith("playground/") ? target + location.search : target);
}

initChrome([GUIDE, DOCS]);
decorateCode();

// ------------------------------------------------------------------ install command
// winget and the .deb/.rpm packages are not available yet, so Windows and Linux use go install.
const installKind = document.getElementById("install-kind");
if (installKind) {
  const COMMANDS = {
    "cli-win": "go install mdsig.dev/cmd/mdsig@latest",
    "cli-mac": "brew install SHIOZAKI-Shota/tap/mdsig",
    "lib-js": "npm install @mdsig/core",
    "lib-go": "go get mdsig.dev/mdsig",
  };
  const platform = navigator.userAgentData?.platform || navigator.platform || navigator.userAgent;
  installKind.value = /mac|iphone|ipad/i.test(platform) ? "cli-mac" : /win|linux|android|cros/i.test(platform) ? "cli-win" : "cli-mac";
  const show = () => (document.getElementById("install-cmd").textContent = COMMANDS[installKind.value]);
  installKind.addEventListener("change", show);
  show();
}

// ------------------------------------------------------------------ sticky header
const header = document.querySelector(".site-header");
if (header) {
  const root = document.documentElement;
  new ResizeObserver(() => root.style.setProperty("--header-h", header.offsetHeight + "px")).observe(header);
}
const footer = document.querySelector(".site-footer");
if (footer) {
  const root = document.documentElement;
  new ResizeObserver(() => root.style.setProperty("--footer-h", footer.offsetHeight + "px")).observe(footer);
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

// ------------------------------------------------------------------ TSA roots
// The list is updated monthly by a workflow; the static rows are a fallback.
const rootsBody = document.querySelector("#roots-table tbody");
if (rootsBody) {
  fetch(new URL("./tsa-roots.json", import.meta.url), { cache: "no-cache" })
    .then((r) => (r.ok ? r.json() : null))
    .then((d) => {
      if (!Array.isArray(d?.roots) || !d.roots.length) return;
      rootsBody.replaceChildren(
        ...d.roots.map((r) => {
          const tr = document.createElement("tr");
          const th = document.createElement("th");
          th.scope = "row";
          th.textContent = String(r.name);
          const until = document.createElement("td");
          until.textContent = String(r.notAfter);
          const fp = document.createElement("td");
          const code = document.createElement("code");
          code.title = String(r.sha256);
          code.textContent = String(r.sha256).slice(0, 16) + "…";
          fp.append(code);
          tr.append(th, until, fp);
          return tr;
        }),
      );
    })
    .catch(() => {});
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
