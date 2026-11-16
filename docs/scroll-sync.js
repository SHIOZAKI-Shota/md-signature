import { ready } from "./editor-cm.js";

const out = document.getElementById("preview");
const toggle = document.getElementById("md-sync");
const KEY = "mdsig-scroll-sync";

let enabled = true;
try {
  enabled = localStorage.getItem(KEY) !== "off";
} catch {}

function scrollerOf(el) {
  for (let n = el?.parentElement; n; n = n.parentElement) {
    const oy = getComputedStyle(n).overflowY;
    if ((oy === "auto" || oy === "scroll") && n.scrollHeight > n.clientHeight) return n;
  }
  return null;
}

const yIn = (el, scroller) => el.getBoundingClientRect().top - scroller.getBoundingClientRect().top + scroller.scrollTop;

const view = await ready;
if (view && out) {
  const doc = () => view.state.doc;
  const editorScroller = view.scrollDOM;
  let lockEditor = 0;
  let lockPreview = 0;

  const anchors = (pv) => {
    const list = [];
    for (const el of out.querySelectorAll(".md-blk")) {
      const line = Number(el.dataset.line);
      if (line + 1 > doc().lines) continue;
      list.push({ line, ey: view.lineBlockAt(doc().line(line + 1).from).top, py: yIn(el, pv) });
    }
    list.push({ line: doc().lines, ey: view.contentHeight, py: pv.scrollHeight });
    return list;
  };

  const map = (list, from, to, value) => {
    if (list.length < 2) return null;
    let i = 0;
    while (i < list.length - 2 && list[i + 1][from] <= value) i++;
    const a = list[i];
    const b = list[i + 1];
    const span = b[from] - a[from];
    const r = span > 0 ? Math.min(1, Math.max(0, (value - a[from]) / span)) : 0;
    return a[to] + r * (b[to] - a[to]);
  };

  const atBottom = (s) => s.scrollTop + s.clientHeight >= s.scrollHeight - 2;

  editorScroller.addEventListener("scroll", () => {
    if (!enabled || performance.now() < lockEditor) return;
    const pv = scrollerOf(out);
    if (!pv) return;
    const target = atBottom(editorScroller) ? pv.scrollHeight : map(anchors(pv), "ey", "py", editorScroller.scrollTop);
    if (target == null) return;
    lockPreview = performance.now() + 120;
    pv.scrollTop = target;
  }, { passive: true });

  let watched = null;
  const watchPreview = () => {
    const pv = scrollerOf(out);
    if (!pv || pv === watched) return;
    watched = pv;
    pv.addEventListener("scroll", () => {
      if (!enabled || performance.now() < lockPreview) return;
      const target = atBottom(pv) ? editorScroller.scrollHeight : map(anchors(pv), "py", "ey", pv.scrollTop);
      if (target == null) return;
      lockEditor = performance.now() + 120;
      editorScroller.scrollTop = target;
    }, { passive: true });
  };
  out.addEventListener("rendered", () => requestAnimationFrame(watchPreview));
  watchPreview();
}

if (toggle) {
  toggle.setAttribute("aria-pressed", String(enabled));
  toggle.addEventListener("click", () => {
    enabled = !enabled;
    toggle.setAttribute("aria-pressed", String(enabled));
    try {
      localStorage.setItem(KEY, enabled ? "on" : "off");
    } catch {}
  });
}
