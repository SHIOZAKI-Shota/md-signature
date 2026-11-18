import { initChrome } from "../site-common.js";
import { t, onLangChange, getLang } from "../i18n.js";
import EDITOR_STRINGS from "../strings-editor.js";
import "../preview.js";
import "../scroll-sync.js";
import "../tab-indicator.js";
import "../key-method.js";
import { loadText, download, $ } from "../app.js";
import { api as cmApi } from "../editor-cm.js";
import { EXAMPLES } from "../examples.js";
import { parseDocument } from "../vendor/core/index.js";
import { setResourceLoader } from "../resource-source.js";

initChrome([EDITOR_STRINGS]);

const editor = $("editor");
const HAS_FS = typeof window.showOpenFilePicker === "function" && typeof window.showSaveFilePicker === "function" && typeof window.showDirectoryPicker === "function";
const MD_TYPES = [{ description: "Markdown", accept: { "text/markdown": [".md", ".markdown"] } }];
const MD_RE = /\.(md|markdown)$/i;

let fileHandle = null;
let fileName = "";
let savedText = editor.value;
let folder = null;
let baseSegments = [];
let eol = "LF";
let sampleLang = null;

// ------------------------------------------------------------------ state
const isDirty = () => editor.value !== savedText;

const normalize = (text) => text.replace(/\r\n?/g, "\n");
const forDisk = (text) => (eol === "CRLF" ? text.replace(/\n/g, "\r\n") : text);

function renderState() {
  const name = sampleLang ? t("ed.sample") : fileName || t("ed.untitled");
  const dirty = isDirty();
  $("ed-name").textContent = name;
  $("ed-name").classList.toggle("is-sample", !!sampleLang);
  $("st-eol").textContent = eol;
  $("ed-name").title = folder && baseSegments ? [folder.name, ...baseSegments, name].join("/") : name;
  $("ed-dirty").hidden = !dirty;
  document.title = (dirty ? "● " : "") + t("ed.title", { name });
}

let noteKey = HAS_FS ? null : { key: "ed.fallback" };
function note(entry) {
  noteKey = entry ?? (HAS_FS ? null : { key: "ed.fallback" });
  renderNote();
}
function renderNote() {
  const n = $("ed-note");
  n.hidden = !noteKey;
  n.classList.toggle("is-error", !!noteKey?.error);
  n.textContent = noteKey ? t(noteKey.key, noteKey.vars) : "";
}

function setDocument(text, name, handle) {
  eol = /\r\n/.test(text) ? "CRLF" : "LF";
  sampleLang = null;
  loadText(text);
  savedText = normalize(text);
  fileName = name;
  fileHandle = handle;
  renderState();
}

function loadSample() {
  const lang = getLang();
  setDocument(EXAMPLES.basic.text[lang] ?? EXAMPLES.basic.text.en, "", null);
  sampleLang = lang;
  renderState();
}

const confirmDiscard = () => !isDirty() || confirm(t("ed.confirmDiscard"));
const isAbort = (e) => e?.name === "AbortError";

async function guarded(fn) {
  try {
    await fn();
  } catch (e) {
    if (isAbort(e)) return;
    note({ key: "ed.error", vars: { error: e?.message ?? String(e) }, error: true });
  }
}

// ------------------------------------------------------------------ resources from the opened folder
function refSegments(ref) {
  if (/^[a-z][a-z0-9+.-]*:/i.test(ref) || ref.startsWith("/") || ref.includes("\\")) return null;
  const segs = ref.split("/").filter((s) => s && s !== ".");
  // SPEC 9.8: ".." is rejected, so a document cannot reach outside its folder.
  if (!segs.length || segs.includes("..")) return null;
  return segs;
}

async function readFromHandle(root, segs) {
  let dir = root;
  for (const s of segs.slice(0, -1)) dir = await dir.getDirectoryHandle(s);
  const file = await (await dir.getFileHandle(segs[segs.length - 1])).getFile();
  return new Uint8Array(await file.arrayBuffer());
}

function syncLoader() {
  if (!folder || !baseSegments) {
    setResourceLoader(null);
    return;
  }
  const base = baseSegments;
  const source = folder;
  setResourceLoader(async (ref) => {
    const segs = refSegments(ref);
    if (!segs) return null;
    const path = [...base, ...segs];
    if (source.handle) {
      try {
        return await readFromHandle(source.handle, path);
      } catch (e) {
        if (e?.name === "NotFoundError" || e?.name === "TypeMismatchError") return null;
        throw e;
      }
    }
    const f = source.files.get(path.join("/"));
    return f ? new Uint8Array(await f.arrayBuffer()) : null;
  });
}

async function locate(handle) {
  if (!folder) return null;
  if (handle && folder.handle) {
    const path = await folder.handle.resolve(handle);
    return path ? path.slice(0, -1) : null;
  }
  return fileName ? null : [];
}

async function placeInFolder(handle, relPath) {
  baseSegments = typeof relPath === "string" ? relPath.split("/").slice(0, -1) : await locate(handle);
  if (folder && !baseSegments) note({ key: "ed.outsideFolder" });
  else note(null);
  syncLoader();
  renderFolderList();
  renderState();
}

// ------------------------------------------------------------------ folder listing
const SKIP_DIRS = new Set(["node_modules", ".git"]);
const MAX_FILES = 2000;

async function listHandle(dir, prefix, out, depth) {
  for await (const [name, h] of dir.entries()) {
    if (out.length >= MAX_FILES) return;
    if (h.kind === "file" && MD_RE.test(name)) out.push(prefix + name);
    else if (h.kind === "directory" && depth < 6 && !name.startsWith(".") && !SKIP_DIRS.has(name)) await listHandle(h, prefix + name + "/", out, depth + 1);
  }
}

function currentPath() {
  if (!folder || !baseSegments || !fileName) return "";
  return [...baseSegments, fileName].join("/");
}

function renderFolderList() {
  const box = $("ed-folder");
  const sel = $("ed-folder-files");
  box.hidden = !folder;
  if (!folder) return;
  const label = t(folder.paths.length ? "ed.folderPick" : "ed.folderNone", { folder: folder.name, n: folder.paths.length });
  const head = new Option(label, "");
  head.disabled = true;
  sel.replaceChildren(head, ...folder.paths.map((p) => new Option(p, p)));
  const cur = currentPath();
  sel.value = folder.paths.includes(cur) ? cur : "";
}

async function openFromFolder(path) {
  if (!confirmDiscard()) {
    renderFolderList();
    return;
  }
  if (folder.handle) {
    const segs = path.split("/");
    let dir = folder.handle;
    for (const s of segs.slice(0, -1)) dir = await dir.getDirectoryHandle(s);
    const handle = await dir.getFileHandle(segs[segs.length - 1]);
    setDocument(await (await handle.getFile()).text(), handle.name, handle);
  } else {
    const file = folder.files.get(path);
    setDocument(await file.text(), file.name, null);
  }
  await placeInFolder(null, path);
}

$("ed-folder-files").addEventListener("change", (e) => {
  if (e.target.value) guarded(() => openFromFolder(e.target.value));
});

// ------------------------------------------------------------------ commands
async function cmdNew() {
  if (!confirmDiscard()) return;
  setDocument("", "", null);
  await placeInFolder(null);
}

async function cmdOpen() {
  if (!confirmDiscard()) return;
  if (!HAS_FS) {
    $("ed-file-input").click();
    return;
  }
  const [handle] = await window.showOpenFilePicker({ types: MD_TYPES, multiple: false });
  setDocument(await (await handle.getFile()).text(), handle.name, handle);
  await placeInFolder(handle);
}

async function writeTo(handle) {
  const text = editor.value;
  const w = await handle.createWritable();
  await w.write(forDisk(text));
  await w.close();
  savedText = text;
  sampleLang = null;
}

async function cmdSave() {
  if (!HAS_FS) {
    download(fileName || t("ed.untitled"), forDisk(editor.value));
    savedText = editor.value;
    sampleLang = null;
    renderState();
    return;
  }
  if (!fileHandle) return cmdSaveAs();
  await writeTo(fileHandle);
  renderState();
}

async function cmdSaveAs() {
  if (!HAS_FS) {
    const name = prompt(t("ed.saveAsPrompt"), fileName || t("ed.untitled"));
    if (!name) return;
    fileName = name;
    download(name, forDisk(editor.value));
    savedText = editor.value;
    sampleLang = null;
    renderState();
    return;
  }
  const handle = await window.showSaveFilePicker({ suggestedName: fileName || t("ed.untitled"), types: MD_TYPES });
  await writeTo(handle);
  fileHandle = handle;
  fileName = handle.name;
  if (folder?.handle) {
    folder.paths = [];
    await listHandle(folder.handle, "", folder.paths, 0);
    folder.paths.sort();
  }
  await placeInFolder(handle);
}

async function cmdOpenFolder() {
  if (!HAS_FS) {
    $("ed-folder-input").click();
    return;
  }
  const handle = await window.showDirectoryPicker({ mode: "read" });
  const paths = [];
  await listHandle(handle, "", paths, 0);
  paths.sort();
  folder = { name: handle.name, handle, paths };
  await placeInFolder(fileHandle);
}

$("ed-new").addEventListener("click", () => guarded(cmdNew));
$("ed-open").addEventListener("click", () => guarded(cmdOpen));
$("ed-save").addEventListener("click", () => guarded(cmdSave));
$("ed-save-as").addEventListener("click", () => guarded(cmdSaveAs));
$("ed-open-folder").addEventListener("click", () => guarded(cmdOpenFolder));

// ------------------------------------------------------------------ fallback inputs
$("ed-file-input").addEventListener("change", (e) =>
  guarded(async () => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    setDocument(await file.text(), file.name, null);
    await placeInFolder(null);
  }),
);

$("ed-folder-input").addEventListener("change", (e) =>
  guarded(async () => {
    const list = [...(e.target.files ?? [])];
    e.target.value = "";
    if (!list.length) return;
    const files = new Map();
    let name = "";
    for (const f of list) {
      const rel = f.webkitRelativePath || f.name;
      const i = rel.indexOf("/");
      if (!name) name = i > 0 ? rel.slice(0, i) : "";
      files.set(i > 0 ? rel.slice(i + 1) : rel, f);
    }
    const paths = [...files.keys()].filter((p) => MD_RE.test(p)).sort();
    folder = { name: name || "folder", handle: null, files, paths };
    await placeInFolder(null);
  }),
);

// ------------------------------------------------------------------ keyboard + leaving
addEventListener("keydown", (e) => {
  if (!(e.ctrlKey || e.metaKey) || e.altKey || e.key.toLowerCase() !== "s") return;
  e.preventDefault();
  guarded(e.shiftKey ? cmdSaveAs : cmdSave);
});

addEventListener("beforeunload", (e) => {
  if (!isDirty()) return;
  e.preventDefault();
  e.returnValue = "";
});

editor.addEventListener("input", renderState);
onLangChange((lang) => {
  if (sampleLang && sampleLang !== lang && editor.value === EXAMPLES.basic.text[sampleLang]) loadSample();
  renderState();
  renderNote();
  renderFolderList();
});

if (!editor.value) loadSample();
renderState();
renderNote();

// ------------------------------------------------------------------ preferences
function stored(key) {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}
function store(key, value) {
  try {
    localStorage.setItem(key, String(value));
  } catch {}
}

// ------------------------------------------------------------------ pane splitter
const main = document.querySelector(".ed-main");
const split = $("ed-split");
const SPLIT_KEY = "mdsig-ed-split";
const clampSplit = (p) => Math.min(80, Math.max(20, p));
let splitPct = 50;
let dragId = null;

function setSplit(p, save = false) {
  splitPct = Math.round(clampSplit(p) * 10) / 10;
  main.style.setProperty("--split", splitPct + "%");
  split.setAttribute("aria-valuenow", String(Math.round(splitPct)));
  if (save) store(SPLIT_KEY, splitPct);
}

split.addEventListener("pointerdown", (e) => {
  if (e.button !== 0) return;
  e.preventDefault();
  dragId = e.pointerId;
  try {
    split.setPointerCapture(e.pointerId);
  } catch {}
  split.classList.add("is-dragging");
  document.documentElement.classList.add("is-resizing");
});
split.addEventListener("pointermove", (e) => {
  if (e.pointerId !== dragId) return;
  const r = main.getBoundingClientRect();
  if (r.width > 0) setSplit(((e.clientX - r.left) / r.width) * 100);
});
function endDrag(e) {
  if (e.pointerId !== dragId) return;
  dragId = null;
  split.classList.remove("is-dragging");
  document.documentElement.classList.remove("is-resizing");
  store(SPLIT_KEY, splitPct);
}
split.addEventListener("pointerup", endDrag);
split.addEventListener("pointercancel", endDrag);
split.addEventListener("dblclick", () => setSplit(50, true));
split.addEventListener("keydown", (e) => {
  const step = { ArrowLeft: -2, ArrowDown: -2, ArrowRight: 2, ArrowUp: 2 }[e.key];
  if (step) setSplit(splitPct + step, true);
  else if (e.key === "Home") setSplit(20, true);
  else if (e.key === "End") setSplit(80, true);
  else return;
  e.preventDefault();
});
setSplit(Number(stored(SPLIT_KEY)) || 50);

// ------------------------------------------------------------------ markdown commands
function selectedLines(state) {
  const nums = new Set();
  for (const r of state.selection.ranges) {
    for (let n = state.doc.lineAt(r.from).number; n <= state.doc.lineAt(r.to).number; n++) nums.add(n);
  }
  return [...nums].sort((a, b) => a - b).map((n) => state.doc.line(n));
}

// Minimal change per line, so cursors inside the line keep their place.
function lineChange(line, next) {
  const cur = line.text;
  let p = 0;
  while (p < cur.length && p < next.length && cur[p] === next[p]) p++;
  let a = cur.length, b = next.length;
  while (a > p && b > p && cur[a - 1] === next[b - 1]) { a--; b--; }
  return { from: line.from + p, to: line.from + a, insert: next.slice(p, b) };
}

function toggleLines(view, has, add, remove) {
  const lines = selectedLines(view.state);
  const target = lines.length > 1 ? lines.filter((l) => l.text.trim()) : lines;
  if (!target.length) return;
  const on = target.every((l) => has(l.text));
  const changes = target.map((l, i) => lineChange(l, on ? remove(l.text) : add(l.text, i)));
  view.dispatch({ changes, userEvent: "input.format", scrollIntoView: true });
}

function wrapSelection(view, A, mark) {
  const { state } = view;
  const n = mark.length;
  view.dispatch(state.changeByRange((r) => {
    if (state.sliceDoc(r.from - n, r.from) === mark && state.sliceDoc(r.to, r.to + n) === mark) {
      return { changes: [{ from: r.from - n, to: r.from }, { from: r.to, to: r.to + n }], range: A.EditorSelection.range(r.from - n, r.to - n) };
    }
    const text = state.sliceDoc(r.from, r.to);
    if (text.length >= 2 * n && text.startsWith(mark) && text.endsWith(mark)) {
      return { changes: { from: r.from, to: r.to, insert: text.slice(n, -n) }, range: A.EditorSelection.range(r.from, r.to - 2 * n) };
    }
    return { changes: [{ from: r.from, insert: mark }, { from: r.to, insert: mark }], range: A.EditorSelection.range(r.from + n, r.to + n) };
  }), { userEvent: "input.format", scrollIntoView: true });
}

const LIST_RE = /^(\s*)(?:[-*+]|\d+[.)])[ \t]+/;
const FENCE = "`".repeat(3);
const MD = {
  heading: (v) => toggleLines(v, (s) => /^#{1,6}\s/.test(s), (s) => "## " + s.replace(/^#{1,6}\s*/, ""), (s) => s.replace(/^#{1,6}\s+/, "")),
  ul: (v) => toggleLines(v, (s) => /^\s*[-*+][ \t]/.test(s), (s) => s.replace(LIST_RE, "$1").replace(/^(\s*)/, "$1- "), (s) => s.replace(LIST_RE, "$1")),
  ol: (v) => toggleLines(v, (s) => /^\s*\d+[.)][ \t]/.test(s), (s, i) => s.replace(LIST_RE, "$1").replace(/^(\s*)/, `$1${i + 1}. `), (s) => s.replace(LIST_RE, "$1")),
  quote: (v) => toggleLines(v, (s) => /^\s*>/.test(s), (s) => "> " + s, (s) => s.replace(/^(\s*)> ?/, "$1")),
  bold: (v, A) => wrapSelection(v, A, "**"),
  italic: (v, A) => wrapSelection(v, A, "*"),
  code: (v, A) => wrapSelection(v, A, "`"),
  link: (v, A) => {
    const { state } = v;
    v.dispatch(state.changeByRange((r) => {
      const text = state.sliceDoc(r.from, r.to);
      if (/^https?:\/\/\S+$/.test(text)) return { changes: { from: r.from, to: r.to, insert: `[](${text})` }, range: A.EditorSelection.cursor(r.from + 1) };
      const urlAt = r.from + text.length + 3;
      return { changes: { from: r.from, to: r.to, insert: `[${text}](https://)` }, range: A.EditorSelection.range(urlAt, urlAt + 8) };
    }), { userEvent: "input.format", scrollIntoView: true });
  },
  fence: (v, A) => {
    const lines = selectedLines(v.state);
    const first = lines[0], last = lines[lines.length - 1];
    if (lines.length === 1 && !first.text.trim()) {
      v.dispatch({ changes: { from: first.from, to: first.to, insert: `${FENCE}\n\n${FENCE}` }, selection: A.EditorSelection.cursor(first.from + 4), userEvent: "input.format", scrollIntoView: true });
      return;
    }
    v.dispatch({ changes: [{ from: first.from, insert: FENCE + "\n" }, { from: last.to, insert: "\n" + FENCE }], userEvent: "input.format", scrollIntoView: true });
  },
};

// ------------------------------------------------------------------ editor toolbar + status bar
const FONT_KEY = "mdsig-ed-font";
const WRAP_KEY = "mdsig-ed-wrap";
const FONT_MIN = 11;
const FONT_MAX = 22;
const toolbar = $("md-toolbar");
const toolButtons = [...toolbar.querySelectorAll("button")];
let fontSize = Math.min(FONT_MAX, Math.max(FONT_MIN, Number(stored(FONT_KEY)) || 14));

const SEARCH_JA = {
  Find: "検索", Replace: "置換", next: "次へ", previous: "前へ", all: "すべて", "match case": "大文字と小文字を区別",
  regexp: "正規表現", "by word": "単語単位", replace: "置換", "replace all": "すべて置換", close: "閉じる",
  "current match": "現在の一致", "on line": "行", "Go to line": "行へ移動", go: "移動",
  "Fold line": "行を折りたたむ", "Unfold line": "行を展開", "folded code": "折りたたまれた範囲", unfold: "展開",
};

function syncRoving() {
  const enabled = toolButtons.filter((b) => !b.disabled);
  const current = toolButtons.find((b) => b.tabIndex === 0 && !b.disabled) ?? enabled[0];
  for (const b of toolButtons) b.tabIndex = b === current ? 0 : -1;
}
toolbar.addEventListener("keydown", (e) => {
  const enabled = toolButtons.filter((b) => !b.disabled);
  const i = enabled.indexOf(document.activeElement);
  if (i < 0) return;
  const next = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: enabled.length - 1 }[e.key];
  if (next === undefined) return;
  e.preventDefault();
  const target = enabled[(next + enabled.length) % enabled.length];
  for (const b of toolButtons) b.tabIndex = b === target ? 0 : -1;
  target.focus();
});
toolbar.addEventListener("focusin", (e) => {
  if (toolButtons.includes(e.target)) for (const b of toolButtons) b.tabIndex = b === e.target ? 0 : -1;
});

cmApi.then((A) => {
  if (!A) return;
  const { view } = A;
  const pane = $("editor-pane");
  toolbar.hidden = false;
  $("ed-status").hidden = false;

  const run = (fn) => () => {
    fn(view, A);
    view.focus();
    return true;
  };
  const on = (id, fn) => $(id).addEventListener("click", run(fn));
  for (const k of ["heading", "bold", "italic", "code", "link", "ul", "ol", "quote", "fence"]) on("md-" + k, MD[k]);
  on("md-undo", () => A.undo());
  on("md-redo", () => A.redo());
  on("md-indent", () => A.indent());
  on("md-outdent", () => A.outdent());
  A.setKeys([
    { key: "Mod-b", run: run(MD.bold) },
    { key: "Mod-i", run: run(MD.italic) },
    { key: "Mod-e", run: run(MD.code) },
    { key: "Mod-k", run: run(MD.link) },
  ]);

  const wrapBtn = $("md-wrap");
  const setWrap = (wrap) => {
    A.setWrap(wrap);
    wrapBtn.setAttribute("aria-pressed", String(wrap));
  };
  wrapBtn.addEventListener("click", () => {
    const wrap = wrapBtn.getAttribute("aria-pressed") !== "true";
    setWrap(wrap);
    store(WRAP_KEY, wrap ? 1 : 0);
  });
  setWrap(stored(WRAP_KEY) !== "0");

  const setFont = (n) => {
    fontSize = Math.min(FONT_MAX, Math.max(FONT_MIN, n));
    pane.style.setProperty("--cm-font-size", fontSize + "px");
    $("md-smaller").disabled = fontSize <= FONT_MIN;
    $("md-larger").disabled = fontSize >= FONT_MAX;
    $("st-size").textContent = t("st.size", { n: fontSize });
    view.requestMeasure();
    syncRoving();
  };
  $("md-smaller").addEventListener("click", () => {
    setFont(fontSize - 1);
    store(FONT_KEY, fontSize);
  });
  $("md-larger").addEventListener("click", () => {
    setFont(fontSize + 1);
    store(FONT_KEY, fontSize);
  });
  setFont(fontSize);

  const maxBtn = $("md-max");
  maxBtn.addEventListener("click", () => {
    const max = maxBtn.getAttribute("aria-pressed") !== "true";
    maxBtn.setAttribute("aria-pressed", String(max));
    document.querySelector(".ed-app").classList.toggle("is-max", max);
    view.requestMeasure();
  });

  const foldBtn = $("md-fold");
  const syncFold = () => foldBtn.setAttribute("aria-pressed", String(A.signaturesFolded()));
  foldBtn.addEventListener("click", () => {
    A.toggleSignatureFolds();
    syncFold();
  });

  let sigCount = 0;
  let sigTimer = 0;
  function renderStatus() {
    const { state } = view;
    const head = state.selection.main.head;
    const line = state.doc.lineAt(head);
    const selected = state.selection.ranges.reduce((n, r) => n + r.to - r.from, 0);
    $("st-pos").textContent = t("st.pos", { line: line.number, col: head - line.from + 1 }) + (selected ? " " + t("st.sel", { n: selected.toLocaleString() }) : "");
    $("st-chars").textContent = t("st.chars", { n: state.doc.length.toLocaleString() });
    $("st-sigs").textContent = sigCount === 1 ? t("st.sigs1") : t("st.sigs", { n: sigCount });
    $("st-size").textContent = t("st.size", { n: fontSize });
  }
  const countSigs = () => {
    sigCount = parseDocument(view.state.doc.toString()).chain.length;
    renderStatus();
  };
  const syncHistory = () => {
    $("md-undo").disabled = A.undoDepth() === 0;
    $("md-redo").disabled = A.redoDepth() === 0;
    syncRoving();
  };

  A.onUpdate((u) => {
    if (u.docChanged || u.transactions.some((tr) => tr.effects.length)) syncFold();
    if (u.docChanged) {
      clearTimeout(sigTimer);
      sigTimer = setTimeout(countSigs, 150);
    }
    if (u.docChanged || u.selectionSet) renderStatus();
    if (u.transactions.length) syncHistory();
  });
  const syncLang = () => {
    A.setPhrases(getLang() === "ja" ? SEARCH_JA : null);
    renderStatus();
  };
  onLangChange(syncLang);
  syncLang();
  countSigs();
  syncFold();
  syncHistory();
});
