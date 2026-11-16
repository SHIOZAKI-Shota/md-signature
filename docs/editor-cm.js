// One local bundle (vendor/codemirror/build.mjs), so every package shares a single @codemirror/state instance.
const BUNDLE = "./vendor/codemirror/codemirror.js";

const textarea = document.getElementById("editor");
const native = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value");
const FULL = textarea?.dataset.cm === "full";

let resolveApi;
export const api = new Promise((r) => (resolveApi = r));

export const ready = textarea ? mount().catch((err) => {
  console.warn("[editor-cm] CodeMirror unavailable; using the plain textarea.", err);
  return null;
}) : Promise.resolve(null);
ready.then((v) => { if (!v) resolveApi(null); });

const SIG_OPEN = /<!--[ \t]*md-signature\b/g;

function sigSpans(text) {
  const out = [];
  SIG_OPEN.lastIndex = 0;
  let m;
  while ((m = SIG_OPEN.exec(text))) {
    const close = text.indexOf("-->", m.index + 4);
    const end = close < 0 ? text.length : close + 3;
    out.push({ from: m.index, close, end });
    SIG_OPEN.lastIndex = end;
  }
  return out;
}

async function mount() {
  const { state: S, view: V, language: L, commands: C, search: Se, markdown: M, highlight: H, autocomplete: A } = await import(BUNDLE);
  const { EditorState, Annotation, RangeSetBuilder, Compartment, Prec } = S;
  const { EditorView, ViewPlugin, Decoration, keymap, lineNumbers, highlightActiveLine,
    highlightActiveLineGutter, highlightSpecialChars, drawSelection } = V;
  const { HighlightStyle, syntaxHighlighting } = L;
  const { history, defaultKeymap, historyKeymap } = C;
  const { searchKeymap, highlightSelectionMatches } = Se;
  const { markdown } = M;
  const { tags: t } = H;

  // Tags updates from textarea.value so toTextarea does not echo them back as input events.
  const external = Annotation.define();

  // ------------------------------------------------------------------ md-signature blocks
  const sigLine = Decoration.line({ class: "cm-mdsig" });
  const sigFirst = Decoration.line({ class: "cm-mdsig cm-mdsig-first" });
  const sigLast = Decoration.line({ class: "cm-mdsig cm-mdsig-last" });
  const sigOnly = Decoration.line({ class: "cm-mdsig cm-mdsig-first cm-mdsig-last" });

  function sigDecorations(doc) {
    const b = new RangeSetBuilder();
    for (const { from, end } of sigSpans(doc.toString())) {
      const first = doc.lineAt(from).number;
      const last = doc.lineAt(end).number;
      for (let n = first; n <= last; n++) {
        const deco = first === last ? sigOnly : n === first ? sigFirst : n === last ? sigLast : sigLine;
        b.add(doc.line(n).from, doc.line(n).from, deco);
      }
    }
    return b.finish();
  }

  const signatureBlocks = ViewPlugin.fromClass(class {
    constructor(view) { this.decorations = sigDecorations(view.state.doc); }
    update(u) { if (u.docChanged) this.decorations = sigDecorations(u.state.doc); }
  }, { decorations: (p) => p.decorations });

  // ------------------------------------------------------------------ look
  const highlight = HighlightStyle.define([
    { tag: t.heading, color: "var(--ink)", fontWeight: "600" },
    { tag: [t.link, t.url], color: "var(--ruri)" },
    { tag: t.comment, color: "var(--muted)" },
    { tag: t.emphasis, fontStyle: "italic" },
    { tag: t.strong, fontWeight: "600" },
    { tag: t.strikethrough, textDecoration: "line-through" },
    { tag: [t.processingInstruction, t.meta, t.contentSeparator],color: "var(--muted)" },
    { tag: [t.monospace, t.quote], color: "var(--ink-2)" },
  ]);

  const base = {
    "&": { color: "var(--ink)", backgroundColor: "var(--code-bg)", fontSize: "12.8px" },
    "&.cm-focused": { outline: "none" },
    "&.cm-focused .cm-activeLineGutter": { color: "var(--ink)" },
    ".cm-scroller": { fontFamily: "var(--mono)", lineHeight: "1.75", overscrollBehavior: "contain" },
    ".cm-content": { padding: "18px 0", caretColor: "var(--ink)" },
    ".cm-line": { padding: "0 20px 0 12px" },
    ".cm-cursor, .cm-dropCursor": { borderLeftColor: "var(--ink)" },
    ".cm-selectionBackground, &.cm-focused > .cm-scroller > .cm-selectionLayer .cm-selectionBackground, .cm-content ::selection":
      { backgroundColor: "var(--ruri-soft)" },
    ".cm-gutters": { backgroundColor: "var(--paper-2)", color: "var(--muted)", border: "none", borderRight: "1px solid var(--line)" },
    ".cm-lineNumbers .cm-gutterElement": { padding: "0 10px 0 14px", minWidth: "2.5em", fontSize: "11px" },
    ".cm-activeLine": { backgroundColor: "color-mix(in srgb, var(--ink) 3.5%, transparent)" },
    ".cm-activeLineGutter": { backgroundColor: "color-mix(in srgb, var(--ink) 5%, transparent)", color: "var(--ink-2)" },
    ".cm-selectionMatch": { backgroundColor: "color-mix(in srgb, var(--ruri-soft) 70%, transparent)" },
    ".cm-searchMatch": { backgroundColor: "color-mix(in srgb, var(--ruri) 18%, transparent)", outline: "1px solid var(--line-strong)" },
    ".cm-searchMatch.cm-searchMatch-selected": { backgroundColor: "color-mix(in srgb, var(--ruri) 32%, transparent)" },
    ".cm-panels": { backgroundColor: "var(--paper-2)", color: "var(--ink)" },
    ".cm-panels.cm-panels-bottom": { borderTop: "1px solid var(--line)" },
    ".cm-panels.cm-panels-top": { borderBottom: "1px solid var(--line)" },
    ".cm-panel.cm-search input, .cm-panel.cm-search button": { fontFamily: "inherit", fontSize: "12px" },
  };

  // ------------------------------------------------------------------ bridge
  const toTextarea = EditorView.updateListener.of((u) => {
    if (!u.docChanged || u.transactions.some((tr) => tr.annotation(external))) return;
    native.set.call(textarea, u.state.doc.toString());
    textarea.dispatchEvent(new Event("input", { bubbles: true }));
  });

  const full = FULL ? fullMode({ S, V, L, C, Se, H, A, t }) : null;

  const view = new EditorView({
    state: EditorState.create({
      doc: native.get.call(textarea),
      extensions: [
        lineNumbers(),
        ...(full ? full.gutter : []),
        highlightActiveLineGutter(),
        highlightSpecialChars(),
        history(),
        drawSelection(),
        full ? full.wrap : EditorView.lineWrapping,
        highlightActiveLine(),
        highlightSelectionMatches(),
        markdown(),
        syntaxHighlighting(full ? full.highlight : highlight),
        signatureBlocks,
        ...(full ? full.extensions : []),
        keymap.of([...defaultKeymap, ...historyKeymap, ...searchKeymap]),
        EditorState.tabSize.of(2),
        EditorView.theme(full ? { ...base, ...full.theme } : base),
        toTextarea,
        EditorView.editorAttributes.of({ class: full ? "mdsig-cm mdsig-cm-full" : "mdsig-cm" }),
        EditorView.contentAttributes.of({
          "aria-labelledby": "editor-label",
          ...(textarea.hasAttribute("aria-describedby") ? { "aria-describedby": textarea.getAttribute("aria-describedby") } : {}),
          spellcheck: "false", autocorrect: "off", autocapitalize: "off", translate: "no",
        }),
      ],
    }),
  });

  // Replaces only the changed span so the cursor and scroll position survive co-signing.
  function fromTextarea() {
    const next = native.get.call(textarea);
    const doc = view.state.doc;
    const cur = doc.toString();
    if (next === cur) return;
    let start = 0;
    const max = Math.min(cur.length, next.length);
    while (start < max && cur.charCodeAt(start) === next.charCodeAt(start)) start++;
    let endCur = cur.length, endNext = next.length;
    while (endCur > start && endNext > start && cur.charCodeAt(endCur - 1) === next.charCodeAt(endNext - 1)) { endCur--; endNext--; }
    view.dispatch({
      changes: { from: start, to: endCur, insert: next.slice(start, endNext) },
      annotations: external.of(true),
    });
  }

  // app.js and preview.js keep using textarea.value; this accessor forwards writes to CodeMirror.
  Object.defineProperty(textarea, "value", {
    configurable: true,
    enumerable: true,
    get() { return native.get.call(this); },
    set(v) { native.set.call(this, v); fromTextarea(); },
  });

  // ------------------------------------------------------------------ swap in
  view.dom.id = "editor-cm";
  if (textarea.getAttribute("role") === "tabpanel") {
    const tab = document.querySelector('[role="tab"][aria-controls="editor"]');
    view.dom.setAttribute("role", "tabpanel");
    if (tab?.id) view.dom.setAttribute("aria-labelledby", tab.id);
    tab?.setAttribute("aria-controls", "editor-cm");
    textarea.removeAttribute("role");
  }
  textarea.setAttribute("aria-hidden", "true");
  textarea.tabIndex = -1;

  const hadFocus = document.activeElement === textarea;
  view.dom.hidden = textarea.hidden;
  textarea.after(view.dom);
  textarea.classList.add("mdsig-cm-source");
  fromTextarea();
  if (hadFocus) view.focus();

  new MutationObserver(() => {
    view.dom.hidden = textarea.hidden;
    if (!textarea.hidden) view.requestMeasure();
  }).observe(textarea, { attributes: true, attributeFilter: ["hidden"] });

  textarea.addEventListener("focus", () => view.focus());

  resolveApi(full ? full.api(view) : null);
  return view;
}

// ------------------------------------------------------------------ full mode (editor page)
function fullMode({ S, V, L, C, Se, H, A, t }) {
  const { EditorState, EditorSelection, Compartment, Prec, RangeSetBuilder } = S;
  const { EditorView, ViewPlugin, Decoration, keymap, rectangularSelection, dropCursor } = V;
  const { HighlightStyle, foldGutter, foldService, foldKeymap, foldEffect, unfoldEffect, foldedRanges,
    bracketMatching, indentUnit, syntaxTree, codeFolding } = L;
  const { indentWithTab, undo, redo, undoDepth, redoDepth, indentMore, indentLess } = C;
  const { search } = Se;
  const { closeBrackets, closeBracketsKeymap } = A;

  const wrapCompartment = new Compartment();
  const phraseCompartment = new Compartment();
  const keysCompartment = new Compartment();
  const listeners = new Set();

  const sigFold = foldService.of((state, lineStart, lineEnd) => {
    const line = state.doc.sliceString(lineStart, lineEnd);
    if (!/^[ \t]*<!--[ \t]*md-signature\b/.test(line)) return null;
    const close = state.doc.sliceString(lineEnd, state.doc.length).indexOf("-->");
    if (close <= 0) return null;
    return { from: lineEnd, to: lineEnd + close };
  });

  function sigRanges(state) {
    const out = [];
    for (const { from, close } of sigSpans(state.doc.toString())) {
      if (close < 0) continue;
      const lineEnd = state.doc.lineAt(from).to;
      if (close > lineEnd) out.push({ from: lineEnd, to: close });
    }
    return out;
  }

  function isFolded(state, r) {
    let hit = false;
    foldedRanges(state).between(r.from, r.to, (from, to) => { if (from === r.from && to === r.to) hit = true; });
    return hit;
  }

  const fence = Decoration.line({ class: "cm-md-fence" });
  const fencedCode = ViewPlugin.fromClass(class {
    constructor(view) { this.decorations = this.build(view); }
    update(u) { if (u.docChanged || u.viewportChanged || syntaxTree(u.startState) !== syntaxTree(u.state)) this.decorations = this.build(u.view); }
    build(view) {
      const b = new RangeSetBuilder();
      const doc = view.state.doc;
      let lastLine = 0;
      for (const { from, to } of view.visibleRanges) {
        syntaxTree(view.state).iterate({ from, to, enter: (n) => {
          if (n.name !== "FencedCode" && n.name !== "CodeBlock") return;
          for (let ln = doc.lineAt(n.from).number; ln <= doc.lineAt(n.to).number; ln++) {
            if (ln <= lastLine) continue;
            b.add(doc.line(ln).from, doc.line(ln).from, fence);
            lastLine = ln;
          }
          return false;
        } });
      }
      return b.finish();
    }
  }, { decorations: (p) => p.decorations });

  const chevron = (open) => {
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 16 16");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("class", "cm-fold-icon");
    const p = document.createElementNS(ns, "path");
    p.setAttribute("d", open ? "M4 6l4 4 4-4" : "M6 4l4 4-4 4");
    svg.append(p);
    const span = document.createElement("span");
    span.className = open ? "cm-fold-marker is-open" : "cm-fold-marker";
    span.append(svg);
    return span;
  };

  const highlight = HighlightStyle.define([
    { tag: t.heading1, class: "cm-md-h cm-md-h1" },
    { tag: t.heading2, class: "cm-md-h cm-md-h2" },
    { tag: [t.heading3, t.heading4, t.heading5, t.heading6], class: "cm-md-h cm-md-h3" },
    { tag: [t.link, t.url], class: "cm-md-link" },
    { tag: t.comment, class: "cm-md-muted" },
    { tag: t.emphasis, class: "cm-md-em" },
    { tag: t.strong, class: "cm-md-strong" },
    { tag: t.strikethrough, class: "cm-md-strike" },
    { tag: [t.processingInstruction, t.meta, t.contentSeparator, t.labelName], class: "cm-md-mark" },
    { tag: t.monospace, class: "cm-md-code" },
    { tag: t.quote, class: "cm-md-quote" },
  ]);

  const theme = {
    "&": { color: "var(--ink)", backgroundColor: "var(--code-bg)", fontSize: "var(--cm-font-size, 14px)" },
    ".cm-content": { padding: "20px 0 40vh", caretColor: "var(--ink)" },
    ".cm-line": { padding: "0 28px 0 14px" },
    ".cm-lineNumbers .cm-gutterElement": { padding: "0 6px 0 16px", minWidth: "3em", fontSize: "0.82em", lineHeight: "calc(1.75em / 0.82)" },
  };

  return {
    highlight,
    theme,
    wrap: wrapCompartment.of(EditorView.lineWrapping),
    gutter: [codeFolding({ placeholderText: "…" }), foldGutter({ markerDOM: chevron })],
    extensions: [
      sigFold,
      fencedCode,
      bracketMatching(),
      closeBrackets(),
      EditorState.languageData.of(() => [{ closeBrackets: { brackets: ["(", "[", "`"] } }]),
      EditorState.allowMultipleSelections.of(true),
      EditorView.clickAddsSelectionRange.of((e) => e.altKey || (/Mac/.test(navigator.platform) ? e.metaKey : e.ctrlKey)),
      rectangularSelection({ eventFilter: (e) => e.altKey && e.shiftKey }),
      dropCursor(),
      indentUnit.of("  "),
      search({ top: true }),
      phraseCompartment.of([]),
      keysCompartment.of([]),
      keymap.of([...closeBracketsKeymap, ...foldKeymap, indentWithTab]),
      EditorView.updateListener.of((u) => { for (const fn of listeners) fn(u); }),
    ],
    api: (view) => ({
      view,
      EditorSelection,
      onUpdate(fn) { listeners.add(fn); return () => listeners.delete(fn); },
      setWrap(on) { view.dispatch({ effects: wrapCompartment.reconfigure(on ? EditorView.lineWrapping : []) }); },
      setPhrases(p) { view.dispatch({ effects: phraseCompartment.reconfigure(p ? EditorState.phrases.of(p) : []) }); },
      setKeys(bindings) { view.dispatch({ effects: keysCompartment.reconfigure(Prec.high(keymap.of(bindings))) }); },
      signaturesFolded() {
        const rs = sigRanges(view.state);
        return rs.length > 0 && rs.every((r) => isFolded(view.state, r));
      },
      toggleSignatureFolds() {
        const rs = sigRanges(view.state);
        if (!rs.length) return false;
        const fold = !rs.every((r) => isFolded(view.state, r));
        const effects = rs.filter((r) => isFolded(view.state, r) !== fold).map((r) => (fold ? foldEffect : unfoldEffect).of(r));
        view.dispatch({ effects });
        return fold;
      },
      undo: () => undo(view),
      redo: () => redo(view),
      indent: () => indentMore(view),
      outdent: () => indentLess(view),
      undoDepth: () => undoDepth(view.state),
      redoDepth: () => redoDepth(view.state),
    }),
  };
}
