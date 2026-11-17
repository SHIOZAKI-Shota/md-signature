import {
  verifyDocument,
  parseDocument,
  signDocument,
  generateEd25519,
  signerFromSeed,
  parseOpenSshPrivateKey,
  formatOpenSshPrivateKey,
  formatSshPublicKey,
  parseSshPublicKeys,
  sshFingerprint,
  parseDnsRecord,
  decodePublicKey,
  dnsName,
  DEFAULT_RESOLVERS,
  ResolutionError,
  findSections,
  findLocalImages,
  fetchResource,
  registerPasskey,
  passkeySigner,
  toBase64,
  fromBase64,
  toHex,
  sha256,
  readTsaRoots,
  DEFAULT_TSA_ROOTS,
  remoteVerify,
  compareResults,
  MemoryTofuStore,
  readPgpSecretKey,
  unlockPgpSecretKey,
} from "./vendor/core/index.js";
import { EXAMPLES, TEST_KEYS } from "./examples.js";
import { registerStrings, t, onLangChange, getLang } from "./i18n.js";
import { getResourceLoader, onResourceLoaderChange } from "./resource-source.js";
import APP_STRINGS from "./strings-app.js";

registerStrings(APP_STRINGS);

// Rendered document content must never answer an id lookup or a delegated click.
const userContent = document.querySelector(".md-preview");
const inUserContent = (n) => !!userContent && n instanceof Node && userContent.contains(n);
export const $ = (id) => {
  const n = document.getElementById(id);
  if (!inUserContent(n)) return n;
  return [...document.querySelectorAll(`[id="${CSS.escape(id)}"]`)].find((x) => !inUserContent(x)) ?? null;
};
const editor = $("editor");
const summary = $("summary");
const cards = $("cards");
const docWarnings = $("doc-warnings");
const RP_ID = location.hostname;
const HAS_WEBAUTHN = typeof window.PublicKeyCredential === "function" && !!navigator.credentials;

function renderRpHost() {
  for (const n of document.querySelectorAll(".rp-host")) n.textContent = RP_ID || t("rp.none");
}
renderRpHost();

function el(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "class") n.className = v;
    else n.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children) if (c != null && c !== false) n.append(c);
  return n;
}
// Defence in depth for SPEC value rules: control and format characters are shown as code points, never applied.
// Hex code point ranges, so that this source file contains none of the invisible characters itself.
const charClass = (ranges) => new RegExp("[" + ranges.split(" ").map((r) => r.split("-").map((h) => String.fromCodePoint(parseInt(h, 16))).join("-")).join("") + "]", "g");
const HIDDEN_CHARS = charClass("0-8 b-1f 7f-9f ad 61c 180e 200b 200e-200f 2028-202e 2060-2069 feff");
const JOINERS = charClass("200c-200d");
const codePoint = (c) => `⟨U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}⟩`;
const visible = (s, strict = true) => {
  const out = String(s).replace(HIDDEN_CHARS, codePoint);
  return strict ? out.replace(JOINERS, codePoint) : out;
};
function shown(value, { max = 64, strict = true } = {}) {
  const s = visible(value, strict);
  return s.length > max ? el("bdi", { title: s.slice(0, 1000) }, s.slice(0, max - 1) + "…") : el("bdi", {}, s);
}
const count = (base, n) => t(`count.${base}.${n === 1 ? "one" : "other"}`, { n });
const capitalize = (s) => s.charAt(0).toUpperCase() + s.slice(1);

function mapText(s, table) {
  if (s == null) return s;
  for (const [re, key, vars] of table) {
    const m = re.exec(s);
    if (m) return t(key, vars ? vars(m) : undefined);
  }
  return s;
}

class UiError extends Error {
  constructor(key, vars) {
    super(t(key, vars));
    this.key = key;
    this.vars = vars;
  }
}
const shownErrors = new Map();
function showError(node, ex) {
  if (ex == null || ex === "") {
    shownErrors.delete(node);
    node.textContent = "";
    return;
  }
  const entry = ex instanceof UiError ? { key: ex.key, vars: ex.vars } : typeof ex === "object" && ex.key ? ex : { raw: ex?.message ?? String(ex) };
  shownErrors.set(node, entry);
  node.textContent = entry.key ? t(entry.key, entry.vars) : entry.raw;
}

// ------------------------------------------------------------------ network
const fetchCache = new Map();
const cachedFetch = (url, init) => {
  const key = String(url);
  if (!fetchCache.has(key)) {
    const p = fetch(url, init).then(async (r) => ({ status: r.status, buf: await r.arrayBuffer(), type: r.headers.get("content-type") }));
    p.catch(() => setTimeout(() => fetchCache.delete(key), 30_000));
    fetchCache.set(key, p);
  }
  return fetchCache.get(key).then((r) => new Response(r.buf.slice(0), { status: r.status, headers: r.type ? { "content-type": r.type } : {} }));
};

// ------------------------------------------------------------------ host consent
// Lookups go to these hosts without asking. Any other host a document names is contacted only after the user allows it (memory only).
const KNOWN_HOSTS = new Set(["cloudflare-dns.com", "dns.google", "github.com", "api.github.com", "gitlab.com", "keys.openpgp.org"]);
const allowedHosts = new Set();
const NEEDS_PERMISSION = "permission needed to contact ";
const NEEDS_PERMISSION_RE = /permission needed to contact ([a-z0-9.:[\]-]+)/g;
const hostOf = (url) => {
  try {
    return new URL(String(url)).host.toLowerCase();
  } catch {
    return null;
  }
};

function remoteResourceUrls(text) {
  const out = new Set();
  try {
    for (const b of parseDocument(text).chain) for (const m of (b.fields?.resources ?? "").matchAll(/https:\/\/\S+/gi)) out.add(m[0]);
  } catch {}
  return out;
}

function gatedFetch(run) {
  return (url, init) => {
    const host = hostOf(url);
    // The "fetch remote resources" checkbox is the consent for the document's own resource URLs.
    if (host && (KNOWN_HOSTS.has(host) || allowedHosts.has(host) || run.resourceUrls.has(String(url)))) return cachedFetch(url, init);
    if (host) run.blocked.add(host);
    return Promise.reject(new TypeError(NEEDS_PERMISSION + (host ?? "an invalid URL")));
  };
}

function permissionHosts(s, blocked) {
  if (s.status !== "unresolved") return [];
  const out = new Set();
  for (const m of `${s.message ?? ""}\n${s.revocation?.detail ?? ""}`.matchAll(NEEDS_PERMISSION_RE)) out.add(m[1].replace(/\.+$/, ""));
  // pgp lookups report "unreachable" without the reason, so the hosts are also derived from the block itself
  const f = s.fields;
  const candidates = [];
  if (f.method === "git-hosting" && f.signer) candidates.push(f.signer.split("/")[0]);
  if (f.method === "pgp" && f.signer?.includes("@")) {
    const domain = f.signer.slice(f.signer.lastIndexOf("@") + 1);
    candidates.push(domain, `openpgpkey.${domain}`);
  }
  if (f.revocation_url) candidates.push(hostOf(f.revocation_url));
  for (const h of candidates) if (h && blocked.has(h.toLowerCase())) out.add(h.toLowerCase());
  return [...out].filter((h) => !allowedHosts.has(h));
}

// ------------------------------------------------------------------ TSA roots
// Same-origin list kept current by the monthly workflow; the core's built-in list is used when it cannot be read.
let tsaRoots;
const tsaRootsReady = fetch(new URL("./tsa-roots.json", import.meta.url), { cache: "no-cache" })
  .then((r) => (r.ok ? r.json() : null))
  .then(async (list) => {
    const ders = [];
    for (const r of list?.roots ?? []) {
      const der = fromBase64(r.der);
      if (toHex(await sha256(der)) !== r.sha256) throw new Error(`tsa-roots.json: fingerprint mismatch for ${r.name}`);
      ders.push(der);
    }
    if (ders.length) {
      tsaRoots = ders;
      builtinRootNames = list.roots.map((r) => r.name);
    }
  })
  .catch((e) => console.warn(e))
  .then(renderTsaRoots);

// Roots the user adds are kept in memory only, like host permissions.
const userTsaRoots = new Map();
let builtinRootNames = DEFAULT_TSA_ROOTS.map((r) => r.name);
let tsaRootNote = "";
function renderTsaRoots() {
  $("tsa-root-list").replaceChildren(
    ...[...userTsaRoots.values()].map((r) =>
      el(
        "li",
        { title: r.sha256 },
        el("bdi", {}, visible(r.name, false)),
        el("span", { class: "opt" }, ` ${r.sha256.slice(0, 16)}… ${t("roots.expires", { date: r.notAfter })} `),
        el("button", { type: "button", class: "ghost small", "data-remove": r.sha256, "aria-label": t("roots.remove", { name: visible(r.name, false) }) }, "×"),
      ),
    ),
  );
  $("tsa-root-note").textContent = tsaRootNote || t("roots.builtin", { n: builtinRootNames.length, names: builtinRootNames.join(getLang() === "ja" ? "、" : ", ") });
}
$("tsa-root-input").addEventListener("change", async (e) => {
  const notes = [];
  for (const file of e.target.files) {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const text = new TextDecoder().decode(bytes.subarray(0, 64));
    try {
      for (const r of await readTsaRoots(text.includes("-----BEGIN") ? new TextDecoder().decode(bytes) : bytes)) {
        if (userTsaRoots.has(r.sha256)) notes.push(t("roots.duplicate", { name: visible(r.name, false) }));
        else userTsaRoots.set(r.sha256, r);
      }
    } catch {
      notes.push(t("roots.invalid", { file: visible(file.name, false) }));
    }
  }
  e.target.value = "";
  tsaRootNote = notes.join(" / ");
  renderTsaRoots();
  scheduleVerify(0);
});
$("tsa-root-list").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-remove]");
  if (!b) return;
  userTsaRoots.delete(b.dataset.remove);
  tsaRootNote = "";
  renderTsaRoots();
  scheduleVerify(0);
});
onLangChange(renderTsaRoots);

// ------------------------------------------------------------------ verification server
// Optional second verifier (CLI_SPEC 3.6). Its verdict is shown next to this page's, never merged into it.
let serverUrl = "";
let serverState = null;
let serverTimer;
let serverAbort;
const serverHost = () => visible(hostOf(serverUrl) ?? "", false);
function renderServerNote() {
  const st = serverState;
  const host = serverHost();
  $("server-note").textContent = !st
    ? ""
    : st.badUrl
      ? t("srv.bad-url")
      : st.pending
        ? t("srv.asking", { host })
        : st.error
          ? t("srv.error", { host, error: visible(st.error, false) })
          : !st.comparison.agree
            ? t("srv.differ", { host })
            : !st.comparison.tsaAgree
              ? t("srv.tsa-differ", { host })
              : t("srv.agree", { host });
}
function askServer(text, id) {
  clearTimeout(serverTimer);
  serverAbort?.abort();
  if (!serverUrl) return;
  serverState = { pending: true };
  renderServerNote();
  serverTimer = setTimeout(async () => {
    serverAbort = new AbortController();
    let next;
    try {
      const remote = await remoteVerify(serverUrl, text, { signal: serverAbort.signal });
      next = { comparison: compareResults(lastResult, remote), remote };
    } catch (e) {
      if (e?.name === "AbortError") return;
      next = { error: String(e?.message ?? e) };
    }
    if (id !== runId || !serverUrl) return;
    serverState = next;
    renderServerNote();
    if (lastResult) render(lastResult);
  }, 400);
}
function serverRow(s) {
  const b = serverState?.comparison?.blocks.find((x) => x.index === s.index);
  if (!b) return null;
  const r = b.remote;
  const parts = !r
    ? [t("srv.block.missing")]
    : [STATUS_KEYS.has(r.status) ? t(`card.status.${r.status}`) : visible(r.status, false), r.tsaVerified === null ? null : r.tsaVerified ? t("srv.block.tsa-verified", { signer: visible(r.tsaSigner ?? "", false) }) : t("srv.block.tsa-unverified")];
  const same = b.agree && b.tsaAgree;
  if (!same) parts.push(t("srv.block.differs"));
  return el("span", { class: `blk-word is-${same ? "plain" : "bad"}` }, parts.filter(Boolean).join(getLang() === "ja" ? "、" : ", "));
}
$("server-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const raw = $("server-url").value.trim();
  let ok = false;
  try {
    const u = new URL(raw);
    ok = u.protocol === "https:" || (u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1"));
  } catch {}
  serverUrl = ok ? raw : "";
  serverState = ok ? null : { badUrl: true };
  renderServerNote();
  scheduleVerify(0);
});
$("server-clear").addEventListener("click", () => {
  serverUrl = "";
  serverState = null;
  serverAbort?.abort();
  $("server-url").value = "";
  renderServerNote();
  if (lastResult) render(lastResult);
});
onLangChange(renderServerNote);

// ------------------------------------------------------------------ attached files
const attached = new Map();
const lastSeg = (p) => p.split("/").pop();
const cleanRef = (ref) => ref.replace(/^(\.\/)+/, "");

async function addFile(file, path) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  path = cleanRef(path || file.name);
  attached.set(path, { name: lastSeg(path), path, bytes });
}

async function loadResource(ref) {
  const external = getResourceLoader();
  if (external) {
    const bytes = await external(ref);
    if (bytes) return bytes;
  }
  const p = cleanRef(ref);
  if (attached.has(p)) return attached.get(p).bytes;
  const name = lastSeg(p);
  for (const f of attached.values()) if (f.name === name) return f.bytes;
  return null;
}

function renderAttached() {
  const list = $("attach-list");
  list.replaceChildren(
    ...[...attached.values()].map((f) =>
      el(
        "li",
        {},
        el("code", {}, f.path),
        el("span", { class: "opt" }, ` ${f.bytes.length.toLocaleString()} B `),
        el("button", { type: "button", class: "ghost small", "data-remove": f.path, "aria-label": t("attach.remove", { path: f.path }) }, "×"),
      ),
    ),
  );
  renderCosignResources();
}

async function addFiles(entries) {
  for (const { file, path } of entries) await addFile(file, path);
  renderAttached();
  scheduleVerify(0);
}

const stripTop = (rel) => (rel && rel.includes("/") ? rel.slice(rel.indexOf("/") + 1) : rel);

$("attach-input").addEventListener("change", async (e) => {
  await addFiles([...e.target.files].map((file) => ({ file, path: file.name })));
  e.target.value = "";
});
$("attach-folder").addEventListener("change", async (e) => {
  await addFiles([...e.target.files].map((file) => ({ file, path: stripTop(file.webkitRelativePath) || file.name })));
  e.target.value = "";
});
$("attach-list").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-remove]");
  if (!b) return;
  attached.delete(b.dataset.remove);
  renderAttached();
  scheduleVerify(0);
});

const statusPane = document.querySelector(".status-pane");
function readEntry(entry, prefix, out) {
  return new Promise((resolve) => {
    if (entry.isFile) {
      entry.file(
        (file) => {
          out.push({ file, path: prefix + file.name });
          resolve();
        },
        () => resolve(),
      );
    } else if (entry.isDirectory) {
      const reader = entry.createReader();
      const all = [];
      const next = () =>
        reader.readEntries(
          async (batch) => {
            if (!batch.length) {
              for (const c of all) await readEntry(c, prefix + entry.name + "/", out);
              resolve();
            } else {
              all.push(...batch);
              next();
            }
          },
          () => resolve(),
        );
      next();
    } else resolve();
  });
}
statusPane.addEventListener("dragover", (e) => {
  if (![...(e.dataTransfer?.types ?? [])].includes("Files")) return;
  e.preventDefault();
  statusPane.classList.add("dropping");
});
statusPane.addEventListener("dragleave", (e) => {
  if (!statusPane.contains(e.relatedTarget)) statusPane.classList.remove("dropping");
});
statusPane.addEventListener("drop", async (e) => {
  if (!e.dataTransfer?.files?.length) return;
  e.preventDefault();
  statusPane.classList.remove("dropping");
  const items = [...(e.dataTransfer.items ?? [])].map((i) => i.webkitGetAsEntry?.()).filter(Boolean);
  const out = [];
  if (items.length) {
    for (const entry of items) await readEntry(entry, "", out);
    if (items.length === 1 && items[0].isDirectory) for (const o of out) o.path = stripTop(o.path);
  } else {
    for (const file of e.dataTransfer.files) out.push({ file, path: file.name });
  }
  await addFiles(out);
});

$("fetch-remote").addEventListener("change", () => scheduleVerify(0));

// ------------------------------------------------------------------ test keys
let useTestKeys = false;
const TEST_WARNING = "TEST KEY from examples/keys.json (RFC 8032), resolved locally, not a real identity";
const testResolvers = {
  async "git-hosting"(fields, opts) {
    const entry = TEST_KEYS["git-hosting"][fields.signer];
    if (!entry) return DEFAULT_RESOLVERS["git-hosting"](fields, opts);
    const keys = [];
    for (const k of parseSshPublicKeys(entry.keys_file)) {
      if (!k.key) continue;
      const fp = await sshFingerprint(k.key);
      if (fields.key_fp && fp !== fields.key_fp) continue;
      keys.push({ alg: "ed25519", key: k.key, source: `test key ${fields.signer} (${fp})` });
    }
    if (!keys.length) throw new ResolutionError(`no test key with fingerprint ${fields.key_fp}`, "not-found");
    return { keys, warnings: [TEST_WARNING] };
  },
  async dns(fields, opts) {
    const name = dnsName(fields);
    const entry = TEST_KEYS.dns[name];
    if (!entry) return DEFAULT_RESOLVERS.dns(fields, opts);
    const rec = parseDnsRecord(entry.txt);
    return { keys: [{ alg: rec.k, key: decodePublicKey(rec.k, fromBase64(rec.p)), source: `test TXT ${name}` }], warnings: [TEST_WARNING] };
  },
};

// examples/pgp certificates answer their own WKD / keyserver URLs from examples.js; other URLs act as unreachable hosts
const TEST_PGP_WARNING = "TEST KEY from examples/pgp, served in the page for its WKD / keyserver URL; not a real identity";
const testPgpFetch = async (url) => {
  const fpr = TEST_KEYS.pgpFetch?.[String(url)];
  if (!fpr) throw new TypeError("Failed to fetch");
  return new Response(TEST_KEYS.pgp[fpr].cert, { status: 200, headers: { "content-type": "application/pgp-keys" } });
};
// Always active: the test certificates use example.org addresses, which cannot belong to anyone.
const pgpTestResolvers = {
  async pgp(fields, opts) {
    if (!TEST_KEYS.pgp?.[fields.fpr]) return DEFAULT_RESOLVERS.pgp(fields, opts);
    const res = await DEFAULT_RESOLVERS.pgp(fields, { ...opts, fetch: testPgpFetch });
    return { keys: res.keys, warnings: [...res.warnings, TEST_PGP_WARNING] };
  },
};
testResolvers.pgp = pgpTestResolvers.pgp;

// ------------------------------------------------------------------ verification
let runId = 0;
let timer;
let lastResult = null;
let initialSummaryKey = null;

function scheduleVerify(delay = 120) {
  clearTimeout(timer);
  timer = setTimeout(runVerify, delay);
}

async function runVerify() {
  const id = ++runId;
  const text = editor.value;
  let result;
  const run = { blocked: new Set(), resourceUrls: $("fetch-remote").checked ? remoteResourceUrls(text) : new Set() };
  await tsaRootsReady;
  try {
    result = await verifyDocument(text, {
      fetch: gatedFetch(run),
      tsaRoots,
      extraTsaRoots: [...userTsaRoots.values()].map((r) => r.der),
      tofuStore: new MemoryTofuStore(),
      // Without attached files or an opened folder, local resources are reported as not checked rather than missing.
      loadResource: attached.size || getResourceLoader() ? loadResource : undefined,
      fetchResources: $("fetch-remote").checked,
      resolvers: useTestKeys ? testResolvers : pgpTestResolvers,
    });
  } catch (e) {
    result = { ok: false, signatures: [], warnings: [], agreement: { status: "none", required: [], missing: [], violations: [] }, error: String(e?.message ?? e) };
  }
  if (id !== runId) return;
  for (const s of result.signatures) s.needsHosts = permissionHosts(s, run.blocked);
  lastResult = result;
  if (serverUrl) serverState = { pending: true };
  render(result);
  askServer(text, id);
  renderCosignSections(text);
  renderCosignResources();
}

const STATUS_KEYS = new Set(["valid", "invalid", "malformed", "unresolved", "unsupported"]);
const CODE_KEYS = new Set([
  "hash-mismatch",
  "bad-signature",
  "expired",
  "revoked",
  "key-changed",
  "key-not-published",
  "resource-mismatch",
  "resource-missing",
  "scope-missing",
  "unknown-field",
  "network",
  "not-found",
  "offline",
  "malformed",
  "unsupported-version",
  "unsupported-hash",
  "unsupported-alg",
  "unsupported-method",
]);
const SHOWN_ELSEWHERE = [/^pgp: the certificate is the current one/, /^partial signature:/, /^webauthn: rp_id is localhost/, /^\d+ resource\(s\) not checked/, /^revocation not checked:/];

const reEscape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const WARNING_TEXT = [
  [new RegExp("^" + reEscape(TEST_WARNING) + "$"), "warn.test-key"],
  [new RegExp("^" + reEscape(TEST_PGP_WARNING) + "$"), "warn.test-pgp-key"],
  [/^pgp key lookup: (.*)$/s, "warn.pgp-lookup", (m) => ({ list: lookupText(m[1]) })],
  [/^OpenPGP key (\S+) expired on (\S+)$/, "warn.pgp-expired", (m) => ({ fpr: groupFpr(m[1]), when: m[2] })],
  [/^tofu: the key is embedded in the document/, "warn.tofu-embedded"],
  [/^tofu: KEY CHANGED for signer "(.*)" \(previously (.*)\)$/, "warn.tofu-key-changed", (m) => ({ signer: m[1], prev: m[2] })],
  [/^ts "(.*)" is not in YYYY-MM-DDTHH:MM:SSZ form$/, "warn.ts-format", (m) => ({ ts: m[1] })],
  [/^timestamp could not be checked: (.*)$/s, "warn.tsa-unchecked", (m) => ({ detail: tsaDetail(m[1]) })],
  [/^line (\d+): an md-signature marker inside the body is treated as document content/, "warn.stray-marker", (m) => ({ line: m[1] })],
];
const REVOCATION_DETAIL = [
  [/^revocation list not fetched \(offline\)$/, "rev.detail.offline"],
  [/^revocation check disabled$/, "rev.detail.disabled"],
  [/^revocation list is not signed by this signer$/, "rev.detail.not-signed"],
  [/^could not fetch revocation list: (.*)$/s, "rev.detail.fetch-failed", (m) => ({ error: m[1] })],
  [/^revocation list does not verify: (.*)$/s, "rev.detail.not-verified", (m) => ({ error: m[1] })],
];
const RESOURCE_DETAIL = [
  [/^remote resources are fetched only on request$/, "res.hint.not-requested"],
  [/^the document's directory is not available$/, "res.hint.no-directory"],
];
const TSA_REASON = [
  [/^TSA certificate does not chain to a trusted root: /, "tsa.reason.untrusted"],
  [/^TSA certificate was not valid at the token's time$/, "tsa.reason.cert-time"],
  [/^TSA certificate lacks the timeStamping extended key usage$/, "tsa.reason.no-eku"],
  [/^signature does not verify with the TSA certificate$/, "tsa.reason.bad-signature"],
  [/^message-digest does not match the TSTInfo$/, "tsa.reason.bad-signature"],
];
const TSA_DETAIL = [
  [/^imprint matched; TSA signature verified \((.*)\)$/s, "tsa.detail.verified", (m) => ({ signer: visible(m[1], false) })],
  [/^imprint matched; TSA signature not verified: (.*)$/s, "tsa.detail.unverified", (m) => ({ reason: visible(mapText(m[1], TSA_REASON), false) })],
  [/^message imprint does not match SHA-256\(sig\)$/, "tsa.detail.mismatch"],
  [/^TSA status (\S+) \(not granted\)$/, "tsa.detail.not-granted", (m) => ({ status: m[1] })],
  [/^unsupported imprint hash (\S+)$/, "tsa.detail.unsupported-hash", (m) => ({ oid: m[1] })],
];
const KEY_SOURCE = [
  [/^embedded pubkey$/, "key.embedded"],
  [/^test key (\S+) \((.*)\)$/, "key.test", (m) => ({ signer: m[1], fp: m[2] })],
  [/^test TXT (\S+)$/, "key.test-txt", (m) => ({ name: m[1] })],
];
const PGP_DETAIL = [
  [/^no OpenPGP key (\S+) found \((.*)\)$/s, "pgp.detail.not-found", (m) => ({ list: lookupText(m[2]) })],
  [/^no valid user ID with <(.*)> on key (\S+)$/, "pgp.detail.no-uid", (m) => ({ email: m[1] })],
  [/^OpenPGP (?:sub)?key (\S+) has been revoked$/, "pgp.detail.revoked"],
  [/^OpenPGP signature does not verify with the signer's key$/, "pgp.detail.bad-signature"],
  [/^OpenPGP signature issuer (\S+) does not match fpr$/, "pgp.detail.issuer", (m) => ({ fpr: groupFpr(m[1]) })],
  [/^OpenPGP signature hash algorithm \d+ is not SHA-256, SHA-384 or SHA-512$/, "pgp.detail.hash"],
  [/^(?:sub)?key \S+ is not marked for signing$/, "pgp.detail.not-signing"],
  [/^(?:signing )?subkey \S+ has no valid (?:primary key )?binding signature$/, "pgp.detail.binding"],
];
const LOOKUP_RESULT = { found: "pgp.lookup.found", "no key": "pgp.lookup.absent", unreachable: "pgp.lookup.unreachable", "skipped (offline)": "pgp.lookup.offline" };
function lookupText(list) {
  const items = list.split("; ").map((part) => {
    const m = /^(.*): (found|no key|unreachable|skipped \(offline\))$/.exec(part);
    if (!m) return part;
    const src = m[1] === "keyring" ? t("pgp.src.keyring") : m[1];
    return t("pgp.lookup.item", { src, result: t(LOOKUP_RESULT[m[2]]) });
  });
  // browsers usually cannot reach WKD hosts because they rarely send CORS headers
  const wkdBlocked = /(^|; )WKD: unreachable/.test(list);
  return items.join(t("list.sep")) + (wkdBlocked ? t("pgp.lookup.wkd-cors") : "");
}
const groupFpr = (f) => (f ?? "").match(/.{1,4}/g)?.join(" ") ?? "";
const PGP_ALG = { ed25519: "Ed25519", "ecdsa-p256": "ECDSA P-256" };
const pgpAlgName = (a) => PGP_ALG[a] ?? (/^rsa\d+$/.test(a ?? "") ? `RSA ${a.slice(3)}` : a);
function pgpSourceText(s) {
  const src = s.pgp?.keySource;
  if (!src) return null;
  let host = "";
  try {
    const url = s.key?.source?.split(" ")[1];
    if (url) host = new URL(url).host;
  } catch {}
  return t(`pgp.src.${src}`) + (host ? ` (${host})` : "");
}
const DOC_ERROR = [
  [/^no signatures found$/, "summary.no-signatures"],
  [/^unsigned content after the last signature \(signature block at line (\d+)/, "summary.unsigned-tail", (m) => ({ line: m[1] })],
];
const warningText = (w) => mapText(w, WARNING_TEXT);
function tsaDetail(d) {
  return mapText(d, TSA_DETAIL);
}

// ------------------------------------------------------------------ status line
const SVG_NS = "http://www.w3.org/2000/svg";
function svgEl(tag, attrs) {
  const n = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  return n;
}
const SEAL_GLYPH = {
  ok: [["path", { d: "M8.2 12.4l2.6 2.6 5-5.6" }]],
  bad: [["path", { d: "M9.2 9.2l5.6 5.6M14.8 9.2l-5.6 5.6" }]],
  warn: [
    ["path", { d: "M9.9 9.9a2.15 2.15 0 1 1 3.1 1.9c-.65.3-1 .75-1 1.45v.35" }],
    ["circle", { cx: "12", cy: "16.1", r: "0.55", fill: "currentColor" }],
  ],
  pending: [
    ["circle", { cx: "8.6", cy: "12", r: "0.6", fill: "currentColor" }],
    ["circle", { cx: "12", cy: "12", r: "0.6", fill: "currentColor" }],
    ["circle", { cx: "15.4", cy: "12", r: "0.6", fill: "currentColor" }],
  ],
  idle: [["path", { d: "M9 12h6" }]],
};
function seal(state) {
  const s = svgEl("svg", { class: "sl-seal", viewBox: "0 0 24 24", width: "22", height: "22", "aria-hidden": "true", fill: "none", stroke: "currentColor", "stroke-linecap": "round", "stroke-linejoin": "round" });
  s.append(svgEl("circle", { cx: "12", cy: "12", r: "10.6", "stroke-width": "1.3" }), svgEl("circle", { cx: "12", cy: "12", r: "8.4", "stroke-width": "0.7", opacity: "0.55" }));
  for (const [tag, attrs] of SEAL_GLYPH[state] ?? SEAL_GLYPH.idle) s.append(svgEl(tag, { "stroke-width": "1.6", ...attrs }));
  return s;
}
function setStatusLine(state, head, sub, tally) {
  summary.className = `sealline is-${state}`;
  summary.replaceChildren(
    seal(state),
    el("div", { class: "sealline-text" }, el("div", { class: "sealline-head" }, head), sub ? el("div", { class: "sealline-sub" }, sub) : null),
    tally ? el("div", { class: "sealline-tally" }, tally) : null,
  );
}
function renderInitialSummary() {
  setStatusLine(initialSummaryKey === "summary.no-webcrypto" ? "bad" : "idle", t(initialSummaryKey));
}

// SPEC 5.8: one plain list for a declaration with a single step that needs everyone, per-step text otherwise
function missingText(a) {
  const stepsOf = new Map();
  for (const q of a.required) stepsOf.set(q.declaredBy, Math.max(stepsOf.get(q.declaredBy) ?? 0, q.step ?? 1));
  const groups = [];
  for (const m of a.missing) {
    let g = groups[groups.length - 1];
    if (!g || g.declaredBy !== m.declaredBy || g.step !== m.step) groups.push((g = { declaredBy: m.declaredBy, step: m.step ?? 1, need: m.need ?? 1, any: m.any ?? 1, blockedBy: m.blockedBy, names: [] }));
    g.names.push(visible(`${m.method}:${m.signer}${m.role ? " " + m.role : ""}`) + (m.early ? t("summary.early") : ""));
  }
  return groups
    .map((g) => {
      const list = g.names.join(", ");
      if (stepsOf.get(g.declaredBy) === 1 && g.any === g.need && g.need === g.names.length) return list;
      return t("summary.step-missing", { step: g.step, need: g.need, list }) + (g.blockedBy ? t("summary.step-after", { step: g.blockedBy }) : "");
    })
    .join(t("list.sep"));
}

const violationText = (vs) => vs.map((v) => t("summary.violation-item", { index: v.index, who: visible(`${v.method}:${v.signer}${v.role ? " " + v.role : ""}`), step: v.step })).join(t("list.sep"));

// signatures still needed in total: a step that needs any m counts m
function agreementTally(a) {
  const steps = new Map();
  for (const q of a.required) steps.set(`${q.declaredBy}/${q.step ?? 1}`, q.any ?? 1);
  const short = new Map();
  for (const m of a.missing) short.set(`${m.declaredBy}/${m.step ?? 1}`, m.need ?? 1);
  const req = [...steps.values()].reduce((x, y) => x + y, 0);
  return { req, got: req - [...short.values()].reduce((x, y) => x + y, 0) };
}

function renderSummary(r) {
  const n = r.signatures.length;
  const valid = r.signatures.filter((s) => s.status === "valid").length;
  const bad = n - valid;
  const sep = t("list.sep");
  const dot = " · ";
  if (!r.ok && n > 0 && valid === n && r.agreement?.status === "violated") {
    setStatusLine("bad", t("summary.violated"), t("summary.violations", { list: violationText(r.agreement.violations) }), t("tally.valid", { ok: valid, n }) + dot + t("tally.violated"));
    return;
  }
  if (r.ok) {
    const a = r.agreement ?? { status: "none", required: [], missing: [], violations: [] };
    const partial = r.signatures.filter((s) => s.partial);
    const sub = [];
    if (partial.length)
      sub.push(
        t("summary.partial", {
          items: partial.map((s) => t("summary.partial-item", { index: s.index, sections: s.partial.sections.join(", ") })).join(sep),
        }),
      );
    const unchecked = r.signatures.flatMap((s) => (s.resources ?? []).filter((x) => x.status === "not-checked")).length;
    if (unchecked) sub.push(t("summary.unchecked", { resources: count("resource", unchecked) }));
    const { req, got } = agreementTally(a);
    const tallyValid = t("tally.valid", { ok: valid, n });
    if (a.violations?.length) sub.push(t("summary.order-warning", { list: violationText(a.violations) }));
    if (a.status === "pending") {
      sub.unshift(t("summary.pending-missing", { list: missingText(a) }));
      setStatusLine("pending", t("summary.pending"), sub.join(" "), tallyValid + dot + t("tally.pending", { got, req }));
      return;
    }
    setStatusLine(
      "ok",
      a.status === "complete" ? t("summary.complete") : t("summary.chain"),
      sub.join(" "),
      tallyValid + dot + (a.status === "complete" ? t("tally.complete", { got, req }) : t("tally.chain-ok")),
    );
  } else if (n === 0) {
    const none = r.error === "no signatures found";
    setStatusLine(none ? "idle" : "bad", r.error ? capitalize(mapText(r.error, DOC_ERROR)) : t("summary.no-signatures"));
  } else {
    const onlyUnresolved = r.signatures.every((s) => s.status === "valid" || s.status === "unresolved" || s.status === "unsupported");
    const first = r.signatures.find((s) => s.status !== "valid");
    setStatusLine(
      onlyUnresolved ? "warn" : "bad",
      t(onlyUnresolved ? "summary.unchecked-sigs" : "summary.failed", { bad, signatures: count("signature", n) }),
      null,
      t("tally.valid", { ok: valid, n }) + dot + (onlyUnresolved ? t("tally.unchecked", { bad }) : t("tally.fails-at", { index: first.index })),
    );
  }
}

const tone = (status) => (status === "valid" ? "ok" : status === "invalid" || status === "malformed" ? "bad" : "warn");
const RES_TONE = { ok: "ok", mismatch: "bad", missing: "bad", unreachable: "warn", "not-checked": "muted" };
const COVERAGE_CODES = new Set(["hash-mismatch", "scope-missing"]);

function renderLink(s) {
  let label;
  if (s.partial) label = t("link.scope", { sections: s.partial.sections.join(", ") });
  else if (s.index <= 1) label = t("link.body");
  else label = t("link.body-prev", { blocks: s.index === 2 ? "#1" : `#1–#${s.index - 1}` });
  const h = s.fields.hash;
  const m = h && /^([a-z0-9-]+):([0-9a-f]{12})[0-9a-f]*$/i.exec(h);
  return el(
    "div",
    { class: "blk-link" },
    el("span", { class: "blk-link-label" }, label),
    m ? el("span", { class: "blk-link-hash", title: h }, `${m[1]}:${m[2]}…`) : null,
  );
}

const defRow = (key, ...value) => [el("dt", {}, t(key)), el("dd", {}, ...value)];

function renderCard(s) {
  const f = s.fields;
  const st = tone(s.status);
  const broken = COVERAGE_CODES.has(s.code);
  const li = el("li", { class: `blk is-${st}${broken ? " is-broken" : ""}${s.partial ? " is-partial" : ""}`, "data-status": s.status });
  const needsHosts = s.needsHosts ?? [];
  const revocationFailed = s.status === "unresolved" && !needsHosts.length && s.revocation?.status === "not-checked";
  const statusText = needsHosts.length
    ? t("card.status.permission")
    : revocationFailed
      ? t("card.status.revocation-unchecked")
      : s.code === "key-not-published"
      ? t("card.status.key-not-published")
      : s.status === "unresolved" && s.resources?.some((x) => x.status === "unreachable")
      ? t("card.status.resource-unreachable")
      : s.status === "valid" && s.partial
        ? t("card.status.valid-partial")
        : STATUS_KEYS.has(s.status)
          ? t(`card.status.${s.status}`)
          : s.status;
  li.append(
    el("span", { class: "blk-node", "aria-hidden": "true" }, `#${s.index}`),
    renderLink(s),
    el(
      "div",
      { class: "blk-head" },
      el("span", { class: "blk-idx" }, `#${s.index}`),
      el("span", { class: "blk-signer" }, f.signer != null ? shown(f.signer) : t("card.no-signer")),
      f.role ? el("span", { class: "blk-role" }, shown(f.role, { max: 40 })) : null,
      el("span", { class: "blk-status" }, statusText),
    ),
    el("div", { class: "blk-meta" }, shown([f.method, f.alg, f.ts].filter(Boolean).join(" · "), { max: 96 })),
  );
  if (needsHosts.length) {
    li.append(el("p", { class: "blk-msg" }, t("code.permission", { hosts: needsHosts.map((h) => visible(h)).join(t("list.sep")) })));
  } else if (revocationFailed) {
    li.append(el("p", { class: "blk-msg" }, t("code.revocation-unchecked")));
    const reason = visible(mapText(s.revocation.detail ?? "", REVOCATION_DETAIL), false);
    li.append(el("p", { class: "blk-detail" }, reason + (s.code === "network" ? " " + t("rev.cors-hint") : "")));
  } else if (s.status !== "valid") {
    const label = CODE_KEYS.has(s.code) ? t(`code.${s.code}`) : undefined;
    const detail = f.method === "pgp" ? mapText(s.message, PGP_DETAIL) : s.message;
    li.append(el("p", { class: "blk-msg" }, label ?? visible(detail ?? "", false)));
    if (label && detail) li.append(el("p", { class: "blk-detail" }, visible(detail, false)));
  }

  const dl = el("dl", { class: "blk-defs" });
  const warns = s.warnings.filter((w) => !SHOWN_ELSEWHERE.some((re) => re.test(w))).map(warningText);
  if (s.pgp) {
    const p = s.pgp;
    if (p.fpr) dl.append(...defRow("def.fpr", el("span", { class: "blk-fpr" }, groupFpr(p.fpr))));
    if (p.uid) dl.append(...defRow("def.uid", shown(p.uid, { max: 160, strict: false })));
    const src = pgpSourceText(s);
    if (src) dl.append(...defRow("def.key-source", src));
    if (p.keyAlg) dl.append(...defRow("def.key-alg", pgpAlgName(p.keyAlg)));
    // SPEC 6.2: the packet time is signer-set like ts; only tsa_token is third-party evidence
    if (p.created) dl.append(...defRow("def.pgp-created", p.created, el("span", { class: "blk-hint" }, " " + t("card.pgp-created-note"))));
    if (p.keySource && p.keySource !== "keyring") warns.push(t("warn.pgp-current-cert"));
  } else if (s.key) dl.append(...defRow("def.key", mapText(s.key.source, KEY_SOURCE)));
  if (s.partial) dl.append(...defRow("def.scope", t("card.partial", { sections: s.partial.sections.join(", ") })));
  if (f.reason) dl.append(...defRow("def.reason", shown(t("card.reason", { reason: f.reason }), { max: 400, strict: false })));
  if (f.expires && s.code !== "expired") dl.append(...defRow("def.expires", shown(f.expires)));
  if (s.webauthn) {
    const w = s.webauthn;
    dl.append(
      ...defRow(
        "def.passkey",
        t("card.passkey.value", { rp: w.rpId, origin: w.origin || "?", uv: t(w.userVerified ? "card.passkey.uv-yes" : "card.passkey.uv-no") }),
      ),
    );
    if (w.rpId === "localhost") warns.unshift(t("card.passkey.localhost"));
  }
  if (s.resources?.length) {
    const ul = el("ul", { class: "blk-res", "aria-label": t("card.resources") });
    for (const x of s.resources) {
      const word = x.status in RES_TONE ? t(`res.${x.status}`) : x.status;
      let hint = mapText(x.detail ?? "", RESOURCE_DETAIL);
      if (x.status === "not-checked" && /^https:/i.test(x.ref)) hint = t("res.hint.enable-fetch");
      else if (x.status === "not-checked") hint = t("res.hint.attach");
      else if (x.status === "missing") hint = t(getResourceLoader() ? "res.hint.missing-folder" : "res.hint.missing");
      ul.append(
        el(
          "li",
          {},
          el("code", { class: "blk-res-ref" }, shown(x.ref, { max: 200 })),
          el("span", { class: `blk-word is-${RES_TONE[x.status] ?? "warn"}` }, word),
          hint ? el("span", { class: "blk-hint" }, hint) : null,
        ),
      );
    }
    dl.append(...defRow("def.resources", ul));
  }
  if (s.revocation) {
    const rv = s.revocation;
    const txt =
      rv.status === "not-revoked"
        ? t("rev.not-revoked")
        : rv.status === "revoked"
          ? t("rev.revoked")
          : rv.detail && !needsHosts.length
            ? t("rev.not-checked-detail", { detail: mapText(rv.detail, REVOCATION_DETAIL) })
            : t("rev.not-checked");
    const rtone = rv.status === "revoked" ? "bad" : rv.status === "not-revoked" ? "plain" : "muted";
    dl.append(...defRow("def.revocation", el("span", { class: `blk-word is-${rtone}` }, txt)));
  }
  if (s.tsa) {
    // genTime is shown only when the TSA signature chains to a built-in root; otherwise the row says why not
    const verified = s.tsa.status === "ok" && s.tsa.verified === true && s.tsa.genTime;
    const word = s.tsa.status === "mismatch" ? t("tsa.status.mismatch") : t("tsa.status.error");
    dl.append(...defRow("def.tsa", verified ? t("card.tsa-verified", { when: s.tsa.genTime, signer: visible(s.tsa.signer ?? "", false) }) : t("card.tsa", { when: word, detail: tsaDetail(s.tsa.detail) })));
  }
  const fromServer = serverRow(s);
  if (fromServer) dl.append(...defRow("def.server", fromServer));
  if (dl.childNodes.length) li.append(dl);
  if (warns.length) li.append(el("ul", { class: "blk-warns" }, ...warns.map((w) => el("li", {}, visible(w, false)))));

  const fields = el("dl", { class: "blk-fields" });
  const entries = Object.entries(f);
  for (const [k, v] of entries) fields.append(el("dt", {}, shown(k)), el("dd", {}, shown(v, { max: 120, strict: false })));
  li.append(el("details", { class: "blk-more" }, el("summary", {}, t("card.fields"), el("span", { class: "blk-more-n" }, String(entries.length))), fields));
  return li;
}

const consentBox = el("div", { class: "net-consent", role: "group", hidden: true });
summary.after(consentBox);
function renderConsent(r) {
  const hosts = [...new Set(r.signatures.flatMap((s) => s.needsHosts ?? []))].filter((h) => !allowedHosts.has(h));
  consentBox.hidden = !hosts.length;
  consentBox.setAttribute("aria-label", t("net.consent.title"));
  if (!hosts.length) return consentBox.replaceChildren();
  consentBox.replaceChildren(
    el("p", {}, t("net.consent.lede")),
    el("ul", {}, ...hosts.map((h) => el("li", {}, el("code", {}, shown(h, { max: 80 })), el("button", { type: "button", class: "ghost small", "data-allow": h }, t("net.consent.allow"))))),
    hosts.length > 1 ? el("button", { type: "button", class: "ghost small", "data-allow": hosts.join(" ") }, t("net.consent.allow-all")) : null,
  );
}
consentBox.addEventListener("click", (e) => {
  const b = e.target.closest("button[data-allow]");
  if (!b) return;
  for (const h of b.dataset.allow.split(" ")) allowedHosts.add(h);
  scheduleVerify(0);
});

function render(r) {
  renderSummary(r);
  renderConsent(r);
  cards.className = "sigchain";
  cards.replaceChildren(...r.signatures.map(renderCard));
  docWarnings.textContent = visible(r.warnings.map(warningText).join(" "), false);
}

// ------------------------------------------------------------------ editor + examples
editor.addEventListener("input", () => scheduleVerify());

const exampleSel = $("example-select");
let currentExample = "";
let exampleLang = getLang();
const exampleText = (id, lang) => EXAMPLES[id]?.text[lang] ?? "";
const exampleLabel = (ex) => ex.title[getLang()] ?? ex.title.en;
if (exampleSel) for (const [id, ex] of Object.entries(EXAMPLES)) exampleSel.append(el("option", { value: id }, exampleLabel(ex)));
function renderExampleOptions() {
  if (exampleSel) for (const o of exampleSel.options) if (EXAMPLES[o.value]) o.textContent = exampleLabel(EXAMPLES[o.value]);
}

function loadExample(id, { updateUrl = true } = {}) {
  const ex = EXAMPLES[id];
  if (!ex) return;
  currentExample = id;
  exampleLang = getLang();
  if (exampleSel) exampleSel.value = id;
  editor.value = exampleText(id, exampleLang);
  setTestKeys(!!ex.testKeys);
  if (ex.files) {
    for (const [path, b64] of Object.entries(ex.files)) attached.set(path, { name: lastSeg(path), path, bytes: fromBase64(b64) });
    renderAttached();
  }
  if (updateUrl) {
    try {
      const u = new URL(location.href);
      u.searchParams.set("example", id);
      history.replaceState(null, "", u);
    } catch {}
  }
  scheduleVerify(0);
}

function setTestKeys(on) {
  useTestKeys = on;
  $("test-keys-badge").hidden = !on;
}

exampleSel?.addEventListener("change", () => loadExample(exampleSel.value));
$("btn-reset")?.addEventListener("click", () => loadExample(exampleSel?.value || currentExample || "basic"));

export function loadText(text) {
  currentExample = "";
  editor.value = text;
  setTestKeys(false);
  scheduleVerify(0);
}

$("file-input")?.addEventListener("change", async (e) => {
  const file = e.target.files?.[0];
  if (!file) return;
  const text = await file.text();
  e.target.value = "";
  loadText(text);
});

export function download(name, text, type = "text/markdown") {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = el("a", { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
$("btn-download")?.addEventListener("click", () => download("signed.md", editor.value));

// ------------------------------------------------------------------ passkey store
const PK_STORE = "mdsig.passkeys";
function loadPasskeys() {
  try {
    const v = JSON.parse(localStorage.getItem(PK_STORE) ?? "[]");
    return Array.isArray(v) ? v.filter((p) => p && p.publicKey && p.credentialId && p.rpId) : [];
  } catch {
    return [];
  }
}
function savePasskeys(list) {
  try {
    localStorage.setItem(PK_STORE, JSON.stringify(list));
    return true;
  } catch {
    return false;
  }
}
let passkeys = loadPasskeys();
const passkeysHere = () => passkeys.filter((p) => p.rpId === RP_ID);

// ------------------------------------------------------------------ co-signing
const form = $("cosign-form");
const methodSel = $("cosign-method");
const PLACEHOLDER = { tofu: "carol@example.org", "git-hosting": "github.com/carol", dns: "example.com" };
const baseMethod = (m) => m.replace(/-passkey$/, "");
const isPasskey = (m) => m.endsWith("-passkey");

if (!HAS_WEBAUTHN) {
  for (const o of methodSel.options) if (isPasskey(o.value)) o.disabled = true;
  $("passkey-unsupported").hidden = false;
}

function renderPasskeyOptions() {
  const sel = $("cosign-passkey");
  const prev = sel.value;
  sel.replaceChildren(...passkeysHere().map((p, i) => el("option", { value: p.credentialId }, p.label || t("pk.default-label", { n: i + 1 }))));
  if (prev) sel.value = prev;
  syncMethod();
}

function syncMethod() {
  const m = methodSel.value;
  const b = baseMethod(m);
  const pk = isPasskey(m);
  form.querySelector(".only-dns").hidden = b !== "dns";
  // SPEC 4.5: key snapshots exist for dns and git-hosting only
  form.querySelector(".only-snapshot").hidden = b !== "dns" && b !== "git-hosting";
  const pgp = b === "pgp";
  form.querySelector(".only-key").hidden = b === "tofu" || pk || pgp;
  form.privkey.required = b !== "tofu" && !pk && !pgp;
  form.querySelector(".only-pgp").hidden = !pgp;
  form.querySelector("label.not-pgp").hidden = pgp;
  form.signer.required = !pgp;
  if (!pgp && pgpInfo) clearPgpKey();
  const has = passkeysHere().length > 0;
  form.querySelector("label.only-passkey").hidden = !pk || !has;
  $("passkey-none").hidden = !pk || has;
  form.signer.placeholder = PLACEHOLDER[b];
  if (pk && b === "tofu" && !form.signer.value) {
    const p = passkeysHere().find((x) => x.credentialId === $("cosign-passkey").value);
    if (p?.label) form.signer.value = p.label;
  }
}
methodSel.addEventListener("change", syncMethod);

// ------------------------------------------------------------------ pgp secret key
// SPEC 9.10: the key and passphrase live only in memory and are dropped after each signing attempt
let pgpInfo = null;
let pgpReadId = 0;
const pgpKeyArea = $("cosign-pgpkey");
const pgpPass = $("cosign-pgp-pass");
const pgpUid = $("cosign-pgp-uid");

function wipePgpInfo(info) {
  try {
    info?.key?.secretPart?.fill(0);
  } catch {}
}
function clearPgpKey() {
  pgpReadId++;
  wipePgpInfo(pgpInfo);
  pgpInfo = null;
  pgpKeyArea.value = "";
  pgpPass.value = "";
  showError($("cosign-pgp-error"), null);
  renderPgpInfo();
}

function renderPgpInfo() {
  const box = $("cosign-pgp-info");
  const i = pgpInfo;
  box.hidden = !i;
  form.querySelector("label.pgp-pass").hidden = !i?.protected;
  const emails = i?.emails ?? [];
  const prev = pgpUid.value;
  pgpUid.replaceChildren(...emails.map((e) => el("option", { value: e }, i.uids.find((u) => u.includes(`<${e}>`)) ?? e)));
  if (emails.includes(prev)) pgpUid.value = prev;
  form.querySelector("label.pgp-uid").hidden = emails.length < 2;
  if (!i) return box.replaceChildren();
  const row = (key, ...v) => [el("dt", {}, t(key)), el("dd", {}, ...v)];
  box.replaceChildren(
    ...row("def.fpr", el("span", { class: "blk-fpr" }, groupFpr(i.fpr))),
    ...row("def.key-alg", `${pgpAlgName(i.keyAlg)} · v${i.version}${i.fpr !== i.primaryFpr ? " · " + t("cs.pgp.subkey") : ""}`),
    ...row("def.uid", ...(i.uids.length ? i.uids.flatMap((u, n) => (n ? [el("br"), u] : [u])) : [t("cs.pgp.no-uid")])),
    ...row("cs.pgp.protection", t(i.protected ? "cs.pgp.protected" : "cs.pgp.unprotected")),
  );
}

async function readPgpKeyText(input) {
  const id = ++pgpReadId;
  wipePgpInfo(pgpInfo);
  pgpInfo = null;
  const err = $("cosign-pgp-error");
  showError(err, null);
  if (typeof input === "string" && !input.trim()) return renderPgpInfo();
  try {
    const info = await readPgpSecretKey(input);
    if (id !== pgpReadId) return wipePgpInfo(info);
    pgpInfo = info;
    if (!info.emails.length) showError(err, { key: "cs.err.pgp-no-email" });
  } catch (ex) {
    if (id === pgpReadId) showError(err, pgpErrorEntry(ex));
  }
  renderPgpInfo();
}

const PGP_ERROR = [
  [/^wrong passphrase$/, "cs.err.pgp-wrong-pass"],
  [/a passphrase is required$/, "cs.err.pgp-pass-required"],
  [/^Argon2-protected/, "cs.err.pgp-argon2"],
  [/^AEAD-protected/, "cs.err.pgp-aead"],
  [/stub for a smartcard or offline key/, "cs.err.pgp-stub"],
  [/^no OpenPGP secret key found$/, "cs.err.pgp-no-secret"],
];
function pgpErrorEntry(ex) {
  const msg = ex?.message ?? String(ex);
  for (const [re, key] of PGP_ERROR) if (re.test(msg)) return { key };
  return { key: "cs.err.pgp-read", vars: { error: msg } };
}

let pgpTimer;
pgpKeyArea.addEventListener("input", () => {
  clearTimeout(pgpTimer);
  pgpTimer = setTimeout(() => readPgpKeyText(pgpKeyArea.value), 150);
});
$("cosign-pgp-file").addEventListener("change", async (e) => {
  const file = e.target.files?.[0];
  e.target.value = "";
  if (!file) return;
  if (file.size > 1024 * 1024) return showError($("cosign-pgp-error"), { key: "cs.err.pgp-too-large" });
  const bytes = new Uint8Array(await file.arrayBuffer());
  // binary (non-armored) keys are read directly and are not shown in the text area
  const armored = new TextDecoder().decode(bytes.subarray(0, 1024)).includes("-----BEGIN PGP");
  pgpKeyArea.value = armored ? new TextDecoder().decode(bytes) : "";
  if (armored) bytes.fill(0);
  await readPgpKeyText(armored ? pgpKeyArea.value : bytes);
});
$("cosign-passkey").addEventListener("change", syncMethod);

function renderCosignSections(text) {
  const box = $("cosign-sections");
  const checked = new Set([...box.querySelectorAll("input:checked")].map((i) => i.value));
  let ids = [];
  try {
    ids = [...findSections(text.replace(/\r\n?/g, "\n")).sections.keys()];
  } catch {}
  const cur = [...box.querySelectorAll("input")].map((i) => i.value).join(",");
  if (cur === ids.join(",")) return;
  box.replaceChildren(
    ...ids.map((id) => el("label", { class: "check" }, el("input", { type: "checkbox", name: "scope", value: id, checked: checked.has(id) }), el("code", {}, id))),
  );
  $("cosign-sections-none").hidden = ids.length > 0;
}

function refFor(file, docRefs) {
  return docRefs.find((r) => cleanRef(r) === file.path) ?? docRefs.find((r) => lastSeg(cleanRef(r)) === file.name) ?? file.path;
}
function renderCosignResources() {
  const box = $("cosign-resources");
  const checked = new Set([...box.querySelectorAll("input")].filter((i) => i.checked).map((i) => i.dataset.path));
  const known = new Set([...box.querySelectorAll("input")].map((i) => i.dataset.path));
  let docRefs = [];
  try {
    docRefs = findLocalImages(editor.value);
  } catch {}
  const fromAttached = [...attached.values()].map((f) => {
    const ref = refFor(f, docRefs);
    const referenced = docRefs.some((r) => r === ref);
    const on = known.has(f.path) ? checked.has(f.path) : referenced;
    return el(
      "label",
      { class: "check" },
      el("input", { type: "checkbox", name: "resource", value: ref, "data-path": f.path, checked: on }),
      el("code", {}, ref),
      referenced ? el("span", { class: "opt" }, t("cosign.referenced")) : null,
    );
  });
  const covered = new Set(fromAttached.map((l) => l.querySelector("input").value));
  const fromFolder = getResourceLoader()
    ? docRefs
        .filter((r) => !covered.has(r))
        .map((ref) => {
          const key = "folder:" + ref;
          return el(
            "label",
            { class: "check" },
            el("input", { type: "checkbox", name: "resource", value: ref, "data-path": key, "data-folder": "", checked: known.has(key) ? checked.has(key) : true }),
            el("code", {}, ref),
            el("span", { class: "opt" }, t("cosign.from-folder")),
          );
        })
    : [];
  box.replaceChildren(...fromAttached, ...fromFolder);
  $("cosign-resources-none").hidden = fromAttached.length + fromFolder.length > 0;
}

function toUtcTs(local) {
  if (!local) return undefined;
  const d = new Date(local);
  if (Number.isNaN(d.getTime())) throw new UiError("cosign.err.expires");
  return d.toISOString().slice(0, 19) + "Z";
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("cosign-error");
  showError(err, null);
  const m = methodSel.value;
  const method = baseMethod(m);
  const submit = form.querySelector('button[type="submit"]');
  submit.disabled = true;
  let signer;
  try {
    if (isPasskey(m)) {
      if (!HAS_WEBAUTHN) throw new UiError("cosign.err.no-webauthn");
      const p = passkeysHere().find((x) => x.credentialId === $("cosign-passkey").value);
      if (!p) throw new UiError("cosign.err.no-passkey", { rp: RP_ID });
      signer = passkeySigner(p.rpId, fromBase64(p.publicKey), fromBase64(p.credentialId));
    } else if (method === "tofu") {
      signer = (await generateEd25519()).signer;
    } else if (method === "pgp") {
      if (!pgpInfo) throw new UiError("cs.err.pgp-no-key");
      if (!pgpInfo.emails.length) throw new UiError("cs.err.pgp-no-email");
      try {
        signer = await unlockPgpSecretKey(pgpInfo, pgpInfo.protected ? pgpPass.value : undefined);
      } catch (ex) {
        const e = pgpErrorEntry(ex);
        throw new UiError(e.key, e.vars);
      }
    } else {
      const { seed } = parseOpenSshPrivateKey(form.privkey.value);
      signer = await signerFromSeed(seed);
    }

    const scope = [...form.querySelectorAll('input[name="scope"]:checked')].map((i) => i.value);
    const require = form.require.value.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    const resources = [];
    for (const i of form.querySelectorAll('input[name="resource"]:checked')) {
      if (i.hasAttribute("data-folder")) {
        const bytes = await getResourceLoader()?.(i.value);
        if (!bytes) throw new UiError("cosign.err.resource-missing", { ref: i.value });
        resources.push({ ref: i.value, bytes });
        continue;
      }
      const f = attached.get(i.dataset.path);
      if (f) resources.push({ ref: i.value, bytes: f.bytes });
    }
    for (const url of form.remote.value.split(/\s+/).filter(Boolean)) {
      try {
        resources.push({ ref: url, bytes: await fetchResource(url) });
      } catch (ex) {
        throw new UiError("cosign.err.fetch", { url, error: ex?.message ?? ex });
      }
    }

    const res = await signDocument(editor.value, {
      signer,
      method,
      signerId: method === "pgp" ? pgpUid.value || pgpInfo.emails[0] : form.signer.value.trim(),
      selector: method === "dns" ? form.selector.value.trim() || undefined : undefined,
      embedKey: (method === "dns" || method === "git-hosting") && form.embedKey.checked ? true : undefined,
      role: form.role.value.trim() || undefined,
      reason: form.reason.value.trim() || undefined,
      scope: scope.length ? scope : undefined,
      require: require.length ? require : undefined,
      resources: resources.length ? resources : undefined,
      expires: toUtcTs(form.expires.value),
      revocationUrl: form.revocation.value.trim() || undefined,
    });
    editor.value = res.text;
    form.privkey.value = "";
    form.reason.value = "";
    editor.dispatchEvent(new Event("input", { bubbles: true }));
    selectTab($("tab-sigs"));
    scheduleVerify(0);
  } catch (ex) {
    showError(err, ex);
  } finally {
    if (method === "pgp") {
      signer?.dispose();
      signer = null;
      clearPgpKey();
    }
    submit.disabled = false;
  }
});

// ------------------------------------------------------------------ tabs
const tabs = [...document.querySelectorAll('.status-pane [role="tab"]')];
function selectTab(tab) {
  for (const t of tabs) {
    const on = t === tab;
    t.setAttribute("aria-selected", String(on));
    t.tabIndex = on ? 0 : -1;
    $(t.getAttribute("aria-controls")).hidden = !on;
  }
}
$("btn-add-signature")?.addEventListener("click", () => {
  selectTab($("tab-keys"));
  methodSel.focus();
});
tabs.forEach((t, i) => {
  t.addEventListener("click", () => selectTab(t));
  t.addEventListener("keydown", (e) => {
    const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
    if (!d) return;
    const next = tabs[(i + d + tabs.length) % tabs.length];
    selectTab(next);
    next.focus();
  });
});

// ------------------------------------------------------------------ key generator
let lastKey;
let lastPasskey;
$("kg-generate").addEventListener("click", async () => {
  lastKey = await generateEd25519();
  renderKey();
});
for (const id of ["kg-domain", "kg-selector"]) {
  $(id).addEventListener("input", () => {
    if (lastKey) renderKey();
    if (lastPasskey) renderPasskeyRecord();
  });
}

function dnsRecordName() {
  const domain = $("kg-domain").value.trim().toLowerCase().replace(/\.$/, "") || "example.com";
  const sel = $("kg-selector").value.trim();
  return sel ? `${sel}._mdsig.${domain}` : `_mdsig.${domain}`;
}

function renderKey() {
  const p = toBase64(lastKey.publicKey);
  $("kg-dns").textContent = `${dnsRecordName()}. IN TXT "v=mdsig1; k=ed25519; p=${p}"`;
  $("kg-tofu").textContent = `ed25519:${p}`;
  $("kg-ssh").textContent = formatSshPublicKey(lastKey.publicKey, "mdsig");
  $("kg-priv").textContent = formatOpenSshPrivateKey(lastKey.seed, lastKey.publicKey, "mdsig");
  $("kg-priv").tabIndex = 0;
  $("kg-output").hidden = false;
}
$("kg-download").addEventListener("click", () => lastKey && download("mdsig_ed25519", $("kg-priv").textContent, "text/plain"));

function renderPasskeyRecord() {
  $("pk-dns").textContent = `${dnsRecordName()}. IN TXT "v=mdsig1; k=es256; p=${lastPasskey.publicKey}"`;
  $("pk-tofu").textContent = `es256:${lastPasskey.publicKey}`;
  $("pk-output").hidden = false;
}

function renderPasskeyList() {
  const list = $("pk-list");
  if (!passkeys.length) {
    list.replaceChildren(el("li", { class: "opt" }, t("pk.none")));
  } else {
    list.replaceChildren(
      ...passkeys.map((p, i) =>
        el(
          "li",
          {},
          el("span", {}, p.label || t("pk.default-label", { n: i + 1 })),
          el("span", { class: "opt" }, t(p.rpId === RP_ID ? "pk.rp" : "pk.rp-other", { rp: p.rpId })),
          el("button", { type: "button", class: "ghost small", "data-show": String(i) }, t("pk.show")),
          el("button", { type: "button", class: "ghost small", "data-forget": String(i), "aria-label": t("pk.forget-aria", { label: p.label || t("pk.default-label", { n: i + 1 }) }) }, t("pk.forget")),
        ),
      ),
    );
  }
  renderPasskeyOptions();
}
$("pk-list").addEventListener("click", (e) => {
  const show = e.target.closest("button[data-show]");
  const forget = e.target.closest("button[data-forget]");
  if (show) {
    lastPasskey = passkeys[Number(show.dataset.show)];
    renderPasskeyRecord();
  } else if (forget) {
    passkeys.splice(Number(forget.dataset.forget), 1);
    savePasskeys(passkeys);
    renderPasskeyList();
  }
});

if (!HAS_WEBAUTHN) {
  $("pk-register").disabled = true;
  $("pk-unsupported").hidden = false;
}
$("pk-register").addEventListener("click", async () => {
  const errEl = $("pk-error");
  showError(errEl, null);
  const label = $("pk-name").value.trim() || "md-signature passkey";
  try {
    const { publicKey, credentialId } = await registerPasskey(RP_ID, label);
    lastPasskey = { publicKey: toBase64(publicKey), credentialId: toBase64(credentialId), rpId: RP_ID, label };
    passkeys.push(lastPasskey);
    if (!savePasskeys(passkeys)) showError(errEl, { key: "pk.save-failed" });
    renderPasskeyRecord();
    renderPasskeyList();
  } catch (ex) {
    showError(errEl, ex);
  }
});

document.addEventListener("click", async (e) => {
  const b = e.target.closest("button.copy");
  if (!b || inUserContent(b)) return;
  await navigator.clipboard.writeText($(b.dataset.copy).textContent);
  if (!copyLabels.has(b)) copyLabels.set(b, b.textContent);
  clearTimeout(copyTimers.get(b));
  b.textContent = t("copy.copied");
  copyTimers.set(
    b,
    setTimeout(() => {
      b.textContent = b.dataset.i18n ? t(b.dataset.i18n) : copyLabels.get(b);
      copyLabels.delete(b);
    }, 1200),
  );
});
const copyLabels = new WeakMap();
const copyTimers = new WeakMap();

// ------------------------------------------------------------------ start
renderAttached();
renderPasskeyList();
if (!globalThis.crypto?.subtle) {
  initialSummaryKey = "summary.no-webcrypto";
  renderInitialSummary();
} else {
  initialSummaryKey = "summary.verifying";
  renderInitialSummary();
  const ex = new URLSearchParams(location.search).get("example") ?? "";
  if (EXAMPLES[ex]) loadExample(ex, { updateUrl: false });
  else if (exampleSel) loadExample("basic", { updateUrl: false });
  else scheduleVerify(0);
}
onResourceLoaderChange(() => {
  renderCosignResources();
  scheduleVerify(0);
});

// ------------------------------------------------------------------ language switch
onLangChange((lang) => {
  if (currentExample && exampleLang !== lang && editor.value === exampleText(currentExample, exampleLang)) {
    editor.value = exampleText(currentExample, lang);
    exampleLang = lang;
    scheduleVerify(0);
  }
  renderRpHost();
  renderExampleOptions();
  if (lastResult) {
    const open = [...cards.querySelectorAll(":scope > li > details")].map((d) => d.open);
    render(lastResult);
    cards.querySelectorAll(":scope > li > details").forEach((d, i) => (d.open = !!open[i]));
  } else if (initialSummaryKey) {
    renderInitialSummary();
  }
  renderAttached();
  renderPasskeyList();
  renderPgpInfo();
  for (const [node, entry] of shownErrors) node.textContent = entry.key ? t(entry.key, entry.vars) : entry.raw;
});
