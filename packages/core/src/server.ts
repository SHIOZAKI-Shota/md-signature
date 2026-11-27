import { fromBase64 } from "./encoding.ts";
import { toJsonResult, tsaToJson } from "./json.ts";
import { MemoryTofuStore } from "./resolvers.ts";
import { checkTsaToken } from "./tsa.ts";
import { verifyDocument, type VerifyOptions } from "./verify.ts";
import { unfoldBinary } from "./canonical.ts";

// --- HTTP API (CLI_SPEC 3.6): the same endpoints as `mdsig serve`, for any runtime with Request / Response

export const API_VERSION = "v1";
const DEFAULT_MAX_BODY_BYTES = 4 * 1024 * 1024;
const DEFAULT_MAX_CONCURRENT = 8;
const MAX_SIG_BYTES = 64 * 1024;
const MAX_REDIRECTS = 5;

export interface VerifyHandlerOptions {
  version?: string;
  // web origins that may call the API from a browser; a request with any other Origin is refused
  allowOrigins?: string[];
  // passed to verifyDocument; tofuStore, loadResource and pgpKeyring are never taken from here
  verify?: Omit<VerifyOptions, "tofuStore" | "loadResource" | "pgpKeyring">;
  maxBodyBytes?: number;
  maxConcurrent?: number;
  // SSRF: by default outbound requests to IP literals, localhost and internal names are refused
  allowPrivateHosts?: boolean;
}

function privateHost(host: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  if (h.startsWith("[") || /^[0-9.]+$/.test(h) || /^0x/i.test(h)) return true;
  if (!h.includes(".")) return true;
  return /(^|\.)(localhost|local|internal|intranet|lan|home|corp|test|invalid|example|onion|arpa)$/.test(h);
}

// A name that resolves to a private address is not caught here: Web APIs cannot see the address.
// Deployments that can reach an internal network must also restrict egress at the network level.
export function publicHostFetch(f: typeof fetch = globalThis.fetch): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    let url = new URL(typeof input === "string" || input instanceof URL ? String(input) : input.url);
    let opts: RequestInit = { ...init, redirect: "manual" };
    for (let hop = 0; ; hop++) {
      if (url.protocol !== "https:" && url.protocol !== "http:") throw new TypeError(`refused ${url.protocol} URL`);
      if (privateHost(url.hostname)) throw new TypeError(`refused request to ${url.hostname}`);
      const res = await f(url, opts);
      const location = res.status >= 300 && res.status < 400 ? res.headers.get("location") : null;
      if (!location) return res;
      if (hop >= MAX_REDIRECTS) throw new TypeError("too many redirects");
      url = new URL(location, url);
      if (res.status === 303 || ((res.status === 301 || res.status === 302) && opts.method === "POST")) opts = { ...opts, method: "GET", body: undefined };
    }
  }) as typeof fetch;
}

async function readBody(req: Request, max: number): Promise<Uint8Array | null> {
  if (Number(req.headers.get("content-length") ?? "0") > max) return null;
  if (!req.body) return new Uint8Array(await req.arrayBuffer());
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > max) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) {
    out.set(c, o);
    o += c.length;
  }
  return out;
}

export function createVerifyHandler(o: VerifyHandlerOptions = {}): (req: Request) => Promise<Response> {
  const maxBody = o.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  const maxConcurrent = o.maxConcurrent ?? DEFAULT_MAX_CONCURRENT;
  const outbound = o.allowPrivateHosts ? (o.verify?.fetch ?? globalThis.fetch) : publicHostFetch(o.verify?.fetch);
  let running = 0;

  return async (req: Request): Promise<Response> => {
    const headers = new Headers({ "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff", vary: "Origin" });
    const reply = (status: number, body: unknown) => new Response(status === 204 ? null : JSON.stringify(body), { status, headers });
    const fail = (status: number, error: string) => reply(status, { error });

    // a page on another origin must not drive this server, even when it cannot read the answer
    const origin = req.headers.get("origin");
    if (origin !== null) {
      if (!(o.allowOrigins ?? []).includes(origin)) return fail(403, "origin not allowed");
      headers.set("access-control-allow-origin", origin);
    }
    if (req.method === "OPTIONS") {
      headers.set("access-control-allow-methods", "GET, POST");
      headers.set("access-control-allow-headers", "Content-Type");
      headers.set("access-control-max-age", "600");
      return reply(204, null);
    }
    const path = new URL(req.url).pathname;
    if (path === `/${API_VERSION}/health`) {
      if (req.method !== "GET") return fail(405, "use GET");
      return reply(200, { name: "@mdsig/core", version: o.version ?? "", api: API_VERSION });
    }
    if (path !== `/${API_VERSION}/verify` && path !== `/${API_VERSION}/tsa`) return fail(404, "not found");
    if (req.method !== "POST") return fail(405, "use POST");
    // application/json is not a "simple" content type, so a browser must pass the CORS preflight first
    if ((req.headers.get("content-type") ?? "").split(";")[0]!.trim().toLowerCase() !== "application/json") return fail(415, "Content-Type must be application/json");
    const raw = await readBody(req, maxBody);
    if (!raw) return fail(413, "request body is too large");
    if (running >= maxConcurrent) {
      headers.set("retry-after", "1");
      return fail(503, "busy");
    }
    running++;
    try {
      let body: Record<string, unknown>;
      try {
        body = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
      } catch {
        body = {};
      }
      if (path === `/${API_VERSION}/verify`) {
        if (typeof body?.document !== "string") return fail(400, 'body must be {"document": "<text>"}');
        // no key store, local files or keyring: a request must not read or change state on this machine
        const r = await verifyDocument(body.document, { ...o.verify, fetch: outbound, tofuStore: new MemoryTofuStore(), loadResource: undefined, pgpKeyring: undefined });
        return reply(200, toJsonResult(r));
      }
      if (typeof body?.token !== "string" || typeof body?.sig !== "string") return fail(400, 'body must be {"token": "<value>", "sig": "<base64>"}');
      let sig: Uint8Array;
      try {
        sig = fromBase64(body.sig);
      } catch {
        sig = new Uint8Array();
      }
      if (!sig.length || sig.length > MAX_SIG_BYTES) return fail(400, "sig must be the base64 of the signature bytes");
      const hash = body.hash ?? "sha256";
      if (hash !== "sha256" && hash !== "sha512") return fail(400, 'hash must be "sha256" or "sha512"');
      return reply(200, tsaToJson(await checkTsaToken(unfoldBinary(body.token), sig, { roots: o.verify?.tsaRoots, extraRoots: o.verify?.extraTsaRoots, hash })));
    } finally {
      running--;
    }
  };
}
