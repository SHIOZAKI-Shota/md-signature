import { toBase64 } from "./encoding.ts";
import { tsaFromJson, toJsonResult, type JsonResult, type JsonTsa } from "./json.ts";
import type { TsaCheck } from "./tsa.ts";
import type { HashAlg } from "./crypto.ts";
import type { VerifyResult } from "./verify.ts";

// --- client for the HTTP API (CLI_SPEC 3.6) served by `mdsig serve` and createVerifyHandler

export interface RemoteOptions {
  fetch?: typeof fetch;
  signal?: AbortSignal;
}

const endpoint = (base: string, path: string) => base.replace(/\/+$/, "") + path;

async function post<T>(url: string, body: unknown, o: RemoteOptions): Promise<T> {
  const res = await (o.fetch ?? globalThis.fetch)(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body), signal: o.signal });
  const text = await res.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error(`verification server answered HTTP ${res.status} without JSON`);
  }
  if (!res.ok) throw new Error(`verification server: ${(json as { error?: string })?.error ?? `HTTP ${res.status}`}`);
  return json as T;
}

export function remoteVerify(baseUrl: string, document: string, o: RemoteOptions = {}): Promise<JsonResult> {
  return post<JsonResult>(endpoint(baseUrl, "/v1/verify"), { document }, o);
}

// for VerifyOptions.tsaVerifier: the server's trust store decides, this side reports its verdict
// the token's imprint is H(data), H = opts.hash (sha256 when absent); the server receives data as "sig" and the hash as "hash"
export function remoteTsaVerifier(baseUrl: string, o: RemoteOptions = {}): (tsaToken: string, data: Uint8Array, opts?: { hash?: HashAlg }) => Promise<TsaCheck> {
  return async (tsaToken, data, opts = {}) => {
    try {
      const body = { token: tsaToken, sig: toBase64(data), ...(opts.hash && opts.hash !== "sha256" ? { hash: opts.hash } : {}) };
      return tsaFromJson(await post<JsonTsa>(endpoint(baseUrl, "/v1/tsa"), body, o));
    } catch (e) {
      return { status: "error", verified: false, detail: (e as Error).message };
    }
  };
}

// --- comparing two verifications of the same document

export interface BlockComparison {
  index: number;
  local: { status: string; code: string | null; tsaVerified: boolean | null; tsaSigner: string | null } | null;
  remote: { status: string; code: string | null; tsaVerified: boolean | null; tsaSigner: string | null } | null;
  // same status and code
  agree: boolean;
  // same answer to "is the timestamp verified"; true when neither side has a token
  tsaAgree: boolean;
}

export interface Comparison {
  // every block agrees on status and code, both sides saw the same number of blocks, and the agreement status matches
  agree: boolean;
  agreementAgree: boolean;
  tsaAgree: boolean;
  blocks: BlockComparison[];
}

export function compareResults(local: VerifyResult | JsonResult, remote: JsonResult): Comparison {
  // only the JSON shape has a null error or snake_case block fields
  const isJson = (r: VerifyResult | JsonResult): r is JsonResult => r.error === null || r.signatures.some((s) => "hash_ok" in s);
  const l = isJson(local) ? local : toJsonResult(local);
  const side = (r: JsonResult, i: number) => {
    const s = r.signatures.find((x) => x.index === i);
    return s ? { status: s.status, code: s.code, tsaVerified: s.tsa ? s.tsa.verified === true : null, tsaSigner: s.tsa?.signer ?? null } : null;
  };
  const indexes = [...new Set([...l.signatures, ...remote.signatures].map((s) => s.index))].sort((a, b) => a - b);
  const blocks = indexes.map((index) => {
    const a = side(l, index);
    const b = side(remote, index);
    return { index, local: a, remote: b, agree: !!a && !!b && a.status === b.status && a.code === b.code, tsaAgree: !!a && !!b && a.tsaVerified === b.tsaVerified };
  });
  const agreementAgree = l.agreement.status === remote.agreement.status;
  return { agree: blocks.every((b) => b.agree) && (l.error ?? null) === (remote.error ?? null) && agreementAgree, agreementAgree, tsaAgree: blocks.every((b) => b.tsaAgree), blocks };
}
