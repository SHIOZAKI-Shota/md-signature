import { parseSshPublicKeys } from "./crypto.ts";
import { fromBase64 } from "./encoding.ts";
import { decodePublicKey, parseDnsRecord, ResolutionError, type Resolver } from "./resolvers.ts";
import type { VerifyOptions } from "./verify.ts";

// --- test vectors (examples/keys.json)

export const TEST_DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query";

export interface VectorKeys {
  now: string;
  "git-hosting"?: Record<string, { keys_file: string }>;
  dns?: Record<string, { txt: string }>;
  dns_records?: Record<string, string[] | "SERVFAIL">;
  fetch?: Record<string, string>;
}

export type VectorFileReader = (path: string) => Uint8Array | null | Promise<Uint8Array | null>;

export function vectorOptions(keys: VectorKeys, readFile: VectorFileReader): VerifyOptions {
  const resolvers: Record<string, Resolver> = {
    "git-hosting": async (f) => {
      const e = keys["git-hosting"]?.[f.signer!];
      if (!e) throw new ResolutionError(`no keys for ${f.signer}`, "not-found");
      return { keys: parseSshPublicKeys(e.keys_file).map((k) => ({ alg: "ed25519", key: k.key!, source: "keys.json" })), warnings: [] };
    },
    dns: async (f) => {
      const name = f.selector ? `${f.selector}._mdsig.${f.signer}` : `_mdsig.${f.signer}`;
      const e = keys.dns?.[name];
      if (!e) throw new ResolutionError(`no TXT record at ${name}`, "not-found");
      const rec = parseDnsRecord(e.txt)!;
      return { keys: [{ alg: rec.k, key: decodePublicKey(rec.k, fromBase64(rec.p)), source: "keys.json" }], warnings: [] };
    },
  };
  const doh = `${TEST_DOH_ENDPOINT}?`;
  const fetch = (async (input: RequestInfo | URL) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url.startsWith(doh)) {
      const records = keys.dns_records?.[new URLSearchParams(url.slice(doh.length)).get("name")!];
      if (records === "SERVFAIL") return Response.json({ Status: 2 });
      return Response.json(records ? { Status: 0, Answer: records.map((r) => ({ type: 16, data: JSON.stringify(r) })) } : { Status: 3 });
    }
    const file = keys.fetch?.[url];
    if (!file) throw new TypeError(`network disabled in tests: ${url}`);
    if (file === "404") return new Response("", { status: 404 });
    const body = await readFile(file);
    if (!body) throw new TypeError(`missing test file ${file}`);
    return new Response(body as Uint8Array<ArrayBuffer>);
  }) as typeof globalThis.fetch;
  return { resolvers, fetch, dohEndpoints: [TEST_DOH_ENDPOINT], loadResource: async (path: string) => readFile(path), now: new Date(keys.now) };
}
