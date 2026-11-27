import { readFileSync, existsSync } from "node:fs";
import { parseSshPublicKeys, parseDnsRecord, fromBase64, decodePublicKey, ResolutionError, type Resolver, type VerifyOptions } from "../src/index.ts";

// --- examples/keys.json stubs, shared by test/examples.test.ts and scripts/gen-examples.ts

export const examplesDir = new URL("../../../examples/", import.meta.url);
export const readExample = (n: string) => readFileSync(new URL(n, examplesDir), "utf8");

export function exampleOptions(): VerifyOptions {
  const keys = JSON.parse(readExample("keys.json"));
  const resolvers: Record<string, Resolver> = {
    "git-hosting": async (f) => {
      const e = keys["git-hosting"][f.signer!];
      if (!e) throw new ResolutionError(`no keys for ${f.signer}`, "not-found");
      return { keys: parseSshPublicKeys(e.keys_file).map((k) => ({ alg: "ed25519", key: k.key!, source: "keys.json" })), warnings: [] };
    },
    dns: async (f) => {
      const name = f.selector ? `${f.selector}._mdsig.${f.signer}` : `_mdsig.${f.signer}`;
      const e = keys.dns[name];
      if (!e) throw new ResolutionError(`no TXT record at ${name}`, "not-found");
      const rec = parseDnsRecord(e.txt)!;
      return { keys: [{ alg: rec.k, key: decodePublicKey(rec.k, fromBase64(rec.p)), source: "keys.json" }], warnings: [] };
    },
  };
  const DOH = "https://cloudflare-dns.com/dns-query?";
  const fetch = (async (url: string) => {
    if (url.startsWith(DOH)) {
      const records: string[] | "SERVFAIL" | undefined = keys.dns_records?.[new URLSearchParams(url.slice(DOH.length)).get("name")!];
      if (records === "SERVFAIL") return Response.json({ Status: 2 });
      return Response.json(records ? { Status: 0, Answer: records.map((r) => ({ type: 16, data: JSON.stringify(r) })) } : { Status: 3 });
    }
    const file = keys.fetch?.[url];
    if (!file) throw new TypeError(`network disabled in tests: ${url}`);
    if (file === "404") return new Response("", { status: 404 });
    return new Response(readFileSync(new URL(file, examplesDir)));
  }) as typeof globalThis.fetch;
  const loadResource = async (path: string) => {
    const u = new URL(path.split("/").map(encodeURIComponent).join("/"), examplesDir);
    return existsSync(u) ? new Uint8Array(readFileSync(u)) : null;
  };
  return { resolvers, fetch, dohEndpoints: ["https://cloudflare-dns.com/dns-query"], loadResource, now: new Date(keys.now) };
}
