import { readFileSync, existsSync } from "node:fs";
import type { VerifyOptions } from "../src/index.ts";
import { vectorOptions } from "../src/testing.ts";

// --- examples/keys.json stubs, shared by test/examples.test.ts and scripts/gen-examples.ts

export const examplesDir = new URL("../../../examples/", import.meta.url);
export const readExample = (n: string) => readFileSync(new URL(n, examplesDir), "utf8");

export function exampleOptions(): VerifyOptions {
  return vectorOptions(JSON.parse(readExample("keys.json")), (path) => {
    const u = new URL(path.split("/").map(encodeURIComponent).join("/"), examplesDir);
    return existsSync(u) ? new Uint8Array(readFileSync(u)) : null;
  });
}
