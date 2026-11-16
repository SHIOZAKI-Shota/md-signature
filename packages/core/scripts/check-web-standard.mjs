import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const dir = new URL("../src/", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
const banned = [/from\s+["']node:/, /require\(/, /\bBuffer\b/, /\bprocess\./, /from\s+["'](fs|path|crypto|dns|zlib|os|child_process)["']/];
let bad = 0;
for (const f of readdirSync(dir)) {
  const src = readFileSync(join(dir, f), "utf8");
  src.split("\n").forEach((line, i) => {
    for (const re of banned) {
      if (re.test(line)) {
        console.error(`${f}:${i + 1}: non-web-standard API: ${line.trim()}`);
        bad++;
      }
    }
  });
}
if (bad) process.exit(1);
console.log("core uses web-standard APIs only");
