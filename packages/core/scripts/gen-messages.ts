import { readFileSync, writeFileSync } from "node:fs";
import { renderMessagesModule } from "./messages-module.ts";

const json = readFileSync(new URL("../../../mdsig/messages_ja.json", import.meta.url), "utf8");
writeFileSync(new URL("../src/messages-ja.ts", import.meta.url), renderMessagesModule(json));
console.log(`${JSON.parse(json).length} messages`);
