import { cpSync, rmSync } from "node:fs";

const from = new URL("../../../examples/", import.meta.url);
const to = new URL("../examples/", import.meta.url);
rmSync(to, { recursive: true, force: true });
cpSync(from, to, { recursive: true });
