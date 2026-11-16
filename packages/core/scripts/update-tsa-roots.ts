import { execFileSync } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { readFileSync, readdirSync, unlinkSync, writeFileSync } from "node:fs";
import { buildTimeStampReq, checkTsaToken, parseTimeStampResp, sha256, toBase64 } from "../src/index.ts";
import { parseDer } from "../src/der.ts";

// Usage: node scripts/update-tsa-roots.ts [--write] [--summary <file>]
// Without --write nothing is changed and the exit code is 1 when the list needs a change or a look.

const CCADB_URL = "https://ccadb.my.salesforce-sites.com/microsoft/IncludedCACertificateReportForMSFTCSV";
const EXPIRY_NOTICE_DAYS = 365;
const MAX_AIA_HOPS = 4;
const MAX_CERT_BYTES = 64 * 1024;

const args = process.argv.slice(2);
const write = args.includes("--write");
const summaryFile = args.includes("--summary") ? args[args.indexOf("--summary") + 1] : undefined;
const dir = new URL("../tsa-roots/", import.meta.url);

const changes: string[] = [];
const attention: string[] = [];
const notes: string[] = [];

// --- CCADB (Microsoft Trusted Root Program)

function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') cell += text[++i];
      else if (c === '"') quoted = false;
      else cell += c;
    } else if (c === '"') quoted = true;
    else if (c === ",") (row.push(cell), (cell = ""));
    else if (c === "\n") (row.push(cell), rows.push(row), (row = []), (cell = ""));
    else if (c !== "\r") cell += c;
  }
  if (cell || row.length) (row.push(cell), rows.push(row));
  return rows;
}

interface Listed {
  status: string;
  ekus: string[];
}

async function ccadb(): Promise<Map<string, Listed>> {
  const res = await fetch(CCADB_URL, { signal: AbortSignal.timeout(60_000) });
  if (!res.ok) throw new Error(`CCADB HTTP ${res.status}`);
  const [header, ...rows] = parseCsv((await res.text()).replace(/^﻿/, ""));
  const col = (name: string) => {
    const i = header!.indexOf(name);
    if (i < 0) throw new Error(`CCADB report has no "${name}" column`);
    return i;
  };
  const [fp, status, ekus] = [col("SHA-256 Fingerprint"), col("Microsoft Status"), col("Microsoft EKUs")];
  const out = new Map<string, Listed>();
  for (const r of rows) if (r[fp]) out.set(r[fp]!.replace(/:/g, "").toLowerCase(), { status: r[status]!, ekus: r[ekus]!.split(";").map((s) => s.trim()) });
  // a truncated or reshaped report must not look like "every root was removed"
  if (out.size < 100) throw new Error(`CCADB report has only ${out.size} rows`);
  return out;
}

const trustedForTimeStamping = (l: Listed | undefined) => l?.status === "Included" && l.ekus.includes("Time Stamping");
const fingerprint = (c: X509Certificate) => c.fingerprint256.replace(/:/g, "").toLowerCase();
const commonName = (c: X509Certificate) => /^CN=(.+)$/m.exec(c.subject)?.[1] ?? /^OU=(.+)$/m.exec(c.subject)?.[1] ?? c.subject;
const toPem = (c: X509Certificate) => `-----BEGIN CERTIFICATE-----\n${c.raw.toString("base64").match(/.{1,64}/g)!.join("\n")}\n-----END CERTIFICATE-----\n`;

// --- bundled roots

function bundled(): { file: string; cert: X509Certificate }[] {
  return readdirSync(dir)
    .filter((f) => f.endsWith(".pem"))
    .sort()
    .map((file) => ({ file, cert: new X509Certificate(readFileSync(new URL(file, dir))) }));
}

function reviewBundled(listed: Map<string, Listed>): void {
  for (const { file, cert } of bundled()) {
    const l = listed.get(fingerprint(cert));
    const name = commonName(cert);
    if (!trustedForTimeStamping(l)) {
      const why = !l ? "is not in the Microsoft root list" : l.status !== "Included" ? `has the status "${l.status}"` : "is no longer listed for Time Stamping";
      changes.push(`Removed **${name}** (\`${file}\`): it ${why}.`);
      if (write) unlinkSync(new URL(file, dir));
      continue;
    }
    const days = Math.floor((Date.parse(cert.validTo) - Date.now()) / 86_400_000);
    if (days < EXPIRY_NOTICE_DAYS) notes.push(`**${name}** expires in ${days} days (${new Date(cert.validTo).toISOString().slice(0, 10)}). Tokens issued before that date keep verifying.`);
  }
}

// --- live services

function tokenCerts(resp: Uint8Array): X509Certificate[] {
  const signedData = parseDer(parseTimeStampResp(resp).token).node.children?.[1]?.children?.[0];
  const set = signedData?.children?.find((n) => n.tag === 0xa0);
  const out: X509Certificate[] = [];
  for (const n of set?.children ?? []) {
    try {
      out.push(new X509Certificate(n.bytes));
    } catch {}
  }
  return out;
}

async function fetchIssuer(c: X509Certificate): Promise<X509Certificate | undefined> {
  const url = /CA Issuers - URI:(\S+)/.exec(c.infoAccess ?? "")?.[1];
  if (!url || !/^https?:\/\//.test(url)) return undefined;
  const res = await fetch(url, { signal: AbortSignal.timeout(20_000) });
  if (!res.ok) return undefined;
  const body = Buffer.from(await res.arrayBuffer());
  if (body.length > MAX_CERT_BYTES) return undefined;
  try {
    return new X509Certificate(body);
  } catch {
    return undefined;
  }
}

// The candidate is only a hint: it is added when its fingerprint is in the CCADB list, wherever its bytes came from.
async function findRoot(certs: X509Certificate[]): Promise<X509Certificate | undefined> {
  const selfIssued = certs.find((c) => c.subject === c.issuer);
  if (selfIssued) return selfIssued;
  let top = certs.find((c) => !certs.some((p) => p.subject === c.issuer));
  for (let hop = 0; top && hop < MAX_AIA_HOPS; hop++) {
    const issuer = await fetchIssuer(top);
    if (!issuer) return undefined;
    if (issuer.subject === issuer.issuer) return issuer;
    top = issuer;
  }
  return undefined;
}

async function probe(svc: { name: string; url: string }, listed: Map<string, Listed>): Promise<void> {
  const data = crypto.getRandomValues(new Uint8Array(32));
  let resp: Uint8Array;
  try {
    const res = await fetch(svc.url, { method: "POST", headers: { "Content-Type": "application/timestamp-query" }, body: buildTimeStampReq(await sha256(data)) as BodyInit, signal: AbortSignal.timeout(30_000) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    resp = new Uint8Array(await res.arrayBuffer());
  } catch (e) {
    notes.push(`${svc.name} (${svc.url}) did not answer: ${(e as Error).message}. Not checked this run.`);
    return;
  }
  const token = "base64:" + toBase64(resp);
  const roots = () => bundled().map((b) => new Uint8Array(b.cert.raw));
  const first = await checkTsaToken(token, data, { roots: roots() });
  if (first.verified) return;

  let root: X509Certificate | undefined;
  try {
    root = await findRoot(tokenCerts(resp));
  } catch {}
  if (!root) {
    attention.push(`${svc.name} (${svc.url}): its token no longer verifies (${first.detail}) and the root could not be located.`);
    return;
  }
  const name = commonName(root);
  if (!trustedForTimeStamping(listed.get(fingerprint(root)))) {
    attention.push(`${svc.name} (${svc.url}): its token chains to **${name}** (\`${fingerprint(root)}\`), which the Microsoft root list does not include for Time Stamping. Not added.`);
    return;
  }
  const withRoot = await checkTsaToken(token, data, { roots: [...roots(), new Uint8Array(root.raw)] });
  if (!withRoot.verified) {
    attention.push(`${svc.name} (${svc.url}): its token does not verify even with **${name}** (${withRoot.detail}).`);
    return;
  }
  const file = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") + ".pem";
  changes.push(`Added **${name}** (\`${file}\`, SHA-256 \`${fingerprint(root)}\`): ${svc.name} now issues tokens under it, and the Microsoft root list includes it for Time Stamping.`);
  if (write) writeFileSync(new URL(file, dir), toPem(root));
}

// --- run

const listed = await ccadb();
reviewBundled(listed);
const services: { name: string; url: string }[] = JSON.parse(readFileSync(new URL("services.json", dir), "utf8"));
for (const s of services) await probe(s, listed);
if (write && changes.length) execFileSync(process.execPath, [new URL("gen-tsa-roots.ts", import.meta.url).pathname], { stdio: "ignore" });

const section = (title: string, items: string[]) => (items.length ? `### ${title}\n\n${items.map((i) => `- ${i}`).join("\n")}\n\n` : "");
const summary =
  `Checked ${bundled().length} bundled TSA roots against the Microsoft root list (CCADB) and ${services.length} live time-stamping services.\n\n` +
  section(write ? "Changes" : "Changes needed", changes) +
  section("Needs a look", attention) +
  section("Notes", notes) +
  (changes.length || attention.length || notes.length ? "" : "Nothing to do.\n");
console.log(summary);
if (summaryFile) writeFileSync(summaryFile, summary);
if (process.env.GITHUB_OUTPUT) writeFileSync(process.env.GITHUB_OUTPUT, `changes=${changes.length}\nattention=${attention.length}\n`, { flag: "a" });
if (!write && (changes.length || attention.length)) process.exit(1);
