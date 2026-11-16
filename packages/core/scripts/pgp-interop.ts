// usage: node scripts/pgp-interop.ts   (needs gpg 2.2+ on PATH; not part of npm test)
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { utf8 } from "../src/encoding.ts";
import { parseCerts, checkCert } from "../src/pgp-keys.ts";
import { readSignaturePacket, verifyRaw } from "../src/pgp-sig.ts";
import { readPgpSecretKey, unlockPgpSecretKey } from "../src/pgp-secret.ts";
import { checkSignaturePacket } from "../src/pgp-verify.ts";

const home = mkdtempSync(join(tmpdir(), "mdsig-gpg-"));
chmodSync(home, 0o700);
writeFileSync(join(home, "gpg-agent.conf"), "allow-loopback-pinentry\n");
// MSYS gpg (Git for Windows) wants /c/... paths; Gpg4win and Unix gpg take native paths
const msys = process.platform === "win32" && /Home: \//.test(execFileSync("gpg", ["--version"]).toString());
const gp = (p: string) => (msys ? p.replace(/^([A-Za-z]):[\\/]/, (_, d: string) => `/${d.toLowerCase()}/`).replace(/\\/g, "/") : p);
const env = { ...process.env, GNUPGHOME: gp(home) };
const gpg = (args: string[], input?: Uint8Array) =>
  execFileSync("gpg", ["--batch", "--pinentry-mode", "loopback", "--passphrase", "test", ...args], { env, input, stdio: ["pipe", "pipe", "pipe"] });

const ids = [
  { email: "frank@example.org", algo: "rsa2048", usage: "sign,cert" },
  { email: "grace@example.org", algo: "ed25519", usage: "cert", sub: "nistp256" },
  { email: "heidi@example.org", algo: "ed25519", usage: "sign,cert" },
  { email: "ivan@example.org", algo: "rsa3072", usage: "cert", sub: "ed25519" },
];
const now = Math.floor(Date.now() / 1000);
let failed = 0;
const report = (ok: boolean, what: string) => {
  console.log(`${ok ? "ok  " : "FAIL"} ${what}`);
  if (!ok) failed++;
};

try {
  for (const id of ids) {
    gpg(["--quick-gen-key", `${id.email.split("@")[0]} <${id.email}>`, id.algo, id.usage, "never"]);
    if (id.sub) {
      const fpr = /^fpr:+([0-9A-F]+):/m.exec(gpg(["--list-keys", "--with-colons", id.email]).toString())![1]!;
      gpg(["--quick-add-key", fpr, id.sub, "sign", "never"]);
    }
    const payload = utf8(`md-signature/v1\nalg=openpgp\nsigner=${id.email}\n`);
    const pub = new Uint8Array(gpg(["--export", id.email]));
    const sec = gpg(["--armor", "--export-secret-keys", id.email]).toString();

    // gpg signs, md-signature verifies
    const sig = new Uint8Array(gpg(["--detach-sign", "--digest-algo", "SHA256", "-u", id.email], payload));
    const parsed = readSignaturePacket(sig);
    const issuer = Array.from(parsed.hashed.find((s) => s.type === 33)!.data.subarray(1), (b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
    report(checkSignaturePacket(sig, issuer).ok, `${id.email} (${id.algo}${id.sub ? "+" + id.sub : ""}): gpg signature passes SPEC 6.2 checks`);
    // gpg --export <subkey fpr> returns the whole certificate
    const viaSub = new Uint8Array(gpg(["--export", issuer]));
    const [cert] = await parseCerts(viaSub);
    const chk = await checkCert(cert!, issuer, id.email, now);
    report(chk.ok, `${id.email}: certificate exported by signing-key fpr validates ${chk.ok ? "" : `(${chk.message})`}`);
    if (chk.ok) report(await verifyRaw(chk.key, parsed, payload), `${id.email}: gpg signature verifies in md-signature`);
    report((await parseCerts(pub)).length === 1, `${id.email}: public export parses`);

    // md-signature signs with the exported (passphrase-protected) key, gpg verifies
    const info = await readPgpSecretKey(sec, now);
    report(info.fpr === issuer && info.protected, `${id.email}: secret key selects the same signing key, protected=${info.protected}`);
    const signer = await unlockPgpSecretKey(info, "test");
    const mine = await signer.sign(payload);
    signer.dispose();
    const dir = mkdtempSync(join(home, "v-"));
    writeFileSync(join(dir, "p"), payload);
    writeFileSync(join(dir, "p.sig"), mine);
    let ok = true;
    try {
      gpg(["--verify", gp(join(dir, "p.sig")), gp(join(dir, "p"))]);
    } catch (e) {
      ok = false;
      console.error(String((e as { stderr?: Buffer }).stderr ?? e));
    }
    report(ok, `${id.email}: md-signature signature verifies in gpg`);
    await unlockPgpSecretKey(info, "wrong").then(
      () => report(false, `${id.email}: wrong passphrase rejected`),
      (e) => report(/wrong passphrase/.test((e as Error).message), `${id.email}: wrong passphrase rejected`),
    );
  }
} finally {
  try {
    execFileSync("gpgconf", ["--kill", "gpg-agent"], { env });
  } catch {}
  rmSync(home, { recursive: true, force: true });
}
console.log(failed ? `${failed} check(s) failed` : "all interop checks passed");
process.exit(failed ? 1 : 0);
