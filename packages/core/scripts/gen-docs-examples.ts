import { readFileSync, writeFileSync } from "node:fs";
import { signDocument, signerFromSeed, sha256, utf8, fromHex, createSoftwareAuthenticator, type PgpSigner } from "../src/index.ts";
import { SIG, createSignature, signaturePacket } from "../src/pgp-sig.ts";
import { ed25519Key } from "./pgp-build.ts";

const root = new URL("../../../", import.meta.url);
const read = (p: string) => readFileSync(new URL(p, root), "utf8");
const keys = JSON.parse(read("examples/keys.json"));
const NL = "\n";
const TS1 = "2026-11-16T09:00:00Z";
const TS2 = "2026-11-16T09:46:00Z";

type Lang = "ja" | "en";
type Text = Record<Lang, string>;
interface Example {
  title: Text;
  text: Text;
  testKeys?: true;
  files?: Record<string, string>;
}

// Deterministic demo identities; the RFC 8032 seeds stay reserved for the test-key example.
const demoSigner = async (name: string) => signerFromSeed(await sha256(utf8(`md-signature docs example: ${name}`)));
const lines = (...l: string[]) => l.join(NL) + NL;

// ------------------------------------------------------------------ basic
async function basic(): Promise<Example> {
  const author = await demoSigner("author");
  const approver = await demoSigner("approver");
  const body: Text = {
    ja: lines(
      "# 基本：2名による連署",
      "",
      "この文書の末尾には署名ブロックが2つあります。第1署名は作成者、第2署名は承認者によるもので、どちらも tofu 方式（公開鍵を署名ブロックに埋め込む方式）です。",
      "",
      "署名ブロックは HTML コメントのため、Markdown として表示しても画面には現れません。",
      "",
      "## 費用",
      "",
      "| 区分 | 金額 |",
      "| --- | --- |",
      "| 設計 | 400,000 円 |",
      "| 実装 | 600,000 円 |",
      "",
      "## 試してみる",
      "",
      "- 表の **600,000** を別の金額に変更してください。第2署名は第1署名を含む文書全体を対象にしているため、2つの署名がともに無効になります。",
      "- 元に戻すと、検証結果も有効に戻ります。",
      "- 第2署名の `reason` の値を変更すると、ハッシュは一致したまま、第2署名の検証だけが失敗します。メタデータも署名対象に含まれるためです。",
    ),
    en: lines(
      "# Basics: two signatures",
      "",
      "Two signature blocks sit at the end of this document. The author signed first and the approver second, both with the tofu method (the public key is embedded in the block).",
      "",
      "The blocks are HTML comments, so a Markdown viewer does not show them.",
      "",
      "## Fees",
      "",
      "| Item | Amount |",
      "| --- | --- |",
      "| Design | 4,000 USD |",
      "| Build | 6,000 USD |",
      "",
      "## Try it",
      "",
      "- Change **6,000** in the table. Signature #2 covers the whole document including signature #1, so both signatures fail.",
      "- Undo the change and both turn valid again.",
      "- Edit the `reason` of signature #2. The hash still matches, but the signature check fails, because the metadata is signed too.",
    ),
  };
  const reasons = { ja: ["初版を作成", "内容を承認"], en: ["Initial draft", "Approved"] };
  const ids = { ja: ["sato@sample-studio.example", "suzuki@example-corp.example"], en: ["alice@sample-studio.example", "bob@example-corp.example"] };
  const text = {} as Text;
  for (const l of ["ja", "en"] as const) {
    const s1 = await signDocument(body[l], { signer: author, method: "tofu", signerId: ids[l][0]!, role: "author", reason: reasons[l][0], ts: TS1 });
    const s2 = await signDocument(s1.text, { signer: approver, method: "tofu", signerId: ids[l][1]!, role: "approver", reason: reasons[l][1], ts: TS2 });
    text[l] = s2.text;
  }
  return { title: { ja: "基本：2名による連署", en: "Basics: two signatures" }, text };
}

// ------------------------------------------------------------------ scoped
async function scoped(): Promise<Example> {
  const signer = await demoSigner("section signer");
  const body: Text = {
    ja: lines(
      "# セクション署名",
      "",
      "署名の対象を文書の一部に限定できます。対象範囲を `<!-- mdsig:section id -->` と `<!-- /mdsig:section -->` で囲み、署名ブロックの `scope` に列挙します。この例の署名は `terms` と `fees` の2つのセクションだけを対象にしています。",
      "",
      "<!-- mdsig:section terms -->",
      "## 契約条件",
      "",
      "各工程の完了後 30 日以内に支払います。",
      "<!-- /mdsig:section -->",
      "",
      "## 進捗メモ（署名対象外）",
      "",
      "キックオフ済み。次回の設計レビューは 11 月 20 日。",
      "",
      "<!-- mdsig:section fees -->",
      "## 費用",
      "",
      "| 工程 | 金額 |",
      "| --- | --- |",
      "| 公開 | 600,000 円 |",
      "<!-- /mdsig:section -->",
      "",
      "## 試してみる",
      "",
      "- 「進捗メモ」の文章を自由に変更してください。署名は「有効・部分」のまま変わりません。",
      "- 費用の **600,000** を変更すると、`fees` セクションのハッシュが一致しなくなり、署名は無効になります。",
      "- `terms` の目印（開始と終了のコメント）を2行とも削除すると、対象セクションの欠落として失敗します。",
    ),
    en: lines(
      "# Section signing",
      "",
      "A signature can cover only part of a document. Wrap each part in `<!-- mdsig:section id -->` and `<!-- /mdsig:section -->`, and list the ids in the block's `scope`. The signature here covers the `terms` and `fees` sections and nothing else.",
      "",
      "<!-- mdsig:section terms -->",
      "## Terms",
      "",
      "Payment within 30 days of each milestone.",
      "<!-- /mdsig:section -->",
      "",
      "## Progress notes (not signed)",
      "",
      "Kick-off done. Design review on November 20.",
      "",
      "<!-- mdsig:section fees -->",
      "## Fees",
      "",
      "| Milestone | Amount |",
      "| --- | --- |",
      "| Launch | 6,000 USD |",
      "<!-- /mdsig:section -->",
      "",
      "## Try it",
      "",
      "- Edit the progress notes as you like. The signature stays \"valid · partial\".",
      "- Change **6,000** in the fees table: the `fees` hash no longer matches and the signature fails.",
      "- Delete both marker lines of `terms`: the signature fails because a signed section is missing.",
    ),
  };
  const reasons = { ja: "契約条件と費用を確認", en: "Terms and fees reviewed" };
  const ids = { ja: "sato@sample-studio.example", en: "alice@sample-studio.example" };
  const text = {} as Text;
  for (const l of ["ja", "en"] as const) {
    text[l] = (await signDocument(body[l], { signer, method: "tofu", signerId: ids[l], role: "author", reason: reasons[l], ts: TS1, scope: ["terms", "fees"] })).text;
  }
  return { title: { ja: "セクション署名", en: "Section signing" }, text };
}

// ------------------------------------------------------------------ pending
async function pending(): Promise<Example> {
  const alice = await signerFromSeed(fromHex(keys["git-hosting"]["github.com/alice"].seed_hex));
  const body: Text = {
    ja: lines(
      "# 承認待ち（require）",
      "",
      "作成者 `github.com/alice` は署名時に `require: dns:example.com approver` を指定しました。`example.com` が `approver` として連署するまで、署名自体は有効でも、合意は「未完了」と表示されます。",
      "",
      "| 項目 | 金額 |",
      "| --- | --- |",
      "| 初期費用 | 100,000 円 |",
      "| 月額 | 20,000 円 |",
      "",
      "## 試してみる",
      "",
      "- 右側の「署名の作成・追加」で tofu の連署を追加してください。`example.com` 以外の署名者では、合意は未完了のままです。",
      "- コマンドライン（`mdsig verify`）では、未完了の合意は終了コード 5 で報告されます。",
      "",
      "この例の鍵は RFC 8032 の公開テスト鍵（`examples/keys.json`）です。鍵はページ内で解決しており、実在の GitHub アカウントや DNS とは無関係です。",
    ),
    en: lines(
      "# Pending approval (require)",
      "",
      "When `github.com/alice` signed, she added `require: dns:example.com approver`. Her signature is valid, but the agreement stays pending until `example.com` co-signs as `approver`.",
      "",
      "| Item | Fee |",
      "| --- | --- |",
      "| Setup | 1,000 USD |",
      "| Monthly | 200 USD |",
      "",
      "## Try it",
      "",
      "- Add a tofu co-signature under \"Create & add signatures\" on the right. Any signer other than `example.com` leaves the agreement pending.",
      "- On the command line, `mdsig verify` reports a pending agreement with exit code 5.",
      "",
      "The keys here are the public RFC 8032 test keys from `examples/keys.json`. The page resolves them locally; they have nothing to do with a real GitHub account or DNS record.",
    ),
  };
  const text = {} as Text;
  for (const l of ["ja", "en"] as const) {
    text[l] = (
      await signDocument(body[l], {
        signer: alice,
        method: "git-hosting",
        signerId: "github.com/alice",
        role: "author",
        reason: l === "ja" ? "example.com の承認を要求" : "Needs approval from example.com",
        ts: TS1,
        require: ["dns:example.com approver"],
      })
    ).text;
  }
  return { title: { ja: "承認待ち（require）", en: "Pending approval (require)" }, text, testKeys: true };
}

// ------------------------------------------------------------------ flow (steps and thresholds)
async function flow(): Promise<Example> {
  const alice = await signerFromSeed(fromHex(keys["git-hosting"]["github.com/alice"].seed_hex));
  const ex = await signerFromSeed(fromHex(keys.dns["2026._mdsig.example.com"].seed_hex));
  const body: Text = {
    ja: lines(
      "# 承認フロー（step と any）",
      "",
      "作成者 `github.com/alice` は、次の順番を `require` に指定しました。",
      "",
      "1. `example.com` が `approver` として承認する",
      "2. その後に `bob@laptop`、`carol@laptop`、`dave@laptop` のうち 2 人が署名する",
      "",
      "`example.com` は承認済みなので段階 1 は成立しています。合意は、段階 2 の 2 人がそろうまで「未完了」です。",
      "",
      "## 試してみる",
      "",
      "- 右側の「署名の作成・追加」で、tofu の署名者を `carol@laptop` などにして連署してください。2 人目で合意が成立します。",
      "- 同じ人が 2 回署名しても 1 人として数えます。",
      "- `order strict` にすると、順番を守らない署名で合意が「順序違反」になります（既定の `pending` では数えないだけです）。",
      "",
      "この例の鍵は RFC 8032 の公開テスト鍵（`examples/keys.json`）です。鍵はページ内で解決しており、実在の GitHub アカウントや DNS とは無関係です。",
    ),
    en: lines(
      "# Approval flow (step and any)",
      "",
      "When `github.com/alice` signed, she put this order into `require`:",
      "",
      "1. `example.com` approves as `approver`",
      "2. then two of `bob@laptop`, `carol@laptop` and `dave@laptop` sign",
      "",
      "`example.com` has approved, so step 1 is complete. The agreement stays pending until two people have signed in step 2.",
      "",
      "## Try it",
      "",
      "- Under \"Create & add signatures\" on the right, co-sign as a tofu signer such as `carol@laptop`. The second one completes the agreement.",
      "- The same person signing twice still counts once.",
      "- With `order strict`, a signature made before its turn makes the agreement \"violated\" (the default `pending` just does not count it).",
      "",
      "The keys here are the public RFC 8032 test keys from `examples/keys.json`. The page resolves them locally; they have nothing to do with a real GitHub account or DNS record.",
    ),
  };
  const text = {} as Text;
  for (const l of ["ja", "en"] as const) {
    const declared = await signDocument(body[l], {
      signer: alice,
      method: "git-hosting",
      signerId: "github.com/alice",
      role: "author",
      reason: l === "ja" ? "承認と 2 人のレビューを要求" : "Needs an approval and two reviews",
      ts: TS1,
      require: ["step 1", "dns:example.com approver", "step 2 any 2", "tofu:bob@laptop", "tofu:carol@laptop", "tofu:dave@laptop"],
    });
    text[l] = (await signDocument(declared.text, { signer: ex, method: "dns", signerId: "example.com", selector: "2026", role: "approver", ts: TS2 })).text;
  }
  return { title: { ja: "承認フロー（step と any）", en: "Approval flow (step and any)" }, text, testKeys: true };
}

// ------------------------------------------------------------------ passkey
async function passkey(): Promise<Example> {
  const body: Text = {
    ja: lines(
      "# パスキー署名",
      "",
      "この文書の署名はパスキー（WebAuthn）で作成したものです。`alg` は `webauthn-es256` で、署名ブロックには認証器が返した `authenticator_data` と `client_data` も記録されます。`rp_id` は `mdsig.dev` です。",
      "",
      "この例は、動作確認用のソフトウェア認証器で署名しています。",
      "",
      "## 試してみる",
      "",
      "- 署名ブロックの `role` を変更すると、検証に失敗します。`rp_id` を含むすべてのフィールドが署名対象です。",
      "- 自身のパスキーで連署するには、「署名の作成・追加」タブでパスキーを登録し、方式に「tofu：パスキーで署名」を選択します。パスキーは表示中のサイトのドメインに結び付きます。",
    ),
    en: lines(
      "# Passkey signature",
      "",
      "This document was signed with a passkey (WebAuthn). The `alg` is `webauthn-es256`, and the block also records the `authenticator_data` and `client_data` returned by the authenticator. The `rp_id` is `mdsig.dev`.",
      "",
      "The signature here comes from a software authenticator used for testing.",
      "",
      "## Try it",
      "",
      "- Change the `role` in the signature block and verification fails. Every field, `rp_id` included, is signed.",
      "- To co-sign with your own passkey, register one in the \"Create & add signatures\" tab and choose \"tofu: sign with a passkey\". A passkey is tied to the domain of the site you are on.",
    ),
  };
  const ids = { ja: "tanaka@passkey.example", en: "carol@passkey.example" };
  const reasons = { ja: "パスキーで承認", en: "Approved with a passkey" };
  const text = {} as Text;
  for (const l of ["ja", "en"] as const) {
    const signer = await createSoftwareAuthenticator("mdsig.dev");
    text[l] = (await signDocument(body[l], { signer, method: "tofu", signerId: ids[l], role: "approver", reason: reasons[l], ts: TS1 })).text;
  }
  return { title: { ja: "パスキー署名", en: "Passkey signature" }, text };
}

// ------------------------------------------------------------------ resources
async function resources(): Promise<Example> {
  const signer = await demoSigner("resource signer");
  const diagram = new Uint8Array(readFileSync(new URL("examples/assets/diagram.svg", root)));
  const REMOTE = "https://example.com/chart.png";
  const body: Text = {
    ja: lines(
      "# 外部ファイルの固定（resources）",
      "",
      "署名ブロックの `resources` には、画像などのファイルの SHA-256 を記録できます。署名後にファイルが差し替えられると、検証で検出されます。",
      "",
      "![構成図](./assets/diagram.svg)",
      "",
      `![リモートのグラフ](${REMOTE})`,
      "",
      "## 試してみる",
      "",
      "- `./assets/diagram.svg` はこの例に添付済みのため「一致」と表示されます。「リソース」の一覧から削除すると「未確認」に変わります。",
      "- 別のファイルを `diagram.svg` という名前で添付すると「不一致」になり、署名は無効になります。",
      `- \`${REMOTE}\` は、リモートリソースの取得を有効にしない限り「未確認」のままです。取得すると配信元に検証の事実が伝わるため、既定では取得しません。`,
    ),
    en: lines(
      "# Bound files (resources)",
      "",
      "A signature block can record the SHA-256 of images and other files in `resources`. If a file is swapped after signing, verification catches it.",
      "",
      "![Diagram](./assets/diagram.svg)",
      "",
      `![Remote chart](${REMOTE})`,
      "",
      "## Try it",
      "",
      "- `./assets/diagram.svg` is attached to this example, so it shows \"ok\". Remove it from the Resources list and it turns \"not checked\".",
      "- Attach a different file named `diagram.svg` and it shows \"mismatch\": the signature fails.",
      `- \`${REMOTE}\` stays "not checked" unless you turn on fetching remote resources. Fetching tells the server that someone is verifying, so it is off by default.`,
    ),
  };
  const ids = { ja: "sato@sample-studio.example", en: "alice@sample-studio.example" };
  const reasons = { ja: "図版を含めて確認", en: "Reviewed with the diagram" };
  const text = {} as Text;
  for (const l of ["ja", "en"] as const) {
    text[l] = (
      await signDocument(body[l], {
        signer,
        method: "tofu",
        signerId: ids[l],
        role: "author",
        reason: reasons[l],
        ts: TS1,
        resources: [
          { ref: "./assets/diagram.svg", bytes: diagram },
          { ref: REMOTE, bytes: utf8("not fetched by default") },
        ],
      })
    ).text;
  }
  return {
    title: { ja: "外部ファイルの固定", en: "Bound files (resources)" },
    text,
    files: { "assets/diagram.svg": Buffer.from(diagram).toString("base64") },
  };
}

// ------------------------------------------------------------------ pgp
const PGP_KEY_CREATED = 1767225600; // must match gen-examples.ts so the certificate fingerprint is the same

async function pgp(): Promise<Example> {
  const k = await ed25519Key(fromHex(keys.pgp["dave@example.org"].seed_hex), PGP_KEY_CREATED, 4);
  // a fixed creation time keeps docs/examples.js stable across builds
  const created = Date.parse(TS1) / 1000;
  const signer: PgpSigner = {
    alg: "openpgp",
    fpr: keys.pgp["dave@example.org"].fpr,
    keyAlg: "ed25519",
    uids: ["Dave Test <dave@example.org>"],
    emails: ["dave@example.org"],
    sign: async (payload) => signaturePacket(await createSignature(k.sk, SIG.binary, payload, { created })),
    dispose() {},
  };
  const body: Text = {
    ja: lines(
      "# OpenPGP 署名（pgp）",
      "",
      "この文書は OpenPGP 鍵（`dave@example.org`、Ed25519）で署名しています。署名ブロックは `method: pgp` と `alg: openpgp` の組で、鍵のフィンガープリントを `fpr` に、OpenPGP の分離署名を `sig` に記録します。",
      "",
      "検証者は `fpr` の鍵を、`signer` のドメインの WKD（`/.well-known/openpgpkey/`）、鍵サーバ（既定は `keys.openpgp.org`）の順に検索します。この例の鍵は WKD から取得したものとして表示されます。",
      "",
      "## 署名時刻の扱い",
      "",
      "OpenPGP の署名パケットは独自の作成時刻を持ちます。`ts` と同様に署名者の端末が設定する値のため、検証結果では別の行に表示します。第三者による証拠となるのは、TSA のタイムスタンプ（`tsa_token`）の時刻のみです。",
      "",
      "## 試してみる",
      "",
      "- 署名ブロックの `role` を変更すると、検証に失敗します。",
      "- 「署名の追加」タブで方式に「pgp」を選択し、`examples/pgp/frank.sec.asc` を読み込むと、RSA 鍵で連署できます。パスフレーズは `test` です。",
      "- 秘密鍵とパスフレーズはこのページのメモリ内でのみ処理し、保存も送信もしません。",
      "",
      "この例の鍵は `examples/pgp` の公開テスト鍵です。`example.org` の WKD と `keys.openpgp.org` への要求はページ内で処理しており、外部には送信しません。",
    ),
    en: lines(
      "# OpenPGP signature (pgp)",
      "",
      "This document is signed with an OpenPGP key (`dave@example.org`, Ed25519). The block pairs `method: pgp` with `alg: openpgp`, records the key fingerprint in `fpr`, and holds an OpenPGP detached signature in `sig`.",
      "",
      "A verifier looks up the `fpr` key in the WKD of the `signer` domain (`/.well-known/openpgpkey/`), then on a keyserver (`keys.openpgp.org` by default). Here the key shows up as found through WKD.",
      "",
      "## Signing time",
      "",
      "An OpenPGP signature packet carries its own creation time. Like `ts`, the signer's machine sets it, so the result lists it on a separate line. Only the time in a TSA timestamp (`tsa_token`) is evidence from a third party.",
      "",
      "## Try it",
      "",
      "- Change the `role` in the signature block and verification fails.",
      "- In the \"Add signatures\" tab, choose \"pgp\" and load `examples/pgp/frank.sec.asc` to co-sign with an RSA key. The passphrase is `test`.",
      "- The secret key and passphrase stay in this page's memory. Nothing is stored or sent.",
      "",
      "The keys here are public test keys from `examples/pgp`. Requests to the `example.org` WKD and to `keys.openpgp.org` for them are answered inside the page and never sent out.",
    ),
  };
  const reasons = { ja: "OpenPGP 鍵で確認", en: "Reviewed with my OpenPGP key" };
  const text = {} as Text;
  for (const l of ["ja", "en"] as const) {
    text[l] = (await signDocument(body[l], { signer, method: "pgp", signerId: "dave@example.org", role: "author", reason: reasons[l], ts: TS1 })).text;
  }
  return { title: { ja: "OpenPGP 署名（pgp）", en: "OpenPGP signature (pgp)" }, text, testKeys: true };
}

// ------------------------------------------------------------------ write
const EXAMPLES = {
  basic: await basic(),
  scoped: await scoped(),
  pending: await pending(),
  flow: await flow(),
  passkey: await passkey(),
  resources: await resources(),
  pgp: await pgp(),
};
const TEST_KEYS = {
  "git-hosting": Object.fromEntries(Object.entries(keys["git-hosting"] as Record<string, { keys_file: string; key_fp: string }>).map(([k, v]) => [k, { keys_file: v.keys_file, key_fp: v.key_fp }])),
  dns: Object.fromEntries(Object.entries(keys.dns as Record<string, { txt: string }>).map(([k, v]) => [k, { txt: v.txt }])),
  ...pgpTestKeys(),
};
// Certificates for the playground's WKD / keyserver interception; only keys that can sign validly.
function pgpTestKeys() {
  const PGP_SIGNERS = ["dave@example.org", "erin@example.org", "frank@example.org", "grace@example.org"];
  const pgp: Record<string, { signer: string; cert: string }> = {};
  const byFile: Record<string, string> = {};
  for (const email of PGP_SIGNERS) {
    const e = keys.pgp[email];
    pgp[e.fpr] = { signer: email, cert: read(`examples/${e.cert}`) };
    byFile[e.cert] = e.fpr;
  }
  const pgpFetch: Record<string, string> = {};
  for (const [url, file] of Object.entries(keys.fetch as Record<string, string>)) if (byFile[file]) pgpFetch[url] = byFile[file]!;
  return { pgp, pgpFetch };
}

const out = `// Generated by packages/core/scripts/gen-docs-examples.ts; do not edit by hand.
// TEST_KEYS are the public test keys of examples/keys.json (RFC 8032 seeds, examples/pgp certificates). Never use them for real signatures.
export const EXAMPLES = ${JSON.stringify(EXAMPLES, null, 2)};

export const TEST_KEYS = ${JSON.stringify(TEST_KEYS, null, 2)};
`;
writeFileSync(new URL("docs/examples.js", root), out);
console.log("wrote docs/examples.js", out.length, "bytes");
