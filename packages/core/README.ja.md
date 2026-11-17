# @md-signature/core

Markdown 文書に埋め込む署名形式 [md-signature](../../README.ja.md) の TypeScript 実装です。署名、検証、検証サーバー、そのクライアントを提供します。

[English](README.md) · [形式仕様](../../SPEC.ja.md) · [CLI・HTTP API 仕様](../../CLI_SPEC.ja.md)

- ブラウザ、Node.js 22 以降、Deno、Bun、Cloudflare Workers で動作します。`node:*` のモジュールは使用していません。
- npm への公開は準備中です。公開後は `npm install @md-signature/core` で導入できる予定。
- ドラフト版です。署名は形式 `0.0.2` で作成し、`0.0.1` と `0.0.2` を検証します。API は 1.0 までに変更する可能性があります。

## 検証

```ts
import { verifyDocument } from "@md-signature/core";

const result = await verifyDocument(text);

result.ok;          // すべての署名が valid のとき true
result.error;       // 文書全体の問題（署名なし、最後の署名の後に未署名の内容がある、など）
result.signatures;  // ブロックごとの結果
result.agreement;   // require による連署の状況（none / complete / pending / violated）
```

ブロックごとの結果は次のとおりです。

| フィールド | 内容 |
| --- | --- |
| `status` | `valid`、`invalid`、`malformed`、`unresolved`、`unsupported` |
| `code` | 失敗の理由。`hash-mismatch`、`bad-signature`、`expired`、`revoked`、`key-changed`、`network`、`not-found` など |
| `message` | 英語の説明 |
| `fields` | ブロックに書かれた値（`signer`、`method`、`role`、`ts` など） |
| `tsa` | タイムスタンプの検査結果。`verified` が `true` のときだけ `genTime` を持つ |
| `revocation`、`resources`、`partial`、`pgp`、`webauthn` | 該当する場合のみ |
| `warnings` | 有効ではあるが利用者に伝えるべき事項 |

`unresolved` は、鍵や撤回リストを取得できず判定できなかった状態です。有効として扱わないでください。

### 主なオプション

| オプション | 内容 |
| --- | --- |
| `fetch` | 外部への取得に使用する関数。中継サーバーを経由させる場合や、テストで差し替える場合に指定する |
| `offline` | ネットワークを使用しない。`tofu` 以外の署名は `unresolved` になる |
| `resolvers` | 方式（`dns`、`git-hosting`、`tofu`、`pgp`）ごとの鍵の取得処理を差し替える |
| `tofuStore` | `tofu` の署名者と鍵の対応を記録する場所。記録済みの鍵と異なる場合は `key-changed` で無効になる |
| `acceptNewTofuKey` | 変更された `tofu` の鍵を受け入れ、記録を更新する |
| `keyserver` | `pgp` の鍵を探索する鍵サーバ。既定は `https://keys.openpgp.org` |
| `loadResource` | `resources` のローカルファイルを読み込む関数。指定しない場合は「未検査」になる |
| `fetchResources` | `https://` のリソースを取得してハッシュを検査する。既定はオフ |
| `checkRevocation` | `false` で撤回リストを取得しない |
| `now` | 有効期限の判定に使用する時刻 |
| `tsaRoots`、`extraTsaRoots`、`tsaVerifier` | 次節を参照 |

## タイムスタンプ（TSA）の信頼設定

`tsa_token` は、TSA の署名と証明書チェーンが信頼するルート証明書まで検証できた場合に限り、時刻（`genTime`）を報告します。検証できないトークンは `status: "error"` と警告になり、時刻は報告しません。署名自体の有効、無効には影響しません。

ブラウザには読み取れるトラストストアがないため、公開 TSA のルート証明書を同梱しています（`DEFAULT_TSA_ROOTS`）。

```ts
import { verifyDocument, DEFAULT_TSA_ROOTS, readTsaRoots } from "@md-signature/core";

// 同梱のルートに追加する
await verifyDocument(text, { extraTsaRoots: [pemText] });

// 同梱のルートを使用せず、指定したものだけを信頼する
await verifyDocument(text, { tsaRoots: [pemText] });

// 証明書の内容を確認する（名前、SHA-256 指紋、期限）
const roots = await readTsaRoots(pemText);
```

値は DER（`Uint8Array`）または PEM の文字列です。PEM は複数の証明書を含められます。`signDocument` も同じオプションを持ち、`tsaUrl` で取得した応答の検証に使用します。

同梱の一覧は、Microsoft のルートプログラム（CCADB）でタイムスタンプ用途として信頼されているものから選択しています。証明書の失効確認（CRL、OCSP）は行いません。

## 署名

```ts
import { signDocument, generateEd25519, signerFromSeed } from "@md-signature/core";

const { signer } = await generateEd25519();          // 新しい鍵
// const signer = await signerFromSeed(seed32bytes); // 既存の Ed25519 シード

const { text } = await signDocument(markdown, {
  signer,
  method: "tofu",           // dns / git-hosting / tofu / pgp
  signerId: "bob@laptop",
  role: "reviewer",
  reason: "内容を確認",
});
```

`require` には 1 行ずつ文字列を渡します。段階と人数、順序の扱いも行で指定します（形式仕様 5.8 節）。

```ts
await signDocument(markdown, {
  signer, method: "git-hosting", signerId: "github.com/alice",
  require: ["order strict", "step 1", "dns:example.com approver", "step 2 any 2", "git-hosting:github.com/bob", "git-hosting:github.com/carol", "git-hosting:github.com/dave"],
});
```

検証結果の `agreement.missing` は段階ごとの不足（`step`、`need`、`blockedBy`、`early`）を、`agreement.violations` は順序違反を示します。`order strict` の違反があると `agreement.status` は `violated` となり、`result.ok` は `false` になります。

既に署名がある文書に対して呼び出すと、連署として末尾に追記します。主なオプションは `selector`（`dns`）、`expires`、`scope`、`require`、`resources`、`revocationUrl`、`tsaUrl` です。意味は[形式仕様](../../SPEC.ja.md)の 5 章を参照してください。

OpenSSH の秘密鍵は `parseOpenSshPrivateKey`、OpenPGP の秘密鍵は `readPgpSecretKey` と `unlockPgpSecretKey`、パスキーは `registerPasskey` と `passkeySigner` で署名者を作成します。

## サーバーでの検証

ブラウザ単体では確認できない項目（CORS で取得できない鍵、OS のトラストストアによる TSA の検証など）を、サーバーに委ねられます。HTTP API は [CLI 仕様 3.6 節](../../CLI_SPEC.ja.md)で規定しており、Go の `mdsig serve` と互換です。

### サーバー側

`createVerifyHandler` は、`Request` を受け取り `Response` を返す関数を作成します。

```ts
import { createVerifyHandler } from "@md-signature/core";

const handler = createVerifyHandler({
  allowOrigins: ["https://app.example.com"],  // ブラウザからの呼び出しを許可するオリジン
  verify: { extraTsaRoots: [pemText] },       // verifyDocument に渡すオプション
});

export default { fetch: handler };  // Cloudflare Workers、Bun
// Deno.serve(handler);             // Deno
```

Node.js の `http` モジュールで使用する場合は、`Request` と `Response` への変換が必要です。

ハンドラは次の点を固定しています。

- 要求ごとに独立して検証します。`tofu` の記録、ローカルのファイル、鍵束は使用しません。
- `Origin` ヘッダを持つ要求は、`allowOrigins` にある場合のみ処理します。
- 本文は 4 MiB まで、同時処理は 8 件までです（`maxBodyBytes`、`maxConcurrent` で変更可能）。
- 外部への取得は、IP アドレスの直接指定、`localhost`、内部向けの名前への接続を拒否します。

最後の制限は、公開の名前が内部のアドレスに解決される場合を検知できません。Web 標準の API からは解決先が見えないためです。内部ネットワークに到達できる環境で動かす場合は、ネットワーク側でも送信先を制限してください。Go 版（`mdsig serve`）は接続時にアドレスを検査します。

認証と TLS は含みません。公開する場合は、前段で対応してください。

### クライアント側

```ts
import { verifyDocument, remoteVerify, remoteTsaVerifier, compareResults } from "@md-signature/core";

// 文書全体をサーバーで検証する
const remote = await remoteVerify("https://verify.example.com", text);

// 手元の判定と突き合わせる
const local = await verifyDocument(text);
const diff = compareResults(local, remote);
diff.agree;     // すべてのブロックで status と code が一致
diff.tsaAgree;  // タイムスタンプを検証できたかどうかが一致
diff.blocks;    // ブロックごとの双方の判定

// TSA の検証だけをサーバーに委ねる
await verifyDocument(text, { tsaVerifier: remoteTsaVerifier("https://verify.example.com") });
```

サーバーに委ねた判定は、そのサーバーを信頼することになります。2 つの判定は合成せず、出所を区別して扱ってください。信頼するルート証明書が異なるため、`tsaAgree` は `false` になることがあります。

`remoteVerify` の戻り値は、`mdsig verify --json` と同じ JSON 形式です。手元の結果を同じ形式にするには `toJsonResult(result)` を使用します。

## Go 版との違い

| 項目 | TypeScript | Go（`mdsig`） |
| --- | --- | --- |
| TSA の信頼の起点 | 同梱のルートと、指定したルート | OS のトラストストアと `--tsa-root` |
| ローカルの gpg 鍵束、ssh-agent | 使用しない | CLI が使用する |
| 外部への取得の制限 | サーバー用ハンドラのみ、名前による制限 | 常に、接続先アドレスによる制限 |
| CLI | なし | あり |

署名形式、判定の語彙、JSON 形式、HTTP API は共通で、[examples](../../examples) のテストベクタを両方の実装が検査しています。

## ライセンス

MIT
