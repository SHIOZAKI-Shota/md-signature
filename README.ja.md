<p align="center"><img src="docs/logo.svg" width="180" alt="md-signature"></p>

# md-signature

**Markdownにも電子署名を。**

[English](README.md) · [仕様書](SPEC.ja.md) · [CLI 仕様](CLI_SPEC.ja.md) · [Playground](https://mdsig.dev/)

`md-signature` は、本文の最終行に署名を追加し検証する、Markdownのためのオープンフォーマットです。特定のベンダーに依存しません。
署名はファイル末尾に HTML コメントとして追記します。

```markdown
# 業務委託契約書

甲と乙は以下のとおり合意する。

<!-- md-signature
v: 0.0.2
method: git-hosting
signer: github.com/alice
key_fp: SHA256:Rx9i...
role: author
ts: 2026-11-16T09:00:00Z
alg: ed25519
hash: sha256:3a0d0b5c...
sig: base64:q1Xv...
-->
```

- 表示に影響しません。GitHub や VS Code など CommonMark 準拠のレンダラーは HTML コメントを表示しないためです。
- 署名は文書と同じファイルに収まります。`.sig` のような別ファイルが不要なので、受け渡しの途中で欠落しません。
- 連署 (co-signing) に対応します。後から追記した署名は、本文とそれ以前の全署名を対象とします（追記型ハッシュチェーン）。
- 検証には既存の鍵を使用できます。GitHub/GitLab に登録済みの SSH 鍵（`https://github.com/<user>.keys`）、自社ドメインの DNS TXT レコード、OpenPGP、埋め込み公開鍵のいずれかです。
- RFC 3161 タイムスタンプトークンを任意で付与できます。長期保存には、署名者を持たないタイムスタンプ専用ブロックを `mdsig timestamp` で重ねて追記し、更新できます。`dns` と `git-hosting` は公開鍵を埋め込めるので（`--embed-key`）、鍵が削除された後も署名の成立を確認できます。
- 承認フローを記述できます。署名者が未完了の連署を宣言すると（`require`）、`mdsig verify` は連署が揃うまで「保留（pending）」と表示します。「課長の承認の後に、3 人中 2 人がレビュー」のような順番（`step`）と人数（`any`）も指定できます。
- スクリーンショットやデータファイル、リモート画像も SHA-256 で文書に固定できます（`resources`）。リンク先が差し替えられると検知します。
- 指定したセクションだけに署名し、メモ欄や記入欄を編集可能なまま保持できます（`scope`）。この場合、検証結果には必ず「部分署名」と表示されます。
- `expires` で有効期限を設定できます。署名付きの撤回リスト（`revocation_url`）を公開すれば、後から署名を撤回することも可能です。
- パスキー（Touch ID、Face ID、Windows Hello、セキュリティキー）を使用して、ブラウザから直接署名できます（`webauthn-es256`）。鍵ファイルは不要です。
- リファレンス実装は Web Crypto・`fetch`・`CompressionStream` のみに依存します。ブラウザ、Cloudflare Workers、Deno、Bun、Node.js のいずれでも同一の動作をします。

## クイックスタート

### CLI (`mdsig`)

```sh
# インストール（Go 1.26 以降が必要。Homebrew、winget、npm での配布とビルド済みバイナリは準備中）
go install mdsig.dev/cmd/mdsig@latest

# GitHub に登録済みの SSH 鍵で署名（ssh-agent または ~/.ssh/id_ed25519 を自動検出）
mdsig sign contract.md -m git-hosting -s github.com/alice -r author --reason "初版確定"

# 別の署名者が DNS 公開鍵で連署し、タイムスタンプを付与
mdsig keygen -o ~/.mdsig/example -d example.com --selector 2026   # 登録用の TXT レコードを表示
mdsig sign contract.md -m dns -s example.com --selector 2026 -k ~/.mdsig/example -r approver --tsa

# チェーン全体を検証
mdsig verify contract.md

# 引数なしで実行すると対話メニューを起動（LANG=ja_JP.UTF-8 なら日本語表示）
mdsig
```

```sh
# 承認者の指定、スクリーンショットの固定、有効期限 30 日の設定
mdsig sign quote.md -m git-hosting -s github.com/alice -r author \
  --require "dns:example.com approver" --auto-resources --expires 30d

# 承認の後に 3 人中 2 人がレビューする流れを宣言
mdsig sign plan.md -m git-hosting -s github.com/alice -r author \
  --require "step 1" --require "dns:example.com approver" \
  --require "step 2 any 2" --require "git-hosting:github.com/bob" \
  --require "git-hosting:github.com/carol" --require "git-hosting:github.com/dave"

# 「terms」と「fees」セクションのみに署名（その他は編集可能）
mdsig sign sow.md -m tofu -s alice@laptop -k ~/.mdsig/alice --scope terms,fees
```

終了コード: `0` 検証成功 / `1` 検証失敗 / `2` 使い方の誤り / `3` ネットワーク・鍵取得エラー / `4` ファイルエラー / `5` 署名は有効だが必須の連署が不足

### 利用例: AI エージェント向け指示書への署名

`CLAUDE.md`、`AGENTS.md`、`SKILL.md` に署名しておき、エージェントの実行環境がこれらを読み込む前に `mdsig verify` を実行します。たとえば Claude Code の `SessionStart` フックに組み込めば、第三者に改変された指示書を検出した時点で起動を中止できます。

検証は実行環境の側で行ってください。注入された文章をすでに読んだエージェント自身に、その真偽の判定は委ねられません。この方法で防止できるのは、PR や再配布の過程での指示書の改変です。ツール出力や Web ページを経由したプロンプトインジェクションは対象外です。

### ライブラリ

md-signature はライブラリとして使用することを主目的にしています。CLI と Playground は、その利用例です。

**TypeScript（`@md-signature/core`）：** ブラウザ、Node.js、Deno、Bun、Cloudflare Workers で動作します。npm への公開は準備中です。

```ts
import { verifyDocument, signDocument, generateEd25519 } from "@md-signature/core";

const result = await verifyDocument(markdown);
if (result.ok) console.log(`${result.signatures.length} 件の署名を確認しました`);

const { signer } = await generateEd25519();
const { text } = await signDocument(markdown, { signer, method: "tofu", signerId: "bob@laptop", role: "reviewer" });
```

**Go（`mdsig.dev/mdsig`）：** CLI と同じ検証処理を関数として呼び出せます。

```go
import "mdsig.dev/mdsig"

r := mdsig.VerifyDocument(ctx, text, &mdsig.VerifyOptions{})
```

**サーバーでの検証：** ブラウザ単体では確認できない項目を、サーバーに委ねられます。Go は `mdsig/server` の `http.Handler`（`mdsig serve` と同じもの）、TypeScript は `createVerifyHandler` で、同じ HTTP API（[CLI 仕様 3.6 節](CLI_SPEC.ja.md)）を提供します。クライアント側は `remoteVerify` で呼び出し、`compareResults` で手元の判定と突き合わせます。

オプションの一覧、TSA のルート証明書の指定、サーバー側での注意点は [packages/core/README.ja.md](packages/core/README.ja.md) を参照してください。

## 検証方式

| `method` | `signer` の例 | 公開鍵の取得元 |
| --- | --- | --- |
| `git-hosting` | `github.com/alice` | `https://github.com/alice.keys` |
| `dns` | `example.com` | `[<selector>.]_mdsig.example.com` の TXT レコード |
| `pgp` | `alice@example.com` + `fpr` | ローカルの鍵束（CLI）、WKD、鍵サーバー（既定は keys.openpgp.org）の順 |
| `tofu` | 任意 | ブロック内の `pubkey`。改ざん検知はできるが、本人性は証明しない |

OpenPGP 署名（`alg: openpgp`）の `sig` は、`gpg --detach-sign` が出力する形式の分離署名です。CLI は gpg を経由して署名するため、gpg-agent やスマートカード上の鍵をそのまま使用できます。鍵ファイルを指定した署名も可能で、ブラウザでも鍵ファイルを読み込んで署名できます。対応する鍵は Ed25519（v4・v6）、RSA（2048 ビット以上）、ECDSA P-256 です。パスフレーズによる保護は、gpg の既定形式（iterated+salted S2K と AES）に対応します。Argon2 と AEAD による保護は CLI のみ対応し、ブラウザでは未対応です。

パスキー署名（`alg: webauthn-es256`）の公開鍵は `tofu` または `dns` で示します。パスキーは署名ページのドメイン（現在は `mdsig.dev`）に結び付きます。Playground を別ドメインへ移すと、旧ドメインで登録したパスキーではそこで署名できません。作成済みの署名は引き続き検証できます。

## リポジトリ構成

| パス | 内容 |
| --- | --- |
| [`SPEC.ja.md`](SPEC.ja.md) | 形式と暗号処理の仕様（原文）。英語版 [`SPEC.md`](SPEC.md) が規範 |
| [`CLI_SPEC.ja.md`](CLI_SPEC.ja.md) | CLI の挙動、JSON 出力、HTTP API の仕様（規範）。英語版は [`CLI_SPEC.md`](CLI_SPEC.md) |
| [`packages/core`](packages/core) | `@md-signature/core`（TypeScript） |
| [`mdsig`](mdsig) | Go ライブラリ。[`mdsig/server`](mdsig/server) は HTTP ハンドラ |
| [`cmd/mdsig`](cmd/mdsig)、[`internal`](internal) | ネイティブ CLI `mdsig`（Go） |
| [`docs`](docs) | Playground（https://mdsig.dev/） |
| [`examples`](examples) | 全実装で共有するテストベクタ |

## 開発

```sh
cd packages/core
npm install
npm test                    # 単体テストと examples/ の適合性ベクタ
npm run check:web-standard  # src/ が Node 専用 API を使用していれば失敗
npm run build:docs          # docs/vendor/core と Playground のデモ文書を再生成

cd ../..
go test ./...
go build -o bin/mdsig ./cmd/mdsig   # ./mdsig はライブラリのディレクトリのため -o が必要
```

## ステータス

ドラフト版です。リリース（CLI とライブラリ）と署名の形式は別々に版を管理しており、現在の形式は `0.0.2` です（`0.0.1` の署名も検証できます）。`mdsig --version` で両方を確認できます。1.0 までに形式と API を変更する可能性があります。

実験的な実装です。第三者によるセキュリティ監査は受けていません。契約など、署名の正しさに重大な結果が伴う用途で、この実装だけに依拠することは避けてください。脆弱性の報告方法は [SECURITY.md](SECURITY.md) を参照してください。

## ライセンス

- 仕様書（`SPEC.md`, `CLI_SPEC.md` と日本語参考訳 `SPEC.ja.md`, `CLI_SPEC.ja.md`）: [CC0 1.0](LICENSE-SPEC)
- コード: [MIT](LICENSE)

形式仕様は日本語版（`SPEC.ja.md`）が原文で、英語版（`SPEC.md`）は IETF 提出用に維持する正本です。CLI 仕様は日本語版（`CLI_SPEC.ja.md`）が正本です。
