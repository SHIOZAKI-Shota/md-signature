<p align="center"><img src="docs/logo.svg" width="180" alt="md-signature"></p>

# md-signature

**Markdown にも電子署名を。**

[English](README.md) · [仕様書](SPEC.ja.md) · [CLI 仕様](CLI_SPEC.ja.md) · [デモ](https://mdsig.dev/playground/)

`md-signature` は、本文の最終行に署名を追加し検証する、Markdown のためのオープンフォーマットです。特定のベンダーに依存しません。
署名はファイル末尾に HTML コメントとして追記します。

```markdown
# 業務委託契約書

甲と乙は以下のとおり合意する。

<!-- mdsig:signatures -->

<!-- md-signature
v: 0.1
method: git-hosting
signer: github.com/alice
key_fp: SHA256:Rx9i...
display_name: Alice Example
role: author
ts: 2026-11-16T09:00:00Z
require: |
  step
    dns:example.com role=approver
alg: ed25519
hash: sha256:3a0d0b5c...
sig: base64:q1Xv...
-->
```

- 表示に影響しません。GitHub や VS Code など CommonMark 準拠のレンダラは HTML コメントを表示しないためです。
- 署名は文書と同じファイルに収まります。`.sig` のような別ファイルが不要なので、受け渡しの途中で欠落しません。
- 連署（co-signing）に対応します。後から追記した署名は、本文とそれ以前の全署名を対象とします（追記型ハッシュチェーン）。
- 検証には既存の鍵を使用できます。GitHub/GitLab に登録済みの SSH 鍵（`https://github.com/<user>.keys`）、自社ドメインの DNS TXT レコード、OpenPGP、埋め込み公開鍵のいずれかです。
- 時刻の証拠が必要な場合は、RFC 3161 のタイムスタンプを `tsa` ブロックとしてチェーンに追記します（`mdsig sign --tsa`、`mdsig timestamp`）。`tsa` ブロックはそれより前のチェーン全体を対象とするので、重ねて追記すれば長期保存のための更新になります。`dns`、`git-hosting`、`directory` は公開鍵を埋め込めるので（`--embed-key`、`directory` は既定で埋め込む）、鍵が削除された後も署名の成立を確認できます。
- 承認フローを記述できます。署名者が必須の連署を宣言すると（`require`）、`mdsig verify` は連署がそろうまで「保留（pending）」と表示します。段階（`step`）と人数（`step any=2`）のほか、相手を名指しせずに資格で指定することもできます。`directory:*@example.com` のようなパターン、組織の名簿（`member_of=`。DNS または署名済みの名簿文書）、パスキーによる利用者確認（`user_verified`）です。
- 本文に `<!-- mdsig:signatures -->` を置くと、表示側（`mdsig render`、デモ）が検証済みのブロックから署名欄を生成し、その位置に描画します。署名欄は本文に書き込まないので、本文の HTML で偽の署名欄を作っても検証結果は偽装できません。表示名（`display_name`）は申告として、検証済みの署名者と並べて示します。
- スクリーンショットやデータファイル、リモート画像も SHA-256 で文書に固定できます（`resources`。各行は `<参照> hash=sha256:<16進数>`）。リンク先が差し替えられると検知します。
- 指定したセクションだけに署名し、メモ欄や記入欄を編集可能なまま保持できます（`scope`。1行に1つのセクション ID）。この場合、検証結果には必ず「部分署名」と表示されます。
- `expires` で有効期限を設定できます。署名済みの撤回リスト（`revocation_url`）を公開すれば、後から署名を撤回することも可能です。
- パスキー（Touch ID、Face ID、Windows Hello、セキュリティキー）を使用して、ブラウザから直接署名できます（`webauthn-es256`）。鍵ファイルは不要です。
- リファレンス実装は Web Crypto・`fetch`・`CompressionStream` のみに依存します。ブラウザ、Cloudflare Workers、Deno、Bun、Node.js のいずれでも同一の動作をします。

## クイックスタート

### CLI（`mdsig`）

```sh
# インストール（Homebrew、または Go 1.26 以降。winget と .deb/.rpm パッケージは準備中）
brew install SHIOZAKI-Shota/tap/mdsig
go install mdsig.dev/cmd/mdsig@latest

# GitHub に登録済みの SSH 鍵で署名（ssh-agent または ~/.ssh/id_ed25519 を自動検出）
mdsig sign contract.md -m git-hosting -s github.com/alice -r author   --display-name "Alice Example" --reason "初版確定"

# 別の署名者が DNS 公開鍵で連署し、続けて tsa ブロック（タイムスタンプ）を追記
mdsig keygen -o ~/.mdsig/example -d example.com --selector 2026   # 登録用の TXT レコードを表示
mdsig sign contract.md -m dns -s example.com --selector 2026 -k ~/.mdsig/example -r approver --tsa

# チェーン全体を検証し、署名欄を付けた HTML を出力
mdsig verify contract.md
mdsig render contract.md -o contract.html

# 引数なしで実行すると対話メニューを起動（LANG=ja_JP.UTF-8 なら日本語表示）
mdsig
```

```sh
# 承認者の指定、スクリーンショットの固定、有効期限30日の設定
mdsig sign quote.md -m git-hosting -s github.com/alice -r author   --require "dns:example.com role=approver" --auto-resources --expires 30d

# 承認の後に3人中2人がレビューする流れを宣言（--require は1行ずつ指定）
mdsig sign plan.md -m git-hosting -s github.com/alice -r author   --require "step" --require "dns:example.com role=approver"   --require "step any=2" --require "git-hosting:github.com/bob role=reviewer"   --require "git-hosting:github.com/carol role=reviewer" --require "git-hosting:github.com/dave role=reviewer"

# 相手を名指しせず、example.com の DNS 名簿に載る社員の承認を求める
mdsig sign request.md -m directory -s alice@example.com -k ~/.mdsig/alice   --require "directory:*@example.com member_of=dns:example.com role=approver"

# 名簿に載せる社員ごとに、設定する TXT レコードを表示
mdsig member-record directory:bob@example.com example.com

# 署名する前に、require の値の意味を確認
printf 'step
  dns:example.com role=approver
step any=2
  dns:*.example.com
' | mdsig require explain -

# 「terms」と「fees」セクションのみに署名（その他は編集可能）
mdsig sign sow.md -m tofu -s alice@laptop -k ~/.mdsig/alice --scope terms,fees
```

署名すると、`require` は段階ごとに字下げした行として書き込まれます。

```
require: |
  step
    dns:example.com role=approver
  step any=2
    git-hosting:github.com/bob role=reviewer
    git-hosting:github.com/carol role=reviewer
    git-hosting:github.com/dave role=reviewer
```

終了コード：`0` 検証成功 / `1` 検証失敗（`order mode=strict` の順序違反、未対応の要件を含む） / `2` 使い方の誤り / `3` ネットワークまたは鍵解決のエラー（`--offline` で検査されなかったブロックがある場合、名簿を参照できず合意を判定できない場合を含む） / `4` ファイルエラー / `5` 署名は有効だが必須の連署が不足

### 利用例：AI エージェント向け指示書への署名

`CLAUDE.md`、`AGENTS.md`、`SKILL.md` に署名しておき、エージェントの実行環境がこれらを読み込む前に `mdsig verify` を実行します。たとえば Claude Code の `SessionStart` フックに組み込めば、第三者に改変された指示書を検出した時点で起動を中止できます。

検証は実行環境の側で行ってください。注入された文章をすでに読んだエージェント自身に、その真偽の判定は委ねられません。この方法で防止できるのは、PR や再配布の過程での指示書の改変です。ツール出力や Web ページを経由したプロンプトインジェクションは対象外です。

### 利用例：エージェント間の取引

AI エージェントが取引条件を承諾する場面でも使用できます。提供者が Markdown の条件文書に署名して公開し、承諾者のエージェントは自身の `dns` 鍵で連署します。承諾ブロックの `hash` は、LCP の `atrHash`（公開した文書の SHA-256）と一致します。提供者は `require` で相手の資格（パターン、名簿）と、自身による最終確認の段階を宣言できます。支払い（x402）や代理権（AP2）は既存のプロトコルに任せます。手順は [AGENT_COMMERCE.ja.md](AGENT_COMMERCE.ja.md)（参考文書）を参照してください。

### ライブラリ

md-signature はライブラリとして使用することを主目的にしています。CLI とデモは、その利用例です。

**TypeScript（`@mdsig/core`）：** ブラウザ、Node.js、Deno、Bun、Cloudflare Workers で動作します。`npm install @mdsig/core` で導入できます。

```ts
import { verifyDocument, signDocument, generateEd25519 } from "@mdsig/core";

const result = await verifyDocument(markdown);
if (result.ok) console.log(`${result.signatures.length} 件の署名を確認しました`);

const { signer } = await generateEd25519();
const { text } = await signDocument(markdown, { signer, method: "tofu", signerId: "bob@laptop", role: "reviewer" });
```

合意の状態は `result.agreement.status`（`none`、`complete`、`pending`、`violated`、`undetermined`、`unsupported`）で、まだ必要な署名は `result.agreement.next` で確認できます。署名欄の行データは `signatureTable(result)`、その HTML は `renderSignatureTableHtml(rows, "ja")`、`require` の値の説明は `explainRequire(value, "ja")` で取得できます。

**Go（`mdsig.dev/mdsig`）：** CLI と同じ検証処理を関数として呼び出せます。

```go
import "mdsig.dev/mdsig"

r := mdsig.VerifyDocument(ctx, text, &mdsig.VerifyOptions{})
```

**サーバでの検証：** ブラウザ単体では確認できない項目を、サーバに委ねられます。Go は `mdsig/server` の `http.Handler`（`mdsig serve` と同じもの）、TypeScript は `createVerifyHandler` で、同じ HTTP API（[CLI 仕様 3.6 節](CLI_SPEC.ja.md)）を提供します。クライアント側は `remoteVerify` で呼び出し、`compareResults` で手元の判定と突き合わせます。

オプションの一覧、TSA のルート証明書の指定、サーバ側での注意点は [packages/core/README.ja.md](packages/core/README.ja.md) を参照してください。

## 検証方式

| `method` | `signer` の例 | 公開鍵の取得元 |
| --- | --- | --- |
| `git-hosting` | `github.com/alice` | `https://github.com/alice.keys` |
| `dns` | `example.com` | `[<selector>.]_mdsig.example.com` の TXT レコード |
| `pgp` | `alice@example.com` + `fpr` | ローカルの鍵束（CLI）、WKD、鍵サーバ（既定は keys.openpgp.org）の順 |
| `tofu` | 任意 | ブロック内の `pubkey`。改ざん検知はできるが、本人性は証明しない |
| `directory` | `alice@example.com` | メールアドレスを確認した鍵ディレクトリ。ドメインが `_mdsig` の `dir=` で指定したもの、なければ検証者が信頼する一覧（既定は keys.mdsig.dev。[一覧の基準](KEY_DIRECTORIES.ja.md)） |

OpenPGP 署名（`alg: openpgp`）の `sig` は、`gpg --detach-sign` が出力する形式の分離署名です。CLI は gpg を経由して署名するため、gpg-agent やスマートカード上の鍵をそのまま使用できます。鍵ファイルを指定した署名も可能で、ブラウザでも鍵ファイルを読み込んで署名できます。対応する鍵は Ed25519（v4・v6）、RSA（2048 ビット以上）、ECDSA P-256 です。パスフレーズによる保護は、gpg の既定形式（iterated+salted S2K と AES）に対応します。Argon2 と AEAD による保護は CLI のみ対応し、ブラウザでは未対応です。

パスキー署名（`alg: webauthn-es256`）の公開鍵は `tofu`、`dns`、`directory` で示します。パスキーは署名ページのドメイン（現在は `mdsig.dev`）に結び付きます。デモを別ドメインへ移すと、旧ドメインで登録したパスキーではそこで署名できません。作成済みの署名は引き続き検証できます。

## リポジトリ構成

| パス | 内容 |
| --- | --- |
| [`SPEC.ja.md`](SPEC.ja.md) | 形式と暗号処理の仕様（原文）。英語版 [`SPEC.md`](SPEC.md) は IETF 提出用に維持する規範テキスト |
| [`CLI_SPEC.ja.md`](CLI_SPEC.ja.md) | CLI の挙動、JSON 出力、HTTP API の仕様（規範）。英語版 [`CLI_SPEC.md`](CLI_SPEC.md) は参考訳 |
| [`AGENT_COMMERCE.ja.md`](AGENT_COMMERCE.ja.md) | エージェント間取引での使用方法（参考文書）。英語版 [`AGENT_COMMERCE.md`](AGENT_COMMERCE.md) |
| [`CHANGELOG.md`](CHANGELOG.md) | リリースごとの変更点 |
| [`packages/core`](packages/core) | `@mdsig/core`（TypeScript） |
| [`mdsig`](mdsig) | Go ライブラリ。[`mdsig/server`](mdsig/server) は HTTP ハンドラ |
| [`cmd/mdsig`](cmd/mdsig)、[`internal`](internal) | ネイティブ CLI `mdsig`（Go） |
| [`docs`](docs) | Web サイト（https://mdsig.dev/）と[デモ](https://mdsig.dev/playground/) |
| [`examples`](examples) | 全実装で共有するテストベクタ |

## 開発

```sh
cd packages/core
npm install
npm test                    # 単体テストと examples/ の適合性ベクタ
npm run check:web-standard  # src/ が Node 専用 API を使用していれば失敗
npm run build:docs          # docs/vendor/core とデモ文書を再生成

cd ../..
go test ./...
go build -o bin/mdsig ./cmd/mdsig   # ./mdsig はライブラリのディレクトリのため -o が必要
```

## ステータス

ドラフト版です。CLI、Go ライブラリ、`@mdsig/core` のリリースは共通のバージョン（現在は `v0.1.1`）で、署名形式とは別に管理しています。現在の形式は `0.1` です。`mdsig --version` で両方を確認できます（`mdsig version 0.1.1 (format 0.1)`）。形式の版は互換性を失う変更を加える場合にのみ上げ、仕様が RFC として発行される時点で `1` とする予定です。API も 1.0 までに変更する可能性があります。

**0.0.x からの移行：** v0.1.0 は形式 `0.0.x` の署名を検証しません（`unsupported-version` となり、旧版で検証するよう案内を表示します）。`0.0.x` で署名した文書に v0.1.0 で連署を追記しても、既存の署名が未対応のまま残るため、文書全体は検証に通りません。既存の文書は mdsig v0.0.5 または `@mdsig/core` 0.0.5 で検証してください。変更点の一覧は [CHANGELOG.md](CHANGELOG.md) にあります。

実験的な実装です。第三者によるセキュリティ監査は受けていません。契約など、署名の正しさに重大な結果が伴う用途で、この実装だけに依拠することは避けてください。脆弱性の報告方法は [SECURITY.md](SECURITY.md) を参照してください。

## ライセンス

- 仕様書（`SPEC.ja.md`、`SPEC.md`、`CLI_SPEC.ja.md`、`CLI_SPEC.md`、`AGENT_COMMERCE.ja.md`、`AGENT_COMMERCE.md`）：[CC0 1.0](LICENSE-SPEC)
- コード：[MIT](LICENSE)

形式仕様は日本語版（`SPEC.ja.md`）が原文で、英語版（`SPEC.md`）は IETF 提出用に維持する規範テキストです。CLI 仕様は日本語版（`CLI_SPEC.ja.md`）が規範で、英語版（`CLI_SPEC.md`）は参考訳です。
