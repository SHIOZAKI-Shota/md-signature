# 変更履歴

[English](CHANGELOG.en.md)

`mdsig` CLI、Go ライブラリ `mdsig.dev/mdsig`、`@mdsig/core` のリリースは共通のバージョンです。署名形式は別のバージョンを持ち、括弧内に示します。

## 0.1.1（形式 0.1）、2026-11-28

### 互換性のない変更

- ローカルのリソース参照で、デコードした結果に `:` を含むものは形式不正になりました。Windows では `notes.txt:hidden` のような名前が代替データストリームを指すためです（SPEC 5.7 節）。

### 追加

- 合意の各宣言に段階ごとの状態 `steps`（必要な署名者数、数えた署名者数、成立したか、待機中の段階、行ごとの割り当て）を加えました。JSON では `declarations[].steps` です（CLI_SPEC 5 節）。
- 数えられなかった理由に `unresolved` を加えました。未解決のブロックはこれまで `not-valid` でしたが、改ざんなどで無効なブロックと区別できます（SPEC 5.8.9 節）。
- 文書全体の判定 `documentVerdict` / `DocumentVerdict` を加えました。CLI の終了コード（CLI_SPEC 4 節）と同じ規則で、CLI もこれを使用します。
- `serializeRequire`（`parseRequire` の逆）と、署名前の入力検査 `checkSignInput`（署名者の正規化、表示名、`require` の説明とエラー）を加えました。
- 利用者向けのメッセージを日本語にする `localizeMessage` / `LocalizeMessage` を加えました。目録は `mdsig/messages_ja.json` 1つで、TypeScript と Go が共有します。CLI は日本語表示のとき警告、判定の説明、エラーを日本語で表示します（`--json` は英語のままです）。
- 画面に表示されない文字を検出する `findHiddenCharacters` と、表示用の `HIDDEN_CHARACTER_RE` を加えました。対象は SPEC 3.2 規則 4 の分類（タブ・改行を除く）、非文字、異体字セレクタやハングルフィラーなどです。絵文字の合成（ZWJ）、旗の絵文字のタグ文字、アラビア文字やインド系文字の単語の中の ZWJ・ZWNJ、異体字セレクタには正当な文脈（`context`）を付け、文脈のないもの（ラテン文字の単語に紛れたタグ文字や ZWJ など）だけを警告対象にできます（SPEC 9.5 節）。
- 各署名の行範囲と対象範囲（`scope` のセクションを含む）、署名されていない末尾を返す `documentLayout` と、要件行1行を日英で説明する `describeRequirement` を加えました。
- `@mdsig/core` に実装間テストベクタを同梱し（`@mdsig/core/examples/*`）、その鍵とネットワークの代替を組み立てる `vectorOptions`（`@mdsig/core/testing`）を加えました。

## 0.1.0（形式 0.1）、2026-11-27

形式 0.1 は、利用者が少ないうちに行う破壊的な整理です。0.0.x のリリースで作成したブロックは、このリリースでは検証できず、連署もできません。

### 互換性のない変更

- `v` は `0.1` でなければなりません。`v: 0.0.1`、`0.0.2`、`0.0.4` のブロックは `unsupported-version` となり、検証者は mdsig v0.0.5 で検証するよう案内を表示します。形式の版は互換性を失う変更でのみ上げ、仕様が RFC として発行される時点で `1` とします（SPEC 3.3 節）。
- `alg` を必須にしました。`hash` と `alg` の既定値はありません。
- 値に `-->`、`--!>`、`<!--` を含めることはできません。`--` 単独は再び使用できるので、国際化ドメイン名（`xn--…`）も署名者にできます。C0・C1 制御文字と双方向制御文字に加えて、一般カテゴリ Cf、Zl、Zp の文字と非文字（ゼロ幅文字、タグ文字など）も拒否します（SPEC 3.2 節）。
- 継続行の末尾の空白は形式不正です（従来のパーサは黙って削除していました）。2つのスペースの字下げより後の空白は値の一部です。
- `role` は `[a-z0-9][a-z0-9._-]*` に一致する単一の語です。
- 署名者の識別子は、正規の形どうしの完全一致で比較します。ドメインは ASCII の小文字（`ldh-domain`。国際化ドメイン名は A-label）、`git-hosting` の利用者名は小文字で、どの方式でも `*` を含めません。正規の形でない値は形式不正です。生成側は `tofu` 以外の方式で、入力の ASCII の英大文字を小文字にそろえます（SPEC 3.4 節）。
- `scope`、`resources`、`require` は共通のリスト形式の行で書きます。対象の後に `name=value` の属性を、1つのスペースで区切って並べます（SPEC 3.5 節）。
  - `scope`：1行に1つのセクション ID。`section:` の接頭辞とカンマ区切りは廃止しました。
  - `resources`：`<参照> hash=sha256:<16進数>`（参照が先）。ローカルの参照はパーセントデコードします（空白は `%20`）。`%2F`、`%5C`、`%00`、`.` と `..` のセグメント、`./` で始まる参照は形式不正です（生成側は `./` を除去します）。
  - `require`：次項のとおりです。
- `require` を書き直しました（SPEC 5.8 節）。
  - `order pending|guide|strict` は `order mode=pending|guide|strict` に変更しました。
  - `step <n>` と `step <n> any <m>` は、`step` と `step any=<m>` に変更しました。段階には出現順に番号を付け、段階に属する行はその下に字下げして書き込みます（読み込みでは字下げは任意です）。
  - 役割は属性で書きます。`dns:example.com approver` ではなく `dns:example.com role=approver` です。
  - `any` のない段階はすべての行を必要とし、1つのブロックは1つの宣言の中で1行にだけ数えます。ブロックと行の割り当ては最大マッチングで決定的に定めるので（SPEC 付録 C）、検証者が行を試す順序に結果が左右されません。
  - `order mode=strict` とパターンの行は併用できません（誰でも早く署名でき、取り消せない違反を作れるためです）。
- 時刻証明は `tsa` ブロックだけで行います。ブロック内の `tsa_url` と `tsa_token` は廃止しました。`mdsig sign --tsa` と `tsaUrl` は、署名ブロックの後ろに `tsa` ブロックを追記します。ブロックの時刻 `T(k)` は、それより後ろにある有効な `tsa` ブロックの `genTime` に誤差を加えた値の最小値です。JSON の署名ごとの `tsa`、鍵のスナップショットの時刻、署名欄は、いずれもこの値を使用します（SPEC 4.6 節）。
- 撤回リストは署名済みリストの形式になりました。項目は、情報文字列が `mdsig-list` のコードフェンス 1つの中に、1行目を `type: revocation` として、1行に1つ `revoked: sha256:<16進数>` を書きます。取得は https のみ、10 MB までです（SPEC 5.10 節）。
- `zstd+base64:` の接頭辞の予約を削除しました。
- 合意の状態に `undetermined`（名簿やネットワークが必要だが利用できない。終了コード 3）と `unsupported`（検証者が知らない方式や属性を要件が使用している。終了コード 1）を追加しました。どちらも `ok` は `false` です。
- JSON（CLI_SPEC 5 節）：要件の属性は `attributes` オブジェクトにまとめました。欠けている要件は `early` に代えて `rejected: [{index, reason}]` を持ちます。`next`、`satisfied`、`declarations` を追加し、署名ごとに `display_name` を、`tsa` に `time` と `block` を追加しました。
- Go：`ParseRequire(value, declaredBy)` は `*ParsedRequire` を返します（版の引数は削除）。`Requirement`、`MissingRequirement`、`OrderViolation`、`Agreement` の形を変更しました。`CheckTSAToken` と `RequestTimestamp` は、`sig` のバイト列に代えて時刻証明の対象（チェーンの署名対象ペイロード）を受け取ります。`ResourceLoader` にはデコード済みのパスを渡します。TypeScript も同様に変更しました。

### 追加

- `require` の属性とパターン（SPEC 5.8.2 節、5.8.3 節）
  - `user_verified`：UP と UV がともに立っているパスキーの署名であることを求めます。文書がこれを要求している場合、署名ツールは認証器に利用者確認を求め、署名ページとの受け渡しは `user_verification=required` を渡します（CLI_SPEC 8 節）。
  - `member_of=<https の URL>`（署名済みの名簿文書、`type: members`）と `member_of=dns:<ドメイン>`（構成員ごとに `<label>._member._mdsig.<ドメイン>` に TXT レコード `v=mdsig1; m=<method:signer>` を設定）。
  - `tofu` の行の `pubkey=`。自分で選んだ名前だけで行を満たされないよう、付与を推奨します。
  - パターン `dns:*`、`dns:*.<ドメイン>`、`directory:*`、`directory:*@<ドメイン>`、`pgp:*`、`pgp:*@<ドメイン>`、`git-hosting:*`。パターンの行は宣言した署名者自身を数えません。
- `display_name`：署名者が申告する表示名。64 コードポイントまで（RFC 8266 の Nickname プロファイル）。表示側は検証済みの署名者と併記し、申告であることを示さなければなりません。
- 署名欄：本文の `<!-- mdsig:signatures -->` は、検証済みのブロックから作成した署名欄を表示側が描画する位置を示します。本文には何も書き込みません。署名欄は描画した本文の外で作成するので、本文の HTML で模倣できません（SPEC 5.11 節、9.5 節）。
- CLI のコマンド
  - `mdsig render <file>`：検証結果の要約、本文、署名欄を 1つの HTML ファイルに出力します。
  - `mdsig require explain <value>`：`require` の値の意味を段階ごとに表示します（`--json` も可）。
  - `mdsig member-record <method:signer> <domain>`：DNS の名簿に設定する TXT レコードを表示します。`--check` で問い合わせて確認します。
  - `mdsig sign --display-name`。
- ライブラリ：`signatureTable` / `SignatureTable`、`renderSignatureTableHtml` / `RenderSignatureTableHTML`、`explainRequire` / `ExplainRequire`、`memberRecordName` / `MemberRecordName`、`parseSignedList`、`CheckSignerID`、`CheckMemberRecord`。
- 旧記法へのヒント：位置で書いた役割、`order strict`、`step 1`、`scope` の `section:`、`resources` の旧順序、`tsa_token`、`v: 0.0.x` に対して、0.1 での書き方を示すメッセージを表示します。判定は変わりません。
- 本文がコードフェンスの途中で終わる文書（すべての署名ブロックがコードとして表示されてしまう）は、署名側が拒否し、検証側が警告します（SPEC 5.5 節）。
- `AGENT_COMMERCE.ja.md`（参考文書）：AI エージェント間で取引条件に署名し承諾する方法。LCP、x402、AP2、PACT との役割分担を示します。
- SPEC に、識別子の正規化、プライバシーに関する考慮事項（RFC 6973）、実装状況（RFC 7942）、IANA の登録簿、相互運用のための最低限の上限（`require` は 64 行、16 段階、名簿の URL は 8 種類、名簿の問い合わせは 256 回、リストは 10 万項目）を追加しました。
- `mdsig revoke` が `-m directory` を受け付けるようになりました。
- Go の依存関係：`github.com/yuin/goldmark`（CLI のみ。`mdsig render` で使用）と `golang.org/x/text`（ライブラリの直接の依存関係になりました。`display_name` の Unicode 正規化に使用）。

### 削除

- 形式 0.0.1、0.0.2、0.0.4 のブロックの検証と、それらにだけ適用していた規則（要件行の重複、1つのブロックで複数の行を満たすこと）。
- `tsa_url` と `tsa_token` のフィールド、`zstd+base64:` の予約。
- HTTP API の `POST /v1/tsa` の要求本文のキー `tsa_token`（`token` に改名）。
- 大文字小文字を区別しない署名者の比較（`sameSigner`）。

### 0.0.x からの移行

- 0.0.x で署名した文書には、このリリースで他の人が署名し直すことも連署することもできません。0.1 のブロックを追記しても、既存のブロックが `unsupported-version` のまま残るため、文書は検証に通りません。こうした文書は、引き続き mdsig v0.0.5 または `@mdsig/core` 0.0.5 で検証してください。
- そのような文書を 0.1 で引き継ぐ場合は、新しい文書を作成して署名します。たとえば旧ファイルを `resources` で固定します。
- `--require` を渡すスクリプトは新しい記法に変更してください：`--require "step"`、`--require "dns:example.com role=approver"`、`--require "step any=2"`、`--require "order mode=strict"`。値の読まれ方は `mdsig require explain` で確認できます。
- JSON 出力を読むスクリプトは、要件の属性を `attributes` から読み、`early` に代えて `rejected` を使用し、`undetermined` と `unsupported` を失敗として扱ってください。
- 撤回リストは、`mdsig-list` のコードフェンスの形式に書き換え、形式 0.1 で署名して公開し直してください。
