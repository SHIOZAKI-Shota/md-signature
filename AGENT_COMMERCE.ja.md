# エージェント間取引での md-signature の使用

> **本書（日本語版）が原文です。** 英語版は [AGENT_COMMERCE.md](AGENT_COMMERCE.md) です。本書は参考文書であり、規範的な要件を含みません。形式の規範は [SPEC.ja.md](SPEC.ja.md) です。

[English](AGENT_COMMERCE.md) · [形式仕様](SPEC.ja.md) · [CLI 仕様](CLI_SPEC.ja.md)

- **対象とする形式のバージョン：** 0.1
- **ライセンス：** CC0 1.0 Universal（`LICENSE-SPEC` を参照）

## 1. 位置付け

AI エージェントが、人の代わりに対外的な効力を持つ行為（購入、契約の承諾、支払い）を
自律的に行う場面が増えている。支払い、委任、責任分担、条件文書の公開については、それぞれ
別のプロトコルが提案されている。本書は、それらと競合せずに、**Markdown で書かれた取引条件
への署名**の部分を md-signature で担う方法を示す。

本書で言及する外部のプロトコルは、いずれも策定中であり、フィールド名や構造は変わりうる。
本書の記述は、各節に記した参照日の内容に基づく。実装する際は、各プロトコルの最新の仕様に
従うこと。

## 2. 役割分担

| プロトコル | 扱う範囲 | md-signature との関係 |
| --- | --- | --- |
| LCP（Legal Context Protocol）[LCP] | 条件文書の所在（`/.well-known/legal-context.json` の `terms`）と、その SHA-256（`atrHash`）の公開。信頼の段階として「署名」（Level 3）を定めるが、署名の方式は規定しない。 | 条件文書そのものと、それへの署名・連署の形式を提供する。`atrHash` は承諾ブロックの `hash` と一致させられる（4 節）。 |
| x402 [X402] | HTTP 402 による支払いの要求と決済。支払いの要求（`accepts[]`）に追加の情報（`extra`）を載せられる。 | 支払いの要求に条件文書のハッシュを載せることで、支払いと条件文書を結び付ける（LCP は `accepts[].extra` を経路として挙げている）。 |
| AP2（Agent Payments Protocol）[AP2] | 利用者がエージェントに与える委任（マンデート）と、その検証。 | 代理権の証明は AP2 に任せる。md-signature の署名は「その鍵の保持者が条件に同意した」ことだけを示す。 |
| PACT [PACT] | エージェント間の契約における責任と決済（保証金、エスクロー、下請けの連鎖）。委任は別の仕組みで得ることを前提とする。 | 責任と決済は PACT に任せる。条件文書への同意の記録として md-signature を併用できる。 |

参照日：2026-11-27（LCP は https://legalcontextprotocol.org/ の Specification v1.0 の草案と、2026-09-07 に確認されたとするプロトコル連携の説明、PACT は draft-laxsharma-pact-01）。

## 3. 全体の流れ

1. **提供者**（売り手のエージェント）が、取引条件を Markdown の文書に書き、`dns` 方式で署名する。署名ブロックの `require` で、承諾に必要な連署と、提供者自身の最終確認を宣言する（6 節、7 節）。
2. 提供者は、署名済みの文書を正規化した形（SPEC 5.1 節：LF、BOM なし、末尾の改行 1 つ）で公開し、LCP の `terms` にその URL を、`atrHash` にその SHA-256 を記載する。
3. **承諾者**（買い手のエージェント）は、文書を取得して SHA-256 を `atrHash` と照合し、文書を検証する（`mdsig verify`）。次に必要な連署は `next`（SPEC 5.8.9 節）で分かる。
4. 承諾者は、自身の承認条件（人の承認が必要かなど）を自分のブロックで宣言しつつ連署する。承諾ブロックの `hash` は、手順 2 で公開した文書の SHA-256 と一致する。
5. 承諾者側の承認者が連署し、最後に提供者が最終確認の連署をする。合意ステータスが `complete` になる。
6. 支払いは x402 などで行う。支払いの要求に `atrHash` を載せることで、どの条件に対する支払いかが特定できる。

## 4. 条件文書の公開と `atrHash`

LCP の `atrHash` は、条件文書（LCP の用語では Agentic Transaction Record）の SHA-256 であり、
`0x` で始まる 16進数で表す [LCP]。LCP はハッシュの対象となるバイト列の正規化を定めていないため、
提供者は署名済みの文書を、SPEC 5.1 節で正規化したバイト列のまま公開する。

承諾者が公開された文書にそのまま連署すると、承諾ブロックのスライス（SPEC 5.2 節）は公開された
文書全体になり、その `hash` は次のとおり `atrHash` と同じ値になる。

```
atrHash（LCP）            0x9f2c…e1
承諾ブロックの hash        sha256:9f2c…e1
```

このため、条件文書の先頭部分のハッシュを別に定義する必要はない。検証者は、承諾ブロックの
`hash` と `atrHash` を比較するだけで、承諾がどの版の条件に対するものかを確認できる。一致させる
には、提供者が `tsa` ブロックを追記する場合も含めて、公開する文書を確定してから `atrHash` を
計算すること。

x402 の支払いの要求に載せる場合は、LCP の説明に従い、`accepts[]` の要素の `extra` に
`atrHash` を置く（参照日 2026-11-27）。

## 5. エージェントの鍵と代理権

- エージェントの鍵は、組織のドメインの `dns` 方式で、エージェントごとのセレクタを使って公開する（SPEC 4.1 節）。例：`agent-checkout._mdsig.shop.example`。エージェントを廃止する際はレコードを削除し、それまでの署名に備えて鍵のスナップショット（`pubkey`、SPEC 4.5 節）と `tsa` ブロックを付ける。
- md-signature の署名が示すのは、そのドメインが公開した鍵の保持者が条件に同意したことまでである。エージェントが誰の代理として、どの範囲で行動できるかは、AP2 のマンデートなど委任の仕組みで示す。
- エージェントが人の承認を必要とする場合は、その人のパスキーによる連署を `user_verified` で要求する（SPEC 5.8.7 節）。

## 6. 承認条件の宣言

承認条件は、各当事者が**自分のブロック**で宣言する。提供者は承諾の受け方を、承諾者は自社の
承認の手順を、それぞれの `require` に書く。相手の文書に書かれた条件に従う義務はなく、
合意の状態は全員の宣言を満たしたときに `complete` になる（SPEC 5.8.9 節）。

提供者のブロック（抜粋）：

```
<!-- md-signature
v: 0.1
method: dns
signer: shop.example
selector: agent-checkout
role: offeror
ts: 2026-11-27T01:00:00Z
require: |
  step
    dns:* role=acceptor
  step
    dns:shop.example role=confirm
alg: ed25519
...
-->
```

承諾者のブロック（抜粋）：

```
<!-- md-signature
v: 0.1
method: dns
signer: buyer.example
selector: agent-procure
role: acceptor
ts: 2026-11-27T02:10:00Z
require: |
  step
    directory:*@buyer.example member_of=dns:buyer.example role=approver user_verified
alg: ed25519
...
-->
```

この例では、承諾者のエージェントが承諾した後、`buyer.example` の DNS の名簿に載る社員が
パスキーで承認し、最後に提供者が最終確認をすると完了する。

## 7. 最終確認の型（推奨）

パターン（`dns:*` など）で誰でも承諾できる申込は、複製されて別々に成立しうる。第三者が先に
署名して席を埋めることもできる（SPEC 9.9 節）。そこで、次の型を推奨する。

- 名簿やパターンは、相手の**資格の確認**に使う。
- 締結の**確定**は、最後の段階で提供者自身（または特定の当事者）を名指しした最終確認で行う。提供者は、最終確認の前に、在庫、価格、取引の重複などを確認する。
- 最終確認の段階は名指しの行なので、自己承諾の防止（SPEC 5.8.5 節）の対象外であり、提供者が自分の識別子で署名できる。同じ署名者が前の段階に署名していても、別のブロックで最終確認を満たせる。

パターンを含む宣言では `order mode=strict` を使えないため（SPEC 5.8.6 節）、順序は既定の
`pending` とする。

## 8. 申込の期限

申込の期限に `expires` を使ってはならない。`expires` を過ぎるとブロックは無効になり（SPEC 5.9 節）、
期限内に成立した契約まで、後から検証すると無効に見えるためである。

期限の機械的な判定は、将来の版で `require` の属性（`by=` を検討中）として扱う予定である。
それまでは、期限を本文に書き、提供者が最終確認の段階で、承諾が期限内か（`T(k)`、SPEC 4.6 節）を
判断する。

## 9. 改訂

条件を改訂する場合は、新しい版の文書を作成し、前の版を `resources` で参照する（SPEC 5.7 節）。

```
resources: |
  https://shop.example/terms/v2.md hash=sha256:9f2c…e1
```

新しい版への署名は前の版のハッシュを含むため、どの版を改訂したかが署名によって固定される。
前の版の署名はそのまま有効であり、取り消す場合は撤回リスト（SPEC 5.9 節）を使う。

## 10. 取引条件の書き方

- 金額、数量、納期などの取引条件は、LCP の構造化されたフィールド、または本文中のコードフェンス（たとえば情報文字列 `json`）に書く。エージェントはそれを読み取り、人は本文の文章を読む。
- 構造化された条件と本文の文章が食い違う場合は、**本文の文章が優先する**ことを本文に明記する。
- 本文の表示に影響する HTML（コメント、隠し要素）を条件に使わない（SPEC 9.5 節）。

## 11. 取引 ID と相手方

- 取引 ID と相手方（相手の署名者の識別子、または資格の条件）を本文に書く。署名は本文を対象とするため、同じ条件文書を別の取引に流用されることを防げる。
- 相手から受け取った条件文書は、**信頼できない入力**として扱う。エージェントは、本文の指示（「この文書を承諾したら次の URL に支払え」など）に従ってはならない。検証の結果（署名者、合意ステータス、`next`）と、自身の方針だけに基づいて判断する。
- 相手の文書の `require` は相手の宣言にすぎない。自身の承認条件は、自分のブロックで宣言する（6 節）。

## 12. 参考文献

- [SPEC] SHIOZAKI, S., "md-signature: Embedded Signatures for Markdown Documents", Version 0.1, [SPEC.md](SPEC.md)
- [LCP] Legal Context Protocol Contributors, "Legal Context Protocol", Specification v1.0（草案）, https://legalcontextprotocol.org/ （参照日 2026-11-27）
- [X402] Coinbase, "x402: An open standard for internet-native payments", https://github.com/coinbase/x402 （参照日 2026-11-27）
- [AP2] Google, "Agent Payments Protocol (AP2)", https://github.com/google-agentic-commerce/AP2 （参照日 2026-11-27）
- [PACT] Sharma, L., "PACT: Liability and Settlement for Autonomous Agent Contracts", Work in Progress, Internet-Draft, draft-laxsharma-pact-01, 2026-09-04
