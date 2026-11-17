# `mdsig` コマンドラインインターフェース仕様

> **本書（日本語版）が正本です。** 英語版 [CLI_SPEC.md](CLI_SPEC.md) は参考訳で、内容に相違がある場合は本書が優先します。

[English](CLI_SPEC.md) · [形式仕様](SPEC.ja.md)

- **バージョン：** 0.0.3（ドラフト。形式のバージョンは 0.0.2）
- **ライセンス：** CC0 1.0 Universal（`LICENSE-SPEC` を参照）
- **形式仕様：** [SPEC.ja.md](SPEC.ja.md)

本書におけるキーワード「MUST」「MUST NOT」「REQUIRED」「SHOULD」「MAY」は、BCP 14 [RFC2119] [RFC8174] の記述に従って解釈する。

## 1. 名称

| 対象 | 名称 |
| --- | --- |
| バイナリ | `mdsig` |
| npm CLI パッケージ | `mdsig`（準備中） |
| コアライブラリ | `@md-signature/core`（npm では未公開） |
| Homebrew | `brew install SHIOZAKI-Shota/tap/mdsig` |
| Go | `go install mdsig.dev/cmd/mdsig@latest`（Go 1.26 以降） |
| winget | `winget install ShiozakiShota.mdsig`（準備中：リリースワークフローで生成するが、まだ公開していない） |
| Debian / RPM | `mdsig`（準備中：パッケージはリリースワークフローで生成するが、まだ公開していない） |

## 2. グローバルフラグ

| フラグ | 説明 |
| --- | --- |
| `--lang <code>` | UI 言語：`en` または `ja`。7 節を参照。 |
| `-h, --help` | ヘルプ。 |
| `--version` | バージョンを表示する。CLI のバージョンと、署名に用いる形式のバージョンを併記する（例：`mdsig version 0.0.3 (format 0.0.2)`）。CLI は SPEC が定める形式の `0.0.1` と `0.0.2` を検証し、`0.0.2` で署名する。 |

## 3. コマンド

### 3.1 `mdsig sign <file>`

Markdown ファイルに署名する。ファイルがすでに署名チェーンを持つ場合、新しい
署名は連署として追加される（SPEC 7 節）。

| フラグ | 既定 | 説明 |
| --- | --- | --- |
| `-m, --method <m>` | `git-hosting` | `git-hosting`、`dns`、`tofu`、または `pgp`。 |
| `-s, --signer <id>` | — | 必須（REQUIRED）。`github.com/alice`、`example.com`、`bob@laptop` など。`pgp` では省略でき、鍵のユーザ ID のメールアドレスから決定する（3.1.2 節）。 |
| `-k, --key <path>` | 自動 | OpenSSH Ed25519 秘密鍵ファイル。3.1.1 節を参照。 |
| `--selector <sel>` | — | `dns` のみ。 |
| `-u, --local-user <id>` | gpg の既定鍵 | `pgp` のみ。gpg に渡す鍵の指定（フィンガープリントまたはユーザ ID）。 |
| `--pgp-key <path>` | — | `pgp` のみ。ASCII armor 形式の OpenPGP 秘密鍵ファイル。指定した場合は gpg を使用せず、CLI が直接署名する。 |
| `-r, --role <role>` | — | `author`、`reviewer`、`approver`、`witness`、または任意の値。 |
| `--reason <text>` | — | 自由記述のテキスト。 |
| `--tsa [url]` | オフ | 時刻認証局（TSA）に RFC 3161 タイムスタンプを要求する。値を省略した場合は `http://ts.ssl.com` を使用する。 |
| `--tsa-root <file>` | — | タイムスタンプトークンの検証で、システムのトラストストアに加えて信頼するルート証明書（PEM または DER のファイル）。繰り返し指定できる。`--tsa` と併せて指定する。 |
| `--stdout` | オフ | ファイルを変更せず、署名済み文書を stdout に出力する。 |
| `--embed-key` | オフ | `dns` と `git-hosting` のみ。署名に用いた公開鍵を `pubkey` としてブロックに含める（SPEC 4.5 節）。鍵が削除された後も、署名が成立することを確認できる。他の方式で指定した場合は終了コード 2。 |
| `--force` | オフ | ファイルに署名ブロックがあり、その後に未署名の内容が続く場合でも署名する。この場合、ファイル全体が新しい文書として署名される。 |
| `--scope <ids>` | — | 指定したセクションのみに署名する。カンマ区切りで指定する：`--scope terms,fees`（SPEC 5.6 節）。 |
| `--require <line>` | — | `require` の値の 1 行を指定する。複数回指定でき、指定した順に行を並べる。要件行 `<method>:<signer>[ <role>]` のほか、段階行 `step <n>[ any <m>]` と順序行 `order pending\|guide\|strict` を使用できる（SPEC 5.8 節）。例：`--require "step 1" --require "dns:example.com approver" --require "step 2 any 2" …`。値全体を SPEC 5.8 節の規則で検査する。 |
| `--resource <ref>` | — | ファイル（文書からの相対パス）または `https://` URL を、その SHA-256 で固定する。複数回指定できる。URL は署名時に 1 回だけ取得する（SPEC 5.7 節）。 |
| `--auto-resources` | オフ | コードフェンスの外で `![..](..)` または `<img src>` によって参照されているすべてのローカル画像も固定する。 |
| `--expires <time>` | — | `YYYY-MM-DDTHH:MM:SSZ`、または現在からの期間：`30d`、`12h`（SPEC 5.9 節）。 |
| `--revocation-url <url>` | — | 署名者の撤回リストの `https://` URL（SPEC 5.9 節）。 |

動作：

- ファイルはアトミックに更新する（同一ディレクトリ内の一時ファイルに書き込んでからリネームする）。改行コード（LF または CRLF）は維持する。
- `--` または改行を含むフィールド値は、終了コード 2 で拒否しなければならない（MUST）。無効な `--scope`、`--require`、`--resource`、`--expires`、`--revocation-url` の値も同様に拒否しなければならない（MUST）。
- 存在しない `--resource` ファイルはファイルエラー（終了コード 4）、取得できない URL はネットワークエラー（終了コード 3）とする。
- パスキー（`webauthn-es256`）による署名は Web ブラウザ（たとえばデモ）で行う。CLI はそのような署名を検証するが、作成はしない。
- 成功時は stderr に 1 行を出力する：`Signed <file> (signature #N, <method> <signer>)`。

#### 3.1.1 鍵の自動検出

`-k` が指定されない場合（`pgp` 以外）：

1. ssh-agent が利用可能な場合（`SSH_AUTH_SOCK`、または Windows では OpenSSH エージェントのパイプ `\\.\pipe\openssh-ssh-agent`）、その `ssh-ed25519` 鍵を使用する。鍵が複数ある場合：`git-hosting` では、まず候補を `https://<signer>.keys` に掲載されている鍵に絞り込む（掲載されている鍵がある場合）。候補が複数残った場合、対話型ランチャーでは利用者に選択を求め、それ以外では最初の候補を使用する。
2. それ以外の場合は `~/.ssh/id_ed25519` を使用する。

パスフレーズで保護された鍵ファイルに対応しなければならない（MUST）。パスフレーズは TTY 上で入力を求めるか、stdin が TTY でない場合は `MDSIG_PASSPHRASE` から読み取る。

#### 3.1.2 `pgp` による署名

- `--pgp-key` がない場合、CLI は `gpg` を呼び出す：`gpg --detach-sign --digest-algo SHA256 [--local-user <id>]`。入力は署名対象ペイロード（SPEC 5.3 節）、出力はバイナリの署名である。これにより、gpg-agent やスマートカード上の鍵で署名できる。
- CLI は gpg の出力が SPEC 6.2 節の条件を満たすこと（署名パケット 1 個、種別 0x00、発行者フィンガープリントを含むことなど）を確認し、満たさない場合は終了コード 2 で失敗しなければならない（MUST）。`fpr` は出力された署名の発行者フィンガープリントから設定する。
- `fpr` は署名の前にブロックに記録する必要があるため、CLI は先に `gpg --list-secret-keys --with-colons` で署名に使用される鍵を特定する。署名後、実際の発行者フィンガープリントがそれと異なる場合は失敗する。
- `--pgp-key` がある場合、CLI はその秘密鍵で直接署名する。保護された鍵では、パスフレーズを TTY 上で入力させるか、stdin が TTY でない場合は `MDSIG_PGP_PASSPHRASE` から読み取る。対応する保護形式は、S2K iterated+salted と AES（CFB）、ならびに Argon2 による S2K と AEAD 保護である。
- `--signer` がない場合、鍵の有効なユーザ ID のメールアドレスを使用する。メールアドレスが複数ある場合、対話型ランチャーでは選択させ、それ以外では終了コード 2 で失敗する。
- `gpg` が見つからず `--pgp-key` もない場合は終了コード 2 とする。
- 秘密鍵とパスフレーズを保持したバイト列は、署名後に消去する。

### 3.2 `mdsig verify <file>...`

各ファイルのチェーン内のすべての署名を検証する（SPEC 5.4 節）。

| フラグ | 説明 |
| --- | --- |
| `--json` | JSON 形式の結果（5 節）を stdout に出力する。 |
| `-q, --quiet` | 出力なし。終了コードのみ。 |
| `--offline` | ネットワークを使用しない。ハッシュはすべてのブロックについて検査する。署名を検査できるのは、`tofu`（記録済みの鍵による）、`pgp`（ローカルの gpg 鍵束にある鍵による）、`tsa` ブロック、および `pubkey` を埋め込んだ `dns`・`git-hosting` のブロックである。`tsa_token` の CMS 署名と証明書チェーンもネットワークなしで検証する。埋め込まれた鍵で署名が成立しないブロックは invalid となる。それ以外のブロックは "not checked (offline)" と報告する。検査されなかったブロックが 1 つでもあるファイルは、終了コード 3 となる。リモートのリソースおよび撤回リストは取得しない。 |
| `--fetch-resources` | `https://` のリソースを取得し、そのハッシュを検査する。取得することで文書が検証されていることがサーバに伝わるため、既定ではオフである（SPEC 9.8 節）。 |
| `--no-revocation` | 撤回リストを取得しない。オンライン時は既定で取得し、取得できない、または信頼できない場合、そのブロックは unresolved（終了コード 3）となる。 |
| `--accept-new-key` | `tofu` の `signer` に記録済みの鍵と異なる鍵を受け入れ、記録を更新する。指定しない場合、鍵が変更されたブロックは invalid（code `key-changed`）となる。 |
| `--no-keyring` | `pgp` の鍵の取得で、ローカルの gpg 鍵束を使用しない（WKD と鍵サーバのみ）。 |
| `--keyserver <url>` | `pgp` の鍵を取得する鍵サーバの `https://` URL。既定：`https://keys.openpgp.org`。鍵サーバは検証者が選択するものであり、ブロックからは取得しない（SPEC 4.3 節）。メールアドレスを確認する鍵サーバを指定すること。 |
| `--tsa-root <file>` | タイムスタンプトークン（`tsa_token` と `tsa` ブロック）の検証で、システムのトラストストアに加えて信頼するルート証明書（PEM または DER のファイル）。PEM は複数の証明書を含んでよい。繰り返し指定できる。読み込めないファイルは使用方法の誤り（終了コード 2）となる。 |

`dns` の名前解決はシステムのリゾルバを使用すべきである（SHOULD）。`git-hosting` は
`https://<signer>.keys` を取得する。`pgp` は、`gpg` が利用可能であれば `gpg --export <fpr>` で
ローカルの鍵束から鍵を取得し、続いて WKD、鍵サーバの順に試みる（SPEC 4.3 節）。TOFU のバインディングは
`<user config dir>/mdsig/known_signers.json` に保存する。バインディングは、そのブロックの検証が
成功した後にのみ保存し、撤回リスト内のブロックからは保存しない。
ローカルのリソースは、検証対象ファイルのディレクトリを基準として常に検査する。シンボリックリンクを
解決した結果がそのディレクトリの外になるパス、通常ファイルでないもの、50 MB を超えるファイルは
読み込まない。URL（リソース、撤回リスト、`git-hosting` の鍵一覧、DoH、WKD、鍵サーバ）を取得する際、CLI はプライベート・ループバック・リンクローカルアドレス、および
50 MB（リソース）または 5 MB（撤回リスト）を超える応答を拒否しなければならない（MUST）。
実際に接続する先のアドレスを検査するため、これらのリクエストには HTTP プロキシを使用しない。

`--json` を指定しない場合の出力では、文書やサーバに由来する文字列（フィールドの値、ユーザ ID、
ファイル名など）に含まれる制御文字と書式文字を `\u{XXXX}` の形式で表示しなければならない（MUST）。
端末のエスケープシーケンスによって検証結果の表示を偽装されることを防止するためである。

人間向けの出力（例）：

```
docs/contract.md
  ✓ #1 author    github.com/alice     2026-11-16T09:00:00Z  git-hosting
      partial: terms, fees
      resources: ✓ ./diagram.png  - https://example.com/chart.png (not checked)
  ✓ #2 approver  example.com          2026-11-16T09:46:00Z  dns  ⏱ TSA 2026-11-16T09:46:02Z (SSL.com Timestamping Unit 2026 E1)
      TSA: imprint matched; TSA signature and certificate chain verified
  Verified: 2 signatures
  Agreement: pending (missing dns:partner.example witness)
```

`require` が段階を持つ場合、欠けている連署は段階ごとに表示する。順番より前に署名したため数えられなかった署名者には、その旨を付記する。
`order guide` の順序違反は警告として、`order strict` の順序違反は合意ステータス `violated` として表示する。

```
  Agreement: pending (step 2 needs 1 more of: git-hosting:github.com/carol reviewer, git-hosting:github.com/dave reviewer (after step 1))
  Agreement: violated (#2 git-hosting:github.com/bob reviewer signed for step 2 before step 1 was complete)
```

パスキーによる署名では、その `rp_id` も表示する。例：`passkey (rp_id mdsig.dev)`。
`pgp` による署名では、フィンガープリント、ユーザ ID、鍵の取得元、および署名パケットの作成時刻を表示する。
作成時刻は `ts` と同じく署名者の申告であり、TSA の時刻とは区別して表示する。

### 3.3 `mdsig inspect <file>`

ネットワークを使用せずに、チェーンと各ブロックの全フィールドを表示する。
各ブロックについて、`hash` が現在の内容と一致するかどうかも表示する。
ファイルを読み取れた場合は、ハッシュの結果にかかわらず 0 で終了する（検査には `verify` を使用する）。ただし、ファイルが有効な UTF-8 でない場合は終了コード 1 とする。

`--json` は次を出力する：

```json
{
  "file": "docs/contract.md",
  "body_lines": 14,
  "stray_marker_line": null,
  "warnings": [],
  "signatures": [
    { "index": 1, "line": 16, "fields": { "v": "0.0.2", "...": "..." }, "errors": [], "hash_ok": true, "computed_hash": "sha256:..." }
  ]
}
```

### 3.4 `mdsig keygen`

Ed25519 鍵ペアを生成する。

| フラグ | 説明 |
| --- | --- |
| `-o, --out <prefix>` | `<prefix>`（OpenSSH 秘密鍵、モード 0600）と `<prefix>.pub` を出力する。既定は `./mdsig_ed25519`。既存のファイルを上書きしてはならない（MUST NOT）。 |
| `-d, --domain <domain>` | このドメイン用の DNS TXT レコードも表示する。 |
| `--selector <sel>` | DNS レコード名に使用するセレクタ。`--domain` なしで指定した場合は終了コード 2。 |

出力（stdout）：

```
Private key: ./mdsig_ed25519
Public key:  ./mdsig_ed25519.pub

DNS TXT record:
  2026._mdsig.example.com. IN TXT "v=mdsig1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="

tofu pubkey:
  ed25519:11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=

SSH fingerprint (key_fp):
  SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8
```

`DNS TXT record` は `--domain` を指定した場合にのみ出力する（例は `-d example.com --selector 2026`）。

### 3.5 `mdsig revoke <file> --list <list.md>`

`<file>` 内の署名者自身の署名を撤回リストに追加し、そのリストに署名する（SPEC 5.9 節）。

| フラグ | 説明 |
| --- | --- |
| `--list <path>` | 必須（REQUIRED）。撤回リストのファイル。存在しない場合は作成する。 |
| `-m`、`-s`、`-k`、`--selector`、`-u`、`--pgp-key` | `sign` と同じ。撤回する署名（`method` と `signer` が同じもの）を選択し、リストに署名するために使用する。 |
| `--index <n>` | `<file>` の署名 `#n` のみを撤回する。既定：`<file>` 内で `method` と `signer` が同じすべての署名。 |

動作：

1. 選択した各ブロックについて撤回の識別子 `SHA-256(signed payload)`（SPEC 5.9 節）を計算し、リスト本文に `revoked: sha256:<hex>` の行を追加する（重複は追加しない）。
2. リストの古い署名チェーンを削除し、更新後のリストを指定された鍵で新しい文書として署名する。このコマンドによってリストに `revocation_url` を付与してはならない（MUST NOT）。
3. 署名鍵と撤回されたブロックの鍵を照合する。`tofu` の場合、署名鍵が撤回されたブロックの `pubkey` と一致しないときは、終了コード 2 で失敗し、リストを変更しない（検証者は、同一の鍵で署名された `tofu` のリストのみを信頼するため）。`git-hosting` の場合、署名鍵のフィンガープリントが撤回されたブロックの `key_fp` と異なるとき、`pgp` の場合、署名鍵の `fpr` が撤回されたブロックの `fpr` と異なるときは、警告を表示する（リストは `method` と `signer` で照合されるため、引き続き信頼される）。
4. リストを公開すべき場所、すなわち撤回されたブロックの `revocation_url` を表示する。それらが `revocation_url` を持たない場合は、検証者がリストを見つけられない旨の警告を表示する。

### 3.6 `mdsig serve`

文書の検証を HTTP で提供する。ブラウザなど、単体では検証できない項目（TSA 証明書チェーン、CORS により取得できない鍵など）を持つ検証者が、検証の全部または一部を委ねるために使用する。応答を受け取った側は、このサーバの判定を信頼することになる。

| フラグ | 既定 | 説明 |
| --- | --- | --- |
| `--listen <host:port>` | `127.0.0.1:8787` | 待ち受けるアドレス。ループバック以外を指定した場合は、stderr に警告を出力する。 |
| `--allow-origin <origin>` | — | ブラウザからの呼び出しを許可するオリジン（例：`https://example.org`）。繰り返し指定できる。 |
| `--offline` | オフ | ネットワークを使用しない（3.2 節と同じ）。 |
| `--fetch-resources` | オフ | `https://` のリソースを取得し、そのハッシュを検査する。 |
| `--no-revocation` | オフ | 撤回リストを取得しない。 |
| `--keyserver <url>` | `https://keys.openpgp.org` | `pgp` の鍵を取得する鍵サーバ。 |
| `--tsa-root <file>` | — | タイムスタンプトークンの検証で、システムのトラストストアに加えて信頼するルート証明書（3.2 節と同じ）。 |

エンドポイントは次のとおり。要求と応答の本文は JSON（UTF-8）である。

| メソッドとパス | 要求 | 応答 |
| --- | --- | --- |
| `POST /v1/verify` | `{ "document": "<文書の全文>" }` | 5 節の `files` の 1 要素から `file` を除いたオブジェクト |
| `POST /v1/tsa` | `{ "tsa_token": "<tsa_token の値>", "sig": "<署名バイト列の base64>" }` | 5 節の `tsa` オブジェクト |
| `GET /v1/health` | — | `{ "name", "version", "api": "v1" }` |

サーバは次の規則に従わなければならない（MUST）。

1. 要求ごとに独立して検証する。`tofu` の鍵の記録、ローカルの gpg 鍵束、サーバ上のファイルは使用しない。したがって、ローカルのリソースは "not checked" となる。
2. `Origin` ヘッダを持つ要求は、そのオリジンが `--allow-origin` で指定されている場合に限り処理し、それ以外は `403` で拒否する。`Origin` を持たない要求（サーバ間の呼び出し）は処理する。
3. `POST` の要求は `Content-Type: application/json` でなければならず、それ以外は `415` で拒否する。これにより、ブラウザからの要求は必ず CORS のプリフライトを経る。
4. 外部への取得は、プライベートアドレスなどへの接続を拒否する（3.2 節の検証と同じ制限）。
5. 本文は 4 MiB までとし、超過した要求は `413` で拒否する。同時に処理する要求数を制限し、超過した要求は `503` と `Retry-After` で拒否する。

検証の結果（invalid、unresolved など）は HTTP ステータス `200` の本文で返す。要求自体の誤りは `400`、`403`、`404`、`405`、`413`、`415` のいずれかと `{ "error": "<説明>" }` で返す。

2 つの検証者（例：ブラウザとこのサーバ）の結果を併用する場合、それぞれの判定は出所を区別して扱うべきである（SHOULD）。信頼するルート証明書が異なるため、`tsa.verified` は一致しないことがある。

### 3.7 `mdsig timestamp <file>`

ファイルの末尾に `tsa` ブロック（SPEC 4.6 節）を追記する。ブロックは、それより前のチェーン全体（以前のタイムスタンプを含む）を対象とするため、重ねて実行すると、そのままタイムスタンプの更新になる。署名ブロックを持たないファイル、および有効な UTF-8 でないファイルは、終了コード 1 で拒否する。

| フラグ | 既定 | 説明 |
| --- | --- | --- |
| `--tsa <url>` | `http://ts.ssl.com` | RFC 3161 の TSA の URL。 |
| `--hash <alg>` | `sha256` | `hash` と `messageImprint` のアルゴリズム。`sha256` または `sha512`。SHA-256 の危殆化に備えた更新には `sha512` を用いる。 |
| `--reason <text>` | — | 自由記述のテキスト。 |
| `--tsa-root <file>` | — | タイムスタンプトークンの検証で、システムのトラストストアに加えて信頼するルート証明書（3.2 節と同じ）。 |
| `--stdout` | オフ | ファイルを変更せず、結果を stdout に出力する。 |

TSA の応答は 3.1 節の `--tsa` と同じ手順で検証する。要求または検証に失敗した場合は終了コード 3 とし、ファイルは変更しない。

## 4. 終了コード

| コード | 意味 |
| --- | --- |
| 0 | 成功。`verify` の場合：すべての署名が有効。 |
| 1 | 検証失敗：ハッシュ不一致、不正な署名、形式不正のブロック、未対応のアルゴリズムまたは方式、タイムスタンプの不一致、署名なし、最後の署名の後に未署名の内容がある、ファイルが有効な UTF-8 でない、または合意ステータスが `violated`（`order strict` の順序違反、SPEC 5.8 節）。`sign` の場合：`--force` なしでの連署の拒否（ブロックの後に未署名の内容がある、または既存の署名が形式不正）。 |
| 2 | 使い方の誤り：未知のフラグ、引数の欠落、無効なフィールド値。 |
| 3 | ネットワークまたは公開鍵の解決のエラー、および `--offline` により検査されなかった署名がある場合（終了コード 1 となる失敗がない場合）。`sign` の場合：TSA リクエストの失敗（ファイルは変更されない）。 |
| 4 | ファイル I/O またはパーミッションのエラー。鍵ファイルが存在しない・読み取れない場合、および `keygen` が上書きを拒否した場合を含む。 |
| 5 | `verify` の場合：すべての署名は有効だが、`require` によって要求された連署が欠けている（合意ステータス `pending`、SPEC 5.8 節）。 |

複数のファイルを検証した場合、終了コードは全ファイルのうち最も重大なものとし、重大度の順序は 1 > 4 > 3 > 5 > 0 とする。

## 5. JSON 出力

`--json` の出力は、ロケールにかかわらず英語を使用し、次のスキーマに従わなければならない（MUST）：

```json
{
  "files": [
    {
      "file": "docs/contract.md",
      "ok": true,
      "error": null,
      "warnings": [],
      "agreement": {
        "status": "pending",
        "required": [{ "method": "dns", "signer": "example.com", "role": "approver", "declared_by": 1, "step": 1, "any": 1 }],
        "missing": [{ "method": "dns", "signer": "example.com", "role": "approver", "declared_by": 1, "step": 1, "any": 1, "need": 1 }],
        "violations": []
      },
      "signatures": [
        {
          "index": 1,
          "line": 12,
          "status": "valid",
          "code": null,
          "message": null,
          "fields": { "v": "0.0.2", "method": "git-hosting", "signer": "github.com/alice", "...": "..." },
          "hash_ok": true,
          "partial": { "sections": ["terms", "fees"] },
          "key_source": "https://github.com/alice.keys (SHA256:...)",
          "webauthn": null,
          "pgp": null,
          "resources": [
            { "ref": "./diagram.png", "status": "ok", "detail": null },
            { "ref": "https://example.com/chart.png", "status": "not-checked", "detail": "remote resources are fetched only on request" }
          ],
          "revocation": { "status": "not-revoked", "detail": null },
          "tsa": { "status": "ok", "verified": true, "signer": "SSL.com Timestamping Unit 2026 E1", "gen_time": "2026-11-16T09:46:02Z", "detail": "imprint matched; TSA signature verified (SSL.com Timestamping Unit 2026 E1)" },
          "warnings": []
        }
      ]
    }
  ]
}
```

ファイルの `ok` は、そのファイル単独で終了コード 0 または 5 となる場合に限り `true` となる。合意ステータスが `violated` のファイルは `false` となる。
両者は `agreement.status` によって区別する。`--offline` 指定時、検査されなかったブロックは
`status: "unresolved"` および `code: "offline"` を持ち、`ok` は false となる。

- `partial`、`webauthn`、`pgp`、`resources`、`revocation`、`tsa` は、該当しない場合は `null` となる。`webauthn` は `{ "rp_id", "origin", "user_verified" }` である。`pgp` は `{ "fpr", "uid", "key_alg", "key_source", "created" }` であり、`key_alg` は `rsa2048`、`ecdsa-p256`、`ed25519` などの文字列、`key_source` は `keyring`、`wkd`、`keyserver` のいずれか、`created` は署名パケットの作成時刻（RFC 3339）である。
- `agreement.status` は `none`、`complete`、`pending`、`violated` のいずれか。要件に役割がない場合、`role` は省略する。
- `required` と `missing` の各要素は、段階の番号 `step` と、その段階で必要な人数 `any` を持つ。段階行のない `require` では `step` は 1、`any` は要件行の件数となる。`missing` の各要素はさらに、その段階であと何件必要かを示す `need` を持ち、前の段階が成立していないため待機中の場合は `blocked_by`（その段階の番号）を、順番より前に署名したため数えられなかった場合は `early: true` を持つ。
- `violations` は順序違反の一覧であり、各要素は `{ "declared_by", "step", "index", "method", "signer", "role", "order" }` である。`index` は違反したブロックの番号、`order` は宣言の順序行の値（`guide` または `strict`）である。`order guide` の違反も一覧に含むが、合意ステータスには影響しない。
- リソースの `status` は `ok`、`mismatch`、`missing`、`unreachable`、`not-checked` のいずれか。撤回の `status` は `not-revoked`、`revoked`、`not-checked` のいずれか。
- `tsa` は `{ "status", "verified", "signer", "gen_time", "detail" }` である。`status` は `ok`、`mismatch`、`error` のいずれか。CLI は、トークンの CMS 署名と TSA 証明書チェーンを、システムのトラストストアおよび `--tsa-root` で指定したルート証明書に照らして検証する。`verified` は検証に成功した場合に限り `true` となり、`gen_time` と `signer`（TSA 証明書の名前）はその場合にのみ値を持つ。検証できないトークンは `status: "error"` となり、警告として表示する。

`status` は `valid`、`invalid`、`malformed`、`unresolved`、`unsupported` のいずれか。
`code` は `malformed`、`unknown-field`、`hash-mismatch`、
`bad-signature`、`scope-missing`、`resource-mismatch`、`resource-missing`、
`expired`、`revoked`、`key-changed`、`key-not-published`、`unsupported-version`、`unsupported-alg`、
`unsupported-hash`、`unsupported-method`、`network`、`not-found`、`offline`、
または `null` のいずれか。

## 6. 対話型ランチャー

TTY 上で引数なしで `mdsig` を実行すると、インラインの矢印キーメニューが起動する
（全画面の代替スクリーンバッファ UI は使用しない）。Go では `charmbracelet/huh` を、
JavaScript では `@clack/prompts` を使用する。

1. 操作を選択する：sign / verify / inspect / keygen。
2. **sign：** カレントディレクトリツリー内の `.md` ファイル（深さ 3 まで、`node_modules` およびドットディレクトリを除く）からファイルを選択するか、パスを入力する。すでに署名を持つファイルには `(N existing signatures → will co-sign)` と表示する。続いて、方式、署名者、役割（プリセット、自由記述、またはスキップ）、理由（任意）、TSA の有無を指定する。
3. **verify / inspect：** ファイルを選択し、結果を表示する。
4. **keygen：** 出力プレフィックスと、任意でドメイン／セレクタの入力を求める。
5. 最後に、同じ操作を行う 1 行のコマンドを表示し、利用者がフラグを覚えられるようにする。
6. 回答済みの質問は端末上に表示したまま保持しなければならない（MUST）（プロンプトライブラリが消去する場合はランチャーが再表示する）。これにより、セッション全体が操作記録として読める。
7. 方式の選択肢には `pgp`（OpenPGP 鍵を使用）を含める。`pgp` を選択した場合は、gpg の鍵（`gpg --list-secret-keys` の一覧）または鍵ファイルを選択させ、署名者 ID はユーザ ID から選択させる。

参考セッション（日本語 UI、`LANG=ja_JP.UTF-8`。各質問は回答中に表示される）：

   ```
   $ mdsig

     md-signature v0.0.3：対話モード

   ? 何を実行しますか？（矢印キーで選択 / Enter で決定）
     ❯ ✍️  文書に署名・連署する（sign）
       🔍  文書の署名を検証する（verify）
       📋  署名履歴・メタデータを表示する（inspect）
       🔑  新しい鍵ペアと DNS TXT レコードを生成する（keygen）

   ? 対象の Markdown ファイルは？（カレントディレクトリの .md 候補 / パス手入力可）
     ❯ README.md
       docs/contract.md  （1件の署名あり → 連署になります）
       [パスを手入力する...]

   ? 検証方式（method）を選択してください：
     ❯ git-hosting （GitHub / GitLab の公開鍵を使用）
       dns         （ドメインの TXT レコードを使用）
       tofu        （公開鍵を直接埋め込み・オフライン向け）
       pgp         （OpenPGP 鍵・gpg を使用）

   ? 署名者 ID（signer）を入力してください：
     > github.com/alice

   ? 役割（role）を選択してください：
     ❯ author   （作成者）
       reviewer （確認者）
       approver （承認者）
       witness  （立会人）
       [自由入力]
       [スキップ]

   ? 署名理由（reason）を入力してください（任意、Enter でスキップ）：
     > 初版確定

   ? RFC 3161 タイムスタンプ（TSA）を付与しますか？
     ❯ いいえ（軽量な通常署名）
       はい  （既定の無料 TSA：http://ts.ssl.com を使用）

   ✓ 署名を追記しました：docs/contract.md

   次回から同じ設定で素早く実行するには：
     $ mdsig sign docs/contract.md -m git-hosting -s github.com/alice -r author --reason "初版確定"
   ```

英語 UI も同じ構成とする（例："Choose a verification method (method):"、"Next time, run the same thing in one line:"）。

stdin または stdout が TTY でない場合、引数なしの `mdsig` は使用方法を stderr に出力し、コード 2 で終了しなければならない（MUST）。

## 7. 言語

UI 言語は次の順序で決定する：

1. `--lang <code>`
2. `MDSIG_LANG`
3. `LC_ALL`、`LC_MESSAGES`、`LANG` のうち最初に空でないもの（例：`ja_JP.UTF-8` → 日本語）。Windows では、いずれも設定されていない場合、ユーザの既定の UI 言語を使用してもよい（MAY）。
4. 英語。

本版で対応する言語：`en`、`ja`。JSON 出力、および stdout が TTY でない場合の出力は英語でなければならない（MUST）。
