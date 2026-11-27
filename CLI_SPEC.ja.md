# `mdsig` コマンドラインインターフェース仕様

> **本書（日本語版）が正本です。** 英語版 [CLI_SPEC.md](CLI_SPEC.md) は参考訳で、内容に相違がある場合は本書が優先します。

[English](CLI_SPEC.md) · [形式仕様](SPEC.ja.md)

- **バージョン：** 0.1.1（ドラフト。形式のバージョンは 0.1）
- **ライセンス：** CC0 1.0 Universal（`LICENSE-SPEC` を参照）
- **形式仕様：** [SPEC.ja.md](SPEC.ja.md)

本書におけるキーワード「MUST」「MUST NOT」「REQUIRED」「SHOULD」「SHOULD NOT」「MAY」は、BCP 14 [RFC2119] [RFC8174] の記述に従って解釈する。

## 1. 名称

| 対象 | 名称 |
| --- | --- |
| バイナリ | `mdsig` |
| npm CLI パッケージ | `mdsig`（準備中） |
| コアライブラリ | `@mdsig/core`（npm） |
| Homebrew | `brew install SHIOZAKI-Shota/tap/mdsig` |
| Go | `go install mdsig.dev/cmd/mdsig@latest`（Go 1.26 以降） |
| winget | `winget install ShiozakiShota.mdsig`（準備中：リリースワークフローで生成するが、まだ公開していない） |
| Debian / RPM | `mdsig`（準備中：パッケージはリリースワークフローで生成するが、まだ公開していない） |

## 2. グローバルフラグ

| フラグ | 説明 |
| --- | --- |
| `--lang <code>` | UI 言語：`en` または `ja`。7 節を参照。 |
| `-h, --help` | ヘルプ。 |
| `--version` | バージョンを表示する。CLI のバージョンと、署名に用いる形式のバージョンを併記する（例：`mdsig version 0.1.1 (format 0.1)`）。CLI は SPEC が定める形式 `0.1` のみを検証し、`0.1` で署名する。`0.0.x` の文書は `unsupported-version` となり、CLI は v0.0.5 で検証するよう案内する。 |

## 3. コマンド

### 3.1 `mdsig sign <file>`

Markdown ファイルに署名する。ファイルがすでに署名チェーンを持つ場合、新しい
署名は連署として追加される（SPEC 7 節）。

| フラグ | 既定 | 説明 |
| --- | --- | --- |
| `-m, --method <m>` | `git-hosting` | `git-hosting`、`dns`、`tofu`、`pgp`、または `directory`。 |
| `-s, --signer <id>` | — | 必須（REQUIRED）。`github.com/alice`、`example.com`、`bob@laptop`、`alice@example.com` など。`tofu` 以外では ASCII の英大文字を小文字に変換して書き込み、SPEC 3.4 節の正規の形でない値は終了コード 2 とする。`pgp` では省略でき、鍵のユーザ ID のメールアドレスから決定する（3.1.2 節）。 |
| `-k, --key <path>` | 自動 | OpenSSH Ed25519 秘密鍵ファイル。3.1.1 節を参照。 |
| `--selector <sel>` | — | `dns` のみ。 |
| `-u, --local-user <id>` | gpg の既定鍵 | `pgp` のみ。gpg に渡す鍵の指定（フィンガープリントまたはユーザ ID）。 |
| `--pgp-key <path>` | — | `pgp` のみ。ASCII armor 形式の OpenPGP 秘密鍵ファイル。指定した場合は gpg を使用せず、CLI が直接署名する。 |
| `-r, --role <role>` | — | `author`、`reviewer`、`approver`、`witness`、または `[a-z0-9][a-z0-9._-]*` に一致する任意の語（SPEC 3.3 節）。 |
| `--display-name <name>` | — | 署名欄などに示す表示名（SPEC 3.3 節）。RFC 8266 の Nickname プロファイルの強制の処理を施して書き込む。64 コードポイントを超える値は終了コード 2。 |
| `--reason <text>` | — | 自由記述のテキスト。 |
| `--tsa [url]` | オフ | 署名ブロックの直後に `tsa` ブロック（SPEC 4.6 節）を追記する。値を省略した場合は `http://ts.ssl.com` を使用する。手順は 3.7 節の `mdsig timestamp` と同じである。 |
| `--tsa-root <file>` | — | タイムスタンプトークンの検証で、システムのトラストストアに加えて信頼するルート証明書（PEM または DER のファイル）。繰り返し指定できる。`--tsa` と併せて指定する。 |
| `--stdout` | オフ | ファイルを変更せず、署名済み文書を stdout に出力する。 |
| `--embed-key` | オフ | `dns`、`git-hosting`、`directory` のみ。署名に用いた公開鍵を `pubkey` としてブロックに含める（SPEC 4.5 節）。鍵が削除された後も、署名が成立することを確認できる。`directory` では既定で含める。他の方式で指定した場合は終了コード 2。 |
| `--no-embed-key` | オフ | `directory` のみ。`pubkey` を含めない。他の方式で指定した場合は終了コード 2。 |
| `--force` | オフ | ファイルに署名ブロックがあり、その後に未署名の内容が続く場合でも署名する。この場合、ファイル全体が新しい文書として署名される。 |
| `--scope <ids>` | — | 指定したセクションのみに署名する。カンマ区切りまたは繰り返しで指定する：`--scope terms,fees`（SPEC 5.6 節）。`scope` は 1 行に 1 つの ID を書くリストとして出力する。 |
| `--require <line>` | — | `require` の値の 1 行を指定する。複数回指定でき、指定した順に行を並べる。要件行 `<method>:<signer\|pattern>[ <attr>…]`（属性は `role=`、`user_verified`、`member_of=`、`pubkey=`）のほか、段階行 `step[ any=<m>]` と順序行 `order mode=pending\|guide\|strict` を使用できる（SPEC 5.8 節）。例：`--require "step" --require "dns:example.com role=approver" --require "step any=2" --require "directory:*@example.com member_of=dns:example.com"`。各行の行頭の空白は除き、段階行の下の要件行は 2 つのスペースで字下げして出力する。値全体を SPEC 5.8 節の規則で検査し、形式不正の場合は終了コード 2 とする。 |
| `--resource <ref>` | — | ファイル（文書からの相対パス）または `https://` URL を、その SHA-256 で固定する。複数回指定できる。URL は署名時に 1 回だけ取得する。ローカルのパスは先頭の `./` を除き、空白などをパーセントエンコードして `<ref> hash=sha256:<hex>` の行として出力する（SPEC 5.7 節）。 |
| `--auto-resources` | オフ | コードフェンスの外で `![..](..)` または `<img src>` によって参照されているすべてのローカル画像も固定する。 |
| `--expires <time>` | — | `YYYY-MM-DDTHH:MM:SSZ`、または現在からの期間：`30d`、`12h`（SPEC 5.9 節）。 |
| `--revocation-url <url>` | — | 署名者の撤回リストの `https://` URL（SPEC 5.9 節）。 |

動作：

- ファイルはアトミックに更新する（同一ディレクトリ内の一時ファイルに書き込んでからリネームする）。改行コード（LF または CRLF）は維持する。
- `-->`、`--!>`、`<!--`、改行、または SPEC 3.2 節の規則 4 が禁止する文字を含むフィールド値は、終了コード 2 で拒否しなければならない（MUST）。無効な `--signer`、`--role`、`--display-name`、`--scope`、`--require`、`--resource`、`--expires`、`--revocation-url` の値も同様に拒否しなければならない（MUST）。
- 本文がコードフェンスの途中で終わる文書（SPEC 5.5 節）への署名は、終了コード 1 で拒否する。`--force` でも署名しない。
- `--tsa` の要求または検証に失敗した場合は終了コード 3 とし、ファイルは変更しない（署名ブロックも追記しない）。
- 存在しない `--resource` ファイルはファイルエラー（終了コード 4）、取得できない URL はネットワークエラー（終了コード 3）とする。
- パスキー（`webauthn-es256`）による署名は Web ブラウザ（たとえばデモ）で行う。CLI はそのような署名を検証するが、作成はしない。ローカルのツールが署名ページに署名を依頼する手順は 8 節で定める。
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
| `--offline` | ネットワークを使用しない。ハッシュはすべてのブロックについて検査する。署名を検査できるのは、`tofu`（記録済みの鍵による）、`pgp`（ローカルの gpg 鍵束にある鍵による）、`tsa` ブロック（CMS 署名と証明書チェーンをネットワークなしで検証する）、および `pubkey` を埋め込んだ `dns`・`git-hosting`・`directory` のブロックである。埋め込まれた鍵で署名が成立しないブロックは invalid となる。それ以外のブロックは "not checked (offline)" と報告する。検査されなかったブロックが 1 つでもあるファイルは、終了コード 3 となる。リモートのリソース、撤回リスト、名簿は取得せず、名簿に依存する合意は `undetermined` となる。 |
| `--fetch-resources` | `https://` のリソースを取得し、そのハッシュを検査する。取得することで文書が検証されていることがサーバに伝わるため、既定ではオフである（SPEC 9.8 節）。 |
| `--no-revocation` | 撤回リストを取得しない。オンライン時は既定で取得し、取得できない、または信頼できない場合、そのブロックは unresolved（終了コード 3）となる。 |
| `--accept-new-key` | `tofu` の `signer` に記録済みの鍵と異なる鍵を受け入れ、記録を更新する。指定しない場合、鍵が変更されたブロックは invalid（code `key-changed`）となる。 |
| `--no-keyring` | `pgp` の鍵の取得で、ローカルの gpg 鍵束を使用しない（WKD と鍵サーバのみ）。 |
| `--keyserver <url>` | `pgp` の鍵を取得する鍵サーバの `https://` URL。既定：`https://keys.openpgp.org`。鍵サーバは検証者が選択するものであり、ブロックからは取得しない（SPEC 4.3 節）。メールアドレスを確認する鍵サーバを指定すること。 |
| `--key-directory <url>` | `directory` の鍵の取得で、この実行に限り信頼する鍵ディレクトリの `https://` URL。繰り返し指定できる。既定の一覧と `mdsig directory trust`（3.8 節）で追加したディレクトリの後に問い合わせる。`signer` のドメインが `_mdsig` の `dir` でディレクトリを指定している場合は、そのディレクトリのみを使用する（SPEC 4.7 節）。`https://` でない URL は終了コード 2。 |
| `--tsa-root <file>` | `tsa` ブロックのタイムスタンプトークンの検証で、システムのトラストストアに加えて信頼するルート証明書（PEM または DER のファイル）。PEM は複数の証明書を含んでよい。繰り返し指定できる。読み込めないファイルは使用方法の誤り（終了コード 2）となる。 |

`dns` の名前解決はシステムのリゾルバを使用すべきである（SHOULD）。`git-hosting` は
`https://<signer>.keys` を取得する。`pgp` は、`gpg` が利用可能であれば `gpg --export <fpr>` で
ローカルの鍵束から鍵を取得し、続いて WKD、鍵サーバの順に試みる（SPEC 4.3 節）。`directory` は、`signer` のドメインの `_mdsig` の `dir`、なければ信頼する鍵ディレクトリの一覧（既定の `https://keys.mdsig.dev`、`<user config dir>/mdsig/key_directories.json`、`--key-directory` の順）から鍵を取得する（SPEC 4.7 節）。`member_of` の名簿は、オンライン時は常に取得する。https の名簿は SPEC 5.10 節のとおり取得して検証し、DNS の名簿はシステムのリゾルバで問い合わせる（SPEC 5.8.8 節）。TOFU のバインディングは
`<user config dir>/mdsig/known_signers.json` に保存する。バインディングは、そのブロックの検証が
成功した後にのみ保存し、撤回リスト内のブロックからは保存しない。
ローカルのリソースは、検証対象ファイルのディレクトリを基準として常に検査する。シンボリックリンクを
解決した結果がそのディレクトリの外になるパス、通常ファイルでないもの、50 MB を超えるファイルは
読み込まない。URL（リソース、撤回リスト、名簿、`git-hosting` の鍵一覧、DoH、WKD、鍵サーバ）を取得する際、CLI はプライベート・ループバック・リンクローカルアドレス、および
50 MB（リソース）または 10 MB（撤回リストと名簿）を超える応答を拒否しなければならない（MUST）。
実際に接続する先のアドレスを検査するため、これらのリクエストには HTTP プロキシを使用しない。

`--json` を指定しない場合の出力では、文書やサーバに由来する文字列（フィールドの値、ユーザ ID、
ファイル名など）に含まれる制御文字と書式文字を `\u{XXXX}` の形式で表示しなければならない（MUST）。
端末のエスケープシーケンスによって検証結果の表示を偽装されることを防止するためである。

人間向けの出力（例）：

```
docs/contract.md
  ✓ #1 author    github.com/alice     2026-11-16T09:00:00Z  git-hosting  "Alice Example" (declared)
      partial: terms, fees
      resources: ✓ diagram.png  - https://example.com/chart.png (not checked)
  ✓ #2 approver  example.com          2026-11-16T09:46:00Z  dns  ⏱ by 2026-11-16T09:46:03Z (#3)
  ✓ #3 tsa       http://ts.ssl.com    TSA 2026-11-16T09:46:02Z ±1s (SSL.com Timestamping Unit 2026 E1)
  Verified: 3 signatures
  Agreement: pending
    next: step 2 needs 2 more (any 2 of 3)
      git-hosting:github.com/bob role=reviewer
      git-hosting:github.com/carol role=reviewer
      git-hosting:github.com/dave role=reviewer
```

`display_name` は、検証済みの署名者の識別子の後に `(declared)`（日本語 UI では「（申告）」）を付けて表示する。
`⏱` は SPEC 4.6 節の `T(k)` であり、それを与えた `tsa` ブロックの番号を併記する。

合意が成立していない場合は、`next`（SPEC 5.8.9 節）の内容を、段階の構造に合わせて字下げして表示する。
数えられなかった署名には、その理由（`rejected`）を付記する。`order mode=guide` の順序違反は警告として、
`order mode=strict` の順序違反は合意ステータス `violated` として表示する。名簿を取得できないなどの理由で
判定できない場合は `undetermined` と、その原因を表示する。

```
  Agreement: pending
    next: step 2 needs 1 more (after step 1)
      git-hosting:github.com/carol role=reviewer
      git-hosting:github.com/dave role=reviewer
    not counted: #2 git-hosting:github.com/bob (early: signed before step 1 was complete)
  Agreement: violated (#2 git-hosting:github.com/bob signed for step 2 before step 1 was complete)
  Agreement: undetermined (roster https://example.org/members.md could not be fetched)
```

`require` の値が SPEC 5.8 節の旧記法（`0.0.x` の段階行、位置で書いた役割など）や、字下げと段階の構造が
一致しない書き方を含む場合、CLI は改善の手がかりを警告として表示してよい（MAY）。判定は変えない。
同様に、ハッシュ不一致が空白の違いだけによると推定される場合は、SPEC 付録 B を案内してよい（MAY）。

パスキーによる署名では、その `rp_id` と、利用者確認（UV）の有無、同期されたパスキーかどうか（BS）も表示する。
例：`passkey (rp_id mdsig.dev, user verified, synced)`。
`pgp` による署名では、フィンガープリント、ユーザ ID、鍵の取得元、および署名パケットの作成時刻を表示する。
作成時刻は `ts` と同じく署名者の申告であり、`T(k)` とは区別して表示する。

本文がコードフェンスの途中で終わる場合（SPEC 5.5 節）と、署名欄のマーカーが複数ある場合（SPEC 5.11 節）は、
警告を表示する。

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
    { "index": 1, "line": 16, "fields": { "v": "0.1", "...": "..." }, "errors": [], "hash_ok": true, "computed_hash": "sha256:..." }
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

1. 選択した各ブロックについて撤回の識別子 `SHA-256(signed payload)`（SPEC 5.9 節）を計算し、リスト本文の `mdsig-list` のフェンス（SPEC 5.10 節）に `revoked: sha256:<hex>` の行を追加する（重複は追加しない）。リストが存在しない場合は、`type: revocation` の行を持つフェンスを含む本文を作成する。既存のリストのフェンスが SPEC 5.10 節の形式に従わない場合は、終了コード 1 で失敗し、リストを変更しない。
2. リストの古い署名チェーンを削除し、更新後のリストを指定された鍵で新しい文書として署名する。このコマンドによってリストに `revocation_url` を付与してはならない（MUST NOT）。
3. 署名鍵と撤回されたブロックの鍵を照合する。`tofu` の場合、署名鍵が撤回されたブロックの `pubkey` と一致しないときは、終了コード 2 で失敗し、リストを変更しない（検証者は、同一の鍵で署名された `tofu` のリストのみを信頼するため）。`git-hosting` の場合、署名鍵のフィンガープリントが撤回されたブロックの `key_fp` と異なるとき、`pgp` の場合、署名鍵の `fpr` が撤回されたブロックの `fpr` と異なるときは、警告を表示する（リストは署名者の識別子で照合されるため、引き続き信頼される）。
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
| `--key-directory <url>` | — | `directory` の鍵の取得で信頼する鍵ディレクトリ（3.2 節と同じ）。 |
| `--tsa-root <file>` | — | タイムスタンプトークンの検証で、システムのトラストストアに加えて信頼するルート証明書（3.2 節と同じ）。 |

エンドポイントは次のとおり。要求と応答の本文は JSON（UTF-8）である。

| メソッドとパス | 要求 | 応答 |
| --- | --- | --- |
| `POST /v1/verify` | `{ "document": "<文書の全文>" }` | 5 節の `files` の 1 要素から `file` を除いたオブジェクト |
| `POST /v1/tsa` | `{ "token": "<tsa ブロックの sig の値>", "sig": "<tsa ブロックの署名対象ペイロードの base64>", "hash": "<sha256 または sha512>" }`。`hash` は `tsa` ブロックの `hash` のアルゴリズムであり、省略時は `sha256`。サーバは `sig` をデコードしたバイト列のダイジェストを `messageImprint` と照合する | 5 節の `tsa` オブジェクト |
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

TSA の応答は、追記する `tsa` ブロックとして SPEC 4.6 節の検証者の手順で検証し、有効とならない場合は追記しない。要求または検証に失敗した場合は終了コード 3 とし、ファイルは変更しない。

### 3.8 `mdsig directory`

鍵ディレクトリ（SPEC 4.7 節）を扱う。

| サブコマンド | 説明 |
| --- | --- |
| `trust add <url>` | 鍵ディレクトリを信頼する一覧に追加する。一覧は `<user config dir>/mdsig/key_directories.json` に保存し、`verify` と `serve` が既定の一覧の後に使用する。`https://` でない URL は終了コード 2。 |
| `trust remove <url>` | 一覧から削除する。一覧にない URL は終了コード 2。既定の一覧は削除できない。 |
| `trust list` | 既定の一覧と、追加した一覧を出力する。 |
| `register --email <addr>` | Ed25519 鍵をメールアドレスに結び付けて公開するよう、鍵ディレクトリに依頼する。鍵は 3.1.1 節の手順で検出し（`-k` で指定可）、ディレクトリが発行したチャレンジに署名して所持を示す。鍵が公開されるのは、ディレクトリから届く確認メールのリンクを開いた後である。`--label <name>` を指定すると、確認メールに表示する鍵の名前をディレクトリに送信する。 |
| `remove --email <addr>` | そのアドレスの鍵（`--key <base64>` を指定した場合はその鍵のみ）の削除を依頼する。削除は確認メールで完了する。 |

`register` と `remove` の送信先は、`--directory <url>` を指定した場合はその URL、指定しない場合は、アドレスのドメインが `_mdsig` の `dir` で指定するディレクトリ、それもなければ `https://keys.mdsig.dev` とする。依頼が受け付けられない場合は終了コード 3。

`mdsig sign -m directory` は、署名の後に、検証者の既定の手順で署名に用いた鍵が見つかるかを確認し、見つからない場合は stderr に警告を出力する。署名は取り消さない。

### 3.9 `mdsig known`

`tofu` の鍵の記録（SPEC 4.4 節）を扱う。記録は `<user config dir>/mdsig/known_signers.json` に保存する。

| サブコマンド | 説明 |
| --- | --- |
| `list` | 記録済みの `signer` と、鍵のフィンガープリントを出力する。`--json` を指定した場合は `[{ "signer", "key", "fingerprint" }]` を出力する。 |
| `remove <signer>` | その `signer` の記録を削除する。記録にない `signer` は終了コード 2。削除した `signer` の鍵は、次の検証で初めて検出した鍵として扱われる。 |

`known_signers.json` は、`signer` をキー、`pubkey` の値（`<key-type>:<base64>`）を値とする JSON オブジェクトである。このファイルを読み書きするツール（CLI、デスクトップアプリなど）は、次に従わなければならない（MUST）。

1. 書き込みはアトミックに行い（一時ファイルに書き込んでからリネームする）、ファイルのパーミッションは所有者のみが読み書きできるものとする。
2. 書き込みの直前にファイルを読み直し、自身が変更していない記録を保持する。
3. 記録は、ブロックの検証が成功した後、または利用者が鍵を明示的に信頼した後にのみ追加し、撤回リスト内のブロックからは追加しない。

鍵のフィンガープリントは、`ed25519` の鍵では OpenSSH 形式（`SHA256:` と、SSH の公開鍵ブロブの SHA-256 をパディングなしの base64 で表したもの。SPEC 4.2 節の `key_fp` と同じ）、それ以外の鍵では `SHA256:` と、`pubkey` の base64 をデコードしたバイト列の SHA-256 をパディングなしの base64 で表したものとする。

利用者が操作するツールは、初めて検出した鍵を記録する前に、フィンガープリントを示して利用者の確認を求めてもよい（MAY）（SPEC 4.4 節）。`mdsig verify` は確認を求めず、検証が成功した時点で記録する。

### 3.10 `mdsig render <file>`

文書を検証し、本文と署名欄を 1 つの HTML ファイルとして出力する（SPEC 5.11 節、9.5 節）。

| フラグ | 既定 | 説明 |
| --- | --- | --- |
| `--lang <code>` | UI 言語（7 節） | 署名欄と検証結果の表示に使う言語。`ja` または `en`。 |
| `-o, --out <path>` | stdout | 出力先の HTML ファイル。既存のファイルは上書きする。 |
| `--offline`、`--fetch-resources`、`--no-revocation`、`--keyserver`、`--key-directory`、`--tsa-root` | — | `verify` と同じ。 |

出力は次に従わなければならない（MUST）。

1. 検証結果の要約（文書の状態と合意ステータス）を、本文の外側の、本文の内容が入り込めない領域に置く。
2. 本文は、スクリプト、イベント属性、フォームの要素、`style` 属性を除いて描画する。
3. 署名欄は、本文を描画した DOM の外で作成する。本文は一度だけ描画する。本文に署名欄のマーカーがある場合は、最初のマーカー（コードフェンスの外のもの）を含む最上位のブロックの直後に署名欄を置く。マーカーが単独のブロックである場合、そのブロックは出力しない。マーカーがない場合は、本文の後に置く。本文のソースをマーカーで分割して別々に描画することはしない（リンク参照定義や HTML ブロックがマーカーをまたぐため）。

署名欄は、チェーンの各ブロック（`tsa` ブロックを除く）について 1 行を持つ。

| 列 | 内容 |
| --- | --- |
| 番号 | チェーンでの位置（`#1` など）。 |
| 表示名 | `display_name`。「（申告）」または "(declared)" を添える。ない場合は空欄。 |
| 署名者 | 署名者の識別子（`method:signer`）。 |
| 確認方法 | 身元の確認方法。例：`dns` は「DNS TXT（example.com）」、`directory` は鍵を返したディレクトリと、`dir` と信頼する一覧のどちらで選択したか、`tofu` は「埋め込み鍵（初回信頼）」とフィンガープリント。 |
| 役割 | `role`。 |
| 申告時刻 | `ts`。 |
| 時刻証明 | `T(k)`（SPEC 4.6 節）。定まらない場合は空欄。 |
| 利用者確認 | `webauthn-es256` の場合、UV の有無。 |
| 状態 | `valid` などの状態。部分署名の場合はその旨と、セクションの ID。 |

合意が成立していない場合は、続けて `next`（5 節）から作った未署名の行を置く。未署名の行は、
段階の番号、必要な人数、候補の要件行（対象と属性）を示し、署名欄の上で署名済みの行と区別する。

終了コードは、同じファイルに対する `verify` と同じとする。検証に失敗した文書も、その結果を示した
HTML を出力する。出力先に書き込めない場合は終了コード 4 とする。

### 3.11 `mdsig require explain <value>`

`require` の値（SPEC 5.8 節）を検査し、その意味を文章で表示する。署名の前に要件を確認するために使う。

- `<value>` は、改行を含む `require` の値全体である。`-` を指定した場合は stdin から読む。
- 出力は、段階ごとに字下げした説明である（UI 言語は 7 節による）。例：

  ```
  $ mdsig require explain "$(printf 'step\n  dns:example.com role=approver\nstep any=2\n  dns:*.example.com member_of=dns:example.com')"
  order: pending (signatures before their turn are not counted)
  step 1: all of
    dns:example.com with role approver
  step 2: any 2 different signers of
    any subdomain of example.com (not example.com itself), on the DNS roster of example.com
  ```

- 警告（`tofu` の行に `pubkey=` がない、字下げと段階の構造が一致しない、など）は stderr に出力する。
- `--json` を指定した場合は、`{ "order", "steps": [{ "step", "any", "lines": [{ "line", "method", "signer", "pattern", "attributes" }] }], "warnings" }` を出力する。各キーの意味は 5 節の `required` と同じである。
- 値が形式不正の場合は、該当する行と理由を表示して終了コード 2 とする。値に未知の方式や属性がある場合は、その旨を警告して終了コード 0 とする。

### 3.12 `mdsig member-record <id> <domain>`

DNS の名簿（SPEC 5.8.8 節）で、署名者の識別子 `<id>`（`method:signer`）を `<domain>` の構成員として示すために設定すべき TXT レコードを表示する。

```
$ mdsig member-record directory:alice@example.com example.com
<52 文字のラベル>._member._mdsig.example.com. IN TXT "v=mdsig1; m=directory:alice@example.com"
```

- `<id>` の `signer` は、`tofu` 以外では ASCII の英大文字を小文字にそろえてから使う。SPEC 3.4 節の正規の形でない `<id>`、パターン、および `ldh-domain` でない `<domain>` は、終了コード 2 とする。
- このコマンドはネットワークを使用しない。`--check` を指定した場合は、システムのリゾルバでレコードを問い合わせ、SPEC 5.8.8 節の分類（構成員である、構成員でない、判定不能）を表示する。判定不能の場合は終了コード 3、構成員でない場合は終了コード 1 とする。

## 4. 終了コード

| コード | 意味 |
| --- | --- |
| 0 | 成功。`verify` の場合：すべての署名が有効。 |
| 1 | 検証失敗：ハッシュ不一致、不正な署名、形式不正のブロック、未対応のアルゴリズムまたは方式、タイムスタンプの不一致、署名なし、最後の署名の後に未署名の内容がある、ファイルが有効な UTF-8 でない、または合意ステータスが `violated`（`order mode=strict` の順序違反）か `unsupported`（未知の方式や属性。SPEC 5.8.9 節）。`sign` の場合：`--force` なしでの連署の拒否（ブロックの後に未署名の内容がある、または既存の署名が形式不正）、および本文がコードフェンスの途中で終わる文書への署名の拒否。 |
| 2 | 使い方の誤り：未知のフラグ、引数の欠落、無効なフィールド値。 |
| 3 | ネットワークまたは公開鍵の解決のエラー、`--offline` により検査されなかった署名がある場合、および合意ステータスが `undetermined` の場合（いずれも終了コード 1 となる失敗がない場合）。`sign` と `timestamp` の場合：TSA リクエストの失敗（ファイルは変更されない）。 |
| 4 | ファイル I/O またはパーミッションのエラー。鍵ファイルが存在しない・読み取れない場合、および `keygen` が上書きを拒否した場合を含む。 |
| 5 | `verify` の場合：すべての署名は有効だが、`require` によって要求された連署が欠けている（合意ステータス `pending`、SPEC 5.8.9 節）。 |
| 130 | 対話型の入力（ランチャーなど）を利用者が中断した。 |

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
        "required": [
          { "declared_by": 1, "step": 1, "any": null, "line": 2, "method": "dns", "signer": "example.com", "pattern": false,
            "attributes": { "role": "approver" } },
          { "declared_by": 1, "step": 2, "any": 2, "line": 4, "method": "git-hosting", "signer": "github.com/bob", "pattern": false,
            "attributes": { "role": "reviewer" } }
        ],
        "missing": [
          { "declared_by": 1, "step": 2, "any": 2, "line": 4, "method": "git-hosting", "signer": "github.com/bob", "pattern": false,
            "attributes": { "role": "reviewer" }, "need": 2,
            "rejected": [{ "index": 2, "reason": "early" }] }
        ],
        "next": [
          { "declared_by": 1, "step": 2, "need": 2,
            "candidates": [{ "declared_by": 1, "step": 2, "any": 2, "line": 4, "method": "git-hosting", "signer": "github.com/bob", "pattern": false, "attributes": { "role": "reviewer" } }],
            "later": [{ "step": 3, "need": 1, "lines": [] }] }
        ],
        "violations": [],
        "satisfied": [{ "declared_by": 1, "step": 1, "line": 2, "index": 2 }],
        "declarations": [{ "declared_by": 1, "order": "pending", "status": "pending", "detail": null }]
      },
      "signatures": [
        {
          "index": 1,
          "line": 12,
          "status": "valid",
          "code": null,
          "message": null,
          "fields": { "v": "0.1", "method": "git-hosting", "signer": "github.com/alice", "...": "..." },
          "display_name": "Alice Example",
          "hash_ok": true,
          "partial": { "sections": ["terms", "fees"] },
          "key_source": "https://github.com/alice.keys (SHA256:...)",
          "tofu": null,
          "webauthn": null,
          "pgp": null,
          "resources": [
            { "ref": "diagram.png", "status": "ok", "detail": null },
            { "ref": "https://example.com/chart.png", "status": "not-checked", "detail": "remote resources are fetched only on request" }
          ],
          "revocation": { "status": "not-revoked", "detail": null },
          "tsa": { "status": "ok", "verified": true, "signer": "SSL.com Timestamping Unit 2026 E1", "gen_time": "2026-11-16T09:46:02Z",
                   "detail": "covered by tsa block #3", "time": "2026-11-16T09:46:03Z", "block": 3 },
          "warnings": []
        }
      ]
    }
  ]
}
```

ファイルの `ok` は、そのファイル単独で終了コード 0 または 5 となる場合に限り `true` となる。合意ステータスが
`violated`、`unsupported`、`undetermined` のファイルは `false` となる。`--offline` 指定時、検査されなかったブロックは
`status: "unresolved"` および `code: "offline"` を持ち、`ok` は false となる。

**署名ごとの値。**

- `partial`、`tofu`、`webauthn`、`pgp`、`resources`、`revocation`、`tsa` は、該当しない場合は `null` となる。`display_name` は、ブロックが `display_name` を持たない場合は `null` となる。値は署名者の申告であり、表示する際は SPEC 3.3 節に従う。
- `tofu` は `{ "status", "fingerprint" }` であり、`tofu` のブロックを鍵の記録（3.9 節）と照合した場合に値を持つ。`status` は `known`（記録と一致）、`new`（初めて検出した鍵）、`replaced`（`--accept-new-key` により記録を置き換えた）のいずれか、`fingerprint` は 3.9 節の鍵のフィンガープリントである。
- `webauthn` は `{ "rp_id", "origin", "user_verified", "backup_eligible", "backed_up" }` である。後の 3 つは `authenticatorData` のフラグ UV、BE、BS（SPEC 6.1 節）の真偽値である。
- `pgp` は `{ "fpr", "uid", "key_alg", "key_source", "created" }` であり、`key_alg` は `rsa2048`、`ecdsa-p256`、`ed25519` などの文字列、`key_source` は `keyring`、`wkd`、`keyserver` のいずれか、`created` は署名パケットの作成時刻（RFC 3339）である。
- リソースの `status` は `ok`、`mismatch`、`missing`、`unreachable`、`not-checked` のいずれか。撤回の `status` は `not-revoked`、`revoked`、`not-checked` のいずれか。
- `tsa` は `{ "status", "verified", "signer", "gen_time", "detail", "time", "block" }` である。`time` はそのブロックの時刻 `T(k)`（SPEC 4.6 節）、`block` はそれを与えた `tsa` ブロックの番号であり、`T(k)` が定まらない場合はともに `null` となる。
  - 署名ブロックでは、`tsa` は `T(k)` が定まる場合に限り値を持ち、`signer`（TSA 証明書の名前）と `gen_time` は `block` が示す `tsa` ブロックのトークンの値である。
  - `method` が `tsa` のブロックでは、`status`、`verified`、`signer`、`gen_time`、`detail` はそのブロック自身のトークンの検査結果である。`status` は `ok`、`mismatch`、`error` のいずれか。CLI は、トークンの CMS 署名と TSA 証明書チェーンを、システムのトラストストアおよび `--tsa-root` で指定したルート証明書に照らして検証する。`verified` は検証に成功した場合に限り `true` となり、`gen_time` と `signer` はその場合にのみ値を持つ。

`status` は `valid`、`invalid`、`malformed`、`unresolved`、`unsupported` のいずれか。
`code` は `malformed`、`unknown-field`、`hash-mismatch`、
`bad-signature`、`scope-missing`、`resource-mismatch`、`resource-missing`、
`expired`、`revoked`、`key-changed`、`key-not-published`、`unsupported-version`、`unsupported-alg`、
`unsupported-hash`、`unsupported-method`、`network`、`not-found`、`offline`、
または `null` のいずれか。

**合意。**

- `agreement.status` は `none`、`complete`、`pending`、`undetermined`、`violated`、`unsupported` のいずれか（SPEC 5.8.9 節）。
- `required` は、すべての宣言のすべての要件行である。各要素は、宣言したブロックの番号 `declared_by`、段階の番号 `step`、その段階の `any` の値（`any` のない段階では `null`）、`require` の値の中での行番号 `line`（1 から数え、順序行と段階行も数える）、対象の `method` と `signer`（パターンの行では `*.example.com` などのパターン）、パターンの行かどうかを示す `pattern`、および属性 `attributes` を持つ。
- `attributes` は、属性の名前をキーとするオブジェクトである。値を取る属性は文字列、値を取らない属性（`user_verified`）は `true` とする。将来の属性も同じオブジェクトに入るため、JSON の形は変わらない。
- `satisfied` は、報告する割り当て（SPEC 5.8.5 節）の一覧であり、各要素は `{ "declared_by", "step", "line", "index" }` である。`index` は、その要件行に割り当てられたブロックの番号である。
- `missing` は、成立していない段階の、割り当てのない要件行である。`required` の要素のキーに加えて、その段階であと何者必要かを示す `need` と、数えられなかったブロックの一覧 `rejected` を持ち、前の段階が成立していないため待機中の場合はその段階の番号 `blocked_by` を持つ。`rejected` の各要素は `{ "index", "reason" }` であり、`reason` は SPEC 5.8.9 節の語彙（`early`、`blocked`、`not-member`、`roster-unavailable`、`not-user-verified`、`key-mismatch`、`self`、`scoped`、`unresolved`、`not-valid`）である。この語彙は署名の `code` とは別のものである。
- `next` は、成立していない宣言ごとに 1 つの要素を持つ。各要素は、成立していない最初の段階の番号 `step`、あと何者必要か `need`、候補の要件行 `candidates`（`required` の要素）、および後に続く段階の概要 `later`（`{ "step", "need", "lines" }` の一覧）を持つ。
- `violations` は順序違反の一覧であり、各要素は `{ "declared_by", "step", "line", "index", "method", "signer", "order" }` である。`index` は違反したブロックの番号、`line` は割り当てられた要件行、`order` は宣言の順序行の値（`guide` または `strict`）である。`order mode=guide` の違反も一覧に含むが、合意ステータスには影響しない。
- `declarations` は宣言ごとの状態であり、各要素は `{ "declared_by", "order", "status", "detail", "steps" }` である。`status` は `agreement.status` と同じ語彙（`none` を除く）である。`detail` は、`unsupported` の場合は理解できなかった方式または属性を、`undetermined` の場合はその原因（オフライン、通信の失敗、名簿を取得できない、SPEC 5.8.10 節の上限）を示し、それ以外は `null` となる。
- `steps` は宣言の段階ごとの状態であり、宣言を評価しなかった場合（`unsupported`、SPEC 5.8.10 節の上限）は空の配列となる。各要素は、段階の番号 `step`、`any` の値（`any` のない段階では `null`）、その段階に必要な署名者数 `need`、数えられた署名者数 `count`、成立しているかを示す `complete`、前の段階が成立していないため待機中の場合はその段階の番号 `blocked_by`（それ以外は `null`）、および要件行ごとの割り当て `lines`（`{ "line", "blocks" }` の一覧。`blocks` はその行に割り当てられたブロックの番号を昇順に並べたもの）を持つ。`lines` は宣言の順に並び、`blocks` の内容は `satisfied` と一致する。

## 6. 対話型ランチャー

TTY 上で引数なしで `mdsig` を実行すると、インラインの矢印キーメニューが起動する
（全画面の代替スクリーンバッファ UI は使用しない）。Go では `charmbracelet/huh` を、
JavaScript では `@clack/prompts` を使用する。

1. 操作を選択する：sign / verify / inspect / keygen。
2. **sign：** カレントディレクトリツリー内の `.md` ファイル（深さ 3 まで、`node_modules` およびドットディレクトリを除く）からファイルを選択するか、パスを入力する。すでに署名を持つファイルには `(N existing signatures → will co-sign)` と表示する。続いて、方式、署名者、表示名（任意）、役割（プリセット、`[a-z0-9][a-z0-9._-]*` の自由記述、またはスキップ）、理由（任意）、`tsa` ブロックの追記の有無を指定する。署名者と役割は入力の時点で SPEC 3.3 節と 3.4 節の規則で検査し、誤りがあれば再入力を求める。文書に満たされていない `require` がある場合は、`next` の候補を表示する。
3. **verify / inspect：** ファイルを選択し、結果を表示する。
4. **keygen：** 出力プレフィックスと、任意でドメイン／セレクタの入力を求める。
5. 最後に、同じ操作を行う 1 行のコマンドを表示し、利用者がフラグを覚えられるようにする。
6. 回答済みの質問は端末上に表示したまま保持しなければならない（MUST）（プロンプトライブラリが消去する場合はランチャーが再表示する）。これにより、セッション全体が操作記録として読める。
7. 方式の選択肢には `pgp`（OpenPGP 鍵を使用）を含める。`pgp` を選択した場合は、gpg の鍵（`gpg --list-secret-keys` の一覧）または鍵ファイルを選択させ、署名者 ID はユーザ ID から選択させる。

参考セッション（日本語 UI、`LANG=ja_JP.UTF-8`。各質問は回答中に表示される）：

   ```
   $ mdsig

     md-signature v0.1.1：対話モード

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

   ? 表示名（display_name）を入力してください（任意、Enter でスキップ）：
     > Alice Example

   ? 役割（role）を選択してください：
     ❯ author   （作成者）
       reviewer （確認者）
       approver （承認者）
       witness  （立会人）
       [自由入力]
       [スキップ]

   ? 署名理由（reason）を入力してください（任意、Enter でスキップ）：
     > 初版確定

   ? 署名の後に RFC 3161 タイムスタンプ（tsa ブロック）を追記しますか？
     ❯ いいえ（軽量な通常署名）
       はい  （既定の無料 TSA：http://ts.ssl.com を使用）

   ✓ 署名を追記しました：docs/contract.md

   次回から同じ設定で素早く実行するには：
     $ mdsig sign docs/contract.md -m git-hosting -s github.com/alice --display-name "Alice Example" -r author --reason "初版確定"
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

## 8. 署名ページとの受け渡し

パスキー（SPEC 6.1 節）は、登録時の RP ID のページでのみ使用できる。ローカルで動作するツール（CLI、デスクトップアプリなど）は、パスキーによる署名を、利用者の Web ブラウザで開く**署名ページ**に依頼する。本節は、その要求と応答を定める。署名ページは誰でも運用でき、本節は特定の運用者やドメインを定めない。

### 8.1 署名ページの選択

- 署名ページは利用者が選択する。ツールは、署名ページの URL を文書から取得してはならない（MUST NOT）。
- 署名ページの URL は `https://` でなければならない（MUST）。
- 鍵ディレクトリ（SPEC 4.7 節）は、`<dir>/sign` に署名ページを置いてよい（MAY）。その署名ページは、ディレクトリのホスト名を RP ID とするパスキーを扱う。
- ツールは、信頼する鍵ディレクトリ（3.8 節）の署名ページを選択肢として示し、利用者が任意の署名ページを追加・削除できるようにすべきである（SHOULD）。
- 受け渡しで作成する署名の `method` は `tofu`、`dns`、`directory` のいずれかである（`git-hosting` と `pgp` はパスキーに対応しない）。

### 8.2 要求

ツールは、署名ページの URL に次のクエリパラメータを付けて、既定の Web ブラウザで開く。値は UTF-8 で、パーセントエンコードする。

| パラメータ | 内容 |
| --- | --- |
| `v` | `1`。 |
| `op` | `key`（パスキーの選択）または `sign`（署名）。 |
| `return` | 応答の送信先 URL（8.4 節）。 |
| `state` | ツールが生成した 128 ビット以上の乱数を base64url で表したもの。応答にそのまま含まれる。 |
| `payload` | `op=sign` の場合のみ。署名対象ペイロード（SPEC 5.3 節）の base64url。 |
| `credential` | `op=sign` の場合に任意。使用するパスキーの credential ID（base64url）。 |
| `name` | 任意。文書の表示名。ブロックの `display_name`（署名者の表示名、SPEC 3.3 節）とは別のものである。 |
| `user_verification` | `op=sign` の場合に任意。`required` を指定すると、署名ページは利用者確認（UV）を伴うアサーションを求める。ツールは、署名する文書に満たされていない `user_verified` の要件行（SPEC 5.8.7 節）がある場合、これを指定すべきである（SHOULD）。 |

ツールは、文書の本文を送信してはならない（MUST NOT）。署名ページが受け取るのは、署名対象ペイロード（フィールドとハッシュ）のみである。

### 8.3 署名ページの処理

`op=key` の場合、署名ページは利用者にパスキーを選択または作成させ、その公開鍵と credential ID を返す。

`op=sign` の場合、署名ページは次をすべて満たす場合に限り署名しなければならない（MUST）。

1. `payload` が `md-signature/v1` の行で始まり、SPEC 5.3 節の形式として解析できる。
2. `alg` が `webauthn-es256` であり、`rp_id` が署名ページの RP ID と一致する。
3. `pubkey` を含む場合、それが使用するパスキーの公開鍵と一致する。
4. 署名の前に、ペイロードのフィールド（少なくとも `method`、`signer`、`display_name`、`role`、`reason`、`expires`、`scope`、`require`、`hash`）、`name`（ツールの申告であることを示して）、`return` の送信先を表示し、利用者の明示的な操作を得る。

署名ページは、チャレンジを SHA-256(payload) としてアサーションを取得し（SPEC 6.1 節）、8.4 節の応答を返す。`user_verification=required` の要求では、`userVerification` に `"required"` を指定してアサーションを取得し、得られた `authenticatorData` の UV フラグ（ビット 2）が立っていない場合は、完了を拒否して `error=unsupported` を返さなければならない（MUST）。署名ページは、ペイロードや署名を自身のサーバに送信すべきではない（SHOULD NOT）。

### 8.4 応答

`return` は、`http` と `https` 以外のスキーム（たとえば `mdsig+fountain-pen:`）の URL、または `http://127.0.0.1:<port>/` もしくは `http://[::1]:<port>/` で始まる URL でなければならない（MUST）。署名ページは、それ以外の `return` を持つ要求を拒否しなければならない（MUST）。Web 上のサイトが署名ページを経由して、利用者のパスキーによる署名を受け取ることを防ぐためである。

署名ページは、`return` に次のクエリパラメータを付けて遷移する。値は base64url（`rp_id` と `error` を除く）である。

| パラメータ | 内容 |
| --- | --- |
| `v`、`state` | `1` と、要求の `state`。 |
| `rp_id`、`key`、`credential` | `op=key` の場合。RP ID、`es256` の公開鍵（SPEC 4.1 節の `p` と同じ鍵のバイト列）、credential ID。 |
| `authenticator_data`、`client_data`、`sig` | `op=sign` の場合。アサーションの `authenticatorData`、`clientDataJSON`、DER 形式の署名。 |
| `error` | 失敗した場合。`cancelled`、`invalid-request`、`unsupported` のいずれか。 |

### 8.5 ツールの処理

- ツールは、未完了の要求の `state` に一致する応答に限り受け付けなければならず（MUST）、各 `state` を 1 回だけ使用しなければならない（MUST）。一致しない応答は無視する。
- `op=key` の応答では、`rp_id` が署名ページのホスト名と一致するか、その上位のドメインであることを確認する。
- `op=sign` の応答では、要求したペイロードと `op=key` で得た公開鍵に対して、SPEC 6.1 節の手順で署名を検証しなければならず（MUST）、成立した場合に限りブロックを追記しなければならない（MUST）。
- `user_verification=required` を指定した要求への応答で、`authenticatorData` の UV フラグが立っていない場合、ツールはブロックを追記してはならない（MUST NOT）。
- 要求から応答までの間に文書が変更された場合、ツールは応答を破棄しなければならない（MUST）。
