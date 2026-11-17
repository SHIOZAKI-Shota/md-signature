# `mdsig` Command-Line Interface Specification

- **Version:** 0.0.1 (draft)
- **License:** CC0 1.0 Universal (see `LICENSE-SPEC`)
- **Format specification:** [SPEC.md](SPEC.md)
- **Normative text:** [日本語 (CLI_SPEC.ja.md)](CLI_SPEC.ja.md). This English version is an informative translation. If they differ, the Japanese text prevails.

The key words "MUST", "MUST NOT", "REQUIRED", "SHOULD", and "MAY" are to be interpreted as described in BCP 14 [RFC2119] [RFC8174].

## 1. Names

| Thing | Name |
| --- | --- |
| Binary | `mdsig` |
| npm CLI package | `mdsig` |
| Core library | `@md-signature/core` |
| Homebrew | `brew install SHIOZAKI-Shota/tap/mdsig` |
| winget | `winget install mdsig` |
| Debian / RPM | `mdsig` |

## 2. Global flags

| Flag | Description |
| --- | --- |
| `--lang <code>` | UI language: `en` or `ja`. See Section 7. |
| `-h, --help` | Help. |
| `--version` | Print version. Shows the CLI version together with the version of the format used for signing (for example `mdsig version 0.0.3 (format 0.0.2)`). The CLI verifies the formats `0.0.1` and `0.0.2` defined by SPEC and signs with `0.0.2`. |

## 3. Commands

### 3.1 `mdsig sign <file>`

Signs a Markdown file. If the file already has a signature chain, the new
signature is appended as a co-signature (SPEC Section 7).

| Flag | Default | Description |
| --- | --- | --- |
| `-m, --method <m>` | `git-hosting` | `git-hosting`, `dns`, `tofu`, or `pgp`. |
| `-s, --signer <id>` | — | REQUIRED. `github.com/alice`, `example.com`, `bob@laptop`, ... With `pgp` it can be omitted; it is then taken from the email address in the key's User ID (3.1.2). |
| `-k, --key <path>` | auto | OpenSSH Ed25519 private key file. See 3.1.1. |
| `--selector <sel>` | — | `dns` only. |
| `-u, --local-user <id>` | gpg default key | `pgp` only. The key to pass to gpg (a fingerprint or User ID). |
| `--pgp-key <path>` | — | `pgp` only. An ASCII-armored OpenPGP private key file. When given, gpg is not used and the CLI signs directly. |
| `-r, --role <role>` | — | `author`, `reviewer`, `approver`, `witness`, or any value. |
| `--reason <text>` | — | Free text. |
| `--tsa [url]` | off | Request an RFC 3161 timestamp. Without a value, uses `http://ts.ssl.com`. |
| `--tsa-root <file>` | — | Root certificate (PEM or DER file) to trust, in addition to the system trust store, when checking the TSA's response. Repeatable. Used together with `--tsa`. |
| `--stdout` | off | Write the signed document to stdout instead of changing the file. |
| `--force` | off | Sign even if the file has a signature block followed by unsigned content. The whole file is then signed as a new document. |
| `--scope <ids>` | — | Sign only these sections, comma-separated: `--scope terms,fees` (SPEC 5.6). |
| `--require <line>` | — | One line of the `require` value. Repeatable; lines keep the order given. Besides requirement lines `<method>:<signer>[ <role>]`, step lines `step <n>[ any <m>]` and order lines `order pending\|guide\|strict` are accepted (SPEC 5.8). Example: `--require "step 1" --require "dns:example.com approver" --require "step 2 any 2" …`. The whole value is checked against the rules of SPEC 5.8. |
| `--resource <ref>` | — | Bind a file (path relative to the document) or an `https://` URL by its SHA-256. Repeatable. URLs are fetched once, at signing time (SPEC 5.7). |
| `--auto-resources` | off | Also bind every local image referenced by `![..](..)` or `<img src>` outside code fences. |
| `--expires <time>` | — | `YYYY-MM-DDTHH:MM:SSZ`, or a duration from now: `30d`, `12h` (SPEC 5.9). |
| `--revocation-url <url>` | — | `https://` URL of the signer's revocation list (SPEC 5.9). |

Behavior:

- The file is updated atomically (write to a temporary file in the same directory, then rename). Line endings (LF or CRLF) are preserved.
- Field values containing `--` or line breaks MUST be rejected with exit code 2. So MUST invalid `--scope`, `--require`, `--resource`, `--expires`, and `--revocation-url` values.
- A `--resource` file that does not exist is a file error (exit code 4); a URL that cannot be fetched is a network error (exit code 3).
- Passkey (`webauthn-es256`) signing happens in a web browser (for example the playground). The CLI verifies such signatures but does not create them.
- On success, print one line to stderr: `Signed <file> (signature #N, <method> <signer>)`.

#### 3.1.1 Key discovery

When `-k` is not given (methods other than `pgp`):

1. If an SSH agent is available (`SSH_AUTH_SOCK`, or on Windows the OpenSSH agent pipe `\\.\pipe\openssh-ssh-agent`), use its `ssh-ed25519` keys. If there is more than one: with `git-hosting`, first narrow the candidates to the keys that appear in `https://<signer>.keys` (if any do). If more than one candidate remains, ask in the interactive launcher; otherwise use the first candidate.
2. Otherwise use `~/.ssh/id_ed25519`.

Passphrase-protected key files MUST be supported: prompt for the passphrase on the TTY, or read it from `MDSIG_PASSPHRASE` when stdin is not a TTY.

#### 3.1.2 Signing with `pgp`

- Without `--pgp-key`, the CLI calls `gpg`: `gpg --detach-sign --digest-algo SHA256 [--local-user <id>]`. The input is the signed payload (SPEC 5.3) and the output is a binary signature. This allows signing with keys held by gpg-agent or on a smartcard.
- The CLI MUST check that the gpg output satisfies the conditions in SPEC 6.2 (exactly one signature packet, type 0x00, an Issuer Fingerprint present, and so on), and fail with exit code 2 if it does not. `fpr` is set from the Issuer Fingerprint of the output signature.
- Because `fpr` has to be recorded in the block before signing, the CLI first identifies the key that will be used with `gpg --list-secret-keys --with-colons`. If the actual Issuer Fingerprint after signing differs from it, the CLI fails.
- With `--pgp-key`, the CLI signs directly with that private key. For a protected key, it prompts for the passphrase on the TTY, or reads it from `MDSIG_PGP_PASSPHRASE` when stdin is not a TTY. Supported protection is S2K iterated+salted with AES (CFB), as well as Argon2 S2K and AEAD protection.
- Without `--signer`, the email address of a valid User ID of the key is used. If there are several email addresses, the interactive launcher asks the user to choose; otherwise the CLI fails with exit code 2.
- If `gpg` is not found and `--pgp-key` is not given, the exit code is 2.
- Byte buffers that held the private key or passphrase are wiped after signing.

### 3.2 `mdsig verify <file>...`

Verifies every signature in each file's chain (SPEC Section 5.4).

| Flag | Description |
| --- | --- |
| `--json` | Print a JSON result (Section 5) to stdout. |
| `-q, --quiet` | No output; exit code only. |
| `--offline` | Do not use the network. Hashes are checked for every block; signatures are checked only for `tofu`. Blocks that need the network are reported as "not checked (offline)". A file with any block that was not checked gives exit code 3. Remote resources and revocation lists are not fetched. |
| `--fetch-resources` | Fetch `https://` resources and check their hashes. Off by default, because fetching tells the server that the document is being verified (SPEC 9.8). |
| `--no-revocation` | Do not fetch revocation lists. They are fetched by default when online; if a list cannot be fetched or is not trusted, the block is unresolved (exit code 3). |
| `--accept-new-key` | Accept a `tofu` key that differs from the one stored for its `signer`, and replace the stored binding. Without it, a block whose key changed is invalid (code `key-changed`). |
| `--no-keyring` | Do not use the local gpg keyring when looking up `pgp` keys (WKD and keyserver only). |
| `--keyserver <url>` | `https://` URL of the keyserver for `pgp` key lookups. Default: `https://keys.openpgp.org`. The verifier chooses the keyserver; it is never taken from the block (SPEC 4.3). Name one that confirms email addresses. |
| `--tsa-root <file>` | Root certificate (PEM or DER file) to trust, in addition to the system trust store, when verifying a `tsa_token`. A PEM file may hold several certificates. Repeatable. A file that cannot be read is a usage error (exit code 2). |

`dns` lookups SHOULD use the system resolver. `git-hosting` fetches
`https://<signer>.keys`. `pgp` looks in the local keyring with
`gpg --export <fpr>` if `gpg` is available, then in WKD, then on the keyserver
(SPEC 4.3). TOFU bindings are stored in
`<user config dir>/mdsig/known_signers.json`. A binding is stored only after
the block has verified, and never from a block inside a revocation list.
Local resources are always checked, relative to the directory of the file
being verified. A path that leaves that directory after symbolic links are
resolved, anything that is not a regular file, and a file larger than 50 MB
are not read. When fetching URLs (resources, revocation lists, `git-hosting`
key lists, DoH, WKD, and the keyserver), the CLI
MUST refuse private, loopback, and link-local addresses, and responses larger
than 50 MB (resources) or 5 MB (revocation lists). It checks the address that
it actually connects to, and therefore does not use HTTP proxies for these
requests.

In output without `--json`, the CLI MUST show control and format characters in
text that comes from the document or from a server (field values, User IDs,
file names, and so on) as `\u{XXXX}`. This prevents terminal escape sequences
from forging the displayed result.

Human-readable output (example):

```
docs/contract.md
  ✓ #1 author    github.com/alice     2026-11-16T09:00:00Z  git-hosting
      partial: terms, fees
      resources: ✓ ./diagram.png  - https://example.com/chart.png (not checked)
  ✓ #2 approver  example.com          2026-11-16T09:46:00Z  dns  ⏱ TSA 2026-11-16T09:46:02Z
  Verified: 2 signatures
  Agreement: pending — missing dns:partner.example witness
```

When `require` has steps, missing co-signatures are shown per step, and a signer whose signature did not count because it came before its turn is marked as such.
An `order guide` violation is shown as a warning, and an `order strict` violation as the agreement status `violated`.

```
  Agreement: pending — step 2 needs 1 more of: git-hosting:github.com/carol reviewer, git-hosting:github.com/dave reviewer (after step 1)
  Agreement: violated — #2 git-hosting:github.com/bob reviewer signed for step 2 before step 1 was complete
```

A passkey signature also shows its `rp_id`, for example `passkey (rp_id mdsig.dev)`.
A `pgp` signature shows the fingerprint, the User ID, where the key was found, and the creation time of the signature packet.
The creation time is claimed by the signer, like `ts`, and is shown separately from the TSA time.

### 3.3 `mdsig inspect <file>`

Prints the chain and all fields of each block without using the network.
For each block it also prints whether `hash` matches the current content.
Exits 0 when the file could be read, whatever the hash results (use `verify` to check).

`--json` prints:

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

Generates an Ed25519 key pair.

| Flag | Description |
| --- | --- |
| `-o, --out <prefix>` | Write `<prefix>` (OpenSSH private key, mode 0600) and `<prefix>.pub`. Default `./mdsig_ed25519`. MUST NOT overwrite existing files. |
| `-d, --domain <domain>` | Also print the DNS TXT record for this domain. |
| `--selector <sel>` | Selector for the DNS record name. |

Output (stdout):

```
Private key: ./mdsig_ed25519
Public key:  ./mdsig_ed25519.pub

DNS TXT record:
  2026._mdsig.example.com. IN TXT "v=mdsig1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="

tofu pubkey:
  ed25519:11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=
```

### 3.5 `mdsig revoke <file> --list <list.md>`

Adds the signer's own signatures in `<file>` to a revocation list and signs the list (SPEC 5.9).

| Flag | Description |
| --- | --- |
| `--list <path>` | REQUIRED. The revocation list file. It is created if it does not exist. |
| `-m`, `-s`, `-k`, `--selector`, `-u`, `--pgp-key` | As for `sign`. They select which signatures are revoked (same `method` and `signer`) and sign the list. |
| `--index <n>` | Revoke only signature `#n` of `<file>`. Default: every signature in `<file>` with the same `method` and `signer`. |

Behavior:

1. Compute the revocation identifier `SHA-256(signed payload)` (SPEC 5.9) of each selected block and add a line `revoked: sha256:<hex>` to the list body (no duplicates).
2. Remove the list's old signature chain and sign the updated list as a new document with the given key. The list MUST NOT get a `revocation_url` from this command.
3. For `pgp`, if the signing key's `fpr` differs from the revoked blocks' `fpr`, print a warning (the list is still trusted, because it is matched by `signer`).
4. Print where the list must be published: the `revocation_url` of the revoked blocks. If they have none, print a warning that verifiers cannot find the list.

### 3.6 `mdsig serve`

Offers document verification over HTTP. It is meant for verifiers that cannot check everything by themselves, such as a browser (TSA certificate chains, keys that CORS keeps out of reach), and want to hand over all or part of the verification. Whoever receives a response trusts this server's verdict.

| Flag | Default | Description |
| --- | --- | --- |
| `--listen <host:port>` | `127.0.0.1:8787` | Address to listen on. For an address other than loopback, a warning is written to stderr. |
| `--allow-origin <origin>` | — | Origin that may call the API from a browser (for example `https://example.org`). Repeatable. |
| `--offline` | off | Do not use the network (as in section 3.2). |
| `--fetch-resources` | off | Fetch `https://` resources and check their hashes. |
| `--no-revocation` | off | Do not fetch revocation lists. |
| `--keyserver <url>` | `https://keys.openpgp.org` | Keyserver for `pgp` key lookups. |
| `--tsa-root <file>` | — | Additional root certificate to trust when verifying a `tsa_token` (as in section 3.2). |

The endpoints are listed below. Request and response bodies are JSON (UTF-8).

| Method and path | Request | Response |
| --- | --- | --- |
| `POST /v1/verify` | `{ "document": "<full text of the document>" }` | One element of `files` from section 5, without `file` |
| `POST /v1/tsa` | `{ "tsa_token": "<value of tsa_token>", "sig": "<base64 of the signature bytes>" }` | The `tsa` object from section 5 |
| `GET /v1/health` | — | `{ "name", "version", "api": "v1" }` |

The server MUST follow these rules.

1. Each request is verified on its own. The stored `tofu` keys, the local gpg keyring and files on the server are not used. Local resources are therefore "not checked".
2. A request that carries an `Origin` header is processed only if that origin was given with `--allow-origin`, and is refused with `403` otherwise. A request without `Origin` (a call from another server) is processed.
3. A `POST` request has `Content-Type: application/json`, and is refused with `415` otherwise. A request from a browser therefore always goes through a CORS preflight.
4. Outbound fetches refuse connections to private and similar addresses (the same limits as verification in section 3.2).
5. A body is at most 4 MiB, and a larger request is refused with `413`. The number of requests processed at the same time is limited, and a request over the limit is refused with `503` and `Retry-After`.

The outcome of a verification (invalid, unresolved and so on) is returned in the body with HTTP status `200`. An error in the request itself is returned as one of `400`, `403`, `404`, `405`, `413`, `415` with `{ "error": "<description>" }`.

When the results of two verifiers (for example a browser and this server) are used together, each verdict SHOULD be kept apart by its source. The sets of trusted root certificates differ, so `tsa.verified` may not match.

## 4. Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success. For `verify`: every signature valid. |
| 1 | Verification failure: hash mismatch, bad signature, malformed block, unsupported algorithm or method, timestamp mismatch, no signatures, unsigned content after the last signature, a file that is not valid UTF-8, or the agreement status `violated` (an `order strict` violation, SPEC 5.8). For `sign`: refusal to co-sign (unsigned content after a block, or a malformed existing signature) without `--force`. |
| 2 | Usage error: unknown flag, missing argument, invalid field value. |
| 3 | Network or key resolution error, or a signature not checked because of `--offline`, when there is no failure that would give exit code 1. For `sign`: TSA request failed (the file is not changed). |
| 4 | File I/O or permission error, including a key file that is missing or unreadable, and `keygen` refusing to overwrite. |
| 5 | For `verify`: every signature is valid, but co-signatures required by `require` are missing (agreement `pending`, SPEC 5.8). |

If several files are verified, the exit code is the most severe across files, in the order 1 > 4 > 3 > 5 > 0.

## 5. JSON output

`--json` output MUST use English and this schema, regardless of locale:

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

A file's `ok` is `true` exactly when that file alone would give exit code 0
or 5; `agreement.status` tells the two apart. A file whose agreement status is
`violated` has `ok: false`. With `--offline`, a block that
was not checked has `status: "unresolved"` and `code: "offline"`, and `ok` is
false.

- `partial`, `webauthn`, `pgp`, `resources`, `revocation`, and `tsa` are `null` when they do not apply. `webauthn` is `{ "rp_id", "origin", "user_verified" }`. `pgp` is `{ "fpr", "uid", "key_alg", "key_source", "created" }`, where `key_alg` is a string such as `rsa2048`, `ecdsa-p256`, or `ed25519`, `key_source` is one of `keyring`, `wkd`, `keyserver`, and `created` is the creation time of the signature packet (RFC 3339).
- `agreement.status` is `none`, `complete`, `pending`, or `violated`. `role` is omitted when the requirement has none.
- Each element of `required` and `missing` has the step number `step` and the number of members its step needs, `any`. For a `require` without step lines, `step` is 1 and `any` is the number of requirement lines. Each element of `missing` also has `need`, how many more signatures its step needs; `blocked_by`, the number of an earlier step that is not complete yet, when it is waiting for one; and `early: true` when the signer signed before their turn and the signature did not count.
- `violations` lists order violations. Each element is `{ "declared_by", "step", "index", "method", "signer", "role", "order" }`, where `index` is the offending block and `order` is the value of the declaration's order line (`guide` or `strict`). `order guide` violations are listed too, but they do not change the agreement status.
- A resource `status` is `ok`, `mismatch`, `missing`, `unreachable`, or `not-checked`. A revocation `status` is `not-revoked`, `revoked`, or `not-checked`.
- `tsa` is `{ "status", "verified", "signer", "gen_time", "detail" }`. `status` is `ok`, `mismatch`, or `error`. The CLI verifies the token's CMS signature and the TSA certificate chain against the system trust store and the root certificates given with `--tsa-root`. `verified` is `true` only when that succeeds, and only then do `gen_time` and `signer` (the name in the TSA certificate) have values. A token that cannot be verified has `status: "error"` and is shown as a warning.

`status` is one of `valid`, `invalid`, `malformed`, `unresolved`, `unsupported`.
`code` is one of `malformed`, `unknown-field`, `hash-mismatch`,
`bad-signature`, `scope-missing`, `resource-mismatch`, `resource-missing`,
`expired`, `revoked`, `key-changed`, `unsupported-version`, `unsupported-alg`,
`unsupported-hash`, `unsupported-method`, `network`, `not-found`, `offline`,
or `null`.

## 6. Interactive launcher

Running `mdsig` with no arguments on a TTY starts an inline arrow-key menu
(not a full-screen alternate-buffer UI). In Go this uses `charmbracelet/huh`;
in JavaScript, `@clack/prompts`.

1. Choose an action: sign / verify / inspect / keygen.
2. **sign:** choose a file from the `.md` files in the current directory tree (up to depth 3, skipping `node_modules` and dot-directories), or type a path. Files that already have signatures show `(N existing signatures → will co-sign)`. Then: method, signer, role (presets or free text or skip), reason (optional), TSA yes/no.
3. **verify / inspect:** choose a file, then show the result.
4. **keygen:** ask for the output prefix and optional domain/selector.
5. At the end, print the equivalent one-line command, so users learn the flags.
6. Each answered question MUST remain visible on the terminal (the launcher re-prints it if the prompt library clears it), so the session reads as a transcript.
7. The method choices include `pgp` (uses an OpenPGP key). When `pgp` is chosen, the launcher asks for a gpg key (from the `gpg --list-secret-keys` list) or a key file, and the signer ID is chosen from the key's User IDs.

Reference session (Japanese UI, `LANG=ja_JP.UTF-8`). Each question is shown while it is being answered:

   ```
   $ mdsig

     md-signature (v0.0.1) — Interactive Mode

   ? 何を実行しますか？ (矢印キーで選択 / Enterで決定)
     ❯ ✍️  文書に署名・連署する (sign)
       🔍  文書の署名を検証する (verify)
       📋  署名履歴・メタデータを見る (inspect)
       🔑  新しい鍵ペアと DNS TXT レコードを生成する (keygen)

   ? 対象の Markdown ファイルは？ (カレントディレクトリの .md 候補 / パス手入力可)
     ❯ README.md
       docs/contract.md (1件の署名あり → 連署になります)
       [パスを手入力する...]

   ? 検証方式 (method) を選択してください：
     ❯ git-hosting (GitHub / GitLab の公開鍵を使用)
       dns         (ドメインの TXT レコードを使用)
       tofu        (公開鍵を直接埋め込み・オフライン向け)
       pgp         (OpenPGP 鍵・gpg を使用)

   ? 署名者 ID (signer) を入力してください：
     > github.com/alice

   ? 役割 (role) を選択してください：
     ❯ author   (作成者)
       reviewer (確認者)
       approver (承認者)
       witness  (立会人)
       [自由入力]
       [スキップ]

   ? 署名理由 (reason) を入力してください (任意 / Enterでスキップ)：
     > 初版確定

   ? RFC 3161 タイムスタンプ (TSA) を付与しますか？
     ❯ いいえ (軽量な通常署名)
       はい   (デフォルト無料TSA: http://ts.ssl.com を使用)

   ✓ 署名を追記しました: docs/contract.md

   次回から同じ設定で素早く実行するには:
     $ mdsig sign docs/contract.md -m git-hosting -s github.com/alice -r author --reason "初版確定"
   ```

The English UI has the same structure, for example "Choose a verification method (method):" and "Next time, run the same thing in one line:".

When stdin or stdout is not a TTY, `mdsig` with no arguments MUST print usage to stderr and exit with code 2.

## 7. Language

The UI language is chosen in this order:

1. `--lang <code>`
2. `MDSIG_LANG`
3. The first non-empty of `LC_ALL`, `LC_MESSAGES`, `LANG` (e.g. `ja_JP.UTF-8` → Japanese). On Windows, if none is set, the user's default UI language MAY be used.
4. English.

Supported in 0.0.1: `en`, `ja`. JSON output and output when stdout is not a TTY MUST be English.
