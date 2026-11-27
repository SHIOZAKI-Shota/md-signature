# `mdsig` Command-Line Interface Specification

- **Version:** 0.1.0 (draft; format version 0.1)
- **License:** CC0 1.0 Universal (see `LICENSE-SPEC`)
- **Format specification:** [SPEC.md](SPEC.md)
- **Normative text:** [日本語 (CLI_SPEC.ja.md)](CLI_SPEC.ja.md). This English version is an informative translation. If they differ, the Japanese text prevails.

The key words "MUST", "MUST NOT", "REQUIRED", "SHOULD", "SHOULD NOT", and "MAY" are to be interpreted as described in BCP 14 [RFC2119] [RFC8174].

## 1. Names

| Thing | Name |
| --- | --- |
| Binary | `mdsig` |
| npm CLI package | `mdsig` (planned) |
| Core library | `@mdsig/core` (npm) |
| Homebrew | `brew install SHIOZAKI-Shota/tap/mdsig` |
| Go | `go install mdsig.dev/cmd/mdsig@latest` (Go 1.26 or later) |
| winget | `winget install ShiozakiShota.mdsig` (not available yet: built by the release workflow but not published) |
| Debian / RPM | `mdsig` (not available yet: packages are built by the release workflow but not published) |

## 2. Global flags

| Flag | Description |
| --- | --- |
| `--lang <code>` | UI language: `en` or `ja`. See Section 7. |
| `-h, --help` | Help. |
| `--version` | Print version. Shows the CLI version together with the version of the format used for signing (for example `mdsig version 0.1.0 (format 0.1)`). The CLI verifies only the format `0.1` defined by SPEC and signs with `0.1`. Documents in `0.0.x` are `unsupported-version`, and the CLI suggests verifying them with v0.0.5. |

## 3. Commands

### 3.1 `mdsig sign <file>`

Signs a Markdown file. If the file already has a signature chain, the new
signature is appended as a co-signature (SPEC Section 7).

| Flag | Default | Description |
| --- | --- | --- |
| `-m, --method <m>` | `git-hosting` | `git-hosting`, `dns`, `tofu`, `pgp`, or `directory`. |
| `-s, --signer <id>` | — | REQUIRED. `github.com/alice`, `example.com`, `bob@laptop`, `alice@example.com`, ... For methods other than `tofu`, ASCII uppercase letters are written in lowercase, and a value not in the canonical form of SPEC 3.4 gives exit code 2. With `pgp` it can be omitted; it is then taken from the email address in the key's user ID (3.1.2). |
| `-k, --key <path>` | auto | OpenSSH Ed25519 private key file. See 3.1.1. |
| `--selector <sel>` | — | `dns` only. |
| `-u, --local-user <id>` | gpg default key | `pgp` only. The key to pass to gpg (a fingerprint or user ID). |
| `--pgp-key <path>` | — | `pgp` only. An ASCII-armored OpenPGP private key file. When given, gpg is not used and the CLI signs directly. |
| `-r, --role <role>` | — | `author`, `reviewer`, `approver`, `witness`, or any word matching `[a-z0-9][a-z0-9._-]*` (SPEC 3.3). |
| `--display-name <name>` | — | Display name for the signature table and similar uses (SPEC 3.3). Written after applying the enforcement rules of the Nickname profile of RFC 8266. A value longer than 64 code points gives exit code 2. |
| `--reason <text>` | — | Free text. |
| `--tsa [url]` | off | Append a `tsa` block (SPEC 4.6) right after the signature block. Without a value, uses `http://ts.ssl.com`. The procedure is the same as `mdsig timestamp` in Section 3.7. |
| `--tsa-root <file>` | — | Root certificate (PEM or DER file) to trust, in addition to the system trust store, when checking a timestamp token. Repeatable. Used together with `--tsa`. |
| `--stdout` | off | Write the signed document to stdout instead of changing the file. |
| `--embed-key` | off | `dns`, `git-hosting`, and `directory` only. Include the public key used for signing in the block as `pubkey` (SPEC 4.5), so that the signature can still be checked after the key is removed. `directory` includes it by default. Exit code 2 with any other method. |
| `--no-embed-key` | off | `directory` only. Do not include `pubkey`. Exit code 2 with any other method. |
| `--force` | off | Sign even if the file has a signature block followed by unsigned content. The whole file is then signed as a new document. |
| `--scope <ids>` | — | Sign only these sections, comma-separated or repeated: `--scope terms,fees` (SPEC 5.6). `scope` is written as a list with one ID per line. |
| `--require <line>` | — | One line of the `require` value. Repeatable; lines keep the order given. Besides requirement lines `<method>:<signer\|pattern>[ <attr>…]` (attributes `role=`, `user_verified`, `member_of=`, `pubkey=`), step lines `step[ any=<m>]` and order lines `order mode=pending\|guide\|strict` are accepted (SPEC 5.8). Example: `--require "step" --require "dns:example.com role=approver" --require "step any=2" --require "directory:*@example.com member_of=dns:example.com"`. Leading spaces of each line are removed, and requirement lines under a step line are written indented by two spaces. The whole value is checked against the rules of SPEC 5.8; a malformed value gives exit code 2. |
| `--resource <ref>` | — | Bind a file (path relative to the document) or an `https://` URL by its SHA-256. Repeatable. URLs are fetched once, at signing time. A local path has any leading `./` removed and spaces and similar characters percent-encoded, and is written as a line `<ref> hash=sha256:<hex>` (SPEC 5.7). |
| `--auto-resources` | off | Also bind every local image referenced by `![..](..)` or `<img src>` outside code fences. |
| `--expires <time>` | — | `YYYY-MM-DDTHH:MM:SSZ`, or a duration from now: `30d`, `12h` (SPEC 5.9). |
| `--revocation-url <url>` | — | `https://` URL of the signer's revocation list (SPEC 5.9). |

Behavior:

- The file is updated atomically (write to a temporary file in the same directory, then rename). Line endings (LF or CRLF) are preserved.
- Field values containing `-->`, `--!>`, `<!--`, line breaks, or characters forbidden by rule 4 of SPEC 3.2 MUST be rejected with exit code 2. So MUST invalid `--signer`, `--role`, `--display-name`, `--scope`, `--require`, `--resource`, `--expires`, and `--revocation-url` values.
- Signing a document whose body ends inside a code fence (SPEC 5.5) is refused with exit code 1, even with `--force`.
- If the `--tsa` request or its check fails, the exit code is 3 and the file is not changed (the signature block is not appended either).
- A `--resource` file that does not exist is a file error (exit code 4); a URL that cannot be fetched is a network error (exit code 3).
- Passkey (`webauthn-es256`) signing happens in a web browser (for example the playground). The CLI verifies such signatures but does not create them. Section 8 defines how a local tool asks a signing page for such a signature.
- On success, print one line to stderr: `Signed <file> (signature #N, <method> <signer>)`.

#### 3.1.1 Key discovery

When `-k` is not given (methods other than `pgp`):

1. If ssh-agent is available (`SSH_AUTH_SOCK`, or on Windows the OpenSSH agent pipe `\\.\pipe\openssh-ssh-agent`), use its `ssh-ed25519` keys. If there is more than one: with `git-hosting`, first narrow the candidates to the keys that appear in `https://<signer>.keys` (if any do). If more than one candidate remains, ask in the interactive launcher; otherwise use the first candidate.
2. Otherwise use `~/.ssh/id_ed25519`.

Passphrase-protected key files MUST be supported: prompt for the passphrase on the TTY, or read it from `MDSIG_PASSPHRASE` when stdin is not a TTY.

#### 3.1.2 Signing with `pgp`

- Without `--pgp-key`, the CLI calls `gpg`: `gpg --detach-sign --digest-algo SHA256 [--local-user <id>]`. The input is the signed payload (SPEC 5.3) and the output is a binary signature. This allows signing with keys held by gpg-agent or on a smartcard.
- The CLI MUST check that the gpg output satisfies the conditions in SPEC 6.2 (exactly one signature packet, type 0x00, an Issuer Fingerprint present, and so on), and fail with exit code 2 if it does not. `fpr` is set from the Issuer Fingerprint of the output signature.
- Because `fpr` has to be recorded in the block before signing, the CLI first identifies the key that will be used with `gpg --list-secret-keys --with-colons`. If the actual Issuer Fingerprint after signing differs from it, the CLI fails.
- With `--pgp-key`, the CLI signs directly with that private key. For a protected key, it prompts for the passphrase on the TTY, or reads it from `MDSIG_PGP_PASSPHRASE` when stdin is not a TTY. Supported protection is S2K iterated+salted with AES (CFB), as well as Argon2 S2K and AEAD protection.
- Without `--signer`, the email address of a valid user ID of the key is used. If there are several email addresses, the interactive launcher asks the user to choose; otherwise the CLI fails with exit code 2.
- If `gpg` is not found and `--pgp-key` is not given, the exit code is 2.
- Byte buffers that held the private key or passphrase are wiped after signing.

### 3.2 `mdsig verify <file>...`

Verifies every signature in each file's chain (SPEC Section 5.4).

| Flag | Description |
| --- | --- |
| `--json` | Print a JSON result (Section 5) to stdout. |
| `-q, --quiet` | No output; exit code only. |
| `--offline` | Do not use the network. Hashes are checked for every block. Signatures can be checked for `tofu` (with the stored key), `pgp` (with a key in the local gpg keyring), `tsa` blocks (their CMS signature and certificate chain are verified without the network), and `dns`, `git-hosting`, or `directory` blocks with an embedded `pubkey`. A block whose signature does not verify with its embedded key is invalid. Any other block is reported as "not checked (offline)". A file with any block that was not checked gives exit code 3. Remote resources, revocation lists, and rosters are not fetched, and an agreement that depends on a roster is `undetermined`. |
| `--fetch-resources` | Fetch `https://` resources and check their hashes. Off by default, because fetching tells the server that the document is being verified (SPEC 9.8). |
| `--no-revocation` | Do not fetch revocation lists. They are fetched by default when online; if a list cannot be fetched or is not trusted, the block is unresolved (exit code 3). |
| `--accept-new-key` | Accept a `tofu` key that differs from the one stored for its `signer`, and replace the stored binding. Without it, a block whose key changed is invalid (code `key-changed`). |
| `--no-keyring` | Do not use the local gpg keyring for `pgp` key lookups (WKD and keyserver only). |
| `--keyserver <url>` | `https://` URL of the keyserver for `pgp` key lookups. Default: `https://keys.openpgp.org`. The verifier chooses the keyserver; it is never taken from the block (SPEC 4.3). Name one that confirms email addresses. |
| `--key-directory <url>` | `https://` URL of a key directory to trust for `directory` key lookups in this run only. Repeatable. It is queried after the default list and the directories added with `mdsig directory trust` (3.8). If the domain of `signer` names a directory with `dir` in `_mdsig`, only that directory is used (SPEC 4.7). A URL that is not `https://` gives exit code 2. |
| `--tsa-root <file>` | Root certificate (PEM or DER file) to trust, in addition to the system trust store, when checking the timestamp token of a `tsa` block. A PEM file may hold several certificates. Repeatable. A file that cannot be read is a usage error (exit code 2). |

`dns` lookups SHOULD use the system resolver. `git-hosting` fetches
`https://<signer>.keys`. `pgp` takes the key from the local keyring with
`gpg --export <fpr>` if `gpg` is available, then tries WKD, then the keyserver
(SPEC 4.3). `directory` takes keys from the directory named by `dir` in the
`_mdsig` record of the signer's domain, or else from the list of trusted key
directories (the default `https://keys.mdsig.dev`, then
`<user config dir>/mdsig/key_directories.json`, then `--key-directory`)
(SPEC 4.7). Rosters in `member_of` are always fetched when online: https rosters are fetched and verified as in SPEC 5.10, and DNS rosters are queried with the system resolver (SPEC 5.8.8). TOFU bindings are stored in
`<user config dir>/mdsig/known_signers.json`. A binding is stored only after
the block has verified, and never from a block inside a revocation list.
Local resources are always checked, relative to the directory of the file
being verified. A path that leaves that directory after symbolic links are
resolved, anything that is not a regular file, and a file larger than 50 MB
are not read. When fetching URLs (resources, revocation lists, rosters, `git-hosting`
key lists, DoH, WKD, and the keyserver), the CLI
MUST refuse private, loopback, and link-local addresses, and responses larger
than 50 MB (resources) or 10 MB (revocation lists and rosters). It checks the address that
it actually connects to, and therefore does not use HTTP proxies for these
requests.

In output without `--json`, the CLI MUST show control and format characters in
text that comes from the document or from a server (field values, user IDs,
file names, and so on) as `\u{XXXX}`. This prevents terminal escape sequences
from forging the displayed result.

Human-readable output (example):

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

A `display_name` is shown after the verified signer identity, followed by `(declared)` (「（申告）」 in the Japanese UI).
`⏱` is `T(k)` of SPEC 4.6, shown with the number of the `tsa` block that gave it.

When the agreement is not complete, the content of `next` (SPEC 5.8.9) is shown, indented to follow the structure of the steps.
Signatures that were not counted are marked with the reason (`rejected`). An `order mode=guide` violation is shown as a warning,
and an `order mode=strict` violation as the agreement status `violated`. When the result cannot be decided, for example because
a roster cannot be fetched, `undetermined` is shown with the cause.

```
  Agreement: pending
    next: step 2 needs 1 more (after step 1)
      git-hosting:github.com/carol role=reviewer
      git-hosting:github.com/dave role=reviewer
    not counted: #2 git-hosting:github.com/bob (early: signed before step 1 was complete)
  Agreement: violated (#2 git-hosting:github.com/bob signed for step 2 before step 1 was complete)
  Agreement: undetermined (roster https://example.org/members.md could not be fetched)
```

When a `require` value contains old syntax from SPEC 5.8 (`0.0.x` step lines, roles written by position, and so on), or indentation
that does not match the structure of the steps, the CLI MAY print hints for fixing it as warnings. The verdict does not change.
Likewise, when a hash mismatch seems to come only from differences in whitespace, the CLI MAY point to SPEC Appendix B.

A passkey signature also shows its `rp_id`, whether the user was verified (UV), and whether the passkey is synced (BS).
For example `passkey (rp_id mdsig.dev, user verified, synced)`.
A `pgp` signature shows the fingerprint, the user ID, where the key was found, and the creation time of the signature packet.
The creation time is claimed by the signer, like `ts`, and is shown separately from `T(k)`.

A warning is printed when the body ends inside a code fence (SPEC 5.5) and when there are several signature table markers (SPEC 5.11).

### 3.3 `mdsig inspect <file>`

Prints the chain and all fields of each block without using the network.
For each block it also prints whether `hash` matches the current content.
Exits 0 when the file could be read, whatever the hash results (use `verify` to check). A file that is not valid UTF-8 gives exit code 1.

`--json` prints:

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

Generates an Ed25519 key pair.

| Flag | Description |
| --- | --- |
| `-o, --out <prefix>` | Write `<prefix>` (OpenSSH private key, mode 0600) and `<prefix>.pub`. Default `./mdsig_ed25519`. MUST NOT overwrite existing files. |
| `-d, --domain <domain>` | Also print the DNS TXT record for this domain. |
| `--selector <sel>` | Selector for the DNS record name. Exit code 2 when given without `--domain`. |

Output (stdout):

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

`DNS TXT record` is printed only with `--domain` (the example uses `-d example.com --selector 2026`).

### 3.5 `mdsig revoke <file> --list <list.md>`

Adds the signer's own signatures in `<file>` to a revocation list and signs the list (SPEC 5.9).

| Flag | Description |
| --- | --- |
| `--list <path>` | REQUIRED. The revocation list file. It is created if it does not exist. |
| `-m`, `-s`, `-k`, `--selector`, `-u`, `--pgp-key` | As for `sign`. They select which signatures are revoked (same `method` and `signer`) and sign the list. |
| `--index <n>` | Revoke only signature `#n` of `<file>`. Default: every signature in `<file>` with the same `method` and `signer`. |

Behavior:

1. Compute the revocation identifier `SHA-256(signed payload)` (SPEC 5.9) of each selected block and add a line `revoked: sha256:<hex>` to the `mdsig-list` fence (SPEC 5.10) in the list body (no duplicates). If the list does not exist, create a body with a fence that has the line `type: revocation`. If the fence of an existing list does not follow the format of SPEC 5.10, fail with exit code 1 and leave the list unchanged.
2. Remove the list's old signature chain and sign the updated list as a new document with the given key. The list MUST NOT get a `revocation_url` from this command.
3. Compare the signing key with the key of the revoked blocks. For `tofu`, if the signing key does not match the revoked block's `pubkey`, fail with exit code 2 and leave the list unchanged (verifiers trust a `tofu` list only when it is signed with the same key). For `git-hosting`, if the signing key's fingerprint differs from the revoked block's `key_fp`, and for `pgp`, if the signing key's `fpr` differs from the revoked block's `fpr`, print a warning (the list is still trusted, because it is matched by signer identity).
4. Print where the list must be published: the `revocation_url` of the revoked blocks. If they have none, print a warning that verifiers cannot find the list.

### 3.6 `mdsig serve`

Offers document verification over HTTP. It is meant for verifiers that cannot check everything by themselves, such as a browser (TSA certificate chains, keys that CORS keeps out of reach), and want to hand over all or part of the verification. Whoever receives a response trusts this server's verdict.

| Flag | Default | Description |
| --- | --- | --- |
| `--listen <host:port>` | `127.0.0.1:8787` | Address to listen on. For an address other than loopback, a warning is written to stderr. |
| `--allow-origin <origin>` | — | Origin that may call the API from a browser (for example `https://example.org`). Repeatable. |
| `--offline` | off | Do not use the network (as in Section 3.2). |
| `--fetch-resources` | off | Fetch `https://` resources and check their hashes. |
| `--no-revocation` | off | Do not fetch revocation lists. |
| `--keyserver <url>` | `https://keys.openpgp.org` | Keyserver for `pgp` key lookups. |
| `--key-directory <url>` | — | Key directory to trust for `directory` key lookups (as in Section 3.2). |
| `--tsa-root <file>` | — | Root certificate to trust, in addition to the system trust store, when checking a timestamp token (as in Section 3.2). |

The endpoints are listed below. Request and response bodies are JSON (UTF-8).

| Method and path | Request | Response |
| --- | --- | --- |
| `POST /v1/verify` | `{ "document": "<full text of the document>" }` | One element of `files` from Section 5, without `file` |
| `POST /v1/tsa` | `{ "token": "<value of the tsa block's sig>", "sig": "<base64 of the tsa block's signed payload>", "hash": "<sha256 or sha512>" }`, where `hash` is the algorithm of the `tsa` block's `hash` (`sha256` when omitted). The server compares the digest of the bytes decoded from `sig` with `messageImprint` | The `tsa` object from Section 5 |
| `GET /v1/health` | — | `{ "name", "version", "api": "v1" }` |

The server MUST follow these rules.

1. Each request is verified on its own. The stored `tofu` keys, the local gpg keyring and files on the server are not used. Local resources are therefore "not checked".
2. A request that carries an `Origin` header is processed only if that origin was given with `--allow-origin`, and is refused with `403` otherwise. A request without `Origin` (a call from another server) is processed.
3. A `POST` request has `Content-Type: application/json`, and is refused with `415` otherwise. A request from a browser therefore always goes through a CORS preflight.
4. Outbound fetches refuse connections to private and similar addresses (the same limits as verification in Section 3.2).
5. A body is at most 4 MiB, and a larger request is refused with `413`. The number of requests processed at the same time is limited, and a request over the limit is refused with `503` and `Retry-After`.

The outcome of a verification (invalid, unresolved and so on) is returned in the body with HTTP status `200`. An error in the request itself is returned as one of `400`, `403`, `404`, `405`, `413`, `415` with `{ "error": "<description>" }`.

When the results of two verifiers (for example a browser and this server) are used together, each verdict SHOULD be kept apart by its source. The sets of trusted root certificates differ, so `tsa.verified` may not match.

### 3.7 `mdsig timestamp <file>`

Appends a `tsa` block (SPEC 4.6) to the end of the file. The block covers the whole chain before it, earlier timestamps included, so running it again renews the timestamp. A file without signature blocks, or one that is not valid UTF-8, is refused with exit code 1.

| Flag | Default | Description |
| --- | --- | --- |
| `--tsa <url>` | `http://ts.ssl.com` | URL of the RFC 3161 TSA. |
| `--hash <alg>` | `sha256` | Algorithm of `hash` and of `messageImprint`: `sha256` or `sha512`. Use `sha512` for a renewal that must outlive SHA-256. |
| `--reason <text>` | — | Free-text reason. |
| `--tsa-root <file>` | — | Root certificate to trust, in addition to the system trust store, when checking a timestamp token (as in Section 3.2). |
| `--stdout` | off | Write the result to stdout instead of changing the file. |

The TSA's response is checked as the `tsa` block to be appended, by the verifier procedure of SPEC 4.6, and is not appended unless it is valid. If the request or the check fails, the exit code is 3 and the file is not changed.

### 3.8 `mdsig directory`

Works with key directories (SPEC 4.7).

| Subcommand | Description |
| --- | --- |
| `trust add <url>` | Add a key directory to the trusted list. The list is stored in `<user config dir>/mdsig/key_directories.json`; `verify` and `serve` use it after the default list. A URL that is not `https://` gives exit code 2. |
| `trust remove <url>` | Remove it from the list. A URL that is not in the list gives exit code 2. The default list cannot be removed. |
| `trust list` | Print the default list and the added directories. |
| `register --email <addr>` | Ask a key directory to publish an Ed25519 key for the email address. The key is found as in 3.1.1 (`-k` to name it), and possession is shown by signing a challenge the directory issued. The key is published only after the link in the directory's confirmation email is opened. `--label <name>` sends a name for the key, shown in the confirmation email. |
| `remove --email <addr>` | Ask for the address's keys to be removed (only the key given with `--key <base64>`, if any). The removal is completed by a confirmation email. |

`register` and `remove` go to `--directory <url>` when it is given, otherwise to the directory the address's domain names with `dir` in `_mdsig`, otherwise to `https://keys.mdsig.dev`. If the request is not accepted, the exit code is 3.

After signing, `mdsig sign -m directory` checks whether verifiers following the default rules would find the key it signed with, and prints a warning to stderr if they would not. The signature is kept.

### 3.9 `mdsig known`

Works with the stored `tofu` keys (SPEC 4.4). They are stored in `<user config dir>/mdsig/known_signers.json`.

| Subcommand | Description |
| --- | --- |
| `list` | Print each stored `signer` with the fingerprint of its key. With `--json`, print `[{ "signer", "key", "fingerprint" }]`. |
| `remove <signer>` | Delete the stored key for that `signer`. A `signer` that is not stored gives exit code 2. The next verification treats that signer's key as seen for the first time. |

`known_signers.json` is a JSON object whose keys are `signer` values and whose values are `pubkey` values (`<key-type>:<base64>`). Tools that read or write this file (the CLI, desktop apps, and others) MUST follow these rules:

1. Write atomically (write a temporary file, then rename it), with permissions that let only the owner read and write the file.
2. Read the file again just before writing, and keep the entries this tool did not change.
3. Add an entry only after the block has verified or after the user has explicitly trusted the key, and never from a block inside a revocation list.

The fingerprint of an `ed25519` key is the OpenSSH form (`SHA256:` followed by the unpadded base64 of the SHA-256 of the SSH public key blob, the same as `key_fp` in SPEC 4.2). For other keys it is `SHA256:` followed by the unpadded base64 of the SHA-256 of the bytes decoded from the `pubkey` base64.

A tool operated by a user MAY show the fingerprint and ask the user to confirm before storing a key seen for the first time (SPEC 4.4). `mdsig verify` does not ask; it stores the key when the block verifies.

### 3.10 `mdsig render <file>`

Verifies a document and writes the body and the signature table as one HTML file (SPEC 5.11 and 9.5).

| Flag | Default | Description |
| --- | --- | --- |
| `--lang <code>` | UI language (Section 7) | Language for the signature table and the verification results: `ja` or `en`. |
| `-o, --out <path>` | stdout | Output HTML file. An existing file is overwritten. |
| `--offline`, `--fetch-resources`, `--no-revocation`, `--keyserver`, `--key-directory`, `--tsa-root` | — | As for `verify`. |

The output MUST follow these rules:

1. A summary of the verification result (the document's status and the agreement status) is placed outside the body, in an area the body's content cannot reach.
2. The body is rendered without scripts, event attributes, form elements, and `style` attributes.
3. The signature table is built outside the DOM the body is rendered into. If the body has a signature table marker, the body is split at the first marker (outside code fences), the parts are rendered separately, and the table is placed between them. Without a marker, the table is placed after the body.

The signature table has one row for each block of the chain (except `tsa` blocks).

| Column | Content |
| --- | --- |
| Number | Position in the chain (`#1` and so on). |
| Display name | `display_name`, marked "(declared)" or 「（申告）」. Empty when absent. |
| Signer | The signer identity (`method:signer`). |
| Identity check | How the identity was checked. For example, for `dns` "DNS TXT (example.com)"; for `directory` the directory that returned the key and whether it was chosen by `dir` or from the trusted list; for `tofu` "embedded key (trust on first use)" with the fingerprint. |
| Role | `role`. |
| Claimed time | `ts`. |
| Proven time | `T(k)` (SPEC 4.6). Empty when not defined. |
| User verification | For `webauthn-es256`, whether UV is set. |
| Status | The status, such as `valid`. For a partial signature, that fact and the section IDs. |

When the agreement is not complete, unsigned rows built from `next` (Section 5) follow. An unsigned row shows the step
number, the number of signers needed, and the candidate requirement lines (target and attributes), and is kept visually
apart from the signed rows.

The exit code is the same as `verify` on the same file. A document that fails verification still gets HTML that shows the
result. If the output cannot be written, the exit code is 4.

### 3.11 `mdsig require explain <value>`

Checks a `require` value (SPEC 5.8) and explains its meaning in prose. Use it to review requirements before signing.

- `<value>` is the whole `require` value, including line breaks. With `-`, it is read from stdin.
- The output is an explanation indented by step (the UI language follows Section 7). For example:

  ```
  $ mdsig require explain "$(printf 'step\n  dns:example.com role=approver\nstep any=2\n  dns:*.example.com member_of=dns:example.com')"
  order: pending (signatures before their turn are not counted)
  step 1: all of
    dns:example.com with role approver
  step 2: any 2 different signers of
    any subdomain of example.com (not example.com itself), on the DNS roster of example.com
  ```

- Warnings (a `tofu` line without `pubkey=`, indentation that does not match the structure of the steps, and so on) go to stderr.
- With `--json`, it prints `{ "order", "steps": [{ "step", "any", "lines": [{ "line", "method", "signer", "pattern", "attributes" }] }], "warnings" }`. The keys mean the same as in `required` in Section 5.
- If the value is malformed, the line and the reason are printed and the exit code is 2. If the value has an unknown method or attribute, a warning says so and the exit code is 0.

### 3.12 `mdsig member-record <id> <domain>`

Prints the TXT record to set so that a DNS roster (SPEC 5.8.8) shows the signer identity `<id>` (`method:signer`) as a member of `<domain>`.

```
$ mdsig member-record directory:alice@example.com example.com
<52-character label>._member._mdsig.example.com. IN TXT "v=mdsig1; m=directory:alice@example.com"
```

- For methods other than `tofu`, ASCII uppercase letters in the `signer` of `<id>` are converted to lowercase first. An `<id>` that is not in the canonical form of SPEC 3.4, a pattern, and a `<domain>` that is not an `ldh-domain` give exit code 2.
- This command does not use the network. With `--check`, it queries the record with the system resolver and prints the classification of SPEC 5.8.8 (member, not a member, undetermined). The exit code is 3 when undetermined and 1 when not a member.

## 4. Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success. For `verify`: every signature valid. |
| 1 | Verification failure: hash mismatch, bad signature, malformed block, unsupported algorithm or method, timestamp mismatch, no signatures, unsigned content after the last signature, a file that is not valid UTF-8, or the agreement status `violated` (an `order mode=strict` violation) or `unsupported` (an unknown method or attribute; SPEC 5.8.9). For `sign`: refusal to co-sign (unsigned content after a block, or a malformed existing signature) without `--force`, and refusal to sign a document whose body ends inside a code fence. |
| 2 | Usage error: unknown flag, missing argument, invalid field value. |
| 3 | Network or key resolution error, a signature not checked because of `--offline`, or the agreement status `undetermined`, in each case when there is no failure that would give exit code 1. For `sign` and `timestamp`: TSA request failed (the file is not changed). |
| 4 | File I/O or permission error, including a key file that is missing or unreadable, and `keygen` refusing to overwrite. |
| 5 | For `verify`: every signature is valid, but co-signatures required by `require` are missing (agreement `pending`, SPEC 5.8.9). |
| 130 | The user canceled an interactive prompt (the launcher and others). |

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

A file's `ok` is `true` exactly when that file alone would give exit code 0
or 5. A file whose agreement status is `violated`, `unsupported`, or
`undetermined` has `ok: false`. With `--offline`, a block that was not checked
has `status: "unresolved"` and `code: "offline"`, and `ok` is false.

**Per signature.**

- `partial`, `tofu`, `webauthn`, `pgp`, `resources`, `revocation`, and `tsa` are `null` when they do not apply. `display_name` is `null` when the block has no `display_name`. The value is the signer's claim; display it as SPEC 3.3 requires.
- `tofu` is `{ "status", "fingerprint" }` and has a value when a `tofu` block was checked against the stored keys (Section 3.9). `status` is one of `known` (matches the stored key), `new` (a key seen for the first time), or `replaced` (the stored key was replaced by `--accept-new-key`), and `fingerprint` is the key fingerprint of Section 3.9.
- `webauthn` is `{ "rp_id", "origin", "user_verified", "backup_eligible", "backed_up" }`. The last three are the booleans of the `authenticatorData` flags UV, BE, and BS (SPEC 6.1).
- `pgp` is `{ "fpr", "uid", "key_alg", "key_source", "created" }`, where `key_alg` is a string such as `rsa2048`, `ecdsa-p256`, or `ed25519`, `key_source` is one of `keyring`, `wkd`, `keyserver`, and `created` is the creation time of the signature packet (RFC 3339).
- A resource `status` is `ok`, `mismatch`, `missing`, `unreachable`, or `not-checked`. A revocation `status` is `not-revoked`, `revoked`, or `not-checked`.
- `tsa` is `{ "status", "verified", "signer", "gen_time", "detail", "time", "block" }`. `time` is the time `T(k)` of the block (SPEC 4.6) and `block` is the number of the `tsa` block that gave it; both are `null` when `T(k)` is not defined.
  - On a signature block, `tsa` has a value only when `T(k)` is defined, and `signer` (the name in the TSA certificate) and `gen_time` are the values from the token of the `tsa` block that `block` names.
  - On a block whose `method` is `tsa`, `status`, `verified`, `signer`, `gen_time`, and `detail` are the result of checking that block's own token. `status` is `ok`, `mismatch`, or `error`. The CLI verifies the token's CMS signature and the TSA certificate chain against the system trust store and the root certificates given with `--tsa-root`. `verified` is `true` only when that succeeds, and only then do `gen_time` and `signer` have values.

`status` is one of `valid`, `invalid`, `malformed`, `unresolved`, `unsupported`.
`code` is one of `malformed`, `unknown-field`, `hash-mismatch`,
`bad-signature`, `scope-missing`, `resource-mismatch`, `resource-missing`,
`expired`, `revoked`, `key-changed`, `key-not-published`, `unsupported-version`, `unsupported-alg`,
`unsupported-hash`, `unsupported-method`, `network`, `not-found`, `offline`,
or `null`.

**Agreement.**

- `agreement.status` is `none`, `complete`, `pending`, `undetermined`, `violated`, or `unsupported` (SPEC 5.8.9).
- `required` lists every requirement line of every declaration. Each element has the number of the declaring block `declared_by`, the step number `step`, the step's `any` value (`null` for a step without `any`), the line number `line` within the `require` value (counting from 1, order and step lines included), the target's `method` and `signer` (for a pattern line, the pattern, such as `*.example.com`), `pattern`, which tells whether it is a pattern line, and the attributes `attributes`.
- `attributes` is an object keyed by attribute name. An attribute that takes a value has a string; an attribute that takes none (`user_verified`) has `true`. Future attributes go into the same object, so the shape of the JSON does not change.
- `satisfied` lists the reported assignment (SPEC 5.8.5). Each element is `{ "declared_by", "step", "line", "index" }`, where `index` is the number of the block assigned to that requirement line.
- `missing` lists the requirement lines without an assignment in steps that are not complete. Besides the keys of `required`, each element has `need`, how many more signers its step needs, and `rejected`, the blocks that were not counted; when it is waiting for an earlier step that is not complete yet, it also has `blocked_by`, the number of that step. Each element of `rejected` is `{ "index", "reason" }`, where `reason` is from the vocabulary of SPEC 5.8.9 (`early`, `blocked`, `not-member`, `roster-unavailable`, `not-user-verified`, `key-mismatch`, `self`, `scoped`, `not-valid`). This vocabulary is separate from the signature `code`.
- `next` has one element per declaration that is not complete. Each element has the number of the first incomplete step `step`, how many more signers it needs `need`, the candidate requirement lines `candidates` (elements of `required`), and an outline of the steps after it, `later` (a list of `{ "step", "need", "lines" }`).
- `violations` lists order violations. Each element is `{ "declared_by", "step", "line", "index", "method", "signer", "order" }`, where `index` is the offending block, `line` is the requirement line it was assigned to, and `order` is the value of the declaration's order line (`guide` or `strict`). `order mode=guide` violations are listed too, but they do not change the agreement status.
- `declarations` gives the status of each declaration. Each element is `{ "declared_by", "order", "status", "detail" }`, where `status` uses the vocabulary of `agreement.status` (except `none`). `detail` names the methods or attributes that were not understood for `unsupported`, and the cause (offline, network failure, roster that cannot be obtained, the limits of SPEC 5.8.10) for `undetermined`; otherwise it is `null`.

## 6. Interactive launcher

Running `mdsig` with no arguments on a TTY starts an inline arrow-key menu
(not a full-screen alternate-buffer UI). In Go this uses `charmbracelet/huh`;
in JavaScript, `@clack/prompts`.

1. Choose an action: sign / verify / inspect / keygen.
2. **sign:** choose a file from the `.md` files in the current directory tree (up to depth 3, skipping `node_modules` and dot-directories), or type a path. Files that already have signatures show `(N existing signatures → will co-sign)`. Then: method, signer, display name (optional), role (presets, free text matching `[a-z0-9][a-z0-9._-]*`, or skip), reason (optional), and whether to append a `tsa` block. The signer and role are checked against SPEC 3.3 and 3.4 as they are entered, and the launcher asks again on an error. If the document has an unsatisfied `require`, the candidates from `next` are shown.
3. **verify / inspect:** choose a file, then show the result.
4. **keygen:** ask for the output prefix and optional domain/selector.
5. At the end, print the equivalent one-line command, so users learn the flags.
6. Each answered question MUST remain visible on the terminal (the launcher re-prints it if the prompt library clears it), so the session reads as a transcript.
7. The method choices include `pgp` (uses an OpenPGP key). When `pgp` is chosen, the launcher asks for a gpg key (from the `gpg --list-secret-keys` list) or a key file, and the signer ID is chosen from the key's user IDs.

Reference session (Japanese UI, `LANG=ja_JP.UTF-8`). Each question is shown while it is being answered:

   ```
   $ mdsig

     md-signature v0.1.0：対話モード

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

The English UI has the same structure, for example "Choose a verification method (method):" and "Next time, run the same thing in one line:".

When stdin or stdout is not a TTY, `mdsig` with no arguments MUST print usage to stderr and exit with code 2.

## 7. Language

The UI language is chosen in this order:

1. `--lang <code>`
2. `MDSIG_LANG`
3. The first non-empty of `LC_ALL`, `LC_MESSAGES`, `LANG` (for example `ja_JP.UTF-8` → Japanese). On Windows, if none is set, the user's default UI language MAY be used.
4. English.

Supported in this release: `en`, `ja`. JSON output and output when stdout is not a TTY MUST be English.

## 8. Handing off to a signing page

A passkey (SPEC 6.1) can be used only on pages of the RP ID it was registered with. A tool that runs locally (the CLI, a desktop app, and others) asks a **signing page**, opened in the user's web browser, to make the passkey signature. This section defines the request and the response. Anyone can run a signing page; this section does not name an operator or a domain.

### 8.1 Choosing a signing page

- The user chooses the signing page. A tool MUST NOT take the signing page's URL from the document.
- The signing page's URL MUST be `https://`.
- A key directory (SPEC 4.7) MAY serve a signing page at `<dir>/sign`. That page works with passkeys whose RP ID is the directory's host name.
- A tool SHOULD offer the signing pages of the trusted key directories (Section 3.8) and let the user add and remove other signing pages.
- A signature made through a handoff has `method` `tofu`, `dns`, or `directory` (`git-hosting` and `pgp` do not support passkeys).

### 8.2 Request

The tool opens the signing page's URL in the default web browser with the following query parameters, UTF-8 and percent-encoded:

| Parameter | Content |
| --- | --- |
| `v` | `1`. |
| `op` | `key` (choose a passkey) or `sign` (sign). |
| `return` | Where the response goes (Section 8.4). |
| `state` | A random value of at least 128 bits made by the tool, in base64url. It is returned unchanged. |
| `payload` | Only for `op=sign`. The signed payload (SPEC 5.3) in base64url. |
| `credential` | Optional for `op=sign`. The credential ID of the passkey to use, in base64url. |
| `name` | Optional. The document's display name. It is not the block's `display_name` (the signer's display name, SPEC 3.3). |
| `user_verification` | Optional for `op=sign`. With `required`, the signing page asks for an assertion with user verification (UV). A tool SHOULD set it when the document to be signed has an unsatisfied `user_verified` requirement line (SPEC 5.8.7). |

The tool MUST NOT send the document's text. The signing page receives only the signed payload (fields and hash).

### 8.3 What the signing page does

For `op=key`, the signing page lets the user choose or create a passkey and returns its public key and credential ID.

For `op=sign`, the signing page MUST sign only when all of the following hold:

1. `payload` starts with the line `md-signature/v1` and parses as the format of SPEC 5.3.
2. `alg` is `webauthn-es256` and `rp_id` equals the signing page's RP ID.
3. If `pubkey` is present, it equals the public key of the passkey being used.
4. Before signing, the page shows the payload's fields (at least `method`, `signer`, `display_name`, `role`, `reason`, `expires`, `scope`, `require`, and `hash`), `name` (marked as reported by the tool), and where `return` goes, and gets an explicit action from the user.

The signing page gets an assertion with the challenge SHA-256(payload) (SPEC 6.1) and returns the response in Section 8.4. For a request with `user_verification=required`, it gets the assertion with `userVerification` set to `"required"`, and if the UV flag (bit 2) of the resulting `authenticatorData` is not set, it MUST refuse to complete and return `error=unsupported`. The signing page SHOULD NOT send the payload or the signature to its own server.

### 8.4 Response

`return` MUST be a URL with a scheme other than `http` and `https` (for example `mdsig+fountain-pen:`), or a URL that starts with `http://127.0.0.1:<port>/` or `http://[::1]:<port>/`. The signing page MUST refuse a request with any other `return`. This keeps web sites from receiving signatures made with the user's passkey through the signing page.

The signing page navigates to `return` with the following query parameters. Values are base64url (except `rp_id` and `error`).

| Parameter | Content |
| --- | --- |
| `v`, `state` | `1` and the request's `state`. |
| `rp_id`, `key`, `credential` | For `op=key`: the RP ID, the `es256` public key (the same key bytes as `p` in SPEC 4.1), and the credential ID. |
| `authenticator_data`, `client_data`, `sig` | For `op=sign`: the assertion's `authenticatorData`, `clientDataJSON`, and the DER signature. |
| `error` | On failure: `cancelled`, `invalid-request`, or `unsupported`. |

### 8.5 What the tool does

- The tool MUST accept only a response whose `state` matches a pending request, and MUST use each `state` once. Other responses are ignored.
- For an `op=key` response, the tool checks that `rp_id` equals the signing page's host name or is a parent domain of it.
- For an `op=sign` response, the tool MUST verify the signature against the requested payload and the public key from `op=key` as in SPEC 6.1, and MUST append the block only if it verifies.
- For a response to a request with `user_verification=required`, if the UV flag of `authenticatorData` is not set, the tool MUST NOT append the block.
- If the document changed between the request and the response, the tool MUST discard the response.
