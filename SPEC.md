# md-signature: Embedded Signatures for Markdown Documents

- **Version:** 0.0.2 (draft)
- **Status:** Working draft, intended for submission as `draft-md-signature-00`
- **License:** CC0 1.0 Universal (see `LICENSE-SPEC`)
- **Original text:** [日本語 (SPEC.ja.md)](SPEC.ja.md). This English version is the normative text, maintained for a possible IETF submission. The two are kept in sync; if they differ, this English text prevails.

## Abstract

This document specifies `md-signature`, a format for embedding one or more
digital signatures inside a Markdown document. Signatures are stored in HTML
comments appended to the end of the file, so they do not affect rendering, and
the signed document stays a single self-contained file. Multiple signers form an
append-only hash chain: each signature covers the document and every signature
before it.

## 1. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when,
and only when, they appear in all capitals, as shown here.

- **Document**: A UTF-8 encoded Markdown file.
- **Signature block** (block): One `<!-- md-signature ... -->` comment as defined in Section 3.
- **Chain**: The ordered sequence of signature blocks at the end of a document (Section 5.2).
- **Body**: The bytes of the document that precede the first block of the chain.
- **Generator**: Software that creates signature blocks.
- **Verifier**: Software that checks signature blocks.

## 2. Design Goals

1. **Zero rendering impact.** Blocks are HTML comments; CommonMark and GFM renderers do not display them.
2. **Single-file portability.** No detached signature files.
3. **Append-only co-signing.** A new signer appends a block that covers all preceding bytes, including earlier blocks.
4. **Crypto-agility.** Algorithm identifiers are explicit, so new algorithms (including post-quantum ones) can be added without changing the format.
5. **Web-standard implementability.** Everything in this specification can be implemented with the Web Crypto API, `fetch`, and `CompressionStream` / `DecompressionStream`.

## 3. Signature Block Syntax

### 3.1 Example

```markdown
# Purchase Agreement

The parties agree to the following terms...

<!-- md-signature
v: 0.0.2
method: git-hosting
signer: github.com/alice
role: author
reason: Initial draft
ts: 2026-11-16T09:00:00Z
alg: ed25519
hash: sha256:3a0d0b5c...
sig: base64:q1Xv...
-->
<!-- md-signature
v: 0.0.2
method: dns
signer: example.com
selector: 2026
role: approver
ts: 2026-11-16T09:46:00Z
alg: ed25519
hash: sha256:8f434346...
sig: base64:Zm9v...
tsa_url: http://ts.ssl.com
tsa_token: |
  gzip+base64:H4sIAAAAAAAA/+3SW0hTURwG8G+mpWZRFl0oKiR7
  sJuZRZJGQSRRQUQk9VJUFBRBhhGFFdGNioqCLu
-->
```

### 3.2 Grammar

The following ABNF [RFC5234] describes a block. `LF` is the line terminator after
normalization (Section 5.1); generators MUST emit `LF`, and verifiers MUST
accept `CRLF` and `CR` by normalizing first.

```abnf
block        = open-line *(field) close-line
open-line    = "<!-- md-signature" LF
close-line   = "-->" [LF]
field        = simple-field / folded-field
simple-field = key ":" SP value LF
folded-field = key ":" SP "|" LF 1*(cont-line)
cont-line    = 2SP value LF
key          = (%x61-7A) *(%x61-7A / DIGIT / "_")      ; lowercase a-z, 0-9, _
value        = vchar *(*SP vchar)                      ; no leading/trailing space
vchar        = %x21-7E / UTF8-non-ascii                ; printable, non-space
```

Rules that apply in addition to the grammar:

1. The open line MUST be exactly `<!-- md-signature` with no leading or trailing characters (trailing spaces/tabs MAY be tolerated by verifiers). The close line MUST be exactly `-->`.
2. A block MUST NOT contain blank lines. CommonMark ends an HTML block at a blank line, so a blank line would make the rest of the block visible when rendered.
3. Values MUST NOT contain the sequence `--`. This prevents an early end of the HTML comment. Generators MUST reject such input rather than silently changing it.
4. Values MUST NOT contain control characters (U+0000–U+001F, U+007F–U+009F), line separators (U+2028, U+2029), or bidirectional control characters (U+202A–U+202E, U+2066–U+2069), except the `LF` that separates the lines of a folded value (rule 7). These characters can be used to forge the verification result shown on a terminal or screen.
5. A key MUST NOT appear more than once in a block. Verifiers MUST reject a block with duplicate keys.
6. Verifiers MUST accept fields in any order. Generators SHOULD emit them in this order: `v`, `method`, `signer`, method-specific keys (`selector`, `key_fp`, `fpr`, `pubkey`), `rp_id`, `role`, `reason`, `ts`, `expires`, `scope`, `require`, `resources`, `revocation_url`, extension keys (`x_*`, sorted), `alg`, `hash`, `sig`, `webauthn_authenticator_data`, `webauthn_client_data`, `tsa_url`, `tsa_token`.
7. **Folding.** A folded field's value is its continuation lines, with the two-space indent removed, joined by `LF` (there is no `LF` after the last line). Each continuation line is checked against rules 3 and 4 on its own. Folding has two uses:
   - **Lists**, such as `require` and `resources`, where each line is one item.
   - **Long binary values.** Generators SHOULD fold `sig`, `tsa_token`, `webauthn_authenticator_data`, and `webauthn_client_data` when they are longer than 76 characters, using lines of at most 76 characters. Decoders of these values MUST remove all `LF` and whitespace before decoding.

   A generator MUST use the folded form for any value that contains `LF`.

### 3.3 Common fields

| Key | Requirement | Description |
| --- | --- | --- |
| `v` | MUST | Format version. This document defines `0.0.2`. Verifiers MUST accept blocks with `0.0.1` and `0.0.2`. `0.0.1` is the same as `0.0.2` except that its `require` has no step or order lines (Section 5.8). A chain MAY contain both. Blocks with an unsupported version are handled by step 1 of Section 5.4. |
| `method` | MUST | How the public key is resolved: `dns`, `git-hosting`, `pgp`, `tofu`, or `directory`; or `tsa` for a timestamp block that has no signer (Section 4). |
| `signer` | MUST | Signer identifier. Its syntax depends on `method`. |
| `role` | MAY | Signer's role. RECOMMENDED values: `author`, `reviewer`, `approver`, `witness`. Other values are allowed. |
| `reason` | MAY | Free-text reason or comment. |
| `ts` | MUST | Signing time claimed by the signer, in UTC: `YYYY-MM-DDTHH:MM:SSZ` [RFC3339]. This is a claim only; see `tsa_token` for third-party evidence. |
| `alg` | MAY | Signature algorithm. Default `ed25519`. See Section 6. `rfc3161` in a `tsa` block (Section 4.6). |
| `hash` | MUST | Digest of the covered document slice: `<hash-alg>:<lowercase-hex>`. Default `sha256`. |
| `sig` | MUST | Signature over the signed payload: `base64:<standard base64 with padding>` [RFC4648, Section 4]. |
| `tsa_url` | MAY | Endpoint of the RFC 3161 time-stamping authority (TSA) used to obtain `tsa_token`. |
| `tsa_token` | MAY | RFC 3161 `TimeStampResp`, DER-encoded, with an encoding prefix: `base64:` or `gzip+base64:` (RECOMMENDED). `zstd+base64:` is reserved and not yet defined for use. |
| `expires` | MAY | Time after which the signature is no longer valid, same format as `ts` (Section 5.9). |
| `scope` | MAY | Sign only marked sections of the document instead of the whole slice (Section 5.6). |
| `require` | MAY | Co-signatures that must follow for the document to be complete (Section 5.8). |
| `resources` | MAY | Hashes of external files and URLs the document refers to (Section 5.7). |
| `revocation_url` | MAY | `https://` URL of the signer's revocation list (Section 5.9). |
| `rp_id`, `webauthn_authenticator_data`, `webauthn_client_data` | — | REQUIRED when `alg` is `webauthn-es256`, and MUST NOT appear otherwise (Section 6.1). |
| `x_*` | MAY | Extension fields for private use, for example `x_ref: PO-123`. |

Method-specific fields are listed in Section 4.

Verifiers MUST reject a block that is missing a REQUIRED field, or that has a
`v` they do not support.

**Unknown fields.** A verifier MUST report a block as **malformed** if it contains
a key that is neither defined in this document nor starts with `x_`. Keys
starting with `x_` carry no meaning defined here: verifiers MUST NOT change
their verification result because of them, but they are still part of the
signed payload (Section 5.3), so they cannot be changed without breaking the
signature. Because unknown fields cause a failure, a future version that adds a
field cannot be mistaken for a valid signature by a verifier that does not
understand that field.

## 4. Key Resolution Methods

### 4.1 `dns`: Domain TXT record

- `signer`: A domain name, lowercase, without a trailing dot.
- `selector` (MAY): A DNS label. If present, the record is at `<selector>._mdsig.<signer>`. If absent, it is at `_mdsig.<signer>`.
- Record value: a list of `tag=value` pairs separated by `;` with optional whitespace, for example:

  ```
  _mdsig.example.com. IN TXT "v=mdsig1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
  ```

  - `v` MUST be `mdsig1`.
  - `k` is the key type. It MUST be the key type of the block's `alg` (Section 6): `ed25519` for `ed25519`, `es256` for `webauthn-es256`.
  - `p` is the public key in standard base64. For `ed25519` it is the raw 32-byte key [RFC8032] (the same convention as DKIM [RFC8463]); verifiers SHOULD also accept a DER `SubjectPublicKeyInfo`. For `es256` it is a DER `SubjectPublicKeyInfo` for a P-256 key [RFC5480]; verifiers SHOULD also accept the 65-byte uncompressed point.
  - `dir` (MAY) is the `https://` URL of a key directory (Section 4.7). `dir` has meaning only in a record at the name `_mdsig.<domain>`, which has no `selector`. A record with `dir` need not have `k` and `p`, and MAY share a record with the key tags. For example: `_mdsig.example.com. IN TXT "v=mdsig1; dir=https://keys.example.com"`.
  - Verifiers MUST ignore unknown tags. A record without `p` is not treated as a key.
- If the TXT record is split into multiple character-strings, verifiers MUST concatenate them before parsing.
- If several TXT records at the name have `v=mdsig1`, the signature is valid if it verifies with any of them. This allows key rotation.
- Implementations that cannot use the system resolver (browsers, edge runtimes) SHOULD use DNS-over-HTTPS [RFC8484], for example the JSON API at `https://cloudflare-dns.com/dns-query` with fallback to `https://dns.google/resolve`. This works for any domain; the domain's DNS provider does not have to support DoH.
- Verifiers SHOULD tell users that DNS records can change after signing (Section 9.3).

### 4.2 `git-hosting`: SSH keys published by a Git hosting service

- `signer`: `<host>/<username>`, for example `github.com/alice` or `gitlab.com/bob`. `<host>` MUST be a domain name of two or more labels. A block whose `<host>` is an IP address or a single-label name (such as `localhost`) is **malformed**.
- `key_fp` (MAY): The OpenSSH fingerprint of the key, `SHA256:<unpadded base64 of SHA-256 over the SSH wire-format public key blob>` (the format printed by `ssh-keygen -l`).
- Lookup: `GET https://<signer>.keys` returns one OpenSSH public key per line. Verifiers MUST use only lines whose key type matches `alg` (`ssh-ed25519` for `ed25519`). If `key_fp` is present, verifiers MUST use only the key with that fingerprint. Otherwise the signature is valid if it verifies with any listed key.
- Generators MUST produce a raw Ed25519 signature [RFC8032] directly over the signed payload (Section 5.3), for example with the raw private key or with an ssh-agent `SSH_AGENTC_SIGN_REQUEST`. Generators MUST NOT use the OpenSSH SSHSIG format (`ssh-keygen -Y sign`), which signs a different, wrapped message and is not compatible.
- An ssh-agent returns the signature in SSH wire format (`string "ssh-ed25519"`, `string signature`). Generators MUST store only the inner 64-byte signature in `sig`.
- Verifiers SHOULD tell users that the key list reflects the account's current keys, not the keys at signing time.

### 4.3 `pgp`: OpenPGP

- `signer`: A lowercase email address (`local@domain`).
- `fpr` (MUST): The fingerprint of the key used to sign (the primary key or a signing subkey), 40 uppercase hexadecimal characters (v4 keys) or 64 (v6 keys) [RFC9580].
- `alg`: MUST be `openpgp`. A block with `method: pgp` whose `alg` is not `openpgp`, and a block whose `method` is not `pgp` and whose `alg` is `openpgp`, are **malformed**. The signature format is specified in Section 6.2.
- **Key lookup.** Verifiers look for the key in the following order and stop at the first certificate (transferable public key) that contains a key with fingerprint `fpr`.
  1. The user's local keyring (only in implementations that have one, for example `gpg --export <fpr>`).
  2. WKD [WKD] for the domain of `signer`. The advanced method (`https://openpgpkey.<domain>/.well-known/openpgpkey/<domain>/hu/<hash>?l=<local>`) is tried first, then the direct method (`https://<domain>/.well-known/openpgpkey/hu/<hash>?l=<local>`). `<hash>` is the z-base-32 encoding of the SHA-1 of the lowercased local part.
  3. A keyserver chosen by the verifier, `https://keys.openpgp.org` by default, using HKP [HKP]: `GET <keyserver>/pks/lookup?op=get&options=mr&search=0x<fpr>`.

  A block cannot name the keyserver. If the signer could, anyone could sign under someone else's `signer` through a keyserver that does not confirm email addresses. Verifiers SHOULD use only keyservers that confirm email addresses.

  In a verifier running in a browser, a WKD fetch can fail because the WKD server does not allow CORS. In that case the verifier SHOULD go on to the keyserver lookup.
- **Key validation.** Verifiers MUST check all of the following on the retrieved certificate.
  1. A primary key or subkey matching `fpr` exists.
  2. A user ID exists that has a valid self-certification by the primary key (signature types 0x10 to 0x13) and whose email address (the part between `<` and `>`, or the whole user ID if there are none) matches `signer`, compared case-insensitively.
  3. If `fpr` refers to a subkey, a valid subkey binding signature (0x18) by the primary key exists, its key flags include signing (0x02), and it contains a valid embedded primary key binding signature (0x19) made by the subkey. If `fpr` refers to the primary key and the self-certification has key flags, they include signing (0x02).
  4. No valid revocation signature (0x20 or 0x28) exists for the key (the primary key, or the subkey `fpr` refers to).

  If no certificate satisfying conditions 1 to 3 is obtained, the result is **unresolved** (code `not-found`). Some keyservers do not distribute user IDs whose email address has not been confirmed, so condition 2 can fail with them. If condition 4 fails, the block is **invalid** (code `revoked`). If the key has expired at verification time, verifiers SHOULD warn but MUST NOT treat the block as invalid for that reason alone. Evidence of the signing time comes from `tsa_token` (Section 5.5).
- **Distinguishing lookup results.** The result is `not-found` only if every source tried answered that the key does not exist. If any source did not answer because of a communication failure, the result is `network`. Verifiers SHOULD show the user the result for each source.
- Generators MAY sign with a local OpenPGP implementation (for example `gpg --detach-sign`). In that case too, the signed data is the signed payload (Section 5.3), and the signature MUST satisfy the conditions in Section 6.2.

### 4.4 `tofu`: Trust on first use (embedded key)

- `signer`: Any identifier, for example `bob@laptop`.
- `pubkey` (MUST): `<key-type>:<base64>`, for example `ed25519:11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=`. The key type and encoding are the same as for `dns` (Section 4.1). A `pubkey` whose key type does not match `alg`, or that cannot be decoded, makes the block **malformed**.
- A `tofu` signature proves only that the document has not changed since someone holding that key signed it. It does not prove who that is.
- Verifiers that keep state SHOULD remember the `signer` → `pubkey` binding the first time they see it and MUST report a block as **invalid** (code `key-changed`) if a later document uses the same `signer` with a different `pubkey`. The binding is stored after the block has verified, and is replaced only when the user explicitly accepts the new key.

### 4.5 Key snapshots (`dns`, `git-hosting`, `directory`)

The public keys of `dns`, `git-hosting`, and `directory` are fetched at verification time, so
once the signer removes or changes a key, earlier signatures can no longer be
checked (Section 9.3). To prepare for this, a `dns`, `git-hosting`, or `directory` block MAY
include the public key it was signed with in `pubkey`, in the format of
Section 4.4. A block whose `v` is `0.0.1` does not include `pubkey`. A `pgp`
block does not include `pubkey`.

`pubkey` is part of the signed payload, but the signer wrote it. A forger can
embed a key of their own, so `pubkey` alone does not show that the key belongs
to `signer`. A verifier MUST verify a `dns`, `git-hosting`, or `directory` block that has
`pubkey` as follows, in place of steps 4 and 5 of Section 5.4.

1. A block whose `pubkey` has a key type that does not match `alg` or cannot be
   decoded, or a `git-hosting` block whose `key_fp` is not the fingerprint of
   `pubkey`, is **malformed**.
2. Verify `sig` with `pubkey`. If it does not verify, the block is
   **invalid (bad signature)**. This check comes before fetching keys.
3. Fetch keys as in Section 4.1, 4.2, or 4.7. If the fetched keys include the key in
   `pubkey`, continue with the remaining steps as usual.
4. If fetching succeeded but did not include that key, or no key exists,
   perform the remaining steps as usual, and if none of them fails, the block
   is **unresolved** (code `key-not-published`). A fetch that fails because of
   the network is **unresolved** as before.

A verifier MUST NOT present a `key-not-published` block as valid. What can be
reported is that the signature holds with the embedded key and, when a
timestamp (`tsa_token` or a later `tsa` block) verifies, that the signature
existed at that time. It cannot be shown that the key was published as
`signer`'s key at that time. When the time of a timestamp is confirmed, a
verifier SHOULD report it as well.

### 4.6 `tsa`: Timestamp block

A `tsa` block has no signer. Its RFC 3161 timestamp shows that the whole chain
before it, earlier timestamps included, existed at a given time. Appending
further `tsa` blocks renews the timestamp, to prepare for a TSA certificate
being revoked or a hash algorithm weakening. The idea is the same as in
RFC 4998.

- `v`: `0.0.2` or later.
- `method`: `tsa`. `alg`: `rfc3161`. A block with only one of the two is **malformed**.
- `signer`: the `http://` or `https://` URL of the TSA. Verification
  authenticates the TSA certificate in the token, not this value.
- `ts`: the time claimed by the generator.
- `hash`: the digest of the slice, as for any block (Section 5.3), with
  `sha256` or `sha512`.
- `sig`: the DER-encoded `TimeStampResp` with an encoding prefix, as in
  `tsa_token`.
- Optionally `reason` and `x_*`. A block with any other field is **malformed**.

The generator digests the signed payload (Section 5.3) with the algorithm of
`hash` and sends a `TimeStampReq` with that digest as `messageImprint` and a
`nonce`.

A verifier MUST verify a `tsa` block as follows, in place of step 4 and the
steps after it in Section 5.4.

1. If the token cannot be decoded, the block is **malformed**.
2. If the response status is not `granted` or `grantedWithMods`, or the
   algorithm and value of `messageImprint` are not the digest of the signed
   payload with the algorithm of `hash`, the block is **invalid (bad
   signature)**.
3. Verify the CMS signature of the token and the TSA certificate chain against
   a trust store of the verifier's choice (Section 5.5). If this succeeds, the
   block is **valid**, and the verifier reports `genTime` and the name of the TSA
   certificate. If it cannot be verified, the block is **unresolved**.

A `tsa` block does not satisfy `require` (Section 5.8).

### 4.7 `directory`: Key directory

A key directory is a service that publishes public keys bound to an email
address after confirming that the address's owner agrees. Signers without a
domain can sign with an email address as `signer`. Anyone can run a key
directory; this document does not name a particular operator.

- `signer`: An email address in lowercase (`local@domain`).
- `alg`: `ed25519` or `webauthn-es256`.
- `pubkey` (MAY): A key snapshot as in Section 4.5. Generators SHOULD include `pubkey`, for the case where the directory stops or the key is removed.
- A block cannot name a key directory. If the signer could name the directory, anyone could sign as someone else's `signer` through a directory that does not confirm addresses (the same reason as for the keyserver in Section 4.3).
- **Choosing the directory.** Verifiers MUST choose the directory to query in this order:
  1. The `dir` tag of the `v=mdsig1` TXT record (Section 4.1) at `_mdsig.<domain>`, where `<domain>` is the domain part of `signer` (after `@`). If there are several different `dir` values, the block is **unresolved** (code `not-found`). If exactly one `dir` value is found, verifiers MUST query only that directory.
  2. If there is no `dir`, the verifier's list of trusted directories. Verifiers query them in order and stop at the first that returns keys. The default list is up to the implementation. Implementations SHOULD let users add to the list or replace it.

  If the DNS query does not complete because of a network failure, the result is **unresolved** (code `network`).
- **Fetching keys.** Verifiers send `GET <dir>/v1/keys/<hex>`, where `<hex>` is the SHA-256 of the UTF-8 bytes of `signer` in lowercase hexadecimal, with any trailing `/` removed from `<dir>`. The response is a JSON object of this form:

  ```json
  {"email": "alice@example.com", "verified": "email",
   "keys": [{"type": "es256", "key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE…", "added": "2026-11-18T09:00:00Z"}]}
  ```

  - Verifiers MUST treat a response whose `email` does not equal `signer` as a response that no key exists.
  - In each element of `keys`, `type` is a key type (Section 6) and `key` is the public key in standard base64, encoded as for `p` in Section 4.1. Verifiers MUST ignore elements whose `type` does not match the block's `alg` and elements with an unknown `type`.
  - `verified` is how the directory confirmed the address's owner. This version defines only `email`.
  - If no confirmed key exists, the directory returns HTTP 404.
- **Distinguishing results.** As in Section 4.3, the result is `not-found` only if every directory queried answered that no key exists. If any directory did not answer because of a network failure, the result is `network`. Verifiers SHOULD show the user which directory returned the keys and whether it was chosen by the domain's `dir` or from the trusted list.
- **Requirements for directories.** A key directory MUST do all of the following:
  1. Before publishing a key, obtain the agreement of the address's owner through a confirmation sent to that address.
  2. Confirm that the registrant holds the private key, through a signature over a challenge the directory issued.
  3. Provide a way for the address's owner to remove keys.
  4. Add `Access-Control-Allow-Origin: *` to lookup responses, for verifiers that run in browsers.

  This document does not specify how keys are registered or removed.

## 5. Normalization and Cryptographic Procedure

### 5.1 Document normalization

Given a byte sequence `S`, `normalize(S)` is:

1. If `S` starts with the UTF-8 byte order mark (`EF BB BF`), remove it.
2. Replace every `CRLF` with `LF`, then every remaining `CR` with `LF`.
3. Remove all trailing `LF`, `SP` (U+0020), and `HTAB` (U+0009) characters from the end.
4. Append exactly one `LF`.

No Unicode normalization is done. Generators SHOULD NOT change the
document's characters before signing.

Documents MUST be valid UTF-8. Generators MUST refuse to sign, and verifiers
MUST report a failure for, a document that is not valid UTF-8.

### 5.2 The chain and document slices

The **chain** is found by scanning from the end of the normalized document:

1. Trailing whitespace is ignored.
2. If the document then ends with a close line `-->`, find the nearest preceding open line `<!-- md-signature`. If every line between them is a valid field line, this is a block. Repeat, skipping whitespace-only lines between blocks.
3. Stop at the first text that is not a block or whitespace. Everything before it, plus that text, is the body.

The hash of every block is computed from the start of the document, so the cost of verification grows with the number of blocks. A verifier MAY limit the number of blocks in a chain. If it does, the limit is at least 256, and a document over the limit is reported as a failure.

So the chain is the largest run of blocks at the end of the file separated only
by whitespace. Example blocks inside the body (for example in a fenced code
block, followed by more prose) are part of the body and are not verified.

The **slice** for block `N` (counting from 1) is every byte of the document
from the start to the first byte of block `N`'s open line. For block 1 that is
the body; for block `N > 1` it is the body plus blocks 1 to `N-1` and the
whitespace between them.

Verifiers MUST treat any non-whitespace text after the last block as a
failure, because no signature covers it. (By the definition above, such text
would also end the chain, so a document whose last non-whitespace content is
not a block has no signatures.) Verifiers SHOULD report "content after the
last signature" when a recognizable block is followed by other text.

### 5.3 Digest and signed payload

For block `N`:

1. `hash = <hash-alg> ":" lowercase-hex(H(normalize(slice_N)))`, where `H` is the hash named by `<hash-alg>` (default SHA-256). If the block has a `scope` field, the input to `H` is defined by Section 5.6 instead.
2. The **signed payload** is built from every field of the block except `sig`, `tsa_url`, `tsa_token`, `webauthn_authenticator_data`, and `webauthn_client_data`:
   1. Sort fields by key, comparing keys as ASCII byte strings.
   2. Write each field as `key "=" value`. If the value contains `LF` (a folded list), write every `LF` in it as `LF` followed by two spaces. Keys start with a lowercase letter, so a continuation line can never be mistaken for another field.
   3. Join with `LF`. There is no trailing `LF`.
   4. Prepend the domain separation line `md-signature/v1` followed by `LF`.
   5. Encode as UTF-8.
3. `sig = "base64:" base64(Sign(private-key, payload))`.

Since `hash` is in the payload, the signature covers the document; since every
other field is in the payload, `signer`, `role`, `reason`, `ts`, and so on cannot be
changed without breaking the signature.

Example payload for the first block in Section 3.1:

```
md-signature/v1
alg=ed25519
hash=sha256:3a0d0b5c...
method=git-hosting
reason=Initial draft
role=author
signer=github.com/alice
ts=2026-11-16T09:00:00Z
v=0.0.2
```

### 5.4 Verification procedure

For each block in the chain, in order, a verifier MUST:

1. If the block has exactly one `v` and its value is not a version the verifier supports, the block is **unsupported** (unsupported version). This check comes before every other check, so that a block with fields added by a later version is reported as an unsupported version rather than as malformed. A block whose `v` is missing or repeated is **malformed** by step 2.
2. Parse the block (Section 3). On a syntax error, a missing REQUIRED field, or an unknown field, the block is **malformed**.
3. Compute the digest of the block's slice (or of its scoped sections, Section 5.6) and compare it with `hash` (constant-time comparison is not required; the values are public). On mismatch the block is **invalid (hash mismatch)**.
4. Build the payload and resolve candidate public keys with `method` (Section 4). If resolution fails because of the network, the result is **unresolved**, which is different from invalid.
5. Verify `sig` with each candidate key (for `webauthn-es256`, as in Section 6.1; for `openpgp`, as in Section 6.2). If none verifies, the block is **invalid (bad signature)**.
6. If `expires` is present and has passed, the block is **invalid (expired)** (Section 5.9).
7. If `resources` is present, check it (Section 5.7).
8. If `revocation_url` is present, check it (Section 5.9).
9. If `tsa_token` is present, check it (Section 5.5).

A block whose `method` is `tsa` is verified as in Section 4.6 in place of step 4
and the steps after it, and a `dns`, `git-hosting`, or `directory` block with `pubkey` as in
Section 4.5 in place of steps 4 and 5.

The document is **verified** only if the chain has at least one block, every
block is valid, there is no unsigned content after the last block, and the
agreement status (Section 5.8) is not `violated`.
Separately, a verified document whose `require` fields (Section 5.8) are not
all satisfied is **verified but pending**; verifiers MUST NOT present such a
document as complete.

### 5.5 RFC 3161 timestamps

The timestamp covers the signature, so the evidence chain is
`document → hash → sig → tsa_token`.

1. The generator computes `SHA-256(raw signature bytes)` (the decoded `sig`, not the base64 text).
2. It sends a `TimeStampReq` [RFC3161] to `tsa_url` with that value as `messageImprint` (hash algorithm `id-sha256`), `certReq` set to `TRUE`, and a random `nonce`.
3. It stores the full DER `TimeStampResp` in `tsa_token`, RECOMMENDED as `gzip+base64:`. The `tsa_url` and `tsa_token` fields are not in the signed payload, so a timestamp can be added after signing.

A verifier that checks a timestamp MUST confirm that the response status is
`granted` or `grantedWithMods` and that the `messageImprint` in the `TSTInfo`
equals `SHA-256(raw signature bytes)`. Because `tsa_token` is not in the signed
payload and a third party can replace it, a verifier SHOULD limit its
decompressed size (RECOMMENDED: 1 MB). It SHOULD report `genTime`. It SHOULD
verify the CMS signature of the token and the TSA certificate chain against a
trust store it chooses. A verifier that does not do the CMS check MUST say so
when it reports the timestamp (for example "imprint matched, TSA signature not
checked").

### 5.6 Section signing (`scope`)

A signer can sign only parts of the document, so that other parts (notes,
fill-in fields, appendices) can still be edited without breaking the signature.

**Section markers.** A section is delimited by two marker lines in the body,
each alone on its line (trailing spaces and tabs are tolerated):

```markdown
<!-- mdsig:section terms -->
## Terms
...
<!-- /mdsig:section -->
```

- The section ID matches `[a-z0-9-]+`.
- Marker lines inside fenced code blocks are not markers.
- Sections MUST NOT be nested, and an ID MUST NOT be used twice.
- Every begin marker MUST have a matching end marker.

**Field.** `scope` is a comma-separated list of `section:<id>`, for example
`scope: section:terms,section:fees`.

**Hash input.** For a block with `scope`, the input to `H` in Section 5.3 is
the concatenation, in the order listed, of `normalize(section)` for each listed
section, where `section` is the text from the first byte of the begin marker
line to the end of the end marker line. Markers are looked up in the block's
slice (Section 5.2). Normalization gives every section exactly one trailing
`LF`, so section boundaries cannot be shifted without changing the hash.

**Verification.**

- If the markers in the slice break the rules above, the block is **malformed**.
- If a listed ID is not found, the block is **invalid (scope missing)**.
- A verifier MUST show, wherever it reports such a block as valid, that the signature covers only the listed sections (for example "valid (partial: terms, fees)").

A block without `scope` still covers its whole slice, including any sections
and the text around them. A signer who wants later edits outside the sections
to keep the chain valid therefore needs every later signer to use `scope` as
well.

### 5.7 External resources (`resources`)

`resources` binds files and URLs that the document refers to, such as
screenshots, diagrams, and data files. Each line of its value is
`sha256:<lowercase-hex> SP <ref>`:

```
resources: |
  sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 ./diagram.png
  sha256:8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4 https://example.com/chart.png
```

- `<ref>` is either an `https://` URL or a relative path. A relative path uses `/` as the separator, is resolved against the directory that contains the document, and MUST NOT be absolute, start with a drive letter, contain `\`, or contain a `..` segment.
- The hash is SHA-256 over the exact bytes of the file or of the HTTP response body.

Verification:

1. **Local files** MUST be checked whenever the verifier has access to the document's directory. If a file is missing, the block is **invalid (resource missing)**. If its hash differs, the block is **invalid (resource mismatch)**.
2. **URLs** SHOULD be fetched only when the user asks for it (Section 9.8). If they are not fetched, the verifier MUST say that the remote resources were not checked. If a URL cannot be fetched, the block is **unresolved**. If its hash differs, the block is **invalid (resource mismatch)**.
3. Verifiers MUST only fetch `https://` URLs, SHOULD limit the response size (RECOMMENDED: 50 MB), and SHOULD refuse addresses in private, loopback, and link-local ranges.

Remote content can change for legitimate reasons, such as re-encoding by a
CDN or the page going away. For long-term evidence, signers SHOULD keep a
local copy and list the copy.

### 5.8 Required co-signatures (`require`)

`require` states which co-signatures must follow before the document is
complete, in what order, and how many of them. Each line of its value is one
of:

- **Requirement line:** `<method>:<signer>` optionally followed by `SP <role>`.
- **Step line:** `step <n>` or `step <n> any <m>`. It starts the step that the following requirement lines belong to.
- **Order line:** `order pending`, `order guide`, or `order strict`.

```
require: |
  order strict
  step 1
  dns:example.com approver
  step 2 any 2
  git-hosting:github.com/bob reviewer
  git-hosting:github.com/carol reviewer
  git-hosting:github.com/dave reviewer
  step 3
  dns:legal.example.com
```

In this example the document is complete once `example.com` has approved,
then two of the three reviewers have signed, and finally `legal.example.com`
has signed.

```abnf
require-value = [order-line LF] (steps / members)
order-line    = "order" SP ("pending" / "guide" / "strict")
steps         = step-group *(LF step-group)
step-group    = step-line 1*(LF member)
step-line     = "step" SP count [SP "any" SP count]
members       = member *(LF member)
member        = method ":" 1*vchar [SP 1*vchar]
method        = %x61-7A *(%x61-7A / DIGIT / "-")
count         = %x31-39 *3DIGIT
```

A verifier MUST treat a block as **malformed** if its value breaks any of these
rules:

1. An order line appears only as the first line of the value.
2. When step lines are used, the first line other than the order line is `step 1`, and the numbers run from 1 without gaps.
3. Every step has at least one requirement line, and the `m` of `any <m>` is not larger than the number of requirement lines in the step.
4. A step does not list two requirement lines with the same `method`, `signer`, and `role`.
5. A block whose `v` is `0.0.1` contains no step or order lines.
6. In a block whose `v` is `0.0.2` or later, the `method` of a requirement line is not `tsa`.

A value without step lines forms one step from all of its requirement lines
and needs all of them. A step without `any` also needs all of its members.

The requirements declared by block `N` are evaluated step by step. A
requirement in a step can be satisfied by a valid block after `N` whose `method`
is not `tsa` and that has the
same `method` and `signer` (domain names compared without case and without a
trailing dot) and, if a role is given, the same `role`. Within one
declaration, a block counts for one requirement only. A step is **complete**
when `m` different requirements are satisfied, and the position of the block
that satisfied the `m`-th one is the step's completion position.

The declaring signer chooses how the order of steps is handled with the order
line. Without an order line, it is `pending`.

- **`pending`:** Only blocks after the completion position of step `i-1` count
  for step `i`. A signature made before its turn does not count, and the
  agreement stays pending. It is satisfied once that signer signs again.
- **`guide`:** Blocks count regardless of their turn. A block that matches a
  requirement of step `i` and comes before step `i-1` is complete is reported
  as an order violation, but it does not change the agreement status.
- **`strict`:** Blocks count regardless of their turn, and any order violation
  makes the agreement `violated`.

Requirements are collected from every block that is valid or unresolved (for
example, not checked because the verifier is offline), so that a chain that
could not be fully checked is never reported as complete. Only valid blocks
satisfy requirements.

A block with `scope` does not satisfy a requirement. Such a block does not
cover the block that declared the requirement, and it stays valid when moved
to another document that contains the same sections (Section 9.9).

Requirements declared by a block whose `v` is `0.0.1` are evaluated under the
earlier rule: each requirement is satisfied if any later valid block matches
it, and one block may satisfy several requirements.

A verifier MUST report the agreement status of a verified document: `none` (no
requirements), `complete` (every step complete), `pending` (with the list of
missing co-signatures), or `violated` (a `strict` order violation, with the
list of offending signatures). A verifier MUST NOT present a document whose
agreement status is `violated` as agreed. The match is on `method` and
`signer` because those are what the signature authenticates; `role` alone is
the signer's own claim.

### 5.9 Expiry and revocation (`expires`, `revocation_url`)

**Expiry.** `expires` MUST be a real calendar date and time in the `ts`
format (for example, `2026-02-30T00:00:00Z` and `2026-11-16T24:00:00Z` are not);
otherwise the block is **malformed**. If the verifier's current time is later than
`expires`, the block is **invalid (expired)**. Verifiers use their own clock.

**Revocation.** `revocation_url` is the `https://` URL of the signer's
revocation list. The list is itself an md-signature document. Its body
contains one line per revoked signature:

```
revoked: sha256:<lowercase-hex of SHA-256(signed payload)>
```

The identifier is computed from the signed payload (Section 5.3) of the revoked
block. It is not computed from the bytes of `sig`, because a third party
without the private key can change an ECDSA or OpenPGP signature into
different bytes that still verify. The identifier would then change and the
revocation would be bypassed.

1. Verifiers SHOULD fetch the list when they are online. They MUST NOT send any information about the document being verified; the request is a plain `GET` of the URL. The fetch follows the restrictions of Section 5.7, with a RECOMMENDED size limit of 5 MB.
2. The list is trusted only if verifying it as a document succeeds and its chain contains a valid block with the same `method` and `signer` as the revoked block (compared as in Section 5.8, and, for `tofu`, with the same `pubkey`).
3. When verifying the list, verifiers MUST NOT follow `revocation_url` fields found in the list itself, MUST NOT fetch its remote resources, and MUST NOT evaluate its `require` fields. This prevents loops.
4. If the block's identifier is on a trusted list, the block is **invalid (revoked)**.
5. If the list cannot be fetched or is not trusted, the block is **unresolved**. Otherwise blocking the fetch would be enough to hide a revocation. If the user turned the fetch off, or the verifier is offline, the verifier MUST report that revocation was not checked. This does not by itself make the block invalid.

## 6. Algorithms

| `alg` | Status | Notes |
| --- | --- | --- |
| `ed25519` | REQUIRED to implement | [RFC8032] pure Ed25519. Key type `ed25519`. |
| `webauthn-es256` | RECOMMENDED to implement for verification | WebAuthn assertion with ECDSA P-256 / SHA-256 (Section 6.1). Key type `es256`. |
| `openpgp` | RECOMMENDED to implement for verification | OpenPGP signature packet [RFC9580] (Section 6.2). Used only with `method: pgp`. |
| `rfc3161` | RECOMMENDED to implement for verification | RFC 3161 timestamp token (Section 4.6). Used only with `method: tsa`. |
| `ml-dsa-44`, `ml-dsa-65` | Reserved | [FIPS204]. |
| `slh-dsa-sha2-128s` | Reserved | [FIPS205]. |
| `ed25519+ml-dsa-65` | Reserved | Composite. `sig` is the concatenation of both signatures. |

| Hash prefix | Status |
| --- | --- |
| `sha256` | REQUIRED to implement, default |
| `sha512` | Available. Used by `tsa` blocks; verifiers accept it on any block. |
| `sha3-256` | Reserved |

A verifier MUST report a block using an unsupported algorithm as
"unsupported", never as valid.

**Post-quantum archival co-signing.** A party that wants long-term protection
can append a block with a post-quantum `alg`. Because that block covers all
earlier blocks, it protects them even if Ed25519 is later broken.

### 6.1 WebAuthn (`webauthn-es256`)

`webauthn-es256` lets a person sign with a passkey or security key in a web
browser [WebAuthn]. An authenticator does not sign arbitrary data. It signs
`authenticatorData || SHA-256(clientDataJSON)`, where `clientDataJSON` contains
a challenge. The signed payload is bound through that challenge.

Additional fields:

| Key | Description |
| --- | --- |
| `rp_id` | The WebAuthn Relying Party ID (a domain) used for the assertion. It is part of the signed payload. |
| `webauthn_authenticator_data` | `authenticatorData` from the assertion, standard base64. Not part of the payload. |
| `webauthn_client_data` | `clientDataJSON` from the assertion, standard base64. Not part of the payload. |
| `sig` | `base64:` of the assertion `signature`, which is an ASN.1 DER `ECDSA-Sig-Value`. |

**Generator.**

1. Build the payload (Section 5.3), including `rp_id`.
2. Call `navigator.credentials.get()` with `challenge = SHA-256(payload)` and `rpId = rp_id`.
3. Store the three values from the response in the fields above.

**Verifier.** The block's signature is valid only if all of the following hold:

1. `clientDataJSON` parses as JSON, its `type` is `webauthn.get`, and its `challenge` equals the unpadded base64url encoding of `SHA-256(payload)`.
2. The host of its `origin` equals `rp_id` or is a subdomain of it. The origin MUST use `https`, except for `localhost`. Verifiers MUST display `rp_id`, and SHOULD warn when it is `localhost`.
3. The first 32 bytes of `authenticatorData` equal `SHA-256(rp_id)`, and the User Present flag (bit 0 of byte 32) is set.
4. `sig` verifies with a candidate `es256` key over `authenticatorData || SHA-256(clientDataJSON)` with ECDSA P-256 / SHA-256. APIs such as Web Crypto that need the fixed-length `r || s` form require a conversion from DER. The conversion MUST reject malformed DER and integers longer than 33 bytes.

The public key comes from the block's `method`, as for any other algorithm:
`tofu` (`pubkey: es256:...`) or `dns` (`k=es256`). Passkeys are bound to their
RP ID (Section 9.9).

### 6.2 OpenPGP (`openpgp`)

`openpgp` lets a person sign with an existing OpenPGP key, including keys held
by gpg-agent or on a smartcard. `sig` is an OpenPGP detached signature over the
signed payload (Section 5.3) as a binary document [RFC9580].

**Format of `sig`.** `base64:` followed by binary data (no ASCII armor) that
contains exactly one OpenPGP signature packet (tag 2). The signature MUST
satisfy all of the following:

1. It is a version 4 or version 6 signature packet. A v6 signature is made with a v6 key, and a v4 signature with a v4 key.
2. The signature type is 0x00 (binary document).
3. The hash algorithm is SHA-256, SHA-384, or SHA-512.
4. The hashed subpackets include a Signature Creation Time (type 2) and an Issuer Fingerprint (type 33) that matches `fpr`.
5. The public-key algorithm is one of the following:

   | ID | Algorithm | Condition |
   | --- | --- | --- |
   | 1 | RSA (PKCS#1 v1.5) | Modulus of at least 2048 bits |
   | 19 | ECDSA | Curve NIST P-256 |
   | 22 | EdDSALegacy | Curve Ed25519 |
   | 27 | Ed25519 | — |

A signature that does not satisfy conditions 1 to 4, or that contains a
subpacket with the critical flag that the verifier cannot interpret, is
**invalid** (code `bad-signature`). A public-key algorithm not listed in
condition 5 is **unsupported** (code `unsupported-alg`).

**On SHA-1.** Condition 3 forbids SHA-1 as the hash algorithm of the
signature. SHA-1 is still used, as each standard specifies, to compute v4 key
fingerprints, the checksum that protects v4 secret keys, and WKD addresses.

**Verifier.** The block's signature is valid only if OpenPGP signature
verification [RFC9580, Section 5.2.4] with the signed payload as input succeeds
with the key obtained by the procedure in Section 4.3 (the primary key or
subkey that `fpr` refers to).

**Signature creation time.** The creation time in the signature packet is a
value set by the signer, like `ts`. Verifiers SHOULD display the creation time,
`ts`, and the `tsa_token` time as separate values. Only `tsa_token` is
third-party evidence (Section 9.4).

**Timestamps.** The "raw signature bytes" in Section 5.5 are the bytes of the
signature packet obtained by decoding `sig`.

## 7. Appending a Signature (Generator Procedure)

1. Read the document and find the existing chain (Section 5.2). If there is unsigned content after the last block, the generator MUST refuse to co-sign, because the new signature would also endorse content earlier signers never signed. (It MAY offer to sign the whole file as a new body instead, which loses nothing but must be an explicit user choice.)
2. Compute `hash` over the whole file as it is now (this is the slice for the new block).
3. Build the fields, compute `sig`, and optionally obtain `tsa_token`.
4. Write: the original file with trailing whitespace removed, then `LF`, then (only if there is no existing chain) one blank line, then the new block followed by `LF`.

## 8. IANA Considerations

This document has no IANA actions at this time. A future revision may request:

- a registry "md-signature Methods" (initial entries `dns`, `git-hosting`, `pgp`, `tofu`, `tsa`, `directory`);
- a registry "md-signature DNS Tags" (initial entries `v`, `k`, `p`, `dir`);
- a registry "md-signature Algorithms" (Section 6);
- registration of the `_mdsig` underscored DNS node name in the "Underscored and Globally Scoped DNS Node Names" registry [RFC8552].

## 9. Security Considerations

### 9.1 What a signature proves

A valid block proves that the holder of the resolved private key signed the
exact bytes of the slice (after normalization) together with the metadata
fields. How much that says about a real person depends on the method: `dns`
binds to a domain's operator, and `git-hosting` to a Git hosting account. `pgp` binds
to the operator of the email address's domain when the key comes from WKD, to
the confirmation of the email address by the keyserver the verifier chose when
it comes from a keyserver, and to the user's own judgment when it comes from the local keyring.
`directory` binds to the operator of the email address's domain when the directory is chosen by the
domain's `dir`, and to that directory's confirmation of the email address when it comes from the trusted list.
`tofu` binds to nothing beyond the key.

### 9.2 Normalization

Normalization treats documents that differ only in line endings, a leading BOM,
or trailing whitespace as the same. Changes to any other byte, including
whitespace inside the document, break the signature. Unicode text that looks
the same but is encoded differently (for example NFC and NFD) is treated as different.

### 9.3 Key rotation and revocation

`dns`, `git-hosting`, `pgp`, and `directory` resolve keys at verification time. If the signer later
removes the key, older signatures will no longer verify; if an attacker takes
over the domain or account, they can publish a key of their own. Neither case
can be detected from the document alone. For long-term evidence, signers
SHOULD add an RFC 3161 timestamp, and verifiers SHOULD record the key they used
and when. Signers of `dns`, `git-hosting`, and `directory` can include a key snapshot
(Section 4.5). It shows that the signature still holds after the key is
removed, but even with a timestamp it does not show that the key was the
signer's (`key-not-published`). Keepers of long-lived documents SHOULD renew
them by appending a `tsa` block (Section 4.6) before the TSA certificate
expires or the hash algorithm weakens.

### 9.4 Claimed time

`ts` is set by the signer and can be anything. The same holds for the creation
time in an OpenPGP signature packet (Section 6.2). Only `tsa_token` gives
third-party evidence that the signature existed at a given time.

### 9.5 Rendering and display

Renderers do not show blocks, so readers of rendered output cannot see whether a
document is signed. Tools SHOULD show verification results next to rendered
output. Verifiers MUST NOT display a document as "signed" based only on the
presence of blocks.

The body of a document can contain HTML, including HTML comments, that renders
differently from its source. A signature covers the source, not the rendering.

### 9.6 Key reuse and domain separation

`git-hosting` reuses SSH keys that are also used for SSH authentication. The
`md-signature/v1` prefix (Section 5.3) makes signed payloads distinguishable
from SSH authentication data and from other protocols.

### 9.7 Comment injection

Rule 3 of Section 3.2 (no `--` in values) prevents a value from ending the
HTML comment early and injecting visible Markdown.

### 9.8 Fetching resources and revocation lists

Fetching a URL tells its server that someone is verifying, and when. This is
the same as a tracking pixel. That is why verifiers fetch remote `resources`
only on request. Revocation lists are fetched as whole files, so the server
learns that some document of that signer is being verified. If the signer
names a different `revocation_url` in each document, the server also learns
which one. A verifier that runs on a server and processes untrusted documents can
be made to request internal addresses (server-side request forgery); the
restrictions in Section 5.7 apply to revocation lists and to key lookups (the
`git-hosting` host, WKD, the keyserver, and key directories) too. The value of `dir` is chosen by
the operator of the signer's domain, so verifiers treat it as an untrusted URL.

### 9.9 Partial signatures, requirements, and passkeys

- A signature with `scope` leaves the rest of the document unsigned. A reader of the rendered document cannot see where the signed sections end, so text outside them can be added to mislead. That is why verifiers must show partial coverage (Section 5.6). A signature with `scope` also stays valid when moved to another document that contains the same sections, so it is not counted as satisfying `require` (Section 5.8).
- `require` is set by the signer of the declaring block. Its status says only whether the listed parties have co-signed; it does not create obligations.
- With `order strict`, a signer of a later step can make the agreement `violated` just by signing before their turn. Declaring signers SHOULD therefore use the default `pending` and use `strict` only when the order itself matters.
- `any <m>` counts different requirements, so a signer who signs several times still counts once. A verifier cannot check, however, that identifiers listed as different requirements belong to different people.
- A passkey can be used only with the RP ID it was registered for. If the site that hosts the signing page moves to another domain, passkeys registered on the old domain cannot sign there. Signatures that were already made stay verifiable, because `rp_id` is recorded in each block.

### 9.10 OpenPGP keys

- v4 key fingerprints are based on SHA-1. Collision attacks on SHA-1 are known, but forging an `fpr` needs a second preimage, and no practical attack is known at present. Signers who want a stronger binding can use v6 keys.
- WKD and keyservers return the current certificate, not the key as it was at signing time. A certificate fetched after the key was revoked contains the revocation signature, so signatures made before the revocation are also reported as invalid. Evidence that a signature existed before the revocation is `tsa_token`, but the verification procedure in this version does not ignore a revocation on that ground.
- Generators that handle private keys in a browser MUST NOT store the private key or its passphrase in persistent storage, and SHOULD wipe erasable buffers (such as decrypted key material) after signing. JavaScript strings and key material copied inside cryptographic APIs cannot be wiped, so this measure only shortens the exposure.

### 9.11 Key directories

- When the trusted list contains several directories, the strength of the binding is that of the least careful one, because if any of them skips confirmation, anyone can claim any address through it. Verifiers SHOULD include only directories that are known to confirm email addresses.
- A directory operator can publish a false key for any address, and whoever takes over an email account can register keys for that address. This is the same kind of trust as in a `pgp` keyserver or a `git-hosting` service.
- A directory returns the current keys. After a key is removed or the directory stops, a block with `pubkey` is also **unresolved** (code `key-not-published` or `network`). Evidence of the time of signing comes from `tsa_token` and `tsa` blocks.
- The binding between a published key and an email address can be fetched by anyone. The lookup URL contains a hash of the address, but guessing an address from its hash is not hard.

## 10. References

- [RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119.
- [RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174.
- [RFC3161] Adams, C., et al., "Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP)", RFC 3161.
- [RFC3339] Klyne, G. and C. Newman, "Date and Time on the Internet: Timestamps", RFC 3339.
- [RFC4648] Josefsson, S., "The Base16, Base32, and Base64 Data Encodings", RFC 4648.
- [RFC5234] Crocker, D. and P. Overell, "Augmented BNF for Syntax Specifications: ABNF", RFC 5234.
- [RFC5480] Turner, S., et al., "Elliptic Curve Cryptography Subject Public Key Information", RFC 5480.
- [WebAuthn] W3C, "Web Authentication: An API for accessing Public Key Credentials", Level 3.
- [RFC8032] Josefsson, S. and I. Liusvaara, "Edwards-Curve Digital Signature Algorithm (EdDSA)", RFC 8032.
- [RFC8463] Levine, J., "A New Cryptographic Signature Method for DomainKeys Identified Mail (DKIM)", RFC 8463.
- [RFC8484] Hoffman, P. and P. McManus, "DNS Queries over HTTPS (DoH)", RFC 8484.
- [RFC8552] Crocker, D., "Scoped Interpretation of DNS Resource Records through Underscored Naming of Attribute Leaves", RFC 8552.
- [RFC9580] Wouters, P., et al., "OpenPGP", RFC 9580.
- [WKD] Koch, W., "OpenPGP Web Key Directory", Work in Progress, Internet-Draft, draft-koch-openpgp-webkey-service.
- [HKP] Shaw, D. and A. Gallagher, "OpenPGP HTTP Keyserver Protocol", Work in Progress, Internet-Draft, draft-gallagher-openpgp-hkp.
- [FIPS204] NIST, "Module-Lattice-Based Digital Signature Standard", FIPS 204.
- [FIPS205] NIST, "Stateless Hash-Based Digital Signature Standard", FIPS 205.
- CommonMark Spec, Section 4.6 "HTML blocks", https://spec.commonmark.org/
