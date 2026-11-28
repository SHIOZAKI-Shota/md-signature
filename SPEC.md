# md-signature: Embedded Signatures for Markdown Documents

- **Version:** 0.1 (draft)
- **Status:** Working draft, intended for submission as the individual Internet-Draft `draft-shiozaki-md-signature-00`
- **Author:** SHIOZAKI Shota (me@shiozakishota.com; issues: https://github.com/SHIOZAKI-Shota/md-signature/issues)
- **License:** CC0 1.0 Universal (see `LICENSE-SPEC`)
- **Original text:** [日本語 (SPEC.ja.md)](SPEC.ja.md). This English version is the normative text, maintained for a possible IETF submission. The two are kept in sync; if they differ, this English text prevails.
- **Related:** [CLI specification](CLI_SPEC.md) · [Use in agent-to-agent commerce (informative)](AGENT_COMMERCE.md)

## Abstract

This document specifies `md-signature`, a format for embedding one or more
digital signatures inside a Markdown document. Signatures are stored in HTML
comments appended to the end of the file, so they do not affect rendering, and
the signed document stays a single self-contained file. Multiple signers form an
append-only hash chain: each signature covers the document and every signature
before it. A signer can declare which co-signatures must follow before the
document is complete, together with their order, their number, and the
qualifications of the signers.

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
- **Signer identity**: The block's `method` and `signer` joined with `:` (for example `dns:example.com`). It follows the rules of Section 3.4 and is compared by exact match.
- **Declaration**: A block that has a `require` field (Section 5.8).
- **Signed list**: An md-signature document whose body holds a list of entries, such as a revocation list or a roster (Section 5.10).

## 2. Design Goals

1. **Zero rendering impact.** Blocks are HTML comments; CommonMark and GFM renderers do not display them.
2. **Single-file portability.** No detached signature files.
3. **Append-only co-signing.** A new signer appends a block that covers all preceding bytes, including earlier blocks.
4. **Crypto-agility.** Algorithm identifiers are explicit, so new algorithms (including post-quantum ones) can be added without changing the format.
5. **Web-standard implementability.** Everything in this specification can be implemented with the Web Crypto API, `fetch`, and `CompressionStream` / `DecompressionStream`.

## 3. Signature Block Syntax

### 3.1 Example

````markdown
# Purchase Agreement

The parties agree to the following terms...

<!-- mdsig:signatures -->

<!-- md-signature
v: 0.1
method: git-hosting
signer: github.com/alice
display_name: Alice Example
role: author
reason: Initial draft
ts: 2026-11-16T09:00:00Z
require: |
  step
    dns:example.com role=approver
  step any=2
    git-hosting:github.com/bob role=reviewer
    git-hosting:github.com/carol role=reviewer
    git-hosting:github.com/dave role=reviewer
alg: ed25519
hash: sha256:3a0d0b5c...
sig: base64:q1Xv...
-->
<!-- md-signature
v: 0.1
method: dns
signer: example.com
selector: 2026
role: approver
ts: 2026-11-16T09:46:00Z
alg: ed25519
hash: sha256:8f434346...
sig: base64:Zm9v...
-->
<!-- md-signature
v: 0.1
method: tsa
signer: http://ts.ssl.com
ts: 2026-11-16T09:46:05Z
alg: rfc3161
hash: sha256:51c2b0e4...
sig: |
  gzip+base64:H4sIAAAAAAAA/+3SW0hTURwG8G+mpWZRFl0oKiR7
  sJuZRZJGQSRRQUQk9VJUFBRBhhGFFdGNioqCLu
-->
````

In this example `github.com/alice` asks first for the approval of
`example.com` and then for the signatures of two of three reviewers
(Section 5.8). The second block is `example.com`'s approval, and the third, a
`tsa` block, proves when the whole chain before it existed (Section 4.6).
`<!-- mdsig:signatures -->` marks where a viewer may draw the signature table
(Section 5.11).

### 3.2 Grammar

The following ABNF [RFC5234] describes a block. `LF` is the line terminator after
normalization (Section 5.1); generators MUST emit `LF`, and verifiers MUST
accept `CRLF` and `CR` by normalizing first.

```abnf
block          = open-line *(field) close-line
open-line      = "<!-- md-signature" LF
close-line     = "-->" [LF]
field          = simple-field / folded-field
simple-field   = key ":" SP value LF
folded-field   = key ":" SP "|" LF 1*(cont-line)
cont-line      = 2SP *SP value LF                      ; spaces after 2SP are part of the value
key            = %x61-7A *(%x61-7A / DIGIT / "_")      ; lowercase a-z, 0-9, _
value          = vchar *(*SP vchar)                    ; no leading/trailing space
vchar          = %x21-7E / UTF8-non-ascii              ; printable, non-space
UTF8-non-ascii = UTF8-2 / UTF8-3 / UTF8-4              ; [RFC3629]
```

Rules that apply in addition to the grammar:

1. The open line MUST be exactly `<!-- md-signature` with no leading or trailing characters (trailing spaces/tabs MAY be tolerated by verifiers). The close line MUST be exactly `-->`.
2. A block MUST NOT contain blank lines. CommonMark ends an HTML block at a blank line, so a blank line would make the rest of the block visible when rendered.
3. Values MUST NOT contain any of the sequences `-->`, `--!>`, or `<!--`. Generators MUST reject such input rather than silently changing it. The reasons:
   - A block is an HTML block of type 2 in CommonMark 0.31.2 [COMMONMARK] (it starts with `<!--` and ends at the line that contains `-->`). A value containing `-->` would end the block on that line and make the remaining fields visible Markdown.
   - When the text is parsed as HTML, the WHATWG HTML [HTML] parser ends a comment at `-->` or `--!>`, and treats `<!--` inside a comment as a parse error.
   - A block is block-level HTML, so CommonMark's rules for inline raw HTML do not apply to it. CommonMark before 0.31 rejected `--` in inline comments, but that rule does not apply to blocks either. This version therefore does not forbid `--`. The A-labels of internationalized domain names (labels starting with `xn--`) contain `--`.
4. Values MUST NOT contain the following characters, except the `LF` that separates the lines of a folded value (rule 7):
   - control characters of general category Cc (U+0000–U+001F, U+007F–U+009F);
   - format characters of general category Cf (including the bidirectional controls U+202A–U+202E and U+2066–U+2069, the zero-width characters U+200B–U+200D and U+FEFF, and the tag characters U+E0001 and U+E0020–U+E007F);
   - general categories Zl (U+2028) and Zp (U+2029);
   - noncharacters (U+FDD0–U+FDEF and the last two code points of every plane, U+xxFFFE and U+xxFFFF).

   General categories are those of Unicode 15.0.0 [UNICODE]. These characters can be used to forge the verification result shown on a terminal or screen.
5. A key MUST NOT appear more than once in a block. Verifiers MUST reject a block with duplicate keys.
6. Verifiers MUST accept fields in any order. Generators SHOULD emit them in this order: `v`, `method`, `signer`, method-specific keys (`selector`, `key_fp`, `fpr`, `pubkey`), `rp_id`, `display_name`, `role`, `reason`, `ts`, `expires`, `scope`, `require`, `resources`, `revocation_url`, extension keys (`x_*`, sorted), `alg`, `hash`, `sig`, `webauthn_authenticator_data`, `webauthn_client_data`.
7. **Folding.** A folded field's value is its continuation lines, with the first two spaces of each removed, joined by `LF` (there is no `LF` after the last line). Any spaces after those two are part of the value and are signed. Each continuation line is checked against rules 3 and 4 on its own. Trailing whitespace on a continuation line breaks the grammar, and the block is **malformed**. Folding has two uses:
   - **Lists**, such as `require`, `resources`, and `scope`, where each line is one item (Section 3.5). Only the parsers of these lists skip the leading spaces of a line.
   - **Long binary values.** Generators SHOULD fold `sig`, `webauthn_authenticator_data`, and `webauthn_client_data` when they are longer than 76 characters, using lines of at most 76 characters. Decoders of these values MUST remove all `LF` and whitespace before decoding.

   A generator MUST use the folded form for any value that contains `LF`.

**Relation to YAML.** Block fields look like YAML, but they are not YAML.
Every value is a string; values have no types. Reading a block with a YAML
parser and writing it back can change values and break the signature. For
example, `v: 0.1` is read as a number, and `ts` is read as a timestamp and may
be written back in another format. In YAML 1.1, `role: no` becomes false. `|`
looks like a YAML literal block, but the indent removed is always two spaces.
Generators and verifiers MUST read and write blocks according to the grammar
in this section.

### 3.3 Common fields

| Key | Requirement | Description |
| --- | --- | --- |
| `v` | MUST | Format version. This document defines `0.1`. See the end of this section and step 1 of Section 5.4. |
| `method` | MUST | How the public key is resolved: `dns`, `git-hosting`, `pgp`, `tofu`, or `directory`; or `tsa` for a timestamp block that has no signer (Section 4). |
| `signer` | MUST | Signer identifier. Its syntax depends on `method` and follows Section 3.4. |
| `display_name` | MAY | Display name claimed by the signer, for the signature table and similar uses (end of this section). |
| `role` | MAY | Signer's role, a single word matching `[a-z0-9][a-z0-9._-]*`. RECOMMENDED values: `author`, `reviewer`, `approver`, `witness`. |
| `reason` | MAY | Free-text reason or comment. |
| `ts` | MUST | Signing time claimed by the signer, in UTC: `YYYY-MM-DDTHH:MM:SSZ` [RFC3339]. This is a claim only; third-party evidence of time comes from `tsa` blocks (Section 4.6). |
| `alg` | MUST | Signature algorithm. See Section 6. `rfc3161` in a `tsa` block (Section 4.6). |
| `hash` | MUST | Digest of the covered document slice: `<hash-alg>:<lowercase-hex>`. |
| `sig` | MUST | Signature over the signed payload: `base64:<standard base64 with padding>` [RFC4648, Section 4]. For `tsa` blocks, see Section 4.6. |
| `expires` | MAY | Time after which the signature is no longer valid, same format as `ts` (Section 5.9). |
| `scope` | MAY | Sign only marked sections of the document instead of the whole slice (Section 5.6). |
| `require` | MAY | Co-signatures that must follow for the document to be complete (Section 5.8). |
| `resources` | MAY | Hashes of external files and URLs the document refers to (Section 5.7). |
| `revocation_url` | MAY | `https://` URL of the signer's revocation list (Section 5.9). |
| `rp_id`, `webauthn_authenticator_data`, `webauthn_client_data` | — | REQUIRED when `alg` is `webauthn-es256`, and MUST NOT appear otherwise (Section 6.1). |
| `x_*` | MAY | Extension fields for private use, for example `x_ref: PO-123`. |

Method-specific fields are listed in Section 4.

Verifiers MUST reject a block that is missing a REQUIRED field.

**Version.** The only version verifiers accept is `0.1`. A block with any
other version is unsupported (`unsupported-version`) by step 1 of Section 5.4.
The version is raised only for changes that keep existing verifiers from
reading new blocks correctly: adding a field, or changing the meaning of an
existing field or rule. Adding a value to an IANA registry (Section 8), such as
a method, an algorithm, a hash prefix, a `require` attribute, or a signed list
type, does not change the version, because existing verifiers report such
values as unsupported. The version is planned to become `1` when this
specification is published as an RFC.

**Unknown fields.** A verifier MUST report a block as **malformed** if it contains
a key that is neither defined in this document nor starts with `x_`. Keys
starting with `x_` carry no meaning defined here: verifiers MUST NOT change
their verification result because of them, but they are still part of the
signed payload (Section 5.3), so they cannot be changed without breaking the
signature. Because unknown fields cause a failure, a future version that adds a
field cannot be mistaken for a valid signature by a verifier that does not
understand that field.

**Display name (`display_name`).** A display name claimed by the signer, shown
next to `signer` in the signature table (Section 5.11) and elsewhere.

- The value MUST be a string that does not change when the enforcement rules [RFC8264] of the Nickname profile of RFC 8266 [RFC8266] are applied, and be at most 64 code points long. Generators MUST apply those rules to the input before writing it.
- Verifiers MUST check the length and treat a block whose value is longer than 64 code points as **malformed**. Verifiers are not required to check conformance to the Nickname profile; rule 4 of Section 3.2 limits which characters a value can contain.
- A display name is self-asserted, and anyone can write any name. A verifier that shows a display name MUST show the signer identity with it and indicate that the display name is a claim. It MUST NOT show the display name alone. For a block that is not valid, it MUST either not show the display name or show, in the same place, that the block is not valid (its status).
- It is not the handoff parameter `name` (the document's display name) of CLI_SPEC Section 8.2.

### 3.4 Identifier normalization

Signer identities are compared by exact match. The `signer` of every method
MUST therefore be in the canonical form given by the syntax below. A block, a
requirement line (Section 5.8), or a roster entry (Section 5.10) with a value
that is not in canonical form is **malformed**. For methods other than `tofu`,
generators MAY convert ASCII uppercase letters in the user's input to
lowercase before writing it, and MUST NOT make any other conversion.

**Domain names (`ldh-domain`).** They follow the host name syntax of RFC 1123
[RFC1123] and the A-label syntax of RFC 5890 [RFC5890].

```abnf
ldh-domain = ldh-label 1*("." ldh-label)
ldh-label  = let-dig [*61(let-dig / "-") let-dig]
let-dig    = %x61-7A / DIGIT                 ; ASCII lowercase letters and digits only
```

- A label is 1 to 63 octets and does not start or end with a hyphen. The whole name is at most 253 octets, has two or more labels, and has no trailing dot.
- The last label does not consist of digits only (RFC 1123, Section 2.1; this keeps names distinct from IPv4 addresses).
- Matching is a syntax check only. Checking that an A-label is valid under IDNA2008 [RFC5891] is not required.

`ldh-domain` applies to: the `dns` `signer`; the domain part of email addresses
(`pgp`, `directory`); the `git-hosting` host; the host of a roster URL and the
`dns:` value in `member_of` (Section 5.8.8); `rp_id` (Section 6.1, where
`localhost` is also allowed); and the domain part of patterns (Section 5.8.3).

**Email addresses.** The `signer` of `pgp` and `directory` is
`local "@" ldh-domain`. `local` is the `dot-atom-text` of RFC 5322 [RFC5322]
extended with the UTF-8 characters of RFC 6531 [RFC6531], and contains no ASCII
uppercase letters. Quoted local parts cannot be used. RFC 5321 allows local
parts to be case-sensitive, but this format handles only the form with ASCII
letters in lowercase.

**`git-hosting`.** The `signer` is `<host>/<username>`, where `<host>` is an
`ldh-domain` and `<username>` is `1*(%x61-7A / DIGIT / "-" / "_" / ".")`.
GitHub and GitLab user names are case-insensitive, so they can be compared in
lowercase. On a host where user names are case-sensitive, the keys of a user
name with uppercase letters may not be retrievable.

**`tofu`.** The `signer` is any string without spaces (`1*vchar`). It is
compared exactly as written, including case.

**Common restrictions.** With every method, `signer` MUST NOT contain `*`. `*`
is used only in `require` patterns (Section 5.8.3). `signer` contains no
spaces.

**Comparison.** Signer identities are compared by exact match of the canonical
forms above. Case is not folded and trailing dots are not removed. `pubkey`
values (Sections 4.4 and 5.8.2) are compared as the key bytes decoded from
base64: for `ed25519`, the raw 32 bytes and a DER `SubjectPublicKeyInfo` are
the same key, and for `es256`, the 65-byte uncompressed point and a DER
`SubjectPublicKeyInfo` are the same key.

**Display.** When showing a domain name that contains an A-label, a verifier
MAY show the U-label only if the A-label passes IDNA2008 validation and the
U-label consists of a single script (see UTS #39 [UTS39] for determining the
script). Otherwise it shows the A-label.

### 3.5 List lines

The values of `scope`, `resources`, and `require` are sequences of lines
separated by `LF`. A value with a single line MAY be written as a simple field
(`scope: terms`). Each line has this form:

```abnf
list-line  = *SP target *(SP attr)
target     = 1*vchar                       ; up to the first SP; may contain "=" (each field defines its target)
attr       = attr-name ["=" attr-value]
attr-name  = %x61-7A *(%x61-7A / DIGIT / "_")
attr-value = 1*vchar
```

- Leading spaces are skipped. Indentation carries no structure and is for readability only.
- The target and the attributes, and the attributes among themselves, are separated by exactly one space.
- The first item of a line is always the target. The target may contain `=` (for example, a URL with a query string). Only the items after the target are attributes.
- An attribute is split into name and value at the first `=`. The value may contain `=` and cannot be empty.
- Attributes may appear in any order. Generators SHOULD emit them in the order each field defines.

A block whose value contains any of the following lines is **malformed**: a
line with an attribute the field does not define (except in `require`, which is
handled as in Section 5.8.9), a repeated attribute, an attribute that takes a
value but has none, or an attribute that takes no value but has one.

## 4. Key Resolution Methods

### 4.1 `dns`: Domain TXT record

- `signer`: An `ldh-domain` (Section 3.4).
- `selector` (MAY): A label of 1 to 63 octets made of ASCII lowercase letters, digits, `-`, and `_`. It MUST NOT start with `_` (so that it cannot collide with names such as `_member` below `_mdsig`; Section 5.8.8). If present, the record is at `<selector>._mdsig.<signer>`. If absent, it is at `_mdsig.<signer>`.
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
- Implementations that cannot use the system resolver (browsers, edge runtimes) SHOULD use DNS-over-HTTPS [RFC8484]. The verifier chooses the DoH service. DoH can resolve names in any domain; the domain's DNS provider does not have to support DoH (examples: public DoH services with a JSON API, such as `https://cloudflare-dns.com/dns-query` and `https://dns.google/resolve`).
- Verifiers SHOULD tell users that DNS records can change after signing (Section 9.3).

### 4.2 `git-hosting`: SSH keys published by a Git hosting service

- `signer`: `<host>/<username>` (Section 3.4), for example `github.com/alice` or `gitlab.com/bob`. A block whose `<host>` is not an `ldh-domain` (an IP address, `localhost`, and so on) is **malformed**.
- `key_fp` (MAY): The OpenSSH fingerprint of the key, `SHA256:<unpadded base64 of SHA-256 over the SSH wire-format public key blob>` (the format printed by `ssh-keygen -l`).
- Lookup: `GET https://<signer>.keys` returns one OpenSSH public key per line. Verifiers MUST use only lines whose key type matches `alg` (`ssh-ed25519` for `ed25519`). If `key_fp` is present, verifiers MUST use only the key with that fingerprint. Otherwise the signature is valid if it verifies with any listed key.
- Generators MUST produce a raw Ed25519 signature [RFC8032] directly over the signed payload (Section 5.3), for example with the raw private key or with an ssh-agent `SSH_AGENTC_SIGN_REQUEST`. Generators MUST NOT use the OpenSSH SSHSIG format (`ssh-keygen -Y sign`), which signs a different, wrapped message and is not compatible.
- An ssh-agent returns the signature in SSH wire format (`string "ssh-ed25519"`, `string signature`). Generators MUST store only the inner 64-byte signature in `sig`.
- Verifiers SHOULD tell users that the key list reflects the account's current keys, not the keys at signing time.

### 4.3 `pgp`: OpenPGP

- `signer`: An email address (Section 3.4).
- `fpr` (MUST): The fingerprint of the key used to sign (the primary key or a signing subkey), 40 uppercase hexadecimal characters (v4 keys) or 64 (v6 keys) [RFC9580].
- `alg`: MUST be `openpgp`. A block with `method: pgp` whose `alg` is not `openpgp`, and a block whose `method` is not `pgp` and whose `alg` is `openpgp`, are **malformed**. The signature format is specified in Section 6.2.
- **Key lookup.** Verifiers look for the key in the following order and stop at the first certificate (transferable public key) that contains a key with fingerprint `fpr`.
  1. The user's local keyring (only in implementations that have one, for example `gpg --export <fpr>`).
  2. WKD [WKD] for the domain of `signer`. The advanced method (`https://openpgpkey.<domain>/.well-known/openpgpkey/<domain>/hu/<hash>?l=<local>`) is tried first, then the direct method (`https://<domain>/.well-known/openpgpkey/hu/<hash>?l=<local>`). `<hash>` is the z-base-32 encoding of the SHA-1 of the lowercased local part.
  3. A keyserver configured by the verifier, using HKP [HKP]: `GET <keyserver>/pks/lookup?op=get&options=mr&search=0x<fpr>` (an example keyserver is `https://keys.openpgp.org`).

  A block cannot name the keyserver. If the signer could, anyone could sign under someone else's `signer` through a keyserver that does not confirm email addresses. Verifiers SHOULD use only keyservers that confirm email addresses.

  In a verifier running in a browser, a WKD fetch can fail because the WKD server does not allow CORS. In that case the verifier SHOULD go on to the keyserver lookup.
- **Key validation.** Verifiers MUST check all of the following on the retrieved certificate.
  1. A primary key or subkey matching `fpr` exists.
  2. A user ID exists that has a valid self-certification by the primary key (signature types 0x10 to 0x13) and whose email address (the part between `<` and `>`, or the whole user ID if there are none), with ASCII uppercase letters converted to lowercase, exactly equals `signer`.
  3. If `fpr` refers to a subkey, a valid subkey binding signature (0x18) by the primary key exists, its key flags include signing (0x02), and it contains a valid embedded primary key binding signature (0x19) made by the subkey. If `fpr` refers to the primary key and the self-certification has key flags, they include signing (0x02).
  4. No valid revocation signature (0x20 or 0x28) exists for the key (the primary key, or the subkey `fpr` refers to).

  If no certificate satisfying conditions 1 to 3 is obtained, the result is **unresolved** (code `not-found`). Some keyservers do not distribute user IDs whose email address has not been confirmed, so condition 2 can fail with them. If condition 4 fails, the block is **invalid** (code `revoked`). If the key has expired at verification time, verifiers SHOULD warn but MUST NOT treat the block as invalid for that reason alone. Evidence of the signing time comes from later `tsa` blocks (Section 4.6).
- **Distinguishing lookup results.** The result is `not-found` only if every source tried answered that the key does not exist. If any source did not answer because of a communication failure, the result is `network`. Verifiers SHOULD show the user the result for each source.
- Generators MAY sign with a local OpenPGP implementation (for example `gpg --detach-sign`). In that case too, the signed data is the signed payload (Section 5.3), and the signature MUST satisfy the conditions in Section 6.2.

### 4.4 `tofu`: Trust on first use (embedded key)

- `signer`: Any identifier without spaces or `*` (Section 3.4), for example `bob@laptop`.
- `pubkey` (MUST): `<key-type>:<base64>`, for example `ed25519:11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=`. The key type and encoding are the same as for `dns` (Section 4.1). A `pubkey` whose key type does not match `alg`, or that cannot be decoded, makes the block **malformed**.
- A `tofu` signature proves only that the document has not changed since someone holding that key signed it. It does not prove who that is.
- Verifiers that keep state SHOULD remember the `signer` → `pubkey` binding the first time they see it and MUST report a block as **invalid** (code `key-changed`) if a later document uses the same `signer` with a different `pubkey`. Keys are compared as decoded bytes, as in Section 3.4. The binding is stored after the block has verified, and is replaced only when the user explicitly accepts the new key.
- Verifiers SHOULD show a key that matches a stored binding differently from a key seen for the first time. A verifier operated by a user MAY show the key's fingerprint and ask the user to confirm before storing a binding for a key seen for the first time. If it asks, it stores the binding only after the user confirms.

### 4.5 Key snapshots (`dns`, `git-hosting`, `directory`)

The public keys of `dns`, `git-hosting`, and `directory` are fetched at verification time, so
once the signer removes or changes a key, earlier signatures can no longer be
checked (Section 9.3). To prepare for this, a `dns`, `git-hosting`, or `directory` block MAY
include the public key it was signed with in `pubkey`, in the format of
Section 4.4. A `pgp` block does not include `pubkey`.

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
reported is that the signature holds with the embedded key and, when the time
`T(k)` (Section 4.6) is defined, that the signature existed by that time. It
cannot be shown that the key was published as `signer`'s key at that time.
When `T(k)` is defined, a verifier SHOULD report it as well.

### 4.6 `tsa`: Timestamp block

Evidence of time is given only by `tsa` blocks. A `tsa` block has no signer.
Its RFC 3161 [RFC3161] timestamp token shows that the whole chain before it,
earlier timestamps included, existed at a given time. A signer who wants the
time of their own block proven appends a `tsa` block right after their
signature block. Further `tsa` blocks can be appended to prepare for a TSA
certificate being revoked or a hash algorithm weakening (the idea is the same
as in RFC 4998 [RFC4998], but, as Section 9.4 explains, this version does not
validate chains of renewals).

- `method`: `tsa`. `alg`: `rfc3161`. A block with only one of the two is **malformed**.
- `signer`: the `http://` or `https://` URL of the TSA. Verification
  authenticates the TSA certificate in the token, not this value.
- `ts`: the time claimed by the generator.
- `hash`: the digest of the slice, as for any block (Section 5.3), with
  `sha256` or `sha512`.
- `sig`: the DER-encoded `TimeStampResp` with an encoding prefix. The prefix
  is `base64:` or `gzip+base64:` (RECOMMENDED). `gzip` is the format of
  RFC 1952 and can be decompressed with the Web-standard
  `DecompressionStream("gzip")`.
- Optionally `reason` and `x_*`. A block with any other field is **malformed**.

**Generator.** The generator digests the signed payload (Section 5.3) with the
algorithm of `hash` and sends the TSA a `TimeStampReq` with that digest as
`messageImprint`, `certReq` set to `TRUE`, and a random `nonce`. It stores the
whole `TimeStampResp` of the response in `sig`.

**Verifier.** A verifier MUST verify a `tsa` block as follows, in place of
step 4 and the steps after it in Section 5.4.

1. If the token cannot be decoded, the block is **malformed**. Because tokens
   made by third parties are decompressed too, a verifier SHOULD limit the
   decompressed size (RECOMMENDED: 1 MB).
2. If the response status is not `granted` or `grantedWithMods`, or the
   algorithm and value of `messageImprint` are not the digest of the signed
   payload with the algorithm of `hash`, the block is **invalid (bad
   signature)**.
3. Verify the CMS signature of the token [RFC5652] [RFC5816] and the TSA
   certificate chain [RFC5280] against a trust store of the verifier's choice.
   If this succeeds, the block is **valid**, and the verifier reports
   `genTime`, `accuracy`, and the name of the TSA certificate. If it cannot be
   verified, the block is **unresolved** (code `not-found`).

**The time `T(k)` of a block.** For the `k`-th block of the chain, `T(k)` is
the minimum of `genTime(j) + accuracy(j)` over the valid `tsa` blocks `j` after
`k` (an absent `accuracy` counts as 0). If there is no such `j`, `T(k)` is not
defined. The slice of `tsa` block `j` contains block `k`, so `T(k)` shows that
block `k` existed by that time. Verifiers MUST use the same `T(k)` everywhere
they report the time of a block (in verification results, in the reports of
Section 4.5, and in the signature table). `T(k)` is shown as a value separate
from `ts`.

A `tsa` block does not satisfy `require` (Section 5.8).

### 4.7 `directory`: Key directory

A key directory is a service that publishes public keys bound to an email
address after confirming that the address's owner agrees. Signers without a
domain can sign with an email address as `signer`. Anyone can run a key
directory; this document does not name a particular operator.

- `signer`: An email address (Section 3.4).
- `alg`: `ed25519` or `webauthn-es256`.
- `pubkey` (MAY): A key snapshot as in Section 4.5. Generators SHOULD include `pubkey`, for the case where the directory stops or the key is removed.
- A block cannot name a key directory. If the signer could name the directory, anyone could sign as someone else's `signer` through a directory that does not confirm addresses (the same reason as for the keyserver in Section 4.3).
- **Choosing the directory.** Verifiers MUST choose the directory to query in this order:
  1. The `dir` tag of the `v=mdsig1` TXT record (Section 4.1) at `_mdsig.<domain>`, where `<domain>` is the domain part of `signer` (after `@`). If there are several different `dir` values, the block is **unresolved** (code `not-found`). If exactly one `dir` value is found, verifiers MUST query only that directory.
  2. If there is no `dir`, the verifier's list of trusted directories. Verifiers query them in order and stop at the first that returns keys. The default list is up to the implementation. Implementations SHOULD let users add to the list or replace it.

  If the DNS query does not complete because of a network failure, the result is **unresolved** (code `network`).
- **Fetching keys.** Verifiers send `GET <dir>/v1/keys/<hex>`, where `<hex>` is the SHA-256 of the UTF-8 bytes of `signer` in lowercase hexadecimal, with any trailing `/` removed from `<dir>`. The response is a JSON [RFC8259] object of this form:

  ```json
  {"email": "alice@example.com", "verified": "email",
   "keys": [{"type": "es256", "key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE…", "added": "2026-11-18T09:00:00Z"}]}
  ```

  - Verifiers MUST treat a response whose `email` does not exactly equal `signer` as a response that no key exists.
  - In each element of `keys`, `type` is a key type (Section 6) and `key` is the public key in standard base64, encoded as for `p` in Section 4.1. Verifiers MUST ignore elements whose `type` does not match the block's `alg` and elements with an unknown `type`.
  - `verified` is how the directory confirmed the address's owner. This version defines only `email`.
  - If no confirmed key exists, the directory returns HTTP 404 [RFC9110].
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

Documents MUST be valid UTF-8 [RFC3629]. Generators MUST refuse to sign, and verifiers
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

1. `hash = <hash-alg> ":" lowercase-hex(H(normalize(slice_N)))`, where `H` is the hash named by `<hash-alg>` [RFC6234]. If the block has a `scope` field, the input to `H` is defined by Section 5.6 instead.
2. The **signed payload** is built from every field of the block except `sig`, `webauthn_authenticator_data`, and `webauthn_client_data`:
   1. Sort fields by key, comparing keys as ASCII byte strings.
   2. Write each field as `key "=" value`. If the value contains `LF` (a folded list), write every `LF` in it as `LF` followed by two spaces. Any indentation at the start of a value line (rule 7 of Section 3.2) follows unchanged. Keys start with a lowercase letter, so a continuation line can never be mistaken for another field.
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
display_name=Alice Example
hash=sha256:3a0d0b5c...
method=git-hosting
reason=Initial draft
require=step
    dns:example.com role=approver
  step any=2
    git-hosting:github.com/bob role=reviewer
    git-hosting:github.com/carol role=reviewer
    git-hosting:github.com/dave role=reviewer
role=author
signer=github.com/alice
ts=2026-11-16T09:00:00Z
v=0.1
```

### 5.4 Verification procedure

For each block in the chain, in order, a verifier MUST:

1. If the block has exactly one `v` and its value is not a version the verifier supports, the block is **unsupported** (unsupported version). This check comes before every other check, so that a block with fields added by a later version is reported as an unsupported version rather than as malformed. A block whose `v` is missing or repeated is **malformed** by step 2.
2. Parse the block (Section 3). On a syntax error, a missing REQUIRED field, an unknown field, or an identifier that is not in canonical form (Section 3.4), the block is **malformed**.
3. Compute the digest of the block's slice (or of its scoped sections, Section 5.6) and compare it with `hash` (constant-time comparison is not required; the values are public). On mismatch the block is **invalid (hash mismatch)**.
4. Build the payload and resolve candidate public keys with `method` (Section 4). If resolution fails because of the network, the result is **unresolved**, which is different from invalid.
5. Verify `sig` with each candidate key (for `webauthn-es256`, as in Section 6.1; for `openpgp`, as in Section 6.2). If none verifies, the block is **invalid (bad signature)**.
6. If `expires` is present and has passed, the block is **invalid (expired)** (Section 5.9).
7. If `resources` is present, check it (Section 5.7).
8. If `revocation_url` is present, check it (Section 5.9).

A block whose `method` is `tsa` is verified as in Section 4.6 in place of step 4
and the steps after it, and a `dns`, `git-hosting`, or `directory` block with `pubkey` as in
Section 4.5 in place of steps 4 and 5.

The document is **verified** only if the chain has at least one block, every
block is valid, there is no unsigned content after the last block, and the
agreement status (Section 5.8.9) is `none`, `complete`, or `pending`. A
document whose agreement status is `undetermined` is not verified, because
part of it could not be decided. Separately, a verified document whose
agreement status is `pending` is **verified but pending**; verifiers MUST NOT present such a
document as complete.

Verifiers SHOULD warn about a document whose body ends inside a code fence
(Section 5.5).

### 5.5 Scanning code fences and markers

Section markers (Section 5.6), the signature table marker (Section 5.11), the
fence of a signed list (Section 5.10), and the detection of stray open lines
`<!-- md-signature` in the body follow the line-by-line scan below. The scan
applies to the body (Section 5.2). It is not a full CommonMark parse: it does
not consider fences inside lists or block quotes, indented code blocks, or HTML
blocks. So that implementations agree, verifiers and generators MUST use this
algorithm.

```
fence := none
for each line L of the body, in order:
  if fence = none:
    if L matches  ^( {0,3})(`{3,}|~{3,})(.*)$ :
      c    := the character of group 2;  n := the length of group 2
      info := group 3 with leading and trailing SP/HTAB removed
      if c = "`" and info contains "`":
        classify L as an ordinary line          ; CommonMark 4.5 rule
      else:
        fence := (c, n);  classify L as a fence opening with info string info
    else:
      classify L as an ordinary line
  else:
    if L matches  ^( {0,3})(c{m,})[ \t]*$  with c = fence.c and m >= fence.n :
      fence := none;  classify L as a fence closing
    else:
      classify L as a line inside the fence
at the end: the body ends inside an open fence iff fence != none
```

Only ordinary lines are treated as markers. A marker line is a line that, with
trailing spaces and tabs removed, exactly equals the marker text (with no
leading whitespace).

If the body ends inside a code fence, CommonMark renderers show every signature
block after it as code. Generators MUST refuse to sign such a document.

### 5.6 Section signing (`scope`)

A signer can sign only parts of the document, so that other parts (notes,
fill-in fields, appendices) can still be edited without breaking the signature.

**Section markers.** A section is delimited by two marker lines in the body:

```markdown
<!-- mdsig:section terms -->
## Terms
...
<!-- /mdsig:section -->
```

- The section ID matches `[a-z0-9-]+`.
- Marker lines are only lines classified as ordinary by the scan of Section 5.5. Lines inside code fences are not markers.
- Sections MUST NOT be nested, and an ID MUST NOT be used twice.
- Every begin marker MUST have a matching end marker.

**Field.** `scope` is a list (Section 3.5), and each line is only a section ID
(there are no attributes). An ID cannot be listed twice. For example:

```
scope: |
  terms
  fees
```

**Hash input.** For a block with `scope`, the input to `H` in Section 5.3 is
the concatenation, in the order listed, of `normalize(section)` for each listed
section, where `section` is the text from the first byte of the begin marker
line to the end of the end marker line. Markers are looked up in the body
(by rule 3 of Section 3.2, a block cannot contain a marker line).
Normalization gives every section exactly one trailing `LF`, so section
boundaries cannot be shifted without changing the hash.

**Verification.**

- If the markers in the body break the rules above, the block is **malformed**.
- If a listed ID is not found, the block is **invalid (scope missing)**.
- A verifier MUST show, wherever it reports such a block as valid, that the signature covers only the listed sections (for example "valid (partial: terms, fees)").

A block without `scope` still covers its whole slice, including any sections
and the text around them. A signer who wants later edits outside the sections
to keep the chain valid therefore needs every later signer to use `scope` as
well.

### 5.7 External resources (`resources`)

`resources` binds files and URLs that the document refers to, such as
screenshots, diagrams, and data files. Its value is a list (Section 3.5), and
each line is `<ref> hash=sha256:<lowercase-hex>`. `hash` is a required
attribute.

```
resources: |
  diagram.png hash=sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  images/screen%20shot.png hash=sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
  https://example.com/chart.png hash=sha256:8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4
```

- `<ref>` is either an absolute URI [RFC3986] starting with `https://` or a local relative reference.
- A **local reference** is percent-decoded as in Section 2.1 of RFC 3986 before use. It uses `/` as the separator and is resolved against the directory that contains the document. A reference is **malformed** if any of the following holds:
  - a `%` is not followed by two hexadecimal digits;
  - it contains `%2F`, `%5C`, or `%00` (in either case);
  - the decoded bytes are not valid UTF-8;
  - the decoded result starts with `/`, or contains `\` or `:` (`:` names a Windows drive letter (`C:`) or an alternate data stream (`notes.txt:hidden`));
  - splitting the decoded result at `/` gives a `.`, `..`, or empty segment.

  A file name containing a space is written with `%20` (to keep it apart from the attribute separator). No Unicode normalization is done. A reference made on a file system that stores names in NFD (such as HFS+ on macOS) may not be found elsewhere, so generators SHOULD write file names in NFC.
- A **remote reference** is used as written, with no decoding or normalization.
- The `hash` value is SHA-256 over the exact bytes of the file or of the HTTP response body. A line with a prefix other than `sha256` makes the block **unsupported** (code `unsupported-hash`).

Verification:

1. **Local files** MUST be checked whenever the verifier has access to the document's directory. If a file is missing, the block is **invalid (resource missing)**. If its hash differs, the block is **invalid (resource mismatch)**.
2. **URLs** SHOULD be fetched only when the user asks for it (Section 9.8). If they are not fetched, the verifier MUST say that the remote resources were not checked. If a URL cannot be fetched, the block is **unresolved**. If its hash differs, the block is **invalid (resource mismatch)**.
3. Verifiers MUST only fetch `https://` URLs, SHOULD limit the response size (RECOMMENDED: 50 MB), and SHOULD refuse addresses in private, loopback, and link-local ranges.

Remote content can change for legitimate reasons, such as re-encoding by a
CDN or the page going away. For long-term evidence, signers SHOULD keep a
local copy and list the copy.

### 5.8 Required co-signatures (`require`)

`require` states which co-signatures must follow before the document is
complete, together with their order, their number, and the qualifications of
the signers. Its status says only whether the listed parties have co-signed;
it does not create obligations.

```
require: |
  order mode=pending
  step
    dns:example.com role=approver
  step any=2
    directory:*@example.com member_of=dns:example.com role=reviewer
    git-hosting:github.com/bob role=reviewer
  step
    dns:legal.example.com user_verified
```

In this example the document is complete once `example.com` has approved,
then two different signers among the employees on `example.com`'s roster and
`github.com/bob` have reviewed, and finally `legal.example.com` has signed
with passkey user verification (Section 6.1).

#### 5.8.1 Syntax

The value of `require` is a list (Section 3.5) that follows this ABNF:

```abnf
require-value = [order-line LF] (step-group *(LF step-group) / req-lines)
order-line    = *SP "order" SP "mode=" ("pending" / "guide" / "strict")
step-group    = step-line 1*(LF req-line)
step-line     = *SP "step" [SP "any=" count]
req-lines     = req-line *(LF req-line)
req-line      = *SP target *(SP attr)
target        = method ":" (signer / pattern)
method        = %x61-7A *(%x61-7A / DIGIT / "-")
signer        = 1*vchar                      ; canonical form of Section 3.4
pattern       = "*" / "*." ldh-domain / "*@" ldh-domain
count         = %x31-39 *3DIGIT
attr          = <attr of Section 3.5>
```

- Without step lines (`step-line`), all requirement lines form one step, which needs all of them. A requirement line cannot come before a step line.
- Steps are numbered from 1 in the order they appear.
- Indentation is optional. Generators SHOULD indent the requirement lines under a step line by two spaces.

A verifier MUST treat a block as **malformed** if its value has any of the
following:

1. It does not match the ABNF, including an order line that is not the first line.
2. The `method` of a requirement line is `tsa`.
3. The `signer` of a named line is not in the canonical form of Section 3.4 for its method.
4. A target containing `*` is not in the list of patterns in Section 5.8.3.
5. An attribute breaks the combinations in the table of Section 5.8.2, an attribute value does not follow its syntax, or an attribute is repeated.
6. In a step without pattern lines, the `m` of `any` exceeds the number of different signers named by the step's named lines.
7. A step without `any` has two or more lines that only the same signer can satisfy (for example, two lines naming the same target).
8. A value with `order mode=strict` contains a pattern line (Section 5.8.6).

A requirement line with a method this document does not define (for example
`foo:bar`) and an attribute with a name this document does not define are not
malformed. They are handled as in Section 5.8.9.

#### 5.8.2 Attributes

| Attribute | Value | Allowed on | Meaning |
| --- | --- | --- | --- |
| `role=<token>` | syntax of `role` in Section 3.3 | every method | The block's `role` exactly equals the value. |
| `user_verified` | none | `dns`, `directory`, and `tofu` lines with `pubkey=` | A passkey signature with user verification (Section 5.8.7). |
| `member_of=<roster>` | an `https` URL, or `dns:<ldh-domain>` | pattern lines and named lines (except `tofu`) | The signer is on the roster (Section 5.8.8). |
| `pubkey=<key-type>:<base64>` | the format of `pubkey` in Section 4.4 | named `tofu` lines only | The block's `pubkey` is the same key (compared as in Section 3.4). |

A block satisfies a line when the block's signer identity matches the line's
target and the block satisfies every attribute of the line. Generators SHOULD
emit attributes in the order `role`, `user_verified`, `member_of`, `pubkey`.

`user_verified` on a `tofu` line requires `pubkey=` because with `tofu` anyone
can make a key that claims the same `signer`. A `tofu` requirement line SHOULD
have `pubkey=`. For a `tofu` line without `pubkey=`, verifiers SHOULD warn that
anyone can satisfy the requirement by claiming the name.

#### 5.8.3 Patterns

A target can have one of the following patterns in place of a `signer`. The
list is closed; any other target that contains `*` is malformed (rule 4 of
Section 5.8.1).

| Pattern | Matching signers |
| --- | --- |
| `dns:*` | every `dns` signer |
| `dns:*.<d>` | domains below `<d>` (not `<d>` itself) |
| `directory:*`, `pgp:*` | every signer of that method |
| `directory:*@<d>`, `pgp:*@<d>` | email addresses whose domain part exactly equals `<d>` (not addresses in domains below `<d>`) |
| `git-hosting:*` | every `git-hosting` signer |

- Domain patterns match at label boundaries. `dns:*.example.com` matches `a.example.com` and `a.b.example.com`, and does not match `example.com` or `badexample.com`.
- `git-hosting` has no pattern that restricts the host, because an account at a Git hosting service does not show membership in an organization.
- There are no `tofu` or `tsa` patterns.
- A pattern restricts only the method and the domain; it does not judge whether a signer is qualified (Section 9.9). To restrict qualification, use `member_of` as well.

#### 5.8.4 Designating an organization

A declaring signer who requires "someone from an organization" SHOULD consider
the means in this order:

1. **Members of the organization**: a DNS roster in the organization's domain (`member_of=dns:<domain>`, Section 5.8.8) is RECOMMENDED. Whoever manages the organization's DNS publishes the identifiers of the members one by one.
2. **Members certified by a third party** (such as the members of an industry association): a signed roster published by that third party (`member_of=https://...`).
3. **A simple means**: domain patterns (such as `directory:*@example.com`) MAY be used. Holding an email address in a domain does not necessarily show membership in the organization.

#### 5.8.5 Evaluating steps

The steps of a declaration `D` (at position `d` in the chain) are evaluated in
order from 1. The result MUST be the same as that of the pseudo-code in
Appendix C.

1. **What counts.** The **eligible blocks** for step `s` are the blocks that are valid, have no `scope`, whose `method` is not `tsa`, that come after the start position, and that were not used by an earlier step of the same declaration. The start position is `d` for step 1, the completion position of step `s-1` for a step `s > 1` under `pending`, and always `d` under `guide` and `strict`.
2. **Edges.** There is an edge from a signer `S` to a line `L` if some eligible block of `S` satisfies `L`. The block representing that edge is the earliest block of `S` that satisfies `L`. A pattern line does not count blocks with the same signer identity as `D` (self-approval prevention; as Section 9.9 explains, it is only advisory).
3. **Capacity.** Each signer counts for only one line in a step. In a step with `any`, a named line has capacity 1 and a pattern line has unlimited capacity. In a step without `any`, every line has capacity 1.
4. **Completion.** A step with `any=m` is complete when the different signers counted reach `m`. A step without `any` is complete when every line is satisfied by a different signer. The completion point `k` of a step on its own is the smallest `k` for which such an assignment is possible using only the eligible blocks up to position `k`. The **completion position** of step `s` is `k` under `pending`, and the larger of `k` and the completion position of step `s-1` under `guide` and `strict`.
5. **Reported assignment.** The assignment is fixed uniquely by augmenting paths (Kuhn's algorithm), trying signers in the order of their earliest eligible block and lines in declaration order (Appendix C). The missing co-signatures, `next`, and the signature table are built from this assignment.
6. **Used blocks.** The blocks that represent edges in the assignment of step `s` are not counted in later steps of the same declaration. The same signer can satisfy a later step with another block.

"Different signers" are told apart by their signer identities. An organization
that signs with several methods counts as several signers.

Requirements are collected from every block that is valid or unresolved (for
example, not checked because the verifier is offline), so that a chain that
could not be fully checked is never reported as complete. Only valid blocks
satisfy requirements. If the declaring block itself is unresolved because of a
communication failure or being offline (code `network` or `offline`), the
status of that declaration is `undetermined` unless it is `violated`
(Section 5.8.9).

A block with `scope` does not satisfy a requirement. Such a block does not
cover the block that declared the requirement, and it stays valid when moved
to another document that contains the same sections (Section 9.9).

#### 5.8.6 Order

The declaring signer chooses how the order of steps is handled with the order
line. Without an order line, it is `pending`.

- **`pending`:** Only blocks after the completion position of step `s-1` count for step `s`. A signature made before its turn does not count, and the agreement stays pending. It is satisfied once that signer signs again.
- **`guide`:** Blocks count regardless of their turn. If a block of step `s` in the reported assignment comes before the completion position of step `s-1` (or step `s-1` is not complete), it is reported as an order violation, but it does not change the agreement status. It is not reported if its signer has edges only to pattern lines.
- **`strict`:** Blocks count regardless of their turn, and any order violation among the blocks in the reported assignment makes the agreement `violated`.

Only blocks in the reported assignment are judged for order violations. Blocks
that merely match a line are not.

A `strict` declaration cannot use pattern lines (rule 8 of Section 5.8.1).
Anyone can append a signature, so a third party matching a pattern could create
an irreversible violation just by signing early.

#### 5.8.7 User verification (`user_verified`)

`user_verified` is satisfied only by a valid block whose `alg` is
`webauthn-es256` and whose `authenticatorData` flags have both UP (bit 0) and
UV (bit 2) set. A block whose `clientDataJSON` has `crossOrigin` true is
invalid by Section 6.1. Verifiers SHOULD report BE (bit 3) and BS (bit 4), that
is, whether the passkey can be synced and whether it is synced.

UV shows that the authenticator claimed to have verified the user. This version
does not check authenticator attestation, so it guarantees neither the kind of
authenticator nor how the user was verified (Section 9.9).

#### 5.8.8 Rosters (`member_of`)

**https rosters.** The URL in `member_of=<URL>` MUST be an absolute `https`
URI. It has no user information and no fragment, its port is absent or `443`,
and its host is an `ldh-domain` (Section 3.4). A value that breaks this
(including an IP address literal) is malformed.

- A roster is a signed list (Section 5.10) of `type: members`.
- The issuer of the roster is `dns:<host>`, whose signer is the host of the URL as written. Redirects MAY be followed within the limits of Section 5.7, but the issuer is not the host redirected to.
- A signer is on the roster only if the roster has a `member:` entry that exactly equals the signer's identity.
- Verifiers MUST fetch the roster when they are online. When offline, when the roster cannot be fetched, and when the roster is not trusted, the result from that roster is **undetermined**.

**DNS rosters.** `member_of=dns:<domain>` shows members with TXT records in
the DNS of `<domain>`.

- The record name is `<label>._member._mdsig.<domain>`. `<label>` is `base32lower-nopad(SHA-256("md-signature/member/v1" LF <id>))`, which is 52 characters long. `<id>` is the signer identity being checked, and `base32lower-nopad` is the base32 of Section 6 of RFC 4648 in lowercase without padding.
- The record value is `v=mdsig1; m=<id>`. Tags are parsed as in Section 4.1.
- A signer is on the roster only if there is a `v=mdsig1` record whose `m` exactly equals the identity being checked. Checking `m` prevents false matches from DNS wildcard records [RFC4592] and from providers that synthesize answers for names that do not exist.
- An NXDOMAIN or NODATA response, or no record with a matching `m`, means "not on the roster". Any other failure (SERVFAIL, a timeout, a DNSSEC validation failure, and so on) is **undetermined**.

Example (`directory:alice@example.com` as a member of `example.com`):

```
<52-character label>._member._mdsig.example.com. IN TXT "v=mdsig1; m=directory:alice@example.com"
```

A roster is judged by its content at verification time. Updates to a roster can
change the agreement status of the same document over time (it is not
monotonic).

#### 5.8.9 Reporting the agreement

A verifier MUST report the agreement status of every document it verifies.

| Status | Meaning |
| --- | --- |
| `none` | There are no declarations. |
| `complete` | Every step of every declaration is complete. |
| `pending` | Some step is not complete, and the conditions for `undetermined` do not apply. Comes with the list of missing co-signatures. |
| `undetermined` | For the lines of a step that is not complete, some part cannot be decided because of a communication failure, being offline, a roster that cannot be obtained, or the limits of Section 5.8.10. This includes a declaring block that is unresolved because of a communication failure or being offline (Section 5.8.5). |
| `violated` | There is a `strict` order violation. Comes with the list of offending signatures. |
| `unsupported` | A declaration contains a requirement line with a method, or an attribute, that the verifier does not understand. |

When there are several declarations, the document's status is the first of
`violated`, `unsupported`, `undetermined`, `pending`, and `complete` that
applies. `unsupported` affects only the evaluation of the agreement; it does
not change the verdict on any block's signature. A verifier MUST NOT present a
document whose agreement status is `violated` or `unsupported` as agreed. The
match is on signer identities because those are what the signature
authenticates; `role` alone is the signer's own claim.

For each line of a missing co-signature, verifiers SHOULD report the blocks
whose identity matched the line's target but which were not counted, with the
reason. The reason uses the following vocabulary, giving the first one that
applies. This vocabulary is separate from the block `code` (Section 5.4).

| Reason | Meaning |
| --- | --- |
| `unresolved` | The block is unresolved, including when it could not be checked because of being offline or a communication failure. |
| `not-valid` | The block is neither valid nor unresolved. |
| `scoped` | The block has `scope`. |
| `self` | On a pattern line, the block has the same signer identity as the declaration. |
| `key-mismatch` | The block's key differs from the key in `pubkey=`. |
| `not-user-verified` | The block does not meet the conditions of `user_verified`. |
| `not-member` | The signer is not on the roster. |
| `roster-unavailable` | The result from the roster is undetermined. |
| `blocked` | The block was used by an earlier step of the same declaration. |
| `early` | The block comes before the start position of a `pending` step. |

Verifiers SHOULD report, as the **next co-signatures** (`next`), how many more
signers the first incomplete step needs and the candidate lines for it. For
each later step, they show how many signers it needs.

#### 5.8.10 Limits

For interoperability, verifiers MUST be able to evaluate declarations of at
least the following size:

- 64 lines and 16 steps per `require` value;
- per document, 8 different https roster URLs and 256 roster lookups (URL fetches and DNS queries together).

A declaration larger than a verifier can evaluate is not malformed; its
agreement status is `undetermined`.

### 5.9 Expiry and revocation (`expires`, `revocation_url`)

**Expiry.** `expires` MUST be a real calendar date and time in the `ts`
format (for example, `2026-02-30T00:00:00Z` and `2026-11-16T24:00:00Z` are not);
otherwise the block is **malformed**. If the verifier's current time is later than
`expires`, the block is **invalid (expired)**. Verifiers use their own clock.

**Revocation.** `revocation_url` is the `https://` URL of the signer's
revocation list. A revocation list is a signed list (Section 5.10) of
`type: revocation` with one entry per revoked signature:

````markdown
```mdsig-list
type: revocation
revoked: sha256:<lowercase-hex of SHA-256(signed payload)>
```
````

The identifier is computed from the signed payload (Section 5.3) of the revoked
block. It is not computed from the bytes of `sig`, because a third party
without the private key can change an ECDSA or OpenPGP signature into
different bytes that still verify. The identifier would then change and the
revocation would be bypassed.

1. Verifiers SHOULD fetch the list when they are online. Fetching and verifying follow Section 5.10.
2. The issuer of a revocation list is the holder of the same signer identity as the revoked block (and, for `tofu`, of the same `pubkey`).
3. If the block's identifier is on a trusted list, the block is **invalid (revoked)**.
4. If the list cannot be fetched or is not trusted, the block is **unresolved**. Otherwise blocking the fetch would be enough to hide a revocation. If the user turned the fetch off, or the verifier is offline, the verifier MUST report that revocation was not checked. This does not by itself make the block invalid.

### 5.10 Signed lists

Revocation lists (Section 5.9) and rosters (Section 5.8.8) are signed lists in
a common format. A signed list is an md-signature document whose body has
exactly one code fence (Section 5.5) with the info string `mdsig-list`. The
entries are written inside that fence. When rendered, the entries are visible,
and there is no ambiguity about entries inside list items or block quotes.
The body outside the fence may hold any explanation.

````markdown
# Example Corp members

```mdsig-list
type: members
member: directory:alice@example.com
member: dns:sales.example.com
```
````

- The first line of the fence is `type: <type>`. This version defines `revocation` and `members`.
- Each later line is one entry. A `revocation` entry is `revoked: sha256:<lowercase-hex>`, and a `members` entry is `member: <signer identity>` (in the canonical form of Section 3.4; patterns cannot be used).
- Lines have no leading or trailing whitespace, and there are no blank lines. An entry MAY appear more than once.

A verifier MUST NOT trust a list in any of these cases: there are zero or two
or more fences with the info string `mdsig-list`, the fence is not closed, the
type is not the expected one, or there is even one invalid line.

**Fetching.** Verifiers fetch only `https://` URLs and apply the restrictions
of Section 5.7 (refusing private addresses, and so on). A size limit of 10 MB
is RECOMMENDED. The request is a plain `GET` of the URL, and verifiers MUST NOT
send any information about the document being verified. Verifiers MAY cache a
fetched list with the URL as the key, but keep the cache only for the duration
of one verification call.

**Verification.** Verifiers verify the list as a document. In doing so, they
MUST NOT follow the list's `revocation_url`, MUST NOT check its resources, and
MUST NOT evaluate its `require`. This prevents recursion. Verifiers MUST NOT
store `tofu` bindings from the blocks of a list.

**Trust.** A list is trusted only if its chain has a valid block without
`scope` by the expected issuer and there is no unsigned content after the last
block. The expected issuer is defined for each use (Sections 5.8.8 and 5.9).

**Size.** Verifiers MUST be able to handle lists of at least 100,000 entries.

The content of a roster is its content at verification time. A verifier that
keeps records for archival purposes SHOULD record the SHA-256 of the roster
bytes it used to decide an agreement.

### 5.11 Signature table marker

When the body contains the following marker line, a viewer can draw a
signature table at that position.

```markdown
<!-- mdsig:signatures -->
```

- A marker line is as defined in Section 5.5. Lines inside code fences are not markers.
- A body can hold one marker. Second and later markers, and markers inside code fences, are ignored, and verifiers SHOULD warn about them.
- The marker is part of the body and is covered by the first signature, so its position is fixed by the first signature. Later signers decide only the content of their own row (`display_name`, `role`).

The content of the signature table is built from the verification result of
the chain. No table is written into the body. The viewer decides whether to
show the table and how. The security requirements for display are in
Section 9.5; the content of the table and an example of rendering are given
with `mdsig render` in CLI_SPEC.

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
| `sha256` | REQUIRED to implement |
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
| `rp_id` | The WebAuthn Relying Party ID used for the assertion: an `ldh-domain` (Section 3.4) or `localhost`. It is part of the signed payload. |
| `webauthn_authenticator_data` | `authenticatorData` from the assertion, standard base64. Not part of the payload. |
| `webauthn_client_data` | `clientDataJSON` from the assertion, standard base64. Not part of the payload. |
| `sig` | `base64:` of the assertion `signature`, which is an ASN.1 DER `ECDSA-Sig-Value`. |

**Generator.**

1. Build the payload (Section 5.3), including `rp_id`.
2. Call `navigator.credentials.get()` with `challenge = SHA-256(payload)` and `rpId = rp_id`. If the document has a `user_verified` requirement line that is not yet satisfied, the generator SHOULD set `userVerification` to `"required"`.
3. Store the three values from the response in the fields above.

**Verifier.** The block's signature is valid only if all of the following hold:

1. `clientDataJSON` parses as JSON, its `type` is `webauthn.get`, and its `challenge` equals the unpadded base64url encoding of `SHA-256(payload)`.
2. The host of its `origin` equals `rp_id` or is a subdomain of it. The origin MUST use `https`, except for `localhost`. Verifiers MUST display `rp_id`, and SHOULD warn when it is `localhost`.
3. The `crossOrigin` member of `clientDataJSON` is absent or false. If it is true, the assertion was made in a frame embedded in another origin, and the page the signer was looking at cannot be identified.
4. The first 32 bytes of `authenticatorData` equal `SHA-256(rp_id)`, and the User Present flag (bit 0 of byte 32) is set.
5. `sig` verifies with a candidate `es256` key over `authenticatorData || SHA-256(clientDataJSON)` with ECDSA P-256 / SHA-256. APIs such as Web Crypto that need the fixed-length `r || s` form require a conversion from DER. The conversion MUST reject malformed DER and integers longer than 33 bytes.

Verifiers SHOULD report the User Verified (bit 2), Backup Eligible (bit 3), and
Backup State (bit 4) flags. They do not affect the validity of the signature;
they are used to decide `user_verified` (Section 5.8.7).

The public key comes from the block's `method`, as for any other algorithm:
`tofu` (`pubkey: es256:...`), `dns` (`k=es256`), or `directory`. Passkeys are
bound to their RP ID (Section 9.9).

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
`ts`, and `T(k)` (Section 4.6) as separate values. Only `T(k)` is
third-party evidence (Section 9.4).

## 7. Appending a Signature (Generator Procedure)

1. Read the document and find the existing chain (Section 5.2). If there is unsigned content after the last block, the generator MUST refuse to co-sign, because the new signature would also endorse content earlier signers never signed. (It MAY offer to sign the whole file as a new body instead, which loses nothing but must be an explicit user choice.) It also refuses to sign when the body ends inside a code fence (Section 5.5).
2. Compute `hash` over the whole file as it is now (this is the slice for the new block).
3. Build the fields (with the value rules of Section 3.2, the canonical identifiers of Section 3.4, and the display name rules of Section 3.3) and compute `sig`.
4. Write: the original file with trailing whitespace removed, then `LF`, then (only if there is no existing chain) one blank line, then the new block followed by `LF`.
5. If evidence of time is needed, append a `tsa` block (Section 4.6) next, by the same procedure.

## 8. IANA Considerations

**DNS names.** IANA is requested to add the following entry to the
"Underscored and Globally Scoped DNS Node Names" registry [RFC8552]:

| RR Type | _NODE NAME | Reference |
| --- | --- | --- |
| TXT | `_mdsig` | this document (Sections 4.1, 4.7, and 5.8.8) |

Names below `_mdsig` are managed in the "md-signature Names below _mdsig"
registry below. Names that do not start with `_` are `dns` selectors
(Section 4.1) and are not registered.

**New registries.** IANA is requested to create a new registry group
"md-signature" with the following registries. The registration policies use
the terms of RFC 8126 [RFC8126]. Each entry has a name, a short description,
and a reference to its specification.

| Registry | Policy | Initial entries |
| --- | --- | --- |
| md-signature Methods | Specification Required | `dns`, `git-hosting`, `pgp`, `tofu`, `tsa`, `directory` (Section 4) |
| md-signature Algorithms | Specification Required | everything in the table of Section 6 (reserved entries included) |
| md-signature Hash Prefixes | Specification Required | `sha256`, `sha512`, `sha3-256` (reserved) |
| md-signature Key Types | Specification Required | `ed25519`, `es256` |
| md-signature Block Fields | IETF Review | the fields of Sections 3.3, 4, and 6.1. Names starting with `x_` are Private Use and are not registered |
| md-signature Require Keywords | IETF Review | line keywords `order`, `step`, `any`; order modes `pending`, `guide`, `strict` |
| md-signature Require Attributes | Specification Required | `role`, `user_verified`, `member_of`, `pubkey` (Section 5.8.2) |
| md-signature Signed List Types | Specification Required | type `revocation` (entry keyword `revoked`), `members` (entry keyword `member`) (Section 5.10) |
| md-signature DNS Tags | Specification Required | `v`, `k`, `p`, `dir`, `m` |
| md-signature Names below _mdsig | Specification Required | `_member` (Section 5.8.8) |
| md-signature Comment Markers | Specification Required | `mdsig:section`, `/mdsig:section` (Section 5.6), `mdsig:signatures` (Section 5.11) |

Block Fields and Require Keywords use IETF Review because additions to them
change the version (Section 3.3).

**Media type.** A signed document is ordinary Markdown, and the registration of
`text/markdown` [RFC7763] needs no change.

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
`tofu` binds to nothing beyond the key. `display_name` is confirmed by none of
these.

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
SHOULD append a `tsa` block after signing, and verifiers SHOULD record the key they used
and when. Signers of `dns`, `git-hosting`, and `directory` can include a key snapshot
(Section 4.5). It shows that the signature still holds after the key is
removed, but even with a timestamp it does not show that the key was the
signer's (`key-not-published`). Keepers of long-lived documents SHOULD renew
them by appending a `tsa` block (Section 4.6) before the TSA certificate
expires or the hash algorithm weakens.

### 9.4 Time

`ts` is set by the signer and can be anything. The same holds for the creation
time in an OpenPGP signature packet (Section 6.2). Only `T(k)` from `tsa`
blocks (Section 4.6) gives third-party evidence that a signature existed at a
given time.

`T(k)` depends on the TSA certificates the verifier trusts. Trust stores differ
between implementations (for example, one uses the operating system's
certificate store and another ships a list of root certificates), so the same
token can verify in one implementation and not in another. This version also
does not validate chains of renewals as RFC 4998 does. Each `tsa` block is
judged on its own against the trust store at verification time, so after a TSA
certificate is revoked or expires, a `tsa` block appended later does not carry
over the time of the earlier one. Keepers who need to assert a time over a long
period SHOULD keep the tokens used and the verification results separately.

### 9.5 Rendering and display

Renderers do not show blocks, so readers of rendered output cannot see whether a
document is signed. Tools SHOULD show verification results next to rendered
output. Verifiers MUST NOT display a document as "signed" based only on the
presence of blocks.

The body of a document can contain HTML, including HTML comments, that renders
differently from its source. A signature covers the source, not the rendering.
This lets what the signer read and what the signature covers drift apart in the
following ways.

- **Content that is not shown.** HTML comments in the body, link reference definitions, and HTML elements hidden with the `hidden` attribute or `style` are covered by the signature but are not displayed. A document with a clause inside a comment extends the signature to words the signer never read.
- **Differences between renderers.** Renderers differ in how they treat raw HTML, extensions such as tables and footnotes, and indentation and lazy continuation lines. A document that renders as X in one renderer and as Y in another lets someone show the signer X and later claim that Y was signed.
- **Confusable characters.** The body can contain bidirectional controls, zero-width characters, and look-alike characters (rule 4 of Section 3.2 restricts block values only) [TROJANSRC]. The order and characters on screen may not match the source string.
- **Links and external content.** The visible text of a link and its URL can differ. External images can be replaced after signing unless they are bound with `resources` (Section 5.7).
- **Fake verification marks.** Anyone can put text or an image that reads as "verified", or a table that imitates a signature table, in the body.

Tools that generate signatures and tools that display verification results
SHOULD let the user see HTML comments, raw HTML, bidirectional controls, and
invisible characters in the body, for example with a source view or by
highlighting them. Verification results belong outside the body, in an area the
document's content cannot reach. Signers of important documents SHOULD review
the source, not only the rendering, before signing.

**Signature table.** A viewer that draws verification results at the signature
table marker (Section 5.11) MUST follow these rules:

- It shows the same verification results in UI the body cannot reach as well (an area outside the body). With only the table inside the body, readers cannot tell the real signature table from a fake table written in the body.
- It builds the signature table outside the sanitized body DOM, so that the body's HTML and styles cannot affect the table's content or appearance. For example, it renders the body once and places the table element right after the top-level block that contains the marker. It does not split the source of the body at the marker and render the parts separately: link reference definitions apply to the whole body, and cutting an HTML block that contains the marker in two would show something other than what the signer saw.
- It shows a display name (`display_name`) next to the signer identity, marked as a claim. In the row of a block that is not valid, it either leaves the display name out or shows the block's status in the same row (Section 3.3).

### 9.6 Key reuse and domain separation

`git-hosting` reuses SSH keys that are also used for SSH authentication. The
`md-signature/v1` prefix (Section 5.3) makes signed payloads distinguishable
from SSH authentication data and from other protocols. The labels of DNS
rosters (Section 5.8.8) use their own prefix, `md-signature/member/v1`.

### 9.7 Comment injection

Rule 3 of Section 3.2 (no `-->`, `--!>`, or `<!--` in values) prevents a value
from ending the HTML comment early and injecting visible Markdown.

### 9.8 Fetching resources and revocation lists

Fetching a URL tells its server that someone is verifying, and when. This is
the same as a tracking pixel. That is why verifiers fetch remote `resources`
only on request. What fetching revocation lists and rosters reveals is covered
in Section 10. A verifier that runs on a server and processes untrusted documents can
be made to request internal addresses (server-side request forgery); the
restrictions in Section 5.7 apply to revocation lists, rosters, and key lookups (the
`git-hosting` host, WKD, the keyserver, and key directories) too. The value of `dir` is chosen by
the operator of the signer's domain, so verifiers treat it as an untrusted URL.
The URL in `member_of` is chosen by the declaring signer and is treated the
same way.

### 9.9 Partial signatures, requirements, and passkeys

- A signature with `scope` leaves the rest of the document unsigned. A reader of the rendered document cannot see where the signed sections end, so text outside them can be added to mislead. That is why verifiers must show partial coverage (Section 5.6). A signature with `scope` also stays valid when moved to another document that contains the same sections, so it is not counted as satisfying `require` (Section 5.8).
- `require` is set by the signer of the declaring block. Its status says only whether the listed parties have co-signed; it does not create obligations.
- A pattern (Section 5.8.3) restricts only the method and the domain. `dns:*` and `git-hosting:*` can be satisfied by anyone with a domain or an account. Judging whether the other party is qualified is done with a roster (`member_of`) or with named lines.
- A document that anyone can sign through a pattern can be copied, and each copy can be completed separately. For example, two parties can each accept the same offer. When exclusivity is needed, the declaring signer SHOULD put a final confirmation step at the end that names themselves or a specific party.
- On pattern lines, a third party can sign first and take a seat (seat-squatting). In a step with `any=m`, unrelated signers can count toward the number. Use rosters or named lines for decisions that matter.
- Self-approval prevention (Section 5.8.5) excludes only the declaration's own signer identity. The same party signing with another method or another identifier is counted, so the prevention is only advisory. Likewise, a verifier cannot check that different identifiers belong to different people.
- With `order mode=strict`, a signer of a later step can make the agreement `violated` just by signing before their turn. Declaring signers SHOULD therefore use the default `pending` and use `strict` only when the order itself matters.
- `user_verified` shows only that the authenticator set the UV flag. This version does not check attestation, so an authenticator implemented in software could also claim UV. A synced passkey (with BS set) can be used from several devices.
- Rosters (Section 5.8.8) are judged by their content at verification time. The signatures of a member removed from a roster no longer satisfy requirements in later verifications, and those of a member added start to. To show the membership at signing time, record the roster's SHA-256 when archiving (Section 5.10). The issuer of an https roster is the host of the URL, not the host redirected to. A DNS roster checks the `m` of the record, so a wildcard record cannot create members.
- Decisions about time depend on trust in TSAs (Section 9.4).
- A passkey can be used only with the RP ID it was registered for. If the site that hosts the signing page moves to another domain, passkeys registered on the old domain cannot sign there. Signatures that were already made stay verifiable, because `rp_id` is recorded in each block.

### 9.10 OpenPGP keys

- v4 key fingerprints are based on SHA-1. Collision attacks on SHA-1 are known, but forging an `fpr` needs a second preimage, and no practical attack is known at present. Signers who want a stronger binding can use v6 keys.
- WKD and keyservers return the current certificate, not the key as it was at signing time. A certificate fetched after the key was revoked contains the revocation signature, so signatures made before the revocation are also reported as invalid. Evidence that a signature existed before the revocation is `T(k)`, but the verification procedure in this version does not ignore a revocation on that ground.
- Generators that handle private keys in a browser MUST NOT store the private key or its passphrase in persistent storage, and SHOULD wipe erasable buffers (such as decrypted key material) after signing. JavaScript strings and key material copied inside cryptographic APIs cannot be wiped, so this measure only shortens the exposure.

### 9.11 Key directories

- When the trusted list contains several directories, the strength of the binding is that of the least careful one, because if any of them skips confirmation, anyone can claim any address through it. Verifiers SHOULD include only directories that are known to confirm email addresses.
- A directory operator can publish a false key for any address, and whoever takes over an email account can register keys for that address. This is the same kind of trust as in a `pgp` keyserver or a `git-hosting` service.
- A directory returns the current keys. After a key is removed or the directory stops, a block with `pubkey` is also **unresolved** (code `key-not-published` or `network`). Evidence of the time of signing comes from `tsa` blocks.

## 10. Privacy Considerations

This section follows the approach of RFC 6973 [RFC6973].

- **Fetching revocation lists and rosters.** A list is fetched as a whole file, so the only information sent is the URL. Even so, the server of a revocation list learns that some document of that signer is being verified, and when. If the signer names a different `revocation_url` in each document, the server also learns which one. The server of an https roster likewise learns that a document referring to that roster is being verified. A declaring signer who names a different roster URL for each document or each counterparty can track who views the document.
- **DNS roster queries.** The query name is derived from the signer identity being checked. The operator of the DoH service and the domain's authoritative servers can learn which identifier was checked as a member of which organization. The label is a hash, but when the candidate identifiers are few, a dictionary attack can reverse it. Where DNSSEC NSEC records [RFC4034] allow zone enumeration, the number of members or the list of labels can become known. An organization that wants to keep its member list confidential considers measures such as NSEC3, or distributes a signed roster to a limited audience.
- **Key lookups.** Queries to key directories, WKD, and keyservers reveal that a document of that signer is being verified. The key directory URL contains a hash of the address, but guessing an address from its hash is not hard. The binding between a published key and an email address can be fetched by anyone.
- **Information in the document.** A block's `signer`, `display_name`, `role`, `ts`, the requirement lines of `require`, and roster entries can be read by everyone who receives the document. Signers SHOULD keep the personal information they include in these to what is needed.
- **Offline verification.** Verification without the network reveals nothing to third parties, but decisions that depend on `dns`, `git-hosting`, `directory`, or rosters do not complete (`unresolved` or `undetermined`).

## 11. Implementation Status

**(Note to the RFC Editor: please remove this section before publication.)**

This section records, following RFC 7942 [RFC7942], the implementations known
at the time of writing. Listing them here does not imply endorsement by the
IETF.

- **`@mdsig/core`** (TypeScript): a reference implementation that generates and verifies signatures. It uses only Web-standard APIs and runs in browsers and on servers. MIT license. https://github.com/SHIOZAKI-Shota/md-signature
- **`mdsig.dev`** (Go): a library that generates and verifies signatures, and the command-line tool `mdsig` (CLI_SPEC). MIT license. Same repository.
- **Playground**: https://keys.mdsig.dev/playground/ lets users sign (including with passkeys) and verify in a browser.

These implementations check that they agree on a shared set of test vectors
(`examples/` in the repository). Both implement version 0.1 of this document.
Contact details are in the author line at the top.

## 12. References

### 12.1 Normative References

- [RFC1123] Braden, R., Ed., "Requirements for Internet Hosts - Application and Support", STD 3, RFC 1123.
- [RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119.
- [RFC3161] Adams, C., et al., "Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP)", RFC 3161.
- [RFC3339] Klyne, G. and C. Newman, "Date and Time on the Internet: Timestamps", RFC 3339.
- [RFC3629] Yergeau, F., "UTF-8, a transformation format of ISO 10646", STD 63, RFC 3629.
- [RFC3986] Berners-Lee, T., Fielding, R., and L. Masinter, "Uniform Resource Identifier (URI): Generic Syntax", STD 66, RFC 3986.
- [RFC4592] Lewis, E., "The Role of Wildcards in the Domain Name System", RFC 4592.
- [RFC4648] Josefsson, S., "The Base16, Base32, and Base64 Data Encodings", RFC 4648.
- [RFC5234] Crocker, D. and P. Overell, "Augmented BNF for Syntax Specifications: ABNF", STD 68, RFC 5234.
- [RFC5280] Cooper, D., et al., "Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile", RFC 5280.
- [RFC5322] Resnick, P., Ed., "Internet Message Format", RFC 5322.
- [RFC5480] Turner, S., et al., "Elliptic Curve Cryptography Subject Public Key Information", RFC 5480.
- [RFC5652] Housley, R., "Cryptographic Message Syntax (CMS)", STD 70, RFC 5652.
- [RFC5816] Santesson, S. and N. Pope, "ESSCertIDv2 Update for RFC 3161", RFC 5816.
- [RFC5890] Klensin, J., "Internationalized Domain Names for Applications (IDNA): Definitions and Document Framework", RFC 5890.
- [RFC5891] Klensin, J., "Internationalized Domain Names in Applications (IDNA): Protocol", RFC 5891.
- [RFC6234] Eastlake 3rd, D. and T. Hansen, "US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF)", RFC 6234.
- [RFC6531] Yao, J. and W. Mao, "SMTP Extension for Internationalized Email", RFC 6531.
- [RFC8032] Josefsson, S. and I. Liusvaara, "Edwards-Curve Digital Signature Algorithm (EdDSA)", RFC 8032.
- [RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174.
- [RFC8259] Bray, T., Ed., "The JavaScript Object Notation (JSON) Data Interchange Format", STD 90, RFC 8259.
- [RFC8264] Saint-Andre, P. and M. Blanchet, "PRECIS Framework: Preparation, Enforcement, and Comparison of Internationalized Strings in Application Protocols", RFC 8264.
- [RFC8266] Saint-Andre, P., "Preparation, Enforcement, and Comparison of Internationalized Strings Representing Nicknames", RFC 8266.
- [RFC8484] Hoffman, P. and P. McManus, "DNS Queries over HTTPS (DoH)", RFC 8484.
- [RFC8552] Crocker, D., "Scoped Interpretation of DNS Resource Records through Underscored Naming of Attribute Leaves", BCP 222, RFC 8552.
- [RFC9110] Fielding, R., Ed., Nottingham, M., Ed., and J. Reschke, Ed., "HTTP Semantics", STD 97, RFC 9110.
- [RFC9580] Wouters, P., Ed., et al., "OpenPGP", RFC 9580.
- [WebAuthn] W3C, "Web Authentication: An API for accessing Public Key Credentials Level 3", W3C Recommendation, 25 August 2026, https://www.w3.org/TR/2026/REC-webauthn-3-20260825/
- [COMMONMARK] MacFarlane, J., "CommonMark Spec", Version 0.31.2, 2024-01-28, https://spec.commonmark.org/0.31.2/
- [HTML] WHATWG, "HTML Living Standard", Section 13.1.6 "Comments" and Section 13.2.5 "Tokenization", accessed 2026-11-27, https://html.spec.whatwg.org/multipage/
- [UNICODE] The Unicode Consortium, "The Unicode Standard, Version 15.0.0", https://www.unicode.org/versions/Unicode15.0.0/

### 12.2 Informative References

- [AGENT_COMMERCE] SHIOZAKI, S., "md-signature for Agent-to-Agent Commerce", informative document, [AGENT_COMMERCE.md](AGENT_COMMERCE.md)
- [RFC4034] Arends, R., et al., "Resource Records for the DNS Security Extensions", RFC 4034.
- [RFC4998] Gondrom, T., Brandner, R., and U. Pordesch, "Evidence Record Syntax (ERS)", RFC 4998.
- [RFC6376] Crocker, D., Ed., Hansen, T., Ed., and M. Kucherawy, Ed., "DomainKeys Identified Mail (DKIM) Signatures", STD 76, RFC 6376.
- [RFC6973] Cooper, A., et al., "Privacy Considerations for Internet Protocols", RFC 6973.
- [RFC7515] Jones, M., Bradley, J., and N. Sakimura, "JSON Web Signature (JWS)", RFC 7515.
- [RFC7763] Leonard, S., "The text/markdown Media Type", RFC 7763.
- [RFC7942] Sheffer, Y. and A. Farrel, "Improving Awareness of Running Code: The Implementation Status Section", BCP 205, RFC 7942.
- [RFC8126] Cotton, M., Leiba, B., and T. Narten, "Guidelines for Writing an IANA Considerations Section in RFCs", BCP 26, RFC 8126.
- [RFC8463] Levine, J., "A New Cryptographic Signature Method for DomainKeys Identified Mail (DKIM)", RFC 8463.
- [RFC9052] Schaad, J., "CBOR Object Signing and Encryption (COSE): Structures and Process", STD 96, RFC 9052.
- [UTS39] The Unicode Consortium, "Unicode Security Mechanisms", Unicode Technical Standard #39.
- [WKD] Koch, W., "OpenPGP Web Key Directory", Work in Progress, Internet-Draft, draft-koch-openpgp-webkey-service.
- [HKP] Shaw, D. and A. Gallagher, "OpenPGP HTTP Keyserver Protocol", Work in Progress, Internet-Draft, draft-gallagher-openpgp-hkp.
- [FIPS204] NIST, "Module-Lattice-Based Digital Signature Standard", FIPS 204.
- [FIPS205] NIST, "Stateless Hash-Based Digital Signature Standard", FIPS 205.
- [MINISIGN] Denis, F., "Minisign", https://jedisct1.github.io/minisign/
- [SIGSTORE] The Sigstore Authors, "Sigstore", https://www.sigstore.dev/
- [GIT] "git-commit(1)" (`--gpg-sign`) and "gpg.format" in git-config(1), https://git-scm.com/docs
- [C2PA] Coalition for Content Provenance and Authenticity, "C2PA Technical Specification", https://c2pa.org/specifications/
- [ISO32000] ISO, "Document management — Portable document format — Part 2: PDF 2.0", ISO 32000-2.
- [TROJANSRC] Boucher, N. and R. Anderson, "Trojan Source: Invisible Vulnerabilities", https://trojansource.codes/

## Appendix A. Relation to Existing Technologies (Informative)

This appendix is informative and contains no normative requirements.

- **OpenPGP cleartext signatures ([RFC9580], Section 7).** Like this format, they place the signature inside the text. However, lines such as `-----BEGIN PGP SIGNED MESSAGE-----` show up when rendered as Markdown, and lines starting with `-` are dash-escaped, which changes the body. There is one signer, and only OpenPGP keys. This format puts signatures in HTML comments so rendering is unaffected, and defines co-signing and several key resolution methods.
- **Detached signatures such as minisign and signify [MINISIGN].** The signature lives in a separate file such as `.minisig`. When a document is sent by email or chat or pasted into a wiki, the signature file is easily lost, and deciding whose public key it is falls to the user. This format keeps the signature in the same file as the document (design goal 2) and resolves keys from DNS, Git hosting, OpenPGP, or key directories (Section 4).
- **Git commit signing and gitsign [GIT] [SIGSTORE].** What is signed is a commit in a repository, not a file. Once the file leaves the repository, its link to the signature is lost, and a record of several parties agreeing to one version in turn is hard to read from commit history. Signatures in this format travel with the file and can be checked by people who do not use Git. The `git-hosting` method reuses SSH keys registered with a Git hosting service (Section 4.2).
- **Sigstore (cosign, gitsign) [SIGSTORE].** It uses OpenID Connect identities, short-lived certificates, and a transparency log. Signatures are stored as detached bundles, and verifiers need Sigstore's trust roots (the certificate authority and the transparency log keys). This format assumes no particular infrastructure, and `tofu` and key snapshots (Section 4.5) can be checked offline. Recording in a transparency log can be done separately from this format.
- **JWS with a detached payload [RFC7515] and COSE [RFC9052].** These are general-purpose signature containers. They do not say where in Markdown a signature goes, how co-signatures chain, or where keys come from. A JWS in compact form could be put in an HTML comment, but metadata such as the signer and role would be hidden inside base64url, out of sight of people reading the source. This format uses fields that stay readable in the source (Section 3.2).
- **C2PA [C2PA].** It records the provenance of media such as images, video, and audio in a manifest embedded in the file. Signatures use X.509 certificates, and verifiers keep a list of trusted certificates. Text such as Markdown is not its main target. This format aims to record agreement to text documents.
- **PDF signatures [ISO32000].** Signatures are appended through incremental updates, and later signatures cover earlier ones, the same idea as this format's append-only chain (Section 5.2). This format does the same in a text format whose changes are easy to diff.
- **DKIM [RFC6376].** The TXT record of the `dns` method (`v=`, `k=`, and `p=` tags) and the representation of Ed25519 keys [RFC8463] follow DKIM.

How to use this format for the terms documents of agent-to-agent transactions
is described in [AGENT_COMMERCE].

## Appendix B. Operational Considerations (Informative)

This appendix is informative and contains no normative requirements.

**Formatters and editing tools.** Normalization (Section 5.1) absorbs only line
endings (`CRLF` and `LF`), a leading BOM, and whitespace and line breaks at the
end of the file. The following changes break signatures:

- Rewrites by formatters such as Prettier, for example list markers (`*` and `-`), emphasis markers (`*` and `_`), spaces in table columns, paragraph wrapping (`proseWrap`), and adding or removing escapes.
- Removing trailing whitespace on each line (an editor's "trim trailing whitespace" setting, markdownlint's automatic fixes, and so on). In Markdown, two trailing spaces mean a line break, so the rendering changes too.
- Converting between tabs and spaces, Unicode normalization (NFC and NFD), and converting between full-width and half-width characters.
- Adding or removing blank lines between the body and the first block or between blocks. The slice of block N includes the body, the blocks before it, and the whitespace between them (Section 5.2), so the signatures of the second and later blocks break. Only a change in the blank lines just before the last block is absorbed by normalization.
- Formatters rewriting the signature blocks themselves (adding or changing indentation, changing folding). The indentation of continuation lines is part of the value (rule 7 of Section 3.2), so even tidying the indentation of `require` breaks the signature.
- Reading and writing blocks with YAML tools (Section 3.2).

In practice:

- Exclude signed documents from formatters (`.prettierignore`, `trim_trailing_whitespace = false` in `.editorconfig`, and so on).
- Run formatters before signing. If formatting is needed after signing, ask for the formatted document to be signed again.
- Keep parts that may be edited later outside `scope` (Section 5.6).
- Run verification in CI to catch unintended rewrites early.

Line ending conversion by Git's `core.autocrlf` is absorbed by normalization,
but settings that rewrite content, such as `filter` and `ident` in
`.gitattributes`, break signatures.

## Appendix C. Step Assignment (Normative)

This appendix is normative. It defines the decisions of Sections 5.8.5 and
5.8.6 in pseudo-code. Verifiers MUST obtain the same results. When the result
from a roster is undetermined (Section 5.8.8), no edge is created and the line
is recorded as undetermined.

```
; D: the declaration (position d, signer identity id(D), order mode)
; chain[i]: the i-th block, with valid(b), scoped(b), id(b)
function evaluate(D):
  used := {}                         ; blocks used by earlier steps
  prev := d                          ; completion position of the previous step (∞ if not complete)
  for s := 1 to number of steps:
    st    := steps[s]
    start := (mode = pending) ? prev : d
    if start = ∞: report step s as blocked_by s-1; continue
    E := [ b in chain | position(b) > start, valid(b), not scoped(b),
                        method(b) != "tsa", b not in used ]
    need := st.any if present, else number of lines of st
    k := none
    for each position p of E, ascending:
      A := assign(st, [ b in E | position(b) <= p ], need)
      if size(A) = need: k := p; break
    if k = none:
      A := assign(st, E, need)        ; not complete; assignment for reporting
      done := ∞
    else:
      done := (mode = pending) ? k : max(k, prev)
    if s > 1 and mode != pending:
      for each (signer x, line L, block b) in A:
        if position(b) < prev (or prev = ∞):
          if mode = guide and every line with an edge from x is a pattern line:
            continue
          record order violation (b, s)
    used := used ∪ { b | (x, L, b) in A }
    prev := done

function matches(b, L):
  if L is named:   if id(b) != L.target: return false
  else:            if not pattern-match(L.target, id(b)): return false
                   if id(b) = id(D): return false        ; self
  each attribute of L holds for b (5.8.2)

function assign(st, B, need):
  ; signers: the ids in B, ordered by the position of each one's earliest block
  X   := distinct id(b) for b in B, ordered by min position
  cap(L) := (st.any present and L is a pattern line) ? ∞ : 1
  edge(x, L) := exists b in B with id(b) = x and matches(b, L)
  rep(x, L)  := the earliest such b
  owner := {}                          ; line -> list of signers
  line  := {}                          ; signer -> line
  for x in X:
    if |line| = need: break
    seen := {}
    augment(x)
  return { (x, line[x], rep(x, line[x])) | x in line }

  function augment(x):
    for L in st.lines in declaration order:
      if not edge(x, L) or L in seen: continue
      seen := seen ∪ {L}
      if |owner[L]| < cap(L):
        owner[L] += x;  line[x] := L;  return true
      for y in owner[L] in insertion order:
        if augment(y):                 ; moves y to another line
          owner[L] := owner[L] - y + x;  line[x] := L;  return true
    return false
```

When `augment(y)` moves `y` to another line, `owner` and `line` reflect the
move. The size of the assignment stops at the number of lines in a step without
`any`, and at `m` in a step with `any=m`.
