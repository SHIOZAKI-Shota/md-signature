<p align="center"><img src="docs/logo.svg" width="180" alt="md-signature"></p>

# md-signature

**Electronic signatures, for Markdown too.**

[日本語](README.ja.md) · [Specification](SPEC.md) · [CLI specification](CLI_SPEC.md) · [Playground](https://mdsig.dev/playground/)

`md-signature` is an open, vendor-neutral format for Markdown that appends a signature after the last line of a document and verifies it.
Each signature is an HTML comment appended to the end of the file:

```markdown
# Service Agreement

The parties agree to the following terms...

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

- Signatures don't show up when the file is rendered. GitHub, VS Code, and other CommonMark renderers hide HTML comments.
- The signature stays in the same file. There is no detached `.sig` file to lose.
- Several people can co-sign. Each new signature covers the document and every earlier signature, forming an append-only hash chain.
- You can verify against keys you already have: SSH keys on GitHub/GitLab (`https://github.com/<user>.keys`), a DNS TXT record on your domain, OpenPGP, or an embedded key.
- When you need evidence of time, an RFC 3161 timestamp is appended to the chain as a `tsa` block (`mdsig sign --tsa`, `mdsig timestamp`). A `tsa` block covers the whole chain before it, so stacking them renews the evidence for long-term keeping. `dns`, `git-hosting`, and `directory` can embed the public key (`--embed-key`; `directory` does by default), so a signature can still be checked after the key is removed.
- A signer can declare which co-signatures are still required (`require`). `mdsig verify` reports the document as *pending* until they are all there. Besides steps (`step`) and thresholds (`step any=2`), a co-signer can be described by qualification instead of by name: a pattern such as `directory:*@example.com`, an organization's roster (`member_of=`, in DNS or as a signed roster document), or user verification with a passkey (`user_verified`).
- Put `<!-- mdsig:signatures -->` in the body and viewers (`mdsig render`, the playground) draw a signature table there, built from the verified blocks. The table is never written into the document, so HTML in the body cannot fake it. A self-declared `display_name` is shown next to the verified signer.
- Screenshots, data files, and even remote images can be bound by SHA-256 (`resources`, one `<ref> hash=sha256:<hex>` per line), so swapping a linked file is detected.
- You can sign only marked sections (`scope`, one section id per line) and leave notes or fill-in fields editable. Verifiers always show that such a signature is partial.
- Signatures can expire (`expires`) or be withdrawn later through a signed revocation list (`revocation_url`).
- Passkeys work too: sign in the browser with Touch ID, Face ID, Windows Hello, or a security key (`webauthn-es256`), with no key files.
- The reference library uses only Web Crypto, `fetch`, and `CompressionStream`, so it runs in browsers, Cloudflare Workers, Deno, Bun, and Node.js.

## Quickstart

### CLI (`mdsig`)

```sh
# Install with Homebrew, or with Go 1.26 or later (winget and .deb/.rpm packages are not available yet)
brew install SHIOZAKI-Shota/tap/mdsig
go install mdsig.dev/cmd/mdsig@latest

# Sign with the SSH key you already use for GitHub (ssh-agent or ~/.ssh/id_ed25519)
mdsig sign contract.md -m git-hosting -s github.com/alice -r author \
  --display-name "Alice Example" --reason "Initial draft"

# A second person co-signs with a key published in DNS, then a tsa block (timestamp) is appended
mdsig keygen -o ~/.mdsig/example -d example.com --selector 2026   # prints the TXT record to publish
mdsig sign contract.md -m dns -s example.com --selector 2026 -k ~/.mdsig/example -r approver --tsa

# Verify the whole chain, and write an HTML page with the signature table
mdsig verify contract.md
mdsig verify --json contract.md
mdsig render contract.md -o contract.html

# Ask for an approval, bind the screenshots, and let the signature expire in 30 days
mdsig sign quote.md -m git-hosting -s github.com/alice -r author \
  --require "dns:example.com role=approver" --auto-resources --expires 30d

# Declare a flow: an approval, then two of three reviewers (one --require per line)
mdsig sign plan.md -m git-hosting -s github.com/alice -r author \
  --require "step" --require "dns:example.com role=approver" \
  --require "step any=2" --require "git-hosting:github.com/bob role=reviewer" \
  --require "git-hosting:github.com/carol role=reviewer" --require "git-hosting:github.com/dave role=reviewer"

# Ask for an approval by anyone on the DNS roster of example.com, without naming them
mdsig sign request.md -m directory -s alice@example.com -k ~/.mdsig/alice \
  --require "directory:*@example.com member_of=dns:example.com role=approver"

# Print the TXT record that puts one person on that roster
mdsig member-record directory:bob@example.com example.com

# Check what a require value means before signing
printf 'step\n  dns:example.com role=approver\nstep any=2\n  dns:*.example.com\n' | mdsig require explain -

# Sign only the "terms" and "fees" sections; the rest stays editable
mdsig sign sow.md -m tofu -s alice@laptop -k ~/.mdsig/alice --scope terms,fees

# Or just run `mdsig` for an interactive menu
mdsig
```

When signed, `require` is written with the lines of each step indented below it:

```
require: |
  step
    dns:example.com role=approver
  step any=2
    git-hosting:github.com/bob role=reviewer
    git-hosting:github.com/carol role=reviewer
    git-hosting:github.com/dave role=reviewer
```

Exit codes: `0` verified, `1` verification failed (including an `order mode=strict` violation and requirements the verifier does not support), `2` usage error, `3` network or key resolution error (also when `--offline` left a block unchecked, or when a roster could not be consulted and the agreement is undetermined), `4` file error, `5` verified but required co-signatures are missing.

### Use case: signed instructions for AI agents

Sign your `CLAUDE.md`, `AGENTS.md`, or `SKILL.md`, and have your agent harness run
`mdsig verify` before loading them. For example, a Claude Code `SessionStart`
hook can refuse to start when the instructions were changed by someone else.
Run the check in the harness. An agent that has already read injected text
cannot be trusted to judge it. This protects
against instruction files modified through pull requests or redistribution. It
does not protect against prompt injection through tool output or web content.

### Use case: agent-to-agent commerce

AI agents can use the format when they accept terms on someone's behalf. The provider signs the terms as a Markdown document and publishes it; the accepting agent co-signs with its own `dns` key. The `hash` of the accepting block equals the LCP `atrHash` (the SHA-256 of the published document). With `require`, the provider declares who qualifies (patterns, rosters) and a final confirmation step by the provider itself. Payment (x402) and delegation (AP2) stay with the existing protocols. See [AGENT_COMMERCE.md](AGENT_COMMERCE.md) (informative).

### Library

md-signature is built as a library first. The CLI and the playground are two users of it.

**TypeScript (`@mdsig/core`):** runs in browsers, Node.js, Deno, Bun, and Cloudflare Workers. Install it with `npm install @mdsig/core`.

```ts
import { verifyDocument, signDocument, generateEd25519 } from "@mdsig/core";

const result = await verifyDocument(markdown);
if (result.ok) console.log(`${result.signatures.length} valid signatures`);

const { signer } = await generateEd25519();
const { text } = await signDocument(markdown, { signer, method: "tofu", signerId: "bob@laptop", role: "reviewer" });
```

The agreement state is `result.agreement.status` (`none`, `complete`, `pending`, `violated`, `undetermined`, `unsupported`), and `result.agreement.next` tells who still has to sign. `signatureTable(result)` gives the rows of the signature table, `renderSignatureTableHtml(rows, "en")` its HTML, and `explainRequire(value, "en")` a description of a `require` value.

**Go (`mdsig.dev/mdsig`):** the same verification the CLI runs, as functions.

```go
import "mdsig.dev/mdsig"

r := mdsig.VerifyDocument(ctx, text, &mdsig.VerifyOptions{})
```

**Verifying on a server:** what a browser cannot check by itself can be handed to a server. Go offers the `http.Handler` in `mdsig/server` (the one behind `mdsig serve`), TypeScript offers `createVerifyHandler`, and both speak the same HTTP API ([CLI spec, section 3.6](CLI_SPEC.md)). A client calls it with `remoteVerify` and compares the answer with its own verdict using `compareResults`.

For the list of options, TSA root certificates, and notes on running a server, see [packages/core/README.md](packages/core/README.md).

## Verification methods

| `method` | `signer` | Public key comes from |
| --- | --- | --- |
| `git-hosting` | `github.com/alice` | `https://github.com/alice.keys` |
| `dns` | `example.com` | TXT record at `[<selector>.]_mdsig.example.com` |
| `pgp` | `alice@example.com` + `fpr` | Local keyring (CLI), then WKD, then a keyserver (keys.openpgp.org by default) |
| `tofu` | anything | Embedded `pubkey` field. Proves integrity, not identity. |
| `directory` | `alice@example.com` | A key directory that confirmed the email address: the one the domain names with `dir=` in `_mdsig`, otherwise the verifier's trusted list (keys.mdsig.dev by default; see [the criteria](KEY_DIRECTORIES.md)) |

OpenPGP signatures (`alg: openpgp`) store a detached signature in `sig`, the same format `gpg --detach-sign` writes. The CLI signs through gpg, so keys held by gpg-agent or on a smartcard work as they are. You can also sign with a key file, in the CLI or in the browser. Supported keys are Ed25519 (v4 and v6), RSA (2048 bits or more), and ECDSA P-256. Passphrase-protected key files are supported in gpg's default protection (iterated+salted S2K with AES). Argon2 and AEAD protection work in the CLI, not in the browser.

Passkey signatures (`alg: webauthn-es256`) use `tofu`, `dns`, or `directory` for the public key.
Passkeys are bound to the domain of the signing page (currently
`mdsig.dev`). If the playground moves to another domain, passkeys
registered on the old one cannot sign there, though existing signatures stay
verifiable.

## Repository layout

| Path | Contents |
| --- | --- |
| [`SPEC.md`](SPEC.md) | Format and cryptographic specification (RFC 2119 style). Normative English text, kept for a possible IETF submission; the original is written in Japanese: [`SPEC.ja.md`](SPEC.ja.md) |
| [`CLI_SPEC.md`](CLI_SPEC.md) | CLI behavior, flags, exit codes. Informative translation; the normative text is Japanese: [`CLI_SPEC.ja.md`](CLI_SPEC.ja.md) |
| [`AGENT_COMMERCE.md`](AGENT_COMMERCE.md) | Using md-signature in agent-to-agent commerce (informative). Original: [`AGENT_COMMERCE.ja.md`](AGENT_COMMERCE.ja.md) |
| [`CHANGELOG.en.md`](CHANGELOG.en.md) | Changes in each release |
| [`packages/core`](packages/core) | `@mdsig/core`, TypeScript, zero dependencies |
| [`mdsig`](mdsig) | Go library (`mdsig.dev/mdsig`); [`mdsig/server`](mdsig/server) is the HTTP handler |
| [`cmd/mdsig`](cmd/mdsig), [`internal`](internal) | `mdsig`, the native CLI (Go) |
| [`docs`](docs) | Website at https://mdsig.dev/, with the [playground](https://mdsig.dev/playground/) |
| [`examples`](examples) | Test vectors shared by all implementations |

## Development

```sh
cd packages/core
npm install
npm test                    # unit tests + examples/ compliance vectors
npm run check:web-standard  # fails if src/ uses Node-only APIs
npm run build:docs          # rebuild docs/vendor/core and the playground demo document

cd ../..
go test ./...
go build -o bin/mdsig ./cmd/mdsig   # -o is needed: ./mdsig is the library directory
```

## Status

This is a draft. Releases of the CLI, the Go library, and `@mdsig/core` share one version number (currently `v0.1.0`), separate from the signature format; the current format is `0.1`. `mdsig --version` shows both: `mdsig version 0.1.0 (format 0.1)`. The format version changes only with incompatible changes and becomes `1` when the specification is published as an RFC. The APIs may also change before 1.0. Feedback is welcome in issues.

**Migrating from 0.0.x:** v0.1.0 does not verify signatures in format `0.0.x` (they are `unsupported-version`, with a hint to use the older release), and a co-signature that v0.1.0 appends to a `0.0.x` document leaves the earlier signatures unsupported, so the document as a whole never verifies. Verify such documents with mdsig v0.0.5 or `@mdsig/core` 0.0.5. See [CHANGELOG.en.md](CHANGELOG.en.md) for the full list of changes.

This is an experimental implementation. It has had no independent security audit. Do not rely on it alone where a wrong signature verdict has serious consequences, such as contracts. To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

- Specification documents (`SPEC.ja.md` and `SPEC.md`, `CLI_SPEC.ja.md` and `CLI_SPEC.md`, `AGENT_COMMERCE.ja.md` and `AGENT_COMMERCE.md`): [CC0 1.0](LICENSE-SPEC)
- Code: [MIT](LICENSE)
