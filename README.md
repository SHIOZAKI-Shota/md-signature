<p align="center"><img src="docs/logo.svg" width="180" alt="md-signature"></p>

# md-signature

**Electronic signatures, for Markdown too.**

[日本語](README.ja.md) · [Specification](SPEC.md) · [CLI specification](CLI_SPEC.md) · [Playground](https://mdsig.dev/playground/)

`md-signature` is an open, vendor-neutral format for Markdown that appends a signature after the last line of a document and verifies it.
Each signature is an HTML comment appended to the end of the file:

```markdown
# Service Agreement

The parties agree to the following terms...

<!-- md-signature
v: 0.0.2
method: git-hosting
signer: github.com/alice
key_fp: SHA256:Rx9i...
role: author
ts: 2026-11-16T09:00:00Z
alg: ed25519
hash: sha256:3a0d0b5c...
sig: base64:q1Xv...
-->
```

- Signatures don't show up when the file is rendered. GitHub, VS Code, and other CommonMark renderers hide HTML comments.
- The signature stays in the same file. There is no detached `.sig` file to lose.
- Several people can co-sign. Each new signature covers the document and every earlier signature, forming an append-only hash chain.
- You can verify against keys you already have: SSH keys on GitHub/GitLab (`https://github.com/<user>.keys`), a DNS TXT record on your domain, OpenPGP, or an embedded key.
- RFC 3161 timestamp tokens can be added if you need a trusted time. For long-term keeping, `mdsig timestamp` appends timestamp blocks without a signer and renews them by stacking. `dns` and `git-hosting` can embed the public key (`--embed-key`), so a signature can still be checked after the key is removed.
- A signer can declare which co-signatures are still required (`require`). `mdsig verify` reports the document as *pending* until they are all there. Steps (`step`) and thresholds (`any`) express flows such as "the manager approves, then two of three reviewers sign".
- Screenshots, data files, and even remote images can be bound by SHA-256 (`resources`), so swapping a linked file is detected.
- You can sign only marked sections (`scope`) and leave notes or fill-in fields editable. Verifiers always show that such a signature is partial.
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
mdsig sign contract.md -m git-hosting -s github.com/alice -r author --reason "Initial draft"

# A second person co-signs, with a key published in DNS, and adds a timestamp
mdsig keygen -o ~/.mdsig/example -d example.com --selector 2026   # prints the TXT record to publish
mdsig sign contract.md -m dns -s example.com --selector 2026 -k ~/.mdsig/example -r approver --tsa

# Verify the whole chain
mdsig verify contract.md
mdsig verify --json contract.md

# Ask for an approval, bind the screenshots, and let the signature expire in 30 days
mdsig sign quote.md -m git-hosting -s github.com/alice -r author \
  --require "dns:example.com approver" --auto-resources --expires 30d

# Declare a flow: an approval, then two of three reviewers
mdsig sign plan.md -m git-hosting -s github.com/alice -r author \
  --require "step 1" --require "dns:example.com approver" \
  --require "step 2 any 2" --require "git-hosting:github.com/bob" \
  --require "git-hosting:github.com/carol" --require "git-hosting:github.com/dave"

# Sign only the "terms" and "fees" sections; the rest stays editable
mdsig sign sow.md -m tofu -s alice@laptop -k ~/.mdsig/alice --scope terms,fees

# Or just run `mdsig` for an interactive menu
mdsig
```

Exit codes: `0` verified, `1` verification failed, `2` usage error, `3` network or key resolution error (also when `--offline` left a block unchecked), `4` file error, `5` verified but required co-signatures are missing.

### Use case: signed instructions for AI agents

Sign your `CLAUDE.md`, `AGENTS.md`, or `SKILL.md`, and have your agent harness run
`mdsig verify` before loading them. For example, a Claude Code `SessionStart`
hook can refuse to start when the instructions were changed by someone else.
Run the check in the harness. An agent that has already read injected text
cannot be trusted to judge it. This protects
against instruction files modified through pull requests or redistribution. It
does not protect against prompt injection through tool output or web content.

### Library

md-signature is built as a library first. The CLI and the playground are two users of it.

**TypeScript (`@mdsig/core`):** runs in browsers, Node.js, Deno, Bun, and Cloudflare Workers. It is not on npm yet.

```ts
import { verifyDocument, signDocument, generateEd25519 } from "@mdsig/core";

const result = await verifyDocument(markdown);
if (result.ok) console.log(`${result.signatures.length} valid signatures`);

const { signer } = await generateEd25519();
const { text } = await signDocument(markdown, { signer, method: "tofu", signerId: "bob@laptop", role: "reviewer" });
```

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

OpenPGP signatures (`alg: openpgp`) store a detached signature in `sig`, the same format `gpg --detach-sign` writes. The CLI signs through gpg, so keys held by gpg-agent or on a smartcard work as they are. You can also sign with a key file, in the CLI or in the browser. Supported keys are Ed25519 (v4 and v6), RSA (2048 bits or more), and ECDSA P-256. Passphrase-protected key files are supported in gpg's default protection (iterated+salted S2K with AES). Argon2 and AEAD protection work in the CLI, not in the browser.

Passkey signatures (`alg: webauthn-es256`) use `tofu` or `dns` for the public key.
Passkeys are bound to the domain of the signing page (currently
`mdsig.dev`). If the playground moves to another domain, passkeys
registered on the old one cannot sign there, though existing signatures stay
verifiable.

## Repository layout

| Path | Contents |
| --- | --- |
| [`SPEC.md`](SPEC.md) | Format and cryptographic specification (RFC 2119 style). Normative English text, kept for a possible IETF submission; the original is written in Japanese: [`SPEC.ja.md`](SPEC.ja.md) |
| [`CLI_SPEC.md`](CLI_SPEC.md) | CLI behavior, flags, exit codes. Informative translation; the normative text is Japanese: [`CLI_SPEC.ja.md`](CLI_SPEC.ja.md) |
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

This is a draft. Releases of the CLI and the Go library (currently `v0.0.3`) and the signature format have separate version numbers; the current format is `0.0.2`, and `0.0.1` signatures still verify. `mdsig --version` shows both: `mdsig version 0.0.3 (format 0.0.2)`. `@mdsig/core` is not published yet and keeps its own version (`0.0.1` in `package.json`) until it is. The format and the APIs may change before 1.0. Feedback is welcome in issues.

This is an experimental implementation. It has had no independent security audit. Do not rely on it alone where a wrong signature verdict has serious consequences, such as contracts. To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

- Specification documents (`SPEC.ja.md` and `SPEC.md`, `CLI_SPEC.ja.md` and `CLI_SPEC.md`): [CC0 1.0](LICENSE-SPEC)
- Code: [MIT](LICENSE)
