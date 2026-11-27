# Changelog

[日本語](CHANGELOG.md)

Releases of the `mdsig` CLI, the Go library `mdsig.dev/mdsig`, and `@mdsig/core` share one version number. The signature format has its own version, shown in parentheses.

## 0.1.0 (format 0.1), unreleased

Format 0.1 is a breaking cleanup made while there are still few users. Blocks written by 0.0.x releases do not verify with this release and cannot be co-signed with it.

### Breaking changes

- `v` must be `0.1`. Blocks with `v: 0.0.1`, `0.0.2`, or `0.0.4` are `unsupported-version`, and the verifier prints a hint to use mdsig v0.0.5. The format version now changes only with incompatible changes and becomes `1` when the specification is published as an RFC (SPEC 3.3).
- `alg` is required. `hash` and `alg` no longer have defaults.
- Values may not contain `-->`, `--!>`, or `<!--`. `--` alone is allowed again, so internationalized domain names (`xn--…`) can be signers. Values also reject characters of general category Cf, Zl, Zp, and noncharacters (zero-width characters, tag characters), not only C0/C1 controls and bidi controls (SPEC 3.2).
- A continuation line with trailing whitespace is malformed; parsers used to strip it silently. Whitespace after the two-space indent is part of the value.
- `role` is a single word matching `[a-z0-9][a-z0-9._-]*`.
- Signer identifiers are compared exactly, in a canonical form: lower-case ASCII domains (`ldh-domain`, A-labels for IDNs), lower-case `git-hosting` user names, and no `*` anywhere. Non-canonical values are malformed. Generators lower-case ASCII input for every method except `tofu` (SPEC 3.4).
- `scope`, `resources`, and `require` use one list-line grammar: a target followed by `name=value` attributes, separated by single spaces (SPEC 3.5).
  - `scope`: one section id per line. The `section:` prefix and comma-separated values are gone.
  - `resources`: `<ref> hash=sha256:<hex>`, with the reference first. Local references are percent-decoded (write a space as `%20`); `%2F`, `%5C`, `%00`, `.` and `..` segments, and `./` prefixes are malformed (generators strip `./`).
  - `require`: see the next section.
- `require` was rewritten (SPEC 5.8):
  - `order mode=pending|guide|strict` replaces `order pending|guide|strict`.
  - `step` and `step any=<m>` replace `step <n>` and `step <n> any <m>`. Steps are numbered by position, and the lines of a step are written indented below it (indentation is optional when reading).
  - Roles are attributes: `dns:example.com role=approver`, not `dns:example.com approver`.
  - A step without `any` needs every line; one block counts for one line of a declaration. Blocks are assigned to lines deterministically by maximum matching (SPEC Appendix C), so the result no longer depends on the order the verifier tries lines in.
  - `order mode=strict` may not be combined with pattern lines (anyone could sign early and cause a violation that cannot be undone).
- Timestamps live only in `tsa` blocks. The in-block fields `tsa_url` and `tsa_token` are removed. `mdsig sign --tsa` and `tsaUrl` now append a `tsa` block after the signature block. The time of a block, `T(k)`, is the earliest `genTime` plus accuracy of a valid `tsa` block after it; the JSON `tsa` member of a signature, key-snapshot times, and the signature table all use it (SPEC 4.6).
- Revocation lists are signed lists: the entries are in a single code fence with the info string `mdsig-list`, starting with `type: revocation`, one `revoked: sha256:<hex>` per line. Lists are fetched over https only, up to 10 MB (SPEC 5.10).
- The `zstd+base64:` prefix is no longer reserved.
- Agreement statuses add `undetermined` (a roster or the network was needed and not available; exit code 3) and `unsupported` (a requirement uses a method or attribute the verifier does not know; exit code 1). In both cases `ok` is `false`.
- JSON (CLI_SPEC 5): requirement attributes are in an `attributes` object; missing requirements carry `rejected: [{index, reason}]` instead of `early`; new `next`, `satisfied`, and `declarations`; signatures carry `display_name`, and `tsa` carries `time` and `block`.
- Go: `ParseRequire(value, declaredBy)` returns `*ParsedRequire` (no version argument); `Requirement`, `MissingRequirement`, `OrderViolation`, and `Agreement` changed shape; `CheckTSAToken` and `RequestTimestamp` take the data to timestamp (the signed payload of the chain) instead of the `sig` bytes; `ResourceLoader` receives the decoded path. TypeScript changed in the same way.

### Added

- `require` attributes and patterns (SPEC 5.8.2, 5.8.3):
  - `user_verified`: the block is a passkey signature with UP and UV set. Signing tools ask the authenticator for user verification when a document requires it, and the signing-page handoff carries `user_verification=required` (CLI_SPEC 8).
  - `member_of=<https URL>` (a signed roster document, `type: members`) and `member_of=dns:<domain>` (one TXT record per member at `<label>._member._mdsig.<domain>`, `v=mdsig1; m=<method:signer>`).
  - `pubkey=` on `tofu` lines, recommended so that a self-chosen name cannot satisfy the line.
  - Patterns `dns:*`, `dns:*.<domain>`, `directory:*`, `directory:*@<domain>`, `pgp:*`, `pgp:*@<domain>`, `git-hosting:*`. Pattern lines never count the declaring signer.
- `display_name`: a self-declared name, at most 64 code points (RFC 8266 Nickname profile). Viewers must show it next to the verified signer and mark it as declared.
- Signature table: `<!-- mdsig:signatures -->` in the body marks where viewers draw a table built from the verified blocks. Nothing is written into the body, and the table is built outside the rendered body so body HTML cannot imitate it (SPEC 5.11, 9.5).
- CLI commands:
  - `mdsig render <file>` writes one HTML file with the verification summary, the body, and the signature table.
  - `mdsig require explain <value>` describes a `require` value step by step (`--json` available).
  - `mdsig member-record <method:signer> <domain>` prints the TXT record for a DNS roster; `--check` looks it up.
  - `mdsig sign --display-name`.
- Library: `signatureTable` / `SignatureTable`, `renderSignatureTableHtml` / `RenderSignatureTableHTML`, `explainRequire` / `ExplainRequire`, `memberRecordName` / `MemberRecordName`, `parseSignedList`, `CheckSignerID`, `CheckMemberRecord`.
- Hints for old syntax: positional roles, `order strict`, `step 1`, `section:` in `scope`, the old `resources` order, `tsa_token`, and `v: 0.0.x` produce a message that names the 0.1 form. The verdict does not change.
- A body that ends inside a code fence (which would show every signature block as code) is refused by signers and warned about by verifiers (SPEC 5.5).
- `AGENT_COMMERCE.md` (informative): using md-signature to sign and accept terms between AI agents, alongside LCP, x402, AP2, and PACT.
- SPEC sections on identifier normalization, privacy considerations (RFC 6973), implementation status (RFC 7942), IANA registries, and minimum limits (64 `require` lines, 16 steps, 8 roster URLs, 256 roster lookups, 100,000 list entries).
- `mdsig revoke` accepts `-m directory`.
- Go dependencies: `github.com/yuin/goldmark` (CLI only, for `mdsig render`) and `golang.org/x/text` (now a direct dependency of the library, for the Unicode normalization of `display_name`).

### Removed

- Verification of format 0.0.1, 0.0.2, and 0.0.4 blocks, including the rules that only applied to them (duplicate requirement lines, one block satisfying several lines).
- `tsa_url` and `tsa_token` fields; the `zstd+base64:` reservation.
- The `tsa_token` key in the `POST /v1/tsa` request body (renamed to `token`).
- Case-insensitive signer comparison (`sameSigner`).

### Migrating from 0.0.x

- Documents signed with 0.0.x cannot be re-signed or co-signed by others with this release: appending a 0.1 block leaves the earlier blocks `unsupported-version`, so the document never verifies. Keep verifying them with mdsig v0.0.5 or `@mdsig/core` 0.0.5.
- To carry on with such a document under 0.1, start a new signed document, for example one that binds the old file with `resources`.
- Scripts that pass `--require` need the new syntax: `--require "step"`, `--require "dns:example.com role=approver"`, `--require "step any=2"`, `--require "order mode=strict"`. `mdsig require explain` shows how a value reads.
- Scripts that read the JSON output should read requirement attributes from `attributes`, use `rejected` instead of `early`, and treat `undetermined` and `unsupported` as failures.
- Revocation lists must be re-published in the `mdsig-list` fence form and signed with format 0.1.
