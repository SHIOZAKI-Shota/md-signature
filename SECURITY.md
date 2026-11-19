# Security policy

md-signature verifies signatures, so a bug here can make a forged or altered document look valid. Reports are welcome.

日本語での報告も受け付けます。

## Reporting a vulnerability

Please report privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability** ([direct link](https://github.com/SHIOZAKI-Shota/md-signature/security/advisories/new)). Do not open a public issue for something that lets a document verify when it should not.

A useful report has:

- what is affected: the format (`SPEC.md`), the TypeScript library (`packages/core`), the Go library or CLI (`mdsig`, `cmd/mdsig`), or the playground (`docs`);
- a document, command, or request that shows the problem, and what you expected instead;
- the version or commit.

This is a small project maintained in spare time. Expect a first answer within about a week.

## Scope

In scope:

- a document or signature block that verifies as valid although its content, signer, time, or covered range is not what the verdict says;
- a way to make a signature appear to come from another signer;
- a revoked, expired, or changed-key signature shown as valid;
- a timestamp shown as verified without a valid chain to a trusted TSA root;
- script execution, request forgery, or data exposure in the playground;
- requests from the CLI, the libraries, or `mdsig serve` to addresses they are meant to refuse.

Out of scope:

- a signer whose own key, DNS zone, hosting account, or mailbox was taken over;
- `tofu` signatures not proving identity (they are documented as integrity only);
- the test keys in `examples/`: they are public on purpose.

## Status

md-signature (release `v0.0.5`, format `0.0.4`) is a draft and has had no independent security audit. See the Status section of the README.

## Supported versions

Until 1.0, only the latest commit on the default branch receives fixes.
