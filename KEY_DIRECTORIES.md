# Default list of key directories

[日本語](KEY_DIRECTORIES.ja.md)

When a verifier checks a `directory` signature ([SPEC 4.7](SPEC.md#47-directory-key-directory))
and the domain of `signer` does not name a directory with `dir` in `_mdsig`, the verifier queries
its own list of trusted key directories. This document sets the default list that the
implementations in this repository ship with (`@mdsig/core` for TypeScript, `mdsig.dev/mdsig` and
the CLI for Go), and the criteria for adding a directory to it.

The list is a verifier setting, not part of the format. Verifiers can add to it or replace it
(`mdsig directory trust` in the CLI, `keyDirectories` and `extraKeyDirectories` in TS,
`ResolveOptions.KeyDirectories` in Go).

## Current list

| URL | Operator | Confirms |
| --- | --- | --- |
| `https://keys.mdsig.dev` | the md-signature project | email |

## Criteria for inclusion

Every directory in the list carries the same weight, so the least careful one sets the level for
all of them (SPEC 9.11). A directory is added only if it meets all of the following:

1. It implements the lookup API of SPEC 4.7 and meets the requirements for directories there
   (agreement obtained by email, possession confirmed by a challenge, a way to remove keys, and
   `Access-Control-Allow-Origin: *`).
2. It publishes how registration, confirmation, and removal work, what data it keeps, and for how long.
3. Its operator and a contact are known, and it announces a shutdown at least 90 days in advance.
4. It answers over HTTPS without interruption (lookup API availability of 99% or more in the
   30 days before the request).
5. It publishes how it handles fraudulent registrations once they are found.

## Requests and review

- Requests to add a directory are made as issues in this repository, with material showing that
  each criterion is met.
- A directory that no longer meets the criteria, or fails to handle fraudulent registrations, is
  removed from the list. Removals are noted in the release notes.
- A change to the list is made in TS (`DEFAULT_KEY_DIRECTORIES`) and Go (`DefaultKeyDirectories`)
  in the same change.
