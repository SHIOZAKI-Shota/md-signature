# @mdsig/core

TypeScript implementation of [md-signature](../../README.md), a signature format embedded in Markdown documents. It signs, verifies, serves verification over HTTP, and talks to such a server.

[日本語](README.ja.md) · [Format specification](../../SPEC.md) · [CLI and HTTP API specification](../../CLI_SPEC.md)

- Runs in browsers, Node.js 22 or later, Deno, Bun, and Cloudflare Workers. No `node:*` modules are used.
- Install it with `npm install @mdsig/core`. Releases share the version number of the `mdsig` CLI.
- This is a draft. It signs with format `0.1` and verifies only `0.1` (`0.0.x` documents are `unsupported-version`; verify them with 0.0.5). The API may change before 1.0.

## Verifying

```ts
import { verifyDocument } from "@mdsig/core";

const result = await verifyDocument(text);

result.ok;          // true when there is no document-level error, every block is valid, and agreement is not violated, undetermined, or unsupported
result.error;       // a problem with the document as a whole (no signature, unsigned content after the last signature, ...)
result.signatures;  // one result per block
result.agreement;   // co-signatures asked for with `require`: none / complete / pending / violated / undetermined / unsupported
```

Each block result has these fields.

| Field | Meaning |
| --- | --- |
| `status` | `valid`, `invalid`, `malformed`, `unresolved`, `unsupported` |
| `code` | Why it failed: `hash-mismatch`, `bad-signature`, `expired`, `revoked`, `key-changed`, `network`, `not-found`, and others |
| `message` | Explanation in English |
| `fields` | The values written in the block (`signer`, `method`, `role`, `ts`, ...) |
| `tsa` | `tsa` blocks only: the check of the token. `genTime` is present only when `verified` is `true` |
| `time` | The block's time `T(k)`: the earliest `genTime` plus accuracy of a valid `tsa` block after it (format specification, section 4.6). Absent when there is none |
| `revocation`, `resources`, `partial`, `pgp`, `webauthn` | Present when they apply |
| `warnings` | Things a user should be told although the block is valid |

`unresolved` means there is no verdict: the key could not be obtained, the revocation list could not be fetched or is not signed by the signer, a resource could not be fetched, the embedded key is no longer published (`key-not-published`), or the chain of a `tsa` block does not verify. Do not treat it as valid. Under `offline`, blocks that could not be checked are `unresolved` too, so `result.ok` is `false`.

A pending agreement leaves `result.ok` `true`; check `agreement.status` (the CLI exits with 5).

### Main options

| Option | Meaning |
| --- | --- |
| `fetch` | Function used for outbound requests. Set it to go through a relay, or to replace the network in tests |
| `offline` | Do not use the network. `tofu` blocks are checked as usual and `tsa` blocks need no network. A `dns` or `git-hosting` block with an embedded `pubkey` is still `invalid` when the signature does not match it. Other blocks become `unresolved` (code `offline`) |
| `resolvers` | Replace how keys are found, per method (`dns`, `git-hosting`, `tofu`, `pgp`) |
| `tofuStore` | Where the signer-to-key bindings of `tofu` are kept. A key that differs from the stored one is invalid with `key-changed` |
| `acceptNewTofuKey` | Accept a changed `tofu` key and replace the stored binding |
| `keyserver` | Keyserver for `pgp` lookups. Default: `https://keys.openpgp.org` |
| `keyDirectories`, `extraKeyDirectories` | Replace or extend the trusted key directories for `directory` lookups. Default: `DEFAULT_KEY_DIRECTORIES` (`https://keys.mdsig.dev`). A directory named by `dir=` in the signer's domain's `_mdsig` record takes precedence |
| `loadResource` | Function that reads the local files named in `resources`. Without it they are "not checked" |
| `fetchResources` | Fetch `https://` resources and check their hashes. Off by default |
| `checkRevocation` | `false` skips revocation lists |
| `now` | Time used for expiry |
| `tsaRoots`, `extraTsaRoots`, `tsaVerifier` | See the next section |

## Trust for timestamps (TSA)

A `tsa` block is valid and yields a time (`genTime`) only when the TSA's signature and certificate chain verify up to a trusted root certificate. Otherwise it is `unresolved` and shows no time. It does not change whether the signature blocks before it are valid; they just get no `time`.

A browser has no trust store a page can read, so the root certificates of public TSAs are built in (`DEFAULT_TSA_ROOTS`).

```ts
import { verifyDocument, DEFAULT_TSA_ROOTS, readTsaRoots } from "@mdsig/core";

// add to the built-in roots
await verifyDocument(text, { extraTsaRoots: [pemText] });

// trust only the given roots
await verifyDocument(text, { tsaRoots: [pemText] });

// look at certificates: name, SHA-256 fingerprint, expiry
const roots = await readTsaRoots(pemText);
```

A value is DER (`Uint8Array`) or PEM text, and PEM text may hold several certificates. `signDocument` takes the same options and uses them to check the `tsa` block it appends for `tsaUrl`.

The built-in list is chosen from the roots that Microsoft's root program (CCADB) trusts for time-stamping. Certificate revocation (CRL, OCSP) is not checked.

## Signing

```ts
import { signDocument, generateEd25519, signerFromSeed } from "@mdsig/core";

const { signer } = await generateEd25519();          // a new key
// const signer = await signerFromSeed(seed32bytes); // an existing Ed25519 seed

const { text } = await signDocument(markdown, {
  signer,
  method: "tofu",           // dns / git-hosting / tofu / pgp
  signerId: "bob@laptop",
  displayName: "Bob",       // shown in the signature table, as declared
  role: "reviewer",
  reason: "Reviewed",
});
```

Pass `require` one line per string. Steps (`step`, `step any=2`) and the order handling (`order mode=…`) are lines too, and the lines of a step are written indented below it (format specification, section 5.8).

```ts
await signDocument(markdown, {
  signer, method: "git-hosting", signerId: "github.com/alice",
  require: ["order mode=strict", "step", "dns:example.com role=approver", "step any=2", "git-hosting:github.com/bob role=reviewer", "git-hosting:github.com/carol role=reviewer", "git-hosting:github.com/dave role=reviewer"],
});
```

In the result, `agreement.missing` lists the lines not yet satisfied (`step`, `need`, `blockedBy`, and `rejected`: blocks that were not counted, with the reason), `agreement.next` tells who has to sign next, and `agreement.violations` lists order violations. An `order mode=strict` violation makes `agreement.status` `violated` and `result.ok` `false`. When a roster (`member_of`) cannot be consulted, the status is `undetermined`. `explainRequire(value, "en")` describes a value before you sign.

Called on a document that already has signatures, it appends a co-signature. The main options are `selector` (for `dns`), `displayName`, `expires`, `scope`, `require`, `resources`, `revocationUrl`, `tsaUrl` (append a `tsa` block after the signature block), and `embedKey` (embed the public key with `dns`, `git-hosting`, and `directory`). Their meaning is in chapter 5 of the [format specification](../../SPEC.md).

A signer is made from an OpenSSH private key with `parseOpenSshPrivateKey`, from an OpenPGP secret key with `readPgpSecretKey` and `unlockPgpSecretKey`, and from a passkey with `registerPasskey` and `passkeySigner`.

## Long-term keeping

`timestampDocument` appends a timestamp block without a signer (`method: tsa`). It covers everything before it, earlier timestamps included, so stacking blocks renews the evidence.

```ts
import { timestampDocument } from "@mdsig/core";

const { text } = await timestampDocument(signed, { tsaUrl: "http://ts.ssl.com", hash: "sha512" });
```

A `dns` or `git-hosting` block signed with `embedKey: true` can still be checked with its embedded key after the key is removed. The result is then `unresolved` / `key-not-published`, not valid, because the document alone cannot show that the key was the signer's (format specification, section 4.5).

## Verifying on a server

What a browser cannot check by itself (keys that CORS keeps out of reach, a TSA check against the operating system's trust store) can be handed to a server. The HTTP API is defined in [section 3.6 of the CLI specification](../../CLI_SPEC.md) and is the one `mdsig serve` (Go) speaks.

### Server side

`createVerifyHandler` returns a function that takes a `Request` and returns a `Response`.

```ts
import { createVerifyHandler } from "@mdsig/core";

const handler = createVerifyHandler({
  allowOrigins: ["https://app.example.com"],  // origins that may call from a browser
  verify: { extraTsaRoots: [pemText] },       // options passed to verifyDocument
});

export default { fetch: handler };  // Cloudflare Workers, Bun
// Deno.serve(handler);             // Deno
```

With the `http` module of Node.js, requests and responses have to be converted to `Request` and `Response`.

The handler fixes the following.

- Each request is verified on its own. Stored `tofu` bindings, local files and keyrings are not used.
- A request with an `Origin` header is processed only if the origin is in `allowOrigins`.
- A body is at most 4 MiB and at most 8 requests run at once (`maxBodyBytes`, `maxConcurrent`).
- Outbound requests to IP literals, `localhost`, and internal names are refused.

The last limit cannot catch a public name that resolves to an internal address, because Web APIs do not show what a name resolves to. Where the server can reach an internal network, restrict its outbound traffic at the network level as well. The Go server (`mdsig serve`) checks the address when it connects.

Authentication and TLS are not included. Put them in front when the server is exposed.

### Client side

```ts
import { verifyDocument, remoteVerify, remoteTsaVerifier, compareResults } from "@mdsig/core";

// verify the whole document on the server
const remote = await remoteVerify("https://verify.example.com", text);

// compare with the local verdict
const local = await verifyDocument(text);
const diff = compareResults(local, remote);
diff.agree;     // status and code match for every block
diff.tsaAgree;  // both sides agree on whether the timestamp was verified
diff.blocks;    // both verdicts, per block

// hand over only the TSA check
await verifyDocument(text, { tsaVerifier: remoteTsaVerifier("https://verify.example.com") });
```

A verdict that comes from a server is trusted as far as that server is. Keep the two verdicts apart by source and do not merge them. The trusted root certificates differ, so `tsaAgree` can be `false`.

`remoteVerify` returns the JSON shape of `mdsig verify --json`. `toJsonResult(result)` gives a local result in the same shape.

## Differences from the Go implementation

| | TypeScript | Go (`mdsig`) |
| --- | --- | --- |
| Trust anchors for TSAs | Built-in roots and the ones you pass | The operating system's trust store and `--tsa-root` |
| Local gpg keyring, ssh-agent | Not used | Used by the CLI |
| Limits on outbound requests | Server handler only, by name | Fetches a document triggers (keys, revocation lists, resources), by connection address |
| CLI | None | Yes |

The signature format, the verdict vocabulary, the JSON shape, and the HTTP API are shared, and both implementations check the test vectors in [examples](../../examples).

## License

MIT
