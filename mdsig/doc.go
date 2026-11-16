// Package mdsig signs and verifies md-signature blocks: signatures embedded in
// Markdown documents as HTML comments at the end of the file, forming an
// append-only hash chain.
//
// The format is defined in SPEC.md of this repository. The mdsig command
// (cmd/mdsig) and the HTTP handler (mdsig/server) are thin layers over this
// package and give the same verdicts.
//
// # Verifying
//
// [VerifyDocument] checks every block of a document and returns one
// [BlockResult] per block. A block is StatusValid, StatusInvalid,
// StatusMalformed, StatusUnresolved or StatusUnsupported. StatusUnresolved
// means a key or a revocation list could not be fetched, so there is no
// verdict: do not treat it as valid. [ToJSON] converts a result to the JSON
// shape of "mdsig verify --json" (CLI_SPEC.md section 5).
//
// # What the caller decides
//
// The zero [VerifyOptions] verifies with network access and no stored state.
// A program that takes documents from other people should set:
//
//   - ResolveOptions.HTTPClient, ResolveOptions.PgpClient and
//     ResourceCheckOptions.FetchClient to [SafeHTTPClient], which refuses
//     connections to private addresses. A document names the hosts that are
//     contacted (git hosting, WKD, revocation lists, resources).
//   - ResolveOptions.TofuStore, if "tofu" signers should be remembered between
//     calls. A key that differs from the stored one is then invalid with the
//     code "key-changed".
//   - ResourceCheckOptions.LoadResource, if local files named by a document
//     may be read. [DirResourceLoader] limits this to one directory.
//
// The handler in mdsig/server fixes these choices for a network service.
//
// # Timestamps
//
// An RFC 3161 token (tsa_token) yields a time only when the TSA's signature
// and its certificate chain verify against the system trust store, plus the
// roots in [TSAVerifyOptions].ExtraRoots ([LoadTSARoots] reads them from
// files). An unverified token never makes a signature invalid; it is reported
// without a time.
//
// # Status
//
// Version 0.0.1 is a draft without an independent security audit. The API may
// change before 1.0.
package mdsig
