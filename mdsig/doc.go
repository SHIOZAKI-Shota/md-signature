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
// StatusMalformed, StatusUnresolved, or StatusUnsupported. StatusUnresolved
// means the block could not be fully checked (a key, a revocation list, or a
// resource could not be fetched or trusted), so there is no verdict: do not
// treat it as valid. [ToJSON] converts a result to the JSON
// shape of "mdsig verify --json" (CLI_SPEC.md section 5).
//
// VerifyResult.Agreement evaluates the require declarations of the chain
// (SPEC 5.8 and Appendix C): complete, pending, undetermined (a roster or a
// declaring block could not be checked), unsupported, or violated. Rosters in
// member_of are fetched or looked up in DNS unless ResolveOptions.Offline is
// set. [SignatureTable] turns a result into the rows of a signature table,
// including the rows still to be signed, and [ExplainRequire] describes a
// require value in prose.
//
// # What the caller decides
//
// The zero [VerifyOptions] verifies with network access and no stored state.
// Outbound requests use [SafeHTTPClient] by default, which refuses
// connections to private addresses; a document names the hosts that are
// contacted (Git hosting, WKD, revocation lists, resources). A program that
// replaces ResolveOptions.HTTPClient, ResolveOptions.PGPClient, or
// ResourceCheckOptions.FetchClient takes over that protection. A caller may also set:
//
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
// A timestamp is a separate tsa block (SPEC 4.6) whose RFC 3161 token covers
// the block's payload. It yields a time only when the TSA's signature and its
// certificate chain verify against the system trust store, plus the roots in
// [TSAVerifyOptions].ExtraRoots ([LoadTSARoots] reads them from files). Each
// block then gets T(k), the earliest such time after it ([BlockResult].Time).
//
// # Status
//
// This release writes and verifies format version 0.1 only; 0.0.x documents are
// "unsupported-version" (verify them with mdsig v0.0.5). It is
// a draft without an independent security audit. The API may change before 1.0.
package mdsig
