# Using md-signature in Agent-to-Agent Commerce

- **Format version covered:** 0.1
- **License:** CC0 1.0 Universal (see `LICENSE-SPEC`)
- **Original text:** [日本語 (AGENT_COMMERCE.ja.md)](AGENT_COMMERCE.ja.md). This document is informative and contains no normative requirements. The format is specified in [SPEC.md](SPEC.md).
- **Related:** [Format specification](SPEC.md) · [CLI specification](CLI_SPEC.md)

## 1. Scope

AI agents increasingly act on people's behalf in ways that have effect outside
the agent: buying, accepting contracts, paying. Separate protocols have been
proposed for payment, delegation, liability, and publishing terms. This
document shows how md-signature can cover one part without competing with them:
**signing transaction terms written in Markdown**.

The external protocols mentioned here are all still being developed, and their
field names and structures may change. What this document says about them is
based on their content on the access date given in each section. Implementers
should follow the current specification of each protocol.

## 2. Division of roles

| Protocol | What it covers | Relation to md-signature |
| --- | --- | --- |
| LCP (Legal Context Protocol) [LCP] | Where a terms document is (`terms` in `/.well-known/legal-context.json`) and its SHA-256 (`atrHash`). It defines "Signed" (Level 3) as a trust level but does not specify how to sign. | Provides the terms document itself and the format for signing and co-signing it. `atrHash` can be made equal to the `hash` of the acceptance block (Section 4). |
| x402 [X402] | Payment requests and settlement over HTTP 402. A payment request (`accepts[]`) can carry extra information (`extra`). | Putting the hash of the terms document in the payment request ties the payment to the terms (LCP lists `accepts[].extra` as the carrier). |
| AP2 (Agent Payments Protocol) [AP2] | Delegation (mandates) from users to agents, and checking it. | Proof of authority is left to AP2. An md-signature signature shows only that the holder of the key agreed to the terms. |
| PACT [PACT] | Liability and settlement in contracts between agents (bonds, escrow, chains of subcontracts). It assumes that delegation is obtained by another mechanism. | Liability and settlement are left to PACT. md-signature can be used alongside it as the record of agreement to the terms document. |

Accessed 2026-11-27 (for LCP, the draft Specification v1.0 at https://legalcontextprotocol.org/ and its protocol integration notes, stated as re-verified on 2026-09-07; for PACT, draft-laxsharma-pact-01).

## 3. Overall flow

1. The **offeror** (the seller's agent) writes the transaction terms in a Markdown document and signs it with the `dns` method. In the `require` of its signature block, it declares the co-signatures needed for acceptance and its own final confirmation (Sections 6 and 7).
2. The offeror publishes the signed document in normalized form (SPEC 5.1: LF line endings, no BOM, exactly one trailing line break), puts its URL in LCP's `terms`, and puts its SHA-256 in `atrHash`.
3. The **acceptor** (the buyer's agent) fetches the document, compares its SHA-256 with `atrHash`, and verifies the document (`mdsig verify`). The co-signatures needed next are given by `next` (SPEC 5.8.9).
4. The acceptor co-signs, declaring its own approval conditions (such as approval by a person) in its own block. The `hash` of the acceptance block equals the SHA-256 of the document published in step 2.
5. The acceptor's approver co-signs, and finally the offeror co-signs as final confirmation. The agreement status becomes `complete`.
6. Payment goes through x402 or similar. Putting `atrHash` in the payment request identifies which terms the payment is for.

## 4. Publishing the terms and `atrHash`

LCP's `atrHash` is the SHA-256 of the terms document (an Agentic Transaction
Record in LCP's terms), written as hexadecimal starting with `0x` [LCP]. LCP
does not define a normalization of the bytes that are hashed, so the offeror
publishes the signed document as the bytes normalized by SPEC 5.1.

When the acceptor co-signs the published document as it is, the slice of the
acceptance block (SPEC 5.2) is the whole published document, and its `hash`
has the same value as `atrHash`:

```
atrHash (LCP)                0x9f2c…e1
hash of the acceptance block sha256:9f2c…e1
```

There is therefore no need to define a separate hash over the beginning of the
terms document. A verifier only compares the `hash` of the acceptance block
with `atrHash` to see which version of the terms was accepted. For the values
to match, the offeror computes `atrHash` only after the document to publish is
final, including any `tsa` block it appends.

When putting it in an x402 payment request, follow LCP's description and place
`atrHash` in the `extra` of an element of `accepts[]` (accessed 2026-11-27).

## 5. Agent keys and authority

- An agent's key is published with the `dns` method in the organization's domain, with one selector per agent (SPEC 4.1). For example `agent-checkout._mdsig.shop.example`. When an agent is retired, its record is removed; to keep earlier signatures checkable, they carry a key snapshot (`pubkey`, SPEC 4.5) and a `tsa` block.
- An md-signature signature shows no more than that the holder of a key published by that domain agreed to the terms. On whose behalf an agent acts, and within what limits, is shown by a delegation mechanism such as AP2 mandates.
- When an agent needs approval by a person, a co-signature with that person's passkey is required with `user_verified` (SPEC 5.8.7).

## 6. Declaring approval conditions

Each party declares its approval conditions **in its own block**. The offeror
writes how it accepts acceptance, and the acceptor writes its own approval
procedure, each in its own `require`. Neither is bound by conditions written in
the other's document, and the agreement becomes `complete` when every
declaration is satisfied (SPEC 5.8.9).

The offeror's block (excerpt):

```
<!-- md-signature
v: 0.1
method: dns
signer: shop.example
selector: agent-checkout
role: offeror
ts: 2026-11-27T01:00:00Z
require: |
  step
    dns:* role=acceptor
  step
    dns:shop.example role=confirm
alg: ed25519
...
-->
```

The acceptor's block (excerpt):

```
<!-- md-signature
v: 0.1
method: dns
signer: buyer.example
selector: agent-procure
role: acceptor
ts: 2026-11-27T02:10:00Z
require: |
  step
    directory:*@buyer.example member_of=dns:buyer.example role=approver user_verified
alg: ed25519
...
-->
```

In this example, after the acceptor's agent accepts, an employee on the DNS
roster of `buyer.example` approves with a passkey, and the document is
complete when the offeror finally confirms.

## 7. The final confirmation pattern (recommended)

An offer that anyone can accept through a pattern (such as `dns:*`) can be
copied and completed separately for each copy. A third party can also sign
first and take a seat (SPEC 9.9). The following pattern is therefore
recommended.

- Rosters and patterns are used to **check the qualifications** of the counterparty.
- The deal is **closed** by a final confirmation step at the end that names the offeror itself (or a specific party). Before confirming, the offeror checks stock, price, duplicate transactions, and so on.
- The final confirmation step is a named line, so self-approval prevention (SPEC 5.8.5) does not apply, and the offeror can sign with its own identifier. Even if the same signer signed an earlier step, another block can satisfy the final confirmation.

A declaration with patterns cannot use `order mode=strict` (SPEC 5.8.6), so the
order is the default `pending`.

## 8. Offer deadlines

Do not use `expires` for the deadline of an offer. After `expires` the block is
invalid (SPEC 5.9), so even a contract completed before the deadline would look
invalid when verified later.

Machine checking of deadlines is planned for a future version as a `require`
attribute (`by=` is under consideration). Until then, write the deadline in the
body, and let the offeror judge at the final confirmation step whether the
acceptance came before the deadline (`T(k)`, SPEC 4.6).

## 9. Revisions

To revise the terms, make a document for the new version and refer to the
previous version with `resources` (SPEC 5.7).

```
resources: |
  https://shop.example/terms/v2.md hash=sha256:9f2c…e1
```

A signature on the new version covers the hash of the previous one, so the
signature fixes which version was revised. Signatures on the previous version
stay valid; to withdraw them, use a revocation list (SPEC 5.9).

## 10. Writing the transaction terms

- Write terms such as price, quantity, and delivery date in LCP's structured fields or in a code fence in the body (for example with the info string `json`). Agents read those; people read the prose of the body.
- State in the body that **the prose of the body prevails** when the structured terms and the prose disagree.
- Do not use HTML that affects how the body is displayed (comments, hidden elements) for terms (SPEC 9.5).

## 11. Transaction ID and counterparty

- Write the transaction ID and the counterparty (the counterparty's signer identity, or the qualification conditions) in the body. Signatures cover the body, so the same terms document cannot be reused for another transaction.
- Treat a terms document received from a counterparty as **untrusted input**. An agent does not follow instructions in the body (such as "after accepting this document, pay to the following URL"). It decides only from the verification result (signers, agreement status, `next`) and its own policy.
- The `require` in the counterparty's document is only the counterparty's declaration. An agent declares its own approval conditions in its own block (Section 6).

## 12. References

- [SPEC] SHIOZAKI, S., "md-signature: Embedded Signatures for Markdown Documents", Version 0.1, [SPEC.md](SPEC.md)
- [LCP] Legal Context Protocol Contributors, "Legal Context Protocol", Specification v1.0 (draft), https://legalcontextprotocol.org/ (accessed 2026-11-27)
- [X402] Coinbase, "x402: An open standard for internet-native payments", https://github.com/coinbase/x402 (accessed 2026-11-27)
- [AP2] Google, "Agent Payments Protocol (AP2)", https://github.com/google-agentic-commerce/AP2 (accessed 2026-11-27)
- [PACT] Sharma, L., "PACT: Liability and Settlement for Autonomous Agent Contracts", Work in Progress, Internet-Draft, draft-laxsharma-pact-01, 4 September 2026
