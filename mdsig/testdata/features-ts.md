# Statement of Work

<!-- mdsig:section terms -->
## Terms
Payment within 30 days.
<!-- /mdsig:section -->

Notes (editable).

![Diagram](./img/diagram.png)

<!-- mdsig:section fees -->
| Fee | 100 |
<!-- /mdsig:section -->

<!-- md-signature
v: 0.1
method: tofu
signer: bob@laptop
pubkey: ed25519:/FHNjmIYoaONpH7QAjDwWAgW7RO6MwOsXeuRFUiQgCU=
display_name: Bob Example
role: author
reason: Scoped draft
ts: 2026-11-16T09:00:00Z
expires: 2027-11-16T00:00:00Z
scope: |
  terms
  fees
require: |
  order mode=guide
  step
    dns:example.com role=approver
    git-hosting:github.com/alice
  step any=1
    tofu:carol@passkey role=witness
    dns:*.example.com member_of=dns:example.com
resources: |
  img/diagram.png hash=sha256:3e6c2709c4ec2c55c5230002e4f6b2d4722d9058c0c77710f3c2c9c57064691b
  https://example.com/chart.png hash=sha256:2131cd6371005fcc97970ed7f9f16fa5dcee10496951f4a909f01b0fb5855297
revocation_url: https://example.com/.well-known/mdsig-revoked.md
x_dept: legal
x_ref: PO-123
alg: ed25519
hash: sha256:347c0977aeaf1fab94d858ae94ffda27069d5fbd7057a38ccd570d0ced92eccb
sig: |
  base64:qEbuZ4SmNx4/1H73003MpXyi/JMBESP0BB/BVs24M0TkKha2jWXgXaGNgnouJtntitohM
  MOKzkPsi61go6BXBg==
-->
