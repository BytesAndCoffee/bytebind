# ByteBind roadmap

## Draft 0.8: Authority discovery

A relying-party package on an overlay-connected machine could discover
Authorities and select one when creating a transaction.

Discovery must authenticate each candidate through a dedicated Authority tag,
restricted tag ownership, overlay identity lookup, and certificate validation.
An accepted Authority is trusted to issue grants, so discovery policy is part
of the authorization boundary.

The RP records which Authority created each `cid`. Transaction creation,
browser attestation, and redemption must reach that same Authority. Failover
requires defined behavior for its pending transactions.

Authorities need consistent authorization policy. Random selection can distribute
load, but selecting among inconsistent policies lets clients retry against a
more permissive node.

Implementation work: a selection layer in `AuthorityClient`, per-transaction
routing, and tests for untrusted candidates, policy disagreement, and outages.

## Questions for the Tailscale community

- What stability guarantees apply to the LocalAPI `status` and `whois` fields
  used by the provider: `TailscaleIPs`, `ShareeNode`, `StableID`, `Tags`, and
  `Sharer`? Is another supported interface preferable?
- Would policy-file app capabilities be a better authorization signal than tags?
- How does this design relate to `tsidp` and Serve identity headers?
- What browser permissions are required when a public page calls a tailnet endpoint?

## Design decisions still open

- **Tag matching:** specify whether required tags mean any or all. The reference
  implementation makes this an RP setting, defaulting to any.
- **Specification license:** the code is MIT; the specification is currently
  copyright with no reuse license. Consider CC BY 4.0. An IETF submission would
  have its own publication terms.
- **Embedded Authority:** investigate an in-process `tsnet` package while
  preserving RP/Authority authentication and state ownership.
- **Managed Authority profile:** define connection-to-device mapping and, if
  offline verification is needed, a signed grant format.

## Recorded verification results

The existing project record reports:

- 96 unit and integration tests covering hostile inputs, control transports,
  Unix-socket peer credentials, races, and clock skew.
- Installation into a fresh virtual environment.
- End-to-end session and transaction-bound exchanges using real processes and
  headless Chromium, with foreign origins and missing required tags refused.

These results describe the test setup. The list below tracks deployment coverage
and independent review still required.

## Verification outstanding

- Real `tailscaled` LocalAPI responses; current tests use recorded shapes.
- Real tailnet listeners and `tailscale cert` certificates.
- HTTPS control traffic between two tailnet nodes.
- macOS and BSD peer credentials; execution so far covers Linux.
- Browser local-network access permissions on supported versions.
- Independent review of the protocol and reference implementation.
