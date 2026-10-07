# ByteBind roadmap

## Specification 0.8-draft (experimental implementation)

`SPEC.md` now specifies protocol v1 at draft 0.8: the full base protocol plus
optional Authority-owned WebAuthn person step-up. The reference implementation
now implements the base exchange and optional person step-up, with signed
synthetic-authenticator tests. Real private-HTTPS browser acceptance, independent
review, and recovery approval remain open. Draft 0.7 is in git `3072234`. Review records are in
[drafts/SPEC-0.8-REVIEW-NOTES.md](drafts/SPEC-0.8-REVIEW-NOTES.md).

### Release gates

1. **Wire freeze:** exact closed schemas, caps, paths, JSON encodings,
   draft/assurance capability negotiation, the person-association handle and
   validation call, typed errors, and every control and browser response
   variant. No fallback may remove a required assurance.
2. **Browser acceptance** on real private HTTPS listeners with current Chrome,
   Safari, and Firefox, and real platform authenticators and security keys:
   - iframe delegation (`publickey-credentials-get`, CSP, Permissions-Policy);
   - Safari's gesture and consent prompt;
   - whether each browser sends `topOrigin`;
   - the actual local-network permission token names and subframe permissions;
   - blocked third-party cookies;
   - refusal when the application page is itself framed;
   - the unsupported-browser message;
   - result long-polling;
   - synced and discoverable credentials;
   - multiple subjects on one device, and multiple devices for one subject;
   - cancellation and tab closure.

   Virtual authenticators supplement but don't replace these.
3. **Enrollment and recovery:** independently authenticated operator mechanism,
   invite transport, existing-subject recovery approvals, management UX, and
   audit policy. Recovery stays disabled until approved.
4. **Timing and storage:** validate the 30/120/30/10-second windows, RP attempt
   retention, cleanup, counter and revocation races, long-poll hold time and
   per-(peer, `cid`) budget, and durable delivery reservation under lost
   responses and crashes. Sequential challenge reissue after an accidental
   cancellation is **undecided**; the draft authorizes none.
5. **Person associations:** handle lifecycle, exact lease binding, logout,
   revocation generations, maximum-age enforcement, device continuity without
   identifier disclosure, and atomic invalidation.
6. **Verifier dependency:** evaluate [Yubico python-fido2](https://developers.yubico.com/python-fido2/)
   (preferred) and Duo py_webauthn. Check the verification API, algorithms,
   user-handle checks, counter and backup handling, parsing limits, security
   history, and license. Authority-only; no custom CBOR/COSE or signature
   verification.
7. **Vectors and independent review:** all v1 labels and encodings including
   `W` and the pairwise subject, first-delivery deadlines, negative vectors,
   state races, and end-to-end scope enforcement.
8. **Multi-Authority:** credential and state ownership and stable RP-ID
   ownership before any failover claim.
9. **Deferred scope:** popups and full-page navigation; related origins; an age
   claim; non-synced and attestation-provenance profiles; opaque address
   commitments; the draft-0.7 device-bound IdP profile (removed in 0.8).

### Protocol acceptance checklist

- Ordering and access:
  - base attestation before any handoff or options;
  - internet and unauthorized peers refused.
- Assertion verification:
  - a valid assertion is accepted;
  - wrong challenge, origin, RP ID, user handle, `cid`, RP, profile, or `Q` is
    refused;
  - a replayed assertion is refused;
  - missing UP or UV is refused;
  - unknown or revoked credentials and suspended subjects are refused;
  - correct `crossOrigin`/`topOrigin` is accepted, an absent `topOrigin` is
    accepted, and a wrong `topOrigin` or a false `crossOrigin` is refused;
  - counters: zero, out-of-order, and from different transactions.
- Framing and the person listener:
  - per-RP `frame-ancestors` lists exactly one origin;
  - a handoff on another RP's path is refused;
  - an unknown `rp_id` gets a generic not-found;
  - enrollment pages can't be framed;
  - no iframe message API;
  - no base-attestation paths on the person listener;
  - no `H2` or proof from the frame;
  - attempt tokens don't depend on cookies.
- Deadlines and concurrency:
  - cancellation and every deadline;
  - simultaneous handoff, assertion, result, redemption, and revocation;
  - durable burns, and the winner survives;
  - loss after success with no replay.
- Disclosure: no forbidden disclosure, and no credential leakage.
- Enrollment: subject attachment and invites.
- Sessions:
  - device-only renewal preserves the association without resetting its age;
  - endpoint-triggered validation, including expired freshness, revocation,
    Authority outage, device mismatch, and subject switch;
  - no stale person claims reach a handler;
  - no session evidence satisfies a fresh transaction.
- Compatibility:
  - exact stored-operation execution;
  - base-only v1 compatibility;
  - draft-capability refusal;
  - no assurance downgrade;
  - labels outside the v1 set refused.

### Demo plan

`/admin` device-only; `/admin/verified` bounded person verification;
`/admin/destructive-demo` a fresh verified transaction. Enrollment and
management are Authority-hosted top-level pages showing the subject and
friendly credential names, with device context kept separate.

After approval, update README, the demo, the blog, and the handshake chart: a
separate draft-0.8 chart shows `person_origin` and the 202/poll loop.

## Authority discovery


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
