# ByteBind roadmap

## Specification 0.8-draft (experimental implementation)

`SPEC.md` now specifies protocol v1 at draft 0.8: the full base protocol plus
optional Authority-owned WebAuthn person step-up. The reference implementation
now implements the base exchange and optional person step-up, with signed
synthetic-authenticator tests and a headless Chrome/virtual-authenticator
exchange on loopback HTTPS. Acceptance with real tailnet HTTPS, platform
authenticators and security keys across supported browsers, independent review,
and recovery approval remain open. Draft 0.7 is in git `3072234`. Design review records are in
[the committed review notes](https://github.com/BytesAndCoffee/bytebind/blob/c1f6e888979aeb61f772340c3c76787ab89e74a5/docs/drafts/SPEC-0.8-REVIEW-NOTES.md).
The [historical implementation review](https://github.com/BytesAndCoffee/bytebind/blob/c1f6e888979aeb61f772340c3c76787ab89e74a5/docs/drafts/SPEC-0.8-IMPLEMENTATION-REVIEW.md) records
findings against `a1e2b2e`, with subsequent fixes noted separately.
`c1f6e88` simplifies enrollment and management, adds eight-character invites and
durable failed-guess limits, accepts omitted optional credential properties when
the stored registration required discoverability, and makes step-up frames invisible.

### Open implementation findings

- **F1:** a validation refusal now requests fresh step-up, but the RP still needs
  to erase the invalid person context from storage so renewal cannot carry it.
  Add coverage across both bindings.
- **F2:** same-host RPs must configure `BYTEBIND_AUTHORITY_UID` when the Authority
  uses a different account. Setup docs now explain it; requiring an explicit UID
  with a clear startup error remains a proposed improvement.
- **F3:** session creation currently uses the requested route's maximum age,
  rather than the largest registered route maximum required by SPEC.md §17.3.
- **F4/F8/F9:** result-poll connection overhead, generation rules for operator
  revocation, and direct discovery-client pin lifetime need follow-up. The
  bindings persist Authority pins, but direct discovering-client redemption is
  tied to its single-process in-memory map.

These findings remain open; documentation updates do not resolve code requirements.
F6's mandatory `credProps.rk` check was changed in `c1f6e88`: omission is accepted
only for a stored `residentKey: required` request; an explicit negative or
malformed report is refused. Signed tests cover the change. Successful real
Firefox registration remains to be verified. F5 is documented as an ES256-only
implementation limit; broader algorithm support is still deferred.

### Release gates

1. **Wire freeze:** exact closed schemas, caps, paths, JSON encodings,
   draft/assurance capability negotiation, the person-association handle and
   validation call, typed errors, and every control and browser response
   variant. No fallback may remove a required assurance.
2. **Browser acceptance** on real private HTTPS listeners with current Chrome,
   Safari, and Firefox, and real platform authenticators and security keys:
   - iframe delegation (`publickey-credentials-get`, CSP, Permissions-Policy);
   - invisible frames invoking `get()` without a frame-local click, including
     Safari's gesture requirements and consent prompt;
   - whether each browser sends `topOrigin`;
   - the actual local-network permission token names and subframe permissions;
   - blocked third-party cookies;
   - refusal when the application page is itself framed;
   - the RP's terminal failure when API support or delegation is unavailable,
     without revealing the frame or falling back to weaker assurance;
   - result long-polling;
   - synced and discoverable credentials;
   - ES256-only enrollment, including refusal of RS256-only authenticators;
   - discoverable registration when the optional `credProps.rk` result is omitted,
     and refusal of explicit negative or malformed reports;
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
6. **Verifier dependency:** the implementation pins [Yubico python-fido2](https://developers.yubico.com/python-fido2/)
   at 2.2.1. Review the verification API, algorithms,
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
- Enrollment codes: eight hex characters; case/separator normalization;
  one-use consumption; expiry at 15 minutes; collision reservation; persistent
  10-per-device/100-per-Authority failed-guess budgets; simultaneous guesses;
  no budget reset after success, process recreation or an IP change.
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

### Examples and diagrams

The [packaged demo](../examples/demo/README.md) offers `/admin` for device access,
`/passkeys` for private Authority registration links, `/verified` for bounded
person verification and `/api/person/approve` for a fresh verified transaction.
The [RP example](../examples/rp_app.py) keeps `/status` and `/restart` device-only,
and adds `/passkeys`, `/verified` and `/restart-verified`.

Enrollment and management are top-level Authority pages; the application receives
neither invite tokens nor credential material. The base handshake chart is
device-only; the person sequence is shown separately in the threat model.

## Authority discovery


A relying-party package on an overlay-connected machine discovers one Authority
when creating a transaction, or uses a configured HTTPS/Unix endpoint.

Discovery uses the dedicated Authority tag or capability, overlay metadata and
certificate validation. Restricted tag/capability ownership defines which
operators may advertise an Authority.
An accepted Authority is trusted to issue grants, so discovery policy is part
of the authorization boundary.

The RP records the creating endpoint for each `cid`. Transaction creation,
browser attestation, and redemption must reach that same Authority. Failover
requires defined behavior for its pending transactions.

Zero or multiple matching Authorities fail closed. Random selection and failover
are not implemented. Multi-Authority deployment still needs credential/state
ownership rules and consistent authorization policy before selection or failover
can be claimed.

## Questions for the Tailscale community

- What stability guarantees apply to the LocalAPI `status` and `whois` fields
  used by the provider: `TailscaleIPs`, `ShareeNode`, `StableID`, `Tags`, and
  `Sharer`? Is another supported interface preferable?
- Would policy-file app capabilities be a better authorization signal than tags?
- How does this design relate to `tsidp` and Serve identity headers?
- What browser permissions are required when a public page calls a tailnet endpoint?

## Design decisions still open

- **Specification license:** the code is MIT; the specification is currently
  copyright with no reuse license. Consider CC BY 4.0. An IETF submission would
  have its own publication terms.
- **Embedded Authority:** investigate an in-process `tsnet` package while
  preserving RP/Authority authentication and state ownership.
- **Managed Authority profile:** define connection-to-device mapping and, if
  offline verification is needed, a signed grant format.

## Recorded verification results

The recorded run through `c1f6e88` reports:

- 260 passing tests on macOS with the pinned `fido2==2.2.1` verifier, including
  both bindings, both headless clients, signed synthetic passkey assertions,
  independent subject enrollment, revocation, renewal, outage and concurrent
  assertion/delivery/quota checks, short-invite collision and guess budgets,
  omitted credential-property reports, enrollment/management UI flows, and
  invisible-frame success, refusal, cancellation and cleanup.
- Successful wheel construction and inclusion of both browser scripts and the
  person modules at the initial implementation snapshot.
- Real local Unix-socket control exchanges with kernel-reported RP and Authority
  peer credentials. Tailnet identity is supplied by test directories.
- Headless Chrome 154 with a virtual CTAP2 authenticator on separate loopback
  HTTPS application and Authority origins: registration, hidden cross-origin
  `get()`, signed assertion acceptance, one-use H2 collection and RP redemption
  succeed. The frame has zero dimensions, stays outside keyboard navigation and
  the accessibility tree, and is removed after completion. This is not a test of
  a physical authenticator, Safari/Firefox, or tailnet local-network permissions.
- A separately staged dev-vps demo exercised real tailnet device access, private
  HTTPS certificates and same-host Unix control. It used an overlay on an earlier
  commit; that exercise does not establish an exact-HEAD deployment or complete
  the browser acceptance matrix.

The earlier device-only project record reports:

- 96 unit and integration tests covering hostile inputs, control transports,
  Unix-socket peer credentials, races, and clock skew.
- Installation into a fresh virtual environment.
- End-to-end session and transaction-bound exchanges using real processes and
  headless Chromium, with foreign origins and missing required tags refused.

These results describe the test setup. The list below tracks deployment coverage
and independent review still required.

## Verification outstanding

- Repeatable integration coverage using real `tailscaled` LocalAPI responses;
  automated tests use controlled directories and recorded shapes.
- The full browser acceptance matrix on real tailnet listeners and certificates;
  the separate demo exercise covers only part of it.
- HTTPS control traffic between two tailnet nodes.
- BSD peer credentials; local socket tests now also run on macOS.
- Browser local-network access permissions on supported versions.
- Independent review of the protocol and reference implementation.
