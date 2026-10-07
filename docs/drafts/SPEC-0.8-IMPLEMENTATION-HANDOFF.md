# Specification 0.8 implementation handoff

This implementation snapshot is committed on `main`. Nothing has been pushed.
Protocol remains v1; package version is `0.8.0.dev0`.

## Implemented

- Authority-owned private person listener and per-RP iframe pages, after base
  attestation; warmed options and WebAuthn called directly from the click.
- Pinned `fido2==2.0.0` verifier, ES256, exact RP ID/origin, embedding checks,
  independent user handles, UP/UV, conservative counters and revocation versions.
- Hashed one-use handoffs, completion and management tokens; generation-checked
  state transitions, 120-second step-up, bounded collection, committed one-use
  H2 delivery and a redemption window beginning at delivery.
- Independent subjects, operator invitations, discoverable UV registration,
  fresh-UV credential management, explicit self-enrollment policy and pairwise
  RP subjects. Recovery remains disabled.
- Person session associations bound to RP, audience, browser lease and device.
  Device renewal preserves the original person age/deadline. Person endpoints
  validate before the handler and fail closed on an Authority outage.
- FastAPI/Flask assurance options and app-facing claim views, browser step-up,
  typed `StepUpRequired` for headless clients, creating-Authority pins, Unix
  peer-UID checks and fresh device-policy checks at redemption.
- Stored-operation replay excludes proof-request cookies and credentials.

## Concrete wire choices to cross-check

Control creation requires `protocol: 1`, `draft: "0.8"` and `assurance` alongside
the existing audience/profile. Each session creation has a random 32-byte
`lease_id`; silent device renewal preserves it. Person session creation adds
`person_max_age`; identity requests add `identify`. Control grants carry
structured `assurance`, a session `device_grant` reference and, when applicable,
`person_association`. `/v1/person-validation` binds those references to RP,
audience and lease; `/v1/person-logout` invalidates the lease association.

Base attestation returns either H2 or HTTP 202 with one `step_up` object containing
`url`, `handoff`, `completion`. `/attestation/result` accepts exactly
`cid`, `completion`, `N`, `H1`, holds at most ten seconds, and returns pending 202
or H2 once. Polls have a two-second minimum interval and one held call per cid.
The person listener exchanges the handoff into a memory-only
`X-ByteBind-Attempt` token; its POSTs require the exact Authority Origin and JSON.
Person payloads are capped at 32 KiB; control payloads at 64 KiB. The existing
base/proof caps remain. Inspect the closed-schema checks at each entry point.

## Verification and remaining gates

224 tests passed, including real ES256 signed synthetic authenticator responses,
both adapters, renewal, outage, disclosure, replay, counter regression, concurrent
assertion/delivery and enrollment quotas. The base vectors still reproduce;
`test-vectors/bytebind-v1-person.json` adds W and a UTF-8 pairwise-subject vector.
A wheel builds and contains both scripts and the person modules.

No real-browser/private-HTTPS acceptance or independent implementation review
has been completed. Permissions-Policy names and actual subframe behavior remain
provisional. Enrollment invite delivery is the operator's trusted channel;
existing-subject recovery has no enabled path. See `docs/ROADMAP.md`.

## Claude review request

Review the implementation commit against the complete SPEC.md, especially state and
counter races, scope binding, enrollment authorization, person identity
disclosure and renewal semantics. Check each wire choice above against the
normative requirements. Historical spec-review hashes prove only those historical
snapshots; they do not attest to this code. Record findings in a new review file
and preserve the existing review history. Coordinate before editing files that
are still being changed.

SPEC.md's implementation-status paragraph changed; its normative requirements
are unchanged. The current snapshot hash in the review notes was updated for
that paragraph change.

## Demo follow-up (separate commit)

After the implementation commit, the user requested passkey registration and
step-up in the demo. The separately committed follow-up adds `/passkeys`, links to the
private Authority's enrollment/management pages, `/verified` with five-minute
person verification and pairwise identity, and `/api/person/approve` requiring
a fresh transaction-bound verified assertion. `BYTEBIND_PERSON_ORIGIN` configures
only the registration links; step-up uses the authenticated transaction origin.

The demo integration test registers a separately invited subject through the
private HTTP listener, refuses a device-only lease on the person page, completes
the session and transaction ceremonies, rejects proof replay and checks subject
suspension. This exposed an RP error distinction: validation refusal (HTTP 403)
now requests fresh step-up; transport failure/Authority outage still refuses
with 503. Review that small `require_person` change with the demo additions.
The browser iframe is also sized to keep its verification controls visible.
The full suite passes with 230 tests after these additions.
