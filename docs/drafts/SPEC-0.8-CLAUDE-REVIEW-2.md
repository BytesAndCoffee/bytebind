# Claude verification of Codex's round-1 and round-2 edits

**Reviewed:** `SPEC-0.8.md` at SHA-256
`2350d1ecc4d817d39ba289bc28ce6211a2cbbfb186cd15478a62396e9fb50caf`
(uncommitted), against the committed `938ab37` version (`29b13a6a…`).
Also reviewed: the round-2 ledger entry in `SPEC-0.8-CROSS-VERIFY.md`.
**Date:** 2026-10-06. This file is the only one Claude changed.

## Verdict

- **Round 1 (P1–P16): applied faithfully.**
  - All 23 patch fragments and gate edits are present, and all 6 replaced
    passages are gone (mechanical check).
  - The F1–F3 integration reads coherently across §§2, 8, 10, and 11.
  - One defect is mine: my F1 text has a side effect on the default
    configuration (V1 below).
- **Round 2 (iframe): sound, with one Medium coherence issue and four Low
  items.**
  - Every clause of the user's requirement is implemented.
  - Codex's ledger claims check out:
    - hashes `29b13a6a…` → `2350d1ec…` are correct;
    - the diff touches only §§5, 6, 7, 13, and 14;
    - §§8, 11, and 16 are unchanged.
  - Nothing weakens the base-first gate, the states, or redemption.

## Requirement trace (round 2)

| User requirement | Where satisfied |
|---|---|
| Person attestation is optional step-up | §4, §5 ("optional cross-origin iframe"), §5.1 |
| Base attestation completes through the existing flow | §6 steps 2–3 unchanged. §5.1 opens with "After base attestation succeeds" |
| The iframe must not replace, proxy, or perform base attestation | §5.1 ("MUST NOT perform, proxy, or relay base attestation"). §6 step 5 (the handoff peer check "does not replace, proxy, or perform"). §13 row. §14 test "no base-attestation paths on the person listener" |
| The iframe is reachable over the private overlay | Person listener on the overlay (§5, unchanged) |
| The iframe's sole function is the WebAuthn ceremony: no proof delivery, no identity to the RP | §5.1 (no messages, no `H2`, no proof, no identity disclosure; fixed request set) |
| The Authority correlates the assertion with the transaction | §7 (`W` from `cid`/`H1`; `topOrigin == allowed_origin`; mode bound at options) |
| The RP learns claims only at redemption | §5.1 last sentence of the second paragraph; §10 unchanged |

## Findings

### V1: Medium. My F1 text strips person assurance at the first renewal when reuse is off, which is the default (§11)

**Text (P2, mine):** "The RP MUST remove all person assurance … when
`person_expires_in` elapses on its own clock, **or when a renewal grant lacks
person evidence**, whichever comes first."

**Combined with §11 paragraph 2:** "Default person-session behavior requires
fresh step-up when issuing a new person lease. Operators MAY permit silent
renewal using an opaque Authority evidence handle…"

When reuse isn't permitted (the default), every renewal grant lacks person
evidence. So a fresh verification survives only until the next fixed renewal,
about 60 seconds, and `person_max_age=600` routes can never be satisfied for
more than a minute. Stripping at renewal is the *safe* rule: without reuse, the
RP can't learn that the renewal came from the same device or that the credential
is still valid. So the fix is to make the configuration explicit, not to relax
the rule.

**Proposed fix:** append to §11 paragraph 2:

> Session-profile `presence` or `verification` requires reuse permission in the
> RP's registration. Without it, the Authority MUST refuse session creation at
> those levels, and the RP uses the transaction profile for person-gated
> operations. Without reuse, person evidence couldn't outlive the next renewal.

Also reword §11 paragraph 3's "assurance" to "the evidence's original assurance
level". The renewal transaction itself now requests `device`, so "match …
assurance" is ambiguous.

### V2: Medium. Handoff consumption, user activation, and fallback don't fit together (§5.1, §6 step 5)

§6 step 5 has the page exchange the handoff "immediately" on load. §5.1 then
offers popup fallback with "the same handoff … only while still unconsumed".
In iframe mode the handoff is always consumed by the time the user could see a
failure, so that clause never applies.

Separately, §5.1 requires `get()` to be invoked "from that control's
activation". If the page fetches options *after* the click, browsers that
expire or narrowly scope transient activation across an `await fetch` may
reject `get()`. Safari is the documented case.

**Proposed text** for §5.1, replacing the sentence from "The same handoff may be
used only while still unconsumed" through "revival of an expired attempt":

> In iframe mode the page MUST check, before exchanging the handoff, that the
> WebAuthn API is present and (where the browser exposes it) that
> `publickey-credentials-get` is allowed in this frame. If either check fails,
> it MUST NOT exchange the handoff, and it tells the user to use the
> application's popup control, which can then use the same unconsumed handoff.
> After a successful exchange, the page fetches options immediately and calls
> `get()` synchronously from its control's activation handler, with no
> intervening network request. Once the handoff is consumed, any fallback
> requires a new transaction, with no transfer of an assertion or revival of an
> expired attempt.

### V3: Low. The source of the "selected mode" is unspecified (§7)

"The attempt's selected mode is bound at options issuance." The text doesn't
say how the Authority learns the mode.

**Proposed addition:**

> The Authority page reports whether it is top-level or framed in its options
> request, and the Authority records that report.

This is safe even though the page reports it itself:

- both modes require the exact Authority `origin`;
- iframe mode additionally binds `topOrigin`;
- an assertion that disagrees with the recorded mode is refused.

Add to gate 3: browsers that set `crossOrigin: true` without `topOrigin` fail
closed in iframe mode, so popup fallback covers them.

### V4: Low. The static `frame-ancestors` list enumerates every registered RP (§5)

Sending all registered application origins in a header on the step-up page has
two effects:

- any overlay peer that can reach the person listener learns which applications
  use this Authority;
- any registered origin can frame the page. `topOrigin` still refuses the
  wrong one, as §13 notes.

**Optional improvement:**

> The `step_up.url` the Authority issues MAY include a per-RP path segment
> (`/step-up/<rp_id>`), whose response lists only that RP's origin in
> `frame-ancestors`. The client validates the URL prefix against
> `person_origin`.

### V5: Low. Origin canonicalization for `topOrigin` (§7)

The check is `topOrigin` "exactly equals the transaction's stored
`allowed_origin`". Browsers serialize origins without default ports. A
registered origin written as `https://app.example.com:443` would never match,
and the check fails closed. The same latent issue already affects the
`Origin`-header checks.

**Proposed addition** (also applies to §2 / 0.7 registration):

> Registered origins are stored in serialized form (lowercase scheme and host;
> default port omitted). Configuration MUST reject other forms.

### V6: Low. The permission-policy token in the example may be stale (§5.1)

`allow="… local-network-access"` matches Chrome's original LNA guidance. A
secondary source reports that Chrome 145 split the permission into
`local-network` and `loopback-network`. This is **unverified**. Mark the token
as provisional in the example and add it to gate 3.

## Confirmed sound (round 2)

- **Enrollment stays non-frameable.** `frame-ancestors 'none'`, `create()`
  never in a frame.
- **COOP is retained for top-level pages.** The isolation rationale for frames
  is stated.
- **The memory-only bearer attempt token** is scoped to the transaction,
  device, generation, and deadline. It is never exposed to the application,
  never persisted, and never logged. `Origin` and `Host` checks remain
  mandatory alongside it. This correctly handles partitioned or blocked
  third-party cookies.
- **§7 verifier rules supplement, not replace,** the RP-ID, signature,
  challenge, UP/UV, peer, and transaction checks. Wrong combinations burn only
  the expected generation.
- **The §13 threat rows match the handoff.** They correctly say that overlay and
  fake-frame attacks yield no assertion, and they make no informed-intent claim.
- **The §14 tests cover every handoff item,** plus "mode switching", which is a
  good addition.

## Requested action

Codex, as owner: decide V1–V6. V1 is a correction of Claude's own F1 text, and
the user should confirm it, because it makes reuse mandatory for session-level
person assurance. Record the outcome in the ledger with the resulting hash.
