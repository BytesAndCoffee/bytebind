# Claude review: specification 0.8 implementation (`a1e2b2e`)

**Reviewed:** commit `a1e2b2e` against `SPEC.md` (protocol v1, 0.8-draft) and
[the implementation handoff](SPEC-0.8-IMPLEMENTATION-HANDOFF.md).
**Date:** 2026-10-06.
**Method:**

- read `store.py`, `person.py`, `person_http.py`, `authority.py`, `rp.py`,
  `binding.py`, `fastapi.py`, the Flask changes, `discovery.py`, `config.py`,
  `protocol.py`, `limits.py`, `bytebind.js`, `person.js`, the Python clients,
  and the new tests;
- ran the full suite in a fresh virtualenv (224 passed);
- checked `fido2` 2.0.0's verifier source;
- ran one temporary probe test (deleted afterwards).

**Edits:** Claude changed only this file. Codex committed `198cdbd` (demo, plus
the F1 403 mapping) during the review. F1 and F2 reflect it: the context-drop
and test remain open, and `BYTEBIND_AUTHORITY_UID` is still undocumented.

## Verdict

**Sound, with one Medium correctness bug (already being fixed), one Medium
deployment regression, and seven Low items.** I found nothing that breaks
base-first gating, independent person identity, single use, or credential
secrecy.

## Findings

### F1: Medium. A revoked or invalid association returns 503 with no way to recover (`rp.py` `require_person`)

**In `a1e2b2e`:**

1. `require_person` calls `/v1/person-validation`.
2. When the Authority refuses (credential revoked, subject suspended, device
   continuity lost), `AuthorityClient._post` raises `AuthorityError(403)`.
3. Both bindings map `AuthorityError` to **503**, not to the person-step-up
   401.

The browser therefore never gets the step-up sign-in page. Worse, silent
device renewal copies the dead `association` into each new lease context, so
the person route returns 503 for the life of the browser lease. This
contradicts §17.3: once validity is lost, "the next person-gated call needs a
fresh step-up". The existing outage test checks 503 for an Authority
*outage*, which is correct, but nothing covers a *refusal*.

**Status:** fixed in `198cdbd`, which maps 403 to `CeremonyError` and makes the
test shim raise `AuthorityError` like the real client. A
probe confirmed that the revoked case then returns 401 with
`X-ByteBind-Person: 1` and the step-up sign-in HTML, before and after a
silent renewal.

**Still needed:**

- **Drop the person context on refusal.** §17.3 says "an RP that learns of
  invalidation MUST drop the person context at once". On a 403, remove
  `association`, `person_at`, `person_deadline`, `person_assurance`, and
  `person_claims` from the stored lease context, so renewals stop carrying
  them and later calls don't keep hitting the Authority.
- **Add a test:**
  1. a person route returns 200;
  2. revoke the credential;
  3. the route returns 401 with the person header;
  4. after a device renewal, the lease context has no `association`;
  5. the route still returns 401.

  Cover both FastAPI and Flask.

### F2: Medium. Same-host Unix-socket RPs now fail unless an undocumented variable is set (`rp.py`, `binding.py`, `discovery.py`)

`AuthorityClient` now verifies the Authority's socket owner and peer UID
(§3.2), which is correct. But `authority_uid` defaults to **the RP's own
euid**. It can only be changed through `BYTEBIND_AUTHORITY_UID`, and that
variable doesn't appear in the README, the demo README, `PERSON-STEP-UP.md`,
or the systemd example.

The Authority itself requires its socket directory to be owned by the
Authority's account (`check_socket_directory`), and the demo docs describe the
RP and the Authority as separate accounts. So every documented same-host
deployment fails closed after upgrading, with a generic 503.

**Recommendation:**

- Require the Authority UID explicitly for `unix:` endpoints: a constructor
  keyword plus the environment variable, with a startup error naming what's
  missing, instead of defaulting to the RP's own UID.
- Document it next to `BYTEBIND_AUTHORITY` in `README.md` and
  `examples/demo/README.md`, and in the systemd env example.

### F3: Low–Medium. Session creation uses the target route's maximum age, not the largest (`fastapi.py`/`flask.py` challenge, `binding.check_assurance`)

The challenge endpoint takes `person_max_age` from the route matching
`target` (default 300 s when unspecified). §17.3 says "the session-creation
maximum age is the RP's largest route maximum, capped by registration."

With routes at 300 s and 600 s, a lease created through the 300 s route gets a
300 s Authority deadline. The 600 s route then prompts again after 300 s.
That's safe, but it prompts more often than the spec intends, and the result
depends on which route the user hit first.

**Fix:** compute the RP's largest person route maximum when the binding is set
up, send that at creation, and keep the per-route check in `require_person`
as it is. **Test:** a lease created through the shorter route still serves the
longer route up to its maximum.

### F4: Low. Long-poll result loop opens a new SQLite connection every 100 ms (`authority.py` `result_endpoint`)

Each held request calls `store.record()` up to about 100 times in 10 s. Each
call opens a connection and runs `PRAGMA journal_mode=WAL`. This isn't a
correctness issue, and tailscaled isn't involved, which matches §12. It does
add avoidable load under concurrent step-ups.

**Suggestion:** poll every 250–500 ms, reuse one connection for the hold, or
notify waiters from `_commit_assertion`.

### F5: Low. ES256-only registration (`person.py`)

`allowed_algorithms` and the registration check accept only alg −7. Some
platform authenticators (notably some Windows Hello configurations) offer only
RS256 (−257). The spec doesn't restrict algorithms. Either add −257 after the
dependency review, or list "ES256-only excludes RS256 authenticators" under
the ROADMAP browser-acceptance gate.

### F6: Low. Registration requires `credProps.rk === true` (`person.py`)

This is a reasonable way to confirm a discoverable credential. But clients
that don't return the `credProps` extension result can never enroll, even
when the authenticator honored `residentKey: required`. Add it to the
acceptance matrix (gate 2), and record whichever browser/authenticator pairs
fail.

### F7: Low. `fido2==2.0.0` pin (resolved: user pinned 2.2.1)

**Resolution (2026-10-06):** pinned `fido2==2.2.1` in `pyproject.toml` (`person` and
`dev` extras) and `docs/PERSON-STEP-UP.md`. All 230 tests pass on 2.2.1. Its
`authenticate_complete` performs the same type, origin, challenge, RP ID hash,
UP, and UV checks. The original note follows.


Version 2.2.1 is current (PyPI, 2026-10-06). ROADMAP gate 6 asks for a reviewed,
tested version, so record why 2.0.0 was chosen, or move to 2.2.x when the gate
is closed. Note that the installed 2.0.0 reports `fido2.__version__ ==
"1.2.1-dev.0"` (an upstream packaging slip), so code shouldn't rely on that
attribute. I confirmed that 2.0.0's `authenticate_complete` checks type,
challenge, origin (through the exact-match callback), the RP ID hash, UP, and
UV when required.

### F8: Low. Revocation and suspension burn without a generation match (`person.py` `manage`/`suspend`)

Both run `UPDATE … SET status='burned' WHERE credential_id/subject_id=? AND
status IN ('stepup_pending','redeemable')`. §14 says every update matches the
expected state **and** generation. The behavior is safe: it's a deliberate
mass invalidation inside `BEGIN IMMEDIATE`, and redemption rechecks person
status atomically. But it's an undocumented exception. Either add one sentence
to SPEC §14 ("Authority-initiated revocation MAY burn every live transaction
of the revoked credential or subject regardless of generation"), or keep the
code and note the exception in the review notes.

### F9: Low. Two Authority-pinning mechanisms (`discovery.py`)

`DiscoveringAuthorityClient` keeps an in-process `_pins` map (210 s), while
`RelyingParty` stores the creating endpoint in the ceremony context and
redeems through `pinned(endpoint)`. The bindings use only the second. The
first adds an in-memory limit (4,096) and fails across RP worker processes if
anyone calls `.redeem()` directly. Keep the context pin and drop `_pins`, or
document that `.redeem()` on the discovering client is single-process only.

## Verified sound

| Area | Evidence |
|---|---|
| Base-first gating | `attest()` runs checks 1–8 and `mark_attested` before `prepare_handoff`. The person listener refuses handoffs it doesn't know, and re-checks the device (`verify_device`) before issuing options |
| State machine | Six states with a `CHECK` constraint. Every success transition is conditional on (state, generation). Burns use the expected generation, so a loser can't burn a winner (`test_concurrent_assertions_cannot_burn_the_winner`) |
| Delivery and redemption | `reserve_delivery` is a one-use reservation that starts the redemption window. `redeem` requires `delivery_reserved`, then rechecks `R`, person status (atomically), and current device policy (`Control.redeem`) |
| WebAuthn verification | `W = SHA-256(label‖cid‖H1‖w)`. The library checks type, challenge, exact origin, RP ID hash, UP, and UV. `crossOrigin` must be true, and a present `topOrigin` must equal `allowed_origin`. User handle is matched. Counter rule matches §13 (either counter non-zero), with conditional update. BE/BS consistency is checked |
| Framing and listener | `/step-up/<rp_id>` sends `frame-ancestors <that origin>`; others send `'none'`. Exact Host check, plus exact Origin and JSON on every POST, before any state is read. Attempt token in an `X-ByteBind-Attempt` header, never a cookie. The frame posts no messages |
| Client | `bytebind.js` validates the challenge members and `person_origin`, the step-up URL (origin plus `/step-up/<rp_id>`, no query or fragment), and top-level context. It embeds with the delegated permissions, polls about every 2 s, and removes the frame. `person.js` checks the API and permissions policy before the handoff, preloads options, and calls `get()` directly from the click |
| Identity independence | Subjects come only from invites or flagged self-enrollment. Provider owner and tags are never consulted for a subject (`test_enrollment_never_uses_owner_or_device_tag_as_person`). Self-enrolled subjects need RP opt-in |
| Disclosure | Pairwise subject matches §16 (length-prefixed `rp_id` and `subject_id`) and is released only with `identify` plus registration. No credential IDs, keys, or user handles appear in grants. The app-facing lease view strips internal handles (`test_app_facing_lease_contains_no_internal_handles`) |
| Sessions | Device renewal requests `device` and carries the association without refreshing `person_at` or `person_deadline`. Validation runs before the handler, with device continuity checked against the latest device grant. An outage fails closed (503) for person routes only |
| Stored operations | `_replay` now keeps only Host, covered headers, and Content-Length, so proof-request cookies and `Authorization` are excluded (§9.3) |
| Transport | `__Host-` cookies with `Path=/`. RP-side socket owner, directory, and `SO_PEERCRED` checks (see F2 for the default). Closed JSON schemas reject duplicate members and non-finite values. Payload caps are enforced |
| API clients | `StepUpRequired` raised on 202 at attestation or on `X-ByteBind-Person`, carrying no tokens or URL |

## Suggested order

1. Finish F1: commit Codex's 403 mapping, add context dropping, add the
   two-binding test.
2. F2: explicit Authority UID plus docs, before anyone upgrades a same-host
   deployment.
3. F3, then the Low items, or record them as gates.

Real-browser acceptance (ROADMAP gate 2) and independent review remain open.
Nothing here substitutes for them.
