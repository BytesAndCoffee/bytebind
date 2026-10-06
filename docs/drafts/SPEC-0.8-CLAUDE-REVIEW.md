# Claude cross-verification of SPEC-0.8.md

**Verdict: reconciled with issues.**

The merge follows the [cross-verification guide](SPEC-0.8-CROSS-VERIFY.md),
and I agree with all ten of its C-1…C-10 resolutions. Two of the Codex
corrections to my draft are improvements I accept without reservation:

- bounding the collection window by the overall 120 s limit;
- not letting an invite replace existing-credential verification.

I found:

- **three Medium issues**, in the session and polling semantics. These are
  real gaps or contradictions in the text, not just release gates;
- **one Low-Medium issue**: a standards mismatch in the counter rule. It came
  from my own draft;
- **eight Low items**.

No finding touches the invariants named in §15: independent person identity,
base-first gating, Authority ownership, v2 separation, and atomic single use.

Per the guide, this file is the only one I changed. `SPEC-0.8.md`, both source
drafts, `SPEC.md`, code, tests, and shared docs are untouched. Nothing is
committed.

## User decisions (2026-10-06)

The user **accepted F1, F2, and F3**. F4–F12 await decision. The patch below
applies the accepted findings to `SPEC-0.8.md` at hash `5ef4019f…`. Whoever owns
the canonical file applies it; it's written as exact old → new pairs so it can be
applied mechanically and checked. It has not been applied.

| # | Section | Replace (exact text at the reviewed hash) | With |
|---|---|---|---|
| P1 (F1) | §8 table, L372 | `` \| `base_attested` \| `redeemable` \| Device-only requirement, or authorized session evidence reuse \| `` | `` \| `base_attested` \| `redeemable` \| Device-only requirement (person evidence MAY be attached by accepted reuse, §11) \| `` |
| P2 (F1) | §11, L580–596 (from "The operator configures a finite maximum person-authentication age;" through "No handler sees stale person identity after expiry.") | — | The F1 replacement paragraph in this review, verbatim |
| P3 (F1) | §2, L74–75: "Person session creation also carries a finite accepted maximum age;" | — | "Person session creation also carries a finite accepted maximum age; a person-lease renewal is requested with `assurance: device` plus a reuse handle (§11);" |
| P4 (F2) | §10, after L557 ("…not an age.") | — | "Session grants issued from a fresh assertion carry `assurance.person_fresh: true`; reuse grants never do. RPs enforce per-route `person_max_age` from their own receipt time of the fresh grant, which reuse never updates, in addition to `assurance.person_expires_in`. The session-creation maximum sent at creation is the RP's largest configured route maximum, capped by registration." |
| P5 (F3) | §5, after L194 ("…server deadlines remain authoritative.") | — | The F3 replacement paragraph in this review, verbatim |
| P6 (F3) | §8, L400–402: "Before issuing options, accepting an assertion, and delivering a result, Authority MUST confirm current private device identity and applicable provider policy." | — | "Before issuing options, accepting an assertion, and delivering a result, Authority MUST confirm current private device identity and applicable provider policy. A pending result response requires only that the socket peer address equal the stored attested address (§5)." |
| P7 (F1, F2) | §10 grant example, L515–520 | — | Add the members `"person_fresh": true` and `"person_expires_in": 600` to the illustrative `assurance` object in a session example, kept separate from the existing transaction example |

Consequential gate edits: gate 6 ("Evidence reuse") gains "dual device/person
lifetimes and `person_fresh` recording". Gate 5 gains "long-poll hold time and
per-(peer, cid) result budget".

### Second round (2026-10-06)

The user **accepted F4, F5, F6, F7, F8, F10, and F11**, chose **F9's simpler
option** (keep `W`, drop the audit claim), and **rejected F12**.

F12 rationale, per the user: whoever controls the Authority tag or capability
is an approved operator. Trusting them is an accepted trust boundary and out of
scope, so §16.1's SHOULD stays as written. Record this in the cross-verify
ledger. THREAT-MODEL T-D1 should be reclassified from "High (deployment),
Partial" to Accepted (operator trust) when that document is updated.

Patch pairs against the same hash (`5ef4019f…`):

| # | Finding | Location | Replace | With |
|---|---|---|---|---|
| P8 | F4 | §7, L321–322 | "Apply the standard's signature-counter and backup-state handling rather than assuming every counter must increase." | "Signature counters follow the profile policy below; backup-state flags follow the standard's handling." |
| P9 | F4 | §7, L356–358 | "For this profile, a nonzero received signature counter that fails to exceed a nonzero stored counter MUST cause refusal, expected-generation burn, and an operator-review event. A zero counter is not sufficient evidence of cloning." | "For this profile, if either the stored or the received signature counter is non-zero and the received value is less than or equal to the stored value, the Authority MUST refuse the assertion, burn the expected generation, and raise an operator-review event. A counter that stays zero is not evidence of cloning." |
| P10 | F5 | §2, L46–47 | "Discovery selects and pins an Authority for a transaction." | "Discovery currently resolves an Authority on each control call; §16.1 requires per-transaction pinning." |
| P11 | F6 | §2, insert after L78 ("No mixed-version proof is accepted.") | — | "The v1 `/attestation` endpoint MUST refuse any `cid` created with protocol 2, and the v2 endpoints MUST refuse any v1 `cid`; each refusal burns only the expected `pending` generation. Version is taken from stored transaction state, never from the request." |
| P12 | F7 | §9, L488, sentence beginning "Registration MUST require discoverable credentials and UV," | insert before that sentence | "Registration MUST NOT use conditional mediation, and the Authority MUST verify that the UP bit is set." |
| P13 | F8 | §10, L548 | "Both IDs use UTF-8; each length is an unsigned 64-bit big-endian byte length." | "`rp_id` is UTF-8; `subject_id` is its stored opaque byte string; each is preceded by its unsigned 64-bit big-endian byte length." |
| P14 | F9 | §7, L351–354 | "An archived assertion may support transcript reconstruction only with all necessary inputs, including `C` and the exact request to reproduce `H1`/`Q`. It does not prove that the person read or approved the application operation. Routine logging MUST NOT retain ceremony secrets to obtain this audit property." | "This derivation is a transcript commitment only. This profile defines no audit record of its inputs, and an assertion never proves that the person read or approved the application operation." |
| P15 | F10 | §5, insert after L198 ("…unspecified navigation fallback.") | — | "The application opens the step-up page without `noopener` and treats only a `null` return as `popup_blocked`. It MUST NOT infer cancellation or success from the window handle." |
| P16 | F11 | §5, insert after L188 ("…distinct from the base Authority URL.") | — | "The person listener MUST refuse requests whose `Host` isn't its exact configured authority, before reading any state." |

Still undecided (non-blocking notes): Mermaid fix at wire freeze; reissuing a
challenge after a mis-tapped cancel (Claude suggests ≤3 sequential reissues
with atomic invalidation, inside 120 s, under gate 5); threat-model mapping when
THREAT-MODEL.md is updated.

## Snapshot verification

| File | SHA-256 at review | Matches guide |
|---|---|---|
| `SPEC-0.8.md` | `5ef4019f0fc6f2e39f55d4752cd80f67d6dd027f70a82c5c1b7ce42b6fa5fbec` | Yes |
| `docs/drafts/SPEC-0.8-CODEX.md` | `95f17f9440e74829c296d87d0ffc84bfbf9859d066700314daf9f03b31df0be3` | Yes |
| `docs/drafts/SPEC-0.8-CLAUDE.md` | `7c62566b3705229badf8adf084fdd79be09d518e4209b2b4a8dc1afb74e1b723` | Yes |

## Findings

Line numbers refer to `SPEC-0.8.md` at the hash above.

### F1 — Medium: person expiry contradicts ambient device access, and the renewal flow is undefined (§11, §10)

**Source:** CODEX §11, Claude §11 (C-6). **Invariant:** ordinary routes keep
ambient behavior. 0.7 §15.1 says one failed renewal must not end a lease.

Two sentences conflict:

- L581–583: "Authority bounds the renewed grant by BOTH the device lease lifetime
  and remaining permitted person age. Near that deadline a grant MAY be shorter
  than v1's 90-second session minimum."
- L588–589: "Device-only routes MAY remain available through a separately
  created device-only transaction and independently checked device grant."

Read together, the *whole* lease ends when person age runs out. Device-only
routes then survive only if some party runs a second, device-only ceremony
before that happens. Nothing specifies who:

- the RP never sees the attestation response, so it can't tell that reuse was
  refused;
- the renewal script runs on a fixed 60 s cadence, so a grant shorter than 90 s
  can lapse before the next renewal. That is exactly the failure the 0.7
  minimum prevents.

The text also doesn't say what a background renewal receives when reuse is
refused (a `202 step_up` with live tokens, or a terminal refusal).

**Proposed fix:** separate the two lifetimes inside one grant, and make a
renewal *request* device assurance, with continued person evidence as an
optional add-on. Nothing is downgraded, because the renewal transaction never
asked for person assurance as a requirement.

Replace L580–596 with:

> The operator configures a finite maximum person-authentication age; the RP MAY
> request a stricter limit. A person-lease renewal is a v2 transaction with
> `assurance: device` and the lease's reuse handle. If the Authority accepts the
> reuse, the grant carries device `expires_in` (subject to 0.7 §15.1's minimum)
> and `assurance.person_expires_in`, the remaining person validity. If it
> refuses the reuse (age, revocation, changed device, subject switch), the grant
> carries device assurance only. The RP MUST remove all person assurance,
> identity claims, and reuse handles from the lease when
> `person_expires_in` elapses on its own clock, or when a renewal grant lacks
> person evidence, whichever comes first. The device part of the lease continues
> under its own deadline. A transaction that *required* person assurance never
> completes as device-only: it fails. Background renewal never receives a
> step-up variant. Routes requiring a person return an explicit
> step-up-required failure and offer a button. No handler sees stale person
> identity after expiry.

Matching §8 change: delete "or authorized session evidence reuse" from the
`base_attested → redeemable` row's condition. Reuse is an add-on to a
device-assurance transaction, not a path through a person-assurance one.

### F2 — Medium: per-route `person_max_age` has no protocol support (§2, §10, §12)

**Source:** CODEX §11–12, Claude §12. **Invariant:** route-level freshness is
enforceable and age is never reset.

The binding example (L616) puts `person_max_age=300` on a route. But §2
(L74–75) sends one "finite accepted maximum age" when the *session* is created,
and §10 defers any age claim (L554–557). A lease created through a route with a
3600 s maximum, then used on a route with a 300 s maximum, can't be checked:
the RP has no person-authentication time, and the grant example has only
`fresh_for_transaction`, which is meaningless for sessions.

**Proposed fix** (no age disclosure needed): add
`assurance.person_fresh: true` to session grants issued from a fresh
assertion, never from reuse. The RP records its own receipt time of that grant
as `person_authenticated_at` and keeps it unchanged across reuse renewals. A
route with `person_max_age` checks
`now − person_authenticated_at ≤ person_max_age` on the RP's clock, as well as
the Authority's `person_expires_in` (F1). The session-creation maximum sent at
`begin` is the RP's largest configured route maximum, capped by registration.
Add this to §10 after L557:

> Session grants issued from a fresh assertion carry `assurance.person_fresh:
> true`; reuse grants never do. RPs enforce per-route `person_max_age` from
> their own receipt time of the fresh grant, which reuse never updates.

### F3 — Medium: result polling against the Authority's rate limit and provider checks (§5, §6 step 7, §8)

**Source:** CODEX §6, Claude §5.2 (C-5 resolution). **Invariant:** step-up must
not lock the device out, and polling must not amplify provider load
(THREAT-MODEL T-AV2, T-AV3).

The baseline has the application page poll `/v2/attestation/result`
(L191–194), and each request "checks … current private peer identity" (L238).
§8 also requires confirming "current private device identity and applicable
provider policy" before delivery (L400–402). On the reference Authority, the
attestation listener's `PeerLimiter` allows 30 requests per minute per device,
**shared across all RPs**. Each identity check calls LocalAPI `status` (up to
4 MiB) and `whois`.

Polling at any responsive cadence across a 120 s window would either:

- exceed the shared limit, blocking that device's attestation for every RP; or
- multiply tailscaled calls.

The text sets no cadence and no separate budget.

**Proposed fix:** add after L194:

> The result endpoint SHOULD hold a pending request open for up to 10 seconds
> and answer as soon as the attempt becomes terminal or deliverable (long
> poll). Clients MUST NOT issue more than one outstanding result request per
> attempt, or more than one per 2 seconds. Result requests are rate-limited per
> (peer, `cid`), not against the device's attestation budget. A pending
> response requires only a match between the socket peer address and the
> stored attested address. The full provider identity and policy check in §8
> runs once, at delivery.

### F4 — Low-Medium: the counter rule is narrower than WebAuthn (§7)

**Source:** Claude §7. The error is mine. **Invariant:** standards-conformant
verification.

L356–357: "a nonzero received signature counter that fails to exceed a nonzero
stored counter MUST cause refusal". WebAuthn L3 §7.2 (editor's draft,
retrieved 2026-10-06) treats it as a possible clone signal if *either* value is
non-zero and the new value is ≤ the stored value. That includes a stored count
of 5 followed by a received 0, which the merged rule accepts. L321–322 ("rather
than assuming every counter must increase") is now ambiguous next to the
refusal rule.

**Replacement for L321–322:** "Signature counters are processed under the
profile policy below; when both counters are zero, no counter check applies."

**Replacement for L356–358:**

> For this profile, if either the stored or the received signature counter is
> non-zero and the received value is less than or equal to the stored value,
> the Authority MUST refuse the assertion, burn the expected generation, and
> raise an operator-review event. A counter that stays zero is not evidence of
> cloning.

The rest of the paragraph (out-of-order races, not proof of cloning, atomic
update) stands.

### F5 — Low: inaccurate statement about current discovery (§2)

**Source:** CODEX §2, inherited. L46–47: "Discovery selects and pins an
Authority for a transaction." The reference implementation doesn't do this.
`DiscoveringAuthorityClient` re-resolves on every `begin` and `redeem`
(`discovery.py`; THREAT-MODEL T-D3). Pinning is what §16.1 *adds*.

**Replace with:** "Discovery currently resolves an Authority on each control
call; §16.1 requires per-transaction pinning."

### F6 — Low: what a v1 endpoint does with a v2 `cid` is unstated (§2)

**Source:** Claude §2 change 2, which was weakened to L71 ("Legacy clients are
not promised to understand the new challenge shape."). The reference clients
reject the four-member challenge. A third-party 0.7 client that ignores unknown
members, however, would send v1 `H1` to `/attestation`. "No mixed-version proof
is accepted" covers the outcome but doesn't say which endpoint enforces it, or
whether that path burns.

**Add after L78:**

> The v1 `/attestation` endpoint MUST refuse any `cid` created with protocol 2,
> and the v2 endpoints MUST refuse any v1 `cid`. Each refusal burns only the
> expected `pending` generation. Version is taken from stored transaction
> state, never from the request.

### F7 — Low: registration doesn't exclude conditional mediation or require UP (§9)

**Standards source:** WebAuthn L3 §7.1: "If `options.mediation` is not set to
`conditional`, verify that the UP bit … is set." Conditional create (passkey
upgrade) can register a credential with UP clear. The combined §9 (L488) requires
discoverable credentials and UV, but doesn't rule this out.

**Add to L488:**

> Registration MUST NOT use conditional mediation, and the Authority MUST verify
> that the UP bit is set.

### F8 — Low: the pairwise encoding calls an opaque ID UTF-8 (§10)

L548: "Both IDs use UTF-8". §9 (L431) defines the subject ID as opaque.
Proposal 4.4 makes it 16 random bytes.

**Replace with:**

> `rp_id` is UTF-8; `subject_id` is its stored opaque byte string; each is
> preceded by its unsigned 64-bit big-endian byte length.

### F9 — Low: the audit rationale for `W` is weaker than my draft claimed (§7)

**Source:** Claude §7 (C-3). The merge correctly notes (L351–354) that
reconstructing the commitment needs `C` and the request, and forbids routine
logging of ceremony secrets. Unless the spec defines where those inputs are
kept, then, `W` delivers no audit property in practice. I overstated this in my
draft.

**Either** keep `W` as a transcript commitment only, and drop the audit
sentences, **or** add:

> An Authority MAY write, after a transaction reaches a terminal state, an
> access-controlled audit record containing `cid`, `N`, `Q`, `w`, `C`, and the
> assertion. `C` grants nothing once the transaction is terminal. This record is
> not routine logging and is subject to the operator's retention policy.

I lean toward the first option for 0.8 (C-3 stays adopted either way).

### F10 — Low: popup handle semantics under COOP (§5)

L190–196 picks `COOP: same-origin` and "no dependence on popup-closed
detection", which is correct. Two details are missing:

1. An opener-side handle to a COOP-isolated cross-origin popup reports
   `closed`, so pages must not read it as cancellation.
2. Opening with `noopener` makes `window.open` return `null` even on success,
   which looks the same as a blocked popup.

**Add:**

> The application opens the step-up page without `noopener` and treats only a
> `null` return as `popup_blocked`. It MUST NOT infer cancellation or success
> from the window handle.

### F11 — Low: the person listener's `Host` check is implicit (§5)

L185–188 requires TLS and socket-peer checks on both listeners. The exact `Host`
validation that 0.7 check 1 applies to attestation (a DNS-rebinding defense) is
not stated for the person listener.

**Add:** "The person listener MUST refuse requests whose `Host` isn't its exact
configured authority, before reading any state."

### F12 — Low: discovery-only trust was weakened without a ledger entry (§16.1)

**Source:** Claude §16.1: "Discovery MUST NOT be the only source of trust in
production." The combined L781 keeps only "Production RPs SHOULD additionally
pin…". That trades a MUST NOT for a SHOULD, and the guide doesn't record the
change. If it was intentional, record it in the ledger. Otherwise restore:

> Discovery MUST NOT be the only source of Authority trust for a production RP.

### Non-blocking notes (no contradiction)

- **Mermaid (L279):** "RP-->>B: cid, C, Authority, protocol" omits
  `person_origin`, and the alt block doesn't show the 202 and polling loop. It's
  illustrative, but worth fixing at wire freeze.
- **One challenge per `cid` (L383–384):** a mis-tap cancellation forces a new
  transaction, a click, and a popup. Sequentially reissuing options within the
  same handoff session, with the previous challenge invalidated atomically,
  would keep single use. That's a UX question for gate 5, not a defect.
- **THREAT-MODEL integration:** §13 should state the effect on existing IDs when
  THREAT-MODEL.md is updated:
  - T-B1 is reduced for person-gated routes only;
  - T-B2 is bounded by person age;
  - T-TS2 gains an independent person identity;
  - T-PR1 is unchanged (§16.4).

## Traceability

### Claude draft → combined

| Claude item | Combined | Status |
|---|---|---|
| §1 | §1 | Faithful |
| §2 changes 1 (v2 for every v2 tx) and 3 (discovery protocols) | §2 L66–71, §16.1 | Faithful. Discovery advertisement made optional with control-channel negotiation, which I accept |
| §2 change 2 (legacy clients fail closed) | §2 L71 | Weakened; see F6 |
| §3 unconfigurable prohibition | §3 L111–114 | Faithful |
| §4 UP / `discouraged` | §4 L143–147 | Improved (incidental UV) |
| §5.1 exact-host RP ID | §5 L183–184 | Faithful (PSL rationale dropped; acceptable) |
| §5.2 separate listener, no CORS, framing, COOP | §5 L177–196 | Faithful; COOP choice made; `Host` check gap F11 |
| §5.3 browser facts | §5 L200–204 | Deliberately excluded as non-conformance facts; acceptable |
| §5.4 no navigation fallback | §5 L164, L197–198 | Faithful |
| §6 completion transcript, 202 shape, origin from challenge, abort | §6 L236–263 | Faithful |
| §7 `W` | §7 L301–313, L348–354 | Faithful and qualified; F9 |
| §7 counter rule | §7 L356–364 | Carried my standards error; F4 |
| §8 delivery-start deadline | §8 L386–398 | Improved |
| §9 invites, audit context, self-enrolled, registration parameters | §9 L473–500 | Faithful or stricter. Direct attestation and non-synced policy deferred, which I accept. F7 added |
| §10 marker, pairwise, `person_origin` | §2, §6, §10 | Faithful; F8. Age deferred (affects F2) |
| §11 step-down | §11 L587–596 | Adopted through a separate transaction; F1 |
| §12 API and decoration errors | §12 L643–652 | Faithful; transaction syntax fixed |
| §13 rows | §13 L682–687 | Faithful (consolidated) |
| §14 library and fixtures | §14 L694–699, L730–735 | Faithful (version claims correctly downgraded) |
| §15 C-1…C-10 | Guide ledger | Faithful |
| §16.1 | §16.1 | Faithful except F12 |
| §16.2 | §16.2 | Strengthened (mutual) |
| §16.3 | §16.3 | Faithful |
| §16.4 | §16.4 | Deferred (`IP` remains visible to RP-origin code); I accept |
| §16.5 | §16.5 | Faithful; path caveat added |

### Codex draft → combined

All 61 normative sentences in CODEX §§1–15 appear verbatim in the combined text,
except six:

| Sentence not reproduced verbatim | How the combined text handles it |
|---|---|
| Reconciliation SHOULD compare by section number | Editorial; superseded by the merge |
| The MUST/SHOULD/MAY conformance sentence | Reworded in §1 |
| Authority page MUST NOT pass credential IDs, assertions, or `H2` through `postMessage` | Replaced by the broader L260 |
| Completion-notification MUST | Removed with hints (C-5) |
| Navigation-fallback MUST | Removed with the fallback (C-2) |
| Registration SHOULD require UV and discoverable credentials | Upgraded to MUST |

All six are accounted for in the guide. No inherited 0.7 rule contradicts a
stated v2 override, apart from the 90-second minimum in F1, which §11
overrides explicitly but avoidably.

## Flow walk-throughs (checklist item 3)

| Flow | Can options, a prompt, `S`, or `H2` escape before its gate? | Notes |
|---|---|---|
| v2 device-only | No. `H2` only after checks 1–8 and the atomic `base_attested → redeemable` with delivery | Redemption starts at delivery |
| Fresh person (session or tx) | No. Handoff only after base acceptance. Options only after handoff exchange plus peer recheck. `H2` only from `redeemable` via completion `{cid, completion, N, H1}` | F3 for polling cost |
| Reused session | Text routes it through `base_attested → redeemable` on a person-assurance tx | Gate holds, but semantics are unclear; F1 restructures it |
| Failed or expired | Burns from the expected generation. A lost first delivery consumes the result (L392–394, L415) and allows no second release | Holds |

**Races (item 5):** these all reduce to conditional single-row updates on
(state, generation), with burns from the expected state only:

- handoff and handoff;
- assertion and assertion;
- assertion and abort;
- assertion and revocation;
- collection and collection;
- collection and redemption (redemption before delivery fails, L392);
- redemption and redemption;
- cleanup and any of the above.

Winners survive. Revocation is atomic with the transition to `redeemable`
(L327–328). I found no lost-update path in the text.

## Facts still unverified (item 11)

| Claim | Status |
|---|---|
| WebAuthn L3 §7.1 UP-at-registration rule; §7.2 counter rule; §16 test vectors | **Verified** against the editor's draft, 2026-10-06 (F4, F7) |
| `ts.net` on the Public Suffix List | Verified 2026-10-06 (proposal); not relied on normatively |
| Popup and Chrome Local Network Access interaction; Firefox Related Origin Requests; Safari iframe `get()` delegation | **Unverified.** Correctly left to gate 3 / excluded |
| `fido2` 2.2.1 dependencies, UV enforcement, no counter check | Checked 2026-10-06; combined text correctly treats it as an evaluation candidate only |

## Reviewed

§§1–16 of `SPEC-0.8.md`; both source drafts in full; the guide; the current
`discovery.py`, `authority.py` (limiter, identity checks), and `rp.py` for the
F3 and F5 claims.

No implementation support, release readiness, or mutual approval is implied.
