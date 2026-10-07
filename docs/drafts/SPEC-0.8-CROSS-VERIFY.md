# Claude: cross-verify the combined ByteBind 0.8 draft

## Review task and editing boundary

The user asked Codex to combine the completed parallel drafts into
[`SPEC-0.8.md`](../../SPEC-0.8.md) and leave instructions for your independent
cross-verification. This guide records how the merge was made. It does not claim
you have approved it. The source drafts were unchanged throughout synthesis.

Please read the full combined draft and both sources, not just this decision
ledger. Check requirements, exceptions, formulas, states, failure behavior,
privacy, and implementation gates. Use the preserved draft as the review basis;
the older Phase 1 proposal is context, not the authoritative latest Claude input.

Write your findings to a **new** `docs/drafts/SPEC-0.8-CLAUDE-REVIEW.md`. Keep
`SPEC-0.8.md`, both source drafts, SPEC.md, implementation, tests, and shared docs
unchanged during that review. Identify corrections by combined section and
exact quoted sentence or line. Supply proposed replacement text where useful.
Do not implement or commit changes merely because this review guide exists.
If the user authorizes revisions afterward, agree canonical file ownership first.

## Source snapshots

Sources are the Codex draft's 15 sections and the Claude draft's 16 sections.
Their status remains working draft. The combined text incorporates the baseline
0.7 rules by reference and states its overrides; it does not copy all of 0.7.

docs/drafts/SPEC-0.8-CODEX.md: 95f17f9440e74829c296d87d0ffc84bfbf9859d066700314daf9f03b31df0be3
docs/drafts/SPEC-0.8-CLAUDE.md: 7c62566b3705229badf8adf084fdd79be09d518e4209b2b4a8dc1afb74e1b723
SPEC-0.8.md: 5ef4019f0fc6f2e39f55d4752cd80f67d6dd027f70a82c5c1b7ce42b6fa5fbec

These SHA-256 values identify the bytes read and produced at synthesis. Verify
before review; if anything changed, report the new hash and review the delta.
The combined hash is a snapshot, not an instruction to reject subsequent
human-authorized corrections.

## Section traceability

| Combined section | Inputs | Disposition |
|---|---|---|
| 1 Scope/conformance | Codex 1; Claude 1 | Rewritten for canonical combined status; baseline inheritance and v2 overrides explicit |
| 2 Compatibility | Codex 2; Claude 2 | Adopt v2 for every explicitly selected v2 transaction; keep v1 device-only path; strict protocol marker |
| 3 Identity | Codex 3; Claude 3 | Preserve user's exact invariant; adopt unconfigurable prohibition on provider-to-person derivation |
| 4 Assurance | Codex 4; Claude 4 | Preserve structured policy; adopt discouraged UV for presence and required UV for verification; check actual flags |
| 5 Browser context | Codex 5; Claude 5 | Adopt exact host and separate private person listener; choose COOP isolation plus bounded polling; defer full-page fallback |
| 6 Exchanges | Codex 6; Claude 6 | Retain separate tokens; adopt transcript fields on completion and configured person-origin URL checking; no hints |
| 7 Binding | Codex 7; Claude 7 | Adopt W derivation; qualify audit/intent claim; add explicitly conservative counter policy and atomic updates |
| 8 States/deadlines | Codex 8; Claude 8 | Adopt first-delivery redemption start, bounded collection, expected generations; prohibit pre-delivery redemption |
| 9 Enrollment | Codex 9; Claude 9 | Adopt invites, provenance, required discoverability/UV; constrain existing-subject invites to credential auth or approved recovery |
| 10 Disclosure | Codex 10; Claude 10 | Adopt protocol marker and pairwise derivation with both IDs length-prefixed; defer age display |
| 11 Sessions | Codex 11; Claude 11 | Preserve bounded reuse; person expiry removes person state; separate base transaction can preserve device-only access |
| 12 DX/API | Codex 12; Claude 12 | Adopt assurance keyword and typed error; correct transaction syntax to grant=bind.TRANSACTION |
| 13 Threat delta | Codex 13; Claude 13 | Preserve both sets of boundaries; qualify clone/XSS claims and disclose overlay-IP exposure |
| 14 Verification | Codex 14; Claude 14 | Preserve test/demo plan; fido2 preferred candidate only; no stale version/dependency claims accepted as release facts |
| 15 Gates | Codex 15; Claude 15 | Replace stale disagreement list with remaining release gates and this independent review |
| 16 Hardening | Claude 16 | Adopt pinning, mutual Unix-peer verification, stored replay state, cookie recommendation; defer IPB crypto change |

## Reconciliation decisions requiring particular scrutiny

| Claude decision | Combined resolution | Reason / required cross-check |
|---|---|---|
| C-1 Browser UX | Authority popup with explicit action; no ROR | Keeps credential handling at Authority and base-before-options; no untested browser compatibility claims |
| C-2 Navigation fallback | Deferred; blocked-popup retry only | Avoids defining incomplete secret persistence/resume rules; verify handoff expiry and retry are coherent |
| C-3 WebAuthn W | Adopt SHA-256(label || cid || H1 || w) | Standard challenge input with fixed-length commitment; archived assertion alone does not prove exact request or informed approval |
| C-4 Deadline start | Adopt delivery start and 30 s collection; collection also bounded by overall 120 s limit | Removes extra-round-trip pressure without unbounded extension; commit before response, lost delivery consumes result |
| C-5 COOP/hints | Choose same-origin COOP and bounded polling | Drops postMessage and popup-close dependence; verify cross-origin polling needs only existing configured CORS |
| C-6 Session step-down | Adopt device-only availability through a separate device grant | A person-requested transaction still fails rather than silently downgrades; stale subject/evidence must be removed |
| C-7 V2 scope | Adopt v2 for all protocol:2 transactions | Claude withdrew v1 person-flow proposal; v1 remains separate device-only mode |
| C-8 Self-enrollment | Adopt provenance flag and explicit RP acceptance | Prevents self-asserted subject from appearing vetted |
| C-9 Library | fido2 preferred evaluation candidate, not final dependency | Library review and tested version remain release gates |
| C-10 Extra scope | Adopt 16.1–16.3 and 16.5; defer 16.4 IPB | Transport/replay protections are compatible; address replacement needs separate transcript/privacy review |

Additional changes to Claude's proposed text:

- **Protocol marker:** a missing marker is refused when v2 was requested. It is
  interpreted as legacy only on a separate v1 attempt; never as automatic fallback.
- **Presence:** discouraged UV does not prohibit an authenticator supplying UV.
  Report actual verified flags under disclosure policy, not an assumed universal
  browser behavior or an unrequested assurance upgrade.
- **Counter regression:** fail closed as a chosen profile policy, not a WebAuthn
  requirement or proof of cloning. Include legitimate out-of-order races.
- **Invites:** a bare invite for an existing subject cannot bypass fresh subject
  verification unless issued as explicitly authenticated, audited recovery.
- **Registration:** UV and discoverability become MUST. Direct attestation/AAGUID
  allowlists and non-synced policy are deferred, because provenance trust and
  metadata verification need more design.
- **Pairwise encoding:** both rp_id and subject_id are UTF-8 and explicitly
  length-prefixed with unsigned 64-bit big-endian lengths. The source formula's
  unqualified concatenation and prose only naming rp_id were made unambiguous.
- **Age:** defer display age; use exact server validity for enforcement. Rounded
  ages cannot enforce maximum authentication age or become fresh-tx evidence.
- **Discovery:** capability protocol advertisement is optional; configured RPs
  can negotiate authenticated support. Define schema evolution before release.
  Never retroactively add a closed-schema member and assume old clients accept it.
- **Provider audit metadata:** may be retained separately, minimized, and never
  used to establish person identity or authorize attachment. An independent
  device-policy evaluation remains permitted.
- **Address privacy:** unchanged IP || S reveals the address to RP-origin script.
  The combined spec states that limitation; it does not overclaim selective privacy.
- **Cookie prefix:** Path=/ and no Domain are required for host-prefixed cookies;
  migrating the old narrow state-cookie path requires review.

## Independent review checklist

1. Trace **every** Claude Agree/Adopt/Differs item to the combined section.
   Report unlisted omissions, especially security requirements hidden in examples.
2. Trace every Codex MUST/MUST NOT. Confirm the ledger accounts for removals or
   changes and that no inherited 0.7 rule contradicts a stated v2 override.
3. Draw successful device, fresh person, reused session, and failed/expired flows
   from the actual text. Verify no options/prompt or S/H2 escapes before its gate.
4. Check all response variants and markers, peer/Origin distinctions across
   listeners, completion {cid, completion, N, H1}, URL validation, and token scope.
5. Enumerate races among handoff, assertion, collection, redemption, cancellation,
   revocation, and cleanup. Check winner survival and durable failure commits.
6. Check when each deadline starts, which deadlines bound collection, and whether
   a lost first-delivery response can accidentally permit retry or second use.
7. Verify W, Q, H1, H2, R, and pairwise encodings; no mixed labels or ambiguous
   variable concatenation. Audit claims must not equate assertion with human intent.
8. Verify shared-device subject separation, invitations/recovery, self-enrollment
   provenance, session reuse association, and complete clearing of person state.
9. Verify person step-down cannot authorize a person route, reuse a tx assertion,
   or carry an old subject into a new device-only handler. Failure is not downgrade.
10. Check selective disclosure, credential secrecy, address leakage, identity
    pseudonym rotation, and exact enforcement independent of rounded display age.
11. Validate WebAuthn claims against primary standards. Recheck browser/library
    facts independently; inherited proposal assertions are not proof of support.
12. Check 16.x additions against current threat model and code. Confirm no
    implementation support, release readiness, or mutual approval is implied.

## Review output

Start with one of: **merge faithfully reconciled**, **reconciled with issues**,
or **not reconciled**. List each finding with severity, combined section/line,
source section, violated invariant, and exact proposed correction. Separate
implementation gates from actual contradictions in this draft.

Include a checklist of reviewed sections, verified snapshot hashes, omitted
source requirements, and unverified browser/library facts. An empty finding list
is acceptable only after tracing both complete drafts. Stop after review and
report the review file to the user; do not silently edit the canonical draft.


## Accepted review applied (2026-10-06)

Claude completed the [cross-verification](SPEC-0.8-CLAUDE-REVIEW.md) and supplied
the [handoff](HANDOFF.md). The user authorized applying it in this chat.

- Reviewed spec SHA-256: `5ef4019f0fc6f2e39f55d4752cd80f67d6dd027f70a82c5c1b7ce42b6fa5fbec`.
- Resulting spec SHA-256: `29b13a6a913d4e01a5dfaa53e825a35ddc579727f214b670cf00a44913324acc`.
- P1–P16 applied, plus the gate 5 and gate 6 edits.
- Gate 1 is closed conditional on preserving the accepted patch text.
- The spec introduction records the completed review and applied corrections.
- Source drafts, review, handoff, baseline SPEC.md, code, and tests are unchanged.

This entry supersedes conflicting initial synthesis decisions above. The earlier
hash and ledger remain historical provenance, not the current snapshot.

| Patches | Applied reconciliation |
|---|---|
| P1–P3, P7 | Renewal requests device assurance plus optional reuse; separate device/person lifetimes; fresh-session grant example |
| P4 | `person_fresh` establishes RP receipt time for per-route freshness; reuse never resets it |
| P5–P6 | Bounded long polling and separate per-(peer, cid) budget; cheap pending address check, full provider check at delivery |
| P8–P9 | Either nonzero counter triggers the accepted regression policy |
| P10–P11 | Correct current discovery description; explicit v1/v2 endpoint refusal from stored version |
| P12–P13 | No conditional registration mediation; UP verification; opaque subject bytes in pairwise encoding |
| P14 | W retained as transcript commitment only; audit-reconstruction claim removed |
| P15–P16 | Defined popup return handling without noopener; explicit person-listener Host validation |

**F12 rejected by the user:** whoever controls the Authority tag or capability
is an approved operator. This is an accepted operator trust boundary and outside
scope; section 16.1's SHOULD remains unchanged. When THREAT-MODEL.md is next
updated, reclassify T-D1 as Accepted (operator trust). That shared document has
not been edited in this pass.

Still deferred: the Mermaid wire details (person_origin and 202/poll loop),
sequential challenge reissue after a mis-tapped cancellation, and the shared
threat-model mappings recorded in the handoff. Sequential reissue is explicitly
tracked under gate 5, with no assumed user decision.


## Round 2: optional Authority-origin iframe (2026-10-06)

The user authorized applying the updated [handoff](HANDOFF.md) in this chat.
The requirement recorded there is preserved verbatim:

> WebAuthn person attestation is an OPTIONAL STEP-UP phase.
>
> The existing ByteBind private-path/device attestation remains the core protocol
> and MUST complete through the existing browser/RP/Authority flow.
>
> The WebAuthn iframe MUST NOT replace, proxy, or perform the base ByteBind
> attestation.
>
> After base attestation succeeds, the Authority MAY require an additional person
> identity attestation. For browser clients, that step-up MAY be performed in an
> Authority-origin iframe reachable over the private overlay.
>
> The iframe's sole security function is to complete the WebAuthn ceremony with the
> Authority. It does not deliver the base ByteBind proof and does not communicate
> identity results to the RP.
>
> The Authority correlates the successful WebAuthn assertion with the existing
> ByteBind transaction and marks the required person-attestation property satisfied.
>
> Redemption remains the point at which the RP learns any permitted resulting
> identity claims.

Applied to sections 5, 6 step 5, 7, 13, and 14:

- Optional iframe person ceremony alongside supported popup mode.
- Frameable step-up only; enrollment/management reject framing.
- Authority-origin assertion checks plus transaction-bound crossOrigin/topOrigin.
- Memory-only bearer attempt session and same-origin CSRF/Origin/Host checks.
- Iframe activation/delegation, private-network browser gates, and explicit popup fallback.
- No frame message API, base-attestation relay, H2/proof delivery, or RP identity disclosure.
- Additional threats and browser/protocol acceptance tests.

Previous spec SHA-256: `29b13a6a913d4e01a5dfaa53e825a35ddc579727f214b670cf00a44913324acc`.
Resulting round-2 spec SHA-256: `2350d1ecc4d817d39ba289bc28ce6211a2cbbfb186cd15478a62396e9fb50caf`.

This entry supersedes the earlier iframe exclusion and popup-only browser
assumptions. Sections 8, 11, and 16, including state, renewal, and redemption
semantics, remain byte-for-byte unchanged. Source drafts, review, handoff,
SPEC.md, implementation, and tests remain unchanged. The Mermaid wire updates
remain deferred as previously recorded. Round-1 review closure is historical;
Claude has not yet cross-verified these round-2 additions.

For Claude's next review, independently check both context modes against the
updated handoff, transaction origin binding, no-cookie session behavior, iframe
request restrictions, activation/delegation and fallback. Verify that fallback
uses an unconsumed handoff or a new transaction, never a consumed token or
transferred assertion. Real-browser support remains an open acceptance gate.


## Review 2 disposition and user-selected session model (2026-10-06)

Reviewed [Claude review 2](SPEC-0.8-CLAUDE-REVIEW-2.md). The user chose:

> device + person verified sessions can silently renew the device lease, person assumes renewed until a new call to a person-attested endpoint is made

The clarification accepted by the user is that retained person association is
checked on the next person-attested endpoint against validity and route freshness,
with fresh step-up when needed; silent device renewal never resets person age.
This supersedes the earlier missing-person-evidence invalidation rule.

| Finding | Decision and application |
|---|---|
| V1 | Do not adopt mandatory reuse permission. Preserve person association through device-only renewal; validate current Authority status and device continuity on each person endpoint before execution. Freshness/deadlines remain finite and original authentication time is unchanged |
| V2 | Adopt pre-handoff frame API/delegation checks and immediately preload options; get() runs directly on activation. Consumed handoff fallback still requires a new transaction |
| V3 | Adopt reported context mode in options request; immutable mode must match verified assertion fields |
| V4 | Defer optional per-RP paths; document static allowlist disclosure and retain fixed URL validation |
| V5 | Require serialized canonical origins and reject noncanonical configuration; implemented 0.7 parser unchanged |
| V6 | Mark LNA token provisional; browser matrix must verify actual tokens, delegation and topOrigin support |

Before SHA-256: `2350d1ecc4d817d39ba289bc28ce6211a2cbbfb186cd15478a62396e9fb50caf`.
After SHA-256: `356262685d77e0610ab66c83f735f7cfc7828baf49d9f903ec6be31c71d1d411`.

States and transaction-redemption rules (section 8), and section 16, remain
byte-for-byte unchanged. Source drafts, review files, handoff, SPEC.md, code,
and tests remain unchanged. The endpoint status check, server-only association
handle, and latest device-grant binding require exact schemas at wire freeze;
this draft defines fail-closed behavior rather than claiming implementation.
Claude should cross-verify this new model, especially no mandatory reuse, no age
reset, no stale handler identity, shared-device continuity, revocation/outage,
and unchanged fresh transaction requirements. Earlier reviews remain historical.


## Round 3: iframe-only — Codex cross-review (2026-10-06)

Claude applied this round directly to the spec under the user's instruction.
The user then authorized Codex to review it and record this ledger entry.
The decisions quoted in the handoff are:

> no popups. iframe only. unless thats a platform compat issue

> update the spec and handoff

Baseline SHA-256: `356262685d77e0610ab66c83f735f7cfc7828baf49d9f903ec6be31c71d1d411`.
Reviewed/result SHA-256: `1100138b0c30fa728a8f5326c8cb7a4815f0438a527c3528fdbd20be89a63c00` (matches Claude's handoff).
Codex made no spec edits during this review.

### Disposition

**Consistent with the iframe-only decision, with one Low wording issue and
browser acceptance still open.** Missing `topOrigin` is accepted as a deliberate
compatibility choice under the trusted-browser/Authority assumptions, not proof
of equivalent signed embedder evidence. The per-RP framing restriction and
RP-path handoff check are both normative. The present topOrigin mismatch still
fails; the crossOrigin flag must be true.

- V3's reported-mode mechanism is superseded: only iframe step-up exists.
- V4's per-RP path deferral is reversed: `/step-up/<rp_id>` and a framing policy
  listing only that RP's origin are now required. This browser-enforced binding
  supports the compatibility choice when signed client data lacks topOrigin.
- No popup, popup-fallback, or selectable top-level step-up mode remains.
  Top-level enrollment/management remains supported and is not person step-up.
- Pre-handoff checks, preloaded options, frame-local activation/error UI,
  no-cookie attempt token, no message API, base-first gate, and redemption-only
  disclosure remain intact. Unsupported configurations grant nothing.
- Sections 8 and 16 match committed `938ab37` byte-for-byte. Section 11 matches
  the prior Codex session-model replacement byte-for-byte. The user's retained
  person association and endpoint-triggered checks were not disturbed.

### Change trace supplied in the handoff

| Section | Change |
|---|---|
| §5 (browser context) | Step-up runs only in an Authority-origin iframe embedded by a top-level application page. Popups and full-page navigation aren't part of the profile. Background renewal must not embed the frame |
| §5 (framing) | **Per-RP step-up path `/step-up/<rp_id>`**, whose `frame-ancestors` lists exactly that RP's origin. The handoff exchange refuses a handoff from another RP's transaction and burns the expected generation. An unknown `rp_id` gets a generic not-found. This replaces the static all-RP allowlist and its disclosure limitation. **It reverses Codex's V4 deferral:** without `topOrigin` on Safari, browser-enforced per-RP framing is what binds the embedder |
| §5 (COOP, polling) | COOP applies to the top-level enrollment and management pages. Popup-blocked and `noopener` text removed |
| §5.1 (renamed "Iframe step-up context") | Per-RP markup, delegating `publickey-credentials-get`, `local-network`, and `local-network-access` (provisional). Top-level embedder required (WebKit single-cross-origin-ancestor rule). Safari gesture and consent noted. On an unavailable API or delegation: no handoff exchange, a frame-local "can't complete person verification" message, no fallback, attempt expires. Preloaded options and `get()` on activation retained. Enrollment stays top-level |
| §6 | Step 5 embeds `/step-up/<rp_id>`. URL validation requires `/step-up/<one rp_id segment>`. Example URL updated. "popup message" changed to "cross-frame message". Mermaid line now "Application embeds Authority step-up iframe" |
| §7 | `crossOrigin` MUST be `true`. A present `topOrigin` MUST equal `allowed_origin`. An absent `topOrigin` is accepted, because binding then rests on per-RP framing plus the RP-scoped handoff. `crossOrigin` false/absent or a mismatched `topOrigin` is refused and burns. The reported-mode mechanism (V3) is removed, since only one mode exists |
| §13 | Rows updated for per-RP framing. New rows: absent `topOrigin`, framed application page, RP enumeration |
| §14 | Popup tests removed. Added: per-RP framing, handoff refused on the wrong RP path, absent `topOrigin` accepted, `crossOrigin` false refused, `topOrigin` presence per browser, framed-embedder refusal, Safari consent, token names, unsupported-browser message |
| §15 | Gate 3 rewritten for iframe acceptance. Gate 10 lists popups as deferred scope |

### R3-1 — Low: unknown-path response does not eliminate RP enumeration

Section 5 says a generic not-found response "doesn't reveal which RPs are
registered". A caller can still distinguish a known RP's step-up page/CSP from
an unknown path's not-found response, and may enumerate guessable identifiers.
Per-RP framing removes bulk disclosure of all origins in one header; it does
not make each RP path secret. The section 13 enumeration row needs the same
qualification. This does not weaken person authorization or handoff isolation.

Proposed correction for review: "An unknown rp_id returns a generic not-found
response. Per-RP paths avoid exposing the full origin list in a single response;
registered RP identifiers and reachable paths are not secret, and guessed paths
may still be enumerable." No correction was applied or silently reverted.

### Standards and platform evidence checked

- [CSP frame-ancestors](https://www.w3.org/TR/CSP3/#directive-frame-ancestors)
  checks ancestor origins in enforcing browser policy. Acceptance tests must
  verify actual enforcing response headers on the delivered document, not a
  report-only policy, and wrong-RP framing/handoff combinations.
- [WebAuthn assertion verification](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion)
  remains mandatory. The missing-topOrigin choice retains challenge, signature,
  Authority origin/RP ID, crossOrigin, UP/UV, and stored transaction checks.
- [WebKit STP 143 release notes](https://webkit.org/blog/12563/release-notes-for-safari-technology-preview-143/)
  document cross-origin iframe WebAuthn support. This establishes engine work,
  not a complete production Safari version/overlay compatibility matrix.
- [WebKit issue 222240](https://bugs.webkit.org/show_bug.cgi?id=222240)
  records cross-origin support work. Current ancestor, gesture, consent, and
  platform-specific behavior still need acceptance tests.
- [Apple-hosted forum report 782988](https://developer.apple.com/forums/thread/782988)
  reports Safari 18.4 omitting topOrigin, with no replies. It is a developer
  observation, not an Apple guarantee about current Safari behavior.
- LNA token/version claims remain provisional. No tailnet/browser runtime test
  was performed and no universal iframe-only compatibility claim is approved.

Gate 3 remains open. Require positive/negative tests for missing and mismatched
topOrigin, wrong-RP paths, direct top-level step-up, nested application framing,
actual CSP enforcement, cookie blocking, permissions and unavailable APIs.
Wire freeze should constrain encoded/ambiguous RP path segments and compare the
resolved RP against stored transaction scope. Existing section 5 requires the
server comparison; client path shape alone is not authorization.

Only this ledger was changed during Codex's review. The spec, handoff, source
drafts, Claude reviews, implementation, and tests remain unchanged.


## Version correction: protocol v1, specification draft 0.8 (2026-10-06)

The user explicitly directed:

> this should all be protocol v1 (spec v0.8). nothing has gone live, this is all in early days

Applied to the canonical spec. This supersedes all earlier v2/coexistence
decisions in this historical ledger and the preserved source drafts. Protocol
v1 is still being designed before stable deployment; 0.7 and 0.8 identify spec
drafts rather than two live protocol versions. No code or baseline/source draft
was changed, and no support claim is made for the draft-0.7 implementation.

- Keep existing base-only `bytebind/v1/*` transcript labels; new person and
  pairwise labels also use `bytebind/v1/*`.
- Use protocol marker 1, existing `/attestation`, and `/attestation/result`;
  remove the proposed v1/v2 endpoint-routing split.
- Draft-capability and assurance negotiation remains explicit and fail closed.
  Protocol number 1 alone never implies person-step-up support.
- Replace migration/coexistence wording, discovery advertisements, vectors, and
  diagram labels accordingly. Old clients require schema compatibility testing.
- Supersede the pre-release application of 0.7 section 30 to this change; retain
  explicit versioning requirements for incompatible changes after stable release.

Before SHA-256: `1100138b0c30fa728a8f5326c8cb7a4815f0438a527c3528fdbd20be89a63c00`.
After SHA-256: `a8435ff437a02a6860db2d0868ca79345126ade46552e60e0d712777ff5eef0c`.

Claude should verify that only version/draft compatibility semantics changed:
iframe-only gating, identity independence, session model, state/expiry rules,
exact-operation binding, and redemption properties remain. Source drafts and
previous review entries are provenance, not alternate active v2 specifications.
