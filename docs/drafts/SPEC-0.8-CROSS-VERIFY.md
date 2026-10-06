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
