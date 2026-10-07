# ByteBind 0.8: review notes

**Status:** Final review complete; user decisions applied 2026-10-06. Not implemented.
**Protocol:** v1. **Specification:** 0.8-draft.
**Specification:** [SPEC.md](../../SPEC.md). Draft 0.7 (implemented) is in git
history at commit `3072234`; the pre-consolidation drafts are in commit `21c290d`.
**Final review:** [SPEC-0.8-CLAUDE-FINAL-REVIEW.md](SPEC-0.8-CLAUDE-FINAL-REVIEW.md).

Current spec SHA-256: `f3047f06301b47e0b36fb10d5d81b038ea42f998f904f7a14a600ba803d38d2f`.
This is a snapshot identifier; if the spec changes, review the delta and update
this value. Nothing in these notes establishes runtime or browser support.

## Whole-protocol consolidation

The user requires draft 0.8 to specify the entire protocol, not a step-up
revision that incorporates 0.7 by reference. The base ceremony is now included
in sections 2–8; provider/browser/storage rules are in sections 19–24. The
reviewed person design is retained in sections 9–18. Shared security, release
gates, and hardening are in sections 25–29.

Reconciliations: base attestation records `base_attested`; only `redeemable`
transactions with committed delivery may redeem. Redemption starts at first
delivery, not base attestation. Base examples carry protocol and assurance;
legacy four-state storage is replaced. Device renewal preserves person
association under endpoint validation. Provider ownership never supplies person
identity. Protocol v1 labels remain unchanged. No implementation changed.

Please independently check all remapped section references and both profile
transcripts, strict encodings, RP authentication, request digest construction,
durable burns, and grant/lease limits. Compare every normative base requirement
against SPEC.md for omissions; resolve differences using the explicit current
decisions rather than applying historical rules by reference.

## Current decisions

| Topic | Accepted design |
|---|---|
| Version | Protocol v1, spec draft 0.8. No stable version has gone live. Keep existing v1 base transcript labels; new person/pairwise labels also use v1 |
| Draft support | Protocol number alone does not establish draft-0.8 capability. Unsupported schema/assurance fails closed; no downgrade |
| Identity | Person subject independent of provider account, owner, principal, and device identity. Derivation from provider principal is prohibited |
| Ownership | Authority owns subjects, enrollment, credentials, assertion verification, and disclosure. Applications declare assurance and consume grants |
| Ordering | Existing private base attestation succeeds before any person handoff/options. Optional step-up never replaces or proxies it |
| Browser | Person step-up is iframe-only at the private Authority origin, embedded by a top-level application. No popup or navigation fallback. Enrollment/management stays top-level |
| Framing | Per-RP step-up path; enforcing frame-ancestors allows only that RP origin. Handoff RP must match the path. Enrollment/management rejects framing |
| Origin verification | Exact Authority origin; crossOrigin true. A present topOrigin must match the transaction origin. Missing topOrigin is accepted under browser-enforced per-RP framing and RP-scoped handoff |
| Iframe isolation | Memory-only attempt bearer token; no cookie dependency or message API. Frame handles only person ceremony, never H2, proof, or RP identity claims |
| Activation | Check API/delegation before consuming handoff. Preload options, then call get() directly from the frame's activated control. Unsupported context grants nothing |
| Binding | W commits to cid/H1 plus fresh randomness. Stored scope, exact Q, single-use state, and expected-generation updates remain mandatory |
| Delivery | Overall 120 s person limit; 30 s collection capped by it; 10 s redemption starts at committed first delivery reservation. Lost delivery cannot replay an operation |
| Session renewal | Device renewal preserves person association without resetting person age or extending its deadline. Missing person evidence on renewal alone does not erase it |
| Person endpoint | Before execution, check person validity/freshness, current credential/subject status, and device continuity through authenticated Authority validation. Outage fails closed for that person route |
| Fresh transaction | Person-gated transaction always requires a new assertion for the exact operation. Session association never substitutes |
| Disclosure | Structured assurance can omit identity. Person identifiers pairwise by default; credentials and raw assertions never reach RPs. IP in H2 remains observable to RP-origin browser code |
| Enrollment | Dedicated private authorization; independent subject attachment permission, existing credential authentication or approved recovery. Invites do not imply device-owner identity |
| Trust | Authority tag/capability owners are approved operators: accepted operator trust boundary. Additional stable-identity pinning remains SHOULD |
| Implementation | No implementation changes or browser/tailnet validation are implied by the draft |

## Remaining issue for final review

**Low — RP enumeration wording (sections 12 and 25).** Generic not-found for an
unknown RP path does not prevent enumeration when known paths return distinguishable
pages or headers. Per-RP paths avoid exposing the entire origin list in one
response. They do not make RP identifiers or reachable paths secret.

Suggested clarification: "An unknown rp_id returns a generic not-found response.
Per-RP paths avoid exposing the full origin list in a single response; registered
RP identifiers and reachable paths are not secret and may still be enumerable."
This clarification has not been applied. It does not change handoff authorization.

## Release gates still open

- Freeze strict wire schemas, paths, caps, assurance/draft negotiation, typed
  errors, association/reuse handles, and latest-device-grant binding.
- Test real private HTTPS listeners and supported Chrome, Safari, and Firefox
  versions: iframe delegation, actual enforcing CSP, topOrigin behavior,
  gesture/consent, cookie blocking, LNA permission tokens, unsupported contexts.
- Finalize independently authenticated enrollment/recovery and audit policy.
- Test all timers, long-poll budgets, crashes, durable burns, counter/revocation
  races, delivery loss, and at-most-once stored operation execution.
- Finalize endpoint-triggered session validation, device continuity without
  identifier disclosure, revocation, logout, subject switch, and finite age.
- Review/pin a maintained Authority-only verifier dependency and algorithms.
- Publish v1 person/pairwise vectors and obtain independent protocol review.
- Define multi-Authority credential/state ownership before claiming failover.
- Sequential challenge reissue after accidental cancellation remains undecided;
  no retry-within-the-same-attempt behavior is authorized by omission.
- Update the handshake chart's person_origin and HTTP 202/poll details at wire
  freeze. Update shared threat model, README, roadmap, and blog after spec approval.

## Instructions for Claude's final look

Read the complete standalone spec and these notes, then compare base-protocol
coverage against historical SPEC.md and the current implementation. SPEC.md is
not a normative dependency of draft 0.8. Treat archived proposals as provenance,
not active alternate requirements. Please verify:

1. Protocol v1 versus spec 0.8 is consistent across labels, markers, paths,
   examples, negotiation, discovery, charts, and versioning rules.
2. Device and person identities remain separate. Shared-device users cannot
   inherit another lease's person association. Enrollment cannot equate ownership
   with the person or attach credentials from only a device tag/subject name.
3. Base authorization precedes step-up; the iframe never handles base attestation,
   H2, ByteBind proof, identity disclosure, or cross-frame messages.
4. Per-RP framing and handoff checks support the missing-topOrigin choice;
   mismatched origins/crossOrigin still fail. All browser claims retain acceptance
   gates; no current Safari or permission-token support is assumed proven.
5. Device-only renewal preserves association but does not refresh person time.
   Person routes check status/freshness/continuity before handlers. Device-only
   routes remain independent; fresh person transactions remain mandatory.
6. Assurance cannot be fabricated by static authorization strings. Disclosure
   permissions, pairwise encoding, credential secrecy, and address leakage are clear.
7. All states, generations, deadlines, cancellation, revocation, and concurrent
   delivery/redemption paths preserve single use and winner survival.
8. No unknown operation is automatically retried after lost delivery/redemption.
   Stored-operation execution cannot use ambient credentials from proof submission.
9. Resolve the enumeration wording issue and flag any new contradiction, omitted
   invariant, stale instruction, or claim of implemented/validated behavior.

Report findings separately with severity, exact spec section/line, rationale,
and proposed replacement text. Distinguish design contradictions from open
implementation gates. Do not implement, commit, or silently edit the spec during
this review; the user will decide any resulting changes.

## Provenance retained outside the repository

The individual drafts, two Claude reviews, merge ledger, handoff, Phase 1
proposal, and pre-cleanup canonical spec were copied byte-for-byte to external
archive `bytebind-spec-0.8-20261006-165035`. Its SHA256-MANIFEST.json and RESTORE.md preserve
verification and restoration instructions. The archive was verified before
repository copies of the superseded working documents were removed.

This final-review package consists of SPEC-0.8.md and these notes; SPEC.md remains
the historical comparison. Earlier tracked review files remain recoverable from
Git history as well as the external archive.

## Consolidation applied (2026-10-06)

Following the final review and the user's decisions:

- Findings D1–D6 and E1–E2 applied. The grant `assurance` schema is unified
  (spec §9.2, §16). Result-endpoint peer checks are consistent (§12). The
  enumeration wording is Codex's. Person validity never resets (§17.3). The
  Authority invalidates associations immediately. The validation call is in the
  exchange table (§5). Headings are renumbered. The proof path is
  application-defined.
- O1: the draft-0.7 device-bound IdP profile is recorded as removed and
  deferred (spec §1; ROADMAP gate 9).
- **Aggressive trim:** 2,140 → about 1,140 lines, with no normative change
  intended:
  - the verification plan and release gates moved to `docs/ROADMAP.md`;
  - the person-step-up threat table moved to `docs/THREAT-MODEL.md` §6.10;
  - labels were deduplicated into one table (§4.1);
  - implementation descriptions, the packaging example, the provider-interface
    sketch, and provenance prose were removed.

  A fuzzy trace of every normative sentence found eight weakened or missing
  requirements, all restored before replacement.
- `SPEC.md` replaced in place. Git preserves draft 0.7. Code comments citing 0.7
  section numbers are accepted as stale (user decision R1).
- THREAT-MODEL T-D1 reclassified as accepted operator trust (user decision F12).
- Provenance: working documents snapshotted in `21c290d` before removal; the
  external archive remains as a secondary copy.

The sections above ("Current decisions", "Remaining issue", "Release gates",
"Instructions for Claude's final look") are historical. The enumeration issue
is resolved, and the live gates are in ROADMAP.

## Codex consolidation follow-up (2026-10-06)

Restored two requirements weakened by the trim: global person identifiers and
global names require separate explicit operator disclosure permission (§16),
and session application responses must disclose neither lease expiry nor
remaining time (§17.2). The spec hash above includes these corrections.

The consolidation review checked the spec hash, JSON examples, and live local
links. The full existing test suite passed before these two documentation-only
corrections, using the existing test environment outside the socket-restricted
sandbox. No implementation changes were made.

## Claude follow-up to Codex's catches (2026-10-06)

Codex's two findings prompted a stricter trace (every MUST/NEVER sentence of the
round-3 spec at `21c290d` and of draft 0.7 at `3072234`, matched below 0.8
token overlap). It found ten more requirements that had been weakened to plain
description or had lost a detail. All are restored in `SPEC.md`:

- applications MUST NOT assume device identity shows the person present (0.7 §18; spec §2.2);
- the RP MUST verify the Unix socket's ownership and access policy (§3.2);
- leases MUST NOT outlast their grant, which also corrects "MAY outlast" (§9.2);
- clients MUST send attestation directly to the Authority (§7);
- the iframe MUST show its own control and MUST call `get()` from its activation (§11.3);
- tokens MUST NOT be included in analytics (§12);
- challenge-linked fields MUST NOT change after options are issued (§13);
- invites MUST be delivered out of band, redacted, and consumed only from an enrollment context (§15);
- omitted disclosure permission MUST NOT be treated as permission (§16);
- a write lock MUST NOT be held across provider or verifier calls (§7.2).

Provenance gap: Codex's 2,140-line standalone draft (`9e98dccb…`), which the
consolidation trimmed, was never committed or archived. Claude removed it without
snapshotting it. Its inputs are in git (`21c290d`, `3072234`), the trim is
traced against them, and its content is reflected in the final review.
