# Claude final review: standalone SPEC-0.8.md and the cleanup proposal

**Reviewed:**

- `SPEC-0.8.md` at SHA-256
  `9e98dccb2962ae6c6e3c38ee0b4e0e2f90ed46c0ef3357431127ce4556e68907`
  (matches the review notes);
- `docs/drafts/SPEC-0.8-REVIEW-NOTES.md`;
- the external archive `~/Documents/Codex/Archives/bytebind-spec-0.8-20261006-165035`;
- the working-tree cleanup (six tracked deletions, one new file).

**Compared against:** `SPEC.md` (0.7) and the current implementation.
**Date:** 2026-10-06. Claude edited only this file; nothing is committed.

## Verdict

**The specification is sound. It needs six Low text corrections and one Medium
one, and the omission of 0.7 §18 should be recorded.**

The cleanup is safe *as an archive*: the manifest verifies 8/8 and includes
review 2 and the round-3 handoff. Two things should happen **before** pushing,
though:

1. **R1 (High, for the replacement step):** replacing `SPEC.md` would leave 29
   code and test references and about 15 doc references pointing at
   renumbered, unimplemented text.
2. **R2 (Medium):** some provenance exists only in the local archive.

## Checklist results (review-notes items 1–9)

| # | Check | Result |
|---|---|---|
| 1 | Protocol v1 / spec 0.8 consistency | Consistent. No `v2`, `/v2/`, or `bytebind/v2` remains. The labels (§3, §4.2, §14, §17), markers (§5.1–5.2, §8.2, §17), paths (`/attestation`, `/attestation/result`), and versioning rule (§9) agree. I concur with keeping v1 labels pre-release: person transactions are gated by state (no `H2` before `redeemable` plus delivery reservation), not by transcript, and §9 forbids selecting a draft-0.7 implementation for person transactions |
| 2 | Device vs. person identity | Holds: §10 (unconfigurable prohibition), §16 (enrollment can't attach from a tag or subject name; invites don't imply owner identity), §18 (no inheritance across leases or users) |
| 3 | Base before step-up; iframe limits | Holds: §6.1 check 9, §12.1, §13 steps 3–5, §15 |
| 4 | Missing `topOrigin` | Holds: §12 makes per-RP `frame-ancestors` and the handoff RP/path check normative (MUST). §14 still refuses `crossOrigin` false or absent and a mismatched `topOrigin`. All browser claims stay gated (§12.1, §26, gate 3) |
| 5 | Renewal and person routes | Holds: §18 (association preserved; no age reset or extension; per-call validation before handler; fresh transaction mandatory). Wording issues D4 and D5 below |
| 6 | No fabricated assurance; disclosure | Holds: §11, §17, §20. Pairwise encoding fixed. Address leakage stated in §25 and §28.4 |
| 7 | State, generation, deadline races | Holds: §6.1–6.2, §8.1, §15 (expected-state-and-generation updates; loser never burns; redemption requires delivery reservation) |
| 8 | No retry after loss; no ambient credentials | Holds: §15 table, §8.3, §28.3 |
| 9 | Enumeration wording; new contradictions | D3 below (Codex's wording adopted), plus D1, D2, D4–D6 and O1 |

## Findings in the specification

### D1: Medium. Two incompatible grant `assurance` shapes (§8.2 vs. §17)

- §8.2 example: `"assurance": {"device": true, "person": "none"}`
- §17 examples: `"assurance": {"device_attested": true, "user_present": …, "user_verified": …, "fresh_for_transaction" | "person_fresh" …, "person_expires_in": …}`

These are both "illustrative", but they disagree on member names, so an
implementer can't tell which is meant before wire freeze.

**Replace the §8.2 example's assurance line with:**

```json
  "assurance": {"device_attested": true, "user_present": false, "user_verified": false},
```

and the sentence after it with: "The `assurance` members follow section 17; this
example illustrates device-only assurance."

### D2: Low. Result-endpoint peer check stated two ways (§13 step 7 vs. §12)

§13 step 7: "This endpoint checks original RP Origin, Host, current private peer
identity, and stored `cid`, `N`, `H1`." §12 says a *pending* response requires
only the socket address match, and the full provider check runs once, at delivery.

**Replace in §13 step 7:**

> "…checks original RP Origin, Host, the socket peer address against the stored
> attested address (and, at delivery, the full provider identity and policy
> check of section 15), and stored `cid`, `N`, `H1`."

### D3: Low. Enumeration overclaim (§12, §25). This is my round-3 text

A response for a known `/step-up/<rp_id>` path is distinguishable from a
not-found, and its `frame-ancestors` header reveals that RP's origin. So
"doesn't reveal which RPs are registered" is false. **Adopt Codex's suggested
wording** in §12:

> An unknown `rp_id` returns a generic not-found response. Per-RP paths avoid
> exposing the full origin list in a single response; registered RP identifiers,
> reachable paths, and each path's framing origin are not secret and may be
> enumerable.

§25 row: change the treatment to "Per-RP paths avoid one response listing every
origin; RP identifiers and per-path origins remain enumerable (accepted)."

### D4: Low. "from the last Authority confirmation" could be read as a reset (§18)

"Person validity is separately bounded by `assurance.person_expires_in` from the
last Authority confirmation; no repeated device renewal extends it."

**Replace with:**

> Person validity is bounded by the original person-validity deadline; each
> Authority confirmation reports only the time remaining until that deadline,
> and no confirmation or device renewal extends it.

### D5: Low. Who acts on "known invalidation" (§18)

"Known invalidation cannot be ignored until another request." §16 says there's
no push revocation to RPs.

**Replace with:**

> The Authority MUST invalidate the association and its handles as soon as it
> learns of revocation, suspension, mismatch, logout, or subject switch, so the
> next validation fails. An RP that learns of invalidation MUST drop the person
> context immediately rather than at its next request.

### D6: Low. The person-association validation exchange isn't in the exchange inventory (§4, §13)

§18 introduces an RP → Authority control call made before every person-route
handler. The §4 table and the §13 list don't mention it.

**Add a §4 table row:**

> RP → Authority | Person-association validation over the control channel | Current person status for this lease, or refusal | 18

### O1: Low–Medium. 0.7 §18 "Device-bound IdP profile" was removed without a record

The 0.7 OIDC/IdP profile (a MAY section, with "Applications MUST NOT assume
that device identity alone proves which human is physically present") is gone.
§10 keeps one sentence: "Any future identity-provider bridge MUST preserve this
distinction; federation remains out of scope". The safety requirement survives
in substance in §2 and §10. But the README and blog discuss the OIDC/`tsidp`
relationship, and neither the notes nor §27 record the removal.

**Either:**

- record it in the review notes and add "device-bound IdP profile (0.7 §18)" to
  gate 10's deferred-scope list; **or**
- restore it as an informative subsection, with the person-identity caveat from
  §10.

I recommend the first: it matches the out-of-scope statement in §1.

### Editorial (no normative effect)

- **E1: heading hierarchy.**
  - Unnumbered `### Channels` is followed by `### 2.1`.
  - §3, §19, §21, §24, §25, and §29 mix unnumbered `###` headings with numbered
    subsections.
  - `---` separators sit inside sections.

  Normalize before this becomes the canonical file.
- **E2: proof path example.** §8's example path is `/bytebind/v1/proof`
  (inherited from 0.7); the reference binding uses `/bytebind/proof`. Paths are
  RP-defined, but use the reference path or a neutral `/proof` to avoid
  implying versioned paths.

## Findings on replacing `SPEC.md` and on the cleanup

### R1: High (replacement step). Implementation and doc references would silently point at the wrong spec

The reference implementation conforms to **0.7** and cites 0.7 section numbers:

- **29 locations** in `src/`, `tests/`, `scripts/`, and `examples/`. For
  example, `authority.py` "Checks 3-9 of SPEC.md 11.1", `store.py` "SPEC.md
  sections 11.2, 13.1, 14", `test_attest.py` "SPEC.md 11.1 checks",
  `__init__.py` "draft 0.7, see SPEC.md", and the handshake script "SPEC.md
  sections 9–13".
- **About 15 lines** in `README.md` ("SPEC.md: the protocol, draft 0.7";
  "SPEC.md 11.1"), `docs/OVERVIEW.md`, and `docs/THREAT-MODEL.md` ("SPEC.md
  3", "15.2", "16.3", "19", …).
- `test-vectors/bytebind-v1.json` says `"version": "draft 0.7"`.

After replacement, `SPEC.md` §11 becomes "Assurance policy", §15 "States", §16
"Subjects", and §19 "Device leases". Every one of those citations would then
point at the wrong section of a spec the code doesn't implement. "Git preserves
0.7" doesn't help a reader following a code comment.

**Recommendation:** keep the implemented spec addressable.

1. `git mv SPEC.md docs/SPEC-0.7.md`, then `git mv SPEC-0.8.md SPEC.md`.
2. Repoint the existing citations from `SPEC.md` to `docs/SPEC-0.7.md`. The
   section numbers stay valid. These are comment, docstring, and doc-only edits:
   no code behavior changes, and the test suite should still pass.
3. README line 16 becomes: "SPEC.md — protocol v1, specification 0.8-draft (not
   implemented); the reference implementation implements
   draft 0.7 (`docs/SPEC-0.7.md`)."
4. Leave `test-vectors/bytebind-v1.json` labeled `draft 0.7`, which is accurate
   for the vectors.

If editing comments is out of scope for this commit, the alternative is to
**not** replace `SPEC.md` yet, and to land `SPEC-0.8.md` alongside it until
implementation starts.

### R2: Medium. Some provenance would exist only in a local, unpushed archive

The archive verifies and is complete. But it lives in `~/Documents/Codex/Archives/`
and is never pushed. Git (`938ab37`) has only the *round-1* versions of
`HANDOFF.md` and `SPEC-0.8-CROSS-VERIFY.md`. The following were never committed
anywhere:

- the round-2 and round-3 handoff;
- the round-2 ledger and the review-2 disposition, which record the user's
  verified-session decision;
- `SPEC-0.8-CLAUDE-REVIEW-2.md`.

Deleting them in the same commit that lands the spec means the pushed history
never contains them.

**Recommendation:** two commits.

1. **"Snapshot 0.8 working documents"**: restore the archive's copies of
   `HANDOFF.md`, `SPEC-0.8-CROSS-VERIFY.md`, and `SPEC-0.8-CLAUDE-REVIEW-2.md`
   into the tree and commit them unchanged. The other archived files already
   match git.
2. **"Consolidate 0.8 spec"**: the cleanup (deletions, the review notes, this
   review, the spec replacement per R1).

The pushed history then contains every decision record, and the local archive
becomes a convenience rather than the only copy.

### R3: Low. Self-references to fix during replacement

- §1: "SPEC.md remains a historical draft-0.7 comparison, not an incorporated
  source of requirements." Rewrite as "Draft 0.7, which the reference
  implementation implements, is at docs/SPEC-0.7.md." (or a git reference if
  you don't adopt R1).
- §1: "Final review of this cleaned package remains pending." and gate 1
  (§27): close them after the user decides these findings.
- Header: Codex's proposed "Protocol v1 · Specification 0.8-draft · Not
  implemented" is good. Replace the "Status: Combined draft for
  cross-verification" line.
- The review notes' links to `../../SPEC-0.8.md` and the "Historical
  comparison: SPEC.md" header, plus the spec SHA-256 in the notes.

## Not findings (verified)

- No stale popup text remains. The only mentions are "not part of this profile"
  and deferred scope.
- §6.2's SQL shows the expected-generation pattern. §24 requires the six-state
  constraint and the extra fields.
- 0.7 rules that were changed deliberately are all reflected:
  - redemption window starts at delivery, not attestation;
  - `Path=/` with the `__Host-` state cookie;
  - fail closed upgraded from SHOULD to MUST;
  - the versioning rule.
- Everything else in 0.7's 105 normative sentences that isn't verbatim is
  renumbered text. I checked each of the 36 non-verbatim matches; O1 is the
  only removal.

## User decisions (2026-10-06)

| Item | Decision |
|---|---|
| R1 | **Replace `SPEC.md` with 0.8 and rely on git for 0.7.** No `docs/SPEC-0.7.md`. Existing 0.7 section citations in code and docs are accepted as stale until a later edit. A reader finds 0.7 at commit `3072234` (or `938ab37`) |
| R2 | **Snapshot, then cleanup.** Commit 1 restores the archived `HANDOFF.md`, `SPEC-0.8-CROSS-VERIFY.md`, and `SPEC-0.8-CLAUDE-REVIEW-2.md` unchanged. Commit 2 is the consolidation |
| O1 | **Record as deferred.** Add "device-bound IdP profile (0.7 §18)" to gate 10 and note the removal in the review notes |
| Length | **Aggressive trim**, to about 1,200–1,300 lines. Apply D1–D6 and E1–E2 first (included in the recommended path the user extended). Then move the test plan, release gates, and person-threat table to the docs, dedupe labels, drop implementation descriptions and provenance prose, and put rationale in short notes. No normative change |
| D1–D6, E1–E2 | Apply as proposed (implied by the length decision) |
| R3 | Apply during replacement: §1 self-reference becomes a git reference to 0.7; the header becomes "Protocol v1 · Specification 0.8-draft · Not implemented"; close gate 1 after the fixes |

## Requested decisions (user)

1. D1–D6 and E1–E2: apply as proposed?
2. O1: record as deferred (recommended) or restore?
3. R1: move 0.7 to `docs/SPEC-0.7.md` and repoint citations (recommended), or
   defer replacing `SPEC.md`?
4. R2: snapshot commit before the cleanup commit?
