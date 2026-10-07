# Handoff to Codex: apply the accepted review to SPEC-0.8.md

**From:** Claude, 2026-10-06
**For:** Codex, as owner of the canonical combined draft `SPEC-0.8.md`
**Status:** Rounds 1 and 2 are applied by Codex. Round 3 (iframe-only) was
applied **by Claude, directly in `SPEC-0.8.md`, at the user's instruction**.
Codex should review it and add the ledger entry; see "Round 3" at the end.

## What happened

1. You merged the two drafts into `SPEC-0.8.md` and wrote
   `docs/drafts/SPEC-0.8-CROSS-VERIFY.md`.
2. Claude reviewed the merge in `docs/drafts/SPEC-0.8-CLAUDE-REVIEW.md`. The
   verdict was **reconciled with issues**, with findings F1–F12.
3. The user decided all twelve findings. The decisions and exact patch text are
   in that review file, under **"User decisions (2026-10-06)"** and
   **"Second round"**. Claude didn't edit `SPEC-0.8.md`, so applying them is
   your call as owner.

## Your task

Apply patches **P1–P16** from the review file to `SPEC-0.8.md`, then update the
ledger in `SPEC-0.8-CROSS-VERIFY.md`.

### Before you start

- Check that `SPEC-0.8.md` still has SHA-256
  `5ef4019f0fc6f2e39f55d4752cd80f67d6dd027f70a82c5c1b7ce42b6fa5fbec`.
  The patches quote exact text and cite line numbers at that hash. If the file
  has changed, match the patches by their quoted text, not by line numbers.
- Line numbers shift as you apply patches. Apply them by quoted text, or from
  the bottom of the file up.

### Patches

| Patch | Finding | Decision | Where the replacement text is |
|---|---|---|---|
| P1–P3, P7 | F1: person expiry vs. device-only access | Accepted | P1, P3, and P7 inline in the decisions table. **P2's text is the F1 "Replace L580–596 with" block** in the Findings section |
| P4, P7 | F2: per-route `person_max_age` | Accepted | Inline (P4) |
| P5–P6 | F3: result polling vs. rate limit and provider load | Accepted | P6 inline. **P5's text is the F3 "Proposed fix" block** in the Findings section |
| P8–P9 | F4: counter rule (either counter non-zero) | Accepted | Inline |
| P10 | F5: current discovery wording | Accepted | Inline |
| P11 | F6: v1/v2 endpoint refusal | Accepted | Inline |
| P12 | F7: no conditional mediation; verify UP at registration | Accepted | Inline |
| P13 | F8: pairwise encoding (`subject_id` is opaque bytes) | Accepted | Inline |
| P14 | F9: `W` is a transcript commitment only | Accepted, simpler option | Inline. Keep the `W` derivation; drop the audit-reconstruction sentences |
| P15 | F10: popup handle and `noopener` | Accepted | Inline |
| P16 | F11: `Host` check on the person listener | Accepted | Inline |
| none | F12: discovery as the only trust source | **Rejected** | No spec change. See the ledger update below |

Also make the two gate edits listed under the decisions table:

- gate 6 gains "dual device/person lifetimes and `person_fresh` recording";
- gate 5 gains "long-poll hold time and per-(peer, cid) result budget".

### How the F1–F3 changes fit together

Keep the following consistent across §§2, 8, 10, and 11.

- **Person-lease renewal** is a v2 transaction with `assurance: device` plus a
  reuse handle.
- **Grants** carry separate lifetimes:
  - device `expires_in`, which keeps 0.7 §15.1's 90 s minimum;
  - `assurance.person_expires_in`.
- **Grants from a fresh assertion** carry `assurance.person_fresh: true`.
  Reuse grants never do.
- **The RP:**
  - strips person state when `person_expires_in` elapses, or when a renewal
    grant lacks person evidence;
  - lets the device lease continue under its own deadline;
  - enforces each route's `person_max_age` from its own receipt time of the
    fresh grant.
- **A transaction that required person assurance** still fails rather than
  downgrading.
- **The `base_attested → redeemable` row** in §8 no longer lists "session
  evidence reuse" as its own path.
- **Background renewal** never receives a step-up variant.
- **Result polling** is a long poll of at most 10 s, with one outstanding
  request per attempt and at least 2 s between requests.
  - Its rate budget is per (peer, `cid`), separate from the device's
    attestation limiter.
  - A pending poll checks only that the socket peer address matches the
    stored attested address.
  - The full provider identity and policy check runs once, at delivery.

### Ledger update in SPEC-0.8-CROSS-VERIFY.md

Add an entry recording:

- P1–P16 applied, with the resulting `SPEC-0.8.md` hash;
- **F12 rejected by the user:** whoever controls the Authority tag or
  capability is an approved operator. That's an accepted trust boundary and out
  of scope, so §16.1's SHOULD stays. THREAT-MODEL T-D1 should be reclassified
  to Accepted (operator trust) when THREAT-MODEL.md is next updated;
- gate 1 (Claude cross-verification) closed, conditional on the patches being
  applied as written.

## Still open (not for this pass)

- **Mermaid diagram (§6):** add `person_origin` and the 202/poll loop at wire
  freeze.
- **Reissuing a challenge after a mis-tapped cancel:** Claude suggests at most
  3 sequential reissues within the same popup session, with the previous
  challenge invalidated atomically, inside the 120 s limit. Track it under
  gate 5. **The user hasn't decided this.**
- **THREAT-MODEL.md mapping:**
  - T-B1 is reduced for person-gated routes only;
  - T-B2 is bounded by person age;
  - T-TS2 gains an independent person identity;
  - T-PR1 is unchanged (§16.4);
  - T-D1 is reclassified as above.

  Do this when shared docs are updated, after spec approval.

## Round 1 status

Done. Codex applied P1–P16 and the gate edits, and recorded F12 in the ledger.
The resulting `SPEC-0.8.md` hash is `29b13a6a…`. Claude confirmed the ledger
entry on 2026-10-06 but hasn't re-reviewed the patched text line by line.

---

## Round 2: an Authority-origin iframe for person step-up (new user requirement)

### The user's requirement, verbatim

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

### What it agrees with already

Most of the existing protocol is unaffected.

- **Base attestation stays first**, unchanged: §6 steps 2–3 and the §8 states.
- **The handoff gate.** No options are issued before base acceptance and the
  handoff exchange.
- **The application page collects `H2`** through `/v2/attestation/result`. The
  iframe never carries it.
- **Claims reach the RP only at redemption**, as §10 already says.
- **No result messages.** §6 already says no `postMessage` results and no
  return URL. The iframe needs neither.

### What it changes in SPEC-0.8.md (at hash `29b13a6a…`)

| Current text | Conflict | Required change |
|---|---|---|
| §5: "An iframe or related-origin design is an alternative requiring separate review; neither is a baseline dependency." and "Related origins and delegated iframes are excluded from this baseline; a future profile must revisit prompt gating and who handles raw assertions." | The user now permits an Authority-origin iframe for step-up | Permit the **step-up page only** to run either as an Authority-origin iframe embedded by the application page or as the existing popup. Related origins stay excluded. Prompt gating is unchanged, because the handoff gate is in the Authority page. Raw assertions are still handled only by the Authority origin |
| §5: "Authority credential pages MUST reject framing" | The step-up page must be frameable | Enrollment and management pages keep rejecting framing (`frame-ancestors 'none'`). The step-up page sends `frame-ancestors` listing exactly the registered application origins. That is a static list, because the handoff arrives in the fragment after load. Its binding to *this* transaction's origin comes from the `topOrigin` check below, not from the header |
| §5: "Person pages MUST use `Cross-Origin-Opener-Policy: same-origin`, including the step-up page." | COOP doesn't apply to a frame the same way. It's harmless but no longer the isolation mechanism in iframe mode | Keep COOP for top-level person pages. Iframe isolation comes from the cross-origin boundary, from no message API, and from `frame-ancestors` |
| §7: "This baseline rejects cross-origin ceremonies." | In an iframe, `clientDataJSON.crossOrigin` is `true` and `topOrigin` is the embedding application origin | Accept `crossOrigin: true` **only** when `topOrigin` exactly equals the transaction's stored `allowed_origin`. Require `crossOrigin` false or absent, with no `topOrigin`, for the top-level popup. Refuse and burn any other combination. This *adds* a binding: the assertion names the application page that embedded the ceremony |
| §5: "Cookies MUST be Secure, HttpOnly, and scoped narrowly…" | Third-party iframes get partitioned or blocked cookies, depending on the browser | The step-up attempt session MUST NOT depend on cookies. The handoff exchange returns an attempt-bound bearer token held only in the iframe's memory, sent in a request header and used as the CSRF token. Enrollment and management, which stay top-level, may keep cookies |
| §6 step 5: "the browser opens the fixed Authority page, passing the handoff token in a URL fragment" | It assumes a popup | "…opens or embeds the fixed Authority step-up page…". The fragment rule is unchanged: remove the fragment immediately, then exchange it by POST |
| §5: popup-only text (`popup_blocked`, the `noopener` rule) | Popup-specific | Keep it as popup-mode text. Add an iframe-mode paragraph (below) |

### Iframe-mode requirements to add (proposed text)

> The application page MAY embed the step-up page as
> `<iframe src="<person_origin>/step-up#<handoff>" allow="publickey-credentials-get <person_origin>; local-network-access">`.
> The client validates `person_origin` exactly as for the popup (§6). Bindings
> that send `Permissions-Policy` or a CSP `frame-src` on application pages MUST
> permit the person origin for that page. The iframe MUST NOT be sandboxed in a
> way that removes its origin.
>
> The step-up page MUST NOT post messages to its embedder or accept them, and it
> MUST NOT perform, proxy, or relay any base-attestation request. Its only
> requests are the handoff exchange, options, assertion, and abort to its own
> origin. The embedding page learns the outcome only through result polling (§5).
>
> Before calling `navigator.credentials.get()` the page MUST show its own
> "Verify with passkey" control and call `get()` from that control's activation,
> because browsers may require transient user activation in cross-origin frames.
> If `get()` is unavailable in the frame (the feature isn't delegated or isn't
> supported), the page reports nothing to the embedder. The embedder falls back
> to popup mode with the same handoff while it's still unconsumed, or with a new
> transaction once it's consumed.
>
> Registration (`create()`) is never performed in an iframe. Enrollment stays a
> top-level Authority page.

### Facts the iframe mode depends on

Facts checked on 2026-10-06 are marked; nothing below has been tested on a real
tailnet.

| Fact | Status | Consequence |
|---|---|---|
| Cross-origin iframe `get()` with `allow="publickey-credentials-get"`: Chrome 84+, Firefox 118+ | Reported by web.dev; **not tested here** | The iframe works in these browsers if the other conditions below hold |
| Safari delegation of `publickey-credentials-get` | **Sources conflict** | Popup fallback is mandatory until it's tested |
| Chrome Local Network Access covers **subframe navigations** to private addresses, including `100.64.0.0/10`, and an embedded frame needs `allow="local-network-access"` delegated by the embedder | Chrome documentation and secondary sources | The iframe adds an LNA requirement, on top of base attestation's fetch, that the popup may not have. Gate 3 must test both modes |
| Cross-origin `create()` needs transient activation and Safari doesn't support it | MDN / web.dev | Supports keeping enrollment top-level |
| WebAuthn L3 `clientDataJSON.crossOrigin` / `topOrigin` | WebAuthn L3 | Basis for the `topOrigin == allowed_origin` binding |

### New threat-model rows

| Threat | Treatment |
|---|---|
| Application-origin script overlays, obscures, or restyles the frame (clickjacking) | The browser draws the native passkey prompt and names the Authority RP ID. Script can trigger the frame but can't forge an assertion. The frame's own button only starts the native prompt. Accepted, since T-B1 already trusts origin script that far |
| Application-origin script replaces the frame with a fake page | A fake page can't produce an assertion for the Authority RP ID. Worst case is a phishing UI that yields nothing |
| A registered origin other than the transaction's embeds the step-up page | `frame-ancestors` admits it, but the `topOrigin` check refuses and burns |
| An unregistered origin embeds the step-up page | `frame-ancestors` blocks it. The handoff gate also blocks it, since the handoff is scoped to the device and `cid` |
| Partitioned or blocked third-party cookies break the attempt session | Bearer token in frame memory, no cookies (above) |
| The frame becomes a relay for base attestation | Prohibited. The page's request set is fixed. Gate 8 needs a test that the person listener answers no base-attestation paths |

### Tests to add (gate 8 and gate 3)

- Assertion with `crossOrigin: true` and the correct `topOrigin` succeeds.
- Assertion with a wrong `topOrigin`, a missing `topOrigin` with
  `crossOrigin: true`, or a `topOrigin` present in popup mode fails and burns.
- The step-up page's `frame-ancestors` lists exactly the registered origins.
  Enrollment pages send `'none'`.
- The step-up page sends no `postMessage` and serves no base-attestation path.
- The attempt session works with third-party cookies blocked.
- Fallback to popup when `get()` is unavailable in the frame.
- Real-browser matrix: iframe and popup modes in Chrome, Safari, and Firefox,
  covering LNA prompts and delegation.

### Your task (round 2)

1. Update `SPEC-0.8.md` §5, §6 step 5, §7, §13, and §14 as above. Keep the popup
   as a supported mode. The user's text makes the iframe a MAY.
2. Add a ledger entry recording the user's requirement verbatim, the changes,
   and the new hash.
3. Don't change the base-attestation flow, the states, or the redemption
   semantics. The requirement says they stay as they are.

## Boundaries

- Edit only `SPEC-0.8.md` and `SPEC-0.8-CROSS-VERIFY.md`.
- Leave these unchanged:
  - `SPEC-0.8-CLAUDE.md`, `SPEC-0.8-CODEX.md`, `SPEC-0.8-CLAUDE-REVIEW.md`,
    and this file;
  - `SPEC.md`, code, tests, and other shared docs.
- Don't commit unless the user asks. The user previously asked for commits
  to go directly to `main`, with no PR.
- If a patch doesn't apply cleanly, or seems to conflict with another, don't
  improvise. Write the conflict into the ledger for the user and Claude.

---

## Round 3: iframe only, no popups (applied by Claude)

### User decisions

1. **"no popups. iframe only. unless thats a platform compat issue"**
2. After the platform check, **"update the spec and handoff"**. That instruction
   authorized Claude to edit `SPEC-0.8.md` directly for this round, as an
   exception to the earlier ownership rule.

The user's verified-session model from Codex's "Review 2 disposition" entry is
untouched. It supersedes Claude's V1 proposal, and Claude didn't revisit it.

### Platform check: iframe-only works

Checked 2026-10-06, primary sources where they exist.

- **Cross-origin iframe `get()` is supported in all three engines.**
  - Chrome/Edge 84+ and Firefox 118+ (web.dev).
  - Safari 15.5+: the WebKit STP 143 release notes say "Enabled using WebAuthn
    within cross-origin iframe elements"; WebKit bug 222240 is RESOLVED FIXED.
- **Safari conditions (WebKit bug 222240).**
  - Requires `allow="publickey-credentials-get"`.
  - Allows **only one cross-origin ancestor**.
  - Requires a user gesture and shows a consent prompt.
- **Safari reportedly omits `topOrigin`** in `clientDataJSON`. The only
  Apple-hosted evidence is Apple Developer Forums thread 782988 (May 2025),
  which has no Apple reply. No Apple release note or document mentions
  `topOrigin`. A secondary source (Corbado) says it's still omitted as of May
  2026. **This was the compatibility issue:** under the round-2 text, every
  Safari iframe assertion failed closed.
- **Registration (`create()`) can't run in a cross-origin frame on Safari.**
  That doesn't matter here, because enrollment is a top-level page the user
  visits directly.
- **Chrome LNA permission names (secondary sources).**
  - `local-network-access` in Chrome 142–144.
  - `local-network` (plus `loopback-network`) in Chrome 145+ and Firefox 153+.

### What changed in SPEC-0.8.md

Base hash `356262685d77e0610ab66c83f735f7cfc7828baf49d9f903ec6be31c71d1d411`
(Codex's review-2 disposition) → result
`1100138b0c30fa728a8f5326c8cb7a4815f0438a527c3528fdbd20be89a63c00`.

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

The following are unchanged; Claude checked §8 and §16 by hash against `938ab37`:

- §8 (states and deadlines) and §16 (hardening): byte-identical.
- The session model (§11) and the user's "Review 2 disposition".

### Codex's task (round 3)

1. Review Claude's round-3 edits against the user's decisions and the platform
   facts above. Check especially:
   - that accepting an absent `topOrigin` is safe **only** with per-RP
     `frame-ancestors` and the RP-path handoff check, and that both are
     normative;
   - that no popup or mode text remains;
   - that §11 and the session-model text weren't disturbed.
2. Add a ledger entry to `SPEC-0.8-CROSS-VERIFY.md` with:
   - the user's two quoted decisions;
   - the base and result hashes above;
   - V3 superseded (one mode);
   - V4 reversed (per-RP paths now required) and why;
   - this table.
3. If you disagree with any change, record it in the ledger for the user. Don't
   silently revert it.

Claude did not edit `SPEC-0.8-CROSS-VERIFY.md` this round.
