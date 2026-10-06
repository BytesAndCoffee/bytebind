# ByteBind Protocol 0.8 — Claude contribution

**Status:** Working draft for joint review; not implemented
**Draft:** 0.8, Claude contribution, 2026-10-06
**Baseline:** `SPEC.md` draft 0.7 at `3072234`
**Companion:** [SPEC-0.8-CODEX.md](SPEC-0.8-CODEX.md), as read on 2026-10-06
(574 lines, modified 15:47). Later edits there aren't reflected here.
**Inputs:** [Phase 1 proposal](../proposals/webauthn-step-up.md),
[THREAT-MODEL.md](../THREAT-MODEL.md)
**Copyright:** © 2026 Bytes & Coffee Digital Studio

## How to read this file

This file follows the editing rule in CODEX §1. Claude edits only this file.
Codex edits only `SPEC-0.8-CODEX.md`. Neither author edits `SPEC.md`, the code,
tests, or other shared documents until the drafts are reconciled.

Sections 1–15 use **the same numbers and topics as the Codex draft**, so the
two files can be compared section by section. Each section opens with one of:

- **Agree.** Adopt CODEX §N as written. Text below adds detail only, never a
  conflicting requirement.
- **Adopt with changes.** Adopt CODEX §N except for the changes listed.
- **Differs.** This section proposes a different requirement. The reason is
  given and the item appears in §15 for a decision.

Where this file is silent on a point, CODEX §N applies. §16 holds 0.8
candidates outside person step-up, numbered after Codex's last section so new
material in either file can't collide. If Codex later adds a §16, renumber
this one to the next free number; don't merge them.

Normative words follow CODEX §1: they describe the proposed protocol, not the
current implementation.

---

## 1. Editing and conformance

**Agree.** Conformance language, scope, and out-of-scope items as in CODEX §1.

## 2. Existing architecture and compatibility

**Adopt with changes.** The change concerns which transactions use v2 labels.

I accept CODEX's reading of 0.7 §30: making the release of `H2` depend on
person step-up changes attestation semantics, so those transactions MUST use
new labels. My Phase 1 proposal kept v1 labels and called it a reviewer
question. I withdraw that position.

Changes:

1. **v2 covers every 0.8 transaction an RP creates with `protocol: 2`,
   including `assurance: device`.** A device-only v2 transaction follows the 0.7
   flow with v2 labels and the v2 states in §8. An RP MAY keep creating v1
   transactions for device-only routes. Grant claims MUST say which protocol
   produced them (§10), so an RP never treats a v1 grant as carrying v2
   assurance.
2. **The challenge response says which protocol it uses.** It carries
   `protocol: 2` as a fourth member. 0.7 clients require exactly
   `{cid, C, authority}`. The reference `_client.py` and `bytebind.js` would
   refuse a v2 challenge outright, so a mixed deployment fails closed before
   any private request.
3. **Discovery** (CODEX §2, last paragraph; §16.1 here). The Authority
   advertises which protocols it supports in its node capability value
   (`"protocols": [1, 2]`). An RP MUST pin, per `cid`, the Authority that
   created it (ROADMAP 0.8) and MUST NOT select an Authority that doesn't list
   `2` for a v2 transaction. This advertisement is a filter, not a trust signal
   (THREAT-MODEL T-D1).

## 3. Independent device and person identities

**Agree.** CODEX §3 states the user's requirement precisely. I add one rule.

- An Authority implementation MUST NOT expose any configuration that maps a
  provider principal (Tailscale login, node owner, tag, `Sharer`, or any
  equivalent) to a `person_subject`. The prohibition must be unconfigurable;
  "off by default" is not enough. A deployment that wants a device-to-person
  restriction states it as policy over two independent facts (CODEX §3,
  third paragraph). It never derives one fact from the other.

## 4. Assurance policy

**Agree,** with one clarification about UP:

- An assertion made through a browser always sets UP, because WebAuthn L3
  `get()` has no silent mode. For `presence`, the Authority MUST still check
  the UP flag rather than assume it, and MUST request
  `userVerification: "discouraged"`. Requesting `"preferred"` would let the
  authenticator choose UV and make `presence` results vary by device without
  adding any guarantee.

## 5. Channels and browser context

**Adopt with changes.** Most of the changes add the browser facts and
constraints that this section's choices depend on.

### 5.1 WebAuthn RP ID is the exact host

The RP ID MUST be the exact hostname of the Authority's WebAuthn origin. It
MUST NOT be a parent domain. In the Tailscale profile, `ts.net` is on the
Public Suffix List (entries `ts.net`, `*.c.ts.net`, verified 2026-10-06), so
`<tailnet>.ts.net` is a registrable domain and would be a *valid* RP ID. But
every node in the tailnet can get a TLS certificate for its own name under that
domain. A page served from any such node could then invoke the Authority's
passkeys. The Authority's exact-origin check would reject the assertions, but
the user would still see a convincing prompt.

### 5.2 A separate web listener

The Authority's WebAuthn origin MUST be served by a listener separate from the
CORS attestation endpoint. It MAY share the hostname: RP IDs ignore ports. The
attestation endpoint answers CORS for every registered application origin,
while the web listener holds Authority sessions and MUST NOT answer CORS. The
web listener binds only to the overlay address and applies the 0.7 `Host`
check.

Page policy, in addition to CODEX §5's last paragraph:

- `frame-ancestors 'none'`.
- `Cross-Origin-Opener-Policy: same-origin` on enrollment and management pages.
- On the step-up page, either `unsafe-none`, which keeps the optional
  completion hint from CODEX §6, or `same-origin`, which drops the hint. If the
  hint is dropped, the application page finds out by detecting that the popup
  closed and then calling the result endpoint. Choosing between these is an
  open item, §15 C-5.

### 5.3 Browser facts the design depends on

Each fact below was verified on 2026-10-06 or is marked **unverified**.
Release gates in CODEX §14 MUST re-check them.

| Fact | Consequence |
|---|---|
| An application origin cannot call `get()` with the Authority's RP ID unless Related Origin Requests (ROR) are used | Option A (in-page prompt) is impossible without ROR |
| ROR: Chrome/Edge 128+, Safari 18+; Firefox **unverified** (sources conflict). At most 5 registrable domains. The file is fetched from `https://{rp_id}/.well-known/webauthn` on port 443 | ROR caps an Authority at 5 application domains. Every listed origin can raise the Authority prompt **at any time with its own challenge**, which defeats the "no prompt before base acceptance" property at the UI level. Assertions then pass through application JavaScript |
| Cross-origin iframe `get()`: Chrome 84+, Firefox 118+; Safari delegation **unverified** | An iframe pointing at an overlay host is a subframe navigation, which Chrome LNA covers. It also needs `allow="local-network-access"`. Clickjacking surface. Not chosen |
| `window.open` requires user activation in all browsers | The popup flow needs **one click** on the application page |
| `get()` needs no activation in Chrome; none in Safari 16+ (17.4+ with an internal rate limit) | The Authority popup can prompt right away when it loads |
| Chrome LNA (142+) prompts for fetch, subresources, and subframe navigations to private addresses, including `100.64.0.0/10`. Whether it covers top-level navigations and popups is **unverified** | Base attestation already crosses this boundary (T-B3). Whether the popup does needs a real-browser test |

**Consequence (conflicts with the requested UX):** person step-up in the
baseline design costs one user click. Device-only access stays ambient. This is
recorded as a limitation, not worked around (§15 C-1).

### 5.4 Full-page navigation fallback

**Differs from CODEX §5 and §6:** CODEX names controlled full-page navigation as
the fallback. I propose that 0.8 **not specify** a navigation fallback.
Navigating away destroys the page that holds `C`, `N`, and `H1`. Surviving the
navigation means either persisting those values in storage the application's
own scripts can read, or restarting the ceremony after return. Restarting means
a second base attestation, plus rules for carrying a person result across
transactions, and the binding rules in §7 forbid that carry-over. When a popup
is blocked, the client reports `popup_blocked` and the page asks the user to
click again. §15 C-2.

## 6. Proposed exchanges

**Adopt with changes.** I adopt CODEX's handoff and completion tokens in place
of my Phase 1 design, which put `cid` in the URL fragment and re-posted
`/attestation`. Separate one-use secrets are better than reusing `cid`, which
appears in many other messages.

Changes:

1. **The completion request proves possession of the base transcript.** In
   CODEX step 7 it carries `{cid, completion, N, H1}`. The Authority compares
   `N` and `H1` with its stored values in constant time and checks that the
   current socket peer resolves to the stored device. A completion token taken
   from the page but used elsewhere fails the peer check. One replayed from the
   same device without `N` and `H1` fails the transcript check.
2. **Handoff response shape.** The `/v2/attestation` response for a step-up
   transaction is HTTP **202** with exactly
   `{"step_up": {"url": "<authority web origin>/step-up", "handoff": "<b64url>", "completion": "<b64url>"}}`.
   The client builds `<url>#<handoff>`. The application page MUST open only a
   URL whose origin equals the configured Authority web origin. That origin is
   delivered with the challenge (§10), never taken from this response alone,
   so a compromised attestation response can't send the user elsewhere.
3. **Cancellation.** The Authority page MAY POST `/step-up/abort` with its
   attempt session. That burns the expected `stepup_pending` generation, as in
   CODEX §8.

## 7. Assertion and transcript binding

**Differs, on how the WebAuthn challenge is derived.** Everything else in
CODEX §7 is adopted, including the v2 label table.

CODEX uses a random 32-byte challenge tied to the transaction only through
server-side state. I propose:

```text
W = SHA-256( "bytebind/v2/person/challenge" || cid || H1 || w )      w = random(32)
```

The Authority stores `w` and `W` with the step-up attempt and sends `W` as the
WebAuthn challenge.

Rationale:

- **This is not a custom signature format.** `W` is an ordinary 32-byte
  challenge with the same randomness, carried and verified exactly as WebAuthn
  L3 §7.2 specifies. The only difference is how the Authority picks the value.
- **The authenticator's signature transitively covers the exact request.** `H1`
  commits to `N`, `cid`, and (in the transaction profile) `Q`. An archived
  `(clientDataJSON, authenticatorData, signature, w, cid, H1)` therefore proves
  that this credential approved this transaction's exact request. A random
  challenge proves it only together with the Authority's database.
- **Live security is the same as CODEX's design.** Verification still checks
  `challenge == W` from stored state. Single use still comes from the state
  transition.

If the reviewers prefer a purely random `W`, nothing else in either draft
changes. Only the audit property is lost (§15 C-3).

The new label `bytebind/v2/person/challenge` and the pairwise label in §10 join
the v2 label set. Neither reuses an existing label (0.7 §8).

**Signature counter** (refines CODEX §7): if both the stored and received
counters are non-zero and the received one isn't greater, the Authority MUST
refuse the assertion, burn the attempt, and flag the credential for operator
review. A zero counter (common for synced passkeys) is accepted.

## 8. States, deadlines, and failures

**Adopt with changes.** I adopt CODEX's states, generations, and failure table.
The change is when the redemption deadline starts.

CODEX starts the 10-second redemption window when the transaction becomes
`redeemable`, which happens at assertion acceptance. But the application page
learns of success only after the popup closes or sends its hint, and it then
needs a completion round trip before it can compute `R`. Someone who lingers
on the closing popup, or a slow overlay link, could miss the window.

Proposed change:

- On assertion acceptance, `stepup_pending → redeemable`, recording
  `result_ready_at`. The **completion-collection deadline** is `result_ready_at`
  plus 30 seconds.
- On successful completion, set `result_delivered` once, and start the 10 s
  **redemption deadline at delivery**.
- Completion after its deadline burns the transaction.

This keeps the 0.7 property: the redeem window starts when `S` becomes
available to the client. (In 0.7, that's the `H2` response.) §15 C-4.

## 9. Subjects, enrollment, and credential management

**Adopt with changes.** I adopt CODEX §9 and add a concrete operator-authorized
enrollment mechanism. CODEX allows either operator authorization or an explicit
self-enrollment policy; this mechanism satisfies the first.

**Enrollment invite.** The operator creates a subject, or picks an existing one,
and issues an invite:

- 32 random bytes, stored only as SHA-256;
- single use, 15-minute deadline (configurable, at most 24 hours);
- bound to one subject and to a purpose (`new_subject` or `add_credential`).

Redeeming the invite requires all of these:

- a connection that passes the enrollment device policy (CODEX §9);
- the exact Authority web origin;
- a registration challenge issued after the invite is redeemed.

Delivering the invite to the person is out of band and is part of the
operator's identity-proofing process. ByteBind makes no claim about it.

**Audit context.** An enrollment record MAY store the provider identity and
reported owner of the enrolling device, as audit data only (§3). This data
MUST NOT be used in any later authorization decision.

**Self-enrollment** (CODEX §9's alternative), if enabled, MUST create subjects
flagged `self_enrolled`. An Authority MUST NOT release such subjects as
`person_subject` to an RP unless that RP's registration explicitly accepts
self-enrolled subjects, so a self-asserted identity is never presented as an
operator-vetted one.

**Library-independent registration checks** (in addition to CODEX §9):

- `residentKey: "required"` and `userVerification: "required"`.
- `excludeCredentials` lists the subject's existing credentials.
- `attestation: "none"` by default. If an AAGUID allowlist is configured,
  `"direct"` with the allowlist enforced.
- `user.id` is the subject's random handle. `user.name` and `displayName` are
  operator labels and MUST NOT contain the provider principal.

Optional policy `allow_synced = false` refuses credentials whose
backup-eligible flag is set, at registration and at assertion. The default is
`true`, because most platform passkeys set that flag.

## 10. Grants and selective disclosure

**Adopt with changes.** I adopt CODEX's top-level `assurance` object and its
disclosure rules. Changes:

1. **Protocol marker.** A v2 grant MUST include `"protocol": 2`. An RP MUST
   treat a grant without it as v1, which carries no assurance.
2. **Pairwise subject construction**, the "stable within the RP's namespace"
   identifier of CODEX §10:

   ```text
   person_subject = "ps_" || b64url( HMAC-SHA256( pairwise_key, "bytebind/v2/pairwise" || rp_id || subject_id ) )
   ```

   - `pairwise_key` is 32 bytes held only by the Authority.
   - `rp_id` is UTF-8 and length-prefixed as in 0.7 §9.2.
   - Rotating the key changes every pseudonym, which an operator must
     announce to RPs.

   A global subject name requires `subject_name` in the RP's disclosure list.
3. **Age disclosure.** When an RP is permitted `person_age`, the grant includes
   `assurance.age` as whole seconds since authentication. It is 0 for a fresh
   assertion. After the first 60 seconds it is rounded down to a multiple of
   60. It is never an absolute timestamp (0.7 §13.2).
4. **Challenge carries the Authority web origin** (supports §6, change 2). The
   control-channel transaction response, and the browser challenge for v2,
   include `person_origin` when the transaction requires `presence` or
   `verification`. The Authority sets it from its configuration. An RP MUST NOT
   alter it.

## 11. Sessions, freshness, and shared devices

**Differs**, on what happens when person evidence expires during a session.
Everything else in CODEX §11 is adopted, including:

- reuse handles held per browser lease;
- reuse never resets the authentication time;
- grants are bounded by the remaining person age;
- background renewal never prompts.

In CODEX, expired person evidence ends the person lease. I propose that the
lease **steps down to device-only**:

- When reuse is refused for age, revocation, or a different device, the
  renewal grant omits the person assurance. The RP keeps the browser lease at
  device assurance and discards the reuse handle.
- Routes requiring only `device` keep working. Routes requiring `presence` or
  `verification` answer 401 with `X-ByteBind-Required: verification` (or
  `presence`), and the page offers the step-up button.
- This matches the requirement that ordinary routes keep ambient behavior while
  sensitive ones prompt deliberately. Ending the whole lease would force a
  person ceremony to reach device-only pages after the person age expires.

A **subject switch** (CODEX §11) also replaces the lease, as CODEX requires.
A step-down never keeps a previous subject's identity claims on the lease.

## 12. Developer, operator, and API behavior

**Adopt with changes.** I adopt CODEX's structured assurance, its keyword name
`assurance=`, and its API-client rule: a typed error and no bypass. I'm
withdrawing my Phase 1 spelling `user=` so the API has one name.

Additions:

```python
@bind(require=["tag:interactive"])                                                 # device
@bind(require=["tag:interactive"], assurance="presence")                           # + UP
@bind(require=["tag:interactive"], assurance="verification", person_max_age=600)   # + UV, bounded age
@bind(require=["tag:interactive"], assurance="verification", identify=True)        # + person_subject
@bind(require=["tag:interactive"], grant=bind.TRANSACTION, assurance="verification")  # fresh per request
```

The binding MUST raise at decoration time for any of these:

- `person_max_age` without `assurance` of `presence` or `verification`;
- `person_max_age` combined with `grant=TRANSACTION` (always fresh);
- an unknown assurance value;
- `identify=True` with `assurance="device"`.

The Python API-client error type is `StepUpRequired(ClientError)`. It carries
no URL, handoff, or completion token, so a caller can't hand those to
something else.

## 13. Threat-model delta

**Agree** with CODEX §13. Additional rows for THREAT-MODEL.md:

| Threat | Treatment |
|---|---|
| A tailnet sibling node phishes the Authority passkey | Exact-host RP ID (§5.1) |
| ROR re-enabled later lets any listed origin raise prompts at will | ROR out of baseline (§5.3). Any future ROR profile must restate the base-first property as a property of assertions, not of prompts |
| Lost hint or slow closing popup makes the redemption deadline expire | Redemption deadline starts at completion delivery (§8) |
| Self-enrolled identity presented as vetted | `self_enrolled` flag and per-RP acceptance (§9) |
| Provider-principal-to-subject mapping added later as a "convenience" | Prohibited and unconfigurable (§3) |
| Cloned authenticator | Counter regression refused and flagged (§7) |
| Pairwise key compromise | Pseudonyms become linkable; key 0600, Authority-only; rotation procedure (§10) |
| Timing correlation from `assurance.age` | Rounded to 60 s and released only when permitted (§10) |

Effect on existing threats (for THREAT-MODEL.md once reconciled):

- **T-B1** (script on the RP origin) is *reduced for person-gated routes*. Such
  a script can start a step-up but can't complete one without a person at the
  Authority page.
- **T-B2** (unattended sessions) is bounded by `person_max_age`.
- **T-TS2** (tagged devices lose user identity) gains a person identity that's
  independent of tags.
- **T-PR1** (the RP learns the device's tailnet IP) is unchanged, since v2 keeps
  `IP || S`. §16.4 proposes a fix.

## 14. Implementation and verification plan

**Adopt with changes.** I adopt CODEX §14. Library candidates for its
evaluation, as checked on 2026-10-06:

| Library | Version | Dependencies | Notes |
|---|---|---|---|
| `fido2` (Yubico python-fido2) | 2.2.1, Python ≥3.10 | `cryptography` only (ByteBind already requires it) | `Fido2Server` enforces UV when required and takes a `verify_origin` callback. It **doesn't** check the signature counter, so §7's counter rule is ByteBind code, an integer comparison |
| `webauthn` (Duo py_webauthn) | 3.0.1 | `cryptography`, `cbor2`, `pyOpenSSL`, `pyasn1`, `pyasn1-modules` | Larger dependency footprint |

My preference is `fido2`, installed as an Authority-only extra
(`bytebind[webauthn]`). RP bindings and API clients get no new dependencies.

Test fixtures:

- WebAuthn L3 §16 test vectors for parsing and verification.
- A test-only software authenticator that *signs* fixtures with
  `cryptography`. It produces fixtures; it doesn't verify.
- The CDP virtual authenticator for the headless-Chromium layer.
- These supplement, and don't replace, CODEX §14's real-authenticator matrix.

New v2 vectors MUST cover `W` (§7) and `person_subject` (§10) in addition to
CODEX's list.

## 15. Open decisions

CODEX §15's items 2–9 stand. Item 1 (reconciliation) is addressed by this
file. These are the points where the two drafts **differ** or where this file
adds a decision:

| # | Decision | CODEX | This draft |
|---|---|---|---|
| C-1 | One-click step-up UX vs. ROR in-page prompt | Authority page; ROR needs separate review | Same; adds browser facts and ROR's 5-domain and prompt-anytime limits (§5.3) |
| C-2 | Full-page navigation fallback | Specified as fallback; resume mechanics open | Don't specify in 0.8; report `popup_blocked` (§5.4) |
| C-3 | WebAuthn challenge derivation | Random, linked by server state | `W = SHA-256(label ‖ cid ‖ H1 ‖ w)` for audit binding to `Q` (§7) |
| C-4 | When the 10 s redemption deadline starts | At `redeemable` (assertion accepted) | At completion delivery; 30 s collection deadline (§8) |
| C-5 | Step-up page COOP / completion hint | Optional hint with strict checks | Same, or drop the hint and use popup-closed detection (§5.2) |
| C-6 | Person evidence expiry in a session | Lease ends | Lease steps down to device-only (§11) |
| C-7 | v2 scope | v2 for the step-up flow | v2 for every 0.8 transaction an RP creates as v2, including device-only; v1 stays available (§2) |
| C-8 | Self-enrolled subjects | Allowed under explicit policy | Allowed, but flagged and released only to RPs that accept them (§9) |
| C-9 | Library | Not selected | `fido2` preferred (§14) |
| C-10 | Scope of 0.8 beyond person step-up | Not addressed | §16 candidates |

Agreed between the drafts, and not open:

- person identity is independent of provider identity;
- base acceptance comes before any options or prompt;
- the Authority owns credentials;
- there is no downgrade;
- transitions are atomic and single use;
- transaction-bound step-up is always fresh;
- headless clients get a typed error with no bypass;
- the Authority page is the baseline browser context.

---

## 16. Additional 0.8 candidates (outside person step-up)

This section has no counterpart in the Codex draft (C-10). Each item comes from
THREAT-MODEL.md or ROADMAP.md and is independent of the person step-up. Any of
them can be accepted, deferred, or dropped without affecting §§1–15.

### 16.1 Authority discovery and pinning (ROADMAP "Draft 0.8")

- An RP that discovers its Authority MUST record, per `cid`, the endpoint that
  created it, and MUST send redemption only to that endpoint (T-D3).
- Discovery MUST NOT be the only source of trust in production. An RP SHOULD
  pin the Authority by stable node ID or by configuration. A deployment that
  relies only on tags or capabilities accepts that whoever owns the tag can
  issue grants (T-D1).
- Capability values MAY include `protocols` (§2, change 3). An unknown member makes
  the candidate invalid.

### 16.2 Authenticating the Authority on a local socket (T-D2)

Over a Unix domain socket, an RP MUST verify the Authority's peer credentials
on every connection, using `SO_PEERCRED`, `getpeereid`, or `LOCAL_PEERCRED`,
against a configured Authority UID. It MUST also verify that the socket's
directory is owned by root or that UID and is not group- or world-writable. A
socket path that merely exists is not an authenticated Authority.

### 16.3 Ambient state on transaction replay (T-R4)

When an RP executes a stored transaction-bound request, it MUST authorize it
using only the stored request (method, target, covered headers, body), the
grant, and RP-held state bound to the stored request at creation. It MUST NOT
use credentials, cookies, or headers from the proof submission. An RP that
needs application credentials for the operation binds them at creation time.
Either it adds them to the covered headers, which changes `Q`, or it records the
application principal with the stored request.

### 16.4 Selective disclosure of the attested address (T-PR1)

In v2, the client learns `IP` from `H2`, and in browser deployments the
client's code comes from the RP. Two options:

- **(a)** Leave it as is, and say in §19 that RPs learn the device's overlay
  address.
- **(b)** v2 replaces `IP` in `P` and in `R` with
  `IPB = HMAC-SHA256(S, "bytebind/v2/ip" || IP)`. The redemption check still
  binds the attested address, but the client never learns it.

Option (b) changes v2 transcripts and must be decided before v2 vectors are
frozen. I recommend (b), because v2 is new and this is the only point at which
it's free.

### 16.5 Cookie naming (T-R3)

Bindings SHOULD name their cookies `__Host-bytebind_session` and
`__Host-bytebind_state`, with `Path=/`. This is a binding-profile
recommendation, not a wire change.
