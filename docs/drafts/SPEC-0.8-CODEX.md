# ByteBind Protocol 0.8 — Authority-Owned Person Step-Up

**Status:** Working draft for joint review; not implemented  
**Draft:** 0.8, Codex contribution, 2026-10-06  
**Baseline:** `SPEC.md` draft 0.7 at `307223480d23445e51366484721df60df3eb5d17`  
**Copyright:** © 2026 Bytes & Coffee Digital Studio

## 1. Editing and conformance

This is a separate candidate specification so Claude and Codex can work in the
same checkout without overwriting each other's work. Codex's changes for this
contribution are confined to this file. `SPEC.md`, implementation, tests,
README, threat model, roadmap, and blog remain separate integration targets.
Claude's parallel [Phase 1 proposal](../proposals/webauthn-step-up.md) is a
separate input. Its summary and architecture were inspected for coordination;
its full design is not presumed reviewed or incorporated here.
Reconciliation SHOULD compare requirements by the section numbers below rather
than replace either author's draft wholesale.

MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY express requirements of the proposed
protocol. They do not claim that the reference implementation supports them.
Sections marked **OPEN** require resolution before implementation or a
conformance claim. Endpoint names and binding syntax are provisional; security
requirements are independent of those spellings.

This draft adds optional Authority-owned passkey enrollment and person step-up
after successful private device attestation. It does not define federation,
OIDC/SAML integration, an authenticator, or arbitrary third-party passkey RP IDs.

## 2. Existing architecture and compatibility

The current Authority owns transactions and provider authorization;
`store.py` persists `pending`, `attested`, `redeemed`, and `burned` states.
`authority.py` validates the private request and returns encrypted `H2`, then
selectively releases claims during authenticated RP redemption. `rp.py` owns
application attempts, leases, and stored transaction requests. `binding.py`
requires every route requirement to match disclosed tags or authorization.
The browser and Python clients perform the same base proof ceremony. Discovery
selects and pins an Authority for a transaction.

Step-up attaches between base authorization and release of `H2`. The RP MUST
NOT verify WebAuthn assertions, store credentials, or operate enrollment.
The Authority owns the WebAuthn RP ID, origins, challenges, credentials,
subject associations, verification, management, and claim disclosure.

The unchanged base-only v1 protocol remains available under draft 0.7.
The new step-up flow uses a proposed **v2** protocol because it changes
attestation states, response variants, and completion semantics. This follows
0.7 section 30 rather than reinterpreting v1. A 0.8 implementation MAY also
implement v1. No v1 request may satisfy a v2 step-up requirement.

An RP MUST select the protocol explicitly on the authenticated control channel.
Unsupported protocol or assurance requests MUST fail; neither client nor server
may retry them as base-only authorization. Discovery MUST retain Authority
pinning and verify support before using a candidate. Capability advertisement
alone is not authorization or evidence of policy equivalence.

## 3. Independent device and person identities

**Person identity MUST be independent of provider/device ownership identity.**
A provider may report an account, owner, or principal associated with a device,
but ByteBind MUST NOT treat that as equivalent to the person presently
participating in the transaction. WebAuthn person attestation allows shared
devices, kiosks, tagged service devices, and other multi-user endpoints to
establish the current human subject independently of the device's overlay
identity.

A `person_subject` is an Authority-managed subject associated with registered
credentials. A `device_id` is a provider-managed endpoint identity. The two
namespaces MUST remain distinct in storage, policy, and grants. Provider owner
metadata MUST NOT populate `person_subject`, authorize attachment of a new
credential to an existing person, or select the current person automatically.

One subject MAY have multiple credentials and use multiple authorized devices.
One authorized device MAY be used by multiple subjects. Enrollment on a device
MUST NOT intrinsically bind a credential to that device. Operator policy MAY
require an explicit subject/device pairing; that restriction does not equate
the identities. Synced credentials are permitted.

Device authorization, credential-authenticated subject, user presence (UP),
and user verification (UV) are separate facts. Subject disclosure is a separate
policy decision from requiring participation. Civil identity and informed
transaction intent are outside this profile's WebAuthn guarantees.

The device-only IdP discussion in 0.7 section 18 does not authorize interpreting
a provider's human-account mapping as the currently participating person.
Any future bridge MUST preserve this distinction; federation remains out of scope.

## 4. Assurance policy

Each v2 transaction stores an immutable assurance requirement accepted from the
authenticated RP and constrained by its Authority registration:

| Requirement | Meaning |
|---|---|
| `device` | Base provider authorization only |
| `presence` | Base authorization plus a current credential assertion with UP |
| `verification` | Base authorization plus a current assertion with UP and UV |

Presence and verification both resolve a credential's subject internally.
Neither requires disclosing that subject to the RP. Person authorization, such
as membership in an operator-managed subject set, MAY be required in addition.
UV implies the required UP check; a presence result MUST NOT satisfy verification.

For transaction-bound requests, presence or verification MUST be fresh for that
specific transaction. No cached person evidence satisfies that requirement.
For session grants, a registration MAY permit bounded reuse under section 11.

The RP MUST bind the assurance requirement to the selected route before creation
and preserve it with the stored operation or lease attempt. A browser-supplied
assurance level is not authoritative. The Authority MUST enforce the accepted
requirement before issuing a grant, and the RP MUST check the returned assurance
before executing the operation or allowing the route. Missing required evidence
fails closed. Static `authorization` strings MUST NOT manufacture person evidence.

## 5. Channels and browser context

Base attestation retains 0.7's private direct connection, socket-derived peer,
registered application Origin, exact Host, JSON, CORS, and provider-policy checks.
The authenticated private control channel remains separate from browser traffic.

The proposed deployment uses one stable, private HTTPS Authority origin for
WebAuthn enrollment and authentication. Its WebAuthn RP ID is that origin's
hostname, without a scheme or port. Changing that hostname requires a credential
migration plan; discovery does not make credential namespaces interchangeable.
Operators MUST configure exact allowed WebAuthn origins, independently of the
registered application origins.

WebAuthn runs in an Authority-owned top-level page. Arbitrary application
JavaScript cannot use the Authority's RP ID directly. A user-activated popup is
the preferred initial UX; controlled full-page navigation is the fallback.
Neither is claimed tested across browsers. Ordinary device-only access remains
ambient; optional person step-up may require an explicit action and visible
Authority page. Background renewal MUST NOT automatically open a popup or invoke
a person ceremony.

An iframe or related-origin design is an alternative requiring separate review;
neither is a baseline dependency. WebAuthn defines RP-ID/origin rules and
related-origin mechanisms; this draft chooses an Authority page to keep
credential operations under Authority control. See [WebAuthn origin and RP-ID
rules](https://www.w3.org/TR/webauthn-3/#sctn-rp-id) and
[related origins](https://www.w3.org/TR/webauthn-3/#sctn-related-origins).

Authority credential pages MUST reject framing, use a restrictive CSP, avoid
third-party scripts, suppress referrers, and disable caching. Same-origin POSTs
MUST validate exact Origin and an attempt-bound CSRF token. Cookies MUST be
Secure, HttpOnly, and scoped narrowly; cookie presence alone never authorizes
step-up or enrollment.

## 6. Proposed exchanges

The paths below describe the candidate v2 interface. All opaque tokens use
canonical unpadded base64url and a cryptographically secure generator.

1. RP creates a v2 transaction over the authenticated control channel with
   audience, profile, optional `Q`, and assurance requirement. Authority stores
   those values, RP identity/origin, secrets, and server deadlines. RP forwards
   `protocol`, `cid`, `C`, and Authority URL, without browser expiry fields.
2. Client computes v2 `H1` and sends it with `cid` and `N` to the private
   `/v2/attestation` endpoint from the application's registered origin.
3. Authority performs the base checks in 0.7 section 11.1, atomically records
   the accepted device and immutable ceremony inputs, and either completes
   device-only attestation or prepares a person handoff. A failed base check
   MUST NOT issue a handoff, WebAuthn options, or a prompt instruction.
4. For fresh person step-up, Authority returns a `step_up_required` variant
   with a one-use 32-byte handoff token and a separate 32-byte completion token.
   Both are scoped to this `cid`, originating RP, and accepted device.
   It MUST NOT return `H2` or expose `S` at this stage.
5. Following explicit user activation, the browser opens the fixed Authority
   page, passing the handoff token in a URL fragment. That page removes the
   fragment immediately and exchanges it in a same-origin JSON POST. Authority
   re-attests its socket peer, requires the same provider/device identity as
   the base attempt, and atomically consumes the handoff. Only then may it
   issue WebAuthn options and an attempt-bound Authority session.
6. Authority page performs the assertion and posts the result directly to the
   Authority. Verification and the state transition in sections 7–8 must finish
   durably before success is reported.
7. The application browser retrieves `H2` using the separate completion token
   in a JSON POST to `/v2/attestation/result`. This endpoint checks original
   RP Origin, Host, current private peer identity, and stored `cid`, `N`, `H1`.
   It never trusts a popup's success message. Pending responses contain no
   proof material. A completed result is released at most once.
8. Client decrypts `H2`, computes v2 `R`, and submits it to its RP. RP consumes
   its attempt binding, redeems with the creating Authority, checks grant scope
   and required evidence, and creates a lease or executes only the stored request.

The Authority page MUST NOT pass credential IDs, assertions, or `H2` to the
application through `postMessage`. An optional completion notification MUST
validate exact origin, source window, and attempt correlation; it is only a
hint to fetch the actual result. No return URL from a client may override the
RP's registered origin. For navigation fallback, the application MUST preserve
its own attempt binding and client proof inputs without putting secrets in a
query string. Exact resume mechanics remain an implementation gate.

Handoff and completion tokens are bearer secrets, not person or device identity.
They MUST NOT be logged or included in analytics. A stolen token without the
required private device context MUST NOT authorize a ceremony or result retrieval.
Private paths inherited through compromised devices remain a trust limitation.

```mermaid
sequenceDiagram
    participant B as Application browser
    participant RP as Application RP
    participant A as Private Authority
    participant W as Authority page / authenticator
    B->>RP: Request protected route
    RP->>A: Begin v2, immutable assurance and Q
    A-->>RP: Scoped challenge
    RP-->>B: cid, C, Authority, protocol
    B->>A: Private base attestation: cid, N, H1
    A->>A: Validate origin, peer, provider, policy; commit base acceptance
    alt Fresh person evidence required
        A-->>B: Handoff and completion tokens; no H2
        B->>W: User opens Authority page
        W->>A: Exchange handoff; recheck private device
        A-->>W: Transaction-scoped WebAuthn options
        W->>A: Assertion from Authority origin
        A->>A: Verify credential and assurance; commit redeemable
        B->>A: Retrieve result with completion token
    end
    A-->>B: H2 only when redeemable
    B->>RP: cid, R
    RP->>A: Authenticated redemption
    A-->>RP: Scoped grant with permitted evidence
    RP->>RP: Check route; lease or execute stored operation once
    RP-->>B: Application result
```

## 7. Assertion and transcript binding

The Authority generates a unique random 32-byte WebAuthn challenge only after
base acceptance. Its record maps that challenge to exactly one `cid`, generation,
RP, audience, profile, `Q` if present, accepted device, `N`, `H1`, assurance,
Authority RP ID/origin, and deadline. These fields MUST NOT change after options
are issued. Server-side challenge association supplies transaction binding;
no custom WebAuthn signature format is introduced.

For verification, request options MUST set `userVerification` to `required`;
the Authority MUST still verify the returned flags. Options are not evidence.

Authentication MUST follow [WebAuthn assertion verification](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion): validate type, challenge, origin, RP-ID hash,
credential ownership, signature, and required UP/UV. This baseline rejects
cross-origin ceremonies. Resolve the subject from Authority credential records;
validate user handle when applicable. Apply the standard's signature-counter
and backup-state handling rather than assuming every counter must increase.
Registration follows [WebAuthn registration verification](https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential).

An assertion is acceptable only while its linked transaction and base context
remain valid. Credential and subject status MUST be checked at acceptance and
redemption. Challenge consumption, credential-version checks, and transition to
redeemable MUST be atomic with respect to revocation. No write lock may be held
while waiting for the browser, provider, or authenticator.

V2 retains 0.7's fixed-size values, algorithms, `IP || S` plaintext, request
encoding, and profile separation, but replaces EVERY transcript label:

| Purpose | Session | Transaction-bound |
|---|---|---|
| H1 | `bytebind/v2/h1` | `bytebind/v2/tx/h1` |
| HKDF info and H2 AAD prefix | `bytebind/v2/h2` | `bytebind/v2/tx/h2` |
| Redemption | `bytebind/v2/redeem` | `bytebind/v2/tx/redeem` |
| Request digest | Not applicable | `bytebind/v2/tx/request` |

All formulas and field lengths otherwise follow 0.7 sections 9.2 and 11–13.
In particular `Q` is computed by the client from its actual submitted operation.
The attested assurance is bound through immutable Authority state referenced by
`cid`; the client never supplies authoritative assurance claims. Implementations
MUST NOT accept mixed v1/v2 labels or infer a version from a successful MAC.
New machine-readable vectors are required before freezing v2.

## 8. States, deadlines, and failures

| State | Permitted next state | Condition |
|---|---|---|
| `pending` | `base_attested` | All base checks and conditional update succeed |
| `base_attested` | `stepup_pending` | One handoff accepted; fresh options issued |
| `base_attested` | `redeemable` | Device-only requirement, or authorized session evidence reuse |
| `stepup_pending` | `redeemable` | Assertion and subject policy succeed atomically |
| `redeemable` | `redeemed` | Correct RP-scoped proof consumed atomically |
| Any live state | `burned` | Applicable failure, cancellation, or expiry |

`stepup_attested` is a logical event in the atomic transition to `redeemable`;
no separate externally observable state is necessary. Result delivery has a
separate one-use flag and does not extend the redemption deadline.

Each update MUST match expected state AND attempt generation. A race loser
MUST NOT burn a winning attempt's later state. Burns and success transitions
MUST commit before a response, including exception paths. Only one WebAuthn
challenge may be outstanding per `cid`; retry requires a new ByteBind transaction.

Proposed defaults for review: 30 seconds to establish base authorization,
120 seconds from base acceptance to finish person step-up, and 10 seconds from
becoming redeemable to redeem. RP attempt retention MUST accommodate the selected
flow; the initial v1-style short deadline cannot remain unchanged for v2 step-up.
Authority returns relative control-channel durations, never browser authorization
expiry. No deadline is extended by polling, handoff, or failed verification.

Base acceptance for step-up has its own bounded deadline. Before issuing options,
accepting an assertion, and delivering a result, Authority MUST confirm current
private device identity and applicable provider policy. If the base deadline
expires, no later assertion revives it. A fresh attempt starts with fresh base
attestation. Policy change at redemption MUST also refuse obsolete authorization.

| Event | Required behavior |
|---|---|
| Foreign Origin/Host | Reject before transaction access or mutation |
| Base validation failure after lookup | Burn only the expected pending generation |
| Wrong handoff/completion secret | Reject without mutating an unrelated attempt |
| Invalid assertion, missing required UV, disabled subject, revoked credential | Burn the authenticated expected step-up generation |
| Cancellation received from bound Authority page | Burn expected generation; issue no grant |
| Browser cancellation without notification or browser disappearance | Server deadline burns/expires attempt |
| Concurrent options/assertions | One conditional winner; others receive generic refusal |
| Step-up succeeds but result delivery is lost | No new secret or operation retry; start a new attempt only under application retry policy |
| Wrong RP tries redemption | Refuse without burning the legitimate RP's transaction, as in 0.7 |
| Bound RP submits invalid redemption | Burn expected redeemable generation |
| Successful redemption response is lost | Remain consumed; operation outcome may be unknown |

The transaction-bound RP MUST still execute at most once and never automatically
retry a possibly executed operation. WebAuthn does not provide distributed
exactly-once execution. Every intermediate state counts toward bounded per-RP
and per-device outstanding work; provider/verification work is rate limited.

## 9. Subjects, enrollment, and credential management

Authority storage separates these records:

| Record | Required associations and data |
|---|---|
| Subject | Opaque subject ID, random WebAuthn user handle, status, policy memberships, revocation generation |
| Credential | Subject ID, credential ID/public key, accepted algorithm, verification metadata, counter/backup state, friendly name, status/version |
| Enrollment attempt | Accepted private context, authorized target subject or new-subject permission, challenge, origin/RP ID, deadline, one-use generation |
| Step-up attempt | Immutable transaction linkage from section 7, tokens stored as hashes, assertion challenge, accepted credential/version |
| Reusable person evidence | Opaque handle, subject/credential generations, RP/audience, device context, assurance, original authentication time and deadline |

The Authority MUST NEVER receive or store credential private keys. Credential
identifiers and user handles are Authority-private and MUST NOT appear in RP
grants. Device observations MAY be recorded separately with bounded retention;
they are not credential ownership records. Names are untrusted display strings.

Enrollment MUST first establish a privileged base context under a dedicated
enrollment policy. Authorization to use an ordinary application is insufficient.
Base authorization allows entry into enrollment; it does not prove which existing
person's credential set may be changed.

Creating a new subject requires explicit operator-authorized enrollment or an
explicit self-enrollment policy. Attaching a credential to an existing subject
requires fresh authentication with an existing credential plus authorization to
manage that subject, or a separately controlled recovery procedure. A supplied
name, provider owner, device tag, or bare subject ID MUST NOT suffice.
New-subject enrollment MUST NOT merge subjects by display name or provider owner.

Registration and credential changes require one-use challenges, exact Authority
Origin checks, CSRF protection, device-policy revalidation, and bounded lifetimes.
For this profile registration SHOULD require UV and discoverable credentials;
otherwise identifying a person on shared devices needs a reviewed alternative.
Default authenticator attestation conveyance SHOULD be `none`; collecting device
provenance is not necessary for these ByteBind claims.

The Authority UI supports register, name, list, and revoke. Existing-subject
management requires fresh verified subject authentication. An operator recovery
interface MUST authenticate its operator independently, audit changes, and
invalidate affected evidence. If recovery has no approved design, recovery is
disabled; it MUST NOT fall back to provider ownership. Revoking the last credential
MAY leave the subject unable to authenticate until an authorized recovery.

Revocation invalidates pending step-ups and reusable evidence. Already issued RP
leases remain valid only until their bounded deadlines unless an independently
authenticated revocation channel is implemented. This draft promises no immediate
revocation of an offline RP lease.

## 10. Grants and selective disclosure

A v2 grant retains `active`, `rp_id`, `audience`, relative `expires_in`, and
`claims`. It additionally returns structured assurance evidence needed to enforce
the accepted requirement. The example is illustrative, not a finalized schema:

```json
{
  "active": true,
  "rp_id": "moderation",
  "audience": "manage",
  "expires_in": 180,
  "assurance": {
    "device_attested": true,
    "user_present": true,
    "user_verified": true,
    "fresh_for_transaction": true
  },
  "claims": {"tags": ["tag:interactive"]}
}
```

Required assurance booleans may be released without a person identifier. An RP
requesting identity MUST be registered for `person_subject` disclosure; absence
of permission is a creation-time failure if identity is required. Default person
identifiers SHOULD be stable only within the authenticated RP's namespace.
Global identifiers require explicit operator disclosure policy. Claim omission
MUST NOT become implicit permission, and a public client cannot select disclosure.

The Authority MUST NOT release credential IDs, public keys, user handles, raw
assertions, authenticator data, or provider owner metadata as person evidence.
The RP consumes the grant under its authenticated control-channel trust; this
draft does not introduce independently verifiable bearer identity tokens.

## 11. Sessions, freshness, and shared devices

Device-only sessions keep the existing fixed renewal cadence and bounded leases.
A person session records its subject association at the Authority even when the
RP is not allowed to receive the subject. Session evidence never derives from a
device-wide "last person" cache.

Default person-session behavior requires fresh step-up when issuing a new person
lease. Operators MAY permit silent renewal using an opaque Authority evidence
handle supplied only through the RP's authenticated control channel. The RP
stores that handle under the specific server-side browser lease; a new client or
another session on the same device cannot inherit it.

Reused evidence MUST match the RP, audience, provider/device identity, assurance,
active subject/credential generations, and the originally established session.
Every renewal still requires successful base attestation. Reuse MUST NOT update
the original person-authentication time, upgrade UP to UV, or satisfy a fresh
transaction requirement. Subject switching requires fresh step-up and replacement
of the browser lease and associated evidence.

The operator configures a finite maximum person-authentication age; the RP MAY
request a stricter limit. Authority bounds the renewed grant by BOTH the device
lease lifetime and remaining permitted person age. Near that deadline a grant MAY
be shorter than v1's 90-second session minimum. Expired person evidence cannot
be renewed by device authorization alone. Background renewal reports that explicit
step-up is needed; it does not prompt automatically.

The Authority uses its own clock for authentication age and returns only relative
remaining authorization duration to the RP. Absolute authentication timestamps
are not required. RP route checks use stored evidence deadlines; possession of a
cookie is insufficient. Evidence reuse handles are secrets and cannot be shared
between otherwise unrelated browser sessions.

On a kiosk, operators SHOULD disable reuse or require fresh transaction step-up
for sensitive operations and provide explicit session termination. A copied or
unended browser lease remains usable for its bounded lifetime, just as a copied
base lease does. Silent renewal establishes device participation, not that the
same person is still physically using the endpoint.

## 12. Developer, operator, and API behavior

Proposed binding syntax separates tags from structured assurance. It is not an
implemented Python API:

```python
@bind(require=["tag:interactive"], assurance="verification", person_max_age=300)
def verified_admin(): ...

@bind(require=["tag:interactive"], mode="tx", assurance="verification")
def destructive_operation(): ...  # always fresh for this operation
```

All current `require` values remain AND requirements. A plain authorization
string named `webauthn:uv` MUST NOT be treated as verified evidence. The smallest
coherent extension is structured assurance alongside existing claim requirements,
with the framework carrying it into creation and grant checks. Subject release
is an independent binding/registration option.

Operator configuration needs a stable Authority RP ID/origin, supported assurance
per RP/audience, person-disclosure permissions, allowed subject policies,
enrollment/recovery authority, maximum person age, and optional reuse permission.
Required route tags must still be permitted by provider policy and disclosed.
Devices tagged both interactive and automated may use either permitted route;
WebAuthn does not manufacture missing device tags.

Existing HTTPX and requests clients continue base-only operation. A headless
client encountering a fresh person requirement MUST receive a typed unsupported
interaction/step-up error and MUST NOT bypass it, downgrade assurance, open an
uncontrolled browser, or retry a protected operation automatically. Automation
routes should declare their authorized device roles and device-only assurance.
A future explicit interactive API-client profile requires separate design.

## 13. Threat-model delta

| Threat or boundary | Required treatment |
|---|---|
| Internet-only or unauthorized peer tries to trigger prompts | No options or handoff before base acceptance; recheck private context at Authority page |
| Registered RP, RP XSS, or compromised application script | Cannot obtain raw credential material or weaken immutable assurance; can request ceremonies within its registered policy after valid base participation |
| Prompt abuse by an otherwise authorized RP | Explicit user action, clear Authority UI showing registered application, rate limits, and user refusal; base gating alone does not eliminate it |
| Phishing or RP-ID/origin confusion | Authority-owned context and exact WebAuthn verification; no third-party RP-ID issuance |
| Assertion replay or cross-RP/profile/operation reuse | Unique challenge linked to immutable cid/RP/profile/Q; atomic consumption |
| UP/UV downgrade or forged authorization claim | Authority checks flags and policy; RP checks structured evidence; no static assurance strings |
| Unauthorized enrollment or existing-subject takeover | Separate enrollment permission and independently authenticated target-subject attachment |
| Shared device mistaken for current person | Separate namespaces; no owner-derived subject or device-wide person cache |
| Stable identifiers and correlation | Per-RP disclosure permissions and identifiers; credential material stays private |
| Revocation, recovery, and racing assertions | Generations and atomic checks; recovery cannot default to device ownership |
| Synced credentials and multiple authenticators | Supported without claiming a credential is exclusive to the enrollment device |
| Lost device or stolen session | Independent person requirement adds a check; existing leases remain bounded; revoke provider/device and credentials as appropriate |
| Authorized-device compromise or powerful extension | Trusted-endpoint boundary remains; passkeys do not isolate all processes or prevent manipulation of an already authorized application |
| Authority compromise | Authority is trusted for enrollment, verification, and claims; compromise breaks these guarantees |
| Authority-page XSS | New critical attack surface; isolate UI, CSP, dependencies, and credential management |
| Success followed by lost delivery or redemption | Consume once; no automatic operation replay; report uncertain outcome |
| Session reuse and fresh destructive operations | Reuse preserves original age and session association; tx requires a new assertion |

WebAuthn authentication does not attest that the authenticator is physically part
of the overlay device. This profile binds the assertion to a ceremony carried by
an accepted device context; it does not infer authenticator location or exclusive
credential possession. Applications needing human transaction confirmation need
a separately defined intent/confirmation mechanism.

## 14. Implementation and verification plan

No implementation changes are authorized by this draft itself. After review,
integration touches Authority/store, configuration, RP state, both bindings,
browser flow, discovery capability handling, and typed Python-client errors.
Choose a maintained server WebAuthn library and evaluate its verification API,
algorithm support, user-handle checks, backup/counter handling, parsing limits,
security history, license, and standards-based fixtures. Do not implement the
verifier or CBOR/COSE handling from scratch. No package is selected or added here.

Required protocol tests cover: base-before-options; refused internet/unauthorized
peers; valid assertion; wrong challenge, origin, RP ID, user handle, cid, RP,
profile, and Q; assertion replay; missing UP/UV; unknown/revoked credential;
subject suspension; cancellation and every deadline; simultaneous handoff,
assertion, result, redemption, and revocation; durable burn on errors; winner
survival; forbidden disclosure; no credential leakage; enrollment subject
attachment; shared-device subject switching; bounded renewal without age reset;
no fresh-tx evidence reuse; loss after success; exact stored-operation execution;
v1 compatibility and rejection of downgrade/mixed transcripts.

Browser acceptance tests MUST use real HTTPS Authority and application origins,
private listeners, platform authenticators/security keys, and current supported
Chrome, Safari, and Firefox versions. Test popup user activation/blocking,
full-page resume, local-network permissions, synced/discoverable credentials,
multiple subjects on one device, multiple devices for one subject, cancellation,
and tab closure. Virtual authenticators supplement but do not replace these tests.
No compatibility claim is made before those results exist.

Proposed demo: `/admin` device-only; `/admin/verified` bounded person verification;
`/admin/destructive-demo` fresh verified transaction. Enrollment/management is
Authority-hosted and shows the subject and friendly credential names, with device
context clearly separate. Normal device-only use retains the no-login experience;
optional enrollment and step-up are visible ceremonies and must be described honestly.

After reconciliation, integrate the approved text into a canonical 0.8 spec,
update threat-model guarantees and limits, roadmap/version notes, README/API and
demo instructions, blog wording, and protocol vectors. Existing v1 handshake
illustrations must remain labeled v1; a separate v2 chart should show the gated
person phase. This contribution does not edit those shared files.

## 15. Open decisions and implementation gates

1. **OPEN — Joint reconciliation:** compare Claude's architecture and draft with
   this candidate; agree canonical file ownership before merging shared docs.
   His current proposal keeps v1 transcripts and suggests draft 0.9; this user-
   requested 0.8 candidate proposes v2 under 0.7 section 30. Resolve that
   disagreement explicitly before any wire implementation. Do not combine the
   response/state changes from one design with version assumptions from the other.
2. **OPEN — Wire schema:** freeze exact v2 endpoints, tagged response schemas,
   strict member rules, size limits, protocol negotiation, and error mapping.
3. **OPEN — Browser handoff:** test popup and full-page fallback, secret retention,
   peer continuity, polling cadence, CSRF/session binding, and resume behavior.
4. **OPEN — Enrollment and recovery:** select subject bootstrap permissions and
   operator recovery policy; independently authenticate operators and subjects.
5. **OPEN — Timers:** validate proposed 30/120/10-second defaults against real
   authenticators and grant limits, without granting unbounded base freshness.
6. **OPEN — Evidence reuse:** define the exact server-only handle lifecycle,
   logout, generations, garbage collection, and any revocation propagation.
7. **OPEN — Dependencies:** select and review verifier library and pin a tested
   version; define mandatory algorithms and metadata handling.
8. **OPEN — Version vectors:** publish v2 examples and adversarial vectors before
   release; keep draft numbering distinct from cryptographic protocol labels.
9. **OPEN — Multi-Authority operation:** define credential/state/evidence sharing
   and stable RP-ID ownership before claiming failover. Independent Authorities
   cannot silently share person credentials or pending transactions.

These gates prevent implementation from turning unresolved security or browser
assumptions into accidental protocol commitments. The alternatives remain open;
the independent person identity, base-first gating, Authority credential ownership,
no downgrade, and atomic single-use requirements do not.
