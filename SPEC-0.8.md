# ByteBind Protocol 0.8 — Combined Draft

**Status:** Combined draft for cross-verification; not implemented  
**Version:** 0.8-draft; v2 for explicitly selected new transactions  
**Date:** 2026-10-06  
**Baseline:** draft 0.7 at `307223480d23445e51366484721df60df3eb5d17`  
**Copyright:** © 2026 Bytes & Coffee Digital Studio

## 1. Scope, sources, and conformance

This combined draft reconciles the preserved [Codex
contribution](docs/drafts/SPEC-0.8-CODEX.md) and [Claude
contribution](docs/drafts/SPEC-0.8-CLAUDE.md). It supersedes those candidates
for review, not the implemented draft 0.7. Reconciliation decisions and source
fingerprints are in the [Claude cross-verification
guide](docs/drafts/SPEC-0.8-CROSS-VERIFY.md). Claude cross-verified the initial merge; the user-decided corrections from that
review have now been applied and are recorded in the ledger.

MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY express requirements of this proposed
protocol. They do not claim reference implementation support. Items marked
**OPEN** are release gates. Endpoint names and binding syntax remain provisional.

This specification incorporates draft 0.7 at the baseline commit by reference:
its channels, trust assumptions, value encodings, cryptographic formulas,
request binding, RP authentication, browser protections, failure rules, and
storage ownership apply except where this document explicitly changes them. V1
operation remains unchanged. For v2, sections 6–8 replace the exchange/state
rules, section 7 replaces transcript labels, sections 10–11 replace person-grant
and lease semantics, and section 16 adds transport and replay requirements. The
inherited 0.7 four-state constraint and expiry windows do not apply to v2. The
provider-owner interpretation in 0.7 section 18 cannot establish a person
subject; section 3 takes precedence. This is a combined revision specification,
not a license or software release.

Scope is optional Authority-owned passkey enrollment and person step-up after
successful private device attestation, with discovery/transport hardening in
section 16. Federation, OIDC/SAML integrations, an authenticator, arbitrary
third-party passkey RP IDs, and human identity federation remain out of scope.

## 2. Existing architecture and compatibility

The current Authority owns transactions and provider authorization; `store.py`
persists `pending`, `attested`, `redeemed`, and `burned` states. `authority.py`
validates the private request and returns encrypted `H2`, then selectively
releases claims during authenticated RP redemption. `rp.py` owns application
attempts, leases, and stored transaction requests. `binding.py` requires every
route requirement to match disclosed tags or authorization. The browser and
Python clients perform the same base proof ceremony. Discovery currently
resolves an Authority on each control call; §16.1 requires per-transaction
pinning.

Step-up attaches between base authorization and release of `H2`. The RP MUST NOT
verify WebAuthn assertions, store credentials, or operate enrollment. The
Authority owns the WebAuthn RP ID, origins, challenges, credentials, subject
associations, verification, management, and claim disclosure.

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

Every transaction created with `protocol: 2` uses v2 labels and states,
including `assurance: device`. The browser challenge and control grant MUST
identify protocol 2 explicitly. A v2 RP expecting v2 MUST reject a missing or
incorrect marker; it MUST NOT accept a missing marker as a compatible fallback.
A separate v1 path may accept a legacy grant only for a v1 device-only attempt.
Legacy clients are not promised to understand the new challenge shape.

The authenticated transaction request carries `protocol`, audience, profile,
assurance, and `Q` for the transaction profile. Person session creation also
carries a finite accepted maximum age; a person-lease renewal is requested with
`assurance: device` plus a reuse handle (§11); identity disclosure is separately
requested. Authority registration constrains every field. The Authority MUST
reject unsupported values rather than omit a requirement. A malformed profile/Q
combination remains invalid. No mixed-version proof is accepted.

The v1 `/attestation` endpoint MUST refuse any `cid` created with protocol 2,
and the v2 endpoints MUST refuse any v1 `cid`; each refusal burns only the
expected `pending` generation. Version is taken from stored transaction state,
never from the request.

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
require an explicit subject/device pairing; that restriction does not equate the
identities. Synced credentials are permitted.

Device authorization, credential-authenticated subject, user presence (UP), and
user verification (UV) are separate facts. Subject disclosure is a separate
policy decision from requiring participation. Civil identity and informed
transaction intent are outside this profile's WebAuthn guarantees.

The device-only IdP discussion in 0.7 section 18 does not authorize interpreting
a provider's human-account mapping as the currently participating person. Any
future bridge MUST preserve this distinction; federation remains out of scope.

The prohibition on deriving a person subject from a provider principal MUST be
unconfigurable. A convenience mapping disabled by default is insufficient. A
separately expressed pairing policy evaluates two independently established
facts; it does not transform a provider account into a person credential.

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
UV implies the required UP check; a presence result MUST NOT satisfy
verification.

For transaction-bound requests, presence or verification MUST be fresh for that
specific transaction. No cached person evidence satisfies that requirement. For
session grants, a registration MAY permit bounded reuse under section 11.

The RP MUST bind the assurance requirement to the selected route before creation
and preserve it with the stored operation or lease attempt. A browser-supplied
assurance level is not authoritative. The Authority MUST enforce the accepted
requirement before issuing a grant, and the RP MUST check the returned assurance
before executing the operation or allowing the route. Missing required evidence
fails closed. Static `authorization` strings MUST NOT manufacture person
evidence.

Presence requests MUST request `userVerification: "discouraged"`; verification
requests MUST request `"required"`. The Authority MUST check the returned UP/UV
flags regardless of those options. Incidental UV on a presence request MAY be
recorded, but reuse or stronger disclosure still requires registration
permission. No prompt or successful options call by itself constitutes evidence.

## 5. Channels and browser context

Base attestation retains 0.7's private direct connection, socket-derived peer,
registered application Origin, exact Host, JSON, CORS, and provider-policy
checks. The authenticated private control channel remains separate from browser
traffic.

The proposed deployment uses one stable, private HTTPS Authority origin for
WebAuthn enrollment and authentication. Its WebAuthn RP ID is that origin's
hostname, without a scheme or port. Changing that hostname requires a credential
migration plan; discovery does not make credential namespaces interchangeable.
Operators MUST configure exact allowed WebAuthn origins, independently of the
registered application origins.

WebAuthn runs in an Authority-owned top-level page. Arbitrary application
JavaScript cannot use the Authority's RP ID directly. A user-activated popup is
the baseline UX. Full-page navigation is deferred pending a separate resume
design. Neither is claimed tested across browsers. Ordinary device-only access
remains ambient; optional person step-up may require an explicit action and
visible Authority page. Background renewal MUST NOT automatically open a popup
or invoke a person ceremony.

An iframe or related-origin design is an alternative requiring separate review;
neither is a baseline dependency. WebAuthn defines RP-ID/origin rules and
related-origin mechanisms; this draft chooses an Authority page to keep
credential operations under Authority control. See [WebAuthn origin and RP-ID
rules](https://www.w3.org/TR/webauthn-3/#sctn-rp-id) and [related
origins](https://www.w3.org/TR/webauthn-3/#sctn-related-origins).

Authority credential pages MUST reject framing, use a restrictive CSP, avoid
third-party scripts, suppress referrers, and disable caching. Same-origin POSTs
MUST validate exact Origin and an attempt-bound CSRF token. Cookies MUST be
Secure, HttpOnly, and scoped narrowly; cookie presence alone never authorizes
step-up or enrollment.

The RP ID MUST be the exact Authority hostname, not a parent domain. This
narrows the browser credential scope as well as the server's exact-origin check.
The person UI MUST use a separate private HTTPS listener from the CORS
attestation listener. They MAY share a hostname on different ports; person
endpoints MUST NOT answer application CORS. TLS and socket-peer checks apply to
both. The configured web origin is distinct from the base Authority URL.

The person listener MUST refuse requests whose `Host` isn't its exact configured
authority, before reading any state.

Person pages MUST use `Cross-Origin-Opener-Policy: same-origin`, including the
step-up page. The baseline uses bounded result polling from the original
application page, with no cross-window completion message and no dependence on
popup-closed detection. Polling MUST stop on terminal response or its local UX
budget; server deadlines remain authoritative.

The result endpoint SHOULD hold a pending request open for up to 10 seconds and
answer as soon as the attempt becomes terminal or deliverable (long poll).
Clients MUST NOT issue more than one outstanding result request per attempt, or
more than one per 2 seconds. Result requests are rate-limited per (peer, `cid`),
not against the device's attestation budget. A pending response requires only a
match between the socket peer address and the stored attested address. The full
provider identity and policy check in §8 runs once, at delivery. The page
retains proof inputs in memory. If the popup is blocked, report `popup_blocked`
and offer an explicit retry while the handoff remains valid. If the attempt
expires or is cancelled, start a new transaction. Never persist proof inputs
merely to implement an unspecified navigation fallback.

The application opens the step-up page without `noopener` and treats only a
`null` return as `popup_blocked`. It MUST NOT infer cancellation or success from
the window handle.

Published browser/version claims from the source proposal are not conformance
facts. Popup behavior, permissions, passkeys, and private-network access require
the real-browser acceptance matrix in section 14. Related origins and delegated
iframes are excluded from this baseline; a future profile must revisit prompt
gating and who handles raw assertions.

## 6. Proposed exchanges

The paths below describe the candidate v2 interface. All opaque tokens use
canonical unpadded base64url and a cryptographically secure generator.

1. RP creates a v2 transaction over the authenticated control channel with
   audience, profile, optional `Q`, and assurance requirement. Authority stores
   those values, RP identity/origin, secrets, and server deadlines. RP forwards
   `protocol`, `cid`, `C`, and Authority URL, plus `person_origin` when person
   participation is required, without browser expiry fields. Authority sets the
   web origin from configuration; the RP MUST preserve it.
2. Client computes v2 `H1` and sends it with `cid` and `N` to the private
   `/v2/attestation` endpoint from the application's registered origin.
3. Authority performs the base checks in 0.7 section 11.1, atomically records
   the accepted device and immutable ceremony inputs, and either completes
   device-only attestation or prepares a person handoff. A failed base check
   MUST NOT issue a handoff, WebAuthn options, or a prompt instruction.
4. For fresh person step-up, Authority returns HTTP 202 with a `step_up` variant
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
7. The application browser retrieves `H2` using exactly
   `{cid, completion, N, H1}` with the separate completion token in a JSON POST to `/v2/attestation/result`. This endpoint checks original
   RP Origin, Host, current private peer identity, and stored `cid`, `N`, `H1`.
   It compares the supplied `N` and `H1` against stored
   inputs in constant time; it does not consume the attempt on a pending poll. Pending responses contain no
   proof material. A completed result is released at most once.
8. Client decrypts `H2`, computes v2 `R`, and submits it to its RP. RP consumes
   its attempt binding, redeems with the creating Authority, checks grant scope
   and required evidence, and creates a lease or executes only the stored request.

The step-up response contains exactly this shape (values are illustrative):

```json
{"step_up":{"url":"https://authority.example:8444/step-up","handoff":"<base64url>","completion":"<base64url>"}}
```

The client MUST validate the URL against the exact `person_origin` carried in
its challenge, including the expected fixed `/step-up` path. It MUST reject
unexpected scheme, credentials, origin, query, or fragment; then append its own
handoff fragment. A result response is HTTP 200 with `H2`; a pending result is
HTTP 202 with no secrets. Errors contain no credential or subject details.
Successful immediate device-only attestation returns `H2` without a handoff.
Strict schemas, caps, and exact error members remain to be frozen in section 15.

The Authority page MUST NOT pass credentials, assertions, or `H2` to the
application. It MAY POST `/step-up/abort` using its bound same-origin attempt
session and CSRF token. Result collection alone starts the short redemption
window under section 8. No arbitrary return URL or popup message is accepted.

Handoff and completion tokens are bearer secrets, not person or device identity.
They MUST NOT be logged or included in analytics. A stolen token without the
required private device context MUST NOT authorize a ceremony or result
retrieval. Private paths inherited through compromised devices remain a trust
limitation.

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

Only after base acceptance, the Authority generates a fresh random 32-byte `w`
and derives the WebAuthn challenge using fixed-length values:

```text
W = SHA-256("bytebind/v2/person/challenge" || cid || H1 || w)
```

The label is ASCII; `cid` is 16 bytes and `H1` and `w` are each 32 bytes. The
Authority stores `W` and `w`. Its record maps that challenge to exactly one
`cid`, generation, RP, audience, profile, `Q` if present, accepted device, `N`,
`H1`, assurance, Authority RP ID/origin, and deadline. These fields MUST NOT
change after options are issued. Server-side challenge association supplies
transaction binding; no custom WebAuthn signature format is introduced.

For verification, request options MUST set `userVerification` to `required`; the
Authority MUST still verify the returned flags. Options are not evidence.

Authentication MUST follow [WebAuthn assertion
verification](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion):
validate type, challenge, origin, RP-ID hash, credential ownership, signature,
and required UP/UV. This baseline rejects cross-origin ceremonies. Resolve the
subject from Authority credential records; validate user handle when applicable.
Signature counters follow the profile policy below; backup-state flags follow
the standard's handling. Registration follows [WebAuthn registration
verification](https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential).

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

All formulas and field lengths otherwise follow 0.7 sections 9.2 and 11–13. In
particular `Q` is computed by the client from its actual submitted operation.
The attested assurance is bound through immutable Authority state referenced by
`cid`; the client never supplies authoritative assurance claims. Implementations
MUST NOT accept mixed v1/v2 labels or infer a version from a successful MAC. New
machine-readable vectors are required before freezing v2.

The `person/challenge` label is also part of v2's label set. This derivation
adds a transcript commitment, not a new assertion/signature format. Live
acceptance still depends on stored state, peer checks, and single use. This
derivation is a transcript commitment only. This profile defines no audit record
of its inputs, and an assertion never proves that the person read or approved
the application operation.

For this profile, if either the stored or the received signature counter is non-zero and the received value is less than or equal to the stored value, the
Authority MUST refuse the assertion, burn the expected generation, and raise an
operator-review event. A counter that stays zero is not evidence of cloning.
This is a chosen conservative policy, not a claim that the WebAuthn standard
mandates refusal or that regression proves a clone. Concurrent legitimate
assertions can arrive out of order. Counter comparison/update and credential
version checks MUST be atomic; test zero counters, out-of-order assertions, and
counters from different transactions. Backup-state flags require standards
validation and do not establish person or overlay-device identity.

## 8. States, deadlines, and failures

| State | Permitted next state | Condition |
|---|---|---|
| `pending` | `base_attested` | All base checks and conditional update succeed |
| `base_attested` | `stepup_pending` | One handoff accepted; fresh options issued |
| `base_attested` | `redeemable` | Device-only requirement (person evidence MAY be attached by accepted reuse, §11) |
| `stepup_pending` | `redeemable` | Assertion and subject policy succeed atomically |
| `redeemable` | `redeemed` | Correct RP-scoped proof consumed atomically |
| Any live state | `burned` | Applicable failure, cancellation, or expiry |

`stepup_attested` is a logical event in the atomic transition to `redeemable`;
no separate externally observable state is necessary. Result delivery has a
separate one-use flag and starts, once, the redemption deadline defined below.

Each update MUST match expected state AND attempt generation. A race loser MUST
NOT burn a winning attempt's later state. Burns and success transitions MUST
commit before a response, including exception paths. Only one WebAuthn challenge
may be outstanding per `cid`; retry requires a new ByteBind transaction.

Proposed defaults for review: 30 seconds to establish base authorization, 120
seconds from base acceptance as the overall person-completion limit, 30 seconds
from becoming redeemable to collect `H2`, and 10 seconds from the atomic first
delivery reservation to redeem. Collection expires at the earlier of the
30-second collection deadline and the overall 120-second limit. Immediate
device-only or accepted-reuse `H2` delivery starts its redemption deadline in
the same atomic way. Before delivery, redemption MUST fail even in `redeemable`.
The delivery reservation and redemption deadline commit before writing the
response; the server cannot know whether the browser received it. RP attempt
retention MUST accommodate the selected flow; the initial v1-style short
deadline cannot remain unchanged for v2 step-up. Authority returns relative
control-channel durations, never browser authorization expiry. No deadline is
extended by polling, handoff, retries, or failed verification. First delivery
creates the redemption deadline; it never resets an existing one.

Base acceptance for step-up has its own bounded deadline. Before issuing
options, accepting an assertion, and delivering a result, Authority MUST confirm
current private device identity and applicable provider policy. A pending result
response requires only that the socket peer address equal the stored attested
address (§5). If the base deadline expires, no later assertion revives it. A
fresh attempt starts with fresh base attestation. Policy change at redemption
MUST also refuse obsolete authorization.

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
Base authorization allows entry into enrollment; it does not prove which
existing person's credential set may be changed.

Creating a new subject requires explicit operator-authorized enrollment or an
explicit self-enrollment policy. Attaching a credential to an existing subject
requires fresh authentication with an existing credential plus authorization to
manage that subject, or a separately controlled recovery procedure. A supplied
name, provider owner, device tag, or bare subject ID MUST NOT suffice. New-subject enrollment MUST NOT merge subjects by display name or provider owner.

Registration and credential changes require one-use challenges, exact Authority
Origin checks, CSRF protection, device-policy revalidation, and bounded
lifetimes. This profile requires UV and discoverable credentials; alternatives
require a separately reviewed profile. Default authenticator attestation
conveyance SHOULD be `none`; collecting device provenance is not necessary for
these ByteBind claims.

The Authority UI supports register, name, list, and revoke. Existing-subject
management requires fresh verified subject authentication. An operator recovery
interface MUST authenticate its operator independently, audit changes, and
invalidate affected evidence. If recovery has no approved design, recovery is
disabled; it MUST NOT fall back to provider ownership. Revoking the last
credential MAY leave the subject unable to authenticate until an authorized
recovery.

Revocation invalidates pending step-ups and reusable evidence. Already issued RP
leases remain valid only until their bounded deadlines unless an independently
authenticated revocation channel is implemented. This draft promises no
immediate revocation of an offline RP lease.

Operator-authorized enrollment uses a 32-byte random invite stored only as a
hash, scoped to one subject and purpose (`new_subject` or `add_credential`).
Default validity is 15 minutes, configurable up to 24 hours. The invite MUST be
delivered out of band, redacted from logs, and consumed only under an accepted
enrollment private context. Consumption creates one bound registration attempt,
not an indefinitely authenticated management session. Losing registration after
invite consumption requires a new invite.

An invite for an existing subject supplements fresh existing-credential
verification; it does not silently replace it. An invite alone may attach a
credential to an existing subject only when explicitly issued through the
approved recovery procedure, with independent operator authentication and audit.
This reconciles subject attachment with recovery rather than letting any device
holding a subject ID add a credential.

Registration MUST NOT use conditional mediation, and the Authority MUST verify
that the UP bit is set.

Registration MUST require discoverable credentials and UV, use the subject's
random user handle, and exclude the subject's existing credential IDs. Labels
MUST NOT derive from provider principals. Direct authenticator attestation or
AAGUID trust policies are deferred; self-reported metadata is not trusted device
provenance. Synced credentials remain supported in the baseline. An optional
non-synced policy would need separate metadata and compatibility review.

If self-enrollment is explicitly enabled, the subject MUST retain a
`self_enrolled` provenance flag. An RP must explicitly accept that provenance
before it can receive or authorize such a person subject. Names alone never make
a self-enrolled subject operator-vetted. Provider/owner audit metadata MAY be
retained under a minimization policy, but cannot establish person identity or
authorize subject attachment.

## 10. Grants and selective disclosure

A v2 grant retains `active`, `rp_id`, `audience`, relative `expires_in`, and
`claims`. It additionally returns structured assurance evidence needed to
enforce the accepted requirement. The example below is a fresh transaction grant
and is illustrative, not a finalized schema:

```json
{
  "protocol": 2,
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

A separate illustrative session grant from a fresh assertion:

```json
{
  "protocol": 2,
  "active": true,
  "rp_id": "moderation",
  "audience": "manage",
  "expires_in": 180,
  "assurance": {
    "device_attested": true,
    "user_present": true,
    "user_verified": true,
    "person_fresh": true,
    "person_expires_in": 600
  },
  "claims": {"tags": ["tag:interactive"]}
}
```

Required assurance booleans may be released without a person identifier. An RP
requesting identity MUST be registered for `person_subject` disclosure; absence
of permission is a creation-time failure if identity is required. Default person
identifiers SHOULD be stable only within the authenticated RP's namespace.
Global identifiers require explicit operator disclosure policy. Claim omission
MUST NOT become implicit permission, and a public client cannot select
disclosure.

The Authority MUST NOT release credential IDs, public keys, user handles, raw
assertions, authenticator data, or provider owner metadata as person evidence.
The RP consumes the grant under its authenticated control-channel trust; this
draft does not introduce independently verifiable bearer identity tokens.

A grant MUST identify `protocol: 2`; section 2 defines strict interpretation.
When permitted, pairwise person identifiers use an Authority-only 32-byte key:

```text
person_subject = "ps_" || b64url(HMAC-SHA256(
    key = pairwise_key,
    data = "bytebind/v2/pairwise" || len(rp_id) || rp_id
           || len(subject_id) || subject_id
))
```

`rp_id` is UTF-8; `subject_id` is its stored opaque byte string; each is
preceded by its unsigned 64-bit big-endian byte length. The ASCII label is part
of the v2 label set. This explicitly length-prefixes both variable fields. Key
rotation changes pseudonyms and requires coordinated RP account migration; never
silently merge changed IDs with existing accounts. The key is Authority-private
and MUST NOT be logged or exposed to RPs.

No age claim is required. An optional age claim is deferred until its privacy
and rounding semantics are frozen. RP enforcement MUST use the exact relative
validity received over the control channel, not a rounded or missing display
age. Freshness for a tx is expressed by `fresh_for_transaction`, not an age.

Session grants issued from a fresh assertion carry `assurance.person_fresh:
true`; reuse grants never do. RPs enforce per-route `person_max_age` from their
own receipt time of the fresh grant, which reuse never updates, in addition to
`assurance.person_expires_in`. The session-creation maximum sent at creation is
the RP's largest configured route maximum, capped by registration. Global names
require an explicit separate disclosure permission.

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

Reused evidence MUST match the RP, audience, provider/device identity,
assurance, active subject/credential generations, and the originally established
session. Every renewal still requires successful base attestation. Reuse MUST
NOT update the original person-authentication time, upgrade UP to UV, or satisfy
a fresh transaction requirement. Subject switching requires fresh step-up and
replacement of the browser lease and associated evidence.

The operator configures a finite maximum person-authentication age; the RP MAY
request a stricter limit. A person-lease renewal is a v2 transaction with
`assurance: device` and the lease's reuse handle. If the Authority accepts the
reuse, the grant carries device `expires_in` (subject to 0.7 §15.1's minimum)
and `assurance.person_expires_in`, the remaining person validity. If it refuses
the reuse (age, revocation, changed device, subject switch), the grant carries
device assurance only. The RP MUST remove all person assurance, identity claims,
and reuse handles from the lease when `person_expires_in` elapses on its own
clock, or when a renewal grant lacks person evidence, whichever comes first. The
device part of the lease continues under its own deadline. A transaction that
*required* person assurance never completes as device-only: it fails. Background
renewal never receives a step-up variant. Routes requiring a person return an
explicit step-up-required failure and offer a button. No handler sees stale
person identity after expiry.

The Authority uses its own clock for authentication age and returns only
relative remaining authorization duration to the RP. Absolute authentication
timestamps are not required. RP route checks use stored evidence deadlines;
possession of a cookie is insufficient. Evidence reuse handles are secrets and
cannot be shared between otherwise unrelated browser sessions.

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

@bind(require=["tag:interactive"], grant=bind.TRANSACTION, assurance="verification")
def destructive_operation(): ...  # always fresh for this operation
```

All current `require` values remain AND requirements. A plain authorization
string named `webauthn:uv` MUST NOT be treated as verified evidence. The
smallest coherent extension is structured assurance alongside existing claim
requirements, with the framework carrying it into creation and grant checks.
Subject release is an independent binding/registration option.

Operator configuration needs a stable Authority RP ID/origin, supported
assurance per RP/audience, person-disclosure permissions, allowed subject
policies, enrollment/recovery authority, maximum person age, and optional reuse
permission. Required route tags must still be permitted by provider policy and
disclosed. Devices tagged both interactive and automated may use either
permitted route; WebAuthn does not manufacture missing device tags.

Existing HTTPX and requests clients continue base-only operation. A headless
client encountering a fresh person requirement MUST receive a typed unsupported
interaction/step-up error and MUST NOT bypass it, downgrade assurance, open an
uncontrolled browser, or retry a protected operation automatically. Automation
routes should declare their authorized device roles and device-only assurance. A
future explicit interactive API-client profile requires separate design.

Bindings MUST reject unknown assurance, `person_max_age` without person
assurance, `person_max_age` for a transaction (always fresh), and
`identify=True` with device-only assurance at configuration/declaration time. An
identity-required route also requires registration permission to disclose
`person_subject`.

Python clients expose `StepUpRequired(ClientError)` with no handoff/completion
secrets or navigation URL. Updated clients MAY implement v2 device-only flows;
legacy clients continue using v1. Receiving an unsupported protocol is distinct
from bypassing a requested person ceremony. Client method and response APIs
remain compatible for existing v1 application calls.

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

WebAuthn authentication does not attest that the authenticator is physically
part of the overlay device. This profile binds the assertion to a ceremony
carried by an accepted device context; it does not infer authenticator location
or exclusive credential possession. Applications needing human transaction
confirmation need a separately defined intent/confirmation mechanism.

Additional boundaries: exact-host RP IDs reduce sibling-host credential scope;
related origins remain excluded. Self-enrollment provenance must not be
presented as vetted. Counter regression is a refusal signal, not proof of
cloning. Pairwise-key compromise affects correlation. Keeping `IP || S` means
application-origin JavaScript can learn the attested overlay IP even when the
grant omits it; selective claim disclosure does not hide that address.

## 14. Implementation and verification plan

No implementation changes are authorized by this draft itself. After review,
integration touches Authority/store, configuration, RP state, both bindings,
browser flow, discovery capability handling, and typed Python-client errors.
Evaluate [Yubico python-fido2](https://developers.yubico.com/python-fido2/) as
the preferred candidate, with Duo py_webauthn as an alternative. Choose a
maintained server WebAuthn library and evaluate its verification API, algorithm
support, user-handle checks, backup/counter handling, parsing limits, security
history, license, and standards-based fixtures. Do not implement the verifier or
CBOR/COSE handling from scratch. No package is selected or added here.

Required protocol tests cover: base-before-options; refused
internet/unauthorized peers; valid assertion; wrong challenge, origin, RP ID,
user handle, cid, RP, profile, and Q; assertion replay; missing UP/UV;
unknown/revoked credential; subject suspension; cancellation and every deadline;
simultaneous handoff, assertion, result, redemption, and revocation; durable
burn on errors; winner survival; forbidden disclosure; no credential leakage;
enrollment subject attachment; shared-device subject switching; bounded renewal
without age reset; no fresh-tx evidence reuse; loss after success; exact stored-operation execution; v1 compatibility and rejection of downgrade/mixed
transcripts.

Browser acceptance tests MUST use real HTTPS Authority and application origins,
private listeners, platform authenticators/security keys, and current supported
Chrome, Safari, and Firefox versions. Test popup user activation/blocking,
blocked-popup recovery, local-network permissions, synced/discoverable
credentials, multiple subjects on one device, multiple devices for one subject,
cancellation, and tab closure. Virtual authenticators supplement but do not
replace these tests. No compatibility claim is made before those results exist.

Proposed demo: `/admin` device-only; `/admin/verified` bounded person
verification; `/admin/destructive-demo` fresh verified transaction.
Enrollment/management is Authority-hosted and shows the subject and friendly
credential names, with device context clearly separate. Normal device-only use
retains the no-login experience; optional enrollment and step-up are visible
ceremonies and must be described honestly.

After cross-verification and approval, update threat-model guarantees and
limits, roadmap/version notes, README/API and demo instructions, blog wording,
and protocol vectors. Existing v1 handshake illustrations must remain labeled
v1; a separate v2 chart should show the gated person phase. This combined draft
does not edit those shared files.

Keep verifier dependencies Authority-only; RP bindings and API clients do not
need a verifier. Exact versions/dependency claims in source drafts must be
rechecked at selection time. Generate standards-based signed test fixtures and
virtual-authenticator tests; never replace the library verifier with custom
signature/CBOR/COSE verification. Add vectors for `W`, pairwise encoding, first-delivery deadline behavior, and explicit person-to-device privilege loss.

## 15. Release gates

The combined decisions are recorded in the cross-verification guide. These
remaining gates do not reopen independent person identity, base-first gating,
Authority ownership, v2 version separation, or atomic single use.

1. **CLOSED — Claude cross-verification:** Claude reviewed the combined draft; the user decided F1–F12, and accepted patches P1–P16 have been applied. Closure is conditional on the accepted patch text and gate edits being preserved; see the reconciliation ledger for the review and resulting snapshot.
2. **OPEN — Wire freeze:** exact closed schemas, caps, paths, JSON encodings,
   version/capability negotiation, renewal evidence handle, typed errors, and
   all control/browser response variants. No fallback removes required assurance.
3. **OPEN — Browser acceptance:** popup opening/retry, COOP-isolated polling,
   private-network permissions, current Safari/Chrome/Firefox behavior, real
   authenticators, and discoverable/synced/shared-device cases.
4. **OPEN — Enrollment/recovery:** independently authenticated operator mechanism,
   invite transport, existing-subject recovery approvals, management UX, and
   audit policy. Recovery remains disabled until approved.
5. **OPEN — Timing and storage:** validate 30/120/30/10-second windows, exact RP
   attempt budgets, transaction cleanup, counter/revocation races, long-poll hold time and per-(peer, cid) result budget, and durable delivery reservation under lost responses and crashes. Track sequential challenge reissue after cancellation as undecided; no reissue behavior is authorized by this draft.
6. **OPEN — Evidence reuse:** server-only handle lifecycle, exact-session binding,
   logout, revocation generations, maximum-age enforcement, dual device/person lifetimes and `person_fresh` recording, and atomic clearing of person state when person validity expires or renewal lacks person evidence.
7. **OPEN — Dependency review:** tested verifier version, supported algorithms,
   parsing limits, origin hooks, counter/backup handling, license/security review.
8. **OPEN — Vectors and independent review:** all v2 transcript labels and
   encodings, state races, negative vectors, and end-to-end scope enforcement.
9. **OPEN — Multi-Authority:** credential/state sharing and stable RP-ID ownership.
   Pin each live transaction; no unreviewed failover or cross-Authority reuse.
10. **Deferred scope:** full-page navigation, related origins, age display,
    non-synced/attestation-provenance profiles, and opaque address commitments
    require separate designs. They are not implemented by omission.

## 16. Additional 0.8 hardening

### 16.1 Discovery and transaction pinning

An RP MUST pin the creating Authority per `cid` and redeem only with that
Authority. Authenticated discovery MAY advertise `protocols: [1, 2]` in its
capability; unsupported or malformed values cannot select a v2 candidate.
Capability schema evolution must be versioned explicitly so legacy discovery
cannot misinterpret new members. A configured candidate may instead negotiate
support over the authenticated control channel. Advertisements filter
candidates; they do not establish trust. Tag/capability ownership is an
authorization trust boundary. Production RPs SHOULD additionally pin stable
Authority identity or use configured endpoints. No policy-equivalence or
failover claim is made.

### 16.2 Mutual Unix-socket authentication

On every Unix-socket connection, the RP MUST verify the Authority's kernel peer
credentials against a configured Authority UID, using the platform-appropriate
API. It MUST verify the containing directory is owned by root or that UID and
not writable by other accounts, and verify socket ownership/access policy. The
Authority still verifies the RP's peer credentials and registration. A socket
path's existence does not authenticate either party. Deployments must review
privileged/shared-account trust; permissions alone do not isolate same-UID
processes. These are transport hardening requirements, not changed v1 MACs.

### 16.3 Stored-operation execution and ambient state

A transaction handler MUST authorize using the stored method, target, covered
headers/body, valid grant, and RP-held application state bound at creation.
Cookies, credentials, or headers from proof submission MUST NOT select an
application principal or change the protected operation. Bind needed credentials
at creation through covered request fields or a stored authenticated principal.
The request digest MUST continue to cover the exact selected request bytes;
stored principal binding does not imply cryptographic coverage of omitted
fields. Execution remains at most once, including on lost responses.

### 16.4 Address privacy

V2 retains `IP || S` and the original address-bearing redemption construction.
Application browser code can therefore learn the overlay IP. This accepted
boundary MUST be documented explicitly. Claude's proposed opaque `IPB`
replacement is deferred because it changes plaintext size and redemption
formulas and needs its own privacy, crypto, and interoperability review. No v2
implementation may substitute it under this specification's labels.

### 16.5 Cookie scope

Browser bindings SHOULD use `__Host-bytebind_session` and `__Host-bytebind_state`, with Secure, HttpOnly, SameSite=Strict, Path=/, and no Domain
attribute. The RP stores only hashes where appropriate and enforces server-side
lifetimes. Adopting the host prefix requires changing the old state cookie path
and reviewing co-hosted applications; it cannot be added while retaining a
narrow path that violates the prefix requirements.

