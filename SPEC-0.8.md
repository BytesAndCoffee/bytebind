# ByteBind Protocol v1 — Specification 0.8 Draft

**Status:** Combined draft for cross-verification; not implemented  
**Specification version:** 0.8-draft; protocol v1
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
storage ownership apply except where this document explicitly changes them. The existing base-only cryptographic transcripts remain unchanged. For draft
0.8, sections 6–8 extend the exchange/state rules, section 7 adds person and
pairwise labels within protocol v1, sections 10–11 define person grants and
leases, and section 16 adds transport and replay requirements. The inherited
0.7 four-state constraint and expiry windows do not govern person step-up. The
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

ByteBind remains protocol **v1**, specified here by **draft 0.8**. Nothing has
been deployed as a stable protocol release. Draft 0.7 and 0.8 are successive
pre-release specifications of v1, not coexisting protocol versions. This user-
selected versioning supersedes the earlier v2 proposal and the application of
0.7 section 30 that required a new label version for this draft work. After a
stable release, incompatible transcript or semantic changes require explicit
versioning; this exception is not permission to redefine a deployed protocol.

All transactions in this draft use v1 labels, including device-only assurance.
The challenge and grant identify `protocol: 1`. This marker identifies the
protocol family, not support for every draft-0.8 feature. RPs and Authorities
MUST explicitly agree on the supported draft schemas and assurance capabilities
through configuration or authenticated capability negotiation. Unsupported
assurance or schema requests MUST fail; no retry may remove person requirements.
Discovery MUST pin the creating Authority and authenticate support. Advertisement
alone is not trust or proof of policy equivalence.

The authenticated transaction request carries `protocol`, audience, profile,
assurance, and `Q` for the transaction profile. Person session creation carries
a finite accepted maximum age; silent device renewal requests `assurance: device`
and preserves the existing person association under section 11. Identity
disclosure is separately requested. Authority registration constrains every field.
Malformed profile/Q combinations and unsupported values MUST be rejected.

A draft-0.7 implementation does not gain person-step-up support merely because
it also uses v1. It MUST NOT be selected for a draft-0.8 person transaction unless
that support has actually been implemented and negotiated. A missing required
marker or requested assurance evidence fails closed. Endpoint processing follows
stored transaction scope and assurance, not an asserted client version. There is
no v1/v2 routing split in this specification. Exact negotiation schema remains a
wire-freeze gate; implementation and old-client upgrades are separate work.

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

Each v1 transaction stores an immutable assurance requirement accepted from the
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
registered application origins. All registered application and Authority origins
MUST be stored in browser-serialized form: lowercase scheme/host, default port
omitted, and canonical host serialization. Configuration MUST reject other forms,
including an explicit `:443` on HTTPS origins. Existing deployments need explicit
configuration migration; this does not change the implemented 0.7 parser.
See the [URL origin serialization rules](https://url.spec.whatwg.org/#ascii-serialisation-of-an-origin).

WebAuthn person step-up runs only in an Authority-origin iframe embedded by a
top-level application page after successful base attestation (section 5.1).
Popups and full-page navigation are not part of this profile. Arbitrary
application JavaScript cannot use the Authority's RP ID directly. The iframe
mode is not claimed tested across browsers. Ordinary device-only access remains
ambient; optional person step-up requires an explicit action in the visible
Authority frame. Background renewal MUST NOT embed the step-up frame or invoke
a person ceremony.

Authority-origin iframes are permitted only for person step-up. Enrollment and
credential management remain top-level. Related-origin credential use remains
excluded; application JavaScript does not perform the Authority ceremony. WebAuthn defines RP-ID/origin rules and
related-origin mechanisms; this draft chooses an Authority page to keep
credential operations under Authority control. See [WebAuthn origin and RP-ID
rules](https://www.w3.org/TR/webauthn-3/#sctn-rp-id) and [related
origins](https://www.w3.org/TR/webauthn-3/#sctn-related-origins).

Authority credential pages MUST use a restrictive CSP, avoid third-party scripts,
suppress referrers, and disable caching. Enrollment and management pages MUST
reject framing with `frame-ancestors 'none'`. The step-up page is served per
registered RP at `/step-up/<rp_id>`, and that response MUST send
`frame-ancestors` listing exactly that RP's registered origin, with no
wildcards and no other origins. The browser therefore enforces that only the
transaction's own application origin can embed its step-up page, including on
browsers that omit `topOrigin` (section 7). The handoff exchange MUST refuse a
handoff whose transaction belongs to an RP other than the path's `rp_id`, and
burn only the expected generation. An unknown `rp_id` returns a generic
not-found response that doesn't reveal which RPs are registered. No other
person page is frameable. Same-origin POSTs
MUST validate exact Origin and an attempt-bound CSRF token. Enrollment and management cookies MUST be Secure, HttpOnly, and scoped narrowly;
cookie presence alone never authorizes enrollment or credential management.
The step-up attempt session MUST NOT depend on cookies. Its handoff exchange
returns an attempt-bound bearer token held only in the Authority page's memory,
sent in a request header on its same-origin options, assertion, and abort
requests, and used as the CSRF token. It is scoped to the accepted transaction,
device, generation, and deadline, never exposed to the application, stored
persistently, or logged. Exact header/schema is a wire-freeze gate. Origin and
Host checks remain mandatory independently of the token.

The RP ID MUST be the exact Authority hostname, not a parent domain. This
narrows the browser credential scope as well as the server's exact-origin check.
The person UI MUST use a separate private HTTPS listener from the CORS
attestation listener. They MAY share a hostname on different ports; person
endpoints MUST NOT answer application CORS. TLS and socket-peer checks apply to
both. The configured web origin is distinct from the base Authority URL.

The person listener MUST refuse requests whose `Host` isn't its exact configured
authority, before reading any state.

Top-level person pages (enrollment and management) MUST use
`Cross-Origin-Opener-Policy: same-origin`. Iframe isolation relies on the
cross-origin boundary, per-RP `frame-ancestors`, and the absence of a message
API; COOP is not its isolation mechanism. The application page learns the
outcome only by bounded result polling, with no cross-frame completion message.
Polling MUST stop on terminal response or its local UX budget; server deadlines
remain authoritative.

The result endpoint SHOULD hold a pending request open for up to 10 seconds and
answer as soon as the attempt becomes terminal or deliverable (long poll).
Clients MUST NOT issue more than one outstanding result request per attempt, or
more than one per 2 seconds. Result requests are rate-limited per (peer, `cid`),
not against the device's attestation budget. A pending response requires only a
match between the socket peer address and the stored attested address. The full
provider identity and policy check in §8 runs once, at delivery. The page
retains proof inputs in memory. If the attempt expires or is cancelled, start a
new transaction. Never persist proof inputs merely to implement an unspecified
navigation fallback.

Published browser/version claims from the source proposal are not conformance
facts. Iframe behavior, permissions, passkeys, and private-network access
require the real-browser acceptance matrix in section 14. Related origins
remain excluded. The iframe requires the base-first handoff gate, and raw
assertions stay entirely at the Authority origin.

### 5.1 Iframe step-up context

After base attestation succeeds, the application embeds the step-up page for
its RP, validating the URL and `person_origin` as in section 6. Illustrative
markup uses the actual validated values in place of the placeholders:

```html
<iframe src="<person_origin>/step-up/<rp_id>#<handoff>"
        allow="publickey-credentials-get <person_origin>; local-network <person_origin>; local-network-access <person_origin>">
</iframe>
```

The embedding page MUST be a top-level document. WebKit refuses WebAuthn in a
frame with more than one cross-origin ancestor, so an application that is
itself framed by another origin cannot host person step-up. Application
`Permissions-Policy` and CSP `frame-src`, when supplied, MUST permit the person
origin for this page. The iframe MUST NOT be sandboxed in a way that removes
its origin.

Two local-network permission tokens are delegated: `local-network` (reported
for Chrome 145+ and Firefox 153+) and `local-network-access` (Chrome 142–144).
Browsers ignore tokens they don't recognize. These names come from secondary
sources and remain provisional. Supported-browser delegation and
private-network permissions remain acceptance gates, not assumptions that this
example works everywhere.

The iframe MUST NOT send or accept messages from its embedder. It MUST NOT
perform, proxy, or relay base attestation, collect or deliver `H2`, submit the
ByteBind proof, or disclose identity results to the RP. Its ceremony requests
are limited to handoff exchange, options, assertion, and abort at its own
Authority origin. The application learns availability only by result polling;
permitted identity claims reach the RP only at redemption.

Before `navigator.credentials.get()`, the iframe MUST show its own "Verify with
passkey" control and invoke `get()` from that control's activation. Some
browsers, including Safari, require a user gesture and show a consent prompt
for cross-origin WebAuthn. Before exchanging the handoff, the page MUST check
that the WebAuthn API is present and, where the browser exposes it, that
`publickey-credentials-get` is allowed in the frame. If either check fails, it
MUST NOT exchange the handoff and shows frame-local text saying that this
browser or page configuration can't complete person verification. It sends no
message to the embedder, and the step-up grants nothing. There is no
alternative browsing context; the attempt expires under section 8.
After a successful exchange, fetch options immediately and keep them in frame
memory. Enable the verification control only when options are ready and valid.
Call `get()` directly from its activation handler, with no intervening network
request or asynchronous options fetch. Once the handoff is consumed, a retry
requires a new transaction, with no transfer of an assertion or revival of an
expired attempt. Registration (`create()`) never runs in a frame: enrollment
and management are top-level Authority pages the user visits directly.

See [WebAuthn iframe guidance](https://www.w3.org/TR/webauthn-3/#sctn-iframe-guidance)
and [Chrome's Local Network Access guidance](https://developer.chrome.com/blog/local-network-access).
Real-browser testing must verify the actual delegation requirements, including
subframe navigation to overlay addresses and cookie blocking.

## 6. Proposed exchanges

The paths below describe the candidate draft-0.8 v1 interface. All opaque tokens use
canonical unpadded base64url and a cryptographically secure generator.

1. RP creates a v1 transaction over the authenticated control channel with
   audience, profile, optional `Q`, and assurance requirement. Authority stores
   those values, RP identity/origin, secrets, and server deadlines. RP forwards
   `protocol`, `cid`, `C`, and Authority URL, plus `person_origin` when person
   participation is required, without browser expiry fields. Authority sets the
   web origin from configuration; the RP MUST preserve it.
2. Client computes v1 `H1` and sends it with `cid` and `N` to the private
   `/attestation` endpoint from the application's registered origin.
3. Authority performs the base checks in 0.7 section 11.1, atomically records
   the accepted device and immutable ceremony inputs, and either completes
   device-only attestation or prepares a person handoff. A failed base check
   MUST NOT issue a handoff, WebAuthn options, or a prompt instruction.
4. For fresh person step-up, Authority returns HTTP 202 with a `step_up` variant
   with a one-use 32-byte handoff token and a separate 32-byte completion token.
   Both are scoped to this `cid`, originating RP, and accepted device.
   It MUST NOT return `H2` or expose `S` at this stage.
5. After base acceptance, the top-level application page embeds its RP's
   Authority step-up page (`/step-up/<rp_id>`) as an iframe, passing the
   handoff token in a URL fragment. That page removes the fragment immediately,
   performs the capability checks in section 5.1, and then exchanges the handoff
   in a same-origin JSON POST. Authority
   re-attests its socket peer, requires the same provider/device identity as
   the base attempt, and atomically consumes the handoff. Only then may it
   issue WebAuthn options and the memory-only, attempt-bound bearer session
   described in section 5. This checks continued private context; it does not
   replace, proxy, or perform the original base ByteBind attestation.
6. Authority page performs the assertion and posts the result directly to the
   Authority. Verification and the state transition in sections 7–8 must finish
   durably before success is reported.
7. The application browser retrieves `H2` using exactly
   `{cid, completion, N, H1}` with the separate completion token in a JSON POST to `/attestation/result`. This endpoint checks original
   RP Origin, Host, current private peer identity, and stored `cid`, `N`, `H1`.
   It compares the supplied `N` and `H1` against stored
   inputs in constant time; it does not consume the attempt on a pending poll. Pending responses contain no
   proof material. A completed result is released at most once.
8. Client decrypts `H2`, computes v1 `R`, and submits it to its RP. RP consumes
   its attempt binding, redeems with the creating Authority, checks grant scope
   and required evidence, and creates a lease or executes only the stored request.

The step-up response contains exactly this shape (values are illustrative):

```json
{"step_up":{"url":"https://authority.example:8444/step-up/moderation","handoff":"<base64url>","completion":"<base64url>"}}
```

The client MUST validate the URL against the exact `person_origin` carried in
its challenge, with a path of exactly `/step-up/` followed by one non-empty
`rp_id` segment. It MUST reject
unexpected scheme, credentials, origin, query, or fragment; then append its own
handoff fragment. A result response is HTTP 200 with `H2`; a pending result is
HTTP 202 with no secrets. Errors contain no credential or subject details.
Successful immediate device-only attestation returns `H2` without a handoff.
Strict schemas, caps, and exact error members remain to be frozen in section 15.

The Authority page MUST NOT pass credentials, assertions, or `H2` to the
application. It MAY POST `/step-up/abort` using its bound same-origin attempt
session and CSRF token. Result collection alone starts the short redemption
window under section 8. No arbitrary return URL or cross-frame message is accepted.

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
    RP->>A: Begin v1, immutable assurance and Q
    A-->>RP: Scoped challenge
    RP-->>B: cid, C, Authority, protocol
    B->>A: Private base attestation: cid, N, H1
    A->>A: Validate origin, peer, provider, policy; commit base acceptance
    alt Fresh person evidence required
        A-->>B: Handoff and completion tokens; no H2
        B->>W: Application embeds Authority step-up iframe
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
W = SHA-256("bytebind/v1/person/challenge" || cid || H1 || w)
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
and required UP/UV. The Authority MUST verify `clientDataJSON.origin` against
its exact configured WebAuthn origin. Step-up runs only in a cross-origin
iframe, so `crossOrigin` MUST be `true`. If `topOrigin` is present, it MUST
exactly equal the transaction's stored `allowed_origin`. If it is absent, the
assertion MAY be accepted. Safari is reported to omit `topOrigin` (Apple
Developer Forums thread 782988; no Apple documentation confirms or explains
it). In that case embedder binding rests on the per-RP `frame-ancestors` policy,
which the browser enforces, and on the handoff being scoped to this
transaction's RP (section 5). An assertion with `crossOrigin` false or absent,
or with a mismatched `topOrigin`, MUST be refused and burn only the
authenticated expected step-up generation. These rules supplement, not replace,
RP-ID, signature, challenge, UP/UV, peer, and transaction checks. Resolve the
subject from Authority credential records; validate user handle when applicable.
Signature counters follow the profile policy below; backup-state flags follow
the standard's handling. Registration follows [WebAuthn registration
verification](https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential).

An assertion is acceptable only while its linked transaction and base context
remain valid. Credential and subject status MUST be checked at acceptance and
redemption. Challenge consumption, credential-version checks, and transition to
redeemable MUST be atomic with respect to revocation. No write lock may be held
while waiting for the browser, provider, or authenticator.

Protocol v1 retains 0.7's fixed-size values, algorithms, `IP || S` plaintext,
request encoding, profile separation, and existing transcript labels:

| Purpose | Session | Transaction-bound |
|---|---|---|
| H1 | `bytebind/v1/h1` | `bytebind/v1/tx/h1` |
| HKDF info and H2 AAD prefix | `bytebind/v1/h2` | `bytebind/v1/tx/h2` |
| Redemption | `bytebind/v1/redeem` | `bytebind/v1/tx/redeem` |
| Request digest | Not applicable | `bytebind/v1/tx/request` |

All formulas and field lengths otherwise follow 0.7 sections 9.2 and 11–13. In
particular `Q` is computed by the client from its actual submitted operation.
The attested assurance is bound through immutable Authority state referenced by
`cid`; the client never supplies authoritative assurance claims. Implementations MUST use the exact v1 labels specified here and MUST NOT accept
labels from the withdrawn v2 proposal or infer negotiated draft support from a
successful MAC. Additional person-step-up vectors are required before freezing v1.

The `person/challenge` label is also part of v1's label set. This derivation
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
retention MUST accommodate the selected flow; the initial draft-0.7 short
deadline cannot remain unchanged for draft-0.8 person step-up. Authority returns relative
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

A v1 grant retains `active`, `rp_id`, `audience`, relative `expires_in`, and
`claims`. It additionally returns structured assurance evidence needed to
enforce the accepted requirement. The example below is a fresh transaction grant
and is illustrative, not a finalized schema:

```json
{
  "protocol": 1,
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
  "protocol": 1,
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

A grant MUST identify `protocol: 1`; section 2 defines strict interpretation.
When permitted, pairwise person identifiers use an Authority-only 32-byte key:

```text
person_subject = "ps_" || b64url(HMAC-SHA256(
    key = pairwise_key,
    data = "bytebind/v1/pairwise" || len(rp_id) || rp_id
           || len(subject_id) || subject_id
))
```

`rp_id` is UTF-8; `subject_id` is its stored opaque byte string; each is
preceded by its unsigned 64-bit big-endian byte length. The ASCII label is part
of the v1 label set. This explicitly length-prefixes both variable fields. Key
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

Device-only sessions retain the fixed renewal cadence and bounded device lease.
A device-plus-person session records its person association separately from its
device authorization. Person identity remains Authority-established even when
the RP is not permitted to receive a subject identifier. There is no device-wide
"last person" cache.

Creating a person association requires fresh step-up. Subsequent silent renewal
requests `assurance: device`, renews only the device lease, and preserves the
session's established person association. Session-level person assurance does
not require operator permission to reissue person evidence at every renewal.
A renewal grant that omits person evidence MUST NOT by itself erase the
association or be treated as person revocation. Background renewal never
receives a step-up variant or prompts. It MUST NOT reset the original person-
authentication time, extend the person-validity deadline, upgrade UP to UV, or
claim a fresh person assertion.

Preserving the association is not authorization to call a person-attested
endpoint. On each such call, before the handler executes, the RP MUST check:

- a currently valid device lease and all route requirements;
- the association's original assurance level, finite person-validity deadline,
  and the route's `person_max_age` measured from receipt of the fresh grant;
- current Authority status for the subject and credential, and continuity with
  the device context of the latest successful base grant for this browser lease.

The last check uses the authenticated private control channel and an opaque
Authority-held person-association handle bound to the exact RP, audience,
browser lease, subject/credential generations, and originally attested device.
The RP supplies a reference to the latest device grant; the Authority MUST bind
it to the same lease and independently match its recorded device context.
This comparison works even when device and subject identifiers are not disclosed.
Neither a public client nor a provider owner supplies the person association.
The validation result authorizes only the current session request; it is not a
fresh assertion, a new identity disclosure, or evidence for another transaction.
Exact request/result schemas and handle lifecycle are wire-freeze gates.
An unavailable Authority or a failed check MUST fail closed for the person route;
device-only routes remain subject to their existing device lease.

When person validity or route freshness has expired, the next person-attested
call requires fresh step-up. Retained association data MAY be used internally to
continue that ceremony, but MUST NOT be passed to a handler as current person
assurance or identity. Confirmed revocation, subject suspension, device mismatch,
logout, or subject switch invalidates the old association and its handles.
Known invalidation cannot be ignored until another request. A subject switch
requires fresh step-up and replacement of the browser lease and person context.
A new browser lease or another user of the same device cannot inherit it.

A transaction that requires person assurance never completes as device-only.
Transaction-bound presence or verification always requires a fresh assertion
for that exact operation, regardless of an existing session association.

Device `expires_in` keeps 0.7 section 15.1's minimum. Person validity is separately
bounded by `assurance.person_expires_in` from the last Authority confirmation;
no repeated device renewal extends it. Optional explicit person-evidence reuse
may reconfirm an unexpired association only under registration policy. Such
reconfirmation MUST match the evidence's original assurance level, RP/audience,
lease, device, and active credential/subject generations, and MUST NOT update
the original authentication time or extend the original maximum age. Lack of
this optional reuse permission does not forbid creating a verified session.

The Authority enforces its own person deadlines and returns relative validity
on the control channel. The RP also enforces its own fresh-grant receipt time
and route maximum. Cookies alone are insufficient. Association and reuse handles
are server-only secrets, never transferable between otherwise unrelated leases.

On shared devices, provide explicit session termination and use fresh transaction
step-up for sensitive operations. A retained association identifies the previously
verified session subject; it does not prove that person still occupies the
endpoint. Device renewal establishes private device participation only.

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
policies, enrollment/recovery authority, maximum person age, session-association validation, and optional person-evidence
reconfirmation permission. Required route tags must still be permitted by provider policy and
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
secrets or navigation URL. Updated clients implement the supported draft-0.8 schemas within protocol v1.
Earlier clients remain limited to the draft features they implement. Unsupported
draft capabilities never justify bypassing a requested person ceremony. Existing
client method/response APIs should be preserved for base-only calls where possible;
compatibility with changed response schemas requires explicit testing.

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
| Application script overlays or obscures the step-up iframe | Native passkey UI names the Authority RP ID; the frame's own activation starts it. Embedding origin script remains an accepted trust boundary; no informed-intent guarantee |
| Fake replacement frame | Cannot produce a valid assertion for the Authority RP ID; phishing/UI deception remains possible and does not grant person assurance |
| Another registered origin embeds this transaction's step-up page | Per-RP `frame-ancestors` admits only the transaction's RP origin; a handoff presented on another RP's path is refused; a present but mismatched `topOrigin` refuses and burns the expected generation |
| Unregistered embedding origin | Per-RP `frame-ancestors` blocks embedding; handoff authorization remains mandatory |
| Browser omits `topOrigin` (reported for Safari) | Accepted. Embedder binding rests on browser-enforced per-RP `frame-ancestors` and the RP-scoped handoff; `topOrigin` is defense in depth where present |
| Application page is itself framed by another origin | WebKit refuses WebAuthn with more than one cross-origin ancestor; person step-up requires a top-level application page |
| Enumeration of registered RPs through the person listener | Per-RP paths list one origin each; unknown `rp_id` returns a generic not-found |
| Third-party cookies blocked or partitioned | Memory-only bearer attempt session; cookies cannot be a ceremony dependency |
| Frame relays base attestation | Prohibited fixed ceremony request set; person listener serves no base-attestation endpoint |
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
without age reset; no fresh-tx evidence reuse; loss after success; exact stored-operation execution; base-only v1 transcript compatibility, draft-capability refusal, and rejection
of assurance downgrade or labels outside the specified v1 set.

Browser acceptance tests MUST use real HTTPS Authority and application origins,
private listeners, platform authenticators/security keys, and current supported
Chrome, Safari, and Firefox versions. Test local-network permissions,
synced/discoverable credentials, multiple subjects on one device, multiple
devices for one subject, cancellation, and tab closure. Test the iframe's
Permissions-Policy and CSP delegation, local-network subframe permissions and
the actual permission token names, blocked third-party cookies, the iframe's
own user activation and Safari's consent prompt, whether each browser sends
`topOrigin`, refusal when the application page is itself framed, and the
unsupported-browser message.
Virtual authenticators supplement but do not
replace these tests. No compatibility claim is made before those results exist.

Proposed demo: `/admin` device-only; `/admin/verified` bounded person
verification; `/admin/destructive-demo` fresh verified transaction.
Enrollment/management is Authority-hosted and shows the subject and friendly
credential names, with device context clearly separate. Normal device-only use
retains the no-login experience; optional enrollment and step-up are visible
ceremonies and must be described honestly.

After cross-verification and approval, update threat-model guarantees and
limits, roadmap/version notes, README/API and demo instructions, blog wording,
and protocol vectors. Handshake illustrations must identify protocol v1 and their supported spec
draft/profile; the draft-0.8 person chart shows the gated person phase. This combined draft
does not edit those shared files.

Keep verifier dependencies Authority-only; RP bindings and API clients do not
need a verifier. Exact versions/dependency claims in source drafts must be
rechecked at selection time. Generate standards-based signed test fixtures and
virtual-authenticator tests; never replace the library verifier with custom
signature/CBOR/COSE verification. Add vectors for `W`, pairwise encoding, first-delivery deadline behavior, and
explicit person endpoint revalidation after silent device-only renewal. Add tests for correct iframe
`crossOrigin`/`topOrigin`, wrong topOrigin, absent topOrigin accepted,
`crossOrigin` false refused, per-RP frame-ancestors listing exactly one origin,
handoff refused on another RP's path, generic not-found for an unknown `rp_id`,
non-frameable enrollment,
no iframe message API, and no base-attestation paths on the person listener.
Verify no options before base acceptance, no H2/proof from the frame, no identity
claims before redemption, and cookie-independent attempt tokens. The iframe
context does not alter the base flow, state transitions, or redemption semantics.

Tests MUST verify that device-only renewal preserves the association even with
reuse disabled, never resets person age, and never conveys stale person claims
to a handler. Cover endpoint-triggered validation, expired freshness, credential
revocation, Authority outage, device mismatch without identifier disclosure,
subject switch, and fresh transaction requirements. Browser tests must cover
pre-handoff capability failure, preloaded options at activation, canonical
origins, and the actual permission-policy tokens. An unsupported browser fails
closed with a frame-local message; there is no fallback browsing context.

## 15. Release gates

The combined decisions are recorded in the cross-verification guide. These
remaining gates do not reopen independent person identity, base-first gating,
Authority ownership, explicit draft/assurance capability checks, or atomic
single use.

1. **CLOSED — Claude cross-verification:** Claude reviewed the combined draft; the user decided F1–F12, and accepted patches P1–P16 have been applied. Closure is conditional on the accepted patch text and gate edits being preserved; see the reconciliation ledger for the review and resulting snapshot.
2. **OPEN — Wire freeze:** exact closed schemas, caps, paths, JSON encodings,
   version/capability negotiation, renewal evidence handle, typed errors, and
   all control/browser response variants. No fallback removes required assurance.
3. **OPEN — Browser acceptance:** iframe delegation and Safari consent,
   `topOrigin` presence per browser, local-network permission token names,
   private-network permissions, result polling, current Safari/Chrome/Firefox
   behavior, real authenticators, and discoverable/synced/shared-device cases.
4. **OPEN — Enrollment/recovery:** independently authenticated operator mechanism,
   invite transport, existing-subject recovery approvals, management UX, and
   audit policy. Recovery remains disabled until approved.
5. **OPEN — Timing and storage:** validate 30/120/30/10-second windows, exact RP
   attempt budgets, transaction cleanup, counter/revocation races, long-poll hold time and per-(peer, cid) result budget, and durable delivery reservation under lost responses and crashes. Track sequential challenge reissue after cancellation as undecided; no reissue behavior is authorized by this draft.
6. **OPEN — Evidence reuse:** server-only handle lifecycle, exact-session binding,
   logout, revocation generations, maximum-age enforcement, dual device/person lifetimes and `person_fresh` recording, endpoint-triggered
   person validation, opaque device-continuity binding, and atomic invalidation
   on known revocation, mismatch, logout, or subject switch. Device-only renewal
   omitting person evidence does not invalidate the association.
7. **OPEN — Dependency review:** tested verifier version, supported algorithms,
   parsing limits, origin hooks, counter/backup handling, license/security review.
8. **OPEN — Vectors and independent review:** all v1 transcript labels and
   encodings, state races, negative vectors, and end-to-end scope enforcement.
9. **OPEN — Multi-Authority:** credential/state sharing and stable RP-ID ownership.
   Pin each live transaction; no unreviewed failover or cross-Authority reuse.
10. **Deferred scope:** popups, full-page navigation, related origins, age display,
    non-synced/attestation-provenance profiles, and opaque address commitments
    require separate designs. They are not implemented by omission.

## 16. Additional 0.8 hardening

### 16.1 Discovery and transaction pinning

An RP MUST pin the creating Authority per `cid` and redeem only with that
Authority. Authenticated discovery MAY advertise `protocols: [1]` plus explicit supported
draft/assurance capabilities. A protocol-1 advertisement alone does not qualify
a candidate for person step-up; unsupported or malformed capabilities fail closed.
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

V1 retains `IP || S` and the original address-bearing redemption construction.
Application browser code can therefore learn the overlay IP. This accepted
boundary MUST be documented explicitly. Claude's proposed opaque `IPB`
replacement is deferred because it changes plaintext size and redemption
formulas and needs its own privacy, crypto, and interoperability review. No v1
implementation may substitute it under this specification's labels.

### 16.5 Cookie scope

Browser bindings SHOULD use `__Host-bytebind_session` and `__Host-bytebind_state`, with Secure, HttpOnly, SameSite=Strict, Path=/, and no Domain
attribute. The RP stores only hashes where appropriate and enforces server-side
lifetimes. Adopting the host prefix requires changing the old state cookie path
and reviewing co-hosted applications; it cannot be added while retaining a
narrow path that violates the prefix requirements.

