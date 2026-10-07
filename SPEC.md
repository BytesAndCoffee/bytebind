# ByteBind Protocol

**Protocol v1 · Specification 0.8-draft · Experimental implementation**
**Date:** 2026-10-06
**Copyright:** © 2026 Bytes & Coffee Digital Studio

The reference implementation in this repository targets this draft. Real-browser
acceptance and independent security review remain release gates. Draft 0.7 is
in git history at commit `3072234`; older code section citations refer to that draft.
Review records for this draft are in
[docs/drafts/SPEC-0.8-REVIEW-NOTES.md](docs/drafts/SPEC-0.8-REVIEW-NOTES.md).
Open verification work and release gates are in
[docs/ROADMAP.md](docs/ROADMAP.md).

## 1. Scope and conformance

This document specifies protocol v1 at specification version 0.8. It defines
the public and private exchanges, both request profiles, byte encodings,
cryptographic transcripts, transaction lifecycle, grants, leases, provider
integration, and optional Authority-owned person attestation. No earlier draft
is needed to interpret it.

MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY express requirements of this
protocol. They don't claim implementation support. Endpoint names, JSON member
names in examples, and binding syntax are provisional until wire freeze.

Device-only authentication stays ambient when private-network access and
browser permissions allow it. Person-gated access adds an Authority-owned
passkey ceremony after device authorization. Out of scope: federation,
OIDC/SAML integration (including the draft-0.7 device-bound IdP profile),
acting as an authenticator, third-party passkey RP IDs, and human identity
federation.

## 2. Overview

ByteBind authorizes management access to a public application through a fresh
exchange involving an authorized device on a private overlay network. The
client receives a challenge from the application, completes an attestation
request on the private network, and returns a redemption proof. The application
redeems that proof with the Authority before issuing a lease or executing a
protected request.

The **session profile** grants a short management lease renewed through further
attestation. The **transaction-bound profile** binds authorization to one stored
application request. Network departure stops successful renewals; an existing
lease remains valid until its server-side deadline.

When an application requires it, the Authority additionally requires a fresh
WebAuthn assertion from a registered person **after** device authorization
succeeds (sections 11–16).

### 2.1 Goals

- Keep the application's management interface on its public HTTPS origin.
- Require a fresh exchange through an explicitly authorized private device.
- Bind the public and private exchanges through cryptographic proofs.
- Consume transactions once and scope grants to the application and policy.
- Release only the identity claims the application needs.

### 2.2 Trust assumptions and limits

The Authority, registered RP, overlay identity service, and authorized device
are trusted for their roles. Whoever controls the Authority's provider tag or
capability is an approved operator. Device attestation establishes device-backed
participation, not the current person. Applications that need person presence or
verification MUST request the corresponding assurance (section 10), and MUST NOT
assume that device identity shows which person is present. Neither device nor
person assurance proves informed approval of a transaction.

The challenge and attestation secrets are transferable. Possessing them doesn't
identify a browser process or prevent deliberate relay by an authorized
participant. A copied application session cookie remains usable while its
server-side lease is valid. Compromise of an authorized device or of the
Authority is outside this threat model.

### 2.3 Parties and state ownership

| Party | Responsibility |
|---|---|
| Client | Browser or API client code that obtains a challenge, calls the private attestation endpoint, and returns a proof |
| Relying Party (RP) | Public application that creates transactions, redeems proofs, and enforces its own sessions and operations |
| Authority | Owns transactions, authenticates RPs, identifies private peers, evaluates policy, owns person credentials, and issues grants |
| Attestation provider | Authority component mapping a private connection to authenticated overlay identity and policy claims |

The Authority MUST own all ByteBind transaction state. The RP MUST access that
state only through the authenticated control channel (section 3.2), including
when both run on the same host. Their databases MUST remain separate. The RP
keeps its own browser-attempt bindings, leases, and stored application requests.

## 3. Channels

### 3.1 Client ↔ RP

Public HTTPS carries the access request, challenge response, completed proof,
and application response. The RP validates its browser origin and manages its
own cookies and request authorization.

### 3.2 RP ↔ Authority control channel

The control channel MUST be authenticated and confidential. Two transports are
defined:

- **HTTPS between overlay nodes.** Both endpoints MUST be on the private overlay,
  and the connection MUST remain on it. The Authority MUST identify the RP from
  the authenticated overlay identity of the connecting node, and MAY also
  require mTLS or a per-RP credential. The RP MUST verify the Authority's
  certificate for its overlay name.
- **Unix domain socket on a shared macOS, Linux, or BSD host.** The socket MUST
  be in a directory writable only by the Authority account, and access MUST be
  limited to the Authority and registered RPs. Authentication is mutual:
  - The Authority MUST identify the RP from kernel-reported peer credentials
    (`SO_PEERCRED`, `getpeereid`, or `LOCAL_PEERCRED`) mapped to a registered
    RP.
  - On every connection, the RP MUST verify the Authority's peer credentials
    against a configured Authority UID, and MUST verify that the containing
    directory is owned by root or that UID and isn't writable by other
    accounts, and MUST verify the socket's ownership and access policy. A
    socket path's existence authenticates neither party.

Transport identity MUST map unambiguously to one registered RP. Several RPs
sharing a node or UID need a per-RP credential or an equivalent independently
authenticated binding. Permissions don't isolate processes sharing a UID.

The Authority MUST bind each auth set to the RP that requested it so another RP
can't redeem it.

### 3.3 Client ↔ Authority

The client calls the Authority's private HTTPS **attestation listener**
directly. The Authority maps the accepted connection to overlay identity. It
returns the encrypted attestation response only after the transaction becomes
redeemable (section 14).

Person ceremonies MUST use a separate private HTTPS **person listener** (section 11).
The two MAY share a hostname on different ports. The person listener MUST NOT
answer application-origin CORS.

## 4. Values, encoding, and labels

Unless noted, byte values are encoded in JSON as unpadded base64url.

| Value | Size | Generated by | Purpose |
|---|---:|---|---|
| `cid` | 16 bytes | Authority | Opaque challenge identifier |
| `C` | 32 bytes | Authority | Public-channel challenge secret |
| `S` | 32 bytes | Authority | Attestation/redeem secret |
| `N` | 32 bytes | Client | Client freshness nonce |
| `IP` | 16 bytes | Authority | Attested peer address as IPv6; IPv4 uses IPv4-mapped IPv6 |
| `IV` | 12 bytes | Authority | AES-GCM nonce |
| `H1` | 32 bytes | Client | Initial proof MAC |
| `H2` | 76 bytes | Authority | `IV` ‖ 48-byte encrypted `IP ‖ S` ‖ 16-byte GCM tag |
| `R` | 32 bytes | Client | Redemption MAC |
| `Q` | 32 bytes | Client and RP independently | Transaction request digest |
| `w` | 32 bytes | Authority | Person-challenge randomness |
| `W` | 32 bytes | Authority | Derived WebAuthn challenge |

All random values MUST come from a cryptographically secure generator. Each
challenge MUST be single-use.

JSON members are case-sensitive. Each endpoint MUST validate against its
declared schema and reject a body with a missing required member, an unknown
member, a value that isn't canonical unpadded base64url, or a value of the wrong
decoded length.

### 4.1 Labels

Every cryptographic transcript MUST begin with a protocol-specific label.
Protocol v1 uses exactly these ASCII labels:

| Purpose | Session profile | Transaction-bound profile |
|---|---|---|
| Request digest `Q` | — | `bytebind/v1/tx/request` |
| `H1` | `bytebind/v1/h1` | `bytebind/v1/tx/h1` |
| HKDF info and `H2` AAD prefix | `bytebind/v1/h2` | `bytebind/v1/tx/h2` |
| Redemption `R` | `bytebind/v1/redeem` | `bytebind/v1/tx/redeem` |
| Person challenge `W` | `bytebind/v1/person/challenge` | same |
| Pairwise subject | `bytebind/v1/pairwise` | same |

Implementations MUST NOT accept other labels, MUST NOT reuse a label for a
different meaning, and MUST NOT infer negotiated draft support from a
successful MAC. Predecessor labels (`tailbind/v1/*`, `bd-mgmt/v1/*`) MUST NOT be
accepted. Transcript fields have fixed lengths, except the variable-length
fields of `Q` and the pairwise subject, which are length-prefixed. Any future
variable-length field MUST use an unambiguous encoding.

`len(x)` is the byte length of `x` as an unsigned 64-bit big-endian integer.

## 5. Exchanges and profiles

| Caller → receiver | Request | Response | Section |
|---|---|---|---|
| Client → RP | Access request (application-defined path) | Challenge | 6 |
| RP → Authority | `POST /v1/transaction` (control) | RP-scoped transaction material | 6 |
| Client → Authority | `POST /attestation` with `cid`, `N`, `H1` | `H2`, or HTTP 202 person step-up | 7, 8, 12 |
| Client → Authority (person page) | Handoff, options, assertion, abort (person listener) | Ceremony state | 12 |
| Client → Authority | `POST /attestation/result` | `H2` or HTTP 202 pending | 12 |
| Client → RP | Proof submission (application-defined path) with `cid`, `R` | Lease or operation result | 9 |
| RP → Authority | `POST /v1/redemption` (control) | Scoped grant | 9 |
| RP → Authority | Person-association validation (control) | Current person status for a lease, or refusal | 17.3 |

Authority paths are those of the reference design; deployments MAY use other
paths but MUST preserve the specified payloads and checks. The RP calls the
control endpoints while handling the corresponding client request, and returns the application response only after successful redemption
and local authorization.

Processing order:

1. The client requests a lease or submits a protected operation to the RP.
2. The RP creates a transaction with the Authority and returns its challenge.
3. The client submits its initial proof directly to the private Authority.
4. The Authority authorizes the device and, after any required person step-up,
   releases the encrypted secret under the delivery rules of section 14.
5. The client submits a redemption proof to the RP.
6. The RP redeems it with the Authority and applies the grant.

### 5.1 Session profile

The access request asks to create or renew a management lease. There is no
`Q`. Redemption consumes the proof and returns a grant for the scoped lease; the
RP creates or renews the lease and returns the application response.

### 5.2 Transaction-bound profile

The privileged application request *is* the access request, bound to the
transaction by:

```text
Q = SHA-256( "bytebind/v1/tx/request"
             || len(method)  || method
             || len(target)  || target
             || len(headers) || headers
             || len(body)    || body )
```

`method` is the uppercase ASCII method; `target` the path and query as sent;
`headers` the profile-selected headers as `name:value` lines (name lowercased,
surrounding whitespace trimmed from name and value), sorted by code point and
joined by `\n`; `body` the body bytes. A profile MAY narrow the covered headers
but MUST NOT change this encoding.

The client MUST compute `Q` from its submitted request and MUST NOT substitute
an RP-supplied digest. The RP MUST send `Q` in transaction creation. The
Authority MUST store it and verify `H1` and `R` against it. The RP MUST store
the request (or enough to execute it) under the `cid`, MUST execute only that
stored request, MUST NOT execute it before a valid grant, and MUST execute it at
most once. The application response is the operation's actual result.

The two profiles use different labels, so a transcript always identifies its
profile and one can't be accepted as the other.

## 6. Transaction creation and challenge

### 6.1 Control request

Before executing a protected operation or issuing a lease, the RP creates a
transaction over the control channel:

```http
POST /v1/transaction
Content-Type: application/json

{"protocol":1,"audience":"manage","profile":"session","assurance":"device"}
```

The request MUST identify `protocol`, `audience`, `profile`, and `assurance`
(section 10). A transaction-bound request adds `Q`. A person session adds a
finite maximum person age. Identity disclosure is requested separately. RP
registration supplies origin and policy and constrains every field. The
Authority MUST reject malformed profile/`Q` combinations and unsupported values,
and MUST validate `allowed_origin` against the requesting RP's registration
rather than accept an origin the RP asks for. One RP MUST NOT obtain an auth set
bound to another RP's origin.

The Authority generates `cid = random(16)`, `C = random(32)`, `S = random(32)`
and stores at least: `cid`, `C`, `S`, `rp_id`, `audience`, `allowed_origin`,
policy, `protocol`, `profile`, `assurance`, person maximum age (person sessions),
`Q` (transaction-bound), `status = pending`, a generation counter, and
`challenge_expires_at` (section 21).

It returns RP-visible material: `cid`, `C`, the attestation URL, `expires_in`
(seconds until the attestation window closes), and, for person transactions,
`person_origin` from its configuration. Times on the control channel are
relative durations, never absolute timestamps. Device identity, peer metadata,
and `S` SHOULD remain Authority-side.

### 6.2 Protocol and draft capability

ByteBind is protocol **v1**; drafts 0.7 and 0.8 are pre-release specifications
of it, not coexisting versions. After a stable release, incompatible changes to
field encodings, transcript structure, key derivation, encryption, challenge
semantics, or attestation semantics MUST use a new cryptographically separated
protocol label. Implementations MUST NOT silently reinterpret a v1 transcript
under a later version.

The `protocol: 1` marker identifies the protocol family, not support for every
draft-0.8 feature. RPs and Authorities MUST explicitly agree on supported draft
schemas and assurance capabilities, through configuration or authenticated
capability negotiation. Unsupported schemas or assurance MUST fail, and no
retry may remove a person requirement. A draft-0.7 implementation MUST NOT be
selected for a person transaction. Endpoint processing follows stored
transaction scope, not an asserted client version.

### 6.3 Challenge response

The RP forwards the client portion:

```json
{"protocol": 1, "cid": "<base64url>", "C": "<base64url>",
 "authority": "https://authority.example.ts.net:8443"}
```

The client sends attestation to `<authority>/attestation`. Person transactions
also carry `person_origin`, which the RP MUST NOT alter. The challenge MUST NOT
carry an expiry.

The RP MUST refuse an access request whose `Origin` isn't its own public origin.
The access request is unauthenticated but makes the RP store state and call the
Authority. The RP MUST bound access-request body size and its pending
transactions, and the Authority MUST bound pending transactions per RP.

The RP MAY issue a short-lived state cookie binding the browser to this attempt
(`HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, no `Domain`, a `__Host-`
name SHOULD be used, short expiry). The RP SHOULD store only its hash.

## 7. Attestation request

The client generates `N = random(32)` and computes, for the session profile:

```text
H1 = HMAC-SHA256(key = C, data = "bytebind/v1/h1" || cid || N)
```

or for the transaction-bound profile:

```text
H1 = HMAC-SHA256(key = C, data = "bytebind/v1/tx/h1" || cid || N || Q)
```

It MUST send the request directly to the Authority:

```http
POST /attestation
Content-Type: application/json
Origin: https://public.example

{"cid": "<base64url>", "N": "<base64url>", "H1": "<base64url>"}
```

The Authority selects the transcript from stored profile scope, never from the
client. It MUST take the peer address from the accepted socket and MUST NOT
trust forwarded-address headers.

### 7.1 Required checks

The Authority MUST check, in order:

1. `Origin` exactly matches some registered RP origin, and `Host` exactly
   matches the expected attestation host. Failing requests MUST be refused
   without reading or changing transaction state.
2. `Content-Type` is `application/json`. This forces a CORS preflight; the
   Authority MUST refuse `text/plain`, `application/x-www-form-urlencoded`, and
   `multipart/form-data`.
3. `cid` exists, is `pending`, and is inside its attestation window.
4. `Origin` exactly matches the `allowed_origin` stored with that `cid`.
   Matching *some* registered origin isn't enough: otherwise a page on RP A
   could attest a challenge an attacker got from RP B, read `H2`, open it with
   the attacker's `C`, and redeem at RP B.
5. `H1` is valid, compared in constant time.
6. The socket peer address is in the provider's private address space.
7. The provider identifies the peer as a valid node.
8. Authority policy authorizes that node.
9. The transaction transitions atomically `pending → base_attested`, recording
   the device context and the accepted `N` and `H1`. Section 14 governs what
   follows. No person-required transaction releases `H2` before its assurance
   is satisfied.

The v1 endpoint refuses a `cid` whose stored scope it doesn't support. A failure
at check 3 or later MUST burn an existing challenge only from the expected
`pending` state and generation. An unknown `cid` has nothing to burn. A request
that lost a race MUST NOT burn the winner's newer state.

### 7.2 Atomicity

Every transition is a single conditional update on expected state **and**
generation that must change exactly one row; that update is the concurrency
protection. A write lock MUST NOT be held across provider or verifier calls.

```sql
UPDATE challenges
SET status = 'base_attested', attested_ip = ?, attested_peer_id = ?,
    accepted_N = ?, accepted_H1 = ?, attested_at = :now,
    generation = generation + 1
WHERE cid = ? AND status = 'pending'
  AND challenge_expires_at > :now AND generation = :expected_generation;
```

Zero updated rows means failure: another request won, or the window closed.
Burns and transitions MUST be durable before the response is sent, including on
error paths. Rolling back a burn silently re-arms the challenge.

## 8. Attestation response

Only after the assurance requirement is satisfied, the transaction is
`redeemable`, and the Authority has committed its first delivery reservation
(section 14), does it return a response only a holder of `C` can open:

```text
K   = HKDF-SHA256(ikm = C, salt = H1, info = <h2 label>, length = 32)
P   = IP || S
IV  = random(12)
AAD = <h2 label> || cid || N || H1
E   = AES-256-GCM(key = K, iv = IV, plaintext = P, aad = AAD)   # includes the tag
H2  = IV || E
```

`<h2 label>` is `bytebind/v1/h2` or `bytebind/v1/tx/h2` by profile. `IP` is the
address observed by the Authority and stored with the challenge. The response is
`{"H2": "<base64url>"}`.

The client derives `K`, decrypts with the exact `AAD`, rejects the response if
authentication fails, and extracts `IP` and `S`.

## 9. Proof, redemption, and grant

The client computes, for the session profile:

```text
R = HMAC-SHA256(key = S, data = "bytebind/v1/redeem" || cid || C || IP)
```

or for the transaction-bound profile:

```text
R = HMAC-SHA256(key = S, data = "bytebind/v1/tx/redeem" || cid || C || IP || Q)
```

and submits `{"cid": "<base64url>", "R": "<base64url>"}` to the RP's proof
endpoint. The client MUST NOT submit an independently chosen `IP`. The RP MUST
refuse a proof submission whose `Origin` isn't its own public origin, MUST check
its state cookie if it set one, and MUST wait for a valid grant before executing
a request or issuing a lease.

### 9.1 Redemption

The RP sends `{"cid", "R", "audience"}` to `POST /v1/redemption`. The Authority
verifies:

1. `cid` exists.
2. It belongs to the requesting RP and audience. Otherwise refuse **without**
   burning the legitimate transaction.
3. State is exactly `redeemable`, and first result delivery has been reserved.
4. It is inside the redemption window, which starts at the committed delivery
   reservation (section 14).
5. `R` matches, using stored `S`, `C`, attested `IP`, and `Q` if applicable.
6. The transaction transitions atomically `redeemable → redeemed`.

A failure at check 3 or later MUST burn only from the expected `redeemable`
state and generation. A losing request MUST NOT burn a concurrently redeemed or
newer record. A redeemed transaction MUST NOT be redeemable again.

### 9.2 Grant

The grant MUST be scoped to the RP, audience, policy, and transaction bound at
creation, and MUST identify `protocol: 1`:

```json
{"protocol": 1, "active": true, "rp_id": "example-rp", "audience": "manage",
 "expires_in": 180,
 "assurance": {"device_attested": true, "user_present": false, "user_verified": false},
 "claims": {"device_id": "node-abc123", "authorization": ["manage:read"]}}
```

Section 16 defines the person members of `assurance` and the disclosure rules.
The RP MUST validate the grant before applying it. `expires_in` is seconds from
receipt, measured on the RP's clock. A lease or other authority derived from a
grant MUST NOT outlast it; the RP MAY end it sooner. A grant MUST NOT carry
absolute timestamps.

### 9.3 Application response

Only after a valid grant MAY the RP exercise the granted authority: execute the
stored request once (transaction-bound), or create or renew the lease (session).
The RP remains responsible for its session cookie, CSRF protection, application
authorization beyond the grant, logout, session expiry, and at-most-once
execution.

When executing a stored request, the RP MUST authorize using only the stored
method, target, covered headers and body, the grant, and RP-held state bound at
creation. Cookies, credentials, or headers from the proof submission MUST NOT
select an application principal or change the operation. Credentials the
operation needs are bound at creation, through covered request fields or a
stored authenticated principal. `Q` MUST still cover the exact selected request
bytes; a stored principal is not cryptographic coverage of omitted fields.

## 10. Identity and assurance

### 10.1 Independent device and person identities

**Person identity MUST be independent of provider/device ownership identity.**
A provider may report an account, owner, or principal associated with a device,
but ByteBind MUST NOT treat that as the person presently participating. WebAuthn
person attestation lets shared devices, kiosks, tagged service devices, and
other multi-user endpoints establish the current human subject independently of
the device's overlay identity.

A `person_subject` is an Authority-managed subject with registered credentials;
a `device_id` is a provider-managed endpoint identity. The namespaces MUST stay
distinct in storage, policy, and grants. Provider owner metadata MUST NOT
populate `person_subject`, authorize attaching a credential to a person, or
select the current person. This prohibition MUST be unconfigurable; an optional
mapping, even disabled by default, is not allowed. A separately expressed
pairing policy MAY require two independently established facts (this subject on
this device) without equating them.

One subject MAY use several credentials and devices; one device MAY be used by
several subjects. Enrollment MUST NOT intrinsically bind a credential to a
device. Synced credentials are permitted.

Device authorization, credential-authenticated subject, user presence (UP), and
user verification (UV) are separate facts. WebAuthn establishes none of civil
identity or informed transaction intent. Any future identity-provider bridge
MUST preserve these distinctions.

### 10.2 Assurance levels

Each transaction stores an immutable assurance requirement, accepted from the
authenticated RP and constrained by its registration:

| Requirement | Meaning |
|---|---|
| `device` | Base provider authorization only |
| `presence` | Base authorization plus a current credential assertion with UP |
| `verification` | Base authorization plus a current assertion with UP and UV |

Both person levels resolve a subject internally without necessarily disclosing
it. Person authorization (for example membership in an operator-managed subject
set) MAY also be required. A presence result MUST NOT satisfy verification.
Transaction-bound person assurance MUST be fresh for that transaction; no
cached evidence satisfies it.

The RP MUST bind the requirement to the route before creation and keep it with
the stored operation or lease attempt. A client-supplied level isn't
authoritative. The Authority MUST enforce the requirement before issuing a
grant, and the RP MUST check returned assurance before executing or allowing the
route. Missing evidence fails closed. Static `authorization` strings MUST NOT
manufacture person evidence.

Presence requests MUST use `userVerification: "discouraged"`; verification
requests MUST use `"required"`. The Authority MUST check the returned UP and UV
flags regardless. Incidental UV on a presence request MAY be recorded, but
reuse or stronger disclosure still needs registration permission. No prompt or
options call is evidence.

## 11. Person step-up: browser context

The Authority owns the WebAuthn RP ID, origins, challenges, credentials, subject
associations, verification, enrollment, management, and claim disclosure. The RP
MUST NOT verify assertions, store credentials, or operate enrollment.

### 11.1 Origin and RP ID

One stable private HTTPS Authority origin serves person enrollment and step-up.
Its RP ID MUST be that origin's exact hostname, not a parent domain. Changing it
requires a credential migration plan. Operators MUST configure the exact
WebAuthn origin, independently of application origins. All registered
application and Authority origins MUST be stored in browser-serialized form
(lowercase scheme and host, default port omitted, canonical host); configuration
MUST reject other forms, including an explicit `:443`.

The person listener MUST refuse requests whose `Host` isn't its configured
authority, before reading state. TLS and socket-peer checks apply as on the
attestation listener.

### 11.2 Iframe only

Person step-up runs only in an Authority-origin iframe embedded by a
**top-level** application page after successful base attestation. Popups,
full-page navigation, and related-origin credential use aren't part of this
profile. Enrollment and management are top-level Authority pages the user visits
directly; `create()` never runs in a frame. Background renewal MUST NOT embed
the step-up frame or invoke a person ceremony.

The step-up page is served per RP at `/step-up/<rp_id>`. That response MUST send
`frame-ancestors` listing exactly that RP's registered origin, with no wildcards.
The handoff exchange MUST refuse a handoff whose transaction belongs to another
RP, burning only the expected generation. An unknown `rp_id` returns a generic
not-found. Per-RP paths avoid exposing every origin in one response; RP
identifiers and each path's framing origin aren't secret and may be enumerable.
Enrollment and management pages MUST send `frame-ancestors 'none'` and
`Cross-Origin-Opener-Policy: same-origin`. No other person page is frameable.

Person pages MUST use a restrictive CSP, no third-party scripts, no referrers,
and no caching. Same-origin POSTs MUST validate exact `Origin` and an
attempt-bound CSRF token. Enrollment and management cookies MUST be `Secure`,
`HttpOnly`, and narrowly scoped, and their presence alone never authorizes
anything. The step-up attempt MUST NOT depend on cookies: the handoff exchange
returns an attempt-bound bearer token held only in the frame's memory, sent in a
request header on its options, assertion, and abort requests, and used as the
CSRF token. It is scoped to the transaction, device, generation, and deadline,
and is never exposed to the application, persisted, or logged.

### 11.3 Embedding

The application embeds the step-up page after validating its URL (section 12):

```html
<iframe src="<person_origin>/step-up/<rp_id>#<handoff>"
        allow="publickey-credentials-get <person_origin>; local-network <person_origin>; local-network-access <person_origin>">
</iframe>
```

The embedding page MUST be top-level: WebKit refuses WebAuthn in a frame with
more than one cross-origin ancestor. Application `Permissions-Policy` and CSP
`frame-src`, when present, MUST permit the person origin. The iframe MUST NOT be
sandboxed in a way that removes its origin. Both local-network token names are
delegated because browsers have used each; the names are provisional.

The iframe MUST NOT send or accept messages to or from its embedder. It MUST NOT
perform, proxy, or relay base attestation, handle `H2`, submit the proof, or
disclose identity results. Its only requests are handoff, options, assertion,
and abort to its own origin. The application learns the outcome only by result
polling (section 12).

Before exchanging the handoff, the page MUST check that the WebAuthn API is
present and, where the browser exposes it, that `publickey-credentials-get` is
allowed. If either check fails it MUST NOT exchange the handoff; it shows
frame-local text that person verification can't complete here, grants nothing,
and the attempt expires. After a successful exchange it fetches options at once.
It MUST show its own "Verify with passkey" control, enabled only when options
are ready, and MUST call `get()` directly from that control's activation with no
intervening network request. Once the handoff is consumed, any retry needs a new
transaction.

Browser behavior (delegation, consent prompts, `topOrigin`, local-network
permissions) is not assumed; see the acceptance gates in ROADMAP.

## 12. Person step-up exchanges

1. The RP creates a transaction with a person assurance level; the challenge
   carries `person_origin` from Authority configuration.
2. The client sends the attestation request (section 7).
3. The Authority runs checks 1–8 and records `base_attested`. A failed base
   check MUST NOT produce a handoff, options, or a prompt instruction.
4. The Authority returns HTTP 202:
   ```json
   {"step_up":{"url":"https://authority.example:8444/step-up/moderation","handoff":"<base64url>","completion":"<base64url>"}}
   ```
   `handoff` and `completion` are separate one-use 32-byte tokens scoped to the
   `cid`, RP, and accepted device. No `H2` or `S` is exposed.
5. The client MUST validate `url` against the exact `person_origin` from its
   challenge, with a path of exactly `/step-up/` plus one non-empty `rp_id`
   segment, and MUST reject other schemes, credentials, origins, queries, or
   fragments. It then embeds the page (section 11.3) with its own handoff
   fragment. The page removes the fragment, runs its capability checks, and
   exchanges the handoff by same-origin POST. The Authority re-checks the socket
   peer, requires the same provider identity as the base attempt, and atomically
   consumes the handoff (`base_attested → stepup_pending`) before issuing options
   and the attempt token. This re-check doesn't replace base attestation.
6. The page runs the assertion and posts it to the Authority. Verification and
   the transition to `redeemable` (sections 13–14) finish durably before success
   is reported. The page MAY post `/step-up/abort`, which burns the expected
   generation.
7. The application page posts exactly `{cid, completion, N, H1}` to
   `/attestation/result`. The endpoint checks the RP `Origin`, `Host`, that the
   socket peer address equals the stored attested address, and the stored `cid`,
   `N`, and `H1` (constant-time). At delivery it also runs the full provider
   identity and policy check (section 14). A pending result is HTTP 202 with no
   secrets and consumes nothing; a delivered result is HTTP 200 with `H2`,
   released at most once.
8. The client decrypts `H2`, computes `R`, and submits the proof (section 9).

Result requests SHOULD be long-polled (held up to 10 seconds). Clients MUST NOT
have more than one outstanding result request per attempt, or send more than one
per 2 seconds, and MUST stop on a terminal response or their local budget.
Result requests are rate-limited per (peer, `cid`), not against the device's
attestation budget. The page keeps proof inputs in memory only and MUST NOT
persist them. An expired or cancelled attempt needs a new transaction.

Handoff, completion, and attempt tokens are bearer secrets, not identities. They
MUST NOT be logged or included in analytics. A stolen token without the required private device context
MUST NOT authorize a ceremony or result retrieval.

```mermaid
sequenceDiagram
    participant B as Application page
    participant RP as Application RP
    participant A as Authority
    participant W as Authority step-up iframe
    B->>RP: Request protected route
    RP->>A: Create transaction (assurance, Q)
    A-->>RP: Scoped challenge
    RP-->>B: protocol, cid, C, authority, person_origin
    B->>A: POST /attestation (cid, N, H1)
    A->>A: Checks 1–8; commit base_attested
    alt Person assurance required
        A-->>B: 202 step_up (url, handoff, completion)
        B->>W: Embed /step-up/<rp_id>#handoff
        W->>A: Exchange handoff; peer re-check
        A-->>W: Options (challenge W)
        W->>A: Assertion
        A->>A: Verify; commit redeemable
        loop Long poll
            B->>A: POST /attestation/result (cid, completion, N, H1)
        end
    end
    A-->>B: H2 (first delivery reserved)
    B->>RP: cid, R
    RP->>A: Redemption
    A-->>RP: Grant
    RP-->>B: Lease or operation result
```

## 13. Assertion verification and binding

Only after base acceptance, the Authority generates `w = random(32)` and
derives the WebAuthn challenge:

```text
W = SHA-256("bytebind/v1/person/challenge" || cid || H1 || w)
```

`cid` is 16 bytes; `H1` and `w` are 32 bytes. The Authority stores `W` and `w`
and maps them to exactly one `cid`, generation, RP, audience, profile, `Q`,
device, `N`, `H1`, assurance, RP ID/origin, and deadline. These MUST NOT
change after options are issued. `W` is a transcript commitment carried as an ordinary
WebAuthn challenge, not a new signature format, and not an audit mechanism.

Verification MUST follow WebAuthn assertion verification (type, challenge,
origin, RP-ID hash, credential ownership, signature, required UP/UV), plus:

- `clientDataJSON.origin` MUST equal the configured Authority origin.
- `crossOrigin` MUST be `true`.
- If `topOrigin` is present, it MUST equal the transaction's `allowed_origin`.
  If absent (reported for Safari), the assertion MAY be accepted: embedder
  binding then rests on the per-RP `frame-ancestors` policy and the RP-scoped
  handoff, both mandatory.
- Any other combination MUST be refused, burning only the expected step-up
  generation.
- The subject is resolved from Authority credential records, with the user
  handle validated.
- Credential and subject status MUST be checked at acceptance and at
  redemption. Challenge consumption, credential-version checks, and the
  transition to `redeemable` MUST be atomic with respect to revocation.
- **Signature counter policy:** if either the stored or received counter is
  non-zero and the received value is less than or equal to the stored value,
  the Authority MUST refuse, burn the expected generation, and raise an
  operator-review event. A counter that stays zero isn't evidence of cloning.
  Counter comparison and update MUST be atomic. This is a chosen policy, not a
  claim that regression proves a clone. Backup-state flags follow WebAuthn and
  establish neither person nor device identity.

An assertion is acceptable only while its transaction and base context remain
valid.

## 14. States, deadlines, and failures

| State | Next | Condition |
|---|---|---|
| `pending` | `base_attested` | All base checks and the conditional update succeed |
| `base_attested` | `stepup_pending` | One handoff accepted; options issued |
| `base_attested` | `redeemable` | Device-only requirement |
| `stepup_pending` | `redeemable` | Assertion and subject policy succeed atomically |
| `redeemable` | `redeemed` | Correct RP-scoped proof consumed atomically |
| any live state | `burned` | Applicable failure, cancellation, or expiry |

These six are the only states; `redeemed` and `burned` are terminal. Expiry is a
comparison against stored deadlines. Each update MUST match expected state and
generation; a race loser MUST NOT burn a winner's later state. Burns and
transitions MUST commit before the response, on exception paths too. At most one
WebAuthn challenge may exist per `cid`; a retry needs a new transaction.

Result delivery is a separate one-use reservation. It commits before the
response is written, so a lost response consumes the result. Before delivery,
redemption MUST fail even in `redeemable`.

| Window | Default | Starts |
|---|---|---|
| Base attestation | 30 s | Transaction creation |
| Overall person completion | 120 s | Base acceptance |
| Result collection | 30 s, capped by the overall limit | Becoming `redeemable` |
| Redemption | 10 s | Committed first delivery |

No deadline is extended by polling, handoff, retries, or failed verification.
First delivery creates the redemption deadline and never resets it. Before
issuing options, accepting an assertion, and delivering a result, the Authority
MUST confirm current private device identity and policy (a pending result needs
only the address match of section 12). An expired base deadline can't be
revived. Policy change before redemption MUST refuse obsolete authorization. RP
attempt retention MUST cover the selected flow.

| Event | Required behavior |
|---|---|
| Foreign `Origin`/`Host` | Reject before reading or changing state |
| Base validation failure after lookup | Burn only the expected `pending` generation |
| Wrong handoff or completion token | Reject without mutating an unrelated attempt |
| Invalid assertion, missing required UV, disabled subject, revoked credential | Burn the expected step-up generation |
| Cancellation from the bound Authority page | Burn the expected generation; no grant |
| Browser closes or cancels silently | The deadline expires the attempt |
| Concurrent options or assertions | One conditional winner; generic refusal for the rest |
| Step-up succeeds but delivery is lost | No new secret and no operation retry; a new attempt only under application retry policy |
| Wrong RP attempts redemption | Refuse without burning |
| Bound RP submits invalid redemption | Burn the expected `redeemable` generation |
| Redemption response lost | Remains consumed; operation outcome may be unknown |

The RP MUST execute a stored operation at most once and MUST NOT automatically
retry one that may have executed. Every intermediate state counts toward bounded
per-RP and per-device outstanding work, and provider and verification work MUST
be rate-limited.

## 15. Subjects, enrollment, and credentials

| Record | Contents |
|---|---|
| Subject | Opaque ID, random WebAuthn user handle, status, policy memberships, revocation generation, provenance (`self_enrolled` if applicable) |
| Credential | Subject ID, credential ID and public key, algorithm, counter and backup state, friendly name, status/version |
| Enrollment attempt | Private context, target subject or new-subject permission, challenge, deadline, one-use generation |
| Step-up attempt | Transaction linkage (section 13), token hashes, challenge, accepted credential/version |
| Person association | Opaque handle, RP/audience, lease, device context, subject/credential generations, level, original authentication time, deadline |

The Authority MUST NEVER receive or store credential private keys. Credential
IDs and user handles are Authority-private and MUST NOT appear in grants. Device
observations and provider owner metadata MAY be retained for audit under a
minimization policy, with bounded retention; they aren't ownership records and
MUST NOT establish person identity or authorize attaching a credential. Names are untrusted display strings.

Enrollment MUST require a private context authorized by a dedicated enrollment
policy; authorization for an ordinary application isn't enough. That context
admits a device to enrollment; it doesn't prove whose credentials may change.

- **New subject:** requires an operator-issued invite or an explicitly enabled
  self-enrollment policy. Self-enrolled subjects MUST keep a `self_enrolled`
  flag, and an RP MUST explicitly accept that provenance before receiving or
  authorizing one.
- **Attaching a credential to an existing subject:** requires fresh
  verification with an existing credential of that subject plus authorization to
  manage it, or an approved recovery procedure with independent operator
  authentication and audit. A name, provider owner, device tag, or bare subject
  ID MUST NOT suffice, and subjects MUST NOT be merged by name or owner.
- **Invites:** 32 random bytes stored only as a hash; scoped to one subject and
  purpose (`new_subject` or `add_credential`); valid 15 minutes by default, at
  most 24 hours. Invites MUST be delivered out of band, MUST be redacted from
  logs, and MUST be consumed only from an enrollment-authorized context, where
  consumption creates one registration attempt. An
  `add_credential` invite supplements fresh existing-credential verification and
  replaces it only when issued through approved recovery.

Registration MUST:

- use one-use challenges, exact Authority `Origin`, CSRF protection, device
  policy revalidation, and bounded lifetimes;
- not use conditional mediation, and verify that the UP bit is set;
- require discoverable credentials and UV;
- use the subject's random user handle, and exclude existing credential IDs.

Labels MUST NOT derive from provider principals. Attestation conveyance SHOULD
be `none`; authenticator-provenance and non-synced policies are deferred.

The management UI supports register, name, list, and revoke. Changing an
existing subject's credentials requires fresh verified authentication. Recovery
is disabled until an approved procedure exists, and MUST NOT fall back to
provider ownership. A recovery interface MUST authenticate its operator
independently, audit changes, and invalidate affected associations. Revoking the last credential MAY leave a subject unable to
authenticate until recovery. Revocation invalidates pending step-ups and person
associations at the Authority immediately; issued RP leases end at their bounded
deadlines (there is no push revocation to RPs).

## 16. Grants and disclosure

The Authority is a policy enforcement point and privacy boundary. It may know
peer address, stable node ID, provider account and owner, tags, shared status,
posture, subjects and credentials, and full transaction state. An RP receives
only what its registration permits; an RP SHOULD request the minimum it needs.
The Authority SHOULD enforce per-RP claim-release policy rather than let an RP
query raw private-network identity.
The Authority MUST NOT release credential IDs, public keys, user handles, raw
assertions, authenticator data, or provider owner metadata as person evidence.
Grants are trusted under the authenticated control channel; this draft defines
no independently verifiable bearer identity token.

A grant's `assurance` object carries `device_attested`, `user_present`, and
`user_verified`, plus:

- `fresh_for_transaction: true` on a transaction grant from a fresh assertion;
- on a session grant from a fresh assertion, `person_fresh: true` and
  `person_expires_in`, the seconds remaining until the person-validity deadline.
  Reuse or reconfirmation grants never carry `person_fresh`.

```json
{"protocol": 1, "active": true, "rp_id": "moderation", "audience": "manage",
 "expires_in": 180,
 "assurance": {"device_attested": true, "user_present": true, "user_verified": true,
               "person_fresh": true, "person_expires_in": 600},
 "claims": {"tags": ["tag:interactive"]}}
```

Assurance booleans may be released without any person identifier. An RP that
requires identity MUST be registered for `person_subject` disclosure; otherwise
creation fails. Omitted permission MUST NOT be treated as permission, and
clients can't select disclosure. Global person identifiers and global names MUST require
separate explicit operator disclosure permission.
Person identifiers are pairwise by default:

```text
person_subject = "ps_" || b64url(HMAC-SHA256(key = pairwise_key,
    data = "bytebind/v1/pairwise" || len(rp_id) || rp_id || len(subject_id) || subject_id))
```

`rp_id` is UTF-8; `subject_id` is its stored opaque bytes. `pairwise_key` is 32
Authority-only bytes that MUST NOT be logged or exposed. Rotating it changes
every pseudonym and requires coordinated RP migration; changed IDs MUST NOT be
silently merged.

No age claim is defined. RP enforcement MUST use the relative validity received
over the control channel.

**Address exposure:** `IP` is inside `H2`, so application-origin code can learn
the device's overlay address even when the grant omits it. Selective disclosure
doesn't hide that address.

## 17. Leases and sessions

### 17.1 Device leases

A management session SHOULD be a lease, renewed silently while the page is open.

| Window | Default |
|---|---|
| Session lease after the last successful ceremony | 180 s, at most 300 s |
| Silent renewal interval | 60 s, fixed |

Because clients renew on a fixed interval, a lease MUST be at least 90 seconds,
so one failed renewal doesn't end it. Shorter attestation and redemption windows
MAY be used; longer ones SHOULD be justified. The RP MUST enforce the lease
deadline server-side; cookie retention doesn't determine it. A lease MUST NOT
outlast the grant that created or renewed it. Each renewal SHOULD rotate the
session token. The server SHOULD NOT extend a session indefinitely on earlier
authentication alone. A device that leaves the network, loses its tag, leaves
policy, or becomes unreachable stops renewing, and its session expires within
one lease.

### 17.2 Expiry is opaque to the client

- The challenge MUST NOT carry an expiry.
- Session application responses MUST NOT disclose the lease's expiry or remaining time.
- The session cookie SHOULD have no lease-derived `Max-Age` or `Expires`.
- The client renews every 60 seconds while the page is open. A refused request
  (for example HTTP 401) means access is unavailable. A failed renewal leaves
  the lease to its stored deadline.

### 17.3 Person association in a session

Creating a person association requires a fresh step-up. Silent renewal MUST
request `assurance: device`, renews only the device lease, and preserves the session's
person association. A renewal grant without person evidence MUST NOT by itself
erase the association. Renewal never prompts, never receives a step-up variant,
and MUST NOT reset the authentication time, extend the person deadline, upgrade
UP to UV, or claim a fresh assertion. There is no device-wide "last person"
cache.

Before a person-gated handler runs, the RP MUST check:

- a valid device lease and all route requirements;
- the association's level, its person deadline, and the route's
  `person_max_age` measured from the RP's receipt of the fresh grant;
- current Authority status, through the person-association validation call.

The Authority holds an opaque association handle bound to the RP, audience,
browser lease, subject/credential generations, and original device. The RP
supplies a reference to the latest device grant for the lease; the Authority
MUST match it to the same lease and recorded device context, without disclosing
device or subject identifiers. The result authorizes only the current request.
It isn't a fresh assertion or evidence for another transaction, and it reports
only time remaining until the original deadline. An unavailable Authority or a
failed check MUST fail closed for that person route; device-only routes depend
only on the device lease.

When person validity or route freshness has expired, the next person-gated call
needs a fresh step-up, and stale association data MUST NOT reach a handler as
current assurance or identity. The Authority MUST invalidate the association
and its handles as soon as it learns of revocation, suspension, device
mismatch, logout, or subject switch. An RP that learns of invalidation MUST drop
the person context at once. A subject switch requires a fresh step-up and a new
browser lease. A new lease or another user of the device can't inherit an
association.

Registration MAY permit optional reconfirmation, where a renewal carries person
evidence for an unexpired association. It MUST match the original level,
RP/audience, lease, device, and generations, and MUST NOT update the original
authentication time or maximum age. The session-creation maximum age is the
RP's largest route maximum, capped by registration. Association handles are
server-only secrets.

A person-required **transaction** never completes as device-only, and always
needs a fresh assertion for that exact operation. On shared devices, provide
explicit session termination and use fresh transaction step-up for sensitive
operations: an association identifies who verified earlier, not who is present
now.

## 18. Application and client behavior

Bindings separate device claims from assurance (illustrative, not an
implemented API):

```python
@bind(require=["tag:interactive"], assurance="verification", person_max_age=300)
@bind(require=["tag:interactive"], grant=bind.TRANSACTION, assurance="verification")
```

`require` values remain AND requirements, and an authorization string such as
`webauthn:uv` MUST NOT be treated as person evidence. Bindings MUST reject at
declaration time:

- unknown assurance values;
- `person_max_age` without person assurance, or on a transaction;
- `identify=True` with device-only assurance.

An identity-required route also needs registration permission for
`person_subject`. WebAuthn never supplies missing device tags.

Headless API clients encountering a person requirement MUST raise a typed error
(`StepUpRequired`), carrying no tokens or URL. They MUST NOT bypass it,
downgrade assurance, open an uncontrolled browser, or retry a protected
operation automatically. Clients implement only the draft capabilities they
support.

## 19. Tailscale provider profile

The core is provider-independent and SHOULD depend only on a normalized
attestation result (peer ID, address, claims). The Tailscale profile:

- The Authority MAY run independently of any RP, reachable from RPs over the
  control channel and from clients over a tailnet attestation listener.
- It SHOULD bind directly to a Tailscale IP and trust the socket address, not
  forwarded headers. It MUST use HTTPS with a valid `.ts.net` certificate for
  browser deployments.
- It SHOULD obtain identity from the tailscaled LocalAPI rather than the CLI.
  Checks MAY include known peer, expected tailnet, shared-in status, stable node
  ID, tags, account, and operator policy. Example policy: required tag
  `tag:bytebind-admin`, shared nodes denied, optional node allowlist.

The successful private request is the liveness signal; Tailscale identity and
policy decide whether that peer is authorized.

## 20. Browser and transport security

- **CORS:** the attestation listener MUST answer with an explicit allowed
  origin, never a wildcard, for `POST` with `Content-Type` only. The person
  listener MUST NOT enable application CORS.
- **Origin:** RP access-request and proof endpoints MUST validate `Origin`
  against the RP's own origin.
- **Host:** every private listener MUST validate its expected `Host` (DNS
  rebinding).
- **Content type:** the attestation endpoint MUST accept only
  `application/json` (section 7.1, check 2).
- **Private network access:** where a browser sends
  `Access-Control-Request-Private-Network: true`, the Authority SHOULD answer
  allowed preflights with `Access-Control-Allow-Private-Network: true`.
- **Browser crypto:** web clients SHOULD use WebCrypto for randomness, HMAC,
  HKDF, and AES-GCM.
- **Cookies:** RP bindings SHOULD use `__Host-bytebind_session` and
  `__Host-bytebind_state` with `Secure`, `HttpOnly`, `SameSite=Strict`,
  `Path=/`, and no `Domain`.
- **Discovery:** an RP MUST pin the Authority that created each `cid` and
  redeem only with it. Discovery MAY advertise `protocols: [1]` with explicit
  draft and assurance capabilities. A protocol advertisement alone doesn't
  qualify a candidate for person step-up, and malformed capabilities fail
  closed. Advertisements filter candidates and don't establish trust. Production
  RPs SHOULD also pin a stable Authority identity or use configured endpoints.

## 21. Storage

Challenge records hold ephemeral secrets. Store them only as long as needed,
delete terminal records promptly, keep the database Authority-only, store only
hashes of state cookies and of handoff, attempt, and association tokens, and
never log `C`, `S`, decrypted `H2`, or cookies.

A transaction record MUST store at least: `cid`, `C`, `S`, `rp_id`,
`allowed_origin`, audience, policy, protocol, profile, assurance, `Q`,
generation, status, `challenge_expires_at`, attested address, peer ID and
claims, accepted `N` and `H1`, person scope and evidence, the overall,
collection, and redemption deadlines, and the delivery reservation. `status`
MUST be constrained to the six states of section 14. Person records are in
section 15; RP attempt bindings stay in the RP's database.

## 22. Security considerations

In-scope attackers include internet clients, unauthorized overlay peers,
shared-in nodes, malicious pages on authorized devices, and clients attempting
forgery, replay, concurrent redemption, or DNS rebinding. Origin, Host, and
CORS checks restrict which origins can use a device's private connection.
Policy separates allowed devices from other reachable peers. Atomic transitions
enforce single use.

Overlapping replay defenses: random `cid`, `C`, and `N`; short lifetimes;
single-use state; transcript-bound HMACs; AES-GCM associated data; atomic
transitions; short leases. Recorded `H1`, `H2`, or `R` values aren't valid for a
fresh challenge.

Implementations MUST fail closed. On malformed input, invalid encoding or
length, bad `Origin` or `Host`, unknown or expired challenge, invalid MAC,
decryption failure, unauthorized device, invalid transition, or replay, return
a generic failure and expose no authorization detail. Failures burn as sections
7.1, 9.1, and 14 require. Rate limiting SHOULD cover the RP access and proof
endpoints, the attestation and result endpoints, the person listener, and the
control endpoints.

Proof continuity: `H1` shows possession of `C` on a provider-accepted private
connection. Opening `H2` releases `S`. `R` shows possession of `S`, and the
Authority consumes the transaction. A grant applies only to the registered RP,
audience, policy, and transaction; the RP remains responsible for application
permissions and execution.

WebAuthn doesn't attest that the authenticator is part of the overlay device,
or exclusive possession of a credential. Applications needing informed human
confirmation of an operation need a separate mechanism. The person-step-up
threat analysis is in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## 23. Test vectors, status, and license

A release SHOULD publish machine-readable vectors (`test-vectors/bytebind-v1.json`)
covering:

- `H1` for both profiles;
- `Q`, including length-prefix edge cases;
- HKDF output;
- `H2` construction and decryption;
- `R`;
- `W`;
- the pairwise subject;
- malformed, expired, and replayed inputs;
- concurrent attestation and redemption.

ByteBind is a draft application protocol with no IETF standards status. Drafts
0.1–0.5 called it TailBind; it was renamed in draft 0.6 because it doesn't
depend on Tailscale.

This specification text is © 2026 Bytes & Coffee Digital Studio. **ByteBind**
is an open name, not a trademark: anyone may use it for an implementation,
conforming or not. An implementation SHOULD state which draft it implements and
SHOULD NOT claim conformance it doesn't have. A separate license governs
reference implementations. Tailscale is a third-party trademark; compatibility
doesn't imply endorsement by Tailscale Inc.
