# ByteBind Protocol

**Status:** Draft  
**Version:** 0.7  
**Copyright:** © 2026 Bytes & Coffee Digital Studio  
**Protocol name:** ByteBind

## 1. Overview

ByteBind is a multi-channel liveness and authentication protocol for **publicly reachable applications whose management plane controls or observes resources on a private authenticated overlay**.

Its primary use case is:

> A public application has privileged access to a private overlay. Its management UI may remain publicly reachable, but a privileged management session should be issued only when the operator's browser is running on a device that is currently present on, identified by, and authorized by that same overlay.

ByteBind binds a public HTTPS session to the contemporaneous presence of an authorized device on the private network.

The reference deployment model uses Tailscale as the private-network identity and transport layer, but the core protocol is designed so other authenticated overlay networks can be supported through interchangeable attestation providers.

ByteBind does **not** prove which human is physically operating a device. It proves that the browser completing the ceremony is participating in a session backed by a currently reachable, authorized private-network device.

A successful ceremony establishes all of the following:

1. A registered relying party requested a fresh authentication transaction.
2. The browser received fresh transaction material over the public application channel.
3. The same browser could send a request over the private overlay.
4. The private-network Authority identified and authorized the source device.
5. The same browser received the Authority's private-network response.
6. The browser returned proof of that exchange to the relying party.
7. The relying party redeemed the proof against the Authority.
8. The transaction was consumed exactly once.

ByteBind is intended for short-lived management sessions, device-bound web authentication, and similar cases where privileged public access should require live presence on an authenticated private trust fabric.

### 1.1 Why ByteBind exists

ByteBind addresses a specific trust-boundary problem:

```text
public application
   |
   +-- ordinary public functionality
   |
   +-- privileged management plane
           |
           +-- can inspect or control private-overlay resources
```

If management authentication is only a conventional internet login, then compromise of that login can turn the public management plane into a weaker path toward resources that otherwise live behind a stronger private-network boundary.

ByteBind instead requires:

```text
public management access
        +
live authenticated private-overlay presence
        +
explicit device authorization policy
        +
fresh browser-bound proof
        =
privileged management session
```

The application may remain publicly reachable, but the authority needed to manage private-overlay resources is not granted solely from the public internet.

### 1.2 Why not serve the whole management UI over the private network?

If an application can simply be private-only, ByteBind is unnecessary.

ByteBind is useful when the application or management UI should remain publicly reachable for deployment, browser-origin, operational, or architectural reasons while privileged use must still depend on live private-network presence.

ByteBind also keeps the private-network attack surface small. The private Authority does not need to serve the application itself; it exposes only narrowly scoped authentication and attestation endpoints.

### 1.3 Seamless operation

ByteBind is designed for **ambient authentication**.

When the browser is already running on an authorized private-network device, authentication SHOULD require no explicit user interaction:

```text
open management page
        |
        v
silent ByteBind ceremony
        |
        v
authorized private device confirmed
        |
        v
management session issued
```

There need be no username prompt, password prompt, WebAuthn gesture, second-device approval, or other visible login ceremony.

From the user's perspective:

> If the browser is running on an authorized live device, management works. If it is not, management does not authenticate.

This seamless behavior is possible because the authenticated overlay itself supplies the device identity and live reachability signal.

## 2. Design goals

ByteBind is designed to provide:

- **Seamless ambient authentication** — an already-authorized device can obtain management access without usernames, passwords, WebAuthn prompts, or explicit user interaction.

- **Public-site usability** — the application can remain publicly reachable over normal HTTPS.
- **Private-network authorization** — login succeeds only when the browser is on an authorized private-network device.
- **Current liveness** — successful authentication requires contemporaneous private-network reachability.
- **Device binding** — the public session is cryptographically tied to an attested private-network device.
- **Replay resistance** — challenges and attestations are short-lived and single-use.
- **Cross-site resistance** — malicious websites opened on an authorized device cannot silently authenticate themselves.
- **Short-lived trust** — sessions can expire quickly when the device leaves the private network or loses authorization.
- **Provider independence** — the protocol core does not require a specific private-network implementation.

ByteBind is intentionally built from established cryptographic primitives. It does not define a new MAC, cipher, or key-derivation function.

---

## 3. Non-goals

ByteBind does not provide:

- proof of which human is at the keyboard;
- protection against compromise of an already-authorized device;
- protection for a session cookie copied from an authorized device while still valid;
- permanent authentication after the private-network connection disappears;
- replacement for private-network identity or authorization policy;
- a general-purpose VPN.

A short management-session TTL limits how long a copied session remains useful.

---

## 4. Parties

ByteBind involves three logical parties.

| Party | Role |
|---|---|
| **Relying Party (RP)** | The public HTTPS application that requests authentication, receives an RP-scoped auth set, redeems completed transactions, and issues its own application session. |
| **ByteBind Authority** | An independent service reachable over the private network. It creates and owns ByteBind transactions, identifies and authorizes connecting devices through an attestation provider, and returns only the RP-visible result required by policy. |
| **Client** | Browser JavaScript that communicates with both the RP and Authority and performs the browser-side cryptographic transcript using WebCrypto. |

The Authority is deliberately separable from the RP. It MAY run on another host entirely.

In the Tailscale reference deployment:

- the **RP** is reachable on its normal public HTTPS origin;
- the **ByteBind Authority** is reachable by the RP over the tailnet and exposes a browser-facing attestation endpoint on the tailnet;
- the **Client** is ordinary browser JavaScript running on the device being attested.

The RP does **not** need direct access to Tailscale LocalAPI, node metadata, tags, or private-network identity. Those concerns belong to the Authority.

The RP and Authority MUST NOT share a database or any other transaction state. The Authority is the sole source of truth for ByteBind transaction state, and the RP reaches it only through the private control channel of section 5.2, even when both run on the same host.

---

## 5. Channels

ByteBind intentionally spans three logical communication paths across two trust domains.

### 5.1 Client ↔ RP public HTTPS channel

Used for:

- beginning authentication;
- carrying the client-visible portion of an auth set;
- final redemption;
- issuing the RP's application session.

### 5.2 RP ↔ Authority private control channel

Used for:

- requesting an auth set;
- conveying RP identity, requested policy, audience, and expiry;
- redeeming or introspecting a completed ByteBind transaction;
- receiving only the claims or authorization result the RP is entitled to see.

This channel MUST be authenticated and confidential, and MUST use one of exactly two transports:

1. **HTTPS between tailnet nodes**, when the RP and Authority run on different hosts. Both endpoints MUST be addresses on the private overlay; the control channel MUST NOT cross the public internet.
2. **A Unix domain socket**, when the RP and Authority run on the same macOS, Linux, or BSD host. The socket file MUST live in a directory writable only by the Authority's account, and MUST NOT be readable or writable by accounts other than the Authority and its registered RPs.

No other transport (plain HTTP, TCP on loopback, Windows named pipes, shared files) is conforming. Section 16.3 defines how the Authority authenticates the RP on each.

### 5.3 Client ↔ Authority private attestation channel

Used for:

- proving current private-network reachability;
- identifying and authorizing the connecting device;
- binding the browser transaction to that live device;
- returning browser-side proof material required for redemption.

The RP is not on the data path for this exchange.

### 5.4 Why not put the whole application on the private network?

See section 1.2.

---

## 6. Threat model

### 6.1 Trusted assumptions

An authorized device is assumed to be under the operator's control and to possess whatever private-network identity, node key, or tag is required by policy.

Compromise of an allowed device is out of scope.

### 6.2 In-scope attackers

ByteBind considers:

- arbitrary internet clients;
- unauthorized peers on the same private network;
- untagged private-network devices;
- shared-in nodes from another tailnet;
- malicious websites opened in a browser on an authorized device;
- replayed protocol messages;
- forged or modified protocol messages;
- concurrent attempts to redeem the same challenge;
- DNS-rebinding attempts against the private attestation endpoint.

### 6.3 Security boundary

ByteBind authenticates **device-backed browser participation**, not human presence.

Applications requiring proof of user presence, phishing resistance against a human identity, or biometric/hardware-backed user verification SHOULD layer WebAuthn/passkeys or another user-authentication mechanism on top.

---

## 6.4 Relationship to Zero Trust and VPN trust

ByteBind does **not** use the traditional rule:

```text
inside VPN address space
    ->
trusted
```

Private-network presence alone is insufficient.

A ByteBind authorization decision combines:

```text
fresh transaction
+ successful live private-overlay connection
+ cryptographically authenticated overlay identity
+ explicit device/tag/node policy
+ browser transaction continuity
+ single-use redemption
```

The private network is therefore not treated as a trusted perimeter. It acts as:

1. an authenticated transport;
2. a device-identity substrate;
3. a source of policy-relevant claims; and
4. a liveness path that the browser must actually traverse during the authentication ceremony.

This is compatible with Zero Trust principles because trust is not inferred merely from network location. Authorization is explicit, device-specific, short-lived, continuously renewable, and evaluated for each authentication transaction.

ByteBind intentionally makes private-overlay presence one authorization condition because its target use case is a management plane whose application itself holds privileged access to that overlay.

The security rationale is:

> The management plane should not become a weaker internet-only route into authority that otherwise exists inside a private trust fabric.

### 6.5 Network presence as an active authentication factor

In many access-control systems, network location or device posture is metadata evaluated before or after a conventional login.

ByteBind makes live private-network participation part of the authentication ceremony itself.

The browser must actively:

1. obtain fresh transaction material from the public relying party;
2. carry that transaction onto the private overlay;
3. receive an Authority response over that overlay; and
4. return cryptographic proof of that exchange to the public relying party.

The resulting session is therefore bound not merely to a claim that the device is "on the network," but to a fresh proof that the browser successfully traversed both trust domains during this authentication event.

---

## 7. Protocol values

Unless otherwise noted, byte values are encoded in JSON as unpadded base64url.

| Value | Size | Generated by | Purpose |
|---|---:|---|---|
| `cid` | 16 bytes | ByteBind Authority | Opaque challenge identifier |
| `C` | 32 bytes | ByteBind Authority | Public-channel challenge secret |
| `S` | 32 bytes | ByteBind Authority | Attestation/redeem secret |
| `N` | 32 bytes | Client | Client freshness nonce |
| `IP` | 16 bytes | ByteBind Authority | Attested peer address in IPv6 form; IPv4 uses IPv4-mapped IPv6 |
| `IV` | 12 bytes | ByteBind Authority | AES-GCM nonce |

All random values MUST be generated using a cryptographically secure random number generator.

Each challenge MUST be single-use.

### 7.1 JSON field names

JSON members are case-sensitive and normative. Protocol values use the names in the table above, exactly: `cid`, `C`, `N`, `H1`, `H2`, `R`. Endpoints MUST reject a body with a missing member, an unknown member, a value that is not unpadded canonical base64url, or a value of the wrong decoded length.

---

## 8. Domain separation

Every cryptographic transcript MUST begin with a protocol/version-specific label.

ByteBind version 1 uses exactly these labels, encoded as ASCII bytes. The session profile uses:

```text
bytebind/v1/h1
bytebind/v1/h2
bytebind/v1/redeem
```

The transaction-bound profile (section 9.2) uses:

```text
bytebind/v1/tx/request
bytebind/v1/tx/h1
bytebind/v1/tx/h2
bytebind/v1/tx/redeem
```

Transcripts using any other labels are not ByteBind version 1. In particular, the `tailbind/v1/*` labels of drafts 0.1 to 0.5 (when the protocol was named TailBind) and the earlier `bd-mgmt/v1/*` labels belong to predecessor drafts and MUST NOT be accepted by a ByteBind v1 implementation.

Implementations MUST NOT reuse a label for a different transcript meaning.

All concatenated transcript fields have fixed lengths in version 1, except inside the request digest `Q`, whose variable-length fields are length-prefixed (section 9.2). Any future variable-length field MUST likewise use an unambiguous encoding such as length-prefixing or a canonical serialization.

---

## 9. Ceremony overview

ByteBind defines a ten-message transaction ceremony between three logical roles:

- **Client** — the browser initiating the privileged application request;
- **Server** — the relying application;
- **Provider** — the ByteBind Authority / private-network attestation provider.

The canonical message verbs are:

```text
PLEASE
BEGIN
TRY
WHO
PROVE
ATTEST
AFFIRM
REDEEM
GRANT
RESPONSE
```

These names are normative **logical** message names. They are not HTTP methods: implementations MUST NOT send them as custom request methods, which proxies and CORS handle poorly. Each request uses an ordinary transport method such as HTTP `POST`, and each reply is its corresponding response.

The logical exchanges are:

| Request | Reply | Transport |
|---|---|---|
| `PLEASE` | `WHO` | `POST` to an RP-defined path on the RP's public origin |
| `BEGIN` | `TRY` | `POST` on the private control channel (section 5.2) |
| `PROVE` | `ATTEST` | `POST <authority>/attest` on the private attestation channel |
| `AFFIRM` | `RESPONSE` | `POST` to an RP-defined path on the RP's public origin |
| `REDEEM` | `GRANT` | `POST` on the private control channel |

`RESPONSE` is the HTTP response to the `AFFIRM` request. While that request is open, the RP sends `REDEEM` and waits for `GRANT`; it sends `RESPONSE` only after `GRANT` (or a failure) arrives.

The message path is:

```text
Client              Server              Provider
  |                   |                    |
  |------ PLEASE ---->|                    |
  |                   |------ BEGIN ------>|
  |                   |<------- TRY -------|
  |<------- WHO ------|                    |
  |---------------- PROVE ---------------->|
  |<--------------- ATTEST ----------------|
  |------ AFFIRM ---->|                    |
  |                   |----- REDEEM ------>|
  |                   |<------ GRANT ------|
  |<----- RESPONSE ---|                    |
```

Equivalently:

```text
Client   -> Server    PLEASE
Server   -> Provider  BEGIN
Provider -> Server    TRY
Server   -> Client    WHO
Client   -> Provider  PROVE
Provider -> Client    ATTEST
Client   -> Server    AFFIRM
Server   -> Provider  REDEEM
Provider -> Server    GRANT
Server   -> Client    RESPONSE
```

The ceremony is intentionally readable as a dialogue:

```text
PLEASE do this.
BEGIN a transaction.
TRY proving them.
WHO are you?
PROVE who I am.
I ATTEST you are you.
I AFFIRM I am me.
REDEEM this ticket.
I GRANT you authority.
Here is your RESPONSE.
```

This mnemonic is explanatory, not normative; the formal semantics below govern.

### 9.1 Message meanings

| Message | Sender → Receiver | Meaning |
|---|---|---|
| `PLEASE` | Client → Server | Submit the privileged application request and ask the Server to authorize it through ByteBind. |
| `BEGIN` | Server → Provider | Ask the Provider to create a fresh ByteBind transaction bound to this Server, origin, policy, audience, and application request. |
| `TRY` | Provider → Server | Return the Server-visible transaction material required to continue the ceremony. |
| `WHO` | Server → Client | Return the Client-visible transaction material and instruct the browser to prove authorized live presence on the private trust fabric. |
| `PROVE` | Client → Provider | Present the browser's private-path proof from an authenticated private-network device. |
| `ATTEST` | Provider → Client | Attest that the Provider observed and authorized the live private-network identity participating in this transaction. |
| `AFFIRM` | Client → Server | Return the completed browser proof to the Server, affirming continuity with the attestation received over the private path. |
| `REDEEM` | Server → Provider | Present the completed transaction ticket/proof to the Provider for one-time redemption. |
| `GRANT` | Provider → Server | Confirm successful redemption and return the scoped authority or claims the Server is permitted to exercise. |
| `RESPONSE` | Server → Client | After `GRANT`, execute or complete the original application request and return its application response. |

### 9.2 Application request binding (transaction-bound profile)

ByteBind has two profiles: the **session profile** (section 9.3) and the **transaction-bound profile** described here. They use different transcript labels, so a transcript always identifies its profile and one can never be accepted as the other.

In the transaction-bound profile, the privileged application request is carried in `PLEASE` and bound to the ByteBind transaction by a 32-byte request digest `Q`:

```text
Q = SHA-256(
    "bytebind/v1/tx/request"
    || len(method)  || method
    || len(target)  || target
    || len(headers) || headers
    || len(body)    || body
)
```

`len(x)` is the byte length of `x` as an unsigned 64-bit big-endian integer. `method` is the uppercase ASCII method, `target` the path and query as sent, `headers` the profile-selected headers serialized as `name:value` lines (name lowercased, surrounding whitespace trimmed from name and value) sorted by code point and joined by `\n`, and `body` the exact body bytes. An implementation profile MAY narrow which headers are covered but MUST NOT change this encoding.

The **Client** MUST compute `Q` itself from the request it sent in `PLEASE`. A `Q` supplied by the Server in `WHO` MUST NOT be used, since the point of `Q` is the browser's own commitment to what it asked for.

The transaction-bound profile uses its own labels:

```text
bytebind/v1/tx/h1
bytebind/v1/tx/h2
bytebind/v1/tx/redeem
```

and these transcripts:

```text
H1  = HMAC-SHA256(key = C, data = "bytebind/v1/tx/h1" || cid || N || Q)
K   = HKDF-SHA256(ikm = C, salt = H1, info = "bytebind/v1/tx/h2", length = 32)
AAD = "bytebind/v1/tx/h2" || cid || N || H1
R   = HMAC-SHA256(key = S, data = "bytebind/v1/tx/redeem" || cid || C || IP || Q)
```

All other cryptographic steps are as in sections 11 to 13.

The Server MUST send `Q` to the Provider in `BEGIN`, and the Provider MUST store it with the transaction and verify `H1` and `R` against it. The Server MUST also store the request itself (or enough to execute it) under the transaction's `cid`, MUST execute only that stored request, and MUST execute it at most once.

`REDEEM` consumes the proof for that exact request. `GRANT` authorizes only the request, audience, policy, and claims bound to that redeemed transaction. The Server MUST NOT execute the request before receiving a valid `GRANT`.

This yields the property:

> The authorized live device did not merely authenticate a session; it participated in authorization for this exact application request, and the Provider granted authority for that exact redeemed transaction.

After `GRANT`, the Server executes the stored request and returns the actual application result in `RESPONSE`.

### 9.3 Session profile

The session profile is an optimization built on the same ceremony.

Instead of binding the ByteBind transaction to one privileged application request, `PLEASE` requests creation or renewal of a short-lived management lease. The session profile has no `Q` and uses the `bytebind/v1/h1`, `bytebind/v1/h2`, and `bytebind/v1/redeem` transcripts of sections 11 to 13 exactly.

`REDEEM` consumes the completed proof. `GRANT` authorizes creation or renewal of the scoped management lease. `RESPONSE` then returns the resulting session state or application response.

The transaction-bound profile provides stronger per-operation authorization, while the session profile reduces repeated ceremony overhead for lower-risk management operations.

### 9.4 Security contribution of each message

```text
PLEASE
    Client contributes application intent.

BEGIN
    Server contributes RP identity, origin, policy, audience,
    and optionally a digest of the exact application request.

TRY
    Provider contributes fresh transaction state and challenge material.

WHO
    Server delivers the client-visible portion of that state to the browser.

PROVE
    Client demonstrates live outbound reachability over the private trust fabric
    and possession of the public-channel challenge material.

ATTEST
    Provider contributes private-network device identity and authorization,
    and proves successful inbound private-path participation.

AFFIRM
    Client binds the completed private-path exchange back to the Server.

REDEEM
    Server asks the Provider to consume the completed proof for this transaction.

GRANT
    Provider confirms one-time redemption and returns scoped authority to the Server.

RESPONSE
    Server exercises only the granted authority and returns
    the result of the original application operation.
```

The ceremony therefore wraps the privileged application transaction itself rather than requiring a separate visible login phase.

## 10. PLEASE, BEGIN, TRY, and WHO — Transaction initialization

### 10.1 PLEASE — Client submits the protected request

The Client first submits the protected application request to the Server as `PLEASE`. Before authorizing or executing that request, the Server sends `BEGIN` to the Provider over the authenticated private control channel to create a new ByteBind transaction.

A `BEGIN` request SHOULD identify at least:

```text
rp_id
audience
allowed_origin
requested_policy
transaction_ttl
optional application context
Q (transaction-bound profile only)
```

The Authority generates:

```text
cid = random(16)
C   = random(32)
S   = random(32)
```

The Authority MUST validate `allowed_origin` against the requesting RP's registration rather than accept whatever origin the RP asks for. One RP MUST NOT be able to obtain an auth set bound to another RP's origin.

The Authority then stores authoritative transaction state including:

```text
cid
C
S
rp_id
audience
allowed_origin
requested_policy
Q (transaction-bound profile only)
status = pending
challenge_expires_at
```

The Authority returns an **auth set** split by audience.

A typical split is:

```text
RP-visible:
    cid
    C
    authority endpoint
    expires_in (seconds until the attestation window closes)
    opaque authority handle or verifier

Client-visible:
    cid
    C
    authority endpoint
```

Expiry is opaque to the Client (section 15.2): the client-visible portion carries no expiry. Times on the control channel are relative durations, never absolute timestamps, so clock skew between the RP and Authority hosts cannot shorten or extend any window.

The RP SHOULD receive only the material it needs to continue and later redeem the transaction.

Private-network identity, device tags, peer metadata, and the secret `S` SHOULD remain Authority-side unless a specific deployment requires otherwise.

### 10.2 TRY and WHO — Provider and Server return transaction material

The Provider returns `TRY` to the Server with Server-visible transaction material. The Server then returns `WHO` to the Client with the client-visible portion of the auth set.

The RP returns the client-visible portion of the auth set, for example:

```json
{
  "cid": "<base64url>",
  "C": "<base64url>",
  "authority": "https://authority.example.ts.net:8443"
}
```

`authority` is the Authority's base URL; the client sends `PROVE` to `<authority>/attest`. `WHO` MUST NOT carry the attestation window's expiry: the Authority enforces it, and the Client either completes in time or fails.

The RP MUST refuse a `PLEASE` whose `Origin` header is not its own public origin, so a malicious website cannot start an authentication attempt in the user's browser.

`PLEASE` arrives unauthenticated, yet it makes the RP store a pending request and call the Authority. The RP MUST bound the size of a `PLEASE` body and the number of pending transactions it holds, and the Authority MUST bound pending transactions per RP, so an internet client cannot use `PLEASE` to exhaust either party.

The RP MAY additionally issue a short-lived state cookie binding the browser to this RP-side authentication attempt.

Recommended cookie properties:

```text
HttpOnly
Secure
SameSite=Strict
Path=<auth path>
short expiry
```

If such a cookie is used, the RP SHOULD store only its hash.

### Security purpose

The Authority creates the underlying transaction and secrets; the RP contributes the fact that a particular relying application is requesting authentication under a particular audience and policy.

`C` is fresh, unpredictable, and client-visible. `S` remains withheld.

The RP-side state cookie, when used, binds the public authentication attempt to the browser instance that initiated it.

## 11. PROVE — Client to Provider

The client generates:

```text
N = random(32)
```

It computes:

```text
H1 = HMAC-SHA256(
    key = C,
    data = "bytebind/v1/h1" || cid || N
)
```

The client sends to the private ByteBind Authority:

```http
POST /attest
Content-Type: application/json
Origin: https://public.example

{
  "cid": "<base64url>",
  "N": "<base64url>",
  "H1": "<base64url>"
}
```

The browser MUST communicate with the ByteBind Authority directly.

The private peer address MUST be obtained from the accepted socket. Forwarded-address headers MUST NOT be trusted.

### 11.1 Required checks

The ByteBind Authority MUST check, in order:

1. `Origin` exactly matches the origin of some registered RP, and `Host` exactly matches the expected private attestation host. Requests failing either check MUST be refused without reading or changing any transaction state.
2. `Content-Type` is `application/json`. This forces a CORS preflight; the Authority MUST refuse the "simple" content types (`text/plain`, `application/x-www-form-urlencoded`, `multipart/form-data`) that a page could send without one.
3. `cid` exists, is `pending`, and is inside its attestation window.
4. `Origin` exactly matches the `allowed_origin` stored with that `cid`. Matching *some* registered origin is not enough: otherwise a page on RP A's origin could attest a challenge an attacker obtained from RP B, read `H2` (CORS permits A's origin), open it with the attacker's `C`, and redeem it at RP B.
5. `H1` is valid using constant-time comparison.
6. The socket peer address belongs to the supported private-network address space.
7. The attestation provider identifies the peer as a valid node.
8. Provider policy authorizes that node.
9. The challenge transitions atomically from `pending` to `attested`.

A failure at check 3 or later MUST burn the challenge, but only from the state the request expected (`pending`), so a request that lost a race never burns the winner's newer state.

### 11.2 Atomicity

The transition MUST be concurrency-safe.

Each transition is a single conditional update that must change exactly one row. That update is the concurrency protection; no transaction is held across the authorization step. Holding a write lock while waiting on the attestation provider would block every other writer.

A typical SQL pattern is:

```sql
-- 1. Read, without a write lock.
SELECT C, S, allowed_origin
FROM challenges
WHERE cid = ?
  AND status = 'pending'
  AND challenge_expires_at > :now;

-- 2. Verify Origin, H1, and the peer with the attestation provider.

-- 3. Transition; require exactly one changed row.
UPDATE challenges
SET
    status = 'attested',
    attested_ip = ?,
    attested_peer_id = ?,
    attested_at = :now,
    redeem_expires_at = :now + :redeem_window
WHERE cid = ?
  AND status = 'pending'
  AND challenge_expires_at > :now;
```

If zero rows are updated, attestation fails: another request won, or the window closed.

Burns and transitions MUST be durable before the response is sent. An implementation that wraps them in a transaction MUST commit it on failure paths too; rolling back a burn when the handler raises an error silently re-arms the challenge.

### Security purpose

Successful delivery of `PROVE` proves that the browser can currently **send** over the private network.

`H1` proves that the sender also possesses `C`, which was obtained from the public HTTPS challenge.

The `Origin` check prevents a malicious unrelated website running in the same browser from using the operator's network position to complete its own attestation.

---

## 12. ATTEST — Provider to Client

After device authorization succeeds, the ByteBind Authority returns a response that only a holder of `C` can open.

### 12.1 Key derivation

Derive:

```text
K = HKDF-SHA256(
    ikm = C,
    salt = H1,
    info = "bytebind/v1/h2",
    length = 32
)
```

### 12.2 Plaintext

```text
P = IP || S
```

`IP` is the peer address observed by the ByteBind Authority and stored with the challenge.

### 12.3 Authenticated encryption

Generate:

```text
IV = random(12)
```

Define associated data:

```text
AAD =
    "bytebind/v1/h2"
    || cid
    || N
    || H1
```

Encrypt using AES-256-GCM:

```text
E = AES-256-GCM(
    key = K,
    iv = IV,
    plaintext = P,
    aad = AAD
)
```

The transmitted `E` includes the GCM authentication tag.

The response is:

```text
H2 = IV || E
```

and is returned as:

```json
{
  "H2": "<base64url>"
}
```

### 12.4 Client processing

The client:

1. derives `K`;
2. parses `IV` and `E`;
3. decrypts and authenticates using the exact `AAD`;
4. rejects the response if authentication fails;
5. extracts `IP` and `S`.

### Security purpose

Successful receipt and decryption of `ATTEST` proves that the same browser can currently **receive** over the private network.

Because the response is bound to `cid`, `N`, and `H1`, it is specific to this exact ceremony transcript.

`S` is disclosed only to the browser that can derive the `H2` key.

TLS and the authenticated private network remain the primary transport protections; the encrypted response additionally keeps `S` hidden from intermediaries such as a TLS-terminating proxy or request logger on the private side.

---

## 13. AFFIRM, REDEEM, GRANT, and RESPONSE

`AFFIRM` carries the completed ByteBind proof from the Client back to the Server.

The Server MUST NOT execute a transaction-bound protected request or issue a session lease merely because it received `AFFIRM`. `AFFIRM` is not itself authority to act.

The Client computes:

```text
R = HMAC-SHA256(
    key = S,
    data =
        "bytebind/v1/redeem"
        || cid
        || C
        || IP
)
```

The transaction-bound profile uses the transcript in section 9.2, which additionally binds `Q`.

The Client sends `AFFIRM` to the RP (the path is RP-defined):

```http
POST /bytebind/v1/affirm
Content-Type: application/json

{
  "cid": "<base64url>",
  "R": "<base64url>"
}
```

If the RP set a state cookie with `WHO`, that cookie is included automatically. The RP MUST refuse an `AFFIRM` whose `Origin` header is not its own public origin, and MUST check the state cookie before continuing.

The Client MUST NOT submit an independently chosen `IP` value during redemption.

### 13.1 REDEEM — Server to Provider

After receiving a validly formed `AFFIRM`, the Server sends `REDEEM` to the Provider over the authenticated private control channel.

Conceptually:

```http
POST /bytebind/v1/transactions/{cid}/redeem

{
  "R": "<base64url>",
  "rp_id": "...",
  "audience": "..."
}
```

The Provider verifies:

1. `cid` exists.
2. The transaction belongs to the requesting RP and audience.
3. Transaction state is exactly `attested`.
4. The transaction is inside its redeem window, which starts at attestation (section 15.1).
5. `R` matches the expected HMAC using the Provider's stored `S`, `C`, and `attested_ip`, plus `Q` in the transaction-bound profile.
6. The transaction atomically transitions from `attested` to `redeemed`, changing exactly one row.

A failure at check 3 or later MUST burn the transaction from the `attested` state.

`REDEEM` is a one-time consumption operation. A successfully redeemed transaction MUST NOT be redeemable again.

### 13.2 GRANT — Provider to Server

If `REDEEM` succeeds, the Provider returns `GRANT`.

`GRANT` is the Provider's authorization result for the redeemed transaction. It MUST be scoped to the RP, audience, policy, and transaction that were bound at `BEGIN`.

Example:

```json
{
  "active": true,
  "expires_in": 180,
  "claims": {
    "device_id": "node-abc123",
    "authorization": ["manage:read"]
  }
}
```

The exact claims returned are policy-controlled.

The Provider SHOULD disclose only what the RP needs. For example, an RP that only needs a yes/no authorization decision need not receive tailnet username, node tags, peer IP, or other private-network metadata.

The Server MUST treat `GRANT`, not `AFFIRM`, as the point at which Provider-backed authority becomes available.

`GRANT`'s `expires_in` is the number of seconds, counted from when the RP receives the `GRANT`, for which the Provider's authorization holds. The RP measures it on its own clock. Any session lease or other authority the RP derives from a `GRANT` MUST NOT outlast it; the RP MAY end it sooner. `GRANT` MUST NOT carry absolute expiry timestamps.

### 13.3 RESPONSE — Server to Client

Only after receiving a valid `GRANT` MAY the Server exercise the granted authority.

For the transaction-bound profile, the Server executes the stored request bound to the redeemed `cid`, at most once, and returns the actual application result as `RESPONSE`.

For the session profile, the Server MAY create or renew the short-lived scoped session lease authorized by `GRANT`, then return the resulting application response.

The RP remains responsible for its own:

- session cookie;
- CSRF protection;
- application authorization beyond the Provider's grant;
- local logout;
- session expiry;
- idempotency and at-most-once execution of transaction-bound operations.

### Security purpose

`R` proves possession of `S`.

`S` was disclosed only inside `ATTEST`, which could only be opened using key material derived from `C`.

`AFFIRM` therefore proves continuity between the Client that received `WHO`, the Client that completed the private-network exchange, and the Client returning to the Server.

`REDEEM` asks the Provider to consume that proof exactly once.

`GRANT` is the Provider's explicit scoped authorization result.

`RESPONSE` occurs only after that grant, so the Server never treats an unredeemed client assertion as authority to execute the protected operation.

## 14. Challenge state machine

```text
pending ──ATTEST──▶ attested ──REDEEM──▶ redeemed
   │                    │
   └── any failure ─────┴──▶ burned
```

- `pending`, `attested`, `redeemed`, and `burned` are the only states. `redeemed` and `burned` are terminal.
- Expiry is a time comparison against the stored deadlines, not a state. A transaction past its deadline is treated as dead and removed by cleanup.
- Every transition is a conditional update from one expected state that MUST change exactly one row.
- A failed check burns the transaction only from the state that request expected, so a request that lost a race never burns the winner's newer state.

---

## 15. Session leases and re-attestation

ByteBind works especially well with short-lived sessions and silent renewal.

The intended user experience is continuous and ambient: while an authorized management page remains open, the browser MAY repeat ByteBind in the background without prompting the user.

A management session SHOULD be treated as a lease.

### 15.1 Recommended timing

| Window | Recommended | Purpose |
|---|---|---|
| Attestation window (`TRY` to `PROVE`) | 30 seconds | A challenge must be attested promptly |
| Redeem window (`ATTEST` to `REDEEM`) | 10 seconds, starting at attestation | "Live" means live now, not sometime this minute |
| Session lease after the last successful ceremony | 180 seconds, at most 5 minutes | Bounds access after the device leaves |
| Silent renewal interval | 60 seconds, fixed | Several renewals can fail before the lease ends |

Implementations MAY choose shorter windows. Longer ones weaken the liveness guarantee and SHOULD be justified. Because Clients renew on a fixed interval, a session lease MUST be at least 90 seconds, so one failed renewal does not end it.

The RP MUST enforce the lease on the server against the time of the last successful ceremony, not rely on the session cookie's own expiry, which the client controls. The lease MUST NOT outlast the `expires_in` of the `GRANT` that created or renewed it, measured on the RP's clock (section 13.2). Each successful renewal SHOULD rotate the session token.

### 15.2 Expiry is opaque to the Client

The Client never learns when anything expires. Expiry is server-side policy: disclosing it gains the Client nothing, since the RP and Authority enforce every window on their own clocks, and it would reveal policy and server time to any page script.

- `WHO` MUST NOT carry an expiry (section 10.2).
- `RESPONSE` in the session profile MUST NOT disclose the lease's expiry or remaining time.
- The RP SHOULD issue the session cookie without `Max-Age` or `Expires` derived from the lease (for example as a browser-session cookie), so the cookie itself does not reveal the lease.
- The Client renews on a fixed 60-second interval while the page is open. A refused request (for example HTTP 401) or a failed ceremony tells the Client the lease is over; it learns nothing more specific.

Example:

```text
successful ByteBind ceremony
          |
          v
   session valid: at most 5 min
          |
          +---- successful silent refresh ----> extend lease
          |
          +---- refresh fails ----------------> expire naturally
```

The page MAY repeat the ceremony silently while open.

If the device:

- leaves the private network;
- loses the required tag;
- is removed from the authorization policy;
- becomes unreachable on the private channel;

then re-attestation stops succeeding and the application session expires within at most one session TTL.

The server SHOULD NOT indefinitely extend a session based solely on earlier authentication.

---

## 16. Tailscale attestation profile

ByteBind core is provider-independent. The Tailscale profile maps private-network attestation to Tailscale identity.

### 16.1 Authority placement

The ByteBind Authority MAY run independently of any relying application.

It SHOULD be reachable:

- from registered RPs over the private control channel: HTTPS between tailnet nodes, or a Unix domain socket when the RP runs on the same host (section 5.2); and
- from client devices over a browser-facing tailnet attestation endpoint.

An RP therefore does not need to expose its own application over Tailscale.

### 16.2 Browser-facing transport

The Authority SHOULD:

- bind directly to a Tailscale IP or otherwise preserve authenticated peer identity;
- use HTTPS with a certificate valid for its `.ts.net` hostname (MUST for browser deployments: a page loaded over public HTTPS cannot call a plain-HTTP private address);
- trust the socket source address rather than forwarded headers;
- keep the attestation endpoint narrowly scoped.

### 16.3 RP-facing control transport

The Authority MUST authenticate each RP independently, according to the transport (section 5.2):

- **HTTPS between tailnet nodes:** the Authority MUST identify the RP from the authenticated overlay identity of the connecting node (Tailscale node identity, checked against ACL or tag policy), and MAY additionally require mTLS or a dedicated per-RP credential. The RP MUST verify the Authority's certificate for its `.ts.net` name.
- **Unix domain socket:** the Authority MUST identify the RP from the kernel-reported peer credentials of the connecting process (`SO_PEERCRED` on Linux, `getpeereid` or `LOCAL_PEERCRED` on macOS and BSD) and map that user ID to a registered RP. File permissions on the socket are a second layer, not a substitute.

The Authority MUST bind each auth set to the RP that requested it so another RP cannot redeem it.

### 16.4 Identity

The Tailscale attestation provider SHOULD obtain identity from Tailscale's local control interface.

A production implementation SHOULD prefer the Tailscale LocalAPI over shelling out to CLI commands where practical.

Provider checks MAY include:

- whether the peer is known to Tailscale;
- whether it belongs to the expected tailnet;
- whether it is a shared-in node;
- stable node ID;
- node tags;
- user/account identity;
- additional operator policy.

### 16.5 Authorization example

```text
required tags:
    tag:bytebind-admin

shared nodes:
    denied

optional node allowlist:
    node-id-1
    node-id-2
```

The successful browser request itself provides the liveness signal. Tailscale identity and metadata determine whether that live peer is authorized.

## 17. Attestation provider interface

A generalized implementation may define an interface similar to:

```python
class AttestationProvider(Protocol):
    async def attest(self, request) -> "PeerAttestation":
        ...

@dataclass
class PeerAttestation:
    peer_id: str
    address: ipaddress.IPv6Address
    claims: dict[str, object]
```

The protocol core SHOULD depend only on the normalized attestation result rather than Tailscale-specific fields.

This permits future providers for other authenticated private overlays.

---

## 18. Device-bound IdP profile

A ByteBind Authority MAY also act as, or back, an OpenID Connect identity provider.

In this profile the Authority converts successful device-backed liveness into a conventional application identity assertion.

A typical flow becomes:

```text
Browser
  |
  v
OIDC authorization request
  |
  v
ByteBind transaction
  |
  +---- public RP/browser path
  |
  +---- private browser/Authority path
  |
  v
successful device attestation
  |
  v
authorization code
  |
  v
ID token / access token
```

Possible token claims include:

```json
{
  "sub": "device:node-abc123",
  "device_id": "node-abc123",
  "auth_time": 1790981250,
  "amr": ["bytebind"],
  "acr": "urn:bytebind:device-bound"
}
```

If the provider exposes a reliable human account mapping, the IdP MAY use a human identity for `sub` while carrying device identity separately.

Applications MUST NOT assume that device identity alone proves which human is physically present.

The key architectural property remains the same: **private-network presence is an active part of the authentication ceremony, not merely posture metadata evaluated after login.**

## 19. Authority trust and selective disclosure

The ByteBind Authority is a policy enforcement point and privacy boundary.

It may know substantially more about a device than any individual RP should receive.

For example:

```text
Authority may know:
    private-network peer IP
    stable node ID
    tailnet identity
    human account mapping
    device tags
    shared-node status
    device posture
    requested RP
    complete ByteBind transaction state

RP may receive:
    active = true
    attested_at
    authorization = manage:read
    optional pseudonymous device identifier
```

An RP SHOULD request the minimum claims required for its authorization decision.

The Authority SHOULD enforce per-RP claim release policy rather than allowing the RP to arbitrarily query raw private-network identity.

This permits ByteBind to act as a bridge from private-network trust into public application sessions without making every relying application a privileged observer of the private network.

---

## 20. Browser security requirements

### 20.1 CORS

The private ByteBind Authority MUST use an explicit allowed public origin.

Example:

```http
Access-Control-Allow-Origin: https://manage.example.com
Access-Control-Allow-Methods: POST
Access-Control-Allow-Headers: Content-Type
```

Wildcard origin authorization MUST NOT be used.

### 20.2 Origin validation

Server-side validation of the `Origin` header is mandatory for browser deployments.

Page JavaScript cannot set an arbitrary `Origin` header for a cross-origin request.

### 20.3 Host validation

The private service MUST validate its expected `Host`.

This helps resist DNS rebinding and accidental exposure through alternate hostnames.

### 20.4 Content type

The attestation endpoint MUST accept only `Content-Type: application/json` and MUST answer preflights only for `POST` with the `Content-Type` request header, from allowed origins. See section 11.1, check 2.

### 20.5 Private Network Access

Chromium sends a preflight carrying `Access-Control-Request-Private-Network: true` before a public page may call a private-network address. The Authority SHOULD answer allowed preflights with `Access-Control-Allow-Private-Network: true`. Newer Chromium versions replace this with a Local Network Access permission prompt, which the user may see on first use; that prompt is a browser decision the protocol cannot suppress.

### 20.6 RP origin validation

The RP's `PLEASE` and `AFFIRM` endpoints MUST validate the `Origin` header against the RP's own public origin (sections 10.2 and 13).

### 20.7 Browser crypto

Web implementations SHOULD use WebCrypto for:

- CSPRNG;
- HMAC-SHA256;
- HKDF-SHA256;
- AES-GCM.

---

## 21. Replay resistance

ByteBind uses several overlapping replay defenses:

- random `cid`;
- random `C`;
- random client nonce `N`;
- short challenge lifetime;
- single-use challenge state;
- transcript-bound HMACs;
- AES-GCM associated data;
- atomic state transitions;
- short-lived application sessions.

Recorded `H1`, `H2`, or `R` values are not valid for a fresh challenge.

---

## 22. Failure behavior

Implementations SHOULD fail closed.

On any of the following:

- malformed input;
- invalid base64url;
- incorrect field length;
- invalid `Origin`;
- invalid `Host`;
- unknown challenge;
- expired challenge;
- invalid HMAC;
- decryption failure;
- unauthorized device;
- invalid state transition;
- replay attempt;

the server SHOULD return a generic authentication failure and SHOULD avoid exposing unnecessary authorization details.

Failures burn the challenge as sections 11.1, 13.1, and 14 require.

Rate limiting SHOULD be applied to the `PLEASE`, `PROVE`, and `AFFIRM` endpoints and to `BEGIN` and `REDEEM` on the control channel, in addition to the `PLEASE` size and pending-transaction limits of section 10.2.

---

## 23. Storage considerations

Challenge records contain ephemeral authentication secrets.

Recommended protections:

- store only for the minimum required lifetime;
- delete or securely expire redeemed challenges quickly;
- store only hashes of challenge-state cookies;
- limit database access to the Authority process; RPs never access it directly (section 4);
- avoid logging `C`, `S`, decrypted `H2`, state cookies, or session cookies;
- use transaction boundaries for every state transition.

---

## 24. Reference database fields

A minimal challenge table might contain:

```text
cid
C
S
state_cookie_hash
rp_id
allowed_origin

status
created_at
challenge_expires_at

attested_at
attested_ip
attested_peer_id
attested_claims
redeem_expires_at

redeemed_at
```

`status` MUST be constrained to `pending`, `attested`, `redeemed`, and `burned`.

---

## 25. Security positioning

ByteBind is not intended to replace general-purpose identity systems.

Its core security statement is narrower:

> A public relying party may grant privileged management access only when the current browser transaction is backed by a live, explicitly authorized identity on the private overlay whose resources the application is privileged to manage.

ByteBind should therefore be understood as **private-overlay-backed, liveness-bound management authentication**.

It differs from traditional perimeter trust because being able to route packets from an internal address is not enough.

It differs from ordinary device posture because the private network is not merely consulted as metadata; the browser must actively traverse it as part of the authentication transaction.

It differs from WebAuthn-style user authentication because no explicit user ceremony is required. ByteBind authenticates live authorized device participation, not human presence.

It differs from simply hosting the management UI privately because the relying application may remain publicly reachable while the authorization decision is anchored to the private trust fabric.

---

## 26. Security summary

ByteBind establishes a browser session by combining trust from two independent channels:

```text
Public HTTPS:
    fresh challenge + browser binding

Private network:
    live reachability + device authorization

Browser:
    transcript continuity across both channels

Public redemption:
    proof that one browser completed the full exchange
```

The core security property can be summarized as:

> A ByteBind-authenticated session is issued only when the browser that received a fresh public challenge also demonstrates contemporaneous participation by an authorized device on the configured private network.

---

## 27. Recommended terminology

Use:

- **ByteBind protocol**
- **ByteBind ceremony**
- **ByteBind attestation**
- **ByteBind session lease**
- **ByteBind provider**
- **Tailscale attestation provider**
- **device-bound authentication**
- **ByteBind message verbs:** `PLEASE`, `BEGIN`, `TRY`, `WHO`, `PROVE`, `ATTEST`, `AFFIRM`, `REDEEM`, `GRANT`, `RESPONSE`

Avoid describing ByteBind as:

- a new cryptographic primitive;
- a replacement for HMAC, HKDF, or AEAD;
- proof of human presence;
- equivalent to MFA by itself.

---

## 28. Example implementation layout

One possible Python packaging model:

```text
bytebind-core
bytebind-tailscale
bytebind-fastapi
bytebind-flask
bytebind-django
```

or:

```bash
pip install "bytebind[tailscale,fastapi]"
```

The protocol specification SHOULD remain independent of any particular framework or implementation language.

---

## 29. Test vectors

A production-quality protocol release SHOULD publish machine-readable test vectors covering:

- H1 computation, for both profiles;
- the transaction-bound request digest `Q`, including length-prefix edge cases;
- HKDF output;
- AES-GCM H2 construction;
- H2 decryption;
- redeem HMAC;
- malformed inputs;
- expired challenges;
- replayed challenges;
- concurrent attestation;
- concurrent redemption.

Recommended file:

```text
test-vectors/bytebind-v1.json
```

This allows independent implementations in Python, Go, Rust, JavaScript, or other languages to verify interoperability.

---

## 30. Versioning

Protocol versions MUST be cryptographically domain-separated.

Version changes that alter:

- field encoding;
- transcript structure;
- key derivation;
- encryption;
- challenge semantics;
- attestation semantics;

MUST use a new protocol version label.

Implementations MUST NOT silently reinterpret a version 1 transcript under a later version.

---

## 31. IANA / standards status

ByteBind is currently an application protocol specification and is not an IETF standard.

The name does not imply registration, endorsement, or standardization by Tailscale or any standards body.

Drafts 0.1 to 0.5 called the protocol TailBind. It was renamed in draft 0.6 because the protocol does not depend on Tailscale (section 16 is one attestation profile among possible others).

---

## 32. License and attribution

This specification text is:

**© 2026 Bytes & Coffee Digital Studio**

The name **ByteBind** is an open name. It is not a trademark, and anyone may use it to refer to an implementation of this protocol, conforming or not, without permission. An implementation SHOULD say which draft version it implements and SHOULD NOT claim conformance it does not have.

A separate software license SHOULD govern reference implementations.

Tailscale is a third-party product and trademark. ByteBind compatibility with Tailscale does not imply endorsement by Tailscale Inc.
