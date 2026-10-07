# ByteBind threat model

**Scope:** the experimental protocol v1 implementation of specification 0.8-draft,
whose person step-up is covered in §6.10, and the
reference implementation: the
Authority (`authority.py`, `store.py`, `config.py`), the Tailscale attestation
provider (`tailscale.py`), Authority discovery (`discovery.py`), the RP core and
FastAPI/Flask bindings (`rp.py`, `binding.py`, `fastapi.py`, `flask.py`), the
browser client (`web/bytebind.js`), the API clients (`client.py`, `requests.py`,
`_client.py`), and the demo deployment (`examples/demo`).

**Basis:** the original device-only review, the 0.8 implementation review of
`a1e2b2e`, and follow-up through `a44e0a6` on 2026-10-06. The recorded run passes
231 tests with `fido2==2.2.1`, including signed synthetic assertions and local
Unix control. Real-tailnet and browser acceptance remain open; see ROADMAP.md.
Agent review does not replace independent security review.

Severity assumes a typical deployment: one Authority, a few RPs on public
HTTPS origins, and operator devices on a Tailscale tailnet.
Status is **Mitigated**, **Partial**, **Open**, or **Accepted** (a documented
limit of the design).

## 1. System

```mermaid
flowchart TB
    client["Client on device D<br/>Browser page or API client"]
    rp["Relying party<br/>Public HTTPS origin"]

    subgraph authority_host["Authority host"]
        authority["Authority<br/>Transaction store: SQLite"]
        tailscaled["tailscaled<br/>status / whois"]
    end

    policy["Tailscale control plane<br/>Tailnet policy"]

    client -->|"Public HTTPS: challenge, proof, API"| rp
    rp -->|"begin / redeem: local Unix socket or tailnet HTTPS"| authority
    client -->|"Tailnet HTTPS over WireGuard: POST /attestation"| authority
    authority -->|"LocalAPI over Unix socket"| tailscaled
    policy -.->|"Peer identity and policy"| tailscaled
```

Trust boundaries:

| # | Boundary | Authenticated by |
|---|---|---|
| B1 | Internet → RP public origin | Nothing before a ceremony; then the lease cookie or a single-use proof |
| B2 | Client → Authority attestation endpoint | Tailnet source address (WireGuard), mapped to a node by tailscaled; `Origin`/`Host` checks; CORS for browsers |
| B3 | RP → Authority control channel | Unix peer UID, or tailnet node identity of the source address |
| B4 | Authority → RP (control responses, grants) | Filesystem permissions on the socket path, or TLS to the Authority's `.ts.net` name |
| B5 | Authority → tailscaled LocalAPI | Unix socket permissions |
| B6 | Tailnet policy → everything | Tailscale admin console and policy-file editors |

### 1.1 Handshake

This sequence shows a successful device-only ByteBind exchange. Public requests use
HTTPS; attestation travels directly over the tailnet. RP control requests use
the authenticated Unix-socket or tailnet HTTPS channel. For transcript encoding
and failure handling, see SPEC.md sections 6–9 and 14.

![ByteBind handshake: challenge, private attestation, redemption, and route authorization](diagrams/handshake.png)

[Mermaid source](diagrams/handshake.mmd).

Person-required exchanges add an invisible Authority iframe and the one-use result
collection between base attestation and redemption:

![ByteBind person handshake: base acceptance, Authority passkey assertion, result collection and redemption](diagrams/person-handshake.png)

[Person sequence source](diagrams/person-handshake.mmd). Enrollment and credential
management use separate top-level Authority pages; they are not part of this iframe.
The browser's native passkey prompt handles person verification. Hiding the frame
does not remove user presence, user verification, or signed origin checks.

The Authority's device policy and the RP's route requirements are separate
checks. An attestation or redeemed grant alone does not authorize every route.
Session renewal repeats the exchange; expiry and route requirements remain
server-enforced. Failure burns and cross-RP rejection rules are detailed in
T-P2 and T-P3. A failed or lost exchange can consume authorization without
executing the operation; a lost operation response can leave its outcome unknown
(T-R5, T-X5).

## 2. Assets

| Asset | Held by | Why it matters |
|---|---|---|
| Lease cookie (`__Host-bytebind_session`) | Client | Bearer token for management access until the server-side deadline (≤ 300 s, default 180 s) |
| Transaction approval | Client → RP | Authorizes one stored request, such as a restart or a config change |
| `C`, `S` per transaction | Authority store; `C` also client and RP; `S` revealed to the client by `H2` | Together they let you complete a ceremony |
| `R` | Client → RP → Authority | Single-use proof, valid inside the 10 s redeem window |
| Grant | Authority → RP | Unsigned JSON. The RP trusts whatever its control channel returns |
| Stored transaction requests | RP database | May contain sensitive bodies |
| Device identity (StableID, name, tags, tailnet IP) | Authority, partly the client | Registered claims limit grant disclosure; tailnet IP in H2 remains visible to application code |
| Subjects, credential public keys and revocation generations | Authority | Enrollment and person assurance depend on their integrity; credential private keys stay with authenticators |
| Pairwise key and person-association handles | Authority; association handle also RP | Correlation and server-side validation secrets; never browser or handler claims |
| Authorization policy (tags, node allowlists, RP registry) | Authority config, tailnet policy | Defines who gets access |

## 3. What the design trusts

ByteBind depends on these components and permissions. Compromising any of them
defeats its protections for the affected RPs. Deployment docs should name each
trust assumption:

1. **The tailnet's policy editors and tag owners.** Whoever can apply a tag the
   Authority's policy accepts can create authorized devices (T-TS1). Whoever can
   apply `tag:bytebind-authority` or the Authority node capability can become the
   Authority for RPs that use discovery (T-D1).
2. **The Tailscale control plane and tailscaled on the Authority node**, for
   peer identity (`status`, `whois`) and for binding source addresses to node keys.
3. **The Authority host** and its database.
4. **The RP host and all code served from the RP's origin.** A script running on
   the origin can run device-only ceremonies silently (T-B1).
5. **The authorized device** (T-X1). Compromise of that device is outside
   SPEC.md's threat model. ByteBind authenticates its node identity and does
   not isolate individual processes on it.

Operators assign node roles through Tailscale tags, restrict who may assign
those tags, and configure the Authority's device policy and returned claims.
Application developers declare each protected route's required claims. ByteBind
checks the authenticated device claims against those requirements and denies
access when any required claim is missing.

For example, a route with `require=["tag:automated"]` accepts only a device
carrying `tag:automated`; a route with `require=["tag:interactive"]` accepts only
a device carrying `tag:interactive`. A node carrying both tags can satisfy either
route. Listing both tags in one route's `require` requires both, not either.
The Authority must include `tags` in its configured grant claims; omitted tags
cannot satisfy a tag requirement. The node must also pass the Authority's policy.

These tags express operator-assigned device roles. An API client cannot fabricate
them: the Authority obtains tags from tailscaled's authenticated peer metadata,
not from client headers or a claimed client mode. Correctly separating node roles
and route requirements prevents an automation-only node from using an
interactive-only route, and vice versa, for both leases and transaction grants.
Incorrect node tagging or missing route requirements are policy risks (T-TS1,
T-A3, T-X1). Code using the permissions of a legitimately authorized node is a
trust assumption, not a bypass of these checks. A role named `tag:interactive`
does not establish human presence; SPEC.md §10 treats that as separate assurance.

## 4. Adversaries

| Adversary | Capabilities | In scope |
|---|---|---|
| Internet client | Any HTTP to RP public endpoints; can forge `Origin` | Yes |
| Malicious web page | Runs in an authorized user's browser on a non-registered origin | Yes |
| Unauthorized tailnet peer | Reaches the attestation port; fails policy | Yes |
| Shared-in node | Reaches the tailnet from another tailnet | Yes |
| Other registered RP | Valid control-channel identity; its own origin is registered | Yes |
| Co-resident process on an authorized device | Uses that node's authenticated identity and permitted roles | No process isolation; authorized-device trust assumption (T-X1) |
| Co-resident process on an RP or Authority host | Local socket and file access | Partly (T-A4, T-R1) |
| Network attacker on the public path | TLS-protected | Yes |
| Script running on a registered RP origin (XSS, compromised dependency, extension) | Same-origin script in an authorized browser | Not defended; consequences in T-B1 |
| Thief with a lease cookie | Replays the cookie from anywhere | Yes, bounded by lease TTL |
| Tailnet admin, Authority host root, compromised authorized device | Everything | No |

## 5. Security properties

What ByteBind is meant to guarantee, and the threats that test each:

| # | Property | Threats |
|---|---|---|
| P1 | No lease or approval without a fresh attestation from a policy-authorized node | T-X1, T-TS1, T-TS2, T-D1, T-R1 |
| P2 | An attestation for RP A can't be used at RP B | T-P2 |
| P3 | Each challenge, proof, and transaction is used at most once, even under concurrency | T-P3, T-R5 |
| P4 | A transaction-bound approval covers exactly the request the client sent | T-R4, T-B1 |
| P5 | Access ends within one lease TTL after the device stops qualifying | T-R2, T-TS3 |
| P6 | The RP learns only the claims registered for it | T-PR1 |
| P7 | An internet client can't exhaust Authority or RP state | T-AV1 to T-AV3 |
| P8 | A protected handler runs only when the authenticated device grant or lease satisfies every route requirement | T-TS1, T-A3, T-X1 |

## 6. Threats

### 6.1 Protocol

**T-P1. Transferable secrets. Accepted.** Anyone holding `C` can drive an
attestation, and anyone holding `S` can redeem. An authorized participant can
deliberately relay a challenge for someone else (SPEC.md §2.2). These secrets are
not bound to a process; the design depends on keeping them out of reach.

**T-P2. Cross-RP relay. Mitigated.** RP A's page or client attests a challenge
obtained from RP B. Authority check 4 requires the request `Origin` to equal
the `allowed_origin` stored with the `cid`. `Control.begin` takes that origin
from B's registration; B cannot supply a different value. Redemption checks
`rp_id` and audience, and refuses without burning when they don't match, so one
RP can't burn another's transactions (`store.redeem`). This depends on clients
sending an honest `Origin`. Browsers always do. The API clients must (invariant I1).

**T-P3. Replay and race. Mitigated.** Each transition is a conditional
`UPDATE` that must change exactly one row. Ceremony failures burn only from the expected
state and generation, so a losing attempt cannot burn the winner. Credential
and association checks commit atomically. A `cid` is
128 random bits, and each one allows a single `H1` or `R` guess before it burns.
The RP also claims a ceremony with a `DELETE` before redemption, so a repeated
proof submission can't execute a stored request twice.
Revocation and suspension use atomic bulk burns; their generation handling is
an open conformance finding in the implementation review (F8).

**T-P4. Downgrade and cross-profile confusion. Mitigated.** The session and
`tx` profiles use different labels. `profile` and `Q` must agree at
`begin`. The predecessor `tailbind/*` labels aren't accepted.

### 6.2 Authority

**T-A1. Attestation from an unauthorized source. Mitigated.** The peer address
comes from the socket, and uvicorn runs with `proxy_headers=False`. The
Authority requires a tailnet address, a known peer that is not shared in
(`ShareeNode`, `Sharer`), agreement between `status` and `whois` on the
StableID, and a policy match.
The listener refuses to bind anything but a tailnet address. It depends on
WireGuard binding source IPs to node keys, which is a provider trust assumption
(SPEC.md §19).

**T-A2. DNS rebinding and alternate hostnames. Mitigated.** `Host` must match
`attest_url` before any state is read. Preflights succeed only for registered
origins, `POST`, and `Content-Type`.

**T-A3. Policy weaker than intended. Partial.** `tag_match` defaults to `any`.
An RP registered with `tags = ["tag:mgmt", "tag:ops"]` and no `tag_match`
accepts a node carrying either tag. `config.parse` validates syntax but can't
tell intent. **Recommendation:** require `tag_match` to be set explicitly
whenever more than one tag is listed. Log the effective policy at startup.

**T-A4. Co-resident RP impersonation over the control channel. Partial.**
The Authority identifies RPs by Unix UID or by tailnet node. On an RP host
reached over HTTPS, *every process on that node* is the RP. Another process
there can:

- create transactions until it hits the RP's `max_pending_per_rp`, which locks
  out real ceremonies (T-AV1);
- redeem proofs that reach it. It can't make the real RP honor the resulting
  grant, though, because grants aren't bearer tokens.

A process can't use another RP's identity or `cid`s. **Recommendation:**
document that one node or UID equals one RP. For HTTPS, consider an optional
per-RP credential or mTLS (SPEC.md §3.2 already allows it).

**T-A5. Authority holds broad tailscaled privileges. Open (deployment).**
`status` and `whois` go through the LocalAPI socket. On Linux, access to that
socket is usually all-or-nothing: root or the `--operator` user. A process with
it can also change the node's preferences or log the node out. A compromise of
the Authority's network-facing code would then reach tailscaled.
**Recommendation:** document the minimum access. Run the attestation listener
under a dedicated user. Track whether tailscaled offers a read-only scope.

**T-A6. Control-channel parsing on the Unix socket. Low, Partial.** The handler
uses `declared_fits`, rejects non-ASCII or oversized lengths and caps bodies at
64 KiB. Malformed-length tests cover this. Only registered UIDs reach body
processing. `ThreadingMixIn` still has no thread cap.

**T-A7. Secrets at rest. Low, Partial.** The store holds `C` and `S` in
plaintext. Redeemed and burned rows are deleted only by `cleanup()`, which runs
on the next `begin`. Expired pending rows keep their secrets until then. These
secrets are dead after expiry, but the database and its backups should be
protected anyway. **Recommendation:** create the database with mode 0600, and
also run cleanup on a timer.

**T-A8. Wall-clock dependence. Low, Accepted.** Windows and leases use
`time.time()`. A backward clock step lengthens attestation and redeem windows
and RP leases. Durations are capped (30 s, 10 s, 300 s), so the effect is
bounded.

### 6.3 Tailscale provider and tailnet policy

**T-TS1. Tag owners can mint authorized devices. High (deployment), Accepted with guidance.**
Policy works on tags. Anyone listed in `tagOwners` for an accepted tag can tag
any node they control: a new VM, a container running `tailscaled`, a phone.
The `examples/tailscale` patch gives `autogroup:admin` ownership, which is the
narrowest reasonable choice. **Recommendation:** treat tag ownership as
part of the authorization boundary in docs. Use `nodes` allowlists for high-value
RPs. Consider Tailscale device approval and Tailnet Lock.

**T-TS2. Tagged devices lose user identity and key expiry. Medium (deployment), Open.**
A tagged node belongs to the tag, not to a person. Grants can't say whose laptop
approved a transaction, and node-key expiry is off by default for tagged nodes,
so a stolen tagged laptop stays authorized until someone removes it.
**Recommendation:** document both points. For human admin devices, evaluate user-owned devices
plus app capabilities (ROADMAP: "app capabilities vs tags") or posture checks.
Add the device's user to grants once the provider can map it reliably.

**T-TS3. Network paths that inherit a node's identity. Medium, Open.**
The Authority attests *the tailnet address the connection came from*. Every one
of these shows up as the authorized node:

- other OS users and processes on the node (T-X1);
- containers whose traffic is NATed out through the host's `tailscale0`;
- clients of tailscaled's `--socks5-server` or `--outbound-http-proxy-listen`,
  including other hosts if the listener isn't loopback-only;
- LAN hosts behind a subnet router that SNATs into the tailnet.

**Recommendation:** in deployment guidance, never tag subnet routers,
container hosts, CI runners, multi-user hosts, or nodes running tailscaled proxy
listeners with an accepted tag.

**T-TS4. LocalAPI field drift. Low, Open (ROADMAP).** Parsing fails closed when
it sees unknown shapes. A future change in what `ShareeNode` or `Sharer` mean
could fail *open*. **Recommendation:** pin tests to recorded responses from each
supported tailscaled version.

### 6.4 Authority discovery (RP side)

**T-D1. A rogue Authority via tag or capability. Accepted (operator trust).**
Whoever controls the Authority tag or capability is an approved operator, so
this is an accepted trust boundary (user decision, 2026-10-06).

With no `BYTEBIND_AUTHORITY` set, the RP uses whichever single online node carries
`tag:bytebind-authority` or the `bytebind.example/authority` capability,
including itself. Grants are unsigned, so whoever controls that node can issue
any grant. Shared, expired, and offline nodes are excluded, and TLS is verified
against the node's MagicDNS name. Anyone who can apply the tag or edit
`nodeAttrs` can become the Authority. A second advertised Authority causes
a "multiple Authorities" error, which also makes it a DoS lever.
**Recommendation:** set `BYTEBIND_AUTHORITY` in production (the demo env has it
commented out). Document discovery as trusting tag owners. Longer term, pin the
Authority's StableID, or sign grants (ROADMAP "managed Authority profile").

**T-D2. Local Authority socket substitution. Mitigated; deployment configuration required.**
Before connecting, the RP rejects a symlink or non-socket, requires socket
ownership by the configured Authority UID, and checks its parent ownership and
write permissions. After connecting it verifies the server's kernel-reported
UID (`SO_PEERCRED` or `getpeereid`). Separate-account deployments must set
`BYTEBIND_AUTHORITY_UID`; the current default is the RP's own effective UID.
An explicit-UID startup requirement and hostile socket-substitution tests remain
follow-up items. See the implementation review's F2.

**T-D3. Authority changes between begin and redeem. Mitigated in the bindings.**
The RP persists the creating Authority endpoint with its ceremony and redeems
only there. Withdrawal or discovery changes cannot redirect an existing
transaction; there is no automatic failover. Direct use of the discovering
client's `redeem()` relies on its in-process pin map and cannot span workers.

### 6.5 Relying party and bindings

**T-R1. Forged grant acceptance. See T-D1 and T-D2.** The RP validates active
status, audience, negotiated draft and assurance, and scoped session evidence.
The authenticated channel establishes who issued the grant; a compromised
Authority can still issue it.

**T-R2. Lease cookie theft. Medium, Accepted.** The lease is a bearer cookie,
not bound to the device (SPEC.md §2.2). Theft paths include the browser profile,
malware, proxies or logs that record cookies, and API-client cookie jars.
Mitigations: `HttpOnly`, `Secure`, `SameSite=Strict`, server-side deadlines,
renewal rotates the token and deletes the old one, and lease length is capped at
the grant TTL (≤ 300 s). A stolen token dies at the victim's next renewal (at
most 60 s while a page or client is active). If the victim is idle, it lives out
the rest of the lease. Use the transaction profile for operations where
three minutes of reuse is unacceptable.

**T-R3. Cookie tossing from sibling subdomains. Mitigated.** Both bindings use
`__Host-bytebind_session` and `__Host-bytebind_state`, with Secure, HttpOnly,
SameSite=Strict, `Path=/` and no Domain attribute. Browsers enforcing the prefix
reject sibling-domain or narrower-path replacements. State-changing routes still
check Origin; the cookie prefix does not replace that check.

**T-R4. Proof-request credentials influencing transaction replay. Mitigated in the bindings.**
`Q` covers the method, target, `Content-Type`, and body (`COVERED_HEADERS`).
On replay, both bindings reconstruct the stored operation using only its method,
target, covered headers and body, plus the in-process grant. Proof-request
cookies, Authorization and unrelated headers are stripped. Handlers must
authorize from that stored operation and grant.

Headers outside Q, including idempotency keys, `If-Match` and tenant selectors,
are not forwarded to the handler. Put operation inputs in the covered target/body
or define an application profile covering them; client-side header rejection
remains open under T-X3.

**T-R5. At-most-once execution. Mitigated.** The ceremony row is deleted before
redemption, and the grant's `operation` must match the route that the stored
target resolves to. A transient Authority failure after the claim loses the
request: it fails closed. A fresh attempt requires a new ceremony. Clients must
not automatically replay an operation after a lost response; the application
must first resolve an uncertain outcome (T-X5).

**T-R6. Origin derived from `Host` when unset. Low, Open.** Without
`BYTEBIND_ORIGIN`, `Core.rp_for` builds an RP from `request.base_url`. Any
`Host` header produces a matching "origin" for the RP's own Origin checks.
Attestation still fails, because the Authority uses the registered origin.
Requests with new hosts beyond the 32-entry cache create a fresh
`RelyingParty` each time. **Recommendation:** require a configured origin, or
refuse a `Host` that doesn't match one. The demo already uses
`TrustedHostMiddleware`.

**T-R7. Rate limiting keyed by the wrong address. Medium (deployment), Partial.**
`challenge_per_minute` is keyed by `request.client.host` (FastAPI) or
`remote_addr` (Flask). Behind a proxy that isn't configured to pass the real
client address, every user shares one 30-per-minute bucket. With a
misconfigured trusted-proxy list, `X-Forwarded-For` can be spoofed to dodge the
limit. The demo sets both up correctly. **Recommendation:** document this
next to `challenge_per_minute`.

### 6.6 Browser client

**T-B1. Script on the RP origin can silently obtain device authority. High, Accepted (design).**
Device-only ceremonies run in the background without user interaction. Any script executing on a registered origin in an authorized
browser can therefore obtain leases *and* approve any transaction-bound request
it builds: XSS, a compromised third-party script, a malicious extension.
`HttpOnly` doesn't help. The transaction profile proves that *the client* sent
the request. It does not establish a person's intent. Other RPs aren't affected (T-P2).
**Recommendation:** state this plainly in the README. Recommend a strict CSP and
no third-party scripts on management origins. For destructive operations,
use fresh person step-up where required. It adds a passkey ceremony but does not
prove informed intent (§6.10).

**T-B2. Unattended sessions. Medium, Accepted.** An open management tab on a
device that stays on the tailnet renews indefinitely, including on a locked or
unattended machine. P5 depends on the device leaving the network or the
policy, not on the user leaving. **Recommendation:** an optional absolute
session cap at the RP (a maximum lifetime regardless of renewals) and
idle detection in the renewal script.

**T-B3. Browser local-network permission prompts. Availability, Open
(ROADMAP).** Browsers' local-network permission rules may classify
`100.64.0.0/10` as private and prompt the user, which breaks silent renewal.
Users trained to accept such prompts aren't exposed further, because check 1
still refuses unregistered origins.

### 6.7 API clients

The API clients run the same ceremony without a browser. Without the browser's
honest `Origin` and CORS enforcement, the protections listed under "malicious
pages" in SPEC.md §20 don't apply to native code.

**T-X1. Device roles and route requirements. Accepted trust boundary; policy mistakes remain deployment risks.**
Operators decide which nodes carry `tag:automated`, `tag:interactive`, or both.
Developers require the corresponding claims on routes. ByteBind enforces those
requirements using Authority-issued claims derived from authenticated Tailscale
metadata. Changing client headers, switching between a browser and Python, or
claiming another access mode cannot supply a missing device tag.

An automation-only node is denied on an interactive-only route. A node carrying
both tags is permitted on either route if the Authority's policy also allows it.
Failing to require a role on a route or assigning that role to the wrong node
weakens this separation. Missing tag claims fail closed.

Any process on a legitimately authorized node can use that node's permitted
roles. ByteBind does not attest process identity or human intent; compromise of
an authorized device is explicitly outside SPEC.md §2.2's threat model. This is not
a failure of route authorization. Delegated network paths, including a full-read
SSRF with header control or a proxy, still need deployment review under T-TS3:
they can expose a node's identity to callers beyond that device.

**Recommendation:** restrict tag ownership, assign automation and interactive
roles deliberately, return the needed tag claims, and require the appropriate
role on each protected route. Use the transaction profile when approval must
cover one exact request. Add user presence only where the application requires
human approval.

**T-X2. The RP picks the Authority URL. Medium, Open.** The clients POST to any
HTTPS `authority` named in a challenge. Relay through the client is still
blocked by I1 and T-P2. What a malicious or compromised RP gains is a narrow
SSRF from the authorized node: a fixed path and body to any HTTPS host and port,
including tailnet-internal ones. It also gets a reachability timing oracle.
**Recommendation:** an optional `authority=` pin, checked before any private I/O.

**T-X3. Transaction headers dropped. Medium, Open.** The client side of T-R4.
`headers=`, `auth=`, and `cookies=` passed to `transaction()` go out only on the
challenge request. **Recommendation:** reject anything outside the covered
headers and `Accept`; T-R4's stored-operation replay already strips them.

**T-X4. Transport downgrade. Low, Partial.** Both clients set
`trust_env=False` and turn off redirects. The requests client also rejects
`verify=False` and retrying adapters. Gaps:

- the httpx `transport=`/`attestation_transport=` arguments accept an insecure
  transport without complaint;
- neither client takes a CA bundle for a private-CA Authority, which invites
  disabling verification.

**Recommendation:** add `authority_verify=`, and rename or warn on test transports.

**T-X5. Ambiguous transaction outcome. Low, Partial.** Nothing is retried at
any layer, which is correct. But `ClientError("proof")` doesn't distinguish
"never sent" from "sent, outcome unknown". **Recommendation:** add an
`ambiguous` flag.

**T-X6. Secrets in error reports and logs. Low, Open.** Exceptions are chained,
so error reporters that capture frame locals (Sentry by default) can record the
cookie jar, the `Ceremony`, and `R`. The httpx and urllib3 logs include
transaction URLs with their query strings. **Recommendation:** document this;
use `raise … from None` on ceremony steps.

**T-X7. Client availability. Low, Open.**

- A failed renewal raises instead of sending the call on a lease that's still
  valid (SPEC.md §17.1).
- The lock is held across the API call itself.
- After `fork()`, parent and child share a token, and the first renewal logs
  the other out.

### 6.8 Availability

**T-AV1. Unauthenticated ceremony starts exhaust the Authority's per-RP quota. Medium, Partial.**
Before base acceptance, each challenge holds a pending transaction for 30 s. With
`max_pending_per_rp = 200` and 30 starts per minute per address, about 14 source
addresses can keep an RP's quota full. Real users then can't start or renew,
and every lease expires within one TTL. Limits keep the state bounded, but
nothing stops this lockout. **Recommendation:** document the arithmetic. Size
the quota to the expected attack. Consider a stricter per-/24 or per-/64 limit,
or a cheap proof of work on `/bytebind/challenge`. Track this as a known limit
of unauthenticated access requests (SPEC.md §§6.3 and 22). After valid base
acceptance, a person attempt can occupy its slot for another 120 s; polling
doesn't extend that limit.

**T-AV2. One page can use up a device's attestation budget. Low, Open.** The
Authority's `PeerLimiter` is keyed by device address and shared across all
RPs. A page on any registered origin that loops attestation attempts locks that
device out of every RP for a minute. **Recommendation:** key the limiter by
(peer, origin).

**T-AV3. Tailscaled load per request. Low, Open.** Every attestation, and
every HTTPS control request, calls `status` (up to 4 MiB) and `whois`. On large
tailnets this amplifies T-AV1. **Recommendation:** cache `status` briefly, or
use `whois` alone.

**T-AV4. A single Authority. Accepted.** Failover isn't defined yet (ROADMAP
draft 0.8).

### 6.9 Privacy

**T-PR1. The RP's code learns the device's tailnet IP. Accepted privacy limit.**
`H2` decrypts to `IP || S`, and the client does the decrypting. In a browser,
that's JavaScript served by the RP. Every RP therefore learns the tailnet
address of each authorized device that visits it, even with `claims = []`, and a tailnet
address identifies the node. SPEC.md §22 records this limit; selective grant
disclosure does not hide the address from application-origin code. An opaque
address commitment remains deferred.

**T-PR2. The Authority logs node names. Low.** `attested … name=` and
`granted … node=` are logged at INFO. That's expected for audit, but name it in
the operations docs and set log retention to match.

**T-PR3. Silent fingerprinting by registered RPs. Low, Accepted.** Background
ceremonies tell an RP whether a visitor's device is authorized for it, without
any user action. This is limited to RPs the operator registered.

### 6.10 Person step-up (specification 0.8-draft; experimental)

These threats apply to the optional Authority-owned WebAuthn step-up in
`SPEC.md` sections 10–17. The experimental code and signed synthetic tests cover
these checks; real-browser acceptance and independent review remain open.

| Threat or boundary | Treatment |
|---|---|
| Internet-only or unauthorized peer tries to trigger prompts | No handoff or options before base acceptance; the private context is re-checked at the Authority page |
| Registered RP, RP XSS, or compromised application script | Can't obtain credential material or weaken stored assurance; can request ceremonies within its registered policy after valid base participation. Reduces T-B1 only for person-gated routes |
| Prompt abuse by an authorized RP | Explicit user action in the Authority frame, Authority UI naming the registered application, rate limits, user refusal. Base gating alone doesn't eliminate it |
| Phishing or RP-ID/origin confusion | Authority-owned context, exact-host RP ID, exact origin verification; no third-party RP IDs |
| Assertion replay or cross-RP/profile/operation reuse | Challenge `W` bound to immutable `cid`/RP/profile/`Q`; atomic consumption |
| UP/UV downgrade or forged authorization strings | Authority checks flags and policy; RP checks structured assurance; static strings never count |
| Unauthorized enrollment or existing-subject takeover | Dedicated enrollment policy; independently authenticated subject attachment; invites never imply device ownership |
| Shared device mistaken for the current person | Separate namespaces; no owner-derived subject; no device-wide person cache; associations are per browser lease |
| Stable identifiers and correlation | Pairwise identifiers by default; global names need explicit permission; credential material stays private |
| Revocation, recovery, and racing assertions | Generations and atomic checks; immediate Authority-side invalidation; recovery never defaults to device ownership |
| Synced credentials and multiple authenticators | The verifier accepts compatible backup flags and credentials; real-browser/authenticator acceptance remains open. No device-ownership claim |
| Lost device or stolen session | A person requirement adds an independent check; leases stay bounded; revoke device and credentials as appropriate |
| Authorized-device compromise or powerful extension | Out of scope. Passkeys don't isolate processes or prevent manipulation of an already authorized application |
| Authority compromise or Authority-page XSS | The Authority is trusted for enrollment, verification, and claims. Its pages are new critical attack surface: CSP, no third-party scripts, isolated UI |
| Application script overlays or replaces the step-up iframe | The native passkey UI names the Authority RP ID. A fake frame can't produce a valid assertion. No informed-intent guarantee |
| Another registered origin embeds a transaction's step-up page | Per-RP `frame-ancestors`; handoff refused on another RP's path; a mismatched `topOrigin` refuses and burns |
| Browser omits `topOrigin` (reported for Safari) | Accepted. Binding rests on browser-enforced per-RP framing and the RP-scoped handoff |
| Application page framed by another origin | The client requires a top-level application page. Real-browser subframe behavior remains an acceptance gate |
| RP enumeration through the person listener | Per-RP paths avoid one response listing every origin. RP identifiers and per-path origins remain enumerable (accepted) |
| Third-party cookies blocked or partitioned | Memory-only attempt token; no cookie dependency |
| Frame relays base attestation | Fixed request set; the person listener serves no base-attestation path |
| Success followed by lost delivery or redemption | Consumed once; no automatic operation replay; outcome reported as uncertain |
| Session renewal after verification | Association preserved without resetting age; validated with the Authority before each person-gated handler; transactions always need a fresh assertion |
| Known RP invalidation and age conformance gaps | Validation refusal prompts fresh step-up, but context erasure and largest-route session maximum remain open (implementation review F1/F3) |
| Overlay address exposure | `IP` in `H2` is visible to application-origin code (as T-PR1) |

WebAuthn doesn't attest that the authenticator is part of the overlay device or
that a credential is held exclusively. It establishes presence or local
verification, never informed approval of an operation.

## 7. Invariants and test coverage

| # | Invariant | Test |
|---|---|---|
| I1 | API clients send the configured origin to the Authority, never a value from the RP, the challenge, or the caller | **None** |
| I2 | No lease cookie, caller header, or caller auth reaches the Authority | Partial: the request is built bare, but no test asserts it |
| I3 | Client API and ceremony URLs stay on the configured origin | `test_cross_origin_calls_fail_before_io`, `test_foreign_urls_fail_before_ceremony` |
| I4 | No redirects, no automatic retries | `test_*redirect*`, `test_*not_replayed`, `test_retry_adapter_is_rejected_before_io` |
| I5 | Verification is on; environment proxies and `netrc` are ignored | `test_insecure_tls_is_rejected_before_io` (requests only); environment: none |
| I6 | Failures burn only from the expected state; cross-RP redemption doesn't burn | `test_attest_is_single_use_and_a_race_loser_does_not_burn_the_winner`, `test_another_rp_cannot_redeem_and_cannot_burn`, `test_wrong_r_burns` |
| I7 | `Q` is computed by the client and never taken from the RP | End-to-end transaction tests |
| I8 | The RP accepts grants only from an authenticated Authority | Real Unix control exercises peer checks; hostile socket owner/UID cases still need dedicated negative tests (T-D2) |
| I9 | The attestation endpoint reads no state before checking `Origin` and `Host` | `test_attest.py` |
| I10 | Error messages carry no secrets | Implicit only |

## 8. Prioritized work

1. **Person conformance:** clear invalidated RP person context and implement the
   largest-route session maximum (implementation review F1/F3), with both-binding tests.
2. **T-D1, T-TS1, T-TS2, T-TS3, T-X1:** a deployment-security section in the
   README covering who can mint authorized devices or Authorities, which nodes
   must never carry accepted tags, and setting `BYTEBIND_AUTHORITY` in production.
3. **T-B1:** document that origin code is fully trusted. Recommend CSP and
   step-up user presence for destructive transactions.
4. **T-X3:** enforce the documented uncovered-header restrictions in API clients;
   T-R4's replay rule is now implemented. Add explicit ambient-credential tests.
5. **I1 test** and **T-X2** `authority=` pin.
6. **T-AV1:** document quota arithmetic. Consider per-prefix limits.
7. **T-D2:** require clear same-host UID configuration and add hostile socket tests.
8. Smaller fixes: T-A3 (explicit `tag_match`), T-A6's thread cap,
   T-A7, T-R6, T-AV2, T-AV3, T-X4, T-X5, T-X7.
