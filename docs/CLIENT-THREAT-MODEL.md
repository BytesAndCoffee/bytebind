# API client threat model

**Scope:** `bytebind.client.Client` (httpx), `bytebind.requests.Session`, and the
shared ceremony in `bytebind._client`. These let a program on an authorized
overlay device call a ByteBind-protected API: they run the session profile
(lease) and the transaction-bound profile without a browser.

This document extends SPEC.md sections 3 and 6. It covers what changes when the
client is not a browser, the threats that follow, what the current code does
about each, and what is still open. Paths and line references are to the
uncommitted client work as of 2026-10-06.

## 1. What changes without a browser

The browser deployment relies on two controls the browser enforces, not ByteBind:

1. **The browser sets `Origin` honestly.** Page script cannot forge it.
   The RP's Origin checks (10.2, 13) and the Authority's per-`cid` origin check
   (11.1 check 4) depend on that.
2. **CORS restricts which code can read `H2`.** Only pages on a registered
   origin can drive the private attestation endpoint and read its response.
   That is the defense against "malicious pages opened on authorized devices"
   in SPEC.md section 6.

A native client sets `Origin` itself and is not subject to CORS. As a result:

- **Every process on an authorized node can obtain a grant.** That includes
  every local user, every container whose traffic leaves through the node's
  tailnet interface, and every CI job on a tagged runner. The Authority sees a
  connection from a node; it cannot tell a browser tab from a script. The
  browser model's unit of authorization was "a page on the RP's origin running
  on an authorized device". With native clients it becomes "any code that can
  originate traffic from the authorized node's tailnet address".
- **The Origin checks no longer authenticate anything.** Any non-browser caller
  can send any `Origin`. The checks still have one job for the API client: an
  *honest* client sends its configured origin to the Authority, so a malicious
  RP cannot relay another RP's challenge through it (T3). That makes the
  client's Origin handling security-critical. Section 4 lists it as an invariant.

None of this is a protocol flaw. SPEC.md already puts device compromise out of
scope and says device-backed participation is not human presence. What changes
is the deployment guidance: with an API client, a node tag authorizes far more.

## 2. Assets

| Asset | Where it lives | Lifetime |
|---|---|---|
| Session lease cookie (`bytebind_session`) | Public cookie jar, in memory | Until server-side deadline (≤ 180 s after last renewal by default); rotated on each renewal |
| State cookie (`bytebind_state`) | Public cookie jar | 60 s, one ceremony |
| `C`, `N`, `H1` | `Ceremony` object | One ceremony |
| `S`, `IP` | Local variables in `Ceremony.proof` | Microseconds |
| `R` | Proof request body | Single use; valid until redeemed or the 10 s redeem window closes |
| Transaction request (method, target, Content-Type, body) | Caller, then the RP's stored request | Executed at most once |
| Authority's attestation of this node | Implicit in the node's tailnet address | As long as the node stays tagged |

## 3. Actors and trust

| Actor | Trust | Notes |
|---|---|---|
| Calling application code | Trusted | Chooses origin, paths, and requests. Can always misuse its own grants |
| Other local processes and users on the node | **Not trusted, but not excluded** (T1) | Can run their own ceremony; can't read this process's memory without OS-level access |
| RP at the configured origin | Trusted for its own API; **not trusted to choose the Authority** (T3) | Supplies `authority` in every challenge |
| Other RPs | Untrusted | Must not be able to use this client to get grants at the configured RP |
| Authority | Trusted | |
| Network between client and RP | Untrusted | TLS with verification |
| Network between client and Authority | Overlay; TLS with verification | |
| Error reporters, log sinks, crash dumps | Partially trusted | May see exception chains and frame locals |

## 4. Invariants the client must keep

These are the properties the mitigations below depend on. Each should have a test;
the right column shows current coverage.

| # | Invariant | Test |
|---|---|---|
| I1 | The `Origin` sent to the Authority is always the configured origin, never a value from the RP, the challenge, or the caller | **None.** Add one: a challenge from a foreign RP must reach the Authority with the configured origin |
| I2 | Lease cookies, caller headers, and caller auth never reach the Authority request | Partial (`_prove` builds a bare request; no assertion on headers) |
| I3 | API and ceremony URLs stay on the configured scheme/host/port | `test_cross_origin_calls_fail_before_io`, `test_foreign_urls_fail_before_ceremony` |
| I4 | No redirects on any request | `test_attestation_redirect_is_not_followed`, `test_redirect_is_not_followed` |
| I5 | No automatic retries of any request, including at the adapter layer | `test_api_errors_are_not_replayed`, `test_lost_*_is_not_replayed`, `test_retry_adapter_is_rejected_before_io` |
| I6 | TLS verification can't be disabled through the public API | `test_insecure_tls_is_rejected_before_io` (requests only) |
| I7 | Environment proxies, `netrc`, and `REQUESTS_CA_BUNDLE`-style settings are ignored | None |
| I8 | `Q` is computed from the exact bytes sent, never taken from the RP | Covered by the end-to-end transaction tests |
| I9 | A tampered or unauthenticated `H2` never produces a proof submission | `test_tampered_attestation_never_submits_proof` |
| I10 | `ClientError` messages carry no proof material or response bodies | Implicit; no assertion |

## 5. Threats

Severity is for a typical deployment: an operator workstation or an automation
host tagged for ByteBind access.

### T1. Co-resident code gets the node's authorization — **High (deployment)**

Any process that can send traffic from the node's tailnet address can run the
ceremony with any `Origin` and get a lease or approve a transaction. That covers:

- other OS users on a shared host, jump box, or CI runner;
- Docker and other containers whose traffic is NATed through the host's
  `tailscale0`;
- anything that can reach a `tailscaled` SOCKS5 or HTTP proxy listener
  (`--socks5-server`, `--outbound-http-proxy-listen`), including other hosts if
  the listener is bound to a non-loopback address;
- LAN hosts behind a subnet router that SNATs their traffic into the tailnet;
- a full-read SSRF with header control in any service on the node. The attacker
  computes `H1` offline from a challenge it requested, and the SSRF only has to
  POST it and return `H2`.

**Current mitigation:** none in the client, and none is possible: the Authority
attests nodes, not processes.

**Recommendations:**

- Document in the client README that authorization is per node and that browser
  CORS protections don't apply.
- Policy guidance: give automation hosts their own tag (for example
  `tag:bytebind-api`) separate from interactive admin devices, and have RPs
  require the stronger tag (`require=["tag:admin"]`) on destructive routes.
- Don't tag multi-tenant hosts, CI runners, subnet routers, or nodes that run
  `tailscaled` proxy listeners.
- Use the transaction-bound profile for destructive operations, so stolen access
  can't be reused beyond one request.

### T2. Lease cookie theft — **Medium**

A copied `bytebind_session` cookie works from any network until its server-side
deadline (SPEC.md 3). Ways to get it from an API client that a browser doesn't
expose: code that pickles or persists the cookie jar, debug logging of request
headers, `httpx` event hooks or `requests` hooks installed by the caller, and
crash dumps.

**Current mitigation:** the jar lives only in memory. Leases are short. Each
renewal rotates the token and deletes the previous one (`rp.py` `accept_proof`
with `previous_session`), so a stolen token dies within 60 s *if the legitimate
client keeps making calls*. An idle client leaves a stolen token valid for the
rest of its lease (up to 180 s).

**Recommendations:** document "never persist the cookie jar". Optionally add a
`close()`/`logout()`-on-exit default for the context manager, so short scripts
end their lease rather than leave it for the full TTL.

### T3. Malicious or compromised RP picks the Authority — **Medium**

`authority` comes from the challenge, and the client POSTs to whatever HTTPS
origin it names (`client.py` `_prove`, `requests.py` `_prove`). An RP the client
is configured to trust, or anyone who controls its responses, can:

- **Relay attempt (blocked):** forward RP B's challenge so that this client
  attests for B. Check 4 at the Authority defeats this, because the client sends
  *its own* configured origin, not B's. This relies on I1.
- **Limited SSRF from the authorized node:** make the client POST
  `{"cid","N","H1"}` with `Origin: <configured origin>` to `/attestation` on any
  HTTPS host and port, including tailnet-internal services that are not
  reachable from the internet. The path and body are fixed, and the response
  must be valid JSON containing a valid `H2`, so impact is low. Whether the proof
  POST arrives also gives the RP a timing oracle for internal reachability.
- **Fake Authority:** an attacker who knows `C` (it issued the challenge) can
  return an `H2` that the client accepts, and learn nothing it didn't already
  have. Harmless.

**Recommendation:** add an optional `authority=` pin (exact origin, or a
predicate) to both clients. If set, refuse a challenge whose `authority`
differs, before any private I/O. Consider defaulting to the Tailscale
discovery rules (Authority tag plus `.ts.net` name) when a LocalAPI socket is
available.

### T4. Headers on a transaction aren't bound or delivered — **Medium (correctness with security consequences)**

`Q` covers the method, target, `Content-Type`, and body (`COVERED_HEADERS`).
After redemption, the RP replays the stored request with the *proof
submission's* headers for everything else (`fastapi.py` `_replay`). In both
clients, caller-supplied `headers=`, `auth=`, and `cookies=` on `transaction()`
go out only on the first (challenge) request. The proof submission omits them.
As a result:

- headers the handler relies on (`Authorization` for a second auth layer,
  `If-Match`, idempotency keys, tenant selectors) are silently dropped. The
  handler runs without them, or with whatever the proof request carries;
- whoever submits the proof decides the ambient headers and cookies the
  approved request executes with. Combined with transferable proofs (SPEC.md 3),
  a relayer can attach their own application credentials to someone else's
  approved request.

**Recommendations:**

- Client: reject `transaction()` calls with headers outside `COVERED_HEADERS`
  plus a short allowlist (`Accept`), and reject `auth`/`cookies`. Or send the
  same caller headers on the proof submission and document that they aren't
  bound by `Q`. Rejecting is safer.
- Spec/RP: state that application authorization for a transaction-bound request
  must come from the stored request and the grant, never from proof-request
  ambient state. Alternatively, extend the covered headers.

### T5. Transaction ambiguity and duplicate execution — **Low (mitigated)**

If the proof submission's response is lost, the caller can't tell whether the
stored request ran. Retrying would start a new transaction and could run the
operation twice.

**Current mitigation:** no retries at any layer (I5). A connection error raises
`ClientError("proof")`, which the docstrings tell callers not to retry.
**Gap:** `ClientError` doesn't distinguish "proof never sent" from "sent,
outcome unknown". Add an `ambiguous` flag (or a separate subclass) so callers
can decide whether to reconcile.

### T6. TLS and transport downgrades — **Low**

**Current mitigation:** `trust_env=False` and redirects off on both paths.
`requests` rejects `verify=False` and retrying adapters. Private requests use a
separate session with no caller headers or cookies.

**Gaps:**

- `httpx`: `transport=`/`attestation_transport=` accept any transport, including
  one built with `verify=False`. That's intended for tests, but nothing marks it.
  Rename it or warn.
- Neither client accepts a CA bundle for the Authority. Deployments with a
  private CA (instead of `tailscale cert`) will be tempted to disable
  verification or monkeypatch `_private`. Add `authority_verify=` taking a CA path.
- `requests`: `Session.proxies` set by the caller is honored for public
  requests. Only TLS-terminating proxies matter, and they need a trusted CA, so
  this is acceptable. Document it.

### T7. Secrets in logs and error reports — **Low**

`ClientError` omits bodies and secrets (I10), but chains the underlying
exception. Error reporters that capture frame locals (Sentry's default) can
record the `Ceremony` (`C`, `N`), the proof dict (`R`), and the cookie jar.
`C` and `N` are useless once the ceremony finishes. `R` is useful only within
the 10 s redeem window and only together with the state cookie. The lease cookie
is the real exposure (T2). `httpx` INFO logs and `urllib3` DEBUG logs include
URLs, so query strings on transaction targets are logged.

**Recommendation:** document it. Optionally clear `Ceremony` fields after
`proof()` and raise `ClientError(...) from None` on ceremony steps.

### T8. Availability — **Low**

- A failed renewal raises, and the call never goes out even when the existing
  lease is still valid. The browser client keeps the lease (SPEC.md 15.2); the API
  client doesn't. Consider sending the call anyway after a failed renewal and
  letting a 401 decide.
- Every call after 60 s idle runs a full ceremony. The RP limits ceremony starts
  per client address (`challenge_per_minute`, default 30), so many clients
  behind one NAT or one busy host share that budget.
- The lock is held across the API call itself, not only the ceremony, so one
  slow request blocks every thread. Hold it only for the renewal decision and
  the ceremony.
- After `os.fork()`, parent and child share a lease token. The first renewal
  rotates it and logs the other process out.

## 6. Out of scope

Same as SPEC.md section 3: a compromised authorized device or Authority, an RP
that executes something other than the stored request, and human presence.
The client cannot check that the RP executed the stored request. It has only the
RP's response.

## 7. Suggested work, in priority order

1. T1 documentation and tag-separation guidance (README, `examples/client`).
2. I1 test: the Authority request carries the configured origin for a foreign challenge.
3. T4: reject unbound headers/auth/cookies on `transaction()`. Add spec text on ambient state at replay.
4. T3: optional `authority=` pin.
5. T6: `authority_verify=` CA option; mark test transports.
6. T5: an ambiguous-outcome signal on `ClientError`.
7. T8: narrow the lock; use the existing lease after a failed renewal.
