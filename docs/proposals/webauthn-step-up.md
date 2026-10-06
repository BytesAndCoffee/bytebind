# Proposal: Authority-owned WebAuthn step-up (Phase 1 design)

**Status:** design for review. No implementation, spec, test, demo or
documentation changes have been made.
**Basis:** repository at `3072234` (SPEC.md draft 0.7, docs/THREAT-MODEL.md,
docs/ROADMAP.md, the Authority, store, Tailscale provider, discovery, RP core,
FastAPI/Flask bindings, `bytebind.js`, the API clients, tests, test vectors,
demo, README and blog post). Browser and library facts were checked on
2026-10-06; anything still unverified is marked **unverified** and listed in
section 15.

## Summary

- **Where it attaches.** Between attestation checks 8 and 9 (SPEC.md 11.1).
  When a transaction requires it, the Authority withholds `H2` after the base
  attestation succeeds, until a WebAuthn assertion is verified. `H1`, `H2`, `R`
  and `Q` are unchanged. The step-up is a new gate in the state machine, plus
  one new labeled hash that makes the WebAuthn challenge commit to the
  ByteBind transcript.
- **Who owns WebAuthn.** The Authority owns the WebAuthn RP ID, enrollment,
  credentials, challenges, verification and revocation. RPs declare a
  requirement (`user=bind.VERIFIED`) and read claims from the normal grant.
  They never see credential material.
- **Browser architecture.** The passkey prompt runs in an **Authority-owned
  top-level window** (a popup) on the Authority's own origin. A page on the RP's
  origin can't use the Authority's RP ID without Related Origin Requests, and
  that mechanism has trade-offs that conflict with stated requirements
  (section 4.3). **A popup needs a user click**, so the "verified" UX is
  *page → button → passkey prompt*, not a prompt that appears by itself. This is
  the main conflict with the desired UX. It's documented below, not
  worked around.
- **Identity model.** A *subject* is an Authority-native record created by the
  operator and bound to passkeys by a one-time invite. Provider-reported device
  ownership (the Tailscale login, node owner or tag) is never treated as the
  person, as you required. RPs receive presence and verification levels, and
  optionally a *pairwise* subject pseudonym or an operator-assigned name.
- **Compatibility.** This is an optional extension. Transactions that don't
  request step-up are byte-identical to 0.7. I propose publishing it as a draft
  revision ("0.9: user step-up"), not as v2 transcripts.

---

## 1. Current architecture, and where this attaches

| Component | Today | Attachment point |
|---|---|---|
| `Control.begin` (`authority.py`) | Accepts the closed member set `{audience, profile, Q, allowed_origin}` | New optional member `user` (`"present"` or `"verified"`) and an optional `continuation`. An unknown member makes a 0.7 Authority reject the request, so the combination fails closed |
| `attest()` checks 3–9 | `pending → attested`, returns `H2` | After check 8 passes, a step-up transaction moves to `awaiting_user` and returns a step-up pointer instead of `H2` |
| `TransactionStore` | Conditional single-row transitions; burns only from the expected state | Two new states; the same transition discipline |
| `Control.redeem` | Builds claims from `rp.claims` and stored `attested_claims` | Adds a `user` claims object according to the RP's registration |
| `config.py` RP registry | `claims ⊆ {device_id, tags}` | Adds user step-up levels, user claims, and a maximum user age |
| `binding.py` `meets()`, `@bind` | Requirements are tags and authorization strings; `grant=LEASE/TRANSACTION` | New keyword arguments `user=`, `max_age=`, `identify=` |
| `rp.py` leases | Store device claims; rotate on renewal | Store user claims; carry them across renewals only when the Authority confirms continuity (section 8) |
| `bytebind.js` | `attestAndProve` posts `/attestation` and expects `H2` | Handles the step-up response: open the Authority window, then re-post `/attestation` to collect `H2` |
| API clients | Same ceremony | On a step-up response, raise `StepUpRequired`; no bypass (section 7.4) |

The design reuses ByteBind's existing structure: the Authority owns all
transaction state (SPEC.md 4), the RP reaches it only over the control channel,
and grant claims come from Authority state rather than from anything the client
asserts. WebAuthn becomes one more Authority-side check whose result is stored
with the `cid` and released through redemption.

## 2. Proposed protocol flow

### 2.1 Step-up transaction

```text
Browser (RP page)        RP                  Authority (attest)    Authority (web UI)   Authenticator
     |                    |                         |                      |                   |
 1   |-- access request ->|                         |                      |                   |
 2   |                    |-- begin {user:"verified"} ->                   |                   |
     |<--- cid, C, authority ---------------------- |                      |                   |
 3   |== POST /attestation {cid,N,H1} (tailnet, CORS) =>                   |                   |
     |                    |      checks 1–8 (unchanged)                    |                   |
     |                    |      pending → awaiting_user                   |                   |
     |<= 202 {"user": {"url": "https://<authority-web>/u#<cid>"}} ======== |                   |
 4   |   [user clicks "Verify with passkey"]          |                      |                   |
     |-- window.open(url) --------------------------------------------- -->|                   |
 5   |                                                |  POST /u/options {cid}                   |
     |                                                |  same node? state awaiting_user?         |
     |                                                |  W = SHA-256(label‖cid‖H1‖w)             |
 6   |                                                |  navigator.credentials.get(W) ---------->|
     |                                                |<----------------- assertion (UP, UV) ----|
 7   |                                                |  POST /u/assertion                       |
     |                                                |  verify; awaiting_user → user_verified   |
     |<--- postMessage("done") to opener, then window closes ---------------|                   |
 8   |== POST /attestation {cid,N,H1} again ========> |                      |                   |
     |                    |  same node, same N and H1; user_verified → attested                 |
     |<= 200 {"H2": ...} ============================ |                      |                   |
 9   |-- proof {cid,R} -->|-- redeem ------------->|                      |                   |
     |                    |<-- grant + user claims -|                      |                   |
     |<-- lease / operation result                  |                      |                   |
```

Without step-up, the flow is exactly today's: step 3 returns `200 {"H2": …}`.

### 2.2 Why each step looks like this

- **Step 3 runs every existing check first.** The step-up pointer is returned
  only after `Origin`, `Host`, content type, `H1`, peer address, provider
  identity and policy have all passed. An internet client can't reach a prompt:
  it can't complete check 6. An unauthorized tailnet node fails check 8 and the
  transaction burns.
- **`H2` is withheld rather than released early.** If `S` were released before
  the step-up, the redemption state check would be the only barrier. Withholding
  it gives two independent gates: the client can't compute `R`, and redemption
  requires `attested`. It also keeps the meaning of `attested` unchanged
  ("`S` released; the redeem window is running"), so `store.redeem` needs no
  change.
- **The second `/attestation` POST.** `H2` is encrypted under `C`, and only the
  RP page holds `C`. The Authority window never needs `C`. Requiring the same
  `N` and `H1` (stored at step 3) and the same node means only the party that
  performed the base attestation can collect `H2`. Anyone else who obtains `H2`
  can't open it.
- **The popup is pre-gated (step 5).** The Authority page asks for WebAuthn
  options before calling `get()`. The Authority returns options only for a `cid`
  in `awaiting_user` whose attested node matches the requesting connection.
  So no passkey prompt for the Authority's RP ID can appear unless a base
  attestation already succeeded on that node (section 4.3 covers the one
  exception, Related Origin Requests). The `cid` travels in the URL fragment,
  so it never reaches server logs or `Referer`.
- **`postMessage` is a hint only.** The message carries nothing secret, uses
  `targetOrigin` set to the transaction's `allowed_origin`, and is only an
  optimization. If the opener reference is lost, the RP page re-posts
  `/attestation` once it sees the popup has closed.

### 2.3 Binding the WebAuthn challenge to the transaction

```text
W = SHA-256( "bytebind/v1/user/challenge" || cid || H1 || w )      w = random(32), stored with cid
```

The Authority sends `W` as the WebAuthn challenge and stores both `W` and `w`.

- **Why this binds without new cryptography.** It is a labeled SHA-256
  transcript, the same construction as `Q`. `H1` already commits to `N`, to
  `cid` and, in the transaction profile, to `Q`. So **the authenticator's
  signature transitively covers the exact request**. An archived assertion
  shows which transaction and which request bytes were approved, which a
  random challenge alone would not.
- **Freshness** comes from `w` and from the single-use `cid`.
- **Reuse is blocked** across transactions (different `cid`/`H1`), across RPs
  (each `cid` belongs to one RP; check 4 ties the base attestation to that RP's
  origin), across time (`W` is consumed by an atomic transition), and between
  profiles (the profile label is inside `H1`).
- **Alternative considered:** an Authority-random `W` bound only through server
  state. It's equally sound for live verification, because the database row ties
  `W` to `cid`, but it gives no offline auditability. I rejected it because the
  derived form costs one hash.
- **Rejected:** putting `cid` in WebAuthn extensions or in
  `user.id`/`allowCredentials`. The challenge is the field WebAuthn defines for
  binding server context.

The Authority's verification uses a library (section 11) and checks:
`type == "webauthn.get"`; `challenge == W`; `origin` exactly equals the
Authority web origin; `crossOrigin` is absent or false and there is no
`topOrigin`; `rpIdHash == SHA-256(rp_id)`; UP is set; UV is set when the level
is `verified`; the signature verifies under the stored credential key; the
credential isn't revoked and its subject is active; `userHandle` matches the
credential's subject; and the sign count, when both values are non-zero,
increases (a decrease is treated as a cloned authenticator and refused).

## 3. State-machine changes

```text
                       base attestation OK,                 assertion OK
            ┌──────── step-up required ───────▶ awaiting_user ─────────▶ user_verified
            │                                     │                          │
 pending ───┤                                     │                          │ second POST: same node, N, H1
            │                                     │                          ▼
            └──── base attestation OK, no step-up ───────────────────────▶ attested ──redeem──▶ redeemed
                                                  │                          │
                 any failed check (from that state only) ──────────────────────────▶ burned
```

- Persisted states: `pending`, `awaiting_user`, `user_verified`, `attested`,
  `redeemed`, `burned`. The `CHECK` constraint and SPEC.md 14 gain two values.
  The proposal's `base-attested` maps to `awaiting_user`, `stepup-attested` to
  `user_verified`, and `redeemable` to `attested`.
- **Windows:** `pending` keeps the 30 s attestation window; the existing cap is
  untouched. `awaiting_user` and `user_verified` share a new `step_up_window`
  (default 120 s, maximum 300 s) that starts at base attestation, because people
  need more than 30 s. The 10 s redeem window starts at `attested`, as today.
  Only authorized nodes can reach these longer windows, so they don't enlarge
  the internet-facing quota attack (T-AV1).
- **Every transition** is a conditional single-row `UPDATE` from one expected
  state. Burns apply only from the state the request expected. Autocommit means
  a burn can't be rolled back.

| Event | Server sees | Outcome |
|---|---|---|
| User cancels the prompt | Nothing: `get()` rejects with `NotAllowedError`, which by design doesn't reveal why. The Authority window posts `/u/abort {cid}` as a best effort | `awaiting_user → burned` on abort, otherwise expiry. Nothing is granted. The RP page sees the popup close without `done` and reports "not verified" |
| Prompt times out | Same as cancellation | Same |
| Invalid assertion (signature, challenge, origin, RP ID, type, `crossOrigin`) | `/u/assertion` | Burn from `awaiting_user`. One attempt per `cid`, matching ByteBind's existing one-guess rule |
| UV required but the UV flag is clear | `/u/assertion` | Burn. The prompt asked for `userVerification: "required"`, but the browser's request isn't trusted; the flag is checked |
| Credential revoked, subject disabled, or unknown credential | `/u/assertion` | Burn, with a generic failure |
| Two assertions race | Both POST | One `awaiting_user → user_verified` succeeds. The loser's update changes zero rows and it gets a generic failure **without burning**, so it can't burn the winner (as in SPEC.md 11.1) |
| Step-up window expires | — | The row is dead (expiry is a comparison, not a state) and cleanup removes it |
| Browser disappears after WebAuthn succeeds | Row sits in `user_verified` | Nobody collects `H2`, so nothing can be redeemed. Expires. Nothing granted |
| Second POST from a different node, or with a different `N` or `H1` | `/attestation` | Burn from `user_verified` |
| Redemption fails after a successful step-up | `redeem` | Burns from `attested`, as today. The user must start over, including the passkey. A successful step-up never carries over to another `cid` |
| Request for `/u/options` for a `cid` not in `awaiting_user`, or from another node | `/u/options` | Generic refusal. No burn, so an attacker who learned a `cid` can't cancel someone else's step-up |

## 4. WebAuthn architecture

### 4.1 RP ID

- **RP ID = the exact hostname of the Authority's web listener**, for example
  `authority.tail1234.ts.net`, or an operator-chosen name (section 15, Q2).
- **Not the tailnet domain.** `ts.net` is on the Public Suffix List (verified:
  entries `ts.net` and `*.c.ts.net`), so `tail1234.ts.net` is a registrable
  domain. Using it as the RP ID would be valid WebAuthn. But **every node in the
  tailnet** can obtain a certificate for its own `*.tail1234.ts.net` name, serve
  a page that requests assertions for that RP ID, and show the user's Authority
  passkeys in a prompt. The Authority's exact-origin check would reject the
  resulting assertions, but the phishing surface is avoidable, so the exact host
  is used.
- **Stability:** the RP ID is permanent for a credential. Renaming the
  Authority node or the tailnet DNS name orphans every passkey. That's a blocker
  for deployment docs, and an argument for an operator-owned domain that
  resolves to the tailnet address (Q2).

### 4.2 Origins and listener

A new Authority listener, `bytebind-authority web`, serves the enrollment UI,
the step-up page, and their JSON endpoints. It binds to the tailnet IP only and
uses TLS with the RP ID's certificate, like `attest`.
`webauthn.origin` is its exact origin. WebAuthn allows only that one origin.
RP origins never appear in `clientDataJSON` in the default mode.

**Why a separate listener and not the attestation listener:** the attestation
endpoint is a CORS JSON API exposed to every registered RP origin. The UI is
HTML that holds a management session. Separating them keeps CORS off the UI and
keeps UI bugs away from the attestation path. They can share the hostname,
since the RP ID ignores ports. Using port 443 gives users clean URLs.

Hardening for the web listener: `Content-Security-Policy` with no inline
script, `frame-ancestors 'none'` (the UI must never be framed: clickjacking),
`Cross-Origin-Opener-Policy: unsafe-none` on the step-up page only (it needs
`window.opener` for the hint; enrollment pages use `same-origin`),
`Referrer-Policy: no-referrer`, and `Host` validation as in check 1.

### 4.3 Getting the prompt into the browser: options

| Option | Works with the Authority's RP ID? | Support | Assessment |
|---|---|---|---|
| **A. `get()` on the RP page** | No. The RP ID must be a registrable suffix of the caller's origin, and `app.example.com` isn't a suffix of `*.ts.net` | — | Impossible without B |
| **B. Related Origin Requests**: Authority serves `https://{rp_id}/.well-known/webauthn` listing RP origins | Yes | Chrome/Edge 128+, Safari 18+. Firefox: one source says 152 (May 2026), web.dev still says "under consideration". **Unverified** | Gives the in-page prompt UX, but: (1) limited to **5 registrable domains**, which caps RPs per Authority; (2) every listed origin can raise the Authority passkey prompt **at any time with its own challenge**, so "no prompt before base attestation" stops being enforceable (assertions would be useless, but prompts can phish); (3) the assertion passes through RP JavaScript; (4) the well-known file is fetched from port 443 of the tailnet host, which may hit LNA (**unverified**) |
| **C. Cross-origin iframe** with `allow="publickey-credentials-get"` | Yes, `get()` in the iframe | Chrome 84+, Firefox 118+. Safari: sources conflict on whether `allow` delegation works. **Unverified** | An iframe from a tailnet host is a subframe navigation, which triggers Chrome LNA and needs `allow="local-network-access"`. It invites clickjacking. Rejected |
| **D. Authority-owned popup (top-level window)** | Yes, same-origin `get()` | All browsers. `window.open` needs a user click. `get()` inside the popup needs no click in Chrome or in Safari 16+/17.4+ (rate-limited) | **Chosen.** RP ID validation is standard, the assertion never touches RP code, the Authority controls what the user sees, and the pre-gate is enforceable |
| **E. Full-page redirect to the Authority and back** | Yes | All | Navigating away destroys the RP page's `C` and `N`. Persisting them in storage to survive the redirect spreads secrets. Rejected for v1. It's possible later if the ceremony restarts after return, at the cost of a second base attestation |

**UX consequence (conflict):** with D, `/admin/verified` is
*open → base ByteBind runs invisibly → "Verify it's you" button → click →
Authority window with native passkey prompt → window closes → page appears*.
The requested "native prompt appears on its own" requires B. Section 15, Q1
asks whether B should be an opt-in mode for deployments that accept its
trade-offs. If it is, an origin that B lists may *display* prompts outside the
ByteBind ordering. What remains enforced is that any assertion it collects is
useless (`W` is issued only after base attestation, and the origin check
binds it to the `cid`'s RP).

**LNA:** Chrome's documentation lists fetch, subresources and subframe
navigations as triggers, and `100.64.0.0/10` is in scope. The base attestation
already crosses that boundary today (T-B3). A top-level popup navigation to a
tailnet host doesn't appear among the triggers. **Unverified on real
browsers**: it's a test item, not an assumption.

### 4.4 Enrollment context

Enrollment needs "privileged context first", but the Authority isn't an RP of
itself, so there's no `cid` ceremony. The web listener instead applies the same
provider checks as attestation checks 6–8 directly to each connection's socket
peer: a tailnet address, a known peer that isn't shared in, `status`/`whois`
agreement, and the new `[enrollment] policy`. A non-qualifying node gets a
static refusal page and never sees `create()` or `get()` options.

**Subjects are independent of provider identity** (your mid-review
requirement, adopted as a MUST):

- A subject is created by the operator (`bytebind-authority subject add
  --name "Alice"`), which prints a one-time invite (32 random bytes, stored
  hashed, 15-minute TTL, single use).
- On a qualifying node, the person opens the enrollment UI, presents the invite
  and runs `create()`. The Authority stores the public credential bound to the
  invite's subject.
- The Tailscale login, node owner, or tag of the enrolling node is **recorded as
  audit context only** ("enrolled from node `nX…`, reported owner `…`"). It is
  never a lookup key for a subject, never allowed to authorize enrollment as a
  subject, and never released as the subject. A kiosk tagged `tag:shared`, a
  service node, or a laptop "owned" by Bob can all enroll and authenticate Alice.
- **Adding another passkey** requires either a fresh UV assertion by the same
  subject within the Authority UI session (5 minutes) or a new invite.
- **Why invites and not self-service:** with self-service, anyone on a qualifying
  node could mint a subject and name it anything, so "subject" would carry no
  meaning beyond "someone with a passkey". Invites put the person-to-subject
  binding where the operator can account for it. Alternatives considered:
  provider-user binding (forbidden by the new requirement) and self-service
  pseudonymous subjects (could be offered later for presence-only deployments,
  but never released as `subject`).

### 4.5 Ceremony parameters

| Parameter | Registration | Authentication |
|---|---|---|
| `rp.id` | Authority RP ID | same |
| `user.id` | Subject's random 16-byte handle, never the name (WebAuthn forbids PII here) | — |
| `user.name` / `displayName` | Operator label | — |
| `residentKey` | `required` (discoverable, so no username is needed at step-up) | — |
| `allowCredentials` | — | Empty (usernameless). Section 15, Q5 covers a "same subject as this lease" hint |
| `userVerification` | `required` | `required` for `verified`; `discouraged` for `present` |
| `attestation` | `none` by default; `direct` plus an AAGUID allowlist if configured | — |
| `timeout` | 120 s | ≤ `step_up_window` |
| `excludeCredentials` | The subject's existing credentials | — |

**UP and UV:** browser-issued assertions always have UP set (the API has no
silent mode), so `present` means *a human interacted with an authenticator* and
`verified` additionally means *the authenticator verified the user locally*
(biometric or PIN). The UV flag is checked server-side.

**Synced passkeys** are allowed by default. The backup-eligible and
backup-state flags are stored and can be restricted by policy:
`allow_synced = false` refuses BE=1 credentials at registration and at
assertion. The option is offered but off by default because it excludes most
platform passkeys.

### 4.6 Browser APIs

`navigator.credentials.create/get` with manual base64url conversion. The
existing `bytebind.js` helpers already do canonical base64url. I'm not relying
on `PublicKeyCredential.parseRequestOptionsFromJSON()`/`toJSON()` because
support is uneven. The enrollment UI and step-up page are Authority-served
static HTML/JS with no third-party scripts.

## 5. Authority storage model

The new tables live in a separate SQLite file, `identity.sqlite3`, opened only
by the Authority. They hold long-lived records with backup needs different from
the ephemeral transaction store.

```sql
CREATE TABLE subjects (
  id BLOB PRIMARY KEY,                  -- 16 random bytes; WebAuthn user.id
  name TEXT NOT NULL,                   -- operator label
  status TEXT NOT NULL CHECK (status IN ('active','disabled')),
  created_at REAL NOT NULL
);
CREATE TABLE credentials (
  id BLOB PRIMARY KEY,                  -- credential ID
  subject_id BLOB NOT NULL REFERENCES subjects(id),
  public_key BLOB NOT NULL,             -- COSE key
  sign_count INTEGER NOT NULL,
  aaguid BLOB, transports TEXT,
  backup_eligible INTEGER NOT NULL, backup_state INTEGER NOT NULL,
  name TEXT NOT NULL,                   -- friendly name
  created_at REAL NOT NULL, last_used_at REAL,
  enrolled_from_node TEXT, enrolled_from_owner TEXT,   -- audit context only (4.4)
  revoked_at REAL
);
CREATE TABLE invites (
  token_hash BLOB PRIMARY KEY, subject_id BLOB NOT NULL,
  expires_at REAL NOT NULL, used_at REAL, created_by TEXT
);
CREATE TABLE continuations (            -- section 8
  handle_hash BLOB PRIMARY KEY, rp_id TEXT NOT NULL, peer_id TEXT NOT NULL,
  subject_id BLOB NOT NULL, credential_id BLOB NOT NULL,
  level TEXT NOT NULL, verified_at REAL NOT NULL, expires_at REAL NOT NULL
);
```

New columns on `transactions`: `user_level` (`NULL`, `present` or `verified`),
`identify` (whether the RP asked for subject claims),
`n`, `h1` (to match the second POST), `w`, `step_up_expires_at`, and the
results `user_subject_id`, `user_credential_id`, `user_flags`, `user_verified_at`.

**Revocation:** setting `revoked_at`, or disabling the subject, takes effect
immediately for new assertions and at the next renewal for continuations
(section 8). The credential row is kept so audit records can still name it.
**Recovery:** an operator invite only. There's deliberately no email or
self-service recovery, because recovery would become the weakest factor.

## 6. Claims and selective disclosure

| The Authority knows | Released to an RP when |
|---|---|
| Device StableID, name, tags, tailnet IP | As today: `device_id` and `tags` when listed in `claims` |
| Step-up level achieved (`present`, `verified`) and its age | **Always, when the RP requested a step-up**: the requester learns whether its own requirement was met |
| Subject ID | Never released raw |
| Pairwise subject pseudonym `HMAC-SHA256(pairwise_key, "bytebind/v1/pairwise" ‖ rp_id ‖ subject_id)` | When `claims` lists `subject` and the transaction requested `identify` |
| Operator-assigned subject name | When `claims` lists `subject_name`. This enables cross-RP correlation; the operator opts in per RP |
| Authentication methods | When `claims` lists `amr`: `["bytebind","webauthn"]`, plus `"uv"` if verified |
| Credential IDs, public keys, assertions, authenticator data, AAGUID, BE/BS flags, enrollment context | **Never** |

The grant keeps device facts at the top level and puts person facts in a
separate `user` object, so the two can't be confused:

```json
{"active": true, "rp_id": "blog", "audience": "manage", "expires_in": 180,
 "claims": {"authorization": [], "tags": ["tag:admin"],
            "user": {"present": true, "verified": true, "age": 0}}}
```

Audit-sensitive RP: `"user": {"present": true, "verified": true, "age": 0,
"subject": "ps_3fA…", "name": "Alice", "amr": ["bytebind","webauthn","uv"]}`.

**Entitlement:** `begin` with `user` is refused (403) unless the level is in the
RP's registered `user` list, and `identify` is refused unless `subject` or
`subject_name` is in its `claims`. The RP can't request what it isn't entitled
to. A refusal fails the ceremony closed, and the binding logs a configuration
error. A new `GET /v1/registration` control endpoint (optional, section 15 Q6)
would let the binding validate decorators at startup.

## 7. Developer and operator configuration

### 7.1 Route API

```python
@bind(require=["tag:admin"])                                              # 1. device only (unchanged)
@bind(require=["tag:admin"], user=bind.PRESENT)                           # 2. + user presence
@bind(require=["tag:admin"], user=bind.VERIFIED, max_age=600)             # 3. + user verification within 10 min
@bind(require=["tag:admin"], user=bind.VERIFIED, identify=True)           # 4. + authenticated subject
@bind(require=["tag:admin"], grant=bind.TRANSACTION, user=bind.VERIFIED)  # fresh assertion per request
async def handler(lease=bind.lease): ...   # lease.user -> User(present, verified, age, subject, name) | None
```

**Why keyword arguments and not `require=["webauthn:uv"]`:** today `require` is a
pure after-the-fact match on grant claims. A step-up requirement *changes the
ceremony* (it must be sent at `begin`) and carries a time dimension (`max_age`).
Mixing that into the claim list would make one string change the protocol flow
and would make misspellings fail at runtime instead of at decoration. `user=` is
an ordered level (`VERIFIED` implies `PRESENT`). `identify` is orthogonal
because presence and identity are different properties (section 6). The
binding still checks the returned claims with `meets()`-style logic as a second
line of defense; it doesn't trust the Authority's enforcement alone.
Validation: `max_age` without `user`, or with `TRANSACTION`, raises at decoration.

### 7.2 Authority configuration

```toml
[webauthn]
rp_id = "authority.tail1234.ts.net"     # exact host; never the tailnet domain (4.1)
rp_name = "Example operations"
origin = "https://authority.tail1234.ts.net"
identity_database = "/var/lib/bytebind/identity.sqlite3"
pairwise_key_file = "/var/lib/bytebind/pairwise.key"   # 32 bytes, 0600
step_up_window = 120                   # ≤ 300
attestation = "none"                   # or "direct" with aaguids = [...]
allow_synced = true
max_user_age = 43200                   # ceiling for continuations (8)

[enrollment]
invite_ttl = 900
[enrollment.policy]
tags = ["tag:admin", "tag:kiosk"]
tag_match = "any"

[[rp]]
id = "manage-app"
# existing fields …
user = ["present", "verified"]         # levels this RP may request; omitted = none
claims = ["tags", "subject"]           # adds subject | subject_name | amr
max_user_age = 3600                    # ≤ global
```

Config validation additions:

- `origin` must be an exact HTTPS origin whose host equals `rp_id`.
- `rp_id` must not equal any RP's origin host.
- `[enrollment.policy]` is required whenever any RP lists `user`.
- `subject_name` requires `subject`.

### 7.3 Operator CLI

`bytebind-authority web …` (listener). `subject add|list|disable`,
`invite SUBJECT`, `credential list SUBJECT|revoke ID`.

### 7.4 API clients

When `/attestation` returns the step-up response, `Client`/`Session` raise
`StepUpRequired` (a `ClientError` subclass) carrying no URL by default. There
is no bypass flag, header or role that skips a route's `user=` requirement.
Routes meant for automation should be declared without `user=` and gated on
automation tags (T-X1). A possible later addition (**not proposed for v1**) is
an opt-in "complete in system browser" helper: it opens the Authority step-up
URL in the default browser on the same node and then collects `H2`. That's
legitimate because a person still uses a real authenticator at the real
Authority origin, and the same-node check still applies.

## 8. Session semantics

1. **Silent renewal and the human claim.** Renewal stays silent and *never*
   prompts. It can **carry** an existing user claim forward, but never refresh
   its age. Mechanism: each grant that carries `user` also carries an opaque
   `user.continuation` handle (random, single-use, stored hashed with
   `{rp_id, peer_id, subject, credential, level, verified_at}`). The RP keeps it
   with the lease, out of the cookie, and passes it in the next `begin`. At
   redemption the Authority re-issues the `user` claims, with
   `age = now − verified_at` and a new handle, only if all of these hold:
   - the renewal attested the **same node**;
   - the credential isn't revoked and the subject is active;
   - `age ≤ min(RP max_user_age, global max_user_age)`.

   Otherwise the grant has no `user` and the lease falls back to device-only.

   *Why Authority-side:* revocation takes effect within one renewal (≤ 60 s);
   device continuity is checked without disclosing `device_id` to the RP; and
   age comes from one clock, as a relative duration. *Alternative:* an RP-only
   timestamp. Simpler, but revocation would wait until `max_age`, and device
   continuity would need `device_id` disclosure.

2. **Maximum human-authentication age:** yes, at two levels. The operator sets
   it per RP and globally; the route sets it with `max_age`. The effective value
   is the minimum.

3. **"Verified within N minutes" with silent renewal:** yes. A lease whose
   `user.age` exceeds the route's `max_age` gets `401` with
   `X-ByteBind-Required: user-verified`. The page shows the verify button and
   runs a session ceremony with `user=verified`. Ordinary routes on the same
   lease keep working, and their silent renewals continue.

4. **Destructive transactions:** a transaction-bound route with `user=` always
   gets a fresh assertion bound to that `cid` (and through `H1`, to `Q`).
   An existing verified lease never satisfies it. That follows from construction,
   not from a flag.

5. **Representing age:** `user.age` is whole seconds since verification, as a
   relative duration (the same rule as `expires_in` in SPEC.md 13.2), rounded
   down to a 60 s bucket after the first minute to reduce timing
   fingerprinting. There are no absolute timestamps. Nothing about age or expiry
   reaches the browser (SPEC.md 15.2).

## 9. Threat-model delta

Terms (to go into THREAT-MODEL.md §3):
- **authorized device**: provider attestation of a node (existing);
- **authenticated subject**: the holder of a passkey enrolled to an
  operator-created subject;
- **user presence**: someone touched an authenticator;
- **user verification**: the authenticator verified its user locally;
- **user intent**: what the person meant to approve. **WebAuthn establishes the
  first three, never the fourth.**

| Threat | Mitigation | Status |
|---|---|---|
| Internet client triggers a prompt | Prompt is reachable only after checks 1–8; `/u/options` requires `awaiting_user` and the same node | Mitigated |
| Unauthorized device triggers step-up or enrollment | Check 8 burns the transaction; the web listener applies the enrollment policy per connection | Mitigated |
| Malicious registered RP | Can step up only its own transactions; gets only registered claims; never sees credential material. Can show arbitrary page text around the button | Partial: the Authority window names the RP from its registration (section 13) |
| XSS, compromised scripts or extensions on the RP origin | Can start a step-up for *its own* request, but can't pass it without the person completing the passkey prompt in the Authority window. That window shows the RP and an operation label, and the signature covers `Q`. Social engineering ("click verify") remains | **Reduces T-B1 for user-gated routes; doesn't remove it** |
| Malicious extension with access to every page, including the Authority window | Out of scope; equivalent to a compromised browser | Accepted |
| Phishing / origin confusion | The RP ID is the exact Authority host; the origin must be the exact Authority web origin; credentials are bound to the RP ID | Mitigated |
| RP-ID confusion via other tailnet nodes | The exact-host RP ID, not the tailnet domain (4.1) | Mitigated |
| Assertion replay, cross-transaction, cross-RP | `W` from `cid`+`H1`+`w`; consumed atomically; origin and RP ID checked | Mitigated |
| Challenge races | Single-row transition; the loser doesn't burn | Mitigated |
| Cancellation or timeout | Grants nothing; best-effort burn, otherwise expiry | Mitigated |
| UP/UV downgrade | UV flag checked server-side; requirement stored at `begin`; RP double-checks `user.verified` | Mitigated |
| Credential revocation | Immediate for new assertions; ≤ 60 s for continuations | Mitigated |
| Credential recovery | Operator invite only | Accepted (operational cost) |
| Synced passkeys | Possession extends to everyone with access to the sync account; `allow_synced=false` available | Accepted with policy |
| Several credentials per subject; several devices per subject | Supported; credentials aren't bound to devices; continuations are bound to the node of *this* session | By design |
| Several users on one authorized device | Each authenticates their own subject; provider owner ignored (4.4) | By design (new requirement) |
| Correlation through stable subject IDs | Pairwise pseudonyms by default; global `subject_name` is opt-in per RP | Mitigated |
| RP requests claims it isn't entitled to | Refused at `begin` | Mitigated |
| Lost or stolen authorized device | A user-gated route now needs the passkey as well. Device-only routes are unchanged (T-TS2) | Improved |
| Compromised authorized device | Out of scope (SPEC.md 3). Malware can't produce UV assertions without the user, but can ride a real verification | Accepted |
| Compromised Authority | Can mint any grant, as today. It still can't use passkeys elsewhere: it holds only public keys, and the RP ID is its own | Accepted |
| Invite theft | Single use, 15-minute TTL, redeemable only from an enrollment-policy node; an alert names the node used | Partial |
| WebAuthn succeeds but redemption is lost | Nothing granted; the person repeats | Accepted |
| Session renewal after WebAuthn | Carry-only with an age ceiling; never refreshes | Mitigated |
| Unattended verified session (T-B2) | `max_age` bounds how long a route trusts the person | Improved |
| The pairwise key leaks | Pseudonyms become linkable to subject IDs. Keep the key 0600; rotation changes all pseudonyms | Accepted |
| DoS: an authorized-but-hostile node holds `awaiting_user` rows | Counted in `max_pending_per_rp`; per-node limit on step-up | Partial |
| RP ID renamed (tailnet or node rename) | All credentials orphaned. Documented; custom-domain option (Q2) | Open |

Changed assumptions: the Authority web UI joins the trusted computing base, and
its CSP and framing rules become security requirements. The operator's invite
process becomes the root of subject identity.

## 10. Compatibility

- **Unchanged:** every 0.7 field, label, transcript (`H1`, `H2`, `R`, `Q`) and
  state transition for transactions that don't request `user`. Existing
  applications see no change.
- **Added:**
  - `begin.user`, `begin.identify`, `begin.continuation`;
  - the `202 {"user": {"url": …}}` attestation response;
  - two states;
  - the step-up window;
  - the `bytebind/v1/user/challenge` and `bytebind/v1/pairwise` labels (new
    transcripts; no existing label reused, per SPEC.md 8);
  - the grant's `claims.user`;
  - the Authority web endpoints.
- **Mixed versions fail closed:**
  - a 0.7 Authority rejects `begin` with unknown members;
  - a 0.7 browser client receiving `202` finds no `H2`, and its base64url
    decode throws;
  - a 0.7 API client's `Ceremony.proof` raises `ClientError("attestation")`;
  - a 0.7 RP never sends `user`.
- **SPEC.md 30 (versioning):** v1 transcripts are neither altered nor
  reinterpreted. What changes is *when* the Authority releases `H2`, for
  transactions explicitly created as step-up. I read that as an extension, not
  a new protocol version. **Reviewer decision needed** (Q7).
- **Proposal:** publish as draft 0.9, "optional user step-up extension". The
  ROADMAP already assigns 0.8 to discovery. Folding both into 0.8 is the
  alternative.

## 11. Dependencies

| Need | Choice | Why | Alternative |
|---|---|---|---|
| WebAuthn verification | **`fido2` (Yubico python-fido2) 2.2.x**, optional extra `bytebind[webauthn]` on the Authority only | Maintained by Yubico; only dependency is `cryptography` (already required); Python ≥3.10; `Fido2Server` checks the UV flag when required and accepts a `verify_origin` callback (used with exact match) | `webauthn` (Duo py_webauthn) 3.0.1: well maintained, but pulls in `pyOpenSSL`, `cbor2`, `pyasn1`, `pyasn1-modules` |
| Sign-count check | ByteBind code (an integer comparison, not cryptography) | `Fido2Server` doesn't check the counter | — |
| Browser | `navigator.credentials` plus existing base64url helpers | Universal; no JSON-helper dependency | `parseRequestOptionsFromJSON` once support is universal |
| RP bindings and API clients | **No new dependencies** | WebAuthn stays Authority-side | — |

## 12. Test plan

Layers:

- **(U)** unit tests on `store` and `Control` with a fake tailnet;
- **(A)** Authority web and attestation apps through `TestClient`, as
  `test_attest.py` does;
- **(E)** end-to-end through the example RP, as `test_end_to_end.py` does;
- **(B)** a headless-Chromium suite using the CDP virtual authenticator
  (`WebAuthn.addVirtualAuthenticator`, with UV and resident keys toggled),
  optional in CI like the existing Chromium checks.

Test assertions are produced by a test-only software authenticator that signs
with `cryptography`. That's fixture generation, not verification. Parsing is
also checked against the WebAuthn Level 3 §16 test vectors.

| Required test | Layer |
|---|---|
| Base attestation must succeed before step-up begins; `/u/options` refuses `pending` | U, A |
| Internet-only client can't trigger step-up (no tailnet peer, so no `awaiting_user`) | A |
| Unauthorized device can't trigger step-up (burned at check 8; options refused) | A |
| Authorized device receives options with `W` derived as specified | A |
| Correct assertion succeeds; UV assertion yields `verified` | A, E, B |
| Wrong challenge, wrong RP ID, wrong origin, `crossOrigin=true`, wrong `type` each fail and burn | A |
| Wrong `cid` fails; assertion for transaction A can't satisfy B | A |
| Replay of a used assertion fails | A |
| UP-only assertion fails when UV is required | A, B |
| Revoked credential and disabled subject fail | A |
| Cancelled or aborted step-up grants nothing; window expiry grants nothing | A, B |
| Concurrent assertions: exactly one succeeds; the loser doesn't burn | U (threads, as the existing race tests) |
| Cross-RP: RP B's `begin` can't request a level it isn't registered for; assertion origin and `cid` mismatches fail | U, A |
| Second `/attestation` from another node, or with another `N`/`H1`, burns | A |
| RP receives only configured claims; never `credential_id`, keys, assertions or AAGUID (assert on full grant JSON) | U, E |
| Pairwise subjects differ across RPs and are stable within one | U |
| Continuation: same node carries; another node, revocation, or age over max drops `user`; age never refreshes | U, E |
| Non-step-up flows unchanged: all existing tests pass unmodified; the vectors file is byte-identical | all |
| Transaction step-up keeps exact-request binding: wrong `Q` still fails at check 5; `W` covers `H1` | A, E |
| Existing burn and race behavior holds for `pending` and `attested` | existing tests |
| Mixed versions fail closed (0.7 JS/API client against a step-up transaction) | E |
| Enrollment: refused from a non-policy node; invite single-use and expiring; provider owner never creates or selects a subject | A |
| API client raises `StepUpRequired`; no bypass path | E |
| Web UI headers: CSP, `frame-ancestors`, `Host` validation | A |

New test vectors: `W` derivation and the pairwise pseudonym, added to
`bytebind-v1.json` under a new `user` section with `scripts/make_vectors.py`.

## 13. Demo plan

- `/admin`: unchanged ambient experience.
- `/admin/verified`: `user=bind.VERIFIED, max_age=600`. The page loads its
  shell, base ByteBind runs, then a "Verify it's you" card appears. One click
  opens the Authority window, which shows "**Example operations** is asking
  **demo.example.com**'s operator to confirm it's you" and then the native
  prompt. The window closes and the content appears.
- `/admin/destructive-demo`: a transaction-bound POST with `user=bind.VERIFIED`.
  The Authority window shows the RP name plus an operation label the RP
  registers per route (for example "Reset demo counter"), marked as supplied by
  the application. Each click requires a fresh passkey.
- **Authority UI** (`https://<authority>/`): invite redemption, the subject's
  name, the list of passkeys (friendly name, created/last used, "synced" badge
  when BE=1, no IDs or keys), rename, revoke, add passkey. It shows the current
  device as "you're connected from *node-name*" with the note that passkeys
  aren't tied to this device.
- **Demo README:** enrollment steps, CLI invite, and a browser matrix for the
  popup flow.

## 14. Documentation changes (after approval)

- **SPEC.md:** new section "User step-up extension" covering states, windows,
  `W`, the endpoints, claims and failure rules. Add a pointer in sections 3 and
  6, two values in section 14, and the terms in section 27.
- **THREAT-MODEL.md:** the section 9 delta; amend T-B1, T-B2 and T-TS2; add
  the terms to §3.
- **ROADMAP.md:** draft 0.9 entry; verification items (popup LNA, ROR,
  Firefox, real authenticators).
- **README:** the two-sentence framing plus "the application doesn't become a
  WebAuthn application"; the route API; Authority web listener commands.
- **Blog post:** a short section using your framing ("First prove the device
  is somewhere it is allowed to be. Then, when policy requires it, prove a
  person is there too."), with an explicit note on what WebAuthn doesn't
  prove (intent).

## 15. Open questions and blockers

1. **UX conflict (blocker for the "prompt appears by itself" goal):** accept
   the one-click popup (option D), or add Related Origin Requests as an opt-in
   mode with its four trade-offs (section 4.3)? I recommend D only for v1.
2. **RP ID stability:** a `*.ts.net` host is simple but rename-fragile. Should
   the design also support an operator-owned domain resolving to the tailnet IP
   (public DNS record pointing at `100.x`, certificate via DNS-01)?
3. **Popup and LNA** must be verified on Chrome (≥142), Safari and Firefox on a
   real tailnet before the demo UX is promised.
4. **Firefox ROR status** is unverified (sources conflict). It matters only if
   Q1 adopts ROR.
5. **"Same person" re-verification:** when a verified lease ages out, should
   `allowCredentials` be limited to the lease's subject? That's better UX and
   prevents a person swap. But the RP would have to send the continuation to
   the step-up `begin` and the Authority would have to map it to a subject.
   Proposed yes, opt-in.
6. **`GET /v1/registration`:** worth adding so bindings can fail at startup on
   decorators the RP isn't registered for?
7. **Versioning:** confirm that the extension is acceptable under SPEC.md 30
   without new `h1`/`h2`/`redeem` labels (section 10).
8. **Operation labels in the Authority window:** RP-asserted text is better
   than nothing but can be misleading. Show it marked as "from the
   application", or show only the RP name?
9. **Self-service presence-only subjects** (no invite, never released as
   `subject`): useful for small deployments, or out of scope for v1?
