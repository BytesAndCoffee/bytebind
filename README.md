# ByteBind

**ByteBind isn’t a nicer login screen. It’s *no login screen*.**

No registration ceremony. No OIDC/OAuth ceremony. No redirects, PINs, keys, or account pickers.

For the developer, it’s an import, an app bind, and route binds. For the operator, it’s a few lines of policy. For the user, it’s seamless, ambient authentication.

**The developer declares what’s protected. The operator declares who’s trusted. The user just opens the page.**

ByteBind authorizes management access to a public application through a fresh
exchange involving an allowed private-overlay device. The browser obtains a
challenge from the application, completes private attestation, and returns a
proof for one-time redemption.

- **[SPEC.md](SPEC.md):** the protocol, draft 0.7.
- **[docs/blog-post.md](docs/blog-post.md):** why it exists, in plain language.
- **[docs/OVERVIEW.md](docs/OVERVIEW.md):** the exchange in one paragraph.
- **[docs/ROADMAP.md](docs/ROADMAP.md):** what's planned for draft 0.8, open questions, and what is and isn't verified.
- **[test-vectors/bytebind-v1.json](test-vectors/bytebind-v1.json):** byte-exact vectors for both profiles.

This repository is the reference implementation, in Python with a dependency-free
browser client. It targets draft 0.7 and uses Tailscale as the attestation provider.

> **Status:** draft protocol, unreviewed implementation. Do not rely on it to
> protect anything important until it has had an independent security review.

## Examples and demos

- **[bytebind-demo](examples/demo/README.md)** — runnable FastAPI app with a public
  homepage and an admin page protected by `tag:admin`. Includes an
  [nginx config](examples/demo/nginx.conf), Authority registration instructions,
  and an optional [systemd service](examples/demo/bytebind-demo.service).
- **[Two-profile example](examples/rp_app.py)** — FastAPI app using the binding for
  both a session lease and a transaction-bound operation.
- **[Python API client example](examples/client/README.md)** — session and
  transaction calls against the two-profile app.

### Explainer video

https://github.com/user-attachments/assets/159b0163-70aa-47ba-bb4b-00a9c3bbbed1

[Download the original explainer (MP4)](docs/bytebind-explainer.mp4).
The inline player uses a smaller copy for GitHub's attachment limit.

### Comments demo video

https://github.com/user-attachments/assets/37dd5628-83c6-412e-a72a-5117f13cf7f0

[Download the comments demo (MP4)](docs/bytebind-comments-demo.mp4).

These are recordings. To run the demo yourself, see [bytebind-demo](examples/demo/README.md).

## Quick start

From a checkout, with Python 3.11 or later:

```bash
python3 -m venv .venv
.venv/bin/pip install .
export BYTEBIND_ORIGIN=https://demo.example.com
export BYTEBIND_RP_DB="$PWD/demo-state/rp.sqlite3"
.venv/bin/bytebind-demo
```

Replace `demo.example.com` with your HTTPS hostname and proxy nginx to
`127.0.0.1:8000`. Follow the [demo setup guide](examples/demo/README.md) to
configure TLS, register the app with the Authority, and set the tailnet policy.

The homepage and `/healthz` work before an Authority is available. To open
`/admin`, the browser must reach the private Authority from a device carrying
`tag:admin`. The app discovers the Authority through its tailnet role tag or
node capability; an explicit endpoint can override discovery. The Authority must
include device tags in its grant claims. Use the public HTTPS URL in your browser
so Secure cookies and WebCrypto work.

## Request flow

| Caller → receiver | Request | Result |
|---|---|---|
| Browser → RP | Application-defined access POST | Challenge for a new transaction |
| RP → Authority | Control POST `/v1/transaction` | RP-scoped transaction material |
| Browser → Authority | Private POST `/attestation` | Encrypted attestation secret |
| Browser → RP | Application-defined proof POST | Lease or operation result after redemption |
| RP → Authority | Control POST `/v1/redemption` | Scoped authorization grant |

The **session profile** grants a short lease, renewed every 60 seconds. Losing
private access stops renewals; the last accepted lease determines remaining
access. The **transaction-bound profile** binds a grant to a submitted request
through digest `Q`; the RP stores that request and executes it at most once.

Expiry is enforced server-side. Control responses use relative durations, and
the browser receives no expiry fields. Supported browsers may require permission
for public-to-private requests; real deployment behavior remains a testing item.

## Layout

| Path | What it is |
|---|---|
| `src/bytebind/protocol.py` | Encoding, `Q`, and the H1, H2, and R transcripts for both profiles |
| `src/bytebind/store.py` | The Authority's transaction store: single-use, conditional state transitions |
| `src/bytebind/tailscale.py` | The Tailscale attestation provider (LocalAPI `status` and `whois`) and policy |
| `src/bytebind/authority.py` | The Authority: attest service, and the control channel over a Unix socket or tailnet HTTPS |
| `src/bytebind/config.py` | Authority configuration (TOML), validated at startup |
| `src/bytebind/binding.py` | What the web bindings share: requirements, stored requests, the renewal script, RP configuration |
| `src/bytebind/fastapi.py` | FastAPI binding: route protection, leases and transaction grants, mounted endpoints, and browser injection |
| `src/bytebind/flask.py` | Flask binding, with the same API |
| `src/bytebind/limits.py` | Rate limiting and capped body reads |
| `src/bytebind/discovery.py` | Authority discovery through tailnet tags and node capabilities |
| `src/bytebind/demo.py` | The packaged `bytebind-demo` app and launcher |
| `src/bytebind/rp.py` | Relying-party side: `AuthorityClient` and `RelyingParty` (state cookies, leases, stored requests) |
| `src/bytebind/client.py` | HTTPX API client for session leases and transaction-bound operations |
| `src/bytebind/requests.py` | Requests Session with the same ceremony and both profiles |
| `src/bytebind/web/bytebind.js` | The browser client (WebCrypto only) |
| `examples/` | Relying-party examples, Authority configuration, and nginx/systemd demo setup |
| `scripts/make_vectors.py` | Regenerates the test vectors |

## Running an Authority

The Authority runs as up to three narrowly scoped listeners, all from one config
file (see [examples/authority.toml](examples/authority.toml)):

```bash
pip install .

# Browser attestation: use the tailnet IP and a valid TLS certificate.
# Preserve the accepted connection's device identity.
bytebind-authority --config authority.toml attest \
  --host 100.x.y.z --port 8443 --certfile attest.crt --keyfile attest.key

# Control channel for RPs on the same host: a Unix socket. Each RP is identified
# by the kernel-reported user ID of the connecting process.
bytebind-authority --config authority.toml control-unix --socket /run/bytebind/control.sock

# Control channel for RPs on other tailnet nodes: HTTPS, RPs identified by node.
bytebind-authority --config authority.toml control-https \
  --host 100.x.y.z --port 9443 --certfile control.crt --keyfile control.key
```

The socket's directory must be owned by the Authority's account and not group-
or world-writable; the Authority refuses to start otherwise.

## Using it from a relying party

For FastAPI, the adapter mounts the ceremony endpoints and adds the browser
client and fixed-interval renewal to HTML responses:

```python
from fastapi import FastAPI
from bytebind.fastapi import ByteBind

app = FastAPI()
bind = ByteBind(app)

@app.get("/admin")
@bind(require=["tag:admin"], grant=bind.LEASE)
async def admin(lease=bind.lease):
    return {"device_id": lease.device_id}

@app.post("/restart")
@bind(require=["tag:admin"], grant=bind.TRANSACTION)
async def restart(body: Restart, grant=bind.grant):
    return {"restarted": body.service, "approved_by": grant.device_id}
```

`bind.LEASE` grants a short session that the page renews in the background.
`bind.TRANSACTION` binds one approval to one request: the first call stores the
request, answers 202 with a challenge, and runs nothing. After the browser's proof
is redeemed at `/bytebind/proof`, the stored request is replayed through the app
and the handler runs exactly once; its response is the proof submission's
response. The approval covers the method, the target as sent, the
`Content-Type` header, and the body (`max_transaction_body=`, default 16 KiB).
FastAPI bounds transaction bodies before model parsing; both bindings cap proof
submissions at 1 KiB and reject oversized inputs with 413.
Call it from the browser with `ByteBind.transaction(url, { body }, "/bytebind/proof")`.

No Authority address is needed: the adapter prefers an existing local
`/run/bytebind/control.sock`, otherwise discovers a single online tailnet node
with `tag:bytebind-authority` or the node capability
`bytebind.example/authority`. Tag-only discovery uses its MagicDNS name and
HTTPS port 9443. TLS certificate verification remains enabled. Shared, expired,
and offline nodes are excluded; zero or multiple matches fail closed with 503.
Discovery runs at each transaction creation and redemption, with no automatic replay or failover.

Set `BYTEBIND_AUTHORITY` to override discovery explicitly. Set
`BYTEBIND_ORIGIN` to the public origin,
`BYTEBIND_AUDIENCE` (default: `manage`), and `BYTEBIND_RP_DB` to a writable
SQLite path (default: `bytebind-rp.sqlite3`). These also have explicit constructor
keywords: `authority`, `origin`, `audience`, and `database`; `rp` accepts an
existing `RelyingParty`. If origin is omitted, it is derived from the request URL;
configure trusted hosts and proxy headers for your deployment.

The RP needs access to tailscaled's LocalAPI (default:
`/var/run/tailscale/tailscaled.sock`, override with `BYTEBIND_TAILSCALE_SOCKET`
or `tailscale_socket=`). Constructor options `authority_tag`,
`authority_capability`, and `authority_port` override discovery conventions.
For a custom port or multiple Authorities, advertise capability metadata in the
tailnet policy:

```json
"nodeAttrs": [{
  "target": ["tag:bytebind-authority"],
  "app": {
    "bytebind.example/authority": [{"port": 9443, "audiences": ["manage"]}]
  }
}]
```

The key `bytebind.example/authority` is a capability identifier in the reserved
`.example` namespace, not a URL to visit. To use your own namespace, set
`authority_capability=` to the same key used in your policy.

This is a ByteBind-defined **node capability**, describing the Authority itself,
rather than an application grant to callers. An omitted `audiences` field matches
any audience; a supplied list filters discovery even when the node has the role
tag. Assign each Authority its appropriate audience metadata when there are
multiple nodes. The capability advertises a port, not an arbitrary destination
URL: the host always comes from that node's MagicDNS identity. Discovery needs
peer visibility and a network grant permitting the RP to reach the control port.
The Authority must run its HTTPS control listener with a valid certificate on
the advertised port; assigning a tag does not start the listener or register RPs.

The Authority must register this RP and audience, permit the device, and include
`tags` in the RP's configured `claims` for `tag:admin` to be available. Every
listed requirement must match: `tag:` requirements check device tags; other
strings check the grant's `authorization`. Missing claims fail closed. A
transaction-bound handler's requirements are checked against its grant before
it runs. Keep the decorator below
`@app.get(...)` as shown; handlers need not declare `lease` or `grant` to be protected.

An unauthenticated HTML GET receives a sign-in page that completes the ceremony
and reloads the URL; API requests receive 401, and insufficient claims receive
403. Cookies require HTTPS. Mounted paths are `/bytebind/client.js`,
`/bytebind/challenge`, `/bytebind/proof`, and `/bytebind/logout`. State-changing
protected requests and logout require the configured Origin. Ceremony starts
are rate limited per client address (`challenge_per_minute=`, default 30), so
anonymous clients cannot fill the Authority's pending quota for this RP. The
renewal script is injected only into protected HTML responses; public pages
never contact the Authority. Injection buffers uncompressed HTML responses and
uses inline JavaScript, so streaming HTML and strict CSP deployments should
account for that behavior.

### Flask

The Flask binding has the same shape. Install it with `pip install "bytebind[flask]"`:

```python
from flask import Flask, request
from bytebind.flask import ByteBind

app = Flask(__name__)
bind = ByteBind(app)

@app.get("/admin")
@bind(require=["tag:admin"])
def admin(lease=bind.lease):
    return {"device_id": lease.device_id}

@app.post("/restart")
@bind(require=["tag:admin"], grant=bind.TRANSACTION)
def restart(grant=bind.grant):
    return {"restarted": request.get_json()["service"], "approved_by": grant.device_id}
```

Parameters whose default is `bind.lease` or `bind.grant` are filled in when the
view runs. It takes the same keyword arguments and environment variables, mounts
the same paths, and serves the same sign-in page and renewal script. Behind a
reverse proxy, wrap the app in Werkzeug's `ProxyFix` so the client address and
origin come from the proxy. The transaction digest covers the target as sent,
read from `REQUEST_URI` or `RAW_URI` (Werkzeug's server and gunicorn set these);
other servers fall back to re-encoding `PATH_INFO`.

### Python API client

Install the optional HTTP client with `pip install "bytebind[client]"`. Run it on
an authorized tailnet device that can reach both the public app and the private
Authority:

```python
from bytebind.client import Client

with Client("https://app.example.com") as api:
    response = api.get("/status")
    response.raise_for_status()
    print(response.json())

    result = api.transaction("/restart", json={"service": "demo"})
    result.raise_for_status()
    print(result.json())
```

`get()`, `post()`, and `request()` establish a session before the first call and
renew before the next call once 60 seconds have elapsed. Idle clients run no
background renewals. `authenticate()` explicitly establishes or renews a lease;
`logout()` ends it. `transaction()` works independently of a session and covers
the exact prepared method, percent-encoded target, Content-Type, and body.
Responses are ordinary HTTPX responses; call `raise_for_status()` to check the
application result. Ceremony failures raise `bytebind.client.ClientError` with
`step` and `status` (absent for network or protocol failures).

The client sends the app's Origin header and maintains its state/session cookies.
Attestation uses a separate connection without application cookies or credentials.
TLS verification stays enabled; environment proxies are ignored. URLs must remain
on the configured public HTTPS origin. Redirects are not followed, and API calls
and proofs are never automatically retried, including on a 401 or lost response.
An operation may have executed before its response was lost; use the application's
recovery or idempotency mechanism before issuing another transaction. Calls on one
client are serialized because ceremony state uses a single cookie.

Custom endpoint paths can be supplied as `challenge_path=`, `proof_path=`, and
`logout_path=`. The client uses the Authority URL in the app's challenge, so it
needs no LocalAPI access or separate Authority discovery configuration. Its device
must satisfy the Authority's policy and have network access to the attestation port.

### Requests compatibility

Install `pip install "bytebind[requests]"` (or `pip install '.[requests]'` from a
checkout) to use the Requests backend without installing HTTPX:

```python
from bytebind.requests import Session

with Session("https://app.example.com") as api:
    response = api.get("/status", timeout=5)
    response.raise_for_status()
    print(response.json())

    result = api.transaction("/restart", json={"service": "demo"})
    result.raise_for_status()
    print(result.json())

    api.logout()
```

`Session` subclasses `requests.Session`. Its usual `get()`, `post()`, `put()`,
`patch()`, `delete()`, and `request()` calls acquire and renew a lease, and return
ordinary `requests.Response` objects. Session headers, cookies, auth, hooks, and
mounted adapters apply to the public application only. Private attestation uses
an independent session. Both backends share the cryptographic ceremony code.

`transaction()` prepares the request through Requests and hashes the exact
prepared target and body. It accepts JSON, buffered bytes or text, form data,
query parameters, and Requests' buffered multipart bodies. Streaming request
bodies are rejected. Calls on one session are serialized; calling `send()`
directly does not acquire or renew a lease. Ceremony/network failures raise
`bytebind.requests.ClientError`; application HTTP errors remain in the response.

Redirects stay disabled even when `allow_redirects=True` is supplied. TLS
verification cannot be disabled, environment proxies and netrc are ignored, and
HTTP adapters with retries enabled are rejected. Use `api.verify` with a CA
bundle path when the public application uses a custom CA; the private Authority
must have a certificate trusted by the separate attestation session. No operation
is automatically replayed after an error or lost response.

See [examples/client/api.py](examples/client/api.py) for a simple application
calling both profiles with Requests.

### Lower-level API

The lower-level API remains available:

```python
from bytebind.rp import AuthorityClient, RelyingParty

rp = RelyingParty(
    AuthorityClient("unix:/run/bytebind/control.sock"),   # or https://authority.tailnet.ts.net:9443
    origin="https://app.example.com",
    audience="manage",
    database="/var/lib/app/bytebind-rp.sqlite3",
)

challenge, state = rp.challenge(request.headers.get("origin"))  # Set `state` as an HttpOnly cookie
done = rp.accept_proof(origin, proof, state_cookie, old_token)   # Redeem the submitted proof
lease = rp.session(session_cookie)                              # None once the lease lapses
```

In the browser:

```js
const lease = await ByteBind.session("/bytebind/challenge", "/bytebind/proof");
const response = await ByteBind.transaction("/restart", { body: JSON.stringify({ service: "x" }) }, "/bytebind/proof");
```

[examples/rp_app.py](examples/rp_app.py) uses the binding for both profiles in a small FastAPI app.

## Tests

```bash
python -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/python -m pytest
```

The suite covers the published vectors (Python and, when Node is installed, the
browser client), every attest check in SPEC.md 11.1 with hostile inputs, both
control transports with real Unix-socket peer credentials, cross-RP isolation,
the state machine and its races, lease capping, and the complete exchange end to end.

## License

The implementation is MIT licensed. The specification and article are
copyright Bytes & Coffee Digital Studio. "ByteBind" is an open name. See [LICENSE](LICENSE).
