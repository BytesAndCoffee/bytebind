# ByteBind

ByteBind binds a public HTTPS session to the live presence of an authorized
device on a private overlay network. A public application can keep its
management UI on its normal origin, yet grant privileged access only while the
operator's browser is running on a device that is on the private network,
identified by it, and authorized by it, right now. No passwords, no prompts.

- **[SPEC.md](SPEC.md):** the protocol, draft 0.6.
- **[docs/blog-post.md](docs/blog-post.md):** why it exists, in plain language.
- **[test-vectors/bytebind-v1.json](test-vectors/bytebind-v1.json):** byte-exact vectors for both profiles.

This repository is the reference implementation, in Python with a dependency-free
browser client. It targets draft 0.6 and uses Tailscale as the attestation provider.

> **Status:** draft protocol, unreviewed implementation. Do not rely on it to
> protect anything important until it has had an independent security review.

## The ceremony

```text
Client              Server              Provider (Authority)
  |------ PLEASE ---->|                    |
  |                   |------ BEGIN ------>|
  |                   |<------- TRY -------|
  |<------- WHO ------|                    |
  |---------------- PROVE ---------------->|   over the private network
  |<--------------- ATTEST ----------------|
  |------ AFFIRM ---->|                    |
  |                   |----- REDEEM ------>|
  |                   |<------ GRANT ------|
  |<----- RESPONSE ---|                    |
```

Two profiles share it: the **session profile** mints a short lease that the page
renews silently, and the **transaction-bound profile** wraps one exact request
(bound by its digest `Q`) and executes it at most once.

## Layout

| Path | What it is |
|---|---|
| `src/bytebind/protocol.py` | Encoding, `Q`, and the H1, H2, and R transcripts for both profiles |
| `src/bytebind/store.py` | The Authority's transaction store: single-use, conditional state transitions |
| `src/bytebind/tailscale.py` | The Tailscale attestation provider (LocalAPI `status` and `whois`) and policy |
| `src/bytebind/authority.py` | The Authority: attest service, and the control channel over a Unix socket or tailnet HTTPS |
| `src/bytebind/config.py` | Authority configuration (TOML), validated at startup |
| `src/bytebind/rp.py` | Relying-party side: `AuthorityClient` and `RelyingParty` (state cookies, leases, stored requests) |
| `src/bytebind/web/bytebind.js` | The browser client (WebCrypto only) |
| `examples/` | An example relying party (FastAPI) and Authority configuration |
| `scripts/make_vectors.py` | Regenerates the test vectors |

## Running an Authority

The Authority runs as up to three narrowly scoped listeners, all from one config
file (see [examples/authority.toml](examples/authority.toml)):

```bash
pip install .

# Browser-facing PROVE/ATTEST: bound to this node's tailnet IP, TLS with a
# `tailscale cert` certificate, never behind a proxy.
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

```python
from bytebind.rp import AuthorityClient, RelyingParty

rp = RelyingParty(
    AuthorityClient("unix:/run/bytebind/control.sock"),   # or https://authority.tailnet.ts.net:9443
    origin="https://app.example.com",
    audience="manage",
    database="/var/lib/app/bytebind-rp.sqlite3",
)

who, state = rp.please(request.headers.get("origin"))          # PLEASE -> WHO; set `state` as an HttpOnly cookie
done = rp.affirm(origin, affirm_body, state_cookie, old_token)  # AFFIRM -> REDEEM -> GRANT
lease = rp.session(session_cookie)                              # None once the lease lapses
```

In the browser:

```js
const lease = await ByteBind.session("/bytebind/please", "/bytebind/affirm");
const response = await ByteBind.transaction("/restart", { body: JSON.stringify({ service: "x" }) }, "/bytebind/affirm");
```

[examples/rp_app.py](examples/rp_app.py) wires both profiles into a small FastAPI app.

## Tests

```bash
python -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/python -m pytest
```

The suite covers the published vectors (Python and, when Node is installed, the
browser client), every attest check in SPEC.md 11.1 with hostile inputs, both
control transports with real Unix-socket peer credentials, cross-RP isolation,
the state machine and its races, lease capping, and all ten messages end to end.

## License

The implementation is MIT licensed. The specification and article are
copyright Bytes & Coffee Digital Studio. "ByteBind" is an open name. See [LICENSE](LICENSE).
