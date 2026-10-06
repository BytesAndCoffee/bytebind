# ByteBind demo behind nginx

A public welcome page, an admin page requiring `tag:admin`, and a protected
“Check access” button. The app uses real ByteBind ceremonies and Authority
autodiscovery. It contains no simulated sign-in or privileged system operations.

## Start the app

On the nginx host, from a checkout of this repository:

```bash
python3 -m venv .venv
.venv/bin/pip install .
export BYTEBIND_ORIGIN=https://demo.example.com
export BYTEBIND_AUDIENCE=manage
export BYTEBIND_RP_DB="$PWD/demo-state/rp.sqlite3"
.venv/bin/bytebind-demo
```

Replace the origin with your public HTTPS site, without a trailing slash. The
state directory is created automatically. The app listens on `127.0.0.1:8000`;
use `--port 8001` to change it and update nginx's upstream to match. The installed
package includes the demo; running `python -m bytebind.demo` works too.

The home page and `/healthz` work before an Authority is available. Protected
routes require a real ceremony. Browse the HTTPS nginx URL, not the loopback HTTP
URL: the session cookies are Secure and the browser client needs WebCrypto.

## Wire into nginx

For a dedicated hostname, edit [nginx.conf](nginx.conf): replace
`demo.example.com` and the certificate paths with your existing hostname and
certificate. Point that hostname's DNS at nginx. On a Debian/Ubuntu-style host:

```bash
sudo cp examples/demo/nginx.conf /etc/nginx/conf.d/bytebind-demo.conf
sudo nginx -t
sudo systemctl reload nginx
```

Edit the copied config before running `nginx -t`. Obtain a valid certificate
through your usual ACME setup before enabling this HTTPS server block.

For an **existing HTTPS virtual host**, add only its `location /` proxy block,
or replace the existing root location. This demo expects its own hostname at
`/`; it is not configured for a path prefix. If using a nonstandard HTTPS port,
include that port in `BYTEBIND_ORIGIN` and the Authority's registered origin.

The config forwards Host and HTTPS scheme, disables proxy caching, and preserves
401 responses so ByteBind's sign-in page reaches the browser. The launcher trusts
forwarded headers only from `127.0.0.1`. See the official
[nginx proxy reference](https://nginx.org/en/docs/http/ngx_http_proxy_module.html).
Do not add a restrictive script CSP without adapting the adapter's inline script
injection.

## Connect the Authority

Both the demo host and your browser device must be on the tailnet. The demo needs
access to tailscaled's LocalAPI; set `BYTEBIND_TAILSCALE_SOCKET` if its socket is
not `/var/run/tailscale/tailscaled.sock`. The service account needs permission to
read status through that socket.

Tag the Authority node `tag:bytebind-authority`. Discovery uses its MagicDNS
name and HTTPS control port 9443. You can advertise a custom port and audience
through the `bytes.coffee/bytebind/authority` node capability; see the main
[README](../../README.md). A local `/run/bytebind/control.sock` takes precedence
when present. Set `BYTEBIND_AUTHORITY` if you want an explicit override.

Register the demo on the Authority by adding this RP entry to its TOML config:

```toml
[[rp]]
id = "bytebind-demo"
origin = "https://demo.example.com"
audiences = ["manage"]
tailnet_node = "REPLACE_WITH_DEMO_HOST_STABLE_NODE_ID"
grant_ttl = 180
claims = ["device_id", "tags"]
authorization = []

[rp.policy]
tags = ["tag:admin"]
tag_match = "all"
```

Use the demo host's stable node ID (`Self.ID` in `tailscale status --json`),
not its hostname, IP address, or node public key. For a same-host Unix control
listener, replace `tailnet_node` with `unix_uid` set to the demo process's numeric
UID. Restart the Authority listeners after changing their registration config.

Your browser's device must carry `tag:admin`; the Authority must include `tags`
in its grant claims, as shown. Merge the following into your existing tailnet
policy, assigning the three tags to the appropriate nodes:

```json
{
  "tagOwners": {
    "tag:bytebind-authority": ["autogroup:admin"],
    "tag:bytebind-demo": ["autogroup:admin"],
    "tag:admin": ["autogroup:admin"]
  },
  "grants": [
    {"src": ["tag:bytebind-demo"], "dst": ["tag:bytebind-authority"], "ip": ["tcp:9443"]},
    {"src": ["tag:admin"], "dst": ["tag:bytebind-authority"], "ip": ["tcp:8443"]}
  ]
}
```

The Authority's HTTPS control listener must run on port 9443 with a valid
certificate for its MagicDNS hostname; the browser attestation listener runs on
8443 in this example. Its `attest_url` must use that reachable private HTTPS URL.
Neither Authority listener goes through the demo's public nginx virtual host.
See [examples/authority.toml](../authority.toml) and the main README for listener
commands. Browser public-to-private access may require permission; availability
varies by browser and is still a live deployment testing item for this project.

## Optional systemd service

Assuming the checkout and installed virtualenv are at `/opt/bytebind`:

```bash
sudo useradd --system --home /var/lib/bytebind-demo --shell /usr/sbin/nologin bytebind-demo
sudo cp examples/demo/demo.env /etc/bytebind-demo.env
sudo cp examples/demo/bytebind-demo.service /etc/systemd/system/
```

Edit `/etc/bytebind-demo.env` to use your real public origin. Check that the
service account can read the checkout, execute its virtualenv, and access the
LocalAPI. Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now bytebind-demo
sudo journalctl -u bytebind-demo -n 30 --no-pager
```

The service creates `/var/lib/bytebind-demo` for its SQLite state. If running an
Authority on the same host, register this account's UID rather than your shell
account's UID. To use another install path, edit `WorkingDirectory` and
`ExecStart` in the unit.

## Check it

```bash
curl https://demo.example.com/healthz
# {"status":"ok"} — process health only, not Authority readiness
curl -i https://demo.example.com/admin
# 401 without a lease
curl -i -H 'Accept: text/html' https://demo.example.com/admin
# 401 with the browser sign-in page
```

Open `/admin` in a browser on the authorized device. The page completes a private
ceremony, reloads, and shows the device identity. “Check access” performs another
server-side lease and tag check. After disconnecting from the tailnet, renewal
stops; the last accepted lease remains usable until its server-side expiry.

A 503 from `/bytebind/please` usually means discovery failed or the control
listener is unavailable: check LocalAPI access, the role tag/capability, audience,
matching node count, and control HTTPS connectivity. A 403 during the ceremony
can indicate an origin, RP registration, or device policy mismatch. A 403 on an
already leased route means its required claims are missing. Internal errors are
not exposed to browser clients.
