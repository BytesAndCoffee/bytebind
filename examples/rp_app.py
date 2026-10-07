"""An example ByteBind relying party (FastAPI) showing both profiles through the binding.

* Session profile: ``@bind(require=[...])`` leases a session. An unauthenticated browser
  gets a sign-in page that completes the ceremony; the page then renews automatically.
* Transaction-bound profile: ``@bind(require=[...], grant=bind.TRANSACTION)`` binds one
  approval to one request. POST /restart answers 202 with a challenge and runs nothing;
  after the proof is redeemed, the handler runs exactly once and its result is the
  proof submission's response.
* Person step-up: GET /verified requires a verified passkey plus a device lease;
  POST /restart-verified requires a fresh verified assertion for that exact request.
* Registration: GET /passkeys links to the private Authority's enrollment and
  management pages. Invites and credentials stay on the Authority.

Run behind your public HTTPS origin, for example:

    BYTEBIND_ORIGIN=https://app.example.com \\
    BYTEBIND_AUDIENCE=manage \\
    BYTEBIND_RP_DB=/var/lib/app/bytebind-rp.sqlite3 \\
    BYTEBIND_PERSON_ORIGIN=https://authority.example-tailnet.ts.net:8444 \\
    uvicorn examples.rp_app:create_app --factory

The Authority is discovered on the tailnet; set BYTEBIND_AUTHORITY to override it.
Use examples/authority.toml, install bytebind[person] on the Authority, and start
its separate private person listener on 8444. Enrollment devices need the
tag:bytebind-enrollment tag; ordinary access needs the registered device policy.
Issue a new-person invite as the Authority operator:

    bytebind-authority --config authority.toml invite --name "Example participant"

Open /passkeys, register on the Authority, then return to /verified. Existing
/status and /restart remain device-only for the headless Python client example.
See docs/PERSON-STEP-UP.md for listener commands and the browser acceptance gates.
"""

from __future__ import annotations

import html
import os

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from bytebind.fastapi import ByteBind
from bytebind.config import exact_https_origin
from bytebind.rp import RelyingParty

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>ByteBind example</title></head><body>
<h1>ByteBind example</h1><p>Signed in from {device}.</p>
<p>{person}</p>
<p><a href="/passkeys">Register or manage passkeys</a> · <a href="/verified">Try passkey step-up</a> · <a href="/">Device-only page</a></p>
<button id="restart">{button_label}</button><p id="result" role="status" aria-live="polite"></p>
<script>
document.querySelector("#restart").addEventListener("click", async () => {{
  const result = document.querySelector("#result");
  const button = document.querySelector("#restart"); button.disabled = true;
  try {{
    const response = await ByteBind.transaction("{operation}", {{ body: JSON.stringify({{ service: "demo" }}) }}, "/bytebind/proof");
    if (!response.ok) throw new Error("Request refused. Start a new attempt.");
    result.textContent = `Response: ${{JSON.stringify(await response.json())}}`;
  }} catch (error) {{ result.textContent = `Not approved (${{error.message}})`; }}
  finally {{ button.disabled = false; }}
}});
</script></body></html>"""


class Restart(BaseModel):
    service: str


def create_app(rp: RelyingParty | None = None, *, person_origin: str | None = None) -> FastAPI:
    person_origin = person_origin if person_origin is not None else os.getenv("BYTEBIND_PERSON_ORIGIN", "")
    app_origin = rp.origin if rp else os.getenv("BYTEBIND_ORIGIN", "")
    if person_origin and (not exact_https_origin(person_origin) or person_origin == app_origin):
        raise ValueError("BYTEBIND_PERSON_ORIGIN must be the separate private Authority HTTPS origin")
    app = FastAPI()
    bind = ByteBind(app, rp=rp)
    restarts = {"count": 0}

    @app.get("/passkeys", response_class=HTMLResponse)
    async def passkeys():
        # Public setup page: an RP never collects enrollment invites or passkeys.
        if not person_origin:
            return '<h1>Passkey setup</h1><p>Set BYTEBIND_PERSON_ORIGIN to the Authority person listener.</p><a href="/">Back</a>'
        private = html.escape(person_origin, quote=True)
        return (
            '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Register a passkey</title></head><body>'
            "<h1>Register an Authority passkey</h1><p>Ask your operator for a one-use enrollment invite. "
            "On an enrollment-authorized device, open the Authority page, paste your invite, "
            "choose Continue, then Create passkey. Naming the passkey is optional.</p>"
            f'<p><a href="{private}/enroll" target="_blank" rel="noopener noreferrer">Register passkey</a></p>'
            f'<p><a href="{private}/manage" target="_blank" rel="noopener noreferrer">Manage passkeys</a></p>'
            "<p>Return here after registration. Your person identity is independent of the device’s owner.</p>"
            '<a href="/verified">Try passkey step-up</a></body></html>'
        )

    @app.get("/", response_class=HTMLResponse)
    @bind(require=["manage:read"])
    async def page(lease=bind.lease):
        # The binding adds the browser client and lease renewal to protected HTML.
        return PAGE.format(
            device=html.escape(lease.device_id or "an authorized device"),
            person="This page requires device participation.",
            operation="/restart",
            button_label="Restart (device transaction)",
        )

    @app.get("/verified", response_class=HTMLResponse)
    @bind(require=["manage:read"], assurance="verification", person_max_age=300, identify=True)
    async def verified(lease=bind.lease):
        person = html.escape(lease.claims["person_subject"])
        return PAGE.format(
            device=html.escape(lease.device_id or "an authorized device"),
            person=f"Person verified for this app: <code>{person}</code>. "
            "Device renewal preserves the original verification age. "
            "The restart below requires another fresh passkey assertion.",
            operation="/restart-verified",
            button_label="Restart with fresh passkey verification",
        )

    @app.get("/status")
    @bind(require=["manage:read"])
    async def status(lease=bind.lease):
        # No expiry for the Client (SPEC.md 15.2): the lease's deadline stays server-side.
        return {"device_id": lease.device_id, "authorization": lease.claims.get("authorization", [])}

    @app.post("/restart")
    @bind(require=["manage:read"], grant=bind.TRANSACTION)
    async def restart(request: Restart, grant=bind.grant):
        # Runs only after a device approved this exact request: method, target, and body.
        restarts["count"] += 1
        return {"restarted": request.service, "count": restarts["count"], "approved_by": grant.device_id}

    @app.post("/restart-verified")
    @bind(require=["manage:read"], grant=bind.TRANSACTION, assurance="verification")
    async def restart_verified(request: Restart, grant=bind.grant):
        # A simulated restart, executed once after a fresh person assertion.
        restarts["count"] += 1
        return {
            "restarted": request.service,
            "count": restarts["count"],
            "approved_by": grant.device_id,
            "assurance": grant.assurance,
        }

    return app
