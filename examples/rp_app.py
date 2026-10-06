"""An example ByteBind relying party (FastAPI) showing both profiles through the binding.

* Session profile: ``@bind(require=[...])`` leases a session. An unauthenticated browser
  gets a sign-in page that completes the ceremony; the page then renews automatically.
* Transaction-bound profile: ``@bind(require=[...], grant=bind.TRANSACTION)`` binds one
  approval to one request. POST /restart answers 202 with a challenge and runs nothing;
  after the proof is redeemed, the handler runs exactly once and its result is the
  proof submission's response.

Run behind your public HTTPS origin, for example:

    BYTEBIND_ORIGIN=https://app.example.com \\
    BYTEBIND_AUDIENCE=manage \\
    BYTEBIND_RP_DB=/var/lib/app/bytebind-rp.sqlite3 \\
    uvicorn examples.rp_app:create_app --factory

The Authority is discovered on the tailnet; set BYTEBIND_AUTHORITY to override it.
"""

from __future__ import annotations

import html

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from bytebind.fastapi import ByteBind
from bytebind.rp import RelyingParty

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>ByteBind example</title></head><body>
<h1>ByteBind example</h1><p>Signed in from {device}.</p>
<button id="restart">Restart (transaction-bound)</button><p id="result" role="status"></p>
<script>
document.querySelector("#restart").addEventListener("click", async () => {{
  const result = document.querySelector("#result");
  try {{
    const response = await ByteBind.transaction("/restart", {{ body: JSON.stringify({{ service: "demo" }}) }}, "/bytebind/proof");
    result.textContent = `Response: ${{JSON.stringify(await response.json())}}`;
  }} catch (error) {{ result.textContent = `Not approved (${{error.message}})`; }}
}});
</script></body></html>"""


class Restart(BaseModel):
    service: str


def create_app(rp: RelyingParty | None = None) -> FastAPI:
    app = FastAPI()
    bind = ByteBind(app, rp=rp)
    restarts = {"count": 0}

    @app.get("/", response_class=HTMLResponse)
    @bind(require=["manage:read"])
    async def page(lease=bind.lease):
        # The binding adds the browser client and lease renewal to protected HTML.
        return PAGE.format(device=html.escape(lease.device_id or "an authorized device"))

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

    return app
