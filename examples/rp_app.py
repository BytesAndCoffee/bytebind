"""An example ByteBind relying party (FastAPI) showing both profiles.

* Session profile: POST /bytebind/please, then POST /bytebind/affirm, then GET /status.
* Transaction-bound profile: POST /restart is the protected request itself (PLEASE);
  the server answers 202 with WHO, and the AFFIRM's response is the restart's result.

Run behind your public HTTPS origin, for example:

    BYTEBIND_AUTHORITY=unix:/run/bytebind/control.sock \
    BYTEBIND_ORIGIN=https://app.example.com \
    BYTEBIND_AUDIENCE=manage \
    BYTEBIND_RP_DB=/var/lib/app/bytebind-rp.sqlite3 \
    uvicorn examples.rp_app:create_app --factory
"""

from __future__ import annotations

import json
import os
from importlib.resources import files

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response

from bytebind.protocol import request_digest
from bytebind.rp import AuthorityClient, CeremonyError, RelyingParty

STATE_COOKIE, SESSION_COOKIE = "bytebind_state", "bytebind_session"
COVERED_HEADERS = ("content-type",)  # the headers Q covers for this app's protected requests

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>ByteBind example</title>
<script src="/bytebind.js"></script></head><body>
<h1>ByteBind example</h1><p id="status">Signing in&hellip;</p><button id="restart">Restart (transaction-bound)</button>
<script>
const status = document.querySelector("#status");
async function renew() {
  try { const lease = await ByteBind.session("/bytebind/please", "/bytebind/affirm");
        status.textContent = `Signed in from ${lease.device_id}; lease ends ${new Date(lease.expires_at * 1000).toLocaleTimeString()}`;
        setTimeout(renew, 60000);
  } catch (error) { status.textContent = `Not signed in (${error.message})`; }
}
document.querySelector("#restart").addEventListener("click", async () => {
  const response = await ByteBind.transaction("/restart", { body: JSON.stringify({ service: "demo" }) }, "/bytebind/affirm");
  status.textContent = `RESPONSE: ${JSON.stringify(await response.json())}`;
});
renew();
</script></body></html>"""


def create_app(rp: RelyingParty | None = None) -> FastAPI:
    rp = rp or RelyingParty(
        AuthorityClient(os.environ["BYTEBIND_AUTHORITY"]), origin=os.environ["BYTEBIND_ORIGIN"],
        audience=os.environ.get("BYTEBIND_AUDIENCE", "manage"), database=os.environ["BYTEBIND_RP_DB"],
    )
    app = FastAPI()
    restarts = {"count": 0}
    operations = {"restart": lambda body: (restarts.__setitem__("count", restarts["count"] + 1),
                                           {"restarted": body.get("service"), "count": restarts["count"]})[1]}

    def set_cookie(response: Response, name: str, value: str, max_age: int, path: str) -> None:
        response.set_cookie(name, value, max_age=max_age, path=path, secure=True, httponly=True, samesite="strict")

    def failed(status: int = 401) -> JSONResponse:
        return JSONResponse({"error": "ceremony_failed"}, status, headers={"Cache-Control": "no-store"})

    def who_response(who: dict, state: str, status: int = 200) -> JSONResponse:
        response = JSONResponse(who, status, headers={"Cache-Control": "no-store"})
        set_cookie(response, STATE_COOKIE, state, 60, "/bytebind/")
        return response

    @app.get("/", response_class=HTMLResponse)
    def page():
        return HTMLResponse(PAGE, headers={"X-Frame-Options": "DENY"})

    @app.get("/bytebind.js")
    def client_script():
        return FileResponse(str(files("bytebind").joinpath("web", "bytebind.js")), media_type="application/javascript")

    @app.post("/bytebind/please")
    def please(request: Request):
        try:
            who, state = rp.please(request.headers.get("origin"))
        except CeremonyError:
            return failed(403)
        return who_response(who, state)

    @app.post("/restart")
    async def restart_please(request: Request):
        """PLEASE for a transaction-bound operation: store it, bind it by Q, execute nothing yet."""
        body = await request.body()
        if len(body) > 4096:
            return failed(413)
        try:
            parsed = json.loads(body)
        except ValueError:
            return failed(400)
        target = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        headers = {name: request.headers.get(name, "") for name in COVERED_HEADERS}
        q = request_digest(request.method, target, headers, body)
        try:
            who, state = rp.please(request.headers.get("origin"), request={"operation": "restart", "body": parsed}, q=q)
        except CeremonyError:
            return failed(403)
        return who_response(who, state, 202)

    @app.post("/bytebind/affirm")
    async def affirm(request: Request):
        try:
            body = json.loads(await request.body())
            done = rp.affirm(request.headers.get("origin"), body, request.cookies.get(STATE_COOKIE), request.cookies.get(SESSION_COOKIE))
        except (CeremonyError, ValueError):
            return failed()
        if done.request is not None:  # transaction-bound: execute the stored request, once
            result = operations[done.request["operation"]](done.request["body"])
            response = JSONResponse(result, headers={"Cache-Control": "no-store"})
        else:
            response = JSONResponse({"device_id": done.lease.device_id, "expires_at": done.lease.expires_at},
                                    headers={"Cache-Control": "no-store"})
            set_cookie(response, SESSION_COOKIE, done.session_token, int(done.lease.expires_at - rp.now()) + 1, "/")
        response.delete_cookie(STATE_COOKIE, path="/bytebind/", secure=True, httponly=True, samesite="strict")
        return response

    @app.get("/status")
    def status(request: Request):
        lease = rp.session(request.cookies.get(SESSION_COOKIE))
        if lease is None:
            return failed()
        return JSONResponse({"device_id": lease.device_id, "authorization": lease.claims.get("authorization", []),
                             "expires_at": lease.expires_at}, headers={"Cache-Control": "no-store"})

    @app.post("/bytebind/logout")
    def logout(request: Request):
        rp.end_session(request.cookies.get(SESSION_COOKIE))
        response = Response(status_code=204)
        response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="strict")
        return response

    return app
