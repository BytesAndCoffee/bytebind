"""A small ByteBind app for an HTTPS nginx reverse proxy."""
from __future__ import annotations

import argparse
import html
import os
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .fastapi import ByteBind
from .config import exact_https_origin
from .rp import RelyingParty

STYLE = """
:root { color-scheme: dark; font-family: system-ui, sans-serif; background: #171511; color: #f4eee4; }
body { max-width: 44rem; margin: 10vh auto; padding: 1.5rem; line-height: 1.6; }
h1 { font-size: clamp(2.5rem, 6vw, 4rem); line-height: 1.1; }
a { color: #ed8c49; } .eyebrow { color: #ed8c49; letter-spacing: .12em; text-transform: uppercase; }
.panel { padding: 1.5rem; border: 1px solid #554536; border-radius: .75rem; margin: 2rem 0; }
button, .button { display: inline-block; border: 0; border-radius: .4rem; background: #b85618;
color: white; padding: .8rem 1.2rem; font: inherit; cursor: pointer; text-decoration: none; }
button:disabled { opacity: .6; } pre { white-space: pre-wrap; overflow-wrap: anywhere; }
"""


def page(title: str, body: str) -> HTMLResponse:
    return HTMLResponse(f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
                        f'<meta name="viewport" content="width=device-width, initial-scale=1">'
                        f'<title>{html.escape(title)} · ByteBind</title><style>{STYLE}</style></head>'
                        f'<body><p class="eyebrow">ByteBind demo</p>{body}</body></html>',
                        headers={"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff"})


def create_app(rp: RelyingParty | None = None, *, person_origin: str | None = None) -> FastAPI:
    origin = rp.origin if rp else os.getenv("BYTEBIND_ORIGIN", "")
    parsed = urlsplit(origin)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment):
        raise ValueError("Set BYTEBIND_ORIGIN to the public HTTPS origin, e.g. https://demo.example.com (no trailing slash)")
    person_origin = person_origin if person_origin is not None else os.getenv("BYTEBIND_PERSON_ORIGIN", "")
    if person_origin and (not exact_https_origin(person_origin) or person_origin == origin):
        raise ValueError("Set BYTEBIND_PERSON_ORIGIN to the separate Authority person HTTPS origin")
    if rp is None:
        database = Path(os.getenv("BYTEBIND_RP_DB", "bytebind-rp.sqlite3")).expanduser()
        database.parent.mkdir(parents=True, exist_ok=True)
    app = FastAPI(title="ByteBind demo", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=[parsed.hostname], www_redirect=False)
    bind = ByteBind(app, rp=rp, origin=origin, database=str(database) if rp is None else None)
    if rp is None:
        # Open the state store at startup; Authority discovery remains lazy.
        bind.rp = RelyingParty(bind._authority_client, origin=origin,
                              audience=bind.audience, database=bind.database)

    @app.get("/healthz")
    def health():
        return {"status": "ok"}

    @app.get("/", response_class=HTMLResponse)
    def home():
        return page("Welcome", '<h1>A public page.<br>A private door.</h1>'
                    '<p>Anyone can view this page. The admin page requires an authorized device '
                    'on the private network.</p><div class="panel"><h2>Try it</h2>'
                    '<p>Connect your device to the private network, then open the admin page.</p>'
                    '<a class="button" href="/admin">Open admin</a></div>'
                    '<div class="panel"><h2>Device + person</h2>'
                    '<p>Register an Authority passkey, then try a page and an approval that require person verification.</p>'
                    '<p><a href="/passkeys">Register or manage passkeys</a></p>'
                    '<a class="button" href="/verified">Try passkey step-up</a></div>')

    @app.get("/passkeys", response_class=HTMLResponse)
    def passkeys():
        if not person_origin:
            return page("Passkeys", '<h1>Passkey setup</h1><p>The operator needs to configure the '
                        'Authority person listener and BYTEBIND_PERSON_ORIGIN before registration is available.</p>'
                        '<a href="/">Back to home</a>')
        private = html.escape(person_origin, quote=True)
        return page("Passkeys", '<h1>Your Authority passkey</h1>'
                    '<p>Ask your operator for a one-use enrollment invite. On a device allowed to enroll, '
                    'open the Authority registration page, enter the invite, and create your passkey.</p>'
                    '<p>Your passkey belongs to your person subject, independently of the device’s owner.</p>'
                    '<div class="panel">'
                    f'<p><a class="button" href="{private}/enroll" target="_blank" rel="noopener noreferrer">Register passkey</a></p>'
                    f'<p><a href="{private}/manage" target="_blank" rel="noopener noreferrer">Manage existing passkeys</a></p>'
                    '</div><p>Registration and management happen on the private Authority. '
                    'Return here after registration.</p>'
                    '<p><a class="button" href="/verified">Try passkey step-up</a></p><a href="/">Back to home</a>')

    @app.get("/verified", response_class=HTMLResponse)
    @bind(require=["tag:admin"], assurance="verification", person_max_age=300, identify=True)
    async def verified(lease=bind.lease):
        person = html.escape(lease.claims["person_subject"])
        return page("Person verified", '<h1>Device + person verified.</h1>'
                    '<p>Your device has admin access and your passkey verified the person using it.</p>'
                    f'<div class="panel"><h2>Your identity for this app</h2><pre>{person}</pre>'
                    '<p>Device renewal preserves this verification’s original age. The Authority validates '
                    'it again on every visit to this page.</p></div>'
                    '<div class="panel"><h2>Approve once</h2>'
                    '<p>This demonstration approval requires a fresh passkey assertion for this exact request.</p>'
                    '<button id="approve">Approve with passkey</button>'
                    '<pre id="approval-result" role="status" aria-live="polite">Ready.</pre></div>'
                    '<p><a href="/passkeys">Passkey registration and management</a></p><a href="/">Back to home</a>'
                    '<script>document.getElementById("approve").addEventListener("click",async()=>{'
                    'const button=document.getElementById("approve"),result=document.getElementById("approval-result");'
                    'button.disabled=true;try{'
                    'const response=await ByteBind.transaction("/api/person/approve",'
                    '{method:"POST",body:"{}",contentType:"application/json"},"/bytebind/proof");'
                    'if(!response.ok)throw new Error("Approval failed. Start a new attempt.");'
                    'result.textContent=(await response.json()).message;'
                    '}catch(error){result.textContent="Approval failed. Start a new attempt.";}'
                    'finally{button.disabled=false;}});</script>')

    @app.post("/api/person/approve")
    @bind(require=["tag:admin"], grant=bind.TRANSACTION, assurance="verification")
    async def approve(grant=bind.grant):
        return {"ok": True, "message": "This request was approved with a fresh verified passkey.",
                "assurance": grant.assurance}

    @app.get("/admin", response_class=HTMLResponse)
    @bind(require=["tag:admin"], grant=bind.LEASE)
    async def admin(lease=bind.lease):
        device = html.escape(lease.device_id or "Authorized device")
        return page("Admin", '<h1>You’re in.</h1><p>Your device has admin access.</p>'
                    f'<div class="panel"><h2>Connected device</h2><p>{device}</p>'
                    '<button id="check">Check access</button><pre id="result" role="status" '
                    'aria-live="polite">Ready.</pre></div><a href="/">Back to home</a>'
                    '<script>document.getElementById("check").addEventListener("click", async () => {'
                    'const button=document.getElementById("check");const result=document.getElementById("result");'
                    'button.disabled=true;try{const response=await fetch("/api/admin/check",{method:"POST"});'
                    'if(!response.ok)throw new Error(response.status===401?"Access expired. Reconnect and reload.":"Access denied.");'
                    'const data=await response.json();result.textContent="Access confirmed for "+data.device_id;'
                    '}catch(error){result.textContent=error.message;}finally{button.disabled=false;}});</script>')

    @app.post("/api/admin/check")
    @bind(require=["tag:admin"], grant=bind.LEASE)
    async def check(lease=bind.lease):
        return {"ok": True, "device_id": lease.device_id}

    return app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the ByteBind demo behind an HTTPS nginx proxy.")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    import uvicorn

    # Only a local reverse proxy may supply forwarded headers.
    uvicorn.run(create_app(), host="127.0.0.1", port=args.port,
                proxy_headers=True, forwarded_allow_ips="127.0.0.1", server_header=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
