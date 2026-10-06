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


def create_app(rp: RelyingParty | None = None) -> FastAPI:
    origin = rp.origin if rp else os.getenv("BYTEBIND_ORIGIN", "")
    parsed = urlsplit(origin)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment):
        raise ValueError("Set BYTEBIND_ORIGIN to the public HTTPS origin, e.g. https://demo.example.com (no trailing slash)")
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
                    '<a class="button" href="/admin">Open admin</a></div>')

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
