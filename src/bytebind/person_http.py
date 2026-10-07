"""Private, same-origin person listener. Never mount on the attestation listener."""

from __future__ import annotations

from importlib.resources import files
from html import escape
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from . import protocol as p
from .authority import open_store, verify_device
from .limits import PeerLimiter, read_capped
from .person import EnrollmentRateLimited, PersonService
from .store import TransactionError
from .tailscale import AttestationError, LocalAPI, authorize, identify


def create_person_app(config, directory=None, store=None):
    store = store or open_store(config)
    service = PersonService(config, store)
    directory = directory or LocalAPI(config.tailscale_socket)
    origin = config.person.origin
    host = urlsplit(origin).netloc
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    limiter = PeerLimiter(60)

    def headers(frame="'none'"):
        return {
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": f"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors {frame}; base-uri 'none'; form-action 'none'",
            "Cross-Origin-Opener-Policy": "same-origin",
            "X-Content-Type-Options": "nosniff",
        }

    @app.middleware("http")
    async def boundary(request, call_next):
        # No state/provider read before Host and, on POST, exact Origin/type.
        if request.headers.get("host") != host or (
            request.method == "POST"
            and (
                request.headers.get("origin") != origin
                or request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json"
            )
        ):
            return JSONResponse({"error": "person_failed"}, 403, headers=headers())
        response = await call_next(request)
        for key, value in headers().items():
            if key not in response.headers:
                response.headers[key] = value
        return response

    def page(mode, rp_id=""):
        application = '<p id="application">Application: ' + escape(config.rps[rp_id].origin) + "</p>" if rp_id else ""
        return (
            '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            '<title>ByteBind passkeys</title><link rel="stylesheet" href="/person.css"></head><body data-mode="'
            + mode
            + '" data-rp="'
            + escape(rp_id, quote=True)
            + '"><main><p class="brand">ByteBind</p><h1 id="heading">Passkeys</h1>'
            '<p id="intro">Loading…</p>'
            + application
            + '<div id="controls"></div><p id="status" role="status" aria-live="polite"></p>'
            '<noscript>Enable JavaScript to use passkeys.</noscript></main><script src="/person.js"></script></body></html>'
        )

    @app.get("/step-up/{rp_id}")
    def step_up_page(rp_id: str):
        rp = config.rps.get(rp_id)
        if rp is None:
            return Response(status_code=404, headers=headers())
        return HTMLResponse(page("stepup", rp_id), headers=headers(rp.origin))

    @app.get("/enroll")
    @app.get("/manage")
    def management_page(request: Request):
        return HTMLResponse(page("enroll" if request.url.path == "/enroll" else "manage"), headers=headers())

    @app.get("/person.js")
    def script():
        return Response(
            files("bytebind").joinpath("web", "person.js").read_text(),
            media_type="application/javascript",
            headers=headers(),
        )

    @app.get("/person.css")
    def stylesheet():
        return Response(
            files("bytebind").joinpath("web", "person.css").read_text(),
            media_type="text/css",
            headers=headers(),
        )

    @app.post("/{area}/{action}")
    async def ceremony(area: str, action: str, request: Request):
        peer = request.client.host if request.client else ""
        if not limiter.allow(peer):
            return JSONResponse({"error": "rate_limited"}, 429, headers=headers())
        raw = await read_capped(request, 32768)
        row = None
        try:
            if raw is None:
                raise ValueError()
            body = p.json_body(raw)
            token = request.headers.get("x-bytebind-attempt")
            if area == "step-up":
                if action == "handoff":
                    if set(body) != {"handoff", "rp_id"}:
                        raise ValueError()
                    row = store.handoff_record(body["handoff"])
                    verify_device(config, directory, peer, row)
                    if body["rp_id"] != row["rp_id"] or body["rp_id"] not in config.rps:
                        store.burn(row["cid"], row["status"], row["generation"])
                        raise ValueError()
                    result = service.assertion_options(row)
                else:
                    row = store.attempt_record(token)
                    verify_device(config, directory, peer, row)
                    if action == "options" and body == {}:
                        result = service.options(token)
                    elif action == "assertion" and set(body) == {"credential"}:
                        service.verify(token, body["credential"])
                        result = {"ok": True}
                    elif action == "abort" and body == {}:
                        store.burn(row["cid"], row["status"], row["generation"])
                        result = {"ok": True}
                    else:
                        raise ValueError()
            elif area in {"enroll", "manage"}:
                device = identify(directory, peer)
                authorize(device, config.person.enrollment_policy)
                if area == "manage" and action == "begin" and body == {}:
                    result = service.management_begin(device.peer_id)
                elif area == "manage" and action == "verify" and set(body) == {"credential"}:
                    result = service.management_complete(token, device.peer_id, body["credential"])
                elif area == "manage" and action in {"list", "revoke", "rename"}:
                    expected = {
                        "list": set(),
                        "revoke": {"credential_id"},
                        "rename": {"credential_id", "name"},
                    }[action]
                    if set(body) != expected:
                        raise ValueError()
                    result = service.manage(
                        token, device.peer_id, action, body.get("credential_id"), body.get("name")
                    )
                elif area == "enroll" and action == "begin" and set(body) in ({"invite"}, {"name"}, set()):
                    result = service.enrollment_begin(
                        device.peer_id,
                        invite=body.get("invite"),
                        self_name=body.get("name"),
                        management=token,
                    )
                elif area == "enroll" and action == "complete" and set(body) == {"credential", "name"}:
                    service.enrollment_complete(token, device.peer_id, body["credential"], body["name"])
                    result = {"ok": True}
                else:
                    raise ValueError()
            else:
                return Response(status_code=404)
            return JSONResponse(result, headers=headers())
        except EnrollmentRateLimited:
            return JSONResponse({"error": "rate_limited"}, 429, headers=headers())
        except (ValueError, TypeError, KeyError, p.ProtocolError, TransactionError, AttestationError):
            if row and row["status"] in {"base_attested", "stepup_pending"}:
                try:
                    if p.ip_bytes(peer) == row["attested_ip"]:
                        store.burn(row["cid"], row["status"], row["generation"])
                except ValueError:
                    pass
            return JSONResponse({"error": "person_failed"}, 403, headers=headers())
        except OSError:
            return JSONResponse({"error": "unavailable"}, 503, headers=headers())

    app.state.person_service = service
    return app
