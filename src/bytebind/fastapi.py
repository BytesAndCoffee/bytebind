"""FastAPI session-profile integration for ByteBind."""
from __future__ import annotations

import inspect
import os
from functools import wraps
from importlib.resources import files

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from .discovery import AUTHORITY_TAG, AUTHORITY_CAPABILITY, DiscoveringAuthorityClient
from .limits import PeerLimiter
from .tailscale import Directory
from .rp import AuthorityClient, AuthorityError, CeremonyError, Lease, RelyingParty

STATE_COOKIE = "bytebind_state"
SESSION_COOKIE = "bytebind_session"
MAX_CACHED_ORIGINS = 32


class ByteBind:
    """Mount ByteBind and protect routes with ``@bind(require=[...], grant=bind.LEASE)``.

    Configuration comes from BYTEBIND_AUTHORITY, BYTEBIND_ORIGIN,
    BYTEBIND_AUDIENCE and BYTEBIND_RP_DB, or explicit keyword arguments.
    The Authority is discovered from tailnet role tags or node capabilities.
    A local /run/bytebind/control.sock listener takes precedence. Without a configured
    origin the application's request URL supplies it; deploy behind trusted host
    and proxy configuration. An existing RelyingParty can be passed as ``rp``.

    ``please_per_minute`` limits ceremony starts per client address. PLEASE is
    unauthenticated and each one holds a pending slot at the Authority, so
    without a limit any client could fill the Authority's per-RP quota.
    """

    LEASE = "session"

    def __init__(self, app: FastAPI, *, rp: RelyingParty | None = None,
                 authority: str | None = None, origin: str | None = None,
                 audience: str | None = None, database: str | None = None,
                 directory: Directory | None = None, tailscale_socket: str | None = None,
                 authority_tag: str = AUTHORITY_TAG,
                 authority_capability: str = AUTHORITY_CAPABILITY,
                 authority_port: int = 9443, please_per_minute: int = 30):
        self.rp = rp
        self._rps: dict[str, RelyingParty] = {}
        self._please_limiter = PeerLimiter(please_per_minute)
        self.authority = authority or os.getenv("BYTEBIND_AUTHORITY")
        self._authority_client = (AuthorityClient(self.authority) if self.authority else
                                  DiscoveringAuthorityClient(directory,
                                      socket_path=tailscale_socket or os.getenv("BYTEBIND_TAILSCALE_SOCKET", "/var/run/tailscale/tailscaled.sock"),
                                      tag=authority_tag, capability=authority_capability, port=authority_port))
        self.origin = origin or os.getenv("BYTEBIND_ORIGIN")
        self.audience = audience or os.getenv("BYTEBIND_AUDIENCE", "manage")
        self.database = database or os.getenv("BYTEBIND_RP_DB", "bytebind-rp.sqlite3")
        def current_lease(request: Request) -> Lease:
            request.state.bytebind_protected = True
            lease = self._rp(request).session(request.cookies.get(SESSION_COOKIE))
            if lease is None:
                raise HTTPException(401, "ByteBind lease required", headers={"X-ByteBind-Required": "1"})
            return lease
        self.lease = Depends(current_lease)
        app.state.bytebind = self

        @app.get("/bytebind/client.js", include_in_schema=False)
        def client():
            return Response(files("bytebind").joinpath("web", "bytebind.js").read_text(),
                            media_type="application/javascript")

        @app.post("/bytebind/please", include_in_schema=False)
        def please(request: Request):
            if not self._please_limiter.allow(request.client.host if request.client else ""):
                return JSONResponse({"error": "rate_limited"}, status_code=429,
                                    headers={"Cache-Control": "no-store", "Retry-After": "60"})
            try:
                who, state = self._rp(request).please(request.headers.get("origin"))
            except CeremonyError:
                return self._failed(403)
            except (AuthorityError, OSError):
                return self._failed(503)
            response = JSONResponse(who, headers={"Cache-Control": "no-store"})
            self._cookie(response, STATE_COOKIE, state, "/bytebind/", 60)
            return response

        @app.post("/bytebind/affirm", include_in_schema=False)
        async def affirm(request: Request):
            try:
                body = await request.json()
                done = await run_in_threadpool(self._rp(request).affirm, request.headers.get("origin"),
                                              body, request.cookies.get(STATE_COOKIE),
                                              request.cookies.get(SESSION_COOKIE))
            except (CeremonyError, ValueError):
                return self._failed(401)
            except (AuthorityError, OSError):
                return self._failed(503)
            response = JSONResponse({"device_id": done.lease.device_id}, headers={"Cache-Control": "no-store"})
            self._cookie(response, SESSION_COOKIE, done.session_token, "/")
            response.delete_cookie(STATE_COOKIE, path="/bytebind/", secure=True, httponly=True, samesite="strict")
            return response

        @app.post("/bytebind/logout", include_in_schema=False)
        def logout(request: Request):
            try:
                self._rp(request).check_origin(request.headers.get("origin"))
            except CeremonyError:
                return self._failed(403)
            self._rp(request).end_session(request.cookies.get(SESSION_COOKIE))
            response = Response(status_code=204, headers={"Cache-Control": "no-store"})
            response.delete_cookie(SESSION_COOKIE, secure=True, httponly=True, samesite="strict")
            return response

        @app.middleware("http")
        async def browser_client(request: Request, call_next):
            response = await call_next(request)
            protected = getattr(request.state, "bytebind_protected", False)
            if protected:
                response.headers["Cache-Control"] = "no-store"
            if response.headers.get("X-ByteBind-Required") and "text/html" in request.headers.get("accept", "") and request.method == "GET":
                return HTMLResponse('<!doctype html><title>ByteBind</title><p id="bytebind-status">Connecting…</p>' + self._script(True),
                                    status_code=401, headers={"Cache-Control": "no-store"})
            # Renewal runs only on protected pages: public pages must not start ceremonies
            # or make visitors' browsers contact the private Authority.
            if protected and "text/html" in response.headers.get("content-type", "") and not response.headers.get("content-encoding"):
                body = b"".join([chunk async for chunk in response.body_iterator])
                script = self._script(False).encode()
                index = body.lower().rfind(b"</body>")
                body = body[:index] + script + body[index:] if index >= 0 else body + script
                result = Response(body, status_code=response.status_code, background=response.background)
                result.raw_headers = [(key, value) for key, value in response.raw_headers
                                      if key.lower() not in (b"content-length", b"cache-control")]
                result.headers["content-length"] = str(len(body))
                result.headers["cache-control"] = "no-store"
                return result
            if response.headers.get("X-ByteBind-Required"):
                response.headers["Cache-Control"] = "no-store"
            return response

    def _rp(self, request: Request) -> RelyingParty:
        if self.rp is not None:
            return self.rp
        # Never pin an origin from the first incoming request: cache one RP per origin.
        origin = self.origin or str(request.base_url).rstrip("/")
        rp = self._rps.get(origin)
        if rp is None:
            rp = RelyingParty(self._authority_client, origin=origin, audience=self.audience, database=self.database)
            if len(self._rps) < MAX_CACHED_ORIGINS:
                self._rps[origin] = rp
        return rp

    @staticmethod
    def _cookie(response, name, value, path, max_age=None):
        response.set_cookie(name, value, path=path, max_age=max_age, secure=True, httponly=True, samesite="strict")

    @staticmethod
    def _failed(status):
        return JSONResponse({"error": "ceremony_failed"}, status_code=status, headers={"Cache-Control": "no-store"})

    @staticmethod
    def _script(reload):
        # Renewal keeps its fixed interval after a failure (SPEC.md 15.1): a failed renewal
        # leaves the lease to its stored deadline, and the next one can still succeed.
        if reload:
            done, failed = "location.reload();", ""
        else:
            done = failed = "setTimeout(renew,ByteBind.RENEW_INTERVAL_MS);"
        return ('<script src="/bytebind/client.js"></script><script>'
                'async function renew(){try{await ByteBind.session("/bytebind/please","/bytebind/affirm");'
                + done + '}catch(e){' + failed + 'const s=document.getElementById("bytebind-status");'
                'if(s)s.textContent="Private network access required";}}renew();</script>')

    def __call__(self, *, require=(), grant=LEASE):
        if grant != self.LEASE:
            raise ValueError("FastAPI integration currently supports only bind.LEASE")
        if isinstance(require, str) or not all(isinstance(item, str) and item for item in require):
            raise ValueError("require must be a sequence of nonempty claim strings")
        required = frozenset(require)

        def authorize(request: Request, response: Response, lease: Lease = self.lease):
            response.headers["Cache-Control"] = "no-store"
            if request.method not in {"GET", "HEAD", "OPTIONS"}:
                try:
                    self._rp(request).check_origin(request.headers.get("origin"))
                except CeremonyError:
                    raise HTTPException(403, "Origin is not this RP's origin") from None
            tags = set(lease.claims.get("tags", []))
            authorization = set(lease.claims.get("authorization", []))
            if not all(item in (tags if item.startswith("tag:") else authorization) for item in required):
                raise HTTPException(403, "ByteBind requirements not met")

        def decorate(endpoint):
            signature = inspect.signature(endpoint, eval_str=True)
            name = "_bytebind_authorization"
            while name in signature.parameters:
                name += "_"
            parameters = list(signature.parameters.values())
            dependency = inspect.Parameter(name, inspect.Parameter.KEYWORD_ONLY, default=Depends(authorize))
            index = next((i for i, p in enumerate(parameters) if p.kind == inspect.Parameter.VAR_KEYWORD), len(parameters))
            parameters.insert(index, dependency)

            @wraps(endpoint)
            async def protected(*args, **kwargs):
                kwargs.pop(name, None)
                if inspect.iscoroutinefunction(endpoint):
                    return await endpoint(*args, **kwargs)
                return await run_in_threadpool(endpoint, *args, **kwargs)

            protected.__signature__ = signature.replace(parameters=parameters)
            return protected
        return decorate
