"""FastAPI integration for ByteBind: session leases and transaction-bound operations."""
from __future__ import annotations

import asyncio
import base64
import inspect
import os
from dataclasses import dataclass
from functools import wraps
from importlib.resources import files
from urllib.parse import unquote

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from .discovery import AUTHORITY_TAG, AUTHORITY_CAPABILITY, DiscoveringAuthorityClient
from .limits import PeerLimiter
from .protocol import request_digest
from .tailscale import Directory
from .rp import AuthorityClient, AuthorityError, CeremonyError, Lease, RelyingParty

STATE_COOKIE = "bytebind_state"
SESSION_COOKIE = "bytebind_session"
MAX_CACHED_ORIGINS = 32
GRANT_SCOPE_KEY = "bytebind.grant"  # set only in-process, on a replayed transaction-bound request
COVERED_HEADERS = ("content-type",)  # the headers Q covers; the browser client sends exactly these


@dataclass(frozen=True)
class Grant:
    """What a transaction-bound handler learns about the device that approved it."""

    device_id: str | None
    claims: dict


def request_target(request: Request) -> str:
    """The path and query as sent (SPEC.md 9.2): still percent-encoded, as the browser hashed it."""
    raw = request.scope.get("raw_path") or request.url.path.encode()
    query = request.scope.get("query_string", b"")
    return raw.decode("latin-1") + ("?" + query.decode("latin-1") if query else "")


def _meets(claims: dict, required: frozenset[str]) -> bool:
    """Every requirement must match: ``tag:`` against device tags, anything else against ``authorization``."""
    tags, authorization = set(claims.get("tags", [])), set(claims.get("authorization", []))
    return all(item in (tags if item.startswith("tag:") else authorization) for item in required)


class ByteBind:
    """Mount ByteBind and protect routes with ``@bind(require=[...], grant=bind.LEASE)``.

    ``grant=bind.TRANSACTION`` binds one approval to one request instead: the first
    call stores the request, answers 202 with a challenge, and runs nothing. After the
    proof is redeemed, the stored request is replayed through the app and the handler
    runs exactly once; its response becomes the proof submission's response.

    Configuration comes from BYTEBIND_AUTHORITY, BYTEBIND_ORIGIN,
    BYTEBIND_AUDIENCE and BYTEBIND_RP_DB, or explicit keyword arguments.
    The Authority is discovered from tailnet role tags or node capabilities.
    A local /run/bytebind/control.sock listener takes precedence. Without a configured
    origin the application's request URL supplies it; deploy behind trusted host
    and proxy configuration. An existing RelyingParty can be passed as ``rp``.

    ``max_transaction_body`` bounds what a transaction-bound request may store.

    ``challenge_per_minute`` limits ceremony starts per client address. A challenge
    request is unauthenticated and each one holds a pending slot at the Authority, so
    without a limit any client could fill the Authority's per-RP quota.
    """

    LEASE = "session"
    TRANSACTION = "tx"

    def __init__(self, app: FastAPI, *, rp: RelyingParty | None = None,
                 authority: str | None = None, origin: str | None = None,
                 audience: str | None = None, database: str | None = None,
                 directory: Directory | None = None, tailscale_socket: str | None = None,
                 authority_tag: str = AUTHORITY_TAG,
                 authority_capability: str = AUTHORITY_CAPABILITY,
                 authority_port: int = 9443, challenge_per_minute: int = 30,
                 max_transaction_body: int = 16 * 1024):
        self.rp = rp
        self._rps: dict[str, RelyingParty] = {}
        self._challenge_limiter = PeerLimiter(challenge_per_minute)
        self.max_transaction_body = max_transaction_body
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

        # Resolved before the binding decides to answer with a challenge, so it is None on
        # that first call; a transaction-bound handler itself only ever runs with a grant.
        def current_grant(request: Request) -> Grant | None:
            grant = request.scope.get(GRANT_SCOPE_KEY)
            return Grant(grant["claims"].get("device_id"), grant["claims"]) if grant else None
        self.grant = Depends(current_grant)
        app.state.bytebind = self

        @app.get("/bytebind/client.js", include_in_schema=False)
        def client():
            return Response(files("bytebind").joinpath("web", "bytebind.js").read_text(),
                            media_type="application/javascript")

        @app.post("/bytebind/challenge", include_in_schema=False)
        def challenge(request: Request):
            if not self._allow_challenge(request):
                return self._rate_limited()
            try:
                issued, state = self._rp(request).challenge(request.headers.get("origin"))
            except CeremonyError:
                return self._failed(403)
            except (AuthorityError, OSError):
                return self._failed(503)
            response = JSONResponse(issued, headers={"Cache-Control": "no-store"})
            self._cookie(response, STATE_COOKIE, state, "/bytebind/", 60)
            return response

        @app.post("/bytebind/proof", include_in_schema=False)
        async def proof(request: Request):
            try:
                body = await request.json()
                done = await run_in_threadpool(self._rp(request).accept_proof, request.headers.get("origin"),
                                              body, request.cookies.get(STATE_COOKIE),
                                              request.cookies.get(SESSION_COOKIE))
            except (CeremonyError, ValueError):
                return self._failed(401)
            except (AuthorityError, OSError):
                return self._failed(503)
            if done.request is not None:  # transaction-bound: run the stored request, once
                response = await self._replay(request, done.request, done.grant)
            else:
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

    def _allow_challenge(self, request: Request) -> bool:
        return self._challenge_limiter.allow(request.client.host if request.client else "")

    @staticmethod
    def _rate_limited():
        return JSONResponse({"error": "rate_limited"}, status_code=429,
                            headers={"Cache-Control": "no-store", "Retry-After": "60"})

    async def _challenge_transaction(self, request: Request, operation: str) -> Response:
        """The access request of a transaction-bound operation: store it, bind it by Q, run nothing."""
        if not self._allow_challenge(request):
            return self._rate_limited()
        declared = request.headers.get("content-length", "0")
        if not declared.isdigit() or int(declared) > self.max_transaction_body:
            return self._failed(413)
        body = await request.body()
        if len(body) > self.max_transaction_body:
            return self._failed(413)
        target = request_target(request)
        headers = {name: request.headers.get(name, "") for name in COVERED_HEADERS}
        q = request_digest(request.method, target, headers, body)
        stored = {"operation": operation, "method": request.method, "target": target, "headers": headers,
                  "body": base64.b64encode(body).decode("ascii")}
        try:
            issued, state = await run_in_threadpool(self._rp(request).challenge, request.headers.get("origin"),
                                                    request=stored, q=q)
        except CeremonyError:
            return self._failed(403)
        except (AuthorityError, OSError):
            return self._failed(503)
        response = JSONResponse(issued, status_code=202, headers={"Cache-Control": "no-store"})
        self._cookie(response, STATE_COOKIE, state, "/bytebind/", 60)
        return response

    async def _replay(self, request: Request, stored: dict, grant: dict) -> Response:
        """Dispatch the stored request through the app, carrying the grant in its ASGI scope.

        The grant lives only in the in-process scope, so no client can supply it; the
        handler sees the original method, target, covered headers, and body.
        """
        path, _, query = stored["target"].partition("?")
        headers = [(key, value) for key, value in request.scope["headers"]
                   if key not in (b"content-type", b"content-length")]
        headers += [(name.encode("latin-1"), value.encode("latin-1")) for name, value in stored["headers"].items() if value]
        body = base64.b64decode(stored["body"])
        headers.append((b"content-length", str(len(body)).encode()))
        scope = {key: value for key, value in request.scope.items()
                 if key in ("type", "asgi", "http_version", "scheme", "server", "client", "root_path", "state", "extensions")}
        if "state" in scope:
            scope["state"] = dict(scope["state"])  # the replay gets its own request state
        scope.update(method=stored["method"], path=unquote(path), raw_path=path.encode("latin-1"),
                     query_string=query.encode("latin-1"), headers=headers)
        scope[GRANT_SCOPE_KEY] = {"operation": stored["operation"], "claims": grant.get("claims", {})}
        delivered = False

        async def receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            await asyncio.Event().wait()  # never disconnects; the replay ends with its response

        start, chunks = {}, []

        async def send(message):
            if message["type"] == "http.response.start":
                start.update(message)
            elif message["type"] == "http.response.body":
                chunks.append(message.get("body", b""))

        await request.app(scope, receive, send)
        result = Response(b"".join(chunks), status_code=start.get("status", 500))
        result.raw_headers = [(key, value) for key, value in start.get("headers", [])
                              if key.lower() not in (b"content-length", b"cache-control")]
        result.headers["content-length"] = str(len(result.body))
        result.headers["cache-control"] = "no-store"
        return result

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
                'async function renew(){try{await ByteBind.session("/bytebind/challenge","/bytebind/proof");'
                + done + '}catch(e){' + failed + 'const s=document.getElementById("bytebind-status");'
                'if(s)s.textContent="Private network access required";}}renew();</script>')

    def __call__(self, *, require=(), grant=LEASE):
        if grant not in (self.LEASE, self.TRANSACTION):
            raise ValueError("grant must be bind.LEASE or bind.TRANSACTION")
        if isinstance(require, str) or not all(isinstance(item, str) and item for item in require):
            raise ValueError("require must be a sequence of nonempty claim strings")
        required = frozenset(require)

        def check_origin(request: Request) -> None:
            try:
                self._rp(request).check_origin(request.headers.get("origin"))
            except CeremonyError:
                raise HTTPException(403, "Origin is not this RP's origin") from None

        def authorize_lease(request: Request, response: Response, lease: Lease = self.lease):
            response.headers["Cache-Control"] = "no-store"
            if request.method not in {"GET", "HEAD", "OPTIONS"}:
                check_origin(request)
            if not _meets(lease.claims, required):
                raise HTTPException(403, "ByteBind requirements not met")

        def decorate(endpoint):
            operation = f"{endpoint.__module__}.{endpoint.__qualname__}"

            async def authorize_transaction(request: Request, response: Response):
                """None runs the handler (a replay with a grant); a Response is returned instead of running it."""
                request.state.bytebind_protected = True
                response.headers["Cache-Control"] = "no-store"
                granted = request.scope.get(GRANT_SCOPE_KEY)
                if granted is None:
                    return await self._challenge_transaction(request, operation)
                if granted["operation"] != operation:
                    raise HTTPException(403, "grant is for another operation")
                if not _meets(granted["claims"], required):
                    raise HTTPException(403, "ByteBind requirements not met")
                return None

            authorize = authorize_lease if grant == self.LEASE else authorize_transaction
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
                challenge = kwargs.pop(name, None)
                if isinstance(challenge, Response):
                    return challenge
                if inspect.iscoroutinefunction(endpoint):
                    return await endpoint(*args, **kwargs)
                return await run_in_threadpool(endpoint, *args, **kwargs)

            protected.__signature__ = signature.replace(parameters=parameters)
            return protected
        return decorate
