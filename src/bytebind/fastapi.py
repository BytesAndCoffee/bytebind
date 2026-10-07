"""FastAPI integration for ByteBind: session leases and transaction-bound operations."""
from __future__ import annotations

import asyncio
import inspect
import json
from functools import wraps
from importlib.resources import files
from urllib.parse import unquote

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from starlette.concurrency import run_in_threadpool
from starlette.routing import Match

from .limits import read_capped

from . import binding as b
from .binding import COVERED_HEADERS, GRANT_KEY, SESSION_COOKIE, STATE_COOKIE, Grant  # noqa: F401 (re-exported)
from .discovery import AUTHORITY_TAG, AUTHORITY_CAPABILITY
from .tailscale import Directory
from .rp import AuthorityError, CeremonyError, Lease, RelyingParty, _supports_evidence

GRANT_SCOPE_KEY = GRANT_KEY


def request_target(request: Request) -> str:
    """The path and query as sent (SPEC.md 9.2): still percent-encoded, as the browser hashed it."""
    raw = request.scope.get("raw_path") or request.url.path.encode()
    query = request.scope.get("query_string", b"")
    return raw.decode("latin-1") + ("?" + query.decode("latin-1") if query else "")


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

    LEASE = b.LEASE
    TRANSACTION = b.TRANSACTION

    def __init__(self, app: FastAPI, *, rp: RelyingParty | None = None,
                 authority: str | None = None, origin: str | None = None,
                 audience: str | None = None, database: str | None = None,
                 directory: Directory | None = None, tailscale_socket: str | None = None,
                 authority_tag: str = AUTHORITY_TAG,
                 authority_capability: str = AUTHORITY_CAPABILITY,
                 authority_port: int = 9443, challenge_per_minute: int = 30,
                 max_transaction_body: int = 16 * 1024):
        self.core = b.Core(rp=rp, authority=authority, origin=origin, audience=audience, database=database,
                           directory=directory, tailscale_socket=tailscale_socket, authority_tag=authority_tag,
                           authority_capability=authority_capability, authority_port=authority_port,
                           challenge_per_minute=challenge_per_minute, max_transaction_body=max_transaction_body)

        def current_lease(request: Request) -> Grant:
            request.state.bytebind_protected = True
            endpoint=getattr(request.scope.get("route"),"endpoint",None)
            options=getattr(endpoint,"__bytebind_person__",{})
            lease = self._rp(request).session(request.cookies.get(SESSION_COOKIE))
            if lease is None:
                raise HTTPException(401,"ByteBind lease required",headers={"X-ByteBind-Required":"1",**({"X-ByteBind-Person":"1"} if options else {})})
            if options:
                try:
                    lease=self._rp(request).require_person(request.cookies.get(SESSION_COOKIE),options["assurance"],options["person_max_age"],options["identify"])
                except CeremonyError:
                    raise HTTPException(401,"Person attestation required",headers={"X-ByteBind-Required":"1","X-ByteBind-Person":"1"}) from None
                except (AuthorityError,OSError):
                    raise HTTPException(503,"Person validation unavailable") from None
            return b.lease_view(lease)
        self.lease = Depends(current_lease)

        # Resolved before the binding decides to answer with a challenge, so it is None on
        # that first call; a transaction-bound handler itself only ever runs with a grant.
        def current_grant(request: Request) -> Grant | None:
            grant = request.scope.get(GRANT_KEY)
            return Grant(grant["claims"].get("device_id"), grant["claims"], grant.get("assurance")) if grant else None
        self.grant = Depends(current_grant)
        app.state.bytebind = self

        @app.get("/bytebind/client.js", include_in_schema=False)
        def client():
            return Response(files("bytebind").joinpath("web", "bytebind.js").read_text(),
                            media_type="application/javascript")

        @app.post("/bytebind/challenge", include_in_schema=False)
        async def challenge(request: Request):
            if not self._allow_challenge(request):
                return self._rate_limited()
            try:
                raw=await read_capped(request,1024)
                from . import protocol as p
                body=p.json_body(raw or b"{}")
                if set(body) not in (set(),{"target"}) or (body and (not isinstance(body["target"],str) or not body["target"].startswith("/") or body["target"].startswith("//"))):
                    raise CeremonyError("invalid challenge target")
                options={}
                if body:
                    scope=dict(request.scope,method="GET",path=body["target"].split("?")[0])
                    for route in app.router.routes:
                        match,_=route.matches(scope)
                        if match==Match.FULL:
                            options=getattr(getattr(route,"endpoint",None),"__bytebind_person__",{})
                            break
                    if not options:
                        raise CeremonyError("target has no person session policy")
                issued,state=await run_in_threadpool(self._rp(request).challenge,request.headers.get("origin"),previous_session=request.cookies.get(SESSION_COOKIE),**options)
            except (CeremonyError,ValueError,p.ProtocolError):
                return self._failed(403)
            except (AuthorityError, OSError):
                return self._failed(503)
            response = JSONResponse(issued, headers={"Cache-Control": "no-store"})
            self._cookie(response, STATE_COOKIE, state, b.STATE_PATH, 210)
            return response

        @app.post("/bytebind/proof", include_in_schema=False)
        async def proof(request: Request):
            try:
                raw = await read_capped(request, b.MAX_PROOF_BODY)
                if raw is None:
                    return self._failed(413)
                body = json.loads(raw)
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
            response.delete_cookie(STATE_COOKIE, path=b.STATE_PATH, secure=True, httponly=True, samesite="strict")
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
            # FastAPI parses model bodies before resolving dependencies. Bound the
            # input here, before parsing, for the first matching transaction route.
            for route in app.router.routes:
                match, _ = route.matches(request.scope)
                if match == Match.FULL:
                    if getattr(getattr(route, "endpoint", None), "__bytebind_transaction__", False):
                        body = await read_capped(request, self.core.max_transaction_body)
                        if body is None:
                            return self._failed(413)
                        # Starlette's cached middleware request replays this body to
                        # downstream parsing without reading the stream a second time.
                        request._body = body
                    break
            response = await call_next(request)
            protected = getattr(request.state, "bytebind_protected", False)
            if protected:
                response.headers["Cache-Control"] = "no-store"
            if response.headers.get("X-ByteBind-Required") and "text/html" in request.headers.get("accept", "") and request.method == "GET":
                return HTMLResponse(b.sign_in_page(str(request.url.path)+("?"+str(request.url.query) if request.url.query else "") if response.headers.get("X-ByteBind-Person") else None), status_code=401, headers={"Cache-Control": "no-store"})
            # Renewal runs only on protected pages: public pages must not start ceremonies
            # or make visitors' browsers contact the private Authority.
            if protected and "text/html" in response.headers.get("content-type", "") and not response.headers.get("content-encoding"):
                body = b.inject_renewal(b"".join([chunk async for chunk in response.body_iterator]))
                result = Response(body, status_code=response.status_code, background=response.background)
                result.raw_headers = [(key, value) for key, value in response.raw_headers
                                      if key.lower() not in (b"content-length", b"cache-control")]
                result.headers["content-length"] = str(len(body))
                result.headers["cache-control"] = "no-store"
                return result
            if response.headers.get("X-ByteBind-Required"):
                response.headers["Cache-Control"] = "no-store"
            return response

    # Configuration lives on the shared core; these keep the binding's attributes readable.
    rp = property(lambda self: self.core.rp, lambda self, value: setattr(self.core, "rp", value))
    authority = property(lambda self: self.core.authority)
    origin = property(lambda self: self.core.origin)
    audience = property(lambda self: self.core.audience)
    database = property(lambda self: self.core.database)
    _authority_client = property(lambda self: self.core.authority_client)

    def _rp(self, request: Request) -> RelyingParty:
        return self.core.rp_for(str(request.base_url).rstrip("/"))

    def _allow_challenge(self, request: Request) -> bool:
        return self.core.allow_challenge(request.client.host if request.client else "")

    @staticmethod
    def _rate_limited():
        return JSONResponse({"error": "rate_limited"}, status_code=429,
                            headers={"Cache-Control": "no-store", "Retry-After": "60"})

    async def _challenge_transaction(self, request: Request, operation: str, assurance="device", identify=False) -> Response:
        """The access request of a transaction-bound operation: store it, bind it by Q, run nothing."""
        if not self._allow_challenge(request):
            return self._rate_limited()
        if not self.core.body_fits(request.headers.get("content-length", "0")):
            return self._failed(413)
        body = await read_capped(request, self.core.max_transaction_body)
        if body is None:
            return self._failed(413)
        try:
            issued, state = await run_in_threadpool(
                self.core.challenge_transaction, self._rp(request), request.headers.get("origin"), operation,
                request.method, request_target(request), request.headers, body, assurance, identify)
        except CeremonyError:
            return self._failed(403)
        except (AuthorityError, OSError):
            return self._failed(503)
        response = JSONResponse(issued, status_code=202, headers={"Cache-Control": "no-store"})
        self._cookie(response, STATE_COOKIE, state, b.STATE_PATH, 210)
        return response

    async def _replay(self, request: Request, stored: dict, grant: dict) -> Response:
        """Dispatch the stored request through the app, carrying the grant in its ASGI scope.

        The grant lives only in the in-process scope, so no client can supply it; the
        handler sees the original method, target, covered headers, and body.
        """
        path, _, query = stored["target"].partition("?")
        headers = [(b"host",self._rp(request).origin.split("//",1)[1].encode("ascii"))]
        headers += [(name.encode("latin-1"), value.encode("latin-1")) for name, value in stored["headers"].items() if value]
        body = b.stored_body(stored)
        headers.append((b"content-length", str(len(body)).encode()))
        scope = {key: value for key, value in request.scope.items()
                 if key in ("type", "asgi", "http_version", "scheme", "server", "client", "root_path")}
        if "state" in scope:
            scope["state"] = dict(scope["state"])  # the replay gets its own request state
        scope.update(method=stored["method"], path=unquote(path), raw_path=path.encode("latin-1"),
                     query_string=query.encode("latin-1"), headers=headers)
        scope[GRANT_KEY] = {"operation": stored["operation"], "claims": grant.get("claims", {}), "assurance":grant.get("assurance",{})}
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

    _script = staticmethod(b.renewal_script)

    def __call__(self, *, require=(), grant=LEASE, assurance="device", person_max_age=None, identify=False):
        if grant not in (self.LEASE, self.TRANSACTION):
            raise ValueError("grant must be bind.LEASE or bind.TRANSACTION")
        required = b.check_requirements(require)
        person_max_age=b.check_assurance(assurance,person_max_age,identify,grant)

        def check_origin(request: Request) -> None:
            try:
                self._rp(request).check_origin(request.headers.get("origin"))
            except CeremonyError:
                raise HTTPException(403, "Origin is not this RP's origin") from None

        def authorize_lease(request: Request, response: Response, lease: Lease = self.lease):
            response.headers["Cache-Control"] = "no-store"
            if request.method not in {"GET", "HEAD", "OPTIONS"}:
                check_origin(request)
            if not b.meets(lease.claims, required):
                raise HTTPException(403, "ByteBind requirements not met")

        def decorate(endpoint):
            operation = f"{endpoint.__module__}.{endpoint.__qualname__}"

            async def authorize_transaction(request: Request, response: Response):
                """None runs the handler (a replay with a grant); a Response is returned instead of running it."""
                request.state.bytebind_protected = True
                response.headers["Cache-Control"] = "no-store"
                granted = request.scope.get(GRANT_KEY)
                if granted is None:
                    return await self._challenge_transaction(request, operation,assurance,identify)
                if granted["operation"] != operation:
                    raise HTTPException(403, "grant is for another operation")
                if not _supports_evidence(granted.get("assurance"),assurance,transaction=True):
                    raise HTTPException(403,"Missing person assurance")
                if not b.meets(granted["claims"], required):
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

            protected.__bytebind_transaction__ = grant == self.TRANSACTION
            protected.__bytebind_person__ = {"assurance":assurance,"person_max_age":person_max_age,"identify":identify} if assurance != "device" and grant == self.LEASE else {}
            protected.__signature__ = signature.replace(parameters=parameters)
            return protected
        return decorate
