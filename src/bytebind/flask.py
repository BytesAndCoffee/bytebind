"""Flask integration for ByteBind: session leases and transaction-bound operations.

The same shape as ``bytebind.fastapi``::

    bind = ByteBind(app)

    @app.get("/admin")
    @bind(require=["tag:admin"])
    def admin(lease=bind.lease):
        return {"device_id": lease.device_id}

    @app.post("/restart")
    @bind(require=["tag:admin"], grant=bind.TRANSACTION)
    def restart(grant=bind.grant):
        return {"restarted": request.get_json()["service"], "approved_by": grant.device_id}

Parameters whose default is ``bind.lease`` or ``bind.grant`` are filled in when the
view runs. Behind a reverse proxy, apply ``werkzeug.middleware.proxy_fix.ProxyFix``
so the client address and origin come from the proxy's headers.
"""
from __future__ import annotations

import inspect
import json
from functools import wraps
from importlib.resources import files
from io import BytesIO
from urllib.parse import quote, unquote_to_bytes

from flask import Flask, Response, current_app, jsonify, request
from werkzeug.test import run_wsgi_app

from . import binding as b
from .limits import declared_fits
from .binding import GRANT_KEY, SESSION_COOKIE, STATE_COOKIE, Grant
from .discovery import AUTHORITY_CAPABILITY, AUTHORITY_TAG
from .rp import AuthorityError, CeremonyError, RelyingParty, _supports_evidence
from .tailscale import Directory

PROTECTED_KEY = "bytebind.protected"  # per-request; Flask's g is shared with a replayed request
_UNRESERVED = "/:@!$&'()*+,;=-._~"


def request_target(environ: dict) -> str:
    """The path and query as sent (SPEC.md 9.2), still percent-encoded, as the browser hashed it.

    Werkzeug's server and gunicorn keep the raw target in REQUEST_URI or RAW_URI. Without
    either, PATH_INFO is re-encoded, which cannot restore escapes of unreserved characters.
    """
    raw = environ.get("REQUEST_URI") or environ.get("RAW_URI")
    if raw:
        path = raw.split("?", 1)[0]
        if "://" in path:  # absolute-form request target
            path = "/" + path.split("://", 1)[1].partition("/")[2]
    else:
        path = environ.get("SCRIPT_NAME", "") + quote(environ.get("PATH_INFO", "").encode("latin-1"), safe=_UNRESERVED)
    query = environ.get("QUERY_STRING", "")
    return path + ("?" + query if query else "")


class _Inject:
    """A parameter default the binding replaces with the lease or grant."""

    def __init__(self, name: str):
        self.name = name

    def __repr__(self) -> str:
        return f"bind.{self.name}"


class ByteBind:
    """Mount ByteBind on a Flask app and protect views with ``@bind(require=[...])``.

    Configuration and keyword arguments match ``bytebind.fastapi.ByteBind``:
    BYTEBIND_AUTHORITY, BYTEBIND_ORIGIN, BYTEBIND_AUDIENCE and BYTEBIND_RP_DB, with
    Authority discovery on the tailnet when no Authority is configured.
    ``grant=bind.TRANSACTION`` binds one approval to one request: the first call stores
    it and answers 202 with a challenge; after the proof is redeemed the stored request
    is replayed through the app and the view runs exactly once.
    """

    LEASE = b.LEASE
    TRANSACTION = b.TRANSACTION

    def __init__(self, app: Flask | None = None, *, rp: RelyingParty | None = None,
                 authority: str | None = None, origin: str | None = None,
                 audience: str | None = None, database: str | None = None,
                 directory: Directory | None = None, tailscale_socket: str | None = None,
                 authority_tag: str = AUTHORITY_TAG, authority_capability: str = AUTHORITY_CAPABILITY,
                 authority_port: int = 9443, challenge_per_minute: int = 30,
                 max_transaction_body: int = 16 * 1024):
        self.core = b.Core(rp=rp, authority=authority, origin=origin, audience=audience, database=database,
                           directory=directory, tailscale_socket=tailscale_socket, authority_tag=authority_tag,
                           authority_capability=authority_capability, authority_port=authority_port,
                           challenge_per_minute=challenge_per_minute, max_transaction_body=max_transaction_body)
        self.lease = _Inject("lease")
        self.grant = _Inject("grant")
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        app.extensions["bytebind"] = self
        app.add_url_rule("/bytebind/client.js", "bytebind_client", self._client_script)
        app.add_url_rule("/bytebind/challenge", "bytebind_challenge", self._challenge, methods=["POST"])
        app.add_url_rule("/bytebind/proof", "bytebind_proof", self._proof, methods=["POST"])
        app.add_url_rule("/bytebind/logout", "bytebind_logout", self._logout, methods=["POST"])
        app.after_request(self._after_request)

    # --- mounted endpoints ------------------------------------------------------------------

    def _client_script(self) -> Response:
        return Response(files("bytebind").joinpath("web", "bytebind.js").read_text(), mimetype="application/javascript")

    def _challenge(self) -> Response:
        if not self.core.allow_challenge(request.remote_addr or ""):
            return self._rate_limited()
        try:
            from . import protocol as p
            if not declared_fits(request.headers.get("Content-Length"),1024):
                return self._failed(413)
            raw=request.stream.read(1025)
            if len(raw)>1024:
                return self._failed(413)
            body=p.json_body(raw or b"{}")
            if set(body) not in (set(),{"target"}) or (body and (not isinstance(body["target"],str) or not body["target"].startswith("/") or body["target"].startswith("//"))):
                raise CeremonyError("invalid challenge target")
            options={}
            if body:
                try:
                    endpoint,_=current_app.url_map.bind_to_environ(request.environ).match(body["target"].split("?")[0],method="GET")
                    options=getattr(current_app.view_functions[endpoint],"__bytebind_person__",{})
                except Exception:
                    raise CeremonyError("target unavailable") from None
                if not options:
                    raise CeremonyError("target has no person session policy")
            issued, state = self._rp().challenge(request.headers.get("Origin"),previous_session=request.cookies.get(SESSION_COOKIE),**options)
        except (CeremonyError,ValueError,p.ProtocolError):
            return self._failed(403)
        except (AuthorityError, OSError):
            return self._failed(503)
        response = self._json(issued)
        self._cookie(response, STATE_COOKIE, state, b.STATE_PATH, 210)
        return response

    def _proof(self) -> Response:
        if not declared_fits(request.headers.get("Content-Length"), b.MAX_PROOF_BODY):
            return self._failed(413)
        raw = request.stream.read(b.MAX_PROOF_BODY + 1)
        if len(raw) > b.MAX_PROOF_BODY:
            return self._failed(413)
        try:
            body = json.loads(raw)
            done = self._rp().accept_proof(request.headers.get("Origin"), body, request.cookies.get(STATE_COOKIE),
                                           request.cookies.get(SESSION_COOKIE))
        except (CeremonyError, ValueError):
            return self._failed(401)
        except (AuthorityError, OSError):
            return self._failed(503)
        if done.request is not None:  # transaction-bound: run the stored request, once
            response = self._replay(done.request, done.grant)
        else:
            response = self._json({"device_id": done.lease.device_id})
            self._cookie(response, SESSION_COOKIE, done.session_token, "/")
        response.delete_cookie(STATE_COOKIE, path=b.STATE_PATH, secure=True, httponly=True, samesite="Strict")
        return response

    def _logout(self) -> Response:
        try:
            self._rp().check_origin(request.headers.get("Origin"))
        except CeremonyError:
            return self._failed(403)
        self._rp().end_session(request.cookies.get(SESSION_COOKIE))
        response = Response(status=204, headers={"Cache-Control": "no-store"})
        response.delete_cookie(SESSION_COOKIE, secure=True, httponly=True, samesite="Strict")
        return response

    def _after_request(self, response: Response) -> Response:
        protected = request.environ.get(PROTECTED_KEY, False)
        required = response.headers.get("X-ByteBind-Required")
        if protected or required:
            response.headers["Cache-Control"] = "no-store"
        if required and "text/html" in request.headers.get("Accept", "") and request.method == "GET":
            return Response(b.sign_in_page(request_target(request.environ) if response.headers.get("X-ByteBind-Person") else None), status=401, mimetype="text/html", headers={"Cache-Control": "no-store"})
        # Renewal runs only on protected pages: public pages must not start ceremonies
        # or make visitors' browsers contact the private Authority.
        if (protected and response.mimetype == "text/html" and not response.is_streamed
                and not response.headers.get("Content-Encoding")):
            response.set_data(b.inject_renewal(response.get_data()))
        return response

    # --- protection ---------------------------------------------------------------------

    def __call__(self, *, require=(), grant=LEASE, assurance="device", person_max_age=None, identify=False):
        if grant not in (self.LEASE, self.TRANSACTION):
            raise ValueError("grant must be bind.LEASE or bind.TRANSACTION")
        required = b.check_requirements(require)
        person_max_age=b.check_assurance(assurance,person_max_age,identify,grant)

        def decorate(view):
            operation = f"{view.__module__}.{view.__qualname__}"
            parameters = inspect.signature(view).parameters
            fills = {name: param.default for name, param in parameters.items() if isinstance(param.default, _Inject)}

            @wraps(view)
            def protected(*args, **kwargs):
                request.environ[PROTECTED_KEY] = True
                if grant == self.LEASE:
                    lease = self._rp().session(request.cookies.get(SESSION_COOKIE))
                    if lease is None:
                        return self._error(401, "lease_required", {"X-ByteBind-Required": "1",**({"X-ByteBind-Person":"1"} if assurance != "device" else {})})
                    if request.method not in {"GET", "HEAD", "OPTIONS"}:
                        try:
                            self._rp().check_origin(request.headers.get("Origin"))
                        except CeremonyError:
                            return self._error(403, "origin_refused")
                    if assurance != "device":
                        try:
                            lease=self._rp().require_person(request.cookies.get(SESSION_COOKIE),assurance,person_max_age,identify)
                        except CeremonyError:
                            return self._error(401,"step_up_required",{"X-ByteBind-Required":"1","X-ByteBind-Person":"1"})
                        except (AuthorityError,OSError):
                            return self._failed(503)
                    claims, values = lease.claims, {"lease": b.lease_view(lease), "grant": None}
                else:
                    granted = request.environ.get(GRANT_KEY)
                    if granted is None:
                        return self._challenge_transaction(operation,assurance,identify)
                    if granted["operation"] != operation:
                        return self._error(403, "grant_for_another_operation")
                    if not _supports_evidence(granted.get("assurance"),assurance,transaction=True):
                        return self._error(403,"missing_assurance")
                    claims = granted["claims"]
                    values = {"lease": None, "grant": Grant(claims.get("device_id"), claims,granted.get("assurance"))}
                if not b.meets(claims, required):
                    return self._error(403, "requirements_not_met")
                for name, default in fills.items():
                    kwargs[name] = values[default.name]
                return current_app.ensure_sync(view)(*args, **kwargs)

            protected.__bytebind_person__={"assurance":assurance,"person_max_age":person_max_age,"identify":identify} if assurance != "device" and grant == self.LEASE else {}
            return protected
        return decorate

    # --- transaction-bound requests ----------------------------------------------------------

    def _challenge_transaction(self, operation: str, assurance="device", identify=False) -> Response:
        """The access request of a transaction-bound operation: store it, bind it by Q, run nothing."""
        if not self.core.allow_challenge(request.remote_addr or ""):
            return self._rate_limited()
        if not self.core.body_fits(request.headers.get("Content-Length", "0")):
            return self._failed(413)
        body = request.stream.read(self.core.max_transaction_body + 1)
        if not self.core.body_fits(None, body):
            return self._failed(413)
        try:
            issued, state = self.core.challenge_transaction(
                self._rp(), request.headers.get("Origin"), operation, request.method,
                request_target(request.environ), request.headers, body,assurance,identify)
        except CeremonyError:
            return self._failed(403)
        except (AuthorityError, OSError):
            return self._failed(503)
        response = self._json(issued, 202)
        self._cookie(response, STATE_COOKIE, state, b.STATE_PATH, 210)
        return response

    def _replay(self, stored: dict, grant: dict) -> Response:
        """Run the stored request through the app with the grant in its WSGI environ.

        WSGI servers only put CGI variables and HTTP_* headers in the environ, so no client
        can supply the grant; the view sees the original method, target, covered headers,
        and body.
        """
        body = b.stored_body(stored)
        target = stored["target"]
        path, _, query = target.partition("?")
        environ = {key: value for key, value in request.environ.items()
                   if key.startswith("wsgi.") or key in {"SERVER_NAME","SERVER_PORT","SERVER_PROTOCOL","REMOTE_ADDR","SCRIPT_NAME","HTTPS"}}
        script = environ.get("SCRIPT_NAME", "")
        path_info = unquote_to_bytes(path).decode("latin-1")
        if script and path_info.startswith(script):
            path_info = path_info[len(script):]
        environ.update({"REQUEST_METHOD": stored["method"], "PATH_INFO": path_info, "QUERY_STRING": query,
                        "REQUEST_URI": target, "RAW_URI": target, "CONTENT_LENGTH": str(len(body)),
                        "wsgi.input": BytesIO(body),
                        GRANT_KEY: {"operation": stored["operation"], "claims": grant.get("claims", {}),"assurance":grant.get("assurance",{})}})
        if stored["headers"].get("content-type"):
            environ["CONTENT_TYPE"] = stored["headers"]["content-type"]
        app_iter, status, headers = run_wsgi_app(current_app.wsgi_app, environ, buffered=True)
        response = current_app.response_class(b"".join(app_iter), status=status, headers=headers)
        response.headers["Cache-Control"] = "no-store"
        return response

    # --- helpers ----------------------------------------------------------------------------

    def _rp(self) -> RelyingParty:
        return self.core.rp_for(request.host_url.rstrip("/"))

    @staticmethod
    def _json(payload: dict, status: int = 200) -> Response:
        response = jsonify(payload)
        response.status_code = status
        response.headers["Cache-Control"] = "no-store"
        return response

    def _error(self, status: int, code: str, headers: dict | None = None) -> Response:
        response = self._json({"error": code}, status)
        response.headers.update(headers or {})
        return response

    def _failed(self, status: int) -> Response:
        return self._json({"error": "ceremony_failed"}, status)

    def _rate_limited(self) -> Response:
        return self._error(429, "rate_limited", {"Retry-After": "60"})

    @staticmethod
    def _cookie(response: Response, name: str, value: str, path: str, max_age: int | None = None) -> None:
        response.set_cookie(name, value, path=path, max_age=max_age, secure=True, httponly=True, samesite="Strict")
