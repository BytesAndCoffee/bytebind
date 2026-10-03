"""The ByteBind Authority: PROVE/ATTEST for browsers, BEGIN/TRY and REDEEM/GRANT for relying parties.

Three listeners, each narrowly scoped:

* the attest service (SPEC.md 11-12), HTTPS on the tailnet IP, no proxy in front;
* the control channel over a Unix domain socket, identifying each RP by the
  kernel-reported peer user ID (SPEC.md 5.2, 16.3);
* the control channel over HTTPS between tailnet nodes, identifying each RP by
  its Tailscale node identity.
"""

from __future__ import annotations

import argparse
import http.server
import json
import logging
import os
import socket
import socketserver
import stat
import struct
import sys
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from . import protocol as p
from .config import AuthorityConfig, RelyingParty, load
from .store import Attestation, TransactionError, TransactionStore
from .tailscale import AttestationError, Directory, LocalAPI, authorize, identify, is_tailscale_address

logger = logging.getLogger("bytebind.authority")
MAX_ATTEST_BODY = 1024
MAX_CONTROL_BODY = 4096


def rfc3339(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class PeerLimiter:
    """A sliding one-minute window per key."""

    def __init__(self, per_minute: int = 30, now: Callable[[], float] = time.monotonic):
        self.per_minute, self.now = per_minute, now
        self.hits: dict[str, list[float]] = {}
        self.lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = self.now()
        with self.lock:
            if len(self.hits) > 10_000:
                self.hits = {k: v for k, v in self.hits.items() if v and now - v[-1] < 60}
            hits = [hit for hit in self.hits.get(key, ()) if now - hit < 60]
            allowed = len(hits) < self.per_minute
            if allowed:
                hits.append(now)
            self.hits[key] = hits
            return allowed


def open_store(config: AuthorityConfig, now: Callable[[], float] = time.time) -> TransactionStore:
    return TransactionStore(config.database, attest_window=config.attest_window, redeem_window=config.redeem_window,
                            max_pending_per_rp=config.max_pending_per_rp, now=now)


# --- PROVE -> ATTEST ---------------------------------------------------------------------

def attest(config: AuthorityConfig, store: TransactionStore, directory: Directory, peer: str, origin: str, body: object) -> bytes:
    """Checks 3-9 of SPEC.md 11.1 (1 and 2 are the caller's). Returns H2."""
    if not isinstance(body, dict) or set(body) != {"cid", "N", "H1"}:
        raise p.ProtocolError("malformed body")
    cid = p.b64decode(body["cid"], p.CID_BYTES)
    try:
        n, h1 = p.b64decode(body["N"], p.SECRET_BYTES), p.b64decode(body["H1"], p.SECRET_BYTES)
        pending = store.pending(cid)                                                    # 3
        if origin != pending.allowed_origin:                                            # 4
            raise p.ProtocolError("Origin is not this transaction's origin")
        if not p.equal(h1, p.compute_h1(pending.profile, pending.c, cid, n, pending.q)):  # 5
            raise p.ProtocolError("H1 does not match")
        rp = config.rps.get(pending.rp_id)
        if rp is None:
            raise p.ProtocolError("transaction's RP is no longer registered")
        attested = identify(directory, peer)                                            # 6, 7
        authorize(attested, rp.policy)                                                  # 8
        claims = {"device_id": attested.peer_id, "name": attested.name, "tags": list(attested.tags)}
        store.mark_attested(cid, Attestation(attested.address, attested.peer_id, claims))  # 9
    except (p.ProtocolError, TransactionError, AttestationError, OSError):
        store.burn(cid, "pending")
        raise
    logger.info("attested rp=%s node=%s name=%s", pending.rp_id, attested.peer_id, attested.name)
    return p.seal_h2(pending.profile, pending.c, cid, n, h1, p.ip_bytes(attested.address), pending.s)


def create_attest_app(config: AuthorityConfig, directory: Directory | None = None, store: TransactionStore | None = None) -> FastAPI:
    store = store or open_store(config)
    directory = directory or LocalAPI(config.tailscale_socket)
    parts = urllib.parse.urlsplit(config.attest_url)
    hosts = {parts.netloc.lower()}
    if parts.port in (None, 443):
        hosts |= {parts.hostname.lower(), f"{parts.hostname.lower()}:443"}
    origins = config.origins
    limiter = PeerLimiter()
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    def cors(origin: str) -> dict[str, str]:
        return {"Access-Control-Allow-Origin": origin, "Vary": "Origin", "Cache-Control": "no-store"}

    def refused(status: int = 403, origin: str | None = None) -> JSONResponse:
        headers = cors(origin) if origin else {"Cache-Control": "no-store"}
        return JSONResponse({"error": "attestation_failed"}, status, headers=headers)

    def trusted(request: Request) -> str | None:
        """Check 1: a registered origin and our own Host, before any state is read."""
        origin = request.headers.get("origin", "")
        return origin if origin in origins and request.headers.get("host", "").lower() in hosts else None

    @app.options("/attest")
    def preflight(request: Request):
        origin = trusted(request)
        requested = {h.strip().lower() for h in request.headers.get("access-control-request-headers", "").split(",") if h.strip()}
        if origin is None or request.headers.get("access-control-request-method") != "POST" or requested - {"content-type"}:
            return Response(status_code=403)
        headers = cors(origin) | {"Access-Control-Allow-Methods": "POST", "Access-Control-Allow-Headers": "Content-Type", "Access-Control-Max-Age": "600"}
        if request.headers.get("access-control-request-private-network") == "true":
            headers["Access-Control-Allow-Private-Network"] = "true"
        return Response(status_code=204, headers=headers)

    @app.post("/attest")
    async def prove(request: Request):
        origin = trusted(request)
        if origin is None:
            logger.warning("PROVE refused: untrusted Origin or Host")
            return refused()
        peer = request.client.host if request.client else ""  # the socket peer; proxy headers are off
        if not limiter.allow(peer):
            return JSONResponse({"error": "rate_limited"}, 429, headers=cors(origin) | {"Retry-After": "60"})
        if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":  # check 2
            return refused(origin=origin)
        raw = await request.body()
        if len(raw) > MAX_ATTEST_BODY:
            return refused(origin=origin)
        try:
            h2 = attest(config, store, directory, peer, origin, json.loads(raw))
        except (p.ProtocolError, TransactionError, AttestationError, ValueError) as exc:
            logger.warning("PROVE refused peer=%s: %s", peer, getattr(exc, "reason", "malformed JSON"))
            return refused(origin=origin)
        except OSError:
            logger.exception("PROVE failed: tailscaled is unavailable")
            return refused(503, origin)
        return JSONResponse({"H2": p.b64encode(h2)}, headers=cors(origin))

    return app


# --- BEGIN -> TRY and REDEEM -> GRANT ---------------------------------------------------------

class ControlError(Exception):
    def __init__(self, status: int, code: str, reason: str):
        super().__init__(reason)
        self.status, self.code, self.reason = status, code, reason


class Control:
    """Transport-independent handling of control-channel requests from an identified RP."""

    def __init__(self, config: AuthorityConfig, store: TransactionStore):
        self.config, self.store = config, store

    def handle(self, rp: RelyingParty, path: str, raw: bytes) -> dict[str, Any]:
        if len(raw) > MAX_CONTROL_BODY:
            raise ControlError(413, "too_large", "body too large")
        try:
            body = json.loads(raw)
        except ValueError as exc:
            raise ControlError(400, "malformed", "malformed JSON") from exc
        if path == "/v1/begin":
            return self.begin(rp, body)
        if path == "/v1/redeem":
            return self.redeem(rp, body)
        raise ControlError(404, "not_found", "unknown path")

    def begin(self, rp: RelyingParty, body: object) -> dict[str, Any]:
        if not isinstance(body, dict) or not {"audience", "profile"} <= set(body) <= {"audience", "profile", "Q", "allowed_origin"}:
            raise ControlError(400, "malformed", "malformed BEGIN")
        audience, profile = body["audience"], body["profile"]
        if audience not in rp.audiences:
            raise ControlError(403, "refused", "audience not registered for this RP")
        if profile not in p.PROFILES or (profile == "tx") != ("Q" in body):
            raise ControlError(400, "malformed", "profile and Q disagree")
        if "allowed_origin" in body and body["allowed_origin"] != rp.origin:
            raise ControlError(403, "refused", "allowed_origin is not this RP's registered origin")
        try:
            q = p.b64decode(body["Q"], p.SECRET_BYTES) if profile == "tx" else None
            begun = self.store.begin(rp.id, audience, rp.origin, profile, q)
        except p.ProtocolError as exc:
            raise ControlError(400, "malformed", exc.reason) from exc
        except TransactionError as exc:
            raise ControlError(429, "too_many_pending", exc.reason) from exc
        return {"cid": p.b64encode(begun.cid), "C": p.b64encode(begun.c), "authority": self.config.attest_url,
                "expires_at": rfc3339(begun.expires_at)}

    def redeem(self, rp: RelyingParty, body: object) -> dict[str, Any]:
        if not isinstance(body, dict) or set(body) != {"cid", "R", "audience"}:
            raise ControlError(400, "malformed", "malformed REDEEM")
        try:
            cid, r = p.b64decode(body["cid"], p.CID_BYTES), p.b64decode(body["R"], p.SECRET_BYTES)
            redeemed = self.store.redeem(cid, rp.id, body["audience"], r)
        except (p.ProtocolError, TransactionError) as exc:
            logger.warning("REDEEM refused rp=%s: %s", rp.id, exc.reason)
            raise ControlError(403, "refused", exc.reason) from exc
        claims: dict[str, Any] = {"authorization": list(rp.authorization)}
        if "device_id" in rp.claims:
            claims["device_id"] = redeemed.claims["device_id"]
        if "tags" in rp.claims:
            claims["tags"] = redeemed.claims["tags"]
        logger.info("granted rp=%s audience=%s node=%s", rp.id, body["audience"], redeemed.claims["device_id"])
        return {"active": True, "rp_id": rp.id, "audience": body["audience"], "attested_at": rfc3339(redeemed.attested_at),
                "expires_at": rfc3339(self.store.now() + rp.grant_ttl), "claims": claims}


def peer_uid(connection: socket.socket) -> int:
    """The connecting process's user ID, as reported by the kernel."""
    if hasattr(socket, "SO_PEERCRED"):  # Linux
        _pid, uid, _gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        return uid
    if sys.platform == "darwin" or "bsd" in sys.platform:  # LOCAL_PEERCRED returns struct xucred
        sol_local, local_peercred = 0, 1
        _version, uid = struct.unpack_from("II", connection.getsockopt(sol_local, local_peercred, 256))
        return uid
    raise OSError("peer credentials are not available on this platform")


def check_socket_directory(path: Path) -> None:
    """The socket's directory must be writable only by the Authority's account (SPEC.md 5.2)."""
    info = path.parent.stat()
    if info.st_uid != os.geteuid() or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise PermissionError(f"{path.parent} must be owned by this account and not group- or world-writable")


def unix_control_server(config: AuthorityConfig, store: TransactionStore, path: str, *, socket_mode: int = 0o660) -> socketserver.UnixStreamServer:
    control = Control(config, store)
    socket_path = Path(path)
    check_socket_directory(socket_path)
    if socket_path.is_socket():
        socket_path.unlink()

    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "bytebind"
        sys_version = ""

        def log_message(self, format: str, *args) -> None:
            logger.debug("control: " + format, *args)

        def reply(self, status: int, payload: dict) -> None:
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self) -> None:
            rp = config.rp_for_uid(peer_uid(self.connection))
            if rp is None:
                logger.warning("control refused: uid is not a registered RP")
                return self.reply(403, {"error": "unknown_rp"})
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_CONTROL_BODY:
                return self.reply(413, {"error": "too_large"})
            try:
                self.reply(200, control.handle(rp, self.path, self.rfile.read(length)))
            except ControlError as exc:
                self.reply(exc.status, {"error": exc.code})

    class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True

        def get_request(self):
            connection, _ = super().get_request()
            return connection, ("unix", 0)

    old_umask = os.umask(0o777 & ~socket_mode)
    try:
        server = Server(path, Handler)
    finally:
        os.umask(old_umask)
    os.chmod(path, socket_mode)
    return server


def create_control_app(config: AuthorityConfig, directory: Directory | None = None, store: TransactionStore | None = None) -> FastAPI:
    """The control channel over HTTPS between tailnet nodes. Run with TLS, bound to the tailnet IP."""
    control = Control(config, store or open_store(config))
    directory = directory or LocalAPI(config.tailscale_socket)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.post("/v1/{action}")
    async def control_endpoint(action: str, request: Request):
        peer = request.client.host if request.client else ""
        if not is_tailscale_address(peer):
            return JSONResponse({"error": "unknown_rp"}, 403)
        try:
            rp = config.rp_for_node(identify(directory, peer).peer_id)
        except AttestationError:
            rp = None
        except OSError:
            return JSONResponse({"error": "unavailable"}, 503)
        if rp is None:
            return JSONResponse({"error": "unknown_rp"}, 403)
        try:
            return JSONResponse(control.handle(rp, f"/v1/{action}", await request.body()))
        except ControlError as exc:
            return JSONResponse({"error": exc.code}, exc.status)

    return app


# --- command line ----------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bytebind-authority", description="Run a ByteBind Authority listener.")
    parser.add_argument("--config", required=True, type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("attest", "control-https"):
        sub = commands.add_parser(name)
        sub.add_argument("--host", required=True, help="this node's tailnet address")
        sub.add_argument("--port", required=True, type=int)
        sub.add_argument("--certfile", required=True)
        sub.add_argument("--keyfile", required=True)
    unix = commands.add_parser("control-unix")
    unix.add_argument("--socket", required=True)
    unix.add_argument("--mode", default="660", help="socket permissions, octal (default 660)")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    config = load(args.config)
    if args.command == "control-unix":
        server = unix_control_server(config, open_store(config), args.socket, socket_mode=int(args.mode, 8))
        logger.info("control channel listening on %s", args.socket)
        server.serve_forever()
        return 0
    import uvicorn

    if not is_tailscale_address(args.host):
        parser.error("--host must be this node's tailnet address")
    app = create_attest_app(config) if args.command == "attest" else create_control_app(config)
    uvicorn.run(app, host=args.host, port=args.port, ssl_certfile=args.certfile, ssl_keyfile=args.keyfile,
                proxy_headers=False, server_header=False, workers=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
