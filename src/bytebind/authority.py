"""The ByteBind Authority: attestation for browsers, transaction creation and redemption for relying parties.

Three listeners, each narrowly scoped:

* the attest service (SPEC.md 11-12), HTTPS on the tailnet IP, no proxy in front;
* the control channel over a Unix domain socket, identifying each RP by the
  kernel-reported peer user ID (SPEC.md 5.2, 16.3);
* the control channel over HTTPS between tailnet nodes, identifying each RP by
  its Tailscale node identity.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import secrets
from contextlib import closing
import http.server
import json
import logging
import os
import socket
import socketserver
import stat
import struct
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any, Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from . import protocol as p
from .config import AuthorityConfig, RelyingParty, load
from .limits import PeerLimiter, read_capped
from .store import Attestation, TransactionError, TransactionStore, token_hash
from .tailscale import AttestationError, Directory, LocalAPI, authorize, identify, is_tailscale_address

logger = logging.getLogger("bytebind.authority")
MAX_ATTEST_BODY = 1024
MAX_CONTROL_BODY = 4096


def open_store(config: AuthorityConfig, now: Callable[[], float] = time.time) -> TransactionStore:
    return TransactionStore(config.database, attest_window=config.attest_window, redeem_window=config.redeem_window,
                            max_pending_per_rp=config.max_pending_per_rp, now=now)


# --- attestation -------------------------------------------------------------------------

def attest(config: AuthorityConfig, store: TransactionStore, directory: Directory, peer: str, origin: str, body: object) -> bytes:
    """Checks 3-9 of SPEC.md 11.1 (1 and 2 are the caller's). Returns H2."""
    if not isinstance(body, dict) or set(body) != {"cid", "N", "H1"}:
        raise p.ProtocolError("malformed body")
    cid = p.b64decode(body["cid"], p.CID_BYTES)
    pending = None
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
        store.mark_attested(cid, Attestation(attested.address, attested.peer_id, claims), n=n, h1=h1, generation=pending.generation)  # 9
    except (p.ProtocolError, TransactionError, AttestationError, OSError):
        store.burn(cid, "pending", pending.generation if pending else 0)
        raise
    logger.info("attested rp=%s node=%s name=%s", pending.rp_id, attested.peer_id, attested.name)
    if pending.assurance != "device":
        handoff, completion = store.prepare_handoff(cid)
        if config.person is None:
            row = store.record(cid)
            store.burn(cid, row["status"], row["generation"])
            raise TransactionError("person service unavailable")
        return {"step_up": {"url": config.person.origin + "/step-up/" + pending.rp_id,
                            "handoff": handoff, "completion": completion}}
    store.reserve_delivery(cid)
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
    result_limiter = PeerLimiter(30, minimum_interval=2)
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

    @app.options("/attestation/result")
    @app.options("/attestation")
    def preflight(request: Request):
        origin = trusted(request)
        requested = {h.strip().lower() for h in request.headers.get("access-control-request-headers", "").split(",") if h.strip()}
        if origin is None or request.headers.get("access-control-request-method") != "POST" or requested - {"content-type"}:
            return Response(status_code=403)
        headers = cors(origin) | {"Access-Control-Allow-Methods": "POST", "Access-Control-Allow-Headers": "Content-Type", "Access-Control-Max-Age": "600"}
        if request.headers.get("access-control-request-private-network") == "true":
            headers["Access-Control-Allow-Private-Network"] = "true"
        return Response(status_code=204, headers=headers)

    @app.post("/attestation")
    async def attest_endpoint(request: Request):
        origin = trusted(request)
        if origin is None:
            logger.warning("attestation refused: untrusted Origin or Host")
            return refused()
        peer = request.client.host if request.client else ""  # the socket peer; proxy headers are off
        if not limiter.allow(peer):
            return JSONResponse({"error": "rate_limited"}, 429, headers=cors(origin) | {"Retry-After": "60"})
        if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":  # check 2
            return refused(origin=origin)
        raw = await read_capped(request, MAX_ATTEST_BODY)
        if raw is None:
            return refused(origin=origin)
        try:
            h2 = attest(config, store, directory, peer, origin, p.json_body(raw))
        except (p.ProtocolError, TransactionError, AttestationError, ValueError) as exc:
            logger.warning("attestation refused peer=%s: %s", peer, getattr(exc, "reason", "malformed JSON"))
            return refused(origin=origin)
        except OSError:
            logger.exception("attestation failed: tailscaled is unavailable")
            return refused(503, origin)
        return JSONResponse(h2 if isinstance(h2,dict) else {"H2": p.b64encode(h2)}, status_code=202 if isinstance(h2,dict) else 200, headers=cors(origin))

    @app.post("/attestation/result")
    async def result_endpoint(request: Request):
        origin = trusted(request)
        if origin is None:
            return refused()
        peer = request.client.host if request.client else ""
        if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
            return refused(origin=origin)
        raw = await read_capped(request, MAX_ATTEST_BODY)
        try:
            body = p.json_body(raw or b"")
            if set(body) != {"cid", "completion", "N", "H1"}:
                raise ValueError()
            cid = p.b64decode(body["cid"],16)
            row = store.record(cid)
            if row["allowed_origin"] != origin or row["attested_ip"] != p.ip_bytes(peer) or not p.equal(row["completion_hash"] or b"",token_hash(body["completion"])):
                raise ValueError()
            if not p.equal(row["accepted_n"],p.b64decode(body["N"],32)) or not p.equal(row["accepted_h1"],p.b64decode(body["H1"],32)):
                raise ValueError()
            if row["delivery_reserved"] or row["status"] in {"burned", "redeemed"}:
                raise ValueError()
            if not result_limiter.allow(peer + ":" + body["cid"]):
                return refused(429, origin)
            # One held result call per attempt, rather than one tailscaled call
            # per pending poll. A second request is refused without state mutation.
            if cid in app.state.result_pending:
                return refused(429, origin)
            app.state.result_pending.add(cid)
            try:
                until = asyncio.get_running_loop().time() + 10
                while row["status"] in {"base_attested", "stepup_pending"} and row["overall_expires_at"] >= store.now() and asyncio.get_running_loop().time() < until:
                    await asyncio.sleep(.1)
                    row = store.record(cid)
                if row["status"] in {"base_attested", "stepup_pending"} and row["overall_expires_at"] >= store.now():
                    return JSONResponse({"pending":True},202,headers=cors(origin))
                verify_device(config, directory, peer, row)
                row = store.reserve_delivery(cid)
                h2 = p.seal_h2(row["profile"],row["c"],cid,row["accepted_n"],row["accepted_h1"],row["attested_ip"],row["s"])
                return JSONResponse({"H2":p.b64encode(h2)},headers=cors(origin))
            finally:
                app.state.result_pending.discard(cid)
        except (p.ProtocolError, TransactionError, AttestationError, ValueError, TypeError):
            return refused(origin=origin)
        except OSError:
            return refused(503,origin)

    app.state.result_pending = set()
    return app


def verify_device(config, directory, peer, row):
    device = identify(directory, peer)
    rp = config.rps.get(row["rp_id"])
    if rp is None or device.peer_id != row["attested_peer_id"] or p.ip_bytes(peer) != row["attested_ip"]:
        raise TransactionError("device context changed")
    authorize(device,rp.policy)
    return device


# --- transaction creation and redemption ----------------------------------------------------

class ControlError(Exception):
    def __init__(self, status: int, code: str, reason: str):
        super().__init__(reason)
        self.status, self.code, self.reason = status, code, reason


class Control:
    """Transport-independent handling of control-channel requests from an identified RP."""

    def __init__(self, config: AuthorityConfig, store: TransactionStore, directory: Directory | None = None):
        self.config, self.store = config, store
        self.directory = directory or LocalAPI(config.tailscale_socket)

    def handle(self, rp: RelyingParty, path: str, raw: bytes) -> dict[str, Any]:
        if len(raw) > MAX_CONTROL_BODY:
            raise ControlError(413, "too_large", "body too large")
        try:
            body = p.json_body(raw)
        except (ValueError, p.ProtocolError) as exc:
            raise ControlError(400, "malformed", "malformed JSON") from exc
        if path == "/v1/transaction":
            return self.begin(rp, body)
        if path == "/v1/redemption":
            return self.redeem(rp, body)
        if path == "/v1/person-validation":
            return self.validate(rp, body)
        if path == "/v1/person-logout":
            if set(body) != {"lease_id"}:
                raise ControlError(400,"malformed","invalid logout")
            self.store.end_association(rp.id, body["lease_id"])
            return {"active":False}
        raise ControlError(404, "not_found", "unknown path")

    def begin(self, rp: RelyingParty, body: object) -> dict[str, Any]:
        if not isinstance(body, dict) or not {"protocol", "draft", "audience", "profile", "assurance"} <= set(body) <= {"protocol", "draft", "audience", "profile", "assurance", "Q", "allowed_origin", "person_max_age", "identify", "lease_id"}:
            raise ControlError(400, "malformed", "malformed transaction request")
        if type(body["protocol"]) is not int or body["protocol"] != 1 or body["draft"] != p.DRAFT:
            raise ControlError(400,"unsupported","unsupported draft schema")
        audience, profile = body["audience"], body["profile"]
        if not isinstance(audience,str) or not isinstance(profile,str):
            raise ControlError(400,"malformed","invalid scope")
        assurance = body["assurance"]
        if not isinstance(assurance,str) or assurance not in rp.assurances:
            raise ControlError(403,"refused","assurance not registered")
        identity = body.get("identify",False)
        if type(identity) is not bool or (identity and (assurance == "device" or "person_subject" not in rp.claims)):
            raise ControlError(403,"refused","identity not registered")
        age = body.get("person_max_age")
        if assurance != "device" and profile == "session":
            if type(age) is not int or not 0 < age <= rp.person_max_age:
                raise ControlError(400,"malformed","invalid person maximum age")
        elif age is not None:
            raise ControlError(400,"malformed","person age forbidden")
        lease_id = body.get("lease_id")
        if profile == "session":
            try:
                p.b64decode(lease_id,32)
            except p.ProtocolError as exc:
                raise ControlError(400,"malformed","session lease binding required") from exc
        elif lease_id is not None:
            raise ControlError(400,"malformed","transaction lease forbidden")
        if audience not in rp.audiences:
            raise ControlError(403, "refused", "audience not registered for this RP")
        if profile not in p.PROFILES or (profile == "tx") != ("Q" in body):
            raise ControlError(400, "malformed", "profile and Q disagree")
        if "allowed_origin" in body and body["allowed_origin"] != rp.origin:
            raise ControlError(403, "refused", "allowed_origin is not this RP's registered origin")
        try:
            q = p.b64decode(body["Q"], p.SECRET_BYTES) if profile == "tx" else None
            begun = self.store.begin(rp.id, audience, rp.origin, profile, q, assurance=assurance, person_max_age=age, identify_person=identity, lease_id=lease_id)
        except p.ProtocolError as exc:
            raise ControlError(400, "malformed", exc.reason) from exc
        except TransactionError as exc:
            raise ControlError(429, "too_many_pending", exc.reason) from exc
        # Relative durations only on the control channel: host clocks need not agree (SPEC.md 10.1).
        return {"protocol":1, "draft":p.DRAFT, "rp_id":rp.id, **({"person_origin":self.config.person.origin} if assurance != "device" else {}), "cid": p.b64encode(begun.cid), "C": p.b64encode(begun.c), "authority": self.config.attest_url,
                "expires_in": max(0, round(begun.expires_at - self.store.now()))}

    def redeem(self, rp: RelyingParty, body: object) -> dict[str, Any]:
        if not isinstance(body, dict) or set(body) != {"cid", "R", "audience"}:
            raise ControlError(400, "malformed", "malformed redemption request")
        if not isinstance(body["audience"],str) or body["audience"] not in rp.audiences:
            raise ControlError(403,"refused","unregistered audience")
        try:
            cid, r = p.b64decode(body["cid"], p.CID_BYTES), p.b64decode(body["R"], p.SECRET_BYTES)
            row = self.store.record(cid)
            if row["rp_id"] == rp.id and row["audience"] == body["audience"] and row["status"] == "redeemable":
                address = ipaddress.IPv6Address(row["attested_ip"])
                try:
                    current = verify_device(self.config,self.directory,str(address.ipv4_mapped or address),row)
                except (AttestationError,TransactionError,OSError):
                    self.store.burn(cid,"redeemable",row["generation"])
                    raise TransactionError("device authorization unavailable") from None
                if self.store._write("UPDATE transactions SET attested_claims=? WHERE cid=? AND status='redeemable' AND generation=?",(json.dumps({"device_id":current.peer_id,"tags":list(current.tags)}),cid,row["generation"])) != 1:
                    raise TransactionError("redemption race lost")
            redeemed = self.store.redeem(cid, rp.id, body["audience"], r)
        except (p.ProtocolError, TransactionError) as exc:
            logger.warning("redemption refused rp=%s: %s", rp.id, exc.reason)
            raise ControlError(403, "refused", exc.reason) from exc
        claims: dict[str, Any] = {"authorization": list(rp.authorization)}
        if "device_id" in rp.claims:
            claims["device_id"] = redeemed.claims["device_id"]
        if "tags" in rp.claims:
            claims["tags"] = redeemed.claims["tags"]
        logger.info("granted rp=%s audience=%s node=%s", rp.id, body["audience"], redeemed.claims["device_id"])
        row = redeemed.transaction
        assurance = {"device_attested":True,"user_present":bool(row["user_present"]),"user_verified":bool(row["user_verified"])}
        extra = {}
        if row["assurance"] != "device":
            if row["identify_person"]:
                key = self.store._read("SELECT value FROM authority_keys WHERE name='pairwise'")[0]
                claims["person_subject"] = p.pairwise_subject(key,rp.id,row["subject_id"])
            if row["profile"] == "tx":
                assurance["fresh_for_transaction"] = True
            else:
                assurance.update(person_fresh=True,person_expires_in=max(0,row["person_deadline"]-self.store.now()))
                extra["person_association"] = self.store.create_association(row)
        if row["profile"] == "session":
            extra["device_grant"] = self.store.device_reference(row,rp.grant_ttl)
        return {"protocol":1,"draft":p.DRAFT,"active": True, "rp_id": rp.id, "audience": body["audience"], "expires_in": rp.grant_ttl, "claims": claims,"assurance":assurance, **extra}

    def validate(self, rp, body):
        if set(body) != {"audience","lease_id","association","device_grant"} or not isinstance(body["audience"],str) or body["audience"] not in rp.audiences:
            raise ControlError(400,"malformed","invalid association request")
        try:
            return self.store.validate_association(rp.id,body["audience"],body["lease_id"],body["association"],body["device_grant"])
        except (TransactionError,p.ProtocolError):
            raise ControlError(403,"refused","association unavailable") from None


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


def unix_control_server(config: AuthorityConfig, store: TransactionStore, path: str, *, socket_mode: int = 0o660, directory: Directory | None = None) -> socketserver.UnixStreamServer:
    control = Control(config, store, directory)
    socket_path = Path(path)
    check_socket_directory(socket_path)
    if socket_path.is_socket():
        socket_path.unlink()

    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "bytebind"
        sys_version = ""
        timeout = 10  # a stalled client must not hold a handler thread

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
            declared = self.headers.get("Content-Length") or "0"
            if not declared.isdigit():
                return self.reply(400, {"error": "malformed"})
            length = int(declared)
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
    directory = directory or LocalAPI(config.tailscale_socket)
    control = Control(config, store or open_store(config), directory)
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
        raw = await read_capped(request, MAX_CONTROL_BODY)
        if raw is None:
            return JSONResponse({"error": "too_large"}, 413)
        try:
            return JSONResponse(control.handle(rp, f"/v1/{action}", raw))
        except ControlError as exc:
            return JSONResponse({"error": exc.code}, exc.status)

    return app


# --- command line ----------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bytebind-authority", description="Run a ByteBind Authority listener.")
    parser.add_argument("--config", required=True, type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("attest", "person", "control-https"):
        sub = commands.add_parser(name)
        sub.add_argument("--host", required=True, help="this node's tailnet address")
        sub.add_argument("--port", required=True, type=int)
        sub.add_argument("--certfile", required=True)
        sub.add_argument("--keyfile", required=True)
    unix = commands.add_parser("control-unix")
    unix.add_argument("--socket", required=True)
    unix.add_argument("--mode", default="660", help="socket permissions, octal (default 660)")
    invite = commands.add_parser("invite",help="Create a new independently named person and one-use enrollment invite")
    invite.add_argument("--name",required=True)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    config = load(args.config)
    if args.command == "invite":
        from .person import PersonService
        if Path(config.database).exists() and Path(config.database).stat().st_uid != os.geteuid():
            parser.error("invites must be issued by the Authority database owner")
        token,subject = PersonService(config,open_store(config)).invite(args.name)
        print("Subject:",subject)
        # Explicit operator output, never a logger or a URL query.
        print("One-use invite (15 minutes):",token)
        return 0
    if args.command == "control-unix":
        server = unix_control_server(config, open_store(config), args.socket, socket_mode=int(args.mode, 8))
        logger.info("control channel listening on %s", args.socket)
        server.serve_forever()
        return 0
    import uvicorn

    if not is_tailscale_address(args.host):
        parser.error("--host must be this node's tailnet address")
    if args.command == "person":
        from .person_http import create_person_app
        app = create_person_app(config)
    else:
        app = create_attest_app(config) if args.command == "attest" else create_control_app(config)
    uvicorn.run(app, host=args.host, port=args.port, ssl_certfile=args.certfile, ssl_keyfile=args.keyfile,
                proxy_headers=False, server_header=False, workers=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
