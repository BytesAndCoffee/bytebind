"""Relying-party side: talk to the Authority, and keep the RP's own state.

The RP never sees the Authority's database. It keeps only what SPEC.md assigns
to it: state-cookie hashes for outstanding ceremonies, stored requests for the
transaction-bound profile, and session leases capped at the grant's expiry.
"""

from __future__ import annotations

import hashlib
import os
import stat
import hmac
import http.client
import json
import math
import secrets
import socket
import sqlite3
import ssl
import time
import urllib.parse
from contextlib import closing
from dataclasses import dataclass
from typing import Any, Callable

from . import protocol as p


class AuthorityError(Exception):
    def __init__(self, status: int, code: str):
        super().__init__(f"Authority refused with HTTP {status}: {code}")
        self.status, self.code = status, code


class CeremonyError(Exception):
    """The ceremony failed; ``reason`` is for logs, clients get a generic failure."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float, authority_uid: int):
        super().__init__("bytebind-authority", timeout=timeout)
        self.socket_path, self.authority_uid = path, authority_uid

    def connect(self) -> None:
        from pathlib import Path
        from .authority import peer_uid
        path = Path(self.socket_path)
        parent = path.parent.stat()
        info = path.lstat()
        if parent.st_uid not in {0,self.authority_uid} or parent.st_mode & (stat.S_IWGRP|stat.S_IWOTH) or not stat.S_ISSOCK(info.st_mode) or info.st_uid != self.authority_uid:
            raise PermissionError("untrusted Authority socket or directory")
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        try:
            self.sock.connect(self.socket_path)
            if peer_uid(self.sock) != self.authority_uid:
                raise PermissionError("Authority UID does not match")
        except BaseException:
            self.sock.close()
            raise


class AuthorityClient:
    """The control channel: ``unix:/path/to/socket`` or ``https://authority.tailnet.ts.net:port``.

    Nothing else is accepted (SPEC.md 5.2). HTTPS verifies the Authority's
    certificate with the system trust store, or with ``cafile``.
    """

    def __init__(self, endpoint: str, *, timeout: float = 5.0, cafile: str | None = None, authority_uid: int | None = None):
        self.endpoint, self.timeout = endpoint, timeout
        self.authority_uid = os.geteuid() if authority_uid is None else authority_uid
        if endpoint.startswith("unix:"):
            self.socket_path = endpoint[len("unix:"):]
            if not self.socket_path.startswith("/"):
                raise ValueError("unix: endpoints need an absolute socket path")
            self.url = None
        else:
            self.url = urllib.parse.urlsplit(endpoint)
            if self.url.scheme != "https" or not self.url.hostname or self.url.path not in ("", "/") or self.url.username is not None or self.url.password is not None or self.url.query or self.url.fragment:
                raise ValueError("the control channel must be unix:/path or https://host[:port]")
            self.context = ssl.create_default_context(cafile=cafile)

    def _connection(self) -> http.client.HTTPConnection:
        if self.url is None:
            return _UnixHTTPConnection(self.socket_path, self.timeout, self.authority_uid)
        return http.client.HTTPSConnection(self.url.hostname, self.url.port or 443, timeout=self.timeout, context=self.context)

    def _post(self, path: str, body: dict) -> dict:
        data = json.dumps(body).encode()
        with closing(self._connection()) as connection:
            connection.request("POST", path, body=data, headers={"Content-Type": "application/json", "Content-Length": str(len(data))})
            response = connection.getresponse()
            raw = response.read(64 * 1024 + 1)
            if len(raw) > 64 * 1024:
                raise AuthorityError(502,"oversized_response")
            try:
                payload = p.json_body(raw or b"{}")
            except (ValueError,p.ProtocolError):
                raise AuthorityError(502,"malformed_response") from None
        if response.status != 200:
            raise AuthorityError(response.status, payload.get("error", "unknown") if isinstance(payload, dict) else "unknown")
        return payload

    def begin(self, audience: str, profile: p.Profile = "session", q: bytes | None = None, *, assurance="device", person_max_age=None, identify=False, lease_id=None) -> dict:
        """Create a transaction; returns the RP-scoped transaction material."""
        body: dict[str, Any] = {"protocol":1,"draft":p.DRAFT,"audience": audience, "profile": profile,"assurance":assurance}
        if profile == "session":
            body["lease_id"] = lease_id or p.b64encode(secrets.token_bytes(32))
        if person_max_age is not None:
            body["person_max_age"] = person_max_age
        if identify:
            body["identify"] = True
        if q is not None:
            body["Q"] = p.b64encode(q)
        return self._post("/v1/transaction", body)

    def redeem(self, cid: str, r: str, audience: str) -> dict:
        """Redeem a proof; returns the grant."""
        return self._post("/v1/redemption", {"cid": cid, "R": r, "audience": audience})


def _supports_evidence(evidence, assurance, *, transaction=False):
    if not isinstance(evidence,dict) or evidence.get("device_attested") is not True:
        return False
    if assurance == "device":
        return True
    return (evidence.get("user_present") is True and
            (assurance != "verification" or evidence.get("user_verified") is True) and
            (not transaction or evidence.get("fresh_for_transaction") is True))


def _digest(value: str) -> bytes:
    return hashlib.sha256(value.encode()).digest()


@dataclass(frozen=True)
class Lease:
    device_id: str | None
    claims: dict
    expires_at: float
    context: dict | None = None


@dataclass(frozen=True)
class Accepted:
    grant: dict
    session_token: str | None  # session profile
    lease: Lease | None  # session profile
    request: Any  # transaction-bound profile: the stored request, to execute exactly once


SCHEMA = """
CREATE TABLE IF NOT EXISTS ceremonies (
    cid TEXT PRIMARY KEY,
    state_hash BLOB NOT NULL,
    profile TEXT NOT NULL,
    request TEXT,
    context TEXT NOT NULL DEFAULT '{}',
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS leases (
    token_hash BLOB PRIMARY KEY,
    device_id TEXT,
    claims TEXT NOT NULL,
    created_at REAL NOT NULL,
    context TEXT NOT NULL DEFAULT '{}',
    expires_at REAL NOT NULL
);
"""


class RelyingParty:
    """Challenges and proof submissions for one public origin.

    ``lease_seconds`` bounds a session after each successful ceremony; it is
    further capped at the grant's ``expires_in``, measured on this host's clock
    (SPEC.md 13.2, 15.1). Expiry stays server-side: nothing this class returns
    for the Client carries it (SPEC.md 15.2).
    """

    def __init__(self, authority: AuthorityClient, *, origin: str, audience: str, database: str,
                 lease_seconds: int = 180, max_pending: int = 500, now: Callable[[], float] = time.time):
        if lease_seconds < 90:
            raise ValueError("lease_seconds must be at least 90: clients renew every 60 seconds")
        self.authority, self.origin, self.audience = authority, origin, audience
        self.database, self.lease_seconds, self.max_pending, self.now = database, lease_seconds, max_pending, now
        with closing(self._connect()) as connection:
            connection.executescript(SCHEMA)
            for table in ("ceremonies","leases"):
                columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
                if "context" not in columns:
                    connection.execute(f"ALTER TABLE {table} ADD COLUMN context TEXT NOT NULL DEFAULT '{{}}'")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=5, isolation_level=None)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def check_origin(self, origin: str | None) -> None:
        if origin != self.origin:
            raise CeremonyError("Origin is not this RP's origin")

    # Access request -> transaction creation -> challenge
    def challenge(self, origin: str | None, *, request: Any = None, q: bytes | None = None, assurance="device", person_max_age=None, identify=False, previous_session=None) -> tuple[dict, str]:
        """Start a ceremony. Returns the challenge (no expiry) and a state token for an HttpOnly cookie.

        For the transaction-bound profile pass the protected ``request`` (JSON-serializable,
        enough to execute it later) and its digest ``q``; the RP stores the request itself.
        """
        self.check_origin(origin)
        profile: p.Profile = "tx" if q is not None else "session"
        now = self.now()
        with closing(self._connect()) as connection:
            connection.execute("DELETE FROM ceremonies WHERE expires_at < ?", (now,))
            connection.execute("DELETE FROM leases WHERE expires_at < ?", (now,))
            if connection.execute("SELECT COUNT(*) FROM ceremonies").fetchone()[0] >= self.max_pending:
                raise CeremonyError("too many pending ceremonies")
        if assurance not in p.ASSURANCES or (person_max_age is not None and (assurance == "device" or profile == "tx")):
            raise CeremonyError("invalid assurance options")
        previous = self.session(previous_session)
        context = dict(previous.context or {}) if previous and assurance == "device" else {}
        context.setdefault("lease_id",p.b64encode(secrets.token_bytes(32)))
        lease_id = context["lease_id"] if profile == "session" else None
        transaction = self.authority.begin(self.audience, profile, q,assurance=assurance,person_max_age=person_max_age,identify=identify,lease_id=lease_id)
        if transaction.get("protocol") != 1 or transaction.get("draft") != p.DRAFT:
            raise CeremonyError("unsupported Authority draft")
        metadata = {"assurance":assurance,"person_max_age":person_max_age,"identify":identify,"lease_id":lease_id,
                    "authority":transaction.get("control_authority",self.authority.endpoint if hasattr(self.authority,"endpoint") else None),
                    "rp_id":transaction.get("rp_id"),"previous_hash":_digest(previous_session).hex() if previous_session else None}
        state = p.b64encode(secrets.token_bytes(32))
        expires = self.now() + int(transaction["expires_in"]) + (165 if assurance != "device" else 15)  # attest window plus the redeem window and slack
        with closing(self._connect()) as connection:
            connection.execute(
                "INSERT INTO ceremonies (cid, state_hash, profile, request, context, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
                (transaction["cid"], _digest(state), profile, json.dumps(request) if profile == "tx" else None, json.dumps(metadata), expires),
            )
        return {key:transaction[key] for key in ("protocol","draft","cid","C","authority","person_origin") if key in transaction}, state

    # Proof submission -> redemption -> grant -> application response
    def accept_proof(self, origin: str | None, body: object, state: str | None, previous_session: str | None = None) -> Accepted:
        self.check_origin(origin)
        if not isinstance(body, dict) or set(body) != {"cid", "R"} or not all(isinstance(v, str) for v in body.values()):
            raise CeremonyError("malformed proof submission")
        cid = body["cid"]
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT state_hash, profile, request, context, expires_at FROM ceremonies WHERE cid = ?", (cid,)).fetchone()
            if row is None:
                raise CeremonyError("unknown or already completed ceremony")
            state_hash, profile, request, context_raw, expires_at = row
            context = json.loads(context_raw)
            # Check the state cookie before claiming: a caller without it cannot cancel someone else's ceremony.
            if not state or not hmac.compare_digest(_digest(state), state_hash):
                raise CeremonyError("state cookie does not match")
            # Claim the ceremony atomically: a retried proof submission can never execute twice.
            if connection.execute("DELETE FROM ceremonies WHERE cid = ? AND state_hash = ?", (cid, state_hash)).rowcount != 1:
                raise CeremonyError("unknown or already completed ceremony")
        if expires_at < self.now():
            raise CeremonyError("ceremony expired")
        try:
            client = self.authority
            if context.get("authority") and hasattr(self.authority,"pinned"):
                client = self.authority.pinned(context["authority"])
            grant = client.redeem(cid, body["R"], self.audience)
        except AuthorityError as exc:
            raise CeremonyError(f"redemption refused: {exc.code}") from exc
        if grant.get("protocol") != 1 or grant.get("draft") != p.DRAFT or grant.get("active") is not True or grant.get("audience") != self.audience or (context.get("rp_id") and grant.get("rp_id") != context["rp_id"]):
            raise CeremonyError("grant is not active for this audience")
        now = self.now()  # the grant's expires_in counts from receipt, on this host's clock
        if not _supports_evidence(grant.get("assurance"),context.get("assurance","device"),transaction=profile == "tx"):
            raise CeremonyError("missing required assurance")
        if context.get("identify") and not isinstance(grant.get("claims",{}).get("person_subject"),str):
            raise CeremonyError("missing person identity")
        ttl = grant.get("expires_in")
        if type(ttl) is not int or not 90 <= ttl <= 300 or not isinstance(grant.get("claims"),dict):
            raise CeremonyError("invalid grant lifetime or claims")
        grant_expires = now + ttl
        if profile == "tx":
            return Accepted(grant, None, None, json.loads(request))
        previous = self.session(previous_session)
        if context.get("previous_hash") != (_digest(previous_session).hex() if previous_session else None):
            raise CeremonyError("renewal changed browser lease")
        new_context = {"lease_id":context["lease_id"],"authority":context.get("authority"),"device_grant":grant.get("device_grant")}
        p.b64decode(new_context["device_grant"],32)
        if grant.get("person_association"):
            evidence = grant["assurance"]
            remaining = evidence.get("person_expires_in")
            if evidence.get("person_fresh") is not True or type(remaining) not in (float,int) or not math.isfinite(remaining) or not 0 < remaining <= (context.get("person_max_age") or 0):
                raise CeremonyError("invalid person evidence lifetime")
            p.b64decode(grant["person_association"],32)
            new_context.update(association=grant["person_association"],person_at=now,person_deadline=now+remaining,person_assurance=evidence,person_claims={k:v for k,v in grant["claims"].items() if k.startswith("person_")})
        elif previous and previous.context and context["assurance"] == "device" and previous.context.get("lease_id") == context["lease_id"]:
            new_context.update({key:value for key,value in previous.context.items() if key in {"association","person_at","person_deadline","person_assurance","person_claims"}})
        lease = Lease(grant["claims"].get("device_id"), grant["claims"], min(now + self.lease_seconds, grant_expires),new_context)
        token = p.b64encode(secrets.token_bytes(32))
        with closing(self._connect()) as connection:
            if previous_session:
                connection.execute("DELETE FROM leases WHERE token_hash = ?", (_digest(previous_session),))
            connection.execute(
                "INSERT INTO leases (token_hash, device_id, claims, created_at, context, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
                (_digest(token), lease.device_id, json.dumps(lease.claims), now, json.dumps(new_context), lease.expires_at),
            )
        if previous and previous.context and previous.context.get("association") and previous.context.get("lease_id") != new_context["lease_id"]:
            client._post("/v1/person-logout",{"lease_id":previous.context["lease_id"]})
        return Accepted(grant, token, lease, None)

    def session(self, token: str | None) -> Lease | None:
        if not token:
            return None
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT device_id, claims, expires_at, context FROM leases WHERE token_hash = ? AND expires_at >= ?", (_digest(token), self.now())
            ).fetchone()
        return Lease(row[0], json.loads(row[1]), row[2],json.loads(row[3])) if row else None

    def require_person(self, token, assurance, max_age, identify=False):
        lease = self.session(token)
        context = lease.context or {} if lease else {}
        now = self.now()
        if not lease or not context.get("association") or context.get("person_deadline",0) <= now or now-context.get("person_at",0) > max_age or not _supports_evidence(context.get("person_assurance"),assurance):
            raise CeremonyError("person step-up required")
        client = self.authority.pinned(context["authority"]) if hasattr(self.authority,"pinned") else self.authority
        result = client._post("/v1/person-validation", {"audience":self.audience,"lease_id":context["lease_id"],"association":context["association"],"device_grant":context["device_grant"]})
        remaining = result.get("assurance",{}).get("person_expires_in")
        if result.get("active") is not True or not _supports_evidence(result.get("assurance"),assurance) or type(remaining) not in (float,int) or not math.isfinite(remaining) or remaining<=0:
            raise CeremonyError("person association invalid")
        claims = dict(lease.claims)
        if identify:
            if not isinstance(context.get("person_claims",{}).get("person_subject"),str):
                raise CeremonyError("person identity missing")
            claims.update(context["person_claims"])
        return Lease(lease.device_id,claims,lease.expires_at,context)

    def end_session(self, token: str | None) -> None:
        if token:
            lease = self.session(token)
            with closing(self._connect()) as connection:
                connection.execute("DELETE FROM leases WHERE token_hash = ?", (_digest(token),))

            if lease and lease.context and lease.context.get("association"):
                client = self.authority.pinned(lease.context["authority"]) if hasattr(self.authority,"pinned") else self.authority
                client._post("/v1/person-logout", {"lease_id":lease.context["lease_id"]})
