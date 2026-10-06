"""Relying-party side: talk to the Authority, and keep the RP's own state.

The RP never sees the Authority's database. It keeps only what SPEC.md assigns
to it: state-cookie hashes for outstanding ceremonies, stored requests for the
transaction-bound profile, and session leases capped at the grant's expiry.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
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
    def __init__(self, path: str, timeout: float):
        super().__init__("bytebind-authority", timeout=timeout)
        self.socket_path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


class AuthorityClient:
    """The control channel: ``unix:/path/to/socket`` or ``https://authority.tailnet.ts.net:port``.

    Nothing else is accepted (SPEC.md 5.2). HTTPS verifies the Authority's
    certificate with the system trust store, or with ``cafile``.
    """

    def __init__(self, endpoint: str, *, timeout: float = 5.0, cafile: str | None = None):
        self.endpoint, self.timeout = endpoint, timeout
        if endpoint.startswith("unix:"):
            self.socket_path = endpoint[len("unix:"):]
            if not self.socket_path.startswith("/"):
                raise ValueError("unix: endpoints need an absolute socket path")
            self.url = None
        else:
            self.url = urllib.parse.urlsplit(endpoint)
            if self.url.scheme != "https" or not self.url.hostname or self.url.path not in ("", "/"):
                raise ValueError("the control channel must be unix:/path or https://host[:port]")
            self.context = ssl.create_default_context(cafile=cafile)

    def _connection(self) -> http.client.HTTPConnection:
        if self.url is None:
            return _UnixHTTPConnection(self.socket_path, self.timeout)
        return http.client.HTTPSConnection(self.url.hostname, self.url.port or 443, timeout=self.timeout, context=self.context)

    def _post(self, path: str, body: dict) -> dict:
        data = json.dumps(body).encode()
        with closing(self._connection()) as connection:
            connection.request("POST", path, body=data, headers={"Content-Type": "application/json", "Content-Length": str(len(data))})
            response = connection.getresponse()
            payload = json.loads(response.read(64 * 1024) or b"{}")
        if response.status != 200:
            raise AuthorityError(response.status, payload.get("error", "unknown") if isinstance(payload, dict) else "unknown")
        return payload

    def begin(self, audience: str, profile: p.Profile = "session", q: bytes | None = None) -> dict:
        """Create a transaction; returns the RP-scoped transaction material."""
        body: dict[str, Any] = {"audience": audience, "profile": profile}
        if q is not None:
            body["Q"] = p.b64encode(q)
        return self._post("/v1/transaction", body)

    def redeem(self, cid: str, r: str, audience: str) -> dict:
        """Redeem a proof; returns the grant."""
        return self._post("/v1/redemption", {"cid": cid, "R": r, "audience": audience})


def _digest(value: str) -> bytes:
    return hashlib.sha256(value.encode()).digest()


@dataclass(frozen=True)
class Lease:
    device_id: str | None
    claims: dict
    expires_at: float


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
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS leases (
    token_hash BLOB PRIMARY KEY,
    device_id TEXT,
    claims TEXT NOT NULL,
    created_at REAL NOT NULL,
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

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=5, isolation_level=None)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def check_origin(self, origin: str | None) -> None:
        if origin != self.origin:
            raise CeremonyError("Origin is not this RP's origin")

    # Access request -> transaction creation -> challenge
    def challenge(self, origin: str | None, *, request: Any = None, q: bytes | None = None) -> tuple[dict, str]:
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
        transaction = self.authority.begin(self.audience, profile, q)
        state = p.b64encode(secrets.token_bytes(32))
        expires = self.now() + int(transaction["expires_in"]) + 15  # attest window plus the redeem window and slack
        with closing(self._connect()) as connection:
            connection.execute(
                "INSERT INTO ceremonies (cid, state_hash, profile, request, expires_at) VALUES (?, ?, ?, ?, ?)",
                (transaction["cid"], _digest(state), profile, json.dumps(request) if profile == "tx" else None, expires),
            )
        return {"cid": transaction["cid"], "C": transaction["C"], "authority": transaction["authority"]}, state

    # Proof submission -> redemption -> grant -> application response
    def accept_proof(self, origin: str | None, body: object, state: str | None, previous_session: str | None = None) -> Accepted:
        self.check_origin(origin)
        if not isinstance(body, dict) or set(body) != {"cid", "R"} or not all(isinstance(v, str) for v in body.values()):
            raise CeremonyError("malformed proof submission")
        cid = body["cid"]
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT state_hash, profile, request, expires_at FROM ceremonies WHERE cid = ?", (cid,)).fetchone()
            if row is None:
                raise CeremonyError("unknown or already completed ceremony")
            state_hash, profile, request, expires_at = row
            # Check the state cookie before claiming: a caller without it cannot cancel someone else's ceremony.
            if not state or not hmac.compare_digest(_digest(state), state_hash):
                raise CeremonyError("state cookie does not match")
            # Claim the ceremony atomically: a retried proof submission can never execute twice.
            if connection.execute("DELETE FROM ceremonies WHERE cid = ? AND state_hash = ?", (cid, state_hash)).rowcount != 1:
                raise CeremonyError("unknown or already completed ceremony")
        if expires_at < self.now():
            raise CeremonyError("ceremony expired")
        try:
            grant = self.authority.redeem(cid, body["R"], self.audience)
        except AuthorityError as exc:
            raise CeremonyError(f"redemption refused: {exc.code}") from exc
        if grant.get("active") is not True or grant.get("audience") != self.audience:
            raise CeremonyError("grant is not active for this audience")
        now = self.now()  # the grant's expires_in counts from receipt, on this host's clock
        grant_expires = now + int(grant["expires_in"])
        if profile == "tx":
            return Accepted(grant, None, None, json.loads(request))
        lease = Lease(grant["claims"].get("device_id"), grant["claims"], min(now + self.lease_seconds, grant_expires))
        token = p.b64encode(secrets.token_bytes(32))
        with closing(self._connect()) as connection:
            if previous_session:
                connection.execute("DELETE FROM leases WHERE token_hash = ?", (_digest(previous_session),))
            connection.execute(
                "INSERT INTO leases (token_hash, device_id, claims, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                (_digest(token), lease.device_id, json.dumps(lease.claims), now, lease.expires_at),
            )
        return Accepted(grant, token, lease, None)

    def session(self, token: str | None) -> Lease | None:
        if not token:
            return None
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT device_id, claims, expires_at FROM leases WHERE token_hash = ? AND expires_at >= ?", (_digest(token), self.now())
            ).fetchone()
        return Lease(row[0], json.loads(row[1]), row[2]) if row else None

    def end_session(self, token: str | None) -> None:
        if token:
            with closing(self._connect()) as connection:
                connection.execute("DELETE FROM leases WHERE token_hash = ?", (_digest(token),))
