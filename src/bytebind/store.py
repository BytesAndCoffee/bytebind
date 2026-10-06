"""The Authority's transaction store (SPEC.md sections 11.2, 13.1, 14). Only the Authority opens it."""

from __future__ import annotations

import json
import secrets
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass
from typing import Callable

from . import protocol as p

SCHEMA = """
CREATE TABLE IF NOT EXISTS transactions (
    cid BLOB PRIMARY KEY,
    c BLOB NOT NULL,
    s BLOB NOT NULL,
    rp_id TEXT NOT NULL,
    audience TEXT NOT NULL,
    allowed_origin TEXT NOT NULL,
    profile TEXT NOT NULL CHECK (profile IN ('session', 'tx')),
    q BLOB,
    status TEXT NOT NULL CHECK (status IN ('pending', 'attested', 'redeemed', 'burned')),
    created_at REAL NOT NULL,
    challenge_expires_at REAL NOT NULL,
    attested_at REAL,
    attested_ip BLOB,
    attested_peer_id TEXT,
    attested_claims TEXT,
    redeem_expires_at REAL,
    redeemed_at REAL
);
CREATE INDEX IF NOT EXISTS transactions_rp_status ON transactions (rp_id, status);
"""


@dataclass(frozen=True)
class Begun:
    cid: bytes
    c: bytes
    expires_at: float


@dataclass(frozen=True)
class Pending:
    rp_id: str
    c: bytes
    s: bytes
    allowed_origin: str
    profile: p.Profile
    q: bytes | None


@dataclass(frozen=True)
class Attestation:
    ip: str
    peer_id: str
    claims: dict


@dataclass(frozen=True)
class Redeemed:
    attested_at: float
    claims: dict


class TransactionError(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class TransactionStore:
    """Every transition is one conditional UPDATE that must change exactly one row.

    Connections are autocommit, so a burn is durable the moment it runs: no error
    path can roll it back. Nothing slow happens while a write lock is held.
    """

    def __init__(self, path: str, *, attest_window: int = 30, redeem_window: int = 10,
                 max_pending_per_rp: int = 200, now: Callable[[], float] = time.time):
        self.path, self.now = path, now
        self.attest_window, self.redeem_window, self.max_pending_per_rp = attest_window, redeem_window, max_pending_per_rp
        with closing(self._connect()) as connection:
            connection.executescript(SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def _write(self, sql: str, params: tuple = ()) -> int:
        with closing(self._connect()) as connection:
            return connection.execute(sql, params).rowcount

    def _read(self, sql: str, params: tuple = ()) -> tuple | None:
        with closing(self._connect()) as connection:
            return connection.execute(sql, params).fetchone()

    def cleanup(self) -> None:
        self._write(
            "DELETE FROM transactions WHERE status IN ('redeemed', 'burned') OR MAX(challenge_expires_at, COALESCE(redeem_expires_at, 0)) < ?",
            (self.now(),),
        )

    # Transaction creation
    def begin(self, rp_id: str, audience: str, origin: str, profile: p.Profile, q: bytes | None) -> Begun:
        p._check_profile(profile, q)
        self.cleanup()
        now = self.now()
        pending = self._read("SELECT COUNT(*) FROM transactions WHERE rp_id = ? AND status = 'pending' AND challenge_expires_at >= ?", (rp_id, now))[0]
        if pending >= self.max_pending_per_rp:
            raise TransactionError("too many pending transactions for this RP")
        cid, c, s = secrets.token_bytes(p.CID_BYTES), secrets.token_bytes(p.SECRET_BYTES), secrets.token_bytes(p.SECRET_BYTES)
        expires = now + self.attest_window
        self._write(
            """INSERT INTO transactions (cid, c, s, rp_id, audience, allowed_origin, profile, q, status, created_at, challenge_expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)""",
            (cid, c, s, rp_id, audience, origin, profile, q, now, expires),
        )
        return Begun(cid, c, expires)

    def burn(self, cid: bytes, expected: str) -> None:
        """Burn only from the state the failing request expected: a race loser never burns the winner."""
        self._write("UPDATE transactions SET status = 'burned' WHERE cid = ? AND status = ?", (cid, expected))

    # Attestation (check 3)
    def pending(self, cid: bytes) -> Pending:
        row = self._read(
            "SELECT rp_id, c, s, allowed_origin, profile, q FROM transactions WHERE cid = ? AND status = 'pending' AND challenge_expires_at >= ?",
            (cid, self.now()),
        )
        if row is None:
            raise TransactionError("transaction is not pending")
        return Pending(*row)

    # Attestation (check 9)
    def mark_attested(self, cid: bytes, attestation: Attestation) -> None:
        now = self.now()
        changed = self._write(
            """UPDATE transactions SET status = 'attested', attested_at = ?, attested_ip = ?, attested_peer_id = ?,
                   attested_claims = ?, redeem_expires_at = ?
               WHERE cid = ? AND status = 'pending' AND challenge_expires_at >= ?""",
            (now, p.ip_bytes(attestation.ip), attestation.peer_id, json.dumps(attestation.claims, sort_keys=True),
             now + self.redeem_window, cid, now),
        )
        if changed != 1:
            raise TransactionError("lost the attest race, or the window closed")

    # Redemption and grant
    def redeem(self, cid: bytes, rp_id: str, audience: str, r: bytes) -> Redeemed:
        row = self._read("SELECT rp_id, audience FROM transactions WHERE cid = ?", (cid,))
        if row is None:
            raise TransactionError("unknown transaction")
        if row != (rp_id, audience):
            # Not this RP's transaction: refuse without burning, or one RP could burn another's.
            raise TransactionError("transaction belongs to another RP or audience")
        row = self._read(
            """SELECT c, s, profile, q, attested_ip, attested_at, attested_claims FROM transactions
               WHERE cid = ? AND status = 'attested' AND redeem_expires_at >= ?""",
            (cid, self.now()),
        )
        if row is None:
            self.burn(cid, "attested")
            raise TransactionError("transaction is not redeemable")
        c, s, profile, q, ip, attested_at, claims = row
        if not p.equal(r, p.compute_r(profile, s, cid, c, ip, q)):
            self.burn(cid, "attested")
            raise TransactionError("R does not match")
        if self._write("UPDATE transactions SET status = 'redeemed', redeemed_at = ? WHERE cid = ? AND status = 'attested'", (self.now(), cid)) != 1:
            raise TransactionError("lost the redeem race")
        return Redeemed(attested_at, json.loads(claims))
