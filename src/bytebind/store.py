"""Authority-owned v1 transactions and person evidence (SPEC §§14–17, 21)."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import time
from contextlib import closing, contextmanager
from dataclasses import dataclass
from typing import Callable

from . import protocol as p

SCHEMA = """
CREATE TABLE IF NOT EXISTS transactions (
 cid BLOB PRIMARY KEY, c BLOB NOT NULL, s BLOB NOT NULL,
 rp_id TEXT NOT NULL, audience TEXT NOT NULL, allowed_origin TEXT NOT NULL,
 profile TEXT NOT NULL CHECK(profile IN ('session','tx')), q BLOB,
 assurance TEXT NOT NULL, person_max_age INTEGER, identify_person INTEGER NOT NULL,
 lease_id TEXT, generation INTEGER NOT NULL DEFAULT 0,
 status TEXT NOT NULL CHECK(status IN ('pending','base_attested','stepup_pending','redeemable','redeemed','burned')),
 created_at REAL NOT NULL, challenge_expires_at REAL NOT NULL,
 attested_at REAL, attested_ip BLOB, attested_peer_id TEXT, attested_claims TEXT,
 accepted_n BLOB, accepted_h1 BLOB, overall_expires_at REAL, collection_expires_at REAL,
 delivery_reserved INTEGER NOT NULL DEFAULT 0, redeem_expires_at REAL, redeemed_at REAL,
 handoff_hash BLOB, completion_hash BLOB, attempt_hash BLOB, w BLOB, webauthn_state TEXT,
 subject_id BLOB, credential_id BLOB, credential_version INTEGER, subject_generation INTEGER,
 user_present INTEGER NOT NULL DEFAULT 0, user_verified INTEGER NOT NULL DEFAULT 0,
 person_at REAL, person_deadline REAL
);
CREATE INDEX IF NOT EXISTS transactions_rp_status ON transactions(rp_id,status);
CREATE TABLE IF NOT EXISTS authority_keys (name TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS subjects (
 id BLOB PRIMARY KEY, user_handle BLOB UNIQUE NOT NULL, name TEXT NOT NULL,
 active INTEGER NOT NULL DEFAULT 1, generation INTEGER NOT NULL DEFAULT 0,
 self_enrolled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS credentials (
 id BLOB PRIMARY KEY, subject_id BLOB NOT NULL, data BLOB NOT NULL,
 counter INTEGER NOT NULL, version INTEGER NOT NULL DEFAULT 0,
 active INTEGER NOT NULL DEFAULT 1, label TEXT NOT NULL, backup_state INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS person_associations (
 handle_hash BLOB PRIMARY KEY, rp_id TEXT NOT NULL, audience TEXT NOT NULL,
 lease_id TEXT NOT NULL, device_id TEXT NOT NULL, subject_id BLOB NOT NULL,
 credential_id BLOB NOT NULL, subject_generation INTEGER NOT NULL, credential_version INTEGER NOT NULL,
 user_present INTEGER NOT NULL, user_verified INTEGER NOT NULL, person_at REAL NOT NULL,
 deadline REAL NOT NULL, active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS device_grants (
 reference_hash BLOB PRIMARY KEY, rp_id TEXT NOT NULL, audience TEXT NOT NULL,
 lease_id TEXT NOT NULL, device_id TEXT NOT NULL, expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS invites (
 token_hash BLOB PRIMARY KEY, subject_id BLOB NOT NULL, expires_at REAL NOT NULL, used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS person_attempts (
 token_hash BLOB PRIMARY KEY, kind TEXT NOT NULL, subject_id BLOB, device_id TEXT NOT NULL,
 state TEXT NOT NULL, expires_at REAL NOT NULL, used INTEGER NOT NULL DEFAULT 0,
 credential_id BLOB, credential_version INTEGER, subject_generation INTEGER
);
"""


def token_hash(token: str) -> bytes:
    return hashlib.sha256(p.b64decode(token, 32)).digest()


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
    generation: int
    assurance: str


@dataclass(frozen=True)
class Attestation:
    ip: str
    peer_id: str
    claims: dict


@dataclass(frozen=True)
class Redeemed:
    attested_at: float
    claims: dict
    transaction: dict


class TransactionError(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class TransactionStore:
    def __init__(
        self,
        path: str,
        *,
        attest_window=30,
        redeem_window=10,
        max_pending_per_rp=200,
        now: Callable[[], float] = time.time,
    ):
        self.path, self.now = path, now
        self.attest_window, self.redeem_window = attest_window, redeem_window
        self.max_pending_per_rp = max_pending_per_rp
        with closing(self._connect()) as connection:
            columns = {row[1] for row in connection.execute("PRAGMA table_info(transactions)")}
            if columns and "generation" not in columns:
                # Drafts have not gone live. Preserve old records, but never resume
                # an old pending authorization under the new lifecycle.
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("ALTER TABLE transactions RENAME TO transactions_v07")
                connection.execute("DROP INDEX IF EXISTS transactions_rp_status")
                connection.commit()
            connection.executescript(SCHEMA)
            connection.execute(
                "INSERT OR IGNORE INTO authority_keys VALUES (?, ?)", ("pairwise", secrets.token_bytes(32))
            )

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    @contextmanager
    def atomic(self):
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                connection.rollback()
                raise
            else:
                connection.commit()

    def _write(self, sql, params=()):
        with closing(self._connect()) as connection:
            return connection.execute(sql, params).rowcount

    def _read(self, sql, params=()):
        with closing(self._connect()) as connection:
            return connection.execute(sql, params).fetchone()

    def record(self, cid: bytes) -> dict:
        with closing(self._connect()) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute("SELECT * FROM transactions WHERE cid=?", (cid,)).fetchone()
        if row is None:
            raise TransactionError("unknown transaction")
        return dict(row)

    def cleanup(self):
        now = self.now()
        self._write(
            "DELETE FROM transactions WHERE status IN ('redeemed','burned') OR "
            "CASE WHEN status='pending' THEN challenge_expires_at "
            "WHEN delivery_reserved=1 THEN redeem_expires_at "
            "ELSE COALESCE(overall_expires_at,challenge_expires_at) END < ?",
            (now,),
        )
        for table in ("invites", "person_attempts", "device_grants"):
            self._write(f"DELETE FROM {table} WHERE expires_at < ?", (now,))
        self._write("DELETE FROM person_associations WHERE deadline < ? OR active=0", (now,))

    def begin(
        self,
        rp_id,
        audience,
        origin,
        profile,
        q,
        *,
        assurance="device",
        person_max_age=None,
        identify_person=False,
        lease_id=None,
    ):
        p._check_profile(profile, q)
        if assurance not in p.ASSURANCES:
            raise TransactionError("unsupported assurance")
        if (
            assurance != "device"
            and profile == "session"
            and (type(person_max_age) is not int or person_max_age <= 0)
        ):
            raise TransactionError("person sessions need finite maximum age")
        self.cleanup()
        now = self.now()
        cid, c, s = secrets.token_bytes(16), secrets.token_bytes(32), secrets.token_bytes(32)
        with self.atomic() as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM transactions WHERE rp_id=? AND status NOT IN ('redeemed','burned')",
                (rp_id,),
            ).fetchone()[0]
            if count >= self.max_pending_per_rp:
                raise TransactionError("too many outstanding transactions")
            connection.execute(
                """INSERT INTO transactions
                (cid,c,s,rp_id,audience,allowed_origin,profile,q,assurance,person_max_age,identify_person,lease_id,status,created_at,challenge_expires_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'pending',?,?)""",
                (
                    cid,
                    c,
                    s,
                    rp_id,
                    audience,
                    origin,
                    profile,
                    q,
                    assurance,
                    person_max_age,
                    int(identify_person),
                    lease_id,
                    now,
                    now + self.attest_window,
                ),
            )
        return Begun(cid, c, now + self.attest_window)

    def burn(self, cid, expected, generation=None):
        if generation is None:
            # Compatibility for local callers: capture a generation, never mutate
            # a row that has advanced since this observation.
            row = self._read("SELECT generation FROM transactions WHERE cid=? AND status=?", (cid, expected))
            if row is None:
                return
            generation = row[0]
        self._write(
            "UPDATE transactions SET status='burned',generation=generation+1 WHERE cid=? AND status=? AND generation=?",
            (cid, expected, generation),
        )

    def pending(self, cid):
        row = self.record(cid)
        if row["status"] != "pending" or row["challenge_expires_at"] < self.now():
            raise TransactionError("transaction is not pending")
        return Pending(
            *(
                row[key]
                for key in ("rp_id", "c", "s", "allowed_origin", "profile", "q", "generation", "assurance")
            )
        )

    def mark_attested(self, cid, attestation, *, n=None, h1=None, generation=0):
        now = self.now()
        changed = self._write(
            """UPDATE transactions SET status='base_attested',generation=generation+1,
            attested_at=?,attested_ip=?,attested_peer_id=?,attested_claims=?,accepted_n=?,accepted_h1=?,overall_expires_at=?
            WHERE cid=? AND status='pending' AND generation=? AND challenge_expires_at>=?""",
            (
                now,
                p.ip_bytes(attestation.ip),
                attestation.peer_id,
                json.dumps(attestation.claims),
                n,
                h1,
                now + 120,
                cid,
                generation,
                now,
            ),
        )
        if changed != 1:
            raise TransactionError("lost attestation race or window closed")
        if self.record(cid)["assurance"] == "device":
            self._write(
                "UPDATE transactions SET status='redeemable',generation=generation+1,collection_expires_at=? WHERE cid=? AND status='base_attested' AND generation=?",
                (now + 30, cid, generation + 1),
            )
            # Legacy direct store helpers without a transcript still get a delivery
            # reservation. Network callers always reserve after fresh peer checks.
            if n is None:
                self.reserve_delivery(cid)

    def prepare_handoff(self, cid):
        handoff, completion = p.b64encode(secrets.token_bytes(32)), p.b64encode(secrets.token_bytes(32))
        row = self.record(cid)
        if (
            self._write(
                "UPDATE transactions SET handoff_hash=?,completion_hash=? WHERE cid=? AND status='base_attested' AND generation=? AND handoff_hash IS NULL",
                (token_hash(handoff), token_hash(completion), cid, row["generation"]),
            )
            != 1
        ):
            raise TransactionError("handoff already prepared")
        return handoff, completion

    def handoff_record(self, handoff):
        row = self._read("SELECT cid FROM transactions WHERE handoff_hash=?", (token_hash(handoff),))
        if row is None:
            raise TransactionError("invalid handoff")
        return self.record(row[0])

    def claim_handoff(self, row, state, w):
        token = p.b64encode(secrets.token_bytes(32))
        if (
            self._write(
                """UPDATE transactions SET status='stepup_pending',generation=generation+1,
            handoff_hash=NULL,attempt_hash=?,webauthn_state=?,w=? WHERE cid=? AND status='base_attested'
            AND generation=? AND overall_expires_at>=?""",
                (token_hash(token), json.dumps(state), w, row["cid"], row["generation"], self.now()),
            )
            != 1
        ):
            raise TransactionError("handoff already consumed")
        return token

    def attempt_record(self, token):
        row = self._read("SELECT cid FROM transactions WHERE attempt_hash=?", (token_hash(token),))
        if row is None:
            raise TransactionError("unknown step-up")
        result = self.record(row[0])
        if result["status"] != "stepup_pending" or result["overall_expires_at"] < self.now():
            raise TransactionError("step-up is not pending")
        return result

    def reserve_delivery(self, cid):
        row = self.record(cid)
        now = self.now()
        if (
            self._write(
                """UPDATE transactions SET delivery_reserved=1,redeem_expires_at=?,generation=generation+1
            WHERE cid=? AND status='redeemable' AND generation=? AND delivery_reserved=0
            AND collection_expires_at>=? AND overall_expires_at>=?""",
                (now + self.redeem_window, cid, row["generation"], now, now),
            )
            != 1
        ):
            raise TransactionError("result unavailable or already delivered")
        return row

    def redeem(self, cid, rp_id, audience, r):
        row = self.record(cid)
        if (row["rp_id"], row["audience"]) != (rp_id, audience):
            raise TransactionError("wrong RP or audience")
        try:
            if (
                row["status"] != "redeemable"
                or not row["delivery_reserved"]
                or row["redeem_expires_at"] < self.now()
            ):
                raise TransactionError("not redeemable")
            if not p.equal(
                r, p.compute_r(row["profile"], row["s"], cid, row["c"], row["attested_ip"], row["q"])
            ):
                raise TransactionError("invalid proof")
            with self.atomic() as connection:
                if row["assurance"] != "device":
                    self.check_person(connection, row)
                if (
                    connection.execute(
                        "UPDATE transactions SET status='redeemed',generation=generation+1,redeemed_at=? WHERE cid=? AND status='redeemable' AND generation=? AND redeem_expires_at>=?",
                        (self.now(), cid, row["generation"], self.now()),
                    ).rowcount
                    != 1
                ):
                    raise TransactionError("lost redemption race")
        except TransactionError:
            self.burn(cid, "redeemable", row["generation"])
            raise
        return Redeemed(row["attested_at"], json.loads(row["attested_claims"]), row)

    @staticmethod
    def check_person(connection, row):
        subject = connection.execute(
            "SELECT active,generation FROM subjects WHERE id=?", (row["subject_id"],)
        ).fetchone()
        credential = connection.execute(
            "SELECT active,version FROM credentials WHERE id=? AND subject_id=?",
            (row["credential_id"], row["subject_id"]),
        ).fetchone()
        if subject != (1, row["subject_generation"]) or credential != (1, row["credential_version"]):
            raise TransactionError("person evidence revoked")

    def device_reference(self, row, ttl):
        token = p.b64encode(secrets.token_bytes(32))
        self._write(
            "INSERT INTO device_grants VALUES (?,?,?,?,?,?)",
            (
                token_hash(token),
                row["rp_id"],
                row["audience"],
                row["lease_id"] or "",
                row["attested_peer_id"],
                self.now() + ttl,
            ),
        )
        return token

    def create_association(self, row):
        token = p.b64encode(secrets.token_bytes(32))
        with self.atomic() as connection:
            self.check_person(connection, row)
            connection.execute(
                "UPDATE person_associations SET active=0 WHERE rp_id=? AND lease_id=?",
                (row["rp_id"], row["lease_id"]),
            )
            connection.execute(
                "INSERT INTO person_associations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,1)",
                (
                    token_hash(token),
                    row["rp_id"],
                    row["audience"],
                    row["lease_id"],
                    row["attested_peer_id"],
                    row["subject_id"],
                    row["credential_id"],
                    row["subject_generation"],
                    row["credential_version"],
                    row["user_present"],
                    row["user_verified"],
                    row["person_at"],
                    row["person_deadline"],
                ),
            )
        return token

    def validate_association(self, rp_id, audience, lease_id, handle, reference):
        # Keep status, device continuity and credential generations in one
        # snapshot. An invalidation cannot slip between independent reads.
        error = None
        result = None
        with self.atomic() as connection:
            names = [col[1] for col in connection.execute("PRAGMA table_info(person_associations)")]
            record = connection.execute(
                "SELECT * FROM person_associations WHERE handle_hash=? AND active=1 AND deadline>?",
                (token_hash(handle), self.now()),
            ).fetchone()
            grant = connection.execute(
                "SELECT rp_id,audience,lease_id,device_id FROM device_grants WHERE reference_hash=? AND expires_at>?",
                (token_hash(reference), self.now()),
            ).fetchone()
            if record is None or grant is None:
                error = "association unavailable"
            else:
                row = dict(zip(names, record))
                if (row["rp_id"], row["audience"], row["lease_id"]) != (rp_id, audience, lease_id) or grant[
                    :3
                ] != (rp_id, audience, lease_id):
                    error = "association scope mismatch"
                elif row["device_id"] != grant[3]:
                    connection.execute(
                        "UPDATE person_associations SET active=0 WHERE handle_hash=?", (token_hash(handle),)
                    )
                    error = "device continuity lost"
                else:
                    try:
                        self.check_person(connection, row)
                    except TransactionError:
                        connection.execute(
                            "UPDATE person_associations SET active=0 WHERE handle_hash=?",
                            (token_hash(handle),),
                        )
                        error = "person evidence invalidated"
                    else:
                        result = {
                            "active": True,
                            "assurance": {
                                "device_attested": True,
                                "user_present": bool(row["user_present"]),
                                "user_verified": bool(row["user_verified"]),
                                "person_expires_in": max(0, row["deadline"] - self.now()),
                            },
                        }
        if error:
            raise TransactionError(error)
        return result

    def end_association(self, rp_id, lease_id):
        self._write("UPDATE person_associations SET active=0 WHERE rp_id=? AND lease_id=?", (rp_id, lease_id))
