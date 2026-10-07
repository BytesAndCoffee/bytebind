"""Authority-owned WebAuthn verifier and enrollment. Never imported by an RP client."""

from __future__ import annotations

import json
import logging
import secrets
import sqlite3
from contextlib import closing
from urllib.parse import urlsplit

from . import protocol as p
from .store import TransactionError, TransactionStore, invite_hash, token_hash

logger = logging.getLogger(__name__)


class EnrollmentRateLimited(TransactionError):
    pass


def _binary(value, maximum=16384):
    if not isinstance(value, str) or len(value) > maximum * 4 // 3 + 4:
        raise ValueError("invalid credential encoding")
    return p.b64decode(value, len(value) * 3 // 4)


def validate_response(value, *, registration=False):
    if not isinstance(value, dict) or not {"id", "rawId", "type", "response"} <= set(value) <= {
        "id",
        "rawId",
        "type",
        "response",
        "clientExtensionResults",
        "authenticatorAttachment",
    }:
        raise ValueError("invalid credential shape")
    if value["type"] != "public-key" or value["id"] != value["rawId"]:
        raise ValueError("invalid credential type")
    _binary(value["rawId"], 1024)
    fields = (
        {"clientDataJSON", "attestationObject"}
        if registration
        else {"clientDataJSON", "authenticatorData", "signature", "userHandle"}
    )
    response = value["response"]
    if not isinstance(response, dict) or set(response) != fields:
        raise ValueError("invalid credential response")
    for key, item in response.items():
        if key != "userHandle" or item is not None:
            _binary(item)
    data = p.json_body(_binary(response["clientDataJSON"]))
    if type(data.get("crossOrigin", False)) is not bool:
        raise ValueError("invalid crossOrigin")
    return data


class PersonService:
    def __init__(self, config, store: TransactionStore):
        if config.person is None:
            raise ValueError("person service is not configured")
        # The verifier is optional and Authority-only. Library INFO messages
        # contain credential IDs, so do not forward those to application logs.
        from fido2.server import Fido2Server
        from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialParameters

        logging.getLogger("fido2.server").setLevel(logging.WARNING)
        self.config, self.store = config, store
        self.origin = config.person.origin
        self.rp_id = urlsplit(self.origin).hostname
        self.server = Fido2Server(
            PublicKeyCredentialRpEntity(id=self.rp_id, name="ByteBind Authority"),
            attestation="none",
            verify_origin=lambda value: value == self.origin,
        )
        self.server.allowed_algorithms = [PublicKeyCredentialParameters(type="public-key", alg=-7)]

    def assertion_options(self, row):
        from fido2.webauthn import UserVerificationRequirement

        w = secrets.token_bytes(32)
        requirement = (
            UserVerificationRequirement.REQUIRED
            if row["assurance"] == "verification"
            else UserVerificationRequirement.DISCOURAGED
        )
        options, state = self.server.authenticate_begin(
            user_verification=requirement, challenge=p.person_challenge(row["cid"], row["accepted_h1"], w)
        )
        token = self.store.claim_handoff(row, state, w)
        return {"token": token, "options": dict(options)}

    def options(self, token):
        row = self.store.attempt_record(token)
        # Reconstruct exactly the immutable challenge; no reissue or TTL refresh.
        return {
            "publicKey": {
                "challenge": p.b64encode(p.person_challenge(row["cid"], row["accepted_h1"], row["w"])),
                "rpId": self.rp_id,
                "userVerification": "required" if row["assurance"] == "verification" else "discouraged",
                "timeout": max(1, int((row["overall_expires_at"] - self.store.now()) * 1000)),
            }
        }

    def verify(self, token, response):
        from fido2.webauthn import AuthenticationResponse, AttestedCredentialData

        row = self.store.attempt_record(token)
        try:
            data = validate_response(response)
            if data.get("crossOrigin") is not True or (
                "topOrigin" in data and data["topOrigin"] != row["allowed_origin"]
            ):
                raise ValueError("invalid embedding context")
            parsed = AuthenticationResponse.from_dict(response)
            credential = self._credential(parsed.raw_id)
            if parsed.response.user_handle != credential["user_handle"]:
                raise ValueError("user handle mismatch")
            rp = self.config.rps[row["rp_id"]]
            subject_text = p.b64encode(credential["subject_id"])
            if credential["self_enrolled"] and not rp.allow_self_enrolled:
                raise ValueError("self-enrolled subject not permitted")
            if rp.person_subjects and subject_text not in rp.person_subjects:
                raise ValueError("subject not permitted")
            self.server.authenticate_complete(
                json.loads(row["webauthn_state"]), [AttestedCredentialData(credential["data"])], parsed
            )
            auth = parsed.response.authenticator_data
            self._commit_assertion(row, credential, auth)
        except (ValueError, KeyError, TypeError, p.ProtocolError, TransactionError):
            self.store.burn(row["cid"], "stepup_pending", row["generation"])
            raise TransactionError("person verification failed") from None

    def _credential(self, credential_id):
        with closing(self.store._connect()) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                """SELECT credentials.*,subjects.user_handle,subjects.generation AS subject_generation,
                subjects.self_enrolled FROM credentials JOIN subjects ON subjects.id=credentials.subject_id
                WHERE credentials.id=? AND credentials.active=1 AND subjects.active=1""",
                (credential_id,),
            ).fetchone()
        if row is None:
            raise TransactionError("unknown credential")
        return dict(row)

    def _commit_assertion(self, row, credential, auth):
        now = self.store.now()
        if (credential["counter"] or auth.counter) and auth.counter <= credential["counter"]:
            logger.warning("passkey counter regression: operator review required")
            raise TransactionError("counter regression")
        if auth.flags & 16 and not auth.flags & 8:
            raise TransactionError("invalid backup flags")
        with self.store.atomic() as connection:
            subject = connection.execute(
                "SELECT active,generation FROM subjects WHERE id=?", (credential["subject_id"],)
            ).fetchone()
            if subject != (1, credential["subject_generation"]):
                raise TransactionError("subject changed")
            if (
                connection.execute(
                    "UPDATE credentials SET counter=?,backup_state=? WHERE id=? AND active=1 AND version=? AND counter=?",
                    (
                        auth.counter,
                        int(bool(auth.flags & 16)),
                        credential["id"],
                        credential["version"],
                        credential["counter"],
                    ),
                ).rowcount
                != 1
            ):
                raise TransactionError("credential changed")
            deadline = now + (row["person_max_age"] or 120)
            if (
                connection.execute(
                    """UPDATE transactions SET status='redeemable',generation=generation+1,
                collection_expires_at=?,subject_id=?,credential_id=?,credential_version=?,subject_generation=?,
                user_present=?,user_verified=?,person_at=?,person_deadline=?
                WHERE cid=? AND status='stepup_pending' AND generation=? AND overall_expires_at>=?""",
                    (
                        min(now + 30, row["overall_expires_at"]),
                        credential["subject_id"],
                        credential["id"],
                        credential["version"],
                        credential["subject_generation"],
                        int(auth.is_user_present()),
                        int(auth.is_user_verified()),
                        now,
                        deadline,
                        row["cid"],
                        row["generation"],
                        now,
                    ),
                ).rowcount
                != 1
            ):
                raise TransactionError("step-up race lost")

    def invite(self, name, *, ttl=900):
        """Local Authority operator command. No device owner mapping, no recovery."""
        if (
            not isinstance(name, str)
            or not name.strip()
            or len(name) > 128
            or type(ttl) is not int
            or not 0 < ttl <= 900
        ):
            raise ValueError("invalid enrollment invite")
        subject_id, user_handle = secrets.token_bytes(32), secrets.token_bytes(32)
        with self.store.atomic() as connection:
            connection.execute("DELETE FROM invites WHERE expires_at<=?", (self.store.now(),))
            for _ in range(16):
                code = secrets.token_hex(4).upper()
                digest = invite_hash(code)
                if connection.execute("SELECT 1 FROM invites WHERE token_hash=?", (digest,)).fetchone() is None:
                    break
            else:
                raise TransactionError("could not allocate an invite")
            connection.execute(
                "INSERT INTO subjects(id,user_handle,name) VALUES (?,?,?)", (subject_id, user_handle, name)
            )
            connection.execute(
                "INSERT INTO invites(token_hash,subject_id,expires_at) VALUES (?,?,?)",
                (digest, subject_id, self.store.now() + ttl),
            )
        return code[:4] + "-" + code[4:], p.b64encode(subject_id)

    def _consume_invite(self, device_id, invite, now):
        # Commit failed guesses before raising. The shared database serializes
        # budgets across processes, IP addresses, listeners and restarts.
        subject_id = None
        with self.store.atomic() as connection:
            connection.execute("DELETE FROM enrollment_failures WHERE failed_at<=?", (now - 900,))
            total = connection.execute("SELECT COUNT(*) FROM enrollment_failures").fetchone()[0]
            device = connection.execute(
                "SELECT COUNT(*) FROM enrollment_failures WHERE device_id=?", (device_id,)
            ).fetchone()[0]
            if device >= 10 or total >= 100:
                raise EnrollmentRateLimited("too many enrollment guesses")
            try:
                digest = invite_hash(invite)
            except (ValueError, TypeError, p.ProtocolError):
                digest = None
            row = connection.execute(
                "SELECT subject_id FROM invites WHERE token_hash=? AND used=0 AND expires_at>?", (digest, now)
            ).fetchone()
            if row is None:
                connection.execute("INSERT INTO enrollment_failures VALUES (?,?)", (device_id, now))
            else:
                connection.execute("UPDATE invites SET used=1 WHERE token_hash=?", (digest,))
                subject_id = row[0]
        if subject_id is None:
            raise TransactionError("invite unavailable")
        return subject_id

    def enrollment_begin(self, device_id, *, invite=None, management=None, self_name=None):
        from fido2.webauthn import PublicKeyCredentialUserEntity, AttestedCredentialData

        now = self.store.now()
        self._quota(device_id)
        subject_id = self._consume_invite(device_id, invite, now) if invite is not None else None
        # Consume authorization into one registration attempt before publishing
        # options. Lost registration requires a new invite or fresh management UV.
        with self.store.atomic() as connection:
            if invite is None:
                if management is not None:
                    subject_id = self._consume_management(connection, management, device_id)[0]
                elif self_name is not None and self.config.person.self_enrollment:
                    if not isinstance(self_name, str) or not self_name.strip() or len(self_name) > 128:
                        raise TransactionError("invalid subject name")
                    subject_id = secrets.token_bytes(32)
                    connection.execute(
                        "INSERT INTO subjects(id,user_handle,name,self_enrolled) VALUES (?,?,?,1)",
                        (subject_id, secrets.token_bytes(32), self_name),
                    )
                else:
                    raise TransactionError("enrollment not authorized")
            subject = connection.execute(
                "SELECT user_handle,name,generation FROM subjects WHERE id=? AND active=1", (subject_id,)
            ).fetchone()
            if subject is None:
                raise TransactionError("subject unavailable")
            existing = [
                AttestedCredentialData(r[0])
                for r in connection.execute("SELECT data FROM credentials WHERE subject_id=?", (subject_id,))
            ]
        options, state = self.server.register_begin(
            PublicKeyCredentialUserEntity(id=subject[0], name=subject[1], display_name=subject[1]),
            credentials=existing,
            resident_key_requirement="required",
            user_verification="required",
            extensions={"credProps": True},
        )
        # credProps.rk is optional. Retain the requirement we issued so its
        # omission cannot turn a preferred/non-resident request into enrollment.
        state["resident_key_requirement"] = "required"
        token = p.b64encode(secrets.token_bytes(32))
        with self.store.atomic() as connection:
            self._quota(device_id, connection)
            connection.execute(
                "INSERT INTO person_attempts(token_hash,kind,subject_id,device_id,state,expires_at,subject_generation) VALUES (?,?,?,?,?,?,?)",
                (
                    token_hash(token),
                    "enroll",
                    subject_id,
                    device_id,
                    json.dumps(state),
                    now + 120,
                    subject[2],
                ),
            )
        return {"token": token, "options": dict(options)}

    def enrollment_complete(self, token, device_id, response, label):
        from fido2.webauthn import RegistrationResponse

        try:
            attempt = self._local_attempt(token, "enroll", device_id)
        except TransactionError:
            logger.warning("passkey registration refused: attempt_unavailable")
            raise
        stage = "response_shape"
        try:
            data = validate_response(response, registration=True)
            stage = "top_level_context"
            if data.get("crossOrigin", False) is not False:
                raise ValueError("registration must be top-level")
            stage = "credential_label"
            if not isinstance(label, str) or not label.strip() or len(label) > 128:
                raise ValueError("invalid label")
            stage = "credential_encoding"
            parsed = RegistrationResponse.from_dict(response)
            state = json.loads(attempt["state"])
            stage = "webauthn_validation"
            auth = self.server.register_complete(state, parsed)
            stage = "algorithm_or_verification"
            if (
                auth.credential_data.public_key.ALGORITHM != -7
                or not auth.is_user_present()
                or not auth.is_user_verified()
            ):
                raise ValueError("unsupported registration")
            # Some platform clients omit this optional extension. They still
            # must honor residentKey=required, which the Authority records above.
            # An explicit negative or malformed report never gets that fallback.
            stage = "discoverable_credential"
            properties = parsed.client_extension_results.get("credProps", {})
            if not isinstance(properties, dict):
                raise ValueError("invalid credential properties")
            if "rk" in properties:
                discoverable = properties["rk"] is True
            else:
                discoverable = state.get("resident_key_requirement") == "required"
            if not discoverable:
                raise ValueError("discoverable credential required")
            stage = "subject_or_storage"
            with self.store.atomic() as connection:
                if connection.execute(
                    "SELECT active,generation FROM subjects WHERE id=?", (attempt["subject_id"],)
                ).fetchone() != (1, attempt["subject_generation"]):
                    raise TransactionError("subject changed")
                self._claim_local(connection, token, attempt)
                connection.execute(
                    "INSERT INTO credentials(id,subject_id,data,counter,label,backup_state) VALUES (?,?,?,?,?,?)",
                    (
                        auth.credential_data.credential_id,
                        attempt["subject_id"],
                        bytes(auth.credential_data),
                        auth.counter,
                        label,
                        int(bool(auth.flags & 16)),
                    ),
                )
        except (ValueError, KeyError, TypeError, p.ProtocolError, TransactionError, sqlite3.IntegrityError):
            # Fixed stage names only: never log user data or verifier exceptions.
            logger.warning("passkey registration refused: %s", stage)
            self.store._write("UPDATE person_attempts SET used=1 WHERE token_hash=?", (token_hash(token),))
            raise TransactionError("registration failed") from None

    def management_begin(self, device_id):
        self._quota(device_id)
        options, state = self.server.authenticate_begin(user_verification="required")
        token = p.b64encode(secrets.token_bytes(32))
        with self.store.atomic() as connection:
            self._quota(device_id, connection)
            connection.execute(
                "INSERT INTO person_attempts(token_hash,kind,device_id,state,expires_at) VALUES (?,?,?,?,?)",
                (token_hash(token), "manage_login", device_id, json.dumps(state), self.store.now() + 120),
            )
        return {"token": token, "options": dict(options)}

    def management_complete(self, token, device_id, response):
        from fido2.webauthn import AuthenticationResponse, AttestedCredentialData

        attempt = self._local_attempt(token, "manage_login", device_id)
        try:
            data = validate_response(response)
            if data.get("crossOrigin", False) is not False:
                raise ValueError("management must be top-level")
            parsed = AuthenticationResponse.from_dict(response)
            credential = self._credential(parsed.raw_id)
            if parsed.response.user_handle != credential["user_handle"]:
                raise ValueError("user handle mismatch")
            self.server.authenticate_complete(
                json.loads(attempt["state"]), [AttestedCredentialData(credential["data"])], parsed
            )
            auth = parsed.response.authenticator_data
            if (credential["counter"] or auth.counter) and auth.counter <= credential["counter"]:
                logger.warning("passkey counter regression: operator review required")
                raise ValueError("counter regression")
            new_token = p.b64encode(secrets.token_bytes(32))
            with self.store.atomic() as connection:
                self._claim_local(connection, token, attempt)
                if connection.execute(
                    "SELECT active,generation FROM subjects WHERE id=?", (credential["subject_id"],)
                ).fetchone() != (1, credential["subject_generation"]):
                    raise TransactionError("subject changed")
                if (
                    connection.execute(
                        "UPDATE credentials SET counter=? WHERE id=? AND active=1 AND version=? AND counter=?",
                        (auth.counter, credential["id"], credential["version"], credential["counter"]),
                    ).rowcount
                    != 1
                ):
                    raise TransactionError("credential changed")
                connection.execute(
                    "INSERT INTO person_attempts(token_hash,kind,subject_id,device_id,state,expires_at,credential_id,credential_version,subject_generation) VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        token_hash(new_token),
                        "manage",
                        credential["subject_id"],
                        device_id,
                        "{}",
                        self.store.now() + 120,
                        credential["id"],
                        credential["version"],
                        credential["subject_generation"],
                    ),
                )
            return {"token": new_token}
        except (ValueError, KeyError, TypeError, p.ProtocolError, TransactionError):
            self.store._write("UPDATE person_attempts SET used=1 WHERE token_hash=?", (token_hash(token),))
            raise TransactionError("management verification failed") from None

    def _quota(self, device_id, connection=None):
        if connection is None:
            with self.store.atomic() as connection:
                return self._quota(device_id, connection)
        connection.execute("DELETE FROM person_attempts WHERE used=1 OR expires_at<?", (self.store.now(),))
        count = connection.execute(
            "SELECT COUNT(*) FROM person_attempts WHERE device_id=? AND used=0", (device_id,)
        ).fetchone()[0]
        if count >= 20:
            raise TransactionError("too many person attempts")

    def suspend(self, subject_id):
        """Authority operator action; never a provider-owner identity operation."""
        with self.store.atomic() as connection:
            connection.execute(
                "UPDATE subjects SET active=0,generation=generation+1 WHERE id=?", (subject_id,)
            )
            connection.execute("UPDATE person_associations SET active=0 WHERE subject_id=?", (subject_id,))
            connection.execute(
                "UPDATE transactions SET status='burned',generation=generation+1 WHERE subject_id=? AND status IN ('stepup_pending','redeemable')",
                (subject_id,),
            )

    def _local_attempt(self, token, kind, device_id):
        with closing(self.store._connect()) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT * FROM person_attempts WHERE token_hash=? AND kind=? AND device_id=? AND used=0 AND expires_at>?",
                (token_hash(token), kind, device_id, self.store.now()),
            ).fetchone()
        if row is None:
            raise TransactionError("attempt unavailable")
        return dict(row)

    def _claim_local(self, connection, token, row):
        if (
            connection.execute(
                "UPDATE person_attempts SET used=1 WHERE token_hash=? AND used=0 AND expires_at>?",
                (token_hash(token), self.store.now()),
            ).rowcount
            != 1
        ):
            raise TransactionError("attempt already consumed")

    def _consume_management(self, connection, token, device_id):
        row = self._local_attempt(token, "manage", device_id)
        self.store.check_person(connection, row)
        self._claim_local(connection, token, row)
        return row["subject_id"], row

    def manage(self, token, device_id, action, credential_id=None, label=None):
        with self.store.atomic() as connection:
            subject_id, _ = self._consume_management(connection, token, device_id)
            if action == "list":
                return {
                    "credentials": [
                        {"id": p.b64encode(row[0]), "name": row[1], "active": bool(row[2])}
                        for row in connection.execute(
                            "SELECT id,label,active FROM credentials WHERE subject_id=?", (subject_id,)
                        )
                    ]
                }
            cid = _binary(credential_id, 1024)
            if action == "rename" and isinstance(label, str) and 0 < len(label) <= 128:
                changed = connection.execute(
                    "UPDATE credentials SET label=? WHERE id=? AND subject_id=?", (label, cid, subject_id)
                ).rowcount
            elif action == "revoke":
                changed = connection.execute(
                    "UPDATE credentials SET active=0,version=version+1 WHERE id=? AND subject_id=? AND active=1",
                    (cid, subject_id),
                ).rowcount
                connection.execute("UPDATE person_associations SET active=0 WHERE credential_id=?", (cid,))
                connection.execute(
                    "UPDATE transactions SET status='burned',generation=generation+1 WHERE credential_id=? AND status IN ('stepup_pending','redeemable')",
                    (cid,),
                )
            else:
                raise TransactionError("unknown management action")
            if changed != 1:
                raise TransactionError("credential unavailable")
        return {"ok": True}
