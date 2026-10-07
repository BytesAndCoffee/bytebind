"""Transport-independent client ceremony and errors."""
from __future__ import annotations

import secrets
from dataclasses import dataclass

from . import protocol as p


class StepUpRequired(Exception):
    """An API call requires a human ceremony. No tokens, URL, or response body."""
    def __init__(self):
        super().__init__("This endpoint requires person attestation")


class ClientError(Exception):
    """A ceremony failed, without including proof material or response bodies."""

    def __init__(self, step: str, status: int | None = None):
        super().__init__(f"ByteBind {step} failed" + (f" (HTTP {status})" if status else ""))
        self.step, self.status = step, status


def response_json(response, step: str, status: int = 200) -> dict:
    if response.status_code == 202 and step == "attestation":
        raise StepUpRequired()
    if response.status_code != status:
        raise ClientError(step, response.status_code)
    try:
        body = response.json()
        if not isinstance(body, dict):
            raise ValueError()
        return body
    except ValueError as exc:
        raise ClientError(step) from exc


@dataclass
class Ceremony:
    challenge: dict
    profile: p.Profile
    q: bytes | None = None

    def __post_init__(self):
        try:
            if not {"protocol", "draft", "cid", "C", "authority"} <= set(self.challenge) <= {"protocol", "draft", "cid", "C", "authority", "person_origin"} or type(self.challenge["protocol"]) is not int or self.challenge["protocol"] != 1 or self.challenge["draft"] != p.DRAFT or not isinstance(self.challenge["authority"], str):
                raise ValueError()
            self.cid = p.b64decode(self.challenge["cid"], p.CID_BYTES)
            self.c = p.b64decode(self.challenge["C"], p.SECRET_BYTES)
            self.n = secrets.token_bytes(p.SECRET_BYTES)
            self.h1 = p.compute_h1(self.profile, self.c, self.cid, self.n, self.q)
        except (ValueError, TypeError, p.ProtocolError) as exc:
            raise ClientError("challenge") from exc

    def request_body(self) -> dict:
        return {"cid": self.challenge["cid"], "N": p.b64encode(self.n), "H1": p.b64encode(self.h1)}

    def proof(self, body: dict) -> dict:
        try:
            ip, s = p.open_h2(self.profile, self.c, self.cid, self.n, self.h1,
                              p.b64decode(body.get("H2"), p.H2_BYTES))
        except p.ProtocolError as exc:
            raise ClientError("attestation") from exc
        return {"cid": self.challenge["cid"], "R": p.b64encode(
            p.compute_r(self.profile, s, self.cid, self.c, ip, self.q))}
