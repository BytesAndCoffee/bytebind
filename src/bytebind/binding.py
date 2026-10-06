"""Framework-neutral parts of the web bindings (``bytebind.fastapi``, ``bytebind.flask``).

Each binding adapts these to its framework's requests, responses, and routing; the
ceremony, the rules for requirements, the stored-request format, and the browser
renewal script are the same everywhere.
"""
from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from typing import Mapping

from .discovery import AUTHORITY_CAPABILITY, AUTHORITY_TAG, DiscoveringAuthorityClient
from .limits import PeerLimiter, declared_fits
from .protocol import request_digest
from .rp import AuthorityClient, RelyingParty
from .tailscale import Directory

STATE_COOKIE = "bytebind_state"
SESSION_COOKIE = "bytebind_session"
STATE_PATH = "/bytebind/"
GRANT_KEY = "bytebind.grant"  # set only in-process, on a replayed transaction-bound request
COVERED_HEADERS = ("content-type",)  # the headers Q covers; the browser client sends exactly these
MAX_CACHED_ORIGINS = 32
MAX_PROOF_BODY = 1024
LEASE = "session"
TRANSACTION = "tx"


@dataclass(frozen=True)
class Grant:
    """What a transaction-bound handler learns about the device that approved it."""

    device_id: str | None
    claims: dict


def meets(claims: dict, required: frozenset[str]) -> bool:
    """Every requirement must match: ``tag:`` against device tags, anything else against ``authorization``."""
    tags, authorization = set(claims.get("tags", [])), set(claims.get("authorization", []))
    return all(item in (tags if item.startswith("tag:") else authorization) for item in required)


def check_requirements(require) -> frozenset[str]:
    if isinstance(require, str):
        raise ValueError("require must be a sequence of nonempty claim strings")
    try:
        require = tuple(require)
    except TypeError:
        raise ValueError("require must be a sequence of nonempty claim strings") from None
    if not all(isinstance(item, str) and item for item in require):
        raise ValueError("require must be a sequence of nonempty claim strings")
    return frozenset(require)


def renewal_script(reload: bool) -> str:
    # Renewal keeps its fixed interval after a failure (SPEC.md 15.1): a failed renewal
    # leaves the lease to its stored deadline, and the next one can still succeed.
    if reload:
        done, failed = "location.reload();", ""
    else:
        done = failed = "setTimeout(renew,ByteBind.RENEW_INTERVAL_MS);"
    return ('<script src="/bytebind/client.js"></script><script>'
            'async function renew(){try{await ByteBind.session("/bytebind/challenge","/bytebind/proof");'
            + done + '}catch(e){' + failed + 'const s=document.getElementById("bytebind-status");'
            'if(s)s.textContent="Private network access required";}}renew();</script>')


def sign_in_page() -> str:
    return '<!doctype html><title>ByteBind</title><p id="bytebind-status">Connecting…</p>' + renewal_script(True)


def inject_renewal(body: bytes) -> bytes:
    """Add the renewal script before ``</body>``, or at the end."""
    script = renewal_script(False).encode()
    index = body.lower().rfind(b"</body>")
    return body[:index] + script + body[index:] if index >= 0 else body + script


def stored_body(stored: dict) -> bytes:
    return base64.b64decode(stored["body"])


class Core:
    """Configuration and relying-party state shared by a binding's routes."""

    def __init__(self, *, rp: RelyingParty | None, authority: str | None, origin: str | None,
                 audience: str | None, database: str | None, directory: Directory | None,
                 tailscale_socket: str | None, authority_tag: str = AUTHORITY_TAG,
                 authority_capability: str = AUTHORITY_CAPABILITY, authority_port: int = 9443,
                 challenge_per_minute: int = 30, max_transaction_body: int = 16 * 1024):
        self.rp = rp
        self._rps: dict[str, RelyingParty] = {}
        self._challenge_limiter = PeerLimiter(challenge_per_minute)
        self.max_transaction_body = max_transaction_body
        self.authority = authority or os.getenv("BYTEBIND_AUTHORITY")
        self.authority_client = (AuthorityClient(self.authority) if self.authority else
                                 DiscoveringAuthorityClient(directory,
                                     socket_path=tailscale_socket or os.getenv("BYTEBIND_TAILSCALE_SOCKET", "/var/run/tailscale/tailscaled.sock"),
                                     tag=authority_tag, capability=authority_capability, port=authority_port))
        self.origin = origin or os.getenv("BYTEBIND_ORIGIN")
        self.audience = audience or os.getenv("BYTEBIND_AUDIENCE", "manage")
        self.database = database or os.getenv("BYTEBIND_RP_DB", "bytebind-rp.sqlite3")

    def rp_for(self, request_origin: str) -> RelyingParty:
        """The RP for this request. Never pin an origin from the first request: cache one per origin."""
        if self.rp is not None:
            return self.rp
        origin = self.origin or request_origin
        rp = self._rps.get(origin)
        if rp is None:
            rp = RelyingParty(self.authority_client, origin=origin, audience=self.audience, database=self.database)
            if len(self._rps) < MAX_CACHED_ORIGINS:
                self._rps[origin] = rp
        return rp

    def allow_challenge(self, client: str) -> bool:
        return self._challenge_limiter.allow(client)

    def body_fits(self, declared: str | None, body: bytes | None = None) -> bool:
        if not declared_fits(declared, self.max_transaction_body):
            return False
        return body is None or len(body) <= self.max_transaction_body

    def challenge_transaction(self, rp: RelyingParty, origin: str | None, operation: str, method: str,
                              target: str, headers: Mapping[str, str], body: bytes) -> tuple[dict, str]:
        """Store a transaction-bound request, bound by Q; returns the challenge and state token."""
        covered = {name: headers.get(name, "") for name in COVERED_HEADERS}
        q = request_digest(method, target, covered, body)
        stored = {"operation": operation, "method": method, "target": target, "headers": covered,
                  "body": base64.b64encode(body).decode("ascii")}
        return rp.challenge(origin, request=stored, q=q)
