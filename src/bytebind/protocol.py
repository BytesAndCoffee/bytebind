"""ByteBind v1 transcripts (SPEC.md sections 7 to 13).

Everything here is pure: encoding, the request digest Q, and the H1, H2, and R
constructions for both profiles. State and transport live elsewhere.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import secrets
import struct
from typing import Literal, Mapping

Profile = Literal["session", "tx"]
PROFILES: tuple[Profile, ...] = ("session", "tx")

CID_BYTES = 16
SECRET_BYTES = 32  # C, S, N, Q, H1, R
IP_BYTES = 16
IV_BYTES = 12
TAG_BYTES = 16
H2_BYTES = IV_BYTES + IP_BYTES + SECRET_BYTES + TAG_BYTES  # 76

LABELS: dict[Profile, dict[str, bytes]] = {
    "session": {"h1": b"bytebind/v1/h1", "h2": b"bytebind/v1/h2", "redeem": b"bytebind/v1/redeem"},
    "tx": {"h1": b"bytebind/v1/tx/h1", "h2": b"bytebind/v1/tx/h2", "redeem": b"bytebind/v1/tx/redeem"},
}
REQUEST_LABEL = b"bytebind/v1/tx/request"


class ProtocolError(Exception):
    """A malformed or unverifiable protocol value. ``reason`` is for logs, never for clients."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


# --- encoding -------------------------------------------------------------------------

def b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64decode(value: object, size: int) -> bytes:
    """Unpadded canonical base64url of exactly ``size`` bytes (SPEC.md 7.1), or ProtocolError."""
    if not isinstance(value, str) or not value.isascii() or len(value) != (size * 4 + 2) // 3:
        raise ProtocolError("malformed field")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise ProtocolError("malformed field") from exc
    if len(decoded) != size or b64encode(decoded) != value:
        raise ProtocolError("malformed field")
    return decoded


def ip_bytes(address: str) -> bytes:
    """The attested peer address as 16 bytes; IPv4 is IPv4-mapped IPv6."""
    parsed = ipaddress.ip_address(address)
    if isinstance(parsed, ipaddress.IPv4Address):
        parsed = ipaddress.IPv6Address(f"::ffff:{parsed}")
    return parsed.packed


def _check_profile(profile: str, q: bytes | None) -> dict[str, bytes]:
    if profile not in LABELS:
        raise ValueError(f"unknown profile {profile!r}")
    if (profile == "tx") != (q is not None):
        raise ValueError("Q is required by the tx profile and forbidden in the session profile")
    if q is not None and len(q) != SECRET_BYTES:
        raise ValueError("Q must be 32 bytes")
    return LABELS[profile]


# --- request digest (transaction-bound profile, SPEC.md 9.2) -----------------------------

def _prefixed(value: bytes) -> bytes:
    return struct.pack(">Q", len(value)) + value


def canonical_headers(headers: Mapping[str, str]) -> bytes:
    """Selected headers as sorted ``name:value`` lines, names lowercased, values trimmed, joined by LF."""
    lines = sorted(f"{name.strip().lower()}:{value.strip()}" for name, value in headers.items())
    return "\n".join(lines).encode("utf-8")


def request_digest(method: str, target: str, headers: Mapping[str, str], body: bytes) -> bytes:
    """Q: a length-prefixed SHA-256 of the exact protected request."""
    digest = hashlib.sha256(REQUEST_LABEL)
    for part in (method.upper().encode("ascii"), target.encode("utf-8"), canonical_headers(headers), body):
        digest.update(_prefixed(part))
    return digest.digest()


# --- transcripts -------------------------------------------------------------------------

def _hmac(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-SHA256."""
    prk = _hmac(salt, ikm)
    output, block = b"", b""
    for counter in range(1, -(-length // 32) + 1):
        block = _hmac(prk, block + info + bytes([counter]))
        output += block
    return output[:length]


def compute_h1(profile: Profile, c: bytes, cid: bytes, n: bytes, q: bytes | None = None) -> bytes:
    labels = _check_profile(profile, q)
    return _hmac(c, labels["h1"] + cid + n + (q or b""))


def h2_key(profile: Profile, c: bytes, h1: bytes) -> bytes:
    return hkdf_sha256(c, h1, LABELS[profile]["h2"], 32)


def h2_aad(profile: Profile, cid: bytes, n: bytes, h1: bytes) -> bytes:
    return LABELS[profile]["h2"] + cid + n + h1


def _aesgcm(key: bytes):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    return AESGCM(key)


def seal_h2(profile: Profile, c: bytes, cid: bytes, n: bytes, h1: bytes, ip: bytes, s: bytes, *, iv: bytes | None = None) -> bytes:
    """ATTEST: AES-256-GCM over IP || S. ``iv`` is only for test vectors; it is random otherwise."""
    iv = secrets.token_bytes(IV_BYTES) if iv is None else iv
    if len(iv) != IV_BYTES or len(ip) != IP_BYTES or len(s) != SECRET_BYTES:
        raise ValueError("bad H2 input length")
    return iv + _aesgcm(h2_key(profile, c, h1)).encrypt(iv, ip + s, h2_aad(profile, cid, n, h1))


def open_h2(profile: Profile, c: bytes, cid: bytes, n: bytes, h1: bytes, h2: bytes) -> tuple[bytes, bytes]:
    """The client's side of ATTEST; returns (IP, S)."""
    from cryptography.exceptions import InvalidTag

    if len(h2) != H2_BYTES:
        raise ProtocolError("malformed H2")
    try:
        plain = _aesgcm(h2_key(profile, c, h1)).decrypt(h2[:IV_BYTES], h2[IV_BYTES:], h2_aad(profile, cid, n, h1))
    except InvalidTag as exc:
        raise ProtocolError("H2 authentication failed") from exc
    return plain[:IP_BYTES], plain[IP_BYTES:]


def compute_r(profile: Profile, s: bytes, cid: bytes, c: bytes, ip: bytes, q: bytes | None = None) -> bytes:
    labels = _check_profile(profile, q)
    return _hmac(s, labels["redeem"] + cid + c + ip + (q or b""))


def equal(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)
