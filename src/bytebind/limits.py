"""Request limits shared by the Authority and the relying-party adapter."""

from __future__ import annotations

import threading
import time
from typing import Callable

from starlette.requests import Request


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


def declared_fits(declared: str | None, limit: int) -> bool:
    """Validate ASCII Content-Length without converting attacker-sized integers."""
    if declared is None:
        return True
    if not declared or any(c < "0" or c > "9" for c in declared):
        return False
    value = declared.lstrip("0") or "0"
    maximum = str(limit)
    return len(value) < len(maximum) or (len(value) == len(maximum) and value <= maximum)


async def read_capped(request: Request, limit: int) -> bytes | None:
    """The request body, or None if it is (or declares itself) larger than ``limit`` bytes."""
    declared = request.headers.get("content-length")
    if not declared_fits(declared, limit):
        return None
    body = bytearray()
    async for chunk in request.stream():
        if len(chunk) > limit - len(body):
            return None
        body += chunk
    return bytes(body)
