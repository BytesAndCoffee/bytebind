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


async def read_capped(request: Request, limit: int) -> bytes | None:
    """The request body, or None if it is (or declares itself) larger than ``limit`` bytes."""
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > limit):
        return None
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > limit:
            return None
    return bytes(body)
