"""Synchronous ByteBind API client. Install with ``pip install 'bytebind[client]'``."""
from __future__ import annotations

import threading
import time
from typing import Callable

import httpx

from . import protocol as p
from ._client import Ceremony, ClientError, response_json


def _origin(value: str) -> httpx.URL:
    try:
        url = httpx.URL(value)
    except httpx.InvalidURL as exc:
        raise ValueError("invalid HTTPS origin") from exc
    if (url.scheme != "https" or not url.host or url.userinfo or url.query or url.fragment
            or url.path not in ("", "/")):
        raise ValueError("expected an HTTPS origin without credentials, query, fragment, or path")
    return url


class Client:
    """Cookie-based API access from an authorized tailnet device.

    Session calls renew before use on a fixed 60-second interval. There is no
    background thread: idle clients establish fresh access on their next call.
    Transaction calls bind the exact prepared method, target, Content-Type and
    body. Calls are serialized to protect the single state cookie. Nothing is
    retried or redirected, including after a lost operation response.

    Public and private HTTP clients have separate cookie jars. TLS verification
    is enabled and environment proxy settings are ignored on both paths.
    ``transport`` and ``attestation_transport`` support custom transports/tests.
    """

    def __init__(self, origin: str, *, timeout: float = 5.0,
                 challenge_path: str = "/bytebind/challenge",
                 proof_path: str = "/bytebind/proof", logout_path: str = "/bytebind/logout",
                 transport: httpx.BaseTransport | None = None,
                 attestation_transport: httpx.BaseTransport | None = None,
                 now: Callable[[], float] = time.monotonic):
        self.origin = _origin(origin)
        for path in (challenge_path, proof_path, logout_path):
            self._url(path)
        self._public = httpx.Client(base_url=self.origin, timeout=timeout, trust_env=False,
                                    follow_redirects=False, transport=transport)
        self._private = httpx.Client(timeout=timeout, trust_env=False, follow_redirects=False,
                                     transport=attestation_transport)
        self.challenge_path, self.proof_path, self.logout_path = challenge_path, proof_path, logout_path
        self._now, self._renewed = now, None
        self._lock = threading.RLock()

    def _url(self, path: str) -> httpx.URL:
        url = self.origin.join(path)
        if (url.scheme, url.host, url.port) != (self.origin.scheme, self.origin.host, self.origin.port) or url.userinfo or url.fragment:
            raise ValueError("API and ceremony URLs must remain on the configured origin")
        return url

    def _send(self, request: httpx.Request, step: str) -> httpx.Response:
        try:
            return self._public.send(request, follow_redirects=False)
        except httpx.HTTPError as exc:
            raise ClientError(step) from exc

    _json = staticmethod(response_json)

    def _post(self, path: str, body: dict, step: str) -> httpx.Response:
        request = self._public.build_request("POST", self._url(path), json=body,
                    headers={"Origin": str(self.origin).rstrip("/"), "Accept": "application/json"})
        return self._send(request, step)

    def _prove(self, challenge: dict, profile: p.Profile, q: bytes | None = None) -> dict:
        ceremony = Ceremony(challenge, profile, q)
        try:
            authority = _origin(challenge["authority"])
        except (ValueError, TypeError) as exc:
            raise ClientError("challenge") from exc
        try:
            # Explicit request: no public cookies, credentials, or caller headers.
            response = self._private.send(httpx.Request("POST", authority.join("/attestation"),
                headers={"Origin": str(self.origin).rstrip("/"), "Content-Type": "application/json"},
                json=ceremony.request_body()), follow_redirects=False)
        except httpx.HTTPError as exc:
            raise ClientError("attestation") from exc
        return ceremony.proof(self._json(response, "attestation"))

    def authenticate(self) -> dict:
        """Establish or renew a session lease; return the RP's response JSON."""
        with self._lock:
            challenge = self._json(self._post(self.challenge_path, {}, "challenge"), "challenge")
            proof = self._prove(challenge, "session")
            result = self._json(self._post(self.proof_path, proof, "proof"), "proof")
            self._renewed = self._now()
            return result

    def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Call a lease-protected API. Return errors without replaying the request."""
        with self._lock:
            target = self._url(url)
            if self._renewed is None or self._now() - self._renewed >= 60:
                self.authenticate()
            request = self._public.build_request(method, target, **kwargs)
            request.headers["Origin"] = str(self.origin).rstrip("/")
            request.headers["Accept"] = "application/json"
            return self._send(request, "request")

    def get(self, url: str, **kwargs) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> httpx.Response:
        return self.request("POST", url, **kwargs)

    def transaction(self, url: str, *, method: str = "POST", **kwargs) -> httpx.Response:
        """Approve one stored request; return its execution response. Never retry."""
        with self._lock:
            request = self._public.build_request(method, self._url(url), **kwargs)
            request.headers["Origin"] = str(self.origin).rstrip("/")
            request.headers["Accept"] = "application/json"
            body = request.read()
            q = p.request_digest(request.method, request.url.raw_path.decode("ascii"),
                                 {"content-type": request.headers.get("content-type", "")}, body)
            challenge = self._json(self._send(request, "challenge"), "challenge", 202)
            return self._post(self.proof_path, self._prove(challenge, "tx", q), "proof")

    def logout(self) -> None:
        with self._lock:
            response = self._post(self.logout_path, {}, "logout")
            if response.status_code != 204:
                raise ClientError("logout", response.status_code)
            self._public.cookies.clear()
            self._renewed = None

    def close(self) -> None:
        self._public.close()
        self._private.close()

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *args) -> None:
        self.close()
