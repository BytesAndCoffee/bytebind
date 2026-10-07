"""Requests Session with ByteBind leases and transaction-bound API calls.

Install with ``pip install 'bytebind[requests]'``.
"""
from __future__ import annotations

import threading
import time
from typing import Callable
from urllib.parse import urljoin, urlsplit

import requests

from . import protocol as p
from ._client import Ceremony, ClientError, StepUpRequired, response_json


def _origin(value: str) -> str:
    try:
        parts = urlsplit(value)
        if (parts.scheme != "https" or not parts.hostname or parts.username is not None
                or parts.password is not None or parts.query or parts.fragment
                or parts.path not in ("", "/")):
            raise ValueError()
        parts.port  # validate the port before preparing or contacting the endpoint
        return requests.Request("GET", value).prepare().url.rstrip("/")
    except (ValueError, requests.RequestException) as exc:
        raise ValueError("expected an HTTPS origin without credentials, query, fragment, or path") from exc


def _require_tls(verify) -> None:
    if verify is not True and not (isinstance(verify, str) and verify):
        raise ValueError("ByteBind requires TLS certificate verification")


class Session(requests.Session):
    """A requests.Session that authenticates lease calls before sending them.

    Standard get/post/request methods return requests.Response. Use transaction()
    for transaction-bound routes. Leases renew before use after 60 seconds; there
    is no background thread. High-level calls are serialized around the state
    cookie. TLS verification is required, environment proxies/netrc are ignored,
    redirects are disabled, and retry-enabled HTTP adapters are rejected.

    Session headers, cookies, auth, hooks and adapters apply only to the public
    application. Private attestation uses an independent requests.Session. Use
    high-level request methods; calling send() directly does not obtain a lease.
    """

    def __init__(self, origin: str, *, timeout: float = 5.0,
                 challenge_path: str = "/bytebind/challenge", proof_path: str = "/bytebind/proof",
                 logout_path: str = "/bytebind/logout", now: Callable[[], float] = time.monotonic):
        self.origin = _origin(origin)
        for path in (challenge_path, proof_path, logout_path):
            self._url(path)
        super().__init__()
        self.trust_env = False
        self._private = requests.Session()
        self._private.trust_env = False
        self.timeout = timeout
        self.challenge_path, self.proof_path, self.logout_path = challenge_path, proof_path, logout_path
        self._now, self._renewed = now, None
        self._lock = threading.RLock()

    def _url(self, path: str) -> str:
        url = urljoin(self.origin + "/", path)
        parts, origin = urlsplit(url), urlsplit(self.origin)
        if ((parts.scheme, parts.hostname, (443 if parts.port is None else parts.port)) != (origin.scheme, origin.hostname, (443 if origin.port is None else origin.port))
                or parts.username is not None or parts.password is not None or parts.fragment):
            raise ValueError("API and ceremony URLs must remain on the configured origin")
        return url

    @staticmethod
    def _no_retries(session: requests.Session, url: str) -> None:
        retry = getattr(session.get_adapter(url), "max_retries", None)
        if retry is not None and retry.total != 0:
            raise ValueError("ByteBind requires HTTP adapters with max_retries=0")

    def send(self, request, **kwargs):
        # Also protect prepared requests passed directly to Session.send().
        self._url(request.url)
        self._no_retries(self, request.url)
        _require_tls(kwargs.get("verify", self.verify))
        kwargs["allow_redirects"] = False
        kwargs.setdefault("timeout", self.timeout)
        response = super().send(request, **kwargs)
        if response.headers.get("X-ByteBind-Person") == "1":
            raise StepUpRequired()
        return response

    def _post(self, path: str, body: dict, step: str) -> requests.Response:
        try:
            return super().request("POST", self._url(path), json=body, timeout=self.timeout,
                headers={"Origin": self.origin, "Accept": "application/json"}, allow_redirects=False)
        except requests.RequestException as exc:
            raise ClientError(step) from exc

    def _prove(self, challenge: dict, profile: p.Profile, q: bytes | None = None) -> dict:
        ceremony = Ceremony(challenge, profile, q)
        try:
            authority = _origin(challenge["authority"])
        except (ValueError, TypeError) as exc:
            raise ClientError("challenge") from exc
        try:
            self._no_retries(self._private, authority)
            # Prepare directly, bypassing session cookies/auth/default headers.
            request = requests.Request("POST", authority + "/attestation",
                headers={"Origin": self.origin}, json=ceremony.request_body()).prepare()
            response = self._private.send(request, timeout=self.timeout, verify=True,
                                          allow_redirects=False, proxies={})
        except requests.RequestException as exc:
            raise ClientError("attestation") from exc
        return ceremony.proof(response_json(response, "attestation"))

    def authenticate(self) -> dict:
        with self._lock:
            challenge = response_json(self._post(self.challenge_path, {}, "challenge"), "challenge")
            result = response_json(self._post(self.proof_path, self._prove(challenge, "session"), "proof"), "proof")
            self._renewed = self._now()
            return result

    def request(self, method, url, **kwargs) -> requests.Response:
        """Call a lease-protected endpoint using requests' usual keyword arguments."""
        with self._lock:
            target = self._url(url)
            verify = kwargs.get("verify")
            _require_tls(self.verify if verify is None else verify)
            if self._renewed is None or self._now() - self._renewed >= 60:
                self.authenticate()
            headers = requests.structures.CaseInsensitiveDict(kwargs.pop("headers", {}) or {})
            headers.update({"Origin": self.origin, "Accept": "application/json"})
            kwargs.update(headers=headers, allow_redirects=False)
            kwargs.setdefault("timeout", self.timeout)
            try:
                return super().request(method, target, **kwargs)
            except requests.RequestException as exc:
                raise ClientError("request") from exc

    def transaction(self, url: str, *, method: str = "POST", **kwargs) -> requests.Response:
        """Approve one buffered request; return its execution response without replay."""
        with self._lock:
            target = self._url(url)
            prepare = {key: kwargs.pop(key) for key in tuple(kwargs)
                       if key in {"params", "data", "json", "headers", "cookies", "auth", "hooks", "files"}}
            timeout = kwargs.pop("timeout", self.timeout)
            verify = kwargs.pop("verify", self.verify)
            cert = kwargs.pop("cert", self.cert)
            proxies = kwargs.pop("proxies", self.proxies)
            kwargs.pop("allow_redirects", None)
            if kwargs:
                raise TypeError("unsupported transaction options: " + ", ".join(sorted(kwargs)))
            verify = self.verify if verify is None else verify
            _require_tls(verify)
            request = self.prepare_request(requests.Request(method, target, **prepare))
            self._url(request.url)
            body = request.body
            if body is None:
                body = b""
            elif isinstance(body, str):
                body = body.encode("utf-8")
            elif not isinstance(body, bytes):
                raise ValueError("transaction bodies must be buffered; use bytes, JSON, or form data")
            if "Transfer-Encoding" in request.headers:
                raise ValueError("transaction bodies must not use Transfer-Encoding")
            request.body = body
            if body or "Content-Length" in request.headers:
                request.headers["Content-Length"] = str(len(body))
            request.headers.update({"Origin": self.origin, "Accept": "application/json"})
            q = p.request_digest(request.method, request.path_url,
                                 {"content-type": request.headers.get("Content-Type", "")}, body)
            try:
                challenged = self.send(request, timeout=timeout, verify=verify, cert=cert, proxies=proxies)
            except requests.RequestException as exc:
                raise ClientError("challenge") from exc
            challenge = response_json(challenged, "challenge", 202)
            return self._post(self.proof_path, self._prove(challenge, "tx", q), "proof")

    def logout(self) -> None:
        with self._lock:
            response = self._post(self.logout_path, {}, "logout")
            if response.status_code != 204:
                raise ClientError("logout", response.status_code)
            self.cookies.clear()
            self._renewed = None

    def close(self) -> None:
        super().close()
        self._private.close()
