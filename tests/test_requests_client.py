"""Requests compatibility against real Authority and RP exchanges."""
from email.message import Message
from types import SimpleNamespace

import pytest
import requests
from requests.adapters import HTTPAdapter

from bytebind.requests import Session, ClientError
from conftest import APP, ATTEST_URL
from test_end_to_end import world  # noqa: F401


class Adapter(HTTPAdapter):
    def __init__(self, app=None, handler=None):
        super().__init__(max_retries=0)
        self.app, self.handler = app, handler
        self.calls = []

    def send(self, request, **kwargs):
        self.calls.append((request, kwargs))
        if self.handler:
            return self.handler(request, **kwargs)
        result = self.app.request(request.method, request.url, content=request.body,
                                  headers=dict(request.headers), follow_redirects=False)
        return response(request, result.status_code, result.content, result.headers.multi_items())


def response(request, status, content=b"", headers=()):
    result = requests.Response()
    result.status_code, result._content = status, content
    result.request, result.url = request, request.url
    result.headers.update(dict(headers))
    message = Message()
    for key, value in headers:
        message.add_header(key, value)
    result.raw = SimpleNamespace(_original_response=SimpleNamespace(msg=message))
    return result


def client(world, clock=None):
    app, authority, _ = world
    api = Session(APP, **({"now": clock} if clock else {}))
    public, private = Adapter(app), Adapter(authority)
    api.mount("https://", public)
    api._private.mount("https://", private)
    return api, public, private


def test_requests_session_lease_renewal_and_transaction(world, clock):
    world[2].now = clock
    api, public, private = client(world, clock)
    with api:
        assert isinstance(api, requests.Session)
        api.headers["X-Public"] = "only-public"
        api.auth = ("user", "password")
        result = api.get("/status", params={"x": "a b"})
        assert isinstance(result, requests.Response)
        result.raise_for_status()
        assert result.json()["authorization"] == ["manage:read"]
        first = api.cookies.get("__Host-bytebind_session")
        assert api.get("/status").status_code == 200
        assert len(private.calls) == 1
        clock.now += 60
        assert api.get("/status").status_code == 200
        assert world[2].session(first) is None
        result = api.transaction("/re%73tart", params={"x": "/"}, json={"service": "café"})
        result.raise_for_status()
        assert result.json()["restarted"] == "café" and result.json()["count"] == 1
        for request, options in private.calls:
            assert "Cookie" not in request.headers
            assert "Authorization" not in request.headers
            assert "X-Public" not in request.headers
            assert request.headers["Origin"] == APP
            assert options["verify"] is True and options["proxies"] == {}
        api.logout()
        assert not api.cookies
        assert api._renewed is None


def test_requests_transaction_flask_exact_utf8_body(world):
    from flask import Flask, request as flask_request
    from bytebind.flask import ByteBind
    app = Flask(__name__)
    bind = ByteBind(app, rp=world[2])
    runs = []

    @app.post("/operation")
    @bind(grant=bind.TRANSACTION, require=["manage:read"])
    def operation():
        runs.append(flask_request.get_data())
        return {"count": len(runs)}

    def send(request, **kwargs):
        result = app.test_client(use_cookies=False).open(request.path_url, method=request.method,
                         base_url=APP, data=request.body, headers=dict(request.headers))
        return response(request, result.status_code, result.data, result.headers.to_wsgi_list())

    api, _, _ = client(world)
    api.mount("https://", Adapter(handler=send))
    with api:
        result = api.transaction("/operation", data="café", headers={"Content-Type": "text/plain"})
        result.raise_for_status()
    assert runs == ["café".encode()]


def test_lost_response_does_not_replay(world):
    api, public, _ = client(world)
    original = public.send
    results = []
    def lost(req, **kwargs):
        result = original(req, **kwargs)
        if req.path_url == "/bytebind/proof":
            results.append(result.json())
            raise requests.ReadTimeout("response lost")
        return result
    public.send = lost
    with api, pytest.raises(ClientError, match="proof"):
        api.transaction("/restart", json={"service": "demo"})
    assert len(results) == 1 and results[0]["count"] == 1


@pytest.mark.parametrize("url", ["https://evil.example/api", "//evil.example/api", "/api#fragment", "https://app.example:0/api"])
def test_foreign_urls_fail_before_ceremony(url):
    with Session(APP) as api:
        with pytest.raises(ValueError):
            api.get(url)
        with pytest.raises(ValueError):
            api.transaction(url)


def test_redirect_is_not_followed(world):
    api, public, _ = client(world)
    original = public.send
    calls = []
    def redirect(req, **kwargs):
        if req.path_url == "/status":
            calls.append(req)
            return response(req, 307, headers=[("Location", "https://evil.example/api")])
        return original(req, **kwargs)
    public.send = redirect
    with api:
        result = api.get("/status", allow_redirects=True)
        assert result.status_code == 307
    assert len(calls) == 1


def test_retry_adapter_is_rejected_before_io():
    with Session(APP) as api:
        api.mount("https://", HTTPAdapter(max_retries=2))
        with pytest.raises(ValueError, match="max_retries"):
            api.get("/status")


@pytest.mark.parametrize("verify", [False, "", 0])
def test_insecure_tls_is_rejected_before_io(verify):
    with Session(APP) as api:
        with pytest.raises(ValueError, match="verification"):
            api.get("/status", verify=verify)
        with pytest.raises(ValueError, match="verification"):
            api.transaction("/operation", verify=verify)


def test_streaming_transaction_is_rejected_before_io():
    with Session(APP) as api:
        with pytest.raises(ValueError, match="buffered"):
            api.transaction("/operation", data=iter([b"one", b"two"]))
