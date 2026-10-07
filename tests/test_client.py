"""The Python API client completes real ceremonies and never replays operations."""
import httpx
import pytest
from bytebind.client import Client, ClientError
from bytebind.protocol import b64encode
from conftest import APP, ATTEST_URL
from test_end_to_end import world  # noqa: F401 (shared integration fixture)


def forwarding(app):
    def handle(request):
        response = app.request(request.method, str(request.url), content=request.read(),
                               headers=dict(request.headers), follow_redirects=False)
        return httpx.Response(response.status_code, headers=response.headers, content=response.content)
    return httpx.MockTransport(handle)


def test_client_session_transaction_renewal_and_logout(world, clock):
    app, authority, rp = world
    rp.now = clock
    public_calls, private_calls = [], []
    public = forwarding(app)
    private = forwarding(authority)

    def public_handler(request):
        public_calls.append((request.method, request.url.path))
        return public.handle_request(request)

    def private_handler(request):
        private_calls.append(dict(request.headers))
        assert "cookie" not in request.headers
        assert "authorization" not in request.headers
        assert request.headers["origin"] == APP
        return private.handle_request(request)

    with Client(APP, transport=httpx.MockTransport(public_handler),
                attestation_transport=httpx.MockTransport(private_handler), now=clock) as client:
        result = client.get("/status")
        assert result.status_code == 200
        assert result.json()["authorization"] == ["manage:read"]
        first = client._public.cookies.get("__Host-bytebind_session")
        assert client.get("/status").status_code == 200
        assert len(private_calls) == 1
        clock.now += 60
        assert client.get("/status").status_code == 200
        assert len(private_calls) == 2
        assert rp.session(first) is None
        # Both percent-encoded target and exact prepared JSON bytes are covered.
        result = client.transaction("/re%73tart?x=%2F", json={"service": "demo"})
        assert result.status_code == 200
        assert result.json()["count"] == 1
        assert result.json()["restarted"] == "demo"
        assert public_calls.count(("POST", "/bytebind/proof")) == 3
        client.logout()
        assert not client._public.cookies
        assert client._renewed is None


def test_transaction_works_with_flask(world):
    from flask import Flask, request
    from bytebind.flask import ByteBind as FlaskBind
    _, authority, rp = world
    app = Flask(__name__)
    bind = FlaskBind(app, rp=rp)
    runs = []

    @app.post("/operation")
    @bind(grant=bind.TRANSACTION, require=["manage:read"])
    def operation():
        runs.append(request.get_json())
        return {"count": len(runs)}

    def send(req):
        response = app.test_client(use_cookies=False).open(req.url.raw_path.decode(), method=req.method, base_url=APP,
                                         data=req.read(), headers=dict(req.headers))
        return httpx.Response(response.status_code, headers=list(response.headers), content=response.data)

    with Client(APP, transport=httpx.MockTransport(send), attestation_transport=forwarding(authority)) as client:
        result = client.transaction("/operation", json={"hello": "world"})
        assert result.status_code == 200
        assert runs == [{"hello": "world"}]


@pytest.mark.parametrize("origin", ["http://app.example", "https://user:pass@app.example", "https://app.example/path", "https://app.example?x=1"])
def test_bad_origins(origin):
    with pytest.raises(ValueError):
        Client(origin)


@pytest.mark.parametrize("url", ["https://evil.example/path", "//evil.example/path", "/path#fragment"])
def test_cross_origin_calls_fail_before_io(url):
    def fail(request):
        pytest.fail("invalid URL reached transport")
    with Client(APP, transport=httpx.MockTransport(fail)) as client:
        with pytest.raises(ValueError):
            client.get(url)
        with pytest.raises(ValueError):
            client.transaction(url)


def test_attestation_redirect_is_not_followed():
    calls = []
    def public(request):
        return httpx.Response(200, json={"protocol":1,"draft":"0.8","cid": b64encode(b"c" * 16), "C": b64encode(b"k" * 32), "authority": ATTEST_URL})
    def private(request):
        calls.append(request)
        return httpx.Response(307, headers={"location": "https://evil.example/attestation"})
    with Client(APP, transport=httpx.MockTransport(public), attestation_transport=httpx.MockTransport(private)) as client:
        with pytest.raises(ClientError) as error:
            client.authenticate()
        assert error.value.step == "attestation" and error.value.status == 307
    assert len(calls) == 1


def test_tampered_attestation_never_submits_proof():
    calls = []
    def public(request):
        calls.append(request.url.path)
        return httpx.Response(200, json={"protocol":1,"draft":"0.8","cid": b64encode(b"c" * 16), "C": b64encode(b"k" * 32), "authority": ATTEST_URL})
    with Client(APP, transport=httpx.MockTransport(public), attestation_transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json={"H2": b64encode(b"x" * 76)}))) as client:
        with pytest.raises(ClientError, match="attestation"):
            client.authenticate()
    assert calls == ["/bytebind/challenge"]


def test_api_errors_are_not_replayed(world):
    app, authority, _ = world
    calls = []
    real = forwarding(app)
    def send(req):
        if req.url.path == "/operation":
            calls.append(req)
            return httpx.Response(401, json={"error": "expired"})
        return real.handle_request(req)
    with Client(APP, transport=httpx.MockTransport(send), attestation_transport=forwarding(authority)) as client:
        assert client.post("/operation", json={"x": 1}).status_code == 401
    assert len(calls) == 1


def test_lost_transaction_response_is_not_replayed(world):
    app, authority, _ = world
    real = forwarding(app)
    proof_calls = []
    results = []

    def send(req):
        response = real.handle_request(req)
        if req.url.path == "/bytebind/proof":
            proof_calls.append(req)
            results.append(response.json())
            raise httpx.ReadTimeout("response lost", request=req)
        return response

    with Client(APP, transport=httpx.MockTransport(send), attestation_transport=forwarding(authority)) as client:
        with pytest.raises(ClientError) as error:
            client.transaction("/restart", json={"service": "demo"})
        assert error.value.step == "proof" and error.value.status is None
    assert len(proof_calls) == 1
    assert results[0]["count"] == 1


@pytest.mark.parametrize("authority", ["http://authority.example", "https://user:secret@authority.example",
    "https://authority.example/path", "https://authority.example#fragment", "https://authority.example:invalid"])
def test_malformed_authority_never_receives_secrets(authority):
    def public(req):
        return httpx.Response(200, json={"protocol":1,"draft":"0.8","cid": b64encode(b"c" * 16), "C": b64encode(b"k" * 32), "authority": authority})
    def private(req):
        pytest.fail("secrets sent to a malformed Authority endpoint")
    with Client(APP, transport=httpx.MockTransport(public), attestation_transport=httpx.MockTransport(private)) as client:
        with pytest.raises(ClientError, match="challenge"):
            client.authenticate()
