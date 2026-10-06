"""The Flask binding: the same behavior as the FastAPI binding, through Flask's test client."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

flask = pytest.importorskip("flask")

from bytebind.authority import create_attest_app  # noqa: E402
from bytebind.flask import ByteBind, request_target  # noqa: E402
from bytebind.protocol import request_digest  # noqa: E402
from bytebind.rp import AuthorityClient, RelyingParty  # noqa: E402
from conftest import APP, ATTEST_URL, PEER, FakeTailnet  # noqa: E402
from test_end_to_end import browser_proof  # noqa: E402


class Browser:
    """A Flask test client on the RP's HTTPS origin, sending its Origin header."""

    def __init__(self, app, origin=APP, remote_addr="203.0.113.10"):
        self.client, self.origin, self.remote_addr = app.test_client(), origin, remote_addr

    def __getattr__(self, method):
        def call(path, headers=None, **kwargs):
            headers = {"Origin": self.origin, **(headers or {})}
            return getattr(self.client, method)(path, base_url=APP, headers=headers,
                                                environ_base={"REMOTE_ADDR": self.remote_addr}, **kwargs)
        return call


@pytest.fixture
def world(config, unix_control, tmp_path, clock):
    path, store = unix_control
    rp = RelyingParty(AuthorityClient(f"unix:{path}"), origin=APP, audience="manage",
                      database=str(tmp_path / "rp.sqlite3"), now=clock)
    app = flask.Flask(__name__)
    bind = ByteBind(app, rp=rp, max_transaction_body=64)
    with TestClient(create_attest_app(config, FakeTailnet(), store), base_url=ATTEST_URL, client=(PEER, 40000)) as authority:
        yield app, bind, authority


def sign_in(browser, authority):
    challenge = browser.post("/bytebind/challenge").get_json()
    response = browser.post("/bytebind/proof", json=browser_proof(authority, challenge))
    assert response.status_code == 200 and "expires" not in response.get_json()
    return response


def test_session_lease(world, clock):
    app, bind, authority = world

    @app.get("/admin")
    @bind(require=["manage:read"])
    def admin(lease=bind.lease):
        return {"device": lease.device_id}

    @app.get("/dashboard")
    @bind(require=["manage:read"])
    def dashboard():
        return "<html><body>Private</body></html>"

    @app.get("/tagged")
    @bind(require=["tag:admin"])
    def tagged():
        return {}

    @app.post("/change")
    @bind(require=["manage:read"])
    def change(lease=bind.lease):
        return {"changed_by": lease.device_id}

    @app.get("/page")
    def page():
        return "<html><body>Hello</body></html>"

    browser = Browser(app)
    assert browser.get("/admin").status_code == 401
    denied = browser.get("/admin", headers={"Accept": "text/html"})
    assert denied.status_code == 401 and "location.reload()" in denied.text
    assert browser.get("/page").text == "<html><body>Hello</body></html>", "public pages never start ceremonies"
    assert "ByteBind" in browser.get("/bytebind/client.js").text
    assert browser.post("/bytebind/challenge", headers={"Origin": "https://evil.example"}).status_code == 403

    response = sign_in(browser, authority)
    cookie = response.headers["Set-Cookie"]
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=Strict" in cookie
    admin_response = browser.get("/admin")
    assert admin_response.get_json() == {"device": "nLaptop1CNTRL"}
    assert admin_response.headers["Cache-Control"] == "no-store"
    page_response = browser.get("/dashboard")
    assert "/bytebind/client.js" in page_response.text and page_response.text.endswith("</body></html>")
    assert int(page_response.headers["Content-Length"]) == len(page_response.data)
    assert browser.get("/tagged").status_code == 403
    assert browser.post("/change").get_json() == {"changed_by": "nLaptop1CNTRL"}
    assert browser.post("/change", headers={"Origin": "https://evil.example"}).status_code == 403

    assert browser.post("/bytebind/logout", headers={"Origin": "https://evil.example"}).status_code == 403
    assert browser.post("/bytebind/logout").status_code == 204
    assert browser.get("/admin").status_code == 401
    sign_in(browser, authority)
    clock.now += 181
    assert browser.get("/admin").status_code == 401


def test_transaction_grant_runs_the_view_once_after_approval(world):
    app, bind, authority = world
    runs = []

    @app.post("/deploy")
    @bind(require=["manage:read"], grant=bind.TRANSACTION)
    def deploy(grant=bind.grant):
        version = flask.request.get_json()["version"]
        runs.append((version, flask.request.args.get("env"), grant.device_id))
        return {"deployed": version}

    @app.post("/wipe")
    @bind(require=["tag:admin"], grant=bind.TRANSACTION)
    def wipe():
        runs.append("wipe")
        return {}

    browser = Browser(app)

    def approve(url, body):
        challenged = browser.post(url, data=body, headers={"Content-Type": "application/json"})
        assert challenged.status_code == 202 and set(challenged.get_json()) == {"cid", "C", "authority"}
        q = request_digest("POST", url, {"content-type": "application/json"}, body)
        return browser_proof(authority, challenged.get_json(), "tx", q)

    proof = approve("/de%70loy?env=prod", b'{"version":"1.2"}')
    assert runs == [], "the access request runs nothing"
    approved = browser.post("/bytebind/proof", json=proof)
    assert approved.status_code == 200 and approved.get_json() == {"deployed": "1.2"}
    assert approved.headers["Cache-Control"] == "no-store"
    assert runs == [("1.2", "prod", "nLaptop1CNTRL")]
    assert browser.post("/bytebind/proof", json=proof).status_code == 401, "one approval, one run"
    assert len(runs) == 1

    # The grant is checked against the view's requirements before it runs.
    assert browser.post("/bytebind/proof", json=approve("/wipe", b"{}")).status_code == 403
    assert "wipe" not in runs

    assert browser.post("/deploy", json={"version": "1"}, headers={"Origin": "https://evil.example"}).status_code == 403
    assert browser.post("/deploy", json={"version": "x" * 100}).status_code == 413
    assert len(runs) == 1


def test_a_client_cannot_supply_a_grant(world):
    app, bind, _ = world
    runs = []

    @app.post("/deploy")
    @bind(grant=bind.TRANSACTION)
    def deploy():
        runs.append(1)
        return {}

    forged = Browser(app).post("/deploy", json={}, headers={"bytebind.grant": "x", "X-Bytebind-Grant": "x"})
    assert forged.status_code == 202 and runs == []


def test_challenges_are_rate_limited_per_client(config, tmp_path):
    class RP:
        def challenge(self, origin):
            return {"cid": "c", "C": "k", "authority": ATTEST_URL}, "state"

    app = flask.Flask(__name__)
    ByteBind(app, rp=RP(), challenge_per_minute=2)
    browser, elsewhere = Browser(app), Browser(app, remote_addr="198.51.100.7")
    assert [browser.post("/bytebind/challenge").status_code for _ in range(3)] == [200, 200, 429]
    assert elsewhere.post("/bytebind/challenge").status_code == 200


@pytest.mark.parametrize("environ, target", [
    ({"REQUEST_URI": "/re%73tart?x=%2F", "QUERY_STRING": "x=%2F"}, "/re%73tart?x=%2F"),
    ({"RAW_URI": "/a%20b", "QUERY_STRING": ""}, "/a%20b"),
    ({"REQUEST_URI": "https://app.example/a?b=1", "QUERY_STRING": "b=1"}, "/a?b=1"),
    ({"SCRIPT_NAME": "/app", "PATH_INFO": "/a b", "QUERY_STRING": "q=1"}, "/app/a%20b?q=1"),
])
def test_request_target_is_the_target_as_sent(environ, target):
    assert request_target(environ) == target
