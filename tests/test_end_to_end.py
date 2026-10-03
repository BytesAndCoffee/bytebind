"""All ten messages, through the example RP, the attest service, and a real Unix-socket control channel."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from bytebind import protocol as p
from bytebind.authority import create_attest_app
from bytebind.rp import AuthorityClient, CeremonyError, RelyingParty
from conftest import APP, ATTEST, PEER, FakeTailnet
from examples.rp_app import create_app

ATTEST_HEADERS = {"Origin": APP, "Content-Type": "application/json"}


@pytest.fixture
def world(config, unix_control, tmp_path):
    path, store = unix_control
    rp = RelyingParty(AuthorityClient(f"unix:{path}"), origin=APP, audience="manage", database=str(tmp_path / "rp.sqlite3"))
    app = TestClient(create_app(rp), base_url=APP, headers={"Origin": APP})
    authority = TestClient(create_attest_app(config, FakeTailnet(), store), base_url=ATTEST, client=(PEER, 40000))
    with app, authority:
        yield app, authority, rp


def browser_prove(authority, who, profile="session", q=None, n=b"\x0c" * 32):
    """What bytebind.js does between WHO and AFFIRM."""
    cid, c = p.b64decode(who["cid"], 16), p.b64decode(who["C"], 32)
    h1 = p.compute_h1(profile, c, cid, n, q)
    attested = authority.post("/attest", headers=ATTEST_HEADERS, content=json.dumps({"cid": who["cid"], "N": p.b64encode(n), "H1": p.b64encode(h1)}))
    assert attested.status_code == 200, attested.text
    ip, s = p.open_h2(profile, c, cid, n, h1, p.b64decode(attested.json()["H2"], 76))
    return {"cid": who["cid"], "R": p.b64encode(p.compute_r(profile, s, cid, c, ip, q))}


def test_session_profile_lease_renewal_and_logout(world, clock):
    app, authority, rp = world
    assert app.get("/status").status_code == 401
    who = app.post("/bytebind/please").json()                                   # PLEASE -> BEGIN -> TRY -> WHO
    response = app.post("/bytebind/affirm", json=browser_prove(authority, who))  # PROVE -> ATTEST, AFFIRM -> REDEEM -> GRANT -> RESPONSE
    assert response.status_code == 200 and response.json()["device_id"] == "nLaptop1CNTRL"
    cookie = response.headers["set-cookie"]
    assert "bytebind_session=" in cookie and "HttpOnly" in cookie and "Secure" in cookie and "SameSite=strict" in cookie
    assert app.get("/status").json()["authorization"] == ["manage:read"]
    first = app.cookies.get("bytebind_session")
    renewed = app.post("/bytebind/affirm", json=browser_prove(authority, app.post("/bytebind/please").json(), n=b"\x0d" * 32))
    assert renewed.status_code == 200 and app.cookies.get("bytebind_session") != first
    assert rp.session(first) is None, "renewal rotates the session token"
    assert app.post("/bytebind/logout").status_code == 204
    assert app.get("/status").status_code == 401


def test_transaction_profile_executes_the_stored_request_exactly_once(world):
    app, authority, _ = world
    body = json.dumps({"service": "demo"}).encode()
    pleased = app.post("/restart?now=1", content=body, headers={"Content-Type": "application/json"})  # PLEASE is the request
    assert pleased.status_code == 202
    q = p.request_digest("POST", "/restart?now=1", {"content-type": "application/json"}, body)  # the browser's own Q
    affirm = browser_prove(authority, pleased.json(), "tx", q)
    response = app.post("/bytebind/affirm", json=affirm)
    assert response.status_code == 200 and response.json() == {"restarted": "demo", "count": 1}  # RESPONSE is the result
    assert app.post("/bytebind/affirm", json=affirm).status_code == 401, "a retried AFFIRM never executes twice"


def test_transaction_profile_refuses_a_different_request(world):
    app, authority, _ = world
    pleased = app.post("/restart", content=b'{"service":"demo"}', headers={"Content-Type": "application/json"})
    q_for_something_else = p.request_digest("POST", "/restart", {"content-type": "application/json"}, b'{"service":"prod"}')
    cid, c = p.b64decode(pleased.json()["cid"], 16), p.b64decode(pleased.json()["C"], 32)
    h1 = p.compute_h1("tx", c, cid, b"\x01" * 32, q_for_something_else)
    attested = authority.post("/attest", headers=ATTEST_HEADERS, content=json.dumps({"cid": pleased.json()["cid"], "N": p.b64encode(b"\x01" * 32), "H1": p.b64encode(h1)}))
    assert attested.status_code == 403


def test_affirm_needs_the_browser_bound_state_cookie(world, config, tmp_path):
    app, authority, rp = world
    who = app.post("/bytebind/please").json()
    affirm = browser_prove(authority, who)
    app.cookies.delete("bytebind_state", path="/bytebind/")
    app.cookies.clear()
    assert app.post("/bytebind/affirm", json=affirm).status_code == 401


@pytest.mark.parametrize("origin", [None, "https://evil.example"])
def test_rp_refuses_foreign_origins(world, origin):
    app, _, _ = world
    headers = {"Origin": origin} if origin else {}
    with TestClient(app.app, base_url=APP, headers=headers) as plain:
        assert plain.post("/bytebind/please").status_code == 403
        assert plain.post("/bytebind/affirm", json={"cid": "x", "R": "y"}).status_code == 401


def test_lease_never_outlasts_the_grant(config, unix_control, tmp_path):
    path, store = unix_control
    rp = RelyingParty(AuthorityClient(f"unix:{path}"), origin=APP, audience="manage", database=str(tmp_path / "rp.sqlite3"), lease_seconds=3600)
    who, state = rp.please(APP)
    with TestClient(create_attest_app(config, FakeTailnet(), store), base_url=ATTEST, client=(PEER, 1)) as authority:
        affirm = browser_prove(authority, who)
    done = rp.affirm(APP, affirm, state)
    from bytebind.rp import _timestamp

    assert done.lease.expires_at == _timestamp(done.grant["expires_at"])
    assert done.lease.expires_at - rp.now() <= 181


def test_rp_refuses_a_malformed_affirm(config, unix_control, tmp_path):
    path, _ = unix_control
    rp = RelyingParty(AuthorityClient(f"unix:{path}"), origin=APP, audience="manage", database=str(tmp_path / "rp.sqlite3"))
    for body in ({}, {"cid": "x"}, {"cid": "x", "R": "y", "IP": "100.64.0.1"}, [], {"cid": 1, "R": "y"}):
        with pytest.raises(CeremonyError):
            rp.affirm(APP, body, "state")
