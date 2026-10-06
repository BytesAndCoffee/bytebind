"""All ten messages, through the example RP, the attest service, and a real Unix-socket control channel."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from bytebind import protocol as p
from bytebind.authority import create_attest_app
from bytebind.rp import AuthorityClient, CeremonyError, RelyingParty
from conftest import APP, ATTEST_URL, PEER, FakeTailnet
from examples.rp_app import create_app

ATTEST_HEADERS = {"Origin": APP, "Content-Type": "application/json"}


@pytest.fixture
def world(config, unix_control, tmp_path):
    path, store = unix_control
    rp = RelyingParty(AuthorityClient(f"unix:{path}"), origin=APP, audience="manage", database=str(tmp_path / "rp.sqlite3"))
    app = TestClient(create_app(rp), base_url=APP, headers={"Origin": APP})
    authority = TestClient(create_attest_app(config, FakeTailnet(), store), base_url=ATTEST_URL, client=(PEER, 40000))
    with app, authority:
        yield app, authority, rp


def browser_proof(authority, challenge, profile="session", q=None, n=b"\x0c" * 32):
    """What bytebind.js does between the challenge and the proof submission."""
    cid, c = p.b64decode(challenge["cid"], 16), p.b64decode(challenge["C"], 32)
    h1 = p.compute_h1(profile, c, cid, n, q)
    attested = authority.post("/attestation", headers=ATTEST_HEADERS, content=json.dumps({"cid": challenge["cid"], "N": p.b64encode(n), "H1": p.b64encode(h1)}))
    assert attested.status_code == 200, attested.text
    ip, s = p.open_h2(profile, c, cid, n, h1, p.b64decode(attested.json()["H2"], 76))
    return {"cid": challenge["cid"], "R": p.b64encode(p.compute_r(profile, s, cid, c, ip, q))}


def test_session_profile_lease_renewal_and_logout(world, clock):
    app, authority, rp = world
    assert app.get("/status").status_code == 401
    assert "location.reload()" in app.get("/", headers={"Accept": "text/html"}).text, "sign-in page first"
    challenge = app.post("/bytebind/challenge").json()                                   # access request -> transaction -> challenge
    response = app.post("/bytebind/proof", json=browser_proof(authority, challenge))  # attestation, proof -> redemption -> grant -> response
    assert response.status_code == 200 and response.json()["device_id"] == "nLaptop1CNTRL"
    cookie = response.headers["set-cookie"]
    assert "bytebind_session=" in cookie and "HttpOnly" in cookie and "Secure" in cookie and "SameSite=strict" in cookie
    assert app.get("/status").json()["authorization"] == ["manage:read"]
    page = app.get("/", headers={"Accept": "text/html"})
    assert "nLaptop1CNTRL" in page.text and "/bytebind/client.js" in page.text, "protected HTML renews its lease"
    first = app.cookies.get("bytebind_session")
    renewed = app.post("/bytebind/proof", json=browser_proof(authority, app.post("/bytebind/challenge").json(), n=b"\x0d" * 32))
    assert renewed.status_code == 200 and app.cookies.get("bytebind_session") != first
    assert rp.session(first) is None, "renewal rotates the session token"
    assert app.post("/bytebind/logout").status_code == 204
    assert app.get("/status").status_code == 401


def test_transaction_profile_executes_the_stored_request_exactly_once(world):
    app, authority, _ = world
    body = json.dumps({"service": "demo"}).encode()
    challenged = app.post("/restart?now=1", content=body, headers={"Content-Type": "application/json"})  # the access request is the protected request
    assert challenged.status_code == 202
    q = p.request_digest("POST", "/restart?now=1", {"content-type": "application/json"}, body)  # the browser's own Q
    proof = browser_proof(authority, challenged.json(), "tx", q)
    response = app.post("/bytebind/proof", json=proof)
    assert response.status_code == 200 and response.json() == {"restarted": "demo", "count": 1, "approved_by": "nLaptop1CNTRL"}  # the response is the operation's result
    assert app.post("/bytebind/proof", json=proof).status_code == 401, "a retried proof submission never executes twice"


def test_transaction_profile_refuses_a_different_request(world):
    app, authority, _ = world
    challenged = app.post("/restart", content=b'{"service":"demo"}', headers={"Content-Type": "application/json"})
    q_for_something_else = p.request_digest("POST", "/restart", {"content-type": "application/json"}, b'{"service":"prod"}')
    cid, c = p.b64decode(challenged.json()["cid"], 16), p.b64decode(challenged.json()["C"], 32)
    h1 = p.compute_h1("tx", c, cid, b"\x01" * 32, q_for_something_else)
    attested = authority.post("/attestation", headers=ATTEST_HEADERS, content=json.dumps({"cid": challenged.json()["cid"], "N": p.b64encode(b"\x01" * 32), "H1": p.b64encode(h1)}))
    assert attested.status_code == 403


def test_proof_needs_the_browser_bound_state_cookie(world, config, tmp_path):
    app, authority, rp = world
    challenge = app.post("/bytebind/challenge").json()
    proof = browser_proof(authority, challenge)
    app.cookies.delete("bytebind_state", path="/bytebind/")
    app.cookies.clear()
    assert app.post("/bytebind/proof", json=proof).status_code == 401


def test_proof_without_the_state_cookie_does_not_cancel_the_ceremony(world):
    app, authority, _ = world
    challenge = app.post("/bytebind/challenge").json()
    proof = browser_proof(authority, challenge)
    state = app.cookies.get("bytebind_state")
    app.cookies.clear()
    assert app.post("/bytebind/proof", json=proof).status_code == 401
    app.cookies.set("bytebind_state", state, path="/bytebind/")
    assert app.post("/bytebind/proof", json=proof).status_code == 200


def test_transaction_digest_covers_the_target_as_sent(world):
    """SPEC.md 9.2: Q covers the percent-encoded path, which the browser hashes as-is."""
    app, authority, _ = world
    body = b'{"service":"demo"}'
    challenged = app.post("/re%73tart?x=%2F", content=body, headers={"Content-Type": "application/json"})
    assert challenged.status_code == 202
    q = p.request_digest("POST", "/re%73tart?x=%2F", {"content-type": "application/json"}, body)
    assert app.post("/bytebind/proof", json=browser_proof(authority, challenged.json(), "tx", q)).status_code == 200


@pytest.mark.parametrize("origin", [None, "https://evil.example"])
def test_rp_refuses_foreign_origins(world, origin):
    app, _, _ = world
    headers = {"Origin": origin} if origin else {}
    with TestClient(app.app, base_url=APP, headers=headers) as plain:
        assert plain.post("/bytebind/challenge").status_code == 403
        assert plain.post("/bytebind/proof", json={"cid": "x", "R": "y"}).status_code == 401


def test_lease_never_outlasts_the_grant(config, unix_control, tmp_path):
    path, store = unix_control
    rp = RelyingParty(AuthorityClient(f"unix:{path}"), origin=APP, audience="manage", database=str(tmp_path / "rp.sqlite3"), lease_seconds=3600)
    challenge, state = rp.challenge(APP)
    with TestClient(create_attest_app(config, FakeTailnet(), store), base_url=ATTEST_URL, client=(PEER, 1)) as authority:
        proof = browser_proof(authority, challenge)
    done = rp.accept_proof(APP, proof, state)
    assert done.grant["expires_in"] == 180
    assert 179 <= done.lease.expires_at - rp.now() <= 180, "capped at the grant, not the RP's 3600"


def test_rp_refuses_a_malformed_proof(config, unix_control, tmp_path):
    path, _ = unix_control
    rp = RelyingParty(AuthorityClient(f"unix:{path}"), origin=APP, audience="manage", database=str(tmp_path / "rp.sqlite3"))
    for body in ({}, {"cid": "x"}, {"cid": "x", "R": "y", "IP": "100.64.0.1"}, [], {"cid": 1, "R": "y"}):
        with pytest.raises(CeremonyError):
            rp.accept_proof(APP, body, "state")


def test_expiry_is_opaque_to_the_client(world):
    """SPEC.md 15.2: no expiry in the challenge, in the response, in /status, or in the session cookie."""
    app, authority, _ = world
    challenged = app.post("/bytebind/challenge")
    challenge = challenged.json()
    assert set(challenge) == {"cid", "C", "authority"}
    response = app.post("/bytebind/proof", json=browser_proof(authority, challenge))
    assert set(response.json()) == {"device_id"}
    session_cookie = next(c for c in response.headers.get_list("set-cookie") if c.startswith("bytebind_session="))
    assert "max-age" not in session_cookie.lower() and "expires" not in session_cookie.lower()
    assert "expires" not in json.dumps(app.get("/status").json())


def test_authority_clock_skew_cannot_stretch_or_break_leases(config, short_dir, tmp_path):
    """A Pi without a real-time clock, a day off: relative durations keep the RP's lease correct."""
    import threading

    from bytebind.authority import open_store, unix_control_server
    from conftest import Clock

    skewed = open_store(config, now=Clock(1_800_000_000.0 + 86_400))
    server = unix_control_server(config, skewed, str(short_dir / "s.sock"))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        rp = RelyingParty(AuthorityClient(f"unix:{short_dir / 's.sock'}"), origin=APP, audience="manage", database=str(tmp_path / "rp.sqlite3"))
        challenge, state = rp.challenge(APP)
        with TestClient(create_attest_app(config, FakeTailnet(), skewed), base_url=ATTEST_URL, client=(PEER, 1)) as authority:
            proof = browser_proof(authority, challenge)
        done = rp.accept_proof(APP, proof, state)
        assert 179 <= done.lease.expires_at - rp.now() <= 180
    finally:
        server.shutdown()
        server.server_close()


def test_rp_refuses_leases_shorter_than_a_renewal_can_survive(tmp_path):
    with pytest.raises(ValueError, match="at least 90"):
        RelyingParty(AuthorityClient("unix:/nonexistent.sock"), origin=APP, audience="manage", database=str(tmp_path / "x.sqlite3"), lease_seconds=60)
