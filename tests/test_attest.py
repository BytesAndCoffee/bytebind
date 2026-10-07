"""Attestation: SPEC.md 11.1 checks, in order, with hostile inputs."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from bytebind import protocol as p
from bytebind.authority import attest, create_attest_app, open_store
from bytebind.store import TransactionError
from bytebind.tailscale import AttestationError
from conftest import APP, ATTEST_URL, NODE, OTHER, PEER, FakeTailnet

JSON = {"Origin": APP, "Content-Type": "application/json"}


@pytest.fixture
def store(config, clock):
    return open_store(config, now=clock)


def attestation_body(begun, n=b"\x07" * 32, profile="session", q=None):
    h1 = p.compute_h1(profile, begun.c, begun.cid, n, q)
    return {"cid": p.b64encode(begun.cid), "N": p.b64encode(n), "H1": p.b64encode(h1)}, h1


def client(config, store, tailnet=None, peer=PEER, base=ATTEST_URL):
    return TestClient(create_attest_app(config, tailnet or FakeTailnet(), store), base_url=base, client=(peer, 40000))


def test_successful_attestation_returns_an_h2_only_the_holder_of_c_can_open(config, store):
    begun = store.begin("app", "manage", APP, "session", None)
    body, h1 = attestation_body(begun)
    with client(config, store) as attest_client:
        response = attest_client.post("/attestation", headers=JSON, content=json.dumps(body))
    assert response.status_code == 200 and response.headers["access-control-allow-origin"] == APP
    ip, s = p.open_h2("session", begun.c, begun.cid, b"\x07" * 32, h1, p.b64decode(response.json()["H2"], 76))
    assert ip == p.ip_bytes(PEER) and len(s) == 32


def test_transaction_origin_must_match_not_just_any_registered_origin(config, store):
    """SPEC.md 11.1 check 4: a page on RP 'other' cannot attest a challenge issued for RP 'app'."""
    begun = store.begin("app", "manage", APP, "session", None)
    body, _ = attestation_body(begun)
    with client(config, store) as attest_client:
        response = attest_client.post("/attestation", headers={**JSON, "Origin": OTHER}, content=json.dumps(body))
    assert response.status_code == 403
    with pytest.raises(TransactionError):  # and it was burned
        store.pending(begun.cid)


@pytest.mark.parametrize("headers", [
    {"Content-Type": "application/json"},
    {"Origin": "https://evil.example", "Content-Type": "application/json"},
    {"Origin": "null", "Content-Type": "application/json"},
])
def test_unregistered_origins_are_refused_without_touching_state(config, store, headers):
    begun = store.begin("app", "manage", APP, "session", None)
    body, _ = attestation_body(begun)
    with client(config, store) as attest_client:
        response = attest_client.post("/attestation", headers=headers, content=json.dumps(body))
    assert response.status_code == 403 and "access-control-allow-origin" not in response.headers
    store.pending(begun.cid)  # still pending


def test_rebound_host_is_refused_without_touching_state(config, store):
    begun = store.begin("app", "manage", APP, "session", None)
    body, _ = attestation_body(begun)
    with client(config, store, base="https://attacker.example:8443") as attest_client:
        assert attest_client.post("/attestation", headers=JSON, content=json.dumps(body)).status_code == 403
    store.pending(begun.cid)


@pytest.mark.parametrize("content_type", ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data", ""])
def test_simple_content_types_are_refused(config, store, content_type):
    begun = store.begin("app", "manage", APP, "session", None)
    body, _ = attestation_body(begun)
    with client(config, store) as attest_client:
        assert attest_client.post("/attestation", headers={**JSON, "Content-Type": content_type}, content=json.dumps(body)).status_code == 403


@pytest.mark.parametrize("tailnet,peer", [
    (FakeTailnet(), "127.0.0.1"),
    (FakeTailnet(), "100.64.9.9"),
    (FakeTailnet({PEER: (NODE, [], False, 0)}), PEER),
    (FakeTailnet({PEER: (NODE, ["tag:ci"], False, 0)}), PEER),
    (FakeTailnet({PEER: (NODE, ["tag:mgmt"], True, 0)}), PEER),
    (FakeTailnet({PEER: (NODE, ["tag:mgmt"], False, 7)}), PEER),
])
def test_unauthorized_peers_are_refused_generically_and_burned(config, store, tailnet, peer):
    begun = store.begin("app", "manage", APP, "session", None)
    body, _ = attestation_body(begun)
    with client(config, store, tailnet, peer) as attest_client:
        response = attest_client.post("/attestation", headers=JSON, content=json.dumps(body))
    assert response.status_code == 403 and response.json() == {"error": "attestation_failed"}
    with pytest.raises(TransactionError):
        store.pending(begun.cid)


def test_tag_match_all_requires_every_tag(tmp_path, clock):
    from bytebind.config import parse
    from conftest import config_data

    config = parse(config_data(str(tmp_path / "a.sqlite3"), policy={"tags": ["tag:mgmt", "tag:laptop"], "tag_match": "all"}))
    store = open_store(config, now=clock)
    for tags, ok in ((["tag:mgmt"], False), (["tag:mgmt", "tag:laptop"], True)):
        begun = store.begin("app", "manage", APP, "session", None)
        body, _ = attestation_body(begun)
        status = 200 if ok else 403
        with client(config, store, FakeTailnet({PEER: (NODE, tags, False, 0)})) as attest_client:
            assert attest_client.post("/attestation", headers=JSON, content=json.dumps(body)).status_code == status


def test_tailscaled_outage_is_503_and_burns(config, store):
    begun = store.begin("app", "manage", APP, "session", None)
    body, _ = attestation_body(begun)
    with client(config, store, FakeTailnet(fail=True)) as attest_client:
        assert attest_client.post("/attestation", headers=JSON, content=json.dumps(body)).status_code == 503
    with pytest.raises(TransactionError):
        store.pending(begun.cid)


def test_forged_h1_burns(config, store):
    begun = store.begin("app", "manage", APP, "session", None)
    body = {"cid": p.b64encode(begun.cid), "N": p.b64encode(bytes(32)), "H1": p.b64encode(bytes(32))}
    with pytest.raises(p.ProtocolError, match="H1"):
        attest(config, store, FakeTailnet(), PEER, APP, body)
    with pytest.raises(TransactionError):
        store.pending(begun.cid)


def test_tx_h1_must_cover_q(config, store):
    q = bytes(range(32))
    begun = store.begin("app", "manage", APP, "tx", q)
    body, _ = attestation_body(begun, profile="session")  # a session H1 for a tx transaction
    with pytest.raises(p.ProtocolError):
        attest(config, store, FakeTailnet(), PEER, APP, body)


def test_attest_is_single_use_and_a_race_loser_does_not_burn_the_winner(config, store):
    begun = store.begin("app", "manage", APP, "session", None)
    body, _ = attestation_body(begun)
    attest(config, store, FakeTailnet(), PEER, APP, body)
    with pytest.raises(TransactionError):
        attest(config, store, FakeTailnet(), PEER, APP, body)
    row = store._read("SELECT status FROM transactions WHERE cid = ?", (begun.cid,))
    assert row == ("redeemable",)


def test_attest_window(config, store, clock):
    begun = store.begin("app", "manage", APP, "session", None)
    body, _ = attestation_body(begun)
    clock.now += 31
    with pytest.raises(TransactionError):
        attest(config, store, FakeTailnet(), PEER, APP, body)


@pytest.mark.parametrize("body", [{}, [], "x", {"cid": "x", "N": "y", "H1": "z"}, {"cid": "A" * 22, "n": "A" * 43, "h1": "A" * 43}])
def test_malformed_bodies(config, store, body):
    with pytest.raises((p.ProtocolError, TransactionError, AttestationError)):
        attest(config, store, FakeTailnet(), PEER, APP, body)


def test_preflight(config, store):
    request = {"Origin": APP, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type",
               "Access-Control-Request-Private-Network": "true"}
    with client(config, store) as attest_client:
        allowed = attest_client.options("/attestation", headers=request)
        assert allowed.status_code == 204 and allowed.headers["access-control-allow-origin"] == APP
        assert allowed.headers["access-control-allow-private-network"] == "true"
        assert attest_client.options("/attestation", headers={**request, "Origin": OTHER}).headers["access-control-allow-origin"] == OTHER
        for bad in ({"Origin": "https://evil.example"}, {"Access-Control-Request-Method": "PUT"},
                    {"Access-Control-Request-Headers": "content-type, authorization"}):
            assert attest_client.options("/attestation", headers={**request, **bad}).status_code == 403


def test_attest_service_exposes_only_attest(config, store):
    assert {route.path for route in create_attest_app(config, FakeTailnet(), store).routes} == {"/attestation", "/attestation/result"}


def test_oversized_bodies_are_refused_before_being_read(config, store):
    begun = store.begin("app", "manage", APP, "session", None)
    body, _ = attestation_body(begun)
    padded = json.dumps({**body, "pad": "x" * 2048})
    with client(config, store) as attest_client:
        assert attest_client.post("/attestation", headers=JSON, content=padded).status_code == 403
        assert attest_client.post("/attestation", headers={**JSON, "Content-Length": "-1"}, content=b"").status_code in (400, 403)
