"""Transaction creation and redemption over both conforming control transports."""

from __future__ import annotations

import json
import os
import socket
import threading

import pytest
from fastapi.testclient import TestClient

from bytebind import protocol as p
from bytebind.authority import attest, check_socket_directory, create_control_app, open_store, peer_uid, unix_control_server
from bytebind.config import parse
from bytebind.rp import AuthorityClient, AuthorityError
from conftest import APP, OTHER_RP_NODE, PEER, FakeTailnet, config_data


def complete_attest(config, store, challenge, profile="session", q=None, n=b"\x05" * 32):
    cid, c = p.b64decode(challenge["cid"], 16), p.b64decode(challenge["C"], 32)
    h1 = p.compute_h1(profile, c, cid, n, q)
    h2 = attest(config, store, FakeTailnet(), PEER, APP, {"cid": challenge["cid"], "N": p.b64encode(n), "H1": p.b64encode(h1)})
    ip, s = p.open_h2(profile, c, cid, n, h1, h2)
    return p.b64encode(p.compute_r(profile, s, cid, c, ip, q))


def test_peer_uid_reads_kernel_credentials():
    a, b = socket.socketpair(socket.AF_UNIX)
    try:
        assert peer_uid(a) == os.getuid()
    finally:
        a.close()
        b.close()


def test_session_ceremony_over_the_unix_socket(config, unix_control):
    path, store = unix_control
    authority = AuthorityClient(f"unix:{path}")
    challenge = authority.begin("manage")
    assert set(challenge) == {"protocol", "draft", "rp_id", "cid", "C", "authority", "expires_in"} and challenge["authority"] == config.attest_url
    assert challenge["expires_in"] == 30, "relative durations only on the control channel"
    grant = authority.redeem(challenge["cid"], complete_attest(config, store, challenge), "manage")
    assert grant["active"] is True and grant["rp_id"] == "app" and grant["audience"] == "manage"
    assert grant["expires_in"] == 180 and "expires_at" not in grant and "attested_at" not in grant
    assert grant["claims"] == {"authorization": ["manage:read"], "device_id": "nLaptop1CNTRL"}, "only the claims this RP may see"


def test_tx_ceremony_binds_q(config, unix_control):
    path, store = unix_control
    authority = AuthorityClient(f"unix:{path}")
    q = p.request_digest("POST", "/restart", {"content-type": "application/json"}, b"{}")
    challenge = authority.begin("manage", "tx", q)
    r = complete_attest(config, store, challenge, "tx", q)
    assert authority.redeem(challenge["cid"], r, "manage")["active"] is True


def test_redeem_is_single_use(config, unix_control):
    path, store = unix_control
    authority = AuthorityClient(f"unix:{path}")
    challenge = authority.begin("manage")
    r = complete_attest(config, store, challenge)
    authority.redeem(challenge["cid"], r, "manage")
    with pytest.raises(AuthorityError) as error:
        authority.redeem(challenge["cid"], r, "manage")
    assert error.value.status == 403


def test_wrong_r_burns(config, unix_control):
    path, store = unix_control
    authority = AuthorityClient(f"unix:{path}")
    challenge = authority.begin("manage")
    r = complete_attest(config, store, challenge)
    with pytest.raises(AuthorityError):
        authority.redeem(challenge["cid"], p.b64encode(bytes(32)), "manage")
    with pytest.raises(AuthorityError):
        authority.redeem(challenge["cid"], r, "manage")


def test_redeem_before_attest_fails(config, unix_control):
    path, _ = unix_control
    authority = AuthorityClient(f"unix:{path}")
    challenge = authority.begin("manage")
    with pytest.raises(AuthorityError):
        authority.redeem(challenge["cid"], p.b64encode(bytes(32)), "manage")


def test_unregistered_audience_and_mismatched_profile(config, unix_control):
    path, _ = unix_control
    authority = AuthorityClient(f"unix:{path}")
    with pytest.raises(AuthorityError) as error:
        authority.begin("ops")  # registered to the other RP
    assert error.value.status == 403
    with pytest.raises(AuthorityError) as error:
        authority._post("/v1/transaction", {"audience": "manage", "profile": "tx"})  # tx without Q
    assert error.value.status == 400
    with pytest.raises(AuthorityError):
        authority._post("/v1/transaction", {"audience": "manage", "profile": "session", "allowed_origin": "https://evil.example"})
    with pytest.raises(AuthorityError):
        authority._post("/v1/transaction", {"audience": "manage", "profile": "session", "extra": 1})


def test_unregistered_uid_is_refused(tmp_path, short_dir):
    config = parse(config_data(str(tmp_path / "a.sqlite3"), uid=os.getuid() + 12345))
    server = unix_control_server(config, open_store(config), str(short_dir / "c.sock"))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(AuthorityError) as error:
            AuthorityClient(f"unix:{short_dir / 'c.sock'}").begin("manage")
        assert error.value.status == 403 and error.value.code == "unknown_rp"
    finally:
        server.shutdown()
        server.server_close()


def test_socket_directory_must_not_be_shared(config, short_dir):
    os.chmod(short_dir, 0o770)
    with pytest.raises(PermissionError):
        check_socket_directory(short_dir / "c.sock")


def test_socket_permissions(config, unix_control):
    path, _ = unix_control
    assert os.stat(path).st_mode & 0o777 == 0o660


def test_another_rp_cannot_redeem_and_cannot_burn(config, unix_control):
    """SPEC.md 16.3: auth sets are bound to the RP that requested them."""
    path, store = unix_control
    challenge = AuthorityClient(f"unix:{path}").begin("manage")
    r = complete_attest(config, store, challenge)
    other = TestClient(create_control_app(config, FakeTailnet({"100.88.0.2": (OTHER_RP_NODE, [], False, 0)}), store),
                       base_url="https://authority.tail1234.ts.net:9443", client=("100.88.0.2", 5000))
    with other:
        response = other.post("/v1/redemption", content=json.dumps({"cid": challenge["cid"], "R": r, "audience": "manage"}))
    assert response.status_code == 403
    assert AuthorityClient(f"unix:{path}").redeem(challenge["cid"], r, "manage")["active"] is True, "not burned by the other RP"


def test_https_control_identifies_rps_by_tailnet_node(config, clock):
    store = open_store(config, now=clock)
    tailnet = FakeTailnet({"100.88.0.2": (OTHER_RP_NODE, [], False, 0), "100.88.0.3": ("nStranger", [], False, 0)})
    app = create_control_app(config, tailnet, store)
    with TestClient(app, base_url="https://a.ts.net", client=("100.88.0.2", 1)) as known:
        response = known.post("/v1/transaction", content=json.dumps({"protocol":1,"draft":"0.8","assurance":"device","lease_id":p.b64encode(bytes(32)),"audience": "ops", "profile": "session"}))
        assert response.status_code == 200
    for peer in ("100.88.0.3", "127.0.0.1", "203.0.113.5"):
        with TestClient(app, base_url="https://a.ts.net", client=(peer, 1)) as stranger:
            assert stranger.post("/v1/transaction", content=json.dumps({"protocol":1,"draft":"0.8","assurance":"device","lease_id":p.b64encode(bytes(32)),"audience": "ops", "profile": "session"})).status_code == 403


def test_pending_cap_per_rp(tmp_path, clock):
    data = config_data(str(tmp_path / "a.sqlite3"))
    data["authority"]["max_pending_per_rp"] = 2
    config = parse(data)
    store = open_store(config, now=clock)
    store.begin("app", "manage", APP, "session", None)
    store.begin("app", "manage", APP, "session", None)
    from bytebind.store import TransactionError

    with pytest.raises(TransactionError):
        store.begin("app", "manage", APP, "session", None)
    store.begin("other", "ops", "https://other.example", "session", None)  # another RP is unaffected


def test_redeem_window(config, clock):
    from bytebind.authority import Control, ControlError

    store = open_store(config, now=clock)
    control = Control(config, store)
    challenge = control.begin(config.rps["app"], {"protocol":1,"draft":"0.8","assurance":"device","lease_id":p.b64encode(bytes(32)),"audience": "manage", "profile": "session"})
    r = complete_attest(config, store, challenge)
    clock.now += 11
    with pytest.raises(ControlError):
        control.redeem(config.rps["app"], {"cid": challenge["cid"], "R": r, "audience": "manage"})


def test_control_client_refuses_nonconforming_transports():
    for endpoint in ("http://authority:80", "tcp://127.0.0.1:9000", "unix:relative.sock", "https://a.ts.net/path"):
        with pytest.raises(ValueError):
            AuthorityClient(endpoint)


@pytest.mark.parametrize("length", ["-1", "abc"])
def test_unix_control_refuses_malformed_content_length(unix_control, length):
    path, _ = unix_control
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(5)
        connection.connect(path)
        connection.sendall(f"POST /v1/transaction HTTP/1.1\r\nHost: x\r\nContent-Length: {length}\r\n\r\n".encode())
        assert connection.recv(64).startswith(b"HTTP/1.0 400")
