import pytest
from fastapi.testclient import TestClient

from bytebind.authority import create_attest_app
from bytebind.config import parse
from bytebind.demo import create_app
from bytebind.rp import AuthorityClient, RelyingParty
from conftest import APP, ATTEST_URL, NODE, PEER, FakeTailnet, config_data
from test_end_to_end import browser_proof


@pytest.fixture
def config(tmp_path):
    return parse(config_data(str(tmp_path / "authority.sqlite3"), claims=["device_id", "tags"],
                             policy={"tags": ["tag:admin"]}))


def test_demo_real_ceremony(config, unix_control, tmp_path, clock):
    path, store = unix_control
    rp = RelyingParty(AuthorityClient(f"unix:{path}"), origin=APP, audience="manage",
                      database=str(tmp_path / "rp.sqlite3"), now=clock)
    app = create_app(rp)
    directory = FakeTailnet({PEER: (NODE, ["tag:admin"], False, 0)})
    with TestClient(app, base_url=APP, headers={"Origin": APP}) as client, TestClient(
        create_attest_app(config, directory, store), base_url=ATTEST_URL, client=(PEER, 40000)
    ) as authority:
        assert client.get("/healthz").json() == {"status": "ok"}
        assert "Open admin" in client.get("/").text
        assert client.get("/healthz", headers={"Host": "evil.example"}).status_code == 400
        assert client.get("/admin", headers={"Accept": "text/html"}).status_code == 401
        assert client.post("/api/admin/check").status_code == 401
        challenge = client.post("/bytebind/challenge").json()
        assert client.post("/bytebind/proof", json=browser_proof(authority, challenge)).status_code == 200
        admin = client.get("/admin")
        assert admin.status_code == 200 and NODE in admin.text
        assert "/bytebind/client.js" in admin.text
        assert admin.headers["cache-control"] == "no-store"
        assert client.post("/api/admin/check").json() == {"ok": True, "device_id": NODE}
        assert client.post("/api/admin/check", headers={"Origin": "https://evil.example"}).status_code == 403
        clock.now += 181
        assert client.post("/api/admin/check").status_code == 401


@pytest.mark.parametrize("origin", [None, "http://app.example", "https://app.example/", "https://app.example/path",
                                     "https://user:pass@app.example", "https://app.example?query=1"])
def test_requires_explicit_https_origin(monkeypatch, origin):
    monkeypatch.delenv("BYTEBIND_ORIGIN", raising=False)
    if origin:
        monkeypatch.setenv("BYTEBIND_ORIGIN", origin)
    with pytest.raises(ValueError, match="BYTEBIND_ORIGIN"):
        create_app()


def test_startup_does_not_require_authority(monkeypatch, tmp_path):
    monkeypatch.setenv("BYTEBIND_ORIGIN", APP)
    monkeypatch.setenv("BYTEBIND_RP_DB", str(tmp_path / "state" / "demo.sqlite3"))
    monkeypatch.delenv("BYTEBIND_AUTHORITY", raising=False)
    app = create_app()
    assert (tmp_path / "state" / "demo.sqlite3").is_file()
    assert app.state.bytebind.authority is None
    with TestClient(app, base_url=APP) as client:
        assert client.get("/healthz").status_code == 200
        assert client.get("/").status_code == 200


def test_identity_is_escaped_and_nonadmins_are_denied():
    from bytebind.rp import Lease

    class RP:
        origin = APP
        def session(self, token):
            return Lease('<script>alert("device")</script>', {"tags": ["tag:admin"] if token == "admin" else []}, 9999999999)

    with TestClient(create_app(RP()), base_url=APP) as client:
        assert client.get("/admin").status_code == 403
        client.cookies.set("__Host-bytebind_session", "admin")
        response = client.get("/admin")
        assert response.status_code == 200
        assert '<script>alert("device")</script>' not in response.text
        assert "&lt;script&gt;" in response.text
