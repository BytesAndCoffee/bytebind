from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient

from bytebind.fastapi import ByteBind
from bytebind.rp import AuthorityClient, RelyingParty
from conftest import APP, ATTEST, PEER, FakeTailnet
from bytebind.authority import create_attest_app
from test_end_to_end import browser_prove


def test_fastapi_dx(config, unix_control, tmp_path, clock):
    path, store = unix_control
    rp = RelyingParty(AuthorityClient(f"unix:{path}"), origin=APP, audience="manage",
                      database=str(tmp_path / "rp.sqlite3"), now=clock)
    app = FastAPI()
    bind = ByteBind(app, rp=rp)
    calls = []

    @app.get("/admin")
    @bind(require=["manage:read"], grant=bind.LEASE)
    async def admin(lease=bind.lease):
        calls.append(lease.device_id)
        return {"device": lease.device_id}

    @app.get("/tagged")
    @bind(require=["tag:admin"])
    def tagged():
        calls.append("tagged")
        return {}

    @app.get("/page", response_class=HTMLResponse)
    def page():
        return "<html><body>Hello</body></html>"

    with TestClient(app, base_url=APP, headers={"Origin": APP}) as client, TestClient(
        create_attest_app(config, FakeTailnet(), store), base_url=ATTEST, client=(PEER, 40000)
    ) as authority:
        assert client.get("/admin").status_code == 401
        denied = client.get("/admin", headers={"Accept": "text/html"})
        assert denied.status_code == 401 and "location.reload()" in denied.text
        assert not calls
        page_response = client.get("/page")
        assert '/bytebind/client.js' in page_response.text
        assert int(page_response.headers["content-length"]) == len(page_response.content)
        assert client.get("/bytebind/client.js").status_code == 200
        assert client.post("/bytebind/please", headers={"Origin": "https://evil.example"}).status_code == 403
        who = client.post("/bytebind/please").json()
        affirmed = client.post("/bytebind/affirm", json=browser_prove(authority, who))
        assert affirmed.status_code == 200
        assert "expires" not in affirmed.json()
        assert client.get("/admin").json() == {"device": "nLaptop1CNTRL"}
        assert client.get("/tagged").status_code == 403
        assert calls == ["nLaptop1CNTRL"]
        assert client.post("/bytebind/logout", headers={"Origin": "https://evil.example"}).status_code == 403
        assert client.post("/bytebind/logout").status_code == 204
        assert client.get("/admin").status_code == 401
        who = client.post("/bytebind/please").json()
        assert client.post("/bytebind/affirm", json=browser_prove(authority, who)).status_code == 200
        clock.now += 181
        assert client.get("/admin").status_code == 401


def test_discovery(monkeypatch, tmp_path):
    monkeypatch.setenv("BYTEBIND_AUTHORITY", "unix:/tmp/authority.sock")
    monkeypatch.setenv("BYTEBIND_RP_DB", str(tmp_path / "rp.sqlite3"))
    app = FastAPI()
    bind = ByteBind(app)
    assert bind.authority == "unix:/tmp/authority.sock"
    assert app.state.bytebind is bind
    assert "/bytebind/please" in app.openapi()["paths"] or any(r.path == "/bytebind/please" for r in app.routes)


def test_tag_claims_and_sync_handlers(tmp_path):
    from bytebind.rp import Lease

    class RP:
        def session(self, token):
            if token == "valid":
                return Lease("node", {"tags": ["tag:admin"]}, 9999999999)
            if token == "wrong-claim":
                return Lease("node", {"authorization": ["tag:admin"]}, 9999999999)
            return None

    app = FastAPI()
    bind = ByteBind(app, rp=RP())

    @app.get("/admin")
    @bind(require=["tag:admin"], grant=bind.LEASE)
    def admin(lease=bind.lease):
        return {"device": lease.device_id}

    with TestClient(app, base_url=APP) as client:
        client.cookies.set("bytebind_session", "valid")
        response = client.get("/admin")
        assert response.json() == {"device": "node"}
        assert response.headers["cache-control"] == "no-store"
        client.cookies.set("bytebind_session", "wrong-claim")
        assert client.get("/admin").status_code == 403


def test_default_adapter_discovers_remote_authority(config, unix_control, tmp_path, monkeypatch):
    from bytebind import discovery
    from test_discovery import Directory

    path, store = unix_control
    endpoints = []

    def control_transport(endpoint):
        endpoints.append(endpoint)
        # Exercise a real Authority exchange through the test's Unix transport.
        return AuthorityClient(f"unix:{path}")

    monkeypatch.delenv("BYTEBIND_AUTHORITY", raising=False)
    monkeypatch.setattr(discovery, "AuthorityClient", control_transport)
    app = FastAPI()
    directory = Directory()
    bind = ByteBind(app, directory=directory, origin=APP, database=str(tmp_path / "discovered.sqlite3"))
    assert bind.authority is None
    bind._authority_client.local_socket = str(tmp_path / "absent")

    @app.get("/admin")
    @bind(require=["manage:read"], grant=bind.LEASE)
    async def admin(lease=bind.lease):
        return {"device": lease.device_id}

    with TestClient(app, base_url=APP, headers={"Origin": APP}) as client, TestClient(
        create_attest_app(config, FakeTailnet(), store), base_url=ATTEST, client=(PEER, 40000)
    ) as authority:
        assert client.get("/admin").status_code == 401
        assert not endpoints, "session checks must not require Authority discovery"
        directory.peer["Tags"] = []
        assert client.post("/bytebind/please").status_code == 503
        directory.peer["Tags"] = [discovery.AUTHORITY_TAG]
        who = client.post("/bytebind/please").json()
        assert client.post("/bytebind/affirm", json=browser_prove(authority, who)).status_code == 200
        assert client.get("/admin").json() == {"device": "nLaptop1CNTRL"}
        assert endpoints == ["https://authority.tail123.ts.net:9443"] * 2
