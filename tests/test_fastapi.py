from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient

from bytebind.fastapi import ByteBind
from bytebind.rp import AuthorityClient, RelyingParty
from conftest import APP, ATTEST_URL, PEER, FakeTailnet
from bytebind.authority import create_attest_app
from test_end_to_end import browser_proof


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

    @app.get("/dashboard", response_class=HTMLResponse)
    @bind(require=["manage:read"])
    def dashboard():
        return "<html><body>Private</body></html>"

    with TestClient(app, base_url=APP, headers={"Origin": APP}) as client, TestClient(
        create_attest_app(config, FakeTailnet(), store), base_url=ATTEST_URL, client=(PEER, 40000)
    ) as authority:
        assert client.get("/admin").status_code == 401
        denied = client.get("/admin", headers={"Accept": "text/html"})
        assert denied.status_code == 401 and "location.reload()" in denied.text
        assert not calls
        assert client.get("/page").text == "<html><body>Hello</body></html>", "public pages never start ceremonies"
        assert client.get("/bytebind/client.js").status_code == 200
        assert client.post("/bytebind/challenge", headers={"Origin": "https://evil.example"}).status_code == 403
        challenge = client.post("/bytebind/challenge").json()
        accepted = client.post("/bytebind/proof", json=browser_proof(authority, challenge))
        assert accepted.status_code == 200
        assert "expires" not in accepted.json()
        assert client.get("/admin").json() == {"device": "nLaptop1CNTRL"}
        dashboard = client.get("/dashboard")
        assert '/bytebind/client.js' in dashboard.text and dashboard.text.endswith("</body></html>")
        assert int(dashboard.headers["content-length"]) == len(dashboard.content)
        assert client.get("/tagged").status_code == 403
        assert calls == ["nLaptop1CNTRL"]
        assert client.post("/bytebind/logout", headers={"Origin": "https://evil.example"}).status_code == 403
        assert client.post("/bytebind/logout").status_code == 204
        assert client.get("/admin").status_code == 401
        challenge = client.post("/bytebind/challenge").json()
        assert client.post("/bytebind/proof", json=browser_proof(authority, challenge)).status_code == 200
        clock.now += 181
        assert client.get("/admin").status_code == 401


def test_discovery(monkeypatch, tmp_path):
    monkeypatch.setenv("BYTEBIND_AUTHORITY", "unix:/tmp/authority.sock")
    monkeypatch.setenv("BYTEBIND_RP_DB", str(tmp_path / "rp.sqlite3"))
    app = FastAPI()
    bind = ByteBind(app)
    assert bind.authority == "unix:/tmp/authority.sock"
    assert app.state.bytebind is bind
    assert "/bytebind/challenge" in app.openapi()["paths"] or any(r.path == "/bytebind/challenge" for r in app.routes)


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
        create_attest_app(config, FakeTailnet(), store), base_url=ATTEST_URL, client=(PEER, 40000)
    ) as authority:
        assert client.get("/admin").status_code == 401
        assert not endpoints, "session checks must not require Authority discovery"
        directory.peer["Tags"] = []
        assert client.post("/bytebind/challenge").status_code == 503
        directory.peer["Tags"] = [discovery.AUTHORITY_TAG]
        challenge = client.post("/bytebind/challenge").json()
        assert client.post("/bytebind/proof", json=browser_proof(authority, challenge)).status_code == 200
        assert client.get("/admin").json() == {"device": "nLaptop1CNTRL"}
        assert endpoints == ["https://authority.tail123.ts.net:9443"] * 2


def test_ceremony_starts_are_rate_limited_per_client():
    class RP:
        def challenge(self, origin):
            return {"cid": "c", "C": "k", "authority": ATTEST_URL}, "state"

    app = FastAPI()
    ByteBind(app, rp=RP(), challenge_per_minute=2)
    with TestClient(app, base_url=APP, headers={"Origin": APP}) as client, TestClient(
        app, base_url=APP, headers={"Origin": APP}, client=("198.51.100.7", 1)
    ) as elsewhere:
        assert [client.post("/bytebind/challenge").status_code for _ in range(3)] == [200, 200, 429]
        assert elsewhere.post("/bytebind/challenge").status_code == 200


def test_renewal_keeps_its_interval_after_a_failure():
    script = ByteBind._script(False)
    failure = script[script.index("catch(e){"):]
    assert "setTimeout(renew,ByteBind.RENEW_INTERVAL_MS)" in failure
    assert "setTimeout" not in ByteBind._script(True), "the sign-in page reports failure instead"


def test_transaction_grant_runs_the_handler_once_after_approval(config, unix_control, tmp_path, clock):
    from pydantic import BaseModel

    from bytebind.protocol import request_digest

    path, store = unix_control
    rp = RelyingParty(AuthorityClient(f"unix:{path}"), origin=APP, audience="manage",
                      database=str(tmp_path / "rp.sqlite3"), now=clock)
    app = FastAPI()
    bind = ByteBind(app, rp=rp, max_transaction_body=64)
    runs = []

    class Deploy(BaseModel):
        version: str

    @app.post("/deploy")
    @bind(require=["manage:read"], grant=bind.TRANSACTION)
    def deploy(body: Deploy, grant=bind.grant):  # sync handlers work too
        runs.append((body.version, grant.device_id))
        return {"deployed": body.version}

    @app.post("/wipe")
    @bind(require=["tag:admin"], grant=bind.TRANSACTION)
    async def wipe():
        runs.append("wipe")
        return {}

    def approve(client, authority, url, body):
        challenged = client.post(url, content=body, headers={"Content-Type": "application/json"})
        assert challenged.status_code == 202 and set(challenged.json()) == {"cid", "C", "authority"}
        q = request_digest("POST", url, {"content-type": "application/json"}, body)
        return browser_proof(authority, challenged.json(), "tx", q)

    with TestClient(app, base_url=APP, headers={"Origin": APP}) as client, TestClient(
        create_attest_app(config, FakeTailnet(), store), base_url=ATTEST_URL, client=(PEER, 40000)
    ) as authority:
        proof = approve(client, authority, "/deploy", b'{"version":"1.2"}')
        assert runs == [], "the access request runs nothing"
        approved = client.post("/bytebind/proof", json=proof)
        assert approved.status_code == 200 and approved.json() == {"deployed": "1.2"}
        assert approved.headers["cache-control"] == "no-store"
        assert runs == [("1.2", "nLaptop1CNTRL")]
        assert client.post("/bytebind/proof", json=proof).status_code == 401, "one approval, one run"
        assert runs == [("1.2", "nLaptop1CNTRL")]

        # The grant is checked against the handler's requirements before it runs.
        assert client.post("/bytebind/proof", json=approve(client, authority, "/wipe", b"{}")).status_code == 403
        assert "wipe" not in runs

        assert client.post("/deploy", json={"version": "1.3"}, headers={"Origin": "https://evil.example"}).status_code == 403
        assert client.post("/deploy", json={"version": "x" * 100}).status_code == 413
        assert client.post("/deploy", json={"wrong": 1}).status_code == 422, "invalid requests never reach the Authority"
        assert len(runs) == 1
