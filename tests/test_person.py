"""Signed WebAuthn fixtures exercise the actual pinned verifier, not a mock verifier."""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from fido2 import cbor
from fido2.cose import ES256
from fido2.webauthn import AttestedCredentialData, AuthenticatorData, CollectedClientData

from bytebind import protocol as p
from bytebind.authority import Control, ControlError, attest, create_attest_app, open_store
from bytebind.config import parse, ConfigError
from bytebind.person import PersonService
from bytebind.person_http import create_person_app
from bytebind.rp import RelyingParty, CeremonyError
from bytebind.store import TransactionError
from conftest import APP, ATTEST_URL, PEER, NODE, FakeTailnet, config_data

PERSON = "https://authority.tail1234.ts.net:8444"


class Authenticator:
    def __init__(self, rp_id):
        self.rp_id = rp_id
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cid = secrets.token_bytes(32)
        self.credential = AttestedCredentialData.create(
            bytes(16), self.cid, ES256.from_cryptography_key(self.key.public_key())
        )
        self.counter = 0
        self.user = None

    def register(self, options, *, uv=True):
        pk = options["publicKey"]
        self.user = p.b64decode(pk["user"]["id"], 32)
        data = CollectedClientData.create("webauthn.create", pk["challenge"], PERSON)
        flags = AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT
        if uv:
            flags |= AuthenticatorData.FLAG.UV
        auth = AuthenticatorData.create(
            hashlib.sha256(self.rp_id.encode()).digest(), flags, self.counter, self.credential
        )
        return {
            "id": p.b64encode(self.cid),
            "rawId": p.b64encode(self.cid),
            "type": "public-key",
            "clientExtensionResults": {"credProps": {"rk": True}},
            "response": {
                "clientDataJSON": p.b64encode(data),
                "attestationObject": p.b64encode(
                    cbor.encode({"fmt": "none", "attStmt": {}, "authData": bytes(auth)})
                ),
            },
        }

    def assertion(
        self, options, *, uv=True, up=True, cross=True, top=APP, origin=PERSON, challenge=None, counter=None
    ):
        pk = options["publicKey"]
        self.counter += 1
        kwargs = {"topOrigin": top} if top is not None else {}
        data = CollectedClientData.create(
            "webauthn.get", challenge or pk["challenge"], origin, cross_origin=cross, **kwargs
        )
        flags = (AuthenticatorData.FLAG.UP if up else 0) | (AuthenticatorData.FLAG.UV if uv else 0)
        auth = AuthenticatorData.create(
            hashlib.sha256(self.rp_id.encode()).digest(), flags, self.counter if counter is None else counter
        )
        signature = self.key.sign(bytes(auth) + data.hash, ec.ECDSA(hashes.SHA256()))
        return {
            "id": p.b64encode(self.cid),
            "rawId": p.b64encode(self.cid),
            "type": "public-key",
            "clientExtensionResults": {},
            "response": {
                "clientDataJSON": p.b64encode(data),
                "authenticatorData": p.b64encode(auth),
                "signature": p.b64encode(signature),
                "userHandle": p.b64encode(self.user),
            },
        }


@pytest.fixture
def world(tmp_path, clock):
    data = config_data(
        str(tmp_path / "authority.db"),
        assurances=["device", "presence", "verification"],
        claims=["device_id", "tags", "person_subject"],
    )
    data["person"] = {"origin": PERSON, "enrollment_tags": ["tag:enrollment"]}
    config = parse(data)
    store = open_store(config, clock)
    tailnet = FakeTailnet({PEER: (NODE, ["tag:mgmt", "tag:enrollment"], False, 0)})
    service = PersonService(config, store)
    invite, subject = service.invite("Independent person")
    options = service.enrollment_begin(NODE, invite=invite)
    authenticator = Authenticator(service.rp_id)
    service.enrollment_complete(
        options["token"], NODE, authenticator.register(options["options"]), "Platform passkey"
    )
    with (
        TestClient(
            create_person_app(config, tailnet, store),
            base_url=PERSON,
            client=(PEER, 1),
            headers={"Origin": PERSON},
        ) as person,
        TestClient(
            create_attest_app(config, tailnet, store),
            base_url=ATTEST_URL,
            client=(PEER, 1),
            headers={"Origin": APP},
        ) as base,
    ):
        yield config, store, tailnet, service, authenticator, person, base, clock, subject


def start(world, assurance="verification", profile="session", identify=False):
    config, store, _, _, _, _, base, _, _ = world
    control = Control(config, store, world[2])
    request = {
        "protocol": 1,
        "draft": "0.8",
        "audience": "manage",
        "profile": profile,
        "assurance": assurance,
        "identify": identify,
    }
    if profile == "session":
        request.update(lease_id=p.b64encode(secrets.token_bytes(32)), person_max_age=600)
    else:
        request["Q"] = p.b64encode(
            p.request_digest("POST", "/destroy", {"content-type": "application/json"}, b"{}")
        )
    challenge = control.begin(config.rps["app"], request)
    cid = p.b64decode(challenge["cid"], 16)
    c = p.b64decode(challenge["C"], 32)
    n = secrets.token_bytes(32)
    q = p.b64decode(request["Q"], 32) if profile == "tx" else None
    h1 = p.compute_h1(profile, c, cid, n, q)
    response = base.post(
        "/attestation", json={"cid": challenge["cid"], "N": p.b64encode(n), "H1": p.b64encode(h1)}
    )
    assert response.status_code == 202 and "H2" not in response.json()
    return challenge, response.json()["step_up"], n, h1, control, q


def exchange(world, step):
    person = world[5]
    response = person.post("/step-up/handoff", json={"handoff": step["handoff"], "rp_id": "app"})
    assert response.status_code == 200, response.text
    return response.json()


def finish(world, start_result, *, assertion_kwargs=None):
    challenge, step, n, h1, control, q = start_result
    exchange_result = exchange(world, step)
    response = world[5].post(
        "/step-up/assertion",
        headers={"X-ByteBind-Attempt": exchange_result["token"]},
        json={"credential": world[4].assertion(exchange_result["options"], **(assertion_kwargs or {}))},
    )
    assert response.status_code == 200, response.text
    result = world[6].post(
        "/attestation/result",
        json={
            "cid": challenge["cid"],
            "completion": step["completion"],
            "N": p.b64encode(n),
            "H1": p.b64encode(h1),
        },
    )
    assert result.status_code == 200, result.text
    c = p.b64decode(challenge["C"], 32)
    cid = p.b64decode(challenge["cid"], 16)
    profile = "tx" if q else "session"
    ip, secret = p.open_h2(profile, c, cid, n, h1, p.b64decode(result.json()["H2"], 76))
    proof = {
        "cid": challenge["cid"],
        "R": p.b64encode(p.compute_r(profile, secret, cid, c, ip, q)),
        "audience": "manage",
    }
    return control.redeem(world[0].rps["app"], proof)


def test_actual_signed_passkey_transaction(world):
    grant = finish(world, start(world, profile="tx", identify=True))
    assert grant["assurance"]["fresh_for_transaction"] is True
    assert grant["claims"]["person_subject"].startswith("ps_")
    assert not {"credential_id", "user_handle", "public_key"} & set(grant["claims"])


@pytest.mark.parametrize(
    "kwargs",
    [
        {"cross": False},
        {"top": "https://evil.example"},
        {"origin": APP},
        {"uv": False},
        {"up": False},
        {"challenge": p.b64encode(bytes(32))},
        {"counter": 0},
    ],
)
def test_assertion_failures_burn_expected_generation(world, kwargs):
    challenge, step, *_ = start(world)
    x = exchange(world, step)
    response = world[5].post(
        "/step-up/assertion",
        headers={"X-ByteBind-Attempt": x["token"]},
        json={"credential": world[4].assertion(x["options"], **kwargs)},
    )
    # Zero stored/received counters are deliberately allowed.
    if kwargs == {"counter": 0}:
        assert response.status_code == 200
        return
    assert response.status_code == 403
    assert world[1].record(p.b64decode(challenge["cid"], 16))["status"] == "burned"


def test_missing_top_origin_is_supported_and_presence_does_not_require_uv(world):
    grant = finish(world, start(world, assurance="presence"), assertion_kwargs={"top": None, "uv": False})
    assert grant["assurance"]["user_present"] and not grant["assurance"]["user_verified"]


def test_base_first_replay_and_framing(world):
    config, store, tailnet, service, auth, person, base, *_ = world
    assert (
        person.post("/step-up/handoff", json={"handoff": p.b64encode(bytes(32)), "rp_id": "app"}).status_code
        == 403
    )
    assert person.get("/step-up/app").headers["content-security-policy"].endswith("form-action 'none'")
    assert "frame-ancestors " + APP + ";" in person.get("/step-up/app").headers["content-security-policy"]
    assert "frame-ancestors 'none'" in person.get("/enroll").headers["content-security-policy"]
    assert person.get("/step-up/unknown").status_code == 404
    _, step, *_ = start(world)
    exchange(world, step)
    assert (
        person.post("/step-up/handoff", json={"handoff": step["handoff"], "rp_id": "app"}).status_code == 403
    )
    assert person.post("/attestation", json={}).status_code == 404
    assert (
        "access-control-allow-origin"
        not in person.options("/step-up/handoff", headers={"Origin": APP}).headers
    )


def test_wrong_handoff_rp_and_peer(world):
    ch, step, *_ = start(world)
    assert (
        world[5].post("/step-up/handoff", json={"handoff": step["handoff"], "rp_id": "other"}).status_code
        == 403
    )
    assert world[1].record(p.b64decode(ch["cid"], 16))["status"] == "burned"


def test_result_delivered_once_and_deadline_starts_at_delivery(world):
    ch, step, n, h1, control, q = start(world)
    x = exchange(world, step)
    world[7].now += 40
    assert (
        world[5]
        .post(
            "/step-up/assertion",
            headers={"X-ByteBind-Attempt": x["token"]},
            json={"credential": world[4].assertion(x["options"])},
        )
        .status_code
        == 200
    )
    cid = p.b64decode(ch["cid"], 16)
    row = world[1].record(cid)
    assert row["redeem_expires_at"] is None
    world[7].now += 20
    body = {"cid": ch["cid"], "completion": step["completion"], "N": p.b64encode(n), "H1": p.b64encode(h1)}
    assert world[6].post("/attestation/result", json=body).status_code == 200
    assert world[1].record(cid)["redeem_expires_at"] == world[7].now + 10
    assert world[6].post("/attestation/result", json=body).status_code == 403


def test_expiry_and_current_device_policy(world):
    ch, step, *_ = start(world)
    x = exchange(world, step)
    world[2].peers[PEER] = (NODE, ["tag:enrollment"], False, 0)
    assert (
        world[5]
        .post(
            "/step-up/assertion",
            headers={"X-ByteBind-Attempt": x["token"]},
            json={"credential": world[4].assertion(x["options"])},
        )
        .status_code
        == 403
    )
    world[7].now += 121
    with pytest.raises(TransactionError):
        world[3].verify(x["token"], world[4].assertion(x["options"]))


def test_enrollment_never_uses_owner_or_device_tag_as_person(world):
    service = world[3]
    with pytest.raises(TransactionError):
        service.enrollment_begin(NODE)
    invite, subject = service.invite("Second human")
    second = service.enrollment_begin(NODE, invite=invite)
    with pytest.raises(TransactionError):
        service.enrollment_begin(NODE, invite=invite)
    authenticator = Authenticator(service.rp_id)
    service.enrollment_complete(
        second["token"], NODE, authenticator.register(second["options"]), "Second key"
    )
    assert authenticator.user != world[4].user
    with pytest.raises(TransactionError):
        service.enrollment_complete(
            second["token"], NODE, authenticator.register(second["options"]), "Replay"
        )


def test_management_uv_revoke_invalidates_association(world):
    grant = finish(world, start(world))
    store = world[1]
    association = store._read("SELECT lease_id FROM person_associations")[0]
    assert store.validate_association(
        "app", "manage", association, grant["person_association"], grant["device_grant"]
    )["active"]
    login = world[3].management_begin(NODE)
    verified = world[3].management_complete(
        login["token"], NODE, world[4].assertion(login["options"], cross=False, top=None)
    )
    world[3].manage(verified["token"], NODE, "revoke", p.b64encode(world[4].cid))
    with pytest.raises(TransactionError):
        store.validate_association(
            "app", "manage", association, grant["person_association"], grant["device_grant"]
        )


def test_foreign_origin_and_host_dont_consume_handoff(world):
    ch, step, *_ = start(world)
    for headers in ({"Origin": APP}, {"Host": "evil.example"}):
        assert (
            world[5]
            .post("/step-up/handoff", json={"handoff": step["handoff"], "rp_id": "app"}, headers=headers)
            .status_code
            == 403
        )
    assert world[1].record(p.b64decode(ch["cid"], 16))["status"] == "base_attested"
    exchange(world, step)


def test_marker_and_assurance_fail_closed(world):
    control = Control(world[0], world[1], world[2])
    rp = world[0].rps["app"]
    for body in (
        {"audience": "manage", "profile": "session"},
        {
            "protocol": 1,
            "draft": "0.7",
            "assurance": "verification",
            "audience": "manage",
            "profile": "session",
        },
    ):
        with pytest.raises(ControlError):
            control.begin(rp, body)


def test_pairwise_namespaces_and_new_transcript():
    key = bytes(range(32))
    subject = bytes(32)
    assert p.pairwise_subject(key, "rp-a", subject) != p.pairwise_subject(key, "rp-b", subject)
    assert p.person_challenge(bytes(16), bytes(32), bytes(32)) != p.person_challenge(
        bytes(16), bytes(32), b"x" * 32
    )


def test_published_person_vectors():
    from pathlib import Path

    vector = json.loads(
        (Path(__file__).resolve().parents[1] / "test-vectors/bytebind-v1-person.json").read_text()
    )
    assert (
        p.b64encode(
            p.person_challenge(
                p.b64decode(vector["cid"], 16), p.b64decode(vector["H1"], 32), p.b64decode(vector["w"], 32)
            )
        )
        == vector["W"]
    )
    assert (
        p.pairwise_subject(
            p.b64decode(vector["key"], 32), vector["rp_id"], p.b64decode(vector["subject_id"], 32)
        )
        == vector["person_subject"]
    )


class InProcessControl:
    endpoint = "https://authority.tail1234.ts.net:9443"

    def __init__(self, world):
        self.control = Control(world[0], world[1], world[2])
        self.rp = world[0].rps["app"]

    def begin(self, audience, profile="session", q=None, **kwargs):
        body = {
            "protocol": 1,
            "draft": "0.8",
            "audience": audience,
            "profile": profile,
            "assurance": kwargs.get("assurance", "device"),
        }
        if profile == "tx":
            body["Q"] = p.b64encode(q)
        else:
            body["lease_id"] = kwargs["lease_id"]
        if kwargs.get("person_max_age") is not None:
            body["person_max_age"] = kwargs["person_max_age"]
        if kwargs.get("identify"):
            body["identify"] = True
        return self.control.begin(self.rp, body)

    def redeem(self, cid, r, audience):
        return self.control.redeem(self.rp, {"cid": cid, "R": r, "audience": audience})

    def _post(self, path, body):
        return self.control.handle(self.rp, path, json.dumps(body).encode())


def prove_rp(world, challenge, assurance="device"):
    cid = p.b64decode(challenge["cid"], 16)
    c = p.b64decode(challenge["C"], 32)
    n = secrets.token_bytes(32)
    h1 = p.compute_h1("session", c, cid, n)
    response = world[6].post(
        "/attestation", json={"cid": challenge["cid"], "N": p.b64encode(n), "H1": p.b64encode(h1)}
    )
    if assurance != "device":
        step = response.json()["step_up"]
        x = exchange(world, step)
        assert (
            world[5]
            .post(
                "/step-up/assertion",
                headers={"X-ByteBind-Attempt": x["token"]},
                json={"credential": world[4].assertion(x["options"])},
            )
            .status_code
            == 200
        )
        response = world[6].post(
            "/attestation/result",
            json={
                "cid": challenge["cid"],
                "completion": step["completion"],
                "N": p.b64encode(n),
                "H1": p.b64encode(h1),
            },
        )
    assert response.status_code == 200, response.text
    ip, s = p.open_h2("session", c, cid, n, h1, p.b64decode(response.json()["H2"], 76))
    return {"cid": challenge["cid"], "R": p.b64encode(p.compute_r("session", s, cid, c, ip))}


def test_device_renewal_preserves_person_without_refreshing_it(world, tmp_path):
    rp = RelyingParty(
        InProcessControl(world), origin=APP, audience="manage", database=str(tmp_path / "rp.db"), now=world[7]
    )
    challenge, state = rp.challenge(APP, assurance="verification", person_max_age=600, identify=True)
    accepted = rp.accept_proof(APP, prove_rp(world, challenge, "verification"), state)
    original = accepted.lease.context
    world[7].now += 60
    challenge, state = rp.challenge(APP, previous_session=accepted.session_token)
    renewed = rp.accept_proof(APP, prove_rp(world, challenge), state, accepted.session_token)
    assert renewed.lease.context["person_at"] == original["person_at"]
    assert renewed.lease.context["person_deadline"] == original["person_deadline"]
    assert renewed.lease.context["association"] == original["association"]
    checked = rp.require_person(renewed.session_token, "verification", 300, True)
    assert checked.claims["person_subject"].startswith("ps_")
    # A different browser lease has no association even on the same device.
    challenge, state = rp.challenge(APP)
    separate = rp.accept_proof(APP, prove_rp(world, challenge), state)
    with pytest.raises(CeremonyError):
        rp.require_person(separate.session_token, "verification", 300)
    assert rp.session(renewed.session_token)
    with pytest.raises(CeremonyError):
        rp.require_person(renewed.session_token, "verification", 30)
    rp.end_session(renewed.session_token)
    assert world[1]._read(
        "SELECT active FROM person_associations WHERE handle_hash=?",
        (__import__("bytebind.store", fromlist=["token_hash"]).token_hash(original["association"]),),
    ) == (0,)


def test_person_endpoint_validates_before_handler_and_blocks_on_outage(world, tmp_path):
    from fastapi import FastAPI
    from bytebind.fastapi import ByteBind
    from bytebind.binding import SESSION_COOKIE, STATE_COOKIE
    from bytebind.rp import AuthorityError

    rp = RelyingParty(
        InProcessControl(world), origin=APP, audience="manage", database=str(tmp_path / "rp.db"), now=world[7]
    )
    app = FastAPI()
    bind = ByteBind(app, rp=rp)
    calls = []

    @app.get("/verified")
    @bind(assurance="verification", person_max_age=300, identify=True)
    def handler(lease=bind.lease):
        calls.append("verified")
        return {"person": lease.claims["person_subject"]}

    @app.get("/device")
    @bind()
    def device():
        return {"ok": True}

    with TestClient(app, base_url=APP, headers={"Origin": APP}) as client:
        assert client.get("/verified").status_code == 401 and not calls
        challenge = client.post("/bytebind/challenge", json={"target": "/verified"}).json()
        assert "person_origin" in challenge
        assert (
            client.post("/bytebind/proof", json=prove_rp(world, challenge, "verification")).status_code == 200
        )
        assert client.get("/verified").json()["person"].startswith("ps_") and calls == ["verified"]
        real = rp.authority._post

        def outage(*args, **kwargs):
            raise AuthorityError(503, "unavailable")

        rp.authority._post = outage
        assert client.get("/verified").status_code == 503 and calls == ["verified"]
        assert client.get("/device").status_code == 200
        rp.authority._post = real


def test_redeem_rechecks_current_device_authorization(world):
    ch, step, n, h1, control, q = start(world)
    x = exchange(world, step)
    assert (
        world[5]
        .post(
            "/step-up/assertion",
            headers={"X-ByteBind-Attempt": x["token"]},
            json={"credential": world[4].assertion(x["options"])},
        )
        .status_code
        == 200
    )
    cid = p.b64decode(ch["cid"], 16)
    c = p.b64decode(ch["C"], 32)
    response = world[6].post(
        "/attestation/result",
        json={"cid": ch["cid"], "completion": step["completion"], "N": p.b64encode(n), "H1": p.b64encode(h1)},
    )
    ip, s = p.open_h2("session", c, cid, n, h1, p.b64decode(response.json()["H2"], 76))
    world[2].peers[PEER] = (NODE, ["tag:enrollment"], False, 0)
    with pytest.raises(ControlError):
        control.redeem(
            world[0].rps["app"],
            {"cid": ch["cid"], "R": p.b64encode(p.compute_r("session", s, cid, c, ip)), "audience": "manage"},
        )
    assert world[1].record(cid)["status"] == "burned"


def test_old_association_cannot_follow_a_different_device_grant(world):
    grant = finish(world, start(world))
    store = world[1]
    lease = store._read("SELECT lease_id FROM person_associations")[0]
    row = {"rp_id": "app", "audience": "manage", "lease_id": lease, "attested_peer_id": "different-node"}
    reference = store.device_reference(row, 180)
    with pytest.raises(TransactionError):
        store.validate_association("app", "manage", lease, grant["person_association"], reference)
    with pytest.raises(TransactionError):
        store.validate_association("app", "manage", lease, grant["person_association"], grant["device_grant"])


def test_counter_regression_after_success_is_refused(world, caplog):
    finish(world, start(world))
    challenge, step, *_ = start(world)
    attempt = exchange(world, step)
    response = world[5].post(
        "/step-up/assertion",
        headers={"X-ByteBind-Attempt": attempt["token"]},
        json={"credential": world[4].assertion(attempt["options"], counter=1)},
    )
    assert response.status_code == 403
    assert world[1].record(p.b64decode(challenge["cid"], 16))["status"] == "burned"
    assert "operator review required" in caplog.text


def test_app_facing_lease_contains_no_internal_handles(world, tmp_path):
    from bytebind.binding import lease_view
    from dataclasses import asdict

    rp = RelyingParty(
        InProcessControl(world), origin=APP, audience="manage", database=str(tmp_path / "rp.db"), now=world[7]
    )
    challenge, state = rp.challenge(APP, assurance="verification", person_max_age=300, identify=True)
    accepted = rp.accept_proof(APP, prove_rp(world, challenge, "verification"), state)
    exposed = asdict(lease_view(accepted.lease))
    assert set(exposed) == {"device_id", "claims", "assurance"}
    serialized = json.dumps(exposed)
    for key in ("association", "device_grant", "lease_id"):
        assert accepted.lease.context[key] not in serialized


def test_headless_step_up_does_not_read_or_expose_handoff():
    from bytebind._client import response_json, StepUpRequired

    class Response:
        status_code = 202

        def json(self):
            raise AssertionError("headless client must not consume the handoff")

    with pytest.raises(StepUpRequired) as caught:
        response_json(Response(), "attestation")
    assert not vars(caught.value)


def test_person_attempt_quota_is_atomic(world):
    from concurrent.futures import ThreadPoolExecutor

    service = world[3]

    def begin(_):
        try:
            service.management_begin(NODE)
            return True
        except TransactionError:
            return False

    with ThreadPoolExecutor(max_workers=8) as workers:
        results = list(workers.map(begin, range(30)))
    assert sum(results) == 20
    assert world[1]._read("SELECT COUNT(*) FROM person_attempts WHERE used=0")[0] == 20


def test_flask_person_binding_validates_before_handler(world, tmp_path):
    from flask import Flask
    from bytebind.flask import ByteBind
    from bytebind.rp import AuthorityError

    rp = RelyingParty(
        InProcessControl(world),
        origin=APP,
        audience="manage",
        database=str(tmp_path / "flask.db"),
        now=world[7],
    )
    app = Flask(__name__)
    bind = ByteBind(app, rp=rp)
    calls = []

    @app.get("/verified")
    @bind(assurance="verification", person_max_age=300, identify=True)
    def handler(lease=bind.lease):
        calls.append(True)
        assert not hasattr(lease, "context")
        return {"person": lease.claims["person_subject"]}

    client = app.test_client()
    assert client.get("/verified", base_url=APP).status_code == 401 and not calls
    challenge = client.post(
        "/bytebind/challenge", base_url=APP, headers={"Origin": APP}, json={"target": "/verified"}
    ).json
    proof = prove_rp(world, challenge, "verification")
    assert (
        client.post("/bytebind/proof", base_url=APP, headers={"Origin": APP}, json=proof).status_code == 200
    )
    assert client.get("/verified", base_url=APP).json["person"].startswith("ps_") and calls == [True]

    def outage(*args, **kwargs):
        raise AuthorityError(503, "unavailable")

    rp.authority._post = outage
    assert client.get("/verified", base_url=APP).status_code == 503 and calls == [True]


def test_poll_cadence_limiter():
    from bytebind.limits import PeerLimiter

    now = [0.0]
    limiter = PeerLimiter(30, lambda: now[0], minimum_interval=2)
    assert limiter.allow("peer:cid")
    now[0] = 1.99
    assert not limiter.allow("peer:cid")
    now[0] = 2
    assert limiter.allow("peer:cid")


def test_concurrent_assertions_cannot_burn_the_winner(world):
    from concurrent.futures import ThreadPoolExecutor

    challenge, step, *_ = start(world)
    attempt = exchange(world, step)
    assertion = world[4].assertion(attempt["options"])

    def verify(_):
        try:
            world[3].verify(attempt["token"], assertion)
            return True
        except TransactionError:
            return False

    with ThreadPoolExecutor(max_workers=4) as workers:
        results = list(workers.map(verify, range(4)))
    assert sum(results) == 1
    cid = p.b64decode(challenge["cid"], 16)
    assert world[1].record(cid)["status"] == "redeemable"

    def deliver(_):
        try:
            world[1].reserve_delivery(cid)
            return True
        except TransactionError:
            return False

    with ThreadPoolExecutor(max_workers=4) as workers:
        assert sum(workers.map(deliver, range(4))) == 1
    assert world[1].record(cid)["status"] == "redeemable"
