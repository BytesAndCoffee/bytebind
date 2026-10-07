"""Human enrollment codes preserve one-use authorization and durable guess budgets."""

import re
import secrets
from concurrent.futures import ThreadPoolExecutor

import pytest

from bytebind import protocol as p
from bytebind.person import EnrollmentRateLimited, PersonService
from bytebind.store import invite_hash, token_hash
from conftest import NODE, PEER
from test_person import world  # noqa: F401 -- signed-credential Authority fixture


@pytest.mark.parametrize("formatting", ["display", "lower", "compact", "padded"])
def test_short_invites_normalize_and_are_one_use(world, formatting):
    service = world[3]
    code, _ = service.invite("Participant")
    assert re.fullmatch(r"[0-9A-F]{4}-[0-9A-F]{4}", code)
    submitted = {"display": code, "lower": code.lower(), "compact": code.replace("-", ""), "padded": " \t" + code + "\n"}[formatting]
    assert invite_hash(submitted) == invite_hash(code)
    assert len(invite_hash(code)) == 32
    with pytest.raises(p.ProtocolError):
        token_hash(code)  # Short invites cannot become handoffs or management tokens.
    service.enrollment_begin(NODE, invite=submitted)
    with pytest.raises(Exception) as refused:
        service.enrollment_begin(NODE, invite=code)
    assert str(refused.value) == "invite unavailable"


@pytest.mark.parametrize("ttl", [0, 901, 86400, True])
def test_short_invite_lifetime_is_bounded(world, ttl):
    with pytest.raises(ValueError):
        world[3].invite("Participant", ttl=ttl)


def test_expiry_and_used_code_collisions(world, monkeypatch):
    service = world[3]
    codes = iter(["ab12cd34", "ab12cd34", "55667788", "ab12cd34", "11223344", "ab12cd34"])
    monkeypatch.setattr(secrets, "token_hex", lambda count: next(codes))
    first, _ = service.invite("First")
    second, _ = service.invite("Second")
    assert first == "AB12-CD34" and second == "5566-7788"
    service.enrollment_begin(NODE, invite=first)
    third, _ = service.invite("Third")
    assert third == "1122-3344", "consumed codes remain reserved until expiry"
    world[7].now += 900
    with pytest.raises(Exception, match="invite unavailable"):
        service.enrollment_begin(NODE, invite=second)
    fourth, _ = service.invite("Fourth")
    assert fourth == first, "expired records can be replaced"
    service.enrollment_begin(NODE, invite=fourth)


def test_previously_issued_long_invite_remains_usable(world):
    code, subject = world[3].invite("Existing operator invite")
    legacy = p.b64encode(secrets.token_bytes(32))
    world[1]._write("INSERT INTO invites VALUES (?,?,?,0)", (token_hash(legacy), p.b64decode(subject, 32), world[7].now + 60))
    assert world[3].enrollment_begin(NODE, invite=legacy)["token"]
    assert world[1]._read("SELECT used FROM invites WHERE token_hash=?", (invite_hash(code),))[0] == 0


def fail(service, device=NODE):
    try:
        service.enrollment_begin(device, invite="invalid")
    except EnrollmentRateLimited:
        return "limited"
    except Exception as error:
        assert str(error) == "invite unavailable"
        return "failed"
    raise AssertionError("bad invite accepted")


def test_device_budget_survives_recreation_and_success_does_not_reset_it(world):
    service = world[3]
    for _ in range(9):
        assert fail(service) == "failed"
    code, _ = service.invite("Participant")
    service.enrollment_begin(NODE, invite=code)
    assert fail(service) == "failed"
    # New listener/service objects retain the budget in the shared database.
    recreated = PersonService(world[0], world[1])
    assert fail(recreated) == "limited"
    correct, _ = recreated.invite("Waiting participant")
    with pytest.raises(EnrollmentRateLimited):
        recreated.enrollment_begin(NODE, invite=correct)
    assert world[1]._read("SELECT used FROM invites WHERE token_hash=?", (invite_hash(correct),))[0] == 0
    world[7].now += 901
    fresh, _ = recreated.invite("Participant after window")
    recreated.enrollment_begin(NODE, invite=fresh)
    assert world[1]._read("SELECT COUNT(*) FROM enrollment_failures")[0] == 0


def test_authority_budget_spans_devices(world):
    for device in range(10):
        for _ in range(10):
            assert fail(world[3], f"node-{device}") == "failed"
    assert fail(world[3], "another-node") == "limited"
    assert world[1]._read("SELECT COUNT(*) FROM enrollment_failures")[0] == 100


def test_concurrent_guesses_share_atomic_device_budget(world):
    for _ in range(8):
        assert fail(world[3]) == "failed"
    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(lambda _: fail(world[3]), range(10)))
    assert results.count("failed") == 2
    assert results.count("limited") == 8
    assert world[1]._read("SELECT COUNT(*) FROM enrollment_failures")[0] == 10


def test_http_budget_follows_device_across_addresses_and_checks_policy_first(world):
    client = world[5]
    other_ip = "fd7a:115c:a1e0::1234"
    world[2].peers[other_ip] = world[2].peers[PEER]
    for _ in range(10):
        assert client.post("/enroll/begin", json={"invite": "wrong"}).status_code == 403
    # Same verified node, different address and a new HTTP limiter key.
    from fastapi.testclient import TestClient
    from bytebind.person_http import create_person_app
    from test_person import PERSON
    with TestClient(create_person_app(world[0], world[2], world[1]), base_url=PERSON, client=(other_ip, 1), headers={"Origin": PERSON}) as second:
        assert second.post("/enroll/begin", json={"invite": "wrong"}).status_code == 429
    world[2].peers[PEER] = (NODE, ["tag:mgmt"], False, 0)
    assert client.post("/enroll/begin", json={"invite": "wrong"}).status_code == 403
    assert world[1]._read("SELECT COUNT(*) FROM enrollment_failures")[0] == 10
