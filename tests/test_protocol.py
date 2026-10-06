"""Transcripts, encoding, and the published test vectors."""

from __future__ import annotations

import json

import pytest

from bytebind import protocol as p
from conftest import ROOT

VECTORS = json.loads((ROOT / "test-vectors" / "bytebind-v1.json").read_text())


def test_published_vectors_match_the_generator():
    import importlib.util

    spec = importlib.util.spec_from_file_location("make_vectors", ROOT / "scripts" / "make_vectors.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.vectors() == VECTORS, "regenerate with scripts/make_vectors.py"


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda case: case["profile"])
def test_vectors_reproduce(case):
    i = case["inputs"]
    cid, c, s, n, iv = (p.b64decode(i[k], size) for k, size in (("cid", 16), ("C", 32), ("S", 32), ("N", 32), ("IV", 12)))
    ip = p.ip_bytes(i["peer_address"])
    assert p.b64encode(ip) == i["IP"]
    q = None
    if case["profile"] == "tx":
        r = i["request"]
        q = p.request_digest(r["method"], r["target"], r["headers"], r["body"].encode())
        assert p.b64encode(q) == i["Q"]
    h1 = p.compute_h1(case["profile"], c, cid, n, q)
    assert p.b64encode(h1) == case["H1"]
    assert p.b64encode(p.h2_key(case["profile"], c, h1)) == case["K"]
    assert p.b64encode(p.seal_h2(case["profile"], c, cid, n, h1, ip, s, iv=iv)) == case["H2"]
    assert p.open_h2(case["profile"], c, cid, n, h1, p.b64decode(case["H2"], 76)) == (ip, s)
    assert p.b64encode(p.compute_r(case["profile"], s, cid, c, ip, q)) == case["R"]


def test_hkdf_matches_rfc_5869_case_1():
    out = p.hkdf_sha256(bytes.fromhex("0b" * 22), bytes.fromhex("000102030405060708090a0b0c"), bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42)
    assert out.hex() == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"


def test_length_prefixing_separates_field_boundaries():
    first, second = VECTORS["request_digest_boundaries"]
    assert first["Q"] != second["Q"]


def test_header_canonicalization_is_order_and_case_insensitive_for_names():
    a = p.request_digest("post", "/x", {"Content-Type": " application/json ", "X-B": "1"}, b"")
    b = p.request_digest("POST", "/x", {"x-b": "1", "content-type": "application/json"}, b"")
    assert a == b
    assert a != p.request_digest("POST", "/x", {"content-type": "application/JSON", "x-b": "1"}, b"")


def test_profiles_cannot_be_confused():
    cid, c, n, q = bytes(16), bytes(range(32)), bytes(32), bytes(range(32, 64))
    assert p.compute_h1("session", c, cid, n) != p.compute_h1("tx", c, cid, n, q)
    with pytest.raises(ValueError):
        p.compute_h1("session", c, cid, n, q)
    with pytest.raises(ValueError):
        p.compute_h1("tx", c, cid, n)
    h1 = p.compute_h1("session", c, cid, n)
    h2 = p.seal_h2("session", c, cid, n, h1, bytes(16), bytes(32))
    with pytest.raises(p.ProtocolError):  # an H2 for one profile does not open as the other
        p.open_h2("tx", c, cid, n, h1, h2)


def test_every_part_of_h2_is_authenticated():
    cid, c, n, s = bytes(16), bytes(range(32)), bytes(32), bytes(range(32))
    h1 = p.compute_h1("session", c, cid, n)
    h2 = p.seal_h2("session", c, cid, n, h1, p.ip_bytes("100.64.0.1"), s)
    for index in (0, 11, 12, 40, 75):
        tampered = bytearray(h2)
        tampered[index] ^= 1
        with pytest.raises(p.ProtocolError):
            p.open_h2("session", c, cid, n, h1, bytes(tampered))
    with pytest.raises(p.ProtocolError):
        p.open_h2("session", c, cid, b"\x01" * 32, h1, h2)  # another N: a replayed attestation response_URL
    assert p.seal_h2("session", c, cid, n, h1, bytes(16), s)[:12] != h2[:12], "fresh IV per H2"


@pytest.mark.parametrize("value", VECTORS["malformed_base64url_16_bytes"] + [None, 7, "ÀAAAAAAAAAAAAAAAAAAAAA"])
def test_base64url_must_be_exact_and_canonical(value):
    with pytest.raises(p.ProtocolError):
        p.b64decode(value, 16)


def test_ipv4_is_mapped():
    assert p.ip_bytes("100.64.0.1") == bytes(10) + b"\xff\xff" + bytes([100, 64, 0, 1])


def test_predecessor_labels_are_not_v1():
    assert all(label.startswith(b"bytebind/v1/") for labels in p.LABELS.values() for label in labels.values())
