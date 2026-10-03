"""Regenerate test-vectors/bytebind-v1.json from the reference implementation.

Every value is deterministic (fixed inputs and a fixed IV), so other
implementations can check byte-for-byte agreement.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bytebind import protocol as p  # noqa: E402


def hexbytes(start: int, length: int) -> bytes:
    return bytes((start + i) % 256 for i in range(length))


def vectors() -> dict:
    cid, c, s, n, iv = hexbytes(0x00, 16), hexbytes(0x20, 32), hexbytes(0x60, 32), hexbytes(0x40, 32), hexbytes(0xA0, 12)
    request = {"method": "POST", "target": "/restart?now=1", "headers": {"Content-Type": "application/json"}, "body": '{"service":"demo"}'}
    q = p.request_digest(request["method"], request["target"], request["headers"], request["body"].encode())
    cases = []
    for profile, ip_text, digest in (("session", "100.101.102.103", None), ("tx", "fd7a:115c:a1e0::53", q)):
        ip = p.ip_bytes(ip_text)
        h1 = p.compute_h1(profile, c, cid, n, digest)
        h2 = p.seal_h2(profile, c, cid, n, h1, ip, s, iv=iv)
        case = {
            "profile": profile,
            "inputs": {"cid": p.b64encode(cid), "C": p.b64encode(c), "S": p.b64encode(s), "N": p.b64encode(n),
                       "IV": p.b64encode(iv), "peer_address": ip_text, "IP": p.b64encode(ip)},
            "H1": p.b64encode(h1),
            "K": p.b64encode(p.h2_key(profile, c, h1)),
            "AAD": p.b64encode(p.h2_aad(profile, cid, n, h1)),
            "H2": p.b64encode(h2),
            "R": p.b64encode(p.compute_r(profile, s, cid, c, ip, digest)),
        }
        if digest is not None:
            case["inputs"]["request"] = request
            case["inputs"]["Q"] = p.b64encode(digest)
        cases.append(case)
    boundary = [
        {"method": "POST", "target": "/a", "headers": {}, "body": "bc"},
        {"method": "POST", "target": "/ab", "headers": {}, "body": "c"},
    ]
    return {
        "protocol": "ByteBind",
        "version": "draft 0.6",
        "encoding": "byte values are unpadded base64url",
        "labels": {profile: {k: v.decode() for k, v in labels.items()} for profile, labels in p.LABELS.items()} | {"request": p.REQUEST_LABEL.decode()},
        "cases": cases,
        "request_digest_boundaries": [
            {"request": item, "Q": p.b64encode(p.request_digest(item["method"], item["target"], item["headers"], item["body"].encode()))}
            for item in boundary
        ],
        "malformed_base64url_16_bytes": ["", "AAAA", "A" * 21, "A" * 23, "AAAAAAAAAAAAAAAAAAAAA+", "AAAAAAAAAAAAAAAAAAAAA=", "AAAAAAAAAAAAAAAAAAAAAB"],
    }


if __name__ == "__main__":
    out = ROOT / "test-vectors" / "bytebind-v1.json"
    out.write_text(json.dumps(vectors(), indent=2) + "\n", encoding="utf-8")
    print(out)
