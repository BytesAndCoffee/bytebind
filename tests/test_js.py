"""The browser client agrees with the published vectors, byte for byte."""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from conftest import ROOT

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")


def test_hidden_person_step_up():
    subprocess.run(
        ["node", str(ROOT / "tests/hidden_stepup.cjs"), str(ROOT / "src/bytebind/web/bytebind.js")],
        capture_output=True, text=True, timeout=30, check=True,
    )


SCRIPT = """
const B = require(%(client)s);
const V = require(%(vectors)s);
(async () => {
  const out = [];
  for (const c of V.cases) {
    const i = c.inputs, d = (k, n) => B.b64decode(i[k], n);
    let q;
    if (c.profile === "tx") {
      const r = i.request;
      q = await B.requestDigest(r.method, r.target, r.headers, new TextEncoder().encode(r.body));
    }
    const h1 = await B.computeH1(c.profile, d("C", 32), d("cid", 16), d("N", 32), q);
    const { ip, s } = await B.openH2(c.profile, d("C", 32), d("cid", 16), d("N", 32), h1, B.b64decode(c.H2, 76));
    const r = await B.computeR(c.profile, s, d("cid", 16), d("C", 32), ip, q);
    let tamper = false;
    const bad = B.b64decode(c.H2, 76); bad[30] ^= 1;
    try { await B.openH2(c.profile, d("C", 32), d("cid", 16), d("N", 32), h1, bad); } catch (_) { tamper = true; }
    out.push({ Q: q ? B.b64encode(q) : null, H1: B.b64encode(h1), IP: B.b64encode(ip), S: B.b64encode(s), R: B.b64encode(r), tamper });
  }
  const boundaries = [];
  for (const b of V.request_digest_boundaries) {
    const r = b.request;
    boundaries.push(B.b64encode(await B.requestDigest(r.method, r.target, r.headers, new TextEncoder().encode(r.body))));
  }
  const rejected = V.malformed_base64url_16_bytes.map((x) => { try { B.b64decode(x, 16); return false; } catch (_) { return true; } });
  console.log(JSON.stringify({ out, boundaries, rejected }));
})().catch((e) => { console.error(e); process.exit(1); });
"""


def test_bytebind_js_matches_vectors():
    vectors_path = ROOT / "test-vectors" / "bytebind-v1.json"
    vectors = json.loads(vectors_path.read_text())
    script = SCRIPT % {"client": json.dumps(str(ROOT / "src/bytebind/web/bytebind.js")), "vectors": json.dumps(str(vectors_path))}
    result = json.loads(subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=30, check=True).stdout)
    for case, got in zip(vectors["cases"], result["out"]):
        assert got["H1"] == case["H1"] and got["R"] == case["R"] and got["IP"] == case["inputs"]["IP"] and got["S"] == case["inputs"]["S"]
        assert got["Q"] == case["inputs"].get("Q")
        assert got["tamper"] is True
    assert result["boundaries"] == [b["Q"] for b in vectors["request_digest_boundaries"]]
    assert all(result["rejected"])
