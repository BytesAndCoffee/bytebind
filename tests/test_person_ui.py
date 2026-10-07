"""Passkey management uses fresh grants; hidden step-up invokes native UI once."""

import shutil
import subprocess

import pytest

from conftest import ROOT


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_person_browser_flows():
    subprocess.run(
        ["node", str(ROOT / "tests/person_ui.cjs"), str(ROOT / "src/bytebind/web/person.js")],
        capture_output=True, text=True, timeout=30, check=True,
    )
