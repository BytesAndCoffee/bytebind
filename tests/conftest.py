from __future__ import annotations

import os
import shutil
import tempfile
import threading
from pathlib import Path

import pytest

from bytebind.config import parse

ROOT = Path(__file__).resolve().parents[1]
APP = "https://app.example"
OTHER = "https://other.example"
ATTEST_URL = "https://authority.tail1234.ts.net:8443"
PEER = "100.101.102.103"
NODE = "nLaptop1CNTRL"
OTHER_RP_NODE = "nOtherRP1CNTRL"


class Clock:
    def __init__(self, now: float = 1_800_000_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


class FakeTailnet:
    """tailscaled LocalAPI answers for a set of peers: {ip: (stable_id, tags, sharee, sharer)}."""

    def __init__(self, peers: dict | None = None, *, fail: bool = False):
        self.peers = peers if peers is not None else {PEER: (NODE, ["tag:mgmt"], False, 0)}
        self.fail = fail
        self.calls: list = []

    def status(self):
        self.calls.append("status")
        if self.fail:
            raise OSError("tailscaled is down")
        return {"Peer": {f"nodekey:{i}": {"ID": node, "TailscaleIPs": [ip], "ShareeNode": sharee, "Tags": tags}
                         for i, (ip, (node, tags, sharee, _)) in enumerate(self.peers.items())}}

    def whois(self, address):
        self.calls.append(("whois", address))
        if address not in self.peers:
            return None
        node, tags, _, sharer = self.peers[address]
        return {"Node": {"StableID": node, "Name": f"{node.lower()}.tail1234.ts.net.", "Tags": tags, "Sharer": sharer}}


def config_data(database: str, *, uid: int | None = None, **app_overrides) -> dict:
    app = {"id": "app", "origin": APP, "audiences": ["manage"], "unix_uid": os.getuid() if uid is None else uid,
           "grant_ttl": 180, "claims": ["device_id"], "authorization": ["manage:read"], "policy": {"tags": ["tag:mgmt"]}}
    app.update(app_overrides)
    other = {"id": "other", "origin": OTHER, "audiences": ["ops"], "tailnet_node": OTHER_RP_NODE,
             "authorization": ["ops:write"], "policy": {"tags": ["tag:mgmt"]}}
    return {"authority": {"attest_url": ATTEST_URL, "database": database}, "rp": [app, other]}


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def config(tmp_path):
    return parse(config_data(str(tmp_path / "authority.sqlite3")))


@pytest.fixture
def short_dir():
    """Unix socket paths are limited to about 104 bytes, so keep them short."""
    path = tempfile.mkdtemp(prefix="bb", dir="/tmp")
    os.chmod(path, 0o700)
    yield Path(path)
    shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def unix_control(config, short_dir):
    """A running control channel on a real Unix socket; yields (socket path, store)."""
    from bytebind.authority import open_store, unix_control_server

    store = open_store(config)
    path = str(short_dir / "control.sock")
    tags = sorted({tag for rp in config.rps.values() for tag in rp.policy.tags})
    server = unix_control_server(config, store, path, directory=FakeTailnet({PEER: (NODE, tags, False, 0)}))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield path, store
    server.shutdown()
    server.server_close()
