from copy import deepcopy

import pytest

from bytebind.discovery import (AUTHORITY_CAPABILITY, AUTHORITY_TAG, DiscoveryError,
                                DiscoveringAuthorityClient, discover_authority)


class Directory:
    def __init__(self, **overrides):
        self.peer = {"ID": "nAuthority", "Online": True, "Tags": [AUTHORITY_TAG],
                     "DNSName": "authority.tail123.ts.net.", "TailscaleIPs": ["100.100.1.2"]}
        self.peer.update(overrides)
        self.data = {"BackendState": "Running", "CurrentTailnet": {"MagicDNSSuffix": "tail123.ts.net"},
                     "Peer": {"key": self.peer}}

    def status(self):
        return deepcopy(self.data)


def test_tag_discovery():
    assert discover_authority(Directory(), audience="manage") == "https://authority.tail123.ts.net:9443"


def test_capability_discovery():
    directory = Directory(Tags=[], CapMap={AUTHORITY_CAPABILITY: [{"port": 443, "audiences": ["manage"]}]})
    assert discover_authority(directory, audience="manage") == "https://authority.tail123.ts.net:443"
    with pytest.raises(DiscoveryError, match="no Authority"):
        discover_authority(directory, audience="other")


def test_capability_excludes_audience_even_with_tag():
    with pytest.raises(DiscoveryError, match="no Authority"):
        discover_authority(Directory(CapMap={AUTHORITY_CAPABILITY: [{"audiences": []}]}), audience="manage")


@pytest.mark.parametrize("fields", [
    {"Online": False}, {"Expired": True}, {"ShareeNode": True}, {"AltSharerUserID": 123},
    {"Tags": []}, {"DNSName": "evil.example"}, {"DNSName": "authority.tail123.ts.net:443"},
    {"TailscaleIPs": ["192.168.1.1"]}, {"CapMap": {AUTHORITY_CAPABILITY: [{"port": True}]}},
    {"CapMap": {AUTHORITY_CAPABILITY: [{"port": 65536}]}},
    {"CapMap": {AUTHORITY_CAPABILITY: [{"audiences": "manage"}]}},
    {"CapMap": {AUTHORITY_CAPABILITY: ["bad"]}},
])
def test_rejects_unusable_or_malformed_candidates(fields):
    with pytest.raises(DiscoveryError):
        discover_authority(Directory(**fields), audience="manage")


def test_multiple_authorities_and_audience_selection():
    directory = Directory(CapMap={AUTHORITY_CAPABILITY: [{"audiences": ["manage"]}]})
    directory.data["Peer"]["other"] = dict(directory.peer, DNSName="other.tail123.ts.net.")
    with pytest.raises(DiscoveryError, match="multiple Authorities"):
        discover_authority(directory, audience="manage")
    directory.data["Peer"]["other"]["CapMap"] = {AUTHORITY_CAPABILITY: [{"audiences": ["ops"]}]}
    assert discover_authority(directory, audience="ops") == "https://other.tail123.ts.net:9443"


def test_local_socket_precedence(short_dir):
    import socket
    path = str(short_dir / "control.sock")
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(path)
        client = DiscoveringAuthorityClient(Directory(), local_socket=path)
        assert client._client("manage").endpoint == f"unix:{path}"


def test_policy_is_refreshed_and_control_uses_discovered_endpoint(monkeypatch, tmp_path):
    from bytebind import discovery
    calls = []

    class Client:
        def __init__(self, endpoint):
            calls.append(endpoint)

        def begin(self, *args):
            return {"begun": args}

        def redeem(self, *args):
            return {"redeemed": args}

    monkeypatch.setattr(discovery, "AuthorityClient", Client)
    directory = Directory()
    client = DiscoveringAuthorityClient(directory, local_socket=str(tmp_path / "absent"))
    assert client.begin("manage")["begun"] == ("manage", "session", None)
    assert client.redeem("cid", "proof", "manage")["redeemed"] == ("cid", "proof", "manage")
    assert calls == ["https://authority.tail123.ts.net:9443"] * 2
    directory.peer["Tags"] = []
    with pytest.raises(DiscoveryError):
        client.begin("manage")


def test_requires_running_tailnet_and_supports_self():
    directory = Directory()
    directory.data["BackendState"] = "Stopped"
    with pytest.raises(DiscoveryError):
        discover_authority(directory, audience="manage")
    directory.data["BackendState"] = "Running"
    directory.data["Self"] = directory.peer
    directory.data["Peer"] = {}
    assert discover_authority(directory, audience="manage") == "https://authority.tail123.ts.net:9443"
