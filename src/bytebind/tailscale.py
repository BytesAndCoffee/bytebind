"""The Tailscale attestation provider (SPEC.md section 16).

tailscaled's LocalAPI is not a documented stable interface, so every use of it
lives in this module and parsing accepts only the fields used here.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import urllib.parse
from contextlib import closing
from dataclasses import dataclass
from typing import Any, Protocol

from .config import Policy

NETWORKS = (ipaddress.ip_network("100.64.0.0/10"), ipaddress.ip_network("fd7a:115c:a1e0::/48"))
MAX_RESPONSE = 4 * 1024 * 1024


class AttestationError(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class Directory(Protocol):
    def status(self) -> dict[str, Any]: ...

    def whois(self, address: str) -> dict[str, Any] | None: ...


@dataclass(frozen=True)
class PeerAttestation:
    """The normalized result the protocol core depends on (SPEC.md section 17)."""

    peer_id: str
    address: str
    name: str
    tags: tuple[str, ...]


def is_tailscale_address(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    return any(parsed in network for network in NETWORKS)


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float):
        super().__init__("local-tailscaled.sock", timeout=timeout)
        self.socket_path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


class LocalAPI:
    def __init__(self, socket_path: str, timeout: float = 3.0):
        self.socket_path, self.timeout = socket_path, timeout

    def _get(self, path: str) -> tuple[int, Any]:
        with closing(_UnixHTTPConnection(self.socket_path, self.timeout)) as connection:
            connection.request("GET", path, headers={"Host": "local-tailscaled.sock", "Sec-Tailscale": "localapi"})
            response = connection.getresponse()
            body = response.read(MAX_RESPONSE + 1)
            if len(body) > MAX_RESPONSE:
                raise OSError("tailscaled response too large")
            return response.status, json.loads(body) if response.status == 200 else None

    def status(self) -> dict[str, Any]:
        code, body = self._get("/localapi/v0/status")
        if code != 200 or not isinstance(body, dict):
            raise OSError(f"tailscaled status failed with HTTP {code}")
        return body

    def whois(self, address: str) -> dict[str, Any] | None:
        code, body = self._get("/localapi/v0/whois?" + urllib.parse.urlencode({"addr": address}))
        if code == 404:
            return None
        if code != 200 or not isinstance(body, dict):
            raise OSError(f"tailscaled whois failed with HTTP {code}")
        return body


def identify(directory: Directory, address: str) -> PeerAttestation:
    """Checks 6 and 7: a Tailscale address that tailscaled knows as a peer of this tailnet, not shared in."""
    if not is_tailscale_address(address):
        raise AttestationError("peer is not a Tailscale address")
    canonical = str(ipaddress.ip_address(address))
    peer = next(
        (candidate for candidate in (directory.status().get("Peer") or {}).values()
         if isinstance(candidate, dict) and canonical in [str(ip) for ip in candidate.get("TailscaleIPs") or ()]),
        None,
    )
    if peer is None:
        raise AttestationError("address is not a known peer")
    if peer.get("ShareeNode"):
        raise AttestationError("peer is shared in from another tailnet")
    who = directory.whois(canonical)
    node = who.get("Node") if isinstance(who, dict) else None
    if not isinstance(node, dict):
        raise AttestationError("whois has no node")
    if node.get("Sharer"):
        raise AttestationError("whois reports a shared node")
    peer_id = node.get("StableID")
    if not isinstance(peer_id, str) or not peer_id or peer_id != peer.get("ID"):
        raise AttestationError("status and whois disagree about the node")
    tags = node.get("Tags") or []
    if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
        raise AttestationError("whois tags are malformed")
    name = node.get("Name") if isinstance(node.get("Name"), str) else peer_id
    return PeerAttestation(peer_id, canonical, name.rstrip("."), tuple(sorted(tags)))


def authorize(peer: PeerAttestation, policy: Policy) -> None:
    """Check 8: the RP's policy for this node."""
    tags = set(peer.tags)
    allowed = policy.tags <= tags if policy.tag_match == "all" else bool(policy.tags & tags)
    if not allowed:
        raise AttestationError("node does not carry the required tags")
    if policy.nodes and peer.peer_id not in policy.nodes:
        raise AttestationError("node is not on the node allowlist")
