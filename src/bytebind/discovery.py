"""Authority discovery from trusted tailscaled node metadata, never host scans."""
from __future__ import annotations

import re
from pathlib import Path

from .rp import AuthorityClient
from .tailscale import Directory, LocalAPI, is_tailscale_address

AUTHORITY_TAG = "tag:bytebind-authority"
AUTHORITY_CAPABILITY = "bytes.coffee/bytebind/authority"
LOCAL_CONTROL_SOCKET = "/run/bytebind/control.sock"


class DiscoveryError(OSError):
    """No unambiguous, usable Authority was advertised by the tailnet."""


def discover_authority(directory: Directory, *, audience: str,
                       tag: str = AUTHORITY_TAG, capability: str = AUTHORITY_CAPABILITY,
                       port: int = 9443) -> str:
    """Select one online node carrying the role tag OR the node capability.

    Capability values may specify ``port`` and ``audiences``. A present capability
    takes precedence over tag-only defaults, including when it excludes an
    audience. Endpoints always use the node's own MagicDNS name and verified TLS.
    Shared, expired, offline and malformed candidates are never accepted.
    """
    status = directory.status()
    if not isinstance(status, dict) or status.get("BackendState") != "Running":
        raise DiscoveryError("tailscaled must be running for Authority discovery")
    suffix = (status.get("CurrentTailnet") or {}).get("MagicDNSSuffix") or status.get("MagicDNSSuffix")
    if not isinstance(suffix, str) or not suffix:
        raise DiscoveryError("tailnet MagicDNS suffix is unavailable")
    suffix = suffix.rstrip(".").lower()
    peers = status.get("Peer") or {}
    if not isinstance(peers, dict):
        raise DiscoveryError("tailscaled returned malformed peers")
    candidates = dict(peers)
    if isinstance(status.get("Self"), dict):
        candidates["self"] = status["Self"]
    endpoints = set()
    for peer in candidates.values():
        if not isinstance(peer, dict) or peer.get("Online") is not True:
            continue
        if peer.get("ShareeNode") or peer.get("AltSharerUserID") or peer.get("Expired"):
            continue
        caps = peer.get("CapMap") or {}
        tags = peer.get("Tags") or []
        legacy = peer.get("Capabilities") or []
        if not isinstance(caps, dict) or not isinstance(tags, list) or not isinstance(legacy, list):
            continue
        has_cap = capability in caps or capability in legacy
        if tag not in tags and not has_cap:
            continue
        name = peer.get("DNSName")
        ips = peer.get("TailscaleIPs")
        if not isinstance(name, str) or not isinstance(ips, list) or not any(
            isinstance(ip, str) and is_tailscale_address(ip) for ip in ips
        ):
            raise DiscoveryError("advertised Authority lacks a tailnet address or DNS name")
        name = name.rstrip(".").lower()
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", name) or not name.endswith("." + suffix):
            raise DiscoveryError("advertised Authority DNS name is outside this tailnet")
        values = caps.get(capability) if has_cap else None
        if values is None or values == []:
            values = [{}]
        if not isinstance(values, list) or not all(isinstance(v, dict) for v in values):
            raise DiscoveryError("malformed Authority capability")
        for value in values:
            audiences = value.get("audiences")
            if audiences is not None:
                if not isinstance(audiences, list) or not all(isinstance(a, str) and a for a in audiences):
                    raise DiscoveryError("malformed Authority audiences")
                if audience not in audiences:
                    continue
            selected_port = value.get("port", port)
            if type(selected_port) is not int or not 1 <= selected_port <= 65535:
                raise DiscoveryError("malformed Authority control port")
            endpoints.add(f"https://{name}:{selected_port}")
    if len(endpoints) != 1:
        raise DiscoveryError("no Authority matches this audience" if not endpoints else
                             "multiple Authorities match; narrow capability audiences or set BYTEBIND_AUTHORITY")
    return endpoints.pop()


class DiscoveringAuthorityClient:
    """Resolve on each control request, so policy changes are not cached indefinitely.

    Explicit endpoints bypass this class. A local Unix listener takes precedence
    when its socket exists. No retry/failover can accidentally replay a redemption.
    Session lookup does not contact tailscaled or the Authority.
    """

    def __init__(self, directory: Directory | None = None, *,
                 socket_path: str = "/var/run/tailscale/tailscaled.sock",
                 local_socket: str = LOCAL_CONTROL_SOCKET,
                 tag: str = AUTHORITY_TAG, capability: str = AUTHORITY_CAPABILITY,
                 port: int = 9443):
        self.directory = directory or LocalAPI(socket_path)
        self.local_socket, self.tag, self.capability, self.port = local_socket, tag, capability, port

    def _client(self, audience: str) -> AuthorityClient:
        endpoint = (f"unix:{self.local_socket}" if Path(self.local_socket).is_socket() else
                    discover_authority(self.directory, audience=audience, tag=self.tag,
                                       capability=self.capability, port=self.port))
        return AuthorityClient(endpoint)

    def begin(self, audience, profile="session", q=None):
        return self._client(audience).begin(audience, profile, q)

    def redeem(self, cid, r, audience):
        return self._client(audience).redeem(cid, r, audience)
