"""Authority discovery from trusted tailscaled node metadata, never host scans."""
from __future__ import annotations

import re
import os
import threading
import time
from pathlib import Path

from .rp import AuthorityClient
from .tailscale import Directory, LocalAPI, is_tailscale_address

AUTHORITY_TAG = "tag:bytebind-authority"
AUTHORITY_CAPABILITY = "bytebind.example/authority"
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
            protocols = value.get("protocols")
            if protocols is not None:
                if not isinstance(protocols,list) or not protocols or any(type(v) is not int for v in protocols):
                    raise DiscoveryError("malformed Authority protocols")
                if 1 not in protocols:
                    continue
            assurances = value.get("assurances")
            if assurances is not None and (not isinstance(assurances,list) or not assurances or any(not isinstance(v,str) or v not in {"device","presence","verification"} for v in assurances)):
                raise DiscoveryError("malformed Authority assurances")
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
    """Discover at transaction creation and pin that Authority through redemption.

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
        self._pins = {}
        self._lock = threading.Lock()

    def _client(self, audience: str) -> AuthorityClient:
        endpoint = (f"unix:{self.local_socket}" if Path(self.local_socket).is_socket() else
                    discover_authority(self.directory, audience=audience, tag=self.tag,
                                       capability=self.capability, port=self.port))
        return self.pinned(endpoint)

    def pinned(self, endpoint):
        if endpoint.startswith("unix:") and "BYTEBIND_AUTHORITY_UID" in os.environ:
            return AuthorityClient(endpoint, authority_uid=int(os.environ["BYTEBIND_AUTHORITY_UID"]))
        return AuthorityClient(endpoint)

    def begin(self, audience, profile="session", q=None, **kwargs):
        with self._lock:
            now=time.monotonic()
            self._pins={cid:value for cid,value in self._pins.items() if value[1]>now}
            if len(self._pins)>=4096:
                raise DiscoveryError("too many pending Authority pins")
            client=self._client(audience)
            result=client.begin(audience,profile,q,**kwargs)
            self._pins[result["cid"]]=(client.endpoint,now+210)
            return result | {"control_authority":client.endpoint}

    def redeem(self, cid, r, audience):
        with self._lock:
            pin=self._pins.pop(cid,None)
        if pin is None or pin[1] < time.monotonic():
            raise DiscoveryError("transaction has no live creating Authority pin")
        return self.pinned(pin[0]).redeem(cid,r,audience)
