"""Authority configuration: one TOML file, validated completely at startup."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

TAG = re.compile(r"tag:[A-Za-z0-9][A-Za-z0-9-]*")
NODE = re.compile(r"[A-Za-z0-9]+")
NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
CLAIMS = frozenset({"device_id", "tags", "person_subject"})


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Policy:
    tags: frozenset[str]
    tag_match: str = "any"  # "any" or "all" of ``tags``
    nodes: frozenset[str] = frozenset()  # empty: any node passing the tag check
    deny_shared: bool = True


@dataclass(frozen=True)
class RelyingParty:
    id: str
    origin: str
    audiences: frozenset[str]
    policy: Policy
    unix_uid: int | None = None  # control over the Unix domain socket
    tailnet_node: str | None = None  # control over HTTPS between tailnet nodes
    grant_ttl: int = 180
    claims: frozenset[str] = frozenset()
    authorization: tuple[str, ...] = ()
    assurances: frozenset[str] = frozenset({"device"})
    person_max_age: int = 600
    person_subjects: frozenset[str] = frozenset()
    allow_self_enrolled: bool = False


@dataclass(frozen=True)
class PersonConfig:
    origin: str
    enrollment_policy: Policy
    self_enrollment: bool = False


@dataclass(frozen=True)
class AuthorityConfig:
    attest_url: str
    database: str
    rps: dict[str, RelyingParty] = field(default_factory=dict)
    tailscale_socket: str = "/var/run/tailscale/tailscaled.sock"
    attest_window: int = 30
    redeem_window: int = 10
    max_pending_per_rp: int = 200
    person: PersonConfig | None = None

    @property
    def origins(self) -> frozenset[str]:
        return frozenset(rp.origin for rp in self.rps.values())

    def rp_for_uid(self, uid: int) -> RelyingParty | None:
        return next((rp for rp in self.rps.values() if rp.unix_uid == uid), None)

    def rp_for_node(self, node_id: str) -> RelyingParty | None:
        return next((rp for rp in self.rps.values() if rp.tailnet_node == node_id), None)


def exact_https_origin(value: str) -> bool:
    if not isinstance(value,str):
        return False
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    try:
        parts.port
    except ValueError:
        return False
    canonical_host = parts.hostname or ""
    canonical_host = "[" + canonical_host + "]" if ":" in canonical_host else canonical_host
    canonical = "https://" + canonical_host + (f":{parts.port}" if parts.port not in (None, 443) else "")
    return (value == canonical and parts.scheme == "https" and bool(parts.hostname) and not parts.path and not parts.query
            and not parts.fragment and parts.username is None and parts.password is None and "*" not in value)


def _positive(table: dict, key: str, default: int, *, maximum: int | None = None) -> int:
    value = table.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0 or (maximum is not None and value > maximum):
        raise ConfigError(f"{key} must be a positive integer" + (f" no greater than {maximum}" if maximum else ""))
    return value


def _grant_ttl(entry: dict, rp_id: str) -> int:
    """Clients renew every 60 seconds, so a lease must survive one failed renewal (SPEC.md 15.1)."""
    value = _positive(entry, "grant_ttl", 180, maximum=300)
    if value < 90:
        raise ConfigError(f"rp {rp_id}: grant_ttl must be at least 90 seconds")
    return value


def _strings(value: object, key: str, pattern: re.Pattern | None = None) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{key} must be a list of strings")
    if pattern is not None and not all(pattern.fullmatch(item) for item in value):
        raise ConfigError(f"{key} has an invalid entry")
    return value


def parse(data: dict) -> AuthorityConfig:
    authority = data.get("authority")
    if not isinstance(authority, dict):
        raise ConfigError("missing [authority] table")
    attest_url = str(authority.get("attest_url", "")).rstrip("/")
    if not exact_https_origin(attest_url):
        raise ConfigError("authority.attest_url must be an exact https://host[:port] URL")
    database = authority.get("database")
    if not isinstance(database, str) or not Path(database).is_absolute():
        raise ConfigError("authority.database must be an absolute path")
    socket_path = authority.get("tailscale_socket", "/var/run/tailscale/tailscaled.sock")
    if not isinstance(socket_path, str) or not Path(socket_path).is_absolute():
        raise ConfigError("authority.tailscale_socket must be an absolute path")
    person = None
    person_table = data.get("person")
    if person_table is not None:
        if not isinstance(person_table, dict) or not exact_https_origin(person_table.get("origin", "")):
            raise ConfigError("person.origin must be a canonical HTTPS origin")
        if person_table["origin"] == attest_url:
            raise ConfigError("person and attestation need separate listeners")
        tags = _strings(person_table.get("enrollment_tags", []), "person.enrollment_tags", TAG)
        if not tags:
            raise ConfigError("person.enrollment_tags must authorize a dedicated enrollment policy")
        if type(person_table.get("self_enrollment", False)) is not bool:
            raise ConfigError("person.self_enrollment must be boolean")
        person = PersonConfig(person_table["origin"], Policy(frozenset(tags), "all"), person_table.get("self_enrollment", False))
    rps: dict[str, RelyingParty] = {}
    entries = data.get("rp", [])
    if not isinstance(entries, list) or not entries:
        raise ConfigError("register at least one [[rp]]")
    for entry in entries:
        if not isinstance(entry, dict):
            raise ConfigError("[[rp]] entries must be tables")
        rp_id = entry.get("id")
        if not isinstance(rp_id, str) or not NAME.fullmatch(rp_id) or rp_id in rps:
            raise ConfigError(f"rp id {rp_id!r} is missing, invalid, or duplicated")
        origin = str(entry.get("origin", "")).rstrip("/")
        if not exact_https_origin(origin):
            raise ConfigError(f"rp {rp_id}: origin must be an exact https://host[:port] origin")
        if urlsplit(origin).hostname == urlsplit(attest_url).hostname:
            raise ConfigError(f"rp {rp_id}: origin must not be the Authority's own host")
        audiences = _strings(entry.get("audiences", []), f"rp {rp_id}: audiences", NAME)
        if not audiences:
            raise ConfigError(f"rp {rp_id}: list at least one audience")
        uid, node = entry.get("unix_uid"), entry.get("tailnet_node")
        if (uid is None) == (node is None):
            raise ConfigError(f"rp {rp_id}: set exactly one of unix_uid or tailnet_node")
        if uid is not None and (not isinstance(uid, int) or isinstance(uid, bool) or uid < 0):
            raise ConfigError(f"rp {rp_id}: unix_uid must be a non-negative integer")
        if node is not None and (not isinstance(node, str) or not NODE.fullmatch(node)):
            raise ConfigError(f"rp {rp_id}: tailnet_node must be a stable node ID")
        policy_table = entry.get("policy")
        if not isinstance(policy_table, dict):
            raise ConfigError(f"rp {rp_id}: missing [rp.policy]")
        tags = _strings(policy_table.get("tags", []), f"rp {rp_id}: policy.tags", TAG)
        if not tags:
            raise ConfigError(f"rp {rp_id}: policy.tags must list at least one tag")
        tag_match = policy_table.get("tag_match", "any")
        if tag_match not in {"any", "all"}:
            raise ConfigError(f"rp {rp_id}: policy.tag_match must be 'any' or 'all'")
        deny_shared = policy_table.get("deny_shared", True)
        if deny_shared is not True:
            raise ConfigError(f"rp {rp_id}: shared-in nodes cannot be allowed by this implementation")
        claims = _strings(entry.get("claims", []), f"rp {rp_id}: claims")
        if not set(claims) <= CLAIMS:
            raise ConfigError(f"rp {rp_id}: claims may only include {sorted(CLAIMS)}")
        assurances = frozenset(_strings(entry.get("assurances", ["device"]), f"rp {rp_id}: assurances"))
        if not assurances or not assurances <= {"device", "presence", "verification"}:
            raise ConfigError(f"rp {rp_id}: invalid assurance")
        if (assurances - {"device"} or "person_subject" in claims) and person is None:
            raise ConfigError(f"rp {rp_id}: person listener required")
        if type(entry.get("allow_self_enrolled", False)) is not bool:
            raise ConfigError("allow_self_enrolled must be boolean")
        rps[rp_id] = RelyingParty(
            id=rp_id, origin=origin, audiences=frozenset(audiences),
            policy=Policy(frozenset(tags), tag_match, frozenset(_strings(policy_table.get("nodes", []), f"rp {rp_id}: policy.nodes", NODE))),
            unix_uid=uid, tailnet_node=node, grant_ttl=_grant_ttl(entry, rp_id),
            assurances=assurances, person_max_age=_positive(entry, "person_max_age", 600, maximum=86400),
            person_subjects=frozenset(_strings(entry.get("person_subjects", []), "person_subjects")),
            allow_self_enrolled=entry.get("allow_self_enrolled", False),
            claims=frozenset(claims), authorization=tuple(_strings(entry.get("authorization", []), f"rp {rp_id}: authorization")),
        )
    if len({rp.unix_uid for rp in rps.values() if rp.unix_uid is not None}) != sum(rp.unix_uid is not None for rp in rps.values()):
        raise ConfigError("two relying parties share a unix_uid")
    if len({rp.tailnet_node for rp in rps.values() if rp.tailnet_node}) != sum(bool(rp.tailnet_node) for rp in rps.values()):
        raise ConfigError("two relying parties share a tailnet_node")
    return AuthorityConfig(
        attest_url=attest_url, database=database, rps=rps, tailscale_socket=socket_path, person=person,
        attest_window=_positive(authority, "attest_window", 30, maximum=30),
        redeem_window=_positive(authority, "redeem_window", 10, maximum=10),
        max_pending_per_rp=_positive(authority, "max_pending_per_rp", 200),
    )


def load(path: str | Path) -> AuthorityConfig:
    with open(path, "rb") as handle:
        return parse(tomllib.load(handle))
