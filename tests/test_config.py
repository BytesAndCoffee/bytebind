from __future__ import annotations

import copy

import pytest

from bytebind.config import ConfigError, parse
from conftest import config_data


def test_valid_config(tmp_path):
    config = parse(config_data(str(tmp_path / "a.sqlite3")))
    assert set(config.rps) == {"app", "other"}
    assert config.rps["app"].policy.tag_match == "any"
    assert config.origins == {"https://app.example", "https://other.example"}


def _mutate(tmp_path, change):
    data = config_data(str(tmp_path / "a.sqlite3"))
    change(data)
    return data


@pytest.mark.parametrize("change,message", [
    (lambda d: d["authority"].__setitem__("attest_url", "http://authority.ts.net"), "attest_url"),
    (lambda d: d["authority"].__setitem__("database", "relative.sqlite3"), "database"),
    (lambda d: d["authority"].__setitem__("attest_window", 120), "attest_window"),
    (lambda d: d["authority"].__setitem__("redeem_window", 60), "redeem_window"),
    (lambda d: d.__setitem__("rp", []), "at least one"),
    (lambda d: d["rp"][0].__setitem__("origin", "https://app.example/path"), "origin"),
    (lambda d: d["rp"][0].__setitem__("origin", "https://authority.tail1234.ts.net"), "Authority's own host"),
    (lambda d: d["rp"][0].__setitem__("tailnet_node", "nX"), "exactly one"),
    (lambda d: d["rp"][0].pop("unix_uid"), "exactly one"),
    (lambda d: d["rp"][0]["policy"].__setitem__("tags", []), "at least one tag"),
    (lambda d: d["rp"][0]["policy"].__setitem__("tags", ["mgmt"]), "policy.tags"),
    (lambda d: d["rp"][0]["policy"].__setitem__("tag_match", "some"), "tag_match"),
    (lambda d: d["rp"][0]["policy"].__setitem__("deny_shared", False), "shared-in"),
    (lambda d: d["rp"][0].__setitem__("claims", ["peer_ip"]), "claims"),
    (lambda d: d["rp"][0].__setitem__("grant_ttl", 3600), "grant_ttl"),
    (lambda d: d["rp"].append(copy.deepcopy(d["rp"][0])), "duplicated"),
    (lambda d: d["rp"][1].update({"tailnet_node": None, "unix_uid": d["rp"][0]["unix_uid"]}), "share a unix_uid"),
])
def test_invalid_configs_fail_at_startup(tmp_path, change, message):
    with pytest.raises(ConfigError, match=message):
        parse(_mutate(tmp_path, change))


def test_example_config_is_valid():
    from bytebind.config import load
    from conftest import ROOT

    config = load(ROOT / "examples" / "authority.toml")
    assert config.rps["manage-app"].unix_uid == 998 and config.rps["ops-console"].policy.tag_match == "all"
