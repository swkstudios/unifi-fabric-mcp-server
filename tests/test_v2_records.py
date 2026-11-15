"""The vpn family's v2 site-record helpers (families/vpn/_v2_records.py)."""

from __future__ import annotations

import pytest

from tests.test_network_vpn_dns import HOST, SITE, V2, Client, Registry
from unifi_fabric.families.vpn._v2_records import (
    merge_leaves,
    site_slug,
    update_leaves,
    v2_get,
    with_verdict,
)


def test_merge_lays_only_the_requested_leaves_over_the_record():
    current = {"a": 1, "nested": {"keep": 1, "mode": "a"}}
    assert merge_leaves(current, {"nested": {"mode": "b"}}) == {
        "a": 1,
        "nested": {"keep": 1, "mode": "b"},
    }
    assert current["nested"]["mode"] == "a"


def test_update_leaves_drops_identity_fields_and_refuses_an_empty_update():
    assert update_leaves({"_id": "x", "value": 2}, "thing") == {"value": 2}
    with pytest.raises(ValueError):
        update_leaves({}, "thing")


def test_with_verdict_keeps_a_non_object_body_whole():
    assert with_verdict([1], {"a": 1}, True, None) == {
        "response": [1],
        "_verified": True,
        "_readAfter": {"a": 1},
    }


async def test_site_resolution_and_v2_reads():
    client, registry = Client(), Registry()
    assert await site_slug(registry, HOST, SITE) == (None, "host-1", "default")
    assert await v2_get(client, registry, HOST, SITE, "/static-dns") == client.dns
    assert client.calls == [("GET", f"{V2}/static-dns", None)]
