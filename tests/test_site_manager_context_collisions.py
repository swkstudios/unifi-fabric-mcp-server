"""Additive tool context preserves colliding upstream data."""

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.families.site_manager import site_manager
from unifi_fabric.registry import Registry


@pytest.fixture
async def client():
    value = UniFiClient(Settings(api_key="synthetic-key"))
    yield value
    await value.close()


@pytest.fixture
def registry(client):
    return Registry(client, ttl_seconds=0)


async def test_compare_preserves_upstream_site_label(client, registry, monkeypatch):
    upstream = {"_siteLabel": "upstream-label", "data": [{"status": "ok"}]}
    monkeypatch.setattr(site_manager, "get_site_health_summary", AsyncMock(return_value=upstream))
    result = await site_manager.compare_site_performance(client, registry, ["site-a"])
    assert result["_comparison"][0]["_siteLabel"] == "upstream-label"
    assert result["_comparison"][0]["_wrapperFields"]["_siteLabel"] == "site-a"
    assert "_wrapperFields" not in upstream


@pytest.mark.parametrize("scope,kind", [("devices", "device"), ("clients", "client")])
async def test_search_preserves_upstream_type(client, registry, monkeypatch, scope, kind):
    registry.get_ea_sites = AsyncMock(return_value=[{"hostId": "host-h1", "siteId": "s1"}])
    registry.resolve_key_for_host = AsyncMock(return_value=None)
    monkeypatch.setattr(
        site_manager,
        "_proxy_site_for_ea",
        AsyncMock(return_value={"id": "00000000-0000-4000-8000-000000000001"}),
    )
    upstream = {"name": "match", "_type": "upstream-type", "_siteId": "own-site"}

    async def collect(client, path, **kwargs):
        return {"items": [upstream] if path.endswith("/" + scope) else [], "incomplete": False}

    monkeypatch.setattr(site_manager, "collect_offset", collect)
    result = await site_manager.search_across_sites(client, registry, "match")
    item = result["data"][0]
    assert item["_type"] == "upstream-type"
    assert item["_wrapperFields"]["_type"] == kind
    assert item["_siteId"] == "own-site"
    assert item["_wrapperFields"]["_siteId"] == "00000000-0000-4000-8000-000000000001"
    assert "_wrapperFields" not in upstream


async def test_protect_file_type_collision(client, registry):
    from unifi_fabric.families.protect import protect

    registry.resolve_key_for_host = AsyncMock(return_value=None)
    registry.resolve_host_id = AsyncMock(return_value="host-h1")
    client.get = AsyncMock(return_value={"data": [], "_file_type": "upstream"})
    result = await protect.list_protect_files(client, registry, "host-h1", "animations")
    assert result["_file_type"] == "upstream"
    assert result["_wrapperFields"]["_file_type"] == "animations"


@pytest.mark.parametrize("fails", [False, True])
async def test_wan_context_collision(client, registry, monkeypatch, fails):
    from unifi_fabric.families.network import network

    registry.resolve_key_for_host = AsyncMock(return_value=None)
    registry.resolve_host_id = AsyncMock(return_value="host-h1")
    registry.resolve_site_id = AsyncMock(return_value="00000000-0000-4000-8000-000000000001")
    registry.resolve_site_slug = AsyncMock(return_value="default")
    monkeypatch.setattr(network, "collect_offset", AsyncMock(return_value={}))
    upstream = {"data": [], "_health": "upstream-health", "_wanHealthError": "upstream-error"}
    monkeypatch.setattr(network, "offset_list_result", lambda _: upstream)
    client.get = (
        AsyncMock(side_effect=RuntimeError("health-failed"))
        if fails
        else AsyncMock(return_value={"data": []})
    )
    result = await network.list_wan_interfaces(client, registry, "host-h1", "site-a")
    field = "_wanHealthError" if fails else "_health"
    assert result[field] == upstream[field]
    assert field in result["_wrapperFields"]
    assert "_wrapperFields" not in upstream


async def test_setting_noop_note_collision(client, registry):
    from unifi_fabric.families.network import network_services_proxy as proxy

    registry.resolve_key_for_host = AsyncMock(return_value=None)
    registry.resolve_host_id = AsyncMock(return_value="host-h1")
    registry.resolve_site_slug = AsyncMock(return_value="default")
    client.get = AsyncMock(
        return_value={"data": [{"key": "mgmt", "enabled": True}], "_note": "upstream-note"}
    )
    client.put = AsyncMock()
    result = await proxy.update_setting(
        client, registry, "host-h1", "site-a", "mgmt", {"enabled": True}
    )
    assert result["_note"] == "upstream-note"
    assert result["_wrapperFields"]["_note"] == "no change needed"
    client.put.assert_not_called()


def test_resolved_profile_annotation_collision():
    from unifi_fabric.families.network import network_services_proxy as proxy

    upstream = {"native_networkconf_id": "network-a", "_resolved_networks": "upstream"}
    result = proxy._resolve_profile_networkconf(upstream, {})
    assert result["_resolved_networks"] == "upstream"
    assert result["_wrapperFields"]["_resolved_networks"] == {
        "native_networkconf_id": {"id": "network-a", "name": None, "vlan": None}
    }


@pytest.mark.parametrize("as_list", [False, True])
def test_resolution_error_annotation_collision(as_list):
    from unifi_fabric.families.network import network_services_proxy as proxy

    upstream = {"_resolvedNetworksError": "upstream"}
    result = proxy._with_resolution([upstream] if as_list else upstream, {}, "lookup-failed")
    if as_list:
        result = result[0]
    assert result["_resolvedNetworksError"] == "upstream"
    assert result["_wrapperFields"]["_resolvedNetworksError"] == "lookup-failed"


async def test_port_exclusion_response_annotation_collisions(client, registry, monkeypatch):
    from unifi_fabric.families.network import network_services_proxy as proxy

    registry.resolve_key_for_host = AsyncMock(return_value=None)
    registry.resolve_host_id = AsyncMock(return_value="host-h1")
    registry.resolve_site_slug = AsyncMock(return_value="default")
    monkeypatch.setattr(proxy, "_networkconf_docs", AsyncMock(return_value=[{"_id": "network-a"}]))
    monkeypatch.setattr(
        proxy,
        "_port_profile_for_write",
        AsyncMock(return_value={"_id": "profile-a", "excluded_networkconf_ids": []}),
    )
    monkeypatch.setattr(proxy, "_name_map_or_error", AsyncMock(return_value=({}, "lookup-failed")))
    fields = ["_profileNote", "_tagged_networks", "_network", "_resolvedNetworksError"]
    upstream = {"data": [], **{field: "upstream-" + field for field in fields}}
    client.put = AsyncMock(return_value=upstream)
    result = await proxy._mutate_port_profile_exclusion(
        client, registry, "host-h1", "site-a", "profile-a", "network-a", exclude=True
    )
    for field in fields:
        assert result[field] == upstream[field]
        assert field in result["_wrapperFields"]


async def test_resolved_site_id_keeps_own_field(client, registry):
    upstream = {"hostId": "host-h1", "siteId": "s1", "_resolvedSiteId": "upstream-site"}
    registry.get_ea_sites = AsyncMock(return_value=[upstream])
    result = await site_manager._resolve_ea_site_record(registry, "s1", client)
    assert result["_resolvedSiteId"] == "upstream-site"
    assert result["_wrapperFields"]["_resolvedSiteId"] == "s1"


async def test_search_site_resolution_keeps_own_field(client, registry, monkeypatch):
    upstream = {"hostId": "host-h1", "siteId": "s1", "_resolvedSiteId": "upstream-site"}
    registry.get_ea_sites = AsyncMock(return_value=[upstream])
    registry.resolve_key_for_host = AsyncMock(return_value=None)
    seen = []

    async def resolve(registry, record, key):
        seen.append(record)
        return {"id": "00000000-0000-4000-8000-000000000001"}

    monkeypatch.setattr(site_manager, "_proxy_site_for_ea", resolve)
    monkeypatch.setattr(
        site_manager, "collect_offset", AsyncMock(return_value={"items": [], "incomplete": False})
    )
    await site_manager.search_across_sites(client, registry, "")
    assert seen[0]["_resolvedSiteId"] == "upstream-site"
    assert seen[0]["_wrapperFields"]["_resolvedSiteId"] == "s1"


@pytest.mark.parametrize("value", ["upstream-warning", None, 17, {"own": "warning"}])
def test_warning_annotation_keeps_non_list_upstream_field(value):
    from unifi_fabric.families.network import network_services_proxy as proxy

    warning = {"code": "test-warning"}
    upstream = {"_warnings": value}
    result = proxy._with_warning(upstream, warning)
    assert result["_warnings"] == value
    assert result["_wrapperFields"]["_warnings"] == [warning]
    assert "_wrapperFields" not in upstream
