"""Tests for network tools — Networks/VLANs, WiFi broadcasts, WAN interfaces."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import PaginationAbortedError
from unifi_fabric.tools.network import (
    PROXY_BASE,
    create_network,
    create_wifi_broadcast,
    delete_network,
    delete_wifi_broadcast,
    get_lag,
    get_mc_lag_domain,
    get_network,
    get_network_application_info,
    get_network_references,
    get_switch_stack,
    get_wifi_broadcast,
    list_lags,
    list_local_sites,
    list_mc_lag_domains,
    list_networks,
    list_switch_stacks,
    list_wan_interfaces,
    list_wifi_broadcasts,
    update_network,
    update_wan_interface,
    update_wifi_broadcast,
)

HOST_ID = "host-001"
SITE_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
SITE_SLUG = "default"
BASE = PROXY_BASE.format(host_id=HOST_ID)
STAT_BASE = f"/v1/connector/consoles/{HOST_ID}/proxy/network/api/s/{SITE_SLUG}/stat"
RESOURCE_ID = "11111111-2222-3333-4444-555555555555"


@pytest.fixture()
def client():
    c = AsyncMock()
    c.get = AsyncMock()
    c.post = AsyncMock()
    c.put = AsyncMock()
    c.delete = AsyncMock()
    return c


@pytest.fixture()
def registry():
    r = AsyncMock()
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    r.resolve_site_id = AsyncMock(return_value=SITE_ID)
    r.resolve_site_slug = AsyncMock(return_value=SITE_SLUG)
    return r


class TestApplicationAndSites:
    async def test_get_network_application_info(self, client, registry):
        client.get.return_value = {"applicationVersion": "10.4.57"}
        result = await get_network_application_info(client, registry, "myhost")
        client.get.assert_called_once_with(f"{BASE}/info")
        assert result["applicationVersion"] == "10.4.57"

    async def test_get_network_application_info_propagates_resolution_error(self, client, registry):
        registry.resolve_host_id.side_effect = ValueError("unknown host")
        with pytest.raises(ValueError, match="unknown host"):
            await get_network_application_info(client, registry, "missing")
        client.get.assert_not_called()

    async def test_list_local_sites_with_pagination_and_filter(self, client, registry):
        client.get.return_value = {"data": [], "offset": 10, "limit": 50}
        result = await list_local_sites(
            client,
            registry,
            "myhost",
            offset=10,
            limit=50,
            filter="name.like('lab*')",
        )
        client.get.assert_called_once_with(
            f"{BASE}/sites",
            params={"offset": 10, "limit": 50, "filter": "name.like('lab*')"},
        )
        assert result["offset"] == 10

    @pytest.mark.parametrize(
        ("offset", "limit", "message"),
        [
            (-1, 25, "offset"),
            (0, 201, "limit"),
        ],
    )
    async def test_list_local_sites_rejects_invalid_page(
        self, client, registry, offset, limit, message
    ):
        with pytest.raises(ValueError, match=message):
            await list_local_sites(client, registry, "myhost", offset=offset, limit=limit)
        client.get.assert_not_called()

    async def test_list_local_sites_drains_all_by_default(self, client, registry):
        client.paginate_offset.return_value = [{"id": "s1"}, {"id": "s2"}]
        result = await list_local_sites(client, registry, "myhost")
        client.paginate_offset.assert_called_once_with(
            f"{BASE}/sites", key=None, params=None, page_size=200
        )
        client.get.assert_not_called()
        assert result == {"data": [{"id": "s1"}, {"id": "s2"}], "totalCount": 2}

    async def test_list_local_sites_drains_with_filter(self, client, registry):
        client.paginate_offset.return_value = []
        await list_local_sites(client, registry, "myhost", filter="name.like('lab*')")
        client.paginate_offset.assert_called_once_with(
            f"{BASE}/sites", key=None, params={"filter": "name.like('lab*')"}, page_size=200
        )

    async def test_list_local_sites_cap_exceeded_marked_incomplete(self, client, registry):
        client.paginate_offset.side_effect = PaginationAbortedError(
            f"{BASE}/sites", 2, "page cap of 2 reached", items=[{"id": "s1"}]
        )
        result = await list_local_sites(client, registry, "myhost")
        assert result["incomplete"] is True
        assert result["data"] == [{"id": "s1"}]


class TestListNetworks:
    async def test_basic_drains_all_by_default(self, client, registry):
        client.paginate_offset.return_value = [{"id": "net-1", "name": "LAN"}]
        result = await list_networks(client, registry, "myhost", "mysite")
        client.paginate_offset.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/networks", key=None, params=None, page_size=200
        )
        client.get.assert_not_called()
        assert result == {"data": [{"id": "net-1", "name": "LAN"}], "totalCount": 1}

    async def test_manual_page_preserves_native_envelope(self, client, registry):
        envelope = {
            "data": [{"id": "net-1"}],
            "offset": 0,
            "limit": 25,
            "count": 1,
            "totalCount": 40,
        }
        client.get.return_value = envelope
        result = await list_networks(client, registry, "h", "s", offset=0, limit=25)
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/networks", params={"offset": 0, "limit": 25}
        )
        client.paginate_offset.assert_not_called()
        assert result == envelope

    async def test_cap_exceeded_marked_incomplete(self, client, registry):
        client.paginate_offset.side_effect = PaginationAbortedError(
            f"{BASE}/sites/{SITE_ID}/networks", 2, "page cap of 2 reached", items=[{"id": "net-1"}]
        )
        result = await list_networks(client, registry, "h", "s")
        assert result["incomplete"] is True
        assert result["data"] == [{"id": "net-1"}]

    async def test_resolves_names(self, client, registry):
        client.paginate_offset.return_value = []
        await list_networks(client, registry, "MyHost", "Office")
        registry.resolve_host_id.assert_called_once_with("MyHost")
        registry.resolve_site_id.assert_called_once_with("Office", HOST_ID)


class TestCreateNetwork:
    async def test_basic(self, client, registry):
        payload = {"name": "Guest", "vlan": 100}
        client.post.return_value = {"id": "net-2", **payload}
        result = await create_network(client, registry, "h", "s", payload)
        client.post.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/networks", json=payload)
        assert result["name"] == "Guest"


class TestGetNetwork:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "net-1", "name": "LAN"}
        result = await get_network(client, registry, "h", "s", "net-1")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/networks/net-1")
        assert result["id"] == "net-1"


class TestUpdateNetwork:
    async def test_basic(self, client, registry):
        payload = {"name": "Updated"}
        client.put.return_value = {"id": "net-1", **payload}
        result = await update_network(client, registry, "h", "s", "net-1", payload)
        client.put.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/networks/net-1", json=payload)
        assert result["name"] == "Updated"

    async def test_strips_read_only_fields(self, client, registry):
        """Read-only fields from get_network output are stripped before PUT."""
        payload = {"id": "net-1", "name": "Updated", "default": True, "metadata": {"x": 1}}
        client.put.return_value = {"id": "net-1", "name": "Updated"}
        result = await update_network(client, registry, "h", "s", "net-1", payload)
        # Only the non-read-only field should be sent
        client.put.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/networks/net-1", json={"name": "Updated"}
        )
        assert result["name"] == "Updated"

    async def test_passes_through_writable_fields(self, client, registry):
        """Fields not in the read-only set pass through unchanged."""
        payload = {"name": "Guest", "vlan": 100, "purpose": "corporate"}
        client.put.return_value = {"id": "net-1", **payload}
        result = await update_network(client, registry, "h", "s", "net-1", payload)
        client.put.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/networks/net-1", json=payload)
        assert result["vlan"] == 100


class TestDeleteNetwork:
    async def test_basic(self, client, registry):
        await delete_network(client, registry, "h", "s", "net-1")
        client.delete.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/networks/net-1")


class TestListWifiBroadcasts:
    async def test_basic(self, client, registry):
        client.get.return_value = [{"id": "wifi-1", "name": "Office"}]
        result = await list_wifi_broadcasts(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/wifi/broadcasts")
        assert result == [{"id": "wifi-1", "name": "Office"}]


class TestCreateWifiBroadcast:
    async def test_basic(self, client, registry):
        payload = {"name": "Guest WiFi", "security": "wpa2"}
        client.post.return_value = {"id": "wifi-2", **payload}
        result = await create_wifi_broadcast(client, registry, "h", "s", payload)
        client.post.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/wifi/broadcasts", json=payload)
        assert result["name"] == "Guest WiFi"


class TestGetWifiBroadcast:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "wifi-1", "name": "Office"}
        result = await get_wifi_broadcast(client, registry, "h", "s", "wifi-1")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/wifi/broadcasts/wifi-1")
        assert result["id"] == "wifi-1"


class TestUpdateWifiBroadcast:
    async def test_basic(self, client, registry):
        payload = {"name": "Updated SSID"}
        client.put.return_value = {"id": "wifi-1", **payload}
        result = await update_wifi_broadcast(client, registry, "h", "s", "wifi-1", payload)
        client.put.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/wifi/broadcasts/wifi-1", json=payload
        )
        assert result["name"] == "Updated SSID"


class TestDeleteWifiBroadcast:
    async def test_basic(self, client, registry):
        await delete_wifi_broadcast(client, registry, "h", "s", "wifi-1")
        client.delete.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/wifi/broadcasts/wifi-1")


class TestListWanInterfaces:
    async def test_basic(self, client, registry):
        wan_data = [{"id": "wan-1", "name": "WAN1"}]
        health_data = {"data": [{"subsystem": "wan", "status": "ok", "speedtest-status": {}}]}
        client.get.side_effect = [wan_data, health_data]
        result = await list_wan_interfaces(client, registry, "h", "s")
        assert client.get.call_count == 2
        assert client.get.call_args_list[0][0][0] == f"{BASE}/sites/{SITE_ID}/wans"
        assert client.get.call_args_list[1][0][0] == f"{STAT_BASE}/health"
        assert result["wans"] == wan_data
        assert result["count"] == 1
        assert result["wanHealth"] == [{"subsystem": "wan", "status": "ok", "speedtest-status": {}}]

    async def test_health_failure_still_returns_wans(self, client, registry):
        wan_data = [{"id": "wan-1", "name": "WAN1"}]
        client.get.side_effect = [wan_data, Exception("health unreachable")]
        result = await list_wan_interfaces(client, registry, "h", "s")
        assert result["wans"] == wan_data
        assert result["wanHealth"] == []

    async def test_resolves_names(self, client, registry):
        client.get.side_effect = [[], {"data": []}]
        await list_wan_interfaces(client, registry, "UDM-Pro", "Main Office")
        registry.resolve_host_id.assert_called_once_with("UDM-Pro")
        registry.resolve_site_id.assert_called_once_with("Main Office", HOST_ID)


class TestUpdateWanInterface:
    async def test_basic(self, client, registry):
        wan = {"name": "ISP2", "dns": ["8.8.8.8"]}
        client.put.return_value = {"id": "wan-1", **wan}
        result = await update_wan_interface(client, registry, "h", "s", "wan-1", wan)
        client.put.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/wans/wan-1", json=wan)
        assert result["name"] == "ISP2"

    async def test_resolves_names(self, client, registry):
        client.put.return_value = {}
        await update_wan_interface(client, registry, "UDM-Pro", "Main Office", "wan-1", {})
        registry.resolve_host_id.assert_called_once_with("UDM-Pro")
        registry.resolve_site_id.assert_called_once_with("Main Office", HOST_ID)


class TestGetNetworkReferences:
    async def test_basic(self, client, registry):
        client.get.return_value = {"data": [{"type": "wifi_broadcast", "id": "wifi-1"}]}
        result = await get_network_references(client, registry, "h", "s", "net-1")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/networks/net-1/references")
        assert result["data"][0]["type"] == "wifi_broadcast"

    async def test_resolves_names(self, client, registry):
        client.get.return_value = {}
        await get_network_references(client, registry, "UDM-Pro", "Main Office", "net-1")
        registry.resolve_host_id.assert_called_once_with("UDM-Pro")
        registry.resolve_site_id.assert_called_once_with("Main Office", HOST_ID)


@pytest.mark.parametrize(
    ("function", "resource"),
    [
        (list_lags, "lags"),
        (list_mc_lag_domains, "mc-lag-domains"),
        (list_switch_stacks, "switch-stacks"),
    ],
)
async def test_list_switching_resource(function, resource, client, registry):
    client.get.return_value = {"data": [], "offset": 5, "limit": 25}
    result = await function(
        client,
        registry,
        "myhost",
        "mysite",
        offset=5,
        limit=25,
        filter="metadata.origin.eq('USER')",
    )
    client.get.assert_called_once_with(
        f"{BASE}/sites/{SITE_ID}/switching/{resource}",
        params={"offset": 5, "limit": 25, "filter": "metadata.origin.eq('USER')"},
    )
    assert result["data"] == []


@pytest.mark.parametrize("function", [list_lags, list_mc_lag_domains, list_switch_stacks])
async def test_list_switching_resource_rejects_invalid_limit(function, client, registry):
    with pytest.raises(ValueError, match="limit"):
        await function(client, registry, "myhost", "mysite", limit=201)
    client.get.assert_not_called()


@pytest.mark.parametrize(
    ("function", "resource"),
    [
        (list_lags, "lags"),
        (list_mc_lag_domains, "mc-lag-domains"),
        (list_switch_stacks, "switch-stacks"),
    ],
)
async def test_list_switching_resource_drains_all_by_default(function, resource, client, registry):
    client.paginate_offset.return_value = [{"id": "r1"}, {"id": "r2"}]
    result = await function(client, registry, "myhost", "mysite")
    client.paginate_offset.assert_called_once_with(
        f"{BASE}/sites/{SITE_ID}/switching/{resource}", key=None, params=None, page_size=200
    )
    client.get.assert_not_called()
    assert result == {"data": [{"id": "r1"}, {"id": "r2"}], "totalCount": 2}


@pytest.mark.parametrize("function", [list_lags, list_mc_lag_domains, list_switch_stacks])
async def test_list_switching_resource_cap_exceeded_marked_incomplete(function, client, registry):
    client.paginate_offset.side_effect = PaginationAbortedError(
        "path", 2, "page cap of 2 reached", items=[{"id": "r1"}]
    )
    result = await function(client, registry, "myhost", "mysite")
    assert result["incomplete"] is True
    assert result["data"] == [{"id": "r1"}]


@pytest.mark.parametrize(
    ("function", "resource"),
    [
        (get_lag, "lags"),
        (get_mc_lag_domain, "mc-lag-domains"),
        (get_switch_stack, "switch-stacks"),
    ],
)
async def test_get_switching_resource(function, resource, client, registry):
    client.get.return_value = {"id": RESOURCE_ID}
    result = await function(client, registry, "myhost", "mysite", RESOURCE_ID)
    client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/switching/{resource}/{RESOURCE_ID}")
    assert result["id"] == RESOURCE_ID


@pytest.mark.parametrize("function", [get_lag, get_mc_lag_domain, get_switch_stack])
async def test_get_switching_resource_rejects_unsafe_id(function, client, registry):
    with pytest.raises(ValueError, match="Invalid"):
        await function(client, registry, "myhost", "mysite", "../unsafe")
    client.get.assert_not_called()
