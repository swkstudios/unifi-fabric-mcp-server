"""Tests for network tools — Networks/VLANs, WiFi broadcasts, WAN interfaces."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.tools.network import (
    PROXY_BASE,
    create_network,
    create_wifi_broadcast,
    delete_network,
    delete_wifi_broadcast,
    get_network,
    get_network_references,
    get_wifi_broadcast,
    list_networks,
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


class TestListNetworks:
    async def test_basic(self, client, registry):
        client.get.return_value = [{"id": "net-1", "name": "LAN"}]
        result = await list_networks(client, registry, "myhost", "mysite")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/networks")
        assert result == [{"id": "net-1", "name": "LAN"}]

    async def test_resolves_names(self, client, registry):
        client.get.return_value = []
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
