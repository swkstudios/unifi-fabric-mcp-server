"""Tests for port-forward and traffic-rule proxy tools (via network_services_proxy)."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.tools.network_services_proxy import (
    _CLASSIC_REST_BASE,
    _V2_API_BASE,
    create_port_forward,
    create_traffic_rule,
    delete_port_forward,
    delete_traffic_rule,
    list_port_forwards,
    list_traffic_rules,
    update_port_forward,
    update_traffic_rule,
)

HOST_ID = "host-001"
SITE_SLUG = "default"
CLASSIC_REST_BASE = _CLASSIC_REST_BASE.format(host_id=HOST_ID, site_slug=SITE_SLUG)
V2_API_BASE = _V2_API_BASE.format(host_id=HOST_ID, site_slug=SITE_SLUG)


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
    r.resolve_key_for_host = AsyncMock(return_value=None)
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    r.resolve_site_slug = AsyncMock(return_value=SITE_SLUG)
    return r


# --- Port Forwards (Classic REST API) ---


class TestListPortForwards:
    async def test_basic(self, client, registry):
        client.get.return_value = {"data": [{"_id": "pf-1"}]}
        result = await list_port_forwards(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/portforward", key=None)
        assert result == {"data": [{"_id": "pf-1"}]}

    async def test_resolves_host_and_site(self, client, registry):
        client.get.return_value = {}
        await list_port_forwards(client, registry, "myhost", "mysite")
        registry.resolve_host_id.assert_called_once_with("myhost", key=None)
        registry.resolve_site_slug.assert_called_once_with("mysite", HOST_ID, key=None)


class TestCreatePortForward:
    async def test_basic(self, client, registry):
        payload = {
            "enabled": True,
            "name": "Web Server",
            "pfwd_interface": "wan",
            "src": "any",
            "dst_port": "80",
            "fwd": "192.168.1.10",
            "fwd_port": "80",
            "proto": "tcp",
        }
        client.post.return_value = {"_id": "pf-2", **payload}
        result = await create_port_forward(client, registry, "h", "s", payload)
        client.post.assert_called_once_with(
            f"{CLASSIC_REST_BASE}/portforward", key=None, json=payload
        )
        assert result["name"] == "Web Server"


class TestUpdatePortForward:
    async def test_basic(self, client, registry):
        payload = {"enabled": False}
        client.get.return_value = {
            "data": [{"_id": "abcdef0123456789abcdef01"}]
        }  # write target resolved first
        client.put.return_value = {"_id": "abcdef0123456789abcdef01", "enabled": False}
        result = await update_port_forward(
            client, registry, "h", "s", "ABCDEF0123456789ABCDEF01", payload
        )
        client.get.assert_any_await(f"{CLASSIC_REST_BASE}/portforward", key=None)
        client.put.assert_called_once_with(
            f"{CLASSIC_REST_BASE}/portforward/abcdef0123456789abcdef01", key=None, json=payload
        )
        assert result["enabled"] is False


class TestDeletePortForward:
    async def test_basic(self, client, registry):
        client.get.return_value = {
            "data": [{"_id": "abcdef0123456789abcdef01"}]
        }  # write target resolved first
        client.delete.return_value = None
        await delete_port_forward(client, registry, "h", "s", "ABCDEF0123456789ABCDEF01")
        client.get.assert_any_await(f"{CLASSIC_REST_BASE}/portforward", key=None)
        client.delete.assert_called_once_with(
            f"{CLASSIC_REST_BASE}/portforward/abcdef0123456789abcdef01", key=None
        )


# --- Traffic Rules (v2 API) ---


class TestListTrafficRules:
    async def test_basic(self, client, registry):
        client.get.return_value = {"data": [{"_id": "tr-1"}]}
        result = await list_traffic_rules(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{V2_API_BASE}/trafficrules", key=None)
        assert result == {"data": [{"_id": "tr-1"}]}

    async def test_resolves_host_and_site(self, client, registry):
        client.get.return_value = {}
        await list_traffic_rules(client, registry, "myhost", "mysite")
        registry.resolve_host_id.assert_called_once_with("myhost", key=None)
        registry.resolve_site_slug.assert_called_once_with("mysite", HOST_ID, key=None)


class TestCreateTrafficRule:
    async def test_basic(self, client, registry):
        payload = {
            "description": "Block Gaming",
            "action": "BLOCK",
            "matching_target": "INTERNET",
            "target_devices": [{"client_mac": "aa:bb:cc:dd:ee:ff"}],
        }
        client.post.return_value = {"_id": "tr-2", **payload}
        result = await create_traffic_rule(client, registry, "h", "s", payload)
        client.post.assert_called_once_with(f"{V2_API_BASE}/trafficrules", key=None, json=payload)
        assert result["description"] == "Block Gaming"


class TestUpdateTrafficRule:
    async def test_basic(self, client, registry):
        payload = {"enabled": False}
        # The write target is resolved (and read for the merge) first.
        client.get.return_value = [
            {"_id": "abcdef0123456789abcdef01", "action": "BLOCK", "enabled": True}
        ]
        client.put.return_value = {"_id": "abcdef0123456789abcdef01", "enabled": False}
        result = await update_traffic_rule(
            client, registry, "h", "s", "ABCDEF0123456789ABCDEF01", payload
        )
        client.get.assert_any_await(f"{V2_API_BASE}/trafficrules", key=None)
        client.put.assert_called_once_with(
            f"{V2_API_BASE}/trafficrules/abcdef0123456789abcdef01/",
            key=None,
            json={"_id": "abcdef0123456789abcdef01", "action": "BLOCK", "enabled": False},
        )
        assert result["enabled"] is False


class TestDeleteTrafficRule:
    async def test_basic(self, client, registry):
        client.get.return_value = [
            {"_id": "abcdef0123456789abcdef01"}
        ]  # write target resolved first
        client.delete.return_value = None
        await delete_traffic_rule(client, registry, "h", "s", "ABCDEF0123456789ABCDEF01")
        client.get.assert_any_await(f"{V2_API_BASE}/trafficrules", key=None)
        client.delete.assert_called_once_with(
            f"{V2_API_BASE}/trafficrules/abcdef0123456789abcdef01/", key=None
        )
