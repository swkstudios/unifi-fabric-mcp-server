"""Proxy UUID contract tests — validates UUID enforcement on proxy paths.

Validates that:
  Selected Integration API routes accept UUID site IDs and reject ObjectIds before HTTP.
  Classic routes resolve the site slug before issuing their requests.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.families.hotspot import hotspot
from unifi_fabric.families.network import firewall_proxy, network, network_services_proxy
from unifi_fabric.families.vpn import vpn

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_VALID_UUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
_HOST_ID = "host-001"
_OBJECT_ID = "000000000000000000000503"  # 24-hex ObjectId — must never reach proxy URL

# A sample proxy sites response returning our test UUID
_PROXY_SITES = {"data": [{"id": _VALID_UUID, "description": "HQ"}]}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_client() -> AsyncMock:
    client = AsyncMock()
    client.get = AsyncMock(return_value={})
    client.post = AsyncMock(return_value={})
    client.put = AsyncMock(return_value={})
    client.delete = AsyncMock(return_value=None)
    client.patch = AsyncMock(return_value={})
    return client


def _make_registry(uuid_site_id: str = _VALID_UUID) -> AsyncMock:
    """Mock registry that returns a UUID or non-UUID site_id."""
    r = AsyncMock()
    r.resolve_key_for_host = AsyncMock(return_value=None)
    r.resolve_host_id = AsyncMock(return_value=_HOST_ID)
    r.resolve_site_id = AsyncMock(return_value=uuid_site_id)
    return r


def _make_registry_raises_objectid() -> AsyncMock:
    """Mock registry that returns an ObjectId — simulating stale /ea/sites data."""
    return _make_registry(uuid_site_id=_OBJECT_ID)


# ---------------------------------------------------------------------------
# network.py — positive (UUID) and negative (ObjectId) cases
# ---------------------------------------------------------------------------


class TestNetworkProxyUuidContract:
    @pytest.mark.asyncio
    async def test_list_networks_uuid_reaches_api(self):
        client = _make_client()
        # Default drain fetches bounded GET pages; assert the UUID reaches the request.
        client.get.return_value = {"data": [], "totalCount": 0}
        registry = _make_registry()
        await network.list_networks(client, registry, "myhost", "mysite")
        client.get.assert_awaited_once()
        url = client.get.call_args.args[0]
        assert client.get.call_args.kwargs["params"] == {"limit": 200, "offset": 0}
        assert _VALID_UUID in url

    @pytest.mark.asyncio
    async def test_list_networks_objectid_raises_before_http(self):
        client = _make_client()
        registry = _make_registry_raises_objectid()
        with pytest.raises(ValueError, match="not a UUID"):
            await network.list_networks(client, registry, "myhost", "mysite")
        client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_create_network_objectid_raises(self):
        client = _make_client()
        registry = _make_registry_raises_objectid()
        # Payload satisfies required-field validation so execution reaches the
        # site-UUID contract check that this test is about.
        with pytest.raises(ValueError, match="not a UUID"):
            await network.create_network(client, registry, "h", "s", {"management": "GATEWAY"})
        client.post.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_network_objectid_raises(self):
        client = _make_client()
        registry = _make_registry_raises_objectid()
        with pytest.raises(ValueError, match="not a UUID"):
            await network.get_network(client, registry, "h", "s", "net-1")
        client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_update_network_objectid_raises(self):
        client = _make_client()
        registry = _make_registry_raises_objectid()
        with pytest.raises(ValueError, match="not a UUID"):
            await network.update_network(client, registry, "h", "s", "net-1", {"name": "renamed"})
        client.put.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_network_objectid_raises(self):
        client = _make_client()
        registry = _make_registry_raises_objectid()
        with pytest.raises(ValueError, match="not a UUID"):
            await network.delete_network(client, registry, "h", "s", "net-1")
        client.delete.assert_not_called()

    @pytest.mark.asyncio
    async def test_list_wifi_broadcasts_objectid_raises(self):
        client = _make_client()
        registry = _make_registry_raises_objectid()
        with pytest.raises(ValueError, match="not a UUID"):
            await network.list_wifi_broadcasts(client, registry, "h", "s")
        client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_list_wan_interfaces_objectid_raises(self):
        client = _make_client()
        registry = _make_registry_raises_objectid()
        with pytest.raises(ValueError, match="not a UUID"):
            await network.list_wan_interfaces(client, registry, "h", "s")
        client.get.assert_not_called()


# ---------------------------------------------------------------------------
# network_services_proxy.py
# ---------------------------------------------------------------------------


class TestNetworkServicesProxyUuidContract:
    @pytest.mark.asyncio
    async def test_list_dns_policies_uuid_reaches_api(self):
        client = _make_client()
        # Default drain fetches bounded GET pages; assert the UUID reaches the request.
        client.get.return_value = {"data": [], "totalCount": 0}
        registry = _make_registry()
        await network_services_proxy.list_dns_policies(client, registry, "h", "s")
        client.get.assert_awaited_once()
        url = client.get.call_args.args[0]
        assert client.get.call_args.kwargs["params"] == {"limit": 200, "offset": 0}
        assert _VALID_UUID in url

    @pytest.mark.asyncio
    async def test_list_dns_policies_objectid_raises(self):
        client = _make_client()
        registry = _make_registry_raises_objectid()
        with pytest.raises(ValueError, match="not a UUID"):
            await network_services_proxy.list_dns_policies(client, registry, "h", "s")
        client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_list_traffic_matching_lists_objectid_raises(self):
        client = _make_client()
        registry = _make_registry_raises_objectid()
        with pytest.raises(ValueError, match="not a UUID"):
            await network_services_proxy.list_traffic_matching_lists(client, registry, "h", "s")
        client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_list_hotspot_vouchers_objectid_raises(self):
        client = _make_client()
        registry = _make_registry_raises_objectid()
        with pytest.raises(ValueError, match="not a UUID"):
            await network_services_proxy.list_hotspot_vouchers(client, registry, "h", "s")
        client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_list_radius_profiles_objectid_raises(self):
        client = _make_client()
        registry = _make_registry_raises_objectid()
        with pytest.raises(ValueError, match="not a UUID"):
            await network_services_proxy.list_radius_profiles(client, registry, "h", "s")
        client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_list_vpn_servers_proxy_objectid_raises(self):
        client = _make_client()
        registry = _make_registry_raises_objectid()
        with pytest.raises(ValueError, match="not a UUID"):
            await network_services_proxy.list_vpn_servers(client, registry, "h", "s")
        client.get.assert_not_called()


# ---------------------------------------------------------------------------
# firewall_proxy.py
# ---------------------------------------------------------------------------


class TestFirewallProxyUuidContract:
    @pytest.mark.asyncio
    async def test_list_firewall_policies_uuid_reaches_api(self):
        client = _make_client()
        # Default drain fetches bounded GET pages; assert the UUID reaches the request.
        client.get.return_value = {"data": [], "totalCount": 0}
        registry = _make_registry()
        await firewall_proxy.list_firewall_policies(client, registry, "h", "s")
        client.get.assert_awaited_once()
        url = client.get.call_args.args[0]
        assert client.get.call_args.kwargs["params"] == {"limit": 200, "offset": 0}
        assert _VALID_UUID in url

    @pytest.mark.asyncio
    async def test_list_firewall_policies_objectid_raises(self):
        client = _make_client()
        registry = _make_registry_raises_objectid()
        with pytest.raises(ValueError, match="not a UUID"):
            await firewall_proxy.list_firewall_policies(client, registry, "h", "s")
        client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_list_firewall_zones_objectid_raises(self):
        client = _make_client()
        registry = _make_registry_raises_objectid()
        with pytest.raises(ValueError, match="not a UUID"):
            await firewall_proxy.list_firewall_zones(client, registry, "h", "s")
        client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_list_acl_rules_objectid_raises(self):
        client = _make_client()
        registry = _make_registry_raises_objectid()
        with pytest.raises(ValueError, match="not a UUID"):
            await firewall_proxy.list_acl_rules(client, registry, "h", "s")
        client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_create_firewall_policy_objectid_raises(self):
        client = _make_client()
        registry = _make_registry_raises_objectid()
        # Payload satisfies required-field validation so execution reaches the
        # site-UUID contract check that this test is about.
        policy = {
            "name": "P",
            "action": {"type": "BLOCK"},
            "enabled": True,
            "source": {"zoneId": "z1"},
            "destination": {"zoneId": "z2"},
            "ipProtocolScope": {"ipVersion": "IPV4_AND_IPV6"},
            "loggingEnabled": False,
        }
        with pytest.raises(ValueError, match="not a UUID"):
            await firewall_proxy.create_firewall_policy(client, registry, "h", "s", policy)
        client.post.assert_not_called()


# ---------------------------------------------------------------------------
# hotspot.py (Classic REST endpoints — resolve_site_slug for list; resolve_site_id for create)
# ---------------------------------------------------------------------------


class TestHotspotUuidContract:
    @pytest.mark.asyncio
    async def test_create_hotspot_operator_uuid_resolves(self):
        client = _make_client()
        client.post.return_value = {"data": {"id": "op-1"}}
        registry = _make_registry()
        registry.resolve_site_slug = AsyncMock(return_value="default")
        await hotspot._create_hotspot_operator(
            client, registry, "myhost", "mysite", "admin", "pass"
        )
        # Classic REST: resolve_site_slug called with host_id (not resolve_site_id)
        registry.resolve_site_slug.assert_called_once_with("mysite", _HOST_ID, key=None)
        registry.resolve_site_id.assert_not_called()

    @pytest.mark.asyncio
    async def test_list_hotspot_operators_uses_classic_rest(self):
        """list_hotspot_operators uses Classic REST (resolve_site_slug, not resolve_site_id)."""
        client = _make_client()
        client.get.return_value = {"data": []}
        registry = _make_registry()
        registry.resolve_site_slug = AsyncMock(return_value="default")
        await hotspot._list_hotspot_operators(client, registry, "myhost", "mysite")
        registry.resolve_host_id.assert_called_once_with("myhost", key=None)
        registry.resolve_site_slug.assert_called_once_with("mysite", _HOST_ID, key=None)
        registry.resolve_site_id.assert_not_called()


# ---------------------------------------------------------------------------
# vpn.py writes (Classic REST networkconf / radiusprofile — resolve_site_slug)
# ---------------------------------------------------------------------------


class TestVpnClassicContract:
    """VPN-server and RADIUS writes use Classic REST networkconf/radiusprofile (site slug).

    The Integration POST/PUT/DELETE routes for VPN servers and RADIUS profiles are not
    served on Network 11.0.81 (405 / 404 "No endpoint"); the controller UI writes them
    through Classic REST, addressed by the site slug, never the Integration site UUID.
    """

    _NETWORKCONF = {
        "meta": {"rc": "ok"},
        "data": [{"_id": "c-1", "external_id": "vpn-1", "purpose": "remote-user-vpn"}],
    }

    @staticmethod
    def _registry() -> AsyncMock:
        registry = _make_registry()
        registry.resolve_site_slug = AsyncMock(return_value="default")
        return registry

    @pytest.mark.asyncio
    async def test_create_vpn_server_uses_site_slug(self):
        client = _make_client()
        registry = self._registry()
        await vpn._create_vpn_server(client, registry, "myhost", "mysite", "my-vpn", "wireguard")
        registry.resolve_site_slug.assert_called_once_with("mysite", _HOST_ID, key=None)
        registry.resolve_site_id.assert_not_called()

    @pytest.mark.asyncio
    async def test_update_vpn_server_uses_site_slug(self):
        client = _make_client()
        client.get.return_value = self._NETWORKCONF
        registry = self._registry()
        await vpn._update_vpn_server(
            client, registry, "myhost", "mysite", "vpn-1", {"enabled": False}
        )
        registry.resolve_site_slug.assert_called_once_with("mysite", _HOST_ID, key=None)
        registry.resolve_site_id.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_vpn_server_uses_site_slug(self):
        client = _make_client()
        client.get.return_value = self._NETWORKCONF
        registry = self._registry()
        await vpn._delete_vpn_server(client, registry, "myhost", "mysite", "vpn-1")
        registry.resolve_site_slug.assert_called_once_with("mysite", _HOST_ID, key=None)
        registry.resolve_site_id.assert_not_called()

    @pytest.mark.asyncio
    async def test_create_radius_profile_uses_site_slug(self):
        client = _make_client()
        registry = self._registry()
        await vpn._create_radius_profile(
            client, registry, "myhost", "mysite", "profile", "1.2.3.4", 1812, "secret"
        )
        registry.resolve_site_slug.assert_called_once_with("mysite", _HOST_ID, key=None)
        registry.resolve_site_id.assert_not_called()
