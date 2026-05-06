"""Tests for vpn tools — VPN servers and RADIUS profiles."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.tools.network import PROXY_BASE
from unifi_fabric.tools.vpn import (
    _create_radius_profile as create_radius_profile,
)
from unifi_fabric.tools.vpn import (
    _create_site_to_site_tunnel as create_site_to_site_tunnel,
)
from unifi_fabric.tools.vpn import (
    _create_vpn_server as create_vpn_server,
)
from unifi_fabric.tools.vpn import (
    _delete_site_to_site_tunnel as delete_site_to_site_tunnel,
)
from unifi_fabric.tools.vpn import (
    _delete_vpn_server as delete_vpn_server,
)
from unifi_fabric.tools.vpn import (
    _get_radius_profile as get_radius_profile,
)
from unifi_fabric.tools.vpn import (
    _get_vpn_server as get_vpn_server,
)
from unifi_fabric.tools.vpn import (
    _list_radius_profiles as list_radius_profiles,
)
from unifi_fabric.tools.vpn import (
    _list_vpn_servers as list_vpn_servers,
)
from unifi_fabric.tools.vpn import (
    _update_site_to_site_tunnel as update_site_to_site_tunnel,
)
from unifi_fabric.tools.vpn import (
    _update_vpn_server as update_vpn_server,
)

HOST_ID = "host-001"
SITE_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"


@pytest.fixture()
def client():
    c = AsyncMock()
    c.get = AsyncMock()
    c.post = AsyncMock()
    c.patch = AsyncMock()
    c.delete = AsyncMock()
    return c


@pytest.fixture()
def registry():
    r = AsyncMock()
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    r.resolve_site_id = AsyncMock(return_value=SITE_ID)
    return r


# --- VPN Servers ---


class TestListVpnServers:
    async def test_no_filters(self, client, registry):
        client.get.return_value = {"data": [{"id": "vpn-1", "name": "MyVPN"}]}
        result = await list_vpn_servers(client, registry)
        client.get.assert_called_once_with("/ea/vpn-servers", params=None)
        assert result["count"] == 1
        assert result["vpnServers"][0]["id"] == "vpn-1"

    async def test_with_host_and_site(self, client, registry):
        client.get.return_value = {"data": []}
        await list_vpn_servers(client, registry, host="myhost", site="mysite")
        registry.resolve_host_id.assert_called_once_with("myhost")
        registry.resolve_site_id.assert_called_once_with("mysite", HOST_ID)
        client.get.assert_called_once_with(
            "/ea/vpn-servers", params={"hostId": HOST_ID, "siteId": SITE_ID}
        )

    async def test_with_page_token(self, client, registry):
        client.get.return_value = {"data": [], "nextToken": "tok-2"}
        result = await list_vpn_servers(client, registry, page_token="tok-1")
        assert "nextToken" in result
        assert result["nextToken"] == "tok-2"

    async def test_empty_data(self, client, registry):
        client.get.return_value = {"data": []}
        result = await list_vpn_servers(client, registry)
        assert result == {"vpnServers": [], "count": 0}


class TestGetVpnServer:
    async def test_basic(self, client, registry):
        client.get.return_value = {"data": [{"id": "vpn-1", "name": "MyVPN"}]}
        result = await get_vpn_server(client, registry, "myhost", "mysite", "vpn-1")
        client.get.assert_called_once_with(
            "/ea/vpn-servers", params={"hostId": HOST_ID, "siteId": SITE_ID}
        )
        assert result["id"] == "vpn-1"

    async def test_resolves_host_and_site(self, client, registry):
        client.get.return_value = {"data": [{"id": "vpn-1"}]}
        await get_vpn_server(client, registry, "myhost", "mysite", "vpn-1")
        registry.resolve_host_id.assert_called_once_with("myhost")
        registry.resolve_site_id.assert_called_once_with("mysite", HOST_ID)

    async def test_not_found(self, client, registry):
        client.get.return_value = {"data": []}
        with pytest.raises(ValueError, match="vpn-missing"):
            await get_vpn_server(client, registry, "h", "s", "vpn-missing")

    async def test_filters_by_id(self, client, registry):
        client.get.return_value = {
            "data": [
                {"id": "vpn-1", "name": "FirstVPN"},
                {"id": "vpn-2", "name": "SecondVPN"},
            ]
        }
        result = await get_vpn_server(client, registry, "h", "s", "vpn-2")
        assert result["id"] == "vpn-2"
        assert result["name"] == "SecondVPN"


class TestCreateVpnServer:
    async def test_basic(self, client, registry):
        client.post.return_value = {"data": {"id": "vpn-2", "name": "CorpVPN"}}
        result = await create_vpn_server(
            client, registry, "myhost", "mysite", "CorpVPN", "wireguard"
        )
        expected_url = f"{_PROXY_BASE}/sites/{SITE_ID}/vpn/servers"
        client.post.assert_called_once_with(
            expected_url,
            json={
                "name": "CorpVPN",
                "type": "wireguard",
                "enabled": True,
            },
        )
        assert result["id"] == "vpn-2"

    async def test_posts_to_proxy_not_ea(self, client, registry):
        """Ensure create_vpn_server uses the per-site proxy endpoint, not /ea/vpn-servers."""
        client.post.return_value = {"data": {"id": "vpn-x"}}
        await create_vpn_server(client, registry, "h", "s", "TestVPN", "wireguard")
        call_url = client.post.call_args[0][0]
        assert "/ea/vpn-servers" not in call_url
        assert f"/sites/{SITE_ID}/vpn/servers" in call_url

    async def test_with_subnet(self, client, registry):
        client.post.return_value = {"data": {"id": "vpn-3"}}
        await create_vpn_server(client, registry, "h", "s", "VPN2", "openvpn", subnet="10.8.0.0/24")
        call_json = client.post.call_args[1]["json"]
        assert call_json["subnet"] == "10.8.0.0/24"

    async def test_disabled(self, client, registry):
        client.post.return_value = {"data": {}}
        await create_vpn_server(client, registry, "h", "s", "VPN3", "l2tp", enabled=False)
        call_json = client.post.call_args[1]["json"]
        assert call_json["enabled"] is False

    async def test_no_host_site_in_body(self, client, registry):
        """hostId and siteId should not be in the request body for the proxy endpoint."""
        client.post.return_value = {"data": {}}
        await create_vpn_server(client, registry, "h", "s", "VPN4", "openvpn")
        call_json = client.post.call_args[1]["json"]
        assert "hostId" not in call_json
        assert "siteId" not in call_json


class TestUpdateVpnServer:
    async def test_basic(self, client):
        client.patch.return_value = {"data": {"id": "vpn-1", "enabled": False}}
        result = await update_vpn_server(client, "vpn-1", enabled=False)
        client.patch.assert_called_once_with("/ea/vpn-servers/vpn-1", json={"enabled": False})
        assert result["enabled"] is False


class TestDeleteVpnServer:
    async def test_basic(self, client):
        client.delete.return_value = None
        result = await delete_vpn_server(client, "vpn-1")
        client.delete.assert_called_once_with("/ea/vpn-servers/vpn-1")
        assert result == {"deleted": True, "serverId": "vpn-1"}


# --- RADIUS Profiles ---


class TestListRadiusProfiles:
    async def test_no_filters(self, client, registry):
        client.get.return_value = {"data": [{"id": "rad-1"}]}
        result = await list_radius_profiles(client, registry)
        client.get.assert_called_once_with("/ea/radius-profiles", params=None)
        assert result["count"] == 1

    async def test_with_host_and_site(self, client, registry):
        client.get.return_value = {"data": []}
        await list_radius_profiles(client, registry, host="h", site="s")
        client.get.assert_called_once_with(
            "/ea/radius-profiles",
            params={"hostId": HOST_ID, "siteId": SITE_ID},
        )

    async def test_pagination(self, client, registry):
        client.get.return_value = {"data": [], "nextToken": "page-2"}
        result = await list_radius_profiles(client, registry, page_token="page-1")
        assert result["nextToken"] == "page-2"


class TestGetRadiusProfile:
    async def test_basic(self, client, registry):
        client.get.return_value = {"data": [{"id": "rad-1", "name": "Corp RADIUS"}]}
        result = await get_radius_profile(client, registry, "rad-1")
        client.get.assert_called_once_with("/ea/radius-profiles", params=None)
        assert result["id"] == "rad-1"
        assert result["name"] == "Corp RADIUS"

    async def test_not_found(self, client, registry):
        client.get.return_value = {"data": []}
        with pytest.raises(ValueError, match="rad-99"):
            await get_radius_profile(client, registry, "rad-99")

    async def test_filters_by_id(self, client, registry):
        client.get.return_value = {
            "data": [
                {"id": "rad-1", "name": "Profile One"},
                {"id": "rad-2", "name": "Profile Two"},
            ]
        }
        result = await get_radius_profile(client, registry, "rad-2")
        assert result["id"] == "rad-2"
        assert result["name"] == "Profile Two"


_PROXY_BASE = f"/v1/connector/consoles/{HOST_ID}/proxy/network/integration/v1"


class TestCreateRadiusProfile:
    async def test_basic(self, client, registry):
        client.post.return_value = {"data": {"id": "rad-2"}}
        await create_radius_profile(
            client,
            registry,
            "myhost",
            "mysite",
            "CorpRADIUS",
            "192.168.1.100",
            1812,
            "secret",
        )
        call_url = client.post.call_args[0][0]
        assert call_url == f"{_PROXY_BASE}/sites/{SITE_ID}/radius/profiles"
        call_json = client.post.call_args[1]["json"]
        assert call_json["name"] == "CorpRADIUS"
        assert call_json["authServerIp"] == "192.168.1.100"
        assert call_json["authServerPort"] == 1812
        assert call_json["authServerSecret"] == "secret"
        assert "hostId" not in call_json
        assert "siteId" not in call_json

    async def test_with_accounting(self, client, registry):
        client.post.return_value = {"data": {}}
        await create_radius_profile(
            client,
            registry,
            "h",
            "s",
            "RAD2",
            "10.0.0.1",
            1812,
            "sec",
            acct_server_ip="10.0.0.2",
            acct_server_port=1813,
            acct_server_secret="acct-sec",
        )
        call_json = client.post.call_args[1]["json"]
        assert call_json["acctServerIp"] == "10.0.0.2"
        assert call_json["acctServerPort"] == 1813
        assert call_json["acctServerSecret"] == "acct-sec"

    async def test_acct_ip_without_secret(self, client, registry):
        client.post.return_value = {"data": {}}
        await create_radius_profile(
            client,
            registry,
            "h",
            "s",
            "R",
            "1.2.3.4",
            1812,
            "s",
            acct_server_ip="1.2.3.5",
        )
        call_json = client.post.call_args[1]["json"]
        assert call_json["acctServerIp"] == "1.2.3.5"
        assert "acctServerSecret" not in call_json


TUNNEL_BASE = f"{PROXY_BASE.format(host_id=HOST_ID)}/sites/{SITE_ID}/vpn/site-to-site-tunnels"


class TestCreateSiteToSiteTunnel:
    async def test_basic(self, client, registry):
        tunnel = {"remoteIp": "10.0.0.1", "psk": "secret"}
        client.post.return_value = {"id": "tun-1", **tunnel}
        result = await create_site_to_site_tunnel(client, registry, "h", "s", tunnel)
        client.post.assert_called_once_with(TUNNEL_BASE, json=tunnel)
        assert result["remoteIp"] == "10.0.0.1"

    async def test_resolves_host_and_site(self, client, registry):
        client.post.return_value = {"id": "tun-1"}
        await create_site_to_site_tunnel(client, registry, "myhost", "mysite", {})
        registry.resolve_host_id.assert_called_once_with("myhost")
        registry.resolve_site_id.assert_called_once_with("mysite", HOST_ID)


class TestUpdateSiteToSiteTunnel:
    async def test_basic(self, client, registry):
        tunnel = {"enabled": False}
        client.put.return_value = {"id": "tun-1", **tunnel}
        result = await update_site_to_site_tunnel(client, registry, "h", "s", "tun-1", tunnel)
        client.put.assert_called_once_with(f"{TUNNEL_BASE}/tun-1", json=tunnel)
        assert result["enabled"] is False


class TestDeleteSiteToSiteTunnel:
    async def test_basic(self, client, registry):
        client.delete.return_value = None
        result = await delete_site_to_site_tunnel(client, registry, "h", "s", "tun-1")
        client.delete.assert_called_once_with(f"{TUNNEL_BASE}/tun-1")
        assert result == {"deleted": True, "tunnelId": "tun-1"}
