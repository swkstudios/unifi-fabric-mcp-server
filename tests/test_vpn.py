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
    c.put = AsyncMock()
    c.patch = AsyncMock()
    c.delete = AsyncMock()
    c.paginate_offset = AsyncMock()
    return c


@pytest.fixture()
def registry():
    r = AsyncMock()
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    r.resolve_site_id = AsyncMock(return_value=SITE_ID)
    return r


# --- VPN Servers ---


class TestGetVpnServer:
    """get_vpn_server drains the working per-console proxy list and filters by ID.

    Regression guard for the path-asymmetry bug: the tool used to filter the
    Site Manager ``/ea/vpn-servers`` list, which is not served on the console and
    404s at the route level, while ``list_vpn_servers`` used the proxy. These
    tests pin it to the proxy path that actually returns data.
    """

    async def test_basic(self, client, registry):
        client.paginate_offset.return_value = [{"id": "vpn-1", "name": "MyVPN"}]
        result = await get_vpn_server(client, registry, "myhost", "mysite", "vpn-1")
        assert result["id"] == "vpn-1"

    async def test_uses_proxy_path_not_ea(self, client, registry):
        client.paginate_offset.return_value = [{"id": "vpn-1"}]
        await get_vpn_server(client, registry, "h", "s", "vpn-1")
        called_path = client.paginate_offset.call_args[0][0]
        assert "/ea/vpn-servers" not in called_path
        assert called_path == f"{_PROXY_BASE}/sites/{SITE_ID}/vpn/servers"

    async def test_resolves_host_and_site(self, client, registry):
        client.paginate_offset.return_value = [{"id": "vpn-1"}]
        await get_vpn_server(client, registry, "myhost", "mysite", "vpn-1")
        registry.resolve_host_id.assert_called_once_with("myhost")
        registry.resolve_site_id.assert_called_once_with("mysite", HOST_ID)

    async def test_not_found(self, client, registry):
        client.paginate_offset.return_value = []
        with pytest.raises(ValueError, match="vpn-missing"):
            await get_vpn_server(client, registry, "h", "s", "vpn-missing")

    async def test_filters_by_id(self, client, registry):
        client.paginate_offset.return_value = [
            {"id": "vpn-1", "name": "FirstVPN"},
            {"id": "vpn-2", "name": "SecondVPN"},
        ]
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
    async def test_basic(self, client, registry):
        client.put.return_value = {"data": {"id": "vpn-1", "enabled": False}}
        result = await update_vpn_server(client, registry, "h", "s", "vpn-1", enabled=False)
        client.put.assert_called_once_with(
            f"{_PROXY_BASE}/sites/{SITE_ID}/vpn/servers/vpn-1", json={"enabled": False}
        )
        assert result["enabled"] is False

    async def test_uses_proxy_path_not_ea(self, client, registry):
        client.put.return_value = {"data": {}}
        await update_vpn_server(client, registry, "h", "s", "vpn-1", enabled=True)
        call_url = client.put.call_args[0][0]
        assert "/ea/vpn-servers" not in call_url
        assert f"/sites/{SITE_ID}/vpn/servers/vpn-1" in call_url

    async def test_resolves_host_and_site(self, client, registry):
        client.put.return_value = {"data": {}}
        await update_vpn_server(client, registry, "myhost", "mysite", "vpn-1", enabled=True)
        registry.resolve_host_id.assert_called_once_with("myhost")
        registry.resolve_site_id.assert_called_once_with("mysite", HOST_ID)


class TestDeleteVpnServer:
    async def test_basic(self, client, registry):
        client.delete.return_value = None
        result = await delete_vpn_server(client, registry, "h", "s", "vpn-1")
        client.delete.assert_called_once_with(f"{_PROXY_BASE}/sites/{SITE_ID}/vpn/servers/vpn-1")
        assert result == {"deleted": True, "serverId": "vpn-1"}

    async def test_uses_proxy_path_not_ea(self, client, registry):
        client.delete.return_value = None
        await delete_vpn_server(client, registry, "h", "s", "vpn-1")
        call_url = client.delete.call_args[0][0]
        assert "/ea/vpn-servers" not in call_url


# --- RADIUS Profiles ---


class TestGetRadiusProfile:
    """get_radius_profile drains the working per-console proxy list and filters by ID.

    Regression guard for the path-asymmetry bug: the tool used to filter the
    Site Manager ``/ea/radius-profiles`` list (not served → route-level 404) and
    took only ``profile_id``. It now requires ``host``/``site`` because the
    profile collection is per-site on the proxy, which is the only served path.
    """

    async def test_basic(self, client, registry):
        client.paginate_offset.return_value = [{"id": "rad-1", "name": "Corp RADIUS"}]
        result = await get_radius_profile(client, registry, "myhost", "mysite", "rad-1")
        assert result["id"] == "rad-1"
        assert result["name"] == "Corp RADIUS"

    async def test_uses_proxy_path_not_ea(self, client, registry):
        client.paginate_offset.return_value = [{"id": "rad-1"}]
        await get_radius_profile(client, registry, "h", "s", "rad-1")
        called_path = client.paginate_offset.call_args[0][0]
        assert "/ea/radius-profiles" not in called_path
        assert called_path == f"{_PROXY_BASE}/sites/{SITE_ID}/radius/profiles"

    async def test_resolves_host_and_site(self, client, registry):
        client.paginate_offset.return_value = [{"id": "rad-1"}]
        await get_radius_profile(client, registry, "myhost", "mysite", "rad-1")
        registry.resolve_host_id.assert_called_once_with("myhost")
        registry.resolve_site_id.assert_called_once_with("mysite", HOST_ID)

    async def test_not_found(self, client, registry):
        client.paginate_offset.return_value = []
        with pytest.raises(ValueError, match="rad-99"):
            await get_radius_profile(client, registry, "h", "s", "rad-99")

    async def test_filters_by_id(self, client, registry):
        client.paginate_offset.return_value = [
            {"id": "rad-1", "name": "Profile One"},
            {"id": "rad-2", "name": "Profile Two"},
        ]
        result = await get_radius_profile(client, registry, "h", "s", "rad-2")
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
