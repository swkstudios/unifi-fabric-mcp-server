"""Tests for vpn tools — VPN servers and RADIUS profiles."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.families.vpn.vpn import (
    _create_radius_profile as create_radius_profile,
)
from unifi_fabric.families.vpn.vpn import (
    _create_site_to_site_tunnel as create_site_to_site_tunnel,
)
from unifi_fabric.families.vpn.vpn import (
    _create_vpn_server as create_vpn_server,
)
from unifi_fabric.families.vpn.vpn import (
    _delete_site_to_site_tunnel as delete_site_to_site_tunnel,
)
from unifi_fabric.families.vpn.vpn import (
    _delete_vpn_server as delete_vpn_server,
)
from unifi_fabric.families.vpn.vpn import (
    _get_radius_profile as get_radius_profile,
)
from unifi_fabric.families.vpn.vpn import (
    _get_vpn_server as get_vpn_server,
)
from unifi_fabric.families.vpn.vpn import (
    _update_site_to_site_tunnel as update_site_to_site_tunnel,
)
from unifi_fabric.families.vpn.vpn import (
    _update_vpn_server as update_vpn_server,
)

HOST_ID = "host-001"
SITE_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"


@pytest.fixture()
def client():
    c = AsyncMock()
    c.get = AsyncMock()
    c.paginate_max_pages = None
    c.post = AsyncMock()
    c.put = AsyncMock()
    c.patch = AsyncMock()
    c.delete = AsyncMock()
    c.paginate_offset = AsyncMock()
    return c


@pytest.fixture()
def registry():
    r = AsyncMock()
    r.resolve_key_for_host = AsyncMock(return_value=None)
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    r.resolve_site_id = AsyncMock(return_value=SITE_ID)
    r.resolve_site_slug = AsyncMock(return_value="default")
    return r


# Classic REST networkconf as the controller serves it: each record carries its own _id
# and, as external_id, the id the Integration list tools report (Network 11.0.81).
CLASSIC = f"/v1/connector/consoles/{HOST_ID}/proxy/network/api/s/default/rest"
NETWORKCONF = {
    "meta": {"rc": "ok"},
    "data": [
        {"_id": "c-lan", "external_id": "i-lan", "name": "Default", "purpose": "corporate"},
        {
            "_id": "c-vpn",
            "external_id": "i-vpn",
            "name": "One-Click VPN",
            "purpose": "remote-user-vpn",
            "vpn_type": "wireguard-server",
        },
        {
            "_id": "c-s2s",
            "external_id": "i-s2s",
            "name": "Branch",
            "purpose": "site-vpn",
            "vpn_type": "openvpn-vpn",
        },
        {"_id": "c-wan", "external_id": "i-wan", "name": "Fiber", "purpose": "wan"},
    ],
}


# --- VPN Servers ---


class TestGetVpnServer:
    """get_vpn_server drains the working per-console proxy list and filters by ID.

    Regression guard for the path-asymmetry bug: the tool used to filter the
    Site Manager ``/ea/vpn-servers`` list, which is not served on the console and
    404s at the route level, while ``list_vpn_servers`` used the proxy. These
    tests pin it to the proxy path that actually returns data.
    """

    async def test_basic(self, client, registry):
        client.get.return_value = [{"id": "vpn-1", "name": "MyVPN"}]
        result = await get_vpn_server(client, registry, "myhost", "mysite", "vpn-1")
        assert result["id"] == "vpn-1"

    async def test_uses_proxy_path_not_ea(self, client, registry):
        client.get.return_value = [{"id": "vpn-1"}]
        await get_vpn_server(client, registry, "h", "s", "vpn-1")
        called_path = client.get.call_args[0][0]
        assert "/ea/vpn-servers" not in called_path
        assert called_path == f"{_PROXY_BASE}/sites/{SITE_ID}/vpn/servers"

    async def test_resolves_host_and_site(self, client, registry):
        client.get.return_value = [{"id": "vpn-1"}]
        await get_vpn_server(client, registry, "myhost", "mysite", "vpn-1")
        registry.resolve_host_id.assert_called_once_with("myhost", key=None)
        registry.resolve_site_id.assert_called_once_with("mysite", HOST_ID, key=None)

    async def test_not_found(self, client, registry):
        client.get.return_value = []
        with pytest.raises(ValueError, match="vpn-missing"):
            await get_vpn_server(client, registry, "h", "s", "vpn-missing")

    async def test_not_found_lists_every_valid_server(self, client, registry):
        """An unknown id fails listing every valid name (id)."""
        rows = [{"id": "vpn-1", "name": "FirstVPN"}, {"id": "vpn-2", "name": "SecondVPN"}]
        client.get.side_effect = [rows, []]
        with pytest.raises(ValueError, match=r"valid: FirstVPN \(vpn-1\), SecondVPN \(vpn-2\)"):
            await get_vpn_server(client, registry, "h", "s", "vpn-missing")

        assert client.get.call_count == 2
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == [0, 2]
        for request in client.get.call_args_list:
            assert request.args == (f"{_PROXY_BASE}/sites/{SITE_ID}/vpn/servers",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }

    async def test_partial_drain_fails_with_that_reason_not_not_found(self, client, registry):
        """A capped/stalled drain is reported as incomplete, never as a false "not found"."""
        rows = [{"id": "vpn-1", "name": "FirstVPN"}] + [
            dict({"id": "vpn-1", "name": "FirstVPN"}, id=f"extra-{index}") for index in range(1, 2)
        ]
        client.paginate_max_pages = 2
        client.get.side_effect = [{"data": [row], "limit": 1} for row in rows]
        with pytest.raises(ValueError) as exc:
            await get_vpn_server(client, registry, "h", "s", "vpn-9")
        msg = str(exc.value)
        assert "incomplete" in msg and "page cap of 2 reached" in msg
        assert "not found" not in msg
        assert "FirstVPN (vpn-1)" in msg
        assert client.get.call_count == 2
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == list(
            range(2)
        )

    async def test_partial_drain_still_finds_a_server_it_read(self, client, registry):
        rows = [{"id": "vpn-1", "name": "FirstVPN"}] + [
            dict({"id": "vpn-1", "name": "FirstVPN"}, id=f"extra-{index}") for index in range(1, 2)
        ]
        client.paginate_max_pages = 2
        client.get.side_effect = [{"data": [row], "limit": 1} for row in rows]
        result = await get_vpn_server(client, registry, "h", "s", "vpn-1")
        assert result == {
            "id": "vpn-1",
            "name": "FirstVPN",
        }
        assert client.get.call_count == 2
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == list(
            range(2)
        )

    async def test_filters_by_id(self, client, registry):
        client.get.return_value = [
            {"id": "vpn-1", "name": "FirstVPN"},
            {"id": "vpn-2", "name": "SecondVPN"},
        ]
        result = await get_vpn_server(client, registry, "h", "s", "vpn-2")
        assert result["id"] == "vpn-2"
        assert result["name"] == "SecondVPN"


class TestCreateVpnServer:
    """create_vpn_server writes a Classic networkconf record of purpose remote-user-vpn.

    The Integration POST /vpn/servers answers HTTP 405 on Network 11.0.81; the controller
    UI creates VPN servers with POST rest/networkconf.
    """

    async def test_basic_body_and_route(self, client, registry):
        body = {"meta": {"rc": "ok"}, "data": [{"_id": "c-new", "external_id": "i-new"}]}
        client.post.return_value = body
        result = await create_vpn_server(
            client, registry, "myhost", "mysite", "CorpVPN", "wireguard"
        )
        client.post.assert_called_once_with(
            f"{CLASSIC}/networkconf",
            key=None,
            json={"purpose": "remote-user-vpn", "name": "CorpVPN", "vpn_type": "wireguard-server"},
        )
        assert result is body  # verbatim, nothing unwrapped
        registry.resolve_site_slug.assert_called_once_with("mysite", HOST_ID, key=None)

    @pytest.mark.parametrize(
        ("given", "sent"),
        [
            ("WIREGUARD", "wireguard-server"),
            ("openvpn", "openvpn-server"),
            ("L2TP", "l2tp-server"),
            ("pptp", "pptp-server"),
            ("openvpn-server", "openvpn-server"),
            ("future-server", "future-server"),
        ],
    )
    async def test_vpn_type_mapping(self, client, registry, given, sent):
        client.post.return_value = {}
        await create_vpn_server(client, registry, "h", "s", "V", given)
        assert client.post.call_args[1]["json"]["vpn_type"] == sent

    async def test_subnet_and_enabled_only_when_given(self, client, registry):
        client.post.return_value = {}
        await create_vpn_server(
            client, registry, "h", "s", "V", "openvpn", subnet="10.8.0.1/24", enabled=False
        )
        sent = client.post.call_args[1]["json"]
        assert sent["ip_subnet"] == "10.8.0.1/24"
        assert sent["enabled"] is False
        client.post.reset_mock()
        await create_vpn_server(client, registry, "h", "s", "V", "openvpn")
        assert set(client.post.call_args[1]["json"]) == {"purpose", "name", "vpn_type"}

    async def test_fields_merged_explicit_arguments_win(self, client, registry):
        client.post.return_value = {}
        await create_vpn_server(
            client,
            registry,
            "h",
            "s",
            "V",
            "wireguard",
            enabled=True,
            fields={"local_port": 51820, "name": "ignored", "enabled": False},
        )
        assert client.post.call_args[1]["json"] == {
            "local_port": 51820,
            "purpose": "remote-user-vpn",
            "name": "V",
            "vpn_type": "wireguard-server",
            "enabled": True,
        }


class TestUpdateVpnServer:
    async def test_integration_id_resolves_to_classic_id(self, client, registry):
        client.get.return_value = NETWORKCONF
        body = {"meta": {"rc": "ok"}, "data": [{"_id": "c-vpn", "enabled": False}]}
        client.put.return_value = body
        result = await update_vpn_server(client, registry, "h", "s", "i-vpn", {"enabled": False})
        client.get.assert_called_once_with(f"{CLASSIC}/networkconf", key=None)
        client.put.assert_called_once_with(
            f"{CLASSIC}/networkconf/c-vpn",
            key=None,
            json={"enabled": False, "purpose": "remote-user-vpn"},
        )
        assert result is body

    async def test_classic_id_accepted(self, client, registry):
        client.get.return_value = NETWORKCONF
        client.put.return_value = {}
        await update_vpn_server(client, registry, "h", "s", "c-vpn", {"name": "x"})
        assert client.put.call_args[0][0] == f"{CLASSIC}/networkconf/c-vpn"

    async def test_unknown_id_lists_every_vpn_server(self, client, registry):
        client.get.return_value = NETWORKCONF
        with pytest.raises(ValueError) as exc:
            await update_vpn_server(client, registry, "h", "s", "nope", {"enabled": True})
        msg = str(exc.value)
        assert "'One-Click VPN': id=i-vpn, _id=c-vpn" in msg
        assert "list_vpn_servers" in msg
        client.put.assert_not_called()

    async def test_id_of_another_purpose_is_not_a_vpn_server(self, client, registry):
        client.get.return_value = NETWORKCONF
        with pytest.raises(ValueError, match="not found"):
            await update_vpn_server(client, registry, "h", "s", "i-wan", {"enabled": True})
        client.put.assert_not_called()

    async def test_unexpected_list_shape_raises(self, client, registry):
        client.get.return_value = [{"_id": "c-vpn"}]
        with pytest.raises(UniFiConnectionError, match="expected an object with a 'data' array"):
            await update_vpn_server(client, registry, "h", "s", "i-vpn", {"enabled": True})

    async def test_body_key_named_like_a_parameter_is_sent(self, client, registry):
        client.get.return_value = NETWORKCONF
        client.put.return_value = {}
        await update_vpn_server(client, registry, "h", "s", "i-vpn", {"site": "x", "host": "y"})
        assert client.put.call_args[1]["json"] == {
            "site": "x",
            "host": "y",
            "purpose": "remote-user-vpn",
        }


class TestDeleteVpnServer:
    async def test_basic(self, client, registry):
        client.get.return_value = NETWORKCONF
        client.delete.return_value = {"meta": {"rc": "ok"}, "data": []}
        result = await delete_vpn_server(client, registry, "h", "s", "i-vpn")
        client.delete.assert_called_once_with(f"{CLASSIC}/networkconf/c-vpn", key=None)
        assert result == {
            "deleted": True,
            "message": "VPN server i-vpn deleted.",
            "response": {"meta": {"rc": "ok"}, "data": []},
        }

    async def test_never_deletes_another_kind(self, client, registry):
        client.get.return_value = NETWORKCONF
        with pytest.raises(ValueError):
            await delete_vpn_server(client, registry, "h", "s", "c-wan")
        client.delete.assert_not_called()


# --- RADIUS Profiles ---


class TestGetRadiusProfile:
    """get_radius_profile drains the working per-console proxy list and filters by ID.

    Regression guard for the path-asymmetry bug: the tool used to filter the
    Site Manager ``/ea/radius-profiles`` list (not served → route-level 404) and
    took only ``profile_id``. It now requires ``host``/``site`` because the
    profile collection is per-site on the proxy, which is the only served path.
    """

    async def test_basic(self, client, registry):
        client.get.return_value = [{"id": "rad-1", "name": "Corp RADIUS"}]
        result = await get_radius_profile(client, registry, "myhost", "mysite", "rad-1")
        assert result["id"] == "rad-1"
        assert result["name"] == "Corp RADIUS"

    async def test_uses_proxy_path_not_ea(self, client, registry):
        client.get.return_value = [{"id": "rad-1"}]
        await get_radius_profile(client, registry, "h", "s", "rad-1")
        called_path = client.get.call_args[0][0]
        assert "/ea/radius-profiles" not in called_path
        assert called_path == f"{_PROXY_BASE}/sites/{SITE_ID}/radius/profiles"

    async def test_resolves_host_and_site(self, client, registry):
        client.get.return_value = [{"id": "rad-1"}]
        await get_radius_profile(client, registry, "myhost", "mysite", "rad-1")
        registry.resolve_host_id.assert_called_once_with("myhost", key=None)
        registry.resolve_site_id.assert_called_once_with("mysite", HOST_ID, key=None)

    async def test_not_found(self, client, registry):
        client.get.return_value = []
        with pytest.raises(ValueError, match="rad-99"):
            await get_radius_profile(client, registry, "h", "s", "rad-99")

    async def test_not_found_lists_every_valid_profile(self, client, registry):
        client.get.return_value = [
            {"id": "rad-1", "name": "Profile One"},
            {"id": "rad-2", "name": "Profile Two"},
        ]
        with pytest.raises(ValueError, match=r"Profile One \(rad-1\), Profile Two \(rad-2\)"):
            await get_radius_profile(client, registry, "h", "s", "rad-99")

    async def test_partial_drain_fails_with_that_reason(self, client, registry):
        client.get.return_value = {"data": [{"id": "rad-1", "name": "One"}], "limit": 1}
        with pytest.raises(ValueError, match="incomplete.*same page again"):
            await get_radius_profile(client, registry, "h", "s", "rad-99")

    async def test_unexpected_list_shape_raises(self, client, registry, monkeypatch):
        from unifi_fabric.families.vpn import vpn

        async def _weird(*_a, **_k):
            return {"unexpected": True}

        monkeypatch.setattr(vpn, "_proxy_list_radius_profiles", _weird)
        with pytest.raises(UniFiConnectionError, match="unexpected"):
            await get_radius_profile(client, registry, "h", "s", "rad-1")

    async def test_filters_by_id(self, client, registry):
        client.get.return_value = [
            {"id": "rad-1", "name": "Profile One"},
            {"id": "rad-2", "name": "Profile Two"},
        ]
        result = await get_radius_profile(client, registry, "h", "s", "rad-2")
        assert result["id"] == "rad-2"
        assert result["name"] == "Profile Two"


_PROXY_BASE = f"/v1/connector/consoles/{HOST_ID}/proxy/network/integration/v1"


class TestCreateRadiusProfile:
    """create_radius_profile writes Classic rest/radiusprofile (Integration POST is 405)."""

    async def test_basic(self, client, registry):
        body = {"meta": {"rc": "ok"}, "data": [{"_id": "c-rad", "external_id": "i-rad"}]}
        client.post.return_value = body
        result = await create_radius_profile(
            client, registry, "myhost", "mysite", "CorpRADIUS", "192.168.1.100", 1812, "secret"
        )
        client.post.assert_called_once_with(
            f"{CLASSIC}/radiusprofile",
            key=None,
            json={
                "name": "CorpRADIUS",
                "auth_servers": [{"ip": "192.168.1.100", "port": 1812, "x_secret": "secret"}],
            },
        )
        assert result is body

    async def test_with_accounting(self, client, registry):
        client.post.return_value = {}
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
        assert client.post.call_args[1]["json"]["acct_servers"] == [
            {"ip": "10.0.0.2", "port": 1813, "x_secret": "acct-sec"}
        ]

    async def test_acct_ip_alone_invents_no_port_or_secret(self, client, registry):
        client.post.return_value = {}
        await create_radius_profile(
            client, registry, "h", "s", "R", "1.2.3.4", 1812, "s", acct_server_ip="1.2.3.5"
        )
        sent = client.post.call_args[1]["json"]
        assert sent["acct_servers"] == [{"ip": "1.2.3.5"}]
        assert "accounting_enabled" not in sent

    async def test_fields_merged_arguments_win(self, client, registry):
        client.post.return_value = {}
        await create_radius_profile(
            client,
            registry,
            "h",
            "s",
            "R",
            "1.2.3.4",
            1812,
            "s",
            fields={"accounting_enabled": True, "name": "ignored"},
        )
        sent = client.post.call_args[1]["json"]
        assert sent["accounting_enabled"] is True
        assert sent["name"] == "R"


class TestCreateSiteToSiteTunnel:
    async def test_basic(self, client, registry):
        tunnel = {"name": "Branch", "vpn_type": "openvpn-vpn", "enabled": False}
        body = {"meta": {"rc": "ok"}, "data": [{"_id": "c-new", **tunnel}]}
        client.post.return_value = body
        result = await create_site_to_site_tunnel(client, registry, "h", "s", tunnel)
        client.post.assert_called_once_with(
            f"{CLASSIC}/networkconf", key=None, json={**tunnel, "purpose": "site-vpn"}
        )
        assert result is body
        assert "purpose" not in tunnel  # the caller's dict is not mutated


class TestUpdateSiteToSiteTunnel:
    async def test_basic(self, client, registry):
        client.get.return_value = NETWORKCONF
        client.put.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "c-s2s"}]}
        result = await update_site_to_site_tunnel(
            client, registry, "h", "s", "i-s2s", {"enabled": False}
        )
        client.put.assert_called_once_with(
            f"{CLASSIC}/networkconf/c-s2s", key=None, json={"enabled": False, "purpose": "site-vpn"}
        )
        assert result == {"meta": {"rc": "ok"}, "data": [{"_id": "c-s2s"}]}

    async def test_vpn_server_id_is_not_a_tunnel(self, client, registry):
        client.get.return_value = NETWORKCONF
        with pytest.raises(ValueError, match="'Branch': id=i-s2s, _id=c-s2s"):
            await update_site_to_site_tunnel(client, registry, "h", "s", "i-vpn", {})
        client.put.assert_not_called()


class TestDeleteSiteToSiteTunnel:
    async def test_basic(self, client, registry):
        client.get.return_value = NETWORKCONF
        client.delete.return_value = None
        result = await delete_site_to_site_tunnel(client, registry, "h", "s", "c-s2s")
        client.delete.assert_called_once_with(f"{CLASSIC}/networkconf/c-s2s", key=None)
        assert result == {
            "deleted": True,
            "message": "Site-to-site VPN tunnel c-s2s deleted.",
            "response": None,
        }
