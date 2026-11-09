"""Tests for network tools — Networks/VLANs, WiFi broadcasts, WAN interfaces."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import UniFiConnectionError
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
    list_integration_device_tags,
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


def _network_body():
    """Fresh synthetic identifiers/values in the live response shape."""
    return {
        "management": "GATEWAY",
        "id": "net-1",
        "name": "LAN",
        "enabled": True,
        "vlanId": 1,
        "metadata": {"origin": "SYSTEM_DEFINED", "configurable": True},
        "isolationEnabled": False,
        "cellularBackupEnabled": True,
        "zoneId": "00000000-0000-4000-a000-000000000002",
        "internetAccessEnabled": True,
        "mdnsForwardingEnabled": False,
        "ipv4Configuration": {
            "autoScaleEnabled": False,
            "hostIpAddress": "10.0.0.24",
            "prefixLength": 24,
            "dhcpConfiguration": {
                "mode": "SERVER",
                "ipAddressRange": {"start": "10.0.0.25", "stop": "10.0.0.26"},
                "leaseTimeSeconds": 86400,
                "domainName": "domainName-0001",
                "pingConflictDetectionEnabled": True,
            },
        },
        "default": True,
    }


def _wifi_body():
    """Fresh synthetic identifiers/values in the live response shape."""
    return {
        "type": "STANDARD",
        "id": "wifi-1",
        "name": "Office",
        "metadata": {"origin": "USER_DEFINED"},
        "enabled": True,
        "securityConfiguration": {
            "type": "WPA2_PERSONAL",
            "fastRoamingEnabled": False,
            "presharedKeys": [
                {
                    "network": {
                        "type": "SPECIFIC",
                        "networkId": "00000000-0000-4000-a000-000000000007",
                    },
                    "passphrase": "placeholder-1",
                },
                {
                    "network": {
                        "type": "SPECIFIC",
                        "networkId": "00000000-0000-4000-a000-00000000000c",
                    },
                    "passphrase": "placeholder-1",
                },
            ],
            "pmfMode": "OPTIONAL",
        },
        "multicastToUnicastConversionEnabled": True,
        "clientIsolationEnabled": False,
        "hideName": False,
        "uapsdEnabled": False,
        "channel2gLockedTo6": False,
        "dtimPeriod2gLockedTo3": False,
        "broadcastingFrequenciesGHz": [2.4],
        "arpProxyEnabled": False,
        "bssTransitionEnabled": False,
        "advertiseDeviceName": False,
    }


@pytest.fixture()
def client():
    c = AsyncMock()
    c.get = AsyncMock()
    c.paginate_max_pages = None
    c.post = AsyncMock()
    c.put = AsyncMock()
    c.delete = AsyncMock()
    return c


@pytest.fixture()
def registry():
    r = AsyncMock()
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    r.resolve_key_for_host = AsyncMock(return_value=None)
    r.resolve_site_id = AsyncMock(return_value=SITE_ID)
    r.resolve_site_slug = AsyncMock(return_value=SITE_SLUG)
    return r


class TestApplicationAndSites:
    async def test_get_network_application_info(self, client, registry):
        client.get.return_value = {"applicationVersion": "10.4.57"}
        result = await get_network_application_info(client, registry, "myhost")
        client.get.assert_called_once_with(f"{BASE}/info", key=None)
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
            key=None,
        )
        assert result["offset"] == 10

    async def test_list_local_sites_rejects_negative_offset_before_any_request(
        self, client, registry
    ):
        with pytest.raises(ValueError, match=r"^offset must be 0 or more; got -1\.$"):
            await list_local_sites(client, registry, "myhost", offset=-1, limit=25)
        client.get.assert_not_called()
        registry.resolve_key_for_host.assert_not_called()

    @pytest.mark.parametrize(("offset", "limit"), [(0, 201), (0, 1000)])
    async def test_list_local_sites_forwards_manual_page_values(
        self, client, registry, offset, limit
    ):
        """An explicit offset selects one verbatim page with the caller's exact limit."""
        client.get.return_value = {
            "offset": 0,
            "limit": 25,
            "count": 0,
            "totalCount": 0,
            "data": [],
        }
        # The old min(limit, 200) assertion encoded a clamp on caller-controlled manual pages.
        result = await list_local_sites(client, registry, "myhost", offset=offset, limit=limit)
        client.get.assert_called_once_with(
            f"{BASE}/sites", key=None, params={"offset": offset, "limit": limit}
        )
        assert result == {
            **client.get.return_value,
            "_pageSize": {"requested": limit, "sent": [limit], "effective": 25, "returned": 0},
        }

    async def test_list_local_sites_upstream_paging_error_passes_through(self, client, registry):
        upstream = UniFiConnectionError(
            'HTTP 400 from GET /sites: {"code":"api.request.argument-type-mismatch",'
            '"message":"limit must be less than or equal to 200"}'
        )
        client.get.side_effect = upstream
        with pytest.raises(UniFiConnectionError) as exc:
            await list_local_sites(client, registry, "myhost", limit=201)
        assert exc.value is upstream

    async def test_list_local_sites_drains_all_by_default(self, client, registry):
        rows = [{"id": "s1"}, {"id": "s2"}]
        client.get.side_effect = [rows, []]
        result = await list_local_sites(client, registry, "myhost")
        assert all(request.args == (f"{BASE}/sites",) for request in client.get.call_args_list)
        assert client.get.call_count == 2
        assert result == {"data": [{"id": "s1"}, {"id": "s2"}], "totalCount": None}
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == [0, 2]
        for request in client.get.call_args_list:
            assert request.args == (f"{BASE}/sites",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }
        assert "incomplete" not in result
        assert "_incomplete" not in result

    async def test_list_local_sites_drains_with_filter(self, client, registry):
        client.get.return_value = []
        await list_local_sites(client, registry, "myhost", filter="name.like('lab*')")
        client.get.assert_called_once_with(
            f"{BASE}/sites",
            key=None,
            params={"filter": "name.like('lab*')", "offset": 0, "limit": 200},
        )

    async def test_list_local_sites_cap_exceeded_marked_incomplete(self, client, registry):
        rows = [{"id": "s1"}] + [dict({"id": "s1"}, id=f"extra-{index}") for index in range(1, 2)]
        client.paginate_max_pages = 2
        client.get.side_effect = [{"data": [row], "limit": 1} for row in rows]
        result = await list_local_sites(client, registry, "myhost")
        assert result["incomplete"] is True
        assert result["data"] == rows
        assert client.get.call_count == 2
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == list(
            range(2)
        )


class TestListNetworks:
    async def test_basic_drains_all_by_default(self, client, registry):
        rows = [{"id": "net-1", "name": "LAN"}]
        client.get.side_effect = [rows, []]
        result = await list_networks(client, registry, "myhost", "mysite")
        assert all(
            request.args == (f"{BASE}/sites/{SITE_ID}/networks",)
            for request in client.get.call_args_list
        )
        assert client.get.call_count == 2
        assert result == {"data": [{"id": "net-1", "name": "LAN"}], "totalCount": None}
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == [0, 1]
        for request in client.get.call_args_list:
            assert request.args == (f"{BASE}/sites/{SITE_ID}/networks",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }
        assert "incomplete" not in result
        assert "_incomplete" not in result

    async def test_manual_page_preserves_native_envelope(self, client, registry):
        envelope = {
            "data": [{"id": f"net-{index}"} for index in range(1, 26)],
            "offset": 0,
            "limit": 25,
            "count": 25,
            "totalCount": 40,
        }
        client.get.return_value = envelope
        result = await list_networks(client, registry, "h", "s", offset=0, limit=25)
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/networks", params={"offset": 0, "limit": 25}, key=None
        )
        client.paginate_offset.assert_not_called()
        assert result == {
            **envelope,
            "_pageSize": {"requested": 25, "sent": [25], "effective": 25, "returned": 25},
        }

    async def test_cap_exceeded_marked_incomplete(self, client, registry):
        rows = [{"id": "net-1"}] + [
            dict({"id": "net-1"}, id=f"extra-{index}") for index in range(1, 2)
        ]
        client.paginate_max_pages = 2
        client.get.side_effect = [{"data": [row], "limit": 1} for row in rows]
        result = await list_networks(client, registry, "h", "s")
        assert result["incomplete"] is True
        assert result["data"] == rows
        assert client.get.call_count == 2
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == list(
            range(2)
        )

    async def test_resolves_names(self, client, registry):
        client.get.return_value = []
        await list_networks(client, registry, "MyHost", "Office")
        registry.resolve_host_id.assert_called_once_with("MyHost", key=None)
        registry.resolve_site_id.assert_called_once_with("Office", HOST_ID, key=None)

    async def test_filter_drains_with_exact_param(self, client, registry):
        client.get.return_value = []
        await list_networks(client, registry, "h", "s", filter="vlanId.eq(100)")
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/networks",
            key=None,
            params={"filter": "vlanId.eq(100)", "offset": 0, "limit": 200},
        )
        client.get.assert_called_once()

    async def test_filter_manual_page_exact_param(self, client, registry):
        client.get.return_value = {"data": [], "offset": 0, "limit": 25, "totalCount": 0}
        await list_networks(client, registry, "h", "s", offset=0, limit=25, filter="vlanId.eq(100)")
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/networks",
            params={"offset": 0, "limit": 25, "filter": "vlanId.eq(100)"},
            key=None,
        )
        client.paginate_offset.assert_not_called()

    async def test_filter_none_omits_param_on_drain(self, client, registry):
        client.get.return_value = []
        await list_networks(client, registry, "h", "s", filter=None)
        _, kwargs = client.get.call_args
        assert kwargs["params"] == {"offset": 0, "limit": 200}

    async def test_filter_threads_owning_key(self, client, registry):
        sentinel = object()
        registry.resolve_key_for_host.return_value = sentinel
        client.get.return_value = []
        await list_networks(client, registry, "h", "s", filter="name.like('*guest*')")
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/networks",
            key=sentinel,
            params={"filter": "name.like('*guest*')", "offset": 0, "limit": 200},
        )


class TestCreateNetwork:
    async def test_basic(self, client, registry):
        # 'management' is the discriminator the controller validates first
        # (Missing $.management); the tool validates it before the request.
        payload = {"management": "GATEWAY", "name": "Guest", "vlanId": 100}
        client.post.return_value = {"id": "net-2", **payload}
        result = await create_network(client, registry, "h", "s", payload)
        client.post.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/networks", json=payload, key=None
        )
        assert result["name"] == "Guest"

    async def test_missing_management_rejected(self, client, registry):
        with pytest.raises(ValueError) as exc:
            await create_network(client, registry, "h", "s", {"name": "Guest"})
        assert str(exc.value) == "create_network requires: management"
        client.post.assert_not_called()


class TestGetNetwork:
    async def test_basic(self, client, registry):
        client.get.return_value = _network_body()
        result = await get_network(client, registry, "h", "s", "net-1")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/networks/net-1", key=None)
        assert result["id"] == "net-1"


class TestUpdateNetwork:
    async def test_basic(self, client, registry):
        payload = {"name": "Updated"}
        client.put.return_value = {"id": "net-1", **payload}
        result = await update_network(client, registry, "h", "s", "net-1", payload)
        client.put.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/networks/net-1", json=payload, key=None
        )
        assert result["name"] == "Updated"

    async def test_strips_read_only_fields(self, client, registry):
        """Read-only fields from get_network output are stripped before PUT."""
        payload = {"id": "net-1", "name": "Updated", "default": True, "metadata": {"x": 1}}
        client.put.return_value = {"id": "net-1", "name": "Updated"}
        result = await update_network(client, registry, "h", "s", "net-1", payload)
        # Only the non-read-only field should be sent
        client.put.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/networks/net-1", json={"name": "Updated"}, key=None
        )
        assert result["name"] == "Updated"

    async def test_passes_through_writable_fields(self, client, registry):
        """Fields not in the read-only set pass through unchanged."""
        payload = {"management": "GATEWAY", "name": "Guest", "vlanId": 100}
        client.put.return_value = {"id": "net-1", **payload}
        result = await update_network(client, registry, "h", "s", "net-1", payload)
        client.put.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/networks/net-1", json=payload, key=None
        )
        assert result["vlanId"] == 100

    @pytest.mark.parametrize(
        "servers,expected",
        [
            (["192.0.2.1", "", ""], ["192.0.2.1"]),
            (["192.0.2.1", "", "192.0.2.2", ""], ["192.0.2.1", "192.0.2.2"]),
            (["", "", ""], []),
        ],
    )
    async def test_dns_servers_preserve_order(self, client, registry, servers, expected):
        # Synthetic padding cases; DNS is absent in the captured live response.
        # Nesting comes from the pinned spec: IPv4 DHCP Server Configuration.
        payload = _network_body()
        dhcp = payload["ipv4Configuration"]["dhcpConfiguration"]
        dhcp["dnsServerIpAddressesOverride"] = servers
        client.put.return_value = {"id": "net-1"}
        await update_network(client, registry, "h", "s", "net-1", payload)
        sent = client.put.call_args.kwargs["json"]
        assert (
            sent["ipv4Configuration"]["dhcpConfiguration"]["dnsServerIpAddressesOverride"]
            == expected
        )
        assert dhcp["dnsServerIpAddressesOverride"] == servers  # caller body untouched

    async def test_get_network_response_round_trips_clean(self, client, registry):
        """The sanitized live GET body preserves its nested IPv4 configuration."""
        get_response = _network_body()
        client.get.return_value = get_response
        response = await get_network(client, registry, "h", "s", "net-1")
        client.put.return_value = {"id": "net-1"}
        await update_network(client, registry, "h", "s", "net-1", response)
        expected = {k: v for k, v in get_response.items() if k not in {"id", "default", "metadata"}}
        client.put.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/networks/net-1",
            json=expected,
            key=None,
        )
        assert expected["vlanId"] == 1
        assert expected["ipv4Configuration"]["dhcpConfiguration"]["mode"] == "SERVER"


class TestDeleteNetwork:
    async def test_basic(self, client, registry):
        await delete_network(client, registry, "h", "s", "net-1")
        client.delete.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/networks/net-1", key=None, params=None
        )

    @pytest.mark.parametrize(("force", "query"), [(True, "true"), (False, "false")])
    async def test_force_is_sent_only_when_given(self, client, registry, force, query):
        await delete_network(client, registry, "h", "s", "net-1", force=force)
        assert client.delete.call_args.kwargs["params"] == {"force": query}


class TestListWifiBroadcasts:
    async def test_basic_drains_all_pages(self, client, registry):
        rows = [{"id": "wifi-1", "name": "Office"}]
        client.get.side_effect = [rows, []]
        result = await list_wifi_broadcasts(client, registry, "h", "s")
        assert client.get.call_args.args[0] == f"{BASE}/sites/{SITE_ID}/wifi/broadcasts"
        # An omitted filter contributes no filter key to the paging controls.
        assert client.get.call_args_list[0].kwargs["params"] == {"offset": 0, "limit": 200}
        assert result == {"data": [{"id": "wifi-1", "name": "Office"}], "totalCount": None}

        assert client.get.call_count == 2
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == [0, 1]
        for request in client.get.call_args_list:
            assert request.args == (f"{BASE}/sites/{SITE_ID}/wifi/broadcasts",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }
        assert "incomplete" not in result
        assert "_incomplete" not in result

    async def test_filter_forwarded_verbatim(self, client, registry):
        rows = [{"id": "wifi-1"}]
        client.get.side_effect = [rows, []]
        result = await list_wifi_broadcasts(client, registry, "h", "s", filter="enabled.eq(true)")
        assert [request.kwargs["params"] for request in client.get.call_args_list] == [
            {"filter": "enabled.eq(true)", "offset": offset, "limit": 200} for offset in (0, 1)
        ]

        assert client.get.call_count == 2
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == [0, 1]
        for request in client.get.call_args_list:
            assert request.args == (f"{BASE}/sites/{SITE_ID}/wifi/broadcasts",)
            assert request.kwargs == {
                "key": None,
                "params": {
                    "offset": request.kwargs["params"]["offset"],
                    "limit": 200,
                    "filter": "enabled.eq(true)",
                },
            }
        assert result["data"] == rows
        assert result["totalCount"] is None
        assert "incomplete" not in result
        assert "_incomplete" not in result

    async def test_filter_threads_owning_key(self, client, registry):
        sentinel = object()
        registry.resolve_key_for_host.return_value = sentinel
        client.get.return_value = []
        await list_wifi_broadcasts(client, registry, "h", "s", filter="name.like('*Guest*')")
        assert client.get.call_args.kwargs["key"] is sentinel


class TestCreateWifiBroadcast:
    async def test_basic(self, client, registry):
        # 'type' is the discriminator the controller validates first (Missing $.type).
        payload = {
            "type": "STANDARD",
            "name": "Guest WiFi",
            "enabled": True,
            "network": {"type": "NATIVE"},
            "securityConfiguration": {"type": "OPEN"},
            "broadcastingFrequenciesGHz": [2.4, 5],
        }
        client.post.return_value = {"id": "wifi-2", **payload}
        result = await create_wifi_broadcast(client, registry, "h", "s", payload)
        client.post.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/wifi/broadcasts", json=payload, key=None
        )
        assert result["name"] == "Guest WiFi"
        assert result["broadcastingFrequenciesGHz"] == [2.4, 5]
        assert result["securityConfiguration"]["type"] == "OPEN"

    async def test_missing_type_rejected(self, client, registry):
        with pytest.raises(ValueError) as exc:
            await create_wifi_broadcast(client, registry, "h", "s", {"name": "Guest WiFi"})
        assert str(exc.value) == "create_wifi_broadcast requires: type"
        client.post.assert_not_called()

    async def test_ap_ssid_limit_refusal_keeps_whole_body_and_adds_scoping_hint(
        self, client, registry
    ):
        """Live 2026-10-28 (Network 11.0.89): an access point at its SSID maximum answers
        HTTP 400 too-many-wifi-broadcasts. The error is kept whole with a hint."""
        upstream = (
            "HTTP 400 from POST /v1/connector/consoles/host-001/proxy/network/integration/v1/"
            'sites/s/wifi/broadcasts: {"statusCode":400,"statusName":"BAD_REQUEST",'
            '"code":"api.wifi-broadcast.validation.too-many-wifi-broadcasts",'
            '"message":"too many WiFi broadcasts assigned to the device with id=dev-1"}'
        )
        client.post.side_effect = UniFiConnectionError(upstream, request_sent=True, status=400)
        with pytest.raises(UniFiConnectionError) as exc:
            await create_wifi_broadcast(client, registry, "h", "s", {"type": "STANDARD"})
        assert str(exc.value).startswith(upstream)
        assert "broadcastingDeviceFilter" in str(exc.value)
        # Live 2026-11-08 (Network 11.0.97): an SSID created disabled was refused the same way.
        assert "enabled: false" in str(exc.value)
        assert exc.value.status == 400 and exc.value.request_sent is True
        assert client.post.await_count == 1

    async def test_other_400_gets_no_scoping_hint(self, client, registry):
        client.post.side_effect = UniFiConnectionError(
            'HTTP 400 from POST /x: {"code":"api.wifi-broadcast.validation.name"}',
            request_sent=True,
            status=400,
        )
        with pytest.raises(UniFiConnectionError) as exc:
            await create_wifi_broadcast(client, registry, "h", "s", {"type": "STANDARD"})
        assert "broadcastingDeviceFilter" not in str(exc.value)


class TestGetWifiBroadcast:
    async def test_basic(self, client, registry):
        client.get.return_value = _wifi_body()
        result = await get_wifi_broadcast(client, registry, "h", "s", "wifi-1")
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/wifi/broadcasts/wifi-1", key=None
        )
        assert result["id"] == "wifi-1"


class TestUpdateWifiBroadcast:
    async def test_basic(self, client, registry):
        payload = {"name": "Updated SSID"}
        client.put.return_value = {"id": "wifi-1", **payload}
        result = await update_wifi_broadcast(client, registry, "h", "s", "wifi-1", payload)
        client.put.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/wifi/broadcasts/wifi-1", json=payload, key=None
        )
        assert result["name"] == "Updated SSID"

    async def test_strips_empty_strings_from_list_fields(self, client, registry):
        # Explicitly synthetic padding added to the live numeric-band shape.
        payload = _wifi_body()
        payload["broadcastingFrequenciesGHz"] = [2.4, "", 5, "", 6]
        client.put.return_value = {"id": "wifi-1"}
        await update_wifi_broadcast(client, registry, "h", "s", "wifi-1", payload)
        sent = client.put.call_args.kwargs["json"]
        assert sent["broadcastingFrequenciesGHz"] == [2.4, 5, 6]
        assert sent["securityConfiguration"] == payload["securityConfiguration"]
        assert payload["broadcastingFrequenciesGHz"] == [2.4, "", 5, "", 6]

    async def test_get_wifi_response_round_trips_clean(self, client, registry):
        payload = _wifi_body()
        client.get.return_value = payload
        response = await get_wifi_broadcast(client, registry, "h", "s", "wifi-1")
        client.put.return_value = {"id": "wifi-1"}
        await update_wifi_broadcast(client, registry, "h", "s", "wifi-1", response)
        expected = {k: v for k, v in payload.items() if k not in {"id", "metadata"}}
        client.put.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/wifi/broadcasts/wifi-1",
            json=expected,
            key=None,
        )
        assert (
            expected["securityConfiguration"]["presharedKeys"][0]["passphrase"] == "placeholder-1"
        )


class TestDeleteWifiBroadcast:
    async def test_basic(self, client, registry):
        await delete_wifi_broadcast(client, registry, "h", "s", "wifi-1")
        client.delete.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/wifi/broadcasts/wifi-1", key=None, params=None
        )

    @pytest.mark.parametrize(("force", "query"), [(True, "true"), (False, "false")])
    async def test_force_is_sent_only_when_given(self, client, registry, force, query):
        await delete_wifi_broadcast(client, registry, "h", "s", "wifi-1", force=force)
        assert client.delete.call_args.kwargs["params"] == {"force": query}


class TestListWanInterfaces:
    """Pass-through contract: the upstream bodies verbatim, derived views under ``_`` keys,
    nothing filtered out of an upstream body."""

    async def test_basic(self, client, registry):
        wan_data = [{"id": "wan-1", "name": "WAN1"}]
        health = {"data": [{"subsystem": "wan", "status": "ok", "speedtest-status": {}}]}
        client.get.side_effect = [wan_data, [], health]
        result = await list_wan_interfaces(client, registry, "h", "s")
        assert client.get.call_args_list[0].args[0] == f"{BASE}/sites/{SITE_ID}/wans"
        assert client.get.call_args_list[2][0][0] == f"{STAT_BASE}/health"
        assert client.get.call_args_list[0].kwargs == {
            "key": None,
            "params": {"offset": 0, "limit": 200},
        }
        assert result["data"] == wan_data
        # the drain's upstream total is carried (None here: the mock reports none)
        assert "totalCount" in result and result["totalCount"] is None
        assert result["_health"] == health
        # no invented non-underscore key
        assert set(result) == {"data", "totalCount", "_health"}

        assert client.get.call_count == 3
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list[0:2]] == [
            0,
            1,
        ]
        for request in client.get.call_args_list[0:2]:
            assert request.args == (f"{BASE}/sites/{SITE_ID}/wans",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }
        assert client.get.call_args_list[2].args == (f"{STAT_BASE}/health",)
        assert result["data"] == wan_data
        assert result["totalCount"] is None
        assert "incomplete" not in result
        assert "_incomplete" not in result

    async def test_health_body_verbatim_every_subsystem(self, client, registry):
        health = {
            "meta": {"rc": "ok"},
            "data": [{"subsystem": "wlan"}, {"subsystem": "wan", "wan_ip": "192.0.2.1"}],
        }
        client.get.side_effect = [[{"id": "wan-1"}], [], health]
        result = await list_wan_interfaces(client, registry, "h", "s")
        # every subsystem kept: nothing is filtered out of the upstream body
        assert result["_health"] == health

        assert client.get.call_count == 3
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list[0:2]] == [
            0,
            1,
        ]
        for request in client.get.call_args_list[0:2]:
            assert request.args == (f"{BASE}/sites/{SITE_ID}/wans",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }
        assert client.get.call_args_list[2].args == (f"{STAT_BASE}/health",)
        assert result["data"] == [{"id": "wan-1"}]
        assert result["totalCount"] is None
        assert "incomplete" not in result
        assert "_incomplete" not in result

    async def test_unexpected_health_shape_is_reported_not_emptied(self, client, registry):
        client.get.side_effect = [[{"id": "wan-1"}], [], {"unexpected": True}]
        result = await list_wan_interfaces(client, registry, "h", "s")
        assert result["_health"] == {"unexpected": True}  # the body received, verbatim
        assert "unexpected" in result["_wanHealthError"]

        assert client.get.call_count == 3
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list[0:2]] == [
            0,
            1,
        ]
        for request in client.get.call_args_list[0:2]:
            assert request.args == (f"{BASE}/sites/{SITE_ID}/wans",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }
        assert client.get.call_args_list[2].args == (f"{STAT_BASE}/health",)
        assert result["data"] == [{"id": "wan-1"}]
        assert result["totalCount"] is None
        assert "incomplete" not in result
        assert "_incomplete" not in result

    async def test_health_failure_still_returns_wans(self, client, registry):
        wan_data = [{"id": "wan-1", "name": "WAN1"}]
        client.get.side_effect = [wan_data, [], Exception("health unreachable")]
        result = await list_wan_interfaces(client, registry, "h", "s")
        assert result["data"] == wan_data
        assert "_health" not in result  # no body was received
        assert result["_wanHealthError"] == "Exception: health unreachable"

        assert client.get.call_count == 3
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list[0:2]] == [
            0,
            1,
        ]
        for request in client.get.call_args_list[0:2]:
            assert request.args == (f"{BASE}/sites/{SITE_ID}/wans",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }
        assert client.get.call_args_list[2].args == (f"{STAT_BASE}/health",)
        assert result["data"] == wan_data
        assert result["totalCount"] is None
        assert "incomplete" not in result
        assert "_incomplete" not in result

    async def test_no_health_error_key_on_success(self, client, registry):
        client.get.side_effect = [[{"id": "wan-1"}], [], {"data": []}]
        result = await list_wan_interfaces(client, registry, "h", "s")
        assert "_wanHealthError" not in result

        assert client.get.call_count == 3
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list[0:2]] == [
            0,
            1,
        ]
        for request in client.get.call_args_list[0:2]:
            assert request.args == (f"{BASE}/sites/{SITE_ID}/wans",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }
        assert client.get.call_args_list[2].args == (f"{STAT_BASE}/health",)
        assert result["data"] == [{"id": "wan-1"}]
        assert result["totalCount"] is None
        assert "incomplete" not in result
        assert "_incomplete" not in result

    async def test_resolves_names(self, client, registry):
        client.get.side_effect = [[], {"data": []}]
        await list_wan_interfaces(client, registry, "UDM-Pro", "Main Office")
        registry.resolve_host_id.assert_called_once_with("UDM-Pro", key=None)
        registry.resolve_site_id.assert_called_once_with("Main Office", HOST_ID, key=None)


WAN_NETWORKCONF = {
    "meta": {"rc": "ok"},
    "data": [
        {"_id": "c-wan1", "external_id": "i-wan1", "name": "Fiber", "purpose": "wan"},
        {"_id": "c-vpn", "external_id": "i-vpn", "name": "VPN", "purpose": "remote-user-vpn"},
    ],
}
CLASSIC_NC = f"/v1/connector/consoles/{HOST_ID}/proxy/network/api/s/{SITE_SLUG}/rest/networkconf"


class TestUpdateWanInterface:
    """update_wan_interface writes the Classic networkconf record of purpose wan.

    The Integration PUT /wans/{id} answers 404 "No endpoint" on Network 11.0.81.
    """

    async def test_basic(self, client, registry):
        client.get.return_value = WAN_NETWORKCONF
        wan = {"wan_load_balance_weight": 60}
        body = {"meta": {"rc": "ok"}, "data": [{"_id": "c-wan1", **wan}]}
        client.put.return_value = body
        result = await update_wan_interface(client, registry, "h", "s", "i-wan1", wan)
        client.get.assert_called_once_with(CLASSIC_NC, key=None)
        client.put.assert_called_once_with(
            f"{CLASSIC_NC}/c-wan1", json={**wan, "purpose": "wan"}, key=None
        )
        assert result is body

    async def test_resolves_names(self, client, registry):
        client.get.return_value = WAN_NETWORKCONF
        client.put.return_value = {}
        await update_wan_interface(client, registry, "UDM-Pro", "Main Office", "c-wan1", {})
        registry.resolve_host_id.assert_called_once_with("UDM-Pro", key=None)
        registry.resolve_site_slug.assert_called_once_with("Main Office", HOST_ID, key=None)

    async def test_strips_empty_strings_from_lists(self, client, registry):
        """Padded list fields are cleaned before the PUT."""
        client.get.return_value = WAN_NETWORKCONF
        client.put.return_value = {}
        await update_wan_interface(
            client, registry, "h", "s", "i-wan1", {"wan_dns": ["8.8.8.8", "", ""]}
        )
        assert client.put.call_args.kwargs["json"] == {"wan_dns": ["8.8.8.8"], "purpose": "wan"}

    async def test_non_wan_id_lists_every_wan(self, client, registry):
        client.get.return_value = WAN_NETWORKCONF
        with pytest.raises(ValueError, match="'Fiber': id=i-wan1, _id=c-wan1"):
            await update_wan_interface(client, registry, "h", "s", "i-vpn", {"name": "x"})
        client.put.assert_not_called()


class TestGetNetworkReferences:
    async def test_basic(self, client, registry):
        client.get.return_value = {"data": [{"type": "wifi_broadcast", "id": "wifi-1"}]}
        result = await get_network_references(client, registry, "h", "s", "net-1")
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/networks/net-1/references", key=None
        )
        assert result["data"][0]["type"] == "wifi_broadcast"

    async def test_resolves_names(self, client, registry):
        client.get.return_value = {}
        await get_network_references(client, registry, "UDM-Pro", "Main Office", "net-1")
        registry.resolve_host_id.assert_called_once_with("UDM-Pro", key=None)
        registry.resolve_site_id.assert_called_once_with("Main Office", HOST_ID, key=None)


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
        key=None,
    )
    assert result["data"] == []


@pytest.mark.parametrize("function", [list_lags, list_mc_lag_domains, list_switch_stacks])
async def test_list_switching_resource_clamps_limit_to_200(function, client, registry):
    client.get.return_value = {"offset": 0, "limit": 201, "count": 0, "totalCount": 0, "data": []}
    await function(client, registry, "myhost", "mysite", limit=201)
    # The old offset=0 assertion encoded an invented control for a limit-only request.
    assert client.get.call_args.kwargs["params"] == {"limit": 200}  # Upstream starts at zero.


@pytest.mark.parametrize(
    ("function", "resource"),
    [
        (list_lags, "lags"),
        (list_mc_lag_domains, "mc-lag-domains"),
        (list_switch_stacks, "switch-stacks"),
    ],
)
async def test_list_switching_resource_drains_all_by_default(function, resource, client, registry):
    rows = [{"id": "r1"}, {"id": "r2"}]
    client.get.side_effect = [rows, []]
    result = await function(client, registry, "myhost", "mysite")
    assert all(
        request.args == (f"{BASE}/sites/{SITE_ID}/switching/{resource}",)
        for request in client.get.call_args_list
    )
    assert client.get.call_count == 2
    assert result == {"data": [{"id": "r1"}, {"id": "r2"}], "totalCount": None}
    assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == [0, 2]
    for request in client.get.call_args_list:
        assert request.args == (f"{BASE}/sites/{SITE_ID}/switching/{resource}",)
        assert request.kwargs == {
            "key": None,
            "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
        }
    assert "incomplete" not in result
    assert "_incomplete" not in result


@pytest.mark.parametrize("function", [list_lags, list_mc_lag_domains, list_switch_stacks])
async def test_list_switching_resource_cap_exceeded_marked_incomplete(function, client, registry):
    rows = [{"id": "r1"}] + [dict({"id": "r1"}, id=f"extra-{index}") for index in range(1, 2)]
    client.paginate_max_pages = 2
    client.get.side_effect = [{"data": [row], "limit": 1} for row in rows]
    result = await function(client, registry, "myhost", "mysite")
    assert result["incomplete"] is True
    assert result["data"] == rows
    assert client.get.call_count == 2
    assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == list(range(2))


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
    client.get.assert_called_once_with(
        f"{BASE}/sites/{SITE_ID}/switching/{resource}/{RESOURCE_ID}", key=None
    )
    assert result["id"] == RESOURCE_ID


@pytest.mark.parametrize("function", [get_lag, get_mc_lag_domain, get_switch_stack])
async def test_get_switching_resource_rejects_unsafe_id(function, client, registry):
    with pytest.raises(ValueError, match="Invalid"):
        await function(client, registry, "myhost", "mysite", "../unsafe")
    client.get.assert_not_called()


class TestCreateNetworkSpecKeys:
    """The Network 11.0.97 spec key is ``ipv4Configuration`` (lower-case v)."""

    async def test_ipv4_configuration_forwarded_verbatim(self, client, registry):
        payload = {
            "management": "GATEWAY",
            "name": "IoT",
            "vlanId": 30,
            "enabled": True,
            "internetAccessEnabled": True,
            "isolationEnabled": False,
            "cellularBackupEnabled": False,
            "ipv4Configuration": {"hostIpAddress": "192.0.2.1", "prefixLength": 24},
        }
        client.post.return_value = {"id": "net-3"}
        await create_network(client, registry, "h", "s", payload)
        sent = client.post.call_args.kwargs["json"]
        assert sent == payload
        assert "ipv4Configuration" in sent and "ipV4Configuration" not in sent

    def test_tool_docstring_uses_spec_key(self):
        from unifi_fabric import server

        doc = server.create_network.__doc__ or ""
        assert "ipv4Configuration" in doc
        assert "ipV4Configuration:" not in doc
        assert "'dhcpMode'" not in doc


class TestListIntegrationDeviceTags:
    async def test_drain_and_filter(self, client, registry):
        rows = [{"id": "tag-1", "name": "APs", "extra": {"unchanged": True}}]
        client.get.side_effect = [rows, []]
        result = await list_integration_device_tags(
            client, registry, "h", "s", filter="name.eq('APs')"
        )
        assert result["data"] == rows
        assert [c.args[0] for c in client.get.call_args_list] == [
            f"{BASE}/sites/{SITE_ID}/device-tags",
            f"{BASE}/sites/{SITE_ID}/device-tags",
        ]
        assert [c.kwargs["params"] for c in client.get.call_args_list] == [
            {"filter": "name.eq('APs')", "offset": n, "limit": 200} for n in (0, 1)
        ]

    async def test_manual_page_passes_body_through(self, client, registry):
        body = {"data": [{"name": "APs", "unknown": 42}], "totalCount": 8, "other": "keep"}
        client.get.return_value = body
        assert await list_integration_device_tags(client, registry, "h", "s", offset=3) == body

    @pytest.mark.parametrize("resolver", ["resolve_key_for_host", "resolve_site_id"])
    async def test_unknown_selector_stops_before_collection_request(
        self, client, registry, resolver
    ):
        getattr(registry, resolver).side_effect = ValueError(
            "Unknown selector; valid choices: example"
        )
        with pytest.raises(ValueError, match="valid choices"):
            await list_integration_device_tags(client, registry, "h", "s")
        client.get.assert_not_called()
