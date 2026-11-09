"""Tests for network_services_proxy — DNS, traffic lists, VPN, RADIUS, hotspot."""

from __future__ import annotations

import copy
import json
from typing import Any
from unittest.mock import AsyncMock, call

import httpx
import pytest

from tests import tool_args
from tests import upstream_harness as uh
from tests.conftest import MULTIKEY_HOSTS_BY_LABEL
from unifi_fabric import server
from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.tools.network import PROXY_BASE
from unifi_fabric.tools.network_services_proxy import (
    _CLASSIC_REST_BASE,
    _CLASSIC_STAT_BASE,
    _V2_API_BASE,
    allow_network_on_port_profile,
    annotate_auto_exclusions,
    bulk_delete_hotspot_vouchers,
    create_dns_policy,
    create_firewall_rule,
    create_hotspot_vouchers,
    create_port_forward,
    create_traffic_matching_list,
    create_traffic_route,
    create_traffic_rule,
    delete_dns_policy,
    delete_hotspot_voucher,
    delete_port_forward,
    delete_traffic_matching_list,
    delete_traffic_route,
    delete_traffic_rule,
    exclude_network_on_port_profile,
    get_account,
    get_channel_plan,
    get_dns_policy,
    get_dynamic_dns,
    get_firewall_group,
    get_firewall_rule,
    get_hotspot_package,
    get_hotspot_voucher,
    get_port_profile,
    get_scheduled_task,
    get_setting,
    get_traffic_matching_list,
    get_traffic_route,
    get_user,
    get_wlan_config,
    get_wlan_group,
    list_accounts,
    list_countries,
    list_device_tags,
    list_dns_policies,
    list_dpi_applications,
    list_dpi_categories,
    list_dynamic_dns,
    list_firewall_groups,
    list_firewall_rules,
    list_hotspot_packages,
    list_hotspot_vouchers,
    list_port_forwards,
    list_port_profiles,
    list_radius_profiles,
    list_rogue_aps,
    list_routing_entries,
    list_scheduled_tasks,
    list_settings,
    list_site_to_site_tunnels,
    list_traffic_matching_lists,
    list_traffic_routes,
    list_traffic_rules,
    list_users,
    list_vpn_servers,
    list_wlan_configs,
    list_wlan_groups,
    update_dns_policy,
    update_dynamic_dns,
    update_port_forward,
    update_port_profile,
    update_setting,
    update_traffic_matching_list,
    update_traffic_route,
    update_traffic_rule,
    update_user,
    update_wlan_config,
)

HOST_ID = "host-001"
SITE_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
SITE_SLUG = "default"
BASE = PROXY_BASE.format(host_id=HOST_ID)
CLASSIC_REST_BASE = _CLASSIC_REST_BASE.format(host_id=HOST_ID, site_slug=SITE_SLUG)
CLASSIC_STAT_BASE = _CLASSIC_STAT_BASE.format(host_id=HOST_ID, site_slug=SITE_SLUG)
V2_API_BASE = _V2_API_BASE.format(host_id=HOST_ID, site_slug=SITE_SLUG)


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
    r.resolve_key_for_host = AsyncMock(return_value=None)
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    r.resolve_site_id = AsyncMock(return_value=SITE_ID)
    r.resolve_ea_site_id = AsyncMock(return_value="000000000000000000000123")
    r.resolve_site_slug = AsyncMock(return_value=SITE_SLUG)
    return r


# --- DNS Policies ---


class TestListDnsPolicies:
    async def test_basic_drains_all_by_default(self, client, registry):
        rows = [{"id": "dns-1", "name": "Default"}]
        client.get.side_effect = [rows, []]
        result = await list_dns_policies(client, registry, "h", "s")
        assert client.get.call_args[0][0] == f"{BASE}/sites/{SITE_ID}/dns/policies"
        assert client.get.call_count == 2
        assert result == {"data": [{"id": "dns-1", "name": "Default"}], "totalCount": None}

        assert client.get.call_count == 2
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == [0, 1]
        for request in client.get.call_args_list:
            assert request.args == (f"{BASE}/sites/{SITE_ID}/dns/policies",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }
        assert result["data"] == rows
        assert result["totalCount"] is None
        assert "incomplete" not in result
        assert "_incomplete" not in result

    async def test_requested_limit_drains_console_clamped_pages(self, client, registry):
        # The old offset+limit batching assertion encoded extra requests for a manual page.
        # Limit alone keeps the original exact five-record drain and each request's size.
        rows = [{"id": f"dns-{index}"} for index in range(1, 6)]

        async def get(path, *, key=None, params):
            offset = params.get("offset", 0)
            size = min(params["limit"], 2)
            return {"data": rows[offset : offset + size], "limit": size, "totalCount": 5}

        client.get.side_effect = get
        result = await list_dns_policies(client, registry, "h", "s", limit=25)
        assert client.get.await_args_list == [
            call(f"{BASE}/sites/{SITE_ID}/dns/policies", key=None, params=params)
            for params in ({"limit": 25}, {"offset": 2, "limit": 2}, {"offset": 4, "limit": 2})
        ]
        client.paginate_offset.assert_not_called()
        assert result == {
            "data": rows,
            "totalCount": 5,
            "_pageSize": {"requested": 25, "sent": [25, 2, 2], "effective": 2, "returned": 5},
        }
        client.get.reset_mock()
        manual_page = await list_dns_policies(client, registry, "h", "s", offset=0, limit=25)
        client.get.assert_awaited_once_with(
            f"{BASE}/sites/{SITE_ID}/dns/policies", key=None, params={"offset": 0, "limit": 25}
        )
        assert manual_page == {
            "data": rows[:2],
            "limit": 2,
            "totalCount": 5,
            "_pageSize": {"requested": 25, "sent": [25], "effective": 2, "returned": 2},
        }


class TestCreateDnsPolicy:
    async def test_basic(self, client, registry):
        # 'type' is the discriminator the controller validates first (Missing $.type).
        payload = {"type": "ALLOW", "name": "Custom DNS"}
        client.post.return_value = {"id": "dns-2", **payload}
        result = await create_dns_policy(client, registry, "h", "s", payload)
        client.post.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/dns/policies", key=None, json=payload
        )
        assert result["name"] == "Custom DNS"

    async def test_missing_type_rejected(self, client, registry):
        with pytest.raises(ValueError) as exc:
            await create_dns_policy(client, registry, "h", "s", {"name": "Custom DNS"})
        assert str(exc.value) == "create_dns_policy requires: type"
        client.post.assert_not_called()


class TestGetDnsPolicy:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "dns-1", "name": "Default"}
        result = await get_dns_policy(client, registry, "h", "s", "dns-1")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/dns/policies/dns-1", key=None)
        assert result["id"] == "dns-1"

    async def test_rejects_path_injection_id(self, client, registry):
        with pytest.raises(ValueError, match="policy_id"):
            await get_dns_policy(client, registry, "h", "s", "../etc")
        registry.resolve_host_id.assert_not_called()
        client.get.assert_not_called()


class TestUpdateDnsPolicy:
    async def test_basic(self, client, registry):
        payload = {"name": "Updated"}
        client.put.return_value = {"id": "dns-1", **payload}
        result = await update_dns_policy(client, registry, "h", "s", "dns-1", payload)
        client.put.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/dns/policies/dns-1", key=None, json=payload
        )
        assert result["name"] == "Updated"

    async def test_rejects_path_injection_id(self, client, registry):
        with pytest.raises(ValueError, match="policy_id"):
            await update_dns_policy(client, registry, "h", "s", "../etc", {"name": "Updated"})
        registry.resolve_host_id.assert_not_called()
        client.put.assert_not_called()

    async def test_strips_empty_strings_from_list_fields(self, client, registry):
        """Padded list fields in a DNS policy object are cleaned
        before the PUT so a read-modify-write round-trip does not 400."""
        payload = {"name": "P1", "domains": ["example.com", "", ""]}
        client.put.return_value = {"id": "dns-1"}
        await update_dns_policy(client, registry, "h", "s", "dns-1", payload)
        client.put.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/dns/policies/dns-1",
            key=None,
            json={"name": "P1", "domains": ["example.com"]},
        )


class TestDeleteDnsPolicy:
    async def test_basic(self, client, registry):
        await delete_dns_policy(client, registry, "h", "s", "dns-1")
        client.delete.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/dns/policies/dns-1", key=None
        )

    async def test_rejects_path_injection_id(self, client, registry):
        with pytest.raises(ValueError, match="policy_id"):
            await delete_dns_policy(client, registry, "h", "s", "../etc")
        registry.resolve_host_id.assert_not_called()
        client.delete.assert_not_called()


# --- Traffic Matching Lists ---


class TestListTrafficMatchingLists:
    async def test_basic(self, client, registry):
        rows = [{"id": "tml-1", "name": "IoT Devices"}]
        client.get.side_effect = [rows, []]
        result = await list_traffic_matching_lists(client, registry, "h", "s")
        assert client.get.call_args.args[0] == f"{BASE}/sites/{SITE_ID}/traffic-matching-lists"
        assert result == {"data": [{"id": "tml-1", "name": "IoT Devices"}], "totalCount": None}

        assert client.get.call_count == 2
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == [0, 1]
        for request in client.get.call_args_list:
            assert request.args == (f"{BASE}/sites/{SITE_ID}/traffic-matching-lists",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }
        assert result["data"] == rows
        assert result["totalCount"] is None
        assert "incomplete" not in result
        assert "_incomplete" not in result


class TestCreateTrafficMatchingList:
    async def test_basic(self, client, registry):
        # Top-level 'type' is the discriminator (Missing $.type); observed value PORTS.
        payload = {"type": "PORTS", "name": "Gaming"}
        client.post.return_value = {"id": "tml-2", **payload}
        result = await create_traffic_matching_list(client, registry, "h", "s", payload)
        client.post.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/traffic-matching-lists", key=None, json=payload
        )
        assert result["name"] == "Gaming"

    async def test_missing_type_rejected(self, client, registry):
        with pytest.raises(ValueError) as exc:
            await create_traffic_matching_list(client, registry, "h", "s", {"name": "Gaming"})
        assert str(exc.value) == "create_traffic_matching_list requires: type"
        client.post.assert_not_called()


class TestGetTrafficMatchingList:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "tml-1", "name": "IoT Devices"}
        result = await get_traffic_matching_list(client, registry, "h", "s", "tml-1")
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/traffic-matching-lists/tml-1", key=None
        )
        assert result["id"] == "tml-1"

    async def test_rejects_path_injection_id(self, client, registry):
        with pytest.raises(ValueError, match="list_id"):
            await get_traffic_matching_list(client, registry, "h", "s", "../etc")
        registry.resolve_host_id.assert_not_called()
        client.get.assert_not_called()


class TestUpdateTrafficMatchingList:
    async def test_basic(self, client, registry):
        payload = {"name": "Updated"}
        client.put.return_value = {"id": "tml-1", **payload}
        result = await update_traffic_matching_list(client, registry, "h", "s", "tml-1", payload)
        client.put.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/traffic-matching-lists/tml-1", key=None, json=payload
        )
        assert result["name"] == "Updated"

    async def test_rejects_path_injection_id(self, client, registry):
        with pytest.raises(ValueError, match="list_id"):
            await update_traffic_matching_list(client, registry, "h", "s", "../etc", {})
        registry.resolve_host_id.assert_not_called()
        client.put.assert_not_called()


class TestDeleteTrafficMatchingList:
    async def test_basic(self, client, registry):
        await delete_traffic_matching_list(client, registry, "h", "s", "tml-1")
        client.delete.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/traffic-matching-lists/tml-1", key=None
        )

    async def test_rejects_path_injection_id(self, client, registry):
        with pytest.raises(ValueError, match="list_id"):
            await delete_traffic_matching_list(client, registry, "h", "s", "../etc")
        registry.resolve_host_id.assert_not_called()
        client.delete.assert_not_called()


# --- VPN Servers ---


class TestListVpnServers:
    async def test_basic_drains_all_by_default(self, client, registry):
        rows = [{"id": "vpn-1", "type": "wireguard"}]
        client.get.side_effect = [rows, []]
        result = await list_vpn_servers(client, registry, "h", "s")
        assert client.get.call_args[0][0] == f"{BASE}/sites/{SITE_ID}/vpn/servers"
        assert client.get.call_count == 2
        assert result == {"data": [{"id": "vpn-1", "type": "wireguard"}], "totalCount": None}

        assert client.get.call_count == 2
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == [0, 1]
        for request in client.get.call_args_list:
            assert request.args == (f"{BASE}/sites/{SITE_ID}/vpn/servers",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }
        assert result["data"] == rows
        assert result["totalCount"] is None
        assert "incomplete" not in result
        assert "_incomplete" not in result


class TestListSiteToSiteTunnels:
    async def test_basic(self, client, registry):
        rows = [{"id": "tun-1", "status": "connected"}]
        client.get.side_effect = [rows, []]
        result = await list_site_to_site_tunnels(client, registry, "h", "s")
        assert client.get.call_args.args[0] == f"{BASE}/sites/{SITE_ID}/vpn/site-to-site-tunnels"
        assert result == {"data": [{"id": "tun-1", "status": "connected"}], "totalCount": None}

        assert client.get.call_count == 2
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == [0, 1]
        for request in client.get.call_args_list:
            assert request.args == (f"{BASE}/sites/{SITE_ID}/vpn/site-to-site-tunnels",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }
        assert result["data"] == rows
        assert result["totalCount"] is None
        assert "incomplete" not in result
        assert "_incomplete" not in result


# --- RADIUS Profiles ---


class TestListRadiusProfiles:
    async def test_basic_drains_all_by_default(self, client, registry):
        rows = [{"id": "rad-1", "name": "Corp Auth"}]
        client.get.side_effect = [rows, []]
        result = await list_radius_profiles(client, registry, "h", "s")
        assert client.get.call_args[0][0] == f"{BASE}/sites/{SITE_ID}/radius/profiles"
        assert client.get.call_count == 2
        assert result == {"data": [{"id": "rad-1", "name": "Corp Auth"}], "totalCount": None}

        assert client.get.call_count == 2
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == [0, 1]
        for request in client.get.call_args_list:
            assert request.args == (f"{BASE}/sites/{SITE_ID}/radius/profiles",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }
        assert result["data"] == rows
        assert result["totalCount"] is None
        assert "incomplete" not in result
        assert "_incomplete" not in result


# --- Hotspot Vouchers ---


class TestListHotspotVouchers:
    async def test_basic_drains_all_by_default(self, client, registry):
        rows = [{"id": "v-1", "code": "ABC123"}]
        client.get.side_effect = [rows, []]
        result = await list_hotspot_vouchers(client, registry, "h", "s")
        assert client.get.call_args[0][0] == f"{BASE}/sites/{SITE_ID}/hotspot/vouchers"
        assert client.get.call_count == 2
        assert result == {"data": [{"id": "v-1", "code": "ABC123"}], "totalCount": None}

        assert client.get.call_count == 2
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == [0, 1]
        for request in client.get.call_args_list:
            assert request.args == (f"{BASE}/sites/{SITE_ID}/hotspot/vouchers",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }
        assert result["data"] == rows
        assert result["totalCount"] is None
        assert "incomplete" not in result
        assert "_incomplete" not in result

    async def test_cap_exceeded_marked_incomplete(self, client, registry):
        rows = [{"id": "v-1"}] + [dict({"id": "v-1"}, id=f"extra-{index}") for index in range(1, 2)]
        client.paginate_max_pages = 2
        client.get.side_effect = [{"data": [row], "limit": 1} for row in rows]
        result = await list_hotspot_vouchers(client, registry, "h", "s")
        assert result["incomplete"] is True
        assert result["data"] == rows
        assert client.get.call_count == 2
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == list(
            range(2)
        )


class TestCreateHotspotVouchers:
    async def test_basic(self, client, registry):
        # name + timeLimitMinutes verified required by the live controller.
        payload = {"name": "Lobby", "timeLimitMinutes": 60, "count": 5}
        client.post.return_value = [{"id": "v-1"}, {"id": "v-2"}]
        result = await create_hotspot_vouchers(client, registry, "h", "s", payload)
        client.post.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/hotspot/vouchers", key=None, json=payload
        )
        assert len(result) == 2

    async def test_missing_required_fields_rejected(self, client, registry):
        with pytest.raises(ValueError) as exc:
            await create_hotspot_vouchers(client, registry, "h", "s", {"count": 5})
        assert str(exc.value) == "create_hotspot_vouchers requires: name, timeLimitMinutes"
        client.post.assert_not_called()


class TestGetHotspotVoucher:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "v-1", "code": "ABC123"}
        result = await get_hotspot_voucher(client, registry, "h", "s", "v-1")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/hotspot/vouchers/v-1", key=None)
        assert result["code"] == "ABC123"

    async def test_rejects_path_injection_id(self, client, registry):
        with pytest.raises(ValueError, match="voucher_id"):
            await get_hotspot_voucher(client, registry, "h", "s", "../etc")
        registry.resolve_host_id.assert_not_called()
        client.get.assert_not_called()


class TestDeleteHotspotVoucher:
    async def test_basic(self, client, registry):
        await delete_hotspot_voucher(client, registry, "h", "s", "v-1")
        client.delete.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/hotspot/vouchers/v-1", key=None
        )

    async def test_rejects_path_injection_id(self, client, registry):
        with pytest.raises(ValueError, match="voucher_id"):
            await delete_hotspot_voucher(client, registry, "h", "s", "../etc")
        registry.resolve_host_id.assert_not_called()
        client.delete.assert_not_called()


class TestBulkDeleteHotspotVouchers:
    async def test_basic(self, client, registry):
        params = {"filter": "name.eq('Conference')", "expired": True}
        await bulk_delete_hotspot_vouchers(client, registry, "h", "s", params)
        client.delete.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/hotspot/vouchers", key=None, params=params
        )

    async def test_missing_filter_fails_fast_naming_it(self, client, registry):
        # The spec marks the DELETE ``filter`` query parameter required.
        with pytest.raises(ValueError, match="filter"):
            await bulk_delete_hotspot_vouchers(client, registry, "h", "s", {"expired": True})
        client.delete.assert_not_called()
        registry.resolve_key_for_host.assert_not_called()


# --- Supporting Resources ---


class TestListDeviceTags:
    async def test_reads_the_v2_list_verbatim(self, client, registry):
        tags = [{"_id": "6501", "name": "IoT", "member_device_macs": ["aa:bb:cc:dd:ee:01"]}]
        client.get.return_value = tags
        result = await list_device_tags(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{V2_API_BASE}/device-tags", key=None)
        client.paginate_offset.assert_not_called()
        assert result is tags


class TestListCountries:
    async def test_basic(self, client, registry):
        rows = [{"code": "US", "name": "United States"}]
        client.get.side_effect = [rows, []]
        result = await list_countries(client, registry, "h")
        assert result == {"data": [{"code": "US", "name": "United States"}], "totalCount": None}
        assert client.get.call_args.args[0] == f"{BASE}/countries"
        registry.resolve_site_id.assert_not_called()

        assert client.get.call_count == 2
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == [0, 1]
        for request in client.get.call_args_list:
            assert request.args == (f"{BASE}/countries",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }
        assert result["data"] == rows
        assert result["totalCount"] is None
        assert "incomplete" not in result
        assert "_incomplete" not in result


# --- Port Forwards (Classic REST API) ---


class TestListPortForwards:
    async def test_uses_classic_rest_url(self, client, registry):
        client.get.return_value = {"data": [{"_id": "pf-1", "name": "SSH"}]}
        result = await list_port_forwards(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/portforward", key=None)
        assert result == {"data": [{"_id": "pf-1", "name": "SSH"}]}

    async def test_resolves_slug_not_uuid(self, client, registry):
        client.get.return_value = {}
        await list_port_forwards(client, registry, "h", "s")
        registry.resolve_site_slug.assert_called_once_with("s", HOST_ID, key=None)
        registry.resolve_site_id.assert_not_called()


class TestCreatePortForward:
    async def test_posts_to_classic_rest(self, client, registry):
        payload = {
            "enabled": True,
            "name": "SSH",
            "pfwd_interface": "wan",
            "src": "any",
            "dst_port": "2222",
            "fwd": "192.168.1.10",
            "fwd_port": "22",
            "proto": "tcp",
            "log": False,
        }
        client.post.return_value = {"_id": "pf-new", **payload}
        result = await create_port_forward(client, registry, "h", "s", payload)
        client.post.assert_called_once_with(
            f"{CLASSIC_REST_BASE}/portforward", key=None, json=payload
        )
        assert result["_id"] == "pf-new"

    async def test_valid_payload_with_all_required_fields(self, client, registry):
        payload = {
            "name": "HTTP",
            "dst_port": "8080",
            "fwd": "192.168.1.20",
            "fwd_port": "80",
        }
        client.post.return_value = {"_id": "pf-x", **payload}
        result = await create_port_forward(client, registry, "h", "s", payload)
        client.post.assert_called_once_with(
            f"{CLASSIC_REST_BASE}/portforward", key=None, json=payload
        )
        assert result["_id"] == "pf-x"


class TestUpdatePortForward:
    async def test_puts_to_classic_rest(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "pf-1"}]}
        payload = {"enabled": False}
        client.put.return_value = {"_id": "pf-1", **payload}
        result = await update_port_forward(client, registry, "h", "s", "pf-1", payload)
        client.put.assert_called_once_with(
            f"{CLASSIC_REST_BASE}/portforward/pf-1", key=None, json=payload
        )
        assert result["_id"] == "pf-1"


class TestDeletePortForward:
    async def test_deletes_via_classic_rest(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "pf-1"}]}
        await delete_port_forward(client, registry, "h", "s", "pf-1")
        client.delete.assert_called_once_with(f"{CLASSIC_REST_BASE}/portforward/pf-1", key=None)


# --- Traffic Rules (v2 API) ---


class TestListTrafficRules:
    async def test_uses_v2_url(self, client, registry):
        client.get.return_value = {"data": [{"_id": "tr-1", "description": "Block Social"}]}
        result = await list_traffic_rules(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{V2_API_BASE}/trafficrules", key=None)
        assert result == {"data": [{"_id": "tr-1", "description": "Block Social"}]}

    async def test_resolves_slug_not_uuid(self, client, registry):
        client.get.return_value = {}
        await list_traffic_rules(client, registry, "h", "s")
        registry.resolve_site_slug.assert_called_once_with("s", HOST_ID, key=None)
        registry.resolve_site_id.assert_not_called()

    async def test_bare_list_wrapped(self, client, registry):
        """v2 API may return [] or [...] directly; normalize to {data: [...], count: N}."""
        rules = [{"_id": "tr-1", "description": "Block Social"}, {"_id": "tr-2"}]
        client.get.return_value = rules
        result = await list_traffic_rules(client, registry, "h", "s")
        assert result == rules

    async def test_empty_bare_list_wrapped(self, client, registry):
        """Empty bare list [] is normalized to {data: [], count: 0}."""
        client.get.return_value = []
        result = await list_traffic_rules(client, registry, "h", "s")
        assert result == []


class TestCreateTrafficRule:
    async def test_posts_to_v2(self, client, registry):
        # Live-verified required set: action, matching_target, target_devices.
        # description/enabled are optional here (not API-required) but ride along fine.
        payload = {
            "action": "BLOCK",
            "matching_target": "INTERNET",
            "target_devices": [{"client_mac": "aa:bb:cc:dd:ee:ff"}],
            "description": "Block Social Media",
        }
        client.post.return_value = {"_id": "tr-new", **payload}
        result = await create_traffic_rule(client, registry, "h", "s", payload)
        client.post.assert_called_once_with(f"{V2_API_BASE}/trafficrules", key=None, json=payload)
        assert result["_id"] == "tr-new"


_STORED_TRAFFIC_RULE: dict[str, Any] = {
    "_id": "tr-1",
    "description": "Block Social Media",
    "action": "BLOCK",
    "matching_target": "INTERNET",
    "target_devices": [{"client_mac": "aa:bb:cc:dd:ee:ff", "type": "CLIENT"}],
    "schedule": {"mode": "CUSTOM", "repeat_on_days": ["mon"], "time_all_day": False},
    "enabled": True,
}


class TestUpdateTrafficRule:
    async def test_partial_payload_is_merged_into_the_listed_rule(self, client, registry):
        """The v2 PUT replaces the whole rule: the documented partial payload
        ({"enabled": false}) must not wipe matching_target / target_devices / schedule."""
        stored = copy.deepcopy(_STORED_TRAFFIC_RULE)
        client.get.side_effect = [[stored], [{**stored, "enabled": False}]]
        client.put.return_value = {**stored, "enabled": False}
        result = await update_traffic_rule(client, registry, "h", "s", "tr-1", {"enabled": False})
        client.put.assert_called_once_with(
            f"{V2_API_BASE}/trafficrules/tr-1/",
            key=None,
            json={**_STORED_TRAFFIC_RULE, "enabled": False},
        )
        assert result["enabled"] is False
        assert result["_verified"] is True
        assert stored == _STORED_TRAFFIC_RULE  # the listed record is not mutated

    async def test_nested_change_keeps_unrequested_siblings(self, client, registry):
        stored = copy.deepcopy(_STORED_TRAFFIC_RULE)
        client.get.return_value = [stored]
        client.put.return_value = {"_id": "tr-1"}
        result = await update_traffic_rule(
            client, registry, "h", "s", "tr-1", {"schedule": {"mode": "ALWAYS"}}
        )
        sent = client.put.call_args.kwargs["json"]
        assert sent["schedule"] == {
            "mode": "ALWAYS",
            "repeat_on_days": ["mon"],
            "time_all_day": False,
        }
        assert sent["target_devices"] == _STORED_TRAFFIC_RULE["target_devices"]
        # The read-back still shows the old mode: the write is not reported verified.
        assert result["_verified"] is False

    async def test_strips_empty_strings_from_list_fields(self, client, registry):
        """Padded list fields in a traffic-rule object are cleaned
        before the PUT so a read-modify-write round-trip does not 400."""
        client.get.return_value = [{"_id": "tr-1"}]
        payload = {"enabled": True, "target_devices": ["dev-1", "", ""]}
        client.put.return_value = {"_id": "tr-1"}
        await update_traffic_rule(client, registry, "h", "s", "tr-1", payload)
        client.put.assert_called_once_with(
            f"{V2_API_BASE}/trafficrules/tr-1/",
            key=None,
            json={"_id": "tr-1", "enabled": True, "target_devices": ["dev-1"]},
        )

    async def test_read_back_failure_is_reported_not_raised(self, client, registry):
        client.get.side_effect = [
            [copy.deepcopy(_STORED_TRAFFIC_RULE)],
            UniFiConnectionError("boom"),
        ]
        client.put.return_value = {"_id": "tr-1"}
        result = await update_traffic_rule(client, registry, "h", "s", "tr-1", {"enabled": False})
        assert result["_verified"] is None
        assert "boom" in result["_readAfterError"]

    @pytest.mark.parametrize("payload", [{}, {"_id": "tr-1"}, {"_resolved": 1}])
    async def test_payload_without_a_field_to_change_sends_nothing(self, client, registry, payload):
        with pytest.raises(ValueError):
            await update_traffic_rule(client, registry, "h", "s", "tr-1", payload)
        client.get.assert_not_called()
        client.put.assert_not_called()


class TestDeleteTrafficRule:
    async def test_deletes_via_v2_with_trailing_slash(self, client, registry):
        client.get.return_value = [{"_id": "tr-1"}]
        await delete_traffic_rule(client, registry, "h", "s", "tr-1")
        client.delete.assert_called_once_with(f"{V2_API_BASE}/trafficrules/tr-1/", key=None)


# --- Users / DHCP Reservations (Classic REST) ---


class TestListUsers:
    async def test_uses_classic_rest_url(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "u-1"}]}
        result = await list_users(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/user", key=None)
        assert result["data"] == [{"_id": "u-1"}]

    async def test_resolves_slug_not_uuid(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": []}
        await list_users(client, registry, "h", "s")
        registry.resolve_site_slug.assert_called_once_with("s", HOST_ID, key=None)
        registry.resolve_site_id.assert_not_called()


class TestGetUser:
    async def test_uses_classic_rest_url(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "u-1"}]}
        result = await get_user(client, registry, "h", "s", "u-1")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/user/u-1", key=None)
        assert result["data"] == [{"_id": "u-1"}]


class TestUpdateUser:
    async def test_puts_to_classic_rest(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "u-1"}]}
        payload = {"name": "My Device", "fixed_ip": "192.168.1.100"}
        client.put.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "u-1", **payload}]}
        result = await update_user(client, registry, "h", "s", "u-1", payload)
        client.put.assert_called_once_with(f"{CLASSIC_REST_BASE}/user/u-1", key=None, json=payload)
        assert result["data"][0]["name"] == "My Device"


# --- Traffic Routes (v2 API) ---


class TestListTrafficRoutes:
    async def test_uses_v2_url(self, client, registry):
        client.get.return_value = [{"_id": "rt-1", "name": "Default Route"}]
        result = await list_traffic_routes(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{V2_API_BASE}/trafficroutes", key=None)
        assert result == [{"_id": "rt-1", "name": "Default Route"}]

    async def test_resolves_slug_not_uuid(self, client, registry):
        client.get.return_value = []
        await list_traffic_routes(client, registry, "h", "s")
        registry.resolve_site_slug.assert_called_once_with("s", HOST_ID, key=None)
        registry.resolve_site_id.assert_not_called()


class TestCreateTrafficRoute:
    async def test_posts_to_v2(self, client, registry):
        # v2 endpoint uses snake_case wire fields (verified: network_id, not networkId).
        payload = {
            "network_id": "ANY",
            "matching_target": "INTERNET",
            "target_devices": [{"network_id": "n1"}],
            "name": "ISP2 Route",
        }
        client.post.return_value = {"_id": "rt-new", **payload}
        result = await create_traffic_route(client, registry, "h", "s", payload)
        client.post.assert_called_once_with(f"{V2_API_BASE}/trafficroutes", key=None, json=payload)
        assert result["_id"] == "rt-new"


class TestGetTrafficRoute:
    async def test_filters_from_list(self, client, registry):
        client.get.return_value = [
            {"_id": "rt-1", "name": "Default Route"},
            {"_id": "rt-2", "name": "ISP2 Route"},
        ]
        result = await get_traffic_route(client, registry, "h", "s", "rt-1")
        client.get.assert_called_once_with(f"{V2_API_BASE}/trafficroutes", key=None)
        assert result == {"_id": "rt-1", "name": "Default Route"}

    async def test_raises_when_not_found(self, client, registry):
        client.get.return_value = [{"_id": "rt-2", "name": "ISP2 Route"}]
        with pytest.raises(ValueError, match="not found"):
            await get_traffic_route(client, registry, "h", "s", "rt-1")


class TestUpdateTrafficRoute:
    async def test_puts_to_v2(self, client, registry):
        client.get.return_value = [{"_id": "rt-1"}]
        payload = {"enabled": False}
        client.put.return_value = {"_id": "rt-1", **payload}
        result = await update_traffic_route(client, registry, "h", "s", "rt-1", payload)
        client.put.assert_called_once_with(
            f"{V2_API_BASE}/trafficroutes/rt-1", key=None, json=payload
        )
        assert result["_id"] == "rt-1"


class TestDeleteTrafficRoute:
    async def test_deletes_via_v2(self, client, registry):
        client.get.return_value = [{"_id": "rt-1"}]
        await delete_traffic_route(client, registry, "h", "s", "rt-1")
        client.delete.assert_called_once_with(f"{V2_API_BASE}/trafficroutes/rt-1", key=None)


# --- Controller Settings (Classic REST) ---


class TestListSettings:
    async def test_uses_classic_rest_url(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"key": "mgmt"}]}
        result = await list_settings(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/setting", key=None)
        assert result["data"] == [{"key": "mgmt"}]

    async def test_management_credentials_survive(self, client, registry):
        # Data-survival: the server is a faithful pass-through. Credential fields
        # returned by the controller reach the caller unchanged; a deployment that
        # wants them hidden layers that policy on top of the response.
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [
                {
                    "key": "mgmt",
                    "x_api_token": "api-token",
                    "x_mgmt_key": "management-key",
                    "x_ssh_password": "password",
                    "x_ssh_sha512passwd": "password-hash",
                    "x_ssh_keys": [{"name": "collector", "key": "ssh-ed25519 PUBLIC"}],
                }
            ],
        }
        result = await list_settings(client, registry, "h", "s")
        mgmt = result["data"][0]
        assert mgmt["x_api_token"] == "api-token"
        assert mgmt["x_mgmt_key"] == "management-key"
        assert mgmt["x_ssh_password"] == "password"
        assert mgmt["x_ssh_sha512passwd"] == "password-hash"
        assert mgmt["x_ssh_keys"][0]["key"] == "ssh-ed25519 PUBLIC"


class TestGetSetting:
    async def test_uses_classic_rest_url_with_key(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"key": "mgmt"}]}
        result = await get_setting(client, registry, "h", "s", "mgmt")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/setting/mgmt", key=None)
        assert result["data"] == [{"key": "mgmt"}]

    async def test_nested_and_suffix_credentials_survive(self, client, registry):
        # Data-survival: nested credential fields at any depth pass through verbatim.
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [
                {
                    "key": "example",
                    "nested": {
                        "client_secret": "client-secret",
                        "refresh_token": "refresh-token",
                        "ordinary_key": "visible",
                    },
                }
            ],
        }
        result = await get_setting(client, registry, "h", "s", "example")
        nested = result["data"][0]["nested"]
        assert nested["client_secret"] == "client-secret"
        assert nested["refresh_token"] == "refresh-token"
        assert nested["ordinary_key"] == "visible"


class TestUpdateSetting:
    async def test_puts_to_classic_rest(self, client, registry):
        """Successful write: pre-state differs from payload, post-state reflects change."""
        payload = {"autobackup": True}
        pre = {"meta": {"rc": "ok"}, "data": [{"key": "mgmt", "autobackup": False}]}
        post_put = {"meta": {"rc": "ok"}, "data": [{"key": "mgmt", "autobackup": True}]}
        post_get = {"meta": {"rc": "ok"}, "data": [{"key": "mgmt", "autobackup": True}]}
        # get (pre-read), put, get (post-verify)
        client.get.side_effect = [pre, post_get]
        client.put.return_value = post_put
        result = await update_setting(client, registry, "h", "s", "mgmt", payload)
        client.put.assert_called_once_with(
            f"{CLASSIC_REST_BASE}/setting/mgmt", key=None, json=payload
        )
        assert result["data"][0]["autobackup"] is True
        assert client.get.call_count == 2, "expected pre+post GETs for state comparison"

    async def test_idempotent_write_skips_put(self, client, registry):
        """If submitted values already equal current state, skip the PUT."""
        payload = {"autobackup": True}
        pre = {"meta": {"rc": "ok"}, "data": [{"key": "mgmt", "autobackup": True}]}
        client.get.return_value = pre
        result = await update_setting(client, registry, "h", "s", "mgmt", payload)
        client.put.assert_not_called()
        assert result["_note"] == "no change needed"
        assert result["data"] == [{"key": "mgmt", "autobackup": True}]

    async def test_silent_noop_preserves_put_and_reports_mismatch(self, client, registry):
        """Rejected values are a verification result beside the upstream body."""
        payload = {"autobackup": True}
        pre = {"meta": {"rc": "ok"}, "data": [{"key": "mgmt", "autobackup": False}]}
        post_put = {"meta": {"rc": "ok"}, "data": [{"key": "mgmt", "autobackup": False}]}
        post_get = {"meta": {"rc": "ok"}, "data": [{"key": "mgmt", "autobackup": False}]}
        client.get.side_effect = [pre, post_get]
        client.put.return_value = post_put
        result = await update_setting(client, registry, "h", "s", "mgmt", payload)
        assert result == {
            **post_put,
            "_verified": False,
            "_unverifiedFields": ["autobackup"],
            "_verificationNote": result["_verificationNote"],
        }
        assert "mgmt" in result["_verificationNote"]

    async def test_silent_noop_note_points_to_get_setting(self, client, registry):
        """Public issue #17, defect 3: the note must teach discovery — name the rejected
        field, explain the silent drop, and point the caller at get_setting."""
        payload = {"autobackup": True}
        pre = {"meta": {"rc": "ok"}, "data": [{"key": "mgmt", "autobackup": False}]}
        unchanged = {"meta": {"rc": "ok"}, "data": [{"key": "mgmt", "autobackup": False}]}
        client.get.side_effect = [pre, unchanged]
        client.put.return_value = unchanged
        result = await update_setting(client, registry, "h", "s", "mgmt", payload)
        assert result["data"] == unchanged["data"]
        assert result["_verified"] is False
        assert result["_unverifiedFields"] == ["autobackup"]
        msg = result["_verificationNote"]
        assert "'autobackup'" in msg
        assert "silently drops" in msg
        assert "get_setting(setting_key='mgmt')" in msg

    async def test_padded_list_field_is_recognised_as_no_op(self, client, registry):
        """A list field whose only difference from current state is the controller's
        empty-string padding must be seen as already-equal and skip the PUT — not
        treated as a change (which would then be mis-flagged as a silent no-op)."""
        payload = {"dns": ["8.8.8.8", "", ""]}
        pre = {"meta": {"rc": "ok"}, "data": [{"key": "mgmt", "dns": ["8.8.8.8", "", ""]}]}
        client.get.return_value = pre
        result = await update_setting(client, registry, "h", "s", "mgmt", payload)
        client.put.assert_not_called()
        assert result["_note"] == "no change needed"

    async def test_real_change_not_flagged_by_unchanged_padded_list(self, client, registry):
        """The regression: a genuine scalar change succeeds while an unchanged
        padded list field rides along. The padded field differs from the stripped
        payload only by placeholders, so it must NOT be reported as a rejected
        write — the tool must return the result, not raise."""
        payload = {"autobackup": True, "dns": ["8.8.8.8", "", ""]}
        pre = {
            "meta": {"rc": "ok"},
            "data": [{"key": "mgmt", "autobackup": False, "dns": ["8.8.8.8", "", ""]}],
        }
        post = {
            "meta": {"rc": "ok"},
            "data": [{"key": "mgmt", "autobackup": True, "dns": ["8.8.8.8", "", ""]}],
        }
        client.get.side_effect = [pre, post]
        client.put.return_value = post
        result = await update_setting(client, registry, "h", "s", "mgmt", payload)
        client.put.assert_called_once_with(
            f"{CLASSIC_REST_BASE}/setting/mgmt",
            key=None,
            json={"autobackup": True, "dns": ["8.8.8.8"]},
        )
        assert result["data"][0]["autobackup"] is True

    async def test_server_managed_fields_excluded(self, client, registry):
        """Server-managed fields changing should not trigger false-positive no-op."""
        payload = {"autobackup": True}
        pre = {
            "meta": {"rc": "ok"},
            "data": [{"key": "mgmt", "autobackup": False, "_updatedAt": 100}],
        }
        post_put = {
            "meta": {"rc": "ok"},
            "data": [{"key": "mgmt", "autobackup": True, "_updatedAt": 200}],
        }
        post_get = {
            "meta": {"rc": "ok"},
            "data": [{"key": "mgmt", "autobackup": True, "_updatedAt": 200}],
        }
        client.get.side_effect = [pre, post_get]
        client.put.return_value = post_put
        result = await update_setting(client, registry, "h", "s", "mgmt", payload)
        assert result["data"][0]["autobackup"] is True

    async def test_secret_fields_survive_in_write_response(self, client, registry):
        payload = {"x_ssh_auth_password_enabled": False}
        pre = {
            "meta": {"rc": "ok"},
            "data": [
                {
                    "key": "mgmt",
                    "x_ssh_auth_password_enabled": True,
                    "x_ssh_password": "old-password",
                }
            ],
        }
        post = {
            "meta": {"rc": "ok"},
            "data": [
                {
                    "key": "mgmt",
                    "x_ssh_auth_password_enabled": False,
                    "x_ssh_password": "old-password",
                }
            ],
        }
        client.get.side_effect = [pre, post]
        client.put.return_value = post
        result = await update_setting(client, registry, "h", "s", "mgmt", payload)
        assert result["data"][0]["x_ssh_password"] == "old-password"

    async def test_secret_fields_survive_in_idempotent_response(self, client, registry):
        payload = {"x_ssh_auth_password_enabled": True}
        pre = {
            "meta": {"rc": "ok"},
            "data": [
                {
                    "key": "mgmt",
                    "x_ssh_auth_password_enabled": True,
                    "x_ssh_password": "current-password",
                }
            ],
        }
        client.get.return_value = pre
        result = await update_setting(client, registry, "h", "s", "mgmt", payload)
        assert result["data"][0]["x_ssh_password"] == "current-password"

    async def test_strips_empty_strings_from_list_fields(self, client, registry):
        """A setting group read back with a padded list field
        round-trips cleanly — the PUT carries only the real entries."""
        payload = {"ntp_server": ["pool.ntp.org", "", ""]}
        pre = {"meta": {"rc": "ok"}, "data": [{"key": "ntp", "ntp_server": ["old.ntp.org"]}]}
        post = {"meta": {"rc": "ok"}, "data": [{"key": "ntp", "ntp_server": ["pool.ntp.org"]}]}
        client.get.side_effect = [pre, post]
        client.put.return_value = post
        await update_setting(client, registry, "h", "s", "ntp", payload)
        client.put.assert_called_once_with(
            f"{CLASSIC_REST_BASE}/setting/ntp",
            key=None,
            json={"ntp_server": ["pool.ntp.org"]},
        )

    async def test_idempotent_after_stripping_padding(self, client, registry):
        """The no-op guard compares the *stripped* payload: a padded submission
        whose real values already match current state skips the PUT rather than
        writing a spurious change."""
        payload = {"ntp_server": ["pool.ntp.org", "", ""]}
        pre = {"meta": {"rc": "ok"}, "data": [{"key": "ntp", "ntp_server": ["pool.ntp.org"]}]}
        client.get.return_value = pre
        result = await update_setting(client, registry, "h", "s", "ntp", payload)
        client.put.assert_not_called()
        assert result["_note"] == "no change needed"


class TestUpdateSettingDryRunAndMask:
    """Dry-run preview is returned unverified; masked secrets are not sent."""

    async def test_dry_run_preview_returned_without_verify(self, client, registry):
        from unifi_fabric.client import DRY_RUN_MESSAGE

        pre = {"meta": {"rc": "ok"}, "data": [{"key": "mgmt", "autobackup": False}]}
        preview = {
            "dryRun": True,
            "message": DRY_RUN_MESSAGE,
            "preview": {"method": "PUT", "path": "/x", "body": {"autobackup": True}},
        }
        client.get.side_effect = [pre]
        client.put.return_value = preview
        result = await update_setting(client, registry, "h", "s", "mgmt", {"autobackup": True})
        assert result == preview
        assert client.get.call_count == 1, "no post-write verify GET under dry-run"

    async def test_masked_fields_dropped_and_never_reported_rejected(
        self, client, registry, monkeypatch
    ):
        monkeypatch.setenv("UNIFI_REDACT_SECRETS", "true")
        from unifi_fabric.redaction import REDACTION_MASK

        payload = {
            "autobackup": True,
            "x_password": REDACTION_MASK,
            "radius": {"x_secret": REDACTION_MASK, "port": 1812},
        }
        stored = {"key": "mgmt", "x_password": "real", "radius": {"x_secret": "s", "port": 1812}}
        pre = {"meta": {"rc": "ok"}, "data": [{**stored, "autobackup": False}]}
        post = {"meta": {"rc": "ok"}, "data": [{**stored, "autobackup": True}]}
        client.get.side_effect = [pre, post]
        client.put.return_value = post
        result = await update_setting(client, registry, "h", "s", "mgmt", payload)
        client.put.assert_called_once_with(
            f"{CLASSIC_REST_BASE}/setting/mgmt",
            key=None,
            json={"autobackup": True, "radius": {"port": 1812}},
        )
        # The PUT envelope verbatim plus the additive read-after verdict.
        assert result == {**post, "_verified": True}

    async def test_only_masked_fields_raises_before_any_request(
        self, client, registry, monkeypatch
    ):
        monkeypatch.setenv("UNIFI_REDACT_SECRETS", "true")
        from unifi_fabric.redaction import REDACTION_MASK

        # Nothing is left to send: the one empty-update guard refuses before the GET
        # (it used to read the setting and answer "no change needed").
        with pytest.raises(ValueError, match="No fields provided"):
            await update_setting(client, registry, "h", "s", "mgmt", {"x_password": REDACTION_MASK})
        client.get.assert_not_called()
        client.put.assert_not_called()
        registry.resolve_key_for_host.assert_not_called()


class TestSettingSchemaHints:
    """Public issue #17, defect 3: get_setting/update_setting must give callers a way to learn
    what a setting_key accepts. The hints are grounded in live controller responses."""

    def test_get_setting_documents_common_keys_and_enums(self):
        doc = get_setting.__doc__ or ""
        # Common keys observed live, including the exact repro key/field from public issue #17.
        for token in ("mdns", "enabled_for", "ntp", "setting_preference", "doh"):
            assert token in doc, f"get_setting docstring should mention {token!r}"
        # It must teach the discovery workflow and the silent-drop hazard.
        assert "silently drops" in doc
        assert "x_" in doc  # flags credential-bearing fields

    def test_update_setting_points_at_get_setting(self):
        doc = update_setting.__doc__ or ""
        assert "get_setting" in doc
        assert "silently drops" in doc


# --- Dynamic DNS (Classic REST) ---


class TestListDynamicDns:
    async def test_uses_classic_rest_url(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "ddns-1"}]}
        result = await list_dynamic_dns(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/dynamicdns", key=None)
        assert result["data"] == [{"_id": "ddns-1"}]

    async def test_x_password_survives(self, client, registry):
        # Data-survival: credential fields pass through verbatim, no opt-in required.
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "ddns-1", "service": "dyndns", "x_password": "secret"}],
        }
        result = await list_dynamic_dns(client, registry, "h", "s")
        assert result["data"] == [{"_id": "ddns-1", "service": "dyndns", "x_password": "secret"}]


class TestGetDynamicDns:
    async def test_uses_classic_rest_url_with_id(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "ddns-1"}]}
        result = await get_dynamic_dns(client, registry, "h", "s", "ddns-1")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/dynamicdns/ddns-1", key=None)
        assert result["data"] == [{"_id": "ddns-1"}]

    async def test_x_password_survives(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "ddns-1", "x_password": "secret"}],
        }
        result = await get_dynamic_dns(client, registry, "h", "s", "ddns-1")
        assert result["data"] == [{"_id": "ddns-1", "x_password": "secret"}]


class TestUpdateDynamicDns:
    async def test_puts_to_classic_rest(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "ddns-1"}]}
        payload = {"service": "dyndns", "hostname": "home.example.com"}
        client.put.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "ddns-1", **payload}]}
        result = await update_dynamic_dns(client, registry, "h", "s", "ddns-1", payload)
        client.put.assert_called_once_with(
            f"{CLASSIC_REST_BASE}/dynamicdns/ddns-1", key=None, json=payload
        )
        assert result["data"][0]["service"] == "dyndns"


# --- Port Profiles (Classic REST) ---


class TestListPortProfiles:
    async def test_uses_classic_rest_url(self, client, registry):
        client.get.side_effect = [
            {"meta": {"rc": "ok"}, "data": [{"_id": "pp-1", "name": "All"}]},
            {"meta": {"rc": "ok"}, "data": []},
        ]
        result = await list_port_profiles(client, registry, "h", "s")
        assert client.get.call_args_list[0].args[0] == f"{CLASSIC_REST_BASE}/portconf"
        assert result["data"] == [{"_id": "pp-1", "name": "All"}]

    async def test_profile_verbatim_with_additive_resolution(self, client, registry):
        """Network-id resolution is ADDITIVE: controller fields stay bare ids; names/VLANs
        are reported under _resolved_networks."""
        client.get.side_effect = [
            {
                "meta": {"rc": "ok"},
                "data": [
                    {
                        "_id": "pp-1",
                        "name": "Estate Trunk",
                        "tagged_vlan_mgmt": "custom",
                        "native_networkconf_id": "netlan",
                        "voice_networkconf_id": "netvoip",
                        "excluded_networkconf_ids": ["netguest", "", "netstale"],
                    }
                ],
            },
            {
                "meta": {"rc": "ok"},
                "data": [
                    {"_id": "netlan", "name": "LAN", "vlan": 1},
                    {"_id": "netvoip", "name": "VoIP", "vlan": 20},
                    {"_id": "netguest", "name": "Guest", "vlan": 3111},
                ],
            },
        ]
        result = await list_port_profiles(client, registry, "h", "s")
        assert client.get.call_args_list[1].args[0] == f"{CLASSIC_REST_BASE}/networkconf"
        prof = result["data"][0]
        # controller fields verbatim (including the empty-string padding)
        assert prof["native_networkconf_id"] == "netlan"
        assert prof["voice_networkconf_id"] == "netvoip"
        assert prof["excluded_networkconf_ids"] == ["netguest", "", "netstale"]
        assert {k: v for k, v in prof.items() if k != "_resolved_networks"} == {
            "_id": "pp-1",
            "name": "Estate Trunk",
            "tagged_vlan_mgmt": "custom",
            "native_networkconf_id": "netlan",
            "voice_networkconf_id": "netvoip",
            "excluded_networkconf_ids": ["netguest", "", "netstale"],
        }
        resolved = prof["_resolved_networks"]
        assert resolved["native_networkconf_id"] == {"id": "netlan", "name": "LAN", "vlan": 1}
        assert resolved["voice_networkconf_id"] == {"id": "netvoip", "name": "VoIP", "vlan": 20}
        # unknown id still resolved to an object; empty padding has nothing to resolve
        assert resolved["excluded_networkconf_ids"] == [
            {"id": "netguest", "name": "Guest", "vlan": 3111},
            {"id": "netstale", "name": None, "vlan": None},
        ]


class TestGetPortProfile:
    async def test_uses_classic_rest_url_with_id(self, client, registry):
        client.get.side_effect = [
            {"meta": {"rc": "ok"}, "data": [{"_id": "pp-1"}]},
            {"meta": {"rc": "ok"}, "data": []},
        ]
        result = await get_port_profile(client, registry, "h", "s", "pp-1")
        assert client.get.call_args_list[0].args[0] == f"{CLASSIC_REST_BASE}/portconf/pp-1"
        assert result["data"] == [{"_id": "pp-1"}]

    async def test_rejects_path_injection_id(self, client, registry):
        with pytest.raises(ValueError, match="profile_id"):
            await get_port_profile(client, registry, "h", "s", "../etc")
        client.get.assert_not_called()


class TestUpdatePortProfile:
    async def test_puts_to_classic_rest(self, client, registry):
        payload = {"poe_mode": "auto"}
        client.put.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "pp-1", **payload, "excluded_networkconf_ids": ["netguest"]}],
        }
        networks = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "netguest", "name": "Guest", "vlan": 3111}],
        }
        profiles = {"meta": {"rc": "ok"}, "data": [{"_id": "pp-1"}]}
        client.get.side_effect = lambda path, **_: (
            profiles if path.endswith("/portconf") else networks
        )
        result = await update_port_profile(client, registry, "h", "s", "pp-1", payload)
        client.get.assert_any_call(f"{CLASSIC_REST_BASE}/portconf", key=None)
        client.put.assert_called_once_with(
            f"{CLASSIC_REST_BASE}/portconf/pp-1", key=None, json=payload
        )
        assert result["data"][0]["poe_mode"] == "auto"
        # response fields verbatim; resolution additive
        assert result["data"][0]["excluded_networkconf_ids"] == ["netguest"]
        assert result["data"][0]["_resolved_networks"]["excluded_networkconf_ids"] == [
            {"id": "netguest", "name": "Guest", "vlan": 3111}
        ]

    async def test_get_result_round_trips_without_additive_key(self, client, registry):
        """data[0] from get_port_profile can be passed straight back: the additive
        _resolved_networks key never reaches the controller."""
        read = {
            "_id": "pp-1",
            "name": "Trunk",
            "native_networkconf_id": "netlan",
            "excluded_networkconf_ids": ["netguest"],
        }
        client.get.side_effect = [
            {"meta": {"rc": "ok"}, "data": [dict(read)]},
            {"meta": {"rc": "ok"}, "data": [{"_id": "netlan", "name": "LAN", "vlan": 1}]},
            {"meta": {"rc": "ok"}, "data": []},
        ]
        got = await get_port_profile(client, registry, "h", "s", "pp-1")
        assert got["meta"] == {"rc": "ok"}
        assert "_resolved_networks" in got["data"][0]
        client.put.return_value = {"meta": {"rc": "ok"}, "data": [dict(read)]}
        networks = {
            "meta": {"rc": "ok"},
            "data": [
                {"_id": "netlan", "name": "LAN", "vlan": 1},
                {"_id": "netguest", "name": "Guest", "vlan": 3111},
            ],
        }
        client.get.side_effect = lambda path, **_: (
            {"meta": {"rc": "ok"}, "data": [dict(read)]} if path.endswith("/portconf") else networks
        )
        await update_port_profile(client, registry, "h", "s", "pp-1", got["data"][0])
        assert client.put.call_args.kwargs["json"] == read

    async def test_strips_empty_strings_from_list_fields(self, client, registry):
        """A port profile read back with a padded list field (e.g.
        tagged VLAN networks) round-trips cleanly."""
        payload = {"poe_mode": "auto", "tagged_networkconf_ids": ["net-1", "", ""]}
        client.put.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "pp-1"}]}
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "pp-1"}]}
        await update_port_profile(client, registry, "h", "s", "pp-1", payload)
        client.put.assert_called_once_with(
            f"{CLASSIC_REST_BASE}/portconf/pp-1",
            key=None,
            json={"poe_mode": "auto", "tagged_networkconf_ids": ["net-1"]},
        )


# Two id spaces name one network (as in the recorded /rest/networkconf fixture): the
# Network Integration id (a UUID: list_networks data[].id, the id create_network returns)
# and the Classic networkconf _id (24-hex), linked by the networkconf ``external_id``.
# Port-profile excluded_networkconf_ids hold the Classic _id. Every id below is distinct.
_PROFILE_ID = "65f1c0ffee0000000000aaaa"
_NET_LAN = {
    "_id": "65f1c0ffee00000000000001",
    "external_id": "3fa85f64-5717-4562-b3fc-2c963f660001",
}
_NET_GUEST = {
    "_id": "65f1c0ffee00000000000002",
    "external_id": "3fa85f64-5717-4562-b3fc-2c963f660002",
}
_NET_IOT = {
    "_id": "65f1c0ffee00000000000003",
    "external_id": "3fa85f64-5717-4562-b3fc-2c963f660003",
}
_NETWORKCONF = {
    "meta": {"rc": "ok"},
    "data": [
        {**_NET_LAN, "name": "LAN", "vlan": 1, "purpose": "corporate"},
        {**_NET_GUEST, "name": "Guest", "vlan": 3111, "purpose": "corporate"},
        {**_NET_IOT, "name": "IoT", "vlan": 40, "purpose": "corporate"},
    ],
}


def _classic_router(**routes: Any) -> Any:
    """client.get side effect: answer by the Classic REST path suffix (exact match)."""

    async def _get(url: str, **_kw: Any) -> Any:
        for suffix, body in routes.items():
            if url.endswith("/" + suffix.replace("__", "/")):
                return body() if callable(body) else body
        raise AssertionError(f"unexpected GET {url}")

    return _get


def _profile(excluded: list[str]) -> dict[str, Any]:
    return {
        "_id": _PROFILE_ID,
        "name": "Estate Trunk",
        "tagged_vlan_mgmt": "custom",
        "native_networkconf_id": _NET_LAN["_id"],
        "excluded_networkconf_ids": list(excluded),
    }


def _router_for(profile: dict[str, Any]) -> Any:
    return _classic_router(
        networkconf=_NETWORKCONF,
        **{f"portconf__{_PROFILE_ID}": {"meta": {"rc": "ok"}, "data": [profile]}},
        portconf={"meta": {"rc": "ok"}, "data": [profile]},
    )


class TestMalformedStoredNetworkconfField:
    """A non-string stored networkconf field is passed through; it only matters when the
    payload needs that same field resolved."""

    @staticmethod
    def _malformed_profile() -> dict[str, Any]:
        return {**_profile([]), "voice_networkconf_id": 5}

    async def test_unrelated_malformed_field_does_not_block_the_update(self, client, registry):
        stored = self._malformed_profile()
        client.get.side_effect = _router_for(stored)
        client.put.return_value = {"meta": {"rc": "ok"}, "data": [stored]}
        await update_port_profile(
            client,
            registry,
            "h",
            "s",
            _PROFILE_ID,
            {"native_networkconf_id": _NET_GUEST["external_id"]},
        )
        sent = client.put.call_args.kwargs["json"]
        assert sent["native_networkconf_id"] == _NET_GUEST["_id"]
        assert "voice_networkconf_id" not in sent

    async def test_malformed_field_round_trips_untouched(self, client, registry):
        stored = self._malformed_profile()
        client.get.side_effect = _router_for(stored)
        client.put.return_value = {"meta": {"rc": "ok"}, "data": [stored]}
        await update_port_profile(
            client, registry, "h", "s", _PROFILE_ID, {"voice_networkconf_id": 5}
        )
        assert client.put.call_args.kwargs["json"]["voice_networkconf_id"] == 5

    async def test_payload_setting_the_malformed_field_to_a_valid_id_repairs_it(
        self, client, registry
    ):
        stored = self._malformed_profile()
        client.get.side_effect = _router_for(stored)
        client.put.return_value = {"meta": {"rc": "ok"}, "data": [stored]}
        await update_port_profile(
            client,
            registry,
            "h",
            "s",
            _PROFILE_ID,
            {"voice_networkconf_id": _NET_IOT["external_id"]},
        )
        assert client.put.call_args.kwargs["json"]["voice_networkconf_id"] == _NET_IOT["_id"]

    async def test_unresolvable_value_for_the_malformed_field_still_raises_naming_it(
        self, client, registry
    ):
        client.get.side_effect = _router_for(self._malformed_profile())
        with pytest.raises(ValueError) as exc:
            await update_port_profile(
                client,
                registry,
                "h",
                "s",
                _PROFILE_ID,
                {"voice_networkconf_id": "no-such-network"},
            )
        msg = str(exc.value)
        assert "voice_networkconf_id value 'no-such-network'" in msg
        assert "stored port profile holds" in msg
        assert "int" in msg
        assert "list_networks" in msg
        client.put.assert_not_called()

    async def test_malformed_list_element_is_untouched_beside_a_valid_one(self, client, registry):
        stored = {**_profile([]), "excluded_networkconf_ids": [7, _NET_GUEST["_id"]]}
        client.get.side_effect = _router_for(stored)
        client.put.return_value = {"meta": {"rc": "ok"}, "data": [stored]}
        await update_port_profile(
            client,
            registry,
            "h",
            "s",
            _PROFILE_ID,
            {"excluded_networkconf_ids": [7, _NET_GUEST["external_id"]]},
        )
        assert client.put.call_args.kwargs["json"]["excluded_networkconf_ids"] == [
            7,
            _NET_GUEST["_id"],
        ]

    async def test_dry_run_does_not_raise_early(self, client, registry):
        from unifi_fabric.client import DRY_RUN_MESSAGE

        client.get.side_effect = _router_for(self._malformed_profile())
        preview = {
            "dryRun": True,
            "message": DRY_RUN_MESSAGE,
            "preview": {"method": "PUT", "path": "x", "params": None, "body": {}},
        }
        client.put.return_value = preview
        result = await update_port_profile(
            client,
            registry,
            "h",
            "s",
            _PROFILE_ID,
            {"native_networkconf_id": _NET_GUEST["external_id"]},
        )
        assert result == preview


class TestAllowNetworkOnPortProfile:
    async def test_integration_id_is_mapped_through_external_id(self, client, registry):
        """``create_network`` returns the Integration id; the profile stores the Classic
        _id. Passing the Integration id un-excludes the matching _id."""
        client.get.side_effect = _router_for(_profile([_NET_GUEST["_id"], _NET_IOT["_id"]]))
        put_body = {"meta": {"rc": "ok"}, "data": [_profile([_NET_IOT["_id"]])]}
        client.put.return_value = put_body
        result = await allow_network_on_port_profile(
            client, registry, "h", "s", _PROFILE_ID, _NET_GUEST["external_id"], confirm=True
        )
        put_json = client.put.call_args.kwargs["json"]
        assert put_json["excluded_networkconf_ids"] == [_NET_IOT["_id"]]
        assert put_json["_id"] == _PROFILE_ID
        assert "_resolved_networks" not in put_json
        # the PUT envelope verbatim (meta kept), profile plus the additive resolution
        assert result["meta"] == {"rc": "ok"}
        prof = result["data"][0]
        assert prof["excluded_networkconf_ids"] == [_NET_IOT["_id"]]
        assert prof["_resolved_networks"]["excluded_networkconf_ids"] == [
            {"id": _NET_IOT["_id"], "name": "IoT", "vlan": 40}
        ]
        # derived tagged set = VLAN nets - native(LAN) - excluded(IoT) = Guest
        assert result["_tagged_networks"] == [
            {"id": _NET_GUEST["_id"], "name": "Guest", "vlan": 3111}
        ]
        assert result["_network"] == {
            "_id": _NET_GUEST["_id"],
            "id": _NET_GUEST["external_id"],
            "name": "Guest",
            "vlan": 3111,
        }

    async def test_classic_id_is_accepted(self, client, registry):
        client.get.side_effect = _router_for(_profile([_NET_GUEST["_id"]]))
        client.put.return_value = {"meta": {"rc": "ok"}, "data": [_profile([])]}
        await allow_network_on_port_profile(
            client, registry, "h", "s", _PROFILE_ID, _NET_GUEST["_id"]
        )
        assert client.put.call_args.kwargs["json"]["excluded_networkconf_ids"] == []

    async def test_unknown_network_lists_every_choice_and_never_writes(self, client, registry):
        """The network id is validated against /rest/networkconf before any write."""
        client.get.side_effect = _router_for(_profile([_NET_GUEST["_id"]]))
        with pytest.raises(ValueError) as exc:
            await allow_network_on_port_profile(
                client, registry, "h", "s", _PROFILE_ID, "3fa85f64-5717-4562-b3fc-2c963f66ffff"
            )
        msg = str(exc.value)
        assert _NET_GUEST["_id"] in {net["_id"] for net in _NETWORKCONF["data"]}
        for net in _NETWORKCONF["data"]:
            assert net["name"] in msg
            assert net["_id"] in msg
            assert net["external_id"] in msg
        client.put.assert_not_called()

    async def test_runs_without_confirm(self, client, registry):
        """No gate: the live PUT proceeds without confirm (controller is reached)."""
        client.get.side_effect = _router_for(_profile([_NET_GUEST["_id"]]))
        client.put.return_value = {"meta": {"rc": "ok"}, "data": [_profile([])]}
        result = await allow_network_on_port_profile(
            client, registry, "h", "s", _PROFILE_ID, _NET_GUEST["_id"]
        )
        client.put.assert_called_once()
        assert "error" not in result

    async def test_rejects_path_injection_network_id(self, client, registry):
        with pytest.raises(ValueError, match="network_id"):
            await allow_network_on_port_profile(
                client, registry, "h", "s", _PROFILE_ID, "../etc", confirm=True
            )
        client.get.assert_not_called()

    async def test_unknown_profile_lists_valid_profiles(self, client, registry):
        """An unknown profile id fails listing every profile (name and _id); the
        profile is resolved in the /rest/portconf list, never taken from a by-id read."""
        other = {**_profile([]), "_id": "65f1c0ffee0000000000bbbb", "name": "Uplinks"}
        client.get.side_effect = _classic_router(
            networkconf=_NETWORKCONF,
            **{f"portconf__{_PROFILE_ID}": {"meta": {"rc": "ok"}, "data": [other]}},
            portconf={"meta": {"rc": "ok"}, "data": [other]},
        )
        with pytest.raises(
            ValueError, match="not found; valid: 'Uplinks' \\(_id=65f1c0ffee0000000000bbbb\\)"
        ):
            await allow_network_on_port_profile(
                client, registry, "h", "s", _PROFILE_ID, _NET_GUEST["_id"], confirm=True
            )
        client.put.assert_not_called()

    async def test_unexpected_profile_shape_raises(self, client, registry):
        """A body that is not a Classic envelope raises with the shape received."""
        client.get.side_effect = _classic_router(
            networkconf=_NETWORKCONF, portconf={"unexpected": 1}
        )
        with pytest.raises(UniFiConnectionError, match="unexpected"):
            await allow_network_on_port_profile(
                client, registry, "h", "s", _PROFILE_ID, _NET_GUEST["_id"]
            )
        client.put.assert_not_called()

    async def test_put_without_profile_is_reported_not_invented(self, client, registry):
        client.get.side_effect = _router_for(_profile([_NET_GUEST["_id"]]))
        client.put.return_value = {"meta": {"rc": "ok"}, "data": []}
        result = await allow_network_on_port_profile(
            client, registry, "h", "s", _PROFILE_ID, _NET_GUEST["_id"]
        )
        assert result["data"] == []
        assert "_profileNote" in result
        assert result["_tagged_networks"] == [
            {"id": _NET_IOT["_id"], "name": "IoT", "vlan": 40},
            {"id": _NET_GUEST["_id"], "name": "Guest", "vlan": 3111},
        ]


class TestExcludeNetworkOnPortProfile:
    async def test_runs_without_confirm(self, client, registry):
        client.get.side_effect = _router_for(_profile([]))
        client.put.return_value = {"meta": {"rc": "ok"}, "data": [_profile([_NET_GUEST["_id"]])]}
        result = await exclude_network_on_port_profile(
            client, registry, "h", "s", _PROFILE_ID, _NET_GUEST["_id"]
        )
        client.put.assert_called_once()
        assert "error" not in result

    async def test_integration_id_writes_the_classic_id(self, client, registry):
        client.get.side_effect = _router_for(_profile([_NET_IOT["_id"]]))
        client.put.return_value = {
            "meta": {"rc": "ok"},
            "data": [_profile([_NET_IOT["_id"], _NET_GUEST["_id"]])],
        }
        await exclude_network_on_port_profile(
            client, registry, "h", "s", _PROFILE_ID, _NET_GUEST["external_id"], confirm=True
        )
        put_json = client.put.call_args.kwargs["json"]
        assert put_json["excluded_networkconf_ids"] == [_NET_IOT["_id"], _NET_GUEST["_id"]]

    async def test_idempotent_when_already_excluded(self, client, registry):
        client.get.side_effect = _router_for(_profile([_NET_GUEST["_id"]]))
        client.put.return_value = {"meta": {"rc": "ok"}, "data": [_profile([_NET_GUEST["_id"]])]}
        await exclude_network_on_port_profile(
            client, registry, "h", "s", _PROFILE_ID, _NET_GUEST["external_id"], confirm=True
        )
        put_json = client.put.call_args.kwargs["json"]
        assert put_json["excluded_networkconf_ids"] == [_NET_GUEST["_id"]]

    async def test_unknown_network_fails_before_write(self, client, registry):
        client.get.side_effect = _router_for(_profile([]))
        with pytest.raises(ValueError, match="valid: LAN \\(vlan 1\\)"):
            await exclude_network_on_port_profile(
                client, registry, "h", "s", _PROFILE_ID, "65f1c0ffee0000000000ffff"
            )
        client.put.assert_not_called()


class TestAnnotateAutoExclusions:
    def _portconf(self) -> dict[str, Any]:
        return {
            "meta": {"rc": "ok"},
            "data": [
                {
                    "_id": "pp-1",
                    "name": "Estate Trunk",
                    "tagged_vlan_mgmt": "custom",
                    "excluded_networkconf_ids": [_NET_GUEST["_id"]],
                },
                {
                    "_id": "pp-2",
                    "name": "Auto Profile",
                    "tagged_vlan_mgmt": "auto",
                    "excluded_networkconf_ids": [_NET_GUEST["_id"]],
                },
                {
                    "_id": "pp-3",
                    "name": "Other Custom",
                    "tagged_vlan_mgmt": "custom",
                    "excluded_networkconf_ids": [],
                },
            ],
        }

    async def test_warning_fires_for_the_integration_id_create_network_returns(
        self, client, registry
    ):
        """H2/D12: create_network returns the Integration id; profiles hold the Classic
        _id. The warning must still fire (mapped through networkconf external_id)."""
        created = {"id": _NET_GUEST["external_id"], "name": "Guest", "vlanId": 3111}
        client.get.side_effect = _classic_router(
            networkconf=_NETWORKCONF, portconf=self._portconf()
        )
        result = await annotate_auto_exclusions(client, registry, "h", "s", created)
        assert result["name"] == "Guest"
        assert len(result["_warnings"]) == 1
        warning = result["_warnings"][0]
        assert warning["code"] == "D12_AUTO_EXCLUSION"
        assert warning["remediation_tool"] == "allow_network_on_port_profile"
        assert warning["networkconf_id"] == _NET_GUEST["_id"]
        # only the custom-tagged profile that actually excludes the new net
        assert warning["profiles"] == [{"id": "pp-1", "name": "Estate Trunk"}]
        assert "3111" in warning["message"]

    async def test_no_warning_when_not_excluded(self, client, registry):
        created = {"id": _NET_IOT["external_id"], "vlanId": 40}
        client.get.side_effect = _classic_router(
            networkconf=_NETWORKCONF, portconf=self._portconf()
        )
        result = await annotate_auto_exclusions(client, registry, "h", "s", created)
        assert "_warnings" not in result

    async def test_unlinked_id_reports_check_failed(self, client, registry):
        created = {"id": "3fa85f64-5717-4562-b3fc-2c963f66ffff", "vlanId": 9}
        client.get.side_effect = _classic_router(
            networkconf=_NETWORKCONF, portconf=self._portconf()
        )
        result = await annotate_auto_exclusions(client, registry, "h", "s", created)
        assert [w["code"] for w in result["_warnings"]] == ["D12_CHECK_FAILED"]
        assert "external_id" in result["_warnings"][0]["message"]

    async def test_non_dict_body_is_kept_whole_under_response(self, client, registry):
        result = await annotate_auto_exclusions(client, registry, "h", "s", ["x"])
        assert result["response"] == ["x"]
        assert [w["code"] for w in result["_warnings"]] == ["D12_CHECK_FAILED"]
        client.get.assert_not_called()


# --- Routing Table (Classic REST) ---


class TestListRoutingEntries:
    async def test_uses_classic_rest_url(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "rt-1", "network": "10.0.0.0/8"}],
        }
        result = await list_routing_entries(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/routing", key=None)
        assert result["data"] == [{"_id": "rt-1", "network": "10.0.0.0/8"}]


# --- WLAN Configs (Classic REST) ---


class TestListWlanConfigs:
    async def test_uses_classic_rest_url(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "wlan-1", "name": "HomeSSID"}],
        }
        result = await list_wlan_configs(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/wlanconf", key=None)
        assert result["data"] == [{"_id": "wlan-1", "name": "HomeSSID"}]

    async def test_x_passphrase_survives(self, client, registry):
        # Data-survival: the WLAN passphrase reaches the operator who owns it.
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "wlan-1", "name": "HomeSSID", "x_passphrase": "secret123"}],
        }
        result = await list_wlan_configs(client, registry, "h", "s")
        assert result["data"] == [
            {"_id": "wlan-1", "name": "HomeSSID", "x_passphrase": "secret123"}
        ]


class TestGetWlanConfig:
    async def test_uses_classic_rest_url_with_id(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "wlan-1"}]}
        result = await get_wlan_config(client, registry, "h", "s", "wlan-1")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/wlanconf/wlan-1", key=None)
        assert result["data"] == [{"_id": "wlan-1"}]

    async def test_x_passphrase_survives(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "wlan-1", "x_passphrase": "secret123"}],
        }
        result = await get_wlan_config(client, registry, "h", "s", "wlan-1")
        assert result["data"] == [{"_id": "wlan-1", "x_passphrase": "secret123"}]


class TestUpdateWlanConfig:
    async def test_puts_to_classic_rest(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "wlan-1"}]}
        payload = {"x_passphrase": "newpassword123"}
        client.put.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "wlan-1", **payload}]}
        result = await update_wlan_config(client, registry, "h", "s", "wlan-1", payload)
        client.put.assert_called_once_with(
            f"{CLASSIC_REST_BASE}/wlanconf/wlan-1", key=None, json=payload
        )
        assert result["data"][0]["x_passphrase"] == "newpassword123"

    async def test_strips_empty_strings_from_list_fields(self, client, registry):
        """A WLAN config read back with a padded list field (e.g. a
        MAC filter list) round-trips cleanly without the empties."""
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "wlan-1"}]}
        payload = {"name": "HomeSSID", "mac_filter_list": ["aa:bb:cc:dd:ee:ff", "", ""]}
        client.put.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "wlan-1"}]}
        await update_wlan_config(client, registry, "h", "s", "wlan-1", payload)
        client.put.assert_called_once_with(
            f"{CLASSIC_REST_BASE}/wlanconf/wlan-1",
            key=None,
            json={"name": "HomeSSID", "mac_filter_list": ["aa:bb:cc:dd:ee:ff"]},
        )


# --- WLAN Groups (Classic REST) ---


class TestListWlanGroups:
    async def test_uses_classic_rest_url(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "wg-1", "name": "Default"}],
        }
        result = await list_wlan_groups(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/wlangroup", key=None)
        assert result["data"] == [{"_id": "wg-1", "name": "Default"}]


class TestGetWlanGroup:
    """GET /rest/wlangroup/{id} is rejected upstream (HTTP 400 api.err.InvalidObject for
    every id, including the built-in Default group), so the tool reads the collection
    route and selects the requested group by _id."""

    _DEFAULT = {
        "_id": "000000000000000000000001",
        "name": "Default",
        "site_id": "site-uuid",
        "attr_no_delete": True,
        "attr_hidden_id": "Default",
    }
    _OTHER = {"_id": "65f1c0ffee0123456789abcd", "name": "Guests", "future_field": {"x": 1}}

    async def test_reads_collection_route_not_by_id_route(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [self._DEFAULT]}
        await get_wlan_group(client, registry, "h", "s", "000000000000000000000001")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/wlangroup", key=None)

    async def test_returns_matching_group_unchanged_as_one_item_list(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [self._DEFAULT, self._OTHER]}
        result = await get_wlan_group(client, registry, "h", "s", "65f1c0ffee0123456789abcd")
        assert result["data"] == [self._OTHER]
        assert result["data"][0] is self._OTHER  # same object: no field added or renamed
        assert result["meta"] == {"rc": "ok"}

    async def test_builtin_default_group_is_found(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [self._DEFAULT, self._OTHER]}
        result = await get_wlan_group(client, registry, "h", "s", "000000000000000000000001")
        assert result["data"] == [self._DEFAULT]

    async def test_unknown_id_fails_listing_valid_groups(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [self._DEFAULT, self._OTHER]}
        with pytest.raises(ValueError) as exc:
            await get_wlan_group(client, registry, "h", "s", "no-such-group")
        msg = str(exc.value)
        assert "WLAN group 'no-such-group' not found" in msg
        assert "Default (000000000000000000000001)" in msg
        assert "Guests (65f1c0ffee0123456789abcd)" in msg

    async def test_unexpected_shape_raises_with_the_shape(self, client, registry):
        client.get.return_value = "not-json-object"
        with pytest.raises(UniFiConnectionError, match="str"):
            await get_wlan_group(client, registry, "h", "s", "000000000000000000000001")

    async def test_invalid_id_rejected_before_upstream_call(self, client, registry):
        with pytest.raises(ValueError):
            await get_wlan_group(client, registry, "h", "s", "../wlanconf")
        client.get.assert_not_called()


# --- Channel Plan (Classic REST) ---


class TestGetChannelPlan:
    async def test_uses_classic_rest_url(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"radio": "ng", "channel": 6, "ht": "HT20"}],
        }
        result = await get_channel_plan(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/channelplan", key=None)
        assert result["data"] == [{"radio": "ng", "channel": 6, "ht": "HT20"}]

    async def test_empty_returned_verbatim(self, client, registry):
        """No channel plan stored = the controller's empty list, not an invented message."""
        client.get.return_value = {"meta": {"rc": "ok"}, "data": []}
        assert await get_channel_plan(client, registry, "h", "s") == client.get.return_value


# --- Rogue APs (Classic Stat) ---


class TestListRogueAps:
    async def test_uses_classic_stat_url(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"bssid": "aa:bb:cc:dd:ee:ff", "ssid": "EvilAP", "channel": 11}],
        }
        result = await list_rogue_aps(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{CLASSIC_STAT_BASE}/rogueap", key=None)
        assert result["data"] == [{"bssid": "aa:bb:cc:dd:ee:ff", "ssid": "EvilAP", "channel": 11}]

    async def test_resolves_slug_not_uuid(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": []}
        await list_rogue_aps(client, registry, "h", "s")
        registry.resolve_site_slug.assert_called_once_with("s", HOST_ID, key=None)
        registry.resolve_site_id.assert_not_called()

    async def test_rogue_only_filters_confirmed_rogues(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [
                {"bssid": "aa:bb:cc:dd:ee:01", "is_rogue": True},
                {"bssid": "aa:bb:cc:dd:ee:02", "is_rogue": False},
                {"bssid": "aa:bb:cc:dd:ee:03"},
            ],
        }
        result = await list_rogue_aps(client, registry, "h", "s", rogue_only=True)
        assert result["data"] == [{"bssid": "aa:bb:cc:dd:ee:01", "is_rogue": True}]

    async def test_rogue_only_false_returns_all(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [
                {"bssid": "aa:bb:cc:dd:ee:01", "is_rogue": True},
                {"bssid": "aa:bb:cc:dd:ee:02", "is_rogue": False},
            ],
        }
        result = await list_rogue_aps(client, registry, "h", "s", rogue_only=False)
        assert len(result) == 2


# --- Classic Firewall Rules (Classic REST) ---


class TestListFirewallRules:
    async def test_uses_classic_rest_url(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "fr-1", "name": "Block Telnet", "action": "drop"}],
        }
        result = await list_firewall_rules(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/firewallrule", key=None)
        assert result["data"] == [{"_id": "fr-1", "name": "Block Telnet", "action": "drop"}]


class TestCreateFirewallRule:
    async def test_posts_to_ea_route_and_preserves_body_and_response(self, client, registry):
        rule = {
            "name": "Synthetic allow rule",
            "action": "accept",
            "protocol": "future-controller-value",
            "synthetic_extension": {"survives": True},
        }
        response = {
            "meta": {"rc": "ok"},
            "data": [{**rule, "_id": "000000000000000000000321"}],
        }
        client.post.return_value = response
        result = await create_firewall_rule(client, registry, "h", "s", rule)
        client.post.assert_awaited_once_with(
            "/ea/sites/000000000000000000000123/rest/firewallrule",
            key=None,
            json=rule,
        )
        registry.resolve_ea_site_id.assert_awaited_once_with("s", host_id=HOST_ID, key=None)
        assert result is response
        assert result["data"][0]["synthetic_extension"] == {"survives": True}

    @pytest.mark.parametrize("rule", [{}, {"name": "Synthetic rule"}])
    async def test_unspecced_payload_forwarded_unchanged(self, client, registry, rule):
        response = {"meta": {"rc": "ok"}, "data": []}
        client.post.return_value = response
        result = await create_firewall_rule(client, registry, "h", "s", rule)
        client.post.assert_awaited_once_with(
            "/ea/sites/000000000000000000000123/rest/firewallrule", key=None, json=rule
        )
        assert result is response

    async def test_non_object_refused_before_resolution_or_request(self, client, registry):
        with pytest.raises(ValueError, match="JSON object"):
            await create_firewall_rule(client, registry, "h", "s", [])
        registry.resolve_key_for_host.assert_not_awaited()
        client.post.assert_not_awaited()

    async def test_unknown_site_error_keeps_valid_choices(self, client, registry):
        registry.resolve_ea_site_id.side_effect = ValueError(
            "Site 'missing' not found; valid: Default (000000000000000000000123)"
        )
        with pytest.raises(ValueError, match="valid: Default"):
            await create_firewall_rule(
                client,
                registry,
                "h",
                "missing",
                {"name": "Synthetic rule", "action": "accept"},
            )
        client.post.assert_not_awaited()


class TestGetFirewallRule:
    async def test_uses_classic_rest_url_with_id(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "fr-1"}]}
        result = await get_firewall_rule(client, registry, "h", "s", "fr-1")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/firewallrule/fr-1", key=None)
        assert result["data"] == [{"_id": "fr-1"}]


async def test_create_firewall_rule_routes_to_owning_key(multikey_client, multikey_registry):
    for label, hosts in MULTIKEY_HOSTS_BY_LABEL.items():
        await multikey_registry.set_hosts(hosts, key=multikey_client.get_key_by_label(label))
    multikey_registry.resolve_host_id = AsyncMock(return_value="console-beta-1")
    multikey_registry.resolve_ea_site_id = AsyncMock(return_value="000000000000000000000123")
    captured: dict[str, object] = {}

    async def _post(path, *, key=None, json=None, params=None):
        captured.update(path=path, key=key, json=json, params=params)
        return {"meta": {"rc": "ok"}, "data": []}

    multikey_client.post = AsyncMock(side_effect=_post)
    rule = {"name": "Synthetic beta rule", "action": "accept"}
    await create_firewall_rule(multikey_client, multikey_registry, "Beta-Branch", "Default", rule)
    assert captured["key"] is not None and captured["key"].label == "beta"
    assert captured["path"] == "/ea/sites/000000000000000000000123/rest/firewallrule"
    assert captured["json"] is rule


# --- Firewall Groups (Classic REST) ---


class TestListFirewallGroups:
    async def test_uses_classic_rest_url(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "fg-1", "name": "RFC1918", "group_type": "address-group"}],
        }
        result = await list_firewall_groups(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/firewallgroup", key=None)
        assert result["data"] == [{"_id": "fg-1", "name": "RFC1918", "group_type": "address-group"}]


class TestGetFirewallGroup:
    async def test_uses_classic_rest_url_with_id(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "fg-1"}]}
        result = await get_firewall_group(client, registry, "h", "s", "fg-1")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/firewallgroup/fg-1", key=None)
        assert result["data"] == [{"_id": "fg-1"}]


# --- RADIUS Accounts (Classic REST) ---


class TestListAccounts:
    async def test_uses_classic_rest_url(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "acc-1", "name": "jdoe", "x_password": "secret"}],
        }
        result = await list_accounts(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/account", key=None)
        assert result["data"] == [{"_id": "acc-1", "name": "jdoe", "x_password": "secret"}]

    async def test_x_password_survives(self, client, registry):
        # Data-survival: RADIUS account credentials pass through verbatim.
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "acc-1", "name": "jdoe", "x_password": "secret"}],
        }
        result = await list_accounts(client, registry, "h", "s")
        assert result["data"] == [{"_id": "acc-1", "name": "jdoe", "x_password": "secret"}]


class TestGetAccount:
    async def test_uses_classic_rest_url_with_id(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "acc-1"}]}
        result = await get_account(client, registry, "h", "s", "acc-1")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/account/acc-1", key=None)
        assert result["data"] == [{"_id": "acc-1"}]

    async def test_x_password_survives(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "acc-1", "name": "jdoe", "x_password": "secret"}],
        }
        result = await get_account(client, registry, "h", "s", "acc-1")
        assert result["data"] == [{"_id": "acc-1", "name": "jdoe", "x_password": "secret"}]


# --- Hotspot Packages (Classic REST) ---


class TestListHotspotPackages:
    async def test_uses_classic_rest_url(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "pkg-1", "name": "Day Pass", "price": 5}],
        }
        result = await list_hotspot_packages(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/hotspotpackage", key=None)
        assert result["data"] == [{"_id": "pkg-1", "name": "Day Pass", "price": 5}]


class TestGetHotspotPackage:
    async def test_uses_classic_rest_url_with_id(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "pkg-1"}]}
        result = await get_hotspot_package(client, registry, "h", "s", "pkg-1")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/hotspotpackage/pkg-1", key=None)
        assert result["data"] == [{"_id": "pkg-1"}]


# --- Scheduled Tasks (Classic REST) ---


def _scheduled_tasks_body():
    """Fresh synthetic identifiers/values in the live response shape."""
    return {
        "meta": {"rc": "ok"},
        "data": [
            {
                "_id": "00000000-0000-4000-a000-000000000001",
                "name": "name-0001",
                "action": "quick-scan",
                "cron_expr": "0 3 * * *",
                "timezone": "America/Chicago",
                "site_id": "00000000-0000-4000-a000-000000000021",
                "execute_only_once": False,
            },
            {
                "_id": "00000000-0000-4000-a000-000000000002",
                "name": "name-0001",
                "action": "upgrade",
                "cron_expr": "0 4 * * 3",
                "site_id": "00000000-0000-4000-a000-000000000021",
                "execute_only_once": False,
                "upgrade_targets": [
                    {"mac": "02:00:5e:00:00:23"},
                    {"mac": "02:00:5e:00:00:24"},
                    {"mac": "02:00:5e:00:00:25"},
                ],
            },
            {
                "_id": "00000000-0000-4000-a000-000000000003",
                "name": "name-0001",
                "action": "speedtest",
                "cron_expr": "36 9 * * *",
                "timezone": "UTC",
                "site_id": "00000000-0000-4000-a000-000000000021",
                "execute_only_once": False,
            },
        ],
    }


class TestListScheduledTasks:
    async def test_uses_classic_rest_url(self, client, registry):
        body = _scheduled_tasks_body()
        client.get.return_value = body
        result = await list_scheduled_tasks(client, registry, "h", "s")
        assert result["data"][0]["action"] == "quick-scan"
        assert result["data"][0]["cron_expr"] == "0 3 * * *"
        assert result["data"][0]["execute_only_once"] is False
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/scheduletask", key=None)
        assert result == body
        assert [task["action"] for task in result["data"]] == ["quick-scan", "upgrade", "speedtest"]
        assert "timezone" not in result["data"][1]
        assert len(result["data"][1]["upgrade_targets"]) == 3


class TestGetScheduledTask:
    async def test_uses_classic_rest_url_with_id(self, client, registry):
        body = {"meta": {"rc": "ok"}, "data": [_scheduled_tasks_body()["data"][0]]}
        client.get.return_value = body
        result = await get_scheduled_task(
            client, registry, "h", "s", "00000000-0000-4000-a000-000000000001"
        )
        client.get.assert_called_once_with(
            f"{CLASSIC_REST_BASE}/scheduletask/00000000-0000-4000-a000-000000000001", key=None
        )
        assert result == body


# --- DPI Categories ---


class TestListDpiCategories:
    async def test_drains_all_by_default(self, client, registry):
        rows = [{"id": "cat-1", "name": "Social Media"}]
        client.get.side_effect = [rows, []]
        result = await list_dpi_categories(client, registry, "h")
        assert all(
            request.args == (f"{BASE}/dpi/categories",) for request in client.get.call_args_list
        )
        assert client.get.call_count == 2
        assert result == {"data": [{"id": "cat-1", "name": "Social Media"}], "totalCount": None}

        assert client.get.call_count == 2
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == [0, 1]
        for request in client.get.call_args_list:
            assert request.args == (f"{BASE}/dpi/categories",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }
        assert result["data"] == rows
        assert result["totalCount"] is None
        assert "incomplete" not in result
        assert "_incomplete" not in result

    async def test_resolves_host(self, client, registry):
        client.get.return_value = []
        await list_dpi_categories(client, registry, "UDM-Pro")
        registry.resolve_host_id.assert_called_once_with("UDM-Pro", key=None)
        registry.resolve_site_id.assert_not_called()

    async def test_with_offset_and_limit_single_page(self, client, registry):
        client.get.return_value = {"data": [], "totalCount": 40}
        await list_dpi_categories(client, registry, "h", offset=10, limit=25)
        client.get.assert_called_once_with(
            f"{BASE}/dpi/categories", key=None, params={"offset": 10, "limit": 25}
        )
        client.paginate_offset.assert_not_called()

    async def test_limit_only(self, client, registry):
        client.get.return_value = {"data": [], "totalCount": 40}
        await list_dpi_categories(client, registry, "h", limit=10)
        client.get.assert_called_once_with(f"{BASE}/dpi/categories", key=None, params={"limit": 10})

    async def test_cap_exceeded_marked_incomplete(self, client, registry):
        rows = [{"id": "cat-1"}] + [
            dict({"id": "cat-1"}, id=f"extra-{index}") for index in range(1, 2)
        ]
        client.paginate_max_pages = 2
        client.get.side_effect = [{"data": [row], "limit": 1} for row in rows]
        result = await list_dpi_categories(client, registry, "h")
        assert result["incomplete"] is True
        assert result["data"] == rows
        assert client.get.call_count == 2
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == list(
            range(2)
        )


# --- DPI Applications ---


class TestListDpiApplications:
    async def test_drains_all_by_default(self, client, registry):
        rows = [{"id": "app-1", "name": "YouTube", "categoryId": "cat-1"}]
        client.get.side_effect = [rows, []]
        result = await list_dpi_applications(client, registry, "h")
        assert all(
            request.args == (f"{BASE}/dpi/applications",) for request in client.get.call_args_list
        )
        assert client.get.call_count == 2
        assert result == {
            "data": [{"id": "app-1", "name": "YouTube", "categoryId": "cat-1"}],
            "totalCount": None,
        }

        assert client.get.call_count == 2
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == [0, 1]
        for request in client.get.call_args_list:
            assert request.args == (f"{BASE}/dpi/applications",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }
        assert result["data"] == rows
        assert result["totalCount"] is None
        assert "incomplete" not in result
        assert "_incomplete" not in result

    async def test_resolves_host(self, client, registry):
        client.get.return_value = []
        await list_dpi_applications(client, registry, "UDM-Pro")
        registry.resolve_host_id.assert_called_once_with("UDM-Pro", key=None)
        registry.resolve_site_id.assert_not_called()

    async def test_with_offset_and_limit_single_page(self, client, registry):
        client.get.return_value = {"data": [], "totalCount": 80}
        await list_dpi_applications(client, registry, "h", offset=5, limit=50)
        client.get.assert_called_once_with(
            f"{BASE}/dpi/applications", key=None, params={"offset": 5, "limit": 50}
        )
        client.paginate_offset.assert_not_called()

    async def test_limit_only(self, client, registry):
        client.get.return_value = {"data": [], "totalCount": 80}
        await list_dpi_applications(client, registry, "h", limit=25)
        client.get.assert_called_once_with(
            f"{BASE}/dpi/applications", key=None, params={"limit": 25}
        )


def test_traffic_matching_list_id_refs_name_source_tool():
    import asyncio
    import inspect

    from unifi_fabric import server

    result = server.mcp.list_tools()
    tools = asyncio.run(result) if inspect.isawaitable(result) else result
    by_name = {t.name: t for t in tools}
    for name in (
        "get_traffic_matching_list",
        "update_traffic_matching_list",
        "delete_traffic_matching_list",
    ):
        desc = by_name[name].parameters["properties"]["list_id"]["description"]
        assert "list_traffic_matching_lists" in desc, name
    for name in ("create_traffic_rule", "create_traffic_route"):
        assert "list_traffic_matching_lists" in (by_name[name].description or ""), name


@pytest.mark.parametrize(
    "put_body",
    [
        {"meta": {"rc": "ok"}, "data": [{"upstreamOnly": "preserved"}]},
        ["upstream", {"accepted": True}],
    ],
)
async def test_setting_partial_rejection_keeps_successful_put_body(client, registry, put_body):
    pre = {
        "meta": {"rc": "ok"},
        "data": [{"key": "mgmt", "radius": {"port": 1812, "enabled": False}}],
    }
    after = {
        "meta": {"rc": "ok"},
        "data": [{"key": "mgmt", "radius": {"port": 1813, "enabled": False}}],
    }
    client.get.side_effect = [pre, after]
    client.put.return_value = put_body
    result = await update_setting(
        client, registry, "h", "s", "mgmt", {"radius": {"port": 1813, "enabled": True}}
    )
    if isinstance(put_body, dict):
        assert {name: result[name] for name in put_body} == put_body
    else:
        assert result["response"] == put_body
    assert result["_verified"] is False
    assert result["_unverifiedFields"] == ["radius.enabled"]
    assert "radius.enabled" in result["_verificationNote"]
    assert "radius.port" in result["_verificationNote"]
    client.put.assert_awaited_once()


@pytest.mark.parametrize(
    "operation", [allow_network_on_port_profile, exclude_network_on_port_profile]
)
@pytest.mark.parametrize(
    "put_body",
    [
        {"meta": {"rc": "ok"}, "data": 42},
        {"meta": {"rc": "ok"}, "data": {"upstreamOnly": True}},
        {"meta": {"rc": "ok"}, "data": "accepted"},
        {"meta": {"rc": "ok"}, "data": None},
        {"upstreamOnly": True},
        ["accepted"],
        42,
        None,
    ],
)
async def test_port_profile_non_list_put_body_is_unchanged(client, registry, operation, put_body):
    client.get.side_effect = _router_for(_profile([_NET_GUEST["_id"]]))
    client.put.return_value = put_body
    result = await operation(client, registry, "h", "s", _PROFILE_ID, _NET_GUEST["_id"])
    assert result == put_body
    client.put.assert_awaited_once()
    # Only the required reads precede the PUT; no response enrichment is attempted.
    assert client.get.await_count == 2


@pytest.mark.parametrize(
    "name", ["allow_network_on_port_profile", "exclude_network_on_port_profile"]
)
@pytest.mark.parametrize(
    "put_body",
    [
        {"meta": {"rc": "ok"}, "data": 42},
        {"meta": {"rc": "ok"}, "data": {"upstreamOnly": True}},
        {"meta": {"rc": "ok"}, "data": "accepted"},
        {"meta": {"rc": "ok"}, "data": None},
        {"upstreamOnly": True},
        ["accepted"],
        42,
        None,
        "accepted",
        True,
    ],
)
async def test_registered_port_profile_preserves_all_upstream_json_bodies(
    monkeypatch, name, put_body
):
    class WriteBodyUpstream(uh.FakeUpstream):
        def __call__(self, request):
            response = super().__call__(request)
            if request.method == "PUT":
                self.served[-1].body = copy.deepcopy(put_body)
                return httpx.Response(
                    200,
                    content=json.dumps(put_body),
                    headers={"Content-Type": "application/json"},
                )
            return response

    upstream = WriteBodyUpstream()
    client = uh.install(monkeypatch, upstream, tool_mode="full")
    try:
        result = await server.mcp.call_tool(
            name,
            {
                "host": uh.HOST,
                "site": uh.SITE,
                **tool_args.OVERRIDES[name],
            },
        )
        payload = uh.result_payload(result)
        if not isinstance(put_body, dict) and isinstance(payload, dict):
            assert set(payload) == {"result"}
            payload = payload["result"]
        assert type(payload) is type(put_body)
        assert payload == put_body
        writes = upstream.writes()
        assert len(writes) == 1
        assert writes[0].method == "PUT"
        assert writes[0].body == put_body
    finally:
        await client.close()


class TestUpdatePortProfileNetworkIds:
    """update_port_profile writes Classic networkconf ``_id`` values: a caller holding the
    Integration id from list_networks gets it converted before the PUT (cold-agent
    rehearsal F-1), and an unknown value fails before any write."""

    async def test_integration_id_maps_to_classic_id_in_put_body(self, client, registry):
        client.get.side_effect = _router_for(_profile([]))
        client.put.return_value = {"meta": {"rc": "ok"}, "data": [_profile([])]}
        await update_port_profile(
            client,
            registry,
            "h",
            "s",
            _PROFILE_ID,
            {"native_networkconf_id": _NET_GUEST["external_id"]},
        )
        put_json = client.put.call_args.kwargs["json"]
        assert put_json["native_networkconf_id"] == _NET_GUEST["_id"]
        assert client.put.call_args.args[0] == f"{CLASSIC_REST_BASE}/portconf/{_PROFILE_ID}"

    async def test_classic_id_passes_through_unchanged(self, client, registry):
        client.get.side_effect = _router_for(_profile([]))
        client.put.return_value = {"meta": {"rc": "ok"}, "data": [_profile([])]}
        payload = {
            "native_networkconf_id": _NET_LAN["_id"],
            "voice_networkconf_id": _NET_IOT["_id"],
            "poe_mode": "auto",
        }
        await update_port_profile(client, registry, "h", "s", _PROFILE_ID, dict(payload))
        assert client.put.call_args.kwargs["json"] == payload

    async def test_list_field_maps_every_element(self, client, registry):
        client.get.side_effect = _router_for(_profile([]))
        client.put.return_value = {"meta": {"rc": "ok"}, "data": [_profile([])]}
        await update_port_profile(
            client,
            registry,
            "h",
            "s",
            _PROFILE_ID,
            {
                "excluded_networkconf_ids": [
                    _NET_GUEST["external_id"],
                    _NET_IOT["_id"],
                    "LAN",
                ]
            },
        )
        assert client.put.call_args.kwargs["json"]["excluded_networkconf_ids"] == [
            _NET_GUEST["_id"],
            _NET_IOT["_id"],
            _NET_LAN["_id"],
        ]

    async def test_networkconf_read_once_and_skipped_without_id_fields(self, client, registry):
        client.get.side_effect = _router_for(_profile([]))
        client.put.return_value = {"meta": {"rc": "ok"}, "data": [_profile([])]}
        await update_port_profile(
            client,
            registry,
            "h",
            "s",
            _PROFILE_ID,
            {
                "native_networkconf_id": _NET_LAN["external_id"],
                "excluded_networkconf_ids": [_NET_GUEST["external_id"]],
            },
        )
        reads = [c.args[0] for c in client.get.call_args_list]
        put_index = len(reads)
        # one networkconf read before the PUT (the read-after resolution follows it)
        pre_put = [r for r in reads[: put_index - 1] if r.endswith("/networkconf")]
        assert len(pre_put) == 1
        client.get.reset_mock()
        client.get.side_effect = _router_for(_profile([]))
        await update_port_profile(client, registry, "h", "s", _PROFILE_ID, {"poe_mode": "off"})
        reads = [c.args[0] for c in client.get.call_args_list]
        # without id fields: the portconf lookup, then only the read-after networkconf read
        assert reads[0].endswith("/portconf")
        assert sum(r.endswith("/networkconf") for r in reads) == 1

    async def test_value_the_profile_already_holds_passes_unchanged(self, client, registry):
        """A read result with a stale reference (no networkconf document) round-trips."""
        stale = "65f1c0ffee000000000000ff"
        client.get.side_effect = _router_for(_profile([stale]))
        client.put.return_value = {"meta": {"rc": "ok"}, "data": [_profile([stale])]}
        await update_port_profile(
            client,
            registry,
            "h",
            "s",
            _PROFILE_ID,
            {"excluded_networkconf_ids": [stale, _NET_GUEST["external_id"]]},
        )
        assert client.put.call_args.kwargs["json"]["excluded_networkconf_ids"] == [
            stale,
            _NET_GUEST["_id"],
        ]

    @pytest.mark.parametrize(
        "payload",
        [
            {"native_networkconf_id": "3fa85f64-5717-4562-b3fc-2c963f66ffff"},
            {"excluded_networkconf_ids": [_NET_GUEST["external_id"], "no-such-network"]},
        ],
    )
    async def test_unknown_id_fails_with_zero_upstream_writes(self, client, registry, payload):
        client.get.side_effect = _router_for(_profile([]))
        with pytest.raises(ValueError) as exc:
            await update_port_profile(client, registry, "h", "s", _PROFILE_ID, payload)
        msg = str(exc.value)
        for net in _NETWORKCONF["data"]:
            assert net["name"] in msg
            assert net["_id"] in msg
            assert net["external_id"] in msg
        assert "list_networks" in msg
        client.put.assert_not_called()
        client.post.assert_not_called()
        client.delete.assert_not_called()
