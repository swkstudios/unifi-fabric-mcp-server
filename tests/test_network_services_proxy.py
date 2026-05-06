"""Tests for network_services_proxy — DNS, traffic lists, VPN, RADIUS, hotspot."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.tools.network import PROXY_BASE
from unifi_fabric.tools.network_services_proxy import (
    _CLASSIC_REST_BASE,
    _CLASSIC_STAT_BASE,
    _V2_API_BASE,
    bulk_delete_hotspot_vouchers,
    create_dns_policy,
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


# --- DNS Policies ---


class TestListDnsPolicies:
    async def test_basic(self, client, registry):
        client.get.return_value = [{"id": "dns-1", "name": "Default"}]
        result = await list_dns_policies(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/dns/policies")
        assert result == [{"id": "dns-1", "name": "Default"}]


class TestCreateDnsPolicy:
    async def test_basic(self, client, registry):
        payload = {"name": "Custom DNS"}
        client.post.return_value = {"id": "dns-2", **payload}
        result = await create_dns_policy(client, registry, "h", "s", payload)
        client.post.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/dns/policies", json=payload)
        assert result["name"] == "Custom DNS"


class TestGetDnsPolicy:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "dns-1", "name": "Default"}
        result = await get_dns_policy(client, registry, "h", "s", "dns-1")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/dns/policies/dns-1")
        assert result["id"] == "dns-1"


class TestUpdateDnsPolicy:
    async def test_basic(self, client, registry):
        payload = {"name": "Updated"}
        client.put.return_value = {"id": "dns-1", **payload}
        result = await update_dns_policy(client, registry, "h", "s", "dns-1", payload)
        client.put.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/dns/policies/dns-1", json=payload
        )
        assert result["name"] == "Updated"


class TestDeleteDnsPolicy:
    async def test_basic(self, client, registry):
        await delete_dns_policy(client, registry, "h", "s", "dns-1")
        client.delete.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/dns/policies/dns-1")


# --- Traffic Matching Lists ---


class TestListTrafficMatchingLists:
    async def test_basic(self, client, registry):
        client.get.return_value = [{"id": "tml-1", "name": "IoT Devices"}]
        result = await list_traffic_matching_lists(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/traffic-matching-lists")
        assert result == [{"id": "tml-1", "name": "IoT Devices"}]


class TestCreateTrafficMatchingList:
    async def test_basic(self, client, registry):
        payload = {"name": "Gaming"}
        client.post.return_value = {"id": "tml-2", **payload}
        result = await create_traffic_matching_list(client, registry, "h", "s", payload)
        client.post.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/traffic-matching-lists", json=payload
        )
        assert result["name"] == "Gaming"


class TestGetTrafficMatchingList:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "tml-1", "name": "IoT Devices"}
        result = await get_traffic_matching_list(client, registry, "h", "s", "tml-1")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/traffic-matching-lists/tml-1")
        assert result["id"] == "tml-1"


class TestUpdateTrafficMatchingList:
    async def test_basic(self, client, registry):
        payload = {"name": "Updated"}
        client.put.return_value = {"id": "tml-1", **payload}
        result = await update_traffic_matching_list(client, registry, "h", "s", "tml-1", payload)
        client.put.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/traffic-matching-lists/tml-1", json=payload
        )
        assert result["name"] == "Updated"


class TestDeleteTrafficMatchingList:
    async def test_basic(self, client, registry):
        await delete_traffic_matching_list(client, registry, "h", "s", "tml-1")
        client.delete.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/traffic-matching-lists/tml-1"
        )


# --- VPN Servers ---


class TestListVpnServers:
    async def test_basic(self, client, registry):
        client.get.return_value = [{"id": "vpn-1", "type": "wireguard"}]
        result = await list_vpn_servers(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/vpn/servers")
        assert result == [{"id": "vpn-1", "type": "wireguard"}]


class TestListSiteToSiteTunnels:
    async def test_basic(self, client, registry):
        client.get.return_value = [{"id": "tun-1", "status": "connected"}]
        result = await list_site_to_site_tunnels(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/vpn/site-to-site-tunnels")
        assert result == [{"id": "tun-1", "status": "connected"}]


# --- RADIUS Profiles ---


class TestListRadiusProfiles:
    async def test_basic(self, client, registry):
        client.get.return_value = [{"id": "rad-1", "name": "Corp Auth"}]
        result = await list_radius_profiles(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/radius/profiles")
        assert result == [{"id": "rad-1", "name": "Corp Auth"}]


# --- Hotspot Vouchers ---


class TestListHotspotVouchers:
    async def test_basic(self, client, registry):
        client.get.return_value = [{"id": "v-1", "code": "ABC123"}]
        result = await list_hotspot_vouchers(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/hotspot/vouchers")
        assert result == [{"id": "v-1", "code": "ABC123"}]


class TestCreateHotspotVouchers:
    async def test_basic(self, client, registry):
        payload = {"count": 5, "duration": 3600}
        client.post.return_value = [{"id": "v-1"}, {"id": "v-2"}]
        result = await create_hotspot_vouchers(client, registry, "h", "s", payload)
        client.post.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/hotspot/vouchers", json=payload
        )
        assert len(result) == 2


class TestGetHotspotVoucher:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "v-1", "code": "ABC123"}
        result = await get_hotspot_voucher(client, registry, "h", "s", "v-1")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/hotspot/vouchers/v-1")
        assert result["code"] == "ABC123"


class TestDeleteHotspotVoucher:
    async def test_basic(self, client, registry):
        await delete_hotspot_voucher(client, registry, "h", "s", "v-1")
        client.delete.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/hotspot/vouchers/v-1")


class TestBulkDeleteHotspotVouchers:
    async def test_basic(self, client, registry):
        params = {"expired": True}
        await bulk_delete_hotspot_vouchers(client, registry, "h", "s", params)
        client.delete.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/hotspot/vouchers", params=params
        )


# --- Supporting Resources ---


class TestListDeviceTags:
    async def test_basic(self, client, registry):
        client.get.return_value = [{"id": "tag-1", "name": "IoT"}]
        result = await list_device_tags(client, registry, "h", "s")
        assert result == [{"id": "tag-1", "name": "IoT"}]
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/device-tags")


class TestListCountries:
    async def test_basic(self, client, registry):
        client.get.return_value = [{"code": "US", "name": "United States"}]
        result = await list_countries(client, registry, "h")
        assert result == [{"code": "US", "name": "United States"}]
        client.get.assert_called_once_with(f"{BASE}/countries")
        registry.resolve_site_id.assert_not_called()


# --- Port Forwards (Classic REST API) ---


class TestListPortForwards:
    async def test_uses_classic_rest_url(self, client, registry):
        client.get.return_value = {"data": [{"_id": "pf-1", "name": "SSH"}]}
        result = await list_port_forwards(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/portforward")
        assert result == {"data": [{"_id": "pf-1", "name": "SSH"}]}

    async def test_resolves_slug_not_uuid(self, client, registry):
        client.get.return_value = {}
        await list_port_forwards(client, registry, "h", "s")
        registry.resolve_site_slug.assert_called_once_with("s", HOST_ID)
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
        client.post.assert_called_once_with(f"{CLASSIC_REST_BASE}/portforward", json=payload)
        assert result["_id"] == "pf-new"

    async def test_empty_payload_rejected(self, client, registry):
        with pytest.raises(ValueError, match="create_port_forward requires"):
            await create_port_forward(client, registry, "h", "s", {})

    async def test_missing_fields_rejected(self, client, registry):
        payload = {"name": "SSH", "dst_port": "2222"}  # missing fwd and fwd_port
        with pytest.raises(ValueError, match="create_port_forward requires"):
            await create_port_forward(client, registry, "h", "s", payload)

    async def test_valid_payload_with_all_required_fields(self, client, registry):
        payload = {
            "name": "HTTP",
            "dst_port": "8080",
            "fwd": "192.168.1.20",
            "fwd_port": "80",
        }
        client.post.return_value = {"_id": "pf-x", **payload}
        result = await create_port_forward(client, registry, "h", "s", payload)
        client.post.assert_called_once_with(f"{CLASSIC_REST_BASE}/portforward", json=payload)
        assert result["_id"] == "pf-x"


class TestUpdatePortForward:
    async def test_puts_to_classic_rest(self, client, registry):
        payload = {"enabled": False}
        client.put.return_value = {"_id": "pf-1", **payload}
        result = await update_port_forward(client, registry, "h", "s", "pf-1", payload)
        client.put.assert_called_once_with(f"{CLASSIC_REST_BASE}/portforward/pf-1", json=payload)
        assert result["_id"] == "pf-1"


class TestDeletePortForward:
    async def test_deletes_via_classic_rest(self, client, registry):
        await delete_port_forward(client, registry, "h", "s", "pf-1")
        client.delete.assert_called_once_with(f"{CLASSIC_REST_BASE}/portforward/pf-1")


# --- Traffic Rules (v2 API) ---


class TestListTrafficRules:
    async def test_uses_v2_url(self, client, registry):
        client.get.return_value = {"data": [{"_id": "tr-1", "description": "Block Social"}]}
        result = await list_traffic_rules(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{V2_API_BASE}/trafficrules")
        assert result == {"data": [{"_id": "tr-1", "description": "Block Social"}]}

    async def test_resolves_slug_not_uuid(self, client, registry):
        client.get.return_value = {}
        await list_traffic_rules(client, registry, "h", "s")
        registry.resolve_site_slug.assert_called_once_with("s", HOST_ID)
        registry.resolve_site_id.assert_not_called()

    async def test_bare_list_wrapped(self, client, registry):
        """v2 API may return [] or [...] directly; normalize to {data: [...], count: N}."""
        rules = [{"_id": "tr-1", "description": "Block Social"}, {"_id": "tr-2"}]
        client.get.return_value = rules
        result = await list_traffic_rules(client, registry, "h", "s")
        assert result == {"data": rules, "count": 2}

    async def test_empty_bare_list_wrapped(self, client, registry):
        """Empty bare list [] is normalized to {data: [], count: 0}."""
        client.get.return_value = []
        result = await list_traffic_rules(client, registry, "h", "s")
        assert result == {"data": [], "count": 0}


class TestCreateTrafficRule:
    async def test_posts_to_v2(self, client, registry):
        payload = {
            "description": "Block Social Media",
            "action": "BLOCK",
            "matching_target": "INTERNET",
            "enabled": True,
        }
        client.post.return_value = {"_id": "tr-new", **payload}
        result = await create_traffic_rule(client, registry, "h", "s", payload)
        client.post.assert_called_once_with(f"{V2_API_BASE}/trafficrules", json=payload)
        assert result["_id"] == "tr-new"


class TestUpdateTrafficRule:
    async def test_puts_to_v2_with_trailing_slash(self, client, registry):
        payload = {"enabled": False}
        client.put.return_value = {"_id": "tr-1", **payload}
        result = await update_traffic_rule(client, registry, "h", "s", "tr-1", payload)
        client.put.assert_called_once_with(f"{V2_API_BASE}/trafficrules/tr-1/", json=payload)
        assert result["_id"] == "tr-1"


class TestDeleteTrafficRule:
    async def test_deletes_via_v2_with_trailing_slash(self, client, registry):
        await delete_traffic_rule(client, registry, "h", "s", "tr-1")
        client.delete.assert_called_once_with(f"{V2_API_BASE}/trafficrules/tr-1/")


# --- Users / DHCP Reservations (Classic REST) ---


class TestListUsers:
    async def test_uses_classic_rest_url(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "u-1"}]}
        result = await list_users(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/user")
        assert result == [{"_id": "u-1"}]

    async def test_resolves_slug_not_uuid(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": []}
        await list_users(client, registry, "h", "s")
        registry.resolve_site_slug.assert_called_once_with("s", HOST_ID)
        registry.resolve_site_id.assert_not_called()


class TestGetUser:
    async def test_uses_classic_rest_url(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "u-1"}]}
        result = await get_user(client, registry, "h", "s", "u-1")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/user/u-1")
        assert result == [{"_id": "u-1"}]


class TestUpdateUser:
    async def test_puts_to_classic_rest(self, client, registry):
        payload = {"name": "My Device", "fixed_ip": "192.168.1.100"}
        client.put.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "u-1", **payload}]}
        result = await update_user(client, registry, "h", "s", "u-1", payload)
        client.put.assert_called_once_with(f"{CLASSIC_REST_BASE}/user/u-1", json=payload)
        assert result[0]["name"] == "My Device"


# --- Traffic Routes (v2 API) ---


class TestListTrafficRoutes:
    async def test_uses_v2_url(self, client, registry):
        client.get.return_value = [{"_id": "rt-1", "name": "Default Route"}]
        result = await list_traffic_routes(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{V2_API_BASE}/trafficroutes")
        assert result == [{"_id": "rt-1", "name": "Default Route"}]

    async def test_resolves_slug_not_uuid(self, client, registry):
        client.get.return_value = []
        await list_traffic_routes(client, registry, "h", "s")
        registry.resolve_site_slug.assert_called_once_with("s", HOST_ID)
        registry.resolve_site_id.assert_not_called()


class TestCreateTrafficRoute:
    async def test_posts_to_v2(self, client, registry):
        payload = {"name": "ISP2 Route", "enabled": True}
        client.post.return_value = {"_id": "rt-new", **payload}
        result = await create_traffic_route(client, registry, "h", "s", payload)
        client.post.assert_called_once_with(f"{V2_API_BASE}/trafficroutes", json=payload)
        assert result["_id"] == "rt-new"


class TestGetTrafficRoute:
    async def test_filters_from_list(self, client, registry):
        client.get.return_value = [
            {"_id": "rt-1", "name": "Default Route"},
            {"_id": "rt-2", "name": "ISP2 Route"},
        ]
        result = await get_traffic_route(client, registry, "h", "s", "rt-1")
        client.get.assert_called_once_with(f"{V2_API_BASE}/trafficroutes")
        assert result == {"_id": "rt-1", "name": "Default Route"}

    async def test_raises_when_not_found(self, client, registry):
        client.get.return_value = [{"_id": "rt-2", "name": "ISP2 Route"}]
        with pytest.raises(ValueError, match="not found"):
            await get_traffic_route(client, registry, "h", "s", "rt-1")


class TestUpdateTrafficRoute:
    async def test_puts_to_v2(self, client, registry):
        payload = {"enabled": False}
        client.put.return_value = {"_id": "rt-1", **payload}
        result = await update_traffic_route(client, registry, "h", "s", "rt-1", payload)
        client.put.assert_called_once_with(f"{V2_API_BASE}/trafficroutes/rt-1", json=payload)
        assert result["_id"] == "rt-1"


class TestDeleteTrafficRoute:
    async def test_deletes_via_v2(self, client, registry):
        await delete_traffic_route(client, registry, "h", "s", "rt-1")
        client.delete.assert_called_once_with(f"{V2_API_BASE}/trafficroutes/rt-1")


# --- Controller Settings (Classic REST) ---


class TestListSettings:
    async def test_uses_classic_rest_url(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"key": "mgmt"}]}
        result = await list_settings(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/setting")
        assert result == [{"key": "mgmt"}]


class TestGetSetting:
    async def test_uses_classic_rest_url_with_key(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"key": "mgmt"}]}
        result = await get_setting(client, registry, "h", "s", "mgmt")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/setting/mgmt")
        assert result == [{"key": "mgmt"}]


class TestUpdateSetting:
    async def test_puts_to_classic_rest(self, client, registry):
        payload = {"autobackup": True}
        client.put.return_value = {"meta": {"rc": "ok"}, "data": [{"key": "mgmt", **payload}]}
        result = await update_setting(client, registry, "h", "s", "mgmt", payload)
        client.put.assert_called_once_with(f"{CLASSIC_REST_BASE}/setting/mgmt", json=payload)
        assert result[0]["autobackup"] is True


# --- Dynamic DNS (Classic REST) ---


class TestListDynamicDns:
    async def test_uses_classic_rest_url(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "ddns-1"}]}
        result = await list_dynamic_dns(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/dynamicdns")
        assert result == [{"_id": "ddns-1"}]

    async def test_redacts_x_password_by_default(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "ddns-1", "service": "dyndns", "x_password": "secret"}],
        }
        result = await list_dynamic_dns(client, registry, "h", "s")
        assert result == [{"_id": "ddns-1", "service": "dyndns", "x_password": "[REDACTED]"}]

    async def test_exposes_x_password_when_include_secrets(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "ddns-1", "service": "dyndns", "x_password": "secret"}],
        }
        result = await list_dynamic_dns(client, registry, "h", "s", include_secrets=True)
        assert result == [{"_id": "ddns-1", "service": "dyndns", "x_password": "secret"}]


class TestGetDynamicDns:
    async def test_uses_classic_rest_url_with_id(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "ddns-1"}]}
        result = await get_dynamic_dns(client, registry, "h", "s", "ddns-1")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/dynamicdns/ddns-1")
        assert result == [{"_id": "ddns-1"}]

    async def test_redacts_x_password_by_default(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "ddns-1", "x_password": "secret"}],
        }
        result = await get_dynamic_dns(client, registry, "h", "s", "ddns-1")
        assert result == [{"_id": "ddns-1", "x_password": "[REDACTED]"}]

    async def test_exposes_x_password_when_include_secrets(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "ddns-1", "x_password": "secret"}],
        }
        result = await get_dynamic_dns(client, registry, "h", "s", "ddns-1", include_secrets=True)
        assert result == [{"_id": "ddns-1", "x_password": "secret"}]


class TestUpdateDynamicDns:
    async def test_puts_to_classic_rest(self, client, registry):
        payload = {"service": "dyndns", "hostname": "home.example.com"}
        client.put.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "ddns-1", **payload}]}
        result = await update_dynamic_dns(client, registry, "h", "s", "ddns-1", payload)
        client.put.assert_called_once_with(f"{CLASSIC_REST_BASE}/dynamicdns/ddns-1", json=payload)
        assert result[0]["service"] == "dyndns"


# --- Port Profiles (Classic REST) ---


class TestListPortProfiles:
    async def test_uses_classic_rest_url(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "pp-1", "name": "All"}]}
        result = await list_port_profiles(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/portconf")
        assert result == [{"_id": "pp-1", "name": "All"}]


class TestGetPortProfile:
    async def test_uses_classic_rest_url_with_id(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "pp-1"}]}
        result = await get_port_profile(client, registry, "h", "s", "pp-1")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/portconf/pp-1")
        assert result == [{"_id": "pp-1"}]


class TestUpdatePortProfile:
    async def test_puts_to_classic_rest(self, client, registry):
        payload = {"poe_mode": "auto"}
        client.put.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "pp-1", **payload}]}
        result = await update_port_profile(client, registry, "h", "s", "pp-1", payload)
        client.put.assert_called_once_with(f"{CLASSIC_REST_BASE}/portconf/pp-1", json=payload)
        assert result[0]["poe_mode"] == "auto"


# --- Routing Table (Classic REST) ---


class TestListRoutingEntries:
    async def test_uses_classic_rest_url(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "rt-1", "network": "10.0.0.0/8"}],
        }
        result = await list_routing_entries(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/routing")
        assert result == [{"_id": "rt-1", "network": "10.0.0.0/8"}]


# --- WLAN Configs (Classic REST) ---


class TestListWlanConfigs:
    async def test_uses_classic_rest_url(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "wlan-1", "name": "HomeSSID"}],
        }
        result = await list_wlan_configs(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/wlanconf")
        assert result == [{"_id": "wlan-1", "name": "HomeSSID"}]

    async def test_redacts_x_passphrase_by_default(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "wlan-1", "name": "HomeSSID", "x_passphrase": "secret123"}],
        }
        result = await list_wlan_configs(client, registry, "h", "s")
        assert result == [{"_id": "wlan-1", "name": "HomeSSID", "x_passphrase": "[REDACTED]"}]

    async def test_exposes_x_passphrase_when_include_secrets(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "wlan-1", "name": "HomeSSID", "x_passphrase": "secret123"}],
        }
        result = await list_wlan_configs(client, registry, "h", "s", include_secrets=True)
        assert result == [{"_id": "wlan-1", "name": "HomeSSID", "x_passphrase": "secret123"}]


class TestGetWlanConfig:
    async def test_uses_classic_rest_url_with_id(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "wlan-1"}]}
        result = await get_wlan_config(client, registry, "h", "s", "wlan-1")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/wlanconf/wlan-1")
        assert result == [{"_id": "wlan-1"}]

    async def test_redacts_x_passphrase_by_default(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "wlan-1", "x_passphrase": "secret123"}],
        }
        result = await get_wlan_config(client, registry, "h", "s", "wlan-1")
        assert result == [{"_id": "wlan-1", "x_passphrase": "[REDACTED]"}]

    async def test_exposes_x_passphrase_when_include_secrets(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "wlan-1", "x_passphrase": "secret123"}],
        }
        result = await get_wlan_config(client, registry, "h", "s", "wlan-1", include_secrets=True)
        assert result == [{"_id": "wlan-1", "x_passphrase": "secret123"}]


class TestUpdateWlanConfig:
    async def test_puts_to_classic_rest(self, client, registry):
        payload = {"x_passphrase": "newpassword123"}
        client.put.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "wlan-1", **payload}]}
        result = await update_wlan_config(client, registry, "h", "s", "wlan-1", payload)
        client.put.assert_called_once_with(f"{CLASSIC_REST_BASE}/wlanconf/wlan-1", json=payload)
        assert result[0]["x_passphrase"] == "newpassword123"


# --- WLAN Groups (Classic REST) ---


class TestListWlanGroups:
    async def test_uses_classic_rest_url(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "wg-1", "name": "Default"}],
        }
        result = await list_wlan_groups(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/wlangroup")
        assert result == [{"_id": "wg-1", "name": "Default"}]


class TestGetWlanGroup:
    async def test_uses_classic_rest_url_with_id(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "wg-1"}]}
        result = await get_wlan_group(client, registry, "h", "s", "wg-1")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/wlangroup/wg-1")
        assert result == [{"_id": "wg-1"}]


# --- Channel Plan (Classic REST) ---


class TestGetChannelPlan:
    async def test_uses_classic_rest_url(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"radio": "ng", "channel": 6, "ht": "HT20"}],
        }
        result = await get_channel_plan(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/channelplan")
        assert result == [{"radio": "ng", "channel": 6, "ht": "HT20"}]

    async def test_empty_returns_informative_message(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": []}
        result = await get_channel_plan(client, registry, "h", "s")
        assert "message" in result
        assert "No channel plan data available" in result["message"]
        assert result["channelPlan"] == []


# --- Rogue APs (Classic Stat) ---


class TestListRogueAps:
    async def test_uses_classic_stat_url(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"bssid": "aa:bb:cc:dd:ee:ff", "ssid": "EvilAP", "channel": 11}],
        }
        result = await list_rogue_aps(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{CLASSIC_STAT_BASE}/rogueap")
        assert result == [{"bssid": "aa:bb:cc:dd:ee:ff", "ssid": "EvilAP", "channel": 11}]

    async def test_resolves_slug_not_uuid(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": []}
        await list_rogue_aps(client, registry, "h", "s")
        registry.resolve_site_slug.assert_called_once_with("s", HOST_ID)
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
        assert result == [{"bssid": "aa:bb:cc:dd:ee:01", "is_rogue": True}]

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
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/firewallrule")
        assert result == [{"_id": "fr-1", "name": "Block Telnet", "action": "drop"}]


class TestGetFirewallRule:
    async def test_uses_classic_rest_url_with_id(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "fr-1"}]}
        result = await get_firewall_rule(client, registry, "h", "s", "fr-1")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/firewallrule/fr-1")
        assert result == [{"_id": "fr-1"}]


# --- Firewall Groups (Classic REST) ---


class TestListFirewallGroups:
    async def test_uses_classic_rest_url(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "fg-1", "name": "RFC1918", "group_type": "address-group"}],
        }
        result = await list_firewall_groups(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/firewallgroup")
        assert result == [{"_id": "fg-1", "name": "RFC1918", "group_type": "address-group"}]


class TestGetFirewallGroup:
    async def test_uses_classic_rest_url_with_id(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "fg-1"}]}
        result = await get_firewall_group(client, registry, "h", "s", "fg-1")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/firewallgroup/fg-1")
        assert result == [{"_id": "fg-1"}]


# --- RADIUS Accounts (Classic REST) ---


class TestListAccounts:
    async def test_uses_classic_rest_url(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "acc-1", "name": "jdoe", "x_password": "secret"}],
        }
        result = await list_accounts(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/account")
        assert result == [{"_id": "acc-1", "name": "jdoe", "x_password": "[REDACTED]"}]

    async def test_exposes_x_password_when_include_secrets(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "acc-1", "name": "jdoe", "x_password": "secret"}],
        }
        result = await list_accounts(client, registry, "h", "s", include_secrets=True)
        assert result == [{"_id": "acc-1", "name": "jdoe", "x_password": "secret"}]


class TestGetAccount:
    async def test_uses_classic_rest_url_with_id(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "acc-1"}]}
        result = await get_account(client, registry, "h", "s", "acc-1")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/account/acc-1")
        assert result == [{"_id": "acc-1"}]

    async def test_redacts_x_password_by_default(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "acc-1", "name": "jdoe", "x_password": "secret"}],
        }
        result = await get_account(client, registry, "h", "s", "acc-1")
        assert result == [{"_id": "acc-1", "name": "jdoe", "x_password": "[REDACTED]"}]

    async def test_exposes_x_password_when_include_secrets(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "acc-1", "name": "jdoe", "x_password": "secret"}],
        }
        result = await get_account(client, registry, "h", "s", "acc-1", include_secrets=True)
        assert result == [{"_id": "acc-1", "name": "jdoe", "x_password": "secret"}]


# --- Hotspot Packages (Classic REST) ---


class TestListHotspotPackages:
    async def test_uses_classic_rest_url(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "pkg-1", "name": "Day Pass", "price": 5}],
        }
        result = await list_hotspot_packages(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/hotspotpackage")
        assert result == [{"_id": "pkg-1", "name": "Day Pass", "price": 5}]


class TestGetHotspotPackage:
    async def test_uses_classic_rest_url_with_id(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "pkg-1"}]}
        result = await get_hotspot_package(client, registry, "h", "s", "pkg-1")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/hotspotpackage/pkg-1")
        assert result == [{"_id": "pkg-1"}]


# --- Scheduled Tasks (Classic REST) ---


class TestListScheduledTasks:
    async def test_uses_classic_rest_url(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "st-1", "name": "Auto Upgrade", "type": "firmware_upgrade"}],
        }
        result = await list_scheduled_tasks(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/scheduletask")
        assert result == [{"_id": "st-1", "name": "Auto Upgrade", "type": "firmware_upgrade"}]


class TestGetScheduledTask:
    async def test_uses_classic_rest_url_with_id(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "st-1"}]}
        result = await get_scheduled_task(client, registry, "h", "s", "st-1")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/scheduletask/st-1")
        assert result == [{"_id": "st-1"}]


# --- DPI Categories ---


class TestListDpiCategories:
    async def test_basic(self, client, registry):
        client.get.return_value = [{"id": "cat-1", "name": "Social Media"}]
        result = await list_dpi_categories(client, registry, "h")
        client.get.assert_called_once_with(f"{BASE}/dpi/categories", params=None)
        assert result == [{"id": "cat-1", "name": "Social Media"}]

    async def test_resolves_host(self, client, registry):
        client.get.return_value = []
        await list_dpi_categories(client, registry, "UDM-Pro")
        registry.resolve_host_id.assert_called_once_with("UDM-Pro")
        registry.resolve_site_id.assert_not_called()

    async def test_with_offset_and_limit(self, client, registry):
        client.get.return_value = []
        await list_dpi_categories(client, registry, "h", offset=10, limit=25)
        client.get.assert_called_once_with(
            f"{BASE}/dpi/categories", params={"offset": 10, "limit": 25}
        )

    async def test_limit_only(self, client, registry):
        client.get.return_value = []
        await list_dpi_categories(client, registry, "h", limit=10)
        client.get.assert_called_once_with(f"{BASE}/dpi/categories", params={"limit": 10})


# --- DPI Applications ---


class TestListDpiApplications:
    async def test_basic(self, client, registry):
        client.get.return_value = [{"id": "app-1", "name": "YouTube", "categoryId": "cat-1"}]
        result = await list_dpi_applications(client, registry, "h")
        client.get.assert_called_once_with(f"{BASE}/dpi/applications", params=None)
        assert result == [{"id": "app-1", "name": "YouTube", "categoryId": "cat-1"}]

    async def test_resolves_host(self, client, registry):
        client.get.return_value = []
        await list_dpi_applications(client, registry, "UDM-Pro")
        registry.resolve_host_id.assert_called_once_with("UDM-Pro")
        registry.resolve_site_id.assert_not_called()

    async def test_with_offset_and_limit(self, client, registry):
        client.get.return_value = []
        await list_dpi_applications(client, registry, "h", offset=5, limit=50)
        client.get.assert_called_once_with(
            f"{BASE}/dpi/applications", params={"offset": 5, "limit": 50}
        )

    async def test_limit_only(self, client, registry):
        client.get.return_value = []
        await list_dpi_applications(client, registry, "h", limit=25)
        client.get.assert_called_once_with(f"{BASE}/dpi/applications", params={"limit": 25})
