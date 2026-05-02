"""Tests for firewall_proxy tools — policies, zones, and ACL rules via connector proxy."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.tools.firewall_proxy import (
    create_acl_rule,
    create_firewall_policy,
    create_firewall_zone,
    delete_acl_rule,
    delete_firewall_policy,
    delete_firewall_zone,
    get_acl_rule,
    get_acl_rule_ordering,
    get_firewall_policy,
    get_firewall_policy_ordering,
    get_firewall_zone,
    list_acl_rules,
    list_firewall_policies,
    list_firewall_zones,
    patch_firewall_policy,
    set_acl_rule_ordering,
    set_firewall_policy_ordering,
    update_acl_rule,
    update_firewall_policy,
    update_firewall_zone,
)
from unifi_fabric.tools.network import PROXY_BASE

HOST_ID = "host-001"
SITE_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
BASE = PROXY_BASE.format(host_id=HOST_ID)


@pytest.fixture()
def client():
    c = AsyncMock()
    c.get = AsyncMock()
    c.post = AsyncMock()
    c.put = AsyncMock()
    c.patch = AsyncMock()
    c.delete = AsyncMock()
    return c


@pytest.fixture()
def registry():
    r = AsyncMock()
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    r.resolve_site_id = AsyncMock(return_value=SITE_ID)
    return r


# --- Firewall Policies ---


class TestListFirewallPolicies:
    async def test_basic(self, client, registry):
        client.get.return_value = {"data": [{"id": "pol-1", "name": "Allow LAN"}], "totalCount": 1}
        result = await list_firewall_policies(client, registry, "h", "s")
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/firewall/policies", params={"limit": 50}
        )
        assert result == {"data": [{"id": "pol-1", "name": "Allow LAN"}], "totalCount": 1}

    async def test_resolves_names(self, client, registry):
        client.get.return_value = {"data": [], "totalCount": 0}
        await list_firewall_policies(client, registry, "MyHost", "Office")
        registry.resolve_host_id.assert_called_once_with("MyHost")
        registry.resolve_site_id.assert_called_once_with("Office", HOST_ID)

    async def test_pagination_params(self, client, registry):
        client.get.return_value = {"data": [], "totalCount": 102}
        await list_firewall_policies(client, registry, "h", "s", offset=50, limit=50)
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/firewall/policies", params={"offset": 50, "limit": 50}
        )

    async def test_no_limit(self, client, registry):
        client.get.return_value = {"data": [], "totalCount": 5}
        await list_firewall_policies(client, registry, "h", "s", offset=0, limit=0)
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/firewall/policies", params=None)


class TestCreateFirewallPolicy:
    async def test_basic(self, client, registry):
        payload = {"name": "Block Guest", "action": "drop"}
        client.post.return_value = {"id": "pol-2", **payload}
        result = await create_firewall_policy(client, registry, "h", "s", payload)
        client.post.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/firewall/policies", json=payload
        )
        assert result["name"] == "Block Guest"


class TestGetFirewallPolicy:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "pol-1", "name": "Allow LAN"}
        result = await get_firewall_policy(client, registry, "h", "s", "pol-1")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/firewall/policies/pol-1")
        assert result["id"] == "pol-1"


class TestUpdateFirewallPolicy:
    async def test_basic(self, client, registry):
        payload = {"name": "Updated Policy"}
        client.put.return_value = {"id": "pol-1", **payload}
        result = await update_firewall_policy(client, registry, "h", "s", "pol-1", payload)
        client.put.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/firewall/policies/pol-1", json=payload
        )
        assert result["name"] == "Updated Policy"


class TestPatchFirewallPolicy:
    async def test_basic(self, client, registry):
        fields = {"enabled": False}
        client.patch.return_value = {"id": "pol-1", "enabled": False}
        result = await patch_firewall_policy(client, registry, "h", "s", "pol-1", fields)
        client.patch.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/firewall/policies/pol-1", json=fields
        )
        assert result["enabled"] is False


class TestDeleteFirewallPolicy:
    async def test_basic(self, client, registry):
        await delete_firewall_policy(client, registry, "h", "s", "pol-1")
        client.delete.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/firewall/policies/pol-1")


class TestFirewallPolicyOrdering:
    async def test_get_ordering(self, client, registry):
        src_zone_id = "zone-uuid-1234"
        dst_zone_id = "zone-uuid-5678"
        client.get.return_value = {"order": ["pol-1", "pol-2"]}
        result = await get_firewall_policy_ordering(
            client, registry, "h", "s", src_zone_id, dst_zone_id
        )
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/firewall/policies/ordering",
            params={
                "sourceFirewallZoneId": src_zone_id,
                "destinationFirewallZoneId": dst_zone_id,
            },
        )
        assert result == {"order": ["pol-1", "pol-2"]}

    async def test_set_ordering(self, client, registry):
        ordering = {"order": ["pol-2", "pol-1"]}
        client.put.return_value = ordering
        result = await set_firewall_policy_ordering(client, registry, "h", "s", ordering)
        client.put.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/firewall/policies/ordering", json=ordering
        )
        assert result == ordering


# --- Firewall Zones ---


class TestListFirewallZones:
    async def test_basic(self, client, registry):
        client.get.return_value = [{"id": "zone-1", "name": "Internal"}]
        result = await list_firewall_zones(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/firewall/zones")
        assert result == [{"id": "zone-1", "name": "Internal"}]


class TestCreateFirewallZone:
    async def test_basic(self, client, registry):
        payload = {"name": "DMZ"}
        client.post.return_value = {"id": "zone-2", **payload}
        result = await create_firewall_zone(client, registry, "h", "s", payload)
        client.post.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/firewall/zones", json=payload)
        assert result["name"] == "DMZ"


class TestGetFirewallZone:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "zone-1", "name": "Internal"}
        result = await get_firewall_zone(client, registry, "h", "s", "zone-1")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/firewall/zones/zone-1")
        assert result["id"] == "zone-1"


class TestUpdateFirewallZone:
    async def test_basic(self, client, registry):
        payload = {"name": "Updated Zone"}
        client.put.return_value = {"id": "zone-1", **payload}
        result = await update_firewall_zone(client, registry, "h", "s", "zone-1", payload)
        client.put.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/firewall/zones/zone-1", json=payload
        )
        assert result["name"] == "Updated Zone"


class TestDeleteFirewallZone:
    async def test_basic(self, client, registry):
        await delete_firewall_zone(client, registry, "h", "s", "zone-1")
        client.delete.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/firewall/zones/zone-1")


# --- ACL Rules ---


class TestListAclRules:
    async def test_basic(self, client, registry):
        client.get.return_value = [{"id": "acl-1", "name": "Block SSH"}]
        result = await list_acl_rules(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/acl-rules")
        assert result == [{"id": "acl-1", "name": "Block SSH"}]

    async def test_resolves_names(self, client, registry):
        client.get.return_value = []
        await list_acl_rules(client, registry, "UDM-Pro", "Main Office")
        registry.resolve_host_id.assert_called_once_with("UDM-Pro")
        registry.resolve_site_id.assert_called_once_with("Main Office", HOST_ID)


class TestCreateAclRule:
    async def test_basic(self, client, registry):
        payload = {"name": "Allow HTTPS", "action": "accept"}
        client.post.return_value = {"id": "acl-2", **payload}
        result = await create_acl_rule(client, registry, "h", "s", payload)
        client.post.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/acl-rules", json=payload)
        assert result["name"] == "Allow HTTPS"


class TestGetAclRule:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "acl-1", "name": "Block SSH"}
        result = await get_acl_rule(client, registry, "h", "s", "acl-1")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/acl-rules/acl-1")
        assert result["id"] == "acl-1"


class TestUpdateAclRule:
    async def test_basic(self, client, registry):
        payload = {"name": "Updated Rule"}
        client.put.return_value = {"id": "acl-1", **payload}
        result = await update_acl_rule(client, registry, "h", "s", "acl-1", payload)
        client.put.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/acl-rules/acl-1", json=payload)
        assert result["name"] == "Updated Rule"


class TestDeleteAclRule:
    async def test_basic(self, client, registry):
        await delete_acl_rule(client, registry, "h", "s", "acl-1")
        client.delete.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/acl-rules/acl-1")


class TestAclRuleOrdering:
    async def test_get_ordering(self, client, registry):
        client.get.return_value = {"order": ["acl-1", "acl-2"]}
        result = await get_acl_rule_ordering(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/acl-rules/ordering")
        assert result == {"order": ["acl-1", "acl-2"]}

    async def test_set_ordering(self, client, registry):
        ordering = {"order": ["acl-2", "acl-1"]}
        client.put.return_value = ordering
        result = await set_acl_rule_ordering(client, registry, "h", "s", ordering)
        client.put.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/acl-rules/ordering", json=ordering
        )
        assert result == ordering
