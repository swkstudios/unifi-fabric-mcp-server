"""Tests for firewall_proxy tools — policies, zones, and ACL rules via connector proxy."""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import PaginationAbortedError
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
    r.resolve_key_for_host = AsyncMock(return_value=None)
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    r.resolve_site_id = AsyncMock(return_value=SITE_ID)
    return r


# --- Firewall Policies ---


class TestListFirewallPolicies:
    async def test_drains_all_by_default(self, client, registry):
        client.paginate_offset.return_value = [
            {"id": "pol-1", "name": "Allow LAN"},
            {"id": "pol-2"},
        ]
        result = await list_firewall_policies(client, registry, "h", "s")
        client.paginate_offset.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/firewall/policies", key=None, params=None, page_size=200
        )
        client.get.assert_not_called()
        assert result == {
            "data": [{"id": "pol-1", "name": "Allow LAN"}, {"id": "pol-2"}],
            "totalCount": 2,
        }

    async def test_resolves_names(self, client, registry):
        client.paginate_offset.return_value = []
        await list_firewall_policies(client, registry, "MyHost", "Office")
        registry.resolve_host_id.assert_called_once_with("MyHost", key=None)
        registry.resolve_site_id.assert_called_once_with("Office", HOST_ID, key=None)

    async def test_pagination_params_single_page(self, client, registry):
        client.get.return_value = {"data": [{"id": "pol-9"}], "totalCount": 102}
        result = await list_firewall_policies(client, registry, "h", "s", offset=50, limit=50)
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/firewall/policies",
            key=None,
            params={"offset": 50, "limit": 50},
        )
        client.paginate_offset.assert_not_called()
        assert result == {"data": [{"id": "pol-9"}], "totalCount": 102}

    async def test_explicit_zero_limit_and_offset_are_sent(self, client, registry):
        client.get.return_value = {"data": [], "totalCount": 5}
        await list_firewall_policies(client, registry, "h", "s", offset=0, limit=0)
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/firewall/policies",
            key=None,
            params={"offset": 0, "limit": 0},
        )

    async def test_cap_exceeded_marked_incomplete(self, client, registry):
        client.paginate_offset.side_effect = PaginationAbortedError(
            f"{BASE}/sites/{SITE_ID}/firewall/policies",
            2,
            "page cap of 2 reached",
            items=[{"id": "pol-1"}],
        )
        result = await list_firewall_policies(client, registry, "h", "s")
        assert result["incomplete"] is True
        assert result["data"] == [{"id": "pol-1"}]
        assert result["totalCount"] == 1

    async def test_filter_drains_with_exact_param(self, client, registry):
        client.paginate_offset.return_value = []
        await list_firewall_policies(client, registry, "h", "s", filter="action.eq('ALLOW')")
        client.paginate_offset.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/firewall/policies",
            key=None,
            params={"filter": "action.eq('ALLOW')"},
            page_size=200,
        )

    async def test_filter_manual_page_exact_param(self, client, registry):
        client.get.return_value = {"data": [], "totalCount": 0}
        await list_firewall_policies(
            client, registry, "h", "s", offset=50, limit=50, filter="enabled.eq(true)"
        )
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/firewall/policies",
            key=None,
            params={"filter": "enabled.eq(true)", "offset": 50, "limit": 50},
        )
        client.paginate_offset.assert_not_called()

    async def test_filter_none_omits_param_not_string(self, client, registry):
        client.paginate_offset.return_value = []
        await list_firewall_policies(client, registry, "h", "s", filter=None)
        client.paginate_offset.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/firewall/policies", key=None, params=None, page_size=200
        )

    async def test_filter_threads_owning_key(self, client, registry):
        sentinel = object()
        registry.resolve_key_for_host.return_value = sentinel
        client.paginate_offset.return_value = []
        await list_firewall_policies(client, registry, "h", "s", filter="action.eq('ALLOW')")
        client.paginate_offset.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/firewall/policies",
            key=sentinel,
            params={"filter": "action.eq('ALLOW')"},
            page_size=200,
        )


class TestCreateFirewallPolicy:
    # Every field below is required by the live controller (an empty body is rejected
    # naming all seven). The tool validates the same set before the request.
    _VALID = {
        "name": "Block Guest",
        "action": {"type": "DENY", "allowReturnTraffic": False},
        "enabled": True,
        "source": {"zoneId": "z1"},
        "destination": {"zoneId": "z2"},
        "ipProtocolScope": {"ipVersion": "BOTH"},
        "loggingEnabled": False,
    }

    async def test_basic(self, client, registry):
        payload = dict(self._VALID)
        client.post.return_value = {"id": "pol-2", **payload}
        result = await create_firewall_policy(client, registry, "h", "s", payload)
        client.post.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/firewall/policies", key=None, json=payload
        )
        assert result["name"] == "Block Guest"

    async def test_missing_required_field_rejected(self, client, registry):
        payload = {k: v for k, v in self._VALID.items() if k != "source"}
        with pytest.raises(ValueError) as exc:
            await create_firewall_policy(client, registry, "h", "s", payload)
        assert str(exc.value) == "create_firewall_policy requires: source"
        client.post.assert_not_called()

    async def test_empty_payload_names_all_missing(self, client, registry):
        with pytest.raises(ValueError) as exc:
            await create_firewall_policy(client, registry, "h", "s", {})
        assert str(exc.value) == (
            "create_firewall_policy requires: action, destination, enabled, "
            "ipProtocolScope, loggingEnabled, name, source"
        )
        client.post.assert_not_called()


class TestGetFirewallPolicy:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "pol-1", "name": "Allow LAN"}
        result = await get_firewall_policy(client, registry, "h", "s", "pol-1")
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/firewall/policies/pol-1", key=None
        )
        assert result["id"] == "pol-1"


class TestUpdateFirewallPolicy:
    async def test_basic(self, client, registry):
        payload = {"name": "Updated Policy"}
        client.put.return_value = {"id": "pol-1", **payload}
        result = await update_firewall_policy(client, registry, "h", "s", "pol-1", payload)
        client.put.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/firewall/policies/pol-1", key=None, json=payload
        )
        assert result["name"] == "Updated Policy"

    async def test_strips_empty_strings_from_list_fields(self, client, registry):
        """Issue #164: a firewall policy read back with padded list fields (e.g.
        source IP groups) round-trips cleanly without the empties."""
        payload = {"name": "P", "source": {"ips": ["10.0.0.0/8", "", ""]}}
        client.put.return_value = {"id": "pol-1"}
        await update_firewall_policy(client, registry, "h", "s", "pol-1", payload)
        client.put.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/firewall/policies/pol-1",
            key=None,
            json={"name": "P", "source": {"ips": ["10.0.0.0/8"]}},
        )

    async def test_strips_readonly_fields_on_round_trip(self, client, registry):
        """A whole get_firewall_policy body PUT straight back must drop the
        server-managed fields the Integration API rejects — id, metadata, and the
        ordering index (verified live: a policy round-trip 400s on $.id, then
        $.index, until all three are gone). The writable edit survives."""
        body = {
            "id": "pol-1",
            "metadata": {"createdAt": 1},
            "index": 7,
            "name": "Renamed",
            "action": "ALLOW",
            "enabled": True,
        }
        client.put.return_value = {"id": "pol-1"}
        await update_firewall_policy(client, registry, "h", "s", "pol-1", body)
        client.put.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/firewall/policies/pol-1",
            key=None,
            json={"name": "Renamed", "action": "ALLOW", "enabled": True},
        )


class TestPatchFirewallPolicy:
    async def test_basic(self, client, registry):
        fields = {"enabled": False}
        client.patch.return_value = {"id": "pol-1", "enabled": False}
        result = await patch_firewall_policy(client, registry, "h", "s", "pol-1", fields)
        client.patch.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/firewall/policies/pol-1", key=None, json=fields
        )
        assert result["enabled"] is False


class TestDeleteFirewallPolicy:
    async def test_basic(self, client, registry):
        await delete_firewall_policy(client, registry, "h", "s", "pol-1")
        client.delete.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/firewall/policies/pol-1", key=None
        )


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
            key=None,
            params={
                "sourceFirewallZoneId": src_zone_id,
                "destinationFirewallZoneId": dst_zone_id,
            },
        )
        assert result == {"order": ["pol-1", "pol-2"]}

    async def test_set_ordering(self, client, registry):
        src_zone_id = "zone-uuid-1234"
        dst_zone_id = "zone-uuid-5678"
        ordering = {"order": ["pol-2", "pol-1"]}
        client.put.return_value = ordering
        result = await set_firewall_policy_ordering(
            client, registry, "h", "s", src_zone_id, dst_zone_id, ordering
        )
        client.put.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/firewall/policies/ordering",
            key=None,
            params={
                "sourceFirewallZoneId": src_zone_id,
                "destinationFirewallZoneId": dst_zone_id,
            },
            json=ordering,
        )
        assert result == ordering

    async def test_set_ordering_forwards_zone_query_params(self, client, registry):
        """Regression for internal #181: the ordering endpoint requires the zone ids as
        query params (sourceFirewallZoneId/destinationFirewallZoneId). Before this fix
        they were dropped and the controller returned HTTP 400 on every call."""
        client.put.return_value = {}
        await set_firewall_policy_ordering(
            client, registry, "h", "s", "zsrc", "zdst", {"order": []}
        )
        _, kwargs = client.put.call_args
        assert kwargs["params"] == {
            "sourceFirewallZoneId": "zsrc",
            "destinationFirewallZoneId": "zdst",
        }
        # zone ids must NOT be smuggled into the JSON body
        assert "sourceFirewallZoneId" not in kwargs["json"]
        assert "destinationFirewallZoneId" not in kwargs["json"]


class TestSourcePortFilterWarning:
    """Runtime warning for the source-portFilter placement footgun (public #17 / #181)."""

    @staticmethod
    def _policy(*, source_filter, action_type="ALLOW", dest_filter=None):
        source = {"zoneId": "z1"}
        if source_filter is not None:
            source["trafficFilter"] = source_filter
        destination = {"zoneId": "z2"}
        if dest_filter is not None:
            destination["trafficFilter"] = dest_filter
        return {
            "name": "p",
            "enabled": True,
            "action": {"type": action_type, "allowReturnTraffic": True},
            "source": source,
            "destination": destination,
            "ipProtocolScope": {"ipVersion": "IPV4"},
            "loggingEnabled": False,
        }

    async def test_create_warns_on_source_port_filter(self, client, registry, caplog):
        client.post.return_value = {}
        policy = self._policy(
            source_filter={"type": "PORT", "portFilter": {"items": [{"port": 443}]}}
        )
        with caplog.at_level(logging.WARNING, logger="unifi_fabric.tools.firewall_proxy"):
            await create_firewall_policy(client, registry, "h", "s", policy)
        msgs = [r.getMessage() for r in caplog.records]
        assert any("source.trafficFilter is a PORT filter" in m for m in msgs)
        # payload still forwarded verbatim (advisory only)
        client.post.assert_called_once()

    async def test_update_warns_on_source_port_filter(self, client, registry, caplog):
        client.put.return_value = {}
        policy = self._policy(
            source_filter={"type": "PORT", "portFilter": {"items": [{"port": 22}]}}
        )
        with caplog.at_level(logging.WARNING, logger="unifi_fabric.tools.firewall_proxy"):
            await update_firewall_policy(client, registry, "h", "s", "pol-1", policy)
        assert any(
            "source.trafficFilter is a PORT filter" in r.getMessage() for r in caplog.records
        )

    async def test_no_warn_when_destination_filter_present(self, client, registry, caplog):
        client.post.return_value = {}
        policy = self._policy(
            source_filter={"type": "PORT", "portFilter": {"items": [{"port": 443}]}},
            dest_filter={"type": "PORT", "portFilter": {"items": [{"port": 443}]}},
        )
        with caplog.at_level(logging.WARNING, logger="unifi_fabric.tools.firewall_proxy"):
            await create_firewall_policy(client, registry, "h", "s", policy)
        assert not any(
            "source.trafficFilter is a PORT filter" in r.getMessage() for r in caplog.records
        )

    async def test_no_warn_when_source_not_port(self, client, registry, caplog):
        client.post.return_value = {}
        policy = self._policy(
            source_filter={"type": "NETWORK", "networkFilter": {"networkIds": ["n1"]}}
        )
        with caplog.at_level(logging.WARNING, logger="unifi_fabric.tools.firewall_proxy"):
            await create_firewall_policy(client, registry, "h", "s", policy)
        assert not any(
            "source.trafficFilter is a PORT filter" in r.getMessage() for r in caplog.records
        )

    async def test_no_warn_when_action_not_allow(self, client, registry, caplog):
        client.post.return_value = {}
        policy = self._policy(
            source_filter={"type": "PORT", "portFilter": {"items": [{"port": 443}]}},
            action_type="DENY",
        )
        with caplog.at_level(logging.WARNING, logger="unifi_fabric.tools.firewall_proxy"):
            await create_firewall_policy(client, registry, "h", "s", policy)
        assert not any(
            "source.trafficFilter is a PORT filter" in r.getMessage() for r in caplog.records
        )


# --- Firewall Zones ---


class TestListFirewallZones:
    async def test_drains_all_by_default(self, client, registry):
        client.paginate_offset.return_value = [{"id": "zone-1", "name": "Internal"}]
        result = await list_firewall_zones(client, registry, "h", "s")
        client.paginate_offset.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/firewall/zones", key=None, params=None, page_size=200
        )
        client.get.assert_not_called()
        assert result == {"data": [{"id": "zone-1", "name": "Internal"}], "totalCount": 1}

    async def test_manual_page_returns_single_page(self, client, registry):
        client.get.return_value = {"data": [{"id": "zone-1"}], "totalCount": 6}
        result = await list_firewall_zones(client, registry, "h", "s", offset=0, limit=25)
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/firewall/zones", key=None, params={"offset": 0, "limit": 25}
        )
        client.paginate_offset.assert_not_called()
        assert result == {"data": [{"id": "zone-1"}], "totalCount": 6}

    async def test_cap_exceeded_marked_incomplete(self, client, registry):
        client.paginate_offset.side_effect = PaginationAbortedError(
            f"{BASE}/sites/{SITE_ID}/firewall/zones",
            2,
            "page cap of 2 reached",
            items=[{"id": "zone-1"}],
        )
        result = await list_firewall_zones(client, registry, "h", "s")
        assert result["incomplete"] is True
        assert result["data"] == [{"id": "zone-1"}]


class TestCreateFirewallZone:
    async def test_basic(self, client, registry):
        payload = {"name": "DMZ", "networkIds": ["n1", "n2"]}
        client.post.return_value = {"id": "zone-2", **payload}
        result = await create_firewall_zone(client, registry, "h", "s", payload)
        client.post.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/firewall/zones", key=None, json=payload
        )
        assert result["name"] == "DMZ"

    async def test_missing_network_ids_rejected(self, client, registry):
        with pytest.raises(ValueError) as exc:
            await create_firewall_zone(client, registry, "h", "s", {"name": "DMZ"})
        assert str(exc.value) == "create_firewall_zone requires: networkIds"
        client.post.assert_not_called()


class TestGetFirewallZone:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "zone-1", "name": "Internal"}
        result = await get_firewall_zone(client, registry, "h", "s", "zone-1")
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/firewall/zones/zone-1", key=None
        )
        assert result["id"] == "zone-1"


class TestUpdateFirewallZone:
    async def test_basic(self, client, registry):
        payload = {"name": "Updated Zone"}
        client.put.return_value = {"id": "zone-1", **payload}
        result = await update_firewall_zone(client, registry, "h", "s", "zone-1", payload)
        client.put.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/firewall/zones/zone-1", key=None, json=payload
        )
        assert result["name"] == "Updated Zone"

    async def test_strips_readonly_fields_on_round_trip(self, client, registry):
        """A whole get_firewall_zone body PUT back drops id and metadata (verified
        live: the round-trip 400s on $.id / $.metadata otherwise)."""
        body = {
            "id": "zone-1",
            "metadata": {"createdAt": 1},
            "name": "Renamed",
            "networkIds": ["n1"],
        }
        client.put.return_value = {"id": "zone-1"}
        await update_firewall_zone(client, registry, "h", "s", "zone-1", body)
        client.put.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/firewall/zones/zone-1",
            key=None,
            json={"name": "Renamed", "networkIds": ["n1"]},
        )


class TestDeleteFirewallZone:
    async def test_basic(self, client, registry):
        await delete_firewall_zone(client, registry, "h", "s", "zone-1")
        client.delete.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/firewall/zones/zone-1", key=None
        )


# --- ACL Rules ---


class TestListAclRules:
    async def test_basic(self, client, registry):
        client.get.return_value = [{"id": "acl-1", "name": "Block SSH"}]
        result = await list_acl_rules(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/acl-rules", key=None)
        assert result == [{"id": "acl-1", "name": "Block SSH"}]

    async def test_resolves_names(self, client, registry):
        client.get.return_value = []
        await list_acl_rules(client, registry, "UDM-Pro", "Main Office")
        registry.resolve_host_id.assert_called_once_with("UDM-Pro", key=None)
        registry.resolve_site_id.assert_called_once_with("Main Office", HOST_ID, key=None)


class TestCreateAclRule:
    async def test_basic(self, client, registry):
        # 'type' is the discriminator the controller validates first (Missing $.type).
        payload = {"type": "MAC", "name": "Allow HTTPS", "action": "accept"}
        client.post.return_value = {"id": "acl-2", **payload}
        result = await create_acl_rule(client, registry, "h", "s", payload)
        client.post.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/acl-rules", key=None, json=payload
        )
        assert result["name"] == "Allow HTTPS"

    async def test_missing_type_rejected(self, client, registry):
        with pytest.raises(ValueError) as exc:
            await create_acl_rule(client, registry, "h", "s", {"name": "Allow HTTPS"})
        assert str(exc.value) == "create_acl_rule requires: type"
        client.post.assert_not_called()


class TestGetAclRule:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "acl-1", "name": "Block SSH"}
        result = await get_acl_rule(client, registry, "h", "s", "acl-1")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/acl-rules/acl-1", key=None)
        assert result["id"] == "acl-1"


class TestUpdateAclRule:
    async def test_basic(self, client, registry):
        payload = {"name": "Updated Rule"}
        client.put.return_value = {"id": "acl-1", **payload}
        result = await update_acl_rule(client, registry, "h", "s", "acl-1", payload)
        client.put.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/acl-rules/acl-1", key=None, json=payload
        )
        assert result["name"] == "Updated Rule"

    async def test_strips_empty_strings_from_list_fields(self, client, registry):
        """Issue #164: an ACL rule read back with padded list fields round-trips
        cleanly without the empties."""
        payload = {"name": "R", "dst_networks": ["net-1", "", ""]}
        client.put.return_value = {"id": "acl-1"}
        await update_acl_rule(client, registry, "h", "s", "acl-1", payload)
        client.put.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/acl-rules/acl-1",
            key=None,
            json={"name": "R", "dst_networks": ["net-1"]},
        )


class TestDeleteAclRule:
    async def test_basic(self, client, registry):
        await delete_acl_rule(client, registry, "h", "s", "acl-1")
        client.delete.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/acl-rules/acl-1", key=None)


class TestAclRuleOrdering:
    async def test_get_ordering(self, client, registry):
        client.get.return_value = {"order": ["acl-1", "acl-2"]}
        result = await get_acl_rule_ordering(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/acl-rules/ordering", key=None)
        assert result == {"order": ["acl-1", "acl-2"]}

    async def test_set_ordering(self, client, registry):
        ordering = {"order": ["acl-2", "acl-1"]}
        client.put.return_value = ordering
        result = await set_acl_rule_ordering(client, registry, "h", "s", ordering)
        client.put.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/acl-rules/ordering", key=None, json=ordering
        )
        assert result == ordering
