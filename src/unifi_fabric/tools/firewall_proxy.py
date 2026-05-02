"""Firewall tools — policies, zones, and ACL rules via connector proxy."""

from __future__ import annotations

from typing import Any

from ..client import UniFiClient, validate_id
from ..registry import Registry, _assert_uuid
from .network import _proxy

# --- Firewall Policies ---


async def list_firewall_policies(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    offset: int = 0,
    limit: int = 50,
) -> dict[str, Any]:
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    params: dict[str, Any] = {}
    if offset:
        params["offset"] = offset
    if limit:
        params["limit"] = limit
    return await client.get(
        _proxy(host_id, f"/sites/{site_id}/firewall/policies"), params=params or None
    )


async def create_firewall_policy(
    client: UniFiClient, registry: Registry, host: str, site: str, policy: dict[str, Any]
) -> dict[str, Any]:
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.post(_proxy(host_id, f"/sites/{site_id}/firewall/policies"), json=policy)


async def get_firewall_policy(
    client: UniFiClient, registry: Registry, host: str, site: str, policy_id: str
) -> dict[str, Any]:
    validate_id(policy_id, "policy_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.get(_proxy(host_id, f"/sites/{site_id}/firewall/policies/{policy_id}"))


async def update_firewall_policy(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    policy_id: str,
    policy: dict[str, Any],
) -> dict[str, Any]:
    validate_id(policy_id, "policy_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.put(
        _proxy(host_id, f"/sites/{site_id}/firewall/policies/{policy_id}"), json=policy
    )


async def patch_firewall_policy(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    policy_id: str,
    fields: dict[str, Any],
) -> dict[str, Any]:
    validate_id(policy_id, "policy_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.patch(
        _proxy(host_id, f"/sites/{site_id}/firewall/policies/{policy_id}"), json=fields
    )


async def delete_firewall_policy(
    client: UniFiClient, registry: Registry, host: str, site: str, policy_id: str
) -> None:
    validate_id(policy_id, "policy_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    await client.delete(_proxy(host_id, f"/sites/{site_id}/firewall/policies/{policy_id}"))


async def get_firewall_policy_ordering(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    source_zone_id: str,
    destination_zone_id: str,
) -> dict[str, Any]:
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.get(
        _proxy(host_id, f"/sites/{site_id}/firewall/policies/ordering"),
        params={
            "sourceFirewallZoneId": source_zone_id,
            "destinationFirewallZoneId": destination_zone_id,
        },
    )


async def set_firewall_policy_ordering(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    ordering: dict[str, Any],
) -> dict[str, Any]:
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.put(
        _proxy(host_id, f"/sites/{site_id}/firewall/policies/ordering"), json=ordering
    )


# --- Firewall Zones ---


async def list_firewall_zones(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> dict[str, Any]:
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.get(_proxy(host_id, f"/sites/{site_id}/firewall/zones"))


async def create_firewall_zone(
    client: UniFiClient, registry: Registry, host: str, site: str, zone: dict[str, Any]
) -> dict[str, Any]:
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.post(_proxy(host_id, f"/sites/{site_id}/firewall/zones"), json=zone)


async def get_firewall_zone(
    client: UniFiClient, registry: Registry, host: str, site: str, zone_id: str
) -> dict[str, Any]:
    validate_id(zone_id, "zone_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.get(_proxy(host_id, f"/sites/{site_id}/firewall/zones/{zone_id}"))


async def update_firewall_zone(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    zone_id: str,
    zone: dict[str, Any],
) -> dict[str, Any]:
    validate_id(zone_id, "zone_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.put(
        _proxy(host_id, f"/sites/{site_id}/firewall/zones/{zone_id}"), json=zone
    )


async def delete_firewall_zone(
    client: UniFiClient, registry: Registry, host: str, site: str, zone_id: str
) -> None:
    validate_id(zone_id, "zone_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    await client.delete(_proxy(host_id, f"/sites/{site_id}/firewall/zones/{zone_id}"))


# --- ACL Rules ---


async def list_acl_rules(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> dict[str, Any]:
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.get(_proxy(host_id, f"/sites/{site_id}/acl-rules"))


async def create_acl_rule(
    client: UniFiClient, registry: Registry, host: str, site: str, rule: dict[str, Any]
) -> dict[str, Any]:
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.post(_proxy(host_id, f"/sites/{site_id}/acl-rules"), json=rule)


async def get_acl_rule(
    client: UniFiClient, registry: Registry, host: str, site: str, rule_id: str
) -> dict[str, Any]:
    validate_id(rule_id, "rule_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.get(_proxy(host_id, f"/sites/{site_id}/acl-rules/{rule_id}"))


async def update_acl_rule(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    rule_id: str,
    rule: dict[str, Any],
) -> dict[str, Any]:
    validate_id(rule_id, "rule_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.put(_proxy(host_id, f"/sites/{site_id}/acl-rules/{rule_id}"), json=rule)


async def delete_acl_rule(
    client: UniFiClient, registry: Registry, host: str, site: str, rule_id: str
) -> None:
    validate_id(rule_id, "rule_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    await client.delete(_proxy(host_id, f"/sites/{site_id}/acl-rules/{rule_id}"))


async def get_acl_rule_ordering(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> dict[str, Any]:
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.get(_proxy(host_id, f"/sites/{site_id}/acl-rules/ordering"))


async def set_acl_rule_ordering(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    ordering: dict[str, Any],
) -> dict[str, Any]:
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.put(_proxy(host_id, f"/sites/{site_id}/acl-rules/ordering"), json=ordering)
