"""Firewall tools — policies, zones, and ACL rules via connector proxy."""

from __future__ import annotations

import logging
from typing import Any

from ..client import UniFiClient, validate_id
from ..registry import Registry, _assert_uuid
from ._pagination import collect_offset, mark_incomplete
from ._payload import require_fields, sanitize_integration_write
from .network import _proxy

logger = logging.getLogger(__name__)


def _source_traffic_filter_is_port(policy: dict[str, Any]) -> bool:
    """True if the policy's source.trafficFilter matches on ports (type PORT / portFilter)."""
    source = policy.get("source")
    if not isinstance(source, dict):
        return False
    tf = source.get("trafficFilter")
    if not isinstance(tf, dict):
        return False
    return tf.get("type") == "PORT" or isinstance(tf.get("portFilter"), dict)


def _warn_source_port_filter(tool: str, policy: dict[str, Any]) -> None:
    """Log the portFilter-placement footgun for an any-destination ALLOW policy.

    A portFilter under ``source.trafficFilter`` matches SOURCE ports, which are
    ephemeral for outbound flows, so an any-destination ALLOW rule built this way
    silently matches nothing. Destination-port rules belong on
    ``destination.trafficFilter`` with ``type`` PORT. This is advisory only -- the
    payload is still forwarded verbatim.
    """
    if not isinstance(policy, dict):
        return
    action = policy.get("action")
    is_allow = isinstance(action, dict) and action.get("type") == "ALLOW"
    destination = policy.get("destination")
    dest_tf = destination.get("trafficFilter") if isinstance(destination, dict) else None
    any_destination = not isinstance(dest_tf, dict)
    if _source_traffic_filter_is_port(policy) and is_allow and any_destination:
        logger.warning(
            "%s: source.trafficFilter is a PORT filter on an ALLOW policy with no "
            "destination.trafficFilter. A source portFilter matches SOURCE ports "
            "(ephemeral for outbound flows), so this rule likely matches nothing. "
            "To match a service/destination port, put the PORT filter on "
            "destination.trafficFilter (type PORT) instead.",
            tool,
        )


# --- Firewall Policies ---


async def list_firewall_policies(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
    *,
    filter: str | None = None,
) -> dict[str, Any]:
    """List firewall policies for a site.

    By default every offset page is drained and the complete policy list is
    returned as ``{data, totalCount}``. Passing offset or limit selects manual
    paging: a single page is returned with the API's totalCount so the caller can
    advance. A drain that hits the page cap returns the policies gathered so far
    with incomplete=true rather than truncating silently. ``filter`` is a
    server-side filter (not paging), forwarded unchanged as the Network
    Integration API ``filter`` query parameter and applied in either mode; when
    ``None`` it is omitted rather than sent as the string ``"None"``.
    """
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    url = _proxy(host_id, f"/sites/{site_id}/firewall/policies")
    base: dict[str, Any] = {}
    if filter is not None:
        base["filter"] = filter
    collected = await collect_offset(
        client, url, key=key, params=base or None, offset=offset, limit=limit
    )
    total = collected["totalCount"]
    result: dict[str, Any] = {
        "data": collected["items"],
        "totalCount": total if total is not None else len(collected["items"]),
    }
    return mark_incomplete(result, collected)


async def create_firewall_policy(
    client: UniFiClient, registry: Registry, host: str, site: str, policy: dict[str, Any]
) -> dict[str, Any]:
    """Create a firewall policy.

    Required fields (all verified live — an empty body is rejected naming every one):
    ``action``, ``destination``, ``enabled``, ``ipProtocolScope``, ``loggingEnabled``,
    ``name``, ``source``.
    """
    require_fields(
        "create_firewall_policy",
        policy,
        {"action", "destination", "enabled", "ipProtocolScope", "loggingEnabled", "name", "source"},
    )
    _warn_source_port_filter("create_firewall_policy", policy)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.post(
        _proxy(host_id, f"/sites/{site_id}/firewall/policies"), key=key, json=policy
    )


async def get_firewall_policy(
    client: UniFiClient, registry: Registry, host: str, site: str, policy_id: str
) -> dict[str, Any]:
    validate_id(policy_id, "policy_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.get(
        _proxy(host_id, f"/sites/{site_id}/firewall/policies/{policy_id}"), key=key
    )


async def update_firewall_policy(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    policy_id: str,
    policy: dict[str, Any],
) -> dict[str, Any]:
    validate_id(policy_id, "policy_id")
    _warn_source_port_filter("update_firewall_policy", policy)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.put(
        _proxy(host_id, f"/sites/{site_id}/firewall/policies/{policy_id}"),
        key=key,
        json=sanitize_integration_write(policy),
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
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.patch(
        _proxy(host_id, f"/sites/{site_id}/firewall/policies/{policy_id}"),
        key=key,
        json=sanitize_integration_write(fields),
    )


async def delete_firewall_policy(
    client: UniFiClient, registry: Registry, host: str, site: str, policy_id: str
) -> None:
    validate_id(policy_id, "policy_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    await client.delete(_proxy(host_id, f"/sites/{site_id}/firewall/policies/{policy_id}"), key=key)


async def get_firewall_policy_ordering(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    source_zone_id: str,
    destination_zone_id: str,
) -> dict[str, Any]:
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.get(
        _proxy(host_id, f"/sites/{site_id}/firewall/policies/ordering"),
        key=key,
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
    source_zone_id: str,
    destination_zone_id: str,
    ordering: dict[str, Any],
) -> dict[str, Any]:
    """Set the ordering of firewall policies within one source/destination zone pair.

    The Network Integration ordering endpoint scopes the ordered list to a single zone
    pair and requires ``sourceFirewallZoneId`` and ``destinationFirewallZoneId`` as
    query parameters -- exactly like ``get_firewall_policy_ordering``. The controller
    does NOT read them from the request body: omitting them (or nesting them under any
    body key) makes it reject the write with HTTP 400 every time. They are forwarded
    here explicitly as query params so a set round-trips against the same zone pair a
    get was read from.
    """
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.put(
        _proxy(host_id, f"/sites/{site_id}/firewall/policies/ordering"),
        key=key,
        params={
            "sourceFirewallZoneId": source_zone_id,
            "destinationFirewallZoneId": destination_zone_id,
        },
        json=ordering,
    )


# --- Firewall Zones ---


async def list_firewall_zones(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """List firewall zones for a site.

    This Network Integration endpoint is offset-paginated (verified live: the
    response carries an ``{offset, limit, count, totalCount, data}`` envelope with a
    native default page size of 25). By default every page is drained and the
    complete list is returned as ``{data, totalCount}``; pass offset or limit for a
    single manual page. A capped drain is flagged ``incomplete`` rather than
    truncating silently.
    """
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    url = _proxy(host_id, f"/sites/{site_id}/firewall/zones")
    collected = await collect_offset(client, url, key=key, offset=offset, limit=limit)
    total = collected["totalCount"]
    result: dict[str, Any] = {
        "data": collected["items"],
        "totalCount": total if total is not None else len(collected["items"]),
    }
    return mark_incomplete(result, collected)


async def create_firewall_zone(
    client: UniFiClient, registry: Registry, host: str, site: str, zone: dict[str, Any]
) -> dict[str, Any]:
    """Create a firewall zone.

    Required fields (verified live — an empty body is rejected naming both):
    ``name`` and ``networkIds`` (the list of network IDs the zone contains).
    """
    require_fields("create_firewall_zone", zone, {"name", "networkIds"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.post(
        _proxy(host_id, f"/sites/{site_id}/firewall/zones"), key=key, json=zone
    )


async def get_firewall_zone(
    client: UniFiClient, registry: Registry, host: str, site: str, zone_id: str
) -> dict[str, Any]:
    validate_id(zone_id, "zone_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.get(_proxy(host_id, f"/sites/{site_id}/firewall/zones/{zone_id}"), key=key)


async def update_firewall_zone(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    zone_id: str,
    zone: dict[str, Any],
) -> dict[str, Any]:
    validate_id(zone_id, "zone_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.put(
        _proxy(host_id, f"/sites/{site_id}/firewall/zones/{zone_id}"),
        key=key,
        json=sanitize_integration_write(zone),
    )


async def delete_firewall_zone(
    client: UniFiClient, registry: Registry, host: str, site: str, zone_id: str
) -> None:
    validate_id(zone_id, "zone_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    await client.delete(_proxy(host_id, f"/sites/{site_id}/firewall/zones/{zone_id}"), key=key)


# --- ACL Rules ---


async def list_acl_rules(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> dict[str, Any]:
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.get(_proxy(host_id, f"/sites/{site_id}/acl-rules"), key=key)


async def create_acl_rule(
    client: UniFiClient, registry: Registry, host: str, site: str, rule: dict[str, Any]
) -> dict[str, Any]:
    """Create an ACL rule.

    Required field: ``type`` — the rule's discriminator, which the API validates first
    (verified live: an empty body is rejected with ``Missing $.type value``). Observed
    values include ``MAC``. Fields beyond the discriminator are type-specific (e.g.
    ``name``, ``action``, ``sourceFilter``, ``networkIdFilter``) and are not validated
    here.
    """
    require_fields("create_acl_rule", rule, {"type"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.post(_proxy(host_id, f"/sites/{site_id}/acl-rules"), key=key, json=rule)


async def get_acl_rule(
    client: UniFiClient, registry: Registry, host: str, site: str, rule_id: str
) -> dict[str, Any]:
    validate_id(rule_id, "rule_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.get(_proxy(host_id, f"/sites/{site_id}/acl-rules/{rule_id}"), key=key)


async def update_acl_rule(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    rule_id: str,
    rule: dict[str, Any],
) -> dict[str, Any]:
    validate_id(rule_id, "rule_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.put(
        _proxy(host_id, f"/sites/{site_id}/acl-rules/{rule_id}"),
        key=key,
        json=sanitize_integration_write(rule),
    )


async def delete_acl_rule(
    client: UniFiClient, registry: Registry, host: str, site: str, rule_id: str
) -> None:
    validate_id(rule_id, "rule_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    await client.delete(_proxy(host_id, f"/sites/{site_id}/acl-rules/{rule_id}"), key=key)


async def get_acl_rule_ordering(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> dict[str, Any]:
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.get(_proxy(host_id, f"/sites/{site_id}/acl-rules/ordering"), key=key)


async def set_acl_rule_ordering(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    ordering: dict[str, Any],
) -> dict[str, Any]:
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.put(
        _proxy(host_id, f"/sites/{site_id}/acl-rules/ordering"), key=key, json=ordering
    )
