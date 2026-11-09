"""Firewall tools — policies, zones, and ACL rules via connector proxy."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from fastmcp import FastMCP

from ..client import UniFiClient, validate_id, validate_spec_id
from ..registry import Registry, _assert_uuid
from ..tool_annotations import READ_ONLY, WRITE
from ._pagination import collect_offset, offset_list_result, validate_pagination
from ._payload import integration_update_body, require_fields
from ._results import deletion_result
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
    validate_pagination(page_size=limit, offset=offset, names={"page_size": "limit"})
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
    return offset_list_result(collected)


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
    policy = integration_update_body("update_firewall_policy", policy)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.put(
        _proxy(host_id, f"/sites/{site_id}/firewall/policies/{policy_id}"),
        key=key,
        json=policy,
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
    fields = integration_update_body("patch_firewall_policy", fields)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.patch(
        _proxy(host_id, f"/sites/{site_id}/firewall/policies/{policy_id}"),
        key=key,
        json=fields,
    )


async def delete_firewall_policy(
    client: UniFiClient, registry: Registry, host: str, site: str, policy_id: str
) -> Any:
    validate_id(policy_id, "policy_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.delete(
        _proxy(host_id, f"/sites/{site_id}/firewall/policies/{policy_id}"), key=key
    )


async def get_firewall_policy_ordering(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    source_zone_id: str,
    destination_zone_id: str,
) -> dict[str, Any]:
    # Query-only (sourceFirewallZoneId / destinationFirewallZoneId: format uuid).
    validate_spec_id(source_zone_id, "source_zone_id", uuid=True)
    validate_spec_id(destination_zone_id, "destination_zone_id", uuid=True)
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
    # Query-only (sourceFirewallZoneId / destinationFirewallZoneId: format uuid).
    validate_spec_id(source_zone_id, "source_zone_id", uuid=True)
    validate_spec_id(destination_zone_id, "destination_zone_id", uuid=True)
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
    *,
    filter: str | None = None,
) -> dict[str, Any]:
    """List firewall zones for a site.

    This Network Integration endpoint is offset-paginated (verified live: the
    response carries an ``{offset, limit, count, totalCount, data}`` envelope with a
    native default page size of 25). By default every page is drained and the
    complete list is returned as ``{data, totalCount}``; pass offset or limit for a
    single manual page. A capped drain is flagged ``incomplete`` rather than
    truncating silently. ``filter`` is forwarded unchanged as the server-side filter
    expression in either mode (omitted when ``None``).
    """
    validate_pagination(page_size=limit, offset=offset, names={"page_size": "limit"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    url = _proxy(host_id, f"/sites/{site_id}/firewall/zones")
    params = {"filter": filter} if filter is not None else None
    collected = await collect_offset(
        client, url, key=key, params=params, offset=offset, limit=limit
    )
    return offset_list_result(collected)


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
    zone = integration_update_body("update_firewall_zone_proxy", zone)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.put(
        _proxy(host_id, f"/sites/{site_id}/firewall/zones/{zone_id}"),
        key=key,
        json=zone,
    )


async def delete_firewall_zone(
    client: UniFiClient, registry: Registry, host: str, site: str, zone_id: str
) -> Any:
    validate_id(zone_id, "zone_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.delete(
        _proxy(host_id, f"/sites/{site_id}/firewall/zones/{zone_id}"), key=key
    )


# --- ACL Rules ---


async def list_acl_rules(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    *,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    validate_pagination(page_size=limit, offset=offset, names={"page_size": "limit"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    params = {"filter": filter} if filter is not None else None
    collected = await collect_offset(
        client,
        _proxy(host_id, f"/sites/{site_id}/acl-rules"),
        key=key,
        params=params,
        offset=offset,
        limit=limit,
    )
    return offset_list_result(collected)


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
    rule = integration_update_body("update_acl_rule", rule)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.put(
        _proxy(host_id, f"/sites/{site_id}/acl-rules/{rule_id}"),
        key=key,
        # The published "ACL rule update" schema lists ``index`` as a request property,
        # so the caller's position change is forwarded (firewall policies drop it).
        json=rule,
    )


async def delete_acl_rule(
    client: UniFiClient, registry: Registry, host: str, site: str, rule_id: str
) -> Any:
    validate_id(rule_id, "rule_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.delete(_proxy(host_id, f"/sites/{site_id}/acl-rules/{rule_id}"), key=key)


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


# Tool modules the wrappers below delegate to, imported after this module's
# own definitions so a module importing from this one never sees it half-built.
from . import firewall_proxy  # noqa: E402


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> dict[str, Callable[..., Any]]:
    """Register the firewall_proxy tool wrappers moved from server.py, in order.

    Returns the registered wrapper functions by name; server.py re-exports them.
    """

    @mcp.tool(annotations=READ_ONLY)
    async def list_firewall_policies(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List firewall policies for a site.

        Returns {data, totalCount}: every page is drained; data holds the firewall policy records
        verbatim and totalCount is the upstream total (null when none was reported). The first page's
        other envelope fields are kept beside them, and incomplete / incompleteReason are added when a
        capped drain stopped short.

        By default every page is drained and the complete policy list is returned as
        {data, totalCount}. Pass offset alone to fetch a single page manually (the
        API's totalCount is surfaced so you can advance). filter: optional Network
        Integration API filter expression, forwarded unchanged as the upstream `filter`
        query parameter for server-side filtering (e.g. `name.like('*guest*')`,
        `metadata.origin.eq('USER_DEFINED')`); omitted entirely when unset. A capped drain
        returns the policies gathered so far with incomplete=true rather than truncating
        silently.

        limit requests a total, gathered automatically in batches up to 200;
        _pageSize reports requested count, actual sent sizes per request,
        observed effective size and returned count, without capping the total.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            offset: Optional zero-based starting record; alone, fetch one page manually.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 200, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain all.
                Example: `25`.
            filter: Optional Network Integration API filter expression, forwarded unchanged as the
                upstream `filter` query parameter for server-side filtering (e.g.
                `name.like('*guest*')`). Omitted entirely when unset.
                Example: `metadata.origin.eq('USER_DEFINED')`."""
        client, registry = deps_fn()
        return await firewall_proxy.list_firewall_policies(
            client, registry, host, site, offset, limit, filter=filter
        )

    @mcp.tool(annotations=WRITE)
    async def create_firewall_policy(
        host: str,
        site: str,
        policy: dict[str, Any],
    ) -> Any:
        """Create a new firewall policy on a site.

        Returns the upstream response body verbatim: the created firewall policy object the API
        answers
        with (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
        message,
        preview: {method, path, params (query parameters), body}} instead).

        The seven required keys of `policy` (name, enabled, loggingEnabled, action, source,
        destination, ipProtocolScope) are validated locally — a missing key raises ValueError
        naming it. action.type is ALLOW, BLOCK, or REJECT (ALLOW also requires
        allowReturnTraffic); ipProtocolScope.ipVersion is IPV4, IPV6, or IPV4_AND_IPV6. There is
        NO 'index' field; use set_firewall_policy_ordering to manage rule order. Get zone IDs
        from list_firewall_zones_proxy (data[].id; match zone names case-insensitively).

        For port-only destination matching use destination.trafficFilter type PORT; for combined
        address and port matching use type IP_ADDRESS with portFilter. A source portFilter
        matches ephemeral source ports. Get zone UUIDs from list_firewall_zones_proxy.
        Use set_firewall_policy_ordering; there is no index field. action.type is ALLOW (requires
        allowReturnTraffic), BLOCK or REJECT; ipProtocolScope.ipVersion is IPV4, IPV6 or
        IPV4_AND_IPV6. Parameter schemas contain the complete trafficFilter variants and body shape.
        Detailed examples: docs/TOOL-USAGE.md#create_firewall_policy.

        Required arguments: host, site, policy (see parameter descriptions for identifiers).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            policy: Full policy, schema "Create or update firewall policy". Required: name, enabled,
                loggingEnabled, action{type:ALLOW|BLOCK|REJECT}, source{zoneId}, destination{zoneId},
                ipProtocolScope{ipVersion}.
        """
        client, registry = deps_fn()
        return await firewall_proxy.create_firewall_policy(client, registry, host, site, policy)

    @mcp.tool(annotations=READ_ONLY)
    async def get_firewall_policy(
        host: str,
        site: str,
        policy_id: str,
    ) -> Any:
        """Get a single firewall policy by ID.

        Returns: the firewall policy object, verbatim. To change it, edit it and pass it as `policy` to
        update_firewall_policy (full replace); patch_firewall_policy takes only the fields its schema
        allows, as `fields`.

        Example call (get_firewall_policy):
            {
              "host": "my-console",
              "site": "Default",
              "policy_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            policy_id: Firewall policy UUID. Get it from list_firewall_policies (data[].id). Network-app
                UUID — not a Protect id.
        """
        client, registry = deps_fn()
        return await firewall_proxy.get_firewall_policy(client, registry, host, site, policy_id)

    @mcp.tool(annotations=WRITE)
    async def update_firewall_policy(
        host: str,
        site: str,
        policy_id: str,
        policy: dict[str, Any],
    ) -> Any:
        """Full-replace a firewall policy by ID.

        Returns the upstream response body verbatim: the replaced firewall policy object the API
        answers
        with (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
        message,
        preview: {method, path, params (query parameters), body}} instead).

        For port-only destination matching use destination.trafficFilter type PORT; for combined
        address and port matching use type IP_ADDRESS with portFilter. A source portFilter
        matches ephemeral source ports. Get zone UUIDs from list_firewall_zones_proxy.
        Use set_firewall_policy_ordering; there is no index field. action.type is ALLOW (requires
        allowReturnTraffic), BLOCK or REJECT; ipProtocolScope.ipVersion is IPV4, IPV6 or
        IPV4_AND_IPV6. Full replacement: get_firewall_policy, edit and send the entire object;
        omitted optional fields are cleared. Parameter schemas contain the complete trafficFilter
        variants and body shape. Detailed examples: docs/TOOL-USAGE.md#update_firewall_policy.

        Required arguments: host, site, policy_id, policy (see parameter descriptions for
        identifiers).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            policy_id: Firewall policy UUID. Get it from list_firewall_policies (data[].id). Network-app
                UUID — not a Protect id.
            policy: Complete official firewall policy object. Fetch it with get_firewall_policy;
                omitted optional fields are cleared by this PUT.
        """
        client, registry = deps_fn()
        return await firewall_proxy.update_firewall_policy(
            client, registry, host, site, policy_id, policy
        )

    @mcp.tool(annotations=WRITE)
    async def patch_firewall_policy(
        host: str,
        site: str,
        policy_id: str,
        fields: dict[str, Any],
    ) -> Any:
        """Partially update a firewall policy by ID.

        Returns the upstream response body verbatim: the updated firewall policy object the API answers
        with (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
        message,
        preview: {method, path, params (query parameters), body}} instead).

        Request body (Network 11.0.97, PATCH /v1/sites/{siteId}/firewall/policies/{firewallPolicyId}
        (patchFirewallPolicy); schema "Patch firewall policy") is passed in `fields`. No key is
        required; send only the keys to change.
        - loggingEnabled: boolean
        - reportFlowEnabled: boolean (report matched traffic in Insights Flows; ignored for the
          predefined Allow Return Traffic, multicast-only and IPv6 neighbor-discovery policies)
        Only loggingEnabled and reportFlowEnabled are patchable per spec; enabled/name/action
        changes need update_firewall_policy (full PUT).

        Example call (patch_firewall_policy):
            {
              "host": "my-console",
              "site": "Default",
              "policy_id": "7d1e4a52-1c3b-4f6e-8a90-0b1c2d3e4f01",
              "fields": {"loggingEnabled": true}
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            policy_id: Firewall policy UUID. Get it from list_firewall_policies (data[].id). Network-app
                UUID — not a Protect id.
            fields: Partial update. Spec "Patch firewall policy" defines ONLY loggingEnabled and
                reportFlowEnabled (booleans). For any other change use update_firewall_policy.
        """
        client, registry = deps_fn()
        return await firewall_proxy.patch_firewall_policy(
            client, registry, host, site, policy_id, fields
        )

    @mcp.tool(annotations=WRITE)
    async def delete_firewall_policy(
        host: str,
        site: str,
        policy_id: str,
    ) -> dict[str, Any]:
        """Delete a firewall policy.

        Consequence: the policy stops applying immediately, so traffic it allowed or blocked falls
        through to the remaining policies; there is no undo.

        Returns {deleted: true, message, response}; response is the upstream DELETE body verbatim
        (decoded JSON, the raw text of a non-JSON body, or null when the body is empty).
        Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false, message,
        response (the preview)}.

        Example call (delete_firewall_policy):
            {
              "host": "my-console",
              "site": "Default",
              "policy_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            policy_id: Firewall policy UUID. Get it from list_firewall_policies (data[].id). Network-app
                UUID — not a Protect id.
        """
        client, registry = deps_fn()
        response = await firewall_proxy.delete_firewall_policy(
            client, registry, host, site, policy_id
        )
        return deletion_result(f"Firewall policy {policy_id} deleted.", response)

    @mcp.tool(annotations=READ_ONLY)
    async def get_firewall_policy_ordering(
        host: str,
        site: str,
        source_zone_id: str,
        destination_zone_id: str,
    ) -> Any:
        """Get the ordering of firewall policies for a site filtered by source and destination zone.

        Returns: {"orderedFirewallPolicyIds": {"beforeSystemDefined": [policy id…],
        "afterSystemDefined": [policy id…]}}, verbatim — the user-defined order for this zone pair. Pass
        it verbatim (reordered, or unchanged for a no-op) as `ordering` to set_firewall_policy_ordering
        with the same source_zone_id and destination_zone_id.
        Ordering is per source/destination zone pair: find the pairs that have policies by
        calling list_firewall_policies and grouping data[] by source.zoneId /
        destination.zoneId (its `filter` narrows it, e.g. metadata.origin.eq('USER_DEFINED')).

        Prerequisite — {"tool": "list_firewall_zones_proxy", "arguments": {"host": "my-console", "site":
        "Default"}, "use": "data[].id of the source and destination zones"}.

        Example call (get_firewall_policy_ordering):
            {
              "host": "my-console",
              "site": "Default",
              "source_zone_id": "0b6c3c4e-6a0f-4f3e-9a51-6a2b8f0c1d01",
              "destination_zone_id": "0b6c3c4e-6a0f-4f3e-9a51-6a2b8f0c1d02"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            source_zone_id: REQUIRED source firewall zone UUID, sent as query param
                sourceFirewallZoneId. Get it from list_firewall_zones_proxy (data[].id); pick the zone
                by name case-insensitively (e.g. Internal, External). Network UUID.
            destination_zone_id: REQUIRED destination firewall zone UUID, sent as query param
                destinationFirewallZoneId. Get it from list_firewall_zones_proxy (data[].id); pick the
                zone by name case-insensitively (e.g. Internal, External). Network UUID.
        """
        client, registry = deps_fn()
        return await firewall_proxy.get_firewall_policy_ordering(
            client, registry, host, site, source_zone_id, destination_zone_id
        )

    @mcp.tool(annotations=WRITE)
    async def set_firewall_policy_ordering(
        host: str,
        site: str,
        source_zone_id: str,
        destination_zone_id: str,
        ordering: dict[str, Any],
    ) -> Any:
        """Set the ordering of firewall policies within one source/destination zone pair.

        Returns: the controller's response, verbatim — the resulting order in the same
        {"orderedFirewallPolicyIds": {"beforeSystemDefined": […], "afterSystemDefined": […]}} shape
        (published response schema IntegrationFirewallPolicyOrderingDto).
        Under dry-run policy nothing is sent: the result is the bare dry-run preview {status: "dry_run",
        dryRun: true, sent: false,
        message, preview: {method, path, params, body}} in place of the upstream body.

        Full replace of the user-defined order for ONE source/destination zone pair: start from
        get_firewall_policy_ordering for the same pair, reorder, and send it back. Use [] for an empty
        side. Afterwards, read back with get_firewall_policy_ordering and compare. If either zone id is
        missing, upstream returns HTTP 400 (the zone ids are query parameters, never read from the
        body).

        Example call (set_firewall_policy_ordering):
            {"host": "my-console", "site": "Default",
             "source_zone_id": "0b6c3c4e-6a0f-4f3e-9a51-6a2b8f0c1d01",
             "destination_zone_id": "0b6c3c4e-6a0f-4f3e-9a51-6a2b8f0c1d02",
             "ordering": {"orderedFirewallPolicyIds": {
               "beforeSystemDefined": ["7d1e4a52-1c3b-4f6e-8a90-0b1c2d3e4f02"],
               "afterSystemDefined": []}}}

        Full request shapes are in the parameter schema; detailed examples and workflows:
        docs/TOOL-USAGE.md#set_firewall_policy_ordering.

        Required arguments: host, site, source_zone_id, destination_zone_id, ordering (see parameter
        descriptions for identifiers).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            source_zone_id: REQUIRED source firewall zone UUID, sent as query param
                sourceFirewallZoneId. Get it from list_firewall_zones_proxy (data[].id); pick the zone
                by name case-insensitively (e.g. Internal, External). Network UUID.
            destination_zone_id: REQUIRED destination firewall zone UUID, sent as query param
                destinationFirewallZoneId. Get it from list_firewall_zones_proxy (data[].id); pick the
                zone by name case-insensitively (e.g. Internal, External). Network UUID.
            ordering: Full replacement
                {"orderedFirewallPolicyIds":{"beforeSystemDefined":[uuid…],"afterSystemDefined":[uuid…]}};
                both arrays required. Start from get_firewall_policy_ordering output.
        """
        client, registry = deps_fn()
        return await firewall_proxy.set_firewall_policy_ordering(
            client, registry, host, site, source_zone_id, destination_zone_id, ordering
        )

    # --- Firewall Zone Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_firewall_zones_proxy(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List all firewall zones for a site via connector proxy.

        This is the firewall-zone list; the _proxy suffix is historical. Returns {data: [{id, name,
        networkIds, metadata: {origin, configurable}}], totalCount}. System-defined zones
        (metadata.origin SYSTEM_DEFINED) carry the names the controller returns — Internal, External,
        Gateway, Vpn, Hotspot and Dmz on Network 11.0.81 — so compare zone names case-insensitively
        ("VPN" matches "Vpn"). Every other tool takes a zone by its id (data[].id), never by name.

        Zones are offset-paginated (native default page size 25); by default every page is
        drained and the complete list is returned as {data, totalCount}. Pass offset alone for a
        single manual page. A capped drain is flagged incomplete.

        limit requests a total, gathered automatically in batches up to 200;
        _pageSize reports requested count, actual sent sizes per request,
        observed effective size and returned count, without capping the total.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            offset: Optional zero-based starting record; alone, fetch one page manually.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 200, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain all.
                Example: `25`.
            filter: Optional Network Integration API filter expression, forwarded unchanged as the
                upstream `filter` query parameter for server-side filtering (e.g.
                `name.like('*guest*')`). Omitted entirely when unset; applies when draining and
                when paging manually.
                Example: `metadata.origin.eq('USER_DEFINED')`."""
        client, registry = deps_fn()
        return await firewall_proxy.list_firewall_zones(
            client, registry, host, site, offset=offset, limit=limit, filter=filter
        )

    @mcp.tool(annotations=WRITE)
    async def create_firewall_zone_proxy(
        host: str,
        site: str,
        zone: dict[str, Any],
    ) -> Any:
        """Create a new firewall zone on a site via connector proxy.

        Returns the upstream response body verbatim: the created firewall zone object the API answers
        with (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
        message,
        preview: {method, path, params (query parameters), body}} instead).

        `zone`: must include {'name': str, 'networkIds': [str]} — both required, validated
        locally (a missing field raises ValueError naming it) and verified against the live
        controller. Get network IDs from list_networks.

        Request body (Network 11.0.97, POST /v1/sites/{siteId}/firewall/zones (createFirewallZone);
        schema "Create or update firewall zone") is passed in `zone`. Required keys — name, networkIds.
        - name: string
        - networkIds: array of string (uuid)

        Example call (create_firewall_zone_proxy):
            {
              "host": "my-console",
              "site": "Default",
              "zone": {"name": "Hotspot", "networkIds": ["dfb21062-8ea0-4dca-b1d8-1eb3da00e58b"]}
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            zone: Full object to create; spec Create or update firewall zone. Required: name,
                networkIds.
        """
        client, registry = deps_fn()
        return await firewall_proxy.create_firewall_zone(client, registry, host, site, zone)

    @mcp.tool(annotations=READ_ONLY)
    async def get_firewall_zone_proxy(
        host: str,
        site: str,
        zone_id: str,
    ) -> Any:
        """Get a single firewall zone by ID via connector proxy.

        Returns: the firewall zone object, verbatim. To change it, edit it and pass it as `zone` to
        update_firewall_zone_proxy.

        Example call (get_firewall_zone_proxy):
            {"host": "my-console", "site": "Default", "zone_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            zone_id: Firewall zone UUID. Get it from list_firewall_zones_proxy (data[].id). Network-app
                UUID — not a Protect id.
        """
        client, registry = deps_fn()
        return await firewall_proxy.get_firewall_zone(client, registry, host, site, zone_id)

    @mcp.tool(annotations=WRITE)
    async def update_firewall_zone_proxy(
        host: str,
        site: str,
        zone_id: str,
        zone: dict[str, Any],
    ) -> Any:
        """Update a firewall zone by ID via connector proxy.

        Returns the upstream response body verbatim: the updated firewall zone object the API answers
        with (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
        message,
        preview: {method, path, params (query parameters), body}} instead).

        Request body (Network 11.0.97, PUT /v1/sites/{siteId}/firewall/zones/{firewallZoneId}
        (updateFirewallZone); schema "Create or update firewall zone") is passed in `zone`. Required
        keys — name, networkIds.
        - name: string
        - networkIds: array of string (uuid)

        Example call (update_firewall_zone_proxy):
            {
              "host": "my-console",
              "site": "Default",
              "zone_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
              "zone": {"name": "Hotspot", "networkIds": ["dfb21062-8ea0-4dca-b1d8-1eb3da00e58b"]}
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            zone_id: Firewall zone UUID. Get it from list_firewall_zones_proxy (data[].id). Network-app
                UUID — not a Protect id.
            zone: FULL replacement object (PUT; omitted fields reset); spec Create or update firewall
                zone. Required: name, networkIds.
        """
        client, registry = deps_fn()
        return await firewall_proxy.update_firewall_zone(
            client, registry, host, site, zone_id, zone
        )

    @mcp.tool(annotations=WRITE)
    async def delete_firewall_zone_proxy(
        host: str,
        site: str,
        zone_id: str,
    ) -> dict[str, Any]:
        """Delete a firewall zone via connector proxy.

        Consequence: the zone is permanently removed; there is no undo.

        Returns {deleted: true, message, response}; response is the upstream DELETE body verbatim
        (decoded JSON, the raw text of a non-JSON body, or null when the body is empty).
        Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false, message,
        response (the preview)}.

        Example call (delete_firewall_zone_proxy):
            {"host": "my-console", "site": "Default", "zone_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            zone_id: Firewall zone UUID. Get it from list_firewall_zones_proxy (data[].id). Network-app
                UUID — not a Protect id.
        """
        client, registry = deps_fn()
        response = await firewall_proxy.delete_firewall_zone(client, registry, host, site, zone_id)
        return deletion_result(f"Firewall zone {zone_id} deleted.", response)

    # --- ACL Rule Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_acl_rules(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List all ACL rules for a site.

        ACL rules include IPv4 network-layer (L3) and MAC access lists, used to filter traffic
        between networks or within a VLAN. Use them only when the user asks for ACL rules; for an
        ordinary firewall rule use zone-based firewall policies (create_firewall_policy).

        Returns {data, totalCount} with every page drained (the API pages at 25 by default).
        Pass offset alone to fetch a single manual page (native envelope preserved).

        limit requests a total, gathered automatically in batches up to 200;
        _pageSize reports requested count, actual sent sizes per request,
        observed effective size and returned count, without capping the total.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            offset: Optional zero-based starting record; alone, fetch one page manually.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 200, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain all.
                Example: `25`.
            filter: Optional Network Integration API filter expression, forwarded unchanged as the
                upstream `filter` query parameter for server-side filtering (e.g.
                `name.like('*guest*')`). Omitted entirely when unset; applies when draining and
                when paging manually.
                Example: `metadata.origin.eq('USER_DEFINED')`."""
        client, registry = deps_fn()
        return await firewall_proxy.list_acl_rules(
            client, registry, host, site, offset=offset, limit=limit, filter=filter
        )

    @mcp.tool(annotations=WRITE)
    async def create_acl_rule(
        host: str,
        site: str,
        rule: dict[str, Any],
    ) -> Any:
        """Create a new ACL rule on a site.

        Returns the upstream response body verbatim: the created ACL rule object the API answers with
        (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
        message, preview: {method, path, params (query parameters), body}} instead).

        Validated locally before the request (a missing field raises ValueError naming it):
        ``type`` — the discriminator the controller validates first (verified live: an empty
        body is rejected with ``Missing $.type value``; observed value: 'MAC'). The remaining
        fields are type-specific and enforced by the controller.
        `rule`: for a MAC-type rule the live object also carries: name (str), action, enabled
        (bool), sourceFilter, networkIdFilter. Read an existing rule with get_acl_rule to see
        the exact shape for the type you want.
        Note: ACL rules include IPv4 network-layer (L3) and MAC access lists for filtering traffic
        between networks or within a VLAN. Use them only when the user asks for ACL rules; otherwise
        use zone-based firewall policies (create_firewall_policy).

        Request body (Network 11.0.97, POST /v1/sites/{siteId}/acl-rules (createAclRule); schema "ACL
        rule update") is passed in `rule`. Required keys — action, enabled, name, type.
        - action: enum[ALLOW|BLOCK]
        - description: string
        - destinationFilter: any
        - enabled: boolean
        - enforcingDeviceFilter: oneOf by type[DEVICES] (ACL rule device filter)
        - index: integer(int32); deprecated, no effect per spec: reorder with set_acl_rule_ordering
        - name: string
        - sourceFilter: any
        - type: string
        Variants by `type` — IPV4 requires action, enabled, name, type; MAC requires action, enabled,
        name, networkIdFilter, type.

        Example call (create_acl_rule):
            {
              "host": "my-console",
              "site": "Default",
              "rule": {
                "type": "IPV4",
                "action": "ALLOW",
                "enabled": true,
                "name": "Allow printer access"
              }
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            rule: Full object to create; spec ACL rule update. Required: action, enabled, name, type.
                'type' selects variant: IPV4|MAC.
        """
        client, registry = deps_fn()
        return await firewall_proxy.create_acl_rule(client, registry, host, site, rule)

    @mcp.tool(annotations=READ_ONLY)
    async def get_acl_rule(
        host: str,
        site: str,
        rule_id: str,
    ) -> Any:
        """Get a single ACL rule by ID.

        Returns: the ACL rule object, verbatim. To change it, edit it and pass it as `rule` to
        update_acl_rule.

        Example call (get_acl_rule):
            {"host": "my-console", "site": "Default", "rule_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            rule_id: ACL rule UUID. Get it from list_acl_rules (data[].id). Network-app UUID — not a
                Protect id.
        """
        client, registry = deps_fn()
        return await firewall_proxy.get_acl_rule(client, registry, host, site, rule_id)

    @mcp.tool(annotations=WRITE)
    async def update_acl_rule(
        host: str,
        site: str,
        rule_id: str,
        rule: dict[str, Any],
    ) -> Any:
        """Update an existing ACL rule by ID.

        Returns the upstream response body verbatim: the updated ACL rule object the API answers with
        (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
        message, preview: {method, path, params (query parameters), body}} instead).

        Request body (Network 11.0.97, PUT /v1/sites/{siteId}/acl-rules/{aclRuleId} (updateAclRule);
        schema "ACL rule update") is passed in `rule`. Required keys — action, enabled, name, type.
        - action: enum[ALLOW|BLOCK]
        - description: string
        - destinationFilter: any
        - enabled: boolean
        - enforcingDeviceFilter: oneOf by type[DEVICES] (ACL rule device filter)
        - index: integer(int32); deprecated, no effect per spec: reorder with set_acl_rule_ordering
        - name: string
        - sourceFilter: any
        - type: string
        Variants by `type` — IPV4 requires action, enabled, name, type; MAC requires action, enabled,
        name, networkIdFilter, type.

        Example call (update_acl_rule):
            {
              "host": "my-console",
              "site": "Default",
              "rule_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
              "rule": {
                "type": "IPV4",
                "action": "ALLOW",
                "enabled": true,
                "name": "Allow printer access"
              }
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            rule_id: ACL rule UUID. Get it from list_acl_rules (data[].id). Network-app UUID — not a
                Protect id.
            rule: FULL replacement object (PUT; omitted fields reset); spec ACL rule update. Required:
                action, enabled, name, type. 'type' selects variant: IPV4|MAC.
        """
        client, registry = deps_fn()
        return await firewall_proxy.update_acl_rule(client, registry, host, site, rule_id, rule)

    @mcp.tool(annotations=WRITE)
    async def delete_acl_rule(
        host: str,
        site: str,
        rule_id: str,
    ) -> dict[str, Any]:
        """Delete an ACL rule.

        Consequence: the rule stops filtering traffic immediately; there is no undo (recreate it from a
        saved copy).

        Returns {deleted: true, message, response}; response is the upstream DELETE body verbatim
        (decoded JSON, the raw text of a non-JSON body, or null when the body is empty).
        Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false, message,
        response (the preview)}.

        Example call (delete_acl_rule):
            {"host": "my-console", "site": "Default", "rule_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            rule_id: ACL rule UUID. Get it from list_acl_rules (data[].id). Network-app UUID — not a
                Protect id.
        """
        client, registry = deps_fn()
        response = await firewall_proxy.delete_acl_rule(client, registry, host, site, rule_id)
        return deletion_result(f"ACL rule {rule_id} deleted.", response)

    @mcp.tool(annotations=READ_ONLY)
    async def get_acl_rule_ordering(
        host: str,
        site: str,
    ) -> Any:
        """Get the ordering of ACL rules for a site.

        Returns: {"orderedAclRuleIds": [rule id…]}, verbatim, in evaluation order. Pass it verbatim
        (reordered, or unchanged for a no-op) as `ordering` to set_acl_rule_ordering.

        Example call (get_acl_rule_ordering):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await firewall_proxy.get_acl_rule_ordering(client, registry, host, site)

    @mcp.tool(annotations=WRITE)
    async def set_acl_rule_ordering(
        host: str,
        site: str,
        ordering: dict[str, Any],
    ) -> Any:
        """Set the ordering of ACL rules for a site.

        Returns: the controller's response, verbatim — the resulting order in the same
        {"orderedAclRuleIds": […]} shape (published response schema "ACL rule ordering").
        Under dry-run policy nothing is sent: the result is the bare dry-run preview {status: "dry_run",
        dryRun: true, sent: false,
        message, preview: {method, path, params, body}} in place of the upstream body.

        Request body (Network 11.0.97, PUT /v1/sites/{siteId}/acl-rules/ordering
        (updateAclRuleOrdering) — "Reorder User-Defined ACL Rules"; schema "ACL rule ordering") is
        passed in `ordering` (sent verbatim as the body). Required keys — orderedAclRuleIds.
        - orderedAclRuleIds: array of string (uuid)
        Full replace of the site-wide user-defined ACL rule order. No zone/query params. Read with
        get_acl_rule_ordering first.

        Typical sequence (one tool call per step):
        1. get_acl_rule_ordering(host="my-console", site="Default").
        2. set_acl_rule_ordering(host="my-console", site="Default", ordering={…}).
        3. get_acl_rule_ordering(host="my-console", site="Default") — read back and compare.

        Example call (set_acl_rule_ordering):
            {
              "host": "my-console",
              "site": "Default",
              "ordering": {
                "orderedAclRuleIds": [
                  "5c2b9e10-3d4f-4a6b-9c8d-7e6f5a4b3c02",
                  "5c2b9e10-3d4f-4a6b-9c8d-7e6f5a4b3c01"
                ]
              }
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            ordering: Full replacement {"orderedAclRuleIds":[uuid…]} in evaluation order (schema "ACL
                rule ordering"). Start from get_acl_rule_ordering; ids from list_acl_rules.
        """
        client, registry = deps_fn()
        return await firewall_proxy.set_acl_rule_ordering(client, registry, host, site, ordering)

    return {
        "list_firewall_policies": list_firewall_policies,
        "create_firewall_policy": create_firewall_policy,
        "get_firewall_policy": get_firewall_policy,
        "update_firewall_policy": update_firewall_policy,
        "patch_firewall_policy": patch_firewall_policy,
        "delete_firewall_policy": delete_firewall_policy,
        "get_firewall_policy_ordering": get_firewall_policy_ordering,
        "set_firewall_policy_ordering": set_firewall_policy_ordering,
        "list_firewall_zones_proxy": list_firewall_zones_proxy,
        "create_firewall_zone_proxy": create_firewall_zone_proxy,
        "get_firewall_zone_proxy": get_firewall_zone_proxy,
        "update_firewall_zone_proxy": update_firewall_zone_proxy,
        "delete_firewall_zone_proxy": delete_firewall_zone_proxy,
        "list_acl_rules": list_acl_rules,
        "create_acl_rule": create_acl_rule,
        "get_acl_rule": get_acl_rule,
        "update_acl_rule": update_acl_rule,
        "delete_acl_rule": delete_acl_rule,
        "get_acl_rule_ordering": get_acl_rule_ordering,
        "set_acl_rule_ordering": set_acl_rule_ordering,
    }
