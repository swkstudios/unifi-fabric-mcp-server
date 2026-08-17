"""Network services tools — DNS, traffic lists, VPN, RADIUS, hotspot via connector proxy."""

from __future__ import annotations

from typing import Any

from ..client import UniFiClient, validate_id
from ..config import APIKeyConfig
from ..registry import Registry, _assert_uuid
from ._pagination import collect_offset, mark_incomplete
from ._payload import require_fields, sanitize_integration_write, strip_empty_list_values
from .network import _proxy


async def _drain_offset_list(
    client: UniFiClient,
    url: str,
    *,
    key: APIKeyConfig | None = None,
    offset: int | None,
    limit: int | None,
) -> dict[str, Any]:
    """Offset list fetch: drain all pages by default, single page when paged manually."""
    if offset is not None or limit is not None:
        params: dict[str, Any] = {}
        if offset is not None:
            params["offset"] = offset
        if limit is not None:
            params["limit"] = limit
        result: dict[str, Any] = await client.get(url, key=key, params=params or None)
        return result
    collected = await collect_offset(client, url, key=key)
    total = collected["totalCount"]
    drained: dict[str, Any] = {
        "data": collected["items"],
        "totalCount": total if total is not None else len(collected["items"]),
    }
    return mark_incomplete(drained, collected)


# --- DNS Policies ---


async def list_dns_policies(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """List DNS policies for a site.

    This Network Integration endpoint is offset-paginated (verified live: the
    response carries an ``{offset, limit, count, totalCount, data}`` envelope and
    the native default page size is only 25). By default every page is drained and
    the complete list is returned as ``{data, totalCount}``; pass offset or limit to
    fetch a single manual page (native envelope preserved). A capped drain is
    flagged ``incomplete`` rather than truncating silently.
    """
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await _drain_offset_list(
        client,
        _proxy(host_id, f"/sites/{site_id}/dns/policies"),
        key=key,
        offset=offset,
        limit=limit,
    )


async def create_dns_policy(
    client: UniFiClient, registry: Registry, host: str, site: str, policy: dict[str, Any]
) -> dict[str, Any]:
    """Create a DNS policy.

    Required field: ``type`` — the policy's discriminator, which the API validates first
    (verified live: an empty body is rejected with ``Missing $.type value``). Fields
    beyond the discriminator are type-specific and are not validated here.
    """
    require_fields("create_dns_policy", policy, {"type"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.post(
        _proxy(host_id, f"/sites/{site_id}/dns/policies"), key=key, json=policy
    )


async def get_dns_policy(
    client: UniFiClient, registry: Registry, host: str, site: str, policy_id: str
) -> dict[str, Any]:
    validate_id(policy_id, "policy_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.get(_proxy(host_id, f"/sites/{site_id}/dns/policies/{policy_id}"), key=key)


async def update_dns_policy(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    policy_id: str,
    policy: dict[str, Any],
) -> dict[str, Any]:
    validate_id(policy_id, "policy_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.put(
        _proxy(host_id, f"/sites/{site_id}/dns/policies/{policy_id}"),
        key=key,
        json=sanitize_integration_write(policy),
    )


async def delete_dns_policy(
    client: UniFiClient, registry: Registry, host: str, site: str, policy_id: str
) -> None:
    validate_id(policy_id, "policy_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    await client.delete(_proxy(host_id, f"/sites/{site_id}/dns/policies/{policy_id}"), key=key)


# --- Traffic Matching Lists ---


async def list_traffic_matching_lists(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> dict[str, Any]:
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.get(_proxy(host_id, f"/sites/{site_id}/traffic-matching-lists"), key=key)


async def create_traffic_matching_list(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    traffic_list: dict[str, Any],
) -> dict[str, Any]:
    """Create a traffic-matching list.

    Required field: ``type`` — the list's discriminator, which the API validates first
    (verified live: an empty body is rejected with ``Missing $.type value``). Observed
    values include ``PORTS``. Fields beyond the discriminator (e.g. ``name``, ``items``)
    are type-specific and are not validated here.
    """
    require_fields("create_traffic_matching_list", traffic_list, {"type"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.post(
        _proxy(host_id, f"/sites/{site_id}/traffic-matching-lists"), key=key, json=traffic_list
    )


async def get_traffic_matching_list(
    client: UniFiClient, registry: Registry, host: str, site: str, list_id: str
) -> dict[str, Any]:
    validate_id(list_id, "list_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.get(
        _proxy(host_id, f"/sites/{site_id}/traffic-matching-lists/{list_id}"), key=key
    )


async def update_traffic_matching_list(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    list_id: str,
    traffic_list: dict[str, Any],
) -> dict[str, Any]:
    validate_id(list_id, "list_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.put(
        _proxy(host_id, f"/sites/{site_id}/traffic-matching-lists/{list_id}"),
        key=key,
        json=sanitize_integration_write(traffic_list),
    )


async def delete_traffic_matching_list(
    client: UniFiClient, registry: Registry, host: str, site: str, list_id: str
) -> None:
    validate_id(list_id, "list_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    await client.delete(
        _proxy(host_id, f"/sites/{site_id}/traffic-matching-lists/{list_id}"), key=key
    )


# --- VPN Servers (read-only) ---


async def list_vpn_servers(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """List VPN servers for a site.

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
    return await _drain_offset_list(
        client,
        _proxy(host_id, f"/sites/{site_id}/vpn/servers"),
        key=key,
        offset=offset,
        limit=limit,
    )


async def list_site_to_site_tunnels(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> dict[str, Any]:
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.get(_proxy(host_id, f"/sites/{site_id}/vpn/site-to-site-tunnels"), key=key)


# --- RADIUS Profiles (read-only) ---


async def list_radius_profiles(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """List RADIUS profiles for a site.

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
    return await _drain_offset_list(
        client,
        _proxy(host_id, f"/sites/{site_id}/radius/profiles"),
        key=key,
        offset=offset,
        limit=limit,
    )


# --- Hotspot Vouchers ---


async def list_hotspot_vouchers(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """List hotspot vouchers for a site.

    This Network Integration endpoint is offset-paginated (verified live: the
    response carries an ``{offset, limit, count, totalCount, data}`` envelope with a
    native default page size of 100). Voucher batches routinely exceed that, so a
    single page silently truncated large sets. By default every page is now drained
    and the complete list is returned as ``{data, totalCount}``; pass offset or limit
    for a single manual page. A capped drain is flagged ``incomplete`` rather than
    truncating silently.
    """
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await _drain_offset_list(
        client,
        _proxy(host_id, f"/sites/{site_id}/hotspot/vouchers"),
        key=key,
        offset=offset,
        limit=limit,
    )


async def create_hotspot_vouchers(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    voucher_config: dict[str, Any],
) -> dict[str, Any]:
    """Create a hotspot voucher batch.

    Required fields (verified live — an empty body is rejected naming both):
    ``name`` and ``timeLimitMinutes`` (the voucher validity window in minutes).
    """
    require_fields("create_hotspot_vouchers", voucher_config, {"name", "timeLimitMinutes"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.post(
        _proxy(host_id, f"/sites/{site_id}/hotspot/vouchers"), key=key, json=voucher_config
    )


async def get_hotspot_voucher(
    client: UniFiClient, registry: Registry, host: str, site: str, voucher_id: str
) -> dict[str, Any]:
    validate_id(voucher_id, "voucher_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.get(
        _proxy(host_id, f"/sites/{site_id}/hotspot/vouchers/{voucher_id}"), key=key
    )


async def delete_hotspot_voucher(
    client: UniFiClient, registry: Registry, host: str, site: str, voucher_id: str
) -> None:
    validate_id(voucher_id, "voucher_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    await client.delete(_proxy(host_id, f"/sites/{site_id}/hotspot/vouchers/{voucher_id}"), key=key)


async def bulk_delete_hotspot_vouchers(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    params: dict[str, Any],
) -> None:
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    await client.delete(
        _proxy(host_id, f"/sites/{site_id}/hotspot/vouchers"), key=key, params=params
    )


# --- Supporting Resources ---


async def list_device_tags(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> dict[str, Any]:
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.get(_proxy(host_id, f"/sites/{site_id}/device-tags"), key=key)


async def list_countries(client: UniFiClient, registry: Registry, host: str) -> dict[str, Any]:
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    return await client.get(_proxy(host_id, "/countries"), key=key)


# --- Port Forwards (Classic REST API) ---

# Classic REST: /proxy/network/api/s/{site_slug}/rest/portforward
_CLASSIC_REST_BASE = "/v1/connector/consoles/{host_id}/proxy/network/api/s/{site_slug}/rest"
# Traffic Rules v2: /proxy/network/v2/api/site/{site_slug}/trafficrules
_V2_API_BASE = "/v1/connector/consoles/{host_id}/proxy/network/v2/api/site/{site_slug}"
# Classic Stat: /proxy/network/api/s/{site_slug}/stat
_CLASSIC_STAT_BASE = "/v1/connector/consoles/{host_id}/proxy/network/api/s/{site_slug}/stat"


def _classic_rest(host_id: str, site_slug: str, path: str) -> str:
    return _CLASSIC_REST_BASE.format(host_id=host_id, site_slug=site_slug) + path


def _v2_api(host_id: str, site_slug: str, path: str) -> str:
    return _V2_API_BASE.format(host_id=host_id, site_slug=site_slug) + path


def _classic_stat(host_id: str, site_slug: str, path: str) -> str:
    return _CLASSIC_STAT_BASE.format(host_id=host_id, site_slug=site_slug) + path


async def list_port_forwards(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> dict[str, Any]:
    """List port-forward rules for a site via the Classic REST API.

    Example response item: {"_id": "abc123", "name": "SSH", "dst_port": "2222",
    "fwd": "192.168.1.10", "fwd_port": "22", "proto": "tcp", "enabled": true}
    """
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.get(_classic_rest(host_id, site_slug, "/portforward"), key=key)


async def create_port_forward(
    client: UniFiClient, registry: Registry, host: str, site: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """Create a port-forward rule via the Classic REST API.

    Required fields: name (str), dst_port (str), fwd (str), fwd_port (str).
    ``proto`` is optional — the controller defaults it (typically ``tcp_udp``) when
    omitted. Verified live that this Classic REST endpoint enforces *no* required
    fields server-side: it accepts an empty body and silently creates a broken rule,
    so this local check is the only guard against a malformed forward.
    Example: {"enabled": true, "name": "SSH", "pfwd_interface": "wan", "src": "any",
    "dst_port": "2222", "fwd": "192.168.1.10", "fwd_port": "22", "proto": "tcp", "log": false}
    """
    require_fields("create_port_forward", payload, {"name", "dst_port", "fwd", "fwd_port"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.post(
        _classic_rest(host_id, site_slug, "/portforward"), key=key, json=payload
    )


async def update_port_forward(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    forward_id: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Update a port-forward rule via the Classic REST API."""
    validate_id(forward_id, "forward_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.put(
        _classic_rest(host_id, site_slug, f"/portforward/{forward_id}"),
        key=key,
        json=strip_empty_list_values(payload),
    )


async def delete_port_forward(
    client: UniFiClient, registry: Registry, host: str, site: str, forward_id: str
) -> None:
    """Delete a port-forward rule via the Classic REST API."""
    validate_id(forward_id, "forward_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    await client.delete(_classic_rest(host_id, site_slug, f"/portforward/{forward_id}"), key=key)


# --- Traffic Rules (v2 API) ---


async def list_traffic_rules(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> dict[str, Any]:
    """List traffic rules for a site via the v2 API.

    Example response item: {"_id": "rule-1", "description": "Block Social Media",
    "action": "BLOCK", "matching_target": "INTERNET", "enabled": true}
    The v2 API may return a bare list; this is normalized to {"data": [...], "count": N}.
    """
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    result = await client.get(_v2_api(host_id, site_slug, "/trafficrules"), key=key)
    if isinstance(result, list):
        return {"data": result, "count": len(result)}
    return result


async def create_traffic_rule(
    client: UniFiClient, registry: Registry, host: str, site: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """Create a traffic rule via the v2 API.

    Required fields (verified live): ``action``, ``matching_target`` and
    ``target_devices``. Note that ``target_devices`` — the devices/networks the rule
    applies to — is required by the API but was previously undocumented, while
    ``description`` and ``enabled`` are *not* API-required (the controller defaults
    ``enabled``); both are accepted as optional fields.
    """
    require_fields("create_traffic_rule", payload, {"action", "matching_target", "target_devices"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.post(_v2_api(host_id, site_slug, "/trafficrules"), key=key, json=payload)


async def update_traffic_rule(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    rule_id: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Update a traffic rule via the v2 API."""
    validate_id(rule_id, "rule_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.put(
        _v2_api(host_id, site_slug, f"/trafficrules/{rule_id}/"),
        key=key,
        json=strip_empty_list_values(payload),
    )


async def delete_traffic_rule(
    client: UniFiClient, registry: Registry, host: str, site: str, rule_id: str
) -> None:
    """Delete a traffic rule via the v2 API."""
    validate_id(rule_id, "rule_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    await client.delete(_v2_api(host_id, site_slug, f"/trafficrules/{rule_id}/"), key=key)


def _extract_data(response: Any) -> Any:
    """Extract the 'data' list from a Classic REST response."""
    if isinstance(response, dict) and "data" in response:
        return response["data"]
    return response


# Fields managed by the UniFi controller that may change on every write
# regardless of whether the submitted payload was accepted.  Exclude these
# from silent-no-op comparison so that timestamp churn does not mask a
# genuinely rejected setting update.
_SERVER_MANAGED_FIELDS = frozenset(
    {
        "_id",
        "site_id",
        "key",
        "last_modified",
        "_updatedAt",
        "_createdAt",
    }
)


# --- Users / DHCP Reservations (Classic REST) ---


async def list_users(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """List DHCP fixed-IP reservations and client aliases via Classic REST /rest/user."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(_classic_rest(host_id, site_slug, "/user"), key=key)
    return _extract_data(response)


async def get_user(
    client: UniFiClient, registry: Registry, host: str, site: str, user_id: str
) -> Any:
    """Get a single DHCP/client-alias entry by ID via Classic REST /rest/user."""
    validate_id(user_id, "user_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(_classic_rest(host_id, site_slug, f"/user/{user_id}"), key=key)
    return _extract_data(response)


async def update_user(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    user_id: str,
    payload: dict[str, Any],
) -> Any:
    """Update a DHCP/client-alias entry via Classic REST /rest/user."""
    validate_id(user_id, "user_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.put(
        _classic_rest(host_id, site_slug, f"/user/{user_id}"),
        key=key,
        json=strip_empty_list_values(payload),
    )
    return _extract_data(response)


# --- Traffic Routes (v2 API) ---


async def list_traffic_routes(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """List static/policy traffic routes via the v2 API."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.get(_v2_api(host_id, site_slug, "/trafficroutes"), key=key)


async def create_traffic_route(
    client: UniFiClient, registry: Registry, host: str, site: str, payload: dict[str, Any]
) -> Any:
    """Create a traffic route via the v2 API.

    Required fields (verified live): ``network_id``, ``matching_target`` and
    ``target_devices`` — the API rejects a body missing any of them.
    """
    require_fields(
        "create_traffic_route", payload, {"network_id", "matching_target", "target_devices"}
    )
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.post(_v2_api(host_id, site_slug, "/trafficroutes"), key=key, json=payload)


async def get_traffic_route(
    client: UniFiClient, registry: Registry, host: str, site: str, route_id: str
) -> Any:
    """Get a single traffic route by ID (list + filter; the API has no GET-by-ID endpoint)."""
    validate_id(route_id, "route_id")
    routes = await list_traffic_routes(client, registry, host, site)
    if isinstance(routes, list):
        for route in routes:
            if route.get("_id") == route_id:
                return route
    raise ValueError(f"Traffic route {route_id!r} not found")


async def update_traffic_route(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    route_id: str,
    payload: dict[str, Any],
) -> Any:
    """Update a traffic route by ID via the v2 API."""
    validate_id(route_id, "route_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.put(
        _v2_api(host_id, site_slug, f"/trafficroutes/{route_id}"),
        key=key,
        json=strip_empty_list_values(payload),
    )


async def delete_traffic_route(
    client: UniFiClient, registry: Registry, host: str, site: str, route_id: str
) -> None:
    """Delete a traffic route by ID via the v2 API."""
    validate_id(route_id, "route_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    await client.delete(_v2_api(host_id, site_slug, f"/trafficroutes/{route_id}"), key=key)


# --- Controller Settings (Classic REST) ---


async def list_settings(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """List controller settings (grouped by key) via Classic REST /rest/setting."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(_classic_rest(host_id, site_slug, "/setting"), key=key)
    return _extract_data(response)


async def get_setting(
    client: UniFiClient, registry: Registry, host: str, site: str, setting_key: str
) -> Any:
    """Get a single controller setting group by key via Classic REST /rest/setting.

    The returned object is the group's full current state: every settable field and its
    current (valid) value. There is no separate schema endpoint, so **reading a group is
    how you discover what it accepts** — inspect the returned keys and current values
    before calling ``update_setting``. The controller silently drops any field or enum
    value it does not recognise (it returns HTTP 200 with the value unchanged rather than
    a validation error), so match an existing field's shape exactly.

    Common setting keys and notable enum fields (grounded in live controller responses;
    valid values are controller-defined — read the current value to confirm):

    * ``mdns`` — ``mode`` (e.g. ``all``), ``enabled_for`` (e.g. ``some``/``none``)
    * ``ntp`` — ``setting_preference`` (``auto``/manual), ``ntp_server_1``..``ntp_server_4``
    * ``locale`` — ``timezone``;  ``country`` — ``code`` (numeric string, e.g. ``840``)
    * ``doh`` — ``state`` (e.g. ``auto``/``off``)
    * ``ips`` — ``ips_mode`` (e.g. ``ids``/``ips``), ``advanced_filtering_preference``
    * ``global_nat`` — ``mode`` (e.g. ``auto``);  ``dashboard`` — ``layout_preference``
    * ``ssl_inspection`` — ``state`` (e.g. ``off``)
    * ``super_mgmt`` — ``data_retention_setting_preference``, ``live_updates``, ``live_chat``
    * ``guest_access`` — ``auth`` (e.g. ``hotspot``);  ``mgmt`` — ``led_enabled`` (bool)

    Fields prefixed ``x_`` hold credentials/secrets (passwords, keys, tokens) and are
    returned verbatim — handle them accordingly.
    """
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(
        _classic_rest(host_id, site_slug, f"/setting/{setting_key}"), key=key
    )
    return _extract_data(response)


async def update_setting(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    setting_key: str,
    payload: dict[str, Any],
) -> Any:
    """Update a controller setting group by key via Classic REST /rest/setting.

    Discovering the schema: there is no schema endpoint. Call ``get_setting(setting_key)``
    first — the returned object lists every settable field and its current (valid) value,
    which is what you match against. The controller silently drops any unrecognised field
    or enum value (HTTP 200, value unchanged), so a guessed value fails invisibly; the
    no-op detection below turns that into a raised error naming the rejected field. See
    ``get_setting`` for common setting keys and their notable enum fields.

    Implements silent-no-op detection (Issue #17, Defect 1):
    1. GET current state before writing.
    2. If every submitted field already matches current state, skip the PUT
       and return the current data with an informational note.
    3. Otherwise PUT, then GET again and verify the targeted fields actually
       changed (excluding server-managed timestamp/metadata fields).
    4. If targeted fields are unchanged despite differing from pre-state,
       raise ``RuntimeError`` naming the rejected setting key.

    Empty-string entries are stripped from list-valued fields before the
    idempotency comparison and the PUT, so a setting group read back with
    padded list fields round-trips cleanly (Issue #164).
    """
    payload = strip_empty_list_values(payload)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    url = _classic_rest(host_id, site_slug, f"/setting/{setting_key}")

    # --- pre-write snapshot ---
    pre_response = await client.get(url, key=key)
    pre_data = _extract_data(pre_response)
    # Classic REST wraps single settings in a one-element list; unwrap.
    pre_state: dict[str, Any] = (
        pre_data[0]
        if isinstance(pre_data, list) and pre_data
        else (pre_data if isinstance(pre_data, dict) else {})
    )

    # Idempotent-write false-positive guard: if submitted values already
    # equal the current values, skip the PUT entirely. The controller pads
    # list fields with placeholder empty strings on read (e.g.
    # ``["8.8.8.8", "", ""]``) but ``payload`` has already had that padding
    # stripped, so the current state must be stripped the same way before
    # comparing — otherwise a genuinely-equal list field reads as "changed"
    # and skips this guard.
    if all(strip_empty_list_values(pre_state.get(k)) == v for k, v in payload.items()):
        return {
            "data": pre_data,
            "note": "no change needed",
        }

    # --- perform the write ---
    response = await client.put(url, key=key, json=payload)
    result = _extract_data(response)

    # --- post-write verification ---
    post_response = await client.get(url, key=key)
    post_data = _extract_data(post_response)
    post_state: dict[str, Any] = (
        post_data[0]
        if isinstance(post_data, list) and post_data
        else (post_data if isinstance(post_data, dict) else {})
    )

    # Compare only the fields the caller submitted, excluding
    # server-managed fields that may change on every request. Both snapshots are
    # stripped of the controller's empty-string list padding so a field that
    # differs only by that padding is not mis-flagged as a rejected write (which
    # would raise a spurious "silent no-op" error for a write that in fact
    # succeeded — or that was a genuine no-op on an already-correct list field).
    rejected_keys: list[str] = []
    for k, v in payload.items():
        if k in _SERVER_MANAGED_FIELDS:
            continue
        pre_v = strip_empty_list_values(pre_state.get(k))
        post_v = strip_empty_list_values(post_state.get(k))
        if pre_v != v and post_v == pre_v:
            rejected_keys.append(k)

    if rejected_keys:
        raise RuntimeError(
            f"update_setting silent no-op: setting key {setting_key!r} "
            f"rejected fields {rejected_keys!r} -- values unchanged after write. "
            f"The controller silently drops values it does not recognise (most often an "
            f"invalid enum). Call get_setting(setting_key={setting_key!r}) to read the "
            f"current valid values and matching field shape before retrying."
        )

    return result


# --- Dynamic DNS (Classic REST) ---


async def list_dynamic_dns(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
) -> Any:
    """List Dynamic DNS provider configurations via Classic REST /rest/dynamicdns."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(_classic_rest(host_id, site_slug, "/dynamicdns"), key=key)
    return _extract_data(response)


async def get_dynamic_dns(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    ddns_id: str,
) -> Any:
    """Get a single Dynamic DNS config by ID via Classic REST /rest/dynamicdns."""
    validate_id(ddns_id, "ddns_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(
        _classic_rest(host_id, site_slug, f"/dynamicdns/{ddns_id}"), key=key
    )
    return _extract_data(response)


async def update_dynamic_dns(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    ddns_id: str,
    payload: dict[str, Any],
) -> Any:
    """Update a Dynamic DNS config by ID via Classic REST /rest/dynamicdns."""
    validate_id(ddns_id, "ddns_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.put(
        _classic_rest(host_id, site_slug, f"/dynamicdns/{ddns_id}"),
        key=key,
        json=strip_empty_list_values(payload),
    )
    return _extract_data(response)


# --- Port Profiles (Classic REST) ---
#
# D12 auto-exclusion footgun (documented UniFi behavior).
# UniFi auto-adds every newly created network to ``excluded_networkconf_ids`` of
# ALL custom-tagged port profiles (``tagged_vlan_mgmt == "custom"``), which
# silently blackholes the new VLAN at the host uplink (guest ARP to gateway
# FAILS).  The UI "Tagged VLANs" list is DERIVED — all VLAN networks minus the
# native minus the excluded — there is no separate tagged-list object.  These
# tools resolve the bare 24-hex networkconf ids to ``{id, name, vlan}`` objects
# against ``/rest/networkconf`` (the same id->name join the remediation runbook
# uses; port-profile ``*_networkconf_id(s)`` fields reference those documents by
# their Mongo ``_id``) so an operator can see at a glance which id IS the new
# network, and the atomic allow_/exclude_ helpers do the whole fresh-read ->
# mutate exclusion list -> PUT cycle in one call.

_NETWORKCONF_LIST_ID_FIELDS = ("excluded_networkconf_ids",)
_NETWORKCONF_SINGLE_ID_FIELDS = ("native_networkconf_id", "voice_networkconf_id")


async def _networkconf_name_map(
    client: UniFiClient,
    host_id: str,
    site_slug: str,
    *,
    key: APIKeyConfig | None,
) -> dict[str, dict[str, Any]]:
    """Build ``{networkconf_id: {id, name, vlan}}`` from Classic REST /rest/networkconf."""
    response = await client.get(_classic_rest(host_id, site_slug, "/networkconf"), key=key)
    result: dict[str, dict[str, Any]] = {}
    data = _extract_data(response)
    if not isinstance(data, list):
        return result
    for conf in data:
        if not isinstance(conf, dict):
            continue
        nid = conf.get("_id")
        if not nid:
            continue
        result[nid] = {"id": nid, "name": conf.get("name"), "vlan": conf.get("vlan")}
    return result


def _render_networkconf_id(nid: Any, name_map: dict[str, dict[str, Any]]) -> Any:
    """Render a single bare networkconf id as ``{id, name, vlan}``.

    An id with no match in the map (e.g. a stale reference) still renders as an
    object with ``name``/``vlan`` = ``None`` so the caller never sees a bare id.
    """
    if not isinstance(nid, str) or not nid:
        return nid
    entry = name_map.get(nid)
    if entry is not None:
        return dict(entry)
    return {"id": nid, "name": None, "vlan": None}


def _resolve_profile_networkconf(profile: Any, name_map: dict[str, dict[str, Any]]) -> Any:
    """Return a copy of a port profile with its networkconf id fields rendered as
    ``{id, name, vlan}`` objects.  Non-dict inputs pass through unchanged."""
    if not isinstance(profile, dict):
        return profile
    out = dict(profile)
    for field in _NETWORKCONF_LIST_ID_FIELDS:
        vals = profile.get(field)
        if isinstance(vals, list):
            out[field] = [_render_networkconf_id(v, name_map) for v in vals if v]
    for field in _NETWORKCONF_SINGLE_ID_FIELDS:
        val = profile.get(field)
        if isinstance(val, str) and val:
            out[field] = _render_networkconf_id(val, name_map)
    return out


def _resolve_profiles(data: Any, name_map: dict[str, dict[str, Any]]) -> Any:
    if isinstance(data, list):
        return [_resolve_profile_networkconf(p, name_map) for p in data]
    return _resolve_profile_networkconf(data, name_map)


def _derive_tagged_networks(
    profile: dict[str, Any], name_map: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    """Compute the DERIVED tagged-VLAN set for a profile: every VLAN network
    (``vlan`` truthy) minus the native minus the excluded, rendered with names.
    Mirrors how the UniFi UI derives its "Tagged VLANs" list."""
    native = profile.get("native_networkconf_id")
    excluded = {v for v in (profile.get("excluded_networkconf_ids") or []) if v}
    tagged: list[dict[str, Any]] = []
    for nid, entry in name_map.items():
        if not entry.get("vlan"):
            continue
        if nid == native or nid in excluded:
            continue
        tagged.append(dict(entry))
    tagged.sort(key=lambda e: e.get("vlan") or 0)
    return tagged


async def list_port_profiles(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """List switch port profiles via Classic REST /rest/portconf.

    Each profile's networkconf id fields (``excluded_networkconf_ids``,
    ``native_networkconf_id``, ``voice_networkconf_id``) are rendered as
    ``{id, name, vlan}`` objects resolved against /rest/networkconf so the D12
    auto-exclusion footgun (a bare id that is silently the newest VLAN) is legible.
    """
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(_classic_rest(host_id, site_slug, "/portconf"), key=key)
    name_map = await _networkconf_name_map(client, host_id, site_slug, key=key)
    return _resolve_profiles(_extract_data(response), name_map)


async def get_port_profile(
    client: UniFiClient, registry: Registry, host: str, site: str, profile_id: str
) -> Any:
    """Get a single switch port profile by ID via Classic REST /rest/portconf.

    Networkconf id fields are rendered as ``{id, name, vlan}`` objects (see
    ``list_port_profiles``)."""
    validate_id(profile_id, "profile_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(
        _classic_rest(host_id, site_slug, f"/portconf/{profile_id}"), key=key
    )
    name_map = await _networkconf_name_map(client, host_id, site_slug, key=key)
    return _resolve_profiles(_extract_data(response), name_map)


async def update_port_profile(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    profile_id: str,
    payload: dict[str, Any],
) -> Any:
    """Update a switch port profile by ID via Classic REST /rest/portconf.

    The write ``payload`` is passed through verbatim (bare networkconf ids), but
    the returned profile has its networkconf id fields rendered as
    ``{id, name, vlan}`` objects (see ``list_port_profiles``)."""
    validate_id(profile_id, "profile_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.put(
        _classic_rest(host_id, site_slug, f"/portconf/{profile_id}"),
        key=key,
        json=strip_empty_list_values(payload),
    )
    name_map = await _networkconf_name_map(client, host_id, site_slug, key=key)
    return _resolve_profiles(_extract_data(response), name_map)


async def _mutate_port_profile_exclusion(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    profile_id: str,
    network_id: str,
    *,
    exclude: bool,
    confirm: bool = False,
) -> dict[str, Any]:
    """Atomically add/remove ``network_id`` from a port profile's exclusion list.

    Fresh-reads the profile, mutates ``excluded_networkconf_ids``, PUTs the whole
    object back, and returns ``{profile, tagged_networks}`` with names resolved.

    This is a live write to a SHARED port profile — the exclusion list affects
    every switch port using the profile — so it refuses unless ``confirm=True``,
    returning an error dict BEFORE any controller call (mirrors the other write
    tools' confirm gate).
    """
    if not confirm:
        return {
            "error": "confirm=True required",
            "reason": (
                "This issues a live PUT to a shared port profile; its "
                "excluded_networkconf_ids affects every switch port using the "
                "profile. Re-call with confirm=True to proceed."
            ),
            "profile_id": profile_id,
            "network_id": network_id,
        }
    validate_id(profile_id, "profile_id")
    validate_id(network_id, "network_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    read = await client.get(_classic_rest(host_id, site_slug, f"/portconf/{profile_id}"), key=key)
    read_data = _extract_data(read)
    profile = read_data[0] if isinstance(read_data, list) and read_data else read_data
    if not isinstance(profile, dict):
        raise ValueError(f"port profile {profile_id!r} not found")
    excluded = [v for v in (profile.get("excluded_networkconf_ids") or []) if v]
    if exclude:
        if network_id not in excluded:
            excluded.append(network_id)
    else:
        excluded = [v for v in excluded if v != network_id]
    write_payload = dict(profile)
    write_payload["excluded_networkconf_ids"] = excluded
    response = await client.put(
        _classic_rest(host_id, site_slug, f"/portconf/{profile_id}"),
        key=key,
        json=strip_empty_list_values(write_payload),
    )
    resp_data = _extract_data(response)
    updated = resp_data[0] if isinstance(resp_data, list) and resp_data else resp_data
    if not isinstance(updated, dict):
        updated = write_payload
    name_map = await _networkconf_name_map(client, host_id, site_slug, key=key)
    return {
        "profile": _resolve_profile_networkconf(updated, name_map),
        "tagged_networks": _derive_tagged_networks(updated, name_map),
    }


async def allow_network_on_port_profile(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    profile_id: str,
    network_id: str,
    confirm: bool = False,
) -> dict[str, Any]:
    """Atomically allow (un-exclude) a network on a port profile — the D12 fix.

    Removes ``network_id`` from the profile's ``excluded_networkconf_ids`` via a
    fresh-read -> PUT cycle and returns ``{profile, tagged_networks}`` with the
    resulting tagged set rendered with names.  This is the remediation for the
    auto-exclusion warning emitted by ``create_network``.

    Live write to a shared port profile: refuses with an error dict unless
    ``confirm=True`` (checked before any controller call).
    """
    return await _mutate_port_profile_exclusion(
        client, registry, host, site, profile_id, network_id, exclude=False, confirm=confirm
    )


async def exclude_network_on_port_profile(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    profile_id: str,
    network_id: str,
    confirm: bool = False,
) -> dict[str, Any]:
    """Atomically exclude (untag) a network on a port profile.

    Adds ``network_id`` to the profile's ``excluded_networkconf_ids`` via a
    fresh-read -> PUT cycle.  Inverse of ``allow_network_on_port_profile``.

    Live write to a shared port profile: refuses with an error dict unless
    ``confirm=True`` (checked before any controller call)."""
    return await _mutate_port_profile_exclusion(
        client, registry, host, site, profile_id, network_id, exclude=True, confirm=confirm
    )


async def annotate_auto_exclusions(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    created: Any,
) -> Any:
    """Append a D12 auto-exclusion warning to a ``create_network`` response.

    Fresh-reads /rest/portconf and lists every custom-tagged profile
    (``tagged_vlan_mgmt == "custom"``) that already auto-excluded the new network,
    so the follow-up ``allow_network_on_port_profile`` step cannot be missed.
    Best-effort: any failure or unexpected shape returns ``created`` unchanged.
    """
    if not isinstance(created, dict):
        return created
    new_id = created.get("id") or created.get("_id")
    if not new_id:
        return created
    try:
        key = await registry.resolve_key_for_host(host)
        host_id = await registry.resolve_host_id(host, key=key)
        site_slug = await registry.resolve_site_slug(site, host_id, key=key)
        response = await client.get(_classic_rest(host_id, site_slug, "/portconf"), key=key)
    except Exception:
        return created
    profiles = _extract_data(response)
    if not isinstance(profiles, list):
        return created
    auto_excluded: list[dict[str, Any]] = []
    for profile in profiles:
        if not isinstance(profile, dict):
            continue
        if profile.get("tagged_vlan_mgmt") != "custom":
            continue
        if new_id in (profile.get("excluded_networkconf_ids") or []):
            auto_excluded.append({"id": profile.get("_id"), "name": profile.get("name")})
    if not auto_excluded:
        return created
    vlan = created.get("vlanId", created.get("vlan"))
    names = ", ".join(str(entry.get("name")) for entry in auto_excluded)
    out = dict(created)
    warning = {
        "code": "D12_AUTO_EXCLUSION",
        "message": (
            f"UniFi auto-excluded this new network (vlan {vlan}) from "
            f"{len(auto_excluded)} custom-tagged port profile(s): {names}. This "
            "blackholes the VLAN at the host uplink (guest->gateway ARP will FAIL). "
            "Run allow_network_on_port_profile(profile_id, network_id) for each "
            "profile to restore tagging."
        ),
        "profiles": auto_excluded,
        "remediation_tool": "allow_network_on_port_profile",
    }
    existing = out.get("warnings")
    out["warnings"] = ([*existing] if isinstance(existing, list) else []) + [warning]
    return out


# --- Routing Table (Classic REST) ---


async def list_routing_entries(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """List static routing table entries via Classic REST /rest/routing."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(_classic_rest(host_id, site_slug, "/routing"), key=key)
    return _extract_data(response)


# --- WLAN Configs (Classic REST) ---


async def list_wlan_configs(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
) -> Any:
    """List per-SSID WLAN configurations via Classic REST /rest/wlanconf."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(_classic_rest(host_id, site_slug, "/wlanconf"), key=key)
    return _extract_data(response)


async def get_wlan_config(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    wlan_id: str,
) -> Any:
    """Get a single WLAN configuration by ID via Classic REST /rest/wlanconf."""
    validate_id(wlan_id, "wlan_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(_classic_rest(host_id, site_slug, f"/wlanconf/{wlan_id}"), key=key)
    return _extract_data(response)


async def update_wlan_config(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    wlan_id: str,
    payload: dict[str, Any],
) -> Any:
    """Update a WLAN configuration by ID via Classic REST /rest/wlanconf."""
    validate_id(wlan_id, "wlan_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.put(
        _classic_rest(host_id, site_slug, f"/wlanconf/{wlan_id}"),
        key=key,
        json=strip_empty_list_values(payload),
    )
    return _extract_data(response)


# --- WLAN Groups (Classic REST) ---


async def list_wlan_groups(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """List WLAN group assignments via Classic REST /rest/wlangroup."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(_classic_rest(host_id, site_slug, "/wlangroup"), key=key)
    return _extract_data(response)


async def get_wlan_group(
    client: UniFiClient, registry: Registry, host: str, site: str, group_id: str
) -> Any:
    """Get a single WLAN group by ID via Classic REST /rest/wlangroup."""
    validate_id(group_id, "group_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(
        _classic_rest(host_id, site_slug, f"/wlangroup/{group_id}"), key=key
    )
    return _extract_data(response)


# --- Channel Plan (Classic REST) ---


async def get_channel_plan(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """Get RF channel assignments and DFS status via Classic REST /rest/channelplan."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(_classic_rest(host_id, site_slug, "/channelplan"), key=key)
    result = _extract_data(response)
    if not result:
        return {
            "message": (
                "No channel plan data available. "
                "Auto-channel optimization may not be active on this host."
            ),
            "channelPlan": [],
        }
    return result


# --- Rogue APs (Classic Stat) ---


async def list_rogue_aps(
    client: UniFiClient, registry: Registry, host: str, site: str, rogue_only: bool = False
) -> Any:
    """List neighboring APs via Classic REST stat /stat/rogueap."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(_classic_stat(host_id, site_slug, "/rogueap"), key=key)
    data = _extract_data(response)
    if rogue_only and isinstance(data, list):
        return [ap for ap in data if ap.get("is_rogue")]
    return data


# --- Classic Firewall Rules (Classic REST) ---


async def list_firewall_rules(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """List classic L3/L4 firewall rules via Classic REST /rest/firewallrule."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(_classic_rest(host_id, site_slug, "/firewallrule"), key=key)
    return _extract_data(response)


async def get_firewall_rule(
    client: UniFiClient, registry: Registry, host: str, site: str, rule_id: str
) -> Any:
    """Get a single classic firewall rule by ID via Classic REST /rest/firewallrule."""
    validate_id(rule_id, "rule_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(
        _classic_rest(host_id, site_slug, f"/firewallrule/{rule_id}"), key=key
    )
    return _extract_data(response)


# --- Firewall Groups (Classic REST) ---


async def list_firewall_groups(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """List firewall groups (IP/port sets used in rules) via Classic REST /rest/firewallgroup."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(_classic_rest(host_id, site_slug, "/firewallgroup"), key=key)
    return _extract_data(response)


async def get_firewall_group(
    client: UniFiClient, registry: Registry, host: str, site: str, group_id: str
) -> Any:
    """Get a single firewall group by ID via Classic REST /rest/firewallgroup."""
    validate_id(group_id, "group_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(
        _classic_rest(host_id, site_slug, f"/firewallgroup/{group_id}"), key=key
    )
    return _extract_data(response)


# --- RADIUS Accounts (Classic REST) ---


async def list_accounts(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
) -> Any:
    """List local RADIUS user accounts via Classic REST /rest/account."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(_classic_rest(host_id, site_slug, "/account"), key=key)
    return _extract_data(response)


async def get_account(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    account_id: str,
) -> Any:
    """Get a single RADIUS account by ID via Classic REST /rest/account."""
    validate_id(account_id, "account_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(
        _classic_rest(host_id, site_slug, f"/account/{account_id}"), key=key
    )
    return _extract_data(response)


# --- Hotspot Packages (Classic REST) ---


async def list_hotspot_packages(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """List guest portal billing packages via Classic REST /rest/hotspotpackage."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(_classic_rest(host_id, site_slug, "/hotspotpackage"), key=key)
    return _extract_data(response)


async def get_hotspot_package(
    client: UniFiClient, registry: Registry, host: str, site: str, package_id: str
) -> Any:
    """Get a single hotspot billing package by ID via Classic REST /rest/hotspotpackage."""
    validate_id(package_id, "package_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(
        _classic_rest(host_id, site_slug, f"/hotspotpackage/{package_id}"), key=key
    )
    return _extract_data(response)


# --- Scheduled Tasks (Classic REST) ---


async def list_scheduled_tasks(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """List scheduled tasks (firmware upgrades, speed tests) via Classic REST /rest/scheduletask."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(_classic_rest(host_id, site_slug, "/scheduletask"), key=key)
    return _extract_data(response)


async def get_scheduled_task(
    client: UniFiClient, registry: Registry, host: str, site: str, task_id: str
) -> Any:
    """Get a single scheduled task by ID via Classic REST /rest/scheduletask."""
    validate_id(task_id, "task_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(
        _classic_rest(host_id, site_slug, f"/scheduletask/{task_id}"), key=key
    )
    return _extract_data(response)


# --- DPI Categories ---


async def list_dpi_categories(
    client: UniFiClient,
    registry: Registry,
    host: str,
    offset: int | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """List DPI app categories available for traffic rules.

    DPI data is host-level (not site-scoped); the site parameter is ignored.
    Drains all pages by default; pass offset/limit for a single manual page. A
    capped drain is flagged incomplete rather than truncated silently.
    """
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    return await _drain_offset_list(
        client, _proxy(host_id, "/dpi/categories"), key=key, offset=offset, limit=limit
    )


# --- DPI Applications ---


async def list_dpi_applications(
    client: UniFiClient,
    registry: Registry,
    host: str,
    offset: int | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """List DPI applications available for traffic rules, grouped by category.

    DPI data is host-level (not site-scoped); the site parameter is ignored.
    Drains all pages by default; pass offset/limit for a single manual page. A
    capped drain is flagged incomplete rather than truncated silently.
    """
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    return await _drain_offset_list(
        client, _proxy(host_id, "/dpi/applications"), key=key, offset=offset, limit=limit
    )
