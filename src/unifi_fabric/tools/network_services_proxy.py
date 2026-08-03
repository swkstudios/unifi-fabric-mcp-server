"""Network services tools — DNS, traffic lists, VPN, RADIUS, hotspot via connector proxy."""

from __future__ import annotations

from typing import Any

from ..client import UniFiClient, validate_id
from ..registry import Registry, _assert_uuid
from ._pagination import collect_offset, mark_incomplete
from .network import _proxy


async def _drain_offset_list(
    client: UniFiClient,
    url: str,
    *,
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
        result: dict[str, Any] = await client.get(url, params=params or None)
        return result
    collected = await collect_offset(client, url)
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
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await _drain_offset_list(
        client, _proxy(host_id, f"/sites/{site_id}/dns/policies"), offset=offset, limit=limit
    )


async def create_dns_policy(
    client: UniFiClient, registry: Registry, host: str, site: str, policy: dict[str, Any]
) -> dict[str, Any]:
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.post(_proxy(host_id, f"/sites/{site_id}/dns/policies"), json=policy)


async def get_dns_policy(
    client: UniFiClient, registry: Registry, host: str, site: str, policy_id: str
) -> dict[str, Any]:
    validate_id(policy_id, "policy_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.get(_proxy(host_id, f"/sites/{site_id}/dns/policies/{policy_id}"))


async def update_dns_policy(
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
        _proxy(host_id, f"/sites/{site_id}/dns/policies/{policy_id}"), json=policy
    )


async def delete_dns_policy(
    client: UniFiClient, registry: Registry, host: str, site: str, policy_id: str
) -> None:
    validate_id(policy_id, "policy_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    await client.delete(_proxy(host_id, f"/sites/{site_id}/dns/policies/{policy_id}"))


# --- Traffic Matching Lists ---


async def list_traffic_matching_lists(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> dict[str, Any]:
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.get(_proxy(host_id, f"/sites/{site_id}/traffic-matching-lists"))


async def create_traffic_matching_list(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    traffic_list: dict[str, Any],
) -> dict[str, Any]:
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.post(
        _proxy(host_id, f"/sites/{site_id}/traffic-matching-lists"), json=traffic_list
    )


async def get_traffic_matching_list(
    client: UniFiClient, registry: Registry, host: str, site: str, list_id: str
) -> dict[str, Any]:
    validate_id(list_id, "list_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.get(_proxy(host_id, f"/sites/{site_id}/traffic-matching-lists/{list_id}"))


async def update_traffic_matching_list(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    list_id: str,
    traffic_list: dict[str, Any],
) -> dict[str, Any]:
    validate_id(list_id, "list_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.put(
        _proxy(host_id, f"/sites/{site_id}/traffic-matching-lists/{list_id}"),
        json=traffic_list,
    )


async def delete_traffic_matching_list(
    client: UniFiClient, registry: Registry, host: str, site: str, list_id: str
) -> None:
    validate_id(list_id, "list_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    await client.delete(_proxy(host_id, f"/sites/{site_id}/traffic-matching-lists/{list_id}"))


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
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await _drain_offset_list(
        client, _proxy(host_id, f"/sites/{site_id}/vpn/servers"), offset=offset, limit=limit
    )


async def list_site_to_site_tunnels(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> dict[str, Any]:
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.get(_proxy(host_id, f"/sites/{site_id}/vpn/site-to-site-tunnels"))


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
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await _drain_offset_list(
        client, _proxy(host_id, f"/sites/{site_id}/radius/profiles"), offset=offset, limit=limit
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
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await _drain_offset_list(
        client, _proxy(host_id, f"/sites/{site_id}/hotspot/vouchers"), offset=offset, limit=limit
    )


async def create_hotspot_vouchers(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    voucher_config: dict[str, Any],
) -> dict[str, Any]:
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.post(
        _proxy(host_id, f"/sites/{site_id}/hotspot/vouchers"), json=voucher_config
    )


async def get_hotspot_voucher(
    client: UniFiClient, registry: Registry, host: str, site: str, voucher_id: str
) -> dict[str, Any]:
    validate_id(voucher_id, "voucher_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.get(_proxy(host_id, f"/sites/{site_id}/hotspot/vouchers/{voucher_id}"))


async def delete_hotspot_voucher(
    client: UniFiClient, registry: Registry, host: str, site: str, voucher_id: str
) -> None:
    validate_id(voucher_id, "voucher_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    await client.delete(_proxy(host_id, f"/sites/{site_id}/hotspot/vouchers/{voucher_id}"))


async def bulk_delete_hotspot_vouchers(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    params: dict[str, Any],
) -> None:
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    await client.delete(_proxy(host_id, f"/sites/{site_id}/hotspot/vouchers"), params=params)


# --- Supporting Resources ---


async def list_device_tags(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> dict[str, Any]:
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.get(_proxy(host_id, f"/sites/{site_id}/device-tags"))


async def list_countries(client: UniFiClient, registry: Registry, host: str) -> dict[str, Any]:
    host_id = await registry.resolve_host_id(host)
    return await client.get(_proxy(host_id, "/countries"))


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
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    return await client.get(_classic_rest(host_id, site_slug, "/portforward"))


async def create_port_forward(
    client: UniFiClient, registry: Registry, host: str, site: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """Create a port-forward rule via the Classic REST API.

    Required fields: name (str), dst_port (str), fwd (str), fwd_port (str), proto (str).
    Example: {"enabled": true, "name": "SSH", "pfwd_interface": "wan", "src": "any",
    "dst_port": "2222", "fwd": "192.168.1.10", "fwd_port": "22", "proto": "tcp", "log": false}
    """
    required = {"name", "dst_port", "fwd", "fwd_port"}
    missing = required - set(payload.keys())
    if missing:
        raise ValueError(f"create_port_forward requires: {', '.join(sorted(missing))}")
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    return await client.post(_classic_rest(host_id, site_slug, "/portforward"), json=payload)


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
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    return await client.put(
        _classic_rest(host_id, site_slug, f"/portforward/{forward_id}"), json=payload
    )


async def delete_port_forward(
    client: UniFiClient, registry: Registry, host: str, site: str, forward_id: str
) -> None:
    """Delete a port-forward rule via the Classic REST API."""
    validate_id(forward_id, "forward_id")
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    await client.delete(_classic_rest(host_id, site_slug, f"/portforward/{forward_id}"))


# --- Traffic Rules (v2 API) ---


async def list_traffic_rules(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> dict[str, Any]:
    """List traffic rules for a site via the v2 API.

    Example response item: {"_id": "rule-1", "description": "Block Social Media",
    "action": "BLOCK", "matching_target": "INTERNET", "enabled": true}
    The v2 API may return a bare list; this is normalized to {"data": [...], "count": N}.
    """
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    result = await client.get(_v2_api(host_id, site_slug, "/trafficrules"))
    if isinstance(result, list):
        return {"data": result, "count": len(result)}
    return result


async def create_traffic_rule(
    client: UniFiClient, registry: Registry, host: str, site: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """Create a traffic rule via the v2 API.

    Required fields: description (str), action (str: BLOCK|ALLOW|THROTTLE),
    matching_target (str: INTERNET|INTRANET|LOCAL), enabled (bool).
    """
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    return await client.post(_v2_api(host_id, site_slug, "/trafficrules"), json=payload)


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
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    return await client.put(_v2_api(host_id, site_slug, f"/trafficrules/{rule_id}/"), json=payload)


async def delete_traffic_rule(
    client: UniFiClient, registry: Registry, host: str, site: str, rule_id: str
) -> None:
    """Delete a traffic rule via the v2 API."""
    validate_id(rule_id, "rule_id")
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    await client.delete(_v2_api(host_id, site_slug, f"/trafficrules/{rule_id}/"))


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
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_rest(host_id, site_slug, "/user"))
    return _extract_data(response)


async def get_user(
    client: UniFiClient, registry: Registry, host: str, site: str, user_id: str
) -> Any:
    """Get a single DHCP/client-alias entry by ID via Classic REST /rest/user."""
    validate_id(user_id, "user_id")
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_rest(host_id, site_slug, f"/user/{user_id}"))
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
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.put(_classic_rest(host_id, site_slug, f"/user/{user_id}"), json=payload)
    return _extract_data(response)


# --- Traffic Routes (v2 API) ---


async def list_traffic_routes(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """List static/policy traffic routes via the v2 API."""
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    return await client.get(_v2_api(host_id, site_slug, "/trafficroutes"))


async def create_traffic_route(
    client: UniFiClient, registry: Registry, host: str, site: str, payload: dict[str, Any]
) -> Any:
    """Create a traffic route via the v2 API."""
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    return await client.post(_v2_api(host_id, site_slug, "/trafficroutes"), json=payload)


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
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    return await client.put(_v2_api(host_id, site_slug, f"/trafficroutes/{route_id}"), json=payload)


async def delete_traffic_route(
    client: UniFiClient, registry: Registry, host: str, site: str, route_id: str
) -> None:
    """Delete a traffic route by ID via the v2 API."""
    validate_id(route_id, "route_id")
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    await client.delete(_v2_api(host_id, site_slug, f"/trafficroutes/{route_id}"))


# --- Controller Settings (Classic REST) ---


async def list_settings(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """List controller settings (grouped by key) via Classic REST /rest/setting."""
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_rest(host_id, site_slug, "/setting"))
    return _extract_data(response)


async def get_setting(
    client: UniFiClient, registry: Registry, host: str, site: str, setting_key: str
) -> Any:
    """Get a single controller setting group by key via Classic REST /rest/setting."""
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_rest(host_id, site_slug, f"/setting/{setting_key}"))
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

    Implements silent-no-op detection (Issue #17, Defect 1):
    1. GET current state before writing.
    2. If every submitted field already matches current state, skip the PUT
       and return the current data with an informational note.
    3. Otherwise PUT, then GET again and verify the targeted fields actually
       changed (excluding server-managed timestamp/metadata fields).
    4. If targeted fields are unchanged despite differing from pre-state,
       raise ``RuntimeError`` naming the rejected setting key.
    """
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    url = _classic_rest(host_id, site_slug, f"/setting/{setting_key}")

    # --- pre-write snapshot ---
    pre_response = await client.get(url)
    pre_data = _extract_data(pre_response)
    # Classic REST wraps single settings in a one-element list; unwrap.
    pre_state: dict[str, Any] = (
        pre_data[0]
        if isinstance(pre_data, list) and pre_data
        else (pre_data if isinstance(pre_data, dict) else {})
    )

    # Idempotent-write false-positive guard: if submitted values already
    # equal the current values, skip the PUT entirely.
    if all(pre_state.get(k) == v for k, v in payload.items()):
        return {
            "data": pre_data,
            "note": "no change needed",
        }

    # --- perform the write ---
    response = await client.put(url, json=payload)
    result = _extract_data(response)

    # --- post-write verification ---
    post_response = await client.get(url)
    post_data = _extract_data(post_response)
    post_state: dict[str, Any] = (
        post_data[0]
        if isinstance(post_data, list) and post_data
        else (post_data if isinstance(post_data, dict) else {})
    )

    # Compare only the fields the caller submitted, excluding
    # server-managed fields that may change on every request.
    rejected_keys: list[str] = []
    for k, v in payload.items():
        if k in _SERVER_MANAGED_FIELDS:
            continue
        if pre_state.get(k) != v and post_state.get(k) == pre_state.get(k):
            rejected_keys.append(k)

    if rejected_keys:
        raise RuntimeError(
            f"update_setting silent no-op: setting key {setting_key!r} "
            f"rejected fields {rejected_keys!r} -- values unchanged after write"
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
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_rest(host_id, site_slug, "/dynamicdns"))
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
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_rest(host_id, site_slug, f"/dynamicdns/{ddns_id}"))
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
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.put(
        _classic_rest(host_id, site_slug, f"/dynamicdns/{ddns_id}"), json=payload
    )
    return _extract_data(response)


# --- Port Profiles (Classic REST) ---


async def list_port_profiles(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """List switch port profiles via Classic REST /rest/portconf."""
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_rest(host_id, site_slug, "/portconf"))
    return _extract_data(response)


async def get_port_profile(
    client: UniFiClient, registry: Registry, host: str, site: str, profile_id: str
) -> Any:
    """Get a single switch port profile by ID via Classic REST /rest/portconf."""
    validate_id(profile_id, "profile_id")
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_rest(host_id, site_slug, f"/portconf/{profile_id}"))
    return _extract_data(response)


async def update_port_profile(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    profile_id: str,
    payload: dict[str, Any],
) -> Any:
    """Update a switch port profile by ID via Classic REST /rest/portconf."""
    validate_id(profile_id, "profile_id")
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.put(
        _classic_rest(host_id, site_slug, f"/portconf/{profile_id}"), json=payload
    )
    return _extract_data(response)


# --- Routing Table (Classic REST) ---


async def list_routing_entries(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """List static routing table entries via Classic REST /rest/routing."""
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_rest(host_id, site_slug, "/routing"))
    return _extract_data(response)


# --- WLAN Configs (Classic REST) ---


async def list_wlan_configs(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
) -> Any:
    """List per-SSID WLAN configurations via Classic REST /rest/wlanconf."""
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_rest(host_id, site_slug, "/wlanconf"))
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
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_rest(host_id, site_slug, f"/wlanconf/{wlan_id}"))
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
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.put(
        _classic_rest(host_id, site_slug, f"/wlanconf/{wlan_id}"), json=payload
    )
    return _extract_data(response)


# --- WLAN Groups (Classic REST) ---


async def list_wlan_groups(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """List WLAN group assignments via Classic REST /rest/wlangroup."""
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_rest(host_id, site_slug, "/wlangroup"))
    return _extract_data(response)


async def get_wlan_group(
    client: UniFiClient, registry: Registry, host: str, site: str, group_id: str
) -> Any:
    """Get a single WLAN group by ID via Classic REST /rest/wlangroup."""
    validate_id(group_id, "group_id")
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_rest(host_id, site_slug, f"/wlangroup/{group_id}"))
    return _extract_data(response)


# --- Channel Plan (Classic REST) ---


async def get_channel_plan(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """Get RF channel assignments and DFS status via Classic REST /rest/channelplan."""
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_rest(host_id, site_slug, "/channelplan"))
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
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_stat(host_id, site_slug, "/rogueap"))
    data = _extract_data(response)
    if rogue_only and isinstance(data, list):
        return [ap for ap in data if ap.get("is_rogue")]
    return data


# --- Classic Firewall Rules (Classic REST) ---


async def list_firewall_rules(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """List classic L3/L4 firewall rules via Classic REST /rest/firewallrule."""
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_rest(host_id, site_slug, "/firewallrule"))
    return _extract_data(response)


async def get_firewall_rule(
    client: UniFiClient, registry: Registry, host: str, site: str, rule_id: str
) -> Any:
    """Get a single classic firewall rule by ID via Classic REST /rest/firewallrule."""
    validate_id(rule_id, "rule_id")
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_rest(host_id, site_slug, f"/firewallrule/{rule_id}"))
    return _extract_data(response)


# --- Firewall Groups (Classic REST) ---


async def list_firewall_groups(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """List firewall groups (IP/port sets used in rules) via Classic REST /rest/firewallgroup."""
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_rest(host_id, site_slug, "/firewallgroup"))
    return _extract_data(response)


async def get_firewall_group(
    client: UniFiClient, registry: Registry, host: str, site: str, group_id: str
) -> Any:
    """Get a single firewall group by ID via Classic REST /rest/firewallgroup."""
    validate_id(group_id, "group_id")
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_rest(host_id, site_slug, f"/firewallgroup/{group_id}"))
    return _extract_data(response)


# --- RADIUS Accounts (Classic REST) ---


async def list_accounts(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
) -> Any:
    """List local RADIUS user accounts via Classic REST /rest/account."""
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_rest(host_id, site_slug, "/account"))
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
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_rest(host_id, site_slug, f"/account/{account_id}"))
    return _extract_data(response)


# --- Hotspot Packages (Classic REST) ---


async def list_hotspot_packages(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """List guest portal billing packages via Classic REST /rest/hotspotpackage."""
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_rest(host_id, site_slug, "/hotspotpackage"))
    return _extract_data(response)


async def get_hotspot_package(
    client: UniFiClient, registry: Registry, host: str, site: str, package_id: str
) -> Any:
    """Get a single hotspot billing package by ID via Classic REST /rest/hotspotpackage."""
    validate_id(package_id, "package_id")
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_rest(host_id, site_slug, f"/hotspotpackage/{package_id}"))
    return _extract_data(response)


# --- Scheduled Tasks (Classic REST) ---


async def list_scheduled_tasks(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """List scheduled tasks (firmware upgrades, speed tests) via Classic REST /rest/scheduletask."""
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_rest(host_id, site_slug, "/scheduletask"))
    return _extract_data(response)


async def get_scheduled_task(
    client: UniFiClient, registry: Registry, host: str, site: str, task_id: str
) -> Any:
    """Get a single scheduled task by ID via Classic REST /rest/scheduletask."""
    validate_id(task_id, "task_id")
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_rest(host_id, site_slug, f"/scheduletask/{task_id}"))
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
    host_id = await registry.resolve_host_id(host)
    return await _drain_offset_list(
        client, _proxy(host_id, "/dpi/categories"), offset=offset, limit=limit
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
    host_id = await registry.resolve_host_id(host)
    return await _drain_offset_list(
        client, _proxy(host_id, "/dpi/applications"), offset=offset, limit=limit
    )
