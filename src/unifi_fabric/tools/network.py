"""Network tools — Networks/VLANs, WiFi broadcasts, and WAN interfaces via connector proxy."""

from __future__ import annotations

from typing import Any

from ..client import UniFiClient, validate_id
from ..registry import Registry, _assert_uuid
from ._pagination import collect_offset, mark_incomplete

PROXY_BASE = "/v1/connector/consoles/{host_id}/proxy/network/integration/v1"

# Read-only fields returned by get_network that the controller rejects
# (HTTP 400) when included in an update_network PUT payload.  Strip these
# from input before sending to avoid caller confusion when round-tripping
# a GET response back into an update.
_NETWORK_READ_ONLY_FIELDS = frozenset(
    {
        "id",
        "default",
        "metadata",
    }
)


def _proxy(host_id: str, path: str) -> str:
    return PROXY_BASE.format(host_id=host_id) + path


# --- Application / Local Sites ---


def _page_params(offset: int, limit: int, filter: str | None) -> dict[str, Any]:
    """Build validated Network Integration API pagination parameters."""
    if offset < 0:
        raise ValueError("offset must be greater than or equal to 0")
    if not 0 <= limit <= 200:
        raise ValueError("limit must be between 0 and 200")
    params: dict[str, Any] = {"offset": offset, "limit": limit}
    if filter is not None:
        params["filter"] = filter
    return params


async def _offset_list(
    client: UniFiClient,
    url: str,
    *,
    offset: int | None,
    limit: int | None,
    filter: str | None,
) -> dict[str, Any]:
    """Fetch an offset-paginated Integration list, draining all pages by default.

    Passing offset or limit selects manual paging: a single validated page is
    returned with the API's native envelope (offset/limit/count/totalCount)
    preserved. Otherwise every page is drained into ``{data, totalCount}`` and a
    capped drain is flagged incomplete instead of truncating silently. ``filter``
    is a server-side filter (not paging) and applies in either mode.
    """
    if offset is not None or limit is not None:
        page = _page_params(
            offset if offset is not None else 0,
            limit if limit is not None else 25,
            filter,
        )
        result: dict[str, Any] = await client.get(url, params=page)
        return result
    base: dict[str, Any] = {}
    if filter is not None:
        base["filter"] = filter
    collected = await collect_offset(client, url, params=base or None)
    total = collected["totalCount"]
    drained: dict[str, Any] = {
        "data": collected["items"],
        "totalCount": total if total is not None else len(collected["items"]),
    }
    return mark_incomplete(drained, collected)


async def get_network_application_info(
    client: UniFiClient,
    registry: Registry,
    host: str,
) -> dict[str, Any]:
    """Get the UniFi Network application version reported by a console."""
    host_id = await registry.resolve_host_id(host)
    return await client.get(_proxy(host_id, "/info"))


async def list_local_sites(
    client: UniFiClient,
    registry: Registry,
    host: str,
    *,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List sites managed by one UniFi Network application.

    By default every offset page is drained and the complete list is returned.
    offset/limit: fetch a single page manually (native envelope preserved). A
    capped drain returns the sites gathered so far with incomplete=true rather
    than truncating silently.
    """
    host_id = await registry.resolve_host_id(host)
    return await _offset_list(
        client, _proxy(host_id, "/sites"), offset=offset, limit=limit, filter=filter
    )


# --- Networks / VLANs ---


async def list_networks(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    *,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List all networks/VLANs for a site.

    This Network Integration endpoint is offset-paginated (verified live: the
    response carries an ``{offset, limit, count, totalCount, data}`` envelope and the
    native default page size is only 25). By default every page is drained and the
    complete list is returned as ``{data, totalCount}``; pass offset or limit to
    fetch a single manual page (native envelope preserved). ``filter`` is a
    server-side filter (not paging) and applies in either mode. A capped drain is
    flagged ``incomplete`` rather than truncating silently.
    """
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await _offset_list(
        client,
        _proxy(host_id, f"/sites/{site_id}/networks"),
        offset=offset,
        limit=limit,
        filter=filter,
    )


async def create_network(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    network: dict[str, Any],
) -> dict[str, Any]:
    """Create a new network/VLAN on a site."""
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.post(_proxy(host_id, f"/sites/{site_id}/networks"), json=network)


async def get_network(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    network_id: str,
) -> dict[str, Any]:
    """Get a single network by ID."""
    validate_id(network_id, "network_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.get(_proxy(host_id, f"/sites/{site_id}/networks/{network_id}"))


async def update_network(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    network_id: str,
    network: dict[str, Any],
) -> dict[str, Any]:
    """Update an existing network/VLAN.

    Strips read-only fields (``id``, ``default``, ``metadata``) from the
    input payload before sending to the controller.  These fields are
    present in ``get_network`` responses but cause HTTP 400 if included in
    an update request (Issue #17, Defect 2).
    """
    validate_id(network_id, "network_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    cleaned = {k: v for k, v in network.items() if k not in _NETWORK_READ_ONLY_FIELDS}
    return await client.put(
        _proxy(host_id, f"/sites/{site_id}/networks/{network_id}"), json=cleaned
    )


async def delete_network(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    network_id: str,
) -> None:
    """Delete a network/VLAN."""
    validate_id(network_id, "network_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    await client.delete(_proxy(host_id, f"/sites/{site_id}/networks/{network_id}"))


# --- WiFi Broadcasts ---


async def list_wifi_broadcasts(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
) -> dict[str, Any]:
    """List all WiFi broadcast SSIDs for a site."""
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.get(_proxy(host_id, f"/sites/{site_id}/wifi/broadcasts"))


async def create_wifi_broadcast(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    broadcast: dict[str, Any],
) -> dict[str, Any]:
    """Create a new WiFi broadcast SSID."""
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.post(_proxy(host_id, f"/sites/{site_id}/wifi/broadcasts"), json=broadcast)


async def get_wifi_broadcast(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    broadcast_id: str,
) -> dict[str, Any]:
    """Get a single WiFi broadcast by ID."""
    validate_id(broadcast_id, "broadcast_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.get(_proxy(host_id, f"/sites/{site_id}/wifi/broadcasts/{broadcast_id}"))


async def update_wifi_broadcast(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    broadcast_id: str,
    broadcast: dict[str, Any],
) -> dict[str, Any]:
    """Update an existing WiFi broadcast SSID."""
    validate_id(broadcast_id, "broadcast_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.put(
        _proxy(host_id, f"/sites/{site_id}/wifi/broadcasts/{broadcast_id}"), json=broadcast
    )


async def delete_wifi_broadcast(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    broadcast_id: str,
) -> None:
    """Delete a WiFi broadcast SSID."""
    validate_id(broadcast_id, "broadcast_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    await client.delete(_proxy(host_id, f"/sites/{site_id}/wifi/broadcasts/{broadcast_id}"))


# --- WAN Interfaces ---


_STAT_BASE = "/v1/connector/consoles/{host_id}/proxy/network/api/s/{site_slug}/stat"


async def list_wan_interfaces(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
) -> dict[str, Any]:
    """List WAN interfaces for a site, enriched with IP, status, and speed from stat/health."""
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    wans = await client.get(_proxy(host_id, f"/sites/{site_id}/wans"))
    wan_list = wans if isinstance(wans, list) else wans.get("data", wans)

    # Enrich with health data (IP, status, speed) from Classic REST stat/health
    try:
        site_slug = await registry.resolve_site_slug(site, host_id)
        health_url = _STAT_BASE.format(host_id=host_id, site_slug=site_slug) + "/health"
        health_data = await client.get(health_url)
        health_list = (
            health_data.get("data", health_data) if isinstance(health_data, dict) else health_data
        )
        wan_health = [h for h in (health_list or []) if h.get("subsystem") == "wan"]
    except Exception:
        wan_health = []

    count = len(wan_list) if isinstance(wan_list, list) else 0
    return {"wans": wan_list, "count": count, "wanHealth": wan_health}


async def update_wan_interface(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    wan_id: str,
    wan: dict[str, Any],
) -> dict[str, Any]:
    """Update a WAN interface configuration."""
    validate_id(wan_id, "wan_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.put(_proxy(host_id, f"/sites/{site_id}/wans/{wan_id}"), json=wan)


# --- Network References ---


async def get_network_references(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    network_id: str,
) -> dict[str, Any]:
    """Get all references to a network (WiFi broadcasts, firewall policies, port profiles)."""
    validate_id(network_id, "network_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.get(_proxy(host_id, f"/sites/{site_id}/networks/{network_id}/references"))


# --- Switching ---


async def _list_switching_resources(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    resource: str,
    *,
    offset: int | None,
    limit: int | None,
    filter: str | None,
) -> dict[str, Any]:
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await _offset_list(
        client,
        _proxy(host_id, f"/sites/{site_id}/switching/{resource}"),
        offset=offset,
        limit=limit,
        filter=filter,
    )


async def _get_switching_resource(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    resource: str,
    resource_id: str,
    field_name: str,
) -> dict[str, Any]:
    validate_id(resource_id, field_name)
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.get(_proxy(host_id, f"/sites/{site_id}/switching/{resource}/{resource_id}"))


async def list_lags(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    *,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List Link Aggregation Groups (LAGs) on a site.

    Drains all pages by default; pass offset/limit for a single manual page. A
    capped drain is flagged incomplete rather than truncated silently.
    """
    return await _list_switching_resources(
        client,
        registry,
        host,
        site,
        "lags",
        offset=offset,
        limit=limit,
        filter=filter,
    )


async def get_lag(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    lag_id: str,
) -> dict[str, Any]:
    """Get one Link Aggregation Group."""
    return await _get_switching_resource(client, registry, host, site, "lags", lag_id, "lag_id")


async def list_mc_lag_domains(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    *,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List Multi-Chassis Link Aggregation (MC-LAG) domains on a site.

    Drains all pages by default; pass offset/limit for a single manual page. A
    capped drain is flagged incomplete rather than truncated silently.
    """
    return await _list_switching_resources(
        client,
        registry,
        host,
        site,
        "mc-lag-domains",
        offset=offset,
        limit=limit,
        filter=filter,
    )


async def get_mc_lag_domain(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    mc_lag_domain_id: str,
) -> dict[str, Any]:
    """Get one Multi-Chassis Link Aggregation domain."""
    return await _get_switching_resource(
        client,
        registry,
        host,
        site,
        "mc-lag-domains",
        mc_lag_domain_id,
        "mc_lag_domain_id",
    )


async def list_switch_stacks(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    *,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List switch stacks on a site.

    Drains all pages by default; pass offset/limit for a single manual page. A
    capped drain is flagged incomplete rather than truncated silently.
    """
    return await _list_switching_resources(
        client,
        registry,
        host,
        site,
        "switch-stacks",
        offset=offset,
        limit=limit,
        filter=filter,
    )


async def get_switch_stack(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    switch_stack_id: str,
) -> dict[str, Any]:
    """Get one switch stack."""
    return await _get_switching_resource(
        client,
        registry,
        host,
        site,
        "switch-stacks",
        switch_stack_id,
        "switch_stack_id",
    )
