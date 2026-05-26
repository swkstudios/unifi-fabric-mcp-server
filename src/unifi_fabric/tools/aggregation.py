"""Cross-site aggregation tools — fleet-wide queries across all consoles and sites."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import Any

from fastmcp import FastMCP

from ..client import UniFiClient, validate_host_id
from ..config import APIKeyConfig
from ..registry import Registry, _assert_uuid
from .network import _proxy

_logger = logging.getLogger(__name__)


def _resolve_key(client: UniFiClient, key_label: str | None) -> APIKeyConfig | None:
    """Resolve an optional key_label to an APIKeyConfig, or None for default."""
    if key_label is None:
        return None
    return client.get_key_by_label(key_label)


async def _get_all_host_site_pairs(
    registry: Registry,
    *,
    key: APIKeyConfig | None = None,
) -> list[dict[str, str]]:
    """Build a list of {hostId, siteId, hostName, siteName} for every site.

    Enumerates hosts from /ea/sites, then fetches UUID site IDs from the
    per-console proxy /sites endpoint. The /ea/sites ``siteId`` field is a
    Fabric ObjectId and cannot be used in proxy URLs — proxy endpoints require
    the UUID returned by the console's Network Integration /sites API.
    """
    ea_sites = await registry.get_ea_sites(key=key)

    # Collect unique hostId -> hostname from ea_sites
    host_map: dict[str, str] = {}
    for site in ea_sites:
        host_id = site.get("hostId", "")
        if not host_id:
            continue
        try:
            validate_host_id(host_id, "hostId")
        except ValueError:
            continue
        if host_id not in host_map:
            host_map[host_id] = site.get("hostname", host_id)

    pairs = []
    for host_id, host_name in host_map.items():
        try:
            proxy_sites = await registry.get_sites(host_id, key=key)
        except Exception as exc:
            _logger.warning("Failed to fetch proxy sites for host %r: %s", host_id, exc)
            continue
        for proxy_site in proxy_sites:
            site_id = proxy_site.get("id") or proxy_site.get("_id", "")
            site_name = proxy_site.get("description") or proxy_site.get("name") or site_id
            if not site_id:
                continue
            try:
                _assert_uuid(site_id)
            except ValueError:
                continue
            pairs.append(
                {
                    "hostId": host_id,
                    "siteId": site_id,
                    "hostName": host_name,
                    "siteName": str(site_name),
                }
            )
    return pairs


async def _list_all_devices_fleet(
    client: UniFiClient,
    *,
    status_filter: str | None = None,
    key_label: str | None = None,
) -> dict[str, Any]:
    """List all devices across the entire fleet using the /ea/devices endpoint.

    Optionally filter by status (e.g. 'offline', 'online', 'updating').
    key_label scopes the query to a specific API key for MSP multi-tenant use.
    """
    key = _resolve_key(client, key_label)
    all_devices = await client.paginate("/ea/devices", key=key)

    if status_filter:
        status_lower = status_filter.lower()
        all_devices = [
            d
            for d in all_devices
            if (d.get("status") or d.get("state") or "").lower() == status_lower
        ]

    return {
        "devices": all_devices,
        "count": len(all_devices),
        "filter": status_filter,
        "key_label": key_label,
    }


async def _list_all_clients_fleet(
    client: UniFiClient,
    registry: Registry,
    *,
    key_label: str | None = None,
) -> dict[str, Any]:
    """List all connected clients across all sites by fanning out proxy requests.

    key_label scopes the query to consoles visible to a specific API key.
    """
    key = _resolve_key(client, key_label)
    pairs = await _get_all_host_site_pairs(registry, key=key)

    async def _fetch_clients(pair: dict[str, str]) -> dict[str, Any]:
        try:
            data = await client.get(
                _proxy(pair["hostId"], f"/sites/{pair['siteId']}/clients"),
                key=key,
            )
            clients_list = data if isinstance(data, list) else data.get("data", [])
            for c in clients_list:
                c["_hostId"] = pair["hostId"]
                c["_hostName"] = pair["hostName"]
                c["_siteId"] = pair["siteId"]
                c["_siteName"] = pair["siteName"]
            return {"clients": clients_list, "error": None}
        except Exception as exc:
            return {"clients": [], "error": f"{pair['siteName']}: {exc}"}

    results = await asyncio.gather(*[_fetch_clients(p) for p in pairs])

    all_clients: list[dict[str, Any]] = []
    errors: list[str] = []
    for r in results:
        all_clients.extend(r["clients"])
        if r["error"]:
            errors.append(r["error"])

    if pairs and len(errors) == len(pairs):
        raise RuntimeError(f"All {len(pairs)} site(s) failed. First error: {errors[0]}")

    result: dict[str, Any] = {
        "clients": all_clients,
        "count": len(all_clients),
        "sitesQueried": len(pairs),
        "key_label": key_label,
    }
    if errors:
        result["errors"] = errors
    return result


def _unwrap_ea_devices(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """/ea/devices returns host-wrapper objects: [{hostId, devices:[...]}, ...].

    Unwrap to get a flat list of device objects. Fall back to using the item
    directly if it is not a wrapper (i.e. has no inner 'devices' list).
    """
    devices: list[dict[str, Any]] = []
    for wrapper in raw:
        inner = wrapper.get("devices")
        if isinstance(inner, list):
            devices.extend(inner)
        else:
            devices.append(wrapper)
    return devices


async def _fleet_summary(
    client: UniFiClient,
    registry: Registry,
    *,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Get a high-level summary of the entire fleet: host/site/device counts and status breakdown.

    key_label scopes the summary to consoles visible to a specific API key.
    """
    key = _resolve_key(client, key_label)
    hosts_data, sites_data, raw_devices = await asyncio.gather(
        client.paginate("/ea/hosts", key=key),
        client.paginate("/ea/sites", key=key),
        client.paginate("/ea/devices", key=key),
    )

    # Opportunistically refresh registry cache for this key
    await registry.set_hosts(hosts_data, key=key)
    await registry.set_ea_sites(sites_data, key=key)

    # /ea/devices returns host-wrapper objects — unwrap to actual device dicts
    devices_data = _unwrap_ea_devices(raw_devices)

    # Device status breakdown
    # The EA API may use "status" or "state" depending on the firmware version.
    status_counts: dict[str, int] = {}
    for d in devices_data:
        status = d.get("status") or d.get("state") or "unknown"
        status_counts[status] = status_counts.get(status, 0) + 1

    # Device type/product-line breakdown
    # The EA API uses "productLine" (e.g. "network", "protect") rather than "type".
    type_counts: dict[str, int] = {}
    for d in devices_data:
        dev_type = d.get("productLine") or d.get("type") or "unknown"
        type_counts[dev_type] = type_counts.get(dev_type, 0) + 1

    return {
        "hosts": len(hosts_data),
        "sites": len(sites_data),
        "devices": {
            "total": len(devices_data),
            "byStatus": status_counts,
            "byType": type_counts,
        },
        "key_label": key_label,
    }


async def _search_device(
    client: UniFiClient,
    query: str,
    *,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Search for a device by name or MAC address across the entire fleet.

    key_label scopes the search to consoles visible to a specific API key.
    """
    key = _resolve_key(client, key_label)
    all_raw = await client.paginate("/ea/devices", key=key)

    # /ea/devices returns host-wrapper objects: [{"devices": [...], "hostId": ...}, ...]
    # Unwrap to get the inner device list; fall back to using the item directly if not wrapped.
    all_devices: list[dict[str, Any]] = []
    for wrapper in all_raw:
        inner = wrapper.get("devices")
        if isinstance(inner, list):
            all_devices.extend(inner)
        else:
            all_devices.append(wrapper)

    query_lower = query.lower()

    matches = []
    for d in all_devices:
        reported = d.get("reportedState") or {}
        searchable = [
            d.get("name", ""),
            d.get("mac", ""),
            d.get("model", ""),
            d.get("shortname", ""),
            d.get("hostname", ""),
            d.get("displayName", ""),
            d.get("ip", ""),
            reported.get("hostname", ""),
            reported.get("model", ""),
            reported.get("shortname", ""),
            reported.get("ip", ""),
            reported.get("mac", ""),
            reported.get("name", ""),
        ]
        if any(query_lower in field.lower() for field in searchable if field):
            matches.append(d)

    return {
        "matches": matches,
        "count": len(matches),
        "query": query,
        "key_label": key_label,
    }


async def _list_api_keys(client: UniFiClient) -> dict[str, Any]:
    """List all configured API keys with their labels and types.

    Returns key labels and whether each is an organization key, without
    exposing the actual key values.
    """
    configs = client._settings.get_key_configs()
    keys = []
    for cfg in configs:
        keys.append(
            {
                "label": cfg.label,
                "is_org_key": cfg.is_org_key,
            }
        )
    return {
        "keys": keys,
        "count": len(keys),
    }


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register all aggregation MCP tools."""

    @mcp.tool()
    async def list_configured_api_keys() -> dict[str, Any]:
        """List all configured API keys with their labels and types.

        Shows which API keys are available for MSP multi-console queries.
        Returns labels and org-key status without exposing actual key values.
        """
        client, _ = deps_fn()
        return await _list_api_keys(client)

    @mcp.tool()
    async def list_all_devices(
        status_filter: str | None = None,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """List all devices across the entire fleet.

        Aggregates devices from all consoles. Optionally filter by status
        (e.g. 'offline', 'online', 'updating') to find problem devices quickly.
        key_label: scope query to a specific API key
        (use list_configured_api_keys to see available keys).
        """
        client, _ = deps_fn()
        return await _list_all_devices_fleet(
            client, status_filter=status_filter, key_label=key_label
        )

    @mcp.tool()
    async def list_all_clients(
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """List all connected clients across all sites.

        Fans out requests to every site and aggregates results with source
        host/site annotations on each client record.
        key_label: scope query to consoles visible to a specific API key.
        """
        client, registry = deps_fn()
        return await _list_all_clients_fleet(client, registry, key_label=key_label)

    @mcp.tool()
    async def get_fleet_summary(
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """Get a high-level fleet summary: host, site, and device counts with status breakdowns.

        Useful for a quick overview of the entire UniFi deployment.
        key_label: scope summary to consoles visible to a specific API key.
        """
        client, registry = deps_fn()
        return await _fleet_summary(client, registry, key_label=key_label)

    @mcp.tool()
    async def search_device_fleet(
        query: str,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """Search for a device by name, MAC address, or model across the entire fleet.

        Returns all matching devices from all consoles.
        key_label: scope search to consoles visible to a specific API key.
        """
        client, _ = deps_fn()
        return await _search_device(client, query, key_label=key_label)
