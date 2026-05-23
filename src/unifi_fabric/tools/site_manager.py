"""Site Manager read-only tools — 9 endpoints from the UniFi Site Manager API."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, cast

import httpx

from ..client import (
    RateLimitError,
    UniFiClient,
    UniFiConnectionError,
    validate_host_id,
    validate_id,
)
from ..registry import Registry, _assert_uuid
from .network import _proxy

logger = logging.getLogger(__name__)


def _filter_gps(host: dict[str, Any], include_gps: bool) -> dict[str, Any]:
    """Strip GPS coordinates from host data unless explicitly requested."""
    if include_gps:
        return host
    result = dict(host)
    reported = result.get("reportedState")
    if isinstance(reported, dict):
        reported = dict(reported)
        reported.pop("latitude", None)
        reported.pop("longitude", None)
        reported.pop("geoInfo", None)
        result["reportedState"] = reported
    return result


async def list_hosts(
    client: UniFiClient,
    registry: Registry,
    *,
    include_gps: bool = False,
    page_token: str | None = None,
    page_size: int = 200,
) -> dict[str, Any]:
    """List all UniFi consoles (hosts) with firmware, WAN IP, and status.

    GPS coordinates are hidden by default. Set include_gps=True to include them.
    """
    params: dict[str, Any] = {"limit": page_size}
    if page_token:
        params["nextToken"] = page_token

    data = await client.get("/ea/hosts", params=params)
    hosts = data.get("data", [])
    filtered = [_filter_gps(h, include_gps) for h in hosts]

    # Update registry cache opportunistically
    if not page_token:
        await registry.set_hosts(hosts)

    result: dict[str, Any] = {"hosts": filtered, "count": len(filtered)}
    if data.get("nextToken"):
        result["nextToken"] = data["nextToken"]
    return result


async def get_host(
    client: UniFiClient,
    registry: Registry,
    host: str,
    *,
    include_gps: bool = False,
) -> dict[str, Any]:
    """Get details for a single UniFi console by name or ID.

    GPS coordinates are hidden by default. Set include_gps=True to include them.
    """
    host_id = await registry.resolve_host_id(host)
    data = await client.get(f"/ea/hosts/{host_id}")
    host_data = data.get("data", data)
    return _filter_gps(host_data, include_gps)


async def list_sites(
    client: UniFiClient,
    registry: Registry,
    *,
    page_token: str | None = None,
) -> dict[str, Any]:
    """List all sites with device/client counts and ISP info."""
    params: dict[str, Any] = {}
    if page_token:
        params["nextToken"] = page_token

    data = await client.get("/ea/sites", params=params or None)
    sites = data.get("data", [])

    if not page_token:
        await registry.set_ea_sites(sites)

    result: dict[str, Any] = {"sites": sites, "count": len(sites)}
    if data.get("nextToken"):
        result["nextToken"] = data["nextToken"]
    return result


async def list_devices(
    client: UniFiClient,
    registry: Registry,
    *,
    host: str | None = None,
    page_token: str | None = None,
) -> dict[str, Any]:
    """List all devices across the fleet with status, firmware, and model."""
    params: dict[str, Any] = {}
    if host:
        host_id = await registry.resolve_host_id(host)
        params["hostId"] = host_id
    if page_token:
        params["nextToken"] = page_token

    data = await client.get("/ea/devices", params=params or None)
    devices = data.get("data", [])

    result: dict[str, Any] = {"devices": devices, "count": len(devices)}
    if data.get("nextToken"):
        result["nextToken"] = data["nextToken"]
    return result


async def get_isp_metrics(
    client: UniFiClient,
    interval: str,
) -> dict[str, Any]:
    """Get WAN health metrics (speed, latency, packet loss, uptime).

    interval: time bucket for aggregation — '5m' or '1h'.
    """
    if interval not in ("5m", "1h"):
        raise ValueError(f"interval must be '5m' or '1h', got {interval!r}")
    data = await client.get(f"/ea/isp-metrics/{interval}")
    result = data.get("data", data) if isinstance(data, dict) else data
    if isinstance(result, list):
        return {"periods": result}
    return cast(dict[str, Any], result)


async def query_isp_metrics(
    client: UniFiClient,
    interval: str,
    *,
    sites: list[dict[str, str]] | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
) -> dict[str, Any]:
    """Query filtered ISP metrics with optional site/time range filters.

    interval: time bucket for aggregation — '5m' or '1h'.
    sites: list of {hostId, siteId} dicts to scope the query.
    start_time/end_time: ISO 8601 timestamps for time range.
    """
    if interval not in ("5m", "1h"):
        raise ValueError(f"interval must be '5m' or '1h', got {interval!r}")
    body: dict[str, Any] = {}
    if sites:
        body["sites"] = sites
    if start_time:
        body["beginTimestamp"] = start_time
    if end_time:
        body["endTimestamp"] = end_time

    data = await client.post(f"/ea/isp-metrics/{interval}/query", json=body)
    result = data.get("data", data) if isinstance(data, dict) else data
    if isinstance(result, list):
        return {"periods": result}
    return cast(dict[str, Any], result)


async def list_sdwan_configs(
    client: UniFiClient,
    *,
    page_token: str | None = None,
) -> dict[str, Any]:
    """List Site Magic (SD-WAN) VPN mesh configurations."""
    params: dict[str, Any] = {}
    if page_token:
        params["nextToken"] = page_token

    data = await client.get("/ea/sd-wan-configs", params=params or None)
    configs = data.get("data", [])

    result: dict[str, Any] = {"configs": configs, "count": len(configs)}
    if data.get("nextToken"):
        result["nextToken"] = data["nextToken"]
    return result


async def get_sdwan_config(
    client: UniFiClient,
    config_id: str,
) -> dict[str, Any]:
    """Get a single SD-WAN configuration by ID."""
    validate_id(config_id, "config_id")
    data = await client.get(f"/ea/sd-wan-configs/{config_id}")
    return cast(dict[str, Any], data.get("data", data))


async def get_sdwan_config_status(
    client: UniFiClient,
    config_id: str,
) -> dict[str, Any]:
    """Get the status of an SD-WAN configuration by ID."""
    validate_id(config_id, "config_id")
    data = await client.get(f"/ea/sd-wan-configs/{config_id}/status")
    return cast(dict[str, Any], data.get("data", data))


# --- /v1/sites/ tools ---


async def _resolve_ea_host_site(registry: Registry, name_or_id: str) -> tuple[str, str]:
    """Resolve a site name or siteId to a validated (hostId, siteId) pair from EA sites.

    Raises ValueError if the site is not found or if either ID fails validation.
    """
    sites = await registry.get_ea_sites()
    for site in sites:
        site_id = site.get("siteId") or site.get("id", "")
        meta = site.get("meta") or {}
        site_name = (
            site.get("siteName")
            or site.get("description")
            or site.get("name")
            or meta.get("desc")
            or meta.get("name")
            or ""
        ).lower()
        if site_id == name_or_id or site_name == name_or_id.lower():
            host_id = site.get("hostId", "")
            try:
                validate_host_id(host_id, "hostId")
                validate_id(site_id, "siteId")
            except ValueError as exc:
                raise ValueError(f"Site {name_or_id!r}: {exc}") from exc
            return host_id, site_id
    raise ValueError(
        f"Site {name_or_id!r} not found. "
        "Use list_sites or list_all_sites_aggregated to see available sites."
    )


async def list_all_sites_aggregated(
    client: UniFiClient,
    registry: Registry,
) -> dict[str, Any]:
    """List all sites with aggregated health stats from /v1/sites/.

    Returns sites merged with health summary: device counts, client counts,
    alerts, and connectivity status in a single call.
    """
    data = await client.get("/v1/sites")
    sites = data.get("data", data) if isinstance(data, dict) else data
    if not isinstance(sites, list):
        sites = []

    # Opportunistically refresh EA site registry cache
    await registry.set_ea_sites(sites)

    return {"sites": sites, "count": len(sites)}


async def get_site_health_summary(
    client: UniFiClient,
    registry: Registry,
    site: str,
) -> dict[str, Any]:
    """Get health summary for a single site: uptime, alerts, and device counts.

    site: site name or ID.
    Routes through Classic REST /stat/health (same endpoint as get_site_statistics).
    """
    host_id, _ = await _resolve_ea_host_site(registry, site)
    site_slug = await registry.resolve_site_slug(site, host_id)
    url = f"/v1/connector/consoles/{host_id}/proxy/network/api/s/{site_slug}/stat/health"
    data = await client.get(url)
    result = data.get("data", data) if isinstance(data, dict) else data
    if isinstance(result, list):
        return {"health": result, "count": len(result)}
    return cast(dict[str, Any], result)


async def compare_site_performance(
    client: UniFiClient,
    registry: Registry,
    sites: list[str],
) -> dict[str, Any]:
    """Compare health and performance metrics across multiple sites.

    sites: list of site names or IDs to compare.
    Returns a list of per-site health summaries side-by-side.
    """

    async def _fetch(site: str) -> dict[str, Any]:
        try:
            result = await get_site_health_summary(client, registry, site)
            result = dict(result) if isinstance(result, dict) else {"raw": result}
            result["_siteLabel"] = site
            return result
        except Exception as exc:
            return {"_siteLabel": site, "error": str(exc)}

    results = await asyncio.gather(*[_fetch(s) for s in sites])
    return {"comparison": list(results), "count": len(results)}


async def search_across_sites(
    client: UniFiClient,
    registry: Registry,
    query: str,
) -> dict[str, Any]:
    """Search for devices or clients matching a query across all sites.

    query: search term matched against name, MAC address, IP, or model.
    Returns matching devices and clients with their site context.
    """
    sites_data = await registry.get_ea_sites()
    query_lower = query.lower()

    async def _search_site(site: dict[str, Any]) -> dict[str, Any]:
        host_id = site.get("hostId", "")
        ea_site_id = site.get("siteId", site.get("id", ""))
        site_name = site.get("siteName", ea_site_id)
        matches: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []

        try:
            validate_host_id(host_id, "hostId")
        except ValueError as exc:
            logger.warning("search_across_sites: skipping site %s: %s", ea_site_id, exc)
            return {"siteId": ea_site_id, "siteName": site_name, "matches": [], "errors": []}

        # Resolve the proxy UUID — EA siteId is a Fabric ObjectId, not a UUID
        try:
            site_id = await registry.resolve_site_id(site_name, host_id)
        except ValueError as exc:
            logger.warning("search_across_sites: skipping site %s: %s", ea_site_id, exc)
            return {"siteId": ea_site_id, "siteName": site_name, "matches": [], "errors": []}

        try:
            data = await client.get(_proxy(host_id, f"/sites/{site_id}/devices"))
            devices = data.get("data", data) if isinstance(data, dict) else data
            if isinstance(devices, list):
                for d in devices:
                    searchable = " ".join(
                        [
                            str(d.get("name", "")),
                            str(d.get("mac", "")),
                            str(d.get("ip", "")),
                            str(d.get("model", "")),
                        ]
                    ).lower()
                    if query_lower in searchable:
                        item = dict(d)
                        item["_type"] = "device"
                        item["_siteId"] = site_id
                        item["_siteName"] = site_name
                        matches.append(item)
        except (httpx.HTTPError, UniFiConnectionError, RateLimitError) as exc:
            logger.warning("search_across_sites: devices fetch failed for %s: %s", site_id, exc)
            errors.append({"siteId": site_id, "scope": "devices", "error": str(exc)})

        try:
            data = await client.get(_proxy(host_id, f"/sites/{site_id}/clients"))
            clients_list = data.get("data", data) if isinstance(data, dict) else data
            if isinstance(clients_list, list):
                for c in clients_list:
                    searchable = " ".join(
                        [
                            str(c.get("name", "")),
                            str(c.get("mac", "")),
                            str(c.get("ip", "")),
                            str(c.get("hostname", "")),
                        ]
                    ).lower()
                    if query_lower in searchable:
                        item = dict(c)
                        item["_type"] = "client"
                        item["_siteId"] = site_id
                        item["_siteName"] = site_name
                        matches.append(item)
        except (httpx.HTTPError, UniFiConnectionError, RateLimitError) as exc:
            logger.warning("search_across_sites: clients fetch failed for %s: %s", site_id, exc)
            errors.append({"siteId": site_id, "scope": "clients", "error": str(exc)})

        return {"siteId": site_id, "siteName": site_name, "matches": matches, "errors": errors}

    results = await client.gather([_search_site(s) for s in sites_data])

    all_matches: list[dict[str, Any]] = []
    all_errors: list[dict[str, str]] = []
    for r in results:
        all_matches.extend(r["matches"])
        all_errors.extend(r["errors"])

    response: dict[str, Any] = {
        "matches": all_matches,
        "count": len(all_matches),
        "query": query,
        "sitesSearched": len(sites_data),
    }
    if all_errors:
        response["errors"] = all_errors
    return response


async def get_site_inventory(
    client: UniFiClient,
    registry: Registry,
    site: str,
) -> dict[str, Any]:
    """Get full inventory for a site: all devices and connected clients.

    site: site name or ID.
    """
    host_id, _ = await _resolve_ea_host_site(registry, site)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)

    devices_data, clients_data = await asyncio.gather(
        client.get(_proxy(host_id, f"/sites/{site_id}/devices")),
        client.get(_proxy(host_id, f"/sites/{site_id}/clients")),
    )

    devices = (
        devices_data.get("data", devices_data) if isinstance(devices_data, dict) else devices_data
    )
    clients_list = (
        clients_data.get("data", clients_data) if isinstance(clients_data, dict) else clients_data
    )

    if not isinstance(devices, list):
        devices = []
    if not isinstance(clients_list, list):
        clients_list = []

    return {
        "siteId": site_id,
        "devices": devices,
        "deviceCount": len(devices),
        "clients": clients_list,
        "clientCount": len(clients_list),
    }
