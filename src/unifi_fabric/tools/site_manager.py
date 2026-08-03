"""Site Manager read-only tools — 9 endpoints from the UniFi Site Manager API."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any, cast

import httpx

from ..client import (
    RateLimitError,
    UniFiClient,
    UniFiConnectionError,
    validate_host_id,
    validate_id,
)
from ..config import APIKeyConfig
from ..registry import Registry, _assert_uuid
from ._pagination import collect_cursor, mark_incomplete
from .network import _proxy

logger = logging.getLogger(__name__)


async def _aggregate_lists_over_keys(
    client: UniFiClient,
    labels: list[str],
    fetch: Callable[[APIKeyConfig], Awaitable[list[dict[str, Any]]]],
    *,
    on_success: Callable[[APIKeyConfig, list[dict[str, Any]]], Awaitable[None]] | None = None,
    transform: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Fan a per-key list fetch across all configured API keys (MSP aggregation).

    Mirrors the partial-failure pattern in ``tools/aggregation.py``
    (``_list_all_clients_fleet``): every key is fetched concurrently via
    ``asyncio.gather``; a per-key failure is captured as an error string rather
    than aborting the whole call; ``RuntimeError`` is raised only when *every*
    key fails. Each returned record is copied and annotated with its source key
    via ``_keyLabel`` (matching the existing ``_hostId`` / ``_siteName``
    per-record annotation convention), so a caller can tell which org each item
    came from. This is what fixes issue #19: without fan-out, only the first
    configured key's org was ever returned.
    """

    async def _fetch(label: str) -> tuple[str, list[dict[str, Any]], str | None]:
        key = client.get_key_by_label(label)
        try:
            items = await fetch(key)
            if on_success is not None:
                await on_success(key, items)
            return label, items, None
        except Exception as exc:
            return label, [], f"{label}: {exc}"

    results = await asyncio.gather(*[_fetch(label) for label in labels])

    aggregated: list[dict[str, Any]] = []
    errors: list[str] = []
    for label, items, err in results:
        if err is not None:
            errors.append(err)
            continue
        for item in items:
            record = dict(transform(item)) if transform is not None else dict(item)
            record["_keyLabel"] = label
            aggregated.append(record)

    if labels and len(errors) == len(labels):
        raise RuntimeError(f"All {len(labels)} API key(s) failed. First error: {errors[0]}")

    return aggregated, errors


async def list_hosts(
    client: UniFiClient,
    registry: Registry,
    *,
    page_token: str | None = None,
    page_size: int = 200,
) -> dict[str, Any]:
    """List all UniFi consoles (hosts) with firmware, WAN IP, and status.

    Host records are returned verbatim, including reportedState GPS coordinates.

    By default every page is drained and the complete host list is returned.
    Pass page_token to fetch a single page manually (the response then carries a
    nextToken cursor to continue). If a full drain hits the page cap it returns
    the hosts gathered so far with incomplete=true rather than truncating
    silently.

    MSP multi-key: when more than one API key is configured, hosts are
    aggregated across every key's org (issue #19) with partial-failure
    semantics, each host annotated with its source ``_keyLabel``; pagination
    tokens do not apply in that mode (every key is fully paginated).
    """
    labels = client.list_key_labels()
    if len(labels) > 1:
        hosts, errors = await _aggregate_lists_over_keys(
            client,
            labels,
            lambda key: client.paginate("/ea/hosts", key=key),
            on_success=lambda key, items: registry.set_hosts(items, key=key),
        )
        mk_result: dict[str, Any] = {"hosts": hosts, "count": len(hosts), "key_labels": labels}
        if errors:
            mk_result["errors"] = errors
        return mk_result

    collected = await collect_cursor(
        client, "/ea/hosts", page_token=page_token, page_size=page_size
    )
    raw_hosts = collected["items"]

    # Update registry cache opportunistically (only a complete drain is cacheable).
    if page_token is None:
        await registry.set_hosts(raw_hosts)

    result: dict[str, Any] = {"hosts": raw_hosts, "count": len(raw_hosts)}
    if collected["nextToken"]:
        result["nextToken"] = collected["nextToken"]
    return mark_incomplete(result, collected)


async def get_host(
    client: UniFiClient,
    registry: Registry,
    host: str,
) -> dict[str, Any]:
    """Get details for a single UniFi console by name or ID.

    Host record is returned verbatim, including reportedState GPS coordinates.
    """
    host_id = await registry.resolve_host_id(host)
    data = await client.get(f"/ea/hosts/{host_id}")
    return cast(dict[str, Any], data.get("data", data))


async def list_sites(
    client: UniFiClient,
    registry: Registry,
    *,
    page_token: str | None = None,
) -> dict[str, Any]:
    """List all sites with device/client counts and ISP info.

    By default every page is drained and the complete site list is returned.
    Pass page_token to fetch a single page manually (the response then carries a
    nextToken cursor to continue). A capped drain returns the sites gathered so
    far with incomplete=true rather than truncating silently.

    MSP multi-key: when more than one API key is configured, sites are
    aggregated across every key's org (issue #19) with partial-failure
    semantics, each site annotated with its source ``_keyLabel``.
    """
    labels = client.list_key_labels()
    if len(labels) > 1:
        sites, errors = await _aggregate_lists_over_keys(
            client,
            labels,
            lambda key: client.paginate("/ea/sites", key=key),
            on_success=lambda key, items: registry.set_ea_sites(items, key=key),
        )
        mk_result: dict[str, Any] = {"sites": sites, "count": len(sites), "key_labels": labels}
        if errors:
            mk_result["errors"] = errors
        return mk_result

    collected = await collect_cursor(client, "/ea/sites", page_token=page_token)
    sites = collected["items"]

    if page_token is None:
        await registry.set_ea_sites(sites)

    result: dict[str, Any] = {"sites": sites, "count": len(sites)}
    if collected["nextToken"]:
        result["nextToken"] = collected["nextToken"]
    return mark_incomplete(result, collected)


async def list_devices(
    client: UniFiClient,
    registry: Registry,
    *,
    host: str | None = None,
    page_token: str | None = None,
) -> dict[str, Any]:
    """List all devices across the fleet with status, firmware, and model.

    By default every page is drained and the complete device list is returned.
    Pass page_token to fetch a single page manually (the response then carries a
    nextToken cursor to continue). A capped drain returns the devices gathered
    so far with incomplete=true rather than truncating silently.
    """
    params: dict[str, Any] = {}
    if host:
        host_id = await registry.resolve_host_id(host)
        params["hostId"] = host_id

    collected = await collect_cursor(
        client, "/ea/devices", params=params or None, page_token=page_token
    )
    devices = collected["items"]

    result: dict[str, Any] = {"devices": devices, "count": len(devices)}
    if collected["nextToken"]:
        result["nextToken"] = collected["nextToken"]
    return mark_incomplete(result, collected)


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
    sites: list of {hostId, siteId} dicts to scope the query. REQUIRED — the UniFi
        Site Manager API rejects an unscoped query body with an opaque HTTP 400
        ("error while parsing request").
    start_time/end_time: ISO 8601 UTC timestamps (e.g. "2026-07-23T00:00:00Z")
        bounding the query window. The UniFi Site Manager API reads the window from
        per-site ``beginTimestamp`` / ``endTimestamp`` fields nested INSIDE each
        ``sites[]`` entry — a top-level timestamp is accepted but silently ignored
        (verified live: a top-level window returns the full default range, whereas a
        nested window is honoured exactly). These params are therefore applied to
        every site entry. A caller may instead set per-entry beginTimestamp/
        endTimestamp directly in the ``sites`` dicts; those explicit values win.
    """
    if interval not in ("5m", "1h"):
        raise ValueError(f"interval must be '5m' or '1h', got {interval!r}")
    if not sites:
        raise ValueError(
            "query_isp_metrics requires at least one site filter; pass "
            "sites=[{'hostId': ..., 'siteId': ...}]. The UniFi API rejects an "
            "unscoped query with HTTP 400 'error while parsing request'."
        )
    # Copy each site dict so the caller's list is never mutated, then inject the
    # time window per-site (where the API actually reads it). setdefault lets a
    # caller pin an explicit per-entry window that overrides the convenience params.
    body: dict[str, Any] = {"sites": [dict(entry) for entry in sites]}
    if start_time or end_time:
        for entry in body["sites"]:
            if start_time:
                entry.setdefault("beginTimestamp", start_time)
            if end_time:
                entry.setdefault("endTimestamp", end_time)

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
    """List Site Magic (SD-WAN) VPN mesh configurations.

    By default every page is drained and the complete config list is returned.
    Pass page_token to fetch a single page manually (the response then carries a
    nextToken cursor to continue). A capped drain returns the configs gathered
    so far with incomplete=true rather than truncating silently.
    """
    collected = await collect_cursor(client, "/ea/sd-wan-configs", page_token=page_token)
    configs = collected["items"]

    result: dict[str, Any] = {"configs": configs, "count": len(configs)}
    if collected["nextToken"]:
        result["nextToken"] = collected["nextToken"]
    return mark_incomplete(result, collected)


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

    MSP multi-key: when more than one API key is configured, sites are
    aggregated across every key's org (issue #19) with partial-failure
    semantics, each site annotated with its source ``_keyLabel``. Single-key
    deployments are unchanged.
    """
    labels = client.list_key_labels()
    if len(labels) > 1:

        async def _fetch_v1_sites(key: APIKeyConfig) -> list[dict[str, Any]]:
            resp = await client.get("/v1/sites", key=key)
            items = resp.get("data", resp) if isinstance(resp, dict) else resp
            return items if isinstance(items, list) else []

        sites, errors = await _aggregate_lists_over_keys(
            client,
            labels,
            _fetch_v1_sites,
            on_success=lambda key, items: registry.set_ea_sites(items, key=key),
        )
        mk_result: dict[str, Any] = {"sites": sites, "count": len(sites), "key_labels": labels}
        if errors:
            mk_result["errors"] = errors
        return mk_result

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
