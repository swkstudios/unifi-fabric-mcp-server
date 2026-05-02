"""Statistics tools — read-only site/device/client stats via Classic REST stat endpoints."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastmcp import FastMCP

from ..client import UniFiClient
from ..registry import Registry

_CLASSIC_STAT_BASE = "/v1/connector/consoles/{host_id}/proxy/network/api/s/{site_slug}/stat"


def _classic_stat(host_id: str, site_slug: str, path: str) -> str:
    return _CLASSIC_STAT_BASE.format(host_id=host_id, site_slug=site_slug) + path


def _extract_data(response: Any) -> Any:
    """Extract the 'data' list from a Classic REST stat response."""
    if isinstance(response, dict) and "data" in response:
        return response["data"]
    return response


async def _get_site_statistics(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_stat(host_id, site_slug, "/health"))
    return _extract_data(response)


async def _get_system_info(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_stat(host_id, site_slug, "/sysinfo"))
    return _extract_data(response)


async def _list_active_clients_stats(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_stat(host_id, site_slug, "/sta"))
    return _extract_data(response)


async def _list_device_stats(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_stat(host_id, site_slug, "/device"))
    return _extract_data(response)


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register all statistics MCP tools."""

    @mcp.tool()
    async def get_site_statistics(
        host: str,
        site: str,
    ) -> Any:
        """Get site health statistics: latency, throughput, and client counts per subsystem.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        Returns a list of subsystem health objects from the Classic REST /stat/health endpoint.
        """
        client, registry = deps_fn()
        return await _get_site_statistics(client, registry, host, site)

    @mcp.tool()
    async def get_system_info(
        host: str,
        site: str,
    ) -> Any:
        """Get controller/console system info: version, uptime, and memory.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        Returns system info objects from the Classic REST /stat/sysinfo endpoint.
        """
        client, registry = deps_fn()
        return await _get_system_info(client, registry, host, site)

    @mcp.tool()
    async def list_active_clients_stats(
        host: str,
        site: str,
    ) -> Any:
        """List detailed per-client statistics: traffic, signal strength, and experience score.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        Returns a list of client stat objects from the Classic REST /stat/sta endpoint.
        """
        client, registry = deps_fn()
        return await _list_active_clients_stats(client, registry, host, site)

    @mcp.tool()
    async def list_device_stats(
        host: str,
        site: str,
    ) -> Any:
        """List per-device statistics: CPU load, memory, uptime, and port throughput.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        Returns a list of device stat objects from the Classic REST /stat/device endpoint.
        """
        client, registry = deps_fn()
        return await _list_device_stats(client, registry, host, site)
