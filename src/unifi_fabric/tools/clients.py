"""Client management tools — list, get, and actions via connector proxy."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastmcp import FastMCP

from ..client import UniFiClient, validate_id
from ..registry import Registry, _assert_uuid
from ._pagination import collect_offset, mark_incomplete
from .network import _proxy

_CLASSIC_CMD_BASE = "/v1/connector/consoles/{host_id}/proxy/network/api/s/{site_slug}/cmd"


def _classic_cmd(host_id: str, site_slug: str, path: str) -> str:
    return _CLASSIC_CMD_BASE.format(host_id=host_id, site_slug=site_slug) + path


async def _list_clients(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
    client_type: str | None = None,
) -> Any:
    """List connected clients for a site with optional pagination and type filter.

    By default every offset page is drained and the complete client list is
    returned as ``{data, totalCount}``. Passing offset or limit selects manual
    paging: a single page is returned with the API's totalCount so the caller can
    advance. client_type is a filter (not paging) and applies in either mode. A
    drain that hits the page cap returns the clients gathered so far with
    incomplete=true rather than truncating silently.
    """
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    base: dict[str, Any] = {}
    if client_type and client_type.upper() != "ALL":
        base["type"] = client_type.upper()
    url = _proxy(host_id, f"/sites/{site_id}/clients")
    collected = await collect_offset(client, url, params=base or None, offset=offset, limit=limit)
    total = collected["totalCount"]
    result: dict[str, Any] = {
        "data": collected["items"],
        "totalCount": total if total is not None else len(collected["items"]),
    }
    return mark_incomplete(result, collected)


async def _get_client(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    client_id: str,
) -> dict[str, Any]:
    """Get details for a single client."""
    validate_id(client_id, "client_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.get(_proxy(host_id, f"/sites/{site_id}/clients/{client_id}"))


async def _execute_client_action(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    client_id: str,
    action: dict[str, Any],
) -> dict[str, Any]:
    """Execute a client action (block, unblock, reconnect)."""
    validate_id(client_id, "client_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.post(
        _proxy(host_id, f"/sites/{site_id}/clients/{client_id}/actions"), json=action
    )


async def _block_client(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    client_id: str,
) -> dict[str, Any]:
    """Block a client on a site via Classic REST stamgr."""
    validate_id(client_id, "client_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    client_data = await client.get(_proxy(host_id, f"/sites/{site_id}/clients/{client_id}"))
    mac = client_data.get("mac") or client_data.get("macAddress", "")
    if not mac:
        raise ValueError(f"Could not retrieve MAC address for client {client_id}")
    site_slug = await registry.resolve_site_slug(site, host_id)
    return await client.post(
        _classic_cmd(host_id, site_slug, "/stamgr"), json={"cmd": "block-sta", "mac": mac}
    )


async def _unblock_client(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    client_id: str,
) -> dict[str, Any]:
    """Unblock a previously blocked client on a site via Classic REST stamgr."""
    validate_id(client_id, "client_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    client_data = await client.get(_proxy(host_id, f"/sites/{site_id}/clients/{client_id}"))
    mac = client_data.get("mac") or client_data.get("macAddress", "")
    if not mac:
        raise ValueError(f"Could not retrieve MAC address for client {client_id}")
    site_slug = await registry.resolve_site_slug(site, host_id)
    return await client.post(
        _classic_cmd(host_id, site_slug, "/stamgr"), json={"cmd": "unblock-sta", "mac": mac}
    )


async def _reconnect_client(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    client_id: str,
) -> dict[str, Any]:
    """Force a client to reconnect on a site via Classic REST stamgr."""
    validate_id(client_id, "client_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    client_data = await client.get(_proxy(host_id, f"/sites/{site_id}/clients/{client_id}"))
    mac = client_data.get("mac") or client_data.get("macAddress", "")
    if not mac:
        raise ValueError(f"Could not retrieve MAC address for client {client_id}")
    site_slug = await registry.resolve_site_slug(site, host_id)
    return await client.post(
        _classic_cmd(host_id, site_slug, "/stamgr"), json={"cmd": "kick-sta", "mac": mac}
    )


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register all client management MCP tools."""

    @mcp.tool()
    async def list_clients(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        client_type: str | None = None,
    ) -> Any:
        """List connected clients for a site.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        By default every page is drained and the complete client list is returned
        as {data, totalCount}. offset/limit: fetch a single page manually (the
        API's totalCount is surfaced so you can advance). client_type: filter by
        connection type — WIRELESS, WIRED, or ALL (default: all types). A capped
        drain returns the clients gathered so far with incomplete=true rather than
        truncating silently.
        """
        client, registry = deps_fn()
        return await _list_clients(
            client, registry, host, site, offset=offset, limit=limit, client_type=client_type
        )

    @mcp.tool()
    async def get_client(
        host: str,
        site: str,
        client_id: str,
    ) -> dict[str, Any]:
        """Get details for a single client.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        """
        client, registry = deps_fn()
        return await _get_client(client, registry, host, site, client_id)

    @mcp.tool()
    async def execute_client_action(
        host: str,
        site: str,
        client_id: str,
        action: dict[str, Any],
    ) -> dict[str, Any]:
        """Execute a client action (block, unblock, reconnect).

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        action: must include: {'action': str}. Common commands: {'action': 'block'},
          {'action': 'unblock'}, {'action': 'reconnect'}.
        """
        client, registry = deps_fn()
        return await _execute_client_action(client, registry, host, site, client_id, action)

    @mcp.tool()
    async def block_client(
        host: str,
        site: str,
        client_id: str,
    ) -> dict[str, Any]:
        """Block a client on a site.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        """
        client, registry = deps_fn()
        return await _block_client(client, registry, host, site, client_id)

    @mcp.tool()
    async def unblock_client(
        host: str,
        site: str,
        client_id: str,
    ) -> dict[str, Any]:
        """Unblock a previously blocked client on a site.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        """
        client, registry = deps_fn()
        return await _unblock_client(client, registry, host, site, client_id)

    @mcp.tool()
    async def reconnect_client(
        host: str,
        site: str,
        client_id: str,
    ) -> dict[str, Any]:
        """Force a client to reconnect on a site.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        """
        client, registry = deps_fn()
        return await _reconnect_client(client, registry, host, site, client_id)
