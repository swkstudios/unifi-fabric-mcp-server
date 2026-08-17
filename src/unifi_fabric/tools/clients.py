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


_VALID_CLIENT_TYPES = frozenset({"WIRED", "WIRELESS", "ALL"})


def _resolve_client_filter(client_type: str | None, filter: str | None) -> str | None:
    """Resolve ``client_type`` and ``filter`` into one upstream filter expression.

    ``client_type`` is a convenience shorthand: it is translated into the upstream
    ``type.eq('WIRED'|'WIRELESS')`` filter expression. The raw ``type`` query
    parameter the UniFi Integration API does NOT honour (it silently returns every
    client regardless), so translating to ``filter`` is what actually narrows the
    result. ``client_type='ALL'`` (case-insensitive) means "no type restriction" and
    contributes no filter.

    ``client_type`` and an explicit ``filter`` are mutually exclusive whenever
    ``client_type`` would itself produce a filter: the upstream filter grammar has no
    conjunction operator (``and`` and ``&&`` are both rejected with HTTP 400), so the
    two cannot be composed. Passing both raises ``ValueError`` rather than silently
    dropping one and returning wrong results. ``client_type='ALL'`` adds no
    restriction, so it composes trivially and defers to the explicit ``filter``.
    """
    if client_type is None:
        return filter
    normalized = client_type.strip().upper()
    if normalized not in _VALID_CLIENT_TYPES:
        raise ValueError(f"client_type must be one of WIRED, WIRELESS, ALL (got {client_type!r})")
    if normalized == "ALL":
        return filter
    if filter is not None:
        raise ValueError(
            "client_type and filter are mutually exclusive; the upstream filter grammar "
            "cannot compose them. Fold the type into your filter expression instead, "
            "e.g. filter=\"type.eq('WIRED')\"."
        )
    return f"type.eq('{normalized}')"


async def _list_clients(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
    client_type: str | None = None,
    filter: str | None = None,
) -> Any:
    """List connected clients for a site with optional pagination and type filter.

    By default every offset page is drained and the complete client list is
    returned as ``{data, totalCount}``. Passing offset or limit selects manual
    paging: a single page is returned with the API's totalCount so the caller can
    advance. client_type is a filter (not paging) and applies in either mode. A
    drain that hits the page cap returns the clients gathered so far with
    incomplete=true rather than truncating silently. ``filter`` is a server-side
    filter (not paging), forwarded unchanged as the Network Integration API
    ``filter`` query parameter and applied in either mode; when ``None`` it is
    omitted rather than sent as the string ``"None"``. ``client_type`` is translated
    into a ``type.eq(...)`` filter expression and is mutually exclusive with an
    explicit ``filter`` (see ``_resolve_client_filter``).
    """
    resolved_filter = _resolve_client_filter(client_type, filter)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    base: dict[str, Any] = {}
    if resolved_filter is not None:
        base["filter"] = resolved_filter
    url = _proxy(host_id, f"/sites/{site_id}/clients")
    collected = await collect_offset(
        client, url, key=key, params=base or None, offset=offset, limit=limit
    )
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
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.get(_proxy(host_id, f"/sites/{site_id}/clients/{client_id}"), key=key)


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
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.post(
        _proxy(host_id, f"/sites/{site_id}/clients/{client_id}/actions"), key=key, json=action
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
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    client_data = await client.get(
        _proxy(host_id, f"/sites/{site_id}/clients/{client_id}"), key=key
    )
    mac = client_data.get("mac") or client_data.get("macAddress", "")
    if not mac:
        raise ValueError(f"Could not retrieve MAC address for client {client_id}")
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.post(
        _classic_cmd(host_id, site_slug, "/stamgr"), key=key, json={"cmd": "block-sta", "mac": mac}
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
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    client_data = await client.get(
        _proxy(host_id, f"/sites/{site_id}/clients/{client_id}"), key=key
    )
    mac = client_data.get("mac") or client_data.get("macAddress", "")
    if not mac:
        raise ValueError(f"Could not retrieve MAC address for client {client_id}")
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.post(
        _classic_cmd(host_id, site_slug, "/stamgr"),
        key=key,
        json={"cmd": "unblock-sta", "mac": mac},
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
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    client_data = await client.get(
        _proxy(host_id, f"/sites/{site_id}/clients/{client_id}"), key=key
    )
    mac = client_data.get("mac") or client_data.get("macAddress", "")
    if not mac:
        raise ValueError(f"Could not retrieve MAC address for client {client_id}")
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.post(
        _classic_cmd(host_id, site_slug, "/stamgr"), key=key, json={"cmd": "kick-sta", "mac": mac}
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
        filter: str | None = None,
    ) -> Any:
        """List connected clients for a site.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        By default every page is drained and the complete client list is returned
        as {data, totalCount}. offset/limit: fetch a single page manually (the
        API's totalCount is surfaced so you can advance). client_type: convenience
        shorthand — WIRELESS, WIRED, or ALL (default: all types) — translated into
        the upstream `type.eq(...)` filter (the raw type query parameter is ignored
        by the UniFi API, so this translation is what actually narrows the result).
        filter: optional Network Integration API filter expression, forwarded
        unchanged as the upstream `filter` query parameter for server-side filtering
        (e.g. `type.eq('WIRED')`, `macAddress.eq('aa:bb:cc:dd:ee:ff')`); omitted
        entirely when unset. client_type and an explicit filter are mutually
        exclusive (the upstream grammar has no conjunction operator to compose them);
        passing both raises an error rather than silently returning wrong results. A
        capped drain returns the clients gathered so far with incomplete=true rather
        than truncating silently.
        """
        client, registry = deps_fn()
        return await _list_clients(
            client,
            registry,
            host,
            site,
            offset=offset,
            limit=limit,
            client_type=client_type,
            filter=filter,
        )

    @mcp.tool()
    async def get_client(
        host: str,
        site: str,
        client_id: str,
    ) -> dict[str, Any]:
        """Get details for a single client.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        client_id: REQUIRED. Obtain it from `list_clients` (its id field).
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
        client_id: REQUIRED. Obtain it from `list_clients` (its id field).
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
        client_id: REQUIRED. Obtain it from `list_clients` (its id field).
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
        client_id: REQUIRED. Obtain it from `list_clients` (its id field).
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
        client_id: REQUIRED. Obtain it from `list_clients` (its id field).
        """
        client, registry = deps_fn()
        return await _reconnect_client(client, registry, host, site, client_id)
