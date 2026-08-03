"""Hotspot operator tools — manage captive portal operator accounts.

Hotspot vouchers are served by the network-services proxy (see
``tools/network_services_proxy.py`` and the ``*_hotspot_vouchers`` tools in
``server.py``), not from this module. This module only owns the Classic-REST
``/rest/hotspotop`` operator tools.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

from fastmcp import FastMCP

from ..client import UniFiClient, validate_id
from ..registry import Registry

# Classic REST: /proxy/network/api/s/{site_slug}/rest
_CLASSIC_REST_BASE = "/v1/connector/consoles/{host_id}/proxy/network/api/s/{site_slug}/rest"


def _classic_rest(host_id: str, site_slug: str, path: str) -> str:
    return _CLASSIC_REST_BASE.format(host_id=host_id, site_slug=site_slug) + path


# ---------------------------------------------------------------------------
# Hotspot operators
# ---------------------------------------------------------------------------


async def _list_hotspot_operators(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
) -> dict[str, Any]:
    """List hotspot operator accounts via Classic REST (/rest/hotspotop)."""
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    data = await client.get(_classic_rest(host_id, site_slug, "/hotspotop"))
    items = data.get("data", [])
    return {"operators": items, "count": len(items)}


async def _create_hotspot_operator(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    name: str,
    password: str,
    *,
    note: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Create a hotspot operator account via Classic REST (/rest/hotspotop).

    Operators are managed through the console's Classic REST controller — the
    same base ``list_hotspot_operators`` reads from — not the Site Manager
    ``/ea/hotspot-operators`` path, which is not served on the console and 404s at
    the route level. The site is addressed by its slug in the URL, so host/site
    identifiers are not repeated in the body; the controller field for the
    operator secret is ``x_password``.

    Args:
        host: Host name or ID.
        site: Site name or ID.
        name: Operator username.
        password: Operator password.
        note: Optional note for this operator.
    """
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)

    body: dict[str, Any] = {
        "name": name,
        "x_password": password,
        **extra,
    }
    if note:
        body["note"] = note

    data = await client.post(_classic_rest(host_id, site_slug, "/hotspotop"), json=body)
    return cast(dict[str, Any], data.get("data", data))


async def _update_hotspot_operator(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    operator_id: str,
    **fields: Any,
) -> dict[str, Any]:
    """Update a hotspot operator by ID via Classic REST (/rest/hotspotop/{id})."""
    validate_id(operator_id, "operator_id")
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    data = await client.put(
        _classic_rest(host_id, site_slug, f"/hotspotop/{operator_id}"), json=fields
    )
    return cast(dict[str, Any], data.get("data", data))


async def _delete_hotspot_operator(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    operator_id: str,
) -> dict[str, Any]:
    """Delete a hotspot operator by ID via Classic REST (/rest/hotspotop/{id})."""
    validate_id(operator_id, "operator_id")
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    await client.delete(_classic_rest(host_id, site_slug, f"/hotspotop/{operator_id}"))
    return {"deleted": True, "operatorId": operator_id}


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register all hotspot MCP tools."""

    @mcp.tool()
    async def list_hotspot_operators(
        host: str,
        site: str,
    ) -> dict[str, Any]:
        """List hotspot operator accounts for captive portal management.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        """
        client, registry = deps_fn()
        return await _list_hotspot_operators(client, registry, host, site)

    @mcp.tool()
    async def create_hotspot_operator(
        host: str,
        site: str,
        name: str,
        password: str,
        note: str | None = None,
    ) -> dict[str, Any]:
        """Create a hotspot operator account.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        name: operator username. password: operator password.
        """
        client, registry = deps_fn()
        return await _create_hotspot_operator(
            client,
            registry,
            host,
            site,
            name,
            password,
            note=note,
        )

    @mcp.tool()
    async def update_hotspot_operator(
        host: str,
        site: str,
        operator_id: str,
        fields: dict[str, Any],
    ) -> dict[str, Any]:
        """Update a hotspot operator by ID.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        operator_id: hotspot operator ID.
        fields: fields to update (name, x_password, note, etc.).
        """
        client, registry = deps_fn()
        return await _update_hotspot_operator(client, registry, host, site, operator_id, **fields)

    @mcp.tool()
    async def delete_hotspot_operator(
        host: str,
        site: str,
        operator_id: str,
    ) -> str:
        """Delete a hotspot operator by ID.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        operator_id: hotspot operator ID.
        """
        client, registry = deps_fn()
        await _delete_hotspot_operator(client, registry, host, site, operator_id)
        return f"Hotspot operator {operator_id} deleted."
