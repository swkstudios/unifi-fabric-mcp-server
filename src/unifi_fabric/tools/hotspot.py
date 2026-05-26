"""Hotspot operator and voucher tools — manage captive portal access."""

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
    """Create a hotspot operator account.

    Args:
        host: Host name or ID.
        site: Site name or ID.
        name: Operator username.
        password: Operator password.
        note: Optional note for this operator.
    """
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)

    body: dict[str, Any] = {
        "hostId": host_id,
        "siteId": site_id,
        "name": name,
        "password": password,
        **extra,
    }
    if note:
        body["note"] = note

    data = await client.post("/ea/hotspot-operators", json=body)
    return cast(dict[str, Any], data.get("data", data))


async def _update_hotspot_operator(
    client: UniFiClient,
    operator_id: str,
    **fields: Any,
) -> dict[str, Any]:
    """Update a hotspot operator by ID."""
    validate_id(operator_id, "operator_id")
    data = await client.patch(f"/ea/hotspot-operators/{operator_id}", json=fields)
    return cast(dict[str, Any], data.get("data", data))


async def _delete_hotspot_operator(
    client: UniFiClient,
    operator_id: str,
) -> dict[str, Any]:
    """Delete a hotspot operator by ID."""
    validate_id(operator_id, "operator_id")
    await client.delete(f"/ea/hotspot-operators/{operator_id}")
    return {"deleted": True, "operatorId": operator_id}


# ---------------------------------------------------------------------------
# Vouchers
# ---------------------------------------------------------------------------


async def _list_vouchers(
    client: UniFiClient,
    registry: Registry,
    *,
    host: str | None = None,
    site: str | None = None,
    page_token: str | None = None,
) -> dict[str, Any]:
    """List hotspot vouchers with usage status and expiry."""
    params: dict[str, Any] = {}
    host_id: str | None = None
    if host:
        host_id = await registry.resolve_host_id(host)
        params["hostId"] = host_id
    if site and host_id is not None:
        params["siteId"] = await registry.resolve_site_id(site, host_id)
    elif site:
        params["siteId"] = site
    if page_token:
        params["nextToken"] = page_token

    data = await client.get("/ea/vouchers", params=params or None)
    items = data.get("data", [])
    result: dict[str, Any] = {"vouchers": items, "count": len(items)}
    if data.get("nextToken"):
        result["nextToken"] = data["nextToken"]
    return result


async def _create_vouchers(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    *,
    count: int = 1,
    duration_minutes: int = 60,
    quota_mb: int | None = None,
    up_bandwidth_kbps: int | None = None,
    down_bandwidth_kbps: int | None = None,
    note: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Generate one or more hotspot vouchers.

    Args:
        host: Host name or ID.
        site: Site name or ID.
        count: Number of vouchers to generate (default 1).
        duration_minutes: Access duration in minutes (default 60).
        quota_mb: Data quota in MB. None for unlimited.
        up_bandwidth_kbps: Upload speed limit in Kbps. None for unlimited.
        down_bandwidth_kbps: Download speed limit in Kbps. None for unlimited.
        note: Optional note for these vouchers.
    """
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)

    body: dict[str, Any] = {
        "hostId": host_id,
        "siteId": site_id,
        "count": count,
        "durationMinutes": duration_minutes,
        **extra,
    }
    if quota_mb is not None:
        body["quotaMb"] = quota_mb
    if up_bandwidth_kbps is not None:
        body["upBandwidthKbps"] = up_bandwidth_kbps
    if down_bandwidth_kbps is not None:
        body["downBandwidthKbps"] = down_bandwidth_kbps
    if note:
        body["note"] = note

    data = await client.post("/ea/vouchers", json=body)
    return cast(dict[str, Any], data.get("data", data))


async def _delete_voucher(
    client: UniFiClient,
    voucher_id: str,
) -> dict[str, Any]:
    """Delete (revoke) a voucher by ID."""
    validate_id(voucher_id, "voucher_id")
    await client.delete(f"/ea/vouchers/{voucher_id}")
    return {"deleted": True, "voucherId": voucher_id}


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
        operator_id: str,
        fields: dict[str, Any],
    ) -> dict[str, Any]:
        """Update a hotspot operator by ID.

        operator_id: hotspot operator ID.
        fields: fields to update (name, password, note, etc.).
        """
        client, _ = deps_fn()
        return await _update_hotspot_operator(client, operator_id, **fields)

    @mcp.tool()
    async def delete_hotspot_operator(
        operator_id: str,
    ) -> str:
        """Delete a hotspot operator by ID."""
        client, _ = deps_fn()
        await _delete_hotspot_operator(client, operator_id)
        return f"Hotspot operator {operator_id} deleted."
