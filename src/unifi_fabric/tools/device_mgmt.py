"""Device management tools — adopted devices, actions, stats, and pending devices."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from fastmcp import FastMCP

from ..client import UniFiClient, validate_id
from ..config import APIKeyConfig
from ..registry import Registry, _assert_uuid
from ._pagination import collect_offset, mark_incomplete
from .network import _proxy

# Matches a bare 12-hex-char MAC (e.g. AABBCCDDEEFF) or colon/hyphen-separated MAC
_MAC_BARE_RE = re.compile(r"^[0-9a-fA-F]{12}$")
_MAC_SEP_RE = re.compile(
    r"^[0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}"
    r"[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}$"
)

# Session-scoped cache: "{site_id}:{normalized_mac}" -> UUID
_mac_uuid_cache: dict[str, str] = {}


def _is_mac(value: str) -> bool:
    """Return True if value looks like a MAC address."""
    return bool(_MAC_BARE_RE.match(value) or _MAC_SEP_RE.match(value))


def _normalize_mac(mac: str) -> str:
    """Normalize a MAC address to lowercase 12-hex string (no separators)."""
    return re.sub(r"[:\-\.]", "", mac).lower()


async def _resolve_device_id(
    client: UniFiClient,
    host_id: str,
    site_id: str,
    device_id: str,
    *,
    key: APIKeyConfig | None = None,
) -> str:
    """Resolve a device_id to a UUID, performing MAC lookup if needed.

    If device_id is a MAC address (bare 12-hex or colon/hyphen-separated),
    fetch the site device list and return the matching device UUID.
    Results are cached per (site_id, mac) for the session lifetime.
    """
    if not _is_mac(device_id):
        return device_id

    normalized = _normalize_mac(device_id)
    cache_key = f"{site_id}:{normalized}"
    if cache_key in _mac_uuid_cache:
        return _mac_uuid_cache[cache_key]

    devices_resp = await client.get(_proxy(host_id, f"/sites/{site_id}/devices"), key=key)
    devices: list[dict[str, Any]] = (
        devices_resp if isinstance(devices_resp, list) else devices_resp.get("data", [])
    )
    for d in devices:
        d_mac = _normalize_mac(d.get("macAddress") or d.get("mac", ""))
        if d_mac == normalized:
            uuid = d.get("id") or d.get("_id", "")
            if uuid:
                _mac_uuid_cache[cache_key] = uuid
                return uuid

    raise ValueError(f"Device with MAC {device_id!r} not found in site {site_id!r}")


# --- Adopted Devices ---


async def _list_site_devices(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
    *,
    filter: str | None = None,
) -> dict[str, Any]:
    """List all adopted devices for a site.

    By default every offset page is drained and the complete device list is
    returned as ``{data, totalCount}``. Passing offset or limit selects manual
    paging: a single page is returned with the API's totalCount. A drain that
    hits the page cap returns the devices gathered so far with incomplete=true
    rather than truncating silently. ``filter`` is a server-side filter (not
    paging), forwarded unchanged as the Network Integration API ``filter`` query
    parameter and applied in either mode; when ``None`` it is omitted rather than
    sent as the string ``"None"``.
    """
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    url = _proxy(host_id, f"/sites/{site_id}/devices")
    base: dict[str, Any] = {}
    if filter is not None:
        base["filter"] = filter
    collected = await collect_offset(
        client, url, key=key, params=base or None, offset=offset, limit=limit
    )
    total = collected["totalCount"]
    result: dict[str, Any] = {
        "data": collected["items"],
        "totalCount": total if total is not None else len(collected["items"]),
    }
    return mark_incomplete(result, collected)


async def _adopt_device(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device: dict[str, Any],
) -> dict[str, Any]:
    """Adopt a device onto a site."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.post(_proxy(host_id, f"/sites/{site_id}/devices"), key=key, json=device)


async def _get_device(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device_id: str,
) -> dict[str, Any]:
    """Get details for a single adopted device."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    device_id = await _resolve_device_id(client, host_id, site_id, device_id, key=key)
    validate_id(device_id, "device_id")
    return await client.get(_proxy(host_id, f"/sites/{site_id}/devices/{device_id}"), key=key)


async def _unadopt_device(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device_id: str,
) -> None:
    """Unadopt (remove) a device from a site."""
    validate_id(device_id, "device_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    await client.delete(_proxy(host_id, f"/sites/{site_id}/devices/{device_id}"), key=key)


async def _execute_device_action(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device_id: str,
    action: dict[str, Any],
) -> dict[str, Any]:
    """Execute a device action (restart, upgrade, locate, etc.)."""
    validate_id(device_id, "device_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.post(
        _proxy(host_id, f"/sites/{site_id}/devices/{device_id}/actions"), key=key, json=action
    )


async def _get_device_statistics(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device_id: str,
) -> dict[str, Any]:
    """Get latest statistics for a device."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    device_id = await _resolve_device_id(client, host_id, site_id, device_id, key=key)
    validate_id(device_id, "device_id")
    return await client.get(
        _proxy(host_id, f"/sites/{site_id}/devices/{device_id}/statistics/latest"), key=key
    )


async def _execute_port_action(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device_id: str,
    port_idx: int,
    action: dict[str, Any],
) -> dict[str, Any]:
    """Execute a port action on a device interface."""
    validate_id(device_id, "device_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.post(
        _proxy(
            host_id,
            f"/sites/{site_id}/devices/{device_id}/interfaces/ports/{port_idx}/actions",
        ),
        key=key,
        json=action,
    )


# --- Pending Devices ---


async def _restart_device(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device_id: str,
) -> dict[str, Any]:
    """Restart an adopted device."""
    return await _execute_device_action(
        client, registry, host, site, device_id, {"action": "restart"}
    )


async def _locate_device(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device_id: str,
    enabled: bool = True,
) -> dict[str, Any]:
    """Toggle the locate LED on an adopted device."""
    return await _execute_device_action(
        client, registry, host, site, device_id, {"action": "locate", "enabled": enabled}
    )


async def _upgrade_device(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device_id: str,
) -> dict[str, Any]:
    """Trigger a firmware upgrade on an adopted device."""
    return await _execute_device_action(
        client, registry, host, site, device_id, {"action": "upgrade"}
    )


async def _list_pending_devices(
    client: UniFiClient,
    registry: Registry,
    host: str,
) -> dict[str, Any]:
    """List devices pending adoption on a console."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    return await client.get(_proxy(host_id, "/pending-devices"), key=key)


# --- Device Tags ---


async def _create_device_tag(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    tag: dict[str, Any],
) -> dict[str, Any]:
    """Create a device tag on a site."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.post(_proxy(host_id, f"/sites/{site_id}/device-tags"), key=key, json=tag)


async def _update_device_tag(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    tag_id: str,
    tag: dict[str, Any],
) -> dict[str, Any]:
    """Update a device tag by ID."""
    validate_id(tag_id, "tag_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.put(
        _proxy(host_id, f"/sites/{site_id}/device-tags/{tag_id}"), key=key, json=tag
    )


async def _delete_device_tag(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    tag_id: str,
) -> dict[str, Any]:
    """Delete a device tag by ID."""
    validate_id(tag_id, "tag_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    await client.delete(_proxy(host_id, f"/sites/{site_id}/device-tags/{tag_id}"), key=key)
    return {"deleted": True, "tagId": tag_id}


# --- Pending Device Actions ---


async def _approve_pending_device(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device_id: str,
) -> dict[str, Any]:
    """Approve a pending device for adoption onto a site."""
    validate_id(device_id, "device_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.post(
        _proxy(host_id, f"/sites/{site_id}/devices/{device_id}/actions"),
        key=key,
        json={"action": "approve"},
    )


async def _reject_pending_device(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device_id: str,
) -> dict[str, Any]:
    """Reject a pending device, preventing it from joining the site."""
    validate_id(device_id, "device_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.post(
        _proxy(host_id, f"/sites/{site_id}/devices/{device_id}/actions"),
        key=key,
        json={"action": "reject"},
    )


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register all device management MCP tools."""

    @mcp.tool()
    async def list_site_devices(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List all adopted devices for a site via connector proxy.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        By default every page is drained and the complete device list is returned.
        offset/limit: fetch a single page manually (the API's totalCount is
        surfaced so you can advance). filter: optional Network Integration API
        filter expression, forwarded unchanged as the upstream `filter` query
        parameter for server-side filtering (e.g. `state.eq('ONLINE')`,
        `model.eq('U6 Pro')`); omitted entirely when unset. A capped drain returns
        the devices gathered so far with incomplete=true rather than truncating
        silently.
        """
        client, registry = deps_fn()
        return await _list_site_devices(
            client, registry, host, site, offset=offset, limit=limit, filter=filter
        )

    @mcp.tool()
    async def adopt_device(
        host: str,
        site: str,
        device: dict[str, Any],
    ) -> dict[str, Any]:
        """Adopt a device onto a site.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        device: device adoption payload (mac, name, etc.).

        Example:
        adopt_device(host="main-office", site="HQ", device={"mac": "aa:bb:cc:dd:ee:ff"})
        """
        client, registry = deps_fn()
        return await _adopt_device(client, registry, host, site, device)

    @mcp.tool()
    async def get_device(
        host: str,
        site: str,
        device_id: str,
    ) -> dict[str, Any]:
        """Get details for a single adopted device.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        device_id: device UUID or MAC address (accepted formats: AA:BB:CC:DD:EE:FF,
        AABBCCDDEEFF, aa-bb-cc-dd-ee-ff).
        """
        client, registry = deps_fn()
        return await _get_device(client, registry, host, site, device_id)

    @mcp.tool()
    async def unadopt_device(
        host: str,
        site: str,
        device_id: str,
    ) -> str:
        """Unadopt (remove) a device from a site.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        device_id: unique identifier of the device to remove.

        Example:
        unadopt_device(host="main-office", site="HQ", device_id="device-uuid-here")
        """
        client, registry = deps_fn()
        await _unadopt_device(client, registry, host, site, device_id)
        return f"Device {device_id} unadopted."

    @mcp.tool()
    async def execute_device_action(
        host: str,
        site: str,
        device_id: str,
        action: dict[str, Any],
    ) -> dict[str, Any]:
        """Execute a device action (restart, upgrade, locate, etc.).

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        action: must include: {'action': str}. Common commands: {'action': 'restart'},
          {'action': 'adopt'}, {'action': 'force-provision'}. Valid commands vary by device type.
        device_id: REQUIRED. Obtain it from `list_devices` (its id field).
        """
        client, registry = deps_fn()
        return await _execute_device_action(client, registry, host, site, device_id, action)

    @mcp.tool()
    async def get_device_statistics(
        host: str,
        site: str,
        device_id: str,
    ) -> dict[str, Any]:
        """Get latest statistics for a device.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        device_id: device UUID or MAC address (accepted formats: AA:BB:CC:DD:EE:FF,
        AABBCCDDEEFF, aa-bb-cc-dd-ee-ff).
        """
        client, registry = deps_fn()
        return await _get_device_statistics(client, registry, host, site, device_id)

    @mcp.tool()
    async def execute_port_action(
        host: str,
        site: str,
        device_id: str,
        port_idx: int,
        action: dict[str, Any],
    ) -> dict[str, Any]:
        """Execute a port action on a device interface.

        OPERATIONAL-ACTION-ONLY, NOT A CONFIG WRITER: this Integration port-actions
        endpoint performs a transient operational action; it does NOT persist port
        configuration. A PoE power cycle ({'action': 'power-cycle'}, canonical id
        POWER_CYCLE) is the only valid action -- it powers a PoE port off and back on
        (only meaningful on PoE-capable ports). Config-style actions such as
        {'action': 'set-poe-mode', ...} are rejected by the controller with HTTP 400
        'unknown-type-id' and leave the port unchanged (verified live). Do NOT use this
        to set PoE mode, STP, VLAN, or any persistent port setting -- there is no
        confirmed per-port persistent-config writer on this API; a shared Ethernet Port
        Profile (update_port_profile) is a different, wide-blast-radius surface.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        port_idx: port index number (1-based, matching the switch's physical port numbering).
        action: the port-action payload, shape {'action': str}, forwarded verbatim to the
          UniFi Network Integration API port-actions endpoint. 'power-cycle' (POWER_CYCLE)
          is the one valid, documented action; other values return HTTP 400
          'unknown-type-id' from the controller.
        device_id: REQUIRED. Obtain it from `list_devices` (its id field).
        """
        client, registry = deps_fn()
        return await _execute_port_action(client, registry, host, site, device_id, port_idx, action)

    @mcp.tool()
    async def restart_device(
        host: str,
        site: str,
        device_id: str,
    ) -> dict[str, Any]:
        """Restart an adopted device.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        device_id: REQUIRED. Obtain it from `list_devices` (its id field).
        """
        client, registry = deps_fn()
        return await _restart_device(client, registry, host, site, device_id)

    @mcp.tool()
    async def locate_device(
        host: str,
        site: str,
        device_id: str,
        enabled: bool = True,
    ) -> dict[str, Any]:
        """Toggle the locate LED on an adopted device.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        enabled: True to enable locate LED, False to disable.
        device_id: REQUIRED. Obtain it from `list_devices` (its id field).
        """
        client, registry = deps_fn()
        return await _locate_device(client, registry, host, site, device_id, enabled)

    @mcp.tool()
    async def upgrade_device(
        host: str,
        site: str,
        device_id: str,
    ) -> dict[str, Any]:
        """Trigger a firmware upgrade on an adopted device.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        device_id: REQUIRED. Obtain it from `list_devices` (its id field).
        """
        client, registry = deps_fn()
        return await _upgrade_device(client, registry, host, site, device_id)

    @mcp.tool()
    async def list_pending_devices(
        host: str,
    ) -> dict[str, Any]:
        """List devices pending adoption on a console.

        host: console name, ID, or composite ID (MAC:numericId format).
        """
        client, registry = deps_fn()
        return await _list_pending_devices(client, registry, host)

    @mcp.tool()
    async def create_device_tag(
        host: str,
        site: str,
        tag: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a device tag on a site. This is a write operation that modifies live config.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        tag: required fields:
          - name (str): tag label shown in the UI
          Optional: color (str, hex color e.g. '#FF5733').
        Tags can then be assigned to devices to group and filter them in the UniFi UI.
        """
        client, registry = deps_fn()
        return await _create_device_tag(client, registry, host, site, tag)

    @mcp.tool()
    async def update_device_tag(
        host: str,
        site: str,
        tag_id: str,
        tag: dict[str, Any],
    ) -> dict[str, Any]:
        """Update a device tag by ID.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        tag_id: device tag ID to update.
        tag: fields to update (name, color, etc.).
        """
        client, registry = deps_fn()
        return await _update_device_tag(client, registry, host, site, tag_id, tag)

    @mcp.tool()
    async def delete_device_tag(
        host: str,
        site: str,
        tag_id: str,
    ) -> dict[str, Any]:
        """Delete a device tag by ID. This permanently removes the tag from the site.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        tag_id: device tag ID to delete.
        """
        client, registry = deps_fn()
        return await _delete_device_tag(client, registry, host, site, tag_id)

    @mcp.tool()
    async def approve_pending_device(
        host: str,
        site: str,
        device_id: str,
    ) -> dict[str, Any]:
        """Approve a pending device for adoption onto a site.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        device_id: device ID from list_pending_devices to approve.
        """
        client, registry = deps_fn()
        return await _approve_pending_device(client, registry, host, site, device_id)

    @mcp.tool()
    async def reject_pending_device(
        host: str,
        site: str,
        device_id: str,
    ) -> dict[str, Any]:
        """Reject a pending device, preventing it from joining the site.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        device_id: device ID from list_pending_devices to reject.
        """
        client, registry = deps_fn()
        return await _reject_pending_device(client, registry, host, site, device_id)
