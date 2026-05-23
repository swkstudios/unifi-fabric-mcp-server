"""Network tools — Networks/VLANs, WiFi broadcasts, and WAN interfaces via connector proxy."""

from __future__ import annotations

from typing import Any

from ..client import UniFiClient, validate_id
from ..registry import Registry, _assert_uuid

PROXY_BASE = "/v1/connector/consoles/{host_id}/proxy/network/integration/v1"


def _proxy(host_id: str, path: str) -> str:
    return PROXY_BASE.format(host_id=host_id) + path


# --- Networks / VLANs ---


async def list_networks(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
) -> dict[str, Any]:
    """List all networks/VLANs for a site."""
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    data = await client.get(_proxy(host_id, f"/sites/{site_id}/networks"))
    return data


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
    """Update an existing network/VLAN."""
    validate_id(network_id, "network_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.put(
        _proxy(host_id, f"/sites/{site_id}/networks/{network_id}"), json=network
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
