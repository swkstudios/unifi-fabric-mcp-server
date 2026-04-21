"""UniFi Fabric MCP Server — FastMCP server exposing UniFi Site Manager API tools."""

from __future__ import annotations

import os

# Suppress pydantic version URLs in validation error messages (information disclosure).
os.environ.setdefault("PYDANTIC_ERRORS_INCLUDE_URL", "0")

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastmcp import FastMCP

from .client import UniFiClient
from .config import Settings
from .registry import Registry
from .tools import (
    aggregation,
    clients,
    device_mgmt,
    firewall_proxy,
    hotspot,
    network,
    network_services_proxy,
    protect,
    site_manager,
    statistics,
    vpn,
)

settings = Settings()
_client: UniFiClient | None = None
_registry: Registry | None = None


@asynccontextmanager
async def lifespan(app: FastMCP) -> AsyncIterator[None]:
    global _client, _registry
    if not settings.get_key_configs():
        raise RuntimeError(
            "No API key configured. Set UNIFI_API_KEY or UNIFI_API_KEYS before starting the server."
        )
    _client = UniFiClient(settings)
    _registry = Registry(
        _client,
        ttl_seconds=settings.cache_ttl_seconds,
        cache_max_hosts=settings.cache_max_hosts,
        cache_max_sites=settings.cache_max_sites,
    )
    try:
        yield
    finally:
        await _client.close()
        _client = None
        _registry = None


INSTRUCTIONS = """
UniFi Fabric MCP Server — manages UniFi network infrastructure via the Ubiquiti
Site Manager (Fabric) API.

## Key Concepts
- **Host**: A UniFi console/gateway (UDM Pro, UDR, UCG, etc.). Each host runs one or
  more applications (Network, Protect, Access).
- **Site**: A logical network partition within a host. Most single-console setups have
  one site called "Default".
- Both `host` and `site` parameters accept human-readable names OR IDs. Prefer names.
- **Device** (in UniFi terminology): network infrastructure hardware — APs, switches,
  gateways, cameras, sensors. Managed via `list_site_devices`, `get_device`, etc.
- **Client**: an end-user device connected to the network (laptop, phone, IoT device).
  Managed via `list_clients`, `get_client`, `block_client`, etc. Do not confuse devices
  (infrastructure) with clients (end-users).

## Getting Started
1. Call `list_hosts` to discover available consoles. Note the host name (e.g., "MyConsole").
2. Call `list_sites` to discover sites. Note the site name (e.g., "Default").
3. Pass these names to any per-host tool: `list_networks(host="MyConsole", site="Default")`.

## Firewall Rule Hierarchy
UniFi has three distinct firewall systems — use the right one for your use case:
1. **Zone-based Firewall Policies** (`list/create/update_firewall_policy`): the modern,
   recommended approach. Rules are scoped between firewall zones (LAN, WAN, Guest, etc.).
   Use `list_firewall_zones_proxy` to discover zones and their IDs first.
2. **ACL Rules** (`list/create/update_acl_rule`): network-layer access control lists,
   typically used for intra-VLAN traffic filtering between networks.
3. **Classic Firewall Rules** (`list_firewall_rules`, `get_firewall_rule`): legacy
   iptables-style rules. Read-only in this server; prefer zone-based policies for new rules.

When asked to "add a firewall rule", default to zone-based firewall policies unless the
user specifically asks for ACL rules or classic rules.

## Tool Organization
- **Network**: networks/VLANs, WiFi broadcasts, WAN interfaces
- **Port Forwarding**: `list_port_forwards`, `create_port_forward`,
  `update_port_forward`, `delete_port_forward`
- **Firewall**: policies, zones, ACL rules, ordering
- **DNS & Traffic**: DNS policies, traffic rules, traffic matching lists, traffic routes
- **Traffic Routes**: `list_traffic_routes`, `create_traffic_route`,
  `update_traffic_route`, `delete_traffic_route`
- **Traffic Rules**: `list_traffic_rules`, `create_traffic_rule`,
  `update_traffic_rule`, `delete_traffic_rule`
- **Traffic Matching Lists**: `list_traffic_matching_lists`,
  `create_traffic_matching_list`, `update_traffic_matching_list`,
  `delete_traffic_matching_list`
- **Dynamic DNS**: `list_dynamic_dns`, `get_dynamic_dns`, `update_dynamic_dns`
- **Settings**: `list_settings`, `get_setting`, `update_setting`
- **WLAN**: `list_wlan_configs`, `get_wlan_config`, `update_wlan_config`,
  `list_wlan_groups`, `get_wlan_group`
- **Clients & Devices**: list/search connected clients, device stats,
  adoption, block/unblock clients
- **Device Stats**: `list_device_stats`, `list_active_clients_stats`, `get_device_statistics`,
  `get_site_statistics`, `get_system_info`
- **Device Management**: adopt, unadopt, restart, upgrade, locate, execute actions
- **Protect**: cameras, chimes, lights, sensors, viewers, liveviews, NVR, snapshots, PTZ control
- **VPN**: VPN servers (full CRUD), site-to-site tunnels (full CRUD),
  RADIUS profiles (list read-only via proxy; CRUD via dedicated tools)
- **Hotspot**: voucher management, operators
- **ISP Metrics**: WAN health metrics (use interval='5m' or '1h')
- **Fleet**: cross-host device search, fleet summary, site comparison

## Parameter Scope Quick Reference
- **host + site required**: network, firewall, DNS, traffic routes, traffic rules,
  traffic matching lists, port forwarding, WLAN, dynamic DNS, settings, device,
  client, VPN server, RADIUS profile, hotspot operator tools,
  `list_device_stats`, `list_active_clients_stats`, `get_device_statistics`,
  `get_site_statistics`, `get_system_info`, `create_radius_profile`
- **host only** (no site): `list_pending_devices`, `list_devices`,
  `list_cameras`, `get_camera`, `get_camera_snapshot`, `update_camera`, `ptz_goto_preset`,
  `ptz_patrol_start`, `ptz_patrol_stop`, `list_sensors`, `get_sensor`, `update_sensor`,
  `list_lights`, `get_light`, `update_light`, `list_chimes`, `get_chime`, `update_chime`,
  `list_viewers`, `get_viewer`, `update_viewer`, `list_liveviews`, `get_liveview`,
  `create_liveview`, `update_liveview`, `get_nvr`, `list_protect_files`, `upload_protect_file`,
  `trigger_alarm_webhook`, `start_talkback_session`, `disable_camera_mic_permanently`,
  `list_countries`
- **no host/site** (global EA API): fleet/aggregation tools
- **ID only** (no host/site): `update_vpn_server`, `delete_vpn_server`,
  `update_radius_profile`, `delete_radius_profile`, `update_hotspot_operator`,
  `delete_hotspot_operator`

## Common Workflows

**Create a new VLAN with firewall isolation:**
1. `list_firewall_zones_proxy` → get zone IDs
2. `create_network` → create VLAN with desired zoneId
3. `create_firewall_policy` → allow/deny traffic between zones

**Set up guest WiFi:**
1. `create_network` → create guest VLAN (set isolationEnabled=true)
2. `create_wifi_broadcast` → create SSID with security settings, reference the VLAN

**Block a client:**
1. `list_clients` → find the client MAC
2. `block_client` → block by client ID

**Check WAN health:**
1. `get_isp_metrics(interval='5m')` for recent metrics
2. `list_wan_interfaces` for current WAN config

## Important Notes
- **Read-only tools** are safe to call freely. Write tools (create/update/delete) modify
  live infrastructure.
- **Irreversible operations** — confirm with the user before calling these:
  - `delete_network`: removes the VLAN and disconnects all clients on it
  - `unadopt_device`: factory-resets the device's association; requires re-adoption
  - `disable_camera_mic_permanently`: hardware-level mic disable, cannot be re-enabled
  - `trigger_alarm_webhook`: triggers physical alarm hardware; real-world consequences
  - `delete_*` tools in general: no undo, no recycle bin
- Many list tools support `page_token` for cursor pagination on large result sets.
- ISP metrics `interval` accepts '5m' (5-minute buckets) or '1h' (1-hour buckets) only.
- The server resolves host/site names internally — you do not need to look up IDs manually.
- **Security defaults for `create_network`**: new networks default to
  `internetAccessEnabled=true`, `isolationEnabled=false`. Set `isolationEnabled=true` for
  guest/IoT VLANs to prevent lateral movement between clients.
"""

mcp = FastMCP("UniFi Fabric", instructions=INSTRUCTIONS, lifespan=lifespan)


def _require() -> tuple[UniFiClient, Registry]:
    if _client is None or _registry is None:
        raise RuntimeError("Server not initialized")
    return _client, _registry


# --- Site Manager Tools ---


@mcp.tool()
async def list_hosts(
    include_gps: bool = False,
    page_token: str | None = None,
) -> dict[str, Any]:
    """List all UniFi consoles (hosts) with firmware, WAN IP, and status.

    GPS coordinates are hidden by default for privacy. Set include_gps=True to include them.
    Supports cursor pagination via page_token.
    """
    client, registry = _require()
    return await site_manager.list_hosts(
        client, registry, include_gps=include_gps, page_token=page_token
    )


@mcp.tool()
async def get_host(
    host: str,
    include_gps: bool = False,
) -> dict[str, Any]:
    """Get details for a single UniFi console by name or ID.

    host: console name, ID, or composite ID (MAC:numericId format for cloud consoles).
    GPS coordinates are hidden by default. Set include_gps=True to include them.
    """
    client, registry = _require()
    return await site_manager.get_host(client, registry, host, include_gps=include_gps)


@mcp.tool()
async def list_sites(
    page_token: str | None = None,
) -> dict[str, Any]:
    """List all sites with device/client counts and ISP info.

    Supports cursor pagination via page_token.
    """
    client, registry = _require()
    return await site_manager.list_sites(client, registry, page_token=page_token)


@mcp.tool()
async def list_devices(
    host: str | None = None,
    page_token: str | None = None,
) -> dict[str, Any]:
    """List all devices across the fleet with status, firmware, and model.

    host: optional filter by console name, ID, or composite ID (MAC:numericId format).
    Supports cursor pagination via page_token.
    """
    client, registry = _require()
    return await site_manager.list_devices(client, registry, host=host, page_token=page_token)


@mcp.tool()
async def get_isp_metrics(
    interval: str,
) -> dict[str, Any]:
    """Get WAN health metrics (speed, latency, packet loss, uptime).

    interval: time bucket for metrics aggregation — '5m' or '1h'.
    Returns a dict with a 'periods' list containing WAN speed, latency, packet loss, and uptime.
    """
    client, _ = _require()
    return await site_manager.get_isp_metrics(client, interval)


@mcp.tool()
async def query_isp_metrics(
    interval: str,
    host: str | None = None,
    site: str | None = None,
    sites: list[dict] | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
) -> dict[str, Any]:
    """Query filtered ISP metrics with optional site/time range filters.

    interval: time bucket for metrics aggregation — '5m' or '1h'.
    host: console name, ID, or composite ID (MAC:numericId format) — resolves to hostId.
    site: site name or ID — resolves to siteId automatically.
    sites: advanced use — list of raw {hostId, siteId} dicts; use host/site params instead for
      human-readable names.
    start_time/end_time: ISO 8601 timestamps for time range.
    """
    client, registry = _require()
    resolved_sites = list(sites) if sites else []
    if host and site:
        host_id = await registry.resolve_host_id(host)
        site_id = await registry.resolve_site_id(site, host_id)
        resolved_sites.append({"hostId": host_id, "siteId": site_id})
    return await site_manager.query_isp_metrics(
        client,
        interval,
        sites=resolved_sites or None,
        start_time=start_time,
        end_time=end_time,
    )


@mcp.tool()
async def list_sdwan_configs(
    page_token: str | None = None,
) -> dict[str, Any]:
    """List Site Magic (SD-WAN) VPN mesh configurations.

    Supports cursor pagination via page_token.
    """
    client, _ = _require()
    return await site_manager.list_sdwan_configs(client, page_token=page_token)


@mcp.tool()
async def get_sdwan_config(
    config_id: str,
) -> dict[str, Any]:
    """Get a single SD-WAN configuration by ID."""
    client, _ = _require()
    return await site_manager.get_sdwan_config(client, config_id)


@mcp.tool()
async def get_sdwan_config_status(
    config_id: str,
) -> dict[str, Any]:
    """Get the status of an SD-WAN configuration by ID."""
    client, _ = _require()
    return await site_manager.get_sdwan_config_status(client, config_id)


@mcp.tool()
async def list_all_sites_aggregated() -> dict[str, Any]:
    """List all sites with aggregated health stats from the /v1/sites/ API.

    Returns sites merged with health summary: device counts, client counts,
    alerts, and connectivity status in a single call.
    """
    client, registry = _require()
    return await site_manager.list_all_sites_aggregated(client, registry)


@mcp.tool()
async def get_site_health_summary(
    site: str,
) -> dict[str, Any]:
    """Get health summary for a single site: uptime, alerts, and device counts.

    site: site name or ID.
    """
    client, registry = _require()
    return await site_manager.get_site_health_summary(client, registry, site)


@mcp.tool()
async def compare_site_performance(
    sites: list[str],
) -> dict[str, Any]:
    """Compare health and performance metrics across multiple sites side-by-side.

    sites: list of site names or IDs to compare.
    """
    client, registry = _require()
    return await site_manager.compare_site_performance(client, registry, sites)


@mcp.tool()
async def search_across_sites(
    query: str,
) -> dict[str, Any]:
    """Search for devices or clients matching a query across all sites.

    query: search term matched against name, MAC address, IP, or model.
    """
    client, registry = _require()
    return await site_manager.search_across_sites(client, registry, query)


@mcp.tool()
async def get_site_inventory(
    site: str,
) -> dict[str, Any]:
    """Get full inventory for a site: all devices and connected clients.

    site: site name or ID.
    """
    client, registry = _require()
    return await site_manager.get_site_inventory(client, registry, site)


# --- Network Tools ---


@mcp.tool()
async def list_networks(
    host: str,
    site: str,
) -> dict[str, Any]:
    """List all networks/VLANs for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network.list_networks(client, registry, host, site)


@mcp.tool()
async def create_network(
    host: str,
    site: str,
    network_config: dict[str, Any],
) -> dict[str, Any]:
    """Create a new network/VLAN on a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    network_config: required fields:
      - name (str, max 32 chars)
      - management: 'GATEWAY' (required)
      - vlanId (int, 1-4094)
      - zoneId (str, zone UUID — get from list_firewall_zones_proxy)
      - enabled (bool)
      - internetAccessEnabled (bool)
      - isolationEnabled (bool)
      - cellularBackupEnabled (bool)
      - mdnsForwardingEnabled (bool)
      - ipv4Configuration: {'dhcpMode': 'SERVER'|'RELAY'|'NONE', 'subnet': str CIDR,
          'hostAddress': str, 'netmask': str, 'broadcastAddress': str,
          'dhcpRangeStart': str, 'dhcpRangeStop': str}
      Field names are camelCase; there is no 'purpose' field in the Network Integration API.
    """
    client, registry = _require()
    return await network.create_network(client, registry, host, site, network_config)


@mcp.tool()
async def get_network(
    host: str,
    site: str,
    network_id: str,
) -> dict[str, Any]:
    """Get a single network/VLAN by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network.get_network(client, registry, host, site, network_id)


@mcp.tool()
async def update_network(
    host: str,
    site: str,
    network_id: str,
    network_config: dict[str, Any],
) -> dict[str, Any]:
    """Update an existing network/VLAN.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    network_config: full network configuration to replace with.
    """
    client, registry = _require()
    return await network.update_network(client, registry, host, site, network_id, network_config)


@mcp.tool()
async def delete_network(
    host: str,
    site: str,
    network_id: str,
) -> str:
    """Delete a network/VLAN.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    await network.delete_network(client, registry, host, site, network_id)
    return f"Network {network_id} deleted."


@mcp.tool()
async def get_network_references(
    host: str,
    site: str,
    network_id: str,
) -> dict[str, Any]:
    """Get all resources referencing a network — useful before deleting to check dependencies.

    Returns WiFi broadcasts, firewall policies, and port profiles that use this network.
    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    network_id: network UUID from list_networks.
    """
    client, registry = _require()
    return await network.get_network_references(client, registry, host, site, network_id)


@mcp.tool()
async def list_wifi_broadcasts(
    host: str,
    site: str,
) -> dict[str, Any]:
    """List all WiFi broadcast SSIDs for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network.list_wifi_broadcasts(client, registry, host, site)


@mcp.tool()
async def create_wifi_broadcast(
    host: str,
    site: str,
    broadcast: dict[str, Any],
) -> dict[str, Any]:
    """Create a new WiFi broadcast SSID on a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    broadcast: must include: {'name': str (SSID name), 'enabled': bool, 'security': 'wpapsk'|'open',
      'wpaKey': str (min 8 chars for wpapsk)}. Optional: 'vlanId', 'band'.
      Field names must be camelCase to match the UniFi Integration API.
    """
    client, registry = _require()
    return await network.create_wifi_broadcast(client, registry, host, site, broadcast)


@mcp.tool()
async def get_wifi_broadcast(
    host: str,
    site: str,
    broadcast_id: str,
) -> dict[str, Any]:
    """Get a single WiFi broadcast SSID by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network.get_wifi_broadcast(client, registry, host, site, broadcast_id)


@mcp.tool()
async def update_wifi_broadcast(
    host: str,
    site: str,
    broadcast_id: str,
    broadcast: dict[str, Any],
) -> dict[str, Any]:
    """Update an existing WiFi broadcast SSID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    broadcast: full WiFi broadcast configuration to replace with.
    """
    client, registry = _require()
    return await network.update_wifi_broadcast(
        client, registry, host, site, broadcast_id, broadcast
    )


@mcp.tool()
async def delete_wifi_broadcast(
    host: str,
    site: str,
    broadcast_id: str,
) -> str:
    """Delete a WiFi broadcast SSID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    await network.delete_wifi_broadcast(client, registry, host, site, broadcast_id)
    return f"WiFi broadcast {broadcast_id} deleted."


@mcp.tool()
async def list_wan_interfaces(
    host: str,
    site: str,
) -> dict[str, Any]:
    """List WAN interfaces for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network.list_wan_interfaces(client, registry, host, site)


@mcp.tool()
async def update_wan_interface(
    host: str,
    site: str,
    wan_id: str,
    wan: dict[str, Any],
) -> dict[str, Any]:
    """Update a WAN interface configuration.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    wan_id: WAN interface ID to update.
    wan: fields to update (name, ip, gateway, dns, etc.).
    """
    client, registry = _require()
    return await network.update_wan_interface(client, registry, host, site, wan_id, wan)


device_mgmt.register(mcp, _require)
clients.register(mcp, _require)


# --- Firewall Policy Tools ---


@mcp.tool()
async def list_firewall_policies(
    host: str,
    site: str,
    offset: int = 0,
    limit: int = 50,
) -> dict[str, Any]:
    """List firewall policies for a site with pagination.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    offset: number of records to skip (0 = start from beginning).
    limit: maximum records to return (0 = no limit, return all). Default 50.
    The response includes totalCount so callers can detect additional pages.
    """
    client, registry = _require()
    return await firewall_proxy.list_firewall_policies(client, registry, host, site, offset, limit)


@mcp.tool()
async def create_firewall_policy(
    host: str,
    site: str,
    policy: dict[str, Any],
) -> dict[str, Any]:
    """Create a new firewall policy on a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    policy: required fields:
      - name (str)
      - enabled (bool)
      - action: {'type': 'ALLOW'|'DENY'|'REJECT', 'allowReturnTraffic': bool}
      - source: {'zoneId': str}
      - destination: {'zoneId': str}
      - ipProtocolScope: {'ipVersion': 'IPV4'|'IPV6'|'BOTH'}
      - loggingEnabled (bool)
      Note: there is NO 'index' field; use set_firewall_policy_ordering to manage rule order.
      Get zone IDs from list_firewall_zones_proxy.
    """
    client, registry = _require()
    return await firewall_proxy.create_firewall_policy(client, registry, host, site, policy)


@mcp.tool()
async def get_firewall_policy(
    host: str,
    site: str,
    policy_id: str,
) -> dict[str, Any]:
    """Get a single firewall policy by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await firewall_proxy.get_firewall_policy(client, registry, host, site, policy_id)


@mcp.tool()
async def update_firewall_policy(
    host: str,
    site: str,
    policy_id: str,
    policy: dict[str, Any],
) -> dict[str, Any]:
    """Full-replace a firewall policy by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    policy: full firewall policy configuration to replace with.
    """
    client, registry = _require()
    return await firewall_proxy.update_firewall_policy(
        client, registry, host, site, policy_id, policy
    )


@mcp.tool()
async def patch_firewall_policy(
    host: str,
    site: str,
    policy_id: str,
    fields: dict[str, Any],
) -> dict[str, Any]:
    """Partially update a firewall policy by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    fields: fields to update on the policy.
    """
    client, registry = _require()
    return await firewall_proxy.patch_firewall_policy(
        client, registry, host, site, policy_id, fields
    )


@mcp.tool()
async def delete_firewall_policy(
    host: str,
    site: str,
    policy_id: str,
) -> str:
    """Delete a firewall policy.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    await firewall_proxy.delete_firewall_policy(client, registry, host, site, policy_id)
    return f"Firewall policy {policy_id} deleted."


@mcp.tool()
async def get_firewall_policy_ordering(
    host: str,
    site: str,
    source_zone_id: str,
    destination_zone_id: str,
) -> dict[str, Any]:
    """Get the ordering of firewall policies for a site filtered by source and destination zone.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    source_zone_id: UUID of the source firewall zone (required by the API).
    destination_zone_id: UUID of the destination firewall zone (required by the API).
    """
    client, registry = _require()
    return await firewall_proxy.get_firewall_policy_ordering(
        client, registry, host, site, source_zone_id, destination_zone_id
    )


@mcp.tool()
async def set_firewall_policy_ordering(
    host: str,
    site: str,
    ordering: dict[str, Any],
) -> dict[str, Any]:
    """Set the ordering of firewall policies for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    ordering: policy ordering configuration.
    """
    client, registry = _require()
    return await firewall_proxy.set_firewall_policy_ordering(client, registry, host, site, ordering)


# --- Firewall Zone Tools ---


@mcp.tool()
async def list_firewall_zones_proxy(
    host: str,
    site: str,
) -> dict[str, Any]:
    """List all firewall zones for a site via connector proxy.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await firewall_proxy.list_firewall_zones(client, registry, host, site)


@mcp.tool()
async def create_firewall_zone_proxy(
    host: str,
    site: str,
    zone: dict[str, Any],
) -> dict[str, Any]:
    """Create a new firewall zone on a site via connector proxy.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    zone: must include: {'name': str, 'networkIds': [str]}. Get network IDs from list_networks.
    """
    client, registry = _require()
    return await firewall_proxy.create_firewall_zone(client, registry, host, site, zone)


@mcp.tool()
async def get_firewall_zone_proxy(
    host: str,
    site: str,
    zone_id: str,
) -> dict[str, Any]:
    """Get a single firewall zone by ID via connector proxy.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await firewall_proxy.get_firewall_zone(client, registry, host, site, zone_id)


@mcp.tool()
async def update_firewall_zone_proxy(
    host: str,
    site: str,
    zone_id: str,
    zone: dict[str, Any],
) -> dict[str, Any]:
    """Update a firewall zone by ID via connector proxy.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    zone: full firewall zone configuration to replace with.
    """
    client, registry = _require()
    return await firewall_proxy.update_firewall_zone(client, registry, host, site, zone_id, zone)


@mcp.tool()
async def delete_firewall_zone_proxy(
    host: str,
    site: str,
    zone_id: str,
) -> str:
    """Delete a firewall zone via connector proxy.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    await firewall_proxy.delete_firewall_zone(client, registry, host, site, zone_id)
    return f"Firewall zone {zone_id} deleted."


# --- ACL Rule Tools ---


@mcp.tool()
async def list_acl_rules(
    host: str,
    site: str,
) -> dict[str, Any]:
    """List all ACL rules for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await firewall_proxy.list_acl_rules(client, registry, host, site)


@mcp.tool()
async def create_acl_rule(
    host: str,
    site: str,
    rule: dict[str, Any],
) -> dict[str, Any]:
    """Create a new ACL rule on a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    rule: required fields:
      - name (str): rule name
      - action: 'ALLOW'|'DENY'
      - networkIds (list[str]): network UUIDs this rule applies to (from list_networks)
      - ipVersion: 'IPV4'|'IPV6'|'BOTH'
      Optional: protocols (list, e.g. ['TCP','UDP']), srcAddress (str CIDR),
      dstAddress (str CIDR), srcPort (str), dstPort (str), enabled (bool, default true).
    Note: ACL rules are for intra-VLAN/inter-network L3 filtering. For zone-based
    perimeter firewall rules, use create_firewall_policy instead.
    """
    client, registry = _require()
    return await firewall_proxy.create_acl_rule(client, registry, host, site, rule)


@mcp.tool()
async def get_acl_rule(
    host: str,
    site: str,
    rule_id: str,
) -> dict[str, Any]:
    """Get a single ACL rule by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await firewall_proxy.get_acl_rule(client, registry, host, site, rule_id)


@mcp.tool()
async def update_acl_rule(
    host: str,
    site: str,
    rule_id: str,
    rule: dict[str, Any],
) -> dict[str, Any]:
    """Update an existing ACL rule by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    rule: full ACL rule configuration to replace with.
    """
    client, registry = _require()
    return await firewall_proxy.update_acl_rule(client, registry, host, site, rule_id, rule)


@mcp.tool()
async def delete_acl_rule(
    host: str,
    site: str,
    rule_id: str,
) -> str:
    """Delete an ACL rule.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    await firewall_proxy.delete_acl_rule(client, registry, host, site, rule_id)
    return f"ACL rule {rule_id} deleted."


@mcp.tool()
async def get_acl_rule_ordering(
    host: str,
    site: str,
) -> dict[str, Any]:
    """Get the ordering of ACL rules for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await firewall_proxy.get_acl_rule_ordering(client, registry, host, site)


@mcp.tool()
async def set_acl_rule_ordering(
    host: str,
    site: str,
    ordering: dict[str, Any],
) -> dict[str, Any]:
    """Set the ordering of ACL rules for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    ordering: ACL rule ordering configuration.
    """
    client, registry = _require()
    return await firewall_proxy.set_acl_rule_ordering(client, registry, host, site, ordering)


# --- DNS Policy Tools ---


@mcp.tool()
async def list_dns_policies(
    host: str,
    site: str,
) -> dict[str, Any]:
    """List all DNS policies for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.list_dns_policies(client, registry, host, site)


@mcp.tool()
async def create_dns_policy(
    host: str,
    site: str,
    policy: dict[str, Any],
) -> dict[str, Any]:
    """Create a new DNS policy on a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    policy: required fields:
      - name (str): policy name
      - networkIds (list[str]): network UUIDs to apply this policy to (from list_networks)
      Optional: servers (list[str], custom DNS server IPs), blockingEnabled (bool),
      blockingCategories (list[str]), safeSearchEnabled (bool).
    """
    client, registry = _require()
    return await network_services_proxy.create_dns_policy(client, registry, host, site, policy)


@mcp.tool()
async def get_dns_policy(
    host: str,
    site: str,
    policy_id: str,
) -> dict[str, Any]:
    """Get a single DNS policy by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.get_dns_policy(client, registry, host, site, policy_id)


@mcp.tool()
async def update_dns_policy(
    host: str,
    site: str,
    policy_id: str,
    policy: dict[str, Any],
) -> dict[str, Any]:
    """Update a DNS policy by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    policy: full DNS policy configuration to replace with.
    """
    client, registry = _require()
    return await network_services_proxy.update_dns_policy(
        client, registry, host, site, policy_id, policy
    )


@mcp.tool()
async def delete_dns_policy(
    host: str,
    site: str,
    policy_id: str,
) -> str:
    """Delete a DNS policy.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    await network_services_proxy.delete_dns_policy(client, registry, host, site, policy_id)
    return f"DNS policy {policy_id} deleted."


# --- Traffic Matching List Tools ---


@mcp.tool()
async def list_traffic_matching_lists(
    host: str,
    site: str,
) -> dict[str, Any]:
    """List all traffic matching lists for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.list_traffic_matching_lists(client, registry, host, site)


@mcp.tool()
async def create_traffic_matching_list(
    host: str,
    site: str,
    traffic_list: dict[str, Any],
) -> dict[str, Any]:
    """Create a new traffic matching list on a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    traffic_list: must include: {'name': str, 'items': [{'value': str, 'type': str}]}.
      Note: the list field is 'items', not 'entries'.
    """
    client, registry = _require()
    return await network_services_proxy.create_traffic_matching_list(
        client, registry, host, site, traffic_list
    )


@mcp.tool()
async def get_traffic_matching_list(
    host: str,
    site: str,
    list_id: str,
) -> dict[str, Any]:
    """Get a single traffic matching list by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.get_traffic_matching_list(
        client, registry, host, site, list_id
    )


@mcp.tool()
async def update_traffic_matching_list(
    host: str,
    site: str,
    list_id: str,
    traffic_list: dict[str, Any],
) -> dict[str, Any]:
    """Update a traffic matching list by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    traffic_list: full traffic matching list configuration to replace with.
    """
    client, registry = _require()
    return await network_services_proxy.update_traffic_matching_list(
        client, registry, host, site, list_id, traffic_list
    )


@mcp.tool()
async def delete_traffic_matching_list(
    host: str,
    site: str,
    list_id: str,
) -> str:
    """Delete a traffic matching list.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    await network_services_proxy.delete_traffic_matching_list(client, registry, host, site, list_id)
    return f"Traffic matching list {list_id} deleted."


# --- VPN Server Tools ---


@mcp.tool()
async def list_vpn_servers(
    host: str,
    site: str,
) -> dict[str, Any]:
    """List VPN servers for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.list_vpn_servers(client, registry, host, site)


@mcp.tool()
async def list_site_to_site_tunnels(
    host: str,
    site: str,
) -> dict[str, Any]:
    """List site-to-site VPN tunnels for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.list_site_to_site_tunnels(client, registry, host, site)


# --- RADIUS Profile Tools ---


@mcp.tool()
async def list_radius_profiles(
    host: str,
    site: str,
) -> dict[str, Any]:
    """List RADIUS profiles for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.list_radius_profiles(client, registry, host, site)


# --- Hotspot Voucher Tools ---


@mcp.tool()
async def list_hotspot_vouchers(
    host: str,
    site: str,
) -> dict[str, Any]:
    """List all hotspot vouchers for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.list_hotspot_vouchers(client, registry, host, site)


@mcp.tool()
async def create_hotspot_vouchers(
    host: str,
    site: str,
    voucher_config: dict[str, Any],
) -> dict[str, Any]:
    """Generate hotspot vouchers for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    voucher_config: voucher generation config (count, duration, quota, bandwidth, etc.).
    """
    client, registry = _require()
    return await network_services_proxy.create_hotspot_vouchers(
        client, registry, host, site, voucher_config
    )


@mcp.tool()
async def get_hotspot_voucher(
    host: str,
    site: str,
    voucher_id: str,
) -> dict[str, Any]:
    """Get a single hotspot voucher by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.get_hotspot_voucher(
        client, registry, host, site, voucher_id
    )


@mcp.tool()
async def delete_hotspot_voucher(
    host: str,
    site: str,
    voucher_id: str,
) -> str:
    """Delete a single hotspot voucher.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    await network_services_proxy.delete_hotspot_voucher(client, registry, host, site, voucher_id)
    return f"Hotspot voucher {voucher_id} deleted."


@mcp.tool()
async def bulk_delete_hotspot_vouchers(
    host: str,
    site: str,
    filter_params: dict[str, Any],
) -> str:
    """Bulk delete hotspot vouchers matching filter criteria.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    filter_params: filter parameters to select vouchers for deletion.
    """
    client, registry = _require()
    await network_services_proxy.bulk_delete_hotspot_vouchers(
        client, registry, host, site, filter_params
    )
    return "Hotspot vouchers deleted."


# --- Supporting Resources Tools ---


@mcp.tool()
async def list_device_tags(
    host: str,
    site: str,
) -> dict[str, Any]:
    """List all device tags defined in a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.list_device_tags(client, registry, host, site)


@mcp.tool()
async def list_countries(
    host: str,
) -> dict[str, Any]:
    """List all countries with ISO codes available on a console.

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await network_services_proxy.list_countries(client, registry, host)


# --- Protect Camera Management Tools ---


@mcp.tool()
async def list_cameras(
    host: str,
) -> dict[str, Any]:
    """List all cameras on a Protect console.

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.list_cameras(client, registry, host)


@mcp.tool()
async def get_camera(
    host: str,
    camera_id: str,
) -> dict[str, Any]:
    """Get details for a single Protect camera by ID.

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.get_camera(client, registry, host, camera_id)


@mcp.tool()
async def update_camera(
    host: str,
    camera_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update settings for a Protect camera (name, recording mode, etc.).

    host: console name, ID, or composite ID (MAC:numericId format).
    settings: key-value pairs of camera settings to update.
    """
    client, registry = _require()
    return await protect.update_camera(client, registry, host, camera_id, **settings)


@mcp.tool()
async def get_camera_snapshot(
    host: str,
    camera_id: str,
) -> dict[str, Any]:
    """Get a snapshot from a Protect camera. Returns base64-encoded JPEG image data.

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.get_camera_snapshot(client, registry, host, camera_id)


@mcp.tool()
async def get_rtsps_stream(
    host: str,
    camera_id: str,
) -> dict[str, Any]:
    """Get existing RTSPS stream URLs for a Protect camera.

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.get_rtsps_stream(client, registry, host, camera_id)


@mcp.tool()
async def create_rtsps_stream(
    host: str,
    camera_id: str,
    qualities: list[str],
) -> dict[str, Any]:
    """Create an RTSPS stream for a Protect camera.

    host: console name, ID, or composite ID (MAC:numericId format).
    qualities: list of quality levels to enable, e.g. ['highest', 'high', 'medium', 'low'].
    Case-insensitive — values are normalized to lowercase before sending to the API.
    """
    client, registry = _require()
    return await protect.create_rtsps_stream(client, registry, host, camera_id, qualities)


@mcp.tool()
async def delete_rtsps_stream(
    host: str,
    camera_id: str,
    qualities: list[str],
) -> str:
    """Delete an RTSPS stream for a Protect camera.

    host: console name, ID, or composite ID (MAC:numericId format).
    qualities: list of quality levels to delete, e.g. ['highest', 'high'].
    Case-insensitive — values are normalized to lowercase before sending to the API.
    """
    client, registry = _require()
    await protect.delete_rtsps_stream(client, registry, host, camera_id, qualities)
    return f"RTSPS stream for camera {camera_id} deleted."


@mcp.tool()
async def start_talkback_session(
    host: str,
    camera_id: str,
) -> dict[str, Any]:
    """Start a talkback audio session on a Protect camera.

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.talkback_start(client, registry, host, camera_id)


@mcp.tool()
async def disable_camera_mic_permanently(
    host: str,
    camera_id: str,
) -> dict[str, Any]:
    """Permanently disable the microphone on a Protect camera. This cannot be undone.

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.disable_mic_permanently(client, registry, host, camera_id)


@mcp.tool()
async def ptz_goto_preset(
    host: str,
    camera_id: str,
    slot: int,
) -> dict[str, Any]:
    """Move a PTZ camera to a preset position slot.

    host: console name, ID, or composite ID (MAC:numericId format).
    slot: preset slot number to move to.
    """
    client, registry = _require()
    return await protect.ptz_goto(client, registry, host, camera_id, slot)


@mcp.tool()
async def ptz_patrol_start(
    host: str,
    camera_id: str,
    slot: int,
) -> dict[str, Any]:
    """Start a PTZ patrol on a preset slot.

    host: console name, ID, or composite ID (MAC:numericId format).
    slot: patrol preset slot number.
    """
    client, registry = _require()
    return await protect.ptz_patrol_start(client, registry, host, camera_id, slot)


@mcp.tool()
async def ptz_patrol_stop(
    host: str,
    camera_id: str,
) -> dict[str, Any]:
    """Stop the current PTZ patrol on a camera.

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.ptz_patrol_stop(client, registry, host, camera_id)


# --- Protect Sensor Tools ---


@mcp.tool()
async def list_sensors(
    host: str,
) -> dict[str, Any]:
    """List all sensors on a Protect console.

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.list_sensors(client, registry, host)


@mcp.tool()
async def get_sensor(
    host: str,
    sensor_id: str,
) -> dict[str, Any]:
    """Get details for a single Protect sensor by ID.

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.get_sensor(client, registry, host, sensor_id)


@mcp.tool()
async def update_sensor(
    host: str,
    sensor_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update settings for a Protect sensor.

    host: console name, ID, or composite ID (MAC:numericId format).
    settings: key-value pairs of sensor settings to update.
    """
    client, registry = _require()
    return await protect.update_sensor(client, registry, host, sensor_id, **settings)


# --- Protect Light Tools ---


@mcp.tool()
async def list_lights(
    host: str,
) -> dict[str, Any]:
    """List all lights on a Protect console.

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.list_lights(client, registry, host)


@mcp.tool()
async def get_light(
    host: str,
    light_id: str,
) -> dict[str, Any]:
    """Get details for a single Protect light by ID.

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.get_light(client, registry, host, light_id)


@mcp.tool()
async def update_light(
    host: str,
    light_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update settings for a Protect light (brightness, sensitivity, etc.).

    host: console name, ID, or composite ID (MAC:numericId format).
    settings: key-value pairs of light settings to update.
    """
    client, registry = _require()
    return await protect.update_light(client, registry, host, light_id, **settings)


# --- Protect Chime Tools ---


@mcp.tool()
async def list_chimes(
    host: str,
) -> dict[str, Any]:
    """List all chimes on a Protect console.

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.list_chimes(client, registry, host)


@mcp.tool()
async def get_chime(
    host: str,
    chime_id: str,
) -> dict[str, Any]:
    """Get details for a single Protect chime by ID.

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.get_chime(client, registry, host, chime_id)


@mcp.tool()
async def update_chime(
    host: str,
    chime_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update settings for a Protect chime (volume, ringtone, etc.).

    host: console name, ID, or composite ID (MAC:numericId format).
    settings: key-value pairs of chime settings to update.
    """
    client, registry = _require()
    return await protect.update_chime(client, registry, host, chime_id, **settings)


# --- Protect Viewer Tools ---


@mcp.tool()
async def list_viewers(
    host: str,
) -> dict[str, Any]:
    """List all viewers on a Protect console.

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.list_viewers(client, registry, host)


@mcp.tool()
async def get_viewer(
    host: str,
    viewer_id: str,
) -> dict[str, Any]:
    """Get details for a single Protect viewer by ID.

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.get_viewer(client, registry, host, viewer_id)


@mcp.tool()
async def update_viewer(
    host: str,
    viewer_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update settings for a Protect viewer (liveview assignment, etc.).

    host: console name, ID, or composite ID (MAC:numericId format).
    settings: key-value pairs of viewer settings to update.
    """
    client, registry = _require()
    return await protect.update_viewer(client, registry, host, viewer_id, **settings)


# --- Protect Liveview Tools ---


@mcp.tool()
async def list_liveviews(
    host: str,
) -> dict[str, Any]:
    """List all liveviews on a Protect console.

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.list_liveviews(client, registry, host)


@mcp.tool()
async def get_liveview(
    host: str,
    liveview_id: str,
) -> dict[str, Any]:
    """Get details for a single Protect liveview by ID.

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.get_liveview(client, registry, host, liveview_id)


@mcp.tool()
async def create_liveview(
    host: str,
    name: str,
    settings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a liveview on a Protect console.

    host: console name, ID, or composite ID (MAC:numericId format).
    name: liveview display name.
    settings: optional additional liveview fields (layout, slots, etc.).
    """
    client, registry = _require()
    extra = settings or {}
    return await protect.create_liveview(client, registry, host, name, **extra)


@mcp.tool()
async def update_liveview(
    host: str,
    liveview_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update a liveview on a Protect console.

    host: console name, ID, or composite ID (MAC:numericId format).
    settings: key-value pairs of liveview settings to update.
    """
    client, registry = _require()
    return await protect.update_liveview(client, registry, host, liveview_id, **settings)


# --- Protect NVR Tools ---


@mcp.tool()
async def get_nvr(
    host: str,
) -> dict[str, Any]:
    """Get NVR details from a Protect console.

    Returns NVR hardware info, storage status, firmware version, and system health.
    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.get_nvr(client, registry, host)


# --- Protect File Tools ---


@mcp.tool()
async def list_protect_files(
    host: str,
    file_type: str,
) -> dict[str, Any]:
    """List Protect device asset files of a given type.

    host: console name, ID, or composite ID (MAC:numericId format).
    file_type: asset category, e.g. 'sounds' or 'images'.
    """
    client, registry = _require()
    return await protect.list_protect_files(client, registry, host, file_type)


@mcp.tool()
async def upload_protect_file(
    host: str,
    file_type: str,
    filename: str,
    file_content_base64: str,
) -> dict[str, Any]:
    """Upload a Protect device asset file. WARNING: Uploads asset file to NVR storage.
    Overwriting system files may not be reversible.

    host: console name, ID, or composite ID (MAC:numericId format).
    file_type: asset category, e.g. 'sounds' or 'images'.
    filename: name of the file to upload (e.g. 'alert.mp3').
    file_content_base64: base64-encoded file content.
    """
    client, registry = _require()
    return await protect.upload_protect_file(
        client, registry, host, file_type, filename, file_content_base64
    )


# --- Protect Alarm Manager Tools ---


@mcp.tool()
async def trigger_alarm_webhook(
    host: str,
    webhook_id: str,
    confirm: bool = False,
) -> dict[str, Any]:
    """Trigger an alarm manager webhook by ID. WARNING: triggers physical alarm hardware.
    Verify webhook ID is correct before confirming.

    host: console name, ID, or composite ID (MAC:numericId format).
    webhook_id: alarm webhook ID to trigger.
    confirm: must be True to execute. Prevents accidental triggers on live infrastructure.
    """
    if not confirm:
        return {
            "status": "not_triggered",
            "reason": (
                "Set confirm=True to trigger physical alarm hardware. Verify webhook_id first."
            ),
        }
    client, registry = _require()
    return await protect.trigger_alarm_webhook(client, registry, host, webhook_id)


# --- Port Forwarding Tools ---


@mcp.tool()
async def list_port_forwards(
    host: str,
    site: str,
) -> dict[str, Any]:
    """List all port forwarding rules for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.list_port_forwards(client, registry, host, site)


@mcp.tool()
async def create_port_forward(
    host: str,
    site: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Create a port forwarding rule via the Classic REST API.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    payload: port forward config. Required fields: name, dst_port, fwd, fwd_port, proto.
    Example: {"enabled": true, "name": "SSH", "pfwd_interface": "wan", "src": "any",
    "dst_port": "2222", "fwd": "192.168.1.10", "fwd_port": "22", "proto": "tcp", "log": false}
    """
    client, registry = _require()
    return await network_services_proxy.create_port_forward(client, registry, host, site, payload)


@mcp.tool()
async def update_port_forward(
    host: str,
    site: str,
    forward_id: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Update a port forwarding rule by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    forward_id: port forward rule ID.
    payload: fields to update.
    """
    client, registry = _require()
    return await network_services_proxy.update_port_forward(
        client, registry, host, site, forward_id, payload
    )


@mcp.tool()
async def delete_port_forward(
    host: str,
    site: str,
    forward_id: str,
) -> str:
    """Delete a port forwarding rule by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    await network_services_proxy.delete_port_forward(client, registry, host, site, forward_id)
    return f"Port forward {forward_id} deleted."


# --- Traffic Rule Tools ---


@mcp.tool()
async def list_traffic_rules(
    host: str,
    site: str,
) -> dict[str, Any]:
    """List traffic matching rules (QoS, application, IP group matching).

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.list_traffic_rules(client, registry, host, site)


@mcp.tool()
async def create_traffic_rule(
    host: str,
    site: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Create a traffic matching rule (QoS, block, or route by application/IP group).

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    payload: required fields:
      - description (str): rule name/description
      - action: 'BLOCK'|'THROTTLE_RATE'|'QUEUE'
      - matching_target: 'INTERNET'|'LOCAL'|'ALL' or a traffic matching list ID
      - enabled (bool)
      Optional: matching_target_type ('INTERNET'|'DOMAIN'|'IP_GROUP'|'APPLICATION_GROUP'),
      bandwidth_limit (dict with up_limit_kbps/down_limit_kbps for THROTTLE_RATE).
    Note: uses the Classic REST v2 API (/v2/api/site/{siteId}/trafficrules). May not exist
    on firmware 10.2.105 and below.
    """
    client, registry = _require()
    return await network_services_proxy.create_traffic_rule(client, registry, host, site, payload)


@mcp.tool()
async def update_traffic_rule(
    host: str,
    site: str,
    rule_id: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Update a traffic rule by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    rule_id: traffic rule ID.
    payload: fields to update.
    """
    client, registry = _require()
    return await network_services_proxy.update_traffic_rule(
        client, registry, host, site, rule_id, payload
    )


@mcp.tool()
async def delete_traffic_rule(
    host: str,
    site: str,
    rule_id: str,
) -> str:
    """Delete a traffic rule by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    await network_services_proxy.delete_traffic_rule(client, registry, host, site, rule_id)
    return f"Traffic rule {rule_id} deleted."


vpn.register(mcp, _require)
hotspot.register(mcp, _require)
aggregation.register(mcp, _require)
statistics.register(mcp, _require)


# --- User / DHCP Reservation Tools ---


@mcp.tool()
async def list_users(
    host: str,
    site: str,
) -> Any:
    """List DHCP fixed-IP reservations and client aliases for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    Returns entries with fields: name, note, fixed_ip, use_fixedip, network_id.
    """
    client, registry = _require()
    return await network_services_proxy.list_users(client, registry, host, site)


@mcp.tool()
async def get_user(
    host: str,
    site: str,
    user_id: str,
) -> Any:
    """Get a single DHCP/client-alias entry by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.get_user(client, registry, host, site, user_id)


@mcp.tool()
async def update_user(
    host: str,
    site: str,
    user_id: str,
    payload: dict[str, Any],
) -> Any:
    """Update a DHCP/client-alias entry by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    payload: fields to update (name, note, fixed_ip, use_fixedip, network_id).
    """
    client, registry = _require()
    return await network_services_proxy.update_user(client, registry, host, site, user_id, payload)


# --- Traffic Route Tools ---


@mcp.tool()
async def list_traffic_routes(
    host: str,
    site: str,
) -> Any:
    """List static/policy traffic routes for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.list_traffic_routes(client, registry, host, site)


@mcp.tool()
async def create_traffic_route(
    host: str,
    site: str,
    payload: dict[str, Any],
) -> Any:
    """Create a traffic route on a site (policy-based routing / WAN load-balancing).

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    payload: required fields:
      - name (str): route name
      - enabled (bool)
      - matchingTarget: 'INTERNET'|'ALL' or a traffic matching list ID
      - networkId (str): source network UUID (from list_networks), or 'ANY'
      - nextHop (str): gateway IP address or WAN interface name
      Optional: matchingTargetType ('INTERNET'|'DOMAIN'|'IP_GROUP'), description (str).
    """
    client, registry = _require()
    return await network_services_proxy.create_traffic_route(client, registry, host, site, payload)


@mcp.tool()
async def get_traffic_route(
    host: str,
    site: str,
    route_id: str,
) -> Any:
    """Get a single traffic route by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.get_traffic_route(client, registry, host, site, route_id)


@mcp.tool()
async def update_traffic_route(
    host: str,
    site: str,
    route_id: str,
    payload: dict[str, Any],
) -> Any:
    """Update a traffic route by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    payload: full traffic route configuration to replace with.
    """
    client, registry = _require()
    return await network_services_proxy.update_traffic_route(
        client, registry, host, site, route_id, payload
    )


@mcp.tool()
async def delete_traffic_route(
    host: str,
    site: str,
    route_id: str,
) -> str:
    """Delete a traffic route by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    await network_services_proxy.delete_traffic_route(client, registry, host, site, route_id)
    return f"Traffic route {route_id} deleted."


# --- Controller Settings Tools ---


@mcp.tool()
async def list_settings(
    host: str,
    site: str,
) -> Any:
    """List all controller setting groups for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    Returns a list of setting objects grouped by key (mgmt, super_smtp, guest_access, etc.).
    """
    client, registry = _require()
    return await network_services_proxy.list_settings(client, registry, host, site)


@mcp.tool()
async def get_setting(
    host: str,
    site: str,
    setting_key: str,
) -> Any:
    """Get a controller setting group by key.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    setting_key: setting group identifier (e.g. 'mgmt', 'super_smtp', 'guest_access').
    """
    client, registry = _require()
    return await network_services_proxy.get_setting(client, registry, host, site, setting_key)


@mcp.tool()
async def update_setting(
    host: str,
    site: str,
    setting_key: str,
    payload: dict[str, Any],
) -> Any:
    """Update a controller setting group by key.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    setting_key: setting group identifier (e.g. 'mgmt', 'super_smtp', 'guest_access').
    payload: setting fields to update.
    """
    client, registry = _require()
    return await network_services_proxy.update_setting(
        client, registry, host, site, setting_key, payload
    )


# --- Dynamic DNS Tools ---


@mcp.tool()
async def list_dynamic_dns(
    host: str,
    site: str,
    include_secrets: bool = False,
) -> Any:
    """List Dynamic DNS provider configurations for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    include_secrets: if True, return plaintext x_password values; defaults to False (redacted).
    """
    client, registry = _require()
    return await network_services_proxy.list_dynamic_dns(
        client, registry, host, site, include_secrets
    )


@mcp.tool()
async def get_dynamic_dns(
    host: str,
    site: str,
    ddns_id: str,
    include_secrets: bool = False,
) -> Any:
    """Get a single Dynamic DNS configuration by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    include_secrets: if True, return plaintext x_password values; defaults to False (redacted).
    """
    client, registry = _require()
    return await network_services_proxy.get_dynamic_dns(
        client, registry, host, site, ddns_id, include_secrets
    )


@mcp.tool()
async def update_dynamic_dns(
    host: str,
    site: str,
    ddns_id: str,
    payload: dict[str, Any],
) -> Any:
    """Update a Dynamic DNS configuration by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    payload: DDNS configuration fields to update.
    """
    client, registry = _require()
    return await network_services_proxy.update_dynamic_dns(
        client, registry, host, site, ddns_id, payload
    )


# --- Port Profile Tools ---


@mcp.tool()
async def list_port_profiles(
    host: str,
    site: str,
) -> Any:
    """List switch port profiles (speed, VLAN, PoE config) for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.list_port_profiles(client, registry, host, site)


@mcp.tool()
async def get_port_profile(
    host: str,
    site: str,
    profile_id: str,
) -> Any:
    """Get a single switch port profile by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    profile_id: port profile ID.
    """
    client, registry = _require()
    return await network_services_proxy.get_port_profile(client, registry, host, site, profile_id)


@mcp.tool()
async def update_port_profile(
    host: str,
    site: str,
    profile_id: str,
    payload: dict[str, Any],
) -> Any:
    """Update a switch port profile by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    profile_id: port profile ID.
    payload: fields to update (e.g. speed, native_networkconf_id, op_mode, poe_mode).
    """
    client, registry = _require()
    return await network_services_proxy.update_port_profile(
        client, registry, host, site, profile_id, payload
    )


# --- Routing Table Tools ---


@mcp.tool()
async def list_routing_entries(
    host: str,
    site: str,
) -> Any:
    """List static routing table entries for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.list_routing_entries(client, registry, host, site)


# --- WLAN Config Tools ---


@mcp.tool()
async def list_wlan_configs(
    host: str,
    site: str,
    include_secrets: bool = False,
) -> Any:
    """List per-SSID WLAN configurations (security, band steering, rate limits) for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    include_secrets: if True, return plaintext x_passphrase values; defaults to False (redacted).
    """
    client, registry = _require()
    return await network_services_proxy.list_wlan_configs(
        client, registry, host, site, include_secrets
    )


@mcp.tool()
async def get_wlan_config(
    host: str,
    site: str,
    wlan_id: str,
    include_secrets: bool = False,
) -> Any:
    """Get a single WLAN (SSID) configuration by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    wlan_id: WLAN config ID.
    include_secrets: if True, return plaintext x_passphrase values; defaults to False (redacted).
    """
    client, registry = _require()
    return await network_services_proxy.get_wlan_config(
        client, registry, host, site, wlan_id, include_secrets
    )


@mcp.tool()
async def update_wlan_config(
    host: str,
    site: str,
    wlan_id: str,
    payload: dict[str, Any],
) -> Any:
    """Update a WLAN (SSID) configuration by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    wlan_id: WLAN config ID.
    payload: fields to update (e.g. x_passphrase, security, band, enabled).
    """
    client, registry = _require()
    return await network_services_proxy.update_wlan_config(
        client, registry, host, site, wlan_id, payload
    )


# --- WLAN Group Tools ---


@mcp.tool()
async def list_wlan_groups(
    host: str,
    site: str,
) -> Any:
    """List WLAN groups for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.list_wlan_groups(client, registry, host, site)


@mcp.tool()
async def get_wlan_group(
    host: str,
    site: str,
    group_id: str,
) -> Any:
    """Get a single WLAN group by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    group_id: WLAN group ID.
    """
    client, registry = _require()
    return await network_services_proxy.get_wlan_group(client, registry, host, site, group_id)


# --- Channel Plan Tools ---


@mcp.tool()
async def get_channel_plan(
    host: str,
    site: str,
) -> Any:
    """Get RF channel assignments and DFS status for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.get_channel_plan(client, registry, host, site)


# --- Rogue AP Tools ---


@mcp.tool()
async def list_rogue_aps(
    host: str,
    site: str,
    rogue_only: bool = False,
) -> Any:
    """List neighboring APs detected by the site's radios.

    Returns ALL neighboring APs (most will have is_rogue=false and are benign neighbors).
    Only a small subset with is_rogue=true are confirmed rogue APs. Set rogue_only=true to
    filter to confirmed rogues only.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    Returns entries with BSSID, SSID, channel, signal strength, is_rogue flag, and detection time.
    """
    client, registry = _require()
    return await network_services_proxy.list_rogue_aps(
        client, registry, host, site, rogue_only=rogue_only
    )


# --- Classic Firewall Rule Tools ---


@mcp.tool()
async def list_firewall_rules(
    host: str,
    site: str,
) -> Any:
    """List classic L3/L4 firewall rules for a site (distinct from Integration API policies).

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.list_firewall_rules(client, registry, host, site)


@mcp.tool()
async def get_firewall_rule(
    host: str,
    site: str,
    rule_id: str,
) -> Any:
    """Get a single classic firewall rule by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    rule_id: firewall rule ID.
    """
    client, registry = _require()
    return await network_services_proxy.get_firewall_rule(client, registry, host, site, rule_id)


# --- Firewall Group Tools ---


@mcp.tool()
async def list_firewall_groups(
    host: str,
    site: str,
) -> Any:
    """List firewall groups (IP/port sets referenced by firewall rules) for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.list_firewall_groups(client, registry, host, site)


@mcp.tool()
async def get_firewall_group(
    host: str,
    site: str,
    group_id: str,
) -> Any:
    """Get a single firewall group by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    group_id: firewall group ID.
    """
    client, registry = _require()
    return await network_services_proxy.get_firewall_group(client, registry, host, site, group_id)


# --- RADIUS Account Tools ---


@mcp.tool()
async def list_accounts(
    host: str,
    site: str,
    include_secrets: bool = False,
) -> Any:
    """List local RADIUS user accounts for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    include_secrets: if True, return plaintext x_password values; defaults to False (redacted).
    """
    client, registry = _require()
    return await network_services_proxy.list_accounts(client, registry, host, site, include_secrets)


@mcp.tool()
async def get_account(
    host: str,
    site: str,
    account_id: str,
    include_secrets: bool = False,
) -> Any:
    """Get a single RADIUS account by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    account_id: RADIUS account ID.
    include_secrets: if True, return plaintext x_password values; defaults to False (redacted).
    """
    client, registry = _require()
    return await network_services_proxy.get_account(
        client, registry, host, site, account_id, include_secrets
    )


# --- Hotspot Package Tools ---


@mcp.tool()
async def list_hotspot_packages(
    host: str,
    site: str,
) -> Any:
    """List guest portal billing packages for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.list_hotspot_packages(client, registry, host, site)


@mcp.tool()
async def get_hotspot_package(
    host: str,
    site: str,
    package_id: str,
) -> Any:
    """Get a single hotspot billing package by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    package_id: hotspot package ID.
    """
    client, registry = _require()
    return await network_services_proxy.get_hotspot_package(
        client, registry, host, site, package_id
    )


# --- Scheduled Task Tools ---


@mcp.tool()
async def list_scheduled_tasks(
    host: str,
    site: str,
) -> Any:
    """List scheduled tasks (firmware upgrade schedules, speed tests) for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.list_scheduled_tasks(client, registry, host, site)


@mcp.tool()
async def get_scheduled_task(
    host: str,
    site: str,
    task_id: str,
) -> Any:
    """Get a single scheduled task by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    task_id: scheduled task ID.
    """
    client, registry = _require()
    return await network_services_proxy.get_scheduled_task(client, registry, host, site, task_id)


# --- DPI Tools ---


@mcp.tool()
async def list_dpi_categories(
    host: str,
    site: str = "",
    offset: int = 0,
    limit: int = 0,
) -> dict[str, Any]:
    """List DPI (Deep Packet Inspection) app categories available for traffic rules.

    Categories include Social Media, Streaming Video, Gaming, etc.
    host: console name, ID, or composite ID (MAC:numericId format).
    site: ignored — DPI data is host-level, not site-scoped.
    offset: number of records to skip (0 = start from beginning).
    limit: maximum records to return (0 = no limit, return all).
    """
    client, registry = _require()
    return await network_services_proxy.list_dpi_categories(client, registry, host, offset, limit)


@mcp.tool()
async def list_dpi_applications(
    host: str,
    site: str = "",
    offset: int = 0,
    limit: int = 0,
) -> dict[str, Any]:
    """List DPI applications available for traffic rules.

    Companion to list_dpi_categories; use application IDs in traffic rule configurations.
    host: console name, ID, or composite ID (MAC:numericId format).
    site: ignored — DPI data is host-level, not site-scoped.
    offset: number of records to skip (0 = start from beginning).
    limit: maximum records to return (0 = no limit, return all).
    """
    client, registry = _require()
    return await network_services_proxy.list_dpi_applications(client, registry, host, offset, limit)


def main() -> None:
    """Entry point for the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
