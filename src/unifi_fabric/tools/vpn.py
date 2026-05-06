"""VPN server and RADIUS profile CRUD tools — manage VPN and auth services."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

from fastmcp import FastMCP

from ..client import UniFiClient, validate_id
from ..registry import Registry, _assert_uuid
from .network import _proxy

# ---------------------------------------------------------------------------
# Site-to-site tunnels
# ---------------------------------------------------------------------------


async def _create_site_to_site_tunnel(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    tunnel: dict[str, Any],
) -> dict[str, Any]:
    """Create a site-to-site VPN tunnel.

    Args:
        host: Host name or ID.
        site: Site name or ID.
        tunnel: Tunnel configuration payload (remoteIp, psk, networks, etc.).
    """
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.post(
        _proxy(host_id, f"/sites/{site_id}/vpn/site-to-site-tunnels"), json=tunnel
    )


async def _update_site_to_site_tunnel(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    tunnel_id: str,
    tunnel: dict[str, Any],
) -> dict[str, Any]:
    """Update a site-to-site VPN tunnel by ID."""
    validate_id(tunnel_id, "tunnel_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    return await client.put(
        _proxy(host_id, f"/sites/{site_id}/vpn/site-to-site-tunnels/{tunnel_id}"), json=tunnel
    )


async def _delete_site_to_site_tunnel(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    tunnel_id: str,
) -> dict[str, Any]:
    """Delete a site-to-site VPN tunnel by ID."""
    validate_id(tunnel_id, "tunnel_id")
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)
    await client.delete(_proxy(host_id, f"/sites/{site_id}/vpn/site-to-site-tunnels/{tunnel_id}"))
    return {"deleted": True, "tunnelId": tunnel_id}


# ---------------------------------------------------------------------------
# VPN servers
# ---------------------------------------------------------------------------


async def _list_vpn_servers(
    client: UniFiClient,
    registry: Registry,
    *,
    host: str | None = None,
    site: str | None = None,
    page_token: str | None = None,
) -> dict[str, Any]:
    """List VPN server configurations (OpenVPN, WireGuard, L2TP)."""
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

    data = await client.get("/ea/vpn-servers", params=params or None)
    items = data.get("data", [])
    result: dict[str, Any] = {"vpnServers": items, "count": len(items)}
    if data.get("nextToken"):
        result["nextToken"] = data["nextToken"]
    return result


async def _get_vpn_server(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    server_id: str,
) -> dict[str, Any]:
    """Get a single VPN server by ID (list + filter; /ea/vpn-servers has no GET-by-ID)."""
    validate_id(server_id, "server_id")
    result = await _list_vpn_servers(client, registry, host=host, site=site)
    for server in result.get("vpnServers", []):
        if server.get("id") == server_id:
            return server
    raise ValueError(f"VPN server {server_id!r} not found")


async def _create_vpn_server(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    name: str,
    vpn_type: str,
    *,
    subnet: str | None = None,
    enabled: bool = True,
    **extra: Any,
) -> dict[str, Any]:
    """Create a VPN server.

    Args:
        host: Host name or ID.
        site: Site name or ID.
        name: VPN server name.
        vpn_type: 'openvpn', 'wireguard', or 'l2tp'.
        subnet: VPN client address pool CIDR.
        enabled: Whether the VPN server is active.
    """
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)

    body: dict[str, Any] = {
        "name": name,
        "type": vpn_type,
        "enabled": enabled,
        **extra,
    }
    if subnet:
        body["subnet"] = subnet

    data = await client.post(_proxy(host_id, f"/sites/{site_id}/vpn/servers"), json=body)
    return cast(dict[str, Any], data.get("data", data))


async def _update_vpn_server(
    client: UniFiClient,
    server_id: str,
    **fields: Any,
) -> dict[str, Any]:
    """Update a VPN server by ID."""
    validate_id(server_id, "server_id")
    data = await client.patch(f"/ea/vpn-servers/{server_id}", json=fields)
    return cast(dict[str, Any], data.get("data", data))


async def _delete_vpn_server(
    client: UniFiClient,
    server_id: str,
) -> dict[str, Any]:
    """Delete a VPN server by ID."""
    validate_id(server_id, "server_id")
    await client.delete(f"/ea/vpn-servers/{server_id}")
    return {"deleted": True, "serverId": server_id}


# ---------------------------------------------------------------------------
# RADIUS profiles
# ---------------------------------------------------------------------------


async def _list_radius_profiles(
    client: UniFiClient,
    registry: Registry,
    *,
    host: str | None = None,
    site: str | None = None,
    page_token: str | None = None,
) -> dict[str, Any]:
    """List RADIUS authentication profiles for WiFi 802.1X and VPN."""
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

    data = await client.get("/ea/radius-profiles", params=params or None)
    items = data.get("data", [])
    result: dict[str, Any] = {"radiusProfiles": items, "count": len(items)}
    if data.get("nextToken"):
        result["nextToken"] = data["nextToken"]
    return result


async def _get_radius_profile(
    client: UniFiClient,
    registry: Registry,
    profile_id: str,
) -> dict[str, Any]:
    """Get a single RADIUS profile by ID (list + filter; /ea/radius-profiles has no GET-by-ID)."""
    validate_id(profile_id, "profile_id")
    result = await _list_radius_profiles(client, registry)
    for profile in result.get("radiusProfiles", []):
        if profile.get("id") == profile_id:
            return profile
    raise ValueError(f"RADIUS profile {profile_id!r} not found")


async def _create_radius_profile(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    name: str,
    auth_server_ip: str,
    auth_server_port: int,
    auth_server_secret: str,
    *,
    acct_server_ip: str | None = None,
    acct_server_port: int = 1813,
    acct_server_secret: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Create a RADIUS profile.

    Args:
        host: Host name or ID.
        site: Site name or ID.
        name: Profile name.
        auth_server_ip: RADIUS authentication server IP.
        auth_server_port: RADIUS authentication server port (typically 1812).
        auth_server_secret: Shared secret for authentication server.
        acct_server_ip: RADIUS accounting server IP (optional).
        acct_server_port: RADIUS accounting server port (default 1813).
        acct_server_secret: Shared secret for accounting server (optional).
    """
    host_id = await registry.resolve_host_id(host)
    site_id = await registry.resolve_site_id(site, host_id)
    _assert_uuid(site_id)

    body: dict[str, Any] = {
        "name": name,
        "authServerIp": auth_server_ip,
        "authServerPort": auth_server_port,
        "authServerSecret": auth_server_secret,
        **extra,
    }
    if acct_server_ip:
        body["acctServerIp"] = acct_server_ip
        body["acctServerPort"] = acct_server_port
        if acct_server_secret:
            body["acctServerSecret"] = acct_server_secret

    data = await client.post(_proxy(host_id, f"/sites/{site_id}/radius/profiles"), json=body)
    return cast(dict[str, Any], data.get("data", data))


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register all VPN, site-to-site tunnel, and RADIUS profile MCP tools."""

    @mcp.tool()
    async def create_site_to_site_tunnel(
        host: str,
        site: str,
        tunnel: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a site-to-site VPN tunnel. This is a write operation that modifies live config.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        tunnel: tunnel configuration payload (remoteIp, psk, networks, enabled, etc.).
        """
        client, registry = deps_fn()
        return await _create_site_to_site_tunnel(client, registry, host, site, tunnel)

    @mcp.tool()
    async def update_site_to_site_tunnel(
        host: str,
        site: str,
        tunnel_id: str,
        tunnel: dict[str, Any],
    ) -> dict[str, Any]:
        """Update a site-to-site VPN tunnel by ID.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        tunnel_id: tunnel ID to update.
        tunnel: fields to update (remoteIp, psk, networks, enabled, etc.).
        """
        client, registry = deps_fn()
        return await _update_site_to_site_tunnel(client, registry, host, site, tunnel_id, tunnel)

    @mcp.tool()
    async def delete_site_to_site_tunnel(
        host: str,
        site: str,
        tunnel_id: str,
    ) -> dict[str, Any]:
        """Delete a site-to-site VPN tunnel by ID. This permanently removes the tunnel config.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        tunnel_id: tunnel ID to delete.
        """
        client, registry = deps_fn()
        return await _delete_site_to_site_tunnel(client, registry, host, site, tunnel_id)

    @mcp.tool()
    async def get_vpn_server(
        host: str,
        site: str,
        server_id: str,
    ) -> dict[str, Any]:
        """Get a single VPN server configuration by ID.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        server_id: VPN server ID.
        """
        client, registry = deps_fn()
        return await _get_vpn_server(client, registry, host, site, server_id)

    @mcp.tool()
    async def create_vpn_server(
        host: str,
        site: str,
        name: str,
        vpn_type: str,
        subnet: str | None = None,
        enabled: bool = True,
    ) -> dict[str, Any]:
        """Create a VPN server (OpenVPN, WireGuard, or L2TP).

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        vpn_type: 'openvpn', 'wireguard', or 'l2tp'.
        subnet: VPN client address pool CIDR.
        """
        client, registry = deps_fn()
        return await _create_vpn_server(
            client,
            registry,
            host,
            site,
            name,
            vpn_type,
            subnet=subnet,
            enabled=enabled,
        )

    @mcp.tool()
    async def update_vpn_server(
        server_id: str,
        fields: dict[str, Any],
    ) -> dict[str, Any]:
        """Update a VPN server configuration by ID.

        server_id: VPN server ID.
        fields: fields to update (name, type, subnet, enabled, etc.).
        """
        client, _ = deps_fn()
        return await _update_vpn_server(client, server_id, **fields)

    @mcp.tool()
    async def delete_vpn_server(
        server_id: str,
    ) -> str:
        """Delete a VPN server by ID. WARNING: Permanently removes VPN server.
        Connected clients will lose access immediately."""
        client, _ = deps_fn()
        await _delete_vpn_server(client, server_id)
        return f"VPN server {server_id} deleted."

    @mcp.tool()
    async def get_radius_profile(
        profile_id: str,
    ) -> dict[str, Any]:
        """Get a single RADIUS authentication profile by ID."""
        client, registry = deps_fn()
        return await _get_radius_profile(client, registry, profile_id)

    @mcp.tool()
    async def create_radius_profile(
        host: str,
        site: str,
        name: str,
        auth_server_ip: str,
        auth_server_port: int,
        auth_server_secret: str,
        acct_server_ip: str | None = None,
        acct_server_port: int = 1813,
        acct_server_secret: str | None = None,
    ) -> dict[str, Any]:
        """Create a RADIUS authentication profile.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        auth_server_ip/port/secret: RADIUS authentication server details.
        acct_server_ip/port/secret: optional accounting server details.
        Note: if the console returns HTTP 405, RADIUS profile creation is not supported on this
        firmware version and profiles are effectively read-only. Use list_radius_profiles instead.
        """
        client, registry = deps_fn()
        return await _create_radius_profile(
            client,
            registry,
            host,
            site,
            name,
            auth_server_ip,
            auth_server_port,
            auth_server_secret,
            acct_server_ip=acct_server_ip,
            acct_server_port=acct_server_port,
            acct_server_secret=acct_server_secret,
        )
