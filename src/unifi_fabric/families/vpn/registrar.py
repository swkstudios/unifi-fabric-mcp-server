"""The vpn family registrar: its tool wrappers, in registration order (the family-owned layout).

The loader map (``catalog/loaders.py``) runs each ``register`` / ``register_<n>`` below at its place
in the ``tools/list`` order, with the ``origin`` its tools are indexed under. The wrappers are the
tools' public surface (names, annotations, docstrings, signatures), moved by
``scripts/move_family.py``; each calls its handler through the handler's module, so a patched
handler still applies (``handlers.py`` indexes them).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

from fastmcp import FastMCP

from ...client import UniFiClient
from ...registry import Registry
from ...shared_shapes._site_config_shared import (
    RADIUS_PROFILES,
    _delete_config_record,
    _update_config_record,
)
from ...tool_annotations import READ_ONLY, WRITE
from . import handlers, network_vpn_dns, vpn, vpn_clients
from .schemas import SiteVpnAction, StaticDnsRecord


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register all VPN, site-to-site tunnel, and RADIUS profile MCP tools."""

    @mcp.tool(annotations=WRITE)
    async def create_site_to_site_tunnel(
        host: str,
        site: str,
        tunnel: dict[str, Any],
    ) -> Any:
        """Create a site-to-site VPN tunnel. Write: modifies live config.

        A manual tunnel is a Classic networkconf record of purpose site-vpn, written with POST /proxy/network/api/s/{site}/rest/networkconf (the controller UI's route; the Integration API serves tunnels GET-only, POST answers 405 on Network 11.0.81). The body is the native networkconf fields, verbatim, with purpose site-vpn; pass name and vpn_type (ipsec-vpn, openvpn-vpn, wireguard-vpn). The controller validates it and answers api.err.InvalidPayload when a field the tunnel type needs is missing; that error gets a hint naming a missing name/vpn_type.

        Returns the upstream Classic envelope {meta: {rc}, data: [the created networkconf]}; data[].external_id is the id list_site_to_site_tunnels reports. Under dry-run policy nothing is sent: the result is the bare dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params, body}}.

        Example call (create_site_to_site_tunnel):
            {
              "host": "my-console",
              "site": "Default",
              "tunnel": {
                "name": "Branch office",
                "vpn_type": "openvpn-vpn",
                "enabled": false,
                "openvpn_remote_host": "203.0.113.10"
              }
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            tunnel: Native Classic networkconf body for a site-vpn record. Pass name (string)
                and vpn_type (ipsec-vpn, openvpn-vpn or wireguard-vpn). An absent or null
                purpose is sent as site-vpn; another purpose is sent as given (an upstream error
                then gets a hint). Other keys are the controller's networkconf fields for that
                tunnel type, sent unchanged.
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await vpn._create_site_to_site_tunnel(client, registry, host, site, tunnel)

    @mcp.tool(annotations=WRITE)
    async def update_site_to_site_tunnel(
        host: str,
        site: str,
        tunnel_id: str,
        tunnel: dict[str, Any],
    ) -> Any:
        """Update a site-to-site VPN tunnel by ID.

        Classic REST PUT /proxy/network/api/s/{site}/rest/networkconf/{_id} (the UI's route; the Integration API has no tunnel update, 404 on Network 11.0.81).

        The id is resolved among the site-vpn records first; an unknown id fails listing every tunnel with both ids. Send only the fields to change: the Classic PUT merges them into the stored record.

        Returns the upstream Classic envelope {meta: {rc}, data: [the updated networkconf]}. Under dry-run policy nothing is sent: the bare dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params, body}} in place of the upstream body.

        Example call (update_site_to_site_tunnel):
            {"host": "my-console", "site": "Default",
             "tunnel_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "tunnel": {"enabled": false}}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            tunnel_id: Site-to-site VPN tunnel id. Get it from list_site_to_site_tunnels
                (data[].id); the Classic networkconf _id also works. Network-app UUID — not a
                Protect id.
            tunnel: Native Classic networkconf fields to change, e.g. enabled, name. Sent unchanged
                (empty-string list placeholders dropped); an absent or null purpose is sent as
                site-vpn, another is sent as given (an upstream error then gets a hint).
                A purpose-only update is refused.
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await vpn._update_site_to_site_tunnel(
            client, registry, host, site, tunnel_id, tunnel
        )

    @mcp.tool(annotations=WRITE)
    async def delete_site_to_site_tunnel(
        host: str,
        site: str,
        tunnel_id: str,
    ) -> dict[str, Any]:
        """Delete a site-to-site VPN tunnel by ID. Permanently removes the tunnel config.

        Consequence: the tunnel goes down and traffic between the sites over it stops; there is no undo.

        Classic REST DELETE /proxy/network/api/s/{site}/rest/networkconf/{_id} (the Integration API has no tunnel delete). The id is resolved among the site's site-vpn records first, so an id of another kind is never deleted. Under dry-run policy nothing is deleted; returns {status: "dry_run", deleted: false, message, response (the preview)}. The dry-run preview contains method, path, params (query parameters), and body.

        Example call (delete_site_to_site_tunnel):
            {"host": "my-console", "site": "Default",
             "tunnel_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            tunnel_id: Site-to-site VPN tunnel id. Get it from list_site_to_site_tunnels
                (data[].id); the Classic networkconf _id also works. Network-app UUID — not a
                Protect id.
        """
        client, registry = deps_fn()
        return await vpn._delete_site_to_site_tunnel(client, registry, host, site, tunnel_id)

    @mcp.tool(annotations=READ_ONLY)
    async def get_vpn_server(
        host: str,
        site: str,
        server_id: str,
    ) -> dict[str, Any]:
        """Get a single VPN server configuration by ID.

        Returns: the VPN server object, verbatim (the Integration overview {id, name, type,
        enabled, metadata}). To change it, pass the native Classic networkconf fields to change
        (e.g. enabled, name) as `fields` to update_vpn_server (server_id = its id). The API has no
        by-id route, so the site's server list is drained and searched; an unknown id fails
        listing every valid name (id), and a list that could not be read completely fails with
        that reason instead of a false "not found".

        Example call (get_vpn_server):
            {
              "host": "my-console",
              "site": "Default",
              "server_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            server_id: VPN server id. Get it from list_vpn_servers (data[].id). Network-app UUID —
                not a Protect id.
        """
        client, registry = deps_fn()
        return await vpn._get_vpn_server(client, registry, host, site, server_id)

    @mcp.tool(annotations=WRITE)
    async def create_vpn_server(
        host: str,
        site: str,
        name: str,
        vpn_type: str,
        subnet: str | None = None,
        enabled: bool | None = None,
        fields: dict[str, Any] | None = None,
    ) -> Any:
        """Create a VPN server (WireGuard, OpenVPN, L2TP or PPTP).

        A Classic networkconf record of purpose remote-user-vpn, written with POST /proxy/network/api/s/{site}/rest/networkconf (the controller UI's route; the Integration API serves VPN servers GET-only, POST answers 405 on Network 11.0.81). The tool sends `fields` plus purpose, name and vpn_type, and ip_subnet/enabled only when you pass subnet/enabled; nothing else is defaulted. The controller answers api.err.InvalidPayload when a field the server type needs is missing (for WireGuard e.g. local_port and the key pair).

        Returns the upstream Classic envelope {meta: {rc}, data: [the created networkconf]}; data[].external_id is the id list_vpn_servers reports. Under dry-run policy nothing is sent: the result is the bare dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params, body}}.

        Example call (create_vpn_server):
            {"host": "my-console", "site": "Default", "name": "Remote access",
             "vpn_type": "wireguard", "subnet": "192.0.2.1/24", "enabled": false,
             "fields": {"local_port": 51820}}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            name: Display name for the VPN server.
            vpn_type: wireguard, openvpn, l2tp or pptp (case-insensitive; sent as the controller's
                wireguard-server, openvpn-server, l2tp-server, pptp-server). Any other value is sent
                unchanged as vpn_type.
            subnet: Client address pool as gateway-IP/prefix, e.g. 192.0.2.1/24; sent as
                ip_subnet, omitted when unset.
            enabled: Whether the new VPN server starts enabled; omitted from the body when unset
                (the controller then applies its own default).
            fields: Optional further native networkconf keys for the server type (e.g. local_port,
                wireguard_interface), merged into the body. An absent or null purpose is
                sent as remote-user-vpn; any other purpose is sent as given (an upstream
                error then gets a hint).
                Name, vpn_type and any explicit subnet / enabled arguments take precedence.
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await vpn._create_vpn_server(
            client,
            registry,
            host,
            site,
            name,
            vpn_type,
            subnet=subnet,
            enabled=enabled,
            fields=fields,
        )

    @mcp.tool(annotations=WRITE)
    async def update_vpn_server(
        host: str,
        site: str,
        server_id: str,
        fields: dict[str, Any],
    ) -> Any:
        """Update a VPN server configuration by ID.

        Classic REST PUT /proxy/network/api/s/{site}/rest/networkconf/{_id} (the UI's route; the Integration API has no VPN-server update, 404 on Network 11.0.81).

        The id is resolved among the remote-user-vpn records first; an unknown id fails listing every VPN server with both ids. Send only the fields to change: the Classic PUT merges them into the stored record.

        Returns the upstream Classic envelope {meta: {rc}, data: [the updated networkconf]}. Under dry-run policy nothing is sent: the bare dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params, body}} in place of the upstream body.

        Example call (update_vpn_server):
            {"host": "my-console", "site": "Default",
             "server_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "fields": {"enabled": false}}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            server_id: VPN server id. Get it from list_vpn_servers (data[].id); the Classic
                networkconf _id also works. Network-app UUID — not a Protect id.
            fields: Native Classic networkconf fields to change, e.g. enabled, name, ip_subnet,
                local_port. Sent unchanged (empty-string list placeholders dropped); an absent or
                null purpose is sent as remote-user-vpn, another is sent as given (an upstream
                error then gets a hint). A purpose-only update is refused.
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await vpn._update_vpn_server(client, registry, host, site, server_id, fields)

    @mcp.tool(annotations=WRITE)
    async def delete_vpn_server(
        host: str,
        site: str,
        server_id: str,
    ) -> dict[str, Any]:
        """Delete a VPN server by ID. WARNING: permanently removes the VPN server.

        Consequence: connected VPN clients lose access immediately and the server configuration is gone; there is no undo.

        Classic REST DELETE /proxy/network/api/s/{site}/rest/networkconf/{_id} (the Integration API has no VPN-server delete). The id is resolved among the site's remote-user-vpn records first, so an id of another kind is never deleted. Under dry-run policy nothing is deleted; returns {status: "dry_run", deleted: false, message, response (the preview)}. The dry-run preview contains method, path, params (query parameters), and body.

        Example call (delete_vpn_server):
            {"host": "my-console", "site": "Default",
             "server_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            server_id: VPN server id. Get it from list_vpn_servers (data[].id); the Classic
                networkconf _id also works. Network-app UUID — not a Protect id.
        """
        client, registry = deps_fn()
        return await vpn._delete_vpn_server(client, registry, host, site, server_id)

    @mcp.tool(annotations=READ_ONLY)
    async def get_radius_profile(
        host: str,
        site: str,
        profile_id: str,
    ) -> dict[str, Any]:
        """Get a single RADIUS authentication profile by ID.

        Returns: the RADIUS profile object, verbatim. The API has no by-id route, so the site's
        profile list is drained and searched; an unknown id fails listing every valid name (id),
        and a list that could not be read completely fails with that reason instead of a false
        "not found".

        Example call (get_radius_profile):
            {
              "host": "my-console",
              "site": "Default",
              "profile_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            profile_id: RADIUS profile id. Get it from list_radius_profiles (data[].id).
        """
        client, registry = deps_fn()
        return await vpn._get_radius_profile(client, registry, host, site, profile_id)

    @mcp.tool(annotations=WRITE)
    async def create_radius_profile(
        host: str,
        site: str,
        name: str,
        auth_server_ip: str,
        auth_server_port: int,
        auth_server_secret: str,
        acct_server_ip: str | None = None,
        acct_server_port: int | None = None,
        acct_server_secret: str | None = None,
        fields: dict[str, Any] | None = None,
    ) -> Any:
        """Create a RADIUS authentication profile.

        Classic REST POST /proxy/network/api/s/{site}/rest/radiusprofile (the UI's route; the Integration API serves RADIUS profiles GET-only, POST answers 405 on Network 11.0.81). The body is `fields` plus name, auth_servers [{ip, port, x_secret}] and, when acct_server_ip is given, acct_servers; port and secret only when given. Nothing is defaulted: accounting stays off unless `fields` sets accounting_enabled.

        Returns the upstream Classic envelope {meta: {rc}, data: [the created radiusprofile]}; data[].external_id is the id list_radius_profiles reports. Under dry-run policy nothing is sent: the result is the bare dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params, body}}.

        Example call (create_radius_profile):
            {"host": "my-console", "site": "Default", "name": "Corp RADIUS",
             "auth_server_ip": "192.0.2.20", "auth_server_port": 1812,
             "auth_server_secret": "s3cret"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            name: Display name for the RADIUS profile.
            auth_server_ip: RADIUS authentication server IP address, e.g. 192.0.2.20.
            auth_server_port: RADIUS authentication UDP port, e.g. 1812.
            auth_server_secret: Shared secret for the authentication server.
            acct_server_ip: Optional accounting server IP address; adds an acct_servers entry.
            acct_server_port: Optional accounting UDP port (e.g. 1813); omitted when unset. It
                belongs with acct_server_ip: without one, the acct_servers entry is sent without
                ip as given, and an upstream error gets a hint.
            acct_server_secret: Optional accounting shared secret; belongs with acct_server_ip
                (sent as given without one; an upstream error then gets a hint).
            fields: Optional further native radiusprofile keys merged into the body, e.g.
                accounting_enabled, interim_update_enabled, vlan_enabled; name and the server
                lists built from the arguments take precedence.
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await vpn._create_radius_profile(
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
            fields=fields,
        )


def register_2(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the vpn family's DNS tools as typed FastMCP functions, in order."""

    def deps() -> tuple[UniFiClient, Registry]:
        return cast(tuple[UniFiClient, Registry], deps_fn())

    @mcp.tool(name="list_static_dns_records", annotations=READ_ONLY)
    async def _list_static_dns_records(host: str, site: str) -> Any:
        """List the site's static DNS records (v2 static-dns, the web app's DNS records).

        Required: host and site. Route: v2 GET static-dns (no published route serves this
        collection; the published dns/policies route is list_dns_policies). Returns the upstream
        body verbatim (a JSON array or object, as sent); each record's _id is the record_id of the
        other static DNS record tools.

        Example call (list_static_dns_records):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
        """
        return await handlers.list_static_dns_records(*deps(), host, site)

    @mcp.tool(name="create_static_dns_record", annotations=WRITE)
    async def _create_static_dns_record(
        host: str, site: str, record: StaticDnsRecord, confirm: bool = False
    ) -> Any:
        """Create a static DNS record (v2 POST static-dns).

        Required: host, site and record. Request body: no published schema; record is
        free-form and sent verbatim, named as list_static_dns_records returns records
        (for example key, value, record_type and enabled). An empty record fails before
        any request. Returns the upstream body verbatim. Dry-run (dry-run policy) returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}}; nothing is sent.

        Example call (create_static_dns_record):
            {"host": "my-console", "site": "Default", "record": {"key": "nas.example.com",
             "value": "192.0.2.20", "record_type": "A", "enabled": true}}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            record: Free-form record object, e.g. {"key": "nas.example.com", "value": "192.0.2.20"}.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        return await handlers.create_static_dns_record(*deps(), host, site, record)

    @mcp.tool(name="update_static_dns_record", annotations=WRITE)
    async def _update_static_dns_record(
        host: str, site: str, record_id: str, record: StaticDnsRecord, confirm: bool = False
    ) -> Any:
        """Update a static DNS record (v2 PUT static-dns/{_id}, read-merge-write).

        Required: host, site, record_id and record. record_id is resolved in list_static_dns_records first; an unknown id fails listing every record and nothing is sent. record holds only the fields to change (free-form, no published schema); they are laid leaf by leaf over the listed record and the whole record is PUT. An empty update fails before any request. Returns the upstream body verbatim plus _verified (type-strict comparison of every requested leaf in a read-after) and _readAfter, or _readAfterError; a non-object write body is returned whole under response with those keys beside it. Dry-run (dry-run policy) returns a dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}; nothing is sent.

        Example call (update_static_dns_record):
            {"host": "my-console", "site": "Default", "record_id": "000000000000000000000107",
             "record": {"value": "192.0.2.21"}}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            record_id: Record _id from list_static_dns_records, e.g. "000000000000000000000107".
            record: Fields to change, e.g. {"value": "192.0.2.21"}. Free-form object.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        return await handlers.update_static_dns_record(*deps(), host, site, record_id, record)

    @mcp.tool(name="delete_static_dns_record", annotations=WRITE)
    async def _delete_static_dns_record(
        host: str, site: str, record_id: str, confirm: bool = False
    ) -> Any:
        """Delete a static DNS record (v2 DELETE static-dns/{_id}).

        Consequence: the name stops resolving through the gateway; there is no undo.
        Required: host, site and record_id. record_id is resolved in
        list_static_dns_records first; an unknown id fails listing every record and
        nothing is deleted. Returns {deleted, message, response} with the upstream body
        verbatim. Dry-run (dry-run policy) returns {status: "dry_run", deleted: false,
        message, response}, where response is the dry-run preview {status: "dry_run",
        dryRun, sent: false, message, preview: {method, path, params, body}}; nothing is sent.

        Example call (delete_static_dns_record):
            {"host": "my-console", "site": "Default", "record_id": "000000000000000000000107"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            record_id: Record _id from list_static_dns_records, e.g. "000000000000000000000107".
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        return await handlers.delete_static_dns_record(*deps(), host, site, record_id)

    @mcp.tool(name="list_doh_servers", annotations=READ_ONLY)
    async def _list_doh_servers(host: str, site: str) -> Any:
        """List the DNS-over-HTTPS server names the gateway offers (v2 settings/doh).

        Required: host and site. Route: v2 GET settings/doh/available-server-names (no
        published route). Returns the upstream body verbatim (a JSON array or object, as sent).

        Example call (list_doh_servers):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
        """
        return await handlers.list_doh_servers(*deps(), host, site)


def register_3(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the N07 VPN tools as typed FastMCP functions.

    The DNS tools register just before them, from the vpn family registrar
    (``registrar.register``), in the order the loader map gives."""

    def deps() -> tuple[UniFiClient, Registry]:
        return cast(tuple[UniFiClient, Registry], deps_fn())

    @mcp.tool(name="get_ipsec_settings", annotations=READ_ONLY)
    async def _get_ipsec_settings(host: str, site: str) -> Any:
        """Get the site's IPsec settings (v2 settings/ipsec).

        Required: host and site. Route: v2 GET settings/ipsec (no published route).
        Returns the upstream object verbatim; a pre-shared key in it is masked only under
        UNIFI_REDACT_SECRETS. Change it with update_ipsec_settings.

        Example call (get_ipsec_settings):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
        """
        return await network_vpn_dns.get_ipsec_settings(*deps(), host, site)

    @mcp.tool(name="update_ipsec_settings", annotations=WRITE)
    async def _update_ipsec_settings(
        host: str, site: str, fields: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Update the site's IPsec settings (v2 POST settings/ipsec, read-merge-write).

        Consequence: IPsec tunnels and remote IPsec users may reconnect.
        Required: host, site and fields. Request body: no published schema; fields is
        free-form and holds only the keys to change, named as get_ipsec_settings returns
        them. The current settings are read, your fields laid over them leaf by leaf and
        the whole object POSTed. An empty update fails before any request. Returns the
        upstream body verbatim plus _verified (type-strict leaf comparison of a
        read-after) and _readAfter, or _readAfterError (a non-object write body is returned
        whole under response with those keys beside it). Dry-run (dry-run policy) returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}}; nothing is sent.

        Example call (update_ipsec_settings):
            {"host": "my-console", "site": "Default", "fields": {"enabled": true}}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            fields: Free-form settings to change, e.g. {"enabled": true}.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        return await network_vpn_dns.update_ipsec_settings(*deps(), host, site, fields)

    @mcp.tool(name="list_vpn_users", annotations=READ_ONLY)
    async def _list_vpn_users(host: str, site: str) -> Any:
        """List the site's remote-access VPN users (v2 vpn/users).

        Required: host and site. Route: v2 GET vpn/users (no published route). Returns the upstream
        body verbatim (a JSON array or object, as sent).

        Example call (list_vpn_users):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
        """
        return await network_vpn_dns.list_vpn_users(*deps(), host, site)

    @mcp.tool(name="list_vpn_connections", annotations=READ_ONLY)
    async def _list_vpn_connections(host: str, site: str) -> Any:
        """List the site's VPN connections (v2 vpn/connections).

        Required: host and site. Route: v2 GET vpn/connections (no published route).
        Returns the upstream body verbatim (a JSON array or object, as sent).

        Example call (list_vpn_connections):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
        """
        return await network_vpn_dns.list_vpn_connections(*deps(), host, site)

    @mcp.tool(name="get_openvpn_client_config", annotations=READ_ONLY)
    async def _get_openvpn_client_config(host: str, site: str, server_id: str) -> Any:
        """Get an OpenVPN server's client configuration (v2 vpn/openvpn/{_id}/configuration).

        Required: host, site and server_id. The configuration is a credential (certificate and
        private key): it is returned as received and masked only under UNIFI_REDACT_SECRETS.
        server_id is resolved among the site's VPN servers first; an unknown id fails listing every
        server. An upstream 404 adds a hint to check for an OpenVPN server on this site.
        Returns the upstream body verbatim (a JSON array or object, as sent) (JSON or text);
        a binary body comes back as {bodyBase64, contentType, sizeBytes}.

        Example call (get_openvpn_client_config):
            {"host": "my-console", "site": "Default", "server_id": "000000000000000000000107"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            server_id: VPN server id from list_vpn_servers or its Classic _id,
                e.g. "000000000000000000000107".
        """
        return await network_vpn_dns.get_openvpn_client_config(*deps(), host, site, server_id)

    @mcp.tool(name="restart_vpn_server", annotations=WRITE)
    async def _restart_vpn_server(
        host: str, site: str, server_id: str, confirm: bool = False
    ) -> Any:
        """Restart one VPN server (v2 POST vpn/{_id}/restart, cmd restart-vpn).

        Consequence: every user connected to this VPN server is disconnected.
        Required: host, site and server_id. Sent once, never retried automatically.
        server_id is resolved among the site's VPN servers first; an unknown id fails
        listing every server and nothing is sent. Returns the upstream body verbatim.
        Dry-run (dry-run policy) returns a dry-run preview {status: "dry_run", dryRun: true, sent:
        false, message, preview: {method, path, params, body}}; nothing is sent.

        Example call (restart_vpn_server):
            {"host": "my-console", "site": "Default", "server_id": "000000000000000000000107"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            server_id: VPN server id from list_vpn_servers or its Classic _id,
                e.g. "000000000000000000000107".
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        return await network_vpn_dns.restart_vpn_server(*deps(), host, site, server_id)

    @mcp.tool(name="list_wireguard_users", annotations=READ_ONLY)
    async def _list_wireguard_users(host: str, site: str, server_id: str | None = None) -> Any:
        """List WireGuard VPN users (v2 wireguard/users or wireguard/{_id}/users).

        Required: host and site. Without server_id every WireGuard server's users are listed; with
        it only that server's (resolved among the site's VPN servers first; an unknown id fails
        listing every server). Returns the upstream body verbatim (a JSON array or object, as sent);
        key fields are masked only under UNIFI_REDACT_SECRETS.

        Example call (list_wireguard_users):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            server_id: Optional WireGuard server id from list_vpn_servers or its Classic _id,
                e.g. "000000000000000000000107".
        """
        return await network_vpn_dns.list_wireguard_users(*deps(), host, site, server_id)

    @mcp.tool(name="list_wireguard_used_subnets", annotations=READ_ONLY)
    async def _list_wireguard_used_subnets(host: str, site: str) -> Any:
        """List the subnets WireGuard users already use (v2 wireguard/users/existing-subnets).

        Required: host and site. Route: v2 GET (no published route). Returns the upstream body
        verbatim (a JSON array or object, as sent).

        Example call (list_wireguard_used_subnets):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
        """
        return await network_vpn_dns.list_wireguard_used_subnets(*deps(), host, site)

    @mcp.tool(name="create_wireguard_users", annotations=WRITE)
    async def _create_wireguard_users(
        host: str,
        site: str,
        server_id: str,
        users: list[dict[str, Any]],
        confirm: bool = False,
    ) -> Any:
        """Create WireGuard users on one server (v2 POST wireguard/{_id}/users/batch).

        Consequence: issues VPN credentials; each new peer can reach the network. Required: host,
        site, server_id and users. Request body: no published schema; users is a free-form JSON
        array of user objects sent verbatim (the web app's batch body), named as
        list_wireguard_users returns users. Keys are passed through and masked only under
        UNIFI_REDACT_SECRETS. server_id is resolved among the site's VPN servers first. Returns the
        upstream body verbatim. Dry-run (dry-run policy) returns a dry-run preview {status:
        "dry_run", dryRun: true, sent: false, message, preview: {method, path, params, body}};
        nothing is sent.

        Example call (create_wireguard_users):
            {"host": "my-console", "site": "Default", "server_id": "000000000000000000000107",
             "users": [{"name": "laptop-01", "interface_ip": "192.0.2.10"}]}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            server_id: WireGuard server id from list_vpn_servers or its Classic _id,
                e.g. "000000000000000000000107".
            users: Non-empty free-form array of user objects (an empty list fails before any
                request), e.g. [{"name": "laptop-01"}].
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        return await network_vpn_dns.create_wireguard_users(*deps(), host, site, server_id, users)

    @mcp.tool(name="update_wireguard_users", annotations=WRITE)
    async def _update_wireguard_users(
        host: str,
        site: str,
        server_id: str,
        users: list[dict[str, Any]],
        confirm: bool = False,
    ) -> Any:
        """Update WireGuard users on one server (v2 PUT wireguard/{_id}/users/batch).

        Consequence: changed keys or addresses disconnect the affected peers. Required: host, site, server_id and users. Each users item names a user by _id (from list_wireguard_users) plus only the fields to change (free-form; no published schema). Every _id is resolved in the server's user list first; an unknown _id fails listing every user and nothing is sent; an item with nothing to change fails before any request. Each listed record with your fields laid over it leaf by leaf is PUT as one array. Returns the upstream body verbatim plus _verified (type-strict, every requested leaf of every user) and _readAfter, or _readAfterError (a non-object write body is returned whole under response with those keys beside it). Dry-run (dry-run policy) returns a dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Example call (update_wireguard_users):
            {"host": "my-console", "site": "Default", "server_id": "000000000000000000000107",
             "users": [{"_id": "000000000000000000000108", "name": "laptop-02"}]}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            server_id: WireGuard server id from list_vpn_servers or its Classic _id,
                e.g. "000000000000000000000107".
            users: Non-empty array of _id plus fields to change (an empty list fails before any
                request), e.g. [{"_id": "000000000000000000000108", "name": "laptop-02"}].
                Shape: {_id:string,...}[]; the other keys of each entry are the fields to change
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        return await network_vpn_dns.update_wireguard_users(*deps(), host, site, server_id, users)

    @mcp.tool(name="delete_wireguard_users", annotations=WRITE)
    async def _delete_wireguard_users(
        host: str,
        site: str,
        server_id: str,
        users: list[str | dict[str, Any]],
        confirm: bool = False,
    ) -> Any:
        """Delete WireGuard users from one server (v2 POST wireguard/{_id}/users/batch_delete).

        Consequence: the peers lose VPN access at once; there is no undo. Required: host, site, server_id and users. users is the batch_delete array sent verbatim (no published schema): user _id strings or user objects carrying _id, from list_wireguard_users. Every _id is resolved in the server's user list first; an unknown _id fails listing every user and nothing is deleted. Returns {deleted, message, response} with the upstream body verbatim. Dry-run (dry-run policy) returns {status: "dry_run", deleted: false, message, response}, where response is the dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}; nothing is sent.

        Example call (delete_wireguard_users):
            {"host": "my-console", "site": "Default", "server_id": "000000000000000000000107",
             "users": ["000000000000000000000108"]}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            server_id: WireGuard server id from list_vpn_servers or its Classic _id,
                e.g. "000000000000000000000107".
            users: Non-empty list of user _ids or objects with _id (an empty list fails before
                any request), e.g. ["000000000000000000000108"].
                Shape: (string|{_id:string,...})[]; each entry is sent as given
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        return await network_vpn_dns.delete_wireguard_users(
            *deps(), host, site, server_id, list(users)
        )

    @mcp.tool(name="create_teleport_invitation", annotations=WRITE)
    async def _create_teleport_invitation(
        host: str, site: str, body: dict[str, Any] | None = None, confirm: bool = False
    ) -> Any:
        """Create a Teleport invitation (v2 POST teleport/token).

        Consequence: issues a credential; whoever holds the link can join the network
        through Teleport until it is used or revoked (revoke_teleport_invitation).
        Required: host and site. The web app sends no body; body is optional, free-form
        and sent verbatim when given. Returns the upstream body verbatim (the token and
        invitation link, masked only under UNIFI_REDACT_SECRETS). Dry-run (dry-run policy)
        returns a dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview:
        {method, path, params, body}}; nothing is sent.

        Example call (create_teleport_invitation):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            body: Optional free-form request body, e.g. {"name": "guest-laptop"}.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        return await network_vpn_dns.create_teleport_invitation(*deps(), host, site, body)

    @mcp.tool(name="revoke_teleport_invitation", annotations=WRITE)
    async def _revoke_teleport_invitation(
        host: str, site: str, invitation_id: str, confirm: bool = False
    ) -> Any:
        """Revoke a Teleport invitation (v2 DELETE teleport/token/{id}).

        Consequence: the invitation link stops working; there is no undo.
        Required: host, site and invitation_id (from query_teleport_invitations). No GET
        route lists invitations by id, so the id is sent as given and the controller
        judges it. Returns {deleted, message, response} with the upstream body verbatim.
        Dry-run (dry-run policy) returns {status: "dry_run", deleted: false, message,
        response}, where response is the dry-run preview {status: "dry_run", dryRun, sent: false,
        message, preview: {method, path, params, body}}; nothing is sent.

        Example call (revoke_teleport_invitation):
            {"host": "my-console", "site": "Default", "invitation_id": "000000000000000000000107"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            invitation_id: Invitation id from query_teleport_invitations,
                e.g. "000000000000000000000107".
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        return await network_vpn_dns.revoke_teleport_invitation(*deps(), host, site, invitation_id)

    @mcp.tool(name="query_teleport_invitations", annotations=WRITE)
    async def _query_teleport_invitations(
        host: str,
        site: str,
        page_number: int | None = None,
        page_size: int | None = None,
        confirm: bool = False,
    ) -> Any:
        """List Teleport invitation history (v2 POST teleport/invitation-history).

        Required: host and site. A read sent as POST (Consequence: none intended; it only reads the history): it is not on the read-POST allowlist, so it is classed as a write: UNIFI_WRITE_POLICY=deny refuses it, and under dry-run policy it returns a dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} of the first page and sends nothing. Without a requested total every page is read (pageNumber 0, 1, ... to the end) and the records are joined under data, adding _count and _pages; a stopped drain (page cap, repeated page, a later page without records) adds incomplete: true and incompleteReason. Returns that joined object. An empty first page is returned verbatim; a first page without a data array is returned verbatim plus _pages and _drainNote. page_number alone returns that page verbatim. page_size alone is window 0: exactly page_size records from record 0; _nextPage counts page_size windows, so resume with page_number=_nextPage and the same page_size. page_number with page_size returns that window. Omit both to drain every record. _pageSize reports the requested count, sent (every pageSize sent, in request order), the effective console page size and the returned count. _nextPage is absent when no record follows the window or the call stopped incomplete.

        Example call (query_teleport_invitations):
            {"host": "my-console", "site": "Default"}

        Write class: its POST is not read-POST allowlisted, so UNIFI_WRITE_POLICY=deny hides the whole tool and discovery mode runs it through call_write_tool.

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            page_number: Zero-based page. With page_size, returns exactly page_size records
                starting at record page_number * page_size, gathered across console pages
                whatever the console page size; resume with _nextPage and the same page_size.
                Without page_size, one request returns that console page verbatim. Example: 0.
            page_size: Number of invitations. Alone, window 0 (the first page_size records,
                fewer only at the end); with page_number, the size of the window. Omit to
                drain all. Example: `100`.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        return await network_vpn_dns.query_teleport_invitations(
            *deps(), host, site, page_number, page_size
        )

    @mcp.tool(name="remove_teleport_client", annotations=WRITE)
    async def _remove_teleport_client(
        host: str,
        site: str,
        client_id: str,
        body: dict[str, Any] | None = None,
        confirm: bool = False,
    ) -> Any:
        """Remove a Teleport client (v2 DELETE teleport/client/{id}).

        Consequence: the client loses Teleport access and must be invited again.

        No GET route lists Teleport clients by id, so the id is sent as given and the controller judges it. body is optional, free-form (shape not published) and sent verbatim when given. Dry-run (dry-run policy) returns {status: "dry_run", deleted: false, message, response}, response being the dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}; nothing is sent.

        Example call (remove_teleport_client):
            {"host": "my-console", "site": "Default", "client_id": "000000000000000000000107"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            client_id: Teleport client id from list_vpn_connections,
                e.g. "000000000000000000000107".
            body: Optional free-form request body, e.g. {"name": "guest-laptop"}.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        return await network_vpn_dns.remove_teleport_client(*deps(), host, site, client_id, body)

    @mcp.tool(name="list_magic_site_vpn", annotations=READ_ONLY)
    async def _list_magic_site_vpn(host: str, site: str) -> Any:
        """List Site Magic site-to-site VPN configurations (v2 magicsitetositevpn/configs).

        Required: host and site. Route: v2 GET (GET-only; change site VPNs with create_site_vpn,
        control_site_vpn and delete_site_vpn). Returns the upstream body verbatim (a JSON array or
        object, as sent).

        Example call (list_magic_site_vpn):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
        """
        return await network_vpn_dns.list_magic_site_vpn(*deps(), host, site)

    @mcp.tool(name="create_site_vpn", annotations=WRITE)
    async def _create_site_vpn(
        host: str, site: str, params: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Create a site VPN (Classic POST cmd/sitemgr, cmd add-site-vpn).

        Consequence: builds a VPN between controller sites; routing between them changes.
        Required: host, site and params. Request body: no published schema and no
        captured body; params is free-form and sent verbatim beside cmd. Success requires
        meta.rc ok; any other answer raises with the full upstream body. Returns the
        Classic {meta, data} envelope verbatim. Dry-run (dry-run policy) returns a dry-run
        preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path,
        params, body}}; nothing is sent.

        Example call (create_site_vpn):
            {"host": "my-console", "site": "Default", "params": {"site": "branch-1"}}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            params: Free-form add-site-vpn parameters, e.g. {"site": "branch-1"}.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        return await network_vpn_dns.create_site_vpn(*deps(), host, site, params)

    @mcp.tool(name="delete_site_vpn", annotations=WRITE)
    async def _delete_site_vpn(
        host: str, site: str, name: str, vpn_site: str, confirm: bool = False
    ) -> Any:
        """Delete a site VPN (Classic POST cmd/sitemgr, cmd delete-site-vpn).

        Consequence: the VPN between the sites is torn down; there is no undo.

        Sends {cmd: delete-site-vpn, name, site: vpn_site} as the web app does; the controller judges both values. Success requires meta.rc ok; any other answer raises with the full upstream body. Dry-run (dry-run policy) returns {status: "dry_run", deleted: false, message, response}, response being the dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}; nothing is sent.

        Example call (delete_site_vpn):
            {"host": "my-console", "site": "Default", "name": "branch-vpn", "vpn_site": "branch-1"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            name: Site VPN name, e.g. "branch-vpn".
            vpn_site: The peer site sent as the body's site, e.g. "branch-1".
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        return await network_vpn_dns.delete_site_vpn(*deps(), host, site, name, vpn_site)

    @mcp.tool(name="control_site_vpn", annotations=WRITE)
    async def _control_site_vpn(
        host: str,
        site: str,
        action: SiteVpnAction,
        name: str | None = None,
        vpn_site: str | None = None,
        params: dict[str, Any] | None = None,
        confirm: bool = False,
    ) -> Any:
        """Enable, disable or rebuild a site VPN (Classic POST cmd/sitemgr).

        Consequence: disable and rebuild interrupt traffic between the sites.
        Required: host, site and action. Sends cmd enable-site-vpn, disable-site-vpn or
        rebuild-site-vpn with name and site (vpn_site) when given (the web app's
        enable/disable body) plus any free-form params (rebuild has no captured body).
        Success requires meta.rc ok; any other answer raises with the full upstream body.
        Returns the Classic {meta, data} envelope verbatim. Dry-run (dry-run policy) returns
        a dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}}; nothing is sent.

        Example call (control_site_vpn):
            {"host": "my-console", "site": "Default", "action": "disable",
             "name": "branch-vpn", "vpn_site": "branch-1"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            action: One of enable, disable, rebuild, e.g. "disable".
            name: Site VPN name, e.g. "branch-vpn".
            vpn_site: The peer site sent as the body's site, e.g. "branch-1".
            params: Optional free-form extra parameters, e.g. {"name": "branch-vpn"}.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        return await network_vpn_dns.control_site_vpn(
            *deps(), host, site, action, name, vpn_site, params
        )


def register_4(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the RADIUS profile update and delete tools."""

    @mcp.tool(annotations=WRITE)
    async def update_radius_profile(
        host: str, site: str, profile_id: str, profile: dict[str, Any]
    ) -> Any:
        """Update a RADIUS profile via Classic REST PUT rest/radiusprofile/{_id} (the UI's route; the Integration API is GET-only).

        The id (list_radius_profiles id = external_id, or the Classic _id) is resolved first; an unknown id fails listing every profile and nothing is sent. auth_servers/acct_servers replace the whole server list: send every server to keep, each {ip, port, x_secret}.

        Returns the upstream body verbatim, {meta: {rc}, data: [the updated profile]}. Additive _warnings (NO_ID_RETURNED, NOT_STORED_AS_SENT: field names only) report a write that did not land as sent. Under dry-run policy nothing is sent: the bare dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params, body}}.

        Example call (update_radius_profile):
            {"host": "my-console", "site": "Default",
             "profile_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
             "profile": {"interim_update_enabled": true}}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            profile_id: RADIUS profile id from list_radius_profiles (data[].id) or its Classic
                _id.
            profile: Native radiusprofile fields to change. Free-form JSON object; no published
                body shape.
        """
        client, registry = deps_fn()
        return await _update_config_record(
            client, registry, host, site, RADIUS_PROFILES, profile_id, "profile_id", profile
        )

    @mcp.tool(annotations=WRITE)
    async def delete_radius_profile(host: str, site: str, profile_id: str) -> dict[str, Any]:
        """Delete a RADIUS profile via Classic REST DELETE rest/radiusprofile/{_id}.

        Consequence: WiFi networks and ports using the profile for 802.1X lose their RADIUS servers (the controller refuses while one still uses it and returns its error). There is no undo.

        The id (list_radius_profiles id = external_id, or the Classic _id) is resolved first, so an unknown id is never reported as deleted. Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false, message, response (the dry-run preview with method, path, params (query parameters), body)}.

        Example call (delete_radius_profile):
            {"host": "my-console", "site": "Default",
             "profile_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            profile_id: RADIUS profile id from list_radius_profiles (data[].id) or its Classic
                _id.
        """
        client, registry = deps_fn()
        return await _delete_config_record(
            client, registry, host, site, RADIUS_PROFILES, profile_id, "profile_id"
        )


def register_5(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the VPN client MCP tools."""

    @mcp.tool(annotations=READ_ONLY)
    async def list_vpn_clients(
        host: str,
        site: str,
    ) -> Any:
        """List the gateway's VPN client connections (outbound WireGuard, OpenVPN, PPTP).

        Reads Classic REST GET network/api/s/{site}/rest/networkconf (the published Integration
        API has no VPN-client list). Returns the complete upstream envelope and data unchanged,
        with an additive _vpn_clients view containing only records of purpose vpn-client.
        Each VPN-client record is verbatim: _id, external_id, name, enabled,
        vpn_type (wireguard-client, openvpn-client, pptp-client), the peer settings and the
        x_-prefixed credential fields (x_wireguard_private_key, x_openvpn_password, ...), which
        are returned as stored unless the operator opted in to UNIFI_REDACT_SECRETS.

        Example call (list_vpn_clients):
            {
              "host": "my-console",
              "site": "Default"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await vpn_clients._list_vpn_clients(client, registry, host, site)

    @mcp.tool(annotations=WRITE)
    async def create_vpn_client(
        host: str,
        site: str,
        name: str,
        vpn_type: str,
        enabled: bool | None = None,
        fields: dict[str, Any] | None = None,
    ) -> Any:
        """Create a VPN client connection on the gateway (WireGuard, OpenVPN or PPTP).

        Consequence: an enabled client makes the gateway connect to the peer, and vpn_client_default_route true sends routed traffic through the tunnel; create it with enabled false to review first.

        A Classic networkconf record of purpose vpn-client, POST network/api/s/{site}/rest/networkconf (the UI's route). The body is `fields` plus purpose, name, vpn_type, and enabled only when given. The controller validates it: a manual WireGuard client needs wireguard_client_mode "manual", wireguard_client_peer_ip/_peer_port/_peer_public_key, x_wireguard_private_key, ip_subnet and an interface DNS server (dhcpd_dns_enabled true with dhcpd_dns_1), else api.err.WireguardMissingInterfaceDns (verified on Network 11.0.81); upstream errors get a hint listing them.

        Returns the Classic body verbatim {meta: {rc}, data: [the created networkconf]}; under dry-run policy, the preview instead.

        Dry-run preview: {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Example call (create_vpn_client):
            {
              "host": "my-console",
              "site": "Default",
              "name": "Office tunnel",
              "vpn_type": "wireguard",
              "enabled": false,
              "fields": {
                "wireguard_client_mode": "manual",
                "wireguard_client_peer_ip": "203.0.113.7",
                "wireguard_client_peer_port": 51820,
                "wireguard_client_peer_public_key": "PEER_PUBLIC_KEY_BASE64",
                "x_wireguard_private_key": "OWN_PRIVATE_KEY_BASE64",
                "ip_subnet": "10.8.0.2/32",
                "dhcpd_dns_enabled": true,
                "dhcpd_dns_1": "10.8.0.1"
              }
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            name: Display name for the VPN client, e.g. "Office tunnel".
            vpn_type: wireguard, openvpn or pptp (case-insensitive; sent as the controller's
                wireguard-client, openvpn-client, pptp-client). Any other value is sent unchanged
                as vpn_type.
            enabled: Whether the client starts enabled; omitted from the body when unset (the
                controller then applies its own default).
            fields: Further native networkconf keys for the client type (see above), merged into
                the body; name, vpn_type and an explicit enabled take precedence. An absent or
                null purpose is sent as vpn-client; another is sent as given (an upstream error
                then gets a hint).
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await vpn_clients._create_vpn_client(
            client, registry, host, site, name, vpn_type, enabled=enabled, fields=fields
        )

    @mcp.tool(annotations=WRITE)
    async def update_vpn_client(
        host: str,
        site: str,
        vpn_client_id: str,
        fields: dict[str, Any],
    ) -> Any:
        """Update a VPN client connection by id.

        Consequence: changes to an enabled client apply to its live tunnel; traffic routed over it can pause while the tunnel reconnects.

        Classic REST PUT network/api/s/{site}/rest/networkconf/{_id}. The id is resolved among the site's vpn-client records first; an unknown id fails listing every VPN client with both ids and nothing is sent. Send only the fields to change: the Classic PUT merges them into the stored record (a rename reads back on Network 11.0.81).

        Returns the Classic body verbatim {meta: {rc}, data: [the updated networkconf]} (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params (query parameters), body}} instead).

        Example call (update_vpn_client):
            {"host": "my-console", "site": "Default", "vpn_client_id": "000000000000000000000102",
             "fields": {"enabled": true}}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            vpn_client_id: The VPN client's networkconf _id or external_id, from
                list_vpn_clients (_vpn_clients[]._id or _vpn_clients[].external_id).
            fields: Native Classic networkconf fields to change, e.g. enabled, name,
                wireguard_client_peer_ip. Sent unchanged (empty-string list placeholders
                dropped); an absent or null purpose is sent as vpn-client, another is sent as
                given (an upstream error then gets a hint). A purpose-only update is refused.
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await vpn_clients._update_vpn_client(
            client, registry, host, site, vpn_client_id, fields
        )

    @mcp.tool(annotations=WRITE)
    async def delete_vpn_client(
        host: str,
        site: str,
        vpn_client_id: str,
    ) -> dict[str, Any]:
        """Delete a VPN client connection by id. Permanently removes its configuration.

        Consequence: the tunnel and its configuration are removed, and traffic routed over it is affected; there is no undo.

        Classic REST DELETE network/api/s/{site}/rest/networkconf/{_id}. The id is resolved among the site's vpn-client records first, so an id of another kind is never deleted. Under dry-run policy nothing is deleted; returns {status: "dry_run", deleted: false, message, response (the dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params (query parameters), body}})}.

        Example call (delete_vpn_client):
            {"host": "my-console", "site": "Default", "vpn_client_id": "000000000000000000000102"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            vpn_client_id: The VPN client's networkconf _id or external_id, from
                list_vpn_clients (_vpn_clients[]._id or _vpn_clients[].external_id).
        """
        client, registry = deps_fn()
        return await vpn_clients._delete_vpn_client(client, registry, host, site, vpn_client_id)
