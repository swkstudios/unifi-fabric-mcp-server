"""VPN client tools: the gateway's outbound VPN connections (WireGuard, OpenVPN, PPTP).

A VPN client is a Classic REST ``networkconf`` record of purpose ``vpn-client``
(``/proxy/network/api/s/{site}/rest/networkconf``), the route the controller's own UI
writes; the published Network Integration API has no VPN-client resource. Proven live on
Network 11.0.81 with a disabled synthetic WireGuard client (create, rename read back,
delete): a manual WireGuard client needs ``wireguard_client_mode``,
``wireguard_client_peer_ip`` / ``_port`` / ``_public_key``, ``x_wireguard_private_key``,
``ip_subnet`` and an interface DNS server (``dhcpd_dns_enabled`` true with
``dhcpd_dns_1``; without it the controller answers ``api.err.WireguardMissingInterfaceDns``).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastmcp import FastMCP

from ...client import UniFiClient
from ...registry import Registry
from ...shared_shapes._classic_objects import (
    _classic_data,
    addressed_body,
    classic_rest,
    of_purpose,
    purpose_hint,
    resolve_networkconf,
    resolve_networkconf_record,
    resolve_site_slug,
    with_purpose,
)
from ...shared_shapes._keys import with_context
from ...shared_shapes._payload import strip_empty_list_values, with_upstream_hint
from ...shared_shapes._results import deletion_result
from ...tool_annotations import READ_ONLY, WRITE

_VPN_CLIENT = "vpn-client"
_KIND = "VPN client"
_LIST_TOOL = "list_vpn_clients"

# Short VPN client type names mapped to the controller's networkconf vpn_type values
# (go-unifi Network.VPNType). Any other value is sent unchanged.
_VPN_CLIENT_TYPES = {
    "wireguard": "wireguard-client",
    "openvpn": "openvpn-client",
    "pptp": "pptp-client",
}

#: Hint appended to an upstream error of a create: the fields the live probe needed.
_CREATE_HINT = (
    "create_vpn_client: a manual WireGuard client (vpn_type wireguard) needs, in fields, "
    "wireguard_client_mode 'manual', wireguard_client_peer_ip, wireguard_client_peer_port, "
    "wireguard_client_peer_public_key, x_wireguard_private_key, ip_subnet (the tunnel "
    "address, e.g. 10.8.0.2/32) and an interface DNS server: dhcpd_dns_enabled true with "
    "dhcpd_dns_1 (api.err.WireguardMissingInterfaceDns without it). An OpenVPN client takes "
    "openvpn_configuration (the .ovpn text) and, when the server asks, openvpn_username / "
    "x_openvpn_password."
)


async def _list_vpn_clients(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    path = classic_rest(host_id, site_slug, "/networkconf")
    body = await client.get(path, key=key)
    records = _classic_data(body, path)
    return with_context(body, {"_vpn_clients": of_purpose(records, _VPN_CLIENT)})


async def _create_vpn_client(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    name: str,
    vpn_type: str,
    *,
    enabled: bool | None,
    fields: dict[str, Any] | None,
) -> Any:
    body = with_purpose("create_vpn_client", dict(fields or {}), _VPN_CLIENT)
    body["name"] = name
    body["vpn_type"] = _VPN_CLIENT_TYPES.get(vpn_type.lower(), vpn_type)
    if enabled is not None:
        body["enabled"] = enabled
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    return await with_upstream_hint(
        client.post(classic_rest(host_id, site_slug, "/networkconf"), key=key, json=body),
        purpose_hint("create_vpn_client", fields or {}, _VPN_CLIENT) or _CREATE_HINT,
    )


async def _update_vpn_client(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    vpn_client_id: str,
    fields: dict[str, Any],
    /,
) -> Any:
    body = strip_empty_list_values(with_purpose("update_vpn_client", fields, _VPN_CLIENT))
    key, host_id, site_slug, record = await resolve_networkconf_record(
        client,
        registry,
        host,
        site,
        vpn_client_id,
        _VPN_CLIENT,
        _KIND,
        _LIST_TOOL,
        "vpn_client_id",
    )
    classic_id = record["_id"]
    return await with_upstream_hint(
        client.put(
            classic_rest(host_id, site_slug, f"/networkconf/{classic_id}"),
            key=key,
            json=addressed_body(body, classic_id, record.get("external_id")),
        ),
        purpose_hint("update_vpn_client", fields, _VPN_CLIENT),
    )


async def _delete_vpn_client(
    client: UniFiClient, registry: Registry, host: str, site: str, vpn_client_id: str
) -> dict[str, Any]:
    key, host_id, site_slug, classic_id = await resolve_networkconf(
        client,
        registry,
        host,
        site,
        vpn_client_id,
        _VPN_CLIENT,
        _KIND,
        _LIST_TOOL,
        "vpn_client_id",
    )
    response = await client.delete(
        classic_rest(host_id, site_slug, f"/networkconf/{classic_id}"), key=key
    )
    return deletion_result(f"VPN client {vpn_client_id} deleted.", response)


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
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
        return await _list_vpn_clients(client, registry, host, site)

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

        Consequence: an enabled VPN client makes the gateway connect to the peer, and
        vpn_client_default_route true sends routed traffic through the tunnel; create it with
        enabled false to review it first.

        A VPN client is a Classic REST networkconf record of purpose vpn-client, written with
        POST network/api/s/{site}/rest/networkconf (the route the controller's own UI uses).
        The body is `fields` plus purpose, name and vpn_type, and enabled only when given;
        nothing else is defaulted. The controller validates the record: a manual WireGuard
        client needs wireguard_client_mode "manual", wireguard_client_peer_ip / _peer_port /
        _peer_public_key, x_wireguard_private_key, ip_subnet and an interface DNS server
        (dhcpd_dns_enabled true with dhcpd_dns_1), and answers
        api.err.WireguardMissingInterfaceDns without the DNS server (verified on Network
        11.0.81). An upstream error gets a hint listing those fields.

        Returns the upstream Classic body verbatim: {meta: {rc}, data: [the created networkconf
        record]} (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent:
        false, message, preview: {method, path, params (query parameters), body}} instead).

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
        return await _create_vpn_client(
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

        Consequence: changes to an enabled client apply to its live tunnel; traffic routed over
        it can pause while the tunnel reconnects.

        Uses Classic REST PUT network/api/s/{site}/rest/networkconf/{_id} (the route the
        controller's own UI uses). The id is resolved among the site's vpn-client records
        first; an unknown id fails listing every VPN client with both ids, and nothing is
        sent. Send only the fields to change: the Classic PUT merges them into the stored
        record (verified on Network 11.0.81: a rename reads back).

        Returns the upstream Classic body verbatim: {meta: {rc}, data: [the updated networkconf
        record]} (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent:
        false, message, preview: {method, path, params (query parameters), body}} instead).

        Example call (update_vpn_client):
            {
              "host": "my-console",
              "site": "Default",
              "vpn_client_id": "000000000000000000000102",
              "fields": {"enabled": true}
            }

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
        return await _update_vpn_client(client, registry, host, site, vpn_client_id, fields)

    @mcp.tool(annotations=WRITE)
    async def delete_vpn_client(
        host: str,
        site: str,
        vpn_client_id: str,
    ) -> dict[str, Any]:
        """Delete a VPN client connection by id. This permanently removes its configuration.

        Consequence: the tunnel and its configuration are removed, and traffic that routes over
        it is affected; there is no undo.

        Uses Classic REST DELETE network/api/s/{site}/rest/networkconf/{_id} (the route the
        controller's own UI uses). The id is resolved among the site's vpn-client records
        first, so an id of another kind is never deleted.

        Returns {deleted: true, message, response}; response is the upstream DELETE body verbatim
        (decoded JSON, the raw text of a non-JSON body, or null when the body is empty).
        Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false, message,
        response (the preview {status: "dry_run", dryRun: true, sent: false, message, preview:
        {method, path, params (query parameters), body}})}.

        Example call (delete_vpn_client):
            {
              "host": "my-console",
              "site": "Default",
              "vpn_client_id": "000000000000000000000102"
            }

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
        return await _delete_vpn_client(client, registry, host, site, vpn_client_id)
