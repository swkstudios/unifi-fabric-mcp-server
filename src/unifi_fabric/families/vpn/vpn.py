"""VPN server and RADIUS profile CRUD tools — manage VPN and auth services."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastmcp import FastMCP

from ...client import (
    UniFiClient,
    UniFiConnectionError,
    describe_shape,
    upstream_error_value,
    validate_id,
)
from ...matching import find_by_id
from ...registry import Registry
from ...shared_shapes._classic_objects import (
    _object_rows,
    addressed_body,
    classic_rest,
    purpose_hint,
    resolve_networkconf,
    resolve_networkconf_record,
    resolve_site_slug,
    with_purpose,
)
from ...shared_shapes._keys import context_value
from ...shared_shapes._payload import (
    missing_fields_hint,
    strip_empty_list_values,
    with_upstream_hint,
)
from ...shared_shapes._results import deletion_result
from ...tool_annotations import READ_ONLY, WRITE
from ..network.network_services_proxy import (
    list_radius_profiles as _proxy_list_radius_profiles,
)
from ..network.network_services_proxy import (
    list_vpn_servers as _proxy_list_vpn_servers,
)

# ---------------------------------------------------------------------------
# Site-to-site tunnels
# ---------------------------------------------------------------------------


_S2S = "site-vpn"
_VPN_SERVER = "remote-user-vpn"


async def _create_site_to_site_tunnel(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    tunnel: dict[str, Any],
    /,
) -> Any:
    """Create a site-to-site VPN tunnel: a Classic networkconf record of purpose site-vpn.

    POST /proxy/network/api/s/{site}/rest/networkconf with the caller's native body plus
    ``purpose: site-vpn``; the upstream ``{meta, data}`` envelope is returned verbatim.
    """
    hint = purpose_hint("create_site_to_site_tunnel", tunnel, _S2S) or missing_fields_hint(
        "create_site_to_site_tunnel",
        tunnel,
        ("name", "vpn_type"),
        "a site-to-site tunnel record is created from them; vpn_type is ipsec-vpn, "
        "openvpn-vpn or wireguard-vpn",
    )
    body = with_purpose("create_site_to_site_tunnel", tunnel, _S2S)
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    return await with_upstream_hint(
        client.post(classic_rest(host_id, site_slug, "/networkconf"), key=key, json=body), hint
    )


async def _update_site_to_site_tunnel(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    tunnel_id: str,
    tunnel: dict[str, Any],
    /,
) -> Any:
    """Update a site-to-site tunnel (Integration id or Classic ``_id``) via Classic networkconf.

    The id is resolved among the site's ``site-vpn`` networkconf records; PUT
    rest/networkconf/{_id} sends the caller's fields (the Classic PUT merges them into the
    stored record) and the upstream envelope is returned verbatim.
    """
    body = strip_empty_list_values(with_purpose("update_site_to_site_tunnel", tunnel, _S2S))
    key, host_id, site_slug, record = await resolve_networkconf_record(
        client,
        registry,
        host,
        site,
        tunnel_id,
        _S2S,
        "Site-to-site VPN tunnel",
        "list_site_to_site_tunnels",
        "tunnel_id",
    )
    classic_id = record["_id"]
    return await with_upstream_hint(
        client.put(
            classic_rest(host_id, site_slug, f"/networkconf/{classic_id}"),
            key=key,
            json=addressed_body(body, classic_id, record.get("external_id")),
        ),
        purpose_hint("update_site_to_site_tunnel", tunnel, _S2S),
    )


async def _delete_site_to_site_tunnel(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    tunnel_id: str,
) -> dict[str, Any]:
    """Delete a site-to-site tunnel (Integration id or Classic ``_id``) via Classic networkconf."""
    key, host_id, site_slug, classic_id = await resolve_networkconf(
        client,
        registry,
        host,
        site,
        tunnel_id,
        _S2S,
        "Site-to-site VPN tunnel",
        "list_site_to_site_tunnels",
        "tunnel_id",
    )
    response = await client.delete(
        classic_rest(host_id, site_slug, f"/networkconf/{classic_id}"), key=key
    )
    return deletion_result(f"Site-to-site VPN tunnel {tunnel_id} deleted.", response)


# ---------------------------------------------------------------------------
# VPN servers
# ---------------------------------------------------------------------------


def _select_by_id(
    result: Any, wanted: str, kind: str, list_tool: str, path_label: str
) -> dict[str, Any]:
    """Pick the record whose ``id`` is ``wanted`` out of a drained Integration list result.

    An unexpected result shape raises with the shape received. An unknown id fails listing
    every valid ``name (id)``; when the drain stopped short (``incomplete``) the error says
    so and carries the reason instead of claiming the id does not exist.
    """
    items = result.get("data") if isinstance(result, dict) else None
    if not isinstance(items, list):
        raise UniFiConnectionError(
            f"Unexpected {path_label} list shape: expected an object with a 'data' array, "
            f"got {describe_shape(result)}"
        )
    records = _object_rows(items, path_label)
    record = find_by_id(records, wanted, "id")
    if record is not None:
        # Exact identity is resolved even if later collection pages were not read.
        return record
    valid = (
        ", ".join(
            f"{upstream_error_value(r.get('name'))} ({upstream_error_value(r.get('id'))})"
            for r in records
        )
        or "(none)"
    )
    if isinstance(result, dict) and context_value(result, "incomplete", strict=True):
        reason = context_value(result, "incompleteReason", strict=True)
        raise ValueError(
            f"{kind} {wanted!r} was not among the {len(records)} {kind}(s) read, but the list "
            f"is incomplete ({upstream_error_value(reason)}), so it may exist past the "
            f"pages read. Read so far: {valid}. Get ids from {list_tool} (data[].id)."
        )
    raise ValueError(
        f"{kind} {wanted!r} not found; valid: {valid}. Get ids from {list_tool} (data[].id)."
    )


async def _get_vpn_server(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    server_id: str,
) -> dict[str, Any]:
    """Get a single VPN server by ID.

    The Network Integration API serves VPN servers as a collection only — there
    is no item-level GET route (``/sites/{site}/vpn/servers/{id}`` returns 404
    NOT_FOUND, and the Site Manager ``/ea/vpn-servers`` path is not served at all).
    So this drains the site's servers over the working per-console proxy list and
    filters by ID, matching the path that ``list_vpn_servers`` already uses.
    """
    validate_id(server_id, "server_id")
    result = await _proxy_list_vpn_servers(client, registry, host, site)
    return _select_by_id(result, server_id, "VPN server", "list_vpn_servers", "VPN server")


# Short VPN type names (the Integration list reports WIREGUARD / OPENVPN / L2TP) mapped to
# the controller's networkconf vpn_type values. Any other value is sent unchanged.
_VPN_SERVER_TYPES = {
    "wireguard": "wireguard-server",
    "openvpn": "openvpn-server",
    "l2tp": "l2tp-server",
    "pptp": "pptp-server",
}


async def _create_vpn_server(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    name: str,
    vpn_type: str,
    *,
    subnet: str | None = None,
    enabled: bool | None = None,
    fields: dict[str, Any] | None = None,
) -> Any:
    """Create a VPN server: a Classic networkconf record of purpose remote-user-vpn.

    POST /proxy/network/api/s/{site}/rest/networkconf. The body is ``fields`` (native
    networkconf keys) plus purpose, name and vpn_type, and ip_subnet / enabled only when
    given; nothing else is defaulted. The upstream ``{meta, data}`` envelope is returned
    verbatim.
    """
    body = with_purpose("create_vpn_server", dict(fields or {}), _VPN_SERVER)
    body["name"] = name
    body["vpn_type"] = _VPN_SERVER_TYPES.get(vpn_type.lower(), vpn_type)
    if subnet is not None:
        body["ip_subnet"] = subnet
    if enabled is not None:
        body["enabled"] = enabled
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    return await with_upstream_hint(
        client.post(classic_rest(host_id, site_slug, "/networkconf"), key=key, json=body),
        purpose_hint("create_vpn_server", fields or {}, _VPN_SERVER),
    )


async def _update_vpn_server(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    server_id: str,
    fields: dict[str, Any],
    /,
) -> Any:
    """Update a VPN server (Integration id or Classic ``_id``) via Classic networkconf.

    ``fields`` is the caller's body, passed as one positional-only dict so a body key
    named like a parameter (``site``, ``host``, ``client``) is sent, never bound. The id is
    resolved among the site's ``remote-user-vpn`` networkconf records; PUT
    rest/networkconf/{_id} merges the fields into the stored record and the upstream
    envelope is returned verbatim.
    """
    body = strip_empty_list_values(with_purpose("update_vpn_server", fields, _VPN_SERVER))
    key, host_id, site_slug, record = await resolve_networkconf_record(
        client,
        registry,
        host,
        site,
        server_id,
        _VPN_SERVER,
        "VPN server",
        "list_vpn_servers",
        "server_id",
    )
    classic_id = record["_id"]
    return await with_upstream_hint(
        client.put(
            classic_rest(host_id, site_slug, f"/networkconf/{classic_id}"),
            key=key,
            json=addressed_body(body, classic_id, record.get("external_id")),
        ),
        purpose_hint("update_vpn_server", fields, _VPN_SERVER),
    )


async def _delete_vpn_server(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    server_id: str,
) -> dict[str, Any]:
    """Delete a VPN server (Integration id or Classic ``_id``) via Classic networkconf."""
    key, host_id, site_slug, classic_id = await resolve_networkconf(
        client,
        registry,
        host,
        site,
        server_id,
        _VPN_SERVER,
        "VPN server",
        "list_vpn_servers",
        "server_id",
    )
    response = await client.delete(
        classic_rest(host_id, site_slug, f"/networkconf/{classic_id}"), key=key
    )
    return deletion_result(f"VPN server {server_id} deleted.", response)


# ---------------------------------------------------------------------------
# RADIUS profiles
# ---------------------------------------------------------------------------


async def _get_radius_profile(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    profile_id: str,
) -> dict[str, Any]:
    """Get a single RADIUS profile by ID.

    RADIUS profiles live on the per-console Network Integration proxy and, like
    VPN servers, expose no item-level GET route (the Site Manager
    ``/ea/radius-profiles`` path is not served). So this drains the site's
    profiles over the working proxy list — the same path ``list_radius_profiles``
    uses — and filters by ID. Requires ``host`` and ``site`` because the profile
    collection is per-site, not global.
    """
    validate_id(profile_id, "profile_id")
    result = await _proxy_list_radius_profiles(client, registry, host, site)
    return _select_by_id(
        result, profile_id, "RADIUS profile", "list_radius_profiles", "RADIUS profile"
    )


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
    acct_server_port: int | None = None,
    acct_server_secret: str | None = None,
    fields: dict[str, Any] | None = None,
) -> Any:
    """Create a RADIUS profile via Classic REST /rest/radiusprofile (the UI's route).

    The body is ``fields`` (native radiusprofile keys) plus name, auth_servers
    [{ip, port, x_secret}] and, when an accounting server IP is given, acct_servers
    [{ip, port, x_secret}] with port and secret only when given. No port or flag is
    defaulted. The upstream ``{meta, data}`` envelope is returned verbatim.
    """
    # An accounting port or secret without acct_server_ip is sent as given (an
    # acct_servers entry without ip); an upstream error gets the hint.
    acct_given = acct_server_port is not None or acct_server_secret is not None
    hint = (
        "create_radius_profile: acct_server_port/acct_server_secret need acct_server_ip "
        "(the accounting server address)."
        if acct_server_ip is None and acct_given
        else None
    )
    body: dict[str, Any] = {
        **(fields or {}),
        "name": name,
        "auth_servers": [
            {"ip": auth_server_ip, "port": auth_server_port, "x_secret": auth_server_secret}
        ],
    }
    if acct_server_ip is not None or acct_given:
        acct: dict[str, Any] = {} if acct_server_ip is None else {"ip": acct_server_ip}
        if acct_server_port is not None:
            acct["port"] = acct_server_port
        if acct_server_secret is not None:
            acct["x_secret"] = acct_server_secret
        body["acct_servers"] = [acct]
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    return await with_upstream_hint(
        client.post(classic_rest(host_id, site_slug, "/radiusprofile"), key=key, json=body), hint
    )


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register all VPN, site-to-site tunnel, and RADIUS profile MCP tools."""

    @mcp.tool(annotations=WRITE)
    async def create_site_to_site_tunnel(
        host: str,
        site: str,
        tunnel: dict[str, Any],
    ) -> Any:
        """Create a site-to-site VPN tunnel. This is a write operation that modifies live config.

        A manual site-to-site tunnel is a Classic REST networkconf record of purpose site-vpn,
        written with POST /proxy/network/api/s/{site}/rest/networkconf (the route the
        controller's own UI uses; the published Integration API serves site-to-site tunnels
        GET-only, POST answers HTTP 405 on Network 11.0.81). The body is the controller's native
        networkconf fields, sent verbatim with purpose set to site-vpn; pass name and vpn_type
        (vpn_type values: ipsec-vpn (manual IPsec), openvpn-vpn, wireguard-vpn). The body is
        sent as given and the controller validates the record: it answers
        api.err.InvalidPayload when a field the tunnel type needs is missing, and that error
        gets a hint naming the missing name / vpn_type.

        Returns: the upstream body verbatim, the Classic envelope {meta: {rc}, data: [the created
        networkconf record]}; data[].external_id is the id list_site_to_site_tunnels reports.
        Under dry-run policy nothing is sent: the result is the bare dry-run preview {status:
        "dry_run", dryRun: true, sent: false,
        message, preview: {method, path, params, body}} in place of the upstream body.

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
        return await _create_site_to_site_tunnel(client, registry, host, site, tunnel)

    @mcp.tool(annotations=WRITE)
    async def update_site_to_site_tunnel(
        host: str,
        site: str,
        tunnel_id: str,
        tunnel: dict[str, Any],
    ) -> Any:
        """Update a site-to-site VPN tunnel by ID.

        Uses Classic REST PUT /proxy/network/api/s/{site}/rest/networkconf/{_id} (the route the
        controller's own UI uses; the published Integration API has no tunnel update, HTTP 404
        "No endpoint" on Network 11.0.81). The id is resolved among the site's site-vpn records
        first; an unknown id fails listing every tunnel with both ids. Send only the fields to
        change: the Classic PUT merges them into the stored record.

        Returns: the upstream body verbatim, the Classic envelope {meta: {rc}, data: [the updated
        networkconf record]}.
        Under dry-run policy nothing is sent: the result is the bare dry-run preview {status:
        "dry_run", dryRun: true, sent: false,
        message, preview: {method, path, params, body}} in place of the upstream body.

        Example call (update_site_to_site_tunnel):
            {
              "host": "my-console",
              "site": "Default",
              "tunnel_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
              "tunnel": {"enabled": false}
            }

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
        return await _update_site_to_site_tunnel(client, registry, host, site, tunnel_id, tunnel)

    @mcp.tool(annotations=WRITE)
    async def delete_site_to_site_tunnel(
        host: str,
        site: str,
        tunnel_id: str,
    ) -> dict[str, Any]:
        """Delete a site-to-site VPN tunnel by ID. This permanently removes the tunnel config.

        Consequence: the tunnel goes down and traffic between the sites over it stops; there is no
        undo.

        Uses Classic REST DELETE /proxy/network/api/s/{site}/rest/networkconf/{_id} (the route
        the controller's own UI uses; the published Integration API has no tunnel delete). The id
        is resolved among the site's site-vpn records first, so an id of another kind is never
        deleted.

        Returns {deleted: true, message, response}; response is the upstream DELETE body verbatim
        (decoded JSON, the raw text of a non-JSON body, or null when the body is empty).
        Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false, message,
        response (the preview)}.

        Example call (delete_site_to_site_tunnel):
            {
              "host": "my-console",
              "site": "Default",
              "tunnel_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        The dry-run preview contains method, path, params (query parameters), and body.

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
        return await _delete_site_to_site_tunnel(client, registry, host, site, tunnel_id)

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
        return await _get_vpn_server(client, registry, host, site, server_id)

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

        A VPN server is a Classic REST networkconf record of purpose remote-user-vpn, written
        with POST /proxy/network/api/s/{site}/rest/networkconf (the route the controller's own
        UI uses; the published Integration API serves VPN servers GET-only, POST answers HTTP 405
        on Network 11.0.81). The tool sends `fields` plus purpose, name and vpn_type, and
        ip_subnet / enabled only when you pass subnet / enabled; nothing else is defaulted. The
        controller validates the record and answers api.err.InvalidPayload when a field the
        server type needs is missing (for WireGuard, e.g. local_port and the server key pair).

        Returns: the upstream body verbatim, the Classic envelope {meta: {rc}, data: [the created
        networkconf record]}; data[].external_id is the id list_vpn_servers reports.
        Under dry-run policy nothing is sent: the result is the bare dry-run preview {status:
        "dry_run", dryRun: true, sent: false,
        message, preview: {method, path, params, body}} in place of the upstream body.

        Example call (create_vpn_server):
            {
              "host": "my-console",
              "site": "Default",
              "name": "Remote access",
              "vpn_type": "wireguard",
              "subnet": "192.0.2.1/24",
              "enabled": false,
              "fields": {"local_port": 51820}
            }

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
        return await _create_vpn_server(
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

        Uses Classic REST PUT /proxy/network/api/s/{site}/rest/networkconf/{_id} (the route the
        controller's own UI uses; the published Integration API has no VPN-server update, HTTP
        404 "No endpoint" on Network 11.0.81). The id is resolved among the site's
        remote-user-vpn records first; an unknown id fails listing every VPN server with both
        ids. Send only the fields to change: the Classic PUT merges them into the stored record.

        Returns: the upstream body verbatim, the Classic envelope {meta: {rc}, data: [the updated
        networkconf record]}.
        Under dry-run policy nothing is sent: the result is the bare dry-run preview {status:
        "dry_run", dryRun: true, sent: false,
        message, preview: {method, path, params, body}} in place of the upstream body.

        Example call (update_vpn_server):
            {
              "host": "my-console",
              "site": "Default",
              "server_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
              "fields": {"enabled": false}
            }

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
        return await _update_vpn_server(client, registry, host, site, server_id, fields)

    @mcp.tool(annotations=WRITE)
    async def delete_vpn_server(
        host: str,
        site: str,
        server_id: str,
    ) -> dict[str, Any]:
        """Delete a VPN server by ID. WARNING: Permanently removes VPN server.
        Connected clients will lose access immediately.

        Consequence: connected VPN clients lose access immediately and the server configuration is
        gone; there is no undo.

        Uses Classic REST DELETE /proxy/network/api/s/{site}/rest/networkconf/{_id} (the route
        the controller's own UI uses; the published Integration API has no VPN-server delete).
        The id is resolved among the site's remote-user-vpn records first, so an id of another
        kind is never deleted.

        Returns {deleted: true, message, response}; response is the upstream DELETE body verbatim
        (decoded JSON, the raw text of a non-JSON body, or null when the body is empty).
        Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false, message,
        response (the preview)}.

        Example call (delete_vpn_server):
            {
              "host": "my-console",
              "site": "Default",
              "server_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        The dry-run preview contains method, path, params (query parameters), and body.

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
        return await _delete_vpn_server(client, registry, host, site, server_id)

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
        return await _get_radius_profile(client, registry, host, site, profile_id)

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

        Uses Classic REST POST /proxy/network/api/s/{site}/rest/radiusprofile (the route the
        controller's own UI uses; the published Integration API serves RADIUS profiles GET-only,
        POST answers HTTP 405 on Network 11.0.81). The body is `fields` plus name, auth_servers
        [{ip, port, x_secret}] and, when acct_server_ip is given, acct_servers [{ip, port,
        x_secret}] carrying port and secret only when given. No port or flag is defaulted:
        accounting stays off unless `fields` sets accounting_enabled.

        Returns: the upstream body verbatim, the Classic envelope {meta: {rc}, data: [the created
        radiusprofile record]}; data[].external_id is the id list_radius_profiles reports.
        Under dry-run policy nothing is sent: the result is the bare dry-run preview {status:
        "dry_run", dryRun: true, sent: false,
        message, preview: {method, path, params, body}} in place of the upstream body.

        Example call (create_radius_profile):
            {
              "host": "my-console",
              "site": "Default",
              "name": "Corp RADIUS",
              "auth_server_ip": "192.0.2.20",
              "auth_server_port": 1812,
              "auth_server_secret": "s3cret"
            }

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
            fields=fields,
        )
