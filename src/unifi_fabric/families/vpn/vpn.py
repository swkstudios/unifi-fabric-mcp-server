"""VPN server and RADIUS profile CRUD tools — manage VPN and auth services."""

from __future__ import annotations

from typing import Any

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
from ...shared_shapes._network_services_proxy_shared import (
    list_radius_profiles as _proxy_list_radius_profiles,
)
from ...shared_shapes._network_services_proxy_shared import (
    list_vpn_servers as _proxy_list_vpn_servers,
)
from ...shared_shapes._payload import (
    missing_fields_hint,
    strip_empty_list_values,
    with_upstream_hint,
)
from ...shared_shapes._results import deletion_result
from .schemas import (  # the family's shapes (family-owned layout)
    _S2S,
    _VPN_SERVER_TYPES,
)

# ---------------------------------------------------------------------------
# Site-to-site tunnels
# ---------------------------------------------------------------------------


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
