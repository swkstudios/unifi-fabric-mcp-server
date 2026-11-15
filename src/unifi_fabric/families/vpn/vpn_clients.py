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

from typing import Any

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
from .schemas import (  # the family's shapes (family-owned layout)
    _CREATE_HINT,
    _KIND,
    _LIST_TOOL,
    _VPN_CLIENT,
    _VPN_CLIENT_TYPES,
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
