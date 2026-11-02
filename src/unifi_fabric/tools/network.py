"""Network tools — Networks/VLANs, WiFi broadcasts, and WAN interfaces via connector proxy."""

from __future__ import annotations

from typing import Any

from ..client import UniFiClient, UniFiConnectionError, describe_shape, validate_id
from ..config import APIKeyConfig
from ..registry import Registry, _assert_uuid
from ._classic_objects import (
    addressed_body,
    classic_rest,
    purpose_hint,
    resolve_networkconf_record,
    with_purpose,
)
from ._keys import with_context
from ._pagination import collect_offset, offset_list_result, validate_pagination
from ._payload import (
    integration_update_body,
    require_fields,
    strip_empty_list_values,
    upstream_hint,
    with_upstream_hint,
)

PROXY_BASE = "/v1/connector/consoles/{host_id}/proxy/network/integration/v1"


def _proxy(host_id: str, path: str) -> str:
    return PROXY_BASE.format(host_id=host_id) + path


# --- Application / Local Sites ---


async def _offset_list(
    client: UniFiClient,
    url: str,
    *,
    key: APIKeyConfig | None = None,
    offset: int | None,
    limit: int | None,
    filter: str | None,
) -> dict[str, Any]:
    """Fetch an offset-paginated Integration list, draining all pages by default.

    Limit alone requests a total gathered in batches; an explicit offset selects one
    native page, with any limit forwarded as its page size. Otherwise every page is
    drained into ``{data, totalCount}``; a capped drain is flagged incomplete. ``filter``
    is a server-side filter (not paging) and applies in either mode.
    """
    base: dict[str, Any] = {}
    if filter is not None:
        base["filter"] = filter
    collected = await collect_offset(
        client, url, key=key, params=base or None, offset=offset, limit=limit
    )
    return offset_list_result(collected)


async def get_network_application_info(
    client: UniFiClient,
    registry: Registry,
    host: str,
) -> dict[str, Any]:
    """Get the UniFi Network application version reported by a console."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    return await client.get(_proxy(host_id, "/info"), key=key)


async def list_local_sites(
    client: UniFiClient,
    registry: Registry,
    host: str,
    *,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List sites managed by one UniFi Network application.

    By default every offset page is drained and the complete list is returned.
    Limit alone requests a total gathered in batches; explicit offset selects a single
    native page, with any limit forwarded as page size. A
    capped drain returns the sites gathered so far with incomplete=true rather
    than truncating silently.
    """
    validate_pagination(page_size=limit, offset=offset, names={"page_size": "limit"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    collected = await collect_offset(
        client,
        _proxy(host_id, "/sites"),
        key=key,
        params={"filter": filter} if filter is not None else None,
        offset=offset,
        limit=limit,
    )
    if offset is None and limit is None and filter is None and not collected["incomplete"]:
        await registry.set_sites(host_id, collected["items"], key=key)
    return offset_list_result(collected)


# --- Networks / VLANs ---


async def list_networks(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    *,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List all networks/VLANs for a site.

    This Network Integration endpoint is offset-paginated (verified live: the
    response carries an ``{offset, limit, count, totalCount, data}`` envelope and the
    native default page size is only 25). By default every page is drained and the
    complete list is returned as ``{data, totalCount}``; limit alone requests a total
    gathered in batches. Explicit offset selects one native page, with any limit
    forwarded as its page size. ``filter`` is a
    server-side filter (not paging) and applies in either mode. A capped drain is
    flagged ``incomplete`` rather than truncating silently.
    """
    validate_pagination(page_size=limit, offset=offset, names={"page_size": "limit"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await _offset_list(
        client,
        _proxy(host_id, f"/sites/{site_id}/networks"),
        key=key,
        offset=offset,
        limit=limit,
        filter=filter,
    )


async def create_network(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    network: dict[str, Any],
) -> dict[str, Any]:
    """Create a new network/VLAN on a site.

    Required field: ``management`` — the network's management mode and the discriminator
    the API validates first (verified live: an empty body is rejected with
    ``Missing $.management value``). Observed values include ``GATEWAY``. The remaining
    required fields are management-mode-specific rather than universal, so only the
    discriminator is validated here; for ``management="GATEWAY"`` the API additionally
    requires ``name``, ``vlanId``, ``enabled``, ``internetAccessEnabled``,
    ``isolationEnabled``, ``cellularBackupEnabled`` and ``ipv4Configuration`` (Network
    10.6.106 spec key, lower-case v). The body is forwarded verbatim — keys are never
    renamed.
    """
    require_fields("create_network", network, {"management"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.post(_proxy(host_id, f"/sites/{site_id}/networks"), key=key, json=network)


async def get_network(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    network_id: str,
) -> dict[str, Any]:
    """Get a single network by ID."""
    validate_id(network_id, "network_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.get(_proxy(host_id, f"/sites/{site_id}/networks/{network_id}"), key=key)


async def update_network(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    network_id: str,
    network: dict[str, Any],
) -> dict[str, Any]:
    """Update an existing network/VLAN.

    Sanitizes a ``get_network`` response so it round-trips cleanly into an
    update:

    * Server-managed read-only fields (``id``, ``default``, ``metadata``, and the
      ordering ``index``) are stripped by name — they are present in
      ``get_network`` output but the Integration API rejects any such field in a
      write body with HTTP 400 ``unknown-property``.
    * Empty-string entries are stripped from list-valued fields — the API pads
      list fields with placeholder empty strings (e.g.
      ``ipv4Configuration.dhcpConfiguration.dnsServerIpAddressesOverride``
      containing ``["192.168.1.1", "", ""]``) which fail validation as
      ``must be valid IPv4 address`` (HTTP 400) if passed back.
    """
    validate_id(network_id, "network_id")
    network = integration_update_body("update_network", network)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.put(
        _proxy(host_id, f"/sites/{site_id}/networks/{network_id}"),
        key=key,
        json=network,
    )


async def delete_network(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    network_id: str,
    *,
    force: bool | None = None,
) -> Any:
    """Delete a network/VLAN; the spec's optional ``force`` query is sent only when given."""
    validate_id(network_id, "network_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.delete(
        _proxy(host_id, f"/sites/{site_id}/networks/{network_id}"),
        key=key,
        params=_force_params(force),
    )


# --- WiFi Broadcasts ---


async def list_wifi_broadcasts(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    *,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List all WiFi broadcast SSIDs for a site.

    ``filter`` is forwarded unchanged as the Network Integration API ``filter``
    query parameter (server-side filtering); when ``None`` it is omitted entirely
    rather than sent as the string ``"None"``. The tool does not implement a local
    filter language — the upstream API validates the grammar and returns its own
    error for a malformed expression.
    """
    validate_pagination(page_size=limit, offset=offset, names={"page_size": "limit"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await _offset_list(
        client,
        _proxy(host_id, f"/sites/{site_id}/wifi/broadcasts"),
        key=key,
        offset=offset,
        limit=limit,
        filter=filter,
    )


#: The Integration error code a Network 11.0.89 controller answers (HTTP 400) when an access
#: point already carries its maximum number of SSIDs (live 2026-10-28).
_WIFI_BROADCAST_LIMIT = "too-many-wifi-broadcasts"
_WIFI_BROADCAST_LIMIT_HINT = (
    "the controller limits how many SSIDs one access point broadcasts. With "
    "broadcastingDeviceFilter null the new SSID goes to every access point; scope it with "
    "broadcastingDeviceFilter ({type: DEVICES or DEVICE_TAGS, ...}) to access points that "
    "have a free slot, or remove an SSID from the full one first."
)


async def create_wifi_broadcast(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    broadcast: dict[str, Any],
) -> dict[str, Any]:
    """Create a new WiFi broadcast SSID.

    Required field: ``type`` — the broadcast's discriminator, which the API validates
    first (verified live: an empty body is rejected with ``Missing $.type value``).
    Observed values include ``STANDARD``. Fields beyond the discriminator are
    type-specific (e.g. ``name``, ``network``, ``securityConfiguration``,
    ``broadcastingFrequenciesGHz`` on a ``STANDARD`` SSID) and are not validated here.
    """
    require_fields("create_wifi_broadcast", broadcast, {"type"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    try:
        return await client.post(
            _proxy(host_id, f"/sites/{site_id}/wifi/broadcasts"), key=key, json=broadcast
        )
    except UniFiConnectionError as exc:
        if exc.status == 400 and _WIFI_BROADCAST_LIMIT in str(exc):
            upstream_hint(exc, _WIFI_BROADCAST_LIMIT_HINT)
            raise
        raise


async def get_wifi_broadcast(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    broadcast_id: str,
) -> dict[str, Any]:
    """Get a single WiFi broadcast by ID."""
    validate_id(broadcast_id, "broadcast_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.get(
        _proxy(host_id, f"/sites/{site_id}/wifi/broadcasts/{broadcast_id}"), key=key
    )


async def update_wifi_broadcast(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    broadcast_id: str,
    broadcast: dict[str, Any],
) -> dict[str, Any]:
    """Update an existing WiFi broadcast SSID.

    Sanitizes a ``get_wifi_broadcast`` response so it round-trips cleanly into an
    update: server-managed read-only fields (``id``, ``metadata``) are stripped
    (the Integration API rejects them with HTTP 400 ``unknown-property``), and
    empty-string placeholders are stripped from list-valued fields.
    """
    validate_id(broadcast_id, "broadcast_id")
    broadcast = integration_update_body("update_wifi_broadcast", broadcast)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.put(
        _proxy(host_id, f"/sites/{site_id}/wifi/broadcasts/{broadcast_id}"),
        key=key,
        json=broadcast,
    )


async def delete_wifi_broadcast(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    broadcast_id: str,
    *,
    force: bool | None = None,
) -> Any:
    """Delete a WiFi broadcast SSID; the spec's optional ``force`` query is sent only when given."""
    validate_id(broadcast_id, "broadcast_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.delete(
        _proxy(host_id, f"/sites/{site_id}/wifi/broadcasts/{broadcast_id}"),
        key=key,
        params=_force_params(force),
    )


def _force_params(force: bool | None) -> dict[str, str] | None:
    """The spec's optional ``force`` DELETE query, present only when the caller gave it."""
    if force is None:
        return None
    return {"force": "true" if force else "false"}


# --- WAN Interfaces ---


_STAT_BASE = "/v1/connector/consoles/{host_id}/proxy/network/api/s/{site_slug}/stat"


async def list_wan_interfaces(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """List WAN interfaces for a site, with the site's ``/stat/health`` body alongside.

    Returns the drained Integration WAN list the way every Integration list tool does:
    ``{data, totalCount}`` plus the upstream envelope fields, with the records verbatim
    (``incomplete`` / ``incompleteReason`` when a capped drain stopped short;
    ``totalCount`` is the upstream total, ``None`` when it reported none). The additive
    ``_health`` is the Classic
    ``/stat/health`` body verbatim (every subsystem, nothing filtered out; the WAN health
    entries are its ``data[]`` entries with ``subsystem == "wan"``). A failed health read
    still returns the interfaces and reports why under ``_wanHealthError`` (``_health`` is
    then the body received when one was, e.g. an unexpected shape, else absent).
    ``offset`` / ``limit`` fetch one page instead (the native page envelope, verbatim; a
    page the upstream answers as a bare array is returned as that array, without
    ``_health``).
    """
    validate_pagination(page_size=limit, offset=offset, names={"page_size": "limit"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    collected = await collect_offset(
        client, _proxy(host_id, f"/sites/{site_id}/wans"), key=key, offset=offset, limit=limit
    )
    page = offset_list_result(collected)
    if not isinstance(page, dict):
        # An explicit page the upstream answered as a bare array is returned unchanged:
        # an array has no room for the additive _health key, and wrapping it would
        # invent an envelope the upstream never sent.
        return page
    result: dict[str, Any] = dict(page)

    # The Classic stat/health read rides along under an additive key. A failed health read
    # still returns the interfaces, and reports why under _wanHealthError.
    try:
        site_slug = await registry.resolve_site_slug(site, host_id, key=key)
        health_url = _STAT_BASE.format(host_id=host_id, site_slug=site_slug) + "/health"
        health_body = await client.get(health_url, key=key)
        result = with_context(result, {"_health": health_body})
        if not isinstance(health_body, dict) or not isinstance(health_body.get("data"), list):
            raise UniFiConnectionError(
                f"Unexpected response shape from GET {health_url}: expected an object with a "
                f"'data' array, got {describe_shape(health_body)}"
            )
    except Exception as exc:
        result = with_context(result, {"_wanHealthError": f"{type(exc).__name__}: {exc}"})
    return result


async def update_wan_interface(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    wan_id: str,
    wan: dict[str, Any],
    /,
) -> Any:
    """Update a WAN interface (Integration id or Classic ``_id``) via Classic networkconf.

    The published Integration API serves WANs GET-only (PUT answers 404 "No endpoint" on
    Network 11.0.81); the controller UI writes a WAN as the Classic networkconf record of
    purpose ``wan``. The id is resolved among those records; PUT rest/networkconf/{_id}
    merges the caller's fields (empty-string list placeholders dropped) and the upstream
    envelope is returned verbatim. ``purpose`` is pinned to ``wan`` in the body (an absent
    or null purpose is sent as ``wan``); any other purpose is sent as given and an upstream
    error gets a hint, by the same rule as the VPN-server and tunnel updates.
    """
    body = strip_empty_list_values(with_purpose("update_wan_interface", wan, "wan"))
    key, host_id, site_slug, record = await resolve_networkconf_record(
        client,
        registry,
        host,
        site,
        wan_id,
        "wan",
        "WAN interface",
        "list_wan_interfaces",
        "wan_id",
    )
    classic_id = record["_id"]
    return await with_upstream_hint(
        client.put(
            classic_rest(host_id, site_slug, f"/networkconf/{classic_id}"),
            key=key,
            json=addressed_body(body, classic_id, record.get("external_id")),
        ),
        purpose_hint("update_wan_interface", wan, "wan"),
    )


# --- Network References ---


async def get_network_references(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    network_id: str,
) -> dict[str, Any]:
    """Get network references: CLIENT, DEVICE, STATIC_ROUTE, OSPF_ROUTE, NEXT_AI, WIFI,
    NAT_RULE, SD_WAN.
    """
    validate_id(network_id, "network_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.get(
        _proxy(host_id, f"/sites/{site_id}/networks/{network_id}/references"), key=key
    )


# --- Switching ---


async def _list_switching_resources(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    resource: str,
    *,
    offset: int | None,
    limit: int | None,
    filter: str | None,
) -> dict[str, Any]:
    validate_pagination(page_size=limit, offset=offset, names={"page_size": "limit"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await _offset_list(
        client,
        _proxy(host_id, f"/sites/{site_id}/switching/{resource}"),
        key=key,
        offset=offset,
        limit=limit,
        filter=filter,
    )


async def _get_switching_resource(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    resource: str,
    resource_id: str,
    field_name: str,
) -> dict[str, Any]:
    validate_id(resource_id, field_name)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.get(
        _proxy(host_id, f"/sites/{site_id}/switching/{resource}/{resource_id}"), key=key
    )


async def list_lags(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    *,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List Link Aggregation Groups (LAGs) on a site.

    Drains all pages by default; limit alone requests a total gathered in batches,
    and explicit offset selects one native page. A capped drain is flagged incomplete
    rather than truncated silently.
    """
    return await _list_switching_resources(
        client,
        registry,
        host,
        site,
        "lags",
        offset=offset,
        limit=limit,
        filter=filter,
    )


async def get_lag(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    lag_id: str,
) -> dict[str, Any]:
    """Get one Link Aggregation Group."""
    return await _get_switching_resource(client, registry, host, site, "lags", lag_id, "lag_id")


async def list_mc_lag_domains(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    *,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List Multi-Chassis Link Aggregation (MC-LAG) domains on a site.

    Drains all pages by default; limit alone requests a total gathered in batches,
    and explicit offset selects one native page. A capped drain is flagged incomplete
    rather than truncated silently.
    """
    return await _list_switching_resources(
        client,
        registry,
        host,
        site,
        "mc-lag-domains",
        offset=offset,
        limit=limit,
        filter=filter,
    )


async def get_mc_lag_domain(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    mc_lag_domain_id: str,
) -> dict[str, Any]:
    """Get one Multi-Chassis Link Aggregation domain."""
    return await _get_switching_resource(
        client,
        registry,
        host,
        site,
        "mc-lag-domains",
        mc_lag_domain_id,
        "mc_lag_domain_id",
    )


async def list_switch_stacks(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    *,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List switch stacks on a site.

    Drains all pages by default; limit alone requests a total gathered in batches,
    and explicit offset selects one native page. A capped drain is flagged incomplete
    rather than truncated silently.
    """
    return await _list_switching_resources(
        client,
        registry,
        host,
        site,
        "switch-stacks",
        offset=offset,
        limit=limit,
        filter=filter,
    )


async def get_switch_stack(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    switch_stack_id: str,
) -> dict[str, Any]:
    """Get one switch stack."""
    return await _get_switching_resource(
        client,
        registry,
        host,
        site,
        "switch-stacks",
        switch_stack_id,
        "switch_stack_id",
    )
