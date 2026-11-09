"""Network tools — Networks/VLANs, WiFi broadcasts, and WAN interfaces via connector proxy."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastmcp import FastMCP

from ..client import (
    UniFiClient,
    UniFiConnectionError,
    describe_shape,
    upstream_error_text,
    validate_id,
)
from ..config import APIKeyConfig
from ..registry import Registry, _assert_uuid
from ..tool_annotations import READ_ONLY, WRITE
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
from ._results import deletion_result

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
    11.0.97 spec key, lower-case v). The body is forwarded verbatim — keys are never
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


async def list_integration_device_tags(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    *,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """Return all device tags defined within a site for WiFi Broadcast assignments."""
    validate_pagination(page_size=limit, offset=offset, names={"page_size": "limit"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await _offset_list(
        client,
        _proxy(host_id, f"/sites/{site_id}/device-tags"),
        key=key,
        offset=offset,
        limit=limit,
        filter=filter,
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
#: point already carries its maximum number of SSIDs (live 2026-10-28). Network 11.0.97 gave
#: the same answer to an SSID created with enabled false (live 2026-11-08).
_WIFI_BROADCAST_LIMIT = "too-many-wifi-broadcasts"
_WIFI_BROADCAST_LIMIT_HINT = (
    "the controller limits how many SSIDs one access point broadcasts, and creating the SSID "
    "disabled (enabled: false) does not avoid the limit. With broadcastingDeviceFilter null "
    "the new SSID goes to every access point; scope it with broadcastingDeviceFilter "
    "({type: DEVICES or DEVICE_TAGS, ...}) to access points that have a free slot, or remove "
    "an SSID from the full one (the device id in the message above) first."
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
        result = with_context(
            result, {"_wanHealthError": f"{type(exc).__name__}: {upstream_error_text(exc, client)}"}
        )
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


# Tool modules the wrappers below delegate to, imported after this module's
# own definitions so a module importing from this one never sees it half-built.
from . import network, network_services_proxy  # noqa: E402


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> dict[str, Callable[..., Any]]:
    """Register the network tool wrappers moved from server.py, in order.

    Returns the registered wrapper functions by name; server.py re-exports them.
    """

    @mcp.tool(annotations=READ_ONLY)
    async def get_network_application_info(
        host: str,
    ) -> Any:
        """Get the UniFi Network application version reported by a console.

        Returns the upstream application-info ({applicationVersion, ...}) object verbatim, exactly as
        the API answers it.

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
        """
        client, registry = deps_fn()
        return await network.get_network_application_info(client, registry, host)

    @mcp.tool(annotations=READ_ONLY)
    async def list_local_sites(
        host: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List sites managed by one UniFi Network application.

        Returns {data, totalCount}: every page is drained; data holds the site records verbatim and
        totalCount is the upstream total (null when none was reported). The first page's other envelope
        fields are kept beside them, and incomplete / incompleteReason are added when a capped drain
        stopped short.

        By default every page is drained and the complete list is returned. Pass
        offset alone to fetch a single page manually (native envelope preserved).
        A capped drain returns the sites gathered so far with incomplete=true rather
        than truncating silently. filter: optional UniFi Integration API filter.

        limit requests a total, gathered automatically in batches up to 200;
        _pageSize reports requested count, actual sent sizes per request,
        observed effective size and returned count, without capping the total.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            offset: Optional zero-based starting record; alone, fetch one page manually.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 200, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain all.
                Example: `25`.
            filter: Optional UniFi Integration API filter expression, forwarded unchanged as the
                upstream `filter` query parameter. Omitted entirely when unset.
                Example: `name.eq('Default')`."""
        client, registry = deps_fn()
        return await network.list_local_sites(
            client,
            registry,
            host,
            offset=offset,
            limit=limit,
            filter=filter,
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_networks(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List all networks/VLANs for a site.

        Returns {data, totalCount}: every page is drained; data holds the network records verbatim and
        totalCount is the upstream total (null when none was reported). The first page's other envelope
        fields are kept beside them, and incomplete / incompleteReason are added when a capped drain
        stopped short.

        Networks are offset-paginated (native default page size 25); by default every page
        is drained and the complete list is returned as {data, totalCount}. Pass offset alone
        for a single manual page. filter: optional Network Integration API filter
        expression, forwarded unchanged as the upstream `filter` query parameter for
        server-side filtering (e.g. `vlanId.eq(100)`, `name.like('*guest*')`,
        `metadata.origin.eq('USER_DEFINED')`); omitted entirely when unset. A capped drain is
        flagged incomplete.

        limit requests a total, gathered automatically in batches up to 200;
        _pageSize reports requested count, actual sent sizes per request,
        observed effective size and returned count, without capping the total.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            offset: Optional zero-based starting record; alone, fetch one page manually.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 200, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain all.
                Example: `25`.
            filter: Optional Network Integration API filter expression, forwarded unchanged as the
                upstream `filter` query parameter (e.g. `vlanId.eq(100)`, `name.like('*guest*')`,
                `metadata.origin.eq('USER_DEFINED')`). Omitted entirely when unset.
                Example: `metadata.origin.eq('USER_DEFINED')`."""
        client, registry = deps_fn()
        return await network.list_networks(
            client, registry, host, site, offset=offset, limit=limit, filter=filter
        )

    @mcp.tool(annotations=WRITE)
    async def create_network(
        host: str,
        site: str,
        network_config: dict[str, Any],
    ) -> Any:
        """Create a new network/VLAN on a site.

        Returns the upstream response body verbatim: the created network object the API answers with
        (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
        message, preview: {method, path, params (query parameters), body}} instead).

        Validated locally before the request (a missing field raises ValueError naming it):
        ``management`` — the discriminator the controller validates first. The rest of the
        required schema is management-mode-specific and enforced by the controller.
        `network_config` is sent verbatim. Field names are camelCase exactly as in the spec —
        the IPv4 block is ``ipv4Configuration`` (lower-case v), not ``ipV4Configuration``; there
        is no 'purpose' field in the Network Integration API. For management='GATEWAY' the
        controller also requires name, vlanId (1 only for the default network,
        otherwise 2-4009), enabled, internetAccessEnabled, isolationEnabled,
        cellularBackupEnabled, and ipv4Configuration (e.g. hostIpAddress + prefixLength, with
        required autoScaleEnabled and optional DHCP settings). Optional: zoneId (zone UUID from
        list_firewall_zones_proxy). Read an existing network with get_network to copy a working
        ipv4Configuration shape.

        Network auto-exclusion: UniFi silently adds every new network to the
        ``excluded_networkconf_ids`` of ALL custom-tagged port profiles
        (``tagged_vlan_mgmt == 'custom'``), blackholing the VLAN at the host uplink.
        When that happens this response carries an additive ``_warnings`` entry (code
        ``D12_AUTO_EXCLUSION``) naming each affected profile and the network's Classic
        networkconf ``_id`` (profiles store that ``_id``, not this response's ``id``); run
        ``allow_network_on_port_profile`` on each to restore tagging (it accepts either id).


        Full request shapes are in the parameter schema; detailed examples and workflows:
        docs/TOOL-USAGE.md#create_network.

        Required arguments: host, site, network_config (see parameter descriptions for identifiers).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            network_config: Full object to create; spec Create or update Network. Required: enabled,
                management, name, vlanId. 'management' selects variant: GATEWAY|SWITCH|UNMANAGED.
        """
        client, registry = deps_fn()
        created = await network.create_network(client, registry, host, site, network_config)
        return await network_services_proxy.annotate_auto_exclusions(
            client, registry, host, site, created
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_network(
        host: str,
        site: str,
        network_id: str,
    ) -> Any:
        """Get a single network/VLAN by ID.

        Returns: the network object, verbatim. To change it, edit it and pass it as `network_config` to
        update_network.

        Example call (get_network):
            {
              "host": "my-console",
              "site": "Default",
              "network_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            network_id: Network/VLAN UUID. Get it from list_networks (data[].id). Network-app UUID — not
                a Protect id.
        """
        client, registry = deps_fn()
        return await network.get_network(client, registry, host, site, network_id)

    @mcp.tool(annotations=WRITE)
    async def update_network(
        host: str,
        site: str,
        network_id: str,
        network_config: dict[str, Any],
    ) -> Any:
        """Update an existing network/VLAN.

        Returns the upstream response body verbatim: the updated network object the API answers with
        (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
        message, preview: {method, path, params (query parameters), body}} instead).

        Request body (Network 11.0.97, PUT /v1/sites/{siteId}/networks/{networkId} (updateNetwork);
        schema "Create or update Network") is passed in `network_config`. Required keys — enabled,
        management, name, vlanId.
        - dhcpGuarding: object (Network DHCP Guarding)
        - enabled: boolean
        - management: string
        - name: string
        - vlanId: integer(int32)
        Variants by `management` — GATEWAY requires cellularBackupEnabled, enabled,
        internetAccessEnabled, ipv4Configuration, isolationEnabled, name, vlanId, management; SWITCH
        requires cellularBackupEnabled, deviceId, enabled, ipv4Configuration, isolationEnabled, name,
        vlanId, management; UNMANAGED requires enabled, name, vlanId, management.

        Example call (update_network):
            {
              "host": "my-console",
              "site": "Default",
              "network_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
              "network_config": {
                "management": "GATEWAY",
                "cellularBackupEnabled": true,
                "enabled": true,
                "internetAccessEnabled": true,
                "ipv4Configuration": {
                  "autoScaleEnabled": true,
                  "hostIpAddress": "192.0.2.1",
                  "prefixLength": 24
                },
                "isolationEnabled": true,
                "name": "Office VLAN",
                "vlanId": 20
              }
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            network_id: Network/VLAN UUID. Get it from list_networks (data[].id). Network-app UUID — not
                a Protect id.
            network_config: FULL replacement object (PUT; omitted fields reset); spec Create or update
                Network. Required: enabled, management, name, vlanId. 'management' selects variant:
                GATEWAY|SWITCH|UNMANAGED.
        """
        client, registry = deps_fn()
        return await network.update_network(
            client, registry, host, site, network_id, network_config
        )

    @mcp.tool(annotations=WRITE)
    async def delete_network(
        host: str,
        site: str,
        network_id: str,
        force: bool | None = None,
    ) -> dict[str, Any]:
        """Delete a network/VLAN.

        Consequence: removes the VLAN and disconnects all clients on that network; there is no undo.

        Network 11.0.97 DELETE /v1/sites/{siteId}/networks/{networkId} (deleteNetwork). The
        spec's optional `force` query parameter is sent only when given.

        Returns {deleted: true, message, response}; response is the upstream DELETE body verbatim
        (decoded JSON, the raw text of a non-JSON body, or null when the body is empty).
        Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false, message,
        response (the preview)}.

        Example call (delete_network):
            {
              "host": "my-console",
              "site": "Default",
              "network_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            network_id: Network/VLAN UUID. Get it from list_networks (data[].id). Network-app UUID — not
                a Protect id.
            force: Optional spec query parameter `force` (boolean, upstream default false); true asks
                the controller to delete a network that is still referenced. Omitted when unset.
        """
        client, registry = deps_fn()
        response = await network.delete_network(
            client, registry, host, site, network_id, force=force
        )
        return deletion_result(f"Network {network_id} deleted.", response)

    @mcp.tool(annotations=READ_ONLY)
    async def get_network_references(
        host: str,
        site: str,
        network_id: str,
    ) -> Any:
        """Get all resources referencing a network — useful before deleting to check dependencies.

        Returns {referenceResources: [...]}, one entry per resource type that references the
        network; each entry is returned as {resourceType, referenceCount, references: [...]}
        and each reference as {referenceId}. resourceType is one of CLIENT, DEVICE,
        STATIC_ROUTE, OSPF_ROUTE, NEXT_AI, WIFI, NAT_RULE or SD_WAN (the pinned enum);
        referenceCount is how many resources of that type reference it, and referenceId is
        the id of one of them. The body is passed through as the console sent it.

        The console may return HTTP 500 for some networks; this is an upstream condition.

        Example call (get_network_references):
            {
              "host": "my-console",
              "site": "Default",
              "network_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            network_id: Network/VLAN UUID. Get it from list_networks (data[].id). Network-app UUID — not
                a Protect id.
        """
        client, registry = deps_fn()
        return await network.get_network_references(client, registry, host, site, network_id)

    @mcp.tool(annotations=READ_ONLY)
    async def list_lags(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List Link Aggregation Groups (LAGs) on a site.

        Returns {data, totalCount}: every page is drained; data holds the LAG records verbatim and
        totalCount is the upstream total (null when none was reported). The first page's other envelope
        fields are kept beside them, and incomplete / incompleteReason are added when a capped drain
        stopped short.

        Drains all pages by default; pass offset alone for a single manual page. A
        capped drain is flagged incomplete rather than truncated silently.

        limit requests a total, gathered automatically in batches up to 200;
        _pageSize reports requested count, actual sent sizes per request,
        observed effective size and returned count, without capping the total.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            offset: Optional zero-based starting record; alone, fetch one page manually.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 200, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain all.
                Example: `25`.
            filter: optional UniFi Integration API filter expression.
                Example: `metadata.origin.eq('USER_DEFINED')`."""
        client, registry = deps_fn()
        return await network.list_lags(
            client,
            registry,
            host,
            site,
            offset=offset,
            limit=limit,
            filter=filter,
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_lag(
        host: str,
        site: str,
        lag_id: str,
    ) -> Any:
        """Get one Link Aggregation Group.

        Returns the upstream LAG object verbatim, exactly as the API answers it.

        Example call (get_lag):
            {"host": "my-console", "site": "Default", "lag_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            lag_id: LAG UUID. Get it from list_lags (data[].id).
        """
        client, registry = deps_fn()
        return await network.get_lag(client, registry, host, site, lag_id)

    @mcp.tool(annotations=READ_ONLY)
    async def list_mc_lag_domains(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List Multi-Chassis Link Aggregation (MC-LAG) domains on a site.

        Returns {data, totalCount}: every page is drained; data holds the MC-LAG domain records verbatim
        and totalCount is the upstream total (null when none was reported). The first page's other
        envelope fields are kept beside them, and incomplete / incompleteReason are added when a capped
        drain stopped short.

        Drains all pages by default; pass offset alone for a single manual page. A
        capped drain is flagged incomplete rather than truncated silently.

        limit requests a total, gathered automatically in batches up to 200;
        _pageSize reports requested count, actual sent sizes per request,
        observed effective size and returned count, without capping the total.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            offset: Optional zero-based starting record; alone, fetch one page manually.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 200, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain all.
                Example: `25`.
            filter: optional UniFi Integration API filter expression.
                Example: `metadata.origin.eq('USER_DEFINED')`."""
        client, registry = deps_fn()
        return await network.list_mc_lag_domains(
            client,
            registry,
            host,
            site,
            offset=offset,
            limit=limit,
            filter=filter,
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_mc_lag_domain(
        host: str,
        site: str,
        mc_lag_domain_id: str,
    ) -> Any:
        """Get one Multi-Chassis Link Aggregation domain.

        Returns the upstream MC-LAG domain object verbatim, exactly as the API answers it.

        Example call (get_mc_lag_domain):
            {
              "host": "my-console",
              "site": "Default",
              "mc_lag_domain_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            mc_lag_domain_id: MC-LAG domain UUID. Get it from list_mc_lag_domains (data[].id).
        """
        client, registry = deps_fn()
        return await network.get_mc_lag_domain(client, registry, host, site, mc_lag_domain_id)

    @mcp.tool(annotations=READ_ONLY)
    async def list_switch_stacks(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List switch stacks on a site.

        Returns {data, totalCount}: every page is drained; data holds the switch stack records verbatim
        and totalCount is the upstream total (null when none was reported). The first page's other
        envelope fields are kept beside them, and incomplete / incompleteReason are added when a capped
        drain stopped short.

        Drains all pages by default; pass offset alone for a single manual page. A
        capped drain is flagged incomplete rather than truncated silently.

        limit requests a total, gathered automatically in batches up to 200;
        _pageSize reports requested count, actual sent sizes per request,
        observed effective size and returned count, without capping the total.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            offset: Optional zero-based starting record; alone, fetch one page manually.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 200, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain all.
                Example: `25`.
            filter: optional UniFi Integration API filter expression.
                Example: `metadata.origin.eq('USER_DEFINED')`."""
        client, registry = deps_fn()
        return await network.list_switch_stacks(
            client,
            registry,
            host,
            site,
            offset=offset,
            limit=limit,
            filter=filter,
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_switch_stack(
        host: str,
        site: str,
        switch_stack_id: str,
    ) -> Any:
        """Get one switch stack.

        Returns the upstream switch stack object verbatim, exactly as the API answers it.

        Example call (get_switch_stack):
            {
              "host": "my-console",
              "site": "Default",
              "switch_stack_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            switch_stack_id: Switch stack UUID. Get it from list_switch_stacks (data[].id).
        """
        client, registry = deps_fn()
        return await network.get_switch_stack(client, registry, host, site, switch_stack_id)

    @mcp.tool(annotations=READ_ONLY)
    async def list_integration_device_tags(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List the Network Integration device-tag collection for a site.

        These device tags are used for WiFi Broadcast assignments, distinct from the UI
        device-tag collection exposed by list_device_tags. By default, drain all pages.
        A limit requests that many records across pages; an offset selects one native page.
        Returns {data, totalCount} with every page drained by default, plus _pageSize
        metadata describing requested and returned counts when limit is set.
        With offset, returns the native upstream page envelope.

        Args:
            host: Console name or ID from list_hosts.
            site: Network site name or UUID from list_local_sites.
            offset: Optional zero-based offset for one native page. Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 200, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain all.
                Example: `25`.
            filter: Optional upstream filter expression. Filterable properties are id (eq,
                ne, in, notIn), name (eq, ne, in, notIn, like), and deviceIds (contains,
                containsAny, containsAll, containsExactly). Example: `name.eq('Guest')`.
        """
        client, registry = deps_fn()
        return await network.list_integration_device_tags(
            client, registry, host, site, offset=offset, limit=limit, filter=filter
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_wifi_broadcasts(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List all WiFi broadcast SSIDs for a site.

        Returns {data, totalCount} with every page drained (the API pages at 25 by default).
        Pass offset alone to fetch a single manual page (native envelope preserved).

        limit requests a total, gathered automatically in batches up to 200;
        _pageSize reports requested count, actual sent sizes per request,
        observed effective size and returned count, without capping the total.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            offset: Optional zero-based starting record; alone, fetch one page manually.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 200, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain all.
                Example: `25`.
            filter: optional Network Integration API filter expression, forwarded unchanged as the
                upstream `filter` query parameter for server-side filtering (e.g. `enabled.eq(true)`,
                `name.like('*Guest*')`); omitted entirely when unset.
                Example: `metadata.origin.eq('USER_DEFINED')`."""
        client, registry = deps_fn()
        return await network.list_wifi_broadcasts(
            client, registry, host, site, offset=offset, limit=limit, filter=filter
        )

    @mcp.tool(annotations=WRITE)
    async def create_wifi_broadcast(
        host: str,
        site: str,
        broadcast: dict[str, Any],
    ) -> Any:
        """Create a new WiFi broadcast SSID on a site.

        Returns the upstream response body verbatim: the created WiFi broadcast object the API
        answers
        with (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
        message,
        preview: {method, path, params (query parameters), body}} instead).

        Validated locally before the request (a missing field raises ValueError naming it):
        ``type`` — the discriminator the controller validates first (observed value:
        'STANDARD'). The remaining fields are type-specific and enforced by the controller.
        `broadcast`: its parameter description lists the keys each ``type`` requires
        ("Variants by type"; STANDARD and IOT_OPTIMIZED differ). Field names are camelCase.
        For an open SSID use securityConfiguration: {type: "OPEN"} and an explicit network
        reference: network: {type: "SPECIFIC", networkId: UUID from list_networks}. The spec
        permits omitting network, but the live controller requires it for OPEN broadcasts.
        An access point carries a limited number of SSIDs: when the controller refuses with HTTP
        400 too-many-wifi-broadcasts, the error keeps its whole body and adds a hint to scope
        the SSID with broadcastingDeviceFilter. Creating it with enabled false does not avoid
        that limit.

        Full request shapes are in the parameter schema; detailed examples and workflows:
        docs/TOOL-USAGE.md#create_wifi_broadcast.

        Required arguments: host, site, broadcast (see parameter descriptions for identifiers).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            broadcast: Full object to create; spec Wifi broadcast create or update. 'type' selects
                variant: IOT_OPTIMIZED|STANDARD.
        """
        client, registry = deps_fn()
        return await network.create_wifi_broadcast(client, registry, host, site, broadcast)

    @mcp.tool(annotations=READ_ONLY)
    async def get_wifi_broadcast(
        host: str,
        site: str,
        broadcast_id: str,
    ) -> Any:
        """Get a single WiFi broadcast SSID by ID.

        Returns: the WiFi broadcast object, verbatim. To change it, edit it and pass it as `broadcast`
        to update_wifi_broadcast.

        Example call (get_wifi_broadcast):
            {
              "host": "my-console",
              "site": "Default",
              "broadcast_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            broadcast_id: WiFi broadcast (SSID) UUID. Get it from list_wifi_broadcasts (data[].id).
                Network-app UUID — not a Protect id.
        """
        client, registry = deps_fn()
        return await network.get_wifi_broadcast(client, registry, host, site, broadcast_id)

    @mcp.tool(annotations=WRITE)
    async def update_wifi_broadcast(
        host: str,
        site: str,
        broadcast_id: str,
        broadcast: dict[str, Any],
    ) -> Any:
        """Update an existing WiFi broadcast SSID.

        Returns the upstream response body verbatim: the updated WiFi broadcast object the API
        answers
        with (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
        message,
        preview: {method, path, params (query parameters), body}} instead).


        For an open SSID use securityConfiguration: {type: "OPEN"} and an explicit network
        reference: network: {type: "SPECIFIC", networkId: UUID from list_networks}. Retain that
        reference in the full replacement object; the live controller requires it for OPEN.

        Full request shapes are in the parameter schema; detailed examples and workflows:
        docs/TOOL-USAGE.md#update_wifi_broadcast.

        Required arguments: host, site, broadcast_id, broadcast (see parameter descriptions for
        identifiers).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            broadcast_id: WiFi broadcast (SSID) UUID. Get it from list_wifi_broadcasts (data[].id).
                Network-app UUID — not a Protect id.
            broadcast: FULL replacement object (PUT; omitted fields reset); spec Wifi broadcast create
                or update. 'type' selects variant: IOT_OPTIMIZED|STANDARD.
        """
        client, registry = deps_fn()
        return await network.update_wifi_broadcast(
            client, registry, host, site, broadcast_id, broadcast
        )

    @mcp.tool(annotations=WRITE)
    async def delete_wifi_broadcast(
        host: str,
        site: str,
        broadcast_id: str,
        force: bool | None = None,
    ) -> dict[str, Any]:
        """Delete a WiFi broadcast SSID.

        Consequence: the SSID stops broadcasting and its connected clients are disconnected; there is no
        undo.

        Network 11.0.97 DELETE /v1/sites/{siteId}/wifi/broadcasts/{wifiBroadcastId}
        (deleteWifiBroadcast). The spec's optional `force` query parameter is sent only when given.

        Returns {deleted: true, message, response}; response is the upstream DELETE body verbatim
        (decoded JSON, the raw text of a non-JSON body, or null when the body is empty).
        Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false, message,
        response (the preview)}.

        Example call (delete_wifi_broadcast):
            {
              "host": "my-console",
              "site": "Default",
              "broadcast_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            broadcast_id: WiFi broadcast (SSID) UUID. Get it from list_wifi_broadcasts (data[].id).
                Network-app UUID — not a Protect id.
            force: Optional spec query parameter `force` (boolean, upstream default false); true asks
                the controller to delete a broadcast that is still referenced. Omitted when unset.
        """
        client, registry = deps_fn()
        response = await network.delete_wifi_broadcast(
            client, registry, host, site, broadcast_id, force=force
        )
        return deletion_result(f"WiFi broadcast {broadcast_id} deleted.", response)

    @mcp.tool(annotations=READ_ONLY)
    async def list_wan_interfaces(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """List WAN interfaces for a site.

        Returns: {data: [wan…], totalCount, _health}. data is the Integration WAN list, entries verbatim
        (every page drained; incomplete/incompleteReason when a capped drain stopped short; with offset
        alone, that single page in its native envelope, plus _health, and a page the upstream
        answers as a bare array is returned as that array, without _health); totalCount is the upstream
        total of that list (null when the upstream reports none). The additive _health is the Classic
        /stat/health body verbatim ({meta: {rc}, data: [...]}, every subsystem; the WAN health entries
        are its data[] entries with subsystem "wan"). When the stat/health read fails, the additive
        _wanHealthError carries the reason (and _health is the body received, if any) — the interfaces
        are still returned. To change one, pass the native Classic networkconf fields to change (e.g.
        wan_load_balance_weight, wan_failover_priority, wan_dns1) as `wan` to update_wan_interface
        (wan_id = its data[] id).

        limit requests a total, gathered automatically in batches up to 200;
        _pageSize reports requested count, actual sent sizes per request,
        observed effective size and returned count, without capping the total.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            offset: Optional zero-based starting record; alone, fetch one page manually.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 200, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain all.
                Example: `25`."""
        client, registry = deps_fn()
        return await network.list_wan_interfaces(
            client, registry, host, site, offset=offset, limit=limit
        )

    @mcp.tool(annotations=WRITE)
    async def update_wan_interface(
        host: str,
        site: str,
        wan_id: str,
        wan: dict[str, Any],
    ) -> Any:
        """Update a WAN interface configuration.

        A WAN interface is a Classic REST networkconf record of purpose wan, written with PUT
        /proxy/network/api/s/{site}/rest/networkconf/{_id} (the route the controller's own UI uses;
        the published Integration API serves WANs GET-only, PUT answers HTTP 404 "No endpoint" on
        Network 11.0.81). The id is resolved among the site's wan records first; an unknown id fails
        listing every WAN with both ids. Send only the fields to change: the Classic PUT merges them
        into the stored record.

        Returns: the upstream body verbatim, the Classic envelope {meta: {rc}, data: [the updated
        networkconf record]}.
        Under dry-run policy nothing is sent: the result is the bare dry-run preview {status: "dry_run",
        dryRun: true, sent: false,
        message, preview: {method, path, params, body}} in place of the upstream body.

        Example call (update_wan_interface):
            {
              "host": "my-console",
              "site": "Default",
              "wan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
              "wan": {"wan_load_balance_weight": 50}
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            wan_id: WAN interface id. Get it from list_wan_interfaces (data[].id); the Classic
                networkconf _id also works. Network-app UUID — not a Protect id.
            wan: Native Classic networkconf fields to change, e.g. name, wan_type, wan_dns1,
                wan_load_balance_weight, wan_failover_priority, wan_vlan_enabled. Sent unchanged
                (empty-string list placeholders dropped); an absent or null purpose is sent as
                wan, another is sent as given (an upstream error then gets a hint).
                A purpose-only update is refused.
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await network.update_wan_interface(client, registry, host, site, wan_id, wan)

    return {
        "get_network_application_info": get_network_application_info,
        "list_local_sites": list_local_sites,
        "list_networks": list_networks,
        "create_network": create_network,
        "get_network": get_network,
        "update_network": update_network,
        "delete_network": delete_network,
        "get_network_references": get_network_references,
        "list_lags": list_lags,
        "get_lag": get_lag,
        "list_mc_lag_domains": list_mc_lag_domains,
        "get_mc_lag_domain": get_mc_lag_domain,
        "list_switch_stacks": list_switch_stacks,
        "get_switch_stack": get_switch_stack,
        "list_wifi_broadcasts": list_wifi_broadcasts,
        "create_wifi_broadcast": create_wifi_broadcast,
        "get_wifi_broadcast": get_wifi_broadcast,
        "update_wifi_broadcast": update_wifi_broadcast,
        "delete_wifi_broadcast": delete_wifi_broadcast,
        "list_wan_interfaces": list_wan_interfaces,
        "update_wan_interface": update_wan_interface,
    }
