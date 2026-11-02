"""Client management tools — list, get, and actions via connector proxy."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastmcp import FastMCP

from ..client import (
    UniFiClient,
    UniFiConnectionError,
    describe_shape,
    object_records,
    validate_id,
    validate_spec_id,
)
from ..macs import colon_mac as _colon_mac
from ..macs import is_mac as _is_mac
from ..macs import record_mac
from ..matching import id_key
from ..registry import Registry, _assert_uuid
from ..resolution_state import note_incomplete_resolution
from ..tool_annotations import READ_ONLY, WRITE
from ._classic_objects import v2_site
from ._pagination import collect_offset, offset_list_result, validate_pagination
from .network import _proxy

_CLASSIC_CMD_BASE = "/v1/connector/consoles/{host_id}/proxy/network/api/s/{site_slug}/cmd"

#: Every connected-client type the published Network spec lists (Network 10.6.106
#: "Client overview" / "Client details" discriminator on ``type``; pinned to the vendored
#: spec by a test, so a type the spec adds fails until it is accepted here).
CLIENT_TYPES = ("WIRED", "WIRELESS", "VPN", "TELEPORT")
# Connected-client types the Integration API reports without a MAC.
_MACLESS_CLIENT_TYPES = frozenset({"VPN", "TELEPORT"})


def _validate_client_ref(client_id: str, name: str = "client_id") -> None:
    """A client reference -- the client's MAC (any accepted form, no surrounding
    whitespace) or its Network Integration client id (a UUID) -- checked before any
    request (a non-UUID id used to reach the upstream and fail there)."""
    if _is_mac(client_id):
        return
    try:
        validate_spec_id(client_id, name, uuid=True)
    except ValueError as exc:
        raise ValueError(
            f"{name} {client_id!r} is neither a client id (UUID) nor a MAC: pass a UUID "
            "(list_clients data[].id) or the client's MAC (any of aa:bb:cc:dd:ee:ff, "
            f"aa-bb-cc-dd-ee-ff, aabbccddeeff). {exc}"
        ) from None


def _record_mac(record: dict[str, Any]) -> str | None:
    for field in ("macAddress", "mac"):
        found = record_mac(record.get(field))
        if found is not None:
            return _colon_mac(found)
    return None


def _describe_clients(records: list[dict[str, Any]]) -> str:
    return "; ".join(
        f"{r.get('name') or r.get('hostname') or '(unnamed)'} (mac={_record_mac(r)}, "
        f"id={r.get('id')})"
        for r in records
    )


async def _resolve_client(
    client: UniFiClient, host_id: str, site_id: str, client_id: str, key: Any
) -> tuple[str, str | None]:
    """``(client id, MAC or None)`` for a client given by id or by MAC.

    An id is returned as given (MAC ``None``: read it from the client when needed). A MAC
    in any form (colon, dash, bare; any case) is looked up with list_clients' server-side
    ``macAddress.eq(...)`` filter (the result is re-checked locally, so an upstream that
    ignores the filter cannot pick the wrong client). No match or several matches raise
    listing the matching or the valid clients; nothing is written.
    """
    if not _is_mac(client_id):
        return client_id, None
    mac = _colon_mac(client_id)
    url = _proxy(host_id, f"/sites/{site_id}/clients")
    collected = await collect_offset(
        client, url, key=key, params={"filter": f"macAddress.eq('{mac}')"}
    )
    rows = object_records(collected["items"], f"GET {url}")
    matches = [r for r in rows if _record_mac(r) == mac]
    ids = []
    for r in matches:
        native_id = r.get("id")
        if not isinstance(native_id, str) or not native_id:
            raise UniFiConnectionError(
                f"Unexpected response shape from GET {url}: client with MAC {mac} needs a "
                f"non-empty string native id; identifying fields: {_describe_clients([r])}; "
                f"id={native_id!r}"
            )
        ids.append(native_id)
    if len({id_key(i) for i in ids}) > 1:
        raise ValueError(
            f"MAC {client_id!r} matches distinct client ids in site {site_id!r}: "
            f"{_describe_clients(matches)}. Pass the client UUID (list_clients data[].id)."
        )
    if ids:
        if collected["incomplete"]:
            note_incomplete_resolution(collected["incompleteReason"])
        return ids[0], mac
    if collected["incomplete"]:
        raise ValueError(
            f"Cannot resolve MAC {client_id!r} in site {site_id!r}: the client list is "
            f"incomplete ({collected['incompleteReason']})."
        )
    everyone = await collect_offset(client, url, key=key)
    valid = object_records(everyone["items"], f"GET {url}")
    partial = (
        f" (the client list is incomplete: {everyone['incompleteReason']})"
        if everyone["incomplete"]
        else ""
    )
    raise ValueError(
        f"No connected client with MAC {mac} in site {site_id!r}{partial}: this tool needs "
        "the client's Integration id, which exists only while the client is connected; "
        f"valid (connected): {_describe_clients(valid) or '(none)'}. Get it from list_clients "
        "(data[].macAddress or data[].id)."
    )


def _classic_cmd(host_id: str, site_slug: str, path: str) -> str:
    return _CLASSIC_CMD_BASE.format(host_id=host_id, site_slug=site_slug) + path


async def _client_mac(
    client: UniFiClient, host_id: str, site_id: str, client_id: str, key: Any
) -> str:
    """The MAC of a connected client (lowercase colon form), read with the Integration
    client GET.

    A body that is not a JSON object (``decode_body`` returns ``None`` for an empty body,
    the text of a non-JSON body, and lists or scalars as received), or an object without
    a ``macAddress`` / ``mac``, raises naming the request and the shape received; a VPN
    or Teleport client (no MAC by design) raises saying so. Nothing is sent to the
    Classic ``stamgr`` command.
    """
    path = _proxy(host_id, f"/sites/{site_id}/clients/{client_id}")
    body = await client.get(path, key=key)
    if not isinstance(body, dict):
        raise UniFiConnectionError(
            f"Unexpected response shape from GET {path}: expected a client object with a "
            f"'macAddress', got {describe_shape(body)}"
        )
    mac = _record_mac(body)
    if mac is not None:
        return mac
    ctype = body.get("type")
    if isinstance(ctype, str) and ctype.upper() in _MACLESS_CLIENT_TYPES:
        kind = "VPN" if ctype.upper() == "VPN" else "Teleport VPN"
        raise ValueError(
            f"client {client_id} is a {kind} client and has no MAC; "
            "block/unblock/reconnect apply to wired and wireless clients only"
        )
    raise UniFiConnectionError(
        f"Could not retrieve the MAC address of client {client_id}: unexpected response "
        f"shape from GET {path}: expected a client object with a 'macAddress', got "
        f"{describe_shape(body)}"
    )


async def _stamgr_mac(
    client: UniFiClient, host_id: str, site_id: str, client_id: str, key: Any
) -> str:
    """The MAC a Classic ``stamgr`` command addresses.

    A MAC (any form) is normalized to lowercase colon form and returned as is: no client
    list is read, because the command addresses any client the controller knows,
    connected or not (a blocked client is offline and absent from list_clients). An id is
    read with the Integration client GET, which answers for connected clients only; an id
    it does not find fails asking for the client's MAC instead. Nothing is sent to
    ``stamgr`` before the MAC is known.
    """
    if _is_mac(client_id):
        return _colon_mac(client_id)
    _validate_client_ref(client_id)
    try:
        return await _client_mac(client, host_id, site_id, client_id, key)
    except UniFiConnectionError as exc:
        if not str(exc).startswith("HTTP 404 from "):
            raise
        raise UniFiConnectionError(
            f"{exc} -- client {client_id} was not found among the connected clients of site "
            f"{site_id!r} (a client id resolves only while the client is connected; an "
            "offline or blocked client has no readable id). Pass the client's MAC instead: "
            "mac from list_known_clients (every known client, incl. offline and blocked) or "
            "the controller UI. Nothing was sent."
        ) from None


# The actions the published executeConnectedClientAction operation accepts (Network
# 10.6.106 "Client action request": a discriminator on ``action``). Block, unblock and
# reconnect are NOT among them: they are block_client / unblock_client / reconnect_client.
_CLIENT_ACTIONS = ("AUTHORIZE_GUEST_ACCESS", "UNAUTHORIZE_GUEST_ACCESS")


def _check_client_action(action: Any) -> None:
    """Fail before any request when ``action`` is not a published client action."""
    name = action.get("action") if isinstance(action, dict) else None
    if name not in _CLIENT_ACTIONS:
        raise ValueError(
            f"action.action must be one of {', '.join(_CLIENT_ACTIONS)} (got {name!r}). "
            "To block, unblock or reconnect a client use block_client, unblock_client or "
            "reconnect_client."
        )


_VALID_CLIENT_TYPES = frozenset({*CLIENT_TYPES, "ALL"})


def _resolve_client_filter(client_type: str | None, filter: str | None) -> str | None:
    """Resolve ``client_type`` and ``filter`` into one upstream filter expression.

    ``client_type`` is a convenience shorthand: it is translated into the upstream
    ``type.eq('<TYPE>')`` filter expression, for every type the spec lists
    (:data:`CLIENT_TYPES`: WIRED, WIRELESS, VPN, TELEPORT). The raw ``type`` query
    parameter the UniFi Integration API does NOT honour (it silently returns every
    client regardless), so translating to ``filter`` is what actually narrows the
    result. ``client_type='ALL'`` (case-insensitive) means "no type restriction" and
    contributes no filter.

    ``client_type`` and an explicit ``filter`` are mutually exclusive whenever
    ``client_type`` would itself produce a filter: the upstream filter grammar has no
    conjunction operator (``and`` and ``&&`` are both rejected with HTTP 400), so the
    two cannot be composed. Passing both raises ``ValueError`` rather than silently
    dropping one and returning wrong results. ``client_type='ALL'`` adds no
    restriction, so it composes trivially and defers to the explicit ``filter``.
    """
    if client_type is None or not client_type.strip():
        return filter  # a blank client_type applies no type filter
    normalized = client_type.strip().upper()
    if normalized not in _VALID_CLIENT_TYPES:
        raise ValueError(
            f"client_type must be one of {', '.join((*CLIENT_TYPES, 'ALL'))} (got {client_type!r})"
        )
    if normalized == "ALL":
        return filter
    if filter is not None:
        raise ValueError(
            "client_type and filter are mutually exclusive; the upstream filter grammar "
            "cannot compose them. Fold the type into your filter expression instead, "
            "e.g. filter=\"type.eq('WIRED')\"."
        )
    return f"type.eq('{normalized}')"


#: ``list_clients`` sources: the published Integration API (default) and the controller's
#: v2 active-client list (Network 11.0.81 web UI, GET
#: /proxy/network/v2/api/site/{site}/clients/active).
LIST_CLIENTS_SOURCES = ("integration", "v2")

#: The v2 client-list query flags the Network 11.0.81 web UI sends on clients/active,
#: clients/local and clients/history: {tool argument: upstream query key}.
V2_CLIENT_FLAGS = {
    "include_matter_thread_clients": "includeMatterThreadClients",
    "include_traffic_usage": "includeTrafficUsage",
    "include_unifi_devices": "includeUnifiDevices",
}


def v2_flag_params(flags: dict[str, bool | None]) -> dict[str, str]:
    """The v2 query parameters for the boolean flags that were given (``"true"`` /
    ``"false"``, the form the web UI sends); an omitted (``None``) flag sends nothing."""
    return {
        V2_CLIENT_FLAGS.get(name, name): "true" if value else "false"
        for name, value in flags.items()
        if value is not None
    }


def _given(value: Any) -> bool:
    """An argument names something: not omitted and not a blank string."""
    return value is not None and not (isinstance(value, str) and not value.strip())


def resolve_list_source(
    tool: str,
    source: str | None,
    choices: tuple[str, ...],
    default: str,
    newer: str,
    *,
    newer_args: dict[str, Any],
    default_args: dict[str, Any],
) -> str:
    """The route a list tool reads, from its own ``source`` argument and the arguments
    that belong to only one route.

    A blank or omitted ``source`` keeps ``default`` unless an argument that only the
    ``newer`` route takes was given (then ``newer`` is used: the argument names it). An
    explicit ``source`` that contradicts the given arguments, or arguments of both routes
    given together, raise before any request: they name two routes at once. A blank string
    names nothing, so it never counts as given.
    """
    chosen = source.strip().lower() if isinstance(source, str) and source.strip() else None
    if chosen is not None and chosen not in choices:
        raise ValueError(f"{tool} source must be one of {', '.join(choices)} (got {source!r})")
    given_newer = sorted(name for name, value in newer_args.items() if _given(value))
    given_default = sorted(name for name, value in default_args.items() if _given(value))
    if given_newer and given_default:
        raise ValueError(
            f"{tool} source conflict: {', '.join(given_newer)} apply only to source "
            f"{newer!r} and {', '.join(given_default)} only to source {default!r}; "
            "pass the arguments of one source."
        )
    if chosen is None:
        return newer if given_newer else default
    if chosen == default and given_newer:
        raise ValueError(
            f"{tool} source conflict: {', '.join(given_newer)} apply only to source "
            f"{newer!r}, but source {default!r} was given; omit source or pass {newer!r}."
        )
    if chosen == newer and given_default:
        raise ValueError(
            f"{tool} source conflict: {', '.join(given_default)} apply only to source "
            f"{default!r}, but source {newer!r} was given; omit them or omit source."
        )
    return chosen


async def _list_clients_v2(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    flags: dict[str, bool | None],
) -> Any:
    """The controller's v2 active-client list, verbatim (one request; the route is not
    paginated in the web UI's use of it)."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    validate_id(site_slug, "site_slug")
    params = v2_flag_params(flags)
    return await client.get(
        v2_site(host_id, site_slug, "/clients/active"),
        key=key,
        **({"params": params} if params else {}),
    )


async def _list_clients(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
    client_type: str | None = None,
    filter: str | None = None,
    source: str | None = None,
    include_matter_thread_clients: bool | None = None,
    include_traffic_usage: bool | None = None,
    include_unifi_devices: bool | None = None,
) -> Any:
    """List connected clients for a site with optional pagination and type filter.

    By default every offset page is drained and the complete client list is
    returned as ``{data, totalCount}``. A limit without offset requests a total
    gathered automatically in batches. An explicit offset selects one native page,
    with any limit forwarded as its page size. client_type is a filter (not paging)
    and applies in either mode. A drain that hits the page cap returns the clients
    gathered so far with incomplete=true rather than truncating silently. ``filter``
    is a server-side filter (not paging), forwarded unchanged as the Network Integration API
    ``filter`` query parameter and applied in either mode; when ``None`` it is
    omitted rather than sent as the string ``"None"``. ``client_type`` is translated
    into a ``type.eq(...)`` filter expression and is mutually exclusive with an
    explicit ``filter`` (see ``_resolve_client_filter``).

    ``source="v2"`` (or any ``include_*`` flag) reads the controller's v2
    active-client list instead and returns its body verbatim (see
    :func:`_list_clients_v2`); the Integration-only arguments then do not apply.
    """
    validate_pagination(page_size=limit, offset=offset, names={"page_size": "limit"})
    flags = {
        "include_matter_thread_clients": include_matter_thread_clients,
        "include_traffic_usage": include_traffic_usage,
        "include_unifi_devices": include_unifi_devices,
    }
    chosen = resolve_list_source(
        "list_clients",
        source,
        LIST_CLIENTS_SOURCES,
        "integration",
        "v2",
        newer_args=flags,
        default_args={
            "offset": offset,
            "limit": limit,
            "client_type": client_type,
            "filter": filter,
        },
    )
    if chosen == "v2":
        return await _list_clients_v2(client, registry, host, site, flags)
    resolved_filter = _resolve_client_filter(client_type, filter)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    base: dict[str, Any] = {}
    if resolved_filter is not None:
        base["filter"] = resolved_filter
    url = _proxy(host_id, f"/sites/{site_id}/clients")
    collected = await collect_offset(
        client, url, key=key, params=base or None, offset=offset, limit=limit
    )
    return offset_list_result(collected)


async def _get_client(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    client_id: str,
) -> dict[str, Any]:
    """Get details for a single client (by UUID, or by MAC resolved with list_clients)."""
    _validate_client_ref(client_id)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    client_id, _mac = await _resolve_client(client, host_id, site_id, client_id, key)
    validate_id(client_id, "client_id")
    return await client.get(_proxy(host_id, f"/sites/{site_id}/clients/{client_id}"), key=key)


async def _execute_client_action(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    client_id: str,
    action: dict[str, Any],
) -> dict[str, Any]:
    """Execute a client action: AUTHORIZE_GUEST_ACCESS or UNAUTHORIZE_GUEST_ACCESS."""
    _check_client_action(action)
    _validate_client_ref(client_id)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    client_id, _mac = await _resolve_client(client, host_id, site_id, client_id, key)
    validate_id(client_id, "client_id")
    return await client.post(
        _proxy(host_id, f"/sites/{site_id}/clients/{client_id}/actions"), key=key, json=action
    )


async def _block_client(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    client_id: str,
) -> dict[str, Any]:
    """Block a client on a site via Classic REST stamgr."""
    _validate_client_ref(client_id)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    mac = await _stamgr_mac(client, host_id, site_id, client_id, key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.post(
        _classic_cmd(host_id, site_slug, "/stamgr"), key=key, json={"cmd": "block-sta", "mac": mac}
    )


async def _unblock_client(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    client_id: str,
) -> dict[str, Any]:
    """Unblock a previously blocked client on a site via Classic REST stamgr."""
    _validate_client_ref(client_id)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    mac = await _stamgr_mac(client, host_id, site_id, client_id, key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.post(
        _classic_cmd(host_id, site_slug, "/stamgr"),
        key=key,
        json={"cmd": "unblock-sta", "mac": mac},
    )


async def _reconnect_client(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    client_id: str,
) -> dict[str, Any]:
    """Force a client to reconnect on a site via Classic REST stamgr."""
    _validate_client_ref(client_id)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    mac = await _stamgr_mac(client, host_id, site_id, client_id, key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.post(
        _classic_cmd(host_id, site_slug, "/stamgr"), key=key, json={"cmd": "kick-sta", "mac": mac}
    )


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register all client management MCP tools."""

    @mcp.tool(annotations=READ_ONLY)
    async def list_clients(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        client_type: str | None = None,
        filter: str | None = None,
        source: str | None = None,
        include_matter_thread_clients: bool | None = None,
        include_traffic_usage: bool | None = None,
        include_unifi_devices: bool | None = None,
    ) -> Any:
        """List connected clients for a site.

        Returns {data, totalCount}: every page is drained; data holds the client records verbatim
        and totalCount is the upstream total (null when none was reported). The first page's other
        envelope fields are kept beside them, and incomplete / incompleteReason are added when a
        capped drain stopped short. A limit without offset requests a total gathered in batches.
        An explicit offset returns one upstream page with its envelope and page-size accounting.
        With source "v2" (or any
        include_* flag) the controller's v2 active-client list (GET
        network/v2/api/site/{site}/clients/active, the web UI's route) is returned verbatim
        instead; it can include Matter/Thread clients.

        By default every page is drained and the complete client list is returned
        as {data, totalCount}. Limit alone requests a total; offset selects one native page
        with the API's totalCount surfaced so you can advance. client_type: convenience
        shorthand — WIRED, WIRELESS, VPN, TELEPORT or ALL (default: all types) — translated into
        the upstream `type.eq(...)` filter (the raw type query parameter is ignored
        by the UniFi API, so this translation is what actually narrows the result).

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            offset: Optional zero-based offset for fetching one page manually. Omit both offset and
                limit to drain every page and get the complete list.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 200, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain all.
                Example: `25`.
            client_type: Optional shorthand WIRED, WIRELESS, VPN, TELEPORT (every type the spec
                lists) or ALL (default: all types), translated into the upstream `type.eq(...)`
                filter. Mutually exclusive with filter. An empty or whitespace value applies no
                type filter (like ALL).
            filter: optional Network Integration API filter expression, forwarded unchanged as the
                upstream `filter` query parameter for server-side filtering (e.g.
                `type.eq('WIRED')`, `macAddress.eq('aa:bb:cc:dd:ee:ff')`); omitted entirely when
                unset. client_type and an explicit filter are mutually exclusive (the upstream
                grammar has no conjunction operator to compose them); passing both raises an error
                rather than silently returning wrong results. A capped drain returns the clients
                gathered so far with incomplete=true rather than truncating silently.
                Example: `type.eq('WIRED')`.
            source: Optional route: "integration" (default, the published API) or "v2"
                (the controller's v2 active-client list). offset, limit, client_type and
                filter apply only to "integration"; the include_* flags only to "v2".
                Example: `v2`.
            include_matter_thread_clients: Optional v2 flag (query includeMatterThreadClients):
                true also lists Matter/Thread clients. Selects source "v2".
                Example: `true`.
            include_traffic_usage: Optional v2 flag (query includeTrafficUsage): true asks the
                controller to include traffic usage. Selects source "v2". Example: `true`.
            include_unifi_devices: Optional v2 flag (query includeUnifiDevices): true asks the
                controller to include UniFi devices. Selects source "v2". Example: `false`.
        """
        client, registry = deps_fn()
        return await _list_clients(
            client,
            registry,
            host,
            site,
            offset=offset,
            limit=limit,
            client_type=client_type,
            filter=filter,
            source=source,
            include_matter_thread_clients=include_matter_thread_clients,
            include_traffic_usage=include_traffic_usage,
            include_unifi_devices=include_unifi_devices,
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_client(
        host: str,
        site: str,
        client_id: str,
    ) -> Any:
        """Get details for a single client.

        Returns the upstream client object verbatim, exactly as the API answers it.

        Example call (get_client):
            {
              "host": "my-console",
              "site": "Default",
              "client_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            client_id: Connected client UUID or MAC (AA:BB:CC:DD:EE:FF, aa-bb-..., AABBCCDDEEFF);
                a MAC is resolved to the client id with list_clients (macAddress filter), so the
                client must be connected; an unknown MAC fails listing the connected clients.
                Get it from list_clients (data[].id or data[].macAddress). Network-app id — not
                a Protect id.
        """
        client, registry = deps_fn()
        return await _get_client(client, registry, host, site, client_id)

    @mcp.tool(annotations=WRITE)
    async def execute_client_action(
        host: str,
        site: str,
        client_id: str,
        action: dict[str, Any],
        confirm: bool = False,
    ) -> Any:
        """Execute a guest-access client action: AUTHORIZE_GUEST_ACCESS or
        UNAUTHORIZE_GUEST_ACCESS (the only actions the API accepts). To block, unblock or
        reconnect a client use block_client, unblock_client or reconnect_client. Any other
        action fails before a request is sent, listing the valid actions.

        Consequence: AUTHORIZE_GUEST_ACCESS lets the guest onto the network now;
        UNAUTHORIZE_GUEST_ACCESS revokes the guest's access.

        Returns the upstream response body verbatim: the action-result object the API answers with
        (under UNIFI_DRY_RUN, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
        message,
        preview: {method, path, params (query parameters), body}} instead).

        Request body (Network 10.6.106, POST /v1/sites/{siteId}/clients/{clientId}/actions
        (executeConnectedClientAction); schema "Client action request") is passed in `action`.
        Required keys — action.
        - action: string, AUTHORIZE_GUEST_ACCESS or UNAUTHORIZE_GUEST_ACCESS
        Variants by `action` — AUTHORIZE_GUEST_ACCESS requires action and takes the optional
        integers timeLimitMinutes (1-1000000, how long the guest is authorized; omitted, the
        site's default limit applies), dataUsageLimitMBytes (1-1048576, data usage limit in
        MB), rxRateLimitKbps and txRateLimitKbps (2-100000, download / upload rate limit in
        kbps); UNAUTHORIZE_GUEST_ACCESS requires action only (it revokes access and
        disconnects the guest).

        Example call (execute_client_action):
            {
              "host": "my-console",
              "site": "Default",
              "client_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
              "action": {"action": "AUTHORIZE_GUEST_ACCESS", "timeLimitMinutes": 60}
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            client_id: Connected client UUID or MAC (AA:BB:CC:DD:EE:FF, aa-bb-..., AABBCCDDEEFF);
                a MAC is resolved to the client id with list_clients (macAddress filter), so the
                client must be connected; an unknown MAC fails listing the connected clients.
                Get it from list_clients (data[].id or data[].macAddress). Network-app id — not
                a Protect id.
            action: Action body; spec Client action request. Required: action. 'action' selects
                variant: AUTHORIZE_GUEST_ACCESS|UNAUTHORIZE_GUEST_ACCESS. AUTHORIZE_GUEST_ACCESS
                optionally takes timeLimitMinutes, dataUsageLimitMBytes, rxRateLimitKbps and
                txRateLimitKbps.
            confirm: Ignored; accepted for backward compatibility. The call executes immediately
                when made unless the operator opted in to UNIFI_DRY_RUN (then nothing
                is sent upstream and a preview of the request is returned).
        """
        client, registry = deps_fn()
        return await _execute_client_action(client, registry, host, site, client_id, action)

    @mcp.tool(annotations=WRITE)
    async def block_client(
        host: str,
        site: str,
        client_id: str,
    ) -> Any:
        """Block a client on a site: any client the controller knows, connected or not (an
        offline client can be pre-blocked by its MAC).

        Consequence: the client is disconnected and cannot rejoin the site until unblocked with
        unblock_client.

        Returns the upstream Classic body verbatim: {meta: {rc}, data: [...]} (under
        UNIFI_DRY_RUN, the dry-run preview {status: "dry_run", dryRun: true, sent: false, message,
        preview: {method, path, params (query parameters), body}} instead).

        Request body: none is passed by the caller. Tool sends
        {"cmd": "block-sta", "mac": CLIENT_MAC} (CLIENT_MAC is the client MAC address) to
        classic cmd/stamgr (no published spec).

        Example call (block_client):
            {
              "host": "my-console",
              "site": "Default",
              "client_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            client_id: Client UUID or MAC (AA:BB:CC:DD:EE:FF, aa-bb-..., AABBCCDDEEFF). A MAC
                may be that of any client the controller knows, connected or not: it is sent
                to the controller as is (lowercase colon form) with no list lookup. A UUID is
                resolved to the MAC with the client GET, which finds connected clients only;
                an unknown UUID fails asking for the MAC. For a connected client,
                get it from list_clients (data[].macAddress or data[].id); for any known client,
                the mac from list_known_clients (includes offline and blocked clients).
                Network-app id — not a Protect id.
        """
        client, registry = deps_fn()
        return await _block_client(client, registry, host, site, client_id)

    @mcp.tool(annotations=WRITE)
    async def unblock_client(
        host: str,
        site: str,
        client_id: str,
    ) -> Any:
        """Unblock a previously blocked client on a site: any client the controller knows,
        connected or not. A blocked client is offline and absent from list_clients: pass its
        MAC (list_known_clients mac).

        Consequence: the client may connect to the site again.

        Returns the upstream Classic body verbatim: {meta: {rc}, data: [...]} (under
        UNIFI_DRY_RUN, the dry-run preview {status: "dry_run", dryRun: true, sent: false, message,
        preview: {method, path, params (query parameters), body}} instead).

        Request body: none is passed by the caller. Tool sends
        {"cmd": "unblock-sta", "mac": CLIENT_MAC} (CLIENT_MAC is the client MAC address) to
        classic cmd/stamgr (no published spec).

        Example call (unblock_client):
            {
              "host": "my-console",
              "site": "Default",
              "client_id": "aa:bb:cc:dd:ee:ff"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            client_id: Client UUID or MAC (AA:BB:CC:DD:EE:FF, aa-bb-..., AABBCCDDEEFF). A MAC
                may be that of any client the controller knows, connected or not: it is sent
                to the controller as is (lowercase colon form) with no list lookup. A UUID is
                resolved to the MAC with the client GET, which finds connected clients only;
                an unknown UUID fails asking for the MAC. For a connected client,
                get it from list_clients (data[].macAddress or data[].id); for any known client,
                the mac from list_known_clients (includes offline and blocked clients).
                Network-app id — not a Protect id.
        """
        client, registry = deps_fn()
        return await _unblock_client(client, registry, host, site, client_id)

    @mcp.tool(annotations=WRITE)
    async def reconnect_client(
        host: str,
        site: str,
        client_id: str,
    ) -> Any:
        """Force a client to reconnect on a site (addressed by MAC; a MAC given is sent as
        is, with no client list read).

        Consequence: the client is disconnected and has to reconnect, briefly interrupting its
        traffic.

        Returns the upstream Classic body verbatim: {meta: {rc}, data: [...]} (under
        UNIFI_DRY_RUN, the dry-run preview {status: "dry_run", dryRun: true, sent: false, message,
        preview: {method, path, params (query parameters), body}} instead).

        Request body: none is passed by the caller. Tool sends
        {"cmd": "kick-sta", "mac": CLIENT_MAC} (CLIENT_MAC is the client MAC address) to
        classic cmd/stamgr (no published spec).

        Example call (reconnect_client):
            {
              "host": "my-console",
              "site": "Default",
              "client_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            client_id: Client UUID or MAC (AA:BB:CC:DD:EE:FF, aa-bb-..., AABBCCDDEEFF). A MAC
                may be that of any client the controller knows, connected or not: it is sent
                to the controller as is (lowercase colon form) with no list lookup. A UUID is
                resolved to the MAC with the client GET, which finds connected clients only;
                an unknown UUID fails asking for the MAC. For a connected client,
                get it from list_clients (data[].macAddress or data[].id); for any known client,
                the mac from list_known_clients (includes offline and blocked clients).
                Network-app id — not a Protect id.
        """
        client, registry = deps_fn()
        return await _reconnect_client(client, registry, host, site, client_id)
