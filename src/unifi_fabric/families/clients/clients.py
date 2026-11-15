"""Client management tools — list, get, and actions via connector proxy."""

from __future__ import annotations

from typing import Any

from ...client import (
    UniFiClient,
    UniFiConnectionError,
    describe_shape,
    object_records,
    upstream_error_value,
    validate_id,
    validate_spec_id,
)
from ...macs import colon_mac as _colon_mac
from ...macs import is_mac as _is_mac
from ...macs import record_mac
from ...matching import id_key
from ...registry import Registry, _assert_uuid
from ...resolution_state import note_incomplete_resolution
from ...shared_shapes._classic_objects import v2_site
from ...shared_shapes._clients_shared import (  # noqa: F401  (shared)
    V2_CLIENT_FLAGS as V2_CLIENT_FLAGS,
)
from ...shared_shapes._clients_shared import (
    _given as _given,
)
from ...shared_shapes._clients_shared import (
    resolve_list_source as resolve_list_source,
)
from ...shared_shapes._clients_shared import (
    v2_flag_params as v2_flag_params,
)
from ...shared_shapes._network_shared import _proxy
from ...shared_shapes._pagination import collect_offset, offset_list_result, validate_pagination
from .schemas import (  # the family's shapes (family-owned layout)
    _CLASSIC_CMD_BASE,
    _CLIENT_ACTIONS,
    CLIENT_TYPES,
)

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


def _describe_clients(records: list[dict[str, Any]], client: UniFiClient) -> str:
    return "; ".join(
        f"{upstream_error_value(r.get('name') or r.get('hostname') or '(unnamed)', client)} "
        f"(mac={_record_mac(r)}, "
        f"id={upstream_error_value(r.get('id'), client)})"
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
                "non-empty string native id; identifying fields: "
                f"{_describe_clients([r], client)}; "
                f"id={upstream_error_value(native_id, client)!r}"
            )
        ids.append(native_id)
    if len({id_key(i) for i in ids}) > 1:
        raise ValueError(
            f"MAC {client_id!r} matches distinct client ids in site {site_id!r}: "
            f"{_describe_clients(matches, client)}. Pass the client UUID (list_clients data[].id)."
        )
    if ids:
        try:
            validate_id(ids[0], "client_id")
        except ValueError:
            try:
                validate_id(upstream_error_value(ids[0], client), "client_id")
            except ValueError as exc:
                raise ValueError(str(exc)) from None
        if collected["incomplete"]:
            note_incomplete_resolution(collected["incompleteReason"])
        return ids[0], mac
    if collected["incomplete"]:
        raise ValueError(
            f"Cannot resolve MAC {client_id!r} in site {site_id!r}: the client list is "
            f"incomplete ({upstream_error_value(collected['incompleteReason'])})."
        )
    everyone = await collect_offset(client, url, key=key)
    valid = object_records(everyone["items"], f"GET {url}")
    partial = (
        f" (the client list is incomplete: {upstream_error_value(everyone['incompleteReason'])})"
        if everyone["incomplete"]
        else ""
    )
    raise ValueError(
        f"No connected client with MAC {mac} in site {site_id!r}{partial}: this tool needs "
        "the client's Integration id, which exists only while the client is connected; "
        f"valid (connected): {_describe_clients(valid, client) or '(none)'}. "
        "Get it from list_clients "
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


async def _list_active_clients(
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
    explicit ``filter`` (see ``_resolve_client_filter``). This tool uses only the
    published Integration API; the controller's private v2 route is exposed separately
    as :func:`_list_active_clients` so official-only source selection remains accurate.
    """
    validate_pagination(page_size=limit, offset=offset, names={"page_size": "limit"})
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


async def _wake_client(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    client_id: str,
) -> dict[str, Any]:
    """Send a Wake-on-LAN packet to a client through the Network v2 wake-on-lan route."""
    _validate_client_ref(client_id)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    mac = await _stamgr_mac(client, host_id, site_id, client_id, key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.post(v2_site(host_id, site_slug, f"/wake-on-lan/{mac}"), key=key, json={})
