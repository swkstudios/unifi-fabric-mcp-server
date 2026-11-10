"""UniFi Mobility tools — workspace-scoped identity (no console host/site).

The UniFi Mobility API (https://developer.ui.com/mobility/v1.0.0) is a *cloud*
resource family served directly from the Site Manager gateway (base
``https://api.ui.com``) under ``/v1/mobility/...``. Its identity model is
**workspace-based**: a workspace (a "mobility cloud site") owns UMR mobile
routers (devices), each of which has clients. A Mobility workspace is not a UniFi
console, so there is no ``host``/``site`` resolution here: the tools take a
``workspace_id`` (and ``device_id``) directly and never touch the host/site registry.

Auth is the same Fabric / Site Manager API key used everywhere else in this
server; an optional ``key_label`` selects a specific configured key for
multi-key deployments (``APIKeyConfig.label``). A missing Mobility scope on the
key, or a workspace whose Mobility subscription is unavailable, surfaces as the
upstream error verbatim (HTTP 401/403 with the gateway's ``code`` / ``message``
/ ``traceId`` body) — the server does not mask it.

Reads are typed pass-throughs. The three documented ``PUT`` writes (device name,
LAN/DHCP, wireless) share one flow: the area opt-out (writes are enabled by default; the
``UNIFI_WRITE_EXCEPTIONS`` entry ``family:mobility=deny`` refuses them) is checked first,
then the arguments are validated, a read-before snapshots the device, an already-applied change
returns ``status="no_op"`` without writing, and a read-after reports the outcome. The
LAN/DHCP endpoint is a documented partial update; device-name and wireless send the
full documented body. Every write result has the same shape: ``changed`` maps each
sent field to ``{"from": ..., "to": ...}``, ``verified`` maps each field observable in
the device detail to a bool, ``device`` is the read-after detail, and ``response`` is the
upstream PUT body verbatim. Every write accepts an optional ``confirm`` argument, which
is ignored.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from typing import Any, cast

from fastmcp import FastMCP
from pydantic import Field

from ... import switches
from ...argument_errors import echoed_input
from ...client import (
    UniFiClient,
    UniFiConnectionError,
    decode_body,
    describe_shape,
    is_dry_run_preview,
    object_records,
    validate_id,
)
from ...config import APIKeyConfig
from ...read_only import guard_request, mark_write_denied
from ...shared_shapes._keys import (
    context_value,
    fan_out,
    first_id,
    first_success,
    merge_first_key,
    report_keys,
    stable_id,
    with_context,
    without_server_fields,
)
from ...shared_shapes._pagination import (
    MOBILITY_MAX_LIMIT,
    collect_batch,
    mark_incomplete,
    validate_pagination,
    verbatim_list_result,
)
from ...shared_shapes._results import (
    leaf_equal,
    read_after_verdict,
    safe_read_after,
    short_circuit_no_op,
    with_read_after_error,
)
from ...shared_shapes._shared import _nullable_default
from ...tool_annotations import READ_ONLY, WRITE
from ...write_body import require_update_fields

#: Cloud gateway base for the Mobility resource family (served from api.ui.com).
MOBILITY_BASE = "/v1/mobility"
_WORKSPACES = f"{MOBILITY_BASE}/workspaces"

#: Documented page-size cap for the offset-paginated device/client collections.
_MAX_PAGE_SIZE = 200

# Optional nullable request fields distinguish omission from an explicit JSON null.
_UNSET: Any = object()

#: The write exception that opts out the three Mobility PUT writes (``family:mobility=deny``).
WRITE_ENABLED_ENV = switches.MOBILITY_WRITES.env

DISABLED_MSG = switches.area_deny_text("Mobility", WRITE_ENABLED_ENV)


def writes_enabled() -> bool:
    """True unless ``UNIFI_WRITE_EXCEPTIONS`` denies this area's family (read now)."""
    return switches.MOBILITY_WRITES.enabled()


def _extract_list(raw: Any, path: str) -> list[dict[str, Any]]:
    """Return the ``data`` array from the response envelope.

    An unexpected shape raises (naming the shape received) instead of reading as an
    empty list — an empty result must mean the API returned no items.
    """
    if isinstance(raw, dict):
        data = raw.get("data")
        if isinstance(data, list):
            return object_records(data, f"GET {path}")
    raise UniFiConnectionError(
        f"Unexpected response shape from GET {path}: expected an object with a 'data' "
        f"array, got {describe_shape(raw)}"
    )


#: Keys a multi-key merge sets itself (the rest of each key's body goes under byKey). The
#: merge drops a key's own value only where the server placed it (``without_server_fields``):
#: an upstream field of the same name stays under byKey.
_MERGE_OWNED = frozenset({"_count", "incomplete", "incompleteReason"})


def _list_result(raw: Any, path: str) -> dict[str, Any]:
    """A single-GET list response: the upstream body verbatim (``data``, ``total``,
    ``offset``, ``limit``, ``httpStatusCode``, ``traceId`` ...) plus the additive
    ``_count``; ``incomplete: true`` when the upstream ``total`` exceeds the rows sent."""
    return verbatim_list_result(raw, _extract_list(raw, path), path)


async def _drain(
    client: UniFiClient,
    path: str,
    key: APIKeyConfig | None,
    *,
    offset: int | None = None,
    limit: int | None = None,
) -> Any:
    """Drain an offset-paginated collection; a capped/stalled drain keeps what was
    gathered and is flagged ``incomplete`` (never discarded, never silent). The upstream
    ``total`` is reported whenever the API sent one, complete or not.

    ``limit`` requests a total gathered across pages of at most 200, starting at
    ``offset`` (or zero), with effective ``_pageSize`` metadata. An offset alone
    fetches one upstream page; the page body is returned verbatim: a bare
    JSON array as that array, an object once it passes the drain's shape check (a
    ``data`` array)."""
    validate_pagination(offset=offset, page_size=limit, names={"page_size": "limit"})
    if limit is not None:
        collected = await collect_batch(
            lambda controls: client.get(path, key=key, params=controls),
            requested=limit,
            known_max=MOBILITY_MAX_LIMIT,
            family="offset",
            start=offset or 0,
            max_pages=client.paginate_max_pages,
        )
        if "raw" in collected:
            return collected["raw"]
        return mark_incomplete(
            with_context(
                {**collected["envelope"], "data": collected["items"]},
                {"_count": len(collected["items"])},
            ),
            collected,
        )
    if offset is not None:
        # limit is None here: a set limit returned through collect_batch above.
        page = await client.get(path, key=key, params={"offset": offset})
        if isinstance(page, list):
            return page
        # The drain's shape check: an object carrying a 'data' array, else it raises.
        _extract_list(page, path)
        return page
    collected = await collect_batch(
        lambda controls: client.get(path, key=key, params=controls),
        requested=None,
        known_max=MOBILITY_MAX_LIMIT,
        default_size=_MAX_PAGE_SIZE,
        family="offset",
        max_pages=client.paginate_max_pages,
        path=path,
    )
    result = mark_incomplete(
        with_context(
            {**collected["envelope"], "data": collected["items"]},
            {"_count": len(collected["items"])},
        ),
        collected,
    )
    if collected["totalCount"] is not None:
        result = with_context(result, {"total": collected["totalCount"]})
    return result


def _require_writes() -> None:
    """Refuse a Mobility write before any upstream call when the area is opted out."""
    guard_request("PUT", "v1/mobility/workspaces/{workspace}/devices/{device}")
    if not writes_enabled():
        raise mark_write_denied(
            ValueError(DISABLED_MSG + switches.current_value_note(WRITE_ENABLED_ENV))
        )


async def _owning_device(
    client: UniFiClient, key_label: str | None, workspace_id: str, device_id: str
) -> tuple[APIKeyConfig | None, dict[str, Any]]:
    """The key whose organization owns the device, and its device-detail GET body
    (read-before), verbatim.

    Every configured key is tried (unless ``key_label`` names one), so a write always
    goes to the organization that actually holds the device.
    """
    return await first_success(
        client, key_label, lambda key: _fetch_device_body(client, workspace_id, device_id, key)
    )


def _device_path(workspace_id: str, device_id: str) -> str:
    return f"{_WORKSPACES}/{workspace_id}/devices/{device_id}"


# --- Validation helpers ------------------------------------------------------


def _validate_ipv4(value: str, name: str) -> None:
    """Reject a string that is not a dotted-quad IPv4 address before it reaches the API.

    Spec-backed: every caller's field is declared ``"type": "string", "format": "ipv4"``
    in the pinned Mobility spec (``tests/fixtures/openapi/mobility-1.0.0.json``,
    ``UpdateNetworkReq``: ``host_address`` line 539, ``dhcp_range_start`` line 553,
    ``dhcp_range_stop`` line 558). A leading-zero octet (``192.168.01.1``) is refused, as
    :class:`ipaddress.IPv4Address` does, because it has two readings (decimal or octal).
    Only call this for a field whose spec declares ``format: ipv4``; any other field is
    passed through as sent.
    """
    try:
        ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, ValueError):
        raise ValueError(
            f"Invalid {name!r} {echoed_input(value)}: expected an IPv4 address"
        ) from None


def _validate_len(value: str, name: str, low: int, high: int) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{name!r} must be a string")
    if not (low <= len(value) <= high):
        raise ValueError(f"{name!r} must be {low}-{high} characters (got {len(value)})")


# --- Reads -------------------------------------------------------------------


async def list_mobility_workspaces(
    client: UniFiClient,
    *,
    key_label: str | None = None,
) -> dict[str, Any]:
    """List UniFi Mobility workspaces visible to the authenticated API key.

    A workspace is a mobility "cloud site" (``workspace_id``, ``workspace_name``,
    ``is_owner``, ``status``). The upstream body is returned verbatim (``data``,
    ``total``, ``offset``, ``limit``, ``httpStatusCode``, ``traceId``) plus ``_count``;
    a ``total`` above the rows returned marks the result ``incomplete``. This endpoint is
    not query-paginated by the API; the full set is returned in one call. With several
    keys the workspaces are merged under ``data`` and each key's other body fields are
    kept under ``byKey[<label>]``.

    key_label: optional configured API-key label to route the request on a
    specific key (multi-key deployments). Omit to cover every configured key: results
    are merged and a key that fails is reported under errors.
    """

    async def _fetch(key: APIKeyConfig | None) -> dict[str, Any]:
        return _list_result(await client.get(_WORKSPACES, key=key), _WORKSPACES)

    results, errors, multi = await fan_out(client, key_label, _fetch)
    if not multi:
        return results[0][1]
    # A workspace visible to several keys is listed once, under the first key in order.
    workspaces = merge_first_key(
        [(label, part["data"]) for label, part in results],
        first_id(stable_id("workspace_id"), stable_id("id")),
        multi=True,
    )
    out: dict[str, Any] = {
        "data": workspaces,
        "_count": len(workspaces),
        # Each key's other upstream body fields (total, traceId ...), never dropped.
        "byKey": {
            str(label): {
                k: v for k, v in without_server_fields(part, _MERGE_OWNED).items() if k != "data"
            }
            for label, part in results
        },
    }
    reasons = [
        f"{label}: {context_value(part, 'incompleteReason', strict=True)}"
        for label, part in results
        if context_value(part, "incomplete", strict=True)
    ]
    if reasons:
        out["incomplete"] = True
        out["incompleteReason"] = "; ".join(reasons)
    return report_keys(out, [label for label, _ in results], errors, multi=True)


async def list_mobility_admins(
    client: UniFiClient,
    workspace_id: str,
    *,
    key_label: str | None = None,
) -> dict[str, Any]:
    """List the admins of a Mobility workspace (mobility permissions only).

    Each admin carries ``name``, ``email``, ``status``, ``is_owner`` and a
    ``permissions`` object exposing the ``umr`` (Mobile Routing) level
    (ALL/VIEW_ONLY/NONE); ``permissions`` is ``null`` for a pending invite.
    The upstream body is returned verbatim plus ``_count`` (``incomplete`` when its
    ``total`` exceeds the rows returned).

    workspace_id: the workspace UUID from list_mobility_workspaces.
    key_label: optional configured API-key label to route on a specific key.
    """
    validate_id(workspace_id, "workspace_id")
    path = f"{_WORKSPACES}/{workspace_id}/admins"

    async def _fetch(key: APIKeyConfig | None) -> dict[str, Any]:
        return _list_result(await client.get(path, key=key), path)

    _key, result = await first_success(client, key_label, _fetch)
    return result


async def list_mobility_devices(
    client: UniFiClient,
    workspace_id: str,
    *,
    key_label: str | None = None,
    offset: int | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """List the UMR devices in a Mobility workspace.

    Each device is the lightweight summary (``id``, ``name``, ``model``,
    ``state``, ``firmware_version``, ``mac_address``). This collection is
    offset-paginated by the API (``limit``/``offset``, 200 max); every page is
    drained and the complete list is returned, unless ``offset`` / ``limit`` ask for
    a requested total gathered across bounded pages with _pageSize metadata.

    workspace_id: the workspace UUID from list_mobility_workspaces.
    key_label: optional configured API-key label to route on a specific key.
    """
    validate_id(workspace_id, "workspace_id")
    path = f"{_WORKSPACES}/{workspace_id}/devices"
    _key, result = await first_success(
        client, key_label, lambda key: _drain(client, path, key, offset=offset, limit=limit)
    )
    return result


async def get_mobility_device(
    client: UniFiClient,
    workspace_id: str,
    device_id: str,
    *,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Get full detail for one UMR device in a Mobility workspace.

    Returns the upstream response object verbatim: the complete DeviceDetail
    (WAN/cellular/WiFi/VPN/subscription/GPS, counts, and the summary fields) under
    ``data``, beside every other envelope field the API sends.

    workspace_id: the workspace UUID from list_mobility_workspaces.
    device_id: the device UUID from list_mobility_devices.
    key_label: optional configured API-key label to route on a specific key.
    """
    validate_id(workspace_id, "workspace_id")
    validate_id(device_id, "device_id")
    path = _device_path(workspace_id, device_id)

    async def _read(key: APIKeyConfig | None) -> dict[str, Any]:
        raw = await client.get(path, key=key)
        _device_from_body(raw, path)  # shape check only; the body is returned verbatim
        return dict(raw)

    _key, body = await first_success(client, key_label, _read)
    return body


async def list_mobility_clients(
    client: UniFiClient,
    workspace_id: str,
    device_id: str,
    *,
    key_label: str | None = None,
    offset: int | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """List the clients associated with a UMR device.

    Each client carries ``mac``, ``name``, ``type`` (WIRED/WIRELESS),
    ``connection_status``, ``ip_address``, ``is_blocked`` and (wireless only) a
    ``wifi_experience`` score. This collection is offset-paginated by the API
    (``limit``/``offset``, 200 max); every page is drained unless ``offset`` /
    ``limit`` ask for a requested total gathered across bounded pages with _pageSize metadata.

    workspace_id: the workspace UUID from list_mobility_workspaces.
    device_id: the device UUID from list_mobility_devices.
    key_label: optional configured API-key label to route on a specific key.
    """
    validate_id(workspace_id, "workspace_id")
    validate_id(device_id, "device_id")
    path = f"{_device_path(workspace_id, device_id)}/clients"
    _key, result = await first_success(
        client, key_label, lambda key: _drain(client, path, key, offset=offset, limit=limit)
    )
    return result


async def _fetch_device_body(
    client: UniFiClient,
    workspace_id: str,
    device_id: str,
    key: APIKeyConfig | None,
) -> dict[str, Any]:
    """GET a device detail and return the body verbatim (envelope kept), shape-checked.

    Write results embed this body whole; comparisons read the device fields through
    :func:`_device_from_body`.
    """
    path = _device_path(workspace_id, device_id)
    raw = await client.get(path, key=key)
    _device_from_body(raw, path)  # raises, naming the shape, unless it carries a device
    return cast(dict[str, Any], raw)


def _device_from_body(raw: Any, path: str) -> dict[str, Any]:
    """The device object of a device-detail body, or raise naming the shape received."""
    if isinstance(raw, dict):
        if "data" not in raw:
            return raw
        inner = raw["data"]
        if isinstance(inner, dict):
            return inner
        raise UniFiConnectionError(
            f"Unexpected response shape from GET {path}: expected 'data' to be a device "
            f"object, got {describe_shape(inner)}"
        )
    raise UniFiConnectionError(
        f"Unexpected response shape from GET {path}: expected a device object, got "
        f"{describe_shape(raw)}"
    )


# --- Writes ------------------------------------------------------------------
#
# Each of the three documented PUT resources follows the same guarded flow, in order:
#   1. env gate     — the write opt-out (writes enabled by default; the
#                     UNIFI_WRITE_EXCEPTIONS entry family:mobility=deny or
#                     UNIFI_WRITE_POLICY=deny makes them read-only) refuses before
#                     any validation or upstream call when set;
#   2. validate     — enforce the documented field constraints locally;
#   3. read-before  — GET the device detail (proves it exists; snapshot state);
#   4. no-op detect — if the change is fully observable in the detail AND already
#                     matches, return status="no_op" without writing;
#   5. PUT          — issue the write. The endpoints answer 204 No Content; any body
#                     the upstream does send is returned verbatim as `response`;
#   6. read-after   — GET again and report `changed` ({field: {from, to}}) plus a
#                     `verified` map for the fields that ARE observable in the detail.
# The result's `device` is the full device-detail GET body verbatim (read-after, or the
# read-before for a no-op), envelope included; nothing is unwrapped.


def _dry_run_result(before_body: dict[str, Any], response: Any) -> dict[str, Any]:
    """Result of a guarded write under ``dry-run policy``: the preview, no read-after.

    No write was sent, so a read-after would only show the unchanged device and report
    the change as unverified; ``device`` is the read-before GET body verbatim.
    """
    return {"status": "dry_run", "device": before_body, "response": response}


async def _read_after(
    client: UniFiClient, workspace_id: str, device_id: str, key: APIKeyConfig | None
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, str | None]:
    """The read-after of an applied write: ``(body, device, None)``, or ``(None, None,
    reason)`` when the re-read fails (never raised: the write already happened)."""
    path = _device_path(workspace_id, device_id)

    async def _read() -> tuple[dict[str, Any], dict[str, Any]]:
        body = await _fetch_device_body(client, workspace_id, device_id, key)
        return body, _device_from_body(body, path)

    read, error = await safe_read_after(_read)
    if read is None:
        return None, None, error
    return read[0], read[1], None


def _updated(
    changed: dict[str, Any],
    checks: dict[str, Any],
    after_body: dict[str, Any] | None,
    after: dict[str, Any] | None,
    response: Any,
    error: str | None,
) -> dict[str, Any]:
    """The result of an applied write (:func:`read_after_verdict`). ``verified`` covers
    every requested field, using null for fields absent from the pinned device-detail
    schema and type-strict booleans for observable fields (a missing field is false). The
    whole map is null when the read-after failed or returned an unexpected shape
    (``readAfterError`` says why)."""
    verified, error = read_after_verdict(
        after,
        error,
        lambda device: {
            name: (None if field is None else field in device and leaf_equal(device[field], value))
            for name, (field, value) in checks.items()
        },
    )
    result = {
        "status": "updated",
        "changed": changed,
        "verified": verified,
        "device": after_body,
        "response": response,
    }
    return with_read_after_error(result, error)


async def _put_no_content(
    client: UniFiClient,
    path: str,
    body: dict[str, Any],
    key: APIKeyConfig | None,
) -> Any:
    """Issue a PUT whose documented success is a 204 No Content.

    Whatever the upstream sends is decoded by ``client.decode_body`` (the server's
    single pass-through rule: decoded JSON, raw text, or ``None`` for the empty 204 body)
    and surfaced as ``response`` in the tool result. Any non-2xx is already raised by
    ``client.request``.
    """
    resp = await client.request("PUT", path, key=key, json=body)
    return decode_body(resp)


async def update_mobility_device_name(
    client: UniFiClient,
    workspace_id: str,
    device_id: str,
    name: str,
    *,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Rename a UMR device (PUT .../devices/{deviceID}). Guarded write.

    Sends the full documented body ``{"name": name}`` (1-32 characters). Does a
    read-before, returns status="no_op" when the device already has this name, and
    re-reads the device to verify the rename (``verified.name``).

    workspace_id: the workspace UUID from list_mobility_workspaces.
    device_id: the device UUID from list_mobility_devices.
    name: the new device name (1-32 characters).
    key_label: optional configured API-key label to route on a specific key.
    """
    _require_writes()
    validate_id(workspace_id, "workspace_id")
    validate_id(device_id, "device_id")
    _validate_len(name, "name", 1, 32)
    path = _device_path(workspace_id, device_id)
    key, before_body = await _owning_device(client, key_label, workspace_id, device_id)
    before = _device_from_body(before_body, path)
    current = before.get("name")
    if short_circuit_no_op(client, "name" in before and leaf_equal(current, name)):
        return {
            "status": "no_op",
            "reason": f"Device name is already {name!r}; no write performed.",
            "device": before_body,
        }

    response = await _put_no_content(client, path, {"name": name}, key)
    if is_dry_run_preview(response):
        return _dry_run_result(before_body, response)
    after_body, after, error = await _read_after(client, workspace_id, device_id, key)
    return _updated(
        {"name": {"from": current, "to": name}},
        {"name": ("name", name)},
        after_body,
        after,
        response,
        error,
    )


async def update_mobility_device_network(
    client: UniFiClient,
    workspace_id: str,
    device_id: str,
    *,
    host_address: str | None = _UNSET,
    dhcp_mode: str | None = _UNSET,
    dhcp_range_start: str | None = _UNSET,
    dhcp_range_stop: str | None = _UNSET,
    dhcp_lease_time: int | None = _UNSET,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Update a UMR device's LAN / DHCP settings (PUT .../devices/{deviceID}/network).

    This endpoint is a documented partial update: only the fields you provide are
    sent (WAN, IPv6 and InternetSource are not configurable here). At least one field
    must be provided. The Mobility docs differ on PUT semantics (the getting-started
    page describes PUT as full replacement, this endpoint documents a partial merge);
    if the console applies full replacement, unsent LAN/DHCP fields can be reset.
    ``dhcp_mode`` is ``"dhcp"`` (enabled) or ``"none"`` (disabled); IP fields must be
    IPv4; ``dhcp_lease_time`` is seconds (0 = infinite). Guarded: read-before, no-op
    detection for the observable ``host_address``, read-after. Only ``host_address``
    appears in the device detail, so DHCP fields have ``verified`` values of null
    (not observable), and are reported in ``changed`` with the read-before value as ``from`` (null
    when the detail does not carry the field).

    workspace_id: the workspace UUID from list_mobility_workspaces.
    device_id: the device UUID from list_mobility_devices.
    host_address: optional new LAN gateway IPv4.
    dhcp_mode: optional 'dhcp' or 'none'.
    dhcp_range_start: optional DHCP pool start IPv4.
    dhcp_range_stop: optional DHCP pool end IPv4.
    dhcp_lease_time: optional DHCP lease seconds (>=0; 0 = infinite).
    key_label: optional configured API-key label to route on a specific key.
    """
    _require_writes()
    validate_id(workspace_id, "workspace_id")
    validate_id(device_id, "device_id")

    body: dict[str, Any] = {}
    if host_address is not _UNSET:
        if host_address is not None:
            _validate_ipv4(host_address, "host_address")
        body["host_address"] = host_address
    if dhcp_mode is not _UNSET:
        if dhcp_mode is not None and dhcp_mode not in ("dhcp", "none"):
            raise ValueError(
                f"Invalid dhcp_mode {echoed_input(dhcp_mode)}: expected 'dhcp' or 'none'"
            )
        body["dhcp_mode"] = dhcp_mode
    if dhcp_range_start is not _UNSET:
        if dhcp_range_start is not None:
            _validate_ipv4(dhcp_range_start, "dhcp_range_start")
        body["dhcp_range_start"] = dhcp_range_start
    if dhcp_range_stop is not _UNSET:
        if dhcp_range_stop is not None:
            _validate_ipv4(dhcp_range_stop, "dhcp_range_stop")
        body["dhcp_range_stop"] = dhcp_range_stop
    if dhcp_lease_time is not _UNSET:
        if dhcp_lease_time is not None and (
            not isinstance(dhcp_lease_time, int) or isinstance(dhcp_lease_time, bool)
        ):
            raise ValueError("dhcp_lease_time must be an integer")
        if dhcp_lease_time is not None and dhcp_lease_time < 0:
            raise ValueError(f"dhcp_lease_time must be >= 0 (got {dhcp_lease_time})")
        body["dhcp_lease_time"] = dhcp_lease_time

    # The server's one empty-update guard (before any request).
    require_update_fields(
        body,
        "Mobility network (host_address, dhcp_mode, dhcp_range_start, dhcp_range_stop, "
        "dhcp_lease_time)",
    )

    detail_path = _device_path(workspace_id, device_id)
    key, before_body = await _owning_device(client, key_label, workspace_id, device_id)
    before = _device_from_body(before_body, detail_path)
    # Only host_address is observable in the device detail; the DHCP pool/lease are
    # not, so a no-op can only be asserted when host_address is the sole change.
    only_host = set(body) == {"host_address"}
    applied = (
        only_host
        and "host_address" in before
        and leaf_equal(before["host_address"], body["host_address"])
    )
    if short_circuit_no_op(client, applied):
        return {
            "status": "no_op",
            "reason": (
                f"host_address is already {body['host_address']!r} and it is the only "
                "provided field; no write performed."
            ),
            "device": before_body,
        }

    path = f"{detail_path}/network"
    response = await _put_no_content(client, path, body, key)
    if is_dry_run_preview(response):
        return _dry_run_result(before_body, response)
    after_body, after, error = await _read_after(client, workspace_id, device_id, key)
    checks = {
        field: (field if field == "host_address" else None, value) for field, value in body.items()
    }
    return _updated(
        {field: {"from": before.get(field), "to": value} for field, value in body.items()},
        checks,
        after_body,
        after,
        response,
        error,
    )


async def update_mobility_device_wireless(
    client: UniFiClient,
    workspace_id: str,
    device_id: str,
    ssid: str,
    password: str,
    *,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Update a UMR device's WiFi SSID + password (PUT .../devices/{deviceID}/wireless).

    Both fields are required by the API (channel, TX power and security protocol
    are not configurable here). ``ssid`` is 1-32 characters; ``password`` is a
    WPA2-PSK secret of 8-63 characters. Guarded: read-before, read-after. There is no
    no-op short-circuit: the password is not observable in the device detail, so an
    unchanged wireless config cannot be proven. ``changed`` and ``verified`` report the
    SSID (the device detail field ``wifi_ssid``); ``verified.password`` is null because
    the device detail cannot report it. The supplied password is sent but not echoed.

    workspace_id: the workspace UUID from list_mobility_workspaces.
    device_id: the device UUID from list_mobility_devices.
    ssid: the new WiFi SSID (1-32 characters).
    password: the new WPA2-PSK password (8-63 characters).
    key_label: optional configured API-key label to route on a specific key.
    """
    _require_writes()
    validate_id(workspace_id, "workspace_id")
    validate_id(device_id, "device_id")
    _validate_len(ssid, "ssid", 1, 32)
    _validate_len(password, "password", 8, 63)
    detail_path = _device_path(workspace_id, device_id)
    key, before_body = await _owning_device(client, key_label, workspace_id, device_id)
    before = _device_from_body(before_body, detail_path)

    path = f"{detail_path}/wireless"
    response = await _put_no_content(client, path, {"ssid": ssid, "password": password}, key)
    if is_dry_run_preview(response):
        return _dry_run_result(before_body, response)
    after_body, after, error = await _read_after(client, workspace_id, device_id, key)
    return _updated(
        {"ssid": {"from": before.get("wifi_ssid"), "to": ssid}},
        {"ssid": ("wifi_ssid", ssid), "password": (None, None)},
        after_body,
        after,
        response,
        error,
    )


# Tool modules the wrappers below delegate to, imported after this module's
# own definitions so a module importing from this one never sees it half-built.
from . import mobility  # noqa: E402


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> dict[str, Callable[..., Any]]:
    """Register the mobility tool wrappers moved from server.py, in order.

    Returns the registered wrapper functions by name; server.py re-exports them.
    """

    @mcp.tool(annotations=READ_ONLY)
    async def list_mobility_workspaces(
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """List UniFi Mobility workspaces visible to the authenticated API key.

        Returns the upstream body verbatim ({data, total, offset, limit, httpStatusCode, traceId}) plus
        _count; incomplete / incompleteReason when total exceeds the rows returned. With several keys:
        {data, _count, _key_labels, byKey} plus errors.

        A workspace is a mobility "cloud site" (workspace_id, workspace_name, is_owner,
        status). Returned verbatim. Not query-paginated by the API. Mobility identity is
        workspace-based and independent of the console host/site model.

        Args:
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to cover
                every configured key: results are merged, each record carries an additive _keyLabel, and
                a key that fails is reported under errors.
        """
        client, _ = deps_fn()
        return await mobility.list_mobility_workspaces(client, key_label=key_label)

    @mcp.tool(annotations=READ_ONLY)
    async def list_mobility_admins(
        workspace_id: str,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """List the admins of a Mobility workspace (mobility permissions only).

        Returns the upstream body verbatim ({data, total, offset, limit, httpStatusCode, traceId}) plus
        _count; incomplete / incompleteReason when total exceeds the rows returned.

        Each admin carries name, email, status, is_owner and a permissions object
        exposing the umr (Mobile Routing) level (ALL/VIEW_ONLY/NONE); permissions is
        null for a pending invite. Returned verbatim.

        Example call (list_mobility_admins):
            {"workspace_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        Args:
            workspace_id: Mobility workspace UUID. Get it from list_mobility_workspaces (workspace_id).
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
                whichever configured key owns the object: every key is tried and the first that answers
                is used.
        """
        client, _ = deps_fn()
        return await mobility.list_mobility_admins(client, workspace_id, key_label=key_label)

    @mcp.tool(annotations=READ_ONLY)
    async def list_mobility_devices(
        workspace_id: str,
        key_label: str | None = None,
        offset: int | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """List the UMR devices in a Mobility workspace.

        Returns {data, _count} plus the first page's other envelope fields (httpStatusCode,
        traceId); total (the upstream total, never computed) only when the upstream sent an
        integer one; incomplete / incompleteReason when the drain stopped short.

        Each device is the lightweight summary (id, name, model, state,
        firmware_version, mac_address). Offset-paginated by the API (limit/offset, 200
        max); every page is drained. Pass offset alone to fetch a single manual page (the
        upstream page body verbatim).

        Example call (list_mobility_devices):
            {"workspace_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        limit requests a total, gathered automatically in batches up to 200;
        _pageSize reports requested count, actual sent sizes per request,
        observed effective size and returned count, without capping the total.

        Args:
            workspace_id: Mobility workspace UUID. Get it from list_mobility_workspaces (workspace_id).
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
                whichever configured key owns the object: every key is tried and the first that answers
                is used.
            offset: Optional zero-based starting record; alone, fetch one page manually.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is gathered
                across pages of at most 200 starting at offset. Omit offset and limit to drain
                all.
                Example: `25`."""
        client, _ = deps_fn()
        return await mobility.list_mobility_devices(
            client, workspace_id, key_label=key_label, offset=offset, limit=limit
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_mobility_device(
        workspace_id: str,
        device_id: str,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """Get full detail for one UMR device in a Mobility workspace.

        Returns the upstream response object verbatim: the complete DeviceDetail
        (WAN/cellular/WiFi/VPN/subscription/GPS, counts, and the summary fields) under data,
        beside every other envelope field the API sends.

        Example call (get_mobility_device):
            {
              "workspace_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
              "device_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        Args:
            workspace_id: Mobility workspace UUID. Get it from list_mobility_workspaces (workspace_id).
            device_id: Mobility device UUID. Get it from list_mobility_devices (same workspace).
                Mobility id — not a Network device UUID.
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
                whichever configured key owns the object: every key is tried and the first that answers
                is used.
        """
        client, _ = deps_fn()
        return await mobility.get_mobility_device(
            client, workspace_id, device_id, key_label=key_label
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_mobility_clients(
        workspace_id: str,
        device_id: str,
        key_label: str | None = None,
        offset: int | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """List the clients associated with a UMR device.

        Returns {data, _count} plus the first page's other envelope fields (httpStatusCode,
        traceId); total (the upstream total, never computed) only when the upstream sent an
        integer one; incomplete / incompleteReason when the drain stopped short.

        Each client carries mac, name, type (WIRED/WIRELESS), connection_status,
        ip_address, is_blocked and (wireless only) a wifi_experience score.
        Offset-paginated by the API (limit/offset, 200 max); every page is drained. Pass
        offset alone to fetch a single manual page (the upstream page body verbatim).

        Example call (list_mobility_clients):
            {
              "workspace_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
              "device_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        limit requests a total, gathered automatically in batches up to 200;
        _pageSize reports requested count, actual sent sizes per request,
        observed effective size and returned count, without capping the total.

        Args:
            workspace_id: Mobility workspace UUID. Get it from list_mobility_workspaces (workspace_id).
            device_id: Mobility device UUID. Get it from list_mobility_devices (same workspace).
                Mobility id — not a Network device UUID.
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
                whichever configured key owns the object: every key is tried and the first that answers
                is used.
            offset: Optional zero-based starting record; alone, fetch one page manually.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is gathered
                across pages of at most 200 starting at offset. Omit offset and limit to drain
                all.
                Example: `25`."""
        client, _ = deps_fn()
        return await mobility.list_mobility_clients(
            client, workspace_id, device_id, key_label=key_label, offset=offset, limit=limit
        )

    @mcp.tool(annotations=WRITE)
    async def update_mobility_device_name(
        workspace_id: str,
        device_id: str,
        name: str,
        confirm: bool = False,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """Rename a UMR device (guarded write). WARNING: mutates live device config.

        Returns {status: "updated", changed: {field: {from, to}}, verified: {field: bool} for the
        fields observable in the device detail (null when the read-after fails; readAfterError says
        why), device (the read-after device-detail GET body verbatim, {data, httpStatusCode,
        traceId}), response (the PUT body verbatim; null for the documented 204)}, or {status:
        "no_op", reason, device (the GET body read first)}.
        Under dry-run policy nothing is sent: {status: "dry_run", device (the body read first), response
        (the preview)}; verified is absent (there is no read-after).

        Sends the full documented body {"name": name} (1-32 chars). Guarded, in order: the Mobility
        write opt-out (family:mobility=deny refuses first; writes are enabled by default),
        read-before, no-op detection (returns status="no_op" when already named this), write, and a
        read-after verification.

        Request body (Mobility 1.0.0, PUT /v1/mobility/workspaces/{workspaceID}/devices/{deviceID}
        (updateDeviceName); schema "UpdateDeviceNameReq") is built from scalar parameters. Required keys
        — name.
        - name: string

        Example call (update_mobility_device_name):
            {
              "workspace_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
              "device_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
              "name": "Van 12"
            }

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            workspace_id: Mobility workspace UUID. Get it from list_mobility_workspaces (workspace_id).
            device_id: Mobility device UUID. Get it from list_mobility_devices (same workspace).
                Mobility id — not a Network device UUID.
            name: New device name, 1-32 chars (spec UpdateDeviceNameReq.name).
            confirm: Ignored. The call runs when made; there is no confirmation step.
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
                whichever configured key owns the object: every key is tried and the first that answers
                is used.
        """
        client, _ = deps_fn()
        return await mobility.update_mobility_device_name(
            client, workspace_id, device_id, name, confirm=confirm, key_label=key_label
        )

    @mcp.tool(annotations=WRITE)
    async def update_mobility_device_network(
        workspace_id: str,
        device_id: str,
        host_address: str | None = Field(default_factory=lambda: mobility._UNSET),
        dhcp_mode: str | None = Field(default_factory=lambda: mobility._UNSET),
        dhcp_range_start: str | None = Field(default_factory=lambda: mobility._UNSET),
        dhcp_range_stop: str | None = Field(default_factory=lambda: mobility._UNSET),
        dhcp_lease_time: int | None = Field(default_factory=lambda: mobility._UNSET),
        confirm: bool = False,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """Update a UMR device's LAN / DHCP settings (guarded write). Mutates live config.

        Returns {status: "updated", changed: {field: {from, to}}, verified: {field: bool or null}
        for every requested field (null for fields absent from the pinned device-detail schema;
        the whole map is null on read-after failure, with readAfterError), device
        (the read-after device-detail GET body verbatim, {data, httpStatusCode,
        traceId}), response (the PUT body verbatim; null for the documented 204)}, or {status:
        "no_op", reason, device (the GET body read first)}.
        Under dry-run policy nothing is sent: {status: "dry_run", device (the body read first),
        response
        (the preview)}; verified is absent (there is no read-after).

        DOCUMENTED partial update: only provided fields are applied (WAN/IPv6/InternetSource are
        not configurable here). At least one field is required. The Mobility docs differ on PUT
        semantics (full replacement vs this endpoint's documented partial merge); if the console
        applies full replacement, unsent LAN/DHCP fields can be reset. Add
        family:mobility=deny to UNIFI_WRITE_EXCEPTIONS to make Mobility read-only. dhcp_mode is 'dhcp' (enabled) or
        'none' (disabled); IPs must be dotted-quad IPv4 (spec format: ipv4; a leading-zero octet
        such as 192.168.01.1 is refused before any request); dhcp_lease_time is seconds
        (0 = infinite). Guarded, in order: the Mobility write opt-out
        (family:mobility=deny refuses first), read-before, no-op detection on the
        observable host_address, write, read-after.

        Each field is nullable: explicit null is forwarded as null; an omitted field stays omitted
        (unchanged).

        Full request shapes are in the parameter schema; detailed examples and workflows:
        docs/TOOL-USAGE.md#update_mobility_device_network.

        Required arguments: workspace_id, device_id (see parameter descriptions for identifiers).

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            workspace_id: Mobility workspace UUID. Get it from list_mobility_workspaces (workspace_id).
            device_id: Mobility device UUID. Get it from list_mobility_devices (same workspace).
                Mobility id — not a Network device UUID.
            host_address: Optional new LAN gateway IPv4 (spec UpdateNetworkReq).
            dhcp_mode: Optional 'dhcp' or 'none'.
            dhcp_range_start: Optional DHCP pool start IPv4.
            dhcp_range_stop: Optional DHCP pool end IPv4.
            dhcp_lease_time: Optional lease seconds (>=0; 0 = infinite).
            confirm: Ignored. The call runs when made; there is no confirmation step.
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
                whichever configured key owns the object: every key is tried and the first that answers
                is used.
        """
        host_address = _nullable_default(host_address, mobility._UNSET)
        dhcp_mode = _nullable_default(dhcp_mode, mobility._UNSET)
        dhcp_range_start = _nullable_default(dhcp_range_start, mobility._UNSET)
        dhcp_range_stop = _nullable_default(dhcp_range_stop, mobility._UNSET)
        dhcp_lease_time = _nullable_default(dhcp_lease_time, mobility._UNSET)
        client, _ = deps_fn()
        return await mobility.update_mobility_device_network(
            client,
            workspace_id,
            device_id,
            host_address=host_address,
            dhcp_mode=dhcp_mode,
            dhcp_range_start=dhcp_range_start,
            dhcp_range_stop=dhcp_range_stop,
            dhcp_lease_time=dhcp_lease_time,
            confirm=confirm,
            key_label=key_label,
        )

    @mcp.tool(annotations=WRITE)
    async def update_mobility_device_wireless(
        workspace_id: str,
        device_id: str,
        ssid: str,
        password: str,
        confirm: bool = False,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """Update a UMR device's WiFi SSID + password (guarded write). Mutates live config.

        Returns {status: "updated", changed: {field: {from, to}}, verified: {field: bool or null}
        for every requested field (null for fields absent from the pinned device-detail schema;
        the whole map is null on read-after failure, with readAfterError), device
        (the read-after device-detail GET body verbatim, {data, httpStatusCode,
        traceId}), response (the PUT body verbatim; null for the documented 204)}. It never returns
        no_op. Under dry-run policy nothing is sent: {status: "dry_run", device (the body read first),
        response (the preview)}; verified is absent (there is no read-after).

        Both fields are required by the API (channel/TX power/security protocol are not configurable
        here). ssid is 1-32 chars; password is a WPA2-PSK secret of 8-63 chars. Guarded, in order:
        the Mobility write opt-out (family:mobility=deny refuses first), read-before,
        write, read-after. There is no no-op short-circuit (the password is not observable, so an
        unchanged config cannot be proven). The supplied password is not echoed back in the result;
        under dry-run policy the preview body shows the request as it would be sent, password
        included (masked as ***REDACTED*** only when UNIFI_REDACT_SECRETS is on, like every
        credential field of every dry-run preview).

        Request body (Mobility 1.0.0, PUT
        /v1/mobility/workspaces/{workspaceID}/devices/{deviceID}/wireless (updateDeviceWireless); schema
        "UpdateWirelessReq") is built from scalar parameters. Required keys — ssid, password.
        - ssid: string
        - password: string

        Example call (update_mobility_device_wireless):
            {
              "workspace_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
              "device_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
              "ssid": "Fleet-WiFi",
              "password": "correct-horse-9"
            }

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            workspace_id: Mobility workspace UUID. Get it from list_mobility_workspaces (workspace_id).
            device_id: Mobility device UUID. Get it from list_mobility_devices (same workspace).
                Mobility id — not a Network device UUID.
            ssid: New SSID, 1-32 chars (spec UpdateWirelessReq.ssid).
            password: New WPA2-PSK, 8-63 chars (spec UpdateWirelessReq.password).
            confirm: Ignored. The call runs when made; there is no confirmation step.
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
                whichever configured key owns the object: every key is tried and the first that answers
                is used.
        """
        client, _ = deps_fn()
        return await mobility.update_mobility_device_wireless(
            client, workspace_id, device_id, ssid, password, confirm=confirm, key_label=key_label
        )

    return {
        "list_mobility_workspaces": list_mobility_workspaces,
        "list_mobility_admins": list_mobility_admins,
        "list_mobility_devices": list_mobility_devices,
        "get_mobility_device": get_mobility_device,
        "list_mobility_clients": list_mobility_clients,
        "update_mobility_device_name": update_mobility_device_name,
        "update_mobility_device_network": update_mobility_device_network,
        "update_mobility_device_wireless": update_mobility_device_wireless,
    }
