"""Network clients, guests, DHCP and hotspot tools.

Route choice: the official published API when it can do the job, else the newer v2 API,
else the Classic API. Per tool:

* ``authorize_guest`` / ``revoke_guest_access``: the official client actions
  ``AUTHORIZE_GUEST_ACCESS`` / ``UNAUTHORIZE_GUEST_ACCESS`` (Network 11.0.97
  ``executeConnectedClientAction``) for a CONNECTED client. The official action exists only
  for connected clients, so a MAC that is not connected (pre-authorizing a guest that has
  not joined yet, or revoking an offline one) uses Classic ``cmd/stamgr``
  ``authorize-guest`` / ``unauthorize-guest``; ``ap_mac`` has no official equivalent and
  also selects Classic; a guest session ``_id`` (``list_hotspot_authorizations``) uses Classic
  ``cmd/hotspot terminate``. The result names the route taken and why.
* v2 (no official route exists): client records by MAC, traffic-control counts, client
  insights and observability, DHCP leases and excluded IPs, client icons, fingerprint
  overrides, the incorrect-WiFi-experience report and the guest-access reset.
* Classic (only the Classic route exists in the Network 11.0.81 web app): DHCP options,
  hotspot packages, hotspot settings, payments, authorizations and portal files.

Every response body is passed through verbatim (server pass-through invariant). Classic
commands go through ``tools._classic_cmd.classic_command``, which requires
``meta.rc == "ok"``. Validation before any request uses only the server's registered
refusals (MAC-or-id selectors, path-safe ids, integer epoch seconds, Classic command
grammar, the empty-update guard and pydantic choice validation); every other value is the
upstream's to judge. Under ``dry-run policy`` every write returns the client's dry-run
preview and sends nothing.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any, Literal, cast

from fastmcp import FastMCP
from pydantic import StrictInt, TypeAdapter

from ...client import (
    UniFiClient,
    is_dry_run_preview,
    object_records,
    path_segment,
    upstream_error_value,
    validate_id,
)
from ...macs import colon_mac as _colon_mac
from ...macs import is_mac as _is_mac
from ...matching import same_id
from ...registry import Registry, _assert_uuid
from ...shared_shapes._classic_cmd import classic_command
from ...shared_shapes._classic_objects import (
    addressed_body,
    classic_rest,
    listed_record_id,
    require_listed_record,
    resolve_site_slug,
    v2_site,
)
from ...shared_shapes._history_common import epoch_warnings, require_epoch_seconds, with_warnings
from ...shared_shapes._keys import with_context
from ...shared_shapes._pagination import collect_offset
from ...shared_shapes._payload import strip_empty_list_values, with_upstream_hint
from ...shared_shapes._results import (
    ADDITIVE_READ_AFTER_ERROR_KEY,
    UNVERIFIED_FIELDS_KEY,
    VERIFIED_KEY,
    deletion_result,
    read_after_verdict,
    safe_read_after,
)
from ...tool_annotations import READ_ONLY, WRITE
from ...write_body import require_unmasked_fields, require_update_fields
from ..clients.clients import _describe_clients, _record_mac, _stamgr_mac, _validate_client_ref
from .network import _proxy

_CONSOLE = "/v1/connector/consoles/{host_id}/proxy/network"

#: Client insight views (``/v2/api/site/{site}/client/{mac}/view``).
InsightView = Literal["24hr-activity", "24hr-satisfaction", "ap-stats", "traffic-insights"]
#: Client observability views (``/v2/api/site/{site}/observability/client/{mac}/...``).
ObservabilityView = Literal["logs-all", "timeline", "timestamps", "topology"]
IconTarget = Literal["client", "matter_node"]
WifiReportTarget = Literal["client", "ap"]
GuestTarget = Literal["client", "guest_session"]

_INSIGHT_VIEW = TypeAdapter(InsightView)
_OBSERVABILITY_VIEW = TypeAdapter(ObservabilityView)
_ICON_TARGET = TypeAdapter(IconTarget)
_WIFI_TARGET = TypeAdapter(WifiReportTarget)
_GUEST_TARGET = TypeAdapter(GuestTarget)
_OPTIONAL_INT = TypeAdapter(StrictInt | None)
_OPTIONAL_BOOL = TypeAdapter(bool | None)


def _classic_stat(host_id: str, site_slug: str, path: str) -> str:
    return _CONSOLE.format(host_id=host_id) + f"/api/s/{site_slug}/stat{path}"


def _given(**params: Any) -> dict[str, Any] | None:
    """Only the query parameters the caller actually gave (no invented defaults)."""
    sent = {k: v for k, v in params.items() if v is not None}
    return sent or None


def _millis(value: int | None, name: str) -> int | None:
    """An optional epoch-seconds argument as epoch milliseconds (type-checked first)."""
    if value is None:
        return None
    return require_epoch_seconds(value, name) * 1000


def _bool_flag(value: bool | None) -> str | None:
    """A v2 boolean query flag spelled as the web app sends it (``true`` / ``false``)."""
    checked = _OPTIONAL_BOOL.validate_python(value, strict=True)
    return None if checked is None else ("true" if checked else "false")


def _validate_json_body(body: Any) -> None:
    """Refuse an unsendable body before resolution, without echoing its secrets."""
    try:
        json.dumps(body, allow_nan=False)
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise ValueError("The write body must be JSON-serialisable.") from None


async def _write_client_target(
    client: UniFiClient, host_id: str, site_id: str, site_slug: str, ref: str, key: Any
) -> tuple[str | None, str | None]:
    """Resolve writes from a complete connected list, allowing known offline MACs."""
    url = _proxy(host_id, f"/sites/{site_id}/clients")
    collected = await collect_offset(client, url, key=key)
    if collected["incomplete"]:
        raise ValueError("Cannot select a write target: the connected client list is incomplete.")
    rows = object_records(collected["items"], f"GET {url}")
    mac = _colon_mac(ref) if _is_mac(ref) else None
    matches = [r for r in rows if (_record_mac(r) == mac if mac else same_id(ref, r.get("id")))]
    if matches:
        ids: set[str] = {r["id"] for r in matches if isinstance(r.get("id"), str) and r.get("id")}
        if len(ids) != 1 and mac is not None:
            return None, mac
        if len(ids) != 1:
            raise ValueError(
                f"Ambiguous client; valid choices: {_describe_clients(matches, client)}"
            )
        native_id = next(iter(ids))
        try:
            _assert_uuid(native_id)
        except ValueError:
            raise ValueError(
                f"site_id {upstream_error_value(native_id, client)!r} is not a UUID — "
                "proxy endpoints require UUID site IDs. "
                "Pass the site name or UUID as returned by the console's /sites endpoint."
            ) from None
        return native_id, mac or _record_mac(matches[0])
    if mac is not None:
        path = _classic_stat(host_id, site_slug, "/alluser")
        body = await client.get(path, key=key)
        records = object_records(
            body.get("data") if isinstance(body, dict) else body, f"GET {path}"
        )
        if any(_record_mac(r) == mac for r in records):
            return None, mac
        rows += records
    raise ValueError(
        f"Unknown client {ref!r}; valid choices: {_describe_clients(rows, client) or '(none)'}. "
        "No write was sent."
    )


async def _write_client_mac_for(
    client: UniFiClient,
    registry: Registry,
    host_id: str,
    site: str,
    site_slug: str,
    ref: str,
    key: Any,
) -> str:
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    _, mac = await _write_client_target(client, host_id, site_id, site_slug, ref, key)
    if mac is None:
        raise ValueError(
            "The connected client has no MAC; cannot select a MAC-addressed write target."
        )
    return mac


async def _client_mac_for(
    client: UniFiClient,
    registry: Registry,
    host_id: str,
    site: str,
    ref: str,
    key: Any,
) -> str:
    """The lowercase colon MAC of a client given by MAC (any form) or by its Network
    Integration id (a connected client, read with the official client GET)."""
    if _is_mac(ref):
        return _colon_mac(ref)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await _stamgr_mac(client, host_id, site_id, ref, key)


def _unrequestable_pages(body: Any) -> list[dict[str, Any]]:
    """A ``_warnings`` entry when a logs-all answer reports more pages than the one sent.

    The web app requests logs-all without a page parameter, and none of ``page_number``,
    ``pageNumber`` or ``page`` moved ``page_number`` live (Network 11.0.81), so the server
    cannot fetch further pages; it says so instead of returning a silently partial list.
    """
    if not isinstance(body, dict):
        return []
    pages, number = body.get("total_page_count"), body.get("page_number")
    # Not a cap: compares the upstream's own logs-all page count (web-app spec field).
    if not isinstance(pages, int) or isinstance(pages, bool) or pages <= 1:
        return []
    return [
        {
            "code": "MORE_PAGES_NOT_REQUESTABLE",
            "total_page_count": pages,
            "page_number": number,
            "message": (
                f"logs-all reports {pages} pages and returned page {number!r}; the route "
                "takes no page parameter, so narrow start/end to read the rest."
            ),
        }
    ]


def _routed(route: str, reason: str, response: Any) -> Any:
    """Preserve upstream shapes; annotate object responses with additive metadata."""
    if is_dry_run_preview(response):
        return response
    if isinstance(response, dict):
        return with_context(response, {"_route": route, "_reason": reason})
    return response


def _revoked(route: str, reason: str, response: Any) -> Any:
    """Return the canonical revocation result without changing the upstream body."""
    return deletion_result("Guest access revoked.", response)


def _deleted(message: str, response: Any) -> Any:
    """Return the canonical deletion result without changing the upstream body."""
    return deletion_result(message, response)


# --------------------------------------------------------------------------- guests


async def authorize_guest(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    client_ref: str,
    *,
    time_limit_minutes: int | None = None,
    data_limit_mbytes: int | None = None,
    rx_rate_limit_kbps: int | None = None,
    tx_rate_limit_kbps: int | None = None,
    ap_mac: str | None = None,
) -> Any:
    """Authorize a guest: official client action when connected, else Classic stamgr."""
    _validate_client_ref(client_ref, "client")
    if ap_mac is not None:
        if not _is_mac(ap_mac):
            raise ValueError("ap_mac must be a MAC address.")
        ap_mac = _colon_mac(ap_mac)
    limits = {
        "timeLimitMinutes": _OPTIONAL_INT.validate_python(time_limit_minutes),
        "dataUsageLimitMBytes": _OPTIONAL_INT.validate_python(data_limit_mbytes),
        "rxRateLimitKbps": _OPTIONAL_INT.validate_python(rx_rate_limit_kbps),
        "txRateLimitKbps": _OPTIONAL_INT.validate_python(tx_rate_limit_kbps),
    }
    classic_params = {
        "minutes": limits["timeLimitMinutes"],
        "bytes": limits["dataUsageLimitMBytes"],
        "down": limits["rxRateLimitKbps"],
        "up": limits["txRateLimitKbps"],
        "ap_mac": ap_mac,
    }
    classic_params = {k: v for k, v in classic_params.items() if v is not None}
    _validate_json_body(classic_params)
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    official_id, mac = await _write_client_target(
        client, host_id, site_id, site_slug, client_ref, key
    )
    if ap_mac is not None:
        official_id = None
    if official_id is not None:
        body: dict[str, Any] = {"action": "AUTHORIZE_GUEST_ACCESS"}
        body.update({k: v for k, v in limits.items() if v is not None})
        response = await client.post(
            _proxy(host_id, f"/sites/{site_id}/clients/{official_id}/actions"),
            key=key,
            json=body,
        )
        return _routed("official", "the client is connected", response)
    if mac is None:
        raise ValueError("The selected client has no MAC for the Classic write.")
    reason = (
        "ap_mac has no official equivalent"
        if ap_mac is not None
        else "the MAC is not a connected client (the official action needs one)"
    )
    response = await classic_command(
        client,
        host_id,
        site_slug,
        "stamgr",
        "authorize-guest",
        {"mac": mac, **classic_params},
        key=key,
    )
    return _routed("classic", reason, response)


async def revoke_guest_access(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    guest: str,
    target_type: str = "client",
) -> Any:
    """Revoke a guest: official action when connected, else Classic unauthorize-guest;
    a guest session ``_id`` (``target_type="guest_session"``) uses Classic terminate."""
    target_type = _GUEST_TARGET.validate_python(target_type)
    if target_type == "guest_session":
        validate_id(guest, "guest")
    else:
        _validate_client_ref(guest, "guest")
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    if target_type == "guest_session":
        record = await require_listed_record(
            client,
            _classic_stat(host_id, site_slug, "/authorization"),
            guest,
            key=key,
            kind="Guest session",
            list_tool="list_hotspot_authorizations",
        )
        guest = listed_record_id(record, "guest")
        response = await classic_command(
            client, host_id, site_slug, "hotspot", "terminate", {"_id": guest}, key=key
        )
        return _revoked(
            "classic", "a guest session _id is addressed only by Classic cmd/hotspot", response
        )
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    official_id, mac = await _write_client_target(client, host_id, site_id, site_slug, guest, key)
    if official_id is not None:
        response = await client.post(
            _proxy(host_id, f"/sites/{site_id}/clients/{official_id}/actions"),
            key=key,
            json={"action": "UNAUTHORIZE_GUEST_ACCESS"},
        )
        return _revoked("official", "the client is connected", response)
    response = await classic_command(
        client, host_id, site_slug, "stamgr", "unauthorize-guest", {"mac": mac}, key=key
    )
    return _revoked(
        "classic", "the MAC is not a connected client (the official action needs one)", response
    )


# --------------------------------------------------------------------------- clients (v2)


async def get_local_client(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    client_ref: str,
    *,
    include_traffic_usage: bool | None = None,
    include_unifi_devices: bool | None = None,
    include_matter_thread_clients: bool | None = None,
) -> Any:
    """GET v2 ``clients/local/{mac}``: the controller's record of one client."""
    _validate_client_ref(client_ref, "client")
    params = _given(
        includeTrafficUsage=_bool_flag(include_traffic_usage),
        includeUnifiDevices=_bool_flag(include_unifi_devices),
        includeMatterThreadClients=_bool_flag(include_matter_thread_clients),
    )
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    mac = await _client_mac_for(client, registry, host_id, site, client_ref, key)
    path = v2_site(host_id, site_slug, f"/clients/local/{path_segment(mac, 'client')}")
    return await client.get(path, key=key, params=params)


async def list_client_traffic_controls(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """GET v2 ``clients/traffic-control``: applied traffic-rule count per client."""
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    return await client.get(v2_site(host_id, site_slug, "/clients/traffic-control"), key=key)


async def get_client_insights(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    client_ref: str,
    view: str,
    *,
    start: int | None = None,
    end: int | None = None,
) -> Any:
    """GET v2 ``client/{mac}/view`` (activity, satisfaction, AP stats, traffic)."""
    view = _INSIGHT_VIEW.validate_python(view)
    _validate_client_ref(client_ref, "client")
    start_ms, end_ms = _millis(start, "start"), _millis(end, "end")
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    mac = await _client_mac_for(client, registry, host_id, site, client_ref, key)
    seg = path_segment(mac, "client")
    params = _given(mac=mac, start=start_ms, end=end_ms)
    result = await client.get(
        v2_site(host_id, site_slug, f"/client/{seg}/{view}"), key=key, params=params
    )
    return with_warnings(result, epoch_warnings(start=start, end=end))


def _check_observability_arguments(
    view: str, start: int | None, end: int | None, timestamp: int | None
) -> None:
    """Refuse, before any request, a time argument the chosen view does not use.

    ``topology`` is one snapshot (``timestamp``, no window); every other view is a window
    (``start`` / ``end``, no snapshot time). An argument the view ignores would be silently
    dropped.
    """
    if view == "topology":
        unused = [n for n, v in (("start", start), ("end", end)) if v is not None]
        if unused:
            raise ValueError(
                f"Client observability view 'topology' takes timestamp, not {' or '.join(unused)}"
                "; pass the snapshot time as timestamp. Nothing was sent."
            )
    elif timestamp is not None:
        raise ValueError(
            f"Client observability view {view!r} takes start and end, not timestamp (timestamp "
            "is for view 'topology'). Nothing was sent."
        )


async def get_client_observability(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    client_ref: str,
    view: str,
    *,
    start: int | None = None,
    end: int | None = None,
    timestamp: int | None = None,
) -> Any:
    """GET v2 ``observability/client/{mac}/...`` (logs, timeline, timestamps, topology)."""
    view = _OBSERVABILITY_VIEW.validate_python(view)
    _check_observability_arguments(view, start, end, timestamp)
    _validate_client_ref(client_ref, "client")
    start_ms, end_ms = _millis(start, "start"), _millis(end, "end")
    at_ms = (
        require_epoch_seconds(cast(int, timestamp), "timestamp") * 1000
        if view == "topology"
        else _millis(timestamp, "timestamp")
    )
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    mac = await _client_mac_for(client, registry, host_id, site, client_ref, key)
    seg = path_segment(mac, "client")
    if view == "topology":
        path = v2_site(host_id, site_slug, f"/observability/client/{seg}/topology/at/{at_ms}")
        params = None
    else:
        path = v2_site(host_id, site_slug, f"/observability/client/{seg}/{view}")
        params = _given(start=start_ms, end=end_ms)
    hint = (
        "The Network UI sends start and end for logs-all; pass both as epoch seconds."
        if view == "logs-all" and (start is None or end is None)
        else None
    )
    result = await with_upstream_hint(client.get(path, key=key, params=params), hint)
    warnings = epoch_warnings(start=start, end=end, timestamp=timestamp)
    warnings += _unrequestable_pages(result) if view == "logs-all" else []
    return with_warnings(result, warnings)


async def set_client_icon(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    target_id: str,
    icon: dict[str, Any] | None,
    target_type: str = "client",
) -> Any:
    """PUT (set) or DELETE (restore the default) a client's or Matter node's AI icon."""
    target_type = _ICON_TARGET.validate_python(target_type)
    if target_type == "client":
        _validate_client_ref(target_id, "target_id")
    else:
        path_segment(target_id, "target_id")
    _validate_json_body(icon)
    require_unmasked_fields(icon, "set_client_icon icon")
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    if target_type == "client":
        mac = await _write_client_mac_for(
            client, registry, host_id, site, site_slug, target_id, key
        )
        route = f"/clients/{path_segment(mac, 'target_id')}/ai-icon"
    else:
        route = f"/matter/nodes/{path_segment(target_id, 'target_id')}/ai-icon"
    path = v2_site(host_id, site_slug, route)
    if icon is None:
        response = await client.delete(path, key=key)
        return _deleted(f"AI icon of {target_type} {target_id} removed.", response)
    return await client.put(path, key=key, json=icon)


async def set_client_fingerprint_override(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    client_ref: str,
    override: dict[str, Any] | None,
) -> Any:
    """PUT (set) or DELETE (restore detection) a client's fingerprint override."""
    _validate_client_ref(client_ref, "client_ref")
    _validate_json_body(override)
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    mac = await _write_client_mac_for(client, registry, host_id, site, site_slug, client_ref, key)
    path = v2_site(
        host_id, site_slug, f"/station/{path_segment(mac, 'client')}/fingerprint_override"
    )
    if override is None:
        response = await client.delete(path, key=key)
        return _deleted(f"Fingerprint override of client {client_ref} removed.", response)
    body = override if "mac" in override else {**override, "mac": mac}
    return await client.put(path, key=key, json=body)


async def report_incorrect_wifi_experience(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    target_type: str,
    target: str,
    reason: str,
    comment: str | None = None,
) -> Any:
    """POST v2 ``{station|device}/{mac}/wifi_experience/incorrect`` (feedback to Ubiquiti)."""
    target_type = _WIFI_TARGET.validate_python(target_type)
    if target_type == "client":
        _validate_client_ref(target, "target")
    else:
        path_segment(target, "target")
    _validate_json_body({"reason": reason, "comment": comment})
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    if target_type == "client":
        mac = await _write_client_mac_for(client, registry, host_id, site, site_slug, target, key)
        route = f"/station/{path_segment(mac, 'target')}/wifi_experience/incorrect"
    else:
        ap = _colon_mac(target) if _is_mac(target) else target
        route = f"/device/{path_segment(ap, 'target')}/wifi_experience/incorrect"
    body: dict[str, Any] = {"reason": reason}
    if comment is not None:
        body["comment"] = comment
    return await client.post(v2_site(host_id, site_slug, route), key=key, json=body)


# --------------------------------------------------------------------------- DHCP


async def list_dhcp_leases(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    network_id: str | None = None,
) -> Any:
    """GET v2 ``active-leases[/{network_id}]``: active DHCP leases."""
    seg = None if network_id is None else path_segment(network_id, "network_id")
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    route = "/active-leases" if seg is None else f"/active-leases/{seg}"
    return await client.get(v2_site(host_id, site_slug, route), key=key)


async def list_dhcp_excluded_ips(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    network_id: str | None = None,
) -> Any:
    """GET v2 ``excluded-ips[/{network_id}]``: addresses excluded from DHCP."""
    seg = None if network_id is None else path_segment(network_id, "network_id")
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    route = "/excluded-ips" if seg is None else f"/excluded-ips/{seg}"
    return await client.get(v2_site(host_id, site_slug, route), key=key)


async def list_dhcp_options(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """GET Classic ``rest/dhcpoption``: custom DHCP option definitions."""
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    return await client.get(classic_rest(host_id, site_slug, "/dhcpoption"), key=key)


async def create_dhcp_option(
    client: UniFiClient, registry: Registry, host: str, site: str, option: dict[str, Any], /
) -> Any:
    """POST Classic ``rest/dhcpoption``: define a custom DHCP option."""
    _validate_json_body(option)
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    return await client.post(classic_rest(host_id, site_slug, "/dhcpoption"), key=key, json=option)


async def _classic_record_write(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    collection: str,
    record_id: str,
    arg_name: str,
    kind: str,
    list_tool: str,
) -> tuple[Any, str, str, str, dict[str, Any]]:
    """``(key, host_id, site_slug, upstream _id, record)`` of a record resolved in its
    list (the controller answers a DELETE on an unknown id with HTTP 200)."""
    validate_id(record_id, arg_name)
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    record = await require_listed_record(
        client,
        classic_rest(host_id, site_slug, f"/{collection}"),
        record_id,
        key=key,
        kind=kind,
        list_tool=list_tool,
    )
    return key, host_id, site_slug, listed_record_id(record, arg_name), record


def _verified_leaves(requested: Any, actual: Any, path: str = "") -> dict[str, bool]:
    missing = object()
    if isinstance(requested, dict):
        if not requested:
            return {path: type(actual) is dict}
        result: dict[str, bool] = {}
        for key, value in requested.items():
            found = actual.get(key, missing) if isinstance(actual, dict) else missing
            result.update(_verified_leaves(value, found, f"{path}.{key}" if path else key))
        return result
    if isinstance(requested, list):
        if not requested:
            return {path: type(actual) is list and actual == []}
        result = {path + ".length": isinstance(actual, list) and len(actual) == len(requested)}
        for index, value in enumerate(requested):
            found = actual[index] if isinstance(actual, list) and index < len(actual) else missing
            result.update(_verified_leaves(value, found, f"{path}[{index}]"))
        return result
    return {path: type(requested) is type(actual) and requested == actual}


def _classic_update_result(
    response: Any, sent: dict[str, Any], actual: Any, error: str | None
) -> Any:
    """The PUT response verbatim plus the additive read-after verdict.

    ``_verified`` is true only when the re-read record carries every sent leaf
    type-strict; false with ``_unverifiedFields`` naming each leaf that differs; null
    with ``_readAfterError`` when the re-read failed or had an unexpected shape.
    A non-object write body is kept whole under ``response`` so the verdict keys are never dropped.
    """
    if not isinstance(response, dict):
        response = {"response": response}
    unmatched, reason = read_after_verdict(
        actual,
        error,
        lambda record: [leaf for leaf, ok in _verified_leaves(sent, record).items() if not ok],
    )
    context: dict[str, Any] = {VERIFIED_KEY: None if unmatched is None else not unmatched}
    if unmatched:
        context[UNVERIFIED_FIELDS_KEY] = unmatched
    if reason is not None:
        context[ADDITIVE_READ_AFTER_ERROR_KEY] = reason
    return with_context(response, context)


def _sent_fields(body: Any, requested: dict[str, Any]) -> dict[str, Any]:
    """The requested top-level fields as actually sent (after empty list strings drop)."""
    sent = body if isinstance(body, dict) else {}
    return {k: sent.get(k, v) for k, v in requested.items()}


def _merged_put_body(record: dict[str, Any], fields: dict[str, Any], upstream_id: str) -> Any:
    """The Classic PUT body: the listed record with the caller's fields laid over it.

    A Classic REST PUT of a partial body answers HTTP 400 ``api.err.Invalid`` (Network
    11.0.81, live on rest/dhcpoption), so the current record read for the id check is sent
    back with the requested fields changed, ``_id`` spelt as upstream, and empty strings in
    list-valued fields dropped.
    """
    return strip_empty_list_values(addressed_body({**record, **fields}, upstream_id))


async def update_dhcp_option(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    option_id: str,
    fields: dict[str, Any],
    /,
) -> Any:
    """PUT Classic ``rest/dhcpoption/{id}`` (the id is resolved in the list first)."""
    clean = require_update_fields(fields, "update_dhcp_option")
    _validate_json_body(clean)
    key, host_id, site_slug, upstream_id, record = await _classic_record_write(
        client,
        registry,
        host,
        site,
        "dhcpoption",
        option_id,
        "option_id",
        "DHCP option",
        "list_dhcp_options",
    )
    body = _merged_put_body(record, clean, upstream_id)
    response = await client.put(
        classic_rest(host_id, site_slug, f"/dhcpoption/{upstream_id}"), key=key, json=body
    )
    if is_dry_run_preview(response):
        return response
    actual, error = await safe_read_after(
        lambda: require_listed_record(
            client,
            classic_rest(host_id, site_slug, "/dhcpoption"),
            upstream_id,
            key=key,
            kind="Updated record",
            read_after=True,
            list_tool="the collection list",
        )
    )
    return _classic_update_result(response, _sent_fields(body, clean), actual, error)


async def delete_dhcp_option(
    client: UniFiClient, registry: Registry, host: str, site: str, option_id: str
) -> Any:
    """DELETE Classic ``rest/dhcpoption/{id}`` (the id is resolved in the list first)."""
    key, host_id, site_slug, upstream_id, record = await _classic_record_write(
        client,
        registry,
        host,
        site,
        "dhcpoption",
        option_id,
        "option_id",
        "DHCP option",
        "list_dhcp_options",
    )
    response = await client.delete(
        classic_rest(host_id, site_slug, f"/dhcpoption/{upstream_id}"), key=key
    )
    return _deleted(f"DHCP option {option_id} deleted.", response)


# --------------------------------------------------------------------------- hotspot


async def get_hotspot_settings(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """GET Classic ``/api/stat/s/{site}/hotspotconfig``: guest portal settings."""
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    path = _CONSOLE.format(host_id=host_id) + f"/api/stat/s/{site_slug}/hotspotconfig"
    return await client.get(path, key=key)


async def list_hotspot_payments(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    *,
    start: int | None = None,
    end: int | None = None,
    within: int | None = None,
) -> Any:
    """GET Classic ``stat/payment``: guest portal payment transactions."""
    start_ms, end_ms = _millis(start, "start"), _millis(end, "end")
    within = _OPTIONAL_INT.validate_python(within)
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    result = await client.get(
        _classic_stat(host_id, site_slug, "/payment"),
        key=key,
        params=_given(start=start_ms, end=end_ms, within=within),
    )
    return with_warnings(result, epoch_warnings(start=start, end=end))


async def list_hotspot_authorizations(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    *,
    start: int | None = None,
    end: int | None = None,
) -> Any:
    """GET Classic ``stat/authorization``: guest authorization history."""
    if start is not None:
        require_epoch_seconds(start, "start")
    if end is not None:
        require_epoch_seconds(end, "end")
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    result = await client.get(
        _classic_stat(host_id, site_slug, "/authorization"),
        key=key,
        params=_given(start=start, end=end),
    )
    return with_warnings(result, epoch_warnings(start=start, end=end))


async def create_hotspot_package(
    client: UniFiClient, registry: Registry, host: str, site: str, package: dict[str, Any], /
) -> Any:
    """POST Classic ``rest/hotspotpackage``: a guest portal billing package."""
    _validate_json_body(package)
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    return await client.post(
        classic_rest(host_id, site_slug, "/hotspotpackage"), key=key, json=package
    )


async def update_hotspot_package(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    package_id: str,
    fields: dict[str, Any],
    /,
) -> Any:
    """PUT Classic ``rest/hotspotpackage/{id}`` (the id is resolved in the list first)."""
    clean = require_update_fields(fields, "update_hotspot_package")
    _validate_json_body(clean)
    key, host_id, site_slug, upstream_id, record = await _classic_record_write(
        client,
        registry,
        host,
        site,
        "hotspotpackage",
        package_id,
        "package_id",
        "Hotspot package",
        "list_hotspot_packages",
    )
    body = _merged_put_body(record, clean, upstream_id)
    response = await client.put(
        classic_rest(host_id, site_slug, f"/hotspotpackage/{upstream_id}"), key=key, json=body
    )
    if is_dry_run_preview(response):
        return response
    actual, error = await safe_read_after(
        lambda: require_listed_record(
            client,
            classic_rest(host_id, site_slug, "/hotspotpackage"),
            upstream_id,
            key=key,
            kind="Updated record",
            read_after=True,
            list_tool="the collection list",
        )
    )
    return _classic_update_result(response, _sent_fields(body, clean), actual, error)


async def delete_hotspot_package(
    client: UniFiClient, registry: Registry, host: str, site: str, package_id: str
) -> Any:
    """DELETE Classic ``rest/hotspotpackage/{id}`` (the id is resolved in the list first)."""
    key, host_id, site_slug, upstream_id, record = await _classic_record_write(
        client,
        registry,
        host,
        site,
        "hotspotpackage",
        package_id,
        "package_id",
        "Hotspot package",
        "list_hotspot_packages",
    )
    response = await client.delete(
        classic_rest(host_id, site_slug, f"/hotspotpackage/{upstream_id}"), key=key
    )
    return _deleted(f"Hotspot package {package_id} deleted.", response)


async def delete_guest_portal_file(
    client: UniFiClient, registry: Registry, host: str, site: str, file_id: str
) -> Any:
    """DELETE Classic ``rest/portalfile/{id}`` (the id is resolved in the list first)."""
    key, host_id, site_slug, upstream_id, record = await _classic_record_write(
        client,
        registry,
        host,
        site,
        "portalfile",
        file_id,
        "file_id",
        "Guest portal file",
        "the rest/portalfile list",
    )
    response = await client.delete(
        classic_rest(host_id, site_slug, f"/portalfile/{upstream_id}"), key=key
    )
    return _deleted(f"Guest portal file {file_id} deleted.", response)


async def reset_guest_access_settings(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    body: dict[str, Any] | None = None,
) -> Any:
    """POST v2 ``settings/guest-access/reset``: restore the guest portal defaults."""
    _validate_json_body(body)
    require_unmasked_fields(body, "reset_guest_access_settings body")
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    return await client.post(
        v2_site(host_id, site_slug, "/settings/guest-access/reset"),
        key=key,
        json={} if body is None else body,
    )


# --------------------------------------------------------------------------- registration


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the network clients, guests, DHCP and hotspot tools."""

    @mcp.tool(name="authorize_guest", annotations=WRITE)
    async def _authorize_guest(
        host: str,
        site: str,
        client: str,
        time_limit_minutes: int | None = None,
        data_limit_mbytes: int | None = None,
        rx_rate_limit_kbps: int | None = None,
        tx_rate_limit_kbps: int | None = None,
        ap_mac: str | None = None,
        confirm: bool = False,
    ) -> Any:
        """Authorize a guest client on the guest portal (let it onto the network now).

        Consequence: the guest gets network access past the portal at once, within the
        limits sent (or the site's guest defaults) until they expire or the guest is revoked.

        Route: a CONNECTED client uses the official client action AUTHORIZE_GUEST_ACCESS
        (Network 11.0.97 POST /v1/sites/{siteId}/clients/{clientId}/actions); a MAC that
        is not connected (pre-authorizing a guest before it joins) or a call with ap_mac
        uses Classic cmd/stamgr authorize-guest (minutes, bytes, down, up, ap_mac), because
        the official action needs a connected client and has no ap_mac. Limits map 1:1:
        time_limit_minutes -> timeLimitMinutes / minutes, data_limit_mbytes ->
        dataUsageLimitMBytes / bytes (MB), rx_rate_limit_kbps -> rxRateLimitKbps / down,
        tx_rate_limit_kbps -> txRateLimitKbps / up. Only the limits you pass are sent;
        omitted, the site's guest defaults apply. The official action answers HTTP 422
        api.client.not-guest for a connected client that is not on a guest network.

        Returns the upstream body verbatim, with _route and _reason added to object
        responses. Bare arrays and scalars remain unchanged. Classic requires rc "ok".
        Under dry-run policy nothing is sent and the dry-run preview remains unchanged.

        Undo with revoke_guest_access.

        Dry-run returns {status: "dry_run", dryRun: true, sent: false, message,
        preview: {method, path, params, body}}; nothing is sent.

        Example call (authorize_guest):
            {"host": "my-console", "site": "Default", "client": "02:00:00:00:00:01",
             "time_limit_minutes": 60}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            client: Guest MAC (any form, e.g. "02:00:00:00:00:01") or connected client UUID.
            time_limit_minutes: Minutes of access, e.g. 60 (official range 1-1000000).
            data_limit_mbytes: Data cap in MB, e.g. 1024 (official range 1-1048576).
            rx_rate_limit_kbps: Download limit in kbps, e.g. 10000 (official 2-100000).
            tx_rate_limit_kbps: Upload limit in kbps, e.g. 2000 (official 2-100000).
            ap_mac: Classic only: the AP MAC the guest is associated with; selects Classic,
                e.g. "02:00:00:00:00:aa".
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        c, registry = deps_fn()
        return await authorize_guest(
            c,
            registry,
            host,
            site,
            client,
            time_limit_minutes=time_limit_minutes,
            data_limit_mbytes=data_limit_mbytes,
            rx_rate_limit_kbps=rx_rate_limit_kbps,
            tx_rate_limit_kbps=tx_rate_limit_kbps,
            ap_mac=ap_mac,
        )

    @mcp.tool(name="revoke_guest_access", annotations=WRITE)
    async def _revoke_guest_access(
        host: str,
        site: str,
        guest: str,
        target_type: GuestTarget = "client",
        confirm: bool = False,
    ) -> Any:
        """Revoke a guest's portal authorization (the guest is disconnected).

        Consequence: the guest loses network access at once and must pass the portal again
        (or be re-authorized with authorize_guest) to reconnect.

        Route by target_type. "client" (default): a CONNECTED guest client (MAC or UUID) uses the
        official client action UNAUTHORIZE_GUEST_ACCESS; a MAC that is not connected uses
        Classic cmd/stamgr unauthorize-guest. target_type "guest_session": guest is a guest
        session _id from list_hotspot_authorizations uses Classic cmd/hotspot terminate;
        it ends that session (the only route addressing a session). Session _ids and client ids are
        both UUIDs on Network 11.x, which is why the selector is explicit. The official
        action answers HTTP 422 api.client.not-guest for a client that is not a guest.

        Returns {deleted, message, response}: deleted is true, message summarizes the delete, and
        response is the upstream body verbatim (decoded JSON, raw text, or null when the body is
        empty). Classic requires rc "ok".

        Under dry-run policy the tool returns {status: "dry_run", deleted: false, message,
        response},
        where response is {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}}; nothing is sent.

        Example call (revoke_guest_access):
            {"host": "my-console", "site": "Default", "guest": "02:00:00:00:00:01"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            guest: Guest MAC (any form) or connected client UUID; for target_type
                guest_session, the session _id from list_hotspot_authorizations, e.g.
                "02:00:00:00:00:01" (client) or "00000000-0000-0000-0000-000000000001".
            target_type: "client" (default) or "guest_session", e.g. "client".
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        c, registry = deps_fn()
        return await revoke_guest_access(c, registry, host, site, guest, target_type)

    @mcp.tool(name="get_local_client", annotations=READ_ONLY)
    async def _get_local_client(
        host: str,
        site: str,
        client: str,
        include_traffic_usage: bool | None = None,
        include_unifi_devices: bool | None = None,
        include_matter_thread_clients: bool | None = None,
    ) -> Any:
        """Get the controller's record of one client by MAC (v2 clients/local/{mac}).

        Route: v2 only (no official route has these fields): the record the Network web
        app opens for a client, with fingerprint, network, uplink, usergroup, tags, note
        flag and fixed-IP state. The collection route clients/local answers HTTP 404 on
        Network 11.0.81, so this reads one client; list connected clients with
        list_clients. A client id (UUID) is turned into its MAC with the official client
        GET first.

        Returns the upstream object verbatim.

        Bare-list returns use the FastMCP {result: [...]} envelope; upstream core shapes
        remain verbatim.

        Example call (get_local_client):
            {"host": "my-console", "site": "Default", "client": "aa:bb:cc:dd:ee:ff"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            client: Client MAC (any form) or connected client UUID, e.g. "aa:bb:cc:dd:ee:ff".
            include_traffic_usage: Sent as includeTrafficUsage=true/false when given, e.g.
                true.
            include_unifi_devices: Sent as includeUnifiDevices=true/false when given, e.g.
                false.
            include_matter_thread_clients: Sent as includeMatterThreadClients=true/false
                when given, e.g. false.
        """
        c, registry = deps_fn()
        return await get_local_client(
            c,
            registry,
            host,
            site,
            client,
            include_traffic_usage=include_traffic_usage,
            include_unifi_devices=include_unifi_devices,
            include_matter_thread_clients=include_matter_thread_clients,
        )

    @mcp.tool(name="list_client_traffic_controls", annotations=READ_ONLY)
    async def _list_client_traffic_controls(host: str, site: str) -> Any:
        """List how many traffic rules apply to each client (v2 clients/traffic-control).

        Route: v2 only. Returns the upstream object verbatim:
        {applied_traffic_rule_count: {client MAC: count}}.

        Bare-list returns use the FastMCP {result: [...]} envelope; upstream core shapes
        remain verbatim.

        Example call (list_client_traffic_controls):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
        """
        c, registry = deps_fn()
        return await list_client_traffic_controls(c, registry, host, site)

    @mcp.tool(name="get_client_insights", annotations=READ_ONLY)
    async def _get_client_insights(
        host: str,
        site: str,
        client: str,
        view: InsightView,
        start: int | None = None,
        end: int | None = None,
    ) -> Any:
        """Get a client insight view (v2 client/{mac}/view).

        Views: 24hr-activity ({historical_activity: [{timestamp, activity_seconds}]}),
        24hr-satisfaction ({historical_scores: [{timestamp, satisfaction}]}), ap-stats
        ({ap_stats: [{device_mac, device_name, session_time_seconds}],
        total_session_time_seconds}; needs start and end) and traffic-insights
        ({traffic_overview: {24hr_bytes, 24hr_wan_bytes}}). Route: v2 only.

        Start / end are epoch SECONDS and are sent as epoch milliseconds (the web app's
        unit; ap-stats answers HTTP 500 to seconds). Returns the upstream object verbatim
        (plus _warnings when a time looks like milliseconds or is negative).

        Bare-list returns use the FastMCP {result: [...]} envelope; upstream core shapes
        remain verbatim.

        Example call (get_client_insights):
            {"host": "my-console", "site": "Default", "client": "aa:bb:cc:dd:ee:ff",
             "view": "ap-stats", "start": 1760000000, "end": 1760003600}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            client: Client MAC (any form) or connected client UUID, e.g. "aa:bb:cc:dd:ee:ff".
            view: One of 24hr-activity, 24hr-satisfaction, ap-stats, traffic-insights,
                e.g. "ap-stats".
            start: Window start, epoch seconds, e.g. 1760000000 (ap-stats needs it).
            end: Window end, epoch seconds, e.g. 1760003600 (ap-stats needs it).
        """
        c, registry = deps_fn()
        return await get_client_insights(
            c, registry, host, site, client, view, start=start, end=end
        )

    @mcp.tool(name="get_client_observability", annotations=READ_ONLY)
    async def _get_client_observability(
        host: str,
        site: str,
        client: str,
        view: ObservabilityView,
        start: int | None = None,
        end: int | None = None,
        timestamp: int | None = None,
    ) -> Any:
        """Get a client observability view (v2 observability/client/{mac}/...).

        Views: logs-all (client connection logs: {data, page_number, total_element_count,
        total_page_count}; the route takes no page parameter, so a multi-page answer adds a
        _warnings entry), timeline (array of timeline entries), timestamps (array of
        epoch-ms times that have a topology snapshot) and topology (the client's path at
        one time: {client, hops, isp, timestamp}; needs timestamp). Route: v2 only.

        Start, end and timestamp are epoch SECONDS and are sent as epoch milliseconds (the
        web app's unit). logs-all, timeline and timestamps require start and end; topology
        takes timestamp (pick one from the timestamps view, divided by 1000). Start or end
        with topology, or timestamp with any other view, fails before any request. Missing
        windows are forwarded. Returns the
        upstream body verbatim (objects also carry _warnings when a time looks like
        milliseconds or is negative).

        Example call (get_client_observability):
            {"host": "my-console", "site": "Default", "client": "aa:bb:cc:dd:ee:ff",
             "view": "timeline", "start": 1760000000, "end": 1760003600}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            client: Client MAC (any form) or connected client UUID, e.g. "aa:bb:cc:dd:ee:ff".
            view: One of logs-all, timeline, timestamps, topology, e.g. "timeline".
            start: Window start, epoch seconds; required for logs-all, timeline and
                timestamps, e.g. 1760000000.
            end: Window end, epoch seconds; required for logs-all, timeline and
                timestamps, e.g. 1760003600.
            timestamp: topology only: the snapshot time, epoch seconds, e.g. 1760003000.
        """
        c, registry = deps_fn()
        return await get_client_observability(
            c, registry, host, site, client, view, start=start, end=end, timestamp=timestamp
        )

    @mcp.tool(name="set_client_icon", annotations=WRITE)
    async def _set_client_icon(
        host: str,
        site: str,
        target_id: str,
        icon: dict[str, Any] | None = None,
        target_type: IconTarget = "client",
        confirm: bool = False,
    ) -> Any:
        """Set or remove the custom (AI-generated) icon of a client or a Matter node.

        Consequence: changes only the icon the controller UI shows for that client or node
        (removal restores the default icon); connectivity is unaffected.

        Icon given: PUT v2 clients/{mac}/ai-icon (or matter/nodes/{id}/ai-icon) with the icon object
        as the body. Returns the upstream body of that PUT verbatim. icon omitted: DELETE on the
        same route restores the default icon and returns {deleted, message, response}: deleted is
        true, message summarizes the delete, and response is the upstream body verbatim (decoded
        JSON, raw text, or null when the body is empty). Route: v2 only (no official route).
        Request body: no published schema; the web app sends its icon generator's object
        {icon_id, icon_set_id, request_id, selected_index, assets: [{url, width, height}]} as
        the body; an empty body answers HTTP 400
        "Validation failure". A MAC that is neither a connected client nor a known client
        (stat/alluser) is refused before any request, listing the valid clients; the upstream
        answers HTTP 404 api.err.ClientNotFound only for a known MAC with no v2 client record.

        Under dry-run policy nothing is sent: the dry-run preview (method, path, params,
        body) is returned unchanged for a PUT; a DELETE (icon removal) returns {status: "dry_run",
        deleted: false, message, response} with the preview as response.

        The PUT dry-run preview is {status: "dry_run", dryRun: true, sent: false, message, preview:
        {method, path, params, body}}.

        Example call (set_client_icon):
            {"host": "my-console", "site": "Default", "target_id": "aa:bb:cc:dd:ee:ff"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            target_id: Client MAC (any form) or connected client UUID; for target_type
                matter_node the Matter node id, e.g. "aa:bb:cc:dd:ee:ff".
            icon: Free-form icon object to set; omit to restore the default icon, e.g.
                the web app icon generator's object with keys icon_id, icon_set_id,
                request_id, selected_index and assets ([{url, width, height}]).
            target_type: "client" (default) or "matter_node", e.g. "client".
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        c, registry = deps_fn()
        return await set_client_icon(c, registry, host, site, target_id, icon, target_type)

    @mcp.tool(name="set_client_fingerprint_override", annotations=WRITE)
    async def _set_client_fingerprint_override(
        host: str,
        site: str,
        client: str,
        override: dict[str, Any] | None = None,
        confirm: bool = False,
    ) -> Any:
        """Override (or restore) the device type the controller detected for a client.

        Consequence: the controller reports the overridden device type for the client in
        place of its fingerprint detection until the override is removed.

        Override given: PUT v2 station/{mac}/fingerprint_override; the web app's body is
        {dev_id_override: fingerprint device id, mac, plus optional search_query, dev_type,
        dev_vendor, dev_model}; mac is added from the client when the body has none. Returns the
        upstream body of that PUT verbatim. override omitted: DELETE on the same route restores
        automatic detection and returns {deleted, message, response}: deleted is true, message
        summarizes the delete, and response is the upstream body verbatim (decoded JSON, raw
        text, or null when the body is empty). The current state is fingerprint.has_override /
        dev_id_override in list_dhcp_leases or get_local_client. Route: v2 only (no official
        route).

        Under dry-run policy nothing is sent: a PUT returns the dry-run preview unchanged; a DELETE
        (restore detection) returns {status: "dry_run", deleted: false, message, response}
        with the preview as response.

        The PUT dry-run preview is {status: "dry_run", dryRun: true, sent: false, message, preview:
        {method, path, params, body}}.

        Example call (set_client_fingerprint_override):
            {"host": "my-console", "site": "Default", "client": "aa:bb:cc:dd:ee:ff",
             "override": {"dev_id_override": 4}}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            client: Client MAC (any form) or connected client UUID, e.g. "aa:bb:cc:dd:ee:ff".
            override: Body {dev_id_override, ...} (free-form); omit to restore detection,
                e.g. {"dev_id_override": 4}.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        c, registry = deps_fn()
        return await set_client_fingerprint_override(c, registry, host, site, client, override)

    @mcp.tool(name="report_incorrect_wifi_experience", annotations=WRITE)
    async def _report_incorrect_wifi_experience(
        host: str,
        site: str,
        target_type: WifiReportTarget,
        target: str,
        reason: str,
        comment: str | None = None,
        confirm: bool = False,
    ) -> Any:
        """Report that a client's or AP's WiFi experience score is wrong (sends feedback
        to Ubiquiti; cannot be withdrawn).

        Consequence: the feedback report is sent to Ubiquiti and cannot be withdrawn; client,
        AP and score are not changed by it.

        POST v2 station/{mac}/wifi_experience/incorrect (target_type client) or
        device/{mac}/wifi_experience/incorrect (target_type ap) with {reason, comment}.
        The web app offers the reasons DROPPED_CONNECTIVITY, POOR_LATENCY and
        POOR_THROUGHPUT; reason is sent as given. Route: v2 only (no official route).
        Returns the upstream body verbatim; under dry-run policy the dry-run preview.

        Dry-run returns {status: "dry_run", dryRun: true, sent: false, message,
        preview: {method, path, params, body}}; nothing is sent.

        Example call (report_incorrect_wifi_experience):
            {"host": "my-console", "site": "Default", "target_type": "client",
             "target": "aa:bb:cc:dd:ee:ff", "reason": "POOR_LATENCY"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            target_type: "client" or "ap", e.g. "client".
            target: Client MAC (any form) or connected client UUID; for ap, the AP MAC,
                e.g. "aa:bb:cc:dd:ee:ff".
            reason: e.g. "POOR_LATENCY" (web app: DROPPED_CONNECTIVITY, POOR_LATENCY,
                POOR_THROUGHPUT).
            comment: Optional free-text comment, e.g. "Calls drop in the kitchen".
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        c, registry = deps_fn()
        return await report_incorrect_wifi_experience(
            c, registry, host, site, target_type, target, reason, comment
        )

    @mcp.tool(name="list_dhcp_leases", annotations=READ_ONLY)
    async def _list_dhcp_leases(host: str, site: str, network_id: str | None = None) -> Any:
        """List active DHCP leases, for the site or one network (v2 active-leases).

        Route: v2 only (no official route). Returns the upstream object verbatim:
        {dhcp_lease_info: [{mac, ip, hostname, display_name, network_id, client_type,
        status, lease_expiration_time, use_fixedip, fixed_ip, fingerprint, ...}]}.

        Bare-list returns use the FastMCP {result: [...]} envelope; upstream core shapes
        remain verbatim.

        Example call (list_dhcp_leases):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            network_id: Optional Classic networkconf _id to list that network's leases only,
                e.g. "000000000000000000000108". It is sent untranslated in the v2 path, so
                the Integration id from list_networks (data[].id) is not a substitute.
        """
        c, registry = deps_fn()
        return await list_dhcp_leases(c, registry, host, site, network_id)

    @mcp.tool(name="list_dhcp_excluded_ips", annotations=READ_ONLY)
    async def _list_dhcp_excluded_ips(host: str, site: str, network_id: str | None = None) -> Any:
        """List addresses excluded from DHCP, for the site or one network (v2 excluded-ips).

        Route: v2 only (no official route). Returns the upstream object verbatim:
        {excluded_ip_client_info: [...], unidentified_excluded_ip_info: [...]}.

        Bare-list returns use the FastMCP {result: [...]} envelope; upstream core shapes
        remain verbatim.

        Example call (list_dhcp_excluded_ips):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            network_id: Optional Classic networkconf _id to scope the list, e.g.
                "000000000000000000000108". It is sent untranslated in the v2 path, so the
                Integration id from list_networks (data[].id) is not a substitute.
        """
        c, registry = deps_fn()
        return await list_dhcp_excluded_ips(c, registry, host, site, network_id)

    @mcp.tool(name="list_dhcp_options", annotations=READ_ONLY)
    async def _list_dhcp_options(host: str, site: str) -> Any:
        """List custom DHCP option definitions (Classic rest/dhcpoption).

        Route: Classic only (the Network 11.0.81 web app has no newer route). Returns the
        Classic envelope {meta: {rc}, data: [option...]} verbatim; each option carries _id,
        name, code, type, width and signed. Change one with update_dhcp_option (option_id
        = its _id).

        Example call (list_dhcp_options):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
        """
        c, registry = deps_fn()
        return await list_dhcp_options(c, registry, host, site)

    @mcp.tool(name="create_dhcp_option", annotations=WRITE)
    async def _create_dhcp_option(
        host: str, site: str, option: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Define a custom DHCP option (Classic POST rest/dhcpoption).

        Request body: no published schema; the controller's fields are name (letters,
        digits, - and _; a 31-character name was rejected with api.err.InvalidValue), code
        (the option number; the web app allows 7-254 except reserved codes; stored as an
        integer),
        type (text, ipaddress, integer, boolean, hexarray, macaddress), width (8, 16 or 32
        for integers) and signed. The body is sent as given. Networks then reference the
        option by name. Route: Classic only.

        Returns the Classic envelope {meta: {rc}, data: [option]} verbatim; the new _id is
        data[0]._id. Under dry-run policy the dry-run preview is returned and nothing sent.

        Dry-run returns {status: "dry_run", dryRun: true, sent: false, message,
        preview: {method, path, params, body}}; nothing is sent.

        Example call (create_dhcp_option):
            {"host": "my-console", "site": "Default",
             "option": {"name": "tftp-server", "code": "150", "type": "ipaddress"}}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            option: Free-form option body: name, code, type, width, signed, e.g.
                {"name": "tftp-server", "code": "150", "type": "ipaddress"}.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        c, registry = deps_fn()
        return await create_dhcp_option(c, registry, host, site, option)

    @mcp.tool(name="update_dhcp_option", annotations=WRITE)
    async def _update_dhcp_option(
        host: str, site: str, option_id: str, fields: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Update a custom DHCP option by _id (Classic PUT rest/dhcpoption/{id}).

        The id is resolved in list_dhcp_options first: an unknown id fails listing every
        valid _id and nothing is written. Request body: no published schema; pass only the
        fields to change (name, code, type, width, signed). The controller rejects a
        partial PUT (HTTP 400 api.err.Invalid), so the record read for the id check is sent
        back with your fields laid over it. Empty strings in list-valued fields are
        dropped. An empty update fails before any request. Route: Classic only.

        Returns the Classic envelope {meta: {rc}, data: [option]} verbatim. Under
        dry-run policy the dry-run preview is returned and nothing is sent.

        Dry-run returns {status: "dry_run", dryRun: true, sent: false, message,
        preview: {method, path, params, body}}; nothing is sent.
        Object results add _verified after a type-strict, leaf-by-leaf re-read: true,
        false with _unverifiedFields naming each differing leaf, or null with
        _readAfterError when the re-read fails. A non-object write body is returned whole
        under response with the same verdict keys beside it. Dry-run skips the re-read.

        Example call (update_dhcp_option):
            {"host": "my-console", "site": "Default",
             "option_id": "000000000000000000000107", "fields": {"name": "tftp-backup"}}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            option_id: DHCP option _id from list_dhcp_options, e.g.
                "000000000000000000000107".
            fields: Free-form fields to change, e.g. {"name": "tftp-backup"}.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        c, registry = deps_fn()
        return await update_dhcp_option(c, registry, host, site, option_id, fields)

    @mcp.tool(name="delete_dhcp_option", annotations=WRITE)
    async def _delete_dhcp_option(
        host: str, site: str, option_id: str, confirm: bool = False
    ) -> Any:
        """Delete a custom DHCP option by _id (Classic DELETE rest/dhcpoption/{id}).

        Consequence: networks stop handing out this option; there is no undo. The id is
        resolved in list_dhcp_options first (the controller answers a DELETE on an unknown
        id with HTTP 200): an unknown id fails listing every valid _id and nothing is
        deleted. Route: Classic only.

        Returns {deleted, message, response}: deleted is true, message summarizes the delete, and
        response is the upstream body verbatim (decoded JSON, raw text, or null when the body is
        empty).

        Under dry-run policy the tool returns {status: "dry_run", deleted: false, message,
        response},
        where response is {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}}; nothing is sent.

        Example call (delete_dhcp_option):
            {"host": "my-console", "site": "Default", "option_id": "000000000000000000000107"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            option_id: DHCP option _id from list_dhcp_options, e.g.
                "000000000000000000000107".
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        c, registry = deps_fn()
        return await delete_dhcp_option(c, registry, host, site, option_id)

    @mcp.tool(name="get_hotspot_settings", annotations=READ_ONLY)
    async def _get_hotspot_settings(host: str, site: str) -> Any:
        """Get the guest portal (hotspot) settings (Classic /api/stat/s/{site}/hotspotconfig).

        Route: Classic only (v2 hotspot/info has only show_hotspot_manager). Returns the
        Classic envelope {meta: {rc}, data: [config]} verbatim: auth, voucher_enabled,
        password_enabled, payment_enabled, radius_enabled, facebook_enabled, tos, title,
        welcome text, colours, logo and background settings, languages and the country
        list.

        Example call (get_hotspot_settings):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
        """
        c, registry = deps_fn()
        return await get_hotspot_settings(c, registry, host, site)

    @mcp.tool(name="list_hotspot_payments", annotations=READ_ONLY)
    async def _list_hotspot_payments(
        host: str,
        site: str,
        start: int | None = None,
        end: int | None = None,
        within: int | None = None,
    ) -> Any:
        """List guest portal payment transactions (Classic stat/payment).

        Route: Classic only. start / end are epoch SECONDS and are sent as epoch
        milliseconds (the web app's unit); within (hours back) is sent as given. Only the
        parameters you pass are sent. Returns the Classic envelope {meta: {rc}, data:
        [payment...]} verbatim (plus _warnings when a time looks like milliseconds).

        Example call (list_hotspot_payments):
            {"host": "my-console", "site": "Default", "start": 1757000000, "end": 1760000000}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            start: Window start, epoch seconds, e.g. 1757000000.
            end: Window end, epoch seconds, e.g. 1760000000.
            within: Hours back from now, e.g. 720.
        """
        c, registry = deps_fn()
        return await list_hotspot_payments(
            c, registry, host, site, start=start, end=end, within=within
        )

    @mcp.tool(name="list_hotspot_authorizations", annotations=READ_ONLY)
    async def _list_hotspot_authorizations(
        host: str, site: str, start: int | None = None, end: int | None = None
    ) -> Any:
        """List guest authorization history (Classic stat/authorization).

        Route: Classic only (community-documented route, served on Network 11.0.81). start
        / end are epoch SECONDS, sent as given; only the parameters you pass are sent.
        Returns the Classic envelope {meta: {rc}, data: [authorization...]} verbatim,
        plus _warnings when a time is negative or looks like milliseconds.

        Example call (list_hotspot_authorizations):
            {"host": "my-console", "site": "Default", "start": 1757000000, "end": 1760000000}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            start: Window start, epoch seconds, e.g. 1757000000.
            end: Window end, epoch seconds, e.g. 1760000000.
        """
        c, registry = deps_fn()
        return await list_hotspot_authorizations(c, registry, host, site, start=start, end=end)

    @mcp.tool(name="create_hotspot_package", annotations=WRITE)
    async def _create_hotspot_package(
        host: str, site: str, package: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Create a guest portal billing package (Classic POST rest/hotspotpackage).

        Request body: no published schema; sent as given. Fields: name, amount, currency,
        hours (paid duration), trial_duration_minutes and trial_reset (free trial),
        charged_as, index, limit_overwrite, limit_up, limit_down, limit_quota and the
        payment_fields_* switches. Live on Network 11.0.81 with payments not configured, a
        trial package {name, amount: 0, currency, trial_duration_minutes, trial_reset} was
        accepted, while paid packages (amount > 0 with hours) answered HTTP 400
        api.err.InvalidHotspotPackageDuration. Guests see packages only when the portal has
        payments enabled (get_hotspot_settings payment_enabled). Route: Classic only.

        Returns the Classic envelope {meta: {rc}, data: [package]} verbatim; the new _id is
        data[0]._id (list them with list_hotspot_packages). Under dry-run policy the
        dry-run preview is returned and nothing is sent.

        Dry-run returns {status: "dry_run", dryRun: true, sent: false, message,
        preview: {method, path, params, body}}; nothing is sent.

        Example call (create_hotspot_package):
            {"host": "my-console", "site": "Default",
             "package": {"name": "Trial", "amount": 0, "currency": "USD",
                         "trial_duration_minutes": 30, "trial_reset": 24}}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            package: Free-form package body, e.g. {"name": "Trial", "amount": 0,
                "currency": "USD", "trial_duration_minutes": 30, "trial_reset": 24}.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        c, registry = deps_fn()
        return await create_hotspot_package(c, registry, host, site, package)

    @mcp.tool(name="update_hotspot_package", annotations=WRITE)
    async def _update_hotspot_package(
        host: str, site: str, package_id: str, fields: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Update a guest portal billing package by _id (Classic PUT rest/hotspotpackage/{id}).

        The id is resolved in list_hotspot_packages first: an unknown id fails listing
        every valid _id and nothing is written. Request body: no published schema; pass
        only the fields to change. The controller rejects a partial Classic PUT, so the
        record read for the id check is sent back with your fields laid over it. Empty
        strings in list-valued fields are dropped. An empty update fails before any
        request. Route: Classic only.

        Returns the Classic envelope {meta: {rc}, data: [package]} verbatim. Under
        dry-run policy the dry-run preview is returned and nothing is sent.

        Dry-run returns {status: "dry_run", dryRun: true, sent: false, message,
        preview: {method, path, params, body}}; nothing is sent.
        Object results add _verified after a type-strict, leaf-by-leaf re-read: true,
        false with _unverifiedFields naming each differing leaf, or null with
        _readAfterError when the re-read fails. A non-object write body is returned whole
        under response with the same verdict keys beside it. Dry-run skips the re-read.

        Example call (update_hotspot_package):
            {"host": "my-console", "site": "Default",
             "package_id": "000000000000000000000107", "fields": {"amount": 6}}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            package_id: Package _id from list_hotspot_packages, e.g.
                "000000000000000000000107".
            fields: Free-form fields to change, e.g. {"amount": 6}.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        c, registry = deps_fn()
        return await update_hotspot_package(c, registry, host, site, package_id, fields)

    @mcp.tool(name="delete_hotspot_package", annotations=WRITE)
    async def _delete_hotspot_package(
        host: str, site: str, package_id: str, confirm: bool = False
    ) -> Any:
        """Delete a guest portal billing package by _id (Classic DELETE rest/hotspotpackage/{id}).

        Consequence: guests can no longer buy this package; there is no undo. The id is
        resolved in list_hotspot_packages first (the controller answers a DELETE on an
        unknown id with HTTP 200): an unknown id fails listing every valid _id and nothing
        is deleted. Route: Classic only.

        Returns {deleted, message, response}: deleted is true, message summarizes the delete, and
        response is the upstream body verbatim (decoded JSON, raw text, or null when the body is
        empty).

        Under dry-run policy the tool returns {status: "dry_run", deleted: false, message,
        response},
        where response is {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}}; nothing is sent.

        Example call (delete_hotspot_package):
            {"host": "my-console", "site": "Default", "package_id": "000000000000000000000107"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            package_id: Package _id from list_hotspot_packages, e.g.
                "000000000000000000000107".
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        c, registry = deps_fn()
        return await delete_hotspot_package(c, registry, host, site, package_id)

    @mcp.tool(name="delete_guest_portal_file", annotations=WRITE)
    async def _delete_guest_portal_file(
        host: str, site: str, file_id: str, confirm: bool = False
    ) -> Any:
        """Delete an uploaded guest portal file (logo or background image) by _id
        (Classic DELETE rest/portalfile/{id}).

        Consequence: the portal stops showing the file; there is no undo. The id is
        resolved in the Classic rest/portalfile list first (the controller answers a DELETE
        on an unknown id with HTTP 200): an unknown id fails listing every file and
        nothing is deleted. Route: Classic only.

        Returns {deleted, message, response}: deleted is true, message summarizes the delete, and
        response is the upstream body verbatim (decoded JSON, raw text, or null when the body is
        empty).

        Under dry-run policy the tool returns {status: "dry_run", deleted: false, message,
        response},
        where response is {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}}; nothing is sent.

        Example call (delete_guest_portal_file):
            {"host": "my-console", "site": "Default", "file_id": "000000000000000000000107"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            file_id: Portal file _id from the Classic rest/portalfile list, e.g.
                "000000000000000000000107".
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        c, registry = deps_fn()
        return await delete_guest_portal_file(c, registry, host, site, file_id)

    @mcp.tool(name="reset_guest_access_settings", annotations=WRITE)
    async def _reset_guest_access_settings(
        host: str, site: str, body: dict[str, Any] | None = None, confirm: bool = False
    ) -> Any:
        """Reset the guest portal (guest access) settings to their defaults
        (v2 POST settings/guest-access/reset).

        Consequence: every customized portal setting (authentication, texts, colours,
        images, terms) returns to the default; there is no undo, so read
        get_hotspot_settings first if you may want to restore them. Request body: none
        published; the web app sends {} (sent when body is omitted). Route: v2 only.

        Returns the upstream body verbatim; under dry-run policy the dry-run preview.

        Dry-run returns {status: "dry_run", dryRun: true, sent: false, message,
        preview: {method, path, params, body}}; nothing is sent.

        Example call (reset_guest_access_settings):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            body: Optional free-form request body; omitted, {} is sent like the web app,
                e.g. {}.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        c, registry = deps_fn()
        return await reset_guest_access_settings(c, registry, host, site, body)
