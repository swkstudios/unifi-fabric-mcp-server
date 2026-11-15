"""Statistics tools — read-only site/device/client stats via Classic REST stat endpoints."""

from __future__ import annotations

from typing import Any

from ...client import (
    UniFiClient,
    UniFiConnectionError,
    describe_shape,
    object_records,
    upstream_error_value,
    validate_id,
    validate_selector,
)
from ...macs import is_mac, normalize_mac, record_mac
from ...matching import id_key, same_id
from ...read_post_routes import post_read
from ...registry import Registry
from ...selector_args import check_selector
from ...shared_shapes._classic_objects import v2_site
from ...shared_shapes._clients_shared import resolve_list_source, v2_flag_params
from ...shared_shapes._history_common import (
    epoch_warnings,
    require_epoch_seconds,
    seconds_to_millis,
    translate_host_not_found,
    with_warnings,
)
from ...shared_shapes._statistics_shared import (  # noqa: F401  (shared)
    health_summary as health_summary,
)
from ...shared_shapes._statistics_shared import (
    with_health_summary as with_health_summary,
)
from .schemas import (  # the family's shapes (family-owned layout)
    _DEVICE_STP_KEYS,
    _DEVICE_THERMAL_POWER_KEYS,
    _MODERN_STATS_BASE,
    _PORT_STP_KEYS,
    KNOWN_CLIENTS_SOURCES,
    REPORT_INTERVALS,
    REPORT_SCOPES,
    SESSION_TYPES,
)

_CLASSIC_STAT_BASE = "/v1/connector/consoles/{host_id}/proxy/network/api/s/{site_slug}/stat"


def _classic_stat(host_id: str, site_slug: str, path: str) -> str:
    return _CLASSIC_STAT_BASE.format(host_id=host_id, site_slug=site_slug) + path


async def _list_controller_stat_schemas(client: UniFiClient, registry: Registry, host: str) -> Any:
    """Return the schemas exposed by the Network 11.x statistics engine."""
    check_selector("host", host)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    return await client.get(_MODERN_STATS_BASE.format(host_id=host_id) + "/schemas", key=key)


# Every stat read returns the controller's Classic envelope {"meta": {...}, "data": [...]}
# verbatim (meta included). A response is a success only with meta.rc "ok": anything else
# is raised by the client chokepoint (client.classic_rc_error). Selection tools return
# the same envelope with ``data`` narrowed to the selected records, and projection tools
# carry the envelope's ``meta`` next to their projection.


def _stat_records(response: Any, source_label: str) -> list[dict[str, Any]]:
    """The record list of a /stat/* envelope, or raise with the shape received."""
    data = response.get("data") if isinstance(response, dict) else None
    if not isinstance(data, list):
        raise UniFiConnectionError(
            f"Unexpected {source_label} response shape: expected an object with a 'data' "
            f"array, got {describe_shape(response)}"
        )
    return object_records(data, source_label)


def _narrowed(response: dict[str, Any], records: list[dict[str, Any]]) -> dict[str, Any]:
    """The upstream envelope with ``data`` narrowed to ``records`` (other keys verbatim)."""
    return {**response, "data": records}


async def _get_site_statistics(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return with_health_summary(
        await client.get(_classic_stat(host_id, site_slug, "/health"), key=key)
    )


async def _get_system_info(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.get(_classic_stat(host_id, site_slug, "/sysinfo"), key=key)


async def _list_active_clients_stats(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.get(_classic_stat(host_id, site_slug, "/sta"), key=key)


async def _list_device_stats(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.get(_classic_stat(host_id, site_slug, "/device"), key=key)


async def _list_client_sessions(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    start: int,
    end: int,
    session_type: str = "all",
) -> Any:
    """Fetch client session history from Classic REST /stat/session.

    ``start``/``end`` are epoch **seconds** — this endpoint natively uses seconds,
    and passing milliseconds returns HTTP 200 with an empty array (no error).

    ``session_type`` must be one of :data:`SESSION_TYPES` and is checked before any
    request: the endpoint ignores an unknown value and answers the full ``all`` set, so a
    typo would otherwise pass for a filtered result.
    """
    if session_type not in SESSION_TYPES:
        raise ValueError(
            f"session_type {session_type!r} is not a session class; valid: "
            f"{', '.join(repr(t) for t in SESSION_TYPES)}. The endpoint ignores an unknown "
            "value and returns every session, so it is rejected here."
        )
    start_s = require_epoch_seconds(start, "start")
    end_s = require_epoch_seconds(end, "end")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    body = {"type": session_type, "start": start_s, "end": end_s}
    try:
        response = await post_read(
            client, _classic_stat(host_id, site_slug, "/session"), key=key, json=body
        )
    except UniFiConnectionError as exc:
        raise translate_host_not_found(exc, host) from exc
    return with_warnings(response, epoch_warnings(start=start, end=end))


async def _get_historical_stats(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    interval: str,
    scope: str,
    start: int,
    end: int,
    attrs: list[str] | None = None,
) -> Any:
    """Fetch bucketed historical statistics from Classic REST /stat/report/{interval}.{scope}.

    ``start``/``end`` are epoch **seconds** and are converted to milliseconds
    internally — unlike /stat/session, this endpoint requires milliseconds.
    ``attrs`` is sent only when the caller passes it (exactly as given); the
    controller accepts a report request without it (verified on Network 11.0.81).
    """
    if interval not in REPORT_INTERVALS:
        raise ValueError(
            f"Invalid interval {interval!r}: expected one of "
            f"{', '.join(repr(v) for v in REPORT_INTERVALS)}"
        )
    if scope not in REPORT_SCOPES:
        raise ValueError(
            f"Invalid scope {scope!r}: expected one of {', '.join(repr(v) for v in REPORT_SCOPES)}"
        )
    start_ms = seconds_to_millis(require_epoch_seconds(start, "start"))
    end_ms = seconds_to_millis(require_epoch_seconds(end, "end"))
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    body: dict[str, Any] = {"start": start_ms, "end": end_ms}
    if attrs is not None:
        body["attrs"] = list(attrs)
    try:
        response = await post_read(
            client,
            _classic_stat(host_id, site_slug, f"/report/{interval}.{scope}"),
            key=key,
            json=body,
        )
    except UniFiConnectionError as exc:
        raise translate_host_not_found(exc, host) from exc
    return with_warnings(response, epoch_warnings(start=start, end=end))


async def _list_speedtest_results(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    start: int,
    end: int,
) -> Any:
    """Read the legacy archive of speed-test results for an epoch-seconds window."""
    start_ms = seconds_to_millis(require_epoch_seconds(start, "start"))
    end_ms = seconds_to_millis(require_epoch_seconds(end, "end"))
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    body = {
        "attrs": [
            "xput_download",
            "xput_upload",
            "latency",
            "time",
            "interface_name",
            "wan_networkgroup",
        ],
        "start": start_ms,
        "end": end_ms,
    }
    try:
        return await post_read(
            client,
            _classic_stat(host_id, site_slug, "/report/archive.speedtest"),
            key=key,
            json=body,
        )
    except UniFiConnectionError as exc:
        raise translate_host_not_found(exc, host) from exc


async def _list_known_clients(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    source: str | None = None,
    within_hours: int | None = None,
    only_blocked: bool | None = None,
    only_non_blocked: bool | None = None,
    include_matter_thread_clients: bool | None = None,
    include_traffic_usage: bool | None = None,
    include_unifi_devices: bool | None = None,
) -> Any:
    """Fetch the full client roster (including offline history) from Classic REST /stat/alluser.

    ``source="v2"`` (or any v2-only argument) reads the controller's v2 client
    history instead, verbatim; the classic route stays the default because the v2 rows
    lack fields the classic roster carries.
    """
    flags: dict[str, bool | None] = {
        "include_matter_thread_clients": include_matter_thread_clients,
        "include_traffic_usage": include_traffic_usage,
        "include_unifi_devices": include_unifi_devices,
    }
    v2_args: dict[str, Any] = {
        "within_hours": within_hours,
        "only_blocked": only_blocked,
        "only_non_blocked": only_non_blocked,
        **flags,
    }
    chosen = resolve_list_source(
        "list_known_clients",
        source,
        KNOWN_CLIENTS_SOURCES,
        "classic",
        "v2",
        newer_args=v2_args,
        default_args={},
    )
    if chosen == "v2":
        params = v2_flag_params(
            {"onlyBlocked": only_blocked, "onlyNonBlocked": only_non_blocked, **flags}
        )
        if within_hours is not None:
            params["withinHours"] = str(within_hours)
        key = await registry.resolve_key_for_host(host)
        host_id = await registry.resolve_host_id(host, key=key)
        site_slug = await registry.resolve_site_slug(site, host_id, key=key)
        validate_id(site_slug, "site_slug")
        try:
            return await client.get(
                v2_site(host_id, site_slug, "/clients/history"),
                key=key,
                **({"params": params} if params else {}),
            )
        except UniFiConnectionError as exc:
            raise translate_host_not_found(exc, host) from exc
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    try:
        response = await client.get(_classic_stat(host_id, site_slug, "/alluser"), key=key)
    except UniFiConnectionError as exc:
        raise translate_host_not_found(exc, host) from exc
    return response


# --- Focused convenience reads over /stat/sta and /stat/device ---
#
# These helpers add NO new Fabric route: each reuses the exact Classic REST request the
# corresponding list_* tool already issues (/stat/sta for clients, /stat/device for
# devices), then selects and/or projects the already-fetched payload in memory. The
# selector is compared against in-memory record fields only and is never interpolated into
# a URL path, so it needs no path-safety validation. Upstream operational fields are
# preserved verbatim; the list_* tools remain the faithful raw pass-throughs.


def _normalize_mac(value: str) -> str:
    """A MAC as 12 lowercase hex digits for equality comparison ('' when ``value`` is not
    a MAC: a non-MAC selector never matches a record's mac)."""
    return normalize_mac(value) if is_mac(value) else ""


def _record_matches(record: dict[str, Any], selector: str, norm_selector: str) -> bool:
    """True if record matches selector by _id/id (a hex id case-insensitively,
    :func:`~unifi_fabric.matching.same_id`) or mac (separator-insensitive)."""
    for field in ("_id", "id"):
        if same_id(selector, record.get(field)):
            return True
    if norm_selector and record_mac(record.get("mac")) == norm_selector:
        return True
    return False


# Where to get an identifier that matches each /stat/* payload. The Integration API ids
# (list_site_devices / list_clients data[].id) are a different identifier space and never
# appear in these classic payloads, so naming them prevents the commonest mismatch.
_SELECTOR_HINTS = {
    "/stat/device": (
        "pass the device MAC (list_site_devices macAddress, or mac from list_devices / "
        "list_device_stats) or the _id from list_device_stats; the Integration API device id "
        "(list_site_devices data[].id) is a different identifier"
    ),
    "/stat/sta": (
        "pass the client MAC (list_clients macAddress, or mac from list_active_clients_stats) "
        "or the _id from list_active_clients_stats; the Integration API client id "
        "(list_clients data[].id) is a different identifier"
    ),
}


def _selector_hint(source_label: str) -> str:
    return _SELECTOR_HINTS.get(source_label, "verify the identifier with the list tool")


def _valid_choices(records: list[dict[str, Any]]) -> str:
    """List every identifying field for each valid choice, without truncation."""
    out = []
    for r in records:
        label = r.get("name") or r.get("hostname") or "(unnamed)"
        out.append(
            f"{upstream_error_value(label)} (mac={upstream_error_value(r.get('mac'))}, "
            f"_id={upstream_error_value(r.get('_id'))}, id={upstream_error_value(r.get('id'))})"
        )
    return "; ".join(out) or "(none)"


def _matching_record(
    records: list[dict[str, Any]], selector: str, kind: str
) -> dict[str, Any] | None:
    norm = _normalize_mac(selector)
    matched = [r for r in records if _record_matches(r, selector, norm)]
    distinct: dict[object, dict[str, Any]] = {}
    for index, record in enumerate(matched):
        native = record.get("_id") or record.get("id")
        # Stat rows can identify an offline client by MAC alone; no write uses these rows.
        identity = id_key(native) if isinstance(native, str) and native else ("row", index)
        distinct.setdefault(identity, record)
    if len(distinct) > 1:
        raise ValueError(
            f"ambiguous {kind} {selector!r}: distinct records: "
            f"{_valid_choices(list(distinct.values()))}."
        )
    return next(iter(distinct.values()), None)


def _select_one_record(
    records: list[dict[str, Any]], selector: str, kind: str, source_label: str
) -> dict[str, Any]:
    """Return the single record matching selector, or raise listing every valid choice."""
    if not selector:
        raise ValueError(f"{kind} selector must not be empty")
    match = _matching_record(records, selector, kind)
    if match is not None:
        return match
    raise ValueError(
        f"No {kind} matching {selector!r} in {source_label} "
        f"(matched against _id, id, and mac); {_selector_hint(source_label)}. "
        f"Valid: {_valid_choices(records)}."
    )


def _port_rows(device: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate every port_table row; only an absent table means no ports."""
    if "port_table" not in device:
        return []
    return object_records(device["port_table"], "/stat/device port_table")


async def _get_client_link_diagnostics(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    client_id: str | None = None,
    client_ids: list[str] | None = None,
) -> Any:
    """Select per-client link/policy diagnostics from the /stat/sta payload.

    Exactly one of ``client_id`` (single) or ``client_ids`` (explicit list) must be
    supplied. Both forms return the upstream ``{"meta", "data"}`` envelope with ``data``
    narrowed to the matching records (unchanged, in the requested order). Reuses the same
    /stat/sta request as _list_active_clients_stats — no new route.
    """
    if client_ids == [] and client_id is None:
        # An empty client_ids list applies no filter: every /stat/sta record is returned.
        client_ids = None
        unfiltered = True
    else:
        unfiltered = False
        if client_ids == []:
            client_ids = None  # not applied: client_id selects
        if (client_id is None) == (client_ids is None):
            raise ValueError("Provide exactly one of client_id (single) or client_ids (list).")
    # Every selector is checked before the /stat/sta read (no request for a bad argument).
    if client_id is not None:
        validate_selector(client_id, "client_id")
    else:
        for index, cid in enumerate(client_ids or []):
            validate_selector(cid, f"client_ids[{index}]")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(_classic_stat(host_id, site_slug, "/sta"), key=key)
    records = _stat_records(response, "/stat/sta")
    if unfiltered:
        return response

    if client_id is not None:
        return _narrowed(response, [_select_one_record(records, client_id, "client", "/stat/sta")])

    selected: list[dict[str, Any]] = []
    missing: list[str] = []
    for cid in client_ids or []:
        match = _matching_record(records, cid, "client")
        if match is None:
            missing.append(cid)
        else:
            selected.append(match)
    if missing:
        raise ValueError(
            f"No /stat/sta client matched: {missing!r} "
            f"(matched against _id, id, and mac); {_selector_hint('/stat/sta')}. "
            f"Valid: {_valid_choices(records)}."
        )
    return _narrowed(response, selected)


async def _get_device_port_state(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device_id: str,
    port_idx: int | None = None,
) -> Any:
    """Project switch port_table / lldp_table / thermal telemetry from /stat/device.

    Reuses the same /stat/device request as _list_device_stats (one Fabric call, no new route). With
    ``port_idx`` omitted returns the device view (verbatim port_table and lldp_table when the record
    carries them, plus a thermal/power summary); with ``port_idx`` set returns that single
    port_table row verbatim. The device view also carries the complete selected /stat/device record,
    verbatim, under ``_device_record``. The additive keys (``_device``, ``_port_idx``, ``_source``,
    ``_port``, ``_thermal_power``) never rename or drop upstream fields; the upstream envelope's
    ``meta`` is carried verbatim.
    """
    validate_selector(device_id, "device_id")
    if port_idx is not None and port_idx < 0:
        raise ValueError("'port_idx' must be a non-negative port number.")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(_classic_stat(host_id, site_slug, "/device"), key=key)
    records = _stat_records(response, "/stat/device")
    device = _select_one_record(records, device_id, "device", "/stat/device")
    ports = _port_rows(device)
    meta = {"meta": response["meta"]} if "meta" in response else {}

    if port_idx is not None:
        for row in ports:
            if row.get("port_idx") == port_idx:
                return {
                    **meta,
                    "_device": device_id,
                    "_port_idx": port_idx,
                    "_source": "/stat/device",
                    "_port": row,
                }
        valid_ports = [upstream_error_value(row.get("port_idx")) for row in ports]
        raise ValueError(
            f"Device {device_id!r} has no port_idx={port_idx} in its /stat/device "
            f"port_table; valid port_idx values: {valid_ports or '(none)'}."
        )

    thermal_power = {k: device[k] for k in _DEVICE_THERMAL_POWER_KEYS if k in device}
    # Verbatim: the device's own port_table / lldp_table, only when the record carries
    # them (an absent table stays absent; no key is invented as null).
    tables = {k: device[k] for k in ("port_table", "lldp_table") if k in device}
    return {
        **meta,
        "_device": device_id,
        "_port_idx": None,
        "_source": "/stat/device",
        **tables,
        "_thermal_power": thermal_power,
        "_device_record": device,
    }


async def _get_device_stp_state(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device_id: str,
) -> Any:
    """Project per-device and per-port STP/RSTP state from the /stat/device payload.

    Fabric-only, over the same /stat/device request as _list_device_stats. Surfaces the
    device-level STP fields (stp_version, stp_priority, root_switch/root, and any other
    ``stp_*`` key present) and per-port STP role/state/path-cost where upstream provides
    them, all verbatim, under the additive ``_stp`` / ``_ports``, plus the complete
    device record under ``_device_record`` and the upstream envelope's ``meta``. No write
    is performed.
    """
    validate_selector(device_id, "device_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(_classic_stat(host_id, site_slug, "/device"), key=key)
    records = _stat_records(response, "/stat/device")
    device = _select_one_record(records, device_id, "device", "/stat/device")
    meta = {"meta": response["meta"]} if "meta" in response else {}

    device_stp: dict[str, Any] = {
        k: v for k, v in device.items() if k in _DEVICE_STP_KEYS or k.startswith("stp_")
    }
    ports_out: list[dict[str, Any]] = []
    for row in _port_rows(device):
        entry: dict[str, Any] = {"port_idx": row.get("port_idx"), "name": row.get("name")}
        entry.update({k: v for k, v in row.items() if k in _PORT_STP_KEYS or k.startswith("stp_")})
        ports_out.append(entry)
    return {
        **meta,
        "_device": device_id,
        "_source": "/stat/device",
        "_stp": device_stp,
        "_ports": ports_out,
        "_device_record": device,
    }
