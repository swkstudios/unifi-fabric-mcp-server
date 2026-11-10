"""Statistics tools — read-only site/device/client stats via Classic REST stat endpoints."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastmcp import FastMCP

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
from ...shared_shapes._history_common import (
    epoch_warnings,
    require_epoch_seconds,
    seconds_to_millis,
    translate_host_not_found,
    with_warnings,
)
from ...shared_shapes._keys import with_context
from ...tool_annotations import READ_ONLY
from ..clients.clients import resolve_list_source, v2_flag_params

_CLASSIC_STAT_BASE = "/v1/connector/consoles/{host_id}/proxy/network/api/s/{site_slug}/stat"
_MODERN_STATS_BASE = "/v1/connector/consoles/{host_id}/proxy/network/v2/api/stats"

# /stat/report path is "{interval}.{scope}", e.g. "hourly.ap". Every interval and scope
# the controller accepts, from live read-only probes of each candidate on Network 11.0.81:
# each value here answered 200 rc "ok" in every interval x scope pair; every other candidate was
# refused (an unknown interval with HTTP 400 api.err.InvalidArgs, an unknown scope with an
# HTTP 500 HTML page), so it is rejected here with this full list instead.
REPORT_INTERVALS = ("minute", "5minutes", "hourly", "daily", "monthly", "archive")
REPORT_SCOPES = ("site", "ap", "user", "gw", "sw", "device", "speedtest", "isp")


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


def health_summary(response: Any) -> dict[str, Any] | None:
    """A compact digest of a Classic ``/stat/health`` body, or ``None`` when it has none.

    ``{subsystems: {subsystem: status}, notOk: [subsystem...], allOk}`` from the ``data[]``
    records that carry a string ``subsystem`` (first record wins for a repeated name);
    ``status`` is copied verbatim (``None`` when a record has none) and ``notOk`` lists, in
    upstream order, every subsystem whose status is not exactly ``"ok"``. It is derived
    from the body only: the body itself is never changed.
    """
    data = response.get("data") if isinstance(response, dict) else None
    if not isinstance(data, list):
        return None
    statuses: dict[str, Any] = {}
    for record in data:
        if isinstance(record, dict) and isinstance(record.get("subsystem"), str):
            statuses.setdefault(record["subsystem"], record.get("status"))
    if not statuses:
        return None
    not_ok = [name for name, status in statuses.items() if status != "ok"]
    return {"subsystems": statuses, "notOk": not_ok, "allOk": not not_ok}


def with_health_summary(response: Any) -> Any:
    """``response`` plus the additive ``_healthSummary`` digest (unchanged when it has none)."""
    summary = health_summary(response)
    if summary is None or not isinstance(response, dict):
        return response
    return with_context(response, {"_healthSummary": summary})


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


#: The session classes of Classic ``stat/session`` ``type``, as UniFi documents them.
SESSION_TYPES = ("all", "user", "guest", "voucher")


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


#: ``list_known_clients`` sources: Classic ``/stat/alluser`` (default) and the controller's
#: v2 client history (Network 11.0.81 web UI, GET
#: /proxy/network/v2/api/site/{site}/clients/history).
KNOWN_CLIENTS_SOURCES = ("classic", "v2")


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


# Device-level thermal/power summary keys surfaced by the device view of
# get_device_port_state. Values are copied verbatim under their upstream names.
_DEVICE_THERMAL_POWER_KEYS = (
    "general_temperature",
    "fan_level",
    "overheating",
    "total_used_power",
    "total_max_power",
)

# Device- and port-level STP keys surfaced by get_device_stp_state. Any additional ``stp_*``
# key present upstream is also carried through, so these are a floor, not a whitelist that
# could silently drop a future field.
_DEVICE_STP_KEYS = ("stp_version", "stp_priority", "root_switch", "root")
_PORT_STP_KEYS = ("stp_state", "stp_role", "stp_pathcost", "stp_path_cost")


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


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register all statistics MCP tools."""

    @mcp.tool(annotations=READ_ONLY)
    async def list_controller_stat_schemas(host: str) -> Any:
        """List schemas supported by a controller's Network 11.x statistics engine.

        GET /v2/api/stats/schemas through the selected console. Each upstream schema can
        describe its name, keys, values, and nested groups. Returns the upstream body verbatim;
        FastMCP wraps an array in result for MCP clients.
        Network versions without the modern statistics engine may return an upstream 404.

        Required argument: host (see the parameter description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
        """
        client, registry = deps_fn()
        return await _list_controller_stat_schemas(client, registry, host)

    @mcp.tool(annotations=READ_ONLY)
    async def get_site_statistics(
        host: str,
        site: str,
    ) -> Any:
        """Get site health statistics: latency, throughput, and client counts per subsystem.

        Returns the Classic REST /stat/health envelope {meta: {rc}, data: [subsystem health…]}
        verbatim, plus an additive _healthSummary {subsystems: {subsystem: status}, notOk:
        [subsystem…], allOk} derived from data[] (omitted when data has no subsystem records).

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await _get_site_statistics(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def get_system_info(
        host: str,
        site: str,
    ) -> Any:
        """Get controller/console system info: version, uptime, and memory.

        Returns the Classic REST /stat/sysinfo envelope {meta: {rc}, data: [system info…]}
        verbatim.

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await _get_system_info(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def list_active_clients_stats(
        host: str,
        site: str,
    ) -> Any:
        """List detailed per-client statistics: traffic, signal strength, and experience score.

        Returns the Classic REST /stat/sta envelope {meta: {rc}, data: [client stats…]}
        verbatim.

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await _list_active_clients_stats(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def list_device_stats(
        host: str,
        site: str,
    ) -> Any:
        """List per-device statistics: CPU load, memory, uptime, and port throughput.

        Returns the Classic REST /stat/device envelope {meta: {rc}, data: [device stats…]}
        verbatim.

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await _list_device_stats(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def get_client_link_diagnostics(
        host: str,
        site: str,
        client_id: str | None = None,
        client_ids: list[str] | None = None,
    ) -> Any:
        """Get first-class per-client link/policy diagnostics for one or more clients.

        Read-only and Fabric-only: reuses the same Classic REST
        /v1/connector/consoles/{host_id}/proxy/network/api/s/{site_slug}/stat/sta request as
        list_active_clients_stats, then selects the requested client(s) from that payload in
        memory. Surfaces link quality (rssi, signal, noise, channel, radio_name),
        rx_rate/tx_rate and retry counters, satisfaction_reason, network/VLAN identity, QoS,
        fixed-IP, and virtual-network override fields when upstream provides them — the
        matching record is returned unchanged, so unknown/future fields survive.

        Returns: the /stat/sta envelope {meta: {rc}, data: [client…]} with data narrowed to the
        selected client(s), in the requested order (one entry for client_id).

        `client_id`: a single client selector — the client's MAC address (case- and
          separator-insensitive) or its classic /stat/sta _id. The Integration API client id
          from list_clients data[].id does not match. Provide EITHER client_id OR client_ids,
          not both.
        `client_ids`: an explicit list of client selectors (any length) for multi-client
          selection, from one /stat/sta read. A selector that matches no client fails listing
          every valid client (name, mac, _id) rather than being silently skipped.

        Example call (get_client_link_diagnostics):
            {"host": "my-console", "site": "Default", "client_id": "aa:bb:cc:dd:ee:ff"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            client_id: Single client MAC address or classic /stat/sta _id. Pass this OR
                client_ids, not both. The MAC is matched case- and separator-insensitively:
                macAddress from list_clients, or mac from list_active_clients_stats. The _id is
                the _id from list_active_clients_stats. The Integration API client id
                (list_clients data[].id, as used by get_client) is a different identifier and
                does not match.
            client_ids: Client selectors (any number), each a MAC address or classic /stat/sta
                _id (same sources as client_id). Pass this OR client_id, not both. An empty
                list applies no filter: the whole /stat/sta envelope is returned verbatim (with
                client_id also given, client_id selects).
                Shape: string[]
        """
        client, registry = deps_fn()
        return await _get_client_link_diagnostics(
            client, registry, host, site, client_id, client_ids
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_device_port_state(
        host: str,
        site: str,
        device_id: str,
        port_idx: int | None = None,
    ) -> Any:
        """Get switch port health, PoE, optics, and LLDP telemetry for a device.

        Returns, for the device view, an object with the keys _device, _port_idx (null),
        _source, _thermal_power and _device_record, plus port_table and lldp_table only when the
        selected record has them and meta only when the upstream envelope has it; with port_idx,
        _device, _port_idx, _source and _port, plus meta only when the envelope has it. An
        absent table or meta is left out, never returned as null. meta, port_table, lldp_table
        and the _device_record / _port rows are upstream values verbatim; _device / _port_idx
        echo the arguments, _source names the read route (/stat/device) and _thermal_power is a
        summary of the record's thermal and power fields (only those it has; {} when none).

        Read-only and Fabric-only: reuses the same Classic REST
        /v1/connector/consoles/{host_id}/proxy/network/api/s/{site_slug}/stat/device request
        as list_device_stats (one call, no new route), then projects the selected device's
        port telemetry from that payload. Upstream operational fields are preserved
        verbatim — link state/speed/duplex, rx/tx byte/packet/error/drop counters, PoE state
        and draw (poe_enable/poe_good/poe_power/poe_voltage/poe_current/poe_class/poe_mode),
        SFP/optics fields where present, and port config identity — nothing is renamed or
        dropped.

        `port_idx`: optional port_table[].port_idx (ports count from 1; any non-negative
          value, 0 included, is matched as given). Omit it for the device view
          (port_table and lldp_table verbatim when the record has them, a thermal/power
          summary, and the complete selected /stat/device record verbatim under
          _device_record); set it to return that single port_table row verbatim (under _port).
          An unknown port_idx fails listing the valid port_idx values.
          Both views carry the upstream envelope's meta verbatim when it has one; an unknown
          device fails listing every valid device (name, mac, _id).

        Example call (get_device_port_state):
            {"host": "my-console", "site": "Default", "device_id": "aa:bb:cc:dd:ee:ff"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            device_id: Device MAC address or classic /stat/device _id. The MAC is matched case- and
                separator-insensitively: macAddress from list_site_devices, mac from list_devices
                or list_device_stats. The _id is the _id from list_device_stats. The Integration
                API device id (list_site_devices data[].id, as used by get_device) is a different
                identifier and does not match.
            port_idx: Optional port_table[].port_idx (switch ports count from 1; any non-negative
                value, 0 included, is matched as given); omit for the whole device view.
        """
        client, registry = deps_fn()
        return await _get_device_port_state(client, registry, host, site, device_id, port_idx)

    @mcp.tool(annotations=READ_ONLY)
    async def get_device_stp_state(
        host: str,
        site: str,
        device_id: str,
    ) -> Any:
        """Get per-device STP/RSTP state and per-port STP role/state/path-cost.

        The result's top-level keys are {meta, _device, _source, _stp, _ports, _device_record}:
        _device echoes the device_id argument and _source names the read route (/stat/device).

        Read-only and Fabric-only: reads the same Classic REST
        /v1/connector/consoles/{host_id}/proxy/network/api/s/{site_slug}/stat/device payload
        as list_device_stats and projects the selected device's STP fields. Returns the
        device-level stp_version, stp_priority, root_switch/root (and any other stp_* field
        present) plus per-port STP role/state/path-cost where upstream provides them, all
        verbatim (under _stp and _ports), the complete selected /stat/device record verbatim
        under _device_record, and
        the upstream envelope's meta verbatim. An unknown device fails listing every valid
        device (name, mac, _id). This tool is read-only: no write is performed.

        Example call (get_device_stp_state):
            {"host": "my-console", "site": "Default", "device_id": "aa:bb:cc:dd:ee:ff"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            device_id: Device MAC address or classic /stat/device _id. The MAC is matched case- and
                separator-insensitively: macAddress from list_site_devices, mac from list_devices
                or list_device_stats. The _id is the _id from list_device_stats. The Integration
                API device id (list_site_devices data[].id, as used by get_device) is a different
                identifier and does not match.
        """
        client, registry = deps_fn()
        return await _get_device_stp_state(client, registry, host, site, device_id)

    @mcp.tool(annotations=READ_ONLY)
    async def list_client_sessions(
        host: str,
        site: str,
        start: int,
        end: int,
        session_type: str = "all",
    ) -> Any:
        """List historical client connection sessions from the Classic REST /stat/session endpoint.

        This is the highest-value history tool: retention is ~90 days, so it covers
        far more than the currently-connected client list.

        Each session includes mac, is_wired, assoc_time (session start, epoch seconds),
        duration (seconds), ap_mac, rx_bytes, tx_bytes, satisfaction, hostname, ip, _id, and
        roaming_sessions[]. Two things that surprise callers:
        - There is NO explicit disconnect timestamp — session end is assoc_time + duration.
        - Radio band lives ONLY inside roaming_sessions[] (radio_band: na/ng/6e), never at the
          top level. Wired sessions have ap_mac=null and carry sw_mac/sw_port instead.

        Returns the Classic REST envelope {meta: {rc}, data: [session…]} verbatim, including
        identifiers (MAC/IP/hostname).

        Required arguments: host, site, start, end (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            start: epoch SECONDS (UTC). This endpoint uses seconds natively — passing milliseconds
                returns HTTP 200 with an EMPTY array and no error. A negative or
                millisecond-magnitude value (>= 1e11) is sent as given and the result carries a
                _warnings entry saying so.
            end: epoch SECONDS (UTC). This endpoint uses seconds natively — passing milliseconds
                returns HTTP 200 with an EMPTY array and no error. A negative or
                millisecond-magnitude value (>= 1e11) is sent as given and the result carries a
                _warnings entry saying so.
            session_type: session class filter. The values that actually narrow the result are "all"
                (default — the full unfiltered set), "user" (regular clients), and "guest"
                (guest-network clients). Valid values: "all", "user", "guest", "voucher"; any
                other value fails before any request, listing them (the endpoint itself ignores an
                unknown value and returns the full "all" set, so a typo would otherwise yield
                everything). (UniFi documents "voucher" as a fourth class; on tested firmware it
                returned the full set, so prefer "user"/"guest" for real narrowing.)
        """
        client, registry = deps_fn()
        return await _list_client_sessions(client, registry, host, site, start, end, session_type)

    @mcp.tool(annotations=READ_ONLY)
    async def get_historical_stats(
        host: str,
        site: str,
        interval: str,
        scope: str,
        start: int,
        end: int,
        attrs: list[str] | None = None,
    ) -> Any:
        """Get bucketed historical statistics from the Classic REST /stat/report endpoint.

        Output "time" is epoch milliseconds. Note: rx_bytes/tx_bytes come back as JSON
        floats in scientific notation (e.g. 5.27e9) — treat them as floats, not ints.

        Returns the Classic REST envelope {meta: {rc}, data: [bucket…]} verbatim.

        An empty data array means the controller has no report rows, not a malformed request:
        Network 11.x controllers (verified on 11.0.81) answer every /stat/report request —
        each interval and scope, with or without attrs/start/end — with
        {"meta": {"rc": "ok"}, "data": []}, while sibling stat routes such as /stat/session
        still return rows. On those releases the dashboard history is served by the v2
        aggregated dashboard; read it with fabric_connector_get, path
        "network/v2/api/site/{site}/aggregated-dashboard".

        Required arguments: host, site, interval, scope, start, end (see each parameter's
        description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            interval: one of "minute", "5minutes", "hourly", "daily", "monthly", "archive" (every
                interval the controller accepts; another value fails listing these).
            scope: one of "site", "ap", "user", "gw", "sw", "device", "speedtest", "isp" (every
                scope the controller accepts; another value fails listing these). The "ap" scope
                carries num_sta per AP per bucket.
            start: epoch SECONDS (UTC). Unlike /stat/session, this endpoint requires MILLISECONDS —
                the tool converts seconds to milliseconds internally, so callers always pass seconds
                for a consistent interface.
            end: epoch SECONDS (UTC). Unlike /stat/session, this endpoint requires MILLISECONDS —
                the tool converts seconds to milliseconds internally, so callers always pass seconds
                for a consistent interface.
            attrs: optional report metrics to aggregate, e.g. ["num_sta", "rx_bytes",
                "tx_bytes"]. Sent as the request's attrs exactly as given; when omitted no attrs
                key is sent and the controller decides which fields each bucket carries.
                Shape: string[]
        """
        client, registry = deps_fn()
        return await _get_historical_stats(
            client, registry, host, site, interval, scope, start, end, attrs
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_speedtest_results(
        host: str,
        site: str,
        start: int,
        end: int,
    ) -> Any:
        """List archived WAN speed-test results for a site and time window.

        Reads the private Classic REST POST /stat/report/archive.speedtest route. It
        requests download/upload throughput, latency, result time, interface name and WAN
        network group. Network 11 may keep its current history on a newer private v2 route;
        an empty archive is returned unchanged.

        Returns the controller's complete response body verbatim. No fields are filtered,
        masked, projected or truncated.

        Required arguments: host, site, start, end (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Network site name or UUID; resolved server-side. Get it from
                list_local_sites (name or id). Names like "Default" work.
            start: Inclusive window start as an integer epoch-seconds timestamp. The tool
                converts it to the route's required epoch milliseconds.
            end: Inclusive window end as an integer epoch-seconds timestamp. The tool
                converts it to the route's required epoch milliseconds.
        """
        client, registry = deps_fn()
        return await _list_speedtest_results(client, registry, host, site, start, end)

    @mcp.tool(annotations=READ_ONLY)
    async def list_known_clients(
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
        """List the full per-site client roster incl. offline history (Classic REST /stat/alluser).

        Unlike list_active_clients_stats (currently-connected only), this includes clients
        seen historically — typically far more entries. (Distinct from the fleet-wide
        list_all_clients aggregation tool, which spans every console.) This endpoint accepts GET.

        Each entry includes mac, first_seen, last_seen, disconnect_timestamp (all epoch
        seconds), is_wired, oui, last_ip, last_radio, hostname, and device-fingerprint fields.

        Returns the Classic REST envelope {meta: {rc}, data: [client…]} verbatim, including
        identifiers (MAC/IP/hostname/name). With source "v2" (or any of the v2
        arguments) the controller's v2 client history (GET
        network/v2/api/site/{site}/clients/history, the web UI's route) is returned verbatim
        instead; Classic stays the default because the v2 rows lack name, note, fixed_ip,
        network_id, local_dns_record, virtual_network_override_id and disconnect_timestamp.

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            source: Optional route: "classic" (default, /stat/alluser) or "v2". Every
                other argument below applies only to "v2" and selects it.
                Example: `v2`.
            within_hours: Optional v2 query withinHours: clients seen in the last N hours,
                sent as given. Example: `24`.
            only_blocked: Optional v2 query onlyBlocked: true lists blocked clients only.
                Example: `true`.
            only_non_blocked: Optional v2 query onlyNonBlocked: true lists non-blocked clients
                only. Example: `true`.
            include_matter_thread_clients: Optional v2 query includeMatterThreadClients: true
                also lists Matter/Thread clients. Example: `true`.
            include_traffic_usage: Optional v2 query includeTrafficUsage: true asks the
                controller to include traffic usage. Example: `true`.
            include_unifi_devices: Optional v2 query includeUnifiDevices: true asks the
                controller to include UniFi devices. Example: `false`.
        """
        client, registry = deps_fn()
        return await _list_known_clients(
            client,
            registry,
            host,
            site,
            source=source,
            within_hours=within_hours,
            only_blocked=only_blocked,
            only_non_blocked=only_non_blocked,
            include_matter_thread_clients=include_matter_thread_clients,
            include_traffic_usage=include_traffic_usage,
            include_unifi_devices=include_unifi_devices,
        )
