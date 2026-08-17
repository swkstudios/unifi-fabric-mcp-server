"""Statistics tools — read-only site/device/client stats via Classic REST stat endpoints."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from fastmcp import FastMCP

from ..client import UniFiClient, UniFiConnectionError
from ..registry import Registry
from ._history_common import (
    require_epoch_seconds,
    seconds_to_millis,
    translate_host_not_found,
)

_CLASSIC_STAT_BASE = "/v1/connector/consoles/{host_id}/proxy/network/api/s/{site_slug}/stat"

# /stat/report path is "{interval}.{scope}", e.g. "hourly.ap".
_REPORT_INTERVALS = frozenset({"5minutes", "hourly", "daily"})
_REPORT_SCOPES = frozenset({"ap", "user", "site"})
_DEFAULT_REPORT_ATTRS = ("num_sta", "rx_bytes", "tx_bytes")


def _classic_stat(host_id: str, site_slug: str, path: str) -> str:
    return _CLASSIC_STAT_BASE.format(host_id=host_id, site_slug=site_slug) + path


def _extract_data(response: Any) -> Any:
    """Extract the 'data' list from a Classic REST stat response."""
    if isinstance(response, dict) and "data" in response:
        return response["data"]
    return response


async def _get_site_statistics(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(_classic_stat(host_id, site_slug, "/health"), key=key)
    return _extract_data(response)


async def _get_system_info(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(_classic_stat(host_id, site_slug, "/sysinfo"), key=key)
    return _extract_data(response)


async def _list_active_clients_stats(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(_classic_stat(host_id, site_slug, "/sta"), key=key)
    return _extract_data(response)


async def _list_device_stats(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(_classic_stat(host_id, site_slug, "/device"), key=key)
    return _extract_data(response)


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
    """
    start_s = require_epoch_seconds(start, "start")
    end_s = require_epoch_seconds(end, "end")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    body = {"type": session_type, "start": start_s, "end": end_s}
    try:
        response = await client.post(
            _classic_stat(host_id, site_slug, "/session"), key=key, json=body
        )
    except UniFiConnectionError as exc:
        raise translate_host_not_found(exc, host) from exc
    return _extract_data(response)


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
    """
    if interval not in _REPORT_INTERVALS:
        raise ValueError(
            f"Invalid interval {interval!r}: expected one of {sorted(_REPORT_INTERVALS)}"
        )
    if scope not in _REPORT_SCOPES:
        raise ValueError(f"Invalid scope {scope!r}: expected one of {sorted(_REPORT_SCOPES)}")
    start_ms = seconds_to_millis(require_epoch_seconds(start, "start"))
    end_ms = seconds_to_millis(require_epoch_seconds(end, "end"))
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    body = {
        "attrs": list(attrs) if attrs else list(_DEFAULT_REPORT_ATTRS),
        "start": start_ms,
        "end": end_ms,
    }
    try:
        response = await client.post(
            _classic_stat(host_id, site_slug, f"/report/{interval}.{scope}"), key=key, json=body
        )
    except UniFiConnectionError as exc:
        raise translate_host_not_found(exc, host) from exc
    return _extract_data(response)


async def _list_known_clients(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """Fetch the full client roster (including offline history) from Classic REST /stat/alluser."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    try:
        response = await client.get(_classic_stat(host_id, site_slug, "/alluser"), key=key)
    except UniFiConnectionError as exc:
        raise translate_host_not_found(exc, host) from exc
    return _extract_data(response)


# --- Focused convenience reads over /stat/sta and /stat/device (issues #183/#184/#188) ---
#
# These helpers add NO new Fabric route: each reuses the exact Classic REST request the
# corresponding list_* tool already issues (/stat/sta for clients, /stat/device for
# devices), then selects and/or projects the already-fetched payload in memory. The
# selector is compared against in-memory record fields only and is never interpolated into
# a URL path, so it needs no path-safety validation. Upstream operational fields are
# preserved verbatim; the list_* tools remain the faithful raw pass-throughs.

_MAC_SEP_RE = re.compile(r"[:\-.]")

# Bounded, explicit multi-select ceiling for get_client_link_diagnostics — keeps the helper
# from being used to scan/fan out an unbounded set of identifiers.
_MAX_MULTI_CLIENT_SELECT = 64

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
    """Lowercase a MAC and strip ':' '-' '.' separators for equality comparison."""
    return _MAC_SEP_RE.sub("", value).lower()


def _as_record_list(data: Any, source_label: str) -> list[dict[str, Any]]:
    """Coerce an extracted /stat/* payload into a list of record dicts, or fail clearly."""
    if not isinstance(data, list):
        raise ValueError(
            f"Unexpected {source_label} response shape: expected a list of records, "
            f"got {type(data).__name__}."
        )
    return [record for record in data if isinstance(record, dict)]


def _record_matches(record: dict[str, Any], selector: str, norm_selector: str) -> bool:
    """True if record matches selector by _id/id (exact) or mac (separator-insensitive)."""
    for id_key in ("_id", "id"):
        value = record.get(id_key)
        if isinstance(value, str) and value == selector:
            return True
    mac = record.get("mac")
    if isinstance(mac, str) and norm_selector and _normalize_mac(mac) == norm_selector:
        return True
    return False


def _select_one_record(
    records: list[dict[str, Any]], selector: str, kind: str, source_label: str
) -> dict[str, Any]:
    """Return the single record matching selector, or raise a clear not-found error."""
    if not selector:
        raise ValueError(f"{kind} selector must not be empty")
    norm = _normalize_mac(selector)
    for record in records:
        if _record_matches(record, selector, norm):
            return record
    raise ValueError(
        f"No {kind} matching {selector!r} in {source_label} "
        f"(matched against _id, id, and mac); verify the identifier with the list tool."
    )


def _port_rows(device: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the device's port_table as a list of row dicts (empty if absent/malformed)."""
    port_table = device.get("port_table")
    if not isinstance(port_table, list):
        return []
    return [row for row in port_table if isinstance(row, dict)]


async def _get_client_link_diagnostics(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    client_id: str | None = None,
    client_ids: list[str] | None = None,
) -> Any:
    """Select per-client link/policy diagnostics from the /stat/sta payload.

    Exactly one of ``client_id`` (single) or ``client_ids`` (bounded explicit list) must be
    supplied. Single selection returns the matching upstream record unchanged; the multi
    form returns a list of unchanged records in the requested order. Reuses the same
    /stat/sta request as _list_active_clients_stats — no new route.
    """
    if (client_id is None) == (client_ids is None):
        raise ValueError("Provide exactly one of client_id (single) or client_ids (bounded list).")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(_classic_stat(host_id, site_slug, "/sta"), key=key)
    records = _as_record_list(_extract_data(response), "/stat/sta")

    if client_id is not None:
        return _select_one_record(records, client_id, "client", "/stat/sta")

    if not client_ids:
        raise ValueError("client_ids must be a non-empty list of client IDs/MACs.")
    if len(client_ids) > _MAX_MULTI_CLIENT_SELECT:
        raise ValueError(
            f"client_ids has {len(client_ids)} entries; the bounded maximum is "
            f"{_MAX_MULTI_CLIENT_SELECT}. Select explicitly rather than scanning."
        )
    selected: list[dict[str, Any]] = []
    missing: list[str] = []
    for cid in client_ids:
        norm = _normalize_mac(cid or "")
        match = next((r for r in records if _record_matches(r, cid, norm)), None)
        if match is None:
            missing.append(cid)
        else:
            selected.append(match)
    if missing:
        raise ValueError(
            f"No /stat/sta client matched: {missing!r} "
            "(matched against _id, id, and mac); verify the identifiers."
        )
    return selected


async def _get_device_port_state(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device_id: str,
    port_idx: int | None = None,
) -> Any:
    """Project switch port_table / lldp_table / thermal telemetry from /stat/device.

    Reuses the same /stat/device request as _list_device_stats (one Fabric call, no new
    route). With ``port_idx`` omitted returns the device view (verbatim port_table and
    lldp_table plus a thermal/power summary); with ``port_idx`` set returns that single
    port_table row verbatim. Envelope keys (device, port_idx, source) are additive and
    never rename or drop upstream fields.
    """
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(_classic_stat(host_id, site_slug, "/device"), key=key)
    records = _as_record_list(_extract_data(response), "/stat/device")
    device = _select_one_record(records, device_id, "device", "/stat/device")
    ports = _port_rows(device)

    if port_idx is not None:
        for row in ports:
            if row.get("port_idx") == port_idx:
                return {
                    "device": device_id,
                    "port_idx": port_idx,
                    "source": "/stat/device",
                    "port": row,
                }
        raise ValueError(
            f"Device {device_id!r} has no port_idx={port_idx} in its /stat/device "
            "port_table; call the device view (omit port_idx) to list available ports."
        )

    thermal_power = {k: device[k] for k in _DEVICE_THERMAL_POWER_KEYS if k in device}
    lldp_table = device.get("lldp_table")
    return {
        "device": device_id,
        "port_idx": None,
        "source": "/stat/device",
        "port_table": ports,
        "lldp_table": lldp_table if isinstance(lldp_table, list) else [],
        "thermal_power": thermal_power,
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
    them, all verbatim. No write is performed (STP-priority write support is investigated in
    the PR description only; STP-priority writes are out of scope for this tool).
    """
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    response = await client.get(_classic_stat(host_id, site_slug, "/device"), key=key)
    records = _as_record_list(_extract_data(response), "/stat/device")
    device = _select_one_record(records, device_id, "device", "/stat/device")

    device_stp: dict[str, Any] = {
        k: v for k, v in device.items() if k in _DEVICE_STP_KEYS or k.startswith("stp_")
    }
    ports_out: list[dict[str, Any]] = []
    for row in _port_rows(device):
        entry: dict[str, Any] = {"port_idx": row.get("port_idx"), "name": row.get("name")}
        entry.update({k: v for k, v in row.items() if k in _PORT_STP_KEYS or k.startswith("stp_")})
        ports_out.append(entry)
    return {
        "device": device_id,
        "source": "/stat/device",
        "stp": device_stp,
        "ports": ports_out,
    }


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register all statistics MCP tools."""

    @mcp.tool()
    async def get_site_statistics(
        host: str,
        site: str,
    ) -> Any:
        """Get site health statistics: latency, throughput, and client counts per subsystem.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        Returns a list of subsystem health objects from the Classic REST /stat/health endpoint.
        """
        client, registry = deps_fn()
        return await _get_site_statistics(client, registry, host, site)

    @mcp.tool()
    async def get_system_info(
        host: str,
        site: str,
    ) -> Any:
        """Get controller/console system info: version, uptime, and memory.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        Returns system info objects from the Classic REST /stat/sysinfo endpoint.
        """
        client, registry = deps_fn()
        return await _get_system_info(client, registry, host, site)

    @mcp.tool()
    async def list_active_clients_stats(
        host: str,
        site: str,
    ) -> Any:
        """List detailed per-client statistics: traffic, signal strength, and experience score.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        Returns a list of client stat objects from the Classic REST /stat/sta endpoint.
        """
        client, registry = deps_fn()
        return await _list_active_clients_stats(client, registry, host, site)

    @mcp.tool()
    async def list_device_stats(
        host: str,
        site: str,
    ) -> Any:
        """List per-device statistics: CPU load, memory, uptime, and port throughput.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        Returns a list of device stat objects from the Classic REST /stat/device endpoint.
        """
        client, registry = deps_fn()
        return await _list_device_stats(client, registry, host, site)

    @mcp.tool()
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

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        client_id: a single client selector — its /stat/sta _id, id, or mac (case- and
          separator-insensitive). Provide EITHER client_id OR client_ids, not both.
        client_ids: a bounded, explicit list of client selectors (max 64) for multi-client
          selection; returns the matching records as a list. A selector that matches no
          client fails clearly rather than being silently skipped.
        """
        client, registry = deps_fn()
        return await _get_client_link_diagnostics(
            client, registry, host, site, client_id, client_ids
        )

    @mcp.tool()
    async def get_device_port_state(
        host: str,
        site: str,
        device_id: str,
        port_idx: int | None = None,
    ) -> Any:
        """Get switch port health, PoE, optics, and LLDP telemetry for a device.

        Read-only and Fabric-only: reuses the same Classic REST
        /v1/connector/consoles/{host_id}/proxy/network/api/s/{site_slug}/stat/device request
        as list_device_stats (one call, no new route), then projects the selected device's
        port telemetry from that payload. Upstream operational fields are preserved
        verbatim — link state/speed/duplex, rx/tx byte/packet/error/drop counters, PoE state
        and draw (poe_enable/poe_good/poe_power/poe_voltage/poe_current/poe_class/poe_mode),
        SFP/optics fields where present, and port config identity — nothing is renamed or
        dropped.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        device_id: device selector — its /stat/device _id, id, or mac (case- and
          separator-insensitive).
        port_idx: optional 1-based port number. Omit it for the device view (verbatim
          port_table and lldp_table plus a thermal/power summary); set it to return that
          single port_table row verbatim. An unknown port_idx fails clearly.
        """
        client, registry = deps_fn()
        return await _get_device_port_state(client, registry, host, site, device_id, port_idx)

    @mcp.tool()
    async def get_device_stp_state(
        host: str,
        site: str,
        device_id: str,
    ) -> Any:
        """Get per-device STP/RSTP state and per-port STP role/state/path-cost.

        Read-only and Fabric-only: reads the same Classic REST
        /v1/connector/consoles/{host_id}/proxy/network/api/s/{site_slug}/stat/device payload
        as list_device_stats and projects the selected device's STP fields. Returns the
        device-level stp_version, stp_priority, root_switch/root (and any other stp_* field
        present) plus per-port STP role/state/path-cost where upstream provides them, all
        verbatim. This tool is read-only: STP-priority write support is documented in the PR
        description only and no write is performed here.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        device_id: device selector — its /stat/device _id, id, or mac (case- and
          separator-insensitive).
        """
        client, registry = deps_fn()
        return await _get_device_stp_state(client, registry, host, site, device_id)

    @mcp.tool()
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

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        start/end: epoch SECONDS (UTC). This endpoint uses seconds natively — passing
          milliseconds returns HTTP 200 with an EMPTY array and no error, so seconds are
          enforced (millisecond-magnitude values are rejected).
        session_type: session class filter. The values that actually narrow the result
          are "all" (default — the full unfiltered set), "user" (regular clients), and
          "guest" (guest-network clients). WARNING: an unrecognised value is NOT rejected
          and does NOT return an empty array — the endpoint silently ignores it and
          returns the full "all" set, so a typo yields everything rather than a visible
          error or "no data". (UniFi documents "voucher" as a fourth class; on tested
          firmware it returned the full set, so prefer "user"/"guest" for real narrowing.)

        Each session includes mac, is_wired, assoc_time (session start, epoch seconds),
        duration (seconds), ap_mac, rx_bytes, tx_bytes, satisfaction, hostname, ip, _id, and
        roaming_sessions[]. Two things that surprise callers:
        - There is NO explicit disconnect timestamp — session end is assoc_time + duration.
        - Radio band lives ONLY inside roaming_sessions[] (radio_band: na/ng/6e), never at the
          top level. Wired sessions have ap_mac=null and carry sw_mac/sw_port instead.

        The response is passed through verbatim, including identifiers (MAC/IP/hostname).
        """
        client, registry = deps_fn()
        return await _list_client_sessions(client, registry, host, site, start, end, session_type)

    @mcp.tool()
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

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        interval: one of "5minutes", "hourly", "daily".
        scope: one of "ap", "user", "site". The "ap" scope carries num_sta per AP per bucket.
        start/end: epoch SECONDS (UTC). Unlike /stat/session, this endpoint requires
          MILLISECONDS — the tool converts seconds to milliseconds internally, so callers
          always pass seconds for a consistent interface.
        attrs: metrics to aggregate; defaults to num_sta, rx_bytes, tx_bytes.

        Retention differs by interval: 5minutes ~1 day, hourly ~7 days, daily ~91 days.
        Output "time" is epoch milliseconds. Note: rx_bytes/tx_bytes come back as JSON
        floats in scientific notation (e.g. 5.27e9) — treat them as floats, not ints.

        The response is passed through verbatim.
        """
        client, registry = deps_fn()
        return await _get_historical_stats(
            client, registry, host, site, interval, scope, start, end, attrs
        )

    @mcp.tool()
    async def list_known_clients(
        host: str,
        site: str,
    ) -> Any:
        """List the full per-site client roster incl. offline history (Classic REST /stat/alluser).

        Unlike list_active_clients_stats (currently-connected only), this includes clients
        seen historically — typically far more entries. (Distinct from the fleet-wide
        list_all_clients aggregation tool, which spans every console.) This endpoint accepts GET.

        host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
        Each entry includes mac, first_seen, last_seen, disconnect_timestamp (all epoch
        seconds), is_wired, oui, last_ip, last_radio, hostname, and device-fingerprint fields.

        The response is passed through verbatim, including identifiers (MAC/IP/hostname/name).
        """
        client, registry = deps_fn()
        return await _list_known_clients(client, registry, host, site)
