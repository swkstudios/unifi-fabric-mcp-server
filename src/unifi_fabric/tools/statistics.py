"""Statistics tools — read-only site/device/client stats via Classic REST stat endpoints."""

from __future__ import annotations

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
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_stat(host_id, site_slug, "/health"))
    return _extract_data(response)


async def _get_system_info(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_stat(host_id, site_slug, "/sysinfo"))
    return _extract_data(response)


async def _list_active_clients_stats(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_stat(host_id, site_slug, "/sta"))
    return _extract_data(response)


async def _list_device_stats(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    response = await client.get(_classic_stat(host_id, site_slug, "/device"))
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
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    body = {"type": session_type, "start": start_s, "end": end_s}
    try:
        response = await client.post(_classic_stat(host_id, site_slug, "/session"), json=body)
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
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    body = {
        "attrs": list(attrs) if attrs else list(_DEFAULT_REPORT_ATTRS),
        "start": start_ms,
        "end": end_ms,
    }
    try:
        response = await client.post(
            _classic_stat(host_id, site_slug, f"/report/{interval}.{scope}"), json=body
        )
    except UniFiConnectionError as exc:
        raise translate_host_not_found(exc, host) from exc
    return _extract_data(response)


async def _list_known_clients(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """Fetch the full client roster (including offline history) from Classic REST /stat/alluser."""
    host_id = await registry.resolve_host_id(host)
    site_slug = await registry.resolve_site_slug(site, host_id)
    try:
        response = await client.get(_classic_stat(host_id, site_slug, "/alluser"))
    except UniFiConnectionError as exc:
        raise translate_host_not_found(exc, host) from exc
    return _extract_data(response)


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
