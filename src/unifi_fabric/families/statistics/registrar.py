"""The statistics family registrar: its tool wrappers, in registration order (the family-owned
layout).

The loader map (``catalog/loaders.py``) runs each ``register`` / ``register_<n>`` below at its place
in the ``tools/list`` order, with the ``origin`` its tools are indexed under. The wrappers are the
tools' public surface (names, annotations, docstrings, signatures), moved by
``scripts/move_family.py``; each calls its handler through the handler's module, so a patched
handler still applies (``handlers.py`` indexes them).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated, Any

from fastmcp import FastMCP
from pydantic import Field

from ...tool_annotations import READ_ONLY
from . import event_streams, statistics, system_log
from .schemas import Product, SystemLogClass


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
        return await statistics._list_controller_stat_schemas(client, registry, host)

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
        return await statistics._get_site_statistics(client, registry, host, site)

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
        return await statistics._get_system_info(client, registry, host, site)

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
        return await statistics._list_active_clients_stats(client, registry, host, site)

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
        return await statistics._list_device_stats(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def get_client_link_diagnostics(
        host: str,
        site: str,
        client_id: str | None = None,
        client_ids: list[str] | None = None,
    ) -> Any:
        """Get per-client link/policy diagnostics for one or more clients. Read-only and Fabric-only: reads the Classic /stat/sta payload (as list_active_clients_stats) and selects the requested client(s) in memory.

        Returns the /stat/sta envelope {meta: {rc}, data: [client...]} with data narrowed to the selected client(s) in the requested order; each record is unchanged (link quality, rx/tx rates, retries, satisfaction_reason, network/VLAN, QoS, fixed-IP and virtual-network override fields when upstream has them).

        The client_id is one client's MAC (case- and separator-insensitive) or classic /stat/sta _id; the Integration API id from list_clients does not match. Use client_ids for a list of selectors. Give EITHER, not both. A selector matching no client fails listing every valid client (name, mac, _id).

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
        return await statistics._get_client_link_diagnostics(
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

        Returns, for the device view, an object with the keys _device, _port_idx (null), _source, _thermal_power and _device_record, plus port_table and lldp_table only when the selected record has them and meta only when the upstream envelope has it; with port_idx, _device, _port_idx, _source and _port, plus meta only when the envelope has it. An absent table or meta is left out, never returned as null. meta, port_table, lldp_table and the _device_record / _port rows are upstream values verbatim; _device / _port_idx echo the arguments, _source names the read route (/stat/device) and _thermal_power is a summary of the record's thermal and power fields (only those it has; {} when none).

        Read-only and Fabric-only: reuses the same Classic REST /v1/connector/consoles/{host_id}/proxy/network/api/s/{site_slug}/stat/device request as list_device_stats (one call, no new route), then projects the selected device's port telemetry from that payload. Upstream operational fields are preserved verbatim — link state/speed/duplex, rx/tx byte/packet/error/drop counters, PoE state and draw (poe_enable/poe_good/poe_power/poe_voltage/poe_current/poe_class/poe_mode), SFP/optics fields where present, and port config identity — nothing is renamed or dropped.

        `port_idx`: optional port_table[].port_idx (ports count from 1; any non-negative value, 0 included, is matched as given). Omit it for the device view (port_table and lldp_table verbatim when the record has them, a thermal/power summary, and the complete selected /stat/device record verbatim under _device_record); set it to return that single port_table row verbatim (under _port). An unknown port_idx fails listing the valid port_idx values. Both views carry the upstream envelope's meta verbatim when it has one; an unknown device fails listing every valid device (name, mac, _id).

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
        return await statistics._get_device_port_state(
            client, registry, host, site, device_id, port_idx
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_device_stp_state(
        host: str,
        site: str,
        device_id: str,
    ) -> Any:
        """Get per-device STP/RSTP state and per-port STP role/state/path-cost. Read-only: reads the Classic /stat/device payload (as list_device_stats) and projects the selected device's STP fields.

        Returns {meta, _device, _source, _stp, _ports, _device_record}: _device echoes device_id, _source names the route (/stat/device), _stp holds stp_version, stp_priority, root_switch/root and any other stp_* field, _ports the per-port role/state/path-cost, all verbatim when upstream has them; _device_record is the whole record and meta the envelope's. An unknown device fails listing every valid device (name, mac, _id).

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
        return await statistics._get_device_stp_state(client, registry, host, site, device_id)

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
        return await statistics._list_client_sessions(
            client, registry, host, site, start, end, session_type
        )

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
        return await statistics._get_historical_stats(
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
        return await statistics._list_speedtest_results(client, registry, host, site, start, end)

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
        """List the full per-site client roster including offline history (Classic REST /stat/alluser). Unlike list_active_clients_stats (connected only) it includes clients seen historically, typically far more entries; not the fleet-wide list_all_clients aggregation. This endpoint accepts GET.

        Each entry has mac, first_seen, last_seen, disconnect_timestamp (epoch seconds), is_wired, oui, last_ip, last_radio, hostname and fingerprint fields. Returns the Classic envelope {meta: {rc}, data: [client...]} verbatim, including identifiers (MAC/IP/hostname/name). With source "v2" (or any v2 argument) the v2 client history (GET network/v2/api/site/{site}/clients/history) is returned verbatim instead; Classic is the default because v2 rows lack name, note, fixed_ip, network_id, local_dns_record, virtual_network_override_id and disconnect_timestamp.

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
        return await statistics._list_known_clients(
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


def register_2(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the system-log MCP tools."""

    @mcp.tool(annotations=READ_ONLY)
    async def get_system_log(
        host: str,
        site: str,
        log_class: SystemLogClass = "all",
        query_body: dict[str, Any] | None = None,
        page: int | None = None,
        page_size: int | None = None,
    ) -> Any:
        """Read Network system-log events and alerts.

        POST network/v2/api/site/{site}/system-log/{log_class} with the supplied query body (a read: the nine classes are on the read-POST allowlist). Classes: all, device-alert, client-alert, admin-activity, update-alert, threat-alert, next-ai-alert, vpn-alert, critical. Any other class is refused before any request. Class filter keys default to the kinds the controller UI sends (nextAiCategory, activity_keys, change_keys, systemLogDeviceTypes, clientType, guestAuthorizationMethod, threatTypes, triggerTypes); query_body can override them.

        A read: it stays available under UNIFI_WRITE_POLICY=deny and in dry-run policy, and discovery mode runs it through call_read_tool.

        Returns, by default, every page drained into {data: [entry, ...], total_element_count, incomplete?, incompleteReason?}. Entries are verbatim; the count is the first page's. Caps, repeated entries, early empty pages or short totals mark the result incomplete; an object with unprovable pagination raises (request an explicit page to inspect it). A scalar response is returned verbatim. With page alone, returns {data, page_number, total_element_count, total_page_count} verbatim; critical normally returns a bare array. page_size alone is window 0; resume with page=_nextPage and the same page_size. With page, the window (see page). _pageSize: requested, sent (each pageSize sent, in order), effective, returned. No _nextPage: nothing follows the window, or the call stopped incomplete. Each page is sent once; HTTP 429 stops the call (narrow or use page).

        Example call (get_system_log):
            {"host": "my-console", "site": "Default", "log_class": "client-alert",
             "query_body": {"timestampFrom": 1760140800000, "timestampTo": 1760227200000}}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            log_class: The log class (URL path segment), e.g. "all", "device-alert",
                "client-alert", "admin-activity", "update-alert", "threat-alert",
                "next-ai-alert", "vpn-alert", "critical". Default "all".
            query_body: Optional query body sent as given: a time window in epoch milliseconds
                (timestampFrom, timestampTo) or a class's own filter keys such as threatTypes. A
                pageNumber / pageSize in it is honoured like page / page_size (the arguments win
                when both are given).
                Example: `{"timestampFrom": 1760140800000, "timestampTo": 1760227200000}`.
                Free-form JSON object; no fixed body shape is published.
            page: Zero-based page. With page_size, returns exactly page_size records starting
                at record page * page_size, gathered across console pages whatever the console
                page size; resume with _nextPage and the same page_size. Without page_size, one
                request returns that console page verbatim. Example: `2`.
            page_size: Optional entry count (sent as pageSize): alone, window 0 (the first
                page_size entries, fewer only at the end); with page, the window size. Omit to
                drain all in batches of 1000. Example: `100`.
        """
        client, registry = deps_fn()
        return await system_log._read_system_log(
            client,
            registry,
            host,
            site,
            log_class,
            query_body,
            page=page,
            page_size=page_size,
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_network_events(
        host: str,
        site: str,
        start: int | None = None,
        end: int | None = None,
        view: str | None = None,
        vpn_user_id: str | None = None,
    ) -> Any:
        """List site network events from the system log, draining every page in controller order.

        Network 11.x keeps events in the system log (the Classic stat/event route answers HTTP 404 on Network 11.0.81). This reads class "all" of POST network/v2/api/site/{site}/system-log/all, with timestampFrom / timestampTo set from start / end when given. view reads another class the same way (live on Network 11.0.81: all, device-alert, client-alert, admin-activity, update-alert, threat-alert, next-ai-alert, vpn-alert, critical). vpn_user_id scopes the log to one VPN user instead: GET network/v2/api/site/{site}/system-log/vpn-user-connection?vpnUserId= (the web UI's route), returned verbatim. For a raw query use get_system_log.

        A read: it stays available under UNIFI_WRITE_POLICY=deny and in dry-run policy.

        Returns {data: [event, ...], total_element_count, incomplete?, incompleteReason?}: each event verbatim (key such as CLIENT_ROAMED_2 or THREAT_DETECTED_KNOWN_SOURCE_CLIENT, category, severity, timestamp in epoch ms, parameters, ...); total_element_count is the controller's count; incomplete / incompleteReason appear when the opt-in UNIFI_PAGINATE_MAX_PAGES cap, repeated entries, an early empty page, or a short declared total stopped the drain. Unprovable pagination metadata raises a clear error; use get_system_log with an explicit page to inspect it. _warnings flags a negative or millisecond-like start / end (still multiplied by 1000; _warnings includes sent_as). Without start / end the whole retained log is read (tens of thousands of entries on a busy site).

        Example call (list_network_events):
            {"host": "my-console", "site": "Default", "start": 1760140800, "end": 1760227200}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            start: Optional window start, epoch seconds (sent as timestampFrom in milliseconds).
                Example: `1760140800`.
            end: Optional window end, epoch seconds (sent as timestampTo in milliseconds).
                Example: `1760227200`.
            view: Optional system-log class to read instead of "all" (URL path segment), one of
                the nine classes, e.g. "device-alert" or "admin-activity". Default "all".
                Example: `device-alert`.
            vpn_user_id: Optional VPN user id: reads that user's VPN connection log (query
                vpnUserId, a GET) instead of a class; start, end and view do not apply.
                Example: `000000000000000000000107`.
        """
        client, registry = deps_fn()
        return await system_log._list_network_events(
            client, registry, host, site, start, end, view=view, vpn_user_id=vpn_user_id
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_ips_events(
        host: str,
        site: str,
        start: int | None = None,
        end: int | None = None,
        threat_types: list[str] | None = None,
    ) -> Any:
        """List intrusion prevention / detection (IPS/IDS) threat events, every page drained.

        Network 11.x reports IPS events in the system log's threat-alert class (the Classic stat/ips/event route answers HTTP 404 on Network 11.0.81). This reads POST network/v2/api/site/{site}/system-log/threat-alert (a read-allowlisted POST) with threatTypes (default ["HONEYPOT", "THREAT"], what the controller UI sends; without it the controller returns no entries) and timestampFrom / timestampTo from start / end when given.

        A read: it stays available under UNIFI_WRITE_POLICY=deny and in dry-run policy.

        Returns {data: [event, ...], total_element_count, incomplete?, incompleteReason?}: each event verbatim (key such as THREAT_DETECTED_KNOWN_SOURCE_CLIENT, category SECURITY, severity, timestamp in epoch ms, parameters with the signature, source and destination, ...); incomplete / incompleteReason appear when the opt-in UNIFI_PAGINATE_MAX_PAGES cap, repeated entries, an early empty page, or a short declared total stopped the drain. Unprovable pagination metadata raises a clear error; use get_system_log with an explicit page to inspect it. _warnings flags a negative or millisecond-like start / end (still multiplied by 1000). Without start / end the whole retained log is read.

        Example call (list_ips_events):
            {"host": "my-console", "site": "Default", "start": 1760140800}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            start: Optional window start, epoch seconds (sent as timestampFrom in milliseconds).
                Example: `1760140800`.
            end: Optional window end, epoch seconds (sent as timestampTo in milliseconds).
                Example: `1760227200`.
            threat_types: Optional threat kinds to include, e.g. ["THREAT"] or ["HONEYPOT"];
                default ["HONEYPOT", "THREAT"].
                Shape: string[]
        """
        client, registry = deps_fn()
        query = system_log._window(start, end)
        if threat_types is not None:
            query["threatTypes"] = threat_types
        result = await system_log._read_system_log(
            client, registry, host, site, "threat-alert", query
        )
        return system_log._epoch_hints(result, start, end)

    @mcp.tool(annotations=READ_ONLY)
    async def get_scoped_system_log(
        host: str,
        site: str,
        scope: str,
        identifier: str,
        query: dict[str, Any] | None = None,
    ) -> Any:
        """Read the Network system log for one device, client connection, admin-activity record or external id (a plain GET, no drain).

        GET network/v2/api/site/{site}/system-log/{scope}/{identifier}. Returns the upstream body verbatim (a list of events for device; non-objects use result). scope: "device" (identifier a device MAC; live 200 with events), "client-connection" (a client MAC; 200 but entry shape unproven), "admin-activity" (a record id) or "by-external-id" (an external id); the last two answered 404 for an id the probe console lacked, so positive responses are unobserved. Routes come from the Network 11.0.81 web app; no published schema describes the responses. For a whole class (all, device-alert, ...) use get_system_log or list_network_events. An unknown scope fails before any request listing the choices.

        Example call (get_scoped_system_log):
            {"host": "my-console", "site": "Default", "scope": "device",
             "identifier": "aa:bb:cc:dd:ee:ff"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            scope: Which log to read: "device", "client-connection", "admin-activity" or
                "by-external-id". Example: `device`.
            identifier: The id the scope names: a device MAC (device), a client MAC
                (client-connection), an admin-activity record id or an external id. Sent as one
                URL path segment. Example: `aa:bb:cc:dd:ee:ff`.
            query: Optional query-string parameters sent as given (the web app builds a dynamic
                query for the device and client-connection routes; its keys are not published).
                Free-form JSON object; omit for none. Example: `{}`.
        """
        client, registry = deps_fn()
        return await system_log._get_scoped_system_log(
            client, registry, host, site, scope, identifier, query
        )

    @mcp.tool(annotations=READ_ONLY)
    async def collect_network_incident_evidence(
        host: str,
        site: str,
        start: int,
        end: int,
        log_classes: list[str] | None = None,
    ) -> Any:
        """Collect normalized incident evidence from the Network system log for one window.

        Reads each system-log class (default "all") over [start, end) with POST network/v2/api/site/{site}/system-log/{class}, drains every page (Consequence: none, it only reads). It returns one document (schema_name "unifi-fabric-incident-evidence", schema_version 1) instead of native entries (see get_system_log); each record keeps the native id (provenance.record_id).

        The "all" POST is a read-allowlisted query, so this tool is a read: UNIFI_WRITE_POLICY=deny and family:network=deny do not hide it and dry-run policy does not intercept it. Any class other than "all" is refused before any request (use get_system_log).

        Every class failure (HTTP or transport error, unusable 2xx body) is recorded as that source's failure; a read has no unknown outcome.

        Returns {schema_name, schema_version, product: "network", status, causality: "not_assessed", ordering, scope, requested_window, collected_at, incomplete, incompleteReason?, _warnings?, sources, records}. status is complete, empty, partial or failed; one failing class makes it partial. incomplete is true exactly when a source's drain stopped early (incompleteReason names it). Each source has an outcome (complete, empty, partial, or a failure kind with http_status and the upstream message), pagination, counts, queried and observed windows, and retention "unknown". Records keep safe fields only (no message text), the event time and its status (in_window, out_of_window, missing, malformed, ambiguous_timezone) and identity (exact, ambiguous or missing; from MAC and IP only), sorted by event time, which claims no cause. A non-object row is only counted (counts.malformed); a wrong-typed safe field is listed in attributes.wrong_typed_fields.

        Example call (collect_network_incident_evidence):
            {"host": "my-console", "site": "Default", "start": 1760140800, "end": 1760144400,
             "log_classes": ["all"]}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            start: Window start, epoch seconds, inclusive; a negative or millisecond-size value is
                sent unchanged with a `_warnings` entry. Example: `1760140800`.
            end: Window end, epoch seconds, exclusive; must be after start (otherwise refused
                before any request). Example: `1760144400`.
            log_classes: Optional system-log classes, each read as its own source (URL path
                segment, sent as given). Only the read-allowlisted class "all" is accepted;
                any other class is refused before any request. Default ["all"]. Repeats are
                read once. Shape: string[]
        """
        client, registry = deps_fn()
        return await system_log._collect_network_incident_evidence(
            client, registry, host, site, start, end, log_classes
        )


def register_3(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the event-stream tools."""

    @mcp.tool(annotations=READ_ONLY)
    async def get_event_stream_status(
        product: Annotated[
            Product | None,
            Field(
                description=(
                    "Optional product: 'network' or 'protect'. Omit for both. Example: \"protect\"."
                )
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Report whether live Network and Protect event streams are available, and listener health. Reads this server's own state only; no console request. Both products publish live events only over WebSocket, which the Fabric connector (a request/response relay) does not carry, so both report state "unsupported", supported false, and use_instead names polling tools (list_network_events, get_system_log, list_ips_events; list_protect_events, collect_protect_events, collect_protect_device_changes). Nothing subscribes the MCP client to notifications.

        Returns {products: [{product, supported, state, transport, stream, summary, checked, evidence: [{request, observed}], fallback_tools, listeners: [...]}], note}. state is "unsupported", "inactive" (supported, no listener) or a listener's connecting, connected, reconnecting, error, closed. Each listener has {product, console_id, site, state, attached, coverage_started_at, connects, disconnects, reconnect_attempts, last_error, gaps, buffered, capacity, evicted, oldest_seq, last_seq}; times are epoch seconds.

        Example call (get_event_stream_status):
            {"product": "protect"}

        Args:
            product: Optional product, "network" or "protect"; omit for both. Example: "protect".
        """
        return event_streams.event_stream_status(product)

    @mcp.tool(annotations=READ_ONLY)
    async def read_recent_events(
        product: Annotated[
            Product,
            Field(description="Product whose event buffer to read: 'network' or 'protect'."),
        ],
        host: Annotated[
            str,
            Field(
                description=(
                    "Console name or id from list_hosts (reportedState.hostname or name, or "
                    'the long data[].id). Example: "my-console".'
                )
            ),
        ],
        site: Annotated[
            str | None,
            Field(
                description=(
                    'Network site name or id from list_local_sites (e.g. "Default"); '
                    "required for 'network', omit for 'protect'."
                )
            ),
        ] = None,
        after_seq: Annotated[
            int | None,
            Field(
                ge=0,
                description=(
                    "Cursor: return events with seq greater than this, oldest first. Pass the "
                    "next_after_seq of the previous read. Omit to get the newest events."
                ),
            ),
        ] = None,
        max_events: Annotated[
            int | None,
            Field(
                ge=1,
                description=(
                    "Optional maximum number of events to return. Omit to return every "
                    "matching buffered event. Example: 100."
                ),
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Read recent live events for one console; both products answer unsupported today.

        Network and Protect live event streams are not reachable through the UniFi Fabric
        connector this server uses (see get_event_stream_status). For both products this tool
        resolves host (and site; an unknown one fails listing the valid choices) and opens no
        stream. Returns {product, host, site, console_id, site_key, state: "unsupported",
        supported: false, attached: false, reason, compatibility, use_instead, note} with no
        events key, so an unsupported stream is never mistaken for a quiet one. Use the tools
        in use_instead for event history: list_network_events / get_system_log /
        list_ips_events for Network, list_protect_events / collect_protect_events /
        collect_protect_device_changes for Protect.

        A supported stream would be read from a bounded in-memory buffer by after_seq cursor;
        none is supported, so after_seq and max_events have no effect today. Reading never
        subscribes the MCP client to notifications.

        Example call (read_recent_events):
            {"product": "protect", "host": "my-console"}

        Args:
            product: "network" or "protect". Example: "protect".
            host: Console name or id from list_hosts. Example: "my-console".
            site: Network site name or id from list_local_sites (e.g. "Default"); required for
                "network", omit for "protect".
            after_seq: Cursor; events with a greater seq, oldest first. Pass next_after_seq from
                the previous read. Omit for the newest events. Example: 120.
            max_events: Optional maximum number of events returned; omit for all. Example: 100.
        """
        client, registry = deps_fn()
        return await event_streams.read_recent_event_buffer(
            registry, client, product, host, site, after_seq, max_events
        )
