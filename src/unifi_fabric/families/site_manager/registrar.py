"""The site_manager family registrar: its tool wrappers, in registration order (the family-owned
layout).

The loader map (``catalog/loaders.py``) runs each ``register`` / ``register_<n>`` below at its place
in the ``tools/list`` order, with the ``origin`` its tools are indexed under. The wrappers are the
tools' public surface (names, annotations, docstrings, signatures), moved by
``scripts/move_family.py``; each calls its handler through the handler's module, so a patched
handler still applies (``handlers.py`` indexes them).
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any, Literal

from fastmcp import FastMCP

from ... import diagnostic_bundle, output_schemas
from ...catalog.deferred import live_app
from ...client import UniFiConnectionError
from ...registry import PartialListingError
from ...shared_shapes import _keys
from ...tool_annotations import READ_ONLY
from . import aggregation, site_manager


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> dict[str, Callable[..., Any]]:
    """Register the site_manager tool wrappers moved from server.py, in order.

    Returns the registered wrapper functions by name; server.py re-exports them.
    """

    @mcp.tool(annotations=READ_ONLY)
    async def list_hosts(
        page_token: str | None = None,
        page_size: int | None = None,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """List all UniFi consoles (hosts) with firmware, WAN IP and status. Returns {data: [host…], _count} with upstream envelope fields, including GPS coordinates. data[].id is the long composite id; reportedState.hostname/name is the short name. Either identifies host arguments case-insensitively; ambiguous names return the matching consoles so the caller can choose an id.

        Default drains all pages in batches of 200. page_size gathers native pages until the requested host count or the end (the full final page can exceed the total); _pageSize reports requested count, sent sizes per request, effective size and returned count. page_token accepts the unchanged native nextToken for one verbatim page, or the opaque _continuation string preserving its physical size when the requested total changes. Capped drains carry incomplete=true.

        With several keys, the default aggregates all keys, annotates each host with _keyLabel, and returns _key_labels, byKey envelopes and per-key errors. key_label reads one key and adds _key_labels. Paging with several keys needs key_label.

        Args:
            page_token: Raw nextToken string for one verbatim page, or the returned opaque
                _continuation string preserving physical size when changing page_size.
                Example: the token from the previous response.
            page_size: Requested host count, gathered across effective pages. Omit both
                paging arguments to drain every page. Example: `100`.
            key_label: Configured API-key label from list_configured_api_keys to read one
                key; required with paging when several keys exist. Example: "primary".
        """
        client, registry = deps_fn()
        return await site_manager.list_hosts(
            client, registry, page_token=page_token, page_size=page_size, key_label=key_label
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_host(
        host: str,
    ) -> dict[str, Any]:
        """Get details for a single UniFi console by name or ID.

        The details of a single console, found by its name or ID (list_hosts lists them all).

        Returns the upstream response object verbatim: the host record under data (including
        reportedState GPS coordinates) beside httpStatusCode and traceId.

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive, e.g.
                "my-console") or the long data[].id (MAC:numericId composite).
        """
        client, registry = deps_fn()
        return await site_manager.get_host(client, registry, host)

    @mcp.tool(annotations=READ_ONLY)
    async def list_sites(
        page_token: str | None = None,
        page_size: int | None = None,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """List all sites with device/client counts and ISP info. Returns {data: [site…], _count} plus upstream envelope fields. siteId is the Site Manager Fabric ObjectId, distinct from per-site proxy UUIDs; pass site names such as "Default" to tools and the server resolves the id.

        Default drains all pages in batches of 200. page_size gathers native pages until the requested site count or the end (the full final page can exceed the total); _pageSize reports requested count, sent sizes per request, effective size and returned count. page_token accepts the unchanged native nextToken for one verbatim page, or the opaque _continuation string preserving its physical size when the requested total changes. Capped drains carry incomplete=true.

        With several keys, the default aggregates all keys, annotates each site with _keyLabel, and returns _key_labels, byKey envelopes and per-key errors. key_label reads one key and adds _key_labels. Paging with several keys needs key_label.

        Args:
            page_token: Raw nextToken string for one verbatim page, or the returned opaque
                _continuation string preserving physical size when changing page_size.
                Example: the token from the previous response.
            page_size: Requested site count, gathered across effective pages. Omit both
                paging arguments to drain every page. Example: `100`.
            key_label: Configured API-key label from list_configured_api_keys to read one
                key; required with paging when several keys exist. Example: "primary".
        """
        client, registry = deps_fn()
        return await site_manager.list_sites(
            client, registry, page_token=page_token, page_size=page_size, key_label=key_label
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_devices(
        host: str | None = None,
        page_token: str | None = None,
        time: str | None = None,
        page_size: int | None = None,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """List all devices across the fleet with status, firmware and model. Returns {data, _count, _consoleCount} plus upstream envelope fields. data holds console wrappers {hostId, hostName, devices: [...]} unchanged; _count counts their devices, _consoleCount the wrappers; null/missing/empty devices count as 0.

        Default drains all pages in batches of 200. page_size gathers native pages until the requested wrapper count or the end (the full final page can exceed the total); _pageSize reports requested count, sent sizes per request, effective size and returned count. page_token accepts native nextToken for one verbatim page, or the opaque _continuation string preserving the physical size when the requested total changes. Capped drains carry incomplete.

        host filters server-side to that console on its owning key. Without host, key_label or paging, several keys are aggregated with _keyLabel per wrapper, _key_labels, byKey envelopes and per-key errors. Paging without host needs key_label when several keys exist.

        Args:
            host: Optional console name or composite id from list_hosts; for example
                "my-console" from reportedState.hostname or its data[].id. Names are case-insensitive.
            page_token: Raw nextToken string for one verbatim page, or the returned opaque
                _continuation string preserving physical size when changing page_size.
                Example: the token from the previous response.
            time: Optional RFC3339 last-processed timestamp, forwarded unchanged as time;
                for example "2026-10-26T00:00:00Z". Omitted when unset.
            page_size: Requested wrapper count, gathered across effective pages.
                Omit both paging arguments to drain all. Example: `100`.
            key_label: Configured API-key label from list_configured_api_keys; required
                with paging and no host when several keys exist. Example: "primary".
        """
        client, registry = deps_fn()
        return await site_manager.list_devices(
            client,
            registry,
            host=host,
            page_token=page_token,
            time=time,
            page_size=page_size,
            key_label=key_label,
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_isp_metrics(
        interval: Literal["5m", "1h"],
        duration: str | None = None,
        begin_timestamp: str | None = None,
        end_timestamp: str | None = None,
    ) -> dict[str, Any]:
        """Get WAN health metrics (speed, latency, packet loss, uptime). Unscoped variant (every site the key sees); `interval` ('5m' or '1h') is the bucket size; duration, or begin_timestamp/end_timestamp, bound the range. To scope by console/site use query_isp_metrics.

        Returns the upstream body verbatim: {data, httpStatusCode, traceId}. data is one object per site, {metricType, hostId, siteId, periods}; each periods[] entry is {metricTime, version, data: {wan: {avgLatency, maxLatency, packetLoss, download_kbps, upload_kbps, uptime, downtime, ispName, ispAsn}}}, so a site's WAN values are at data[i].periods[j].data.wan.

        With several keys every key is queried and data keeps that path (each object has an additive _keyLabel); byKey holds the rest of each key's body (httpStatusCode, traceId), _key_labels lists the keys that answered, and a failed key is under errors.

        Args:
            interval: time bucket for metrics aggregation — '5m' or '1h'.
            duration: Optional (query duration): time range ending now — '24h' for 5m metrics, '7d'
                or '30d' for 1h metrics. Cannot be combined with begin_timestamp/end_timestamp.
            begin_timestamp: Optional (query beginTimestamp): earliest time, an RFC3339 string such
                as "2026-07-23T00:00:00Z".
            end_timestamp: Optional (query endTimestamp): latest time, an RFC3339 string.
        """
        client, _ = deps_fn()
        return await site_manager.get_isp_metrics(
            client,
            interval,
            duration=duration,
            begin_timestamp=begin_timestamp,
            end_timestamp=end_timestamp,
        )

    @mcp.tool(annotations=READ_ONLY)
    async def query_isp_metrics(
        interval: Literal["5m", "1h"],
        host: str | None = None,
        site: str | None = None,
        sites: list[dict | None] | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
    ) -> dict[str, Any]:
        """Query filtered ISP metrics for scoped sites: `sites`, or `host`+`site` (both is an error). The filtered variant of get_isp_metrics: start_time/end_time bound the window; for a quick unscoped read use get_isp_metrics.

        Returns the upstream body verbatim: {data: {metrics, status?, message?}, httpStatusCode, traceId}. data.metrics is one object per site, {metricType, hostId, siteId, periods}, each periods[] entry {metricTime, version, data: {wan: {...}}}. data.status/data.message report partial success (some sites had no data).

        With several keys each site is queried on the key owning its console; the result keeps the data.metrics path with every key's per-site objects (each with an additive _keyLabel), byKey holds the rest of each key's body (data.status/message, httpStatusCode, traceId), _key_labels lists the keys that answered, and a failed key is under errors (the call fails only when every key fails).

        Required arguments: interval (see each parameter's description).

        Args:
            interval: time bucket for metrics aggregation — '5m' or '1h'.
            host: Optional. Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive, e.g.
                "my-console") or the long data[].id (MAC:numericId composite). One console serves both
                Network and Protect. Resolves to hostId.
            site: site name or ID — resolves to siteId automatically.
            sites: advanced use — list of {hostId, siteId} dicts, optionally with per-entry
                beginTimestamp/endTimestamp. hostId may be a console name or id (resolved to the
                id); siteId must be a Site Manager site on that console (from list_sites; a site
                name is resolved too). An unknown console or site fails before the query, listing
                the valid choices; a malformed hostId/siteId (empty, whitespace, control character)
                fails before any request. A null beginTimestamp/endTimestamp is treated as absent
                (start_time/end_time apply). Use host/site instead for a single site. An empty list
                names no site: with host/site those scope the query; alone it is sent as given
                ({"sites": []}) for the upstream to judge, and an upstream error gets a hint
                appended.
                Shape: ({hostId:string,siteId:string,beginTimestamp?:string|null,
                endTimestamp?:string|null}|null)[]
            start_time: ISO 8601 UTC timestamp STRINGS, e.g. "2026-07-23T00:00:00Z". These are strings,
                NOT epoch numbers — passing an epoch integer (seconds or milliseconds) is rejected by
                schema validation with 'Input should be a valid string [type=string_type]'. (Note the
                deliberate inconsistency with the epoch-based history tools: list_protect_events,
                list_client_sessions and get_historical_stats take epoch SECONDS as integers, whereas
                this Site Manager tool takes ISO 8601 strings.) An epoch supplied AS a string (e.g.
                "1690000000000") is also rejected, with the expected format, rather than being forwarded
                to the API as a meaningless window. An empty or
                whitespace-only value is an error, never read as omitted.
            end_time: ISO 8601 UTC timestamp STRINGS, e.g. "2026-07-23T00:00:00Z". These are strings,
                NOT epoch numbers — passing an epoch integer (seconds or milliseconds) is rejected by
                schema validation with 'Input should be a valid string [type=string_type]'. (Note the
                deliberate inconsistency with the epoch-based history tools: list_protect_events,
                list_client_sessions and get_historical_stats take epoch SECONDS as integers, whereas
                this Site Manager tool takes ISO 8601 strings.) An epoch supplied AS a string (e.g.
                "1690000000000") is also rejected, with the expected format, rather than being forwarded
                to the API as a meaningless window. An empty or
                whitespace-only value is an error, never read as omitted.
        """
        client, registry = deps_fn()
        # Every argument (the window, the host/site pair, every sites[] entry) is validated
        # before ANY console/site resolution: a malformed entry anywhere in sites[] fails
        # with zero upstream requests, never after earlier entries were resolved.
        site_manager.validate_isp_query(interval, start_time, end_time)
        entries = site_manager.validate_isp_sites(sites, host, site)
        # Group selectors by their owning key, but resolve each key's sites inside its
        # error boundary so one failed /v1/sites listing cannot abort healthy keys.
        by_key: dict[str | None, tuple[Any, list[dict[str, Any] | None]]] = {}
        routed_entries: dict[int, str | None] = {}
        for index, entry in enumerate(entries):
            if entry is None:
                continue
            owner = await registry.resolve_key_for_host(entry["hostId"])
            label = owner.label if owner is not None else None
            routed_entries[index] = label
            by_key.setdefault(label, (owner, []))[1].append(entry)
        if host and site:
            owner = await registry.resolve_key_for_host(host)
            label = owner.label if owner is not None else None
            by_key.setdefault(label, (owner, []))[1].append({"hostId": host, "siteId": site})
        if any(entry is None for entry in entries):
            if not by_key:
                for label in client.list_key_labels():
                    by_key[label] = (client.get_key_by_label(label), [])
            for label, (_owner, group) in by_key.items():
                group[:] = [
                    entry
                    for index, entry in enumerate(entries)
                    if entry is None or routed_entries[index] == label
                ]
        if not by_key:
            by_key[None] = (None, [])
        query_path = f"/v1/isp-metrics/{interval}/query"

        # Resolve every selector before the first metrics request. A query for a healthy
        # key must not race ahead of an invalid selector on another key. Upstream listing
        # failures remain scoped to their key, while invalid selectors fail the whole call.
        async def _resolve(owner: Any, group: list[dict[str, Any] | None]) -> list[Any]:
            resolved: list[dict[str, Any] | None] = []
            for entry in group:
                if entry is None:
                    resolved.append(None)
                    continue
                host_id = await registry.resolve_host_id(entry["hostId"], key=owner)
                # ISP metrics uses the Fabric ObjectId from /v1/sites, not a proxy UUID.
                site_id = await registry.resolve_ea_site_id(
                    entry["siteId"], host_id=host_id, key=owner
                )
                resolved.append({**entry, "hostId": host_id, "siteId": site_id})
            return resolved

        resolved_by_key: dict[str | None, list[dict[str, Any] | None]] = {}
        resolution_errors: dict[str | None, Exception] = {}
        outcomes = await asyncio.gather(
            *(_resolve(owner, group) for owner, group in by_key.values()), return_exceptions=True
        )
        for label, outcome in zip(by_key, outcomes, strict=True):
            if not isinstance(outcome, BaseException):
                resolved_by_key[label] = outcome
                continue
            if not isinstance(outcome, Exception):
                raise outcome
            # An invalid selector fails the whole call; a key that could not list its hosts or
            # sites, or listed them only in part, fails only that key's query.
            if isinstance(outcome, ValueError) and not isinstance(
                outcome, (UniFiConnectionError, PartialListingError)
            ):
                raise outcome
            resolution_errors[label] = outcome
            resolved_by_key[label] = []

        async def _query(owner: Any) -> dict[str, Any]:
            label = owner.label if owner is not None else None
            if label in resolution_errors:
                raise resolution_errors[label]
            resolved = resolved_by_key[label]
            body = await site_manager.query_isp_metrics(
                client,
                interval,
                sites=resolved,
                start_time=start_time,
                end_time=end_time,
                key=owner,
            )
            if len(by_key) > 1:
                site_manager.isp_metric_records(body, "POST", query_path, query=True)
            return body

        results, errors, multi = await _keys.fan_out_scopes(
            [(label, owner) for label, (owner, _entries) in by_key.items()], _query
        )
        if not multi:
            return results[0][1]
        return site_manager.merge_isp_metric_bodies(results, errors, query=True)

    @mcp.tool(annotations=READ_ONLY)
    async def list_sdwan_configs(
        page_token: str | None = None,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """List Site Magic (SD-WAN) VPN mesh configurations.

        Returns {data, _count} plus the upstream envelope fields (httpStatusCode, traceId), and
        nextToken when the service returns one; with several keys {data, _count, _key_labels, byKey}
        plus errors; incomplete / incompleteReason on a capped drain.

        In a multi-key deployment without key_label every configured key is queried: results are
        merged, each record carries an additive _keyLabel, and a key that fails is reported under
        errors.

        The published contract declares no pagination parameters or nextToken. By default the server
        follows a nextToken if the service returns one. Pass page_token to fetch a single page manually;
        with several API keys it needs key_label (a cursor belongs to one key's listing). A capped
        drain returns the configs gathered so far with incomplete=true rather than truncating silently.

        Args:
            page_token: Optional pagination cursor (a nextToken if returned by the service) to fetch one
                page manually. Omit it to drain every page and get the complete list.
                Example: the `nextToken` string from a previous response, passed unchanged.
            key_label: Optional configured API-key label (see list_configured_api_keys) to read one
                key. Omit it to cover every key. With several keys configured, page_token needs it;
                without it the call fails listing the labels.
        """
        client, _ = deps_fn()
        return await site_manager.list_sdwan_configs(
            client, page_token=page_token, key_label=key_label
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_sdwan_config(
        config_id: str,
    ) -> dict[str, Any]:
        """Get a single SD-WAN configuration by ID.

        Returns the upstream response object verbatim: the configuration under data beside
        httpStatusCode and traceId.
        In a multi-key deployment every configured key is tried and the first that answers is used.

        Example call (get_sdwan_config):
            {"config_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        Args:
            config_id: SD-WAN configuration id (Site Manager). Get it from list_sdwan_configs (id).
        """
        client, _ = deps_fn()
        return await site_manager.get_sdwan_config(client, config_id)

    @mcp.tool(annotations=READ_ONLY)
    async def get_sdwan_config_status(
        config_id: str,
    ) -> dict[str, Any]:
        """Get the status of an SD-WAN configuration by ID.

        Returns the upstream response object verbatim: the status under data beside
        httpStatusCode and traceId.
        In a multi-key deployment every configured key is tried and the first that answers is used.

        Example call (get_sdwan_config_status):
            {"config_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        Args:
            config_id: SD-WAN configuration id (Site Manager). Get it from list_sdwan_configs (id).
        """
        client, _ = deps_fn()
        return await site_manager.get_sdwan_config_status(client, config_id)

    @mcp.tool(
        annotations=READ_ONLY, output_schema=output_schemas.SELF_BUILT["list_all_sites_aggregated"]
    )
    async def list_all_sites_aggregated() -> dict[str, Any]:
        """List all sites with aggregated health stats from the /v1/sites/ API.

        Result: {data, _count} plus the upstream envelope fields (httpStatusCode, traceId); with several
        keys {data, _count, _key_labels, byKey} plus errors.

        Returns sites merged with health summary: device counts, client counts,
        alerts, and connectivity status in a single call. Every page is drained (multi-key:
        every key, per-key failures under errors); a capped drain is flagged incomplete and is
        never cached for name resolution.
        """
        client, registry = deps_fn()
        return await site_manager.list_all_sites_aggregated(client, registry)

    @mcp.tool(annotations=READ_ONLY)
    async def get_site_health_summary(
        site: str,
    ) -> dict[str, Any]:
        """Get a site's health: the Classic /stat/health body, verbatim.

        Returns the controller's {meta, data} envelope unchanged: meta is {rc, msg?} and data has
        one record per subsystem (wan, www, wlan, lan, vpn) with its status and that subsystem's
        counters (e.g. num_adopted / num_disconnected devices, num_user clients, wan latency and
        uptime fields), plus an additive _healthSummary {subsystems: {subsystem: status}, notOk:
        [subsystem…], allOk} derived from data[] (omitted when data has no subsystem records). When
        the site was resolved against a partial Site Manager site list the result adds _incomplete
        and _incompleteReason.

        Args:
            site: Site Manager site name or siteId (list_sites: data[].meta.desc / meta.name, or
                siteId). A name shared by sites on several consoles is rejected with the matches
                listed; pass that siteId then.
        """
        client, registry = deps_fn()
        return await site_manager.get_site_health_summary(client, registry, site)

    @mcp.tool(
        annotations=READ_ONLY, output_schema=output_schemas.SELF_BUILT["compare_site_performance"]
    )
    async def compare_site_performance(
        sites: list[str],
    ) -> dict[str, Any]:
        """Compare health and performance metrics across multiple sites side-by-side.

        Returns {_comparison, _count}: one comparison entry per site, in the order given, each the
        site's Classic /stat/health body verbatim with its additive _healthSummary (as
        get_site_health_summary returns it) plus an additive _siteLabel, or {_siteLabel, error} for
        a site that failed (the call fails only
        when every site fails). incomplete/incompleteReason name any site resolved against a
        partial site list.

        Args:
            sites: Site Manager site names or siteIds to compare (list_sites: meta.desc / meta.name, or
                siteId); a shared name is reported as an error for that entry — pass the siteId. An
                empty list compares no site: _comparison is empty and no request is sent.
        """
        client, registry = deps_fn()
        return await site_manager.compare_site_performance(client, registry, sites)

    @mcp.tool(annotations=READ_ONLY)
    async def search_across_sites(
        query: str,
    ) -> dict[str, Any]:
        """Search for devices or clients matching a query across all sites.

        Returns {data (the matching records), _count, _query, _sitesTotal, _sitesSearched,
        _sitesSucceeded, _sitesFailed, _sitesIncomplete} plus errors and _skipped (sites that could
        not be searched, each with its reason) when present. Each errors entry is an object {key
        (the API-key label), siteId, scope ("devices" / "clients" for a per-site fetch failure;
        "sites" with siteId "" for a key whose site list failed), reason (a string)}. A site whose
        device or client list stopped at
        the UNIFI_PAGINATE_MAX_PAGES cap counts in _sitesIncomplete (not _sitesFailed or
        _sitesSucceeded) and the result carries
        incomplete=true with the reasons. Each match is the upstream record plus additive _type /
        _siteId / _siteName / _hostId (its console), and _keyLabel (the API key that read it) when
        several keys are configured.

        Args:
            query: case-insensitive substring matched against a device's name, macAddress,
                ipAddress or model, or a client's name, macAddress, ipAddress or hostname, e.g.
                "02:00:5e" or "10.0.2.". An empty or whitespace query applies no filter: every
                device and client record of every searched site is returned.
        """
        client, registry = deps_fn()
        return await site_manager.search_across_sites(client, registry, query)

    @mcp.tool(annotations=READ_ONLY)
    async def get_site_inventory(
        site: str,
        device_filter: str | None = None,
        client_filter: str | None = None,
    ) -> dict[str, Any]:
        """Get full inventory for a site: all devices and connected clients.

        _devicesEnvelope and _clientsEnvelope hold each list's upstream envelope fields (totalCount,
        ...).

        Returns {_siteId (the console site UUID), _devices, _deviceCount, _clients, _clientCount}
        (the two upstream record lists, verbatim, under additive keys); both
        lists are drained across every page (incomplete=true with the reason only when the opt-in
        UNIFI_PAGINATE_MAX_PAGES cap stops a drain).

        Args:
            site: Site Manager site name or siteId (list_sites: data[].meta.desc / meta.name, or
                siteId). A name shared by sites on several consoles is rejected with the matches
                listed; pass that siteId then.
            device_filter: Optional Network Integration API filter expression, forwarded unchanged as
                the `filter` query parameter of the site's device list. Omitted when unset.
            client_filter: Optional Network Integration API filter expression, forwarded unchanged as
                the `filter` query parameter of the site's client list. Omitted when unset.
        """
        client, registry = deps_fn()
        return await site_manager.get_site_inventory(
            client, registry, site, device_filter=device_filter, client_filter=client_filter
        )

    return {
        "list_hosts": list_hosts,
        "get_host": get_host,
        "list_sites": list_sites,
        "list_devices": list_devices,
        "get_isp_metrics": get_isp_metrics,
        "query_isp_metrics": query_isp_metrics,
        "list_sdwan_configs": list_sdwan_configs,
        "get_sdwan_config": get_sdwan_config,
        "get_sdwan_config_status": get_sdwan_config_status,
        "list_all_sites_aggregated": list_all_sites_aggregated,
        "get_site_health_summary": get_site_health_summary,
        "compare_site_performance": compare_site_performance,
        "search_across_sites": search_across_sites,
        "get_site_inventory": get_site_inventory,
    }


def register_2(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register all aggregation MCP tools."""

    @mcp.tool(
        annotations=READ_ONLY, output_schema=output_schemas.SELF_BUILT["list_configured_api_keys"]
    )
    async def list_configured_api_keys() -> dict[str, Any]:
        """List all configured API keys with their labels and types.

        Result: {keys, count}: one entry per configured key, and how many.

        Shows which API keys are available for MSP multi-console queries.
        Returns labels and org-key status without exposing actual key values.
        """
        client, _ = deps_fn()
        return await aggregation._list_api_keys(client)

    @mcp.tool(annotations=READ_ONLY)
    async def get_server_diagnostic_bundle(
        live_probes: list[diagnostic_bundle.LiveProbe] | None = None,
    ) -> dict[str, Any]:
        """Build a sanitized diagnostic bundle about this MCP server, for a bug report (not a controller support file; see generate_support_file). Returns {bundle, schemaVersion, generatedAt, review, collection, sections, neverCollected, sanitization}. collection.mode is "local" or "local+live"; collection.upstreamRequests counts requests sent (0 by default). sections: server (versions, OS family), configuration (modes, key count, cache, paging, log/audit settings as enums, booleans, numbers), policy (effective write and exposure policy and digest), transport, cache, runtime (tool count) and liveProbes; each has a status (complete, partial, failed, unavailable) and a source; a failed section gives an exception type name only.

        By default it reads local and cached state and contacts no console or Site Manager. It never includes API key values or labels, tokens, paths, host names, IPs, ports, URLs, console/site/device ids, upstream bodies, error messages or other environment variables; configured secrets are scrubbed and checked. Nothing is saved or sent: review it, then share it yourself.

        Args:
            live_probes: Optional live read probes to run once per configured API key,
                from a fixed allowlist: "hosts" runs list_hosts (GET /v1/hosts) and
                "sites" runs list_sites (GET /v1/sites). Each reports per key a status,
                record count, duration and a reason such as "HTTP 401"; no record is
                copied. A probe failure gives a partial bundle, never an error. Omit, or
                pass [], to send no request. Example: ["hosts"].
                Shape: string[]. Each item is "hosts" or "sites".
        """
        probes = diagnostic_bundle.validate_probes(live_probes)
        client, registry = deps_fn()

        async def hosts(label: str) -> Any:
            return await site_manager.list_hosts(client, registry, key_label=label)

        async def sites(label: str) -> Any:
            return await site_manager.list_sites(client, registry, key_label=label)

        async def tool_count() -> int:
            # The live server's catalog, also when this step was staged (C6).
            return len(await live_app(mcp).list_tools(run_middleware=False))

        return await diagnostic_bundle.build_bundle(
            client,
            registry,
            live_probes=probes,
            fetchers={"hosts": hosts, "sites": sites},
            tool_count=tool_count,
        )

    @mcp.tool(annotations=READ_ONLY, output_schema=output_schemas.SELF_BUILT["list_all_devices"])
    async def list_all_devices(
        status_filter: str | None = None,
        key_label: str | None = None,
        host_ids: list[str] | None = None,
        time: str | None = None,
    ) -> dict[str, Any]:
        """List all devices across the entire fleet (every configured API key unless key_label names one; per-key failures under errors). A console visible to more than one key is listed once, under the first key in configuration order (as list_all_clients does).

        Returns {data, _count, _filter, _key_label}: /v1/devices returns one wrapper per console, unwrapped so data[] holds the device records verbatim plus _hostId/_hostName/_updatedAt naming the console; _count is the device count, _filter echoes status_filter. With one key the envelope fields (httpStatusCode, traceId) sit beside data, with several they are under byKey with _key_labels. errors and incomplete/incompleteReason are added when they apply.

        status_filter (e.g. 'offline', 'online', 'updating') is applied locally by exact case-insensitive match on each device's status/state. WARNING: an unrecognised value is not rejected: it matches nothing and returns an EMPTY list, so a typo (e.g. 'ofline') looks like a healthy fleet. Omit it to get the full fleet and read the real status values off the records.

        Args:
            status_filter: Optional status to match LOCALLY (exact, case-insensitive) against each
                device's status/state, e.g. 'offline', 'online', 'updating'. An unrecognised value
                is not rejected: it matches nothing and returns an empty list. An empty or
                whitespace value applies no filter.
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to
                cover every configured key: results are merged, each record carries an additive
                _keyLabel, and a key that fails is reported under errors.
            host_ids: Optional console ids (list_hosts data[].id, the long MAC:numericId form),
                forwarded verbatim as the upstream hostIds[] query parameter to every covered key
                (an empty list sends no hostIds[] parameter).
                Shape: string[]
            time: Optional RFC3339 timestamp, forwarded verbatim as the upstream time query
                parameter (the spec's "last processed timestamp of devices").
        """
        client, _ = deps_fn()
        return await aggregation._list_all_devices_fleet(
            client, status_filter=status_filter, key_label=key_label, host_ids=host_ids, time=time
        )

    @mcp.tool(annotations=READ_ONLY, output_schema=output_schemas.SELF_BUILT["list_all_clients"])
    async def list_all_clients(
        key_label: str | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List all connected clients across all sites. Fans out to every site (every configured API key unless key_label names one; a console visible to more than one key is queried once, under the first key in configuration order), drains each site's client list and aggregates it.

        Returns {data, _count, _sitesQueried, _sitesSucceeded, _sitesFailed, _sitesIncomplete, _key_label, _siteEnvelopes}: data holds every site's client records verbatim plus _hostId/_hostName/_siteId/_siteName (and _keyLabel with several keys); _siteEnvelopes maps "hostId/siteId" to that site's upstream envelope fields (totalCount ...). errors, _skipped (hosts/sites that could not be queried, each with its reason), _key_labels and incomplete/incompleteReason are added when they apply. A site stopped at the UNIFI_PAGINATE_MAX_PAGES cap counts in _sitesIncomplete, not as failed, and the result carries incomplete=true with the reasons.

        Args:
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to
                cover every configured key: results are merged, each record carries an additive
                _keyLabel, and a key that fails is reported under errors.
            filter: Optional Network Integration API filter expression, forwarded unchanged as
                each site's upstream `filter` query parameter. Omitted entirely when unset.
                Example: `type.eq('WIRED')`.
        """
        client, registry = deps_fn()
        return await aggregation._list_all_clients_fleet(
            client, registry, key_label=key_label, filter_expr=filter
        )

    @mcp.tool(annotations=READ_ONLY, output_schema=output_schemas.SELF_BUILT["get_fleet_summary"])
    async def get_fleet_summary(
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """Get a high-level fleet summary: host, site and device counts with status breakdowns. Covers every configured API key unless key_label names one (per-key failures under errors); a console visible to more than one key is counted once, under the first key in configuration order (as list_all_clients does).

        Returns counts only, no records: {hosts, sites, devices: {total, byStatus, byType}, _key_label}. With several keys also _key_labels and _keyTotals (one entry per answering key, over the consoles counted under it, summing to the top-level totals; a failed key has no entry). errors lists a failed key (label, reason); incomplete/incompleteReason is added when a list stopped at the opt-in UNIFI_PAGINATE_MAX_PAGES cap.

        Args:
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to
                cover every configured key: every key's consoles, sites and devices are counted
                together, and a key that fails is reported under errors.
        """
        client, registry = deps_fn()
        return await aggregation._fleet_summary(client, registry, key_label=key_label)

    @mcp.tool(annotations=READ_ONLY, output_schema=output_schemas.SELF_BUILT["search_device_fleet"])
    async def search_device_fleet(
        query: str,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """Search for a device by name, MAC address, or model across the entire fleet.

        Result: {data, _count, _query, _key_label}: _query and _key_label echo the arguments.

        Returns all matching devices from all consoles (every configured API key unless
        key_label names one; per-key failures under errors); each match carries the wrapper's
        fields as additive _hostId / _hostName / _updatedAt naming its console. A console
        visible to more than one key is searched once, under the first key in configuration
        order.

        Required arguments: query (see each parameter's description).

        Args:
            query: REQUIRED. Search string matched against device name, model, and MAC across the
                fleet. An empty or whitespace query applies no filter: every device is returned.
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to
                cover every configured key: results are merged, each record carries an additive
                _keyLabel, and a key that fails is reported under errors.
        """
        client, _ = deps_fn()
        return await aggregation._search_device(client, query, key_label=key_label)
