"""System log tools: the Network application's event log, alerts and IPS threat events.

Network 11.x keeps its event history in the v2 system log, read with POST
``/proxy/network/v2/api/site/{site}/system-log/{class}`` and a JSON query body. These POSTs are
classified as writes until their exact raw routes
are approved in a separate read-POST allowlist PR. UNIFI_READ_ONLY refuses these tools
before any upstream request; UNIFI_DRY_RUN returns a write preview without sending the POST. The
Classic routes
older controllers used are gone on Network 11.0.81: ``stat/event`` and ``stat/ips/event``
answer HTTP 404 ``api.err.NotFound`` and ``list/alarm`` answers HTTP 400
``api.err.InvalidObject`` (probed live), so these tools read the system log.

A class page is ``{data: [...], page_number, total_element_count, total_page_count}``
(``critical`` answers a bare JSON array). Pages are numbered from 0 with ``pageNumber`` /
``pageSize`` in the body. Some classes return nothing unless the body names the kinds of
entries wanted (on Network 11.0.81 ``threat-alert`` without ``threatTypes`` returned no
entries while the same query with ``threatTypes`` returned entries); for those the tools
send the full list the controller UI sends, and a caller's own value for that key
replaces it.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastmcp import FastMCP

from ..client import (
    UniFiClient,
    UniFiConnectionError,
    describe_shape,
    is_dry_run_preview,
    path_segment,
    validate_id,
    validate_selector,
)
from ..config import APIKeyConfig
from ..read_only import guard_action
from ..registry import Registry
from ..tool_annotations import READ_ONLY, WRITE
from ._classic_objects import resolve_site_slug, v2_site
from ._history_common import epoch_warnings, require_epoch_seconds, with_warnings
from ._number_window import collect_number_window
from ._pagination import collect_batch, mark_incomplete, validate_pagination

#: Page size of a default drain (a caller page_size requests a total). Network 11.0.81
#: served pages of 1,000 and 5,000 entries; the default page is 50, so a full drain
#: of a busy log would otherwise take hundreds of requests.
DRAIN_PAGE_SIZE = 1000

#: The entry kinds the controller UI names for each class whose query needs them (the
#: Art-of-WiFi UniFi API client's get_system_log carries the same lists). Sent only when
#: the caller's query does not already set that key.
CLASS_DEFAULTS: dict[str, dict[str, list[str]]] = {
    "next-ai-alert": {"nextAiCategory": ["CLIENT", "DEVICE", "INTERNET", "VPN"]},
    "admin-activity": {
        "activity_keys": [
            "ACCESSED_NETWORK_WEB",
            "ACCESSED_NETWORK_IOS",
            "ACCESSED_NETWORK_ANDROID",
        ],
        "change_keys": [
            "CLIENT",
            "DEVICE",
            "HOTSPOT",
            "INTERNET",
            "NETWORK",
            "PROFILE",
            "ROUTING",
            "SECURITY",
            "SYSTEM",
            "VPN",
            "WIFI",
        ],
    },
    "update-alert": {
        "systemLogDeviceTypes": [
            "GATEWAYS",
            "SWITCHES",
            "ACCESS_POINT",
            "SMART_POWER",
            "BUILDING_TO_BUILDING_BRIDGES",
            "UNIFI_LTE",
        ]
    },
    "client-alert": {
        "clientType": ["GUEST", "TELEPORT", "VPN", "WIRELESS", "RADIUS", "WIRED"],
        "guestAuthorizationMethod": [
            "FACEBOOK_SOCIAL_GATEWAY",
            "FREE_TRIAL",
            "GOOGLE_SOCIAL_GATEWAY",
            "NONE",
            "PASSWORD",
            "PAYMENT",
            "RADIUS",
            "VOUCHER",
        ],
    },
    "threat-alert": {"threatTypes": ["HONEYPOT", "THREAT"]},
    "triggers": {"triggerTypes": ["TRAFFIC_RULE", "TRAFFIC_ROUTE", "FIREWALL_RULE"]},
}

#: The classes seen answering on Network 11.0.81 (``triggers`` answered 404 there), for
#: descriptions only. This is not a classifier or allowlist: every system-log POST is
#: a write, including these classes and any other class sent for the controller to judge.
KNOWN_CLASSES = (
    "all",
    "device-alert",
    "client-alert",
    "admin-activity",
    "update-alert",
    "threat-alert",
    "next-ai-alert",
    "vpn-alert",
    "critical",
    "triggers",
)


#: The GET routes ``system-log/{scope}/{identifier}`` of the Network 11.0.81 frontend bundle
#: (``tests/fixtures/private_api/inventory_network_11.0.81.json``). ``device`` and
#: ``client-connection`` answered HTTP 200 on a live console (probed 2026-10-17, ``device``
#: with a list of events; ``client-connection`` with an empty list, shape unproven);
#: ``admin-activity`` and ``by-external-id`` answered HTTP 404 for an id the console did not
#: hold (no admin record and no external-id match existed to ask for), so their positive shape
#: is unproven. This is a route selector, not a classifier: every route is a plain GET.
SCOPED_LOG_ROUTES: dict[str, str] = {
    "device": "a device MAC address",
    "client-connection": "a client MAC address",
    "admin-activity": "an admin-activity record id",
    "by-external-id": "an external id",
}


def _class_query(log_class: str, query: dict[str, Any] | None) -> dict[str, Any]:
    """The caller's query with the class's UI entry-kind lists added where it sets none."""
    body = dict(CLASS_DEFAULTS.get(log_class, {}))
    body.update(query or {})
    return body


async def _post_page(
    client: UniFiClient,
    host_id: str,
    site_slug: str,
    log_class: str,
    body: dict[str, Any],
    key: APIKeyConfig | None,
) -> Any:
    """One system-log POST, classified as a write."""
    return await client.post(
        v2_site(host_id, site_slug, f"/system-log/{log_class}"), key=key, json=body
    )


def _page_rows(page: Any, label: str) -> list[Any]:
    rows = page.get("data") if isinstance(page, dict) else None
    if not isinstance(rows, list):
        raise UniFiConnectionError(
            f"Unexpected response shape from POST {label}: expected an object with a 'data' "
            f"array, got {describe_shape(page)}"
        )
    return rows


def _paging_integer(name: str, value: Any, minimum: int) -> int:
    """Validate controls used in local paging arithmetic before sending the POST.

    ``minimum`` 0 is a zero-based page and 1 a count; the message names ``name``.
    """
    kind = "zero_page" if minimum == 0 else "page_size"
    # A JSON null in the query is not an integer either; the validator reads None as
    # "not given", so it is checked under its printed form.
    validate_pagination(**{kind: "None" if value is None else value}, names={kind: name})
    return int(value)


async def _read_system_log(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    log_class: str,
    query: dict[str, Any] | None,
    *,
    page: int | None = None,
    page_size: int | None = None,
) -> Any:
    """Read one system-log class. Zero-based page: with page_size, returns exactly
    page_size records starting at record page * page_size, gathered across console pages
    whatever the console page size; resume with _nextPage and the same page_size. Without
    page_size, one request returns that console page verbatim. page_size alone is page 0:
    exactly page_size records from record 0; with neither, all entries are drained.
    """
    guard_action("system-log POST")
    validate_id(log_class, "log_class")
    body = _class_query(log_class, query)
    # Paging keys in the query are honoured, never refused: a pageNumber counts as page
    # and a pageSize as page_size; the explicit arguments win.
    # Validate body controls even when explicit arguments override them. These
    # integers drive local paging arithmetic; other body fields stay free-form.
    in_number = (
        _paging_integer("query_body.pageNumber", body.pop("pageNumber"), 0)
        if "pageNumber" in body
        else None
    )
    in_size = (
        _paging_integer("query_body.pageSize", body.pop("pageSize"), 1)
        if "pageSize" in body
        else None
    )
    page = _paging_integer("page", page, 0) if page is not None else in_number
    page_size = _paging_integer("page_size", page_size, 1) if page_size is not None else in_size
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    label = f"system-log/{log_class}"

    async def fetch(paging: dict[str, Any]) -> Any:
        return await _post_page(client, host_id, site_slug, log_class, {**body, **paging}, key)

    if page is not None or page_size is not None:
        if page_size is not None:
            # The logical window [page*N, page*N + N), whatever the console page size;
            # page_size alone is window 0 (a bare array included), so its _nextPage counts
            # page_size windows and page_size alone matches page=0 for the same console.
            window = await collect_number_window(
                fetch, page=page or 0, page_size=page_size, max_pages=client.paginate_max_pages
            )
            if "raw" not in window:
                return mark_incomplete({**window["envelope"], "data": window["items"]}, window)
            one = window["raw"]
        else:
            # Explicit paging: exactly one page, carrying only the paging parameters given.
            one = await fetch({"pageNumber": page})
        if is_dry_run_preview(one):
            return one
        if not isinstance(one, dict):
            # This POST is an applied write.  Preserve a scalar response instead of
            # reporting that completed write as an envelope-shape failure.
            return one
        _page_rows(one, label)
        return one

    collected = await collect_batch(
        fetch,
        requested=page_size,
        default_size=DRAIN_PAGE_SIZE,
        family="number",
        max_pages=client.paginate_max_pages,
        strict_total=True,
        allow_unpaged=True,
    )
    if "raw" in collected:
        return collected["raw"]
    result = {
        k: v
        for k, v in collected["envelope"].items()
        if k not in ("page_number", "total_page_count")
    }
    result["data"] = collected["items"]
    return mark_incomplete(result, collected)


def _window(start: int | None, end: int | None) -> dict[str, Any]:
    """Epoch-second start / end as the system log's millisecond timestamps (only those given).

    A non-integer value is refused (the shared epoch-type rule); a negative value or one that
    looks like milliseconds is sent as given and reported by :func:`_epoch_hints`."""
    out: dict[str, Any] = {}
    if start is not None:
        out["timestampFrom"] = require_epoch_seconds(start, "start") * 1000
    if end is not None:
        out["timestampTo"] = require_epoch_seconds(end, "end") * 1000
    return out


def _epoch_hints(result: Any, start: int | None, end: int | None) -> Any:
    """``result`` with the shared ``_warnings`` entries for implausible start / end values."""
    return with_warnings(result, epoch_warnings(start=start, end=end))


async def _vpn_user_connection_log(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    vpn_user_id: str,
    *,
    start: int | None,
    end: int | None,
    view: str | None,
) -> Any:
    """One VPN user's connection log (GET ``system-log/vpn-user-connection?vpnUserId=``),
    verbatim. The route takes no class and no window, so a ``view``, ``start`` or ``end``
    given with it is refused before any request rather than silently dropped."""
    validate_selector(vpn_user_id, "vpn_user_id")
    given = [
        name
        for name, value in (("start", start), ("end", end), ("view", view))
        if value is not None and not (isinstance(value, str) and not value.strip())
    ]
    if given:
        raise ValueError(
            f"list_network_events scope conflict: {', '.join(given)} cannot be combined with "
            "vpn_user_id (the VPN-user connection log takes no class or time window); omit "
            "them or omit vpn_user_id."
        )
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    return await client.get(
        v2_site(host_id, site_slug, "/system-log/vpn-user-connection"),
        key=key,
        params={"vpnUserId": vpn_user_id},
    )


async def _get_scoped_system_log(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    scope: str,
    identifier: str,
    query: dict[str, Any] | None = None,
) -> Any:
    """GET ``system-log/{scope}/{identifier}`` verbatim (a plain read, no POST).

    ``scope`` must name one of :data:`SCOPED_LOG_ROUTES` (an unknown scope fails listing the
    choices); ``identifier`` is encoded as exactly one path segment (a MAC address is sent
    as given). ``query`` is sent as the query string when non-empty."""
    validate_selector(scope, "scope")
    if scope not in SCOPED_LOG_ROUTES:
        raise ValueError(
            f"get_scoped_system_log scope must be one of {', '.join(SCOPED_LOG_ROUTES)}; "
            f"got {scope!r}"
        )
    if scope in {"device", "client-connection"}:
        # The identifier is a caller MAC here: the one selector rule refuses an empty,
        # padded or control-character value (a padded MAC is never sent or stripped); its
        # spelling is otherwise the caller's, as the bundle route types it only as ``{}``.
        validate_selector(identifier, "identifier")
    # A MAC is sent with its colons as given (the probed form); every other reserved
    # character stays percent-encoded, so the value is still exactly one path segment.
    segment = path_segment(identifier, "identifier").replace("%3A", ":")
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    path = v2_site(host_id, site_slug, f"/system-log/{scope}/{segment}")
    if query:
        return await client.get(path, key=key, params=query)
    return await client.get(path, key=key)


async def _list_network_events(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    start: int | None,
    end: int | None,
    *,
    view: str | None = None,
    vpn_user_id: str | None = None,
) -> Any:
    """Class ``view`` (default ``all``) of the system log, every page drained, with the
    start / end window; or, with ``vpn_user_id``, that VPN user's connection log."""
    if vpn_user_id is not None:
        return await _vpn_user_connection_log(
            client, registry, host, site, vpn_user_id, start=start, end=end, view=view
        )
    log_class = view.strip() if isinstance(view, str) and view.strip() else "all"
    query = _window(start, end)
    result = await _read_system_log(client, registry, host, site, log_class, query)
    return _epoch_hints(result, start, end)


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the system-log MCP tools."""

    @mcp.tool(annotations=WRITE)
    async def get_system_log(
        host: str,
        site: str,
        log_class: str = "all",
        query_body: dict[str, Any] | None = None,
        page: int | None = None,
        page_size: int | None = None,
    ) -> Any:
        """Read Network system-log events and alerts.

        POST network/v2/api/site/{site}/system-log/{log_class} with the supplied query body
        (classified as a write; Consequence: none intended, it only reads).
        Classes seen on Network 11.0.81: all, device-alert, client-alert, admin-activity,
        update-alert, threat-alert (IPS/IDS), next-ai-alert, vpn-alert, critical; triggers
        answered 404. Any other class is sent as given.
        Class filter keys default to the entry kinds the controller UI sends
        (nextAiCategory, activity_keys, change_keys, systemLogDeviceTypes, clientType,
        guestAuthorizationMethod, threatTypes, triggerTypes); query_body can override them.

        UNIFI_READ_ONLY or UNIFI_ENABLE_NETWORK_WRITE=false hides this tool before requests
        (not read-POST allowlisted). UNIFI_DRY_RUN previews the first page without sending:
        {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params,
        body}}.

        Returns, by default, every page drained into {data: [entry, ...], total_element_count,
        incomplete?, incompleteReason?}. Entries are verbatim; the count is the first
        page's. Caps, repeated entries, early empty pages or short totals mark the result
        incomplete; an object with unprovable pagination raises (request an explicit page
        to inspect it). A scalar response is returned verbatim. With page alone, returns
        {data, page_number, total_element_count, total_page_count} verbatim; critical normally
        returns a bare array. page_size alone is window 0; resume with page=_nextPage and
        the same page_size. With page, the window (see page). _pageSize: requested, sent
        (each pageSize sent, in order), effective, returned. No _nextPage: nothing follows
        the window, or the call stopped incomplete.
        Narrow large logs with timestampFrom/timestampTo in query_body.
        Each page is sent once; HTTP 429 stops the call (narrow or use page).

        Example call (get_system_log):
            {
              "host": "my-console",
              "site": "Default",
              "log_class": "client-alert",
              "query_body": {"timestampFrom": 1760140800000, "timestampTo": 1760227200000}
            }

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
        return await _read_system_log(
            client,
            registry,
            host,
            site,
            log_class,
            query_body,
            page=page,
            page_size=page_size,
        )

    @mcp.tool(annotations=WRITE)
    async def list_network_events(
        host: str,
        site: str,
        start: int | None = None,
        end: int | None = None,
        view: str | None = None,
        vpn_user_id: str | None = None,
    ) -> Any:
        """List the site's network events (device, client, admin, security, update and other
        entries of the system log), every page drained, in the order the controller returns.

        Network 11.x keeps events in the system log (the Classic stat/event route answers
        HTTP 404 on Network 11.0.81). This reads class "all" of POST
        network/v2/api/site/{site}/system-log/all (classified as a write), with
        timestampFrom / timestampTo
        set from start / end when given. view reads another class the same way (live on
        Network 11.0.81: all, device-alert, client-alert, admin-activity, update-alert,
        threat-alert, next-ai-alert, vpn-alert, critical). vpn_user_id scopes the log to one VPN
        user instead: GET network/v2/api/site/{site}/system-log/vpn-user-connection?vpnUserId=
        (the web UI's route), returned verbatim. For a raw query use get_system_log.

        Consequence: none intended. Read POSTs are classed as writes (not read-POST
        allowlisted). UNIFI_READ_ONLY or UNIFI_ENABLE_NETWORK_WRITE=false hides the whole tool.
        UNIFI_DRY_RUN previews the first page without sending a POST:
        {status: "dry_run", dryRun: true, sent: false, message,
        preview: {method, path, params, body}}.

        Returns {data: [event, ...], total_element_count, incomplete?, incompleteReason?}:
        each event verbatim (key such as CLIENT_ROAMED_2 or THREAT_DETECTED_KNOWN_SOURCE_CLIENT,
        category, severity, timestamp in epoch ms, parameters, ...); total_element_count is the
        controller's count; incomplete / incompleteReason appear when the opt-in
        UNIFI_PAGINATE_MAX_PAGES cap, repeated entries, an early empty page, or a short declared
        total stopped the drain. Unprovable pagination metadata raises a clear error; use
        get_system_log with an explicit page to inspect it. _warnings appears when
        start or end is negative or looks like milliseconds (sent as given). Without start / end
        the whole retained log is read (tens of thousands of entries on a busy site).

        Example call (list_network_events):
            {
              "host": "my-console",
              "site": "Default",
              "start": 1760140800,
              "end": 1760227200
            }

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
            view: Optional system-log class to read instead of "all" (URL path segment, sent
                as given), e.g. "device-alert" or "admin-activity". Default "all".
                Example: `device-alert`.
            vpn_user_id: Optional VPN user id: reads that user's VPN connection log (query
                vpnUserId, a GET) instead of a class; start, end and view do not apply.
                Example: `65f1c0ffee0123456789abcd`.
        """
        client, registry = deps_fn()
        return await _list_network_events(
            client, registry, host, site, start, end, view=view, vpn_user_id=vpn_user_id
        )

    @mcp.tool(annotations=WRITE)
    async def list_ips_events(
        host: str,
        site: str,
        start: int | None = None,
        end: int | None = None,
        threat_types: list[str] | None = None,
    ) -> Any:
        """List intrusion prevention / detection (IPS/IDS) threat events, every page drained.

        Network 11.x reports IPS events in the system log's threat-alert class (the Classic
        stat/ips/event route answers HTTP 404 on Network 11.0.81). This reads POST
        network/v2/api/site/{site}/system-log/threat-alert (classified as a write;
        Consequence: none intended, it only reads the log) with
        threatTypes (default
        ["HONEYPOT", "THREAT"], what the controller UI sends; without it the controller returns
        no entries) and timestampFrom / timestampTo from start / end when given.

        These POST queries are treated as writes pending a separately approved read-POST
        allowlist PR. UNIFI_READ_ONLY and UNIFI_ENABLE_NETWORK_WRITE=false hide the tool
        before any upstream request.
        UNIFI_DRY_RUN returns {status: "dry_run", dryRun: true, sent: false, message,
        preview: {method, path, params, body}} for the first page without sending a POST.

        Returns {data: [event, ...], total_element_count, incomplete?, incompleteReason?}: each
        event verbatim (key such as THREAT_DETECTED_KNOWN_SOURCE_CLIENT, category SECURITY,
        severity, timestamp in epoch ms, parameters with the signature, source and destination,
        ...); incomplete / incompleteReason appear when the opt-in UNIFI_PAGINATE_MAX_PAGES cap,
        repeated entries, an early empty page, or a short declared total stopped the drain.
        Unprovable pagination metadata raises a clear error; use get_system_log with an explicit
        page to inspect it. _warnings appears when start or end is negative or looks like
        milliseconds (sent as given). Without start / end the whole retained log is
        read.

        Example call (list_ips_events):
            {
              "host": "my-console",
              "site": "Default",
              "start": 1760140800
            }

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
        query = _window(start, end)
        if threat_types is not None:
            query["threatTypes"] = threat_types
        result = await _read_system_log(client, registry, host, site, "threat-alert", query)
        return _epoch_hints(result, start, end)

    @mcp.tool(annotations=READ_ONLY)
    async def get_scoped_system_log(
        host: str,
        site: str,
        scope: str,
        identifier: str,
        query: dict[str, Any] | None = None,
    ) -> Any:
        """Read the Network system log for one device, client connection, admin-activity record
        or external id (a plain GET, no drain).

        GET network/v2/api/site/{site}/system-log/{scope}/{identifier}, returned verbatim.
        scope selects the route: "device" (identifier is a device MAC address; HTTP 200 with a
        list of events on a live console, probed 2026-10-17), "client-connection" (identifier
        is a client MAC address; HTTP 200 on a live console but the one client tried returned
        an empty list, so the entry shape is unproven), "admin-activity" (identifier is an
        admin-activity record id) and "by-external-id" (identifier is an external id). The last
        two answered HTTP 404 on the probe console for an id it did not hold (it had no admin
        record and no external-id match), so their positive responses have not been observed.
        The routes come from the Network 11.0.81 web app; no published schema describes the
        responses. For a whole class (all, device-alert, ...) use get_system_log or
        list_network_events. An unknown scope fails before any request listing the choices.

        Returns the upstream body verbatim (a list of events for device; nonobjects use
        result).

        Example call (get_scoped_system_log):
            {
              "host": "my-console",
              "site": "Default",
              "scope": "device",
              "identifier": "aa:bb:cc:dd:ee:ff"
            }

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
        return await _get_scoped_system_log(client, registry, host, site, scope, identifier, query)
