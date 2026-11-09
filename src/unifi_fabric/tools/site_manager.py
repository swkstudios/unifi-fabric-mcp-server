"""Site Manager read-only tools — 9 endpoints from the UniFi Site Manager API.

Namespace policy: these tools target the stable Official
``/v1/`` Site Manager namespace. All five families (hosts, sites, devices,
isp-metrics, sd-wan-configs) were migrated from ``/ea/`` to ``/v1/`` in place
without renaming any tool. New Site Manager tools MUST call ``/v1/`` where a
published equivalent exists; ``/ea/`` is permitted only when no ``/v1/`` path
is served, and such a tool MUST carry an explicit "Early Access — endpoint may
change" note in its docstring. Tests pin the exact ``/v1/`` URL each tool builds
so a namespace regression fails at Tier 1.

The Site Manager ``siteId`` is a Fabric ObjectId on BOTH ``/ea`` and ``/v1``
(live-verified 2026-08-15); the UUID site ID used in proxy URLs comes only from
the per-console connector ``/sites`` endpoint, which is unaffected by this policy.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Awaitable, Callable, Hashable
from typing import Any, Literal

import httpx
from fastmcp import FastMCP

from ..argument_errors import echoed_input
from ..argument_values import is_blank
from ..client import (
    PaginationAbortedError,
    RateLimitError,
    UniFiClient,
    UniFiConnectionError,
    describe_shape,
    gather_or_cancel,
    log_reason,
    nullable_object_records,
    object_records,
    path_segment,
    upstream_error_text,
    upstream_error_value,
    validate_host_id,
    validate_id,
    wrong_type_error,
)
from ..config import APIKeyConfig
from ..matching import NAME_TIERS, id_key, name_keys, same_id
from ..read_post_routes import post_read
from ..registry import (
    PartialListingError,
    Registry,
    _assert_uuid,
    ea_site_labels,
    filter_records,
    incomplete_reason,
    match_ea_site,
)
from ..resolution_state import note_incomplete_resolution
from ..selector_args import nested_selector_problems
from ..tool_annotations import READ_ONLY
from ._device_wrappers import wrapper_devices
from ._keys import (
    context_value,
    fan_out,
    first_id,
    first_success,
    key_error,
    key_scopes,
    merge_first_key,
    page_mode_scope,
    report_keys,
    stable_id,
    with_context,
)
from ._pagination import (
    DRAIN_PAGE_SIZE,
    bare_page,
    collect_cursor,
    collect_offset,
    cursor_continuation,
    mark_incomplete,
    validate_pagination,
    with_envelope,
)
from ._payload import with_upstream_hint
from .network import _proxy
from .statistics import with_health_summary

logger = logging.getLogger(__name__)

# An all-digit string (optionally with a decimal fraction) is an epoch value, never a
# valid ISO 8601 timestamp. Used to reject bare-epoch start_time/end_time in
# query_isp_metrics before they reach the API as a meaningless window.
_EPOCH_STRING_RE = re.compile(r"\s*\d+(\.\d+)?\s*")


async def _aggregate_lists_over_keys(
    client: UniFiClient,
    labels: list[str],
    fetch: Callable[[APIKeyConfig], Awaitable[list[Any]]],
    *,
    identity: Callable[[Any], Hashable | None],
    on_success: Callable[[APIKeyConfig, list[Any]], Awaitable[None]] | None = None,
    transform: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    by_key: dict[str, Any] | None = None,
    nullable_items: bool = False,
) -> tuple[list[Any], list[str], list[str], list[str]]:
    """Fan a per-key list fetch across all configured API keys (MSP aggregation).

    Mirrors the partial-failure pattern in ``tools/aggregation.py``
    (``_list_all_clients_fleet``): every key is fetched concurrently via
    ``gather_or_cancel`` (no key fetch outlives the call); a per-key failure is
    captured as an error string rather than aborting the whole call;
    ``RuntimeError`` is raised only when *every* key fails. Each returned record is
    copied and annotated with its source key via ``_keyLabel`` (through
    ``with_context``: a record's own different value goes under ``_ownFields``),
    matching the existing ``_hostId`` / ``_siteName``
    per-record annotation convention), so a caller can tell which org each item
    came from. This is what fixes public issue
    https://github.com/swkstudios/unifi-fabric-mcp-server/issues/19: without fan-out,
    only the first configured key's org was ever returned.

    Returns ``(records, answering labels, per-key errors, incomplete reasons)``; the
    answering labels are the keys whose records are included (``_key_labels``, through
    :func:`report_keys`). A key whose drain stops
    at the opt-in ``UNIFI_PAGINATE_MAX_PAGES`` cap (or a repeated cursor) keeps the
    records it gathered and is reported in the incomplete reasons; its partial list is
    never passed to ``on_success`` (so it is never cached). A fetch that reads through
    the registry reports a partial list the same way: the list it returns carries its
    reason (:func:`~unifi_fabric.registry.incomplete_reason`).

    ``by_key``, when given, is filled with each answering key's upstream envelope (the
    first page's top-level fields other than the records and paging controls, such as
    ``traceId`` / ``httpStatusCode``), so a merge drops no upstream key. Only a key whose
    records passed the shape check is stored: a key reported under errors never has a
    byKey entry, and every answering key has one (``{}`` when its body carried nothing
    beside the records), so the byKey keys are exactly ``_key_labels``.
    """

    def _records(label: str, items: list[Any]) -> list[Any]:
        out: list[Any] = []
        validate = nullable_object_records if nullable_items else object_records
        for item in validate(items, f"the list read with API key {label!r}"):
            if item is None:
                out.append(item)
                continue
            record = transform(item) if transform is not None else item
            # Preserve upstream labels; trusted routing uses private server context.
            out.append(with_context(record, {"_keyLabel": label}))
        return out

    async def _fetch(label: str) -> tuple[str, list[Any], str | None, str | None]:
        # Everything per key (fetch, shape check, tagging) is inside the per-key try, so
        # one key's bad shape is that key's error and never fails the whole call.
        key = client.get_key_by_label(label)
        # A key's envelope is stored only once its records passed the shape check (and
        # its success hook ran), so byKey holds answering keys only (== _key_labels).
        try:
            try:
                items = await fetch(key)
            except PaginationAbortedError as exc:
                partial = _records(label, exc.items)
                if by_key is not None:
                    # An answering key always has an entry ({} when its body carried
                    # nothing beside the records), so byKey == _key_labels.
                    by_key[label] = dict(exc.envelope or {})
                return label, partial, None, exc.reason
            reason = incomplete_reason(items)
            records = _records(label, items)
            if on_success is not None and reason is None:
                await on_success(key, items)
            envelope = getattr(items, "envelope", None)
            if by_key is not None:
                by_key[label] = dict(envelope) if isinstance(envelope, dict) else {}
            return label, records, None, reason
        except Exception as exc:
            return label, [], key_error(label, exc), None

    results = await gather_or_cancel(*[_fetch(label) for label in labels])

    per_key: list[tuple[str | None, list[Any]]] = []
    answering: list[str] = []
    errors: list[str] = []
    incomplete: list[str] = []
    for label, items, err, reason in results:
        if err is not None:
            errors.append(err)
            continue
        if reason:
            incomplete.append(f"{label}: {reason}")
        per_key.append((label, items))
        answering.append(label)
    # One multi-key rule: an object (or console) several keys see is returned once, under
    # the first key in configuration order (records are already tagged above).
    aggregated: list[Any] = merge_first_key(per_key, identity, multi=False)

    if labels and len(errors) == len(labels):
        raise RuntimeError(f"All {len(labels)} API key(s) failed: {'; '.join(errors)}")

    return aggregated, answering, errors, incomplete


def _mark_reasons(result: dict[str, Any], reasons: list[str]) -> dict[str, Any]:
    """Flag ``result`` incomplete with every reason (no-op when the list is empty)."""
    if reasons:
        return with_context(result, {"incomplete": True, "incompleteReason": "; ".join(reasons)})
    return result


_CURSOR_PAGING = "page_token/page_size"


def _page_size(page_size: int | None, paging: bool) -> int | None:
    """The requested record count, or the default size for an unlimited drain.

    A raw ``page_token`` alone sends no size; an opaque continuation string preserves
    its physical page size. ``page_size`` is a total gathered across native pages."""
    if page_size is not None:
        return page_size
    return None if paging else DRAIN_PAGE_SIZE


def _single_key_result(result: dict[str, Any], label: str | None) -> dict[str, Any]:
    """A one-key listing in a multi-key deployment names the key it read (``_key_labels``)."""
    if label is not None:
        return with_context(result, {"_key_labels": [label]})
    return result


async def list_hosts(
    client: UniFiClient,
    registry: Registry,
    *,
    page_token: str | None = None,
    page_size: int | None = None,
    key_label: str | None = None,
) -> Any:
    """List all UniFi consoles (hosts) with firmware, WAN IP, and status.

    Host records are returned verbatim, including reportedState GPS coordinates.
    By default every page is drained with 200 records per request. ``page_size`` asks
    for that many records, or all available if fewer exist; the server follows
    ``nextToken`` across native pages, retaining the full final page so no records
    disappear behind a token. ``_pageSize`` reports requested, actual sent sizes per
    request, observed effective size and returned count, including any overshoot.
    Resume with the returned opaque ``page_token=_continuation`` string to preserve the
    physical size even when changing the requested total. Raw nextToken strings
    remain accepted; a raw token requests one verbatim page.
    A capped drain returns gathered hosts with incomplete=true.

    MSP multi-key: without ``key_label`` or paging, hosts are aggregated across every
    configured key's org, with per-key failures and source ``_keyLabel`` annotations
    (public issue https://github.com/swkstudios/unifi-fabric-mcp-server/issues/19).
    ``key_label`` reads one key. A paged listing needs ``key_label`` when several
    keys are configured because its cursor belongs to one key's listing."""
    cursor_continuation(page_token, "cursor")
    paging = page_token is not None or page_size is not None
    labels = client.list_key_labels()
    if not paging and key_label is None and len(labels) > 1:
        envelopes: dict[str, Any] = {}
        hosts, answering, errors, reasons = await _aggregate_lists_over_keys(
            client,
            labels,
            lambda key: client.paginate("/v1/hosts", key=key),
            identity=stable_id("id"),
            on_success=lambda key, items: registry.set_hosts(items, key=key),
            by_key=envelopes,
        )
        mk_result = report_keys(
            {"data": hosts, "_count": len(hosts)}, answering, errors, multi=True
        )
        if envelopes:
            mk_result["byKey"] = envelopes
        return _mark_reasons(mk_result, reasons)

    label, key = page_mode_scope(client, key_label, tool="list_hosts", paging=_CURSOR_PAGING)
    collected = await collect_cursor(
        client,
        "/v1/hosts",
        key=key,
        page_token=page_token,
        page_size=_page_size(page_size, paging),
        one_page=paging,
    )
    if (page := bare_page(collected)) is not None:
        return page
    raw_hosts = collected["items"]

    # Update registry cache opportunistically (only a complete drain is cacheable).
    if not paging and not collected["incomplete"]:
        await registry.set_hosts(raw_hosts, key=key)

    result: dict[str, Any] = {"data": raw_hosts, "_count": len(raw_hosts)}
    if collected["nextToken"]:
        result["nextToken"] = collected["nextToken"]
    result = mark_incomplete(with_envelope(result, collected), collected)
    return _single_key_result(result, label if len(labels) > 1 else None)


async def get_host(
    client: UniFiClient,
    registry: Registry,
    host: str,
) -> dict[str, Any]:
    """Get details for a single UniFi console by name or ID.

    The upstream response object is returned verbatim: the host record under ``data``
    (including reportedState GPS coordinates) beside the envelope's ``httpStatusCode``
    and ``traceId``.
    """
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    path = f"/v1/hosts/{host_id}"
    return _object_body(await client.get(path, key=key), "GET", path)


def _object_body(body: Any, method: str, path: str) -> dict[str, Any]:
    """The upstream body when it is a JSON object; otherwise raise naming the request.

    ``decode_body`` returns ``None`` for an empty body, the text of a non-JSON body, and
    lists or scalars as received; none of those is an object, so the shape received is
    reported instead of failing later with an attribute error.
    """
    if not isinstance(body, dict):
        raise UniFiConnectionError(
            f"Unexpected response shape from {method} {path}: expected a JSON object, got "
            f"{describe_shape(body)}"
        )
    return body


async def list_sites(
    client: UniFiClient,
    registry: Registry,
    *,
    page_token: str | None = None,
    page_size: int | None = None,
    key_label: str | None = None,
) -> Any:
    """List all sites with device/client counts and ISP info.

    By default every page is drained with 200 records per request. ``page_size`` asks
    for that many records, or all available if fewer exist; the server follows
    ``nextToken`` across native pages, retaining the full final page so no records
    disappear behind a token. ``_pageSize`` reports requested, actual sent sizes per
    request, observed effective size and returned count, including any overshoot.
    Resume with the returned opaque ``page_token=_continuation`` string to preserve the
    physical size even when changing the requested total. Raw nextToken strings
    remain accepted; a raw token requests one verbatim page.
    A capped drain returns gathered sites with incomplete=true.

    MSP multi-key: without ``key_label`` or paging, sites are aggregated across every
    configured key's org, with per-key failures and source ``_keyLabel`` annotations
    (public issue https://github.com/swkstudios/unifi-fabric-mcp-server/issues/19).
    A paged listing needs ``key_label`` when several keys are configured because
    its cursor belongs to one key's listing."""
    cursor_continuation(page_token, "cursor")
    paging = page_token is not None or page_size is not None
    labels = client.list_key_labels()
    if not paging and key_label is None and len(labels) > 1:
        envelopes: dict[str, Any] = {}
        sites, answering, errors, reasons = await _aggregate_lists_over_keys(
            client,
            labels,
            lambda key: client.paginate("/v1/sites", key=key),
            identity=stable_id("hostId", "siteId"),
            on_success=lambda key, items: registry.set_ea_sites(items, key=key),
            nullable_items=True,
            by_key=envelopes,
        )
        mk_result = report_keys(
            {"data": sites, "_count": len(sites)}, answering, errors, multi=True
        )
        if envelopes:
            mk_result["byKey"] = envelopes
        return _mark_reasons(mk_result, reasons)

    label, key = page_mode_scope(client, key_label, tool="list_sites", paging=_CURSOR_PAGING)
    collected = await collect_cursor(
        client,
        "/v1/sites",
        key=key,
        page_token=page_token,
        page_size=_page_size(page_size, paging),
        one_page=paging,
    )
    if (page := bare_page(collected)) is not None:
        return page
    sites = collected["items"]

    if not paging and not collected["incomplete"]:
        await registry.set_ea_sites(sites, key=key)

    result: dict[str, Any] = {"data": sites, "_count": len(sites)}
    if collected["nextToken"]:
        result["nextToken"] = collected["nextToken"]
    result = mark_incomplete(with_envelope(result, collected), collected)
    return _single_key_result(result, label if len(labels) > 1 else None)


async def list_devices(
    client: UniFiClient,
    registry: Registry,
    *,
    host: str | None = None,
    page_token: str | None = None,
    page_size: int | None = None,
    time: str | None = None,
    key_label: str | None = None,
) -> Any:
    """List all devices across the fleet with status, firmware, and model.

    /v1/devices returns one wrapper per console ({hostId, hostName, devices: [...]}),
    passed through verbatim in ``data``; ``_count`` is the number of devices inside
    them and ``_consoleCount`` is the number of wrappers.

    By default every page is drained with 200 records per request. ``page_size`` asks
    for that many upstream wrapper records, or all available if fewer exist; the
    server follows ``nextToken`` across native pages, retaining the full final page
    to preserve continuity. ``_pageSize`` reports requested, actual sent sizes per
    request, observed effective size and returned count, including any overshoot.
    Resume with the returned opaque ``page_token=_continuation`` string to preserve the
    physical size even when changing the requested total. Raw nextToken strings
    remain accepted and request one verbatim page. Capped drains carry incomplete.

    ``host`` filters server-side to that console (``hostIds[]``) on its owning key,
    named in ``_key_labels`` in a multi-key deployment. Without ``host``, ``key_label``
    or paging, every key's consoles are listed, with source ``_keyLabel`` annotations
    and per-key failures under ``errors``. A paged listing without ``host`` needs
    ``key_label`` in a multi-key deployment. ``time`` is the optional RFC3339 last
    processed timestamp, forwarded unchanged on every request."""
    cursor_continuation(page_token, "cursor")
    paging = page_token is not None or page_size is not None
    params: dict[str, Any] = {}
    if time is not None:
        params["time"] = time
    key: APIKeyConfig | None = None
    label: str | None = None
    labels: list[str] = []
    if host is not None:
        validate_pagination(page_size=page_size, names={"page_size": "page_size"})
        if key_label is not None:
            # An unknown label fails listing the valid labels whatever the number of keys:
            # a single-key server resolves no key for the host below.
            client.get_key_by_label(key_label)
        key = await registry.resolve_key_for_host(host)
        if key_label is not None and key is not None and key.label != key_label:
            raise ValueError(
                f"list_devices: console {echoed_input(host)} belongs to API key {key.label!r}, not "
                f"{key_label!r}; omit key_label (the console selects its key) or pass "
                f"{key.label!r}"
            )
        host_id = await registry.resolve_host_id(host, key=key)
        params["hostIds[]"] = [host_id]
        # The console's key answers: a multi-key result names it like any one-key listing.
        label = key.label if key is not None else None
        labels = client.list_key_labels()
    elif not paging and key_label is None and len(labels := client.list_key_labels()) > 1:
        # params only when the caller set one, so the default request is unchanged
        extra: dict[str, Any] = {"params": params} if params else {}
        envelopes: dict[str, Any] = {}

        def _validate_wrapper(item: dict[str, Any]) -> dict[str, Any]:
            inner = wrapper_devices(item)
            if inner is not None:
                nullable_object_records(inner, "GET /v1/devices wrapper devices")
            return item

        wrappers, answering, errors, reasons = await _aggregate_lists_over_keys(
            client,
            labels,
            lambda k: client.paginate("/v1/devices", key=k, **extra),
            identity=stable_id("hostId"),
            transform=_validate_wrapper,
            nullable_items=True,
            by_key=envelopes,
        )
        mk: dict[str, Any] = {
            "data": wrappers,
            "_count": _count_wrapped_devices(wrappers),
            "_consoleCount": len(wrappers),
        }
        report_keys(mk, answering, errors, multi=True)
        if envelopes:
            mk["byKey"] = envelopes
        return _mark_reasons(mk, reasons)
    else:
        label, key = page_mode_scope(client, key_label, tool="list_devices", paging=_CURSOR_PAGING)
        labels = client.list_key_labels()

    collected = await collect_cursor(
        client,
        "/v1/devices",
        key=key,
        params=params or None,
        page_token=page_token,
        page_size=_page_size(page_size, paging),
        one_page=paging,
    )
    if (page := bare_page(collected)) is not None:
        return page
    devices = collected["items"]

    result: dict[str, Any] = {
        "data": devices,
        "_count": _count_wrapped_devices(devices),
        "_consoleCount": len(devices),
    }
    if collected["nextToken"]:
        result["nextToken"] = collected["nextToken"]
    result = mark_incomplete(with_envelope(result, collected), collected)
    return _single_key_result(result, label if len(labels) > 1 else None)


def _count_wrapped_devices(wrappers: list[Any]) -> int:
    """Number of devices in /v1/devices console wrappers.

    A wrapper whose ``devices`` is null, missing or ``[]`` contributes 0
    (:func:`wrapper_devices`); only an item that is not a console wrapper at all counts as
    one record.
    """
    total = 0
    for item in wrappers:
        if item is None:
            continue
        inner = wrapper_devices(item)
        total += 1 if inner is None else sum(device is not None for device in inner)
    return total


async def get_isp_metrics(
    client: UniFiClient,
    interval: str,
    *,
    duration: str | None = None,
    begin_timestamp: str | None = None,
    end_timestamp: str | None = None,
) -> dict[str, Any]:
    """Get WAN health metrics (speed, latency, packet loss, uptime).

    interval: time bucket for aggregation — '5m' or '1h'.
    duration / begin_timestamp / end_timestamp: the spec's optional ``duration``,
    ``beginTimestamp`` and ``endTimestamp`` query parameters, forwarded verbatim when
    given (the upstream validates them: ``duration`` is ``24h`` for 5m metrics or
    ``7d``/``30d`` for 1h metrics and cannot be combined with the timestamps, which are
    RFC3339 strings).

    One key: the upstream body verbatim, ``{"data": [<per-site metric object>],
    "httpStatusCode", "traceId"}`` where each per-site object is ``{metricType, hostId,
    siteId, periods: [{metricTime, version, data: {wan: {...}}}]}``. Several keys: see
    :func:`merge_isp_metric_bodies` (same ``data`` access path).
    """
    if interval not in ("5m", "1h"):
        raise ValueError(f"interval must be '5m' or '1h', got {echoed_input(interval)}")
    path = f"/v1/isp-metrics/{interval}"
    multi = len(key_scopes(client, None)) > 1
    params = {
        name: value
        for name, value in (
            ("duration", duration),
            ("beginTimestamp", begin_timestamp),
            ("endTimestamp", end_timestamp),
        )
        if value is not None
    }

    async def _fetch(key: APIKeyConfig | None) -> dict[str, Any]:
        extra: dict[str, Any] = {"params": params} if params else {}
        body = _object_body(await client.get(path, key=key, **extra), "GET", path)
        if multi:
            isp_metric_records(body, "GET", path, query=False)  # this key's error if not
        return body

    results, errors, is_multi = await fan_out(client, None, _fetch)
    if not is_multi:
        return results[0][1]
    return merge_isp_metric_bodies(results, errors, query=False)


def isp_metric_records(body: Any, method: str, path: str, *, query: bool) -> list[Any]:
    """The per-site metric objects an ISP-metrics body carries, or raise with its shape.

    GET ``/v1/isp-metrics/{type}`` carries them in ``data``; POST ``.../query`` in
    ``data.metrics`` (with optional ``data.status`` / ``data.message`` for a partial
    success). Used to merge several keys' bodies, where a key whose body has another
    shape is that key's error.
    """
    data = body.get("data") if isinstance(body, dict) else None
    if query:
        data = data.get("metrics") if isinstance(data, dict) else None
    if not isinstance(data, list):
        where = "data.metrics" if query else "data"
        raise UniFiConnectionError(
            f"Unexpected response shape from {method} {path}: expected a {where!r} array, got "
            f"{describe_shape(body)}"
        )
    return nullable_object_records(data, f"{method} {path}")


def merge_isp_metric_bodies(
    results: list[tuple[str | None, Any]], errors: list[str], *, query: bool
) -> dict[str, Any]:
    """Merge several keys' ISP-metrics bodies (each already shape-checked).

    The result keeps the single-key access path: the per-site metric objects of every key
    are in ``data`` (GET) or ``data.metrics`` (query), each verbatim plus an additive
    ``_keyLabel``. Everything else each key's body carried (``httpStatusCode``,
    ``traceId``, a query's ``data.status`` / ``data.message``) is kept verbatim under
    ``byKey[<label>]``, so nothing upstream is dropped. ``_key_labels`` lists the keys
    that answered; a key that failed is reported under ``errors``.
    """
    per_key: list[tuple[str | None, list[Any]]] = []
    by_key: dict[str, Any] = {}
    for label, body in results:
        data = body["data"]
        records = data["metrics"] if query else data
        per_key.append((label, records))
        rest = {k: v for k, v in body.items() if k != "data"}
        if query:
            rest["data"] = {k: v for k, v in data.items() if k != "metrics"}
        by_key[str(label)] = rest
    # GET: every key answers for every site it can see, so a site's metrics seen through
    # several keys are kept once (first key in order). A query routes each requested site
    # to the one key that owns its console, so its per-key bodies never overlap.
    metric_id = first_id(stable_id("metricType", "hostId", "siteId"), stable_id("id"))
    merged = merge_first_key(per_key, (lambda _r: None) if query else metric_id, multi=True)
    out: dict[str, Any] = {
        "data": {"metrics": merged} if query else merged,
        "byKey": by_key,
    }
    return report_keys(out, [label for label, _ in results], errors, multi=True)


def validate_isp_query(interval: str, start_time: str | None, end_time: str | None) -> None:
    """The ISP-metrics query arguments (interval and time window), or raise.

    Makes no request: ``query_isp_metrics`` calls it before resolving any console or site.
    start_time/end_time must be ISO 8601 strings; an empty or whitespace-only value is an
    error ("must not be empty"), never read as omitted. A bare epoch value (all digits) slips past
    the string-typed signature but is a meaningless timestamp to the Site Manager API,
    which then silently ignores the window and returns the full default range.
    """
    if interval not in ("5m", "1h"):
        raise ValueError(f"interval must be '5m' or '1h', got {echoed_input(interval)}")
    for label, value in (("start_time", start_time), ("end_time", end_time)):
        if value is not None and not isinstance(value, str):
            raise ValueError(
                f"{label} must be an ISO 8601 UTC timestamp string like "
                f"'2026-07-23T00:00:00Z'; got {type(value).__name__}."
            )
        if value is not None and not value.strip():
            raise ValueError(
                f"{label} must not be empty or whitespace ({echoed_input(value)}); "
                "pass an ISO 8601 UTC "
                "timestamp string like '2026-07-23T00:00:00Z', or omit it."
            )
        if value is not None and _EPOCH_STRING_RE.fullmatch(value):
            raise ValueError(
                f"{label} must be an ISO 8601 UTC timestamp string like "
                f"'2026-07-23T00:00:00Z', not an epoch value ({echoed_input(value)}). "
                "Convert epoch "
                "seconds or milliseconds to an ISO 8601 string before calling."
            )


def validate_isp_sites(
    sites: Any, host: str | None, site: str | None
) -> list[dict[str, Any] | None]:
    """Validate the scoping arguments of ``query_isp_metrics`` as a whole, or raise.

    Makes no request: every check runs before any console or site is resolved, so an
    error in the LAST ``sites[]`` entry is reported with zero upstream requests. Checks:
    exactly one of ``sites`` or both ``host`` and ``site`` (``host`` without ``site``, the
    reverse, or a non-empty ``sites`` together with ``host``/``site``, is an error; an
    empty ``sites`` names nothing, so ``host`` + ``site`` alone scope the query); ``sites`` is a
    list (an empty one is sent as given); every entry is an object whose ``hostId`` and
    ``siteId`` are well-formed selectors (the same rule as the top-level ``host`` / ``site``); an
    entry's ``beginTimestamp`` / ``endTimestamp``, when present and not null, is a
    non-empty ISO 8601 string (not an epoch value). An explicit null timestamp is
    treated as absent: it is left out of the body, so ``start_time`` / ``end_time``
    apply to that entry. Returns the entries (copies) in order.
    """
    if (
        (host is None) != (site is None)
        or (host is not None and not host.strip())
        or (site is not None and not site.strip())
    ):
        raise ValueError(
            "query_isp_metrics: `host` and `site` go together (pass both, non-empty), "
            f"got host={echoed_input(host)} site={echoed_input(site)}; or pass `sites` instead."
        )
    if sites is None:
        if host is None:
            raise ValueError(
                "query_isp_metrics requires scoping: pass `sites`, or both `host` and `site`."
            )
        return []
    if host is not None and sites:
        raise ValueError(
            "query_isp_metrics: pass ONE of `sites` or `host` + `site`, not both (both "
            "would query the same site twice); add the host/site pair to `sites` instead."
        )
    if not isinstance(sites, list):
        raise ValueError(
            f"sites must be a list of {{hostId, siteId}} objects; got {describe_shape(sites)}."
        )
    out: list[dict[str, Any] | None] = []
    for index, entry in enumerate(sites):
        if entry is None:
            out.append(None)
            continue
        if not isinstance(entry, dict):
            raise ValueError(
                f"sites[{index}] must be a {{hostId, siteId}} object; got {describe_shape(entry)}."
            )
        for field, hint in (
            ("hostId", "a console name or id from list_hosts"),
            ("siteId", "from list_sites"),
        ):
            if entry.get(field) is None:
                raise ValueError(
                    f"sites[{index}] needs a {field} ({hint}); got {describe_shape(entry)}."
                )
        problem = nested_selector_problems("sites", [entry])
        if problem is not None:
            raise ValueError(problem.replace("sites[0]", f"sites[{index}]", 1))
        clean = dict(entry)
        for name in ("beginTimestamp", "endTimestamp"):
            value = clean.get(name, None)
            if value is None:
                # An explicit null is absent: never sent, so start_time/end_time apply.
                clean.pop(name, None)
                continue
            if not isinstance(value, str) or not value.strip() or _EPOCH_STRING_RE.fullmatch(value):
                raise ValueError(
                    f"sites[{index}].{name} must be a non-empty ISO 8601 UTC timestamp string "
                    f"like '2026-07-23T00:00:00Z' (or null/omitted); got {echoed_input(value)}."
                )
        out.append(clean)
    return out


async def query_isp_metrics(
    client: UniFiClient,
    interval: str,
    *,
    sites: list[dict[str, Any] | None] | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    key: APIKeyConfig | None = None,
) -> dict[str, Any]:
    """Query filtered ISP metrics with optional site/time range filters.

    Returns the upstream body verbatim: ``{"data": {"metrics": [<per-site metric
    object>], "status"?, "message"?}, "httpStatusCode", "traceId"}``.

    key: the API key that owns the sites' consoles (multi-key routing).

    interval: time bucket for aggregation — '5m' or '1h'.
    sites: list of {hostId, siteId} dicts to scope the query, sent as given. An empty
        list is sent too, for the upstream to judge; an upstream error gets a hint
        appended.
    start_time/end_time: ISO 8601 UTC timestamp STRINGS (e.g. "2026-07-23T00:00:00Z"),
        not epoch numbers — the typed signature rejects an integer with
        'Input should be a valid string', and a bare-epoch string (all digits) is
        rejected here with the expected ISO 8601 format. Unlike the epoch-seconds history tools
        (list_protect_events, list_client_sessions, get_historical_stats), this Site
        Manager endpoint takes ISO 8601 strings. These params bound the query window.
        The UniFi Site Manager API reads the window from
        per-site ``beginTimestamp`` / ``endTimestamp`` fields nested INSIDE each
        ``sites[]`` entry — a top-level timestamp is accepted but silently ignored
        (verified live: a top-level window returns the full default range, whereas a
        nested window is honoured exactly). These params are therefore applied to
        every site entry. A caller may instead set per-entry beginTimestamp/
        endTimestamp directly in the ``sites`` dicts; those explicit values win.
    """
    validate_isp_query(interval, start_time, end_time)
    # Copy each site dict so the caller's list is never mutated, then inject the
    # time window per-site (where the API actually reads it). setdefault lets a
    # caller pin an explicit per-entry window that overrides the convenience params.
    # An explicit null per-entry timestamp is absent (never sent; the window applies).
    body: dict[str, Any] = {
        "sites": [
            {
                k: v
                for k, v in entry.items()
                if v is not None or k not in {"beginTimestamp", "endTimestamp"}
            }
            if entry is not None
            else None
            for entry in sites or []
        ]
    }
    if start_time or end_time:
        for entry in body["sites"]:
            if entry is None:
                continue
            if start_time:
                entry.setdefault("beginTimestamp", start_time)
            if end_time:
                entry.setdefault("endTimestamp", end_time)

    # The upstream body verbatim: {"data": {"metrics": [...], "status"?, "message"?},
    # "httpStatusCode", "traceId"} (status/message report a partial success).
    # An empty sites list is sent as given for the upstream to judge; its error gets the hint.
    hint = (
        None
        if body["sites"]
        else "the query names no site: pass sites=[{hostId, siteId}] or host + site."
    )
    data = await with_upstream_hint(
        post_read(client, f"/v1/isp-metrics/{interval}/query", key=key, json=body), hint
    )
    return _object_body(data, "POST", f"/v1/isp-metrics/{interval}/query")


async def list_sdwan_configs(
    client: UniFiClient,
    *,
    page_token: str | None = None,
    key_label: str | None = None,
) -> Any:
    """List Site Magic (SD-WAN) VPN mesh configurations.

    The published contract declares no pagination parameters or nextToken. The server
    follows a nextToken if the service returns one. Pass a raw page_token to fetch one page.
    The returned opaque _continuation string preserves its physical size.
    A capped drain returns the configs gathered
    so far with incomplete=true rather than truncating silently. ``key_label`` reads
    one key; a manual page needs it when several keys are configured
    (:func:`page_mode_scope`).
    """
    cursor_continuation(page_token, "cursor")
    labels = client.list_key_labels()
    if page_token is None and key_label is None and len(labels) > 1:

        async def _drain(key: APIKeyConfig | None) -> dict[str, Any]:
            # The published spec defines no query parameters for /v1/sd-wan-configs.
            collected = await collect_cursor(client, "/v1/sd-wan-configs", key=key, page_size=None)
            object_records(collected["items"], "GET /v1/sd-wan-configs")
            return collected

        results, errors, _multi = await fan_out(client, None, _drain)
        merged = merge_first_key(
            [(label, col["items"]) for label, col in results], stable_id("id"), multi=True
        )
        mk = report_keys(
            {"data": merged, "_count": len(merged)},
            [label for label, _ in results],
            errors,
            multi=True,
        )
        # Every answering key ({} when it sent nothing beside the records): byKey ==
        # _key_labels.
        envelopes = {str(label): dict(col.get("envelope") or {}) for label, col in results}
        if envelopes:
            mk["byKey"] = envelopes
        reasons = [
            f"{label}: {col['incompleteReason']}" for label, col in results if col["incomplete"]
        ]
        return _mark_reasons(mk, reasons)
    label, key = page_mode_scope(client, key_label, tool="list_sdwan_configs", paging="page_token")
    collected = await collect_cursor(
        client, "/v1/sd-wan-configs", key=key, page_token=page_token, page_size=None
    )
    if (page := bare_page(collected)) is not None:
        return page
    configs = collected["items"]

    result: dict[str, Any] = {"data": configs, "_count": len(configs)}
    if collected["nextToken"]:
        result["nextToken"] = collected["nextToken"]
    result = mark_incomplete(with_envelope(result, collected), collected)
    return _single_key_result(result, label if len(labels) > 1 else None)


async def get_sdwan_config(
    client: UniFiClient,
    config_id: str,
) -> dict[str, Any]:
    """Get a single SD-WAN configuration by ID.

    The upstream response object is returned verbatim (the configuration under
    ``data`` beside ``httpStatusCode`` and ``traceId``).
    """
    path = f"/v1/sd-wan-configs/{path_segment(config_id, 'config_id')}"
    _key, data = await first_success(client, None, lambda key: client.get(path, key=key))
    return _object_body(data, "GET", path)


async def get_sdwan_config_status(
    client: UniFiClient,
    config_id: str,
) -> dict[str, Any]:
    """Get the status of an SD-WAN configuration by ID.

    The upstream response object is returned verbatim (the status under ``data`` beside
    ``httpStatusCode`` and ``traceId``).
    """
    path = f"/v1/sd-wan-configs/{path_segment(config_id, 'config_id')}/status"
    _key, data = await first_success(client, None, lambda key: client.get(path, key=key))
    return _object_body(data, "GET", path)


# --- /v1/sites/ tools ---


async def _resolve_ea_host_site(
    registry: Registry, name_or_id: str, client: UniFiClient | None = None
) -> tuple[str, str]:
    """Resolve a site name or siteId to a validated (hostId, siteId) pair."""
    record = await _resolve_ea_site_record(registry, name_or_id, client)
    return record["hostId"], context_value(record, "_resolvedSiteId")


def _ea_slug(record: dict[str, Any]) -> str:
    meta = record.get("meta")
    name = meta.get("name") if isinstance(meta, dict) else None
    return name if isinstance(name, str) else ""


async def _proxy_site_for_ea(
    registry: Registry, record: dict[str, Any], key: APIKeyConfig | None
) -> dict[str, Any]:
    """The console (proxy) site behind a Site Manager site record.

    Matched by the site's internal reference (Site Manager ``meta.name`` == the
    console site's ``internalReference``, e.g. ``default``), which is unique per
    console — so a Site Manager siteId, or a display name shared by two consoles,
    still maps to exactly one console site. Falls back to a unique label match. Anything
    else (no match, several matches) raises listing the console's sites; a console's only
    site is never assumed to be the one meant.

    Both sides are upstream names, so each is compared in the name tiers of
    :mod:`unifi_fabric.matching` (exact, NFC + casefold, stripped): a console site whose
    description carries edge whitespace still maps. The console's list keeps its
    incomplete state through every step: an internal reference is unique per
    console, so it maps on a capped list too, but a LABEL match on a capped list is
    refused (a second site with that label may lie past the cap), naming the cap.
    """
    host_id = record["hostId"]
    proxy_sites = object_records(
        await registry.get_sites(host_id, key=key), "console sites resolution"
    )
    by_ref = _tier_match(proxy_sites, [_ea_slug(record)], lambda s: s.get("internalReference"))
    by_ref = _unique_proxy_sites(by_ref)
    if len(by_ref) > 1:
        raise ValueError(
            f"ambiguous console internalReference {upstream_error_value(_ea_slug(record))!r}: "
            f"{_console_site_choices(registry, host_id, key, proxy_sites)}"
        )
    if len(by_ref) == 1:
        return _resolution_metadata(by_ref[0], record)
    # Both of a console site's labels (description AND name): one never hides the other.
    by_label = _tier_match(
        proxy_sites, ea_site_labels(record), lambda s: [s.get("description"), s.get("name")]
    )
    by_label = _unique_proxy_sites(by_label)
    if len(by_label) == 1:
        reason = incomplete_reason(proxy_sites)
        if reason:
            raise ValueError(
                f"Site Manager site {upstream_error_value(context_value(record, '_resolvedSiteId'))!r} "
                "(meta.name="
                f"{upstream_error_value(_ea_slug(record))!r}) matches console site "
                f"{upstream_error_value(by_label[0].get('id'))!r} on "
                f"{upstream_error_value(host_id)!r} by label only, and the console's "
                f"site list is incomplete ({reason}), so another site with that label may "
                "exist past the cap; the label match is not trusted. Raise or unset "
                "UNIFI_PAGINATE_MAX_PAGES so the console's whole site list is read."
            )
        return _resolution_metadata(by_label[0], record)
    raise ValueError(
        f"Site Manager site {upstream_error_value(context_value(record, '_resolvedSiteId'))!r} "
        f"(meta.name={upstream_error_value(_ea_slug(record))!r}) "
        "does not map to exactly one site on console "
        f"{upstream_error_value(host_id)!r}; console sites: "
        f"{_console_site_choices(registry, host_id, key, proxy_sites)}."
    )


def _unique_proxy_sites(sites: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Validate selected native IDs and count distinct console sites, not rows."""
    distinct: dict[str, dict[str, Any]] = {}
    for site in sites:
        site_id = site.get("id")
        identifying = {
            field: site[field]
            for field in ("id", "internalReference", "description", "name")
            if field in site
        }
        if not isinstance(site_id, str) or not site_id:
            raise ValueError(
                "Selected console site has no non-empty string native id; "
                f"identifying fields: {upstream_error_text(identifying)}"
            )
        try:
            _assert_uuid(site_id)
        except ValueError as exc:
            raise ValueError(
                f"{exc}; identifying fields: {upstream_error_text(identifying)}"
            ) from exc
        distinct.setdefault(id_key(site_id), site)
    return list(distinct.values())


def _resolution_metadata(result: dict[str, Any], *sources: Any) -> dict[str, Any]:
    """Carry incomplete resolution provenance beside the upstream fields."""
    reasons: list[str] = []
    for source in sources:
        reason = (
            context_value(source, "_incompleteReason", strict=True)
            if isinstance(source, dict)
            else None
        )
        if reason and reason not in reasons:
            reasons.append(reason)
    if reasons:
        reason = "; ".join(reasons)
        note_incomplete_resolution(reason)
        return with_context(result, {"_incomplete": True, "_incompleteReason": reason})
    # Server provenance (empty) even when complete, so a later reader never takes an
    # upstream ``_incompleteReason`` on this record for the server's own.
    return with_context(result, {})


def _tier_match(
    sites: list[dict[str, Any]], wanted: list[str], label: Callable[[dict[str, Any]], Any]
) -> list[dict[str, Any]]:
    """The sites whose ``label`` equals one of ``wanted`` in the first name tier with any
    match (exact, NFC + casefold, stripped); ``[]`` when none matches. ``label`` returns
    one label or a list of labels (each one matches)."""
    wanted_keys = [name_keys(w) for w in wanted if isinstance(w, str) and w]
    keyed = [
        (site, name_keys(value))
        for site in sites
        for value in _as_labels(label(site))
        if isinstance(value, str) and value
    ]
    for tier in range(NAME_TIERS):
        targets = {keys[tier] for keys in wanted_keys if keys[tier]}
        found = [site for site, keys in keyed if keys[tier] in targets]
        if found:
            return found
    return []


def _as_labels(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list | tuple) else [value]


def _console_site_choices(
    registry: Registry, host_id: str, key: APIKeyConfig | None, proxy_sites: list[Any]
) -> str:
    """The console's sites as actionable choices, plus a note when the list is partial."""
    choices = ", ".join(
        f"{upstream_error_value(s.get('description') or s.get('name'))} "
        f"(id={upstream_error_value(s.get('id'))}, "
        f"internalReference={upstream_error_value(s.get('internalReference'))})"
        for s in proxy_sites
        if isinstance(s, dict)
    )
    partial = incomplete_reason(proxy_sites)
    note = f" (the console's site list is incomplete: {partial})" if partial else ""
    return f"{choices or '(none)'}{note}"


async def _resolve_ea_site_record(
    registry: Registry, name_or_id: str, client: UniFiClient | None = None
) -> dict[str, Any]:
    """Resolve a site name or siteId to its Site Manager site record (validated).

    Reads the Site Manager sites list (the registry EA-sites cache, sourced from
    `/v1/sites`).

    Raises ValueError if the site is not found (listing the valid sites), if a site
    name matches more than one site (listing them — e.g. "Default" on several
    consoles; pass the siteId then), or if either ID fails validation. In a multi-key
    deployment the sites of every configured key are considered.
    """
    api = client if client is not None else registry._client  # noqa: SLF001 - same package
    labels = api.list_key_labels()
    sites: list[dict[str, Any]] = []
    key_errors: list[str] = []
    partial: list[str] = []
    if len(labels) > 1:
        for label in labels:
            key = api.get_key_by_label(label)
            try:
                key_sites = await registry.get_ea_sites(key=key)
                validated = object_records(key_sites, f"Site Manager sites for {label!r}")
            except Exception as exc:
                key_errors.append(
                    f"API key {label!r} could not list its sites: {upstream_error_text(exc, api)}"
                )
                continue
            sites.extend(validated)
            if reason := incomplete_reason(key_sites):
                partial.append(f"{label}: {reason}")
    else:
        sites = object_records(await registry.get_ea_sites(), "Site Manager sites resolution")
        if reason := incomplete_reason(sites):
            partial.append(reason)
    # The one matcher every Site Manager resolver shares (an exact siteId resolves on a
    # partial list; a name there is refused).
    chosen = match_ea_site(
        sites,
        name_or_id,
        partial=partial,
        max_pages=api.paginate_max_pages,
        failures=key_errors,
    )

    def _site_id(site: dict[str, Any]) -> str:
        value = site.get("siteId") or site.get("id") or ""
        return value if isinstance(value, str) else ""

    host_id = chosen.get("hostId", "")
    site_id = _site_id(chosen)
    try:
        validate_host_id(host_id, "hostId")
        validate_id(site_id, "siteId")
    except ValueError as exc:
        raise ValueError(f"Site {name_or_id!r}: {exc}") from exc
    result = with_context(chosen, {"_resolvedSiteId": site_id})
    reasons = partial + key_errors
    if reasons and not same_id(name_or_id, site_id):
        reason = "; ".join(reasons)
        note_incomplete_resolution(reason)
        result = with_context(result, {"_incomplete": True, "_incompleteReason": reason})
    return result


async def list_all_sites_aggregated(
    client: UniFiClient,
    registry: Registry,
) -> dict[str, Any]:
    """List all sites with aggregated health stats from /v1/sites/.

    Returns sites merged with health summary: device counts, client counts,
    alerts, and connectivity status in a single call.

    MSP multi-key: when more than one API key is configured, sites are
    aggregated across every key's org (public issue
    https://github.com/swkstudios/unifi-fabric-mcp-server/issues/19) with partial-failure
    semantics, each site annotated with its source ``_keyLabel``. Single-key
    deployments are unchanged.
    """
    labels = client.list_key_labels()
    if len(labels) > 1:

        async def _fetch_v1_sites(key: APIKeyConfig) -> list[dict[str, Any]]:
            # Every page; a capped drain keeps what it gathered, is flagged incomplete,
            # and is never cached.
            return await client.paginate("/v1/sites", key=key)

        envelopes: dict[str, Any] = {}
        sites, answering, errors, reasons = await _aggregate_lists_over_keys(
            client,
            labels,
            _fetch_v1_sites,
            identity=stable_id("hostId", "siteId"),
            on_success=lambda key, items: registry.set_ea_sites(items, key=key),
            nullable_items=True,
            by_key=envelopes,
        )
        mk_result = report_keys(
            {"data": sites, "_count": len(sites)}, answering, errors, multi=True
        )
        if envelopes:
            mk_result["byKey"] = envelopes
        return _mark_reasons(mk_result, reasons)

    collected = await collect_cursor(client, "/v1/sites")
    sites = collected["items"]

    # Refresh the Site Manager site registry cache only from a complete drain.
    if not collected["incomplete"]:
        await registry.set_ea_sites(sites)

    return mark_incomplete(
        with_envelope({"data": sites, "_count": len(sites)}, collected), collected
    )


async def get_site_health_summary(
    client: UniFiClient,
    registry: Registry,
    site: str,
) -> dict[str, Any]:
    """Get the Classic ``/stat/health`` body of a single site, verbatim.

    site: site name or ID.
    Routes through Classic REST /stat/health (same endpoint as get_site_statistics) and
    returns the controller's ``{"meta", "data"}`` envelope unchanged: ``data`` is one
    record per subsystem (wan, www, wlan, lan, vpn) with its status and counters. The
    additive ``_healthSummary`` digest (:func:`statistics.health_summary`) sits beside it. A
    site resolved against a partial Site Manager site list adds ``_incomplete`` /
    ``_incompleteReason``.
    """
    record = await _resolve_ea_site_record(registry, site, client)
    host_id = record["hostId"]
    key = await registry.resolve_key_for_host(host_id)
    proxy_site = await _proxy_site_for_ea(registry, record, key)
    site_slug = proxy_site.get("internalReference")
    if not isinstance(site_slug, str) or not site_slug:
        # The Classic REST slug is the console's internalReference; it is never guessed
        # from the Site Manager meta.name.
        proxy_sites = await registry.get_sites(host_id, key=key)
        raise ValueError(
            f"Console site {upstream_error_value(proxy_site.get('id'))!r} on "
            f"{upstream_error_value(host_id)!r} has no internalReference, "
            "so its Classic REST site slug is unknown; the console did not report it. "
            f"Console sites: {_console_site_choices(registry, host_id, key, proxy_sites)}."
        )
    validate_id(site_slug, "site_slug")
    url = f"/v1/connector/consoles/{host_id}/proxy/network/api/s/{site_slug}/stat/health"
    return _resolution_metadata(
        with_health_summary(_object_body(await client.get(url, key=key), "GET", url)),
        record,
        proxy_site,
    )


async def compare_site_performance(
    client: UniFiClient,
    registry: Registry,
    sites: list[str],
) -> dict[str, Any]:
    """Compare health and performance metrics across multiple sites.

    sites: list of site names or IDs to compare.
    Returns ``{"_comparison": [...], "_count"}``: one entry per site, in the order given,
    each the site's Classic ``/stat/health`` body verbatim (as get_site_health_summary
    returns it) plus an additive ``_siteLabel``, or ``{_siteLabel, error}`` for a site
    that failed. The call fails only when every site fails.
    """

    # Every entry is a selector, checked like a top-level `site` before any request; an
    # empty list compares no site (an empty _comparison, no request).
    problem = nested_selector_problems("sites", sites)
    if problem is not None:
        raise ValueError(problem)

    async def _fetch(site: str) -> tuple[bool, dict[str, Any]]:
        # (ok, entry): failure is tracked out of band, so an upstream body shaped like
        # ``{"error": ...}`` (or carrying its own ``_siteLabel``) is never taken for a
        # failed site. The health body keeps its server provenance (no plain-dict copy).
        try:
            result = await get_site_health_summary(client, registry, site)
            result = result if isinstance(result, dict) else {"raw": result}
            return True, with_context(result, {"_siteLabel": site})
        except Exception as exc:
            return False, {"_siteLabel": site, "error": upstream_error_text(exc, client)}

    fetched = await gather_or_cancel(*[_fetch(s) for s in sites])
    results = [entry for _ok, entry in fetched]
    failed = [(site, entry) for site, (ok, entry) in zip(sites, fetched, strict=True) if not ok]
    if results and len(failed) == len(results):
        raise RuntimeError(
            f"All {len(results)} site(s) failed: "
            + "; ".join(f"{site}: {entry['error']}" for site, entry in failed)
        )
    out: dict[str, Any] = {"_comparison": results, "_count": len(results)}
    reasons = []
    for site, (ok, entry) in zip(sites, fetched, strict=True):
        if not ok:
            continue
        reason = context_value(entry, "_incompleteReason", strict=True)
        if context_value(entry, "_incomplete", strict=True) or reason:
            reasons.append(f"{site}: {reason}")
    return _mark_reasons(out, reasons)


def _site_list_error(labels: list[str], entry: str) -> dict[str, Any]:
    """A failed key's ``"<label>: <reason>"`` as a search_across_sites errors entry."""
    label = next((lb for lb in labels if entry.startswith(f"{lb}: ")), None)
    reason = entry[len(label) + 2 :] if label is not None else entry
    return {"key": label, "siteId": "", "scope": "sites", "reason": reason}


async def search_across_sites(
    client: UniFiClient,
    registry: Registry,
    query: str,
) -> dict[str, Any]:
    """Search for devices or clients matching a query across all sites.

    query: search term matched against name, MAC address, IP, or model.
    Returns matching devices and clients with their site context. Each site's device
    and client lists are drained across every page. In a multi-key deployment the
    sites of EVERY configured key are searched; a key, console or site that cannot be
    searched is reported under ``errors`` / ``skipped`` and the rest still succeeds.
    An empty or whitespace ``query`` applies no filter: every device and client record of
    every searched site is returned.
    """
    labels = client.list_key_labels()
    key_errors: list[dict[str, Any]] = []
    list_partial: list[str] = []
    answering: list[str] = []
    if len(labels) > 1:
        sites_data, answering, errs, list_partial = await _aggregate_lists_over_keys(
            client,
            labels,
            lambda key: registry.get_ea_sites(key=key),
            identity=stable_id("hostId", "siteId"),
            nullable_items=True,
        )
        # Each failed key's site list, structured like a per-site entry: {key, siteId: "",
        # scope: "sites", reason}.
        key_errors = [_site_list_error(labels, e) for e in errs]
    else:
        sites_data = await registry.get_ea_sites()
        only = incomplete_reason(sites_data)
        list_partial = [only] if only else []
    query_lower = query.lower()

    def _skip(ea_site_id: Any, site_name: Any, reason: str, code: str) -> dict[str, Any]:
        # A bounded reason code only: ``reason`` (reported under _skipped) can carry a
        # complete upstream error body, which is never logged.
        logger.warning(
            "search_across_sites: skipping site %s: %s",
            upstream_error_value(ea_site_id, client),
            code,
        )
        return {
            "siteId": ea_site_id,
            "siteName": site_name,
            "matches": [],
            "errors": [],
            "skipped": reason,
        }

    def _matches(record: dict[str, Any], fields: tuple[str, ...]) -> bool:
        # A missing or null field never matches (str(None) would match "none").
        if is_blank(query):
            return True  # a blank query applies no filter
        return any(
            query_lower in str(value).lower()
            for f in fields
            if (value := record.get(f)) is not None and not isinstance(value, dict | list)
        )

    claimed_sites: dict[tuple[str, str], tuple[Any, object]] = {}

    async def _search_site(site: dict[str, Any]) -> dict[str, Any]:
        host_id = site.get("hostId", "")
        ea_site_id = site.get("siteId", site.get("id", ""))
        site_name: Any = ea_site_id
        matches: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        partial: list[dict[str, str]] = []

        # Everything read from the record is inside the per-site try: a
        # malformed record (meta that is not an object, a non-string id) is skipped and
        # reported under skipped, exactly like a bad hostId; the other sites are searched.
        try:
            _labels = ea_site_labels(site)
            site_name = _labels[0] if _labels else ea_site_id
            validate_host_id(host_id, "hostId", client=client)
            if not isinstance(ea_site_id, str):
                raise wrong_type_error("siteId", ea_site_id)
        except ValueError as exc:
            return _skip(
                ea_site_id, site_name, upstream_error_text(exc, client), "invalid site record"
            )

        # The owning key: the key the site was listed under (multi-key), else resolved.
        try:
            label = context_value(site, "_keyLabel")
            key = (
                client.get_key_by_label(label)
                if isinstance(label, str)
                else await registry.resolve_key_for_host(host_id)
            )
            # Map by the Site Manager record (internal reference), not by display
            # name, so a name shared by two sites never skips a site.
            record = with_context(
                site, {"_resolvedSiteId": upstream_error_value(ea_site_id, client)}
            )
            proxy_site = await _proxy_site_for_ea(registry, record, key)
            site_id = proxy_site["id"]
            if reason := context_value(proxy_site, "_incompleteReason", strict=True):
                partial.append({"siteId": site_id, "scope": "resolution", "reason": reason})
            _assert_uuid(site_id, client=client)
        except Exception as exc:
            return _skip(
                ea_site_id,
                site_name,
                f"{type(exc).__name__}: {upstream_error_text(exc, client)}",
                f"console site resolution failed: {log_reason(exc)}",
            )
        # Each console site is searched once: two Site Manager records that resolve to
        # the same console site (one console visible to two API keys, for example) would
        # otherwise return every record of that site twice. The later one is reported.
        claim = object()
        owner = claimed_sites.setdefault((id_key(host_id), id_key(site_id)), (ea_site_id, claim))
        if owner[1] is not claim:
            return _skip(
                ea_site_id,
                site_name,
                f"console site {site_id} on {host_id} is already searched for Site "
                f"Manager site {owner[0]!r}",
                f"console site {site_id} already searched",
            )

        scopes_ok = 0
        for scope, fields in (
            # Network Integration records carry macAddress/ipAddress; mac/ip are kept
            # for records that use the short names.
            ("devices", ("name", "macAddress", "ipAddress", "mac", "ip", "model")),
            ("clients", ("name", "macAddress", "ipAddress", "mac", "ip", "hostname")),
        ):
            try:
                collected = await collect_offset(
                    client, _proxy(host_id, f"/sites/{site_id}/{scope}"), key=key
                )
                object_records(collected["items"], f"{scope} of site {site_id}")
            except (httpx.HTTPError, UniFiConnectionError, RateLimitError) as exc:
                # Status and reason code only; the complete error is under errors[].
                logger.warning(
                    "search_across_sites: %s fetch failed for %s (GET %s): %s",
                    scope,
                    site_id,
                    scope,
                    log_reason(exc),
                )
                errors.append(
                    {
                        "key": key.label if key else (labels[0] if labels else None),
                        "siteId": site_id,
                        "scope": scope,
                        "reason": upstream_error_text(exc, client),
                    }
                )
                continue
            scopes_ok += 1
            if collected["incomplete"]:
                partial.append(
                    {"siteId": site_id, "scope": scope, "reason": collected["incompleteReason"]}
                )
            for record_item in collected["items"]:
                if isinstance(record_item, dict) and _matches(record_item, fields):
                    # Where the match came from: its console and site, and (several keys
                    # configured) the key it was read with, as in list_all_clients.
                    context: dict[str, Any] = {
                        "_siteId": site_id,
                        "_siteName": site_name,
                        "_hostId": host_id,
                    }
                    if len(labels) > 1:
                        context["_keyLabel"] = key.label if key is not None else None
                    context["_type"] = "device" if scope == "devices" else "client"
                    item = with_context(record_item, context)
                    matches.append(item)

        return {
            "siteId": site_id,
            "siteName": site_name,
            "matches": matches,
            "errors": errors,
            "partial": partial,
            "searched_ok": scopes_ok > 0,
        }

    sites_data = filter_records(sites_data, lambda s: s is not None)
    results = await client.gather([_search_site(s) for s in sites_data])

    all_matches: list[dict[str, Any]] = []
    all_errors: list[dict[str, Any]] = []
    all_partial: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []
    for r in results:
        all_matches.extend(r["matches"])
        all_errors.extend(r["errors"])
        all_partial.extend(r.get("partial", []))
        if r.get("skipped"):
            skipped.append(
                {"siteId": r["siteId"], "siteName": r["siteName"], "reason": r["skipped"]}
            )

    # A site with a failed scope is failed; a site whose lists were only capped
    # (incomplete) is neither failed nor succeeded and is counted separately.
    failed_sites = {e["siteId"] for e in all_errors if e.get("scope") != "sites"}
    incomplete_sites = {p["siteId"] for p in all_partial} - failed_sites
    searched = len(sites_data) - len(skipped)
    if sites_data and not any(r.get("searched_ok") for r in results):
        # Every reason, never a sample: each skipped site and each failed scope.
        reasons = [
            f"{upstream_error_value(s['siteName'], client)} ({upstream_error_value(s['siteId'], client)}): "
            f"{upstream_error_value(s['reason'], client)}"
            for s in skipped
        ] + [
            " ".join(
                str(upstream_error_value(p, client))
                for p in (e.get("key"), e.get("siteId"), e.get("scope"))
                if p
            )
            + f": {upstream_error_value(e['reason'], client)}"
            for e in key_errors + all_errors
        ]
        raise RuntimeError(
            f"No site could be searched ({len(skipped)} skipped, {len(failed_sites)} failed): "
            + "; ".join(reasons)
        )
    response: dict[str, Any] = {
        "data": all_matches,
        "_count": len(all_matches),
        "_query": query,
        "_sitesTotal": len(sites_data),
        "_sitesSearched": searched,
        "_sitesSucceeded": searched - len(failed_sites) - len(incomplete_sites),
        "_sitesFailed": len(failed_sites),
        "_sitesIncomplete": len(incomplete_sites),
    }
    # One errors list (each failed key's site list, then each failed site scope), placed
    # once: a separate site-error assignment would push the key errors into a collision
    # bucket.
    report_keys(response, answering, key_errors + all_errors, multi=len(labels) > 1)
    if skipped:
        response["_skipped"] = skipped
    reasons = [f"site list: {upstream_error_value(r)}" for r in list_partial] + [
        f"{upstream_error_value(p['siteId'])} {upstream_error_value(p['scope'])}: "
        f"{upstream_error_value(p['reason'])}"
        for p in all_partial
    ]
    return _mark_reasons(response, reasons)


async def get_site_inventory(
    client: UniFiClient,
    registry: Registry,
    site: str,
    *,
    device_filter: str | None = None,
    client_filter: str | None = None,
) -> dict[str, Any]:
    """Get full inventory for a site: all devices and connected clients.

    site: site name or ID.
    device_filter / client_filter: optional Network Integration filter expressions,
    forwarded verbatim as the ``filter`` query parameter of the device list and of the
    client list respectively (each sent only when given, a blank one included: the
    spec's ``filter`` is any string, and the upstream judges it).
    """
    record = await _resolve_ea_site_record(registry, site, client)
    host_id = record["hostId"]
    key = await registry.resolve_key_for_host(host_id)
    proxy_site = await _proxy_site_for_ea(registry, record, key)
    site_id = proxy_site["id"]
    _assert_uuid(site_id)

    # Both lists are offset-paginated (25 per page by default): drain every page. A
    # filter is sent only when given, so the default requests are unchanged.
    device_extra: dict[str, Any] = (
        {"params": {"filter": device_filter}} if device_filter is not None else {}
    )
    client_extra: dict[str, Any] = (
        {"params": {"filter": client_filter}} if client_filter is not None else {}
    )
    # A failing list cancels (and awaits) the other: no request outlives the call.
    devices_c, clients_c = await gather_or_cancel(
        collect_offset(
            client, _proxy(host_id, f"/sites/{site_id}/devices"), key=key, **device_extra
        ),
        collect_offset(
            client, _proxy(host_id, f"/sites/{site_id}/clients"), key=key, **client_extra
        ),
    )
    devices = devices_c["items"]
    clients_list = clients_c["items"]
    result: dict[str, Any] = {
        "_siteId": site_id,
        "_devices": devices,
        "_deviceCount": len(devices),
        "_clients": clients_list,
        "_clientCount": len(clients_list),
        # Each list's upstream envelope (totalCount, traceId ...), so no key is dropped.
        "_devicesEnvelope": devices_c.get("envelope") or {},
        "_clientsEnvelope": clients_c.get("envelope") or {},
    }
    reasons = [
        f"{name}: {c['incompleteReason']}"
        for name, c in (("devices", devices_c), ("clients", clients_c))
        if c["incomplete"]
    ]
    return _resolution_metadata(_mark_reasons(result, reasons), record, proxy_site)


# Tool modules the wrappers below delegate to, imported after this module's
# own definitions so a module importing from this one never sees it half-built.
from . import _keys, site_manager  # noqa: E402


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
        """List all UniFi consoles (hosts) with firmware, WAN IP, and status.

        Returns {data: [host…], _count} with upstream envelope fields, including GPS
        coordinates. data[].id is the long composite id; reportedState.hostname/name is
        the short name. Either identifies host arguments case-insensitively; ambiguous
        names return the matching consoles so the caller can choose an id.

        Default drains all pages in batches of 200. page_size gathers native pages until
        the requested host count or the end; the full final page can exceed the total; _pageSize reports
        requested count, actual sent sizes per request,
        observed effective size and returned count. page_token accepts the unchanged
        native nextToken for one verbatim page, or the opaque _continuation string
        preserving its physical size when the requested total changes.
        Capped drains carry incomplete=true.

        With several keys, the default aggregates all keys, annotates each host with
        _keyLabel, and returns _key_labels, byKey envelopes and per-key errors. key_label
        reads one key and adds _key_labels. Paging with several keys needs key_label.

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
        """List all sites with device/client counts and ISP info.

        Returns {data: [site...], _count} plus upstream envelope fields. siteId is the
        Site Manager Fabric ObjectId, distinct from per-site proxy UUIDs. Pass site names
        such as "Default" to tools; the server resolves the appropriate id.

        Default drains all pages in batches of 200. page_size gathers native pages until
        the requested site count or the end; the full final page can exceed the total; _pageSize reports
        requested count, actual sent sizes per request,
        observed effective size and returned count. page_token accepts the unchanged
        native nextToken for one verbatim page, or the opaque _continuation string
        preserving its physical size when the requested total changes.
        Capped drains carry incomplete=true.

        With several keys, the default aggregates all keys, annotates each site with
        _keyLabel, and returns _key_labels, byKey envelopes and per-key errors. key_label
        reads one key and adds _key_labels. Paging with several keys needs key_label.

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
        """List all devices across the fleet with status, firmware, and model.

        Returns {data, _count, _consoleCount} plus upstream envelope fields. data contains
        console wrappers {hostId, hostName, devices: [...]}, unchanged; _count counts their
        devices and _consoleCount counts wrappers. Null/missing/empty devices count as 0.

        Default drains all pages in batches of 200. page_size gathers native pages until
        the requested wrapper count or the end; the full final page can exceed the total; _pageSize
        reports requested count, actual sent sizes per request, observed effective size
        and returned count. page_token accepts native nextToken for one verbatim page,
        or the opaque _continuation string preserving the physical size when the
        requested total changes. Capped drains carry incomplete.

        host filters server-side to that console on its owning key. Without host,
        key_label or paging, several keys are aggregated with _keyLabel per wrapper,
        _key_labels, byKey envelopes and per-key errors. Paging without host needs
        key_label when several keys exist; a single selected key is named in _key_labels.

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
        """Get WAN health metrics (speed, latency, packet loss, uptime).

        `interval` ('5m' or '1h') is the metric bucket size. This is the unscoped variant (every
        site the key sees); duration, or begin_timestamp/end_timestamp, bound the time range. To
        scope by console/site, use `query_isp_metrics` instead.

        Returns the upstream body verbatim: {data, httpStatusCode, traceId}. data is a list with
        one object per site, {metricType, hostId, siteId, periods}; each periods[] entry is
        {metricTime, version, data: {wan: {avgLatency, maxLatency, packetLoss, download_kbps,
        upload_kbps, uptime, downtime, ispName, ispAsn}}}. So the WAN values of a site are at
        data[i].periods[j].data.wan.

        In a multi-key deployment every configured key is queried and the result keeps the same
        data path: data holds every key's per-site objects (each with an additive _keyLabel),
        byKey (one entry per key label) holds the rest of that key's body (httpStatusCode,
        traceId), _key_labels lists the keys that answered, and a key that fails is reported
        under errors.

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
        """Query filtered ISP metrics for one or more scoped sites (via `sites`, or `host`+`site`).

        One of: `sites`, or `host`+`site` (passing both is an error, never a duplicate query).

        This is the filtered variant of `get_isp_metrics`: pass host/site to scope the query and
        start_time/end_time to bound the window. For a quick unscoped read, use `get_isp_metrics`.

        Returns the upstream body verbatim: {data: {metrics, status?, message?}, httpStatusCode,
        traceId}. data.metrics has one object per site, {metricType, hostId, siteId, periods};
        each periods[] entry is {metricTime, version, data: {wan: {...}}}. data.status /
        data.message report a partial success (some sites returned no data).

        In a multi-key deployment each site is queried on the key that owns its console. When
        the sites span several keys the result keeps the same data.metrics path: it holds every
        key's per-site objects (each with an additive _keyLabel), byKey (one entry per key
        label) holds the rest of that key's body verbatim (its data.status / data.message,
        httpStatusCode, traceId),
        _key_labels lists the keys that answered, and a key whose query fails is reported under
        errors (the call fails only when every key fails).

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

    @mcp.tool(annotations=READ_ONLY)
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

    @mcp.tool(annotations=READ_ONLY)
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
