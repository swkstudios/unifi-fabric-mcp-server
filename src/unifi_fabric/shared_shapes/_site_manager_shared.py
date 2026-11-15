"""Names the site_manager family's ``site_manager`` shares with other families.

Used by innerspace, network, site_manager. Moved verbatim by ``scripts/move_family.py`` from
``families/site_manager/site_manager.py``, which import them back where they use them, so their own
code and import paths stay.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Hashable
from typing import Any

from ..argument_errors import echoed_input
from ..client import (
    PaginationAbortedError,
    UniFiClient,
    gather_or_cancel,
    nullable_object_records,
    object_records,
)
from ..config import APIKeyConfig
from ..registry import Registry, incomplete_reason
from ..shared_shapes._device_wrappers import wrapper_devices
from ..shared_shapes._keys import (
    key_error,
    merge_first_key,
    page_mode_scope,
    report_keys,
    stable_id,
    with_context,
)
from ..shared_shapes._pagination import (
    DRAIN_PAGE_SIZE,
    bare_page,
    collect_cursor,
    cursor_continuation,
    mark_incomplete,
    validate_pagination,
    with_envelope,
)


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

    Mirrors the partial-failure pattern in ``families/site_manager/aggregation.py``
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
