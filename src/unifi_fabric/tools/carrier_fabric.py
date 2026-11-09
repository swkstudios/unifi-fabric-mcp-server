"""UniFi Carrier / ISP Fabric — Subscriber API tools (cloud, api.ui.com/v1/carrier).

The UniFi Carrier / ISP Fabric *Subscriber API* (published at
https://developer.ui.com/carrier-fabric/v1.0.0, OpenAPI 3.0.3, version 1.0.0) lets
an ISP operator's CRM / BSS manage subscribers and read service plans on the UniFi
Carrier (ISP) Fabric. It is a *cloud* resource family served directly from the Site
Manager gateway (base ``https://api.ui.com``) under ``/v1/carrier/...``. Its identity
model is the ISP **organization** that owns the API key — there is no console
``host``/``site`` resolution here (like Mobility, and unlike the Network/Protect
tools), so these tools never touch the host/site registry.

Auth is the same Fabric / Site Manager API key plumbing used everywhere else in this
server: the key is sent in the ``X-API-Key`` header (the spec's ``apiKeyAuth``
scheme), and an optional ``key_label`` selects a specific configured key for
multi-key deployments (``APIKeyConfig.label``). A key of the wrong type (the spec
requires an *ISP* key), a missing permission-whitelist scope, or a request outside a
key's subscriber-group whitelist surfaces as the upstream error verbatim (HTTP
401 ``unauthorized`` / 403 ``insufficient_scope`` / 404 / 409, with the gateway's
machine-readable ``error.code`` and ``traceId``) — the server does not mask it. The
documented, stable field to switch on is ``error.code``; never parse ``error.message``.

Test coverage: these tools are spec-conformance tested only. Every tool is exercised by
hermetic fixtures built from the published OpenAPI request/response shapes; none is
tested against a live Carrier Fabric organization. A ``verified`` flag in a write result
reports that the write response carries the requested value, as documented.

Reads are typed pass-throughs. The seven documented writes (create / patch a
subscriber; attach / detach the gateway host; assign a plan; suspend / resume) share
one flow: the area opt-out (writes are enabled by default; the ``UNIFI_WRITE_EXCEPTIONS``
entry ``family:carrier=deny`` refuses them) is checked first, then the arguments are
validated, then (for an existing subscriber) a read-before proves existence and snapshots state, an already-applied change returns
``status="no_op"`` without writing, and the write response serves as the read-after.
Every write result carries the upstream write body verbatim under ``response``, the
per-field ``changed`` map ``{field: {"from": ..., "to": ...}}``, and (for writes that
change an existing subscriber) a ``verified`` flag. Every write accepts an optional
``confirm`` argument, which is ignored. For a read-only deployment add
``family:carrier=deny`` to ``UNIFI_WRITE_EXCEPTIONS`` or set ``UNIFI_WRITE_POLICY=deny``.

Null semantics of the subscriber PATCH (spec schema ``SubscriberPatch``): an absent field
is unchanged; JSON ``null`` clears ``name``, ``email``, ``notes``, ``serviceAddress`` and
``planId``; ``subscriberNumber`` cannot be cleared; and ``metadata`` is NOT cleared by
``null`` - ``null`` leaves it unchanged, and a supplied object replaces the whole document
(send ``{}`` to empty it). Because ``metadata`` replaces rather than merges, and every
other field is a scalar, update verification compares whole field values.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from typing import Any, cast

from fastmcp import FastMCP
from pydantic import Field

from .. import switches
from ..client import (
    DrainedItems,
    PaginationAbortedError,
    UniFiClient,
    UniFiConnectionError,
    describe_shape,
    is_dry_run_preview,
    object_records,
    upstream_error_text,
    validate_id,
    validate_spec_id,
)
from ..config import APIKeyConfig
from ..matching import same_id
from ..read_only import guard_action, mark_write_denied
from ..tool_annotations import READ_ONLY, WRITE
from ..write_body import require_update_fields
from ._continuation import encode_continuation
from ._keys import (
    context_value,
    fan_out,
    first_success,
    merge_first_key,
    page_mode_scope,
    report_keys,
    stable_id,
    with_context,
    without_server_fields,
)
from ._pagination import (
    CARRIER_SUBSCRIBERS_MAX_LIMIT,
    collect_batch,
    cursor_continuation,
    mark_incomplete,
    validate_pagination,
    verbatim_list_result,
)
from ._results import (
    MISSING,
    leaf_equal,
    read_after_verdict,
    response_field,
    safe_read_after,
    short_circuit_no_op,
    with_read_after_error,
)
from ._shared import _nullable_default

#: Cloud gateway base for the Carrier / ISP Fabric family (served from api.ui.com).
CARRIER_BASE = "/v1/carrier"
_SUBSCRIBERS = f"{CARRIER_BASE}/subscribers"
_SERVICE_PLANS = f"{CARRIER_BASE}/service-plans"

#: Documented ``limit`` bound for the cursor-paginated subscriber collection
#: (OpenAPI: minimum 1, maximum 500, default 50). The drainer requests the max.
_MAX_PAGE_SIZE = 500

#: Documented ``sort`` enum for listSubscribers.
_SORT_VALUES = ("createdAt", "-createdAt", "name", "-name", "subscriberNumber", "-subscriberNumber")

#: The write exception that opts out the seven Carrier Fabric writes (``family:carrier=deny``).
WRITE_ENABLED_ENV = switches.CARRIER_WRITES.env

DISABLED_MSG = switches.area_deny_text("Carrier Fabric", WRITE_ENABLED_ENV)

#: sentinel value distinguishing "argument omitted" from "explicitly set to null" on the
#: nullable PATCH fields, so a caller can clear a nullable subscriber field.
_UNSET: Any = object()


# --- Key / gate / envelope helpers ------------------------------------------


async def _create_key(
    client: UniFiClient, key_label: str | None, plan_id: str | None
) -> APIKeyConfig | None:
    """The key a create runs on; never a silent first-key default in a multi-key setup.

    A named label wins (unknown labels fail listing the valid ones). With one key the
    default key is used. With several keys and no label, a given ``plan_id`` routes to
    the key that owns that plan (looked up on every key, like the sibling tools); with
    no plan to route by, the target organization is ambiguous and the call fails fast
    listing the configured labels.
    """
    if key_label is not None or len(client.list_key_labels()) <= 1:
        return _select_key(client, key_label)
    if plan_id is not None:
        key, _plan = await first_success(
            client, None, lambda k: client.get(f"{_SERVICE_PLANS}/{plan_id}", key=k)
        )
        return key
    labels = ", ".join(client.list_key_labels())
    raise ValueError(
        "Several API keys are configured and the subscriber's organization is ambiguous: "
        f"pass key_label (one of: {labels}) or a plan_id owned by the target organization."
    )


def _select_key(client: UniFiClient, key_label: str | None) -> APIKeyConfig | None:
    """Resolve the optional API-key label to a key config (None → default key).

    Raises ``ValueError`` (via ``get_key_by_label``, listing the valid labels) when the
    label is unknown, so a typo'd label fails loudly rather than riding the default key.
    """
    if key_label is None:
        return None
    return client.get_key_by_label(key_label)


def _require_writes(method: str) -> None:
    """Refuse a Carrier Fabric write before any upstream call when the area is opted out."""
    guard_action(method)
    if not writes_enabled():
        raise mark_write_denied(
            ValueError(DISABLED_MSG + switches.current_value_note(WRITE_ENABLED_ENV))
        )


def writes_enabled() -> bool:
    """True unless ``UNIFI_WRITE_EXCEPTIONS`` denies this area's family (read now)."""
    return switches.CARRIER_WRITES.enabled()


def _unwrap_data_obj(raw: Any) -> dict[str, Any]:
    """Return the ``data`` object from a single-resource envelope.

    An object body without a ``data`` key is returned verbatim. A ``data`` key holding
    anything but an object, or a body that is not an object, raises naming the shape
    received; it is never returned as if it were the resource.
    """
    if isinstance(raw, dict):
        if "data" not in raw:
            return raw
        inner = raw["data"]
        if isinstance(inner, dict):
            return inner
        raise UniFiConnectionError(
            "Unexpected Carrier Fabric response shape: expected 'data' to be an object, "
            f"got {describe_shape(inner)}"
        )
    raise UniFiConnectionError(
        f"Unexpected Carrier Fabric response shape: expected a JSON object, got "
        f"{describe_shape(raw)}"
    )


def _verbatim_resource(raw: Any) -> dict[str, Any]:
    """A single-resource read body, shape-checked and returned verbatim (pass-through).

    The envelope is never unwrapped: ``httpStatusCode`` / ``traceId`` and any field the
    API adds later stay beside ``data``.
    """
    _unwrap_data_obj(raw)  # raises, naming the shape, unless it carries the resource
    return cast(dict[str, Any], raw)


# --- Validation helpers ------------------------------------------------------


def _validate_len(value: Any, name: str, low: int, high: int) -> None:
    """Enforce the documented min/max character length for a string field."""
    if not isinstance(value, str):
        raise ValueError(f"{name!r} must be a string")
    if not (low <= len(value) <= high):
        raise ValueError(f"{name!r} must be {low}-{high} characters (got {len(value)})")


def _validate_subscriber_number(value: Any, *, trim: bool) -> None:
    """``subscriberNumber`` per the spec of the request it travels in. The value is sent as
    given.

    * create (``SubscriberCreate``): 1-32 characters, counted as given (the create schema
      states no trimming);
    * update (``SubscriberPatch``, ``trim=True``): 1-32 characters AFTER trimming
      (whitespace-only is rejected upstream with 400 ``validation_failed``).
    """
    if not isinstance(value, str):
        raise ValueError("'subscriber_number' must be a string")
    if not trim:
        if not 1 <= len(value) <= 32:
            raise ValueError(f"'subscriber_number' must be 1-32 characters (got {len(value)})")
        return
    trimmed = value.strip()
    if not 1 <= len(trimmed) <= 32:
        raise ValueError(
            "'subscriber_number' must be 1-32 characters after trimming surrounding "
            f"whitespace (got {len(trimmed)})"
        )


def _validate_bytes(value: Any, name: str, high: int) -> None:
    """Enforce a maximum counted in UTF-8 bytes, so a multi-byte character counts as more
    than one.

    Used only where the field's own spec description states the limit in bytes:
    SubscriberCreate / SubscriberPatch ``name`` (128), ``email`` (255), ``notes`` (4096)
    and ``serviceAddress`` (1024) each say "The N limit is bytes of UTF-8". Their schema
    ``maxLength`` keyword carries the same N, and a value of at most N bytes is also at
    most N characters, so this check satisfies both. A limit the spec states only as a
    ``maxLength`` (characters, e.g. the suspend ``reason``) is checked with
    :func:`_validate_len` instead.
    """
    if not isinstance(value, str):
        raise ValueError(f"{name!r} must be a string")
    size = len(value.encode("utf-8"))
    if size > high:
        raise ValueError(
            f"{name!r} must be at most {high} bytes of UTF-8 (got {size} bytes in "
            f"{len(value)} characters); multi-byte characters count as more than one"
        )


#: Metadata is cleared with {} and omitted by the pinned Subscriber response.
_OMITTED_WHEN_EMPTY: dict[str, Any] = {"metadata": {}}


def _current(record: dict[str, Any], wire: str) -> Any:
    """Read the pinned Subscriber omission contract without altering the response."""
    value = response_field(record, wire, spec="carrier-fabric-1.0.0.json", schema="Subscriber")
    if (value is None or value is MISSING) and wire in _OMITTED_WHEN_EMPTY:
        return copy.deepcopy(_OMITTED_WHEN_EMPTY[wire])
    return value


#: SubscriberCreate / SubscriberPatch ``metadata``: "The serialized JSON object must not
#: exceed 8192 bytes (8 KiB); a larger object is rejected with 400."
METADATA_MAX_BYTES = 8192


def _validate_metadata(value: Any, name: str = "metadata") -> None:
    """Enforce that a metadata field is a JSON object (the documented ``type: object``)
    whose serialized JSON is at most :data:`METADATA_MAX_BYTES` bytes of UTF-8, as the
    spec description states. The size is that of the most compact serialization (no
    spaces), so a document the upstream could accept is never refused."""
    if not isinstance(value, dict):
        raise ValueError(f"{name!r} must be an object (mapping)")
    size = len(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    if size > METADATA_MAX_BYTES:
        raise ValueError(
            f"{name!r} serializes to {size} bytes of JSON (UTF-8); the spec allows at most "
            f"{METADATA_MAX_BYTES} bytes ('The serialized JSON object must not exceed 8192 "
            "bytes')"
        )


# --- Cursor pagination -------------------------------------------------------


async def _paginate_cursor(
    client: UniFiClient,
    path: str,
    *,
    key: APIKeyConfig | None,
    params: dict[str, Any],
    page_size: int,
) -> DrainedItems:
    """Drain the Carrier Fabric cursor-paginated collection into a single list.

    The returned list carries the first page's envelope (every top-level key but
    ``data`` and the paging ``meta``, e.g. ``traceId``).

    The subscriber list is neither offset- nor ``nextToken``-paginated: it returns a
    ``{"data": [...], "meta": {"nextCursor": ..., "limit": N, "hasMore": bool}}``
    envelope where the follow-up page is requested with ``?cursor=<meta.nextCursor>``.
    Pages are drained until ``meta.hasMore`` is false. Every way the upstream can fail
    to finish raises ``PaginationAbortedError`` carrying the pages already gathered
    (the caller reports them with ``incomplete: true``), never a silent stop or a loop:

    * ``hasMore`` true with no ``nextCursor`` (the next page cannot be requested);
    * a page identical to the previous one (the repeat is dropped, not appended);
    * a cursor already followed earlier in this drain (a cycle such as A, B, A);
    * the opt-in ``UNIFI_PAGINATE_MAX_PAGES`` cap.
    """
    collected = await collect_batch(
        lambda controls: client.get(path, key=key, params={**params, **controls}),
        requested=None,
        known_max=CARRIER_SUBSCRIBERS_MAX_LIMIT,
        default_size=page_size,
        family="carrier",
        max_pages=client.paginate_max_pages,
        path=path,
    )
    if collected["incomplete"]:
        raise PaginationAbortedError(
            path,
            collected["pages"],
            collected["incompleteReason"],
            items=collected["items"],
            envelope=collected["envelope"],
        )
    return DrainedItems(collected["items"], None, collected["envelope"])


# --- Reads -------------------------------------------------------------------


async def list_carrier_subscribers(
    client: UniFiClient,
    *,
    plan_id: str | None = None,
    suspended: bool | None = None,
    sort: str | None = None,
    key_label: str | None = None,
    limit: int | None = None,
    cursor: str | None = None,
) -> Any:
    """List Carrier / ISP Fabric subscribers visible to the authenticated ISP key.

    Each subscriber carries ``id``, ``orgId``, ``subscriberNumber``, ``name``,
    ``email``, ``notes``, ``serviceAddress``, ``planId``, ``hostId``, ``state``
    (pending_assignment/provisioned/installed/suspended), ``suspended``,
    ``suspendReason``, and the ``*At`` timestamps, returned verbatim. The collection
    is cursor-paginated by the API (``limit``/``cursor`` with a ``meta.hasMore``
    signal); every page is drained and the complete list is returned under
    ``data`` (with ``_count`` and the first page's other envelope fields, e.g.
    ``traceId``; the paging ``meta`` describes one page and is not returned).

    plan_id: optional service-plan UUID to return only subscribers on that plan.
    suspended: optional boolean to filter by suspension state.
    sort: optional ordering — one of createdAt, -createdAt, name, -name,
        subscriberNumber, -subscriberNumber.
    key_label: optional configured API-key label to route on a specific key.
    limit: requested total, gathered across native pages of at most 500. The final
        full page is retained to avoid skipping records, so the count can exceed
        the request. _pageSize reports requested, actual sent sizes per request,
        observed effective size and returned count. Resume with cursor=_continuation
        string to preserve the physical size while changing the total.
        Raw cursor strings request one verbatim page (a bare array is returned as-is;
        otherwise an object with a data array), including a supplied limit
        and native ``meta.hasMore`` / ``meta.nextCursor`` on ONE
        key: ``key_label`` names it, and with several keys configured it is required (a
        cursor belongs to the key whose listing issued it; :func:`page_mode_scope`). The
        default (both omitted) drains every page.
    """
    native_cursor, continuation_size = cursor_continuation(cursor, "carrier")
    validate_pagination(page_size=limit, names={"page_size": "limit"})
    params: dict[str, Any] = {}
    if plan_id is not None:
        validate_spec_id(plan_id, "plan_id", uuid=True)  # query planId: format uuid
        params["planId"] = plan_id
    if suspended is not None:
        if not isinstance(suspended, bool):
            raise ValueError("suspended must be a boolean")
        params["suspended"] = suspended
    if sort is not None:
        if sort not in _SORT_VALUES:
            raise ValueError(f"Invalid sort {sort!r}: expected one of {', '.join(_SORT_VALUES)}")
        params["sort"] = sort
    if limit is not None or cursor is not None:
        page_params = dict(params)
        if limit is not None:
            page_params["limit"] = limit
        if native_cursor is not None:
            page_params["cursor"] = native_cursor
        if continuation_size is not None and limit is None:
            page_params["limit"] = continuation_size

        async def _page(key: APIKeyConfig | None) -> Any:
            if limit is not None and (cursor is None or continuation_size is not None):
                collected = await collect_batch(
                    lambda controls: client.get(
                        _SUBSCRIBERS, key=key, params={**params, **controls}
                    ),
                    requested=limit,
                    known_max=CARRIER_SUBSCRIBERS_MAX_LIMIT,
                    family="carrier",
                    token=cursor,
                    max_pages=client.paginate_max_pages,
                )
                if "raw" in collected:
                    return collected["raw"]
                result = with_context(
                    {**collected["envelope"], "data": collected["items"]},
                    {"_count": len(collected["items"])},
                )
                if collected.get("meta") is not None:
                    result["meta"] = collected["meta"]
                meta = collected.get("meta")
                if (
                    not collected["incomplete"]
                    and isinstance(meta, dict)
                    and meta.get("hasMore") is True
                    and not meta.get("nextCursor")
                ):
                    collected["incomplete"] = True
                    collected["incompleteReason"] = (
                        "meta.hasMore is true but meta.nextCursor is missing; "
                        "the next page cannot be requested"
                    )
                return mark_incomplete(result, collected)
            raw = await client.get(_SUBSCRIBERS, key=key, params=page_params)
            if isinstance(raw, list):
                return raw  # a bare-array page is returned as that array, unchanged
            # The same shape check as the drain: an object with a 'data' array.
            if not isinstance(raw, dict) or not isinstance(raw.get("data"), list):
                raise UniFiConnectionError(
                    f"Unexpected response shape from GET {_SUBSCRIBERS}: expected an object "
                    f"with a 'data' array, got {describe_shape(raw)}"
                )
            if continuation_size is not None:
                meta = raw.get("meta")
                following = meta.get("nextCursor") if isinstance(meta, dict) else None
                if isinstance(meta, dict) and meta.get("hasMore") and following is not None:
                    return with_context(
                        raw,
                        {
                            "_continuation": encode_continuation(
                                {"cursor": following, "limit": continuation_size}
                            )
                        },
                    )
            return raw

        _label, page_key = page_mode_scope(
            client, key_label, tool="list_carrier_subscribers", paging="limit/cursor"
        )
        return await _page(page_key)

    async def _fetch(key: APIKeyConfig | None) -> tuple[list[Any], str | None, dict[str, Any]]:
        try:
            items = await _paginate_cursor(
                client, _SUBSCRIBERS, key=key, params=params, page_size=_MAX_PAGE_SIZE
            )
            object_records(items, f"GET {_SUBSCRIBERS}")
            return items, None, items.envelope
        except PaginationAbortedError as exc:
            # Keep every page gathered and say why the drain stopped instead of
            # discarding them.
            object_records(exc.items, f"GET {_SUBSCRIBERS}")
            return exc.items, exc.reason, exc.envelope

    results, errors, multi = await fan_out(client, key_label, _fetch)
    reasons: list[str] = []
    for label, (_items, reason, _env) in results:
        if reason:
            reasons.append(f"{label}: {reason}" if multi else reason)
    # A subscriber visible to several keys is listed once, under the first key in order.
    subscribers = merge_first_key(
        [(label, items) for label, (items, _reason, _env) in results], stable_id("id"), multi=multi
    )
    out: dict[str, Any] = {"data": subscribers}
    # The first page's envelope fields (traceId ...): beside the records with one key,
    # under byKey[<label>] when several keys are merged. Server metadata goes beside the
    # envelope through with_context, so a colliding upstream field keeps its value.
    if not multi and results:
        out = {**results[0][1][2], **out}
    out = with_context(out, {"_count": len(subscribers)})
    if multi:
        out["byKey"] = {str(label): env for label, (_i, _r, env) in results}
    if reasons:
        out = with_context(out, {"incomplete": True, "incompleteReason": "; ".join(reasons)})
    return report_keys(out, [label for label, _ in results], errors, multi=multi)


async def get_carrier_subscriber(
    client: UniFiClient,
    subscriber_id: str,
    *,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Get one Carrier / ISP Fabric subscriber by ID.

    Returns the upstream response object verbatim: the Subscriber under ``data`` beside
    every envelope field the API sends (``httpStatusCode``, ``traceId``). A subscriber
    outside the key's whitelist, or an unknown id, surfaces the upstream
    ``subscriber_not_found`` (404) verbatim.

    subscriber_id: the subscriber UUID from list_carrier_subscribers.
    key_label: optional configured API-key label to route on a specific key.
    """
    validate_id(subscriber_id, "subscriber_id")
    _key, raw = await first_success(
        client, key_label, lambda key: client.get(f"{_SUBSCRIBERS}/{subscriber_id}", key=key)
    )
    return _verbatim_resource(raw)


async def list_carrier_service_plans(
    client: UniFiClient,
    *,
    key_label: str | None = None,
) -> dict[str, Any]:
    """List the Carrier / ISP Fabric service plans for the authenticated organization.

    Each plan carries ``id``, ``orgId``, ``name``, ``status`` (active/archived),
    ``downloadMbps``, ``uploadMbps``, ``metadata`` and the ``*At`` timestamps. The
    upstream body is returned verbatim (``data``, ``httpStatusCode``, ``traceId`` ...)
    plus ``_count``; a reported total above the rows returned marks it ``incomplete``.
    This endpoint is not query-paginated by the API; the full set is returned in one
    call. With several keys the plans are merged under ``data`` and each key's other
    body fields are kept under ``byKey[<label>]``.

    key_label: optional configured API-key label to route on a specific key.
    """

    async def _fetch(key: APIKeyConfig | None) -> dict[str, Any]:
        raw = await client.get(_SERVICE_PLANS, key=key)
        data = raw.get("data") if isinstance(raw, dict) else None
        if not isinstance(data, list):
            raise UniFiConnectionError(
                f"Unexpected response shape from GET {_SERVICE_PLANS}: expected an object "
                f"with a 'data' array, got {describe_shape(raw)}"
            )
        return verbatim_list_result(
            raw, object_records(data, f"GET {_SERVICE_PLANS}"), _SERVICE_PLANS
        )

    results, errors, multi = await fan_out(client, key_label, _fetch)
    if not multi:
        return results[0][1]
    plans = merge_first_key(
        [(label, part["data"]) for label, part in results], stable_id("id"), multi=True
    )
    # The merge recomputes these; an upstream field of the same name stays under byKey.
    owned = {"_count", "incomplete", "incompleteReason"}
    out: dict[str, Any] = {
        "data": plans,
        "_count": len(plans),
        "byKey": {
            str(label): {k: v for k, v in without_server_fields(part, owned).items() if k != "data"}
            for label, part in results
        },
    }
    reasons = [
        f"{label}: {context_value(part, 'incompleteReason', strict=True)}"
        for label, part in results
        if context_value(part, "incomplete", strict=True)
    ]
    if reasons:
        out["incomplete"] = True
        out["incompleteReason"] = "; ".join(reasons)
    return report_keys(out, [label for label, _ in results], errors, multi=True)


async def get_carrier_service_plan(
    client: UniFiClient,
    plan_id: str,
    *,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Get one Carrier / ISP Fabric service plan by ID.

    Returns the upstream response object verbatim: the ServicePlan under ``data`` beside
    every envelope field the API sends (``httpStatusCode``, ``traceId``). An unknown
    id surfaces the upstream ``service_plan_not_found`` (404) verbatim.

    plan_id: the service-plan UUID from list_carrier_service_plans.
    key_label: optional configured API-key label to route on a specific key.
    """
    validate_id(plan_id, "plan_id")
    _key, raw = await first_success(
        client, key_label, lambda key: client.get(f"{_SERVICE_PLANS}/{plan_id}", key=key)
    )
    return _verbatim_resource(raw)


# --- Writes ------------------------------------------------------------------
#
# All seven writes share the guarded flow, in this order:
#   1. env gate    — the write opt-out (writes enabled by default; the
#                    UNIFI_WRITE_EXCEPTIONS entry family:carrier=deny or
#                    UNIFI_WRITE_POLICY=deny makes them read-only) refuses
#                    before any validation or upstream call when set;
#   2. validate    — enforce the documented field constraints locally;
#   3. read-before — (mutations of an existing subscriber) GET it: proves existence
#                    and snapshots the current, observable state;
#   4. no-op       — if the change is fully observable AND already applied, return
#                    status="no_op" without writing;
#   5. write       — issue it. Every Carrier write is documented to answer 200/201 with
#                    the updated resource, which serves as the read-after; a body that
#                    does not carry it is read back with a GET. The body is returned
#                    verbatim under ``response`` either way, never raised.


async def _fetch_subscriber(
    client: UniFiClient, subscriber_id: str, key: APIKeyConfig | None
) -> dict[str, Any]:
    """GET a subscriber (read-before / read-after): the body verbatim, shape-checked.

    The envelope is never unwrapped, so it is what a write result embeds; callers read
    the subscriber fields for their comparisons with ``_unwrap_data_obj``.
    """
    raw = await client.get(f"{_SUBSCRIBERS}/{subscriber_id}", key=key)
    return _verbatim_resource(raw)


#: Body fields that carry an id: compared with the shared id rule (exact, or ignoring
#: case for an id made of hex digits and ``-`` / ``:``), never case-sensitively.
_ID_FIELDS = frozenset({"planId", "hostId"})


def _field_matches(record: dict[str, Any], wire: str, value: Any) -> bool:
    """True when ``record``'s ``wire`` field already holds ``value``.

    An id field (:data:`_ID_FIELDS`) set to a string compares with
    :func:`~unifi_fabric.matching.same_id`, so an upper-case spelling of the current
    plan / host id is the same id (a no-op, and a verified write); every other field
    compares with ``leaf_equal``.
    """
    current = _current(record, wire)
    if wire in _ID_FIELDS and isinstance(value, str):
        return same_id(value, current)
    return leaf_equal(current, value)


def _upstream_subscriber_id(before: dict[str, Any], subscriber_id: str) -> str:
    """The subscriber id as the read-before reported it, when it names the same record
    (:func:`~unifi_fabric.matching.same_id`); the write and its read-back then address
    the subscriber by the upstream spelling, never the caller's."""
    upstream = before.get("id")
    if isinstance(upstream, str) and same_id(subscriber_id, upstream):
        return upstream
    return subscriber_id


def _changed(before: dict[str, Any], wanted: dict[str, Any]) -> dict[str, Any]:
    """``{field: {"from": before, "to": wanted}}`` for every field the write changes."""
    return {
        wire: {"from": before.get(wire), "to": value}
        for wire, value in wanted.items()
        if not _field_matches(before, wire, value)
    }


def _no_op(reason: str, before_body: dict[str, Any]) -> dict[str, Any]:
    """A no-op result; ``subscriber`` is the read-before GET body verbatim."""
    return {"status": "no_op", "reason": reason, "subscriber": before_body}


def _dry_run_result(before_body: dict[str, Any], raw: Any) -> dict[str, Any]:
    """Result of a guarded write under ``dry-run policy``: the preview, no read-after.

    No write was sent: the preview is not the updated subscriber, and a read-back would
    only show the unchanged one. ``subscriber`` is the read-before GET body verbatim.
    """
    return {"status": "dry_run", "subscriber": before_body, "response": raw}


def _carries_resource(raw: Any) -> bool:
    """True when a write body is the documented resource envelope carrying the resource.

    The documented 200/201 body is ``{"data": {<subscriber>}, "traceId": ...}``. Only a
    ``data`` object that carries an ``id`` counts: a stub such as ``{}`` or
    ``{"httpStatusCode": 204}`` is not the resource, so the caller reads it back with a
    GET instead of presenting the stub as the subscriber.
    """
    if not isinstance(raw, dict):
        return False
    data = raw.get("data")
    return isinstance(data, dict) and isinstance(data.get("id"), str) and bool(data["id"])


async def _after_write(
    client: UniFiClient, subscriber_id: str, key: APIKeyConfig | None, raw: Any
) -> tuple[dict[str, Any] | None, str | None]:
    """The read-after body of a write, verbatim (never unwrapped).

    The documented 200 body carries the updated subscriber, so it is the read-after
    itself. The write has already happened when the body arrives, so a body that does
    not carry the resource (empty, text, or another shape) is not an error: it is
    returned verbatim under ``response`` by the caller, and the subscriber is read back
    with a GET whose full body is returned.
    """
    if _carries_resource(raw) and same_id(subscriber_id, raw["data"]["id"]):
        return cast(dict[str, Any], raw), None
    # The write already happened: a failing read-back is reported, never raised.
    body, error = await safe_read_after(lambda: _fetch_subscriber(client, subscriber_id, key))
    if error is None:
        try:
            matches = same_id(subscriber_id, _unwrap_data_obj(body).get("id"))
        except UniFiConnectionError as exc:
            return body, str(exc)
        if not matches:
            return body, "Read-after subscriber identity does not match the addressed subscriber"
    return body, error


def _written(
    status: str,
    changed: dict[str, Any],
    after_body: dict[str, Any] | None,
    error: str | None,
    raw: Any,
    check: Any,
    **extra: Any,
) -> dict[str, Any]:
    """The result of an applied write (:func:`read_after_verdict`). ``verified`` is
    ``check(after)`` over the read-after subscriber; it is null when the read-back failed,
    returned no object or an envelope that cannot be matched (``readAfterError`` says
    why), never a raised error after the write was applied."""
    verified, error = read_after_verdict(
        after_body, error, lambda body: check(_unwrap_data_obj(body))
    )
    result = {
        "status": status,
        "changed": changed,
        **extra,
        "verified": verified,
        "subscriber": after_body,
        "response": raw,
    }
    return with_read_after_error(result, error)


def _prev_host_id(raw: Any) -> Any:
    """``prevHostId`` from a HostLinkResponse envelope (it sits beside ``data``)."""
    return raw.get("prevHostId") if isinstance(raw, dict) else None


async def create_carrier_subscriber(
    client: UniFiClient,
    subscriber_number: str,
    *,
    name: str | None = None,
    email: str | None = None,
    notes: str | None = None,
    service_address: str | None = _UNSET,
    plan_id: str | None = None,
    metadata: dict[str, Any] | None = None,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Create a Carrier / ISP Fabric subscriber (POST /v1/carrier/subscribers). Guarded write.

    Sends the documented SubscriberCreate body. ``subscriber_number`` is required
    (1-32 chars, unique within the org). Optional: ``name`` (<=128), ``email``
    (<=255), ``notes`` (<=4096), ``service_address`` (<=1024), ``plan_id`` (a service
    plan UUID; an archived/unknown plan is rejected upstream), and ``metadata`` (an
    opaque JSON object). There is no read-before/no-op for a create. Returns
    ``{status: "created", changed, subscriber, response}``: ``subscriber`` is the
    created resource from the 201 body (null when the body does not carry it),
    ``changed`` maps every sent field to ``{from: null, to}``.

    subscriber_number: the unique subscriber number (1-32 characters).
    name/email/notes/service_address: optional profile fields (see length limits above).
    service_address: explicit None is sent as JSON null; omission leaves the field absent.
    plan_id: optional service-plan UUID to assign at creation.
    metadata: optional opaque JSON object.
    key_label: optional configured API-key label to route on a specific key. In a
        multi-key deployment an omitted label routes to the key owning ``plan_id``; with
        no ``plan_id`` it fails fast listing the labels (never a first-key default).
    """
    _require_writes("POST")
    _validate_subscriber_number(subscriber_number, trim=False)
    body: dict[str, Any] = {"subscriberNumber": subscriber_number}
    if name is not None:
        _validate_bytes(name, "name", 128)
        body["name"] = name
    if email is not None:
        _validate_bytes(email, "email", 255)
        body["email"] = email
    if notes is not None:
        _validate_bytes(notes, "notes", 4096)
        body["notes"] = notes
    if service_address is not _UNSET:
        if service_address is not None:
            _validate_bytes(service_address, "service_address", 1024)
        body["serviceAddress"] = service_address
    if plan_id is not None:
        validate_spec_id(plan_id, "plan_id", uuid=True)  # body planId: format uuid
        body["planId"] = plan_id
    if metadata is not None:
        _validate_metadata(metadata)
        body["metadata"] = metadata

    raw = await client.post(
        _SUBSCRIBERS, key=await _create_key(client, key_label, plan_id), json=body
    )
    if is_dry_run_preview(raw):
        # dry-run policy: nothing was created; the preview is not the new subscriber.
        return {"status": "dry_run", "subscriber": None, "response": raw}
    return {
        "status": "created",
        "changed": {wire: {"from": None, "to": value} for wire, value in body.items()},
        # the 201 body verbatim when it carries the resource (never unwrapped); an empty or
        # non-resource body leaves no id to read back: reported as null
        "subscriber": raw if _carries_resource(raw) else None,
        "response": raw,
    }


async def update_carrier_subscriber(
    client: UniFiClient,
    subscriber_id: str,
    *,
    subscriber_number: str = _UNSET,
    name: str | None = _UNSET,
    email: str | None = _UNSET,
    notes: str | None = _UNSET,
    service_address: str | None = _UNSET,
    plan_id: str | None = _UNSET,
    metadata: dict[str, Any] | None = _UNSET,
    confirm: bool = False,
    key_label: str | None = None,
    _preserve_subscriber_number: bool = False,
) -> dict[str, Any]:
    """Update a Carrier Fabric subscriber (PATCH .../subscribers/{id}).

    This is a DOCUMENTED partial update: only the fields you pass are sent, and any
    field you omit is left unchanged. At least one field must be provided. The
    nullable fields (``name``, ``email``, ``notes``, ``service_address``, ``plan_id``)
    accept an explicit ``None``, sent as JSON null, which clears them. ``metadata=None``
    leaves metadata UNCHANGED per the spec; metadata=null alone is a no-op. It is
    sent as JSON null only alongside another change (pass
    ``{}`` to empty it; an object replaces the whole document), so it is not compared
    for the no-op check or ``verified``. ``subscriber_number`` is not nullable (1-32
    chars when provided). Guarded: read-before, no-op when every provided field already
    matches the current subscriber, and a read-after from the PATCH response (200).
    ``verified`` is true when the response carries every sent value.

    subscriber_id: the subscriber UUID from list_carrier_subscribers.
    subscriber_number: optional new subscriber number (1-32 characters).
    name/email/notes/service_address/plan_id: optional new values; pass None to clear
        the field. Fields not passed are left untouched. A ``name`` value must be non-empty
        after trimming (SubscriberPatch).
    metadata: optional replacement object; metadata=null alone is a no-op. Alongside
        another change, None is sent as null and leaves metadata unchanged (spec). The spec omits
        ``metadata`` from a subscriber that has none, so
        an absent key compares equal to ``{}`` (no-op and ``verified``).
    key_label: optional configured API-key label to route on a specific key.
    """
    _require_writes("PATCH")
    validate_id(subscriber_id, "subscriber_id")

    # The partial body carries only the provided (non-sentinel) fields.
    body: dict[str, Any] = {}
    if subscriber_number is not _UNSET:
        _validate_subscriber_number(subscriber_number, trim=True)
        # Retain the direct-helper normalization contract; MCP opts into raw forwarding.
        body["subscriberNumber"] = (
            subscriber_number if _preserve_subscriber_number else subscriber_number.strip()
        )
    if name is not _UNSET:
        if name is not None:
            _validate_bytes(name, "name", 128)
            # SubscriberPatch.name: "a value must be non-empty after trimming".
            if not name.strip():
                raise ValueError(
                    "'name' must be non-empty after trimming surrounding whitespace (the "
                    "spec rejects an empty or whitespace-only name); clear it with "
                    "clear_fields instead"
                )
        body["name"] = name
    if email is not _UNSET:
        if email is not None:
            _validate_bytes(email, "email", 255)
        body["email"] = email
    if notes is not _UNSET:
        if notes is not None:
            _validate_bytes(notes, "notes", 4096)
        body["notes"] = notes
    if service_address is not _UNSET:
        if service_address is not None:
            _validate_bytes(service_address, "service_address", 1024)
        body["serviceAddress"] = service_address
    if plan_id is not _UNSET:
        if plan_id is not None:
            validate_spec_id(plan_id, "plan_id", uuid=True)  # body planId: uuid, nullable
        body["planId"] = plan_id
    if metadata is not _UNSET:
        if metadata is not None:
            _validate_metadata(metadata)
        body["metadata"] = metadata

    # The server's one empty-update guard (metadata={} is a value: it empties the doc).
    require_update_fields(
        body,
        "subscriber (subscriber_number, name, email, notes, service_address, plan_id, "
        "metadata; or clear_fields)",
        opaque=frozenset({"metadata"}),
    )

    key, before_body = await first_success(
        client, key_label, lambda k: _fetch_subscriber(client, subscriber_id, k)
    )
    before = _unwrap_data_obj(before_body)
    if not same_id(subscriber_id, before.get("id")):
        raise UniFiConnectionError(
            "Read-before subscriber identity does not match the addressed subscriber "
            f"(addressed {subscriber_id!r}, "
            f"read {upstream_error_text(before.get('id'), client)!r}); "
            "no write was sent"
        )
    subscriber_id = _upstream_subscriber_id(before, subscriber_id)
    # metadata=null is a documented "leave unchanged", so it is no change to compare.
    # Every other field is a scalar and metadata replaces the whole document, so whole
    # values are compared (no nested merge applies to this PATCH).
    # SubscriberPatch trims the number upstream: compare its canonical value without
    # rewriting the submitted request body.
    compared = {
        w: v.strip() if w == "subscriberNumber" else v
        for w, v in body.items()
        if not (w == "metadata" and v is None)
    }
    # A field the spec omits when empty reads as that empty value (metadata {}), so
    # metadata={} over a subscriber with no metadata is a no-op and verifies.
    applied = all(_field_matches(before, w, value) for w, value in compared.items())
    if short_circuit_no_op(client, applied):
        return _no_op(
            "Every provided field already matches the subscriber; no write performed.", before_body
        )

    raw = await client.patch(f"{_SUBSCRIBERS}/{subscriber_id}", key=key, json=body)
    if is_dry_run_preview(raw):
        return _dry_run_result(before_body, raw)
    after_body, error = await _after_write(client, subscriber_id, key, raw)
    return _written(
        "updated",
        _changed(before, compared),
        after_body,
        error,
        raw,
        lambda after: all(_field_matches(after, w, v) for w, v in compared.items()),
    )


async def attach_carrier_subscriber_host(
    client: UniFiClient,
    subscriber_id: str,
    host_id: str,
    *,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Attach or re-link a subscriber's gateway host (PUT .../subscribers/{id}/host). Guarded.

    Sends the documented body ``{"hostId": host_id}``. ``host_id`` must be a host in
    the same ISP organization (an out-of-org host, or a gateway already attached
    elsewhere, is rejected upstream — 400 ``host_not_in_organization`` / 409
    ``gateway_already_attached``). Guarded: read-before, no-op when the subscriber is
    already linked to this host, and a read-after from the response (200
    HostLinkResponse; its envelope-level ``prevHostId`` is also reported as ``_prev_host_id``).

    subscriber_id: the subscriber UUID from list_carrier_subscribers.
    host_id: the gateway host id to link (as reported by the host directory).
    key_label: optional configured API-key label to route on a specific key.
    """
    _require_writes("PUT")
    validate_id(subscriber_id, "subscriber_id")
    # Body-only (HostLinkRequest.hostId: string, maxLength 128): validated per the spec,
    # not by path rules - it never reaches a URL path.
    validate_spec_id(host_id, "host_id", max_length=128)

    key, before_body = await first_success(
        client, key_label, lambda k: _fetch_subscriber(client, subscriber_id, k)
    )
    before = _unwrap_data_obj(before_body)
    subscriber_id = _upstream_subscriber_id(before, subscriber_id)
    if short_circuit_no_op(client, _field_matches(before, "hostId", host_id)):
        return _no_op(
            f"Subscriber is already linked to host {host_id!r}; no write performed.", before_body
        )

    raw = await client.put(
        f"{_SUBSCRIBERS}/{subscriber_id}/host", key=key, json={"hostId": host_id}
    )
    if is_dry_run_preview(raw):
        return _dry_run_result(before_body, raw)
    after_body, error = await _after_write(client, subscriber_id, key, raw)
    return _written(
        "attached",
        _changed(before, {"hostId": host_id}),
        after_body,
        error,
        raw,
        lambda after: _field_matches(after, "hostId", host_id),
        _prev_host_id=_prev_host_id(raw),
    )


async def detach_carrier_subscriber_host(
    client: UniFiClient,
    subscriber_id: str,
    *,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Detach a subscriber's gateway host (DELETE .../subscribers/{id}/host). Guarded write.

    Takes no body. Guarded: read-before, no-op when the subscriber has no attached
    host (``hostId`` is null — the upstream would otherwise answer 409
    ``no_attached_host``), and a read-after from the response (200 HostLinkResponse;
    its envelope-level ``prevHostId`` names the just-detached host and is also reported as
    ``_prev_host_id``).

    subscriber_id: the subscriber UUID from list_carrier_subscribers.
    key_label: optional configured API-key label to route on a specific key.
    """
    _require_writes("DELETE")
    validate_id(subscriber_id, "subscriber_id")
    key, before_body = await first_success(
        client, key_label, lambda k: _fetch_subscriber(client, subscriber_id, k)
    )
    before = _unwrap_data_obj(before_body)
    subscriber_id = _upstream_subscriber_id(before, subscriber_id)
    if short_circuit_no_op(client, "hostId" in before and before["hostId"] in (None, "")):
        return _no_op("Subscriber has no attached host; no write performed.", before_body)

    raw = await client.delete(f"{_SUBSCRIBERS}/{subscriber_id}/host", key=key)
    if is_dry_run_preview(raw):
        return _dry_run_result(before_body, raw)
    after_body, error = await _after_write(client, subscriber_id, key, raw)
    return _written(
        "detached",
        _changed(before, {"hostId": None}),
        after_body,
        error,
        raw,
        lambda after: "hostId" in after and after["hostId"] in (None, ""),
        _prev_host_id=_prev_host_id(raw),
    )


async def assign_carrier_subscriber_plan(
    client: UniFiClient,
    subscriber_id: str,
    plan_id: str,
    *,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Assign a service plan to a subscriber (PUT .../subscribers/{id}/plan). Guarded write.

    Sends the documented body ``{"planId": plan_id}``. An archived or unknown plan is
    rejected upstream (400 ``service_plan_archived`` / 404 ``service_plan_not_found``).
    Guarded: read-before, no-op when the subscriber is already on this plan, and a
    read-after from the response (200).

    subscriber_id: the subscriber UUID from list_carrier_subscribers.
    plan_id: the service-plan UUID to assign (from list_carrier_service_plans).
    key_label: optional configured API-key label to route on a specific key.
    """
    _require_writes("PUT")
    validate_id(subscriber_id, "subscriber_id")
    validate_spec_id(plan_id, "plan_id", uuid=True)  # body planId: format uuid

    key, before_body = await first_success(
        client, key_label, lambda k: _fetch_subscriber(client, subscriber_id, k)
    )
    before = _unwrap_data_obj(before_body)
    subscriber_id = _upstream_subscriber_id(before, subscriber_id)
    if short_circuit_no_op(client, _field_matches(before, "planId", plan_id)):
        return _no_op(
            f"Subscriber is already on plan {plan_id!r}; no write performed.", before_body
        )

    raw = await client.put(
        f"{_SUBSCRIBERS}/{subscriber_id}/plan", key=key, json={"planId": plan_id}
    )
    if is_dry_run_preview(raw):
        return _dry_run_result(before_body, raw)
    after_body, error = await _after_write(client, subscriber_id, key, raw)
    return _written(
        "assigned",
        _changed(before, {"planId": plan_id}),
        after_body,
        error,
        raw,
        lambda after: _field_matches(after, "planId", plan_id),
    )


async def suspend_carrier_subscriber(
    client: UniFiClient,
    subscriber_id: str,
    *,
    reason: str | None = None,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Suspend a subscriber's service (POST .../subscribers/{id}/suspend). Guarded write.

    Sends the documented body ``{"reason": reason}`` when a reason is supplied (the body is
    optional per the spec; an omitted reason sends no body). Guarded: read-before, no-op only
    when the subscriber is already suspended and the reason is omitted or already equals
    ``suspendReason`` (a different reason is sent upstream, which decides), and a read-after
    from the response (200). ``changed`` reports ``suspended`` (and ``suspendReason`` when a
    reason is sent).

    subscriber_id: the subscriber UUID from list_carrier_subscribers.
    reason: optional free-text suspension reason recorded on the subscriber.
    key_label: optional configured API-key label to route on a specific key.
    """
    _require_writes("POST")
    validate_id(subscriber_id, "subscriber_id")
    if reason is not None:
        # The suspend body's reason: string, maxLength 1024 (characters; no byte unit).
        _validate_len(reason, "reason", 0, 1024)

    key, before_body = await first_success(
        client, key_label, lambda k: _fetch_subscriber(client, subscriber_id, k)
    )
    before = _unwrap_data_obj(before_body)
    subscriber_id = _upstream_subscriber_id(before, subscriber_id)
    already = before.get("suspended") is True and (
        reason is None or leaf_equal(before.get("suspendReason"), reason)
    )
    if short_circuit_no_op(client, already):
        return _no_op("Subscriber is already suspended; no write performed.", before_body)

    body = {"reason": reason} if reason is not None else None
    raw = await client.post(f"{_SUBSCRIBERS}/{subscriber_id}/suspend", key=key, json=body)
    if is_dry_run_preview(raw):
        return _dry_run_result(before_body, raw)
    after_body, error = await _after_write(client, subscriber_id, key, raw)
    wanted: dict[str, Any] = {"suspended": True}
    if reason is not None:
        wanted["suspendReason"] = reason
    return _written(
        "suspended",
        _changed(before, wanted),
        after_body,
        error,
        raw,
        lambda after: all(_field_matches(after, field, value) for field, value in wanted.items()),
    )


async def resume_carrier_subscriber(
    client: UniFiClient,
    subscriber_id: str,
    *,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Resume a suspended subscriber's service (POST .../subscribers/{id}/resume). Guarded.

    Takes no body. Guarded: read-before, no-op when the subscriber is not currently
    suspended, and a read-after from the response (200). ``changed`` reports
    ``suspended``.

    subscriber_id: the subscriber UUID from list_carrier_subscribers.
    key_label: optional configured API-key label to route on a specific key.
    """
    _require_writes("POST")
    validate_id(subscriber_id, "subscriber_id")
    key, before_body = await first_success(
        client, key_label, lambda k: _fetch_subscriber(client, subscriber_id, k)
    )
    before = _unwrap_data_obj(before_body)
    subscriber_id = _upstream_subscriber_id(before, subscriber_id)
    if short_circuit_no_op(client, before.get("suspended") is False):
        return _no_op("Subscriber is not suspended; no write performed.", before_body)

    raw = await client.post(f"{_SUBSCRIBERS}/{subscriber_id}/resume", key=key, json=None)
    if is_dry_run_preview(raw):
        return _dry_run_result(before_body, raw)
    after_body, error = await _after_write(client, subscriber_id, key, raw)
    return _written(
        "resumed",
        _changed(before, {"suspended": False}),
        after_body,
        error,
        raw,
        lambda after: after.get("suspended") is False,
    )


# Tool modules the wrappers below delegate to, imported after this module's
# own definitions so a module importing from this one never sees it half-built.
from . import carrier_fabric  # noqa: E402


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> dict[str, Callable[..., Any]]:
    """Register the carrier_fabric tool wrappers moved from server.py, in order.

    Returns the registered wrapper functions by name; server.py re-exports them.
    """

    @mcp.tool(annotations=READ_ONLY)
    async def list_carrier_subscribers(
        plan_id: str | None = None,
        suspended: bool | None = None,
        sort: str | None = None,
        key_label: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        """List Carrier / ISP Fabric subscribers visible to the authenticated ISP key.

        Returns {data, _count} and the first page's envelope fields; several keys put
        envelopes under byKey, annotate records with _keyLabel, and report per-key
        errors. incomplete/incompleteReason appear when a drain stops early. A bare-array
        page is returned as an array; an object without a data array raises.
        Spec-conformance tested only, without live Carrier.

        Default drains every cursor page. limit requests that many subscribers, or all
        available if fewer exist, gathered in native pages up to the spec maximum 500;
        the full final page can exceed limit to preserve its native continuation;
        _pageSize reports requested count, actual sent sizes per request,
        observed effective size and returned count. cursor selects the
        starting meta.nextCursor; alone, it fetches one page with its native meta
        continuation. With several keys, limit/cursor needs key_label.

        Args:
            plan_id: Optional service-plan UUID from list_carrier_service_plans (id).
                Example: "3fa85f64-5717-4562-b3fc-2c963f66afa6".
            suspended: Optional filter: true for suspended, false for active. Example: false.
            sort: createdAt|-createdAt|name|-name|subscriberNumber|-subscriberNumber.
                Example: "-createdAt".
            key_label: Configured API-key label from list_configured_api_keys; omit to
                aggregate all keys. Required with limit/cursor and several keys.
                Example: "primary".
            limit: Requested subscriber count, gathered in batches up to 500. Example: `100`.
            cursor: Raw meta.nextCursor for one verbatim page, or the returned opaque
                _continuation string preserving physical size when changing the requested limit.
                Example: the token from the previous response.
        """
        client, _ = deps_fn()
        return await carrier_fabric.list_carrier_subscribers(
            client,
            plan_id=plan_id,
            suspended=suspended,
            sort=sort,
            key_label=key_label,
            limit=limit,
            cursor=cursor,
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_carrier_subscriber(
        subscriber_id: str,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """Get one Carrier / ISP Fabric subscriber by ID.

        Spec-conformance tested only (not against a live Carrier Fabric).
        Returns the upstream response object verbatim: the Subscriber under data beside
        httpStatusCode and traceId; an unknown id surfaces the upstream
        subscriber_not_found (404) verbatim.

        Example call (get_carrier_subscriber):
            {"subscriber_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        Args:
            subscriber_id: Carrier Fabric subscriber UUID. Get it from list_carrier_subscribers (id).
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
                whichever configured key owns the object: every key is tried and the first that answers
                is used.
        """
        client, _ = deps_fn()
        return await carrier_fabric.get_carrier_subscriber(
            client, subscriber_id, key_label=key_label
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_carrier_service_plans(
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """List the Carrier / ISP Fabric service plans for the authenticated organization.

        Returns the upstream body verbatim ({data, httpStatusCode, traceId, ...}) plus _count; with
        several keys {data, _count, byKey} plus errors.

        Spec-conformance tested only (not against a live Carrier Fabric).
        Not query-
        paginated by the API; the full set is returned under data (the upstream key), with the
        additive _count.

        Args:
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to cover
                every configured key: results are merged, each record carries an additive _keyLabel, and
                a key that fails is reported under errors.
        """
        client, _ = deps_fn()
        return await carrier_fabric.list_carrier_service_plans(client, key_label=key_label)

    @mcp.tool(annotations=READ_ONLY)
    async def get_carrier_service_plan(
        plan_id: str,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """Get one Carrier / ISP Fabric service plan by ID.

        Spec-conformance tested only (not against a live Carrier Fabric).
        Returns the upstream response object verbatim: the ServicePlan under data beside
        httpStatusCode and traceId. An unknown id
        surfaces the upstream service_plan_not_found (404) verbatim.

        Example call (get_carrier_service_plan):
            {"plan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        Args:
            plan_id: Carrier Fabric service-plan UUID. Get it from list_carrier_service_plans (id).
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
                whichever configured key owns the object: every key is tried and the first that answers
                is used.
        """
        client, _ = deps_fn()
        return await carrier_fabric.get_carrier_service_plan(client, plan_id, key_label=key_label)

    @mcp.tool(annotations=WRITE)
    async def create_carrier_subscriber(
        subscriber_number: str,
        name: str | None = None,
        email: str | None = None,
        notes: str | None = None,
        service_address: str | None = Field(default_factory=lambda: carrier_fabric._UNSET),
        plan_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        confirm: bool = False,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """Create a Carrier / ISP Fabric subscriber (POST /v1/carrier/subscribers). Guarded write.

        Returns {status: "created", changed (every sent field as {from: null, to}), subscriber (the
        201 body verbatim, {data, traceId}, when it carries the created resource, else null),
        response (the upstream write body verbatim)}.
        Under dry-run policy nothing is sent: {status: "dry_run", subscriber: null, response (the
        preview)}.

        Spec-conformance tested only (not against a live Carrier Fabric).
        subscriber_number is required (1-32 chars). Optional name (<=128 bytes),
        email (<=255 bytes), notes (<=4096 bytes), service_address (<=1024 bytes), plan_id (UUID),
        metadata (object). Per the spec those limits are bytes of UTF-8, so a multi-byte character
        counts as more than one. Refused when UNIFI_WRITE_POLICY=deny or the
        UNIFI_WRITE_EXCEPTIONS entry family:carrier=deny is set (writes are enabled by default).

        Request body (Carrier Fabric 1.0.0, POST /v1/carrier/subscribers (createSubscriber); schema
        "SubscriberCreate") is built from scalar parameters. Required keys — subscriberNumber.
        - subscriberNumber: string
        - name: string
        - email: string(email)
        - notes: string
        - serviceAddress: string
        - planId: string(uuid)
        - metadata: object

        Example call (create_carrier_subscriber):
            {"subscriber_number": "SUB-1001"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            subscriber_number: Unique subscriber number, 1-32 chars. REQUIRED (body field
                subscriberNumber: string).
            name: Subscriber display name. Optional (body field name: string).
            email: Subscriber email. Optional (body field email: string(email)).
            notes: Free-text notes. Optional (body field notes: string).
            service_address: Free-text service address (a string, per the spec), at most 1024
                bytes of UTF-8. Optional (body field serviceAddress: string).
            plan_id: Carrier Fabric service-plan UUID. Get it from list_carrier_service_plans (id).
            metadata: Optional profile key/values (body field metadata: object); its serialized
                JSON may be at most 8192 bytes of UTF-8, as the spec states.
                Free-form JSON object; arbitrary metadata properties are passed unchanged.
            confirm: Ignored. The call runs when made; there is no confirmation step.
            key_label: Optional configured API-key label (see list_configured_api_keys). With one key,
                omit it. With several keys: when plan_id is given and key_label is omitted, the
                subscriber is created under the key that owns that plan; otherwise pass the label
                of the organization that should own the subscriber (omitting it fails fast listing
                the configured labels, it never picks the first key).
        """
        service_address = _nullable_default(service_address, carrier_fabric._UNSET)
        client, _ = deps_fn()
        return await carrier_fabric.create_carrier_subscriber(
            client,
            subscriber_number,
            name=name,
            email=email,
            notes=notes,
            service_address=service_address,
            plan_id=plan_id,
            metadata=metadata,
            confirm=confirm,
            key_label=key_label,
        )

    @mcp.tool(annotations=WRITE)
    async def update_carrier_subscriber(
        subscriber_id: str,
        subscriber_number: str | None = None,
        name: str | None = Field(default_factory=lambda: carrier_fabric._UNSET),
        email: str | None = Field(default_factory=lambda: carrier_fabric._UNSET),
        notes: str | None = Field(default_factory=lambda: carrier_fabric._UNSET),
        service_address: str | None = Field(default_factory=lambda: carrier_fabric._UNSET),
        plan_id: str | None = Field(default_factory=lambda: carrier_fabric._UNSET),
        metadata: dict[str, Any] | None = Field(  # noqa: B008 — distinguish omission from null
            default_factory=lambda: carrier_fabric._UNSET
        ),
        confirm: bool = False,
        key_label: str | None = None,
        clear_fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """Update a Carrier Fabric subscriber (PATCH .../subscribers/{id}).

        Returns {status: "updated", changed: {field: {from, to}}, verified, subscriber, response
        (the upstream write body verbatim)}, or {status: "no_op", reason, subscriber}.
        subscriber is a full body, never unwrapped: the write response when it carries the
        subscriber, else the read-back GET body (for no_op, the GET body read first).
        verified is null, with readAfterError, when the read-after fails or cannot be matched.
        Under dry-run policy nothing is sent: {status: "dry_run", subscriber (the body read first),
        response (the preview)}; there is no read-after.

        Spec-conformance tested only (not live). Partial update: pass at least one field.
        subscriber_number is 1-32 chars after trimming when
        provided; name, email, notes,
        service_address are limited to 128 / 255 / 4096 / 1024 bytes of UTF-8 (the spec's unit).
        Guarded, in order: the Carrier write opt-out (family:carrier=deny refuses
        first), read-before, no-op when all provided
        fields already match, write, read-after. Omission leaves a field unchanged; explicit null
        clears a nullable field, as does naming it in clear_fields (sent as JSON null). Per the spec,
        null
        clears name, email, notes, serviceAddress and planId; subscriberNumber cannot be cleared,
        and metadata=null leaves metadata unchanged (send metadata={} to empty it).
        Explicit metadata=null alone is a no-op; null is forwarded only alongside another change.

        Request body (Carrier Fabric 1.0.0, PATCH /v1/carrier/subscribers/{id} (updateSubscriber);
        schema "SubscriberPatch") is built from scalar parameters. No key is required; send only the
        keys to change.
        - subscriberNumber: string
        - name: string
        - email: string(email)
        - notes: string
        - serviceAddress: string
        - planId: string(uuid)
        - metadata: object

        Example call (update_carrier_subscriber):
            {"subscriber_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "notes": "Moved to plan B"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            subscriber_id: Carrier Fabric subscriber UUID. Get it from list_carrier_subscribers (id).
            subscriber_number: Unique subscriber number, 1-32 chars. Optional (body field
                subscriberNumber: string).
            name: Subscriber display name, non-empty after trimming (the spec rejects a blank name;
                clear it with explicit null or clear_fields). Optional (body field name: string).
            email: Subscriber email. Optional (body field email: string(email)).
            notes: Free-text notes. Optional (body field notes: string).
            service_address: Free-text service address (a string, per the spec), at most 1024
                bytes of UTF-8. Optional (body field serviceAddress: string).
            plan_id: Carrier Fabric service-plan UUID. Get it from list_carrier_service_plans (id).
            metadata: Optional replacement metadata object (body field metadata); it replaces the
                whole document, so pass {} to empty it. Explicit metadata=null alone is a no-op;
                null is forwarded only alongside another change and leaves metadata unchanged.
                Omission leaves metadata unchanged. A subscriber with no metadata reads back
                without the key (the spec omits it), which counts as {}: metadata={} on it is a no-op.
                Its serialized JSON may be at most 8192 bytes of UTF-8, as the spec states.
                Free-form JSON object; arbitrary metadata properties are passed unchanged.
            confirm: Ignored. The call runs when made; there is no confirmation step.
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
                whichever configured key owns the object: every key is tried and the first that answers
                is used.
            clear_fields: Optional list of fields to clear by sending JSON null: any of "name",
                "email", "notes", "service_address", "plan_id". A field named here must not also be
                given a value. Omit to clear nothing (the default; existing behaviour).
                Shape: ('name'|'email'|'notes'|'service_address'|'plan_id')[]
        """
        name = _nullable_default(name, carrier_fabric._UNSET)
        email = _nullable_default(email, carrier_fabric._UNSET)
        notes = _nullable_default(notes, carrier_fabric._UNSET)
        service_address = _nullable_default(service_address, carrier_fabric._UNSET)
        plan_id = _nullable_default(plan_id, carrier_fabric._UNSET)
        metadata = _nullable_default(metadata, carrier_fabric._UNSET)
        client, _ = deps_fn()
        kwargs: dict[str, Any] = {"confirm": confirm, "key_label": key_label}
        clearable = ("name", "email", "notes", "service_address", "plan_id")
        given = {
            "name": name,
            "email": email,
            "notes": notes,
            "service_address": service_address,
            "plan_id": plan_id,
        }
        for field in clear_fields or []:
            if field not in clearable:
                raise ValueError(
                    f"clear_fields: {field!r} cannot be cleared. Clearable fields (sent as JSON null): "
                    f"{', '.join(clearable)}. subscriber_number cannot be cleared, and metadata is not "
                    "cleared by null (pass metadata={} to empty it)."
                )
            if given[field] is not carrier_fabric._UNSET and given[field] is not None:
                raise ValueError(
                    f"clear_fields names {field!r} but a value was also given for it: pass one or the "
                    "other."
                )
            kwargs[field] = None
        # Preserve omitted fields separately from explicit JSON null clears.
        if subscriber_number is not None:
            kwargs["subscriber_number"] = subscriber_number
            kwargs["_preserve_subscriber_number"] = True
        if name is not carrier_fabric._UNSET:
            kwargs["name"] = name
        if email is not carrier_fabric._UNSET:
            kwargs["email"] = email
        if notes is not carrier_fabric._UNSET:
            kwargs["notes"] = notes
        if service_address is not carrier_fabric._UNSET:
            kwargs["service_address"] = service_address
        if plan_id is not carrier_fabric._UNSET:
            kwargs["plan_id"] = plan_id
        if metadata is not carrier_fabric._UNSET:
            kwargs["metadata"] = metadata
        return await carrier_fabric.update_carrier_subscriber(client, subscriber_id, **kwargs)

    @mcp.tool(annotations=WRITE)
    async def attach_carrier_subscriber_host(
        subscriber_id: str,
        host_id: str,
        confirm: bool = False,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """Attach or re-link a subscriber's gateway host (PUT .../subscribers/{id}/host). Guarded.

        Returns {status: "attached", changed, _prev_host_id (the response's prevHostId), verified,
        subscriber, response (verbatim)}, or {status: "no_op", reason, subscriber}. subscriber is
        a full body ({data, ...}), never unwrapped: the write response when it carries the
        subscriber, else the read-back GET body (for no_op, the GET body read first).
        verified is null, with readAfterError, when the read-after fails or cannot be matched.
        Under dry-run policy nothing is sent: {status: "dry_run", subscriber (the body read first),
        response (the preview)}; there is no read-after.

        Spec-conformance tested only (not against a live Carrier Fabric). host_id must be a host in
        the same ISP organization. Guarded, in order: the Carrier write opt-out
        (family:carrier=deny refuses first), read-before, no-op when already linked,
        write, read-after (reports _prev_host_id).

        Request body (Carrier Fabric 1.0.0, PUT /v1/carrier/subscribers/{id}/host
        (attachSubscriberHost); schema "inline requestBody schema") is built from scalar parameters.
        Required keys — hostId.
        - hostId: string

        Example call (attach_carrier_subscriber_host):
            {
              "subscriber_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
              "host_id": "942A6FF664C0000000000964970E0000000009E710560000000068A9873F:9999999999"
            }

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            subscriber_id: Carrier Fabric subscriber UUID. Get it from list_carrier_subscribers (id).
            host_id: Gateway host id (Site Manager) in the same ISP org. Get it from list_hosts (id).
            confirm: Ignored. The call runs when made; there is no confirmation step.
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
                whichever configured key owns the object: every key is tried and the first that answers
                is used.
        """
        client, _ = deps_fn()
        return await carrier_fabric.attach_carrier_subscriber_host(
            client, subscriber_id, host_id, confirm=confirm, key_label=key_label
        )

    @mcp.tool(annotations=WRITE)
    async def detach_carrier_subscriber_host(
        subscriber_id: str,
        confirm: bool = False,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """Detach a subscriber's gateway host (DELETE .../subscribers/{id}/host). Guarded write.

        Consequence: the gateway host is no longer linked to the subscriber until re-attached with
        attach_carrier_subscriber_host.

        Returns {status: "detached", changed, _prev_host_id (the response's prevHostId), verified,
        subscriber, response (verbatim)}, or {status: "no_op", reason, subscriber}. subscriber is
        a full body ({data, ...}), never unwrapped: the write response when it carries the
        subscriber, else the read-back GET body (for no_op, the GET body read first).
        verified is null, with readAfterError, when the read-after fails or cannot be matched.
        Under dry-run policy nothing is sent: {status: "dry_run", subscriber (the body read first),
        response (the preview)}; there is no read-after.

        Spec-conformance tested only (not against a live Carrier Fabric). Guarded, in order: the
        Carrier write opt-out (family:carrier=deny refuses first), read-before,
        no-op when no host is attached, write, read-after (reports the just-detached
        _prev_host_id).

        Example call (detach_carrier_subscriber_host):
            {"subscriber_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            subscriber_id: Carrier Fabric subscriber UUID. Get it from list_carrier_subscribers (id).
            confirm: Ignored. The call runs when made; there is no confirmation step.
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
                whichever configured key owns the object: every key is tried and the first that answers
                is used.
        """
        client, _ = deps_fn()
        return await carrier_fabric.detach_carrier_subscriber_host(
            client, subscriber_id, confirm=confirm, key_label=key_label
        )

    @mcp.tool(annotations=WRITE)
    async def assign_carrier_subscriber_plan(
        subscriber_id: str,
        plan_id: str,
        confirm: bool = False,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """Assign a service plan to a subscriber (PUT .../subscribers/{id}/plan). Guarded write.

        Returns {status: "assigned", changed, verified, subscriber, response (verbatim)}, or
        {status: "no_op", reason, subscriber}. subscriber is a full body ({data, ...}), never
        unwrapped: the write response when it carries the subscriber, else the read-back GET body
        (for no_op, the GET body read first).
        verified is null, with readAfterError, when the read-after fails or cannot be matched.
        Under dry-run policy nothing is sent: {status: "dry_run", subscriber (the body read first),
        response (the preview)}; there is no read-after.

        Spec-conformance tested only (not against a live Carrier Fabric). An archived or unknown
        plan is rejected upstream. Guarded, in order: the Carrier write opt-out
        (family:carrier=deny refuses first), read-before, no-op when already on this
        plan, write, read-after.

        Request body (Carrier Fabric 1.0.0, PUT /v1/carrier/subscribers/{id}/plan
        (assignSubscriberPlan); schema "inline requestBody schema") is built from scalar parameters.
        Required keys — planId.
        - planId: string(uuid)

        Example call (assign_carrier_subscriber_plan):
            {
              "subscriber_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
              "plan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            subscriber_id: Carrier Fabric subscriber UUID. Get it from list_carrier_subscribers (id).
            plan_id: Carrier Fabric service-plan UUID. Get it from list_carrier_service_plans (id).
            confirm: Ignored. The call runs when made; there is no confirmation step.
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
                whichever configured key owns the object: every key is tried and the first that answers
                is used.
        """
        client, _ = deps_fn()
        return await carrier_fabric.assign_carrier_subscriber_plan(
            client, subscriber_id, plan_id, confirm=confirm, key_label=key_label
        )

    @mcp.tool(annotations=WRITE)
    async def suspend_carrier_subscriber(
        subscriber_id: str,
        reason: str | None = None,
        confirm: bool = False,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """Suspend a subscriber's service (POST .../subscribers/{id}/suspend). Guarded write.

        Consequence: the subscriber's service stops until resumed with resume_carrier_subscriber.

        Returns {status: "suspended", changed (suspended, and suspendReason when a reason is sent),
        verified, subscriber, response (verbatim)}, or {status: "no_op", reason, subscriber}.
        subscriber is a full body ({data, ...}), never unwrapped: the write response when it
        carries the subscriber, else the read-back GET body (for no_op, the GET body read first).
        verified is null, with readAfterError, when the read-after fails or cannot be matched.
        Under dry-run policy nothing is sent: {status: "dry_run", subscriber (the body read first),
        response (the preview)}; there is no read-after.

        Spec-conformance tested only (not against a live Carrier Fabric). Guarded, in order: the
        Carrier write opt-out (family:carrier=deny refuses first), read-before,
        no-op only when already suspended AND no reason is given or the current suspendReason
        already equals it (a different reason is sent upstream), write, read-after. An optional
        reason is recorded on the subscriber.

        Request body (Carrier Fabric 1.0.0, POST /v1/carrier/subscribers/{id}/suspend
        (suspendSubscriber); schema "inline requestBody schema") is built from scalar parameters. No key
        is required; send only the keys to change.
        - reason: string

        Example call (suspend_carrier_subscriber):
            {"subscriber_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            subscriber_id: Carrier Fabric subscriber UUID. Get it from list_carrier_subscribers (id).
            reason: Optional suspension reason, max 1024 chars (spec body reason).
            confirm: Ignored. The call runs when made; there is no confirmation step.
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
                whichever configured key owns the object: every key is tried and the first that answers
                is used.
        """
        client, _ = deps_fn()
        return await carrier_fabric.suspend_carrier_subscriber(
            client, subscriber_id, reason=reason, confirm=confirm, key_label=key_label
        )

    @mcp.tool(annotations=WRITE)
    async def resume_carrier_subscriber(
        subscriber_id: str,
        confirm: bool = False,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """Resume a suspended subscriber's service (POST .../subscribers/{id}/resume). Guarded.

        Consequence: the subscriber's service is restored.

        Returns {status: "resumed", changed, verified, subscriber, response (verbatim)}, or {status:
        "no_op", reason, subscriber}. subscriber is a full body ({data, ...}), never unwrapped: the
        write response when it carries the subscriber, else the read-back GET body; for no_op it is
        the GET body read first.
        verified is null, with readAfterError, when the read-after fails or cannot be matched.
        Under dry-run policy nothing is sent: {status: "dry_run", subscriber (the body read first),
        response (the preview)}; there is no read-after.

        Spec-conformance tested only (not against a live Carrier Fabric). Guarded, in order: the
        Carrier write opt-out (family:carrier=deny refuses first), read-before,
        no-op when not currently suspended, write, read-after.

        Example call (resume_carrier_subscriber):
            {"subscriber_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            subscriber_id: Carrier Fabric subscriber UUID. Get it from list_carrier_subscribers (id).
            confirm: Ignored. The call runs when made; there is no confirmation step.
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
                whichever configured key owns the object: every key is tried and the first that answers
                is used.
        """
        client, _ = deps_fn()
        return await carrier_fabric.resume_carrier_subscriber(
            client, subscriber_id, confirm=confirm, key_label=key_label
        )

    return {
        "list_carrier_subscribers": list_carrier_subscribers,
        "get_carrier_subscriber": get_carrier_subscriber,
        "list_carrier_service_plans": list_carrier_service_plans,
        "get_carrier_service_plan": get_carrier_service_plan,
        "create_carrier_subscriber": create_carrier_subscriber,
        "update_carrier_subscriber": update_carrier_subscriber,
        "attach_carrier_subscriber_host": attach_carrier_subscriber_host,
        "detach_carrier_subscriber_host": detach_carrier_subscriber_host,
        "assign_carrier_subscriber_plan": assign_carrier_subscriber_plan,
        "suspend_carrier_subscriber": suspend_carrier_subscriber,
        "resume_carrier_subscriber": resume_carrier_subscriber,
    }
