"""Network NAT, QoS, content-filtering and traffic-observability tools (GS3 lane NC).

None of these objects has a published Integration API route (the pinned Network spec
serves only ``/v1/countries`` and ``/v1/dpi/{applications,categories}`` reference lists
near this area). Every tool uses the Network controller's own web-UI route under
``/proxy/network/v2/api/site/{site}`` as inventoried from the public Network 11.0.81
front-end bundles (``tests/fixtures/private_api/inventory_network_11.0.81.json``), with
the site's short name (``default``) resolved from the caller's site name or UUID.

* The inventory records no request-body keys for these routes (``body_keys`` is empty),
  so every create/update/action body is a free-form JSON object (or array) sent as
  given; no key is invented or required by this module.
* Updates read the record from its collection, merge only the requested leaves into it,
  PUT the merged record and read it back, comparing every requested leaf type-strictly
  (``_verified``; ``_readAfterError`` when the read-back failed). An empty update is
  refused before any request.
* Updates and deletes resolve the id in its collection first (the controller answers a
  write on an unknown id without an error), failing with every valid id listed.
* ``query_traffic_flows`` is an evidenced read-POST, available under read-only and
  dry-run. Export and app-traffic-rate remain writes until successful live read evidence.
* The traffic-flow POSTs drain every page the upstream reports (``has_next`` /
  ``total_page_count``) by advancing ``pageNumber``; no time window or page count is
  capped by this module, including when ``UNIFI_PAGINATE_MAX_PAGES`` is configured.
  A caller ``pageSize`` above :data:`TRAFFIC_FLOWS_MAX_PAGE_SIZE` (the largest size the
  console accepts) is fetched at that size per page and drained, so the caller gets every
  requested record (or everything available if fewer exist) instead of the console's
  HTTP 400. Sizes at or below it are sent as given; every integer size is a requested total.
"""

from __future__ import annotations

import base64
import re
import sys
import time
from collections.abc import Awaitable, Callable
from typing import Any, Literal, cast

from fastmcp import FastMCP

from ..client import (
    UniFiClient,
    UniFiConnectionError,
    decode_body,
    describe_shape,
    is_dry_run_preview,
    upstream_error_value,
    validate_id,
)
from ..config import APIKeyConfig
from ..read_post_routes import post_read
from ..redaction import drop_and_note_masked_fields
from ..registry import Registry
from ..request_shape import request_shape
from ..selector_args import check_selector
from ..tool_annotations import READ_ONLY, WRITE
from ..write_body import IDENTITY_FIELDS, require_unmasked_fields, require_update_fields
from ._classic_objects import resolve_site_slug, v2_site
from ._keys import with_context
from ._pagination import PageSizeBatch, followed_page_width
from ._payload import upstream_hint
from ._results import (
    deletion_readback_ids,
    deletion_result,
    requested_leaves_verdict,
    safe_read_after,
    with_read_after_error,
)

#: This module, so each registered tool (named exactly as the tool, which the family
#: index reads) calls the module-level implementation of the same name.
_SELF = sys.modules[__name__]

_NAT = "/nat"
_QOS = "/qos-rules"
_CONTENT_FILTERS = "/content-filtering"
_FLOWS = "/traffic-flows"
#: The largest traffic-flow ``pageSize`` the console accepts. Measured live 2026-10-26 on
#: a development controller (read-POST evidence record 2026-10-26-flows-cap, cited by the
#: network-v2-traffic-flows entry of ``read_post_routes.READ_POST_ROUTES``): pageSize 5000
#: answered HTTP 200 and pageSize 10000 answered HTTP 400. A caller pageSize above it is
#: sent as this size until the requested total is gathered (:func:`_flow_page_batch`); a size at or
#: below it is sent unchanged and any upstream error for it is passed through verbatim.
TRAFFIC_FLOWS_MAX_PAGE_SIZE = 5000
_TOPOLOGY_VIEWS = ("live", "timeline", "timestamps", "at")


# --------------------------------------------------------------------------- arguments


def _nc_scope(host: str, site: str) -> None:
    """Refuse a malformed host or site selector before any request."""
    check_selector("host", host)
    check_selector("site", site)


def _nc_object(value: Any, name: str) -> dict[str, Any]:
    """``value`` when it is a JSON object, else raise (the argument's declared type)."""
    if not isinstance(value, dict):
        raise ValueError(
            f'{name} must be a JSON object, got {describe_shape(value)}; e.g. {{"enabled": true}}'
        )
    return value


def _nc_optional_object(value: Any, name: str) -> dict[str, Any] | None:
    return None if value is None else _nc_object(value, name)


def _nc_object_or_array(value: Any, name: str) -> dict[str, Any] | list[str | dict[str, Any]]:
    """``value`` when it is a JSON object or array, else raise (the declared type)."""
    if not isinstance(value, dict | list):
        raise ValueError(
            f"{name} must be a JSON object or array, got {describe_shape(value)}; "
            'e.g. ["65f1c0ffee0123456789abcd"]'
        )
    if isinstance(value, list) and not value:
        raise ValueError(
            f"{name} is an empty list, so it names no QoS rule; pass at least one rule id "
            'or entry, e.g. ["65f1c0ffee0123456789abcd"]. Nothing was sent.'
        )
    return value


def _nc_epoch_ms(value: Any, name: str) -> int:
    """``value`` when it is a JSON integer (booleans are not), else raise."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(
            f"{name} must be an integer Unix epoch in milliseconds, e.g. 1710000000000; "
            f"got {value!r}"
        )
    return value


def _nc_integer(value: Any, name: str) -> int:
    """``value`` when it is a JSON integer (booleans are not), else raise."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer, e.g. 10; got {value!r}")
    return value


def _nc_epoch_warnings(**values: int | None) -> list[dict[str, Any]]:
    """One ``_warnings`` entry per epoch argument given, naming its unit (milliseconds)."""
    return [
        {
            "code": "EPOCH_MILLISECONDS",
            "argument": name,
            "value": value,
            "message": (
                f"{name} is a Unix epoch in MILLISECONDS (e.g. 1710000000000) and was sent "
                "as given; multiply epoch seconds by 1000."
            ),
        }
        for name, value in values.items()
        if value is not None
    ]


def _nc_with_warnings(result: Any, warnings: list[dict[str, Any]]) -> Any:
    """An object result plus the additive ``_warnings`` list (other shapes unchanged)."""
    if not warnings or not isinstance(result, dict):
        return result
    return with_context(result, {"_warnings": warnings})


def _nc_changes(tool: str, value: Any, name: str) -> dict[str, Any]:
    """The requested update leaves (masked and identity fields dropped), or raise."""
    clean = require_update_fields(drop_and_note_masked_fields(value), f"{tool} {name}")
    return {key: item for key, item in clean.items() if key not in IDENTITY_FIELDS}


async def _nc_site(
    registry: Registry, host: str, site: str
) -> tuple[APIKeyConfig | None, str, str]:
    """``(key, host_id, site_slug)``: the owning key (multi-key), console and v2 site."""
    return await resolve_site_slug(registry, host, site)


# --------------------------------------------------------------------------- collections


def _nc_rows(body: Any, path: str) -> list[dict[str, Any]]:
    """The records of a v2 collection (bare array, or ``{data: [...]}``), or raise."""
    rows = body.get("data") if isinstance(body, dict) else body
    if not isinstance(rows, list):
        raise UniFiConnectionError(
            f"Unexpected response shape from GET {path}: expected a JSON array or an object "
            f"with a 'data' array, got {describe_shape(body)}"
        )
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise UniFiConnectionError(
                f"Unexpected response shape from GET {path}: row {index} expected an object, "
                f"got {describe_shape(row)}"
            )
    return rows


def _nc_row_id(row: dict[str, Any]) -> str | None:
    for field in ("_id", "id"):
        value = row.get(field)
        if isinstance(value, str) and value:
            return value
    return None


def _nc_match(rows: list[dict[str, Any]], wanted: str) -> dict[str, Any] | None:
    lowered = wanted.lower()
    for row in rows:
        if any(
            isinstance(row.get(field), str) and row[field].lower() == lowered
            for field in ("_id", "id")
        ):
            return row
    return None


def _by_value(choice: str) -> str:
    """Sort key of a field=value choice: the id value."""
    return choice.split("=", 1)[1]


def _nc_choice(row: dict[str, Any]) -> str | None:
    """A listed row's id, named by its field (``_id=...`` or ``id=...``)."""
    for field in ("_id", "id"):
        value = row.get(field)
        if isinstance(value, str) and value:
            return f"{field}={upstream_error_value(value)}"
    return None


def _nc_unknown(label: str, wanted: str, rows: list[dict[str, Any]], list_tool: str) -> str:
    """The unknown-id error: not found, every valid id with its field, no write sent."""
    choices = sorted(filter(None, (_nc_choice(row) for row in rows)), key=_by_value)
    return (
        f"{label} {wanted!r} not found; valid choices: {', '.join(choices) or '(none)'}. "
        f"Get ids from {list_tool} (_id). No write was sent."
    )


async def _nc_listed(
    client: UniFiClient,
    path: str,
    key: APIKeyConfig | None,
    wanted: str,
    label: str,
    list_tool: str,
) -> dict[str, Any]:
    """The record of collection ``path`` whose ``_id`` or ``id`` is ``wanted``, or raise
    listing every valid id."""
    rows = _nc_rows(await client.get(path, key=key), path)
    row = _nc_match(rows, wanted)
    if row is None:
        raise ValueError(_nc_unknown(label, wanted, rows, list_tool))
    return row


async def _nc_target(
    client: UniFiClient,
    path: str,
    key: APIKeyConfig | None,
    wanted: str,
    label: str,
    list_tool: str,
) -> tuple[dict[str, Any], str]:
    """The listed record and its upstream id (validated as a URL path segment)."""
    row = await _nc_listed(client, path, key, wanted, label, list_tool)
    resolved = _nc_row_id(row)
    if resolved is None:  # pragma: no cover - _nc_match only matches string ids
        raise UniFiConnectionError(f"Selected {label} in GET {path} has no string _id or id")
    validate_id(resolved, "id")
    return row, resolved


def _nc_merge(current: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge only the requested leaves into the current upstream record."""
    merged = dict(current)
    for name, value in changes.items():
        prior = merged.get(name)
        merged[name] = (
            _nc_merge(prior, value)
            if isinstance(prior, dict) and isinstance(value, dict)
            else value
        )
    return merged


async def _nc_list(
    client: UniFiClient, registry: Registry, host: str, site: str, suffix: str
) -> Any:
    _nc_scope(host, site)
    key, host_id, slug = await _nc_site(registry, host, site)
    return await client.get(v2_site(host_id, slug, suffix), key=key)


async def _nc_create(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    route: str,
    body: Any,
    name: str,
) -> Any:
    _nc_scope(host, site)
    payload = _nc_object(body, name)
    key, host_id, slug = await _nc_site(registry, host, site)
    return await client.post(v2_site(host_id, slug, route), key=key, json=payload)


async def _nc_update(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    collection: str,
    identifier: str,
    id_arg: str,
    body: Any,
    body_arg: str,
    tool: str,
    label: str,
    list_tool: str,
) -> Any:
    """Read-merge-write, then read back every requested leaf with strict comparison."""
    _nc_scope(host, site)
    validate_id(identifier, id_arg)
    changes = _nc_changes(tool, _nc_object(body, body_arg), body_arg)
    key, host_id, slug = await _nc_site(registry, host, site)
    path = v2_site(host_id, slug, collection)
    current, resolved = await _nc_target(client, path, key, identifier, label, list_tool)
    response = await client.put(f"{path}/{resolved}", key=key, json=_nc_merge(current, changes))
    if is_dry_run_preview(response):
        # UNIFI_DRY_RUN: nothing was written, so there is nothing to verify.
        return response
    after, error = await safe_read_after(
        lambda: _nc_listed(client, path, key, resolved, label, list_tool)
    )
    verified, error = requested_leaves_verdict(changes, after, error)
    result = response if isinstance(response, dict) else {"response": response}
    additions: dict[str, Any] = {"_verified": verified}
    if error is not None:
        additions["_readAfterError"] = error
    return with_context(result, additions)


async def _nc_delete(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    collection: str,
    identifier: str,
    id_arg: str,
    label: str,
    list_tool: str,
) -> Any:
    _nc_scope(host, site)
    validate_id(identifier, id_arg)
    key, host_id, slug = await _nc_site(registry, host, site)
    path = v2_site(host_id, slug, collection)
    _row, resolved = await _nc_target(client, path, key, identifier, label, list_tool)
    response = await client.delete(f"{path}/{resolved}", key=key)
    return deletion_result(f"{label} {resolved} deleted", response)


# --------------------------------------------------------------------------- NAT rules


async def list_nat_rules(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """GET the site's NAT rules; the upstream body is returned verbatim."""
    return await _nc_list(client, registry, host, site, _NAT)


async def create_nat_rule(
    client: UniFiClient, registry: Registry, host: str, site: str, rule: dict[str, Any]
) -> Any:
    """POST ``rule`` verbatim to the site's NAT rules."""
    return await _nc_create(client, registry, host, site, _NAT, rule, "rule")


async def update_nat_rule(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    rule_id: str,
    rule: dict[str, Any],
) -> Any:
    """Merge ``rule`` into the listed NAT rule, PUT it and verify the requested leaves."""
    return await _nc_update(
        client,
        registry,
        host,
        site,
        _NAT,
        rule_id,
        "rule_id",
        rule,
        "rule",
        "update_nat_rule",
        "NAT rule",
        "list_nat_rules",
    )


async def delete_nat_rule(
    client: UniFiClient, registry: Registry, host: str, site: str, rule_id: str
) -> Any:
    """Resolve ``rule_id`` in the NAT rule list, then DELETE it."""
    return await _nc_delete(
        client, registry, host, site, _NAT, rule_id, "rule_id", "NAT rule", "list_nat_rules"
    )


# --------------------------------------------------------------------------- QoS rules


async def list_qos_rules(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """GET the site's QoS rules; the upstream body is returned verbatim."""
    return await _nc_list(client, registry, host, site, _QOS)


async def create_qos_rule(
    client: UniFiClient, registry: Registry, host: str, site: str, rule: dict[str, Any]
) -> Any:
    """POST ``rule`` verbatim to the site's QoS rules."""
    return await _nc_create(client, registry, host, site, _QOS, rule, "rule")


async def update_qos_rule(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    rule_id: str,
    rule: dict[str, Any],
) -> Any:
    """Merge ``rule`` into the listed QoS rule, PUT it and verify the requested leaves."""
    return await _nc_update(
        client,
        registry,
        host,
        site,
        _QOS,
        rule_id,
        "rule_id",
        rule,
        "rule",
        "update_qos_rule",
        "QoS rule",
        "list_qos_rules",
    )


async def delete_qos_rule(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    body: dict[str, Any] | list[str | dict[str, Any]],
) -> Any:
    """POST ``body`` verbatim to ``qos-rules/batch-delete`` (the only QoS delete route).

    When ``body`` is a JSON array of id strings, every id is first resolved in the QoS
    rule list (an unknown id fails listing every valid id, and nothing is sent).
    """
    _nc_scope(host, site)
    payload = _nc_object_or_array(body, "body")
    key, host_id, slug = await _nc_site(registry, host, site)
    collection = v2_site(host_id, slug, _QOS)
    ids = [i for i in payload if isinstance(i, str)] if isinstance(payload, list) else []
    if ids and len(ids) == len(payload):
        rows = _nc_rows(await client.get(collection, key=key), collection)
        for wanted in ids:
            if _nc_match(rows, wanted) is None:
                raise ValueError(_nc_unknown("QoS rule", wanted, rows, "list_qos_rules"))
    response = await client.post(
        f"{collection}/batch-delete", key=key, json=cast(dict[str, Any], payload)
    )
    result = deletion_result("QoS rule batch-delete sent", response)
    if is_dry_run_preview(response) or not ids or len(ids) != len(payload):
        return result

    async def read_after() -> set[str]:
        rows = _nc_rows(await client.get(collection, key=key), collection)
        return {item.lower() for item in deletion_readback_ids(rows, "_id")}

    after, error = await safe_read_after(read_after)
    if after is None:
        result.update(deleted=False, message="QoS batch-delete accepted; read-back failed.")
        return with_read_after_error(result, error)
    if any(item.lower() in after for item in ids):
        result.update(deleted=False, message="QoS batch-delete accepted; rules remain listed.")
    return result


async def reorder_qos_rules(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    body: dict[str, Any] | list[str | dict[str, Any]],
) -> Any:
    """PUT ``body`` verbatim to ``qos-rules/batch-reorder``."""
    _nc_scope(host, site)
    payload = _nc_object_or_array(body, "body")
    key, host_id, slug = await _nc_site(registry, host, site)
    return await client.put(
        v2_site(host_id, slug, f"{_QOS}/batch-reorder"),
        key=key,
        json=cast(dict[str, Any], payload),
    )


# --------------------------------------------------------------------------- content filters


async def list_content_filters(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """GET the site's content-filtering profiles; returned verbatim."""
    return await _nc_list(client, registry, host, site, _CONTENT_FILTERS)


async def create_content_filter(
    client: UniFiClient, registry: Registry, host: str, site: str, content_filter: dict[str, Any]
) -> Any:
    """POST ``content_filter`` verbatim to ``content-filtering/create``."""
    return await _nc_create(
        client,
        registry,
        host,
        site,
        f"{_CONTENT_FILTERS}/create",
        content_filter,
        "content_filter",
    )


async def update_content_filter(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    filter_id: str,
    content_filter: dict[str, Any],
) -> Any:
    """Merge into the listed content filter, PUT it and verify the requested leaves."""
    return await _nc_update(
        client,
        registry,
        host,
        site,
        _CONTENT_FILTERS,
        filter_id,
        "filter_id",
        content_filter,
        "content_filter",
        "update_content_filter",
        "content filter",
        "list_content_filters",
    )


async def delete_content_filter(
    client: UniFiClient, registry: Registry, host: str, site: str, filter_id: str
) -> Any:
    """Resolve ``filter_id`` in the content-filter list, then DELETE it."""
    return await _nc_delete(
        client,
        registry,
        host,
        site,
        _CONTENT_FILTERS,
        filter_id,
        "filter_id",
        "content filter",
        "list_content_filters",
    )


async def list_content_filter_categories(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """GET the content-filtering category catalogue; returned verbatim."""
    return await _nc_list(client, registry, host, site, f"{_CONTENT_FILTERS}/categories")


# --------------------------------------------------------------------------- traffic reads


async def get_traffic_stats(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    params: dict[str, Any] | None = None,
) -> Any:
    """GET ``/traffic`` with ``params`` forwarded as the query string, verbatim."""
    _nc_scope(host, site)
    query = _nc_optional_object(params, "params")
    key, host_id, slug = await _nc_site(registry, host, site)
    try:
        result = await client.get(v2_site(host_id, slug, "/traffic"), key=key, params=query)
    except UniFiConnectionError as exc:
        if exc.status == 400 and not {"start", "end"} <= (query or {}).keys():
            upstream_hint(
                exc,
                (
                    "The Network UI sends start and end for traffic queries; "
                    "pass them in params as epoch milliseconds."
                ),
            )
            raise
        raise
    epochs = {
        name: value
        for name, value in (query or {}).items()
        if name in {"start", "end"} and isinstance(value, int) and not isinstance(value, bool)
    }
    return _nc_with_warnings(result, _nc_epoch_warnings(**epochs))


async def get_latest_traffic_flow_stats(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    period: str | None = "DAY",
    top: int | None = None,
) -> Any:
    """GET ``/traffic-flow-latest-statistics`` with the given ``period`` / ``top``."""
    _nc_scope(host, site)
    query: dict[str, Any] = {}
    # The Network 11.0.89 web app sends HOUR, DAY, WEEK or MONTH (upper case; live on
    # 11.0.89 each answers 200, lower case "day" and an omitted period answer HTTP 400).
    # DAY is the web app's default. The value is sent as given.
    if period is not None:
        if not isinstance(period, str):
            raise ValueError(f'period must be a string, e.g. "day"; got {period!r}')
        query["period"] = period
    if top is not None:
        query["top"] = _nc_integer(top, "top")
    key, host_id, slug = await _nc_site(registry, host, site)
    return await client.get(
        v2_site(host_id, slug, "/traffic-flow-latest-statistics"), key=key, params=query or None
    )


async def get_poe_info(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    params: dict[str, Any] | None = None,
) -> Any:
    """GET ``/poe-info`` with ``params`` forwarded as the query string, verbatim."""
    _nc_scope(host, site)
    query = _nc_optional_object(params, "params")
    key, host_id, slug = await _nc_site(registry, host, site)
    try:
        return await client.get(v2_site(host_id, slug, "/poe-info"), key=key, params=query)
    except UniFiConnectionError as exc:
        if exc.status == 400 and "mac" not in (query or {}):
            upstream_hint(
                exc,
                "Pass params.mac as the device MAC in lowercase colon form, "
                "for example 02:00:5e:00:00:a1.",
            )
            raise
        raise


async def get_topology_snapshot(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    view: Literal["live", "timeline", "timestamps", "at"] = "live",
    start: int | None = None,
    end: int | None = None,
    at: int | None = None,
) -> Any:
    """GET the live topology snapshot or its history (``timeline`` / ``timestamps`` over
    ``start``..``end``, or the snapshot ``at`` one instant); epochs are milliseconds."""
    _nc_scope(host, site)
    if view not in _TOPOLOGY_VIEWS:
        raise ValueError(f"view must be one of {list(_TOPOLOGY_VIEWS)}; got {view!r}")
    query: dict[str, Any] | None = None
    warnings: list[dict[str, Any]] = []
    if view == "live":
        if start is not None or end is not None or at is not None:
            raise ValueError(
                "view 'live' takes no start, end or at; pass view 'timeline', 'timestamps' "
                "or 'at' to read history"
            )
        suffix = "/topology/snapshot/live"
    elif view == "at":
        if at is None or start is not None or end is not None:
            raise ValueError(
                "view 'at' requires at (epoch milliseconds, e.g. 1710000000000) and takes no "
                "start or end"
            )
        at_ms = _nc_epoch_ms(at, "at")
        suffix = f"/topology/snapshot/history/at/{at_ms}"
        warnings = _nc_epoch_warnings(at=at_ms)
    else:
        if start is None or end is None or at is not None:
            raise ValueError(
                f"view {view!r} requires start and end (epoch milliseconds, e.g. "
                "1710000000000) and takes no at"
            )
        query = {"start": _nc_epoch_ms(start, "start"), "end": _nc_epoch_ms(end, "end")}
        suffix = f"/topology/snapshot/history/{view}"
        warnings = _nc_epoch_warnings(start=query["start"], end=query["end"])
    key, host_id, slug = await _nc_site(registry, host, site)
    result = await client.get(v2_site(host_id, slug, suffix), key=key, params=query)
    return _nc_with_warnings(result, warnings)


# --------------------------------------------------------------------------- read-type POSTs


def _nc_page_items(page: Any, path: str) -> list[Any]:
    """The ``data`` array of one traffic-flow page, or raise naming the shape."""
    items = page.get("data") if isinstance(page, dict) else None
    if not isinstance(items, list):
        raise UniFiConnectionError(
            f"Unexpected response shape from POST {path}: expected an object with a 'data' "
            f"array on a paged response, got {describe_shape(page)}"
        )
    return items


def _nc_has_more(page: dict[str, Any], number: int, path: str) -> bool:
    """Whether page ``number`` says another page follows (``has_next`` first, then
    ``total_page_count``); a wrong-typed control raises naming the field."""
    has_next = page.get("has_next")
    if has_next is not None:
        if not isinstance(has_next, bool):
            raise UniFiConnectionError(
                f"Unexpected response shape from POST {path}: has_next must be a boolean "
                f"(got {describe_shape(has_next)})"
            )
        return has_next
    total = page.get("total_page_count")
    if total is not None:
        if isinstance(total, bool) or not isinstance(total, int):
            raise UniFiConnectionError(
                f"Unexpected response shape from POST {path}: total_page_count must be an "
                f"integer (got {describe_shape(total)})"
            )
        return number + 1 < total
    return False


def _nc_page_number(value: Any) -> int | None:
    """Read the integer-like page numbers accepted by the console."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


async def _nc_drain(
    client: UniFiClient,
    path: str,
    body: dict[str, Any] | None,
    first: Any,
    fetch: Callable[[dict[str, Any]], Awaitable[Any]],
    batch: dict[str, Any] | None = None,
) -> Any:
    """Gather the requested total, or drain when no pageSize was supplied.

    The shared page-size policy bounds each wire request and reads the effective size
    back before advancing pageNumber. Existing continuation, repeat, error and envelope
    handling is retained. There is no implicit page cap, timeout or retry.
    """
    if not isinstance(first, dict) or is_dry_run_preview(first):
        return first
    skip = batch["skip"] if batch is not None else 0
    requested = _nc_page_number((body or {}).get("pageNumber"))
    echoed_first = _nc_page_number(first.get("page_number"))
    number = requested if requested is not None else (echoed_first or 0)
    more = _nc_has_more(first, number, path)
    if not more and batch is None:
        return first
    first_items = _nc_page_items(first, path)
    policy: PageSizeBatch | None = batch["policy"] if batch is not None else None

    async def fetch_page(page_body: dict[str, Any]) -> Any:
        if policy is not None:
            policy.record_sent(page_body.get("pageSize"))
        return await fetch(page_body)

    reason: str | None = None
    if policy is not None and batch is not None:
        policy.observe(first, first_items, "number", first=True, requested_page=number)
        logical_offset = batch["offset"]
        if logical_offset is None:
            # An unreadable caller value remains pass-through. Follow the console's
            # echoed page instead of inventing a logical page zero.
            batch = {**batch, "offset": number * (policy.effective or 0)}
        else:
            attempted = 0
            try:
                # A size echo, page zero, or a followed page whose width is proven
                # (followed_page_width) establishes the native size. Otherwise discover it
                # on page zero, retaining that response for the translated window
                # rather than fetching it again or discarding its records.
                discovered: tuple[dict[str, Any], list[Any]] | None = None
                echoed_size = first.get("limit")
                has_size = (
                    isinstance(echoed_size, int)
                    and not isinstance(echoed_size, bool)
                    and echoed_size > 0
                )
                proven = (
                    followed_page_width(
                        first, number, (body or {}).get("pageSize"), len(first_items)
                    )
                    if _nc_has_more(first, number, path)
                    else None
                )
                if logical_offset > 0 and number != 0 and not has_size and proven is not None:
                    policy.effective = proven
                elif logical_offset > 0 and number != 0 and not has_size:
                    probe = await fetch_page({**(body or {}), "pageNumber": 0})
                    if not isinstance(probe, dict) or is_dry_run_preview(probe):
                        return probe
                    probe_items = _nc_page_items(probe, path)
                    policy.observe(probe, probe_items, "number", first=True, requested_page=0)
                    discovered = (probe, probe_items)
                if discovered is not None and not _nc_has_more(discovered[0], 0, path):
                    # A terminal page zero contains the whole collection, even if
                    # the endpoint ignores pageSize. Its actual native size need
                    # not be inferred to select the exact logical window.
                    first, first_items = discovered
                    number = 0
                    body = {**(body or {}), "pageNumber": 0}
                    skip = logical_offset
                else:
                    # Translate only after observing the effective physical size.
                    physical, translated_skip = divmod(logical_offset, policy.effective or 1)
                    if physical != number:
                        attempted = physical
                        translated_body = {
                            **(body or {}),
                            "pageNumber": physical,
                            "pageSize": policy.effective,
                        }
                        if physical == 0 and discovered is not None:
                            translated, first_items = discovered
                        else:
                            translated = await fetch_page(translated_body)
                            if not isinstance(translated, dict) or is_dry_run_preview(translated):
                                return translated
                            first_items = _nc_page_items(translated, path)
                        first, body, number = translated, translated_body, physical
                    skip = translated_skip
            except UniFiConnectionError as exc:
                status = f"HTTP {exc.status}" if exc.status is not None else "transport error"
                reason = f"page {attempted} failed ({status}): {exc}"
                # The native page is a sizing probe, not the requested logical window.
                first_items = []
                skip = 0
    items = list(first_items[skip:])
    if policy is not None and policy.requested is not None:
        items = items[: policy.requested]
    page: dict[str, Any] = first
    previous = first_items
    seen = {number}
    pages = 1
    while (
        reason is None
        and _nc_has_more(page, number, path)
        and not (policy is not None and policy.done(len(items)))
    ):
        if not previous:
            reason = f"page {number} was empty but the upstream reported more pages"
            break
        number += 1
        try:
            next_body = {**(body or {}), "pageNumber": number}
            if policy is not None and batch is not None:
                next_body["pageSize"] = policy.effective
            nxt = await fetch_page(next_body)
        except UniFiConnectionError as exc:
            status = f"HTTP {exc.status}" if exc.status is not None else "transport error"
            reason = f"page {number} failed ({status}): {exc}"
            break
        if not isinstance(nxt, dict):
            raise UniFiConnectionError(
                f"Unexpected response shape from POST {path}: page {number} expected an "
                f"object, got {describe_shape(nxt)}"
            )
        data = _nc_page_items(nxt, path)
        echoed = _nc_page_number(nxt.get("page_number"))
        if (echoed is not None and echoed in seen) or (data and data == previous):
            reason = (
                f"the upstream repeated page {echoed if echoed is not None else number - 1} "
                f"when page {number} was requested"
            )
            break
        seen.add(number)
        if policy is not None and batch is not None:
            policy.observe(nxt, data, "number", first=False)
            remaining = policy.requested - len(items) if policy.requested is not None else len(data)
            items.extend(data[:remaining])
        else:
            items.extend(data)
        previous = data
        page = nxt
        pages += 1
    context = {"_pages": pages} if batch is None else _batch_context(batch, pages, len(items))
    result = with_context({**page, "data": items}, context)
    if reason is None and policy is not None and batch is not None and policy.done(len(items)):
        # The native page describes the final physical batch. A logical next page
        # can also begin inside that batch, even when its native has_next is false.
        returned_end = batch["offset"] + len(items)
        physical_end = number * (policy.effective or 0) + len(previous)
        if returned_end < physical_end or _nc_has_more(page, number, path):
            result = with_context(
                result,
                {"_nextPage": {"offset": returned_end, "pageSize": policy.requested}},
            )
    if reason is not None:
        result = with_context(result, {"incomplete": True, "incompleteReason": reason})
    return result


def _batch_context(batch: dict[str, Any], pages: int, returned: int) -> dict[str, Any]:
    """The additive markers of a batched drain: ``_pages`` and ``_pageSize``."""
    policy: PageSizeBatch = batch["policy"]
    return {"_pages": pages, **policy.context(returned=returned)}


def _flow_page_batch(
    body: dict[str, Any] | None,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """The request and shared policy for a caller's requested pageSize total.

    Oversized logical pages retain the original starting record by translating their
    pageNumber to a bounded wire page and skipping its leading records.
    """
    if body is None:
        return None, None
    # An additive continuation denotes a record offset, independent of the next
    # call's pageSize. Consume it locally; the console only receives page numbers.
    continuation = body.get("pageNumber")
    logical_offset = None
    if isinstance(continuation, dict):
        logical_offset = continuation.get("offset")
        previous_size = continuation.get("pageSize")
        if (
            not isinstance(logical_offset, int)
            or isinstance(logical_offset, bool)
            or logical_offset < 0
            or not isinstance(previous_size, int)
            or isinstance(previous_size, bool)
            or previous_size <= 0
        ):
            raise ValueError(
                "body.pageNumber continuation requires a non-negative integer offset "
                "and a positive integer pageSize; pass the returned _nextPage object"
            )
        body = {**body, "pageSize": body.get("pageSize", previous_size)}
    size = body.get("pageSize")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        if logical_offset is not None:
            raise ValueError("body.pageSize must be a positive integer when following _nextPage")
        return body, None
    policy = PageSizeBatch(size, TRAFFIC_FLOWS_MAX_PAGE_SIZE)
    number = _nc_page_number(body["pageNumber"]) if "pageNumber" in body else 0
    if logical_offset is None and number is not None:
        logical_offset = number * size
    sent = {**body, "pageSize": policy.sent}
    if logical_offset is not None and (logical_offset > 0 or isinstance(continuation, dict)):
        physical, _ = divmod(logical_offset, policy.effective or 1)
        if physical != number or isinstance(continuation, dict):
            sent["pageNumber"] = physical
    return sent, {"policy": policy, "skip": 0, "offset": logical_offset, "page": number}


@request_shape(
    tool="query_traffic_flows",
    args=("window", "direction", "action", "risk"),
    evidence="query_traffic_flows.{argument}",
)
def _traffic_flow_body(
    body: dict[str, Any] | None,
    window: str | None,
    direction: str | list[str] | None,
    action: str | list[str] | None,
    risk: str | list[str] | None,
) -> dict[str, Any] | None:
    """Build console selectors, preserving every explicitly supplied body key."""
    selected = dict(body or {})
    if window is not None and ("timestampFrom" not in selected or "timestampTo" not in selected):
        match = re.fullmatch(r"(\d+(?:\.\d+)?)([smhdw])", window)
        if match is None:
            selected.setdefault("window", window)
        else:
            millis = int(
                float(match[1])
                * {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[match[2]]
                * 1000
            )
            now = int(time.time() * 1000)
            selected.setdefault("timestampFrom", now - millis)
            selected.setdefault("timestampTo", now)
    for key, value in (("direction", direction), ("action", action), ("risk", risk)):
        if value is not None:
            selected.setdefault(key, [value] if isinstance(value, str) else value)
    return selected if selected or body is not None else None


async def query_traffic_flows(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    body: dict[str, Any] | None = None,
) -> Any:
    """POST ``/traffic-flows``; gather pageSize records or drain without a size."""
    _nc_scope(host, site)
    payload = _nc_optional_object(body, "body")
    sent, batch = _flow_page_batch(payload)
    key, host_id, slug = await _nc_site(registry, host, site)
    path = v2_site(host_id, slug, _FLOWS)

    async def fetch(page_body: dict[str, Any]) -> Any:
        return await post_read(client, path, key=key, json=page_body)

    if batch is not None:
        batch["policy"].record_sent((sent or {}).get("pageSize"))
    first = await post_read(client, path, key=key, json=sent)
    return await _nc_drain(client, path, sent, first, fetch, batch)


def _nc_export_body(resp: Any) -> Any:
    """A JSON export decoded verbatim; text as ``{contentType, sizeBytes, body}``; any
    other content base64-encoded as ``{contentType, sizeBytes, bodyBase64}``."""
    content_type = resp.headers.get("content-type")
    raw: bytes = resp.content
    media = (content_type or "").split(";", 1)[0].strip().lower()
    if not raw or media.endswith("json") or media.endswith("+json"):
        return decode_body(resp)
    if media.startswith("text/") or media in {"application/csv"}:
        return {"contentType": content_type, "sizeBytes": len(raw), "body": resp.text}
    return {
        "contentType": content_type,
        "sizeBytes": len(raw),
        "bodyBase64": base64.b64encode(raw).decode("ascii"),
    }


async def export_traffic_flows(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    body: dict[str, Any] | None = None,
) -> Any:
    """POST ``body`` verbatim to ``/traffic-flows/export``; the export is returned whole."""
    _nc_scope(host, site)
    payload = _nc_optional_object(body, "body")
    require_unmasked_fields(payload, "export_traffic_flows body")
    sent, batch = _flow_page_batch(payload)
    key, host_id, slug = await _nc_site(registry, host, site)
    path = v2_site(host_id, slug, f"{_FLOWS}/export")

    async def fetch(page_body: dict[str, Any] | None) -> Any:
        resp = await client.request(
            "POST", path, key=key, json=page_body, accept="application/json, text/plain, */*"
        )
        return _nc_export_body(resp)

    if batch is not None:
        batch["policy"].record_sent((sent or {}).get("pageSize"))
    first = await fetch(sent)
    if batch is not None and not (isinstance(first, dict) and isinstance(first.get("data"), list)):
        return first  # a non-paged export (text or binary) is returned whole, as received
    return await _nc_drain(client, path, sent, first, fetch, batch)


async def query_app_traffic_rates(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    params: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
) -> Any:
    """POST ``/app-traffic-rate`` with ``params`` as the query string and ``body`` as given.

    The route requires a request body (live: no body answers HTTP 400 "Required request
    body is missing"); the Network 11.0.89 web app always posts one, ``{}`` when it filters
    no app or client (``data: {...apps.length && {apps}, ...client_macs.length &&
    {client_macs}}``), so an omitted body is sent as ``{}``.
    """
    _nc_scope(host, site)
    query = _nc_optional_object(params, "params")
    payload = _nc_optional_object(body, "body")
    if payload is None:
        payload = {}
    require_unmasked_fields(payload, "query_app_traffic_rates body")
    key, host_id, slug = await _nc_site(registry, host, site)
    return await client.post(
        v2_site(host_id, slug, "/app-traffic-rate"), key=key, json=payload, params=query
    )


# --------------------------------------------------------------------------- registration


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the 21 NAT, QoS, content-filtering and traffic tools."""

    def deps() -> tuple[UniFiClient, Registry]:
        return cast(tuple[UniFiClient, Registry], deps_fn())

    @mcp.tool(name="list_nat_rules", annotations=READ_ONLY)
    async def list_nat_rules(host: str, site: str) -> Any:
        """List a site's NAT rules (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/nat; the upstream body is returned verbatim
        (the route takes no paging parameter). Rule ids (_id) feed update_nat_rule and
        delete_nat_rule.

        Returns the upstream body verbatim (a JSON object or array, as sent).

        Required arguments: host, site.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
        """
        return await _SELF.list_nat_rules(*deps(), host, site)

    @mcp.tool(name="create_nat_rule", annotations=WRITE)
    async def create_nat_rule(host: str, site: str, rule: dict[str, Any]) -> Any:
        """Create a NAT rule (Network v2 route). Consequence: changes how the gateway
        translates traffic for the site.

        POST /proxy/network/v2/api/site/{site}/nat with rule sent verbatim; the upstream
        body is returned verbatim. The request body is free-form: no field list is
        published, so copy the shape list_nat_rules returns. Never auto-retried.

        Returns the upstream body verbatim (a JSON object or array, as sent).
        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, rule.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            rule: Required free-form NAT rule object in the shape list_nat_rules returns,
                e.g. {"description": "web", "enabled": false}.
        """
        return await _SELF.create_nat_rule(*deps(), host, site, rule)

    @mcp.tool(name="update_nat_rule", annotations=WRITE)
    async def update_nat_rule(host: str, site: str, rule_id: str, rule: dict[str, Any]) -> Any:
        """Update a NAT rule (Network v2 route). Consequence: changes live gateway NAT.

        Reads the rule from list_nat_rules (an unknown id fails listing every valid id),
        merges only the given leaves into it, PUTs the merged rule to
        /proxy/network/v2/api/site/{site}/nat/{_id} and reads it back: the upstream body
        is returned plus _verified (every requested leaf matched, type-strict) and
        _readAfterError when the read-back failed. An empty rule is refused before any
        request.

        Returns the upstream PUT body plus _verified (true only when every requested leaf
        read back equal, type-strict) and _readAfterError when the read-back failed; a
        non-object PUT body is kept under response.
        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, rule_id, rule.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            rule_id: Required NAT rule _id from list_nat_rules,
                e.g. "65f1c0ffee0123456789abcd".
            rule: Required free-form fields to change, e.g. {"enabled": false}.
        """
        return await _SELF.update_nat_rule(*deps(), host, site, rule_id, rule)

    @mcp.tool(name="delete_nat_rule", annotations=WRITE)
    async def delete_nat_rule(host: str, site: str, rule_id: str) -> Any:
        """Delete a NAT rule (Network v2 route). Consequence: permanently removes the rule.

        Resolves rule_id in list_nat_rules first (an unknown id fails listing every valid
        id and nothing is deleted), then DELETE
        /proxy/network/v2/api/site/{site}/nat/{_id}. Returns deleted, message and the
        upstream response verbatim. Never auto-retried.

        Returns deleted, message and response (the upstream body verbatim).
        Under UNIFI_DRY_RUN nothing is sent and the tool returns {status: "dry_run",
        deleted: false, message, response}, where response is the dry-run preview (status,
        dryRun, sent: false, message and preview with method, path, params, body).

        Required arguments: host, site, rule_id.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            rule_id: Required NAT rule _id from list_nat_rules,
                e.g. "65f1c0ffee0123456789abcd".
        """
        return await _SELF.delete_nat_rule(*deps(), host, site, rule_id)

    @mcp.tool(name="list_qos_rules", annotations=READ_ONLY)
    async def list_qos_rules(host: str, site: str) -> Any:
        """List a site's QoS rules (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/qos-rules; the upstream body is returned
        verbatim (no paging parameter). Rule ids (_id) feed update_qos_rule,
        delete_qos_rule and reorder_qos_rules.

        Returns the upstream body verbatim (a JSON object or array, as sent).

        Required arguments: host, site.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
        """
        return await _SELF.list_qos_rules(*deps(), host, site)

    @mcp.tool(name="create_qos_rule", annotations=WRITE)
    async def create_qos_rule(host: str, site: str, rule: dict[str, Any]) -> Any:
        """Create a QoS rule (Network v2 route). Consequence: shapes or prioritises live
        traffic.

        POST /proxy/network/v2/api/site/{site}/qos-rules with rule sent verbatim; the
        upstream body is returned verbatim. The request body is free-form: no field list
        is published, so copy the shape list_qos_rules returns. Never auto-retried.

        Returns the upstream body verbatim (a JSON object or array, as sent).
        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, rule.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            rule: Required free-form QoS rule object in the shape list_qos_rules returns,
                e.g. {"name": "voip", "enabled": false}.
        """
        return await _SELF.create_qos_rule(*deps(), host, site, rule)

    @mcp.tool(name="update_qos_rule", annotations=WRITE)
    async def update_qos_rule(host: str, site: str, rule_id: str, rule: dict[str, Any]) -> Any:
        """Update a QoS rule (Network v2 route). Consequence: changes live traffic shaping.

        Reads the rule from list_qos_rules (an unknown id fails listing every valid id),
        merges only the given leaves, PUTs the merged rule to
        /proxy/network/v2/api/site/{site}/qos-rules/{_id} and reads it back: the upstream
        body is returned plus _verified (type-strict, every requested leaf) and
        _readAfterError when the read-back failed. An empty rule is refused before any
        request.

        Returns the upstream PUT body plus _verified (true only when every requested leaf
        read back equal, type-strict) and _readAfterError when the read-back failed; a
        non-object PUT body is kept under response.
        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, rule_id, rule.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            rule_id: Required QoS rule _id from list_qos_rules,
                e.g. "65f1c0ffee0123456789abcd".
            rule: Required free-form fields to change, e.g. {"enabled": false}.
        """
        return await _SELF.update_qos_rule(*deps(), host, site, rule_id, rule)

    @mcp.tool(name="delete_qos_rule", annotations=WRITE)
    async def delete_qos_rule(
        host: str, site: str, body: dict[str, Any] | list[str | dict[str, Any]]
    ) -> Any:
        """Delete QoS rules (Network v2 batch-delete route). Consequence: permanently removes
        the rules.

        POST /proxy/network/v2/api/site/{site}/qos-rules/batch-delete with body sent
        verbatim (the controller has no single-rule DELETE route). The body is free-form:
        no field list is published. When body is a JSON array of id strings, each id is
        resolved in list_qos_rules first and an unknown id fails listing every valid id
        (nothing is sent). Returns deleted, message and the upstream response verbatim.
        Never auto-retried.

        Returns deleted, message and response (the upstream body verbatim).
        Under UNIFI_DRY_RUN nothing is sent and the tool returns {status: "dry_run",
        deleted: false, message, response}, where response is the dry-run preview (status,
        dryRun, sent: false, message and preview with method, path, params, body).

        Required arguments: host, site, body.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            body: Required free-form batch-delete body (an empty list fails before any
                request), e.g. ["65f1c0ffee0123456789abcd"].
        """
        return await _SELF.delete_qos_rule(*deps(), host, site, body)

    @mcp.tool(name="reorder_qos_rules", annotations=WRITE)
    async def reorder_qos_rules(
        host: str, site: str, body: dict[str, Any] | list[str | dict[str, Any]]
    ) -> Any:
        """Reorder QoS rules (Network v2 route). Consequence: changes which rule matches
        live traffic first.

        PUT /proxy/network/v2/api/site/{site}/qos-rules/batch-reorder with body sent
        verbatim; the upstream body is returned verbatim. The body is free-form: no field
        list is published, so build it from the rule ids list_qos_rules returns. Never
        auto-retried.

        Returns the upstream body verbatim (a JSON object or array, as sent).
        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, body.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            body: Required free-form reorder body (an empty list fails before any request),
                e.g. ["65f1c0ffee0123456789abce", "65f1c0ffee0123456789abcd"].
        """
        return await _SELF.reorder_qos_rules(*deps(), host, site, body)

    @mcp.tool(name="list_content_filters", annotations=READ_ONLY)
    async def list_content_filters(host: str, site: str) -> Any:
        """List a site's content-filtering profiles (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/content-filtering; the upstream body is
        returned verbatim (no paging parameter). Profile ids (_id) feed
        update_content_filter and delete_content_filter.

        Returns the upstream body verbatim (a JSON object or array, as sent).

        Required arguments: host, site.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
        """
        return await _SELF.list_content_filters(*deps(), host, site)

    @mcp.tool(name="create_content_filter", annotations=WRITE)
    async def create_content_filter(host: str, site: str, content_filter: dict[str, Any]) -> Any:
        """Create a content-filtering profile (Network v2 route). Consequence: can block
        web categories for the clients and networks it targets.

        POST /proxy/network/v2/api/site/{site}/content-filtering/create with
        content_filter sent verbatim; the upstream body is returned verbatim. The body is
        free-form: copy the shape list_content_filters returns; category names come from
        list_content_filter_categories. Never auto-retried.

        Returns the upstream body verbatim (a JSON object or array, as sent).
        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, content_filter.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            content_filter: Required free-form profile object,
                e.g. {"name": "kids", "enabled": false}.
        """
        return await _SELF.create_content_filter(*deps(), host, site, content_filter)

    @mcp.tool(name="update_content_filter", annotations=WRITE)
    async def update_content_filter(
        host: str, site: str, filter_id: str, content_filter: dict[str, Any]
    ) -> Any:
        """Update a content-filtering profile (Network v2 route). Consequence: changes
        which web categories are blocked.

        Reads the profile from list_content_filters (an unknown id fails listing every
        valid id), merges only the given leaves, PUTs the merged profile to
        /proxy/network/v2/api/site/{site}/content-filtering/{_id} and reads it back: the
        upstream body is returned plus _verified (type-strict) and _readAfterError when
        the read-back failed. An empty update is refused before any request.

        Returns the upstream PUT body plus _verified (true only when every requested leaf
        read back equal, type-strict) and _readAfterError when the read-back failed; a
        non-object PUT body is kept under response.
        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, filter_id, content_filter.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            filter_id: Required profile _id from list_content_filters,
                e.g. "65f1c0ffee0123456789abcd".
            content_filter: Required free-form fields to change, e.g. {"enabled": false}.
        """
        return await _SELF.update_content_filter(*deps(), host, site, filter_id, content_filter)

    @mcp.tool(name="delete_content_filter", annotations=WRITE)
    async def delete_content_filter(host: str, site: str, filter_id: str) -> Any:
        """Delete a content-filtering profile (Network v2 route). Consequence: permanently
        removes the profile and stops its blocking.

        Resolves filter_id in list_content_filters first (an unknown id fails listing
        every valid id and nothing is deleted), then DELETE
        /proxy/network/v2/api/site/{site}/content-filtering/{_id}. Returns deleted,
        message and the upstream response verbatim. Never auto-retried.

        Returns deleted, message and response (the upstream body verbatim).
        Under UNIFI_DRY_RUN nothing is sent and the tool returns {status: "dry_run",
        deleted: false, message, response}, where response is the dry-run preview (status,
        dryRun, sent: false, message and preview with method, path, params, body).

        Required arguments: host, site, filter_id.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            filter_id: Required profile _id from list_content_filters,
                e.g. "65f1c0ffee0123456789abcd".
        """
        return await _SELF.delete_content_filter(*deps(), host, site, filter_id)

    @mcp.tool(name="list_content_filter_categories", annotations=READ_ONLY)
    async def list_content_filter_categories(host: str, site: str) -> Any:
        """List the content-filtering categories a profile can block (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/content-filtering/categories; the upstream
        body is returned verbatim.

        Returns the upstream body verbatim (a JSON object or array, as sent).

        Required arguments: host, site.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
        """
        return await _SELF.list_content_filter_categories(*deps(), host, site)

    @mcp.tool(name="get_traffic_stats", annotations=READ_ONLY)
    async def get_traffic_stats(host: str, site: str, params: dict[str, Any] | None = None) -> Any:
        """Read the site's traffic statistics over a time window (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/traffic with params forwarded as the query
        string unchanged; the upstream body is returned verbatim. The query keys are
        free-form: the web UI sends start and end (milliseconds), and includeUnidentified.
        An upstream HTTP 400 with a missing window adds a hint.

        Returns the upstream body verbatim (a JSON object or array, as sent).

        Required arguments: host, site.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            params: Optional free-form query parameters, e.g. {"start": 1710000000000,
                "end": 1710003600000, "includeUnidentified": true}. The console
                expects a window in milliseconds; integer window fields add _warnings to
                object results.
        """
        return await _SELF.get_traffic_stats(*deps(), host, site, params)

    @mcp.tool(name="get_latest_traffic_flow_stats", annotations=READ_ONLY)
    async def get_latest_traffic_flow_stats(
        host: str, site: str, period: str | None = "DAY", top: int | None = None
    ) -> Any:
        """Read the latest traffic-flow statistics (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/traffic-flow-latest-statistics with period
        (default DAY; explicit null omits it) and top when given, the two
        keys the web UI sends. The upstream body is returned verbatim.

        Returns the upstream body verbatim (a JSON object or array, as sent).

        Required arguments: host, site.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            period: Observed periods include HOUR, DAY, WEEK and MONTH; default
                "DAY", the web UI's default, e.g. "HOUR".
            top: Optional number of top entries sent as given, e.g. 10.
        """
        return await _SELF.get_latest_traffic_flow_stats(*deps(), host, site, period, top)

    @mcp.tool(name="query_traffic_flows", annotations=READ_ONLY)
    async def query_traffic_flows(
        host: str,
        site: str,
        body: dict[str, Any] | None = None,
        window: str | None = None,
        direction: str | list[str] | None = None,
        action: str | list[str] | None = None,
        risk: str | list[str] | None = None,
    ) -> Any:
        """Query traffic flows: a Network v2 read-POST, available in read-only and dry-run modes.

        POST /proxy/network/v2/api/site/{site}/traffic-flows. Allowlisted by live read
        evidence (2026-10-26, 50+ calls, configuration digests unchanged); UNIFI_DRY_RUN
        sends it normally. Body keys override typed selectors. Window becomes epoch-ms
        timestampFrom/timestampTo; direction, action and risk become lists.

        Without pageSize, drain every page reported by has_next/total_page_count from
        pageNumber (default 0). A body pageSize above 5000 is sent as 5000 per page
        (larger wire sizes cause HTTP 400); at or below 5000 it is sent as given.
        Every integer pageSize requests that many records or fewer at the end, starting
        at pageNumber * pageSize. Upstream errors pass through unchanged. No time-window
        or page-count cap applies, including UNIFI_PAGINATE_MAX_PAGES; large queries can
        consume substantial controller memory and time.

        _nextPage {offset, pageSize} resumes at the first unreturned record: pass the
        object as body.pageNumber, with any new body.pageSize or omit to reuse its size.
        _pageSize {requested, sent, effective, returned} reports each physical request
        size in sent, the observed console size in effective, and the returned count.

        Returns one page without pageSize verbatim, or the last page's envelope with
        gathered data and _pages. Repeated/empty pages claiming more return gathered
        data with incomplete and incompleteReason; a later failure also names its
        zero-based page, status and full upstream error.

        Required arguments: host, site.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            body: Optional free-form query body; its keys take precedence over selectors.
                Explicit timestamps use epoch ms, e.g. {"timestampFrom": 1710000000000}.
            window: Duration converted to epoch-millisecond bounds, e.g. "5m".
            direction: Shape: a string or an array of strings; sent as an array.
                Observed values local, outgoing, incoming (2026-10-26).
                Any value is forwarded for the console to validate, e.g. "outgoing".
            action: Shape: a string or an array of strings; sent as an array.
                Observed values allowed, blocked (2026-10-26).
                Any value is forwarded for the console to validate, e.g. "blocked".
            risk: Shape: a string or an array of strings; sent as an array.
                Observed values low, medium, high (2026-10-26).
                Any value is forwarded for the console to validate, e.g. "high".
        """
        return await _SELF.query_traffic_flows(
            *deps(), host, site, _traffic_flow_body(body, window, direction, action, risk)
        )

    @mcp.tool(name="export_traffic_flows", annotations=WRITE)
    async def export_traffic_flows(host: str, site: str, body: dict[str, Any] | None = None) -> Any:
        """Export traffic flows (Network v2 route; a read-type POST, classed as a write).
        Consequence: none intended (an export); classed as a write because the POST is
        not on the read-POST allowlist.

        POST /proxy/network/v2/api/site/{site}/traffic-flows/export with body sent
        verbatim (free-form; no field list is published). The export is returned whole:
        JSON verbatim (paged JSON is drained as query_traffic_flows does), text as
        {contentType, sizeBytes, body}, any other content base64-encoded as
        {contentType, sizeBytes, bodyBase64}. No size or window cap.
        A body pageSize above 5000 (the largest page the console accepts; it answers a
        larger one with HTTP 400) is sent as pageSize 5000 and paged JSON is gathered until
        the requested total or the end, starting at record pageNumber * pageSize;
        every integer pageSize returns _pages and _pageSize with requested, sent, effective,
        returned. sent lists each physical request size and effective is the observed
        console size. Resume by passing _nextPage {offset, pageSize} as body.pageNumber;
        body.pageSize can change without moving the continuation's record offset.
        A pageSize at or below 5000 is sent as given, and an upstream error for it is
        returned as received.

        Returns a single page without pageSize verbatim; a gathered result is the last
        page's envelope with data holding the requested records, plus _pages, and incomplete with
        incompleteReason when the drain stopped short.
        A non-JSON export returns contentType, sizeBytes and body (text) or bodyBase64.
        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            body: Optional free-form export body,
                e.g. {"timestampFrom": 1710000000000, "timestampTo": 1710003600000}.
        """
        return await _SELF.export_traffic_flows(*deps(), host, site, body)

    @mcp.tool(name="query_app_traffic_rates", annotations=WRITE)
    async def query_app_traffic_rates(
        host: str,
        site: str,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> Any:
        """Query per-application traffic rates (Network v2 route; a read-type POST, classed
        as a write). Consequence: none intended (a query); classed as a write because the
        POST is not on the read-POST allowlist.

        POST /proxy/network/v2/api/site/{site}/app-traffic-rate with params forwarded as
        the query string and body sent verbatim; an omitted body is sent as {} (the route
        requires a body, and the web app sends {} when it filters no app or client). The
        upstream body is returned verbatim.

        Returns the upstream body verbatim (a JSON object or array, as sent).
        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            params: Optional free-form query parameters, e.g.
                {"start": 1710000000000, "end": 1710003600000,
                "includeUnidentified": true}. The pinned Network 11.0.81 UI uses these
                fields, with no period parameter or period enum.
            body: Optional free-form request body filtering apps or clients, e.g.
                {"client_macs": ["02:00:5e:00:53:01"]}; omit it to send {} (no filter).
        """
        return await _SELF.query_app_traffic_rates(*deps(), host, site, params, body)

    @mcp.tool(name="get_poe_info", annotations=READ_ONLY)
    async def get_poe_info(host: str, site: str, params: dict[str, Any] | None = None) -> Any:
        """Read the site's PoE budget and per-port power information (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/poe-info with params forwarded as the query
        string unchanged. The console expects params.mac in lowercase colon form; a missing
        mac on HTTP 400 adds a hint. The upstream body is returned verbatim.

        Returns the upstream body verbatim (a JSON object or array, as sent).

        Required arguments: host, site.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            params: Optional free-form query parameters, e.g. {"mac": "02:00:5e:00:00:a1"}.
        """
        return await _SELF.get_poe_info(*deps(), host, site, params)

    @mcp.tool(name="get_topology_snapshot", annotations=READ_ONLY)
    async def get_topology_snapshot(
        host: str,
        site: str,
        view: Literal["live", "timeline", "timestamps", "at"] = "live",
        start: int | None = None,
        end: int | None = None,
        at: int | None = None,
    ) -> Any:
        """Read the site's network topology snapshot or its history (Network v2 routes).

        With view "live": GET .../topology/snapshot/live. With "timeline" or "timestamps": GET
        .../topology/snapshot/history/{view}?start=&end= (start and end required). With
        "at": GET .../topology/snapshot/history/at/{at} (at required). All under
        /proxy/network/v2/api/site/{site}. Epochs are Unix MILLISECONDS, sent as given;
        the result carries an additive _warnings entry naming the unit. The upstream body
        is returned verbatim.

        Returns the upstream body verbatim (a JSON object or array) plus _warnings for
        history views.

        Required arguments: host, site.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            view: Snapshot view, e.g. "timeline".
            start: Range start, epoch milliseconds, e.g. 1710000000000.
            end: Range end, epoch milliseconds, e.g. 1710003600000.
            at: Instant for view "at", epoch milliseconds, e.g. 1710000000000.
        """
        return await _SELF.get_topology_snapshot(*deps(), host, site, view, start, end, at)
