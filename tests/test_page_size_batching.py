"""Requested totals survive console clamps across the managed pagination families.

Every upstream here is synthetic. It returns the wire envelope of its family and
clamps only the physical page size, so row/order/request assertions catch both
silent truncation and loops caused by advancing by the caller's oversized size.
"""

from __future__ import annotations

from math import ceil
from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import UniFiClient, UniFiConnectionError
from unifi_fabric.config import Settings
from unifi_fabric.registry import Registry
from unifi_fabric.tools import carrier_fabric, mobility, recognition, site_manager
from unifi_fabric.tools._continuation import decode_continuation
from unifi_fabric.tools._keys import context_value, with_context
from unifi_fabric.tools._pagination import (
    collect_batch,
    collect_cursor,
    collect_links,
    collect_offset,
    mark_incomplete,
    offset_list_result,
    verbatim_list_result,
    with_envelope,
)
from unifi_fabric.tools.protect_events_cases import get_protect_case_activity


class ClampingUpstream:
    """A deterministic fake with faithful offset/cursor/links response controls."""

    def __init__(self, family: str, maximum: int, available: int, field: str = "data"):
        self.family = family
        self.maximum = maximum
        self.available = available
        self.field = field
        self.calls: list[dict] = []

    async def get(self, path, *, key=None, params=None):
        params = dict(params or {})
        self.calls.append(params)
        size_key = "limit" if self.family in {"offset", "carrier"} else "pageSize"
        size = min(params[size_key], self.maximum)
        if self.family == "offset":
            start = params.get("offset", 0)
        elif self.family == "links":
            start = (params.get("page", 1) - 1) * size
        elif self.family == "number":
            start = params.get("pageNumber", 0) * size
        else:
            start = int(params.get("cursor", params.get("nextToken", "0")))
        stop = min(start + size, self.available)
        result = {self.field: [{"id": str(i)} for i in range(start, stop)], "traceId": "synthetic"}
        if self.family == "offset":
            result.update(offset=start, limit=size, count=stop - start, totalCount=self.available)
        elif self.family == "links":
            result["links"] = {
                "next": f"?pageSize={size}&page={params.get('page', 1) + 1}"
                if stop < self.available
                else None
            }
        elif self.family == "carrier":
            result["meta"] = {
                "limit": size,
                "hasMore": stop < self.available,
                "nextCursor": str(stop) if stop < self.available else None,
            }
        elif self.family == "number":
            result.update(
                page_number=params.get("pageNumber", 0),
                total_page_count=ceil(self.available / size),
            )
        elif stop < self.available:
            result["nextToken"] = str(stop)
        return result


def _client(upstream):
    client = UniFiClient(Settings(api_key="synthetic-page-size-test"))
    client.get = upstream.get
    return client


def _assert_rows(rows, count):
    assert rows == [{"id": str(i)} for i in range(count)]


def _count(family, requested, maximum, available):
    physical = min(requested, maximum)
    # Page-only and opaque-cursor continuations cannot resume inside a page.
    boundary = requested if family == "offset" else ceil(requested / physical) * physical
    return min(boundary, available)


def _links_count(requested, available):
    return min(requested, available)


def _controls(family, requested, maximum, available, *, known_max=True, start=0):
    count = _count(family, requested, maximum, available)
    physical = min(requested, maximum)
    controls = []
    consumed = 0
    while not controls or consumed < count:
        size = min(requested, maximum) if known_max else requested
        if controls and family not in {"cursor", "carrier"}:
            size = physical
        if family == "offset":
            size = min(size, requested - consumed)
        control = {"limit" if family in {"offset", "carrier"} else "pageSize": size}
        if family == "offset" and (start or controls):
            control["offset"] = start + consumed
        elif family == "number":
            control["pageNumber"] = start + len(controls)
        elif family == "links":
            control["page"] = start + len(controls)
        elif consumed:
            control["cursor" if family == "carrier" else "nextToken"] = str(consumed)
        controls.append(control)
        consumed += min(physical, size, available - consumed)
    if family == "offset" and len(controls) == 1 and count < available:
        controls.append({"offset": start + count, "limit": 1})
    return controls


def _page_size(requested, controls, family, effective, returned):
    key = "limit" if family in {"offset", "carrier"} else "pageSize"
    return {
        "requested": requested,
        "sent": [control[key] for control in controls],
        "effective": effective,
        "returned": returned,
    }


async def _assert_links_followup(upstream, result, count):
    requested = result["_pageSize"]["requested"]
    expected = 2 if count < upstream.available else None
    assert result["nextPage"] == expected
    if expected is None:
        return
    before = len(upstream.calls)
    followup = await collect_links(
        _client(upstream), "/synthetic", upstream.field, page=2, page_size=requested
    )
    assert followup["items"] == [
        {"id": str(i)} for i in range(count, min(count + requested, upstream.available))
    ]
    assert upstream.calls[before:] == [{"page": page, "pageSize": 100} for page in [3, 4, 5, 6]]
    assert followup["_pageSize"] == {
        "requested": requested,
        "sent": [100, 100, 100, 100],
        "effective": 100,
        "returned": 275,
    }
    assert followup["nextPage"] == 3
    assert not followup["incomplete"]


async def _assert_native_followup(upstream, result, family, count, maximum):
    continuation_key = {
        "offset": "nextOffset",
        "cursor": "nextToken",
        "carrier": "nextCursor",
        "number": "nextPage",
        "links": "nextPage",
    }[family]
    expected = (
        (
            count
            if family == "offset"
            else str(count)
            if family in {"cursor", "carrier"}
            else count // maximum + (family == "links")
        )
        if count < upstream.available
        else None
    )
    assert result[continuation_key] == expected
    if expected is None:
        return
    before = len(upstream.calls)
    key = "limit" if family in {"offset", "carrier"} else "pageSize"
    # Native cursor strings remain visible; the additive continuation binds the
    # original physical size so a changed logical size cannot reinterpret a page-index token.
    wire_size = upstream.calls[0][key] if family in {"cursor", "carrier"} else maximum
    follow_size = max(1, maximum // 2) if family in {"cursor", "carrier"} else maximum
    token = None
    if family in {"cursor", "carrier"}:
        token_key = "pageToken" if family == "cursor" else "cursor"
        size_key = "pageSize" if family == "cursor" else "limit"
        assert isinstance(result["_continuation"], str)
        assert decode_continuation(result["_continuation"]) == {
            token_key: expected,
            size_key: wire_size,
        }
        token = result["_continuation"]
    followup = await collect_batch(
        lambda controls: upstream.get("/synthetic", params=controls),
        requested=follow_size,
        known_max=maximum,
        family=family,
        start=expected if family in {"offset", "number", "links"} else 0,
        token=token,
    )
    assert followup["items"] == [
        {"id": str(i)} for i in range(count, min(count + maximum, upstream.available))
    ]
    position_key = {
        "offset": "offset",
        "number": "pageNumber",
        "links": "page",
        "cursor": "nextToken",
        "carrier": "cursor",
    }[family]
    expected_calls = [{key: wire_size, position_key: expected}]
    if family == "offset" and count + maximum < upstream.available:
        expected_calls.append({"offset": count + maximum, "limit": 1})
    assert upstream.calls[before:] == expected_calls
    assert followup["_pageSize"] == {
        "requested": follow_size,
        "sent": [call[key] for call in expected_calls],
        "effective": maximum,
        "returned": min(maximum, upstream.available - count),
    }


@pytest.mark.parametrize(
    ("family", "maximum"),
    [
        ("offset", 200),
        ("offset", 1000),
        ("links", 100),
        ("cursor", 200),
        ("carrier", 500),
        ("number", 200),
    ],
)
@pytest.mark.parametrize(("requested", "available"), [(1000, 450), (10000, 215), (275, 900)])
async def test_shared_batch_gathers_requested_total_at_effective_maximum(
    family, maximum, requested, available
):
    upstream = ClampingUpstream(family, maximum, available)
    result = await collect_batch(
        lambda controls: upstream.get("/synthetic", params=controls),
        requested=requested,
        known_max=None if family in {"cursor", "number"} else maximum,
        family=family,
        start=1 if family == "links" else 0,
    )
    # Old exact requested-length + fixed-size assertions encoded the 125-record skip:
    # retain full opaque/page-only final pages, but make offset tails exactly N.
    count = _count(family, requested, maximum, available)
    expected_controls = _controls(
        family,
        requested,
        maximum,
        available,
        known_max=family not in {"cursor", "number"},
        start=1 if family == "links" else 0,
    )
    _assert_rows(result["items"], count)
    assert upstream.calls == expected_controls
    assert result["_pageSize"] == _page_size(
        requested, expected_controls, family, min(requested, maximum), count
    )
    assert not result["incomplete"]
    assert result["envelope"]["traceId"] == "synthetic"
    await _assert_native_followup(upstream, result, family, count, min(requested, maximum))


@pytest.mark.parametrize(("requested", "available"), [(1000, 450), (10000, 215), (275, 900)])
@pytest.mark.parametrize("family", ["offset", "links", "cursor"])
async def test_collection_entry_points_use_effective_batching(family, requested, available):
    maximum = 100 if family == "links" else 200
    upstream = ClampingUpstream(family, maximum, available)
    client = _client(upstream)
    if family == "offset":
        result = await collect_offset(client, "/synthetic", limit=requested)
    elif family == "links":
        result = await collect_links(client, "/synthetic", "data", page_size=requested)
    else:
        result = await collect_cursor(client, "/synthetic", page_size=requested, one_page=True)
    # Old exact-length assertions trimmed records behind links/opaque tokens and skipped them.
    count = (
        _links_count(requested, available)
        if family == "links"
        else _count(family, requested, maximum, available)
    )
    expected_controls = _controls(
        family,
        requested,
        maximum,
        available,
        known_max=family != "cursor",
        start=1 if family == "links" else 0,
    )
    _assert_rows(result["items"], count)
    assert upstream.calls == expected_controls
    assert result["_pageSize"] == _page_size(
        requested, expected_controls, family, min(requested, maximum), count
    )
    assert not result["incomplete"]
    if family == "links":
        await _assert_links_followup(upstream, result, count)
    else:
        await _assert_native_followup(upstream, result, family, count, min(requested, maximum))


@pytest.mark.parametrize("name", ["list_hosts", "list_sites", "list_devices"])
@pytest.mark.parametrize(("requested", "available"), [(1000, 450), (10000, 215), (275, 900)])
async def test_site_manager_page_size_drains_next_token(name, requested, available):
    upstream = ClampingUpstream("cursor", 200, available)
    client = _client(upstream)
    registry = Registry(client)
    result = await getattr(site_manager, name)(client, registry, page_size=requested)
    # Old exact-N assertion discarded 125 records before handing back the page-end token.
    count = _count("cursor", requested, 200, available)
    expected_controls = _controls("cursor", requested, 200, available, known_max=False)
    _assert_rows(result["data"], count)
    assert upstream.calls == expected_controls
    assert result["_pageSize"] == _page_size(requested, expected_controls, "cursor", 200, count)
    assert "incomplete" not in result
    assert result.get("nextToken") == (str(count) if count < available else None)
    if count < available:
        before = len(upstream.calls)
        next_result = await getattr(site_manager, name)(
            client, registry, page_token=result["nextToken"], page_size=200
        )
        assert next_result["data"] == [
            {"id": str(i)} for i in range(count, min(count + 200, available))
        ]
        assert upstream.calls[before:] == [{"pageSize": 200, "nextToken": str(count)}]


@pytest.mark.parametrize("name", ["list_mobility_devices", "list_mobility_clients"])
@pytest.mark.parametrize(("requested", "available"), [(1000, 450), (10000, 215), (275, 900)])
async def test_mobility_tools_batch_spec_maximum(name, requested, available):
    upstream = ClampingUpstream("offset", 200, available)
    client = _client(upstream)
    args = [client, "11111111-1111-4111-8111-111111111111"]
    if name == "list_mobility_clients":
        args.append("22222222-2222-4222-8222-222222222222")
    result = await getattr(mobility, name)(*args, limit=requested)
    # Old fixed-size tail assertion encoded overfetch-and-trim; offset tails can request N exactly.
    count = min(requested, available)
    expected_controls = _controls("offset", requested, 200, available)
    _assert_rows(result["data"], count)
    assert upstream.calls == expected_controls
    assert result["_pageSize"] == _page_size(requested, expected_controls, "offset", 200, count)
    assert result.get("_nextOffset") == (count if count < available else None)
    if count < available:
        before = len(upstream.calls)
        next_result = await getattr(mobility, name)(*args, offset=result["_nextOffset"], limit=200)
        assert next_result["data"] == [
            {"id": str(i)} for i in range(count, min(count + 200, available))
        ]
        assert upstream.calls[before:] == [
            {"offset": count, "limit": 200},
            {"offset": count + 200, "limit": 1},
        ]


@pytest.mark.parametrize(("requested", "available"), [(1000, 450), (10000, 215), (725, 1400)])
async def test_carrier_subscribers_batch_spec_maximum(requested, available):
    upstream = ClampingUpstream("carrier", 500, available)
    client = _client(upstream)
    result = await carrier_fabric.list_carrier_subscribers(client, limit=requested)
    # Old exact-N assertion hid records behind the native page-end carrier cursor.
    count = _count("carrier", requested, 500, available)
    expected_controls = _controls("carrier", requested, 500, available)
    _assert_rows(result["data"], count)
    assert upstream.calls == expected_controls
    assert result["_pageSize"] == _page_size(requested, expected_controls, "carrier", 500, count)
    assert result["meta"]["nextCursor"] == (str(count) if count < available else None)
    assert result["meta"]["hasMore"] is (count < available)
    if count < available:
        before = len(upstream.calls)
        next_result = await carrier_fabric.list_carrier_subscribers(
            client, cursor=result["meta"]["nextCursor"], limit=500
        )
        assert next_result["data"] == [
            {"id": str(i)} for i in range(count, min(count + 500, available))
        ]
        assert upstream.calls[before:] == [{"limit": 500, "cursor": str(count)}]


@pytest.mark.parametrize(
    ("name", "field"),
    [
        ("list_recognition_groups", "groups"),
        ("list_recognition_detections", "detections"),
        ("get_protect_case_activity", "activities"),
    ],
)
@pytest.mark.parametrize(("requested", "available"), [(1000, 450), (10000, 215), (275, 900)])
async def test_protect_links_tools_batch_effective_maximum(name, field, requested, available):
    upstream = ClampingUpstream("links", 100, available, field)
    client = _client(upstream)
    registry = Registry(client)
    registry.resolve_key_for_host = AsyncMock(return_value=None)
    registry.resolve_host_id = AsyncMock(return_value="synthetic-host")
    if name == "get_protect_case_activity":
        result = await get_protect_case_activity(
            client, registry, "synthetic-host", "case-1", page_size=requested
        )
    elif name == "list_recognition_detections":
        result = await recognition.list_recognition_detections(
            client, registry, "synthetic-host", "face", "group-1", page_size=requested
        )
    else:
        result = await recognition.list_recognition_groups(
            client, registry, "synthetic-host", "face", page_size=requested
        )
    # Old exact-N assertion truncated the linked final page and skipped its unreturned rows.
    count = _links_count(requested, available)
    expected_controls = _controls("links", requested, 100, available, start=1)
    _assert_rows(result[field], count)
    assert upstream.calls == expected_controls
    assert result["_pageSize"] == _page_size(requested, expected_controls, "links", 100, count)
    assert result.get("_nextPage") == (2 if count < available else None)
    if count < available:
        before = len(upstream.calls)
        paging = {"page": result["_nextPage"], "page_size": requested}
        if name == "get_protect_case_activity":
            next_result = await get_protect_case_activity(
                client, registry, "synthetic-host", "case-1", **paging
            )
        elif name == "list_recognition_detections":
            next_result = await recognition.list_recognition_detections(
                client, registry, "synthetic-host", "face", "group-1", **paging
            )
        else:
            next_result = await recognition.list_recognition_groups(
                client, registry, "synthetic-host", "face", **paging
            )
        assert next_result[field] == [
            {"id": str(i)} for i in range(count, min(count + requested, available))
        ]
        assert upstream.calls[before:] == [{"pageSize": 100, "page": page} for page in [3, 4, 5, 6]]
        assert next_result["_pageSize"] == {
            "requested": 275,
            "sent": [100, 100, 100, 100],
            "effective": 100,
            "returned": 275,
        }
        assert next_result["_nextPage"] == 3
        assert "incomplete" not in next_result


@pytest.mark.parametrize("family", ["offset", "cursor", "links", "carrier", "number"])
async def test_requested_aggregate_strips_first_page_controls(family):
    upstream = ClampingUpstream(family, 100, 250)
    result = await collect_batch(
        lambda controls: upstream.get("/synthetic", params=controls),
        requested=1000,
        known_max=100,
        family=family,
        start=1 if family == "links" else 0,
    )
    assert len(upstream.calls) == 3
    _assert_rows(result["items"], 250)
    assert result["envelope"] == {
        "traceId": "synthetic",
        **(
            {"totalCount": 250}
            if family == "offset"
            else {"page_number": 0, "total_page_count": 3}
            if family == "number"
            else {}
        ),
    }
    # Old sent=100 described the observed clamp; A5 records every actual wire size.
    assert result["_pageSize"] == {
        "requested": 1000,
        "sent": [100, 100, 100],
        "effective": 100,
        "returned": 250,
    }


async def test_requested_single_page_preserves_native_envelope():
    upstream = ClampingUpstream("offset", 200, 50)
    result = await collect_batch(
        lambda controls: upstream.get("/synthetic", params=controls),
        requested=1000,
        known_max=200,
        family="offset",
    )
    assert result["envelope"] == {
        "traceId": "synthetic",
        "offset": 0,
        "limit": 200,
        "count": 50,
        "totalCount": 50,
    }
    # Old sent=200 described the clamp; retain that as effective and assert the wire request.
    assert result["_pageSize"] == {
        "requested": 1000,
        "sent": [200],
        "effective": 200,
        "returned": 50,
    }


@pytest.mark.parametrize("rows", [[], [{"id": "0"}]])
@pytest.mark.parametrize("allow_unpaged", [False, True])
async def test_requested_bare_array_has_aggregate_and_page_size(rows, allow_unpaged):
    fetch = AsyncMock(side_effect=[rows, []]) if rows else AsyncMock(return_value=rows)
    result = await collect_batch(fetch, requested=1000, allow_unpaged=allow_unpaged)
    assert result["items"] == rows
    assert result["array_key"] == "data"
    assert result["_pageSize"] == {
        "requested": 1000,
        "sent": [1000, 1000] if rows else [1000],
        "effective": 1000,
        "returned": len(rows),
    }
    assert not result["incomplete"]
    if rows:
        assert fetch.await_count == 2
        assert fetch.await_args_list[1].args == ({"pageNumber": 1, "pageSize": 1000},)
    else:
        fetch.assert_awaited_once()


@pytest.mark.parametrize("malformed", [None, "invalid", {"unexpected": []}])
async def test_malformed_later_response_retains_collected_records(malformed):
    first = {"data": [{"id": "0"}], "page_number": 0, "total_page_count": 2}
    fetch = AsyncMock(side_effect=[first, malformed])
    result = await collect_batch(fetch, requested=1000)
    assert result["items"] == first["data"]
    assert result["incomplete"]
    assert "without a records array" in result["incompleteReason"]
    # Old sent=1 hid the oversized first request and its observed clamp.
    assert result["_pageSize"] == {
        "requested": 1000,
        "sent": [1000, 1],
        "effective": 1,
        "returned": 1,
    }
    assert fetch.await_count == 2


async def test_default_bare_array_drain_retains_historical_array_key():
    rows = [{"id": "0"}]
    result = await collect_batch(AsyncMock(return_value=rows), requested=None, family="offset")
    assert result["items"] == rows
    assert result["array_key"] is None
    assert "_pageSize" not in result


@pytest.mark.parametrize("family", ["offset", "cursor", "carrier", "links"])
@pytest.mark.parametrize("malformed", [None, True, 1, "invalid"])
async def test_non_number_first_page_rejects_scalar_body(family, malformed):
    with pytest.raises(UniFiConnectionError):
        await collect_batch(AsyncMock(return_value=malformed), requested=1000, family=family)


@pytest.mark.parametrize(
    ("name", "field"),
    [
        ("list_recognition_groups", "groups"),
        ("list_recognition_detections", "detections"),
        ("get_protect_case_activity", "activities"),
    ],
)
@pytest.mark.parametrize(
    ("paging", "expected_ids", "expected_pages"),
    [
        ({}, [0, 1, 2, 3, 4], [1, 2, 3]),
        ({"page_size": 4}, [0, 1, 2, 3], [1, 2]),
        ({"page": 2}, [2, 3], [2]),
        ({"page": 2, "page_size": 3}, [3, 4], [2, 3]),
    ],
)
async def test_links_tools_drain_without_total_and_preserve_explicit_paging(
    name, field, paging, expected_ids, expected_pages
):
    calls = []

    async def get(path, *, key=None, params=None):
        controls = dict(params or {})
        calls.append(controls)
        page = controls["page"]
        start = (page - 1) * 2
        return {
            field: [{"id": str(i)} for i in range(start, min(start + 2, 5))],
            "links": {"next": f"?page={page + 1}&pageSize=2"} if page < 3 else {},
            "traceId": "synthetic-links-drain",
        }

    client = UniFiClient(Settings(api_key="synthetic-links-drain"))
    client.get = get
    registry = Registry(client)
    registry.resolve_key_for_host = AsyncMock(return_value=None)
    registry.resolve_host_id = AsyncMock(return_value="synthetic-host")
    try:
        if name == "get_protect_case_activity":
            result = await get_protect_case_activity(
                client, registry, "synthetic-host", "case-1", **paging
            )
        elif name == "list_recognition_detections":
            result = await recognition.list_recognition_detections(
                client, registry, "synthetic-host", "face", "group-1", **paging
            )
        else:
            result = await recognition.list_recognition_groups(
                client, registry, "synthetic-host", "face", **paging
            )
        assert result[field] == [{"id": str(i)} for i in expected_ids]
        assert result["_count"] == len(expected_ids)
        if "page_size" in paging:
            assert len(result[field]) <= paging["page_size"]
        assert [call["page"] for call in calls] == expected_pages
        assert result["traceId"] == "synthetic-links-drain"
        assert "incomplete" not in result
        if paging == {"page": 2}:
            assert calls == [{"page": 2}]
            assert result["_nextPage"] == 3
        elif "page_size" in paging:
            # Old sent=2 hid the first requested size; preserve exact effective and sent sizes.
            assert result["_pageSize"] == {
                "requested": paging["page_size"],
                "sent": [paging["page_size"], *([2] * (len(expected_pages) - 1))],
                "effective": 2,
                "returned": len(expected_ids),
            }
            assert calls[0]["pageSize"] == paging["page_size"]
            assert all(call["pageSize"] == 2 for call in calls[1:])
        else:
            assert calls == [
                {"page": 1, "pageSize": 100},
                {"page": 2, "pageSize": 2},
                {"page": 3, "pageSize": 2},
            ]
            assert "_pageSize" not in result
            assert "_nextPage" not in result
    finally:
        await client.close()


@pytest.mark.parametrize("name", ["list_mobility_devices", "list_mobility_clients"])
async def test_mobility_small_total_survives_a_smaller_wire_page(name):
    upstream = ClampingUpstream("offset", 2, 12)
    client = _client(upstream)
    args = [client, "11111111-1111-4111-8111-111111111111"]
    if name == "list_mobility_clients":
        args.append("22222222-2222-4222-8222-222222222222")
    result = await getattr(mobility, name)(*args, limit=3)
    _assert_rows(result["data"], 3)
    # Old fixed-size tail assertion overfetched; an offset API can send the exact remainder.
    assert result["_pageSize"] == {"requested": 3, "sent": [3, 1], "effective": 2, "returned": 3}
    # The caller supplied only limit, so the first request must not invent offset=0.
    assert upstream.calls == [{"limit": 3}, {"limit": 1, "offset": 2}]
    assert result["_nextOffset"] == 3
    next_result = await getattr(mobility, name)(*args, offset=result["_nextOffset"], limit=2)
    assert next_result["data"] == [{"id": "3"}, {"id": "4"}]
    assert upstream.calls[2:] == [{"offset": 3, "limit": 2}, {"offset": 5, "limit": 1}]


class CollidingUpstream(ClampingUpstream):
    """Synthetic upstream fields must survive server pagination context."""

    async def get(self, path, *, key=None, params=None):
        result = await super().get(path, key=key, params=params)
        return {
            **result,
            "_count": "upstream-count",
            "_pageSize": "upstream-page-size",
            "_wrapperFields": {"upstream": True},
        }


@pytest.mark.parametrize("name", ["list_mobility_devices", "list_mobility_clients"])
@pytest.mark.parametrize("requested", [None, 3])
async def test_mobility_pagination_preserves_colliding_upstream_metadata(name, requested):
    upstream = CollidingUpstream("offset", 2, 3)
    client = _client(upstream)
    args = [client, "11111111-1111-4111-8111-111111111111"]
    if name == "list_mobility_clients":
        args.append("22222222-2222-4222-8222-222222222222")
    try:
        result = await getattr(mobility, name)(*args, limit=requested)
        _assert_rows(result["data"], 3)
        assert result["_count"] == "upstream-count"
        assert result["_pageSize"] == "upstream-page-size"
        assert result["_wrapperFields"] == {"upstream": True}
        if requested is None:
            assert result["_wrapperFields_2"] == {"_count": 3}
            assert context_value(result, "_count", strict=True) == 3
        else:
            assert result["_wrapperFields_2"] == {
                "_pageSize": {"requested": 3, "sent": [3, 1], "effective": 2, "returned": 3}
            }
            assert context_value(result, "_pageSize", strict=True) == {
                "requested": 3,
                "sent": [3, 1],
                "effective": 2,
                "returned": 3,
            }
    finally:
        await client.close()


@pytest.mark.parametrize("pattern", ["with_context", "with_envelope", "offset", "verbatim"])
async def test_pagination_result_patterns_preserve_colliding_upstream_metadata(pattern):
    upstream = CollidingUpstream("offset", 2, 3)
    collected = await collect_batch(
        lambda controls: upstream.get("/synthetic", params=controls),
        requested=3,
        known_max=2,
        family="offset",
    )
    body = {**collected["envelope"], "data": collected["items"]}
    if pattern == "with_context":
        result = with_context(body, {"_count": 3})
    elif pattern == "with_envelope":
        result = with_envelope({"data": collected["items"], "_count": 3}, collected)
    elif pattern == "offset":
        result = offset_list_result(collected)
    else:
        result = verbatim_list_result(body, collected["items"], "/synthetic")
    result = mark_incomplete(result, collected)
    _assert_rows(result["data"], 3)
    assert result["_count"] == "upstream-count"
    assert result["_pageSize"] == "upstream-page-size"
    assert result["_wrapperFields"] == {"upstream": True}
    if pattern == "offset":
        assert result["_wrapperFields_2"] == {
            "_pageSize": {"requested": 3, "sent": [2, 1], "effective": 2, "returned": 3}
        }
    else:
        assert result["_wrapperFields_2"] == {"_count": 3}
        assert result["_wrapperFields_3"] == {
            "_pageSize": {"requested": 3, "sent": [2, 1], "effective": 2, "returned": 3}
        }
    assert context_value(result, "_pageSize", strict=True) == {
        "requested": 3,
        "sent": [2, 1],
        "effective": 2,
        "returned": 3,
    }
