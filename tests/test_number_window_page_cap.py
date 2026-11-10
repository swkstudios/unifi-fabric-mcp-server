"""UNIFI_PAGINATE_MAX_PAGES on number-family windows; synthetic upstreams only.

Every request of a window counts against one page budget:
- page 0 discovery: a call that starts past page 0 and cannot prove the console page size
  from its first page asks for page 0; with the budget spent, no discovery request is sent
  and the result says why (window and page-number drain, with uncapped controls);
- page_size alone: the window at page 0 gathers clamped console pages under the cap and
  stops incomplete, with the cap as the reason and no continuation, on every tool;
- the page-1 repeat check after a short page 0: the request that shows a console ignores
  pageNumber is inside the budget, so a cap of 1 stops the window incomplete with the cap
  as the reason, and a cap of 2 sends the check, whose repeat is the reason.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from unifi_fabric.families.network import network_controller_insights
from unifi_fabric.families.statistics import system_log
from unifi_fabric.families.vpn import network_vpn_dns
from unifi_fabric.shared_shapes._number_window import collect_number_window
from unifi_fabric.shared_shapes._pagination import collect_batch

RECORDS = list(range(100))


def _console(calls: list[dict[str, Any]], width: int = 4, total: int | None = None) -> Any:
    """A console that clamps pageSize to ``width`` and declares no page count; ``total``
    adds a declared ``totalCount``."""

    async def fetch(controls: dict[str, Any]) -> Any:
        calls.append(dict(controls))
        number = controls["pageNumber"]
        body: dict[str, Any] = {"data": RECORDS[number * width : (number + 1) * width]}
        if total is not None:
            body["totalCount"] = total
        return body

    return fetch


async def test_window_page_cap_reached_before_page_zero_discovery():
    calls: list[dict[str, Any]] = []
    window = await collect_number_window(
        _console(calls, total=100), page=3, page_size=10, max_pages=1
    )
    # Page 3 held records but proved no console page size; page 0 was not requested. The
    # capped result keeps the declared totalCount of the page it read.
    assert calls == [{"pageNumber": 3, "pageSize": 10}]
    assert window["totalCount"] == 100
    assert window["items"] == []
    assert window["incomplete"] is True
    assert window["incompleteReason"] == "UNIFI_PAGINATE_MAX_PAGES page cap of 1 reached"
    assert window["nextPage"] is None
    assert window["pages"] == 1
    assert window["_pageSize"] == {"requested": 10, "sent": [10], "effective": None, "returned": 0}


async def test_window_discovery_uses_the_budget_when_it_allows():
    calls: list[dict[str, Any]] = []
    window = await collect_number_window(_console(calls), page=3, page_size=10, max_pages=None)
    assert calls[:2] == [{"pageNumber": 3, "pageSize": 10}, {"pageNumber": 0, "pageSize": 10}]
    assert window["items"] == RECORDS[30:40]
    assert not window["incomplete"]
    assert window["nextPage"] == 4

    # A console that ignores pageNumber and pageSize answers the discovery request with the
    # probe's oversized page again. Inside a budget of two requests that page is the whole
    # unpaged collection, and the window is selected from it, complete.
    rows = [{"id": i} for i in range(100)]
    calls = []

    async def unpaged(controls: dict[str, Any]) -> Any:
        calls.append(dict(controls))
        return {"data": list(rows)}

    window = await collect_number_window(unpaged, page=3, page_size=10, max_pages=2)
    assert calls == [{"pageNumber": 3, "pageSize": 10}, {"pageNumber": 0, "pageSize": 10}]
    assert window["items"] == rows[30:40]
    assert not window["incomplete"]
    assert window["nextPage"] == 4
    assert window["_pageSize"] == {
        "requested": 10,
        "sent": [10, 10],
        "effective": 100,
        "returned": 10,
    }


@pytest.mark.parametrize("cap", [2, 3])
async def test_window_cap_after_discovery_stops_the_gather_incomplete(cap):
    calls: list[dict[str, Any]] = []
    window = await collect_number_window(
        _console(calls, total=100), page=3, page_size=10, max_pages=cap
    )
    # The page-0 check and discovery spend two requests; none is sent past the cap. The
    # declared totalCount survives the stop.
    assert len(calls) == cap
    assert calls[:2] == [{"pageNumber": 3, "pageSize": 10}, {"pageNumber": 0, "pageSize": 10}]
    assert window["incomplete"] is True
    assert window["incompleteReason"] == f"UNIFI_PAGINATE_MAX_PAGES page cap of {cap} reached"
    assert window["nextPage"] is None
    assert window["totalCount"] == 100


async def test_tool_window_respects_paginate_max_pages_before_discovery():
    requests: list[dict[str, Any]] = []

    async def post(path, *, key=None, json=None, always_write=False):
        requests.append(dict(json))
        number = json["pageNumber"]
        return {"data": RECORDS[number * 4 : (number + 1) * 4], "traceId": "synthetic-cap"}

    client = SimpleNamespace(post=post, paginate_max_pages=1)
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = None
    registry.resolve_host_id.return_value = "console"
    result = await network_controller_insights.get_sites_overview(
        client, registry, "console", page=3, page_size=10
    )
    assert requests == [{"pageNumber": 3, "pageSize": 10}]
    assert result["data"] == []
    assert result["_incomplete"] is True
    assert result["_incompleteReason"] == "UNIFI_PAGINATE_MAX_PAGES page cap of 1 reached"
    assert "_nextPage" not in result

    # An empty page 3 whose declared totalCount (25) ends before the window start (30)
    # proves the window empty: no discovery request is needed, so the cap is never reached.
    requests.clear()

    async def past_the_end(path, *, key=None, json=None):
        requests.append(dict(json))
        return {"data": [], "totalCount": 25, "traceId": "synthetic-cap"}

    result = await network_controller_insights.get_sites_overview(
        SimpleNamespace(post=past_the_end, paginate_max_pages=1),
        registry,
        "console",
        page=3,
        page_size=10,
    )
    assert requests == [{"pageNumber": 3, "pageSize": 10}]
    assert result["data"] == []
    assert "_incomplete" not in result
    assert "_nextPage" not in result


async def test_drain_page_cap_reached_before_page_zero_discovery():
    calls: list[dict[str, Any]] = []
    collected = await collect_batch(
        _console(calls), requested=10, default_size=None, family="number", start=2, max_pages=1
    )
    assert calls == [{"pageNumber": 2, "pageSize": 10}]
    # The original page is returned, marked incomplete with the cap as the reason.
    assert collected["items"] == RECORDS[8:12]
    assert collected["incomplete"] is True
    assert collected["incompleteReason"] == (
        "UNIFI_PAGINATE_MAX_PAGES page cap of 1 reached before page 0 could establish the "
        "page-2 origin; returned the original page only"
    )
    assert collected["nextPage"] is None


async def test_drain_discovery_is_sent_when_the_budget_allows():
    # The budget decides: a cap of 2 leaves room for the discovery request, a cap of 1 does
    # not, and the request is never sent past it.
    for cap, expected in (
        (2, [{"pageNumber": 2, "pageSize": 10}, {"pageNumber": 0, "pageSize": 10}]),
        (1, [{"pageNumber": 2, "pageSize": 10}]),
    ):
        calls: list[dict[str, Any]] = []
        await collect_batch(
            _console(calls),
            requested=10,
            default_size=None,
            family="number",
            start=2,
            max_pages=cap,
        )
        assert calls == expected, cap


CAP_REASON = "UNIFI_PAGINATE_MAX_PAGES page cap of {cap} reached"
REPEAT_REASON = (
    "page 1 repeated the entries of an earlier page; the controller did not page by "
    "pageNumber, so the window cannot be located"
)
ROWS = [{"id": i} for i in range(100)]


def _registry() -> AsyncMock:
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = None
    registry.resolve_host_id.return_value = "console"
    registry.resolve_site_slug.return_value = "default"
    return registry


async def _tool(tool: str, post: Any, cap: int, page: int | None, size: int) -> Any:
    client = SimpleNamespace(post=post, paginate_max_pages=cap)
    if tool == "system_log":
        return await system_log._read_system_log(
            client, _registry(), "console", "default", "all", None, page=page, page_size=size
        )
    if tool == "overview":
        return await network_controller_insights.get_sites_overview(
            client, _registry(), "console", page=page, page_size=size
        )
    return await network_vpn_dns.query_teleport_invitations(
        client, _registry(), "console", "default", page_number=page, page_size=size
    )


def _incomplete(result: dict[str, Any]) -> tuple[Any, Any]:
    if "_incomplete" in result:
        return result["_incomplete"], result["_incompleteReason"]
    return result.get("incomplete"), result.get("incompleteReason")


@pytest.mark.parametrize("tool", ["system_log", "overview", "teleport"])
async def test_page_size_alone_window_stops_at_the_cap_without_a_continuation(tool):
    requests: list[dict[str, Any]] = []

    async def post(path, *, key=None, json=None, always_write=False):
        # Clamps pageSize to 4 and declares no total or page count.
        requests.append({k: json[k] for k in ("pageNumber", "pageSize")})
        number = json["pageNumber"]
        return {"data": ROWS[number * 4 : number * 4 + 4]}

    result = await _tool(tool, post, 2, None, 10)
    assert requests == [{"pageNumber": 0, "pageSize": 10}, {"pageNumber": 1, "pageSize": 4}]
    assert result["data"] == ROWS[0:8]
    assert _incomplete(result) == (True, CAP_REASON.format(cap=2))
    assert "_nextPage" not in result
    assert result["_pageSize"] == {"requested": 10, "sent": [10, 4], "effective": 4, "returned": 8}


@pytest.mark.parametrize("cap", [1, 2])
async def test_short_page_zero_repeat_check_is_inside_the_cap(cap):
    calls: list[dict[str, Any]] = []
    rows = ROWS[0:3]

    async def fetch(controls: dict[str, Any]) -> Any:
        # Ignores pageNumber: every page is the same short page.
        calls.append(dict(controls))
        return {"data": rows}

    window = await collect_number_window(fetch, page=0, page_size=10, max_pages=cap)
    assert window["items"] == rows
    assert window["nextPage"] is None
    if cap == 1:
        # The repeat check would be a second request: the window stops incomplete.
        assert calls == [{"pageNumber": 0, "pageSize": 10}]
        assert window["incomplete"] is True
        assert window["incompleteReason"] == CAP_REASON.format(cap=1)
    else:
        assert calls == [{"pageNumber": 0, "pageSize": 10}, {"pageNumber": 1, "pageSize": 3}]
        assert window["incomplete"] is True
        assert window["incompleteReason"] == REPEAT_REASON


@pytest.mark.parametrize("tool", ["system_log", "overview", "teleport"])
@pytest.mark.parametrize("cap", [1, 2])
async def test_tool_page_size_alone_short_ignoring_console_under_the_cap(tool, cap):
    requests: list[dict[str, Any]] = []

    async def post(path, *, key=None, json=None, always_write=False):
        requests.append({k: json[k] for k in ("pageNumber", "pageSize")})
        return {"data": ROWS[0:3]}

    result = await _tool(tool, post, cap, None, 10)
    assert result["data"] == ROWS[0:3]
    assert len(requests) == cap
    if cap == 1:
        assert _incomplete(result) == (True, CAP_REASON.format(cap=1))
    else:
        assert _incomplete(result) == (True, REPEAT_REASON)
    assert "_nextPage" not in result
