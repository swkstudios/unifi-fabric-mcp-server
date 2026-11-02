"""A short page 0 that page 1 repeats is an abort, never completion.

A console that ignores ``pageNumber`` answers page 1 with page 0 again. After a SHORT page
0 (fewer records than ``page_size``), page 1 is sent at the console size ``k`` and the
repeat holds exactly ``k`` records: it is no larger than the size sent, so under the
canonical sentence of SHORTPAGE-EXPECTATIONS ("a repeated page is
an abort unless the repeated page exceeded the sent size") it is an abort that keeps the
records of page 0. A console that clamps ``pageSize`` at ``k`` answers the same way for a
longer collection, so the short page is not evidence of the end. ``page=0, page_size=N``
and ``page_size`` alone agree. A repeat after a FULL page 0, or one with evidence of more
records, is an abort too. Synthetic upstreams only.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from unifi_fabric.tools import network_controller_insights, network_vpn_dns, system_log
from unifi_fabric.tools._number_window import collect_number_window

REPEAT_REASON = (
    "page 1 repeated the entries of an earlier page; the controller did not page by "
    "pageNumber, so the window cannot be located"
)


def _ignoring(body: Any, calls: list[dict[str, Any]]) -> Any:
    """A console that answers every page number with the same ``body``."""

    async def fetch(controls: dict[str, Any]) -> Any:
        calls.append(dict(controls))
        return body

    return fetch


async def test_short_bare_page_zero_repeated_is_an_abort_keeping_page_zero():
    rows = [{"id": i} for i in range(4)]
    calls: list[dict[str, Any]] = []
    window = await collect_number_window(
        _ignoring(rows, calls), page=0, page_size=10, max_pages=None
    )
    assert "raw" not in window
    assert window["items"] == rows
    assert window["incomplete"] is True
    assert window["incompleteReason"] == REPEAT_REASON
    assert window["nextPage"] is None
    assert window["_pageSize"] == {"requested": 10, "sent": [10, 4], "effective": 4, "returned": 4}
    assert calls == [{"pageNumber": 0, "pageSize": 10}, {"pageNumber": 1, "pageSize": 4}]


async def test_short_envelope_page_zero_repeated_is_an_abort_keeping_page_zero():
    rows = [{"id": i} for i in range(4)]
    calls: list[dict[str, Any]] = []
    window = await collect_number_window(
        _ignoring({"data": rows, "traceId": "t"}, calls), page=0, page_size=10, max_pages=None
    )
    assert window["items"] == rows
    assert window["incomplete"] is True
    assert window["incompleteReason"] == REPEAT_REASON
    assert window["nextPage"] is None
    assert window["envelope"] == {"traceId": "t"}
    assert window["_pageSize"] == {"requested": 10, "sent": [10, 4], "effective": 4, "returned": 4}


async def test_repeat_after_a_full_console_page_inside_the_window_stays_an_abort():
    # Page 0 holds 4 (a clamp), page 1 holds the next 4, page 2 repeats page 1: a repeat
    # after a full console page is an abort, not completion.
    calls: list[dict[str, Any]] = []

    async def fetch(controls: dict[str, Any]) -> Any:
        calls.append(dict(controls))
        number = min(controls["pageNumber"], 1)
        return {"data": [{"id": i} for i in range(number * 4, number * 4 + 4)]}

    window = await collect_number_window(fetch, page=0, page_size=20, max_pages=None)
    assert window["incomplete"]
    assert window["incompleteReason"] == (
        "page 2 repeated the entries of an earlier page; the controller did not page by "
        "pageNumber, so the window cannot be located"
    )
    assert window["nextPage"] is None


@pytest.mark.parametrize(
    "evidence",
    [
        {"total_element_count": 9},
        {"totalCount": 9},
        {"total_page_count": 3},
        {"has_next": True},
    ],
)
async def test_short_page_zero_repeated_with_evidence_of_more_stays_an_abort(evidence):
    rows = [{"id": i} for i in range(4)]
    calls: list[dict[str, Any]] = []
    window = await collect_number_window(
        _ignoring({"data": rows, **evidence}, calls), page=0, page_size=10, max_pages=None
    )
    assert window["incomplete"]
    assert window["incompleteReason"] == REPEAT_REASON
    assert window["nextPage"] is None
    assert len(calls) == 2


def _client(body: Any, calls: list[dict[str, Any]]) -> SimpleNamespace:
    async def post(path, *, key=None, json=None):
        calls.append({k: v for k, v in json.items() if k in ("pageNumber", "pageSize")})
        return body

    return SimpleNamespace(post=post, paginate_max_pages=None)


def _registry() -> AsyncMock:
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = None
    registry.resolve_host_id.return_value = "console"
    registry.resolve_site_slug.return_value = "default"
    return registry


async def _tool(tool: str, client: Any, page: int | None) -> Any:
    if tool == "overview":
        return await network_controller_insights.get_sites_overview(
            client, _registry(), "console", page=page, page_size=10
        )
    if tool == "teleport":
        return await network_vpn_dns.query_teleport_invitations(
            client, _registry(), "console", "default", page_number=page, page_size=10
        )
    return await system_log._read_system_log(
        client, _registry(), "console", "default", "all", None, page=page, page_size=10
    )


@pytest.mark.parametrize("tool", ["overview", "teleport", "system_log"])
async def test_tools_page_zero_and_page_size_alone_agree_on_a_short_ignoring_console(tool):
    rows = [{"id": i} for i in range(4)]
    # get_sites_overview documents _incomplete/_incompleteReason; the others the plain keys.
    mark = "_incomplete" if tool == "overview" else "incomplete"
    for page in (0, None):
        calls: list[dict[str, Any]] = []
        result = await _tool(tool, _client({"data": rows}, calls), page)
        assert result["data"] == rows, page
        assert result[mark] is True, page
        assert result[f"{mark}Reason"] == REPEAT_REASON, page
        assert result.get("_nextPage") is None, page
        assert calls == [{"pageNumber": 0, "pageSize": 10}, {"pageNumber": 1, "pageSize": 4}]
