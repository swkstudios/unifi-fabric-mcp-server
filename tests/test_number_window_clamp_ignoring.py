"""A console that clamps pageSize and ignores pageNumber is never a false complete.

The console below holds nine records, clamps every page to four and answers every page
number with records 0-3. Page 0 at pageSize 10 is short (4 records) and page 1 at the
console size 4 repeats it. The repeated page is not larger than the size sent for it, so
under SHORTPAGE-EXPECTATIONS (canonical sentence: "a repeated page
is an abort unless the repeated page exceeded the sent size") it is an abort: the short
page equals the console clamp and is not evidence of the end. Before the fix the window
was reported complete with four of the nine records, no ``nextPage`` and no
``incomplete``. Synthetic upstreams only.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from unifi_fabric.tools import network_controller_insights, network_vpn_dns, system_log
from unifi_fabric.tools._number_window import collect_number_window

CLAMP = 4
RECORDS = [{"id": i} for i in range(9)]
REASON = (
    "page 1 repeated the entries of an earlier page; the controller did not page by "
    "pageNumber, so the window cannot be located"
)


def _console(calls: list[dict[str, Any]], *, bare: bool) -> Any:
    async def fetch(controls: dict[str, Any]) -> Any:
        calls.append(dict(controls))
        rows = RECORDS[: min(controls["pageSize"], CLAMP)]
        return list(rows) if bare else {"data": list(rows)}

    return fetch


@pytest.mark.parametrize("bare", [True, False])
async def test_clamping_console_that_ignores_page_number_is_incomplete(bare):
    calls: list[dict[str, Any]] = []
    window = await collect_number_window(
        _console(calls, bare=bare), page=0, page_size=10, max_pages=None
    )
    assert "raw" not in window
    assert window["incomplete"] is True
    assert window["incompleteReason"] == REASON
    assert window["nextPage"] is None
    # The records gathered once are kept; nothing is duplicated.
    assert window["items"] == RECORDS[:CLAMP]
    assert window["_pageSize"]["sent"] == [10, CLAMP]
    assert calls == [{"pageNumber": 0, "pageSize": 10}, {"pageNumber": 1, "pageSize": CLAMP}]


def _client(calls: list[dict[str, Any]], *, bare: bool) -> SimpleNamespace:
    fetch = _console(calls, bare=bare)

    async def post(path, *, key=None, json=None):
        return await fetch({"pageNumber": json["pageNumber"], "pageSize": json["pageSize"]})

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


@pytest.mark.parametrize("bare", [True, False])
@pytest.mark.parametrize("page", [0, None])
@pytest.mark.parametrize("tool", ["overview", "teleport", "system_log"])
async def test_tools_report_the_clamping_ignoring_console_incomplete(tool, page, bare):
    calls: list[dict[str, Any]] = []
    result = await _tool(tool, _client(calls, bare=bare), page)
    assert isinstance(result, dict)
    # get_sites_overview documents _incomplete/_incompleteReason; the others the plain keys.
    mark = "_incomplete" if tool == "overview" else "incomplete"
    assert result["data"] == RECORDS[:CLAMP]
    assert result[mark] is True
    assert result[f"{mark}Reason"] == REASON
    assert result.get("_nextPage") is None
    assert len(calls) == 2


# --------------------------------------------------------------------------------------
# Nonzero sized windows whose repeated physical pages differ in a non-identity field.
#
# The console below holds twenty records, clamps every page to two and ignores
# ``pageNumber``: each request answers records 0-1, but a live field (``client_count``)
# changes on every call, so no two answers are equal as whole records. A repeated page is
# recognised by record identity (the shared repeat contract), never by whole-record
# equality, so the window ``page=1, page_size=4`` is reported incomplete instead of
# returning ids [0, 1, 0, 1] as a complete window.
# --------------------------------------------------------------------------------------
LIVE_CLAMP = 2
LIVE_TOTAL = 20
LIVE_REASON = (
    "page 2 repeated the entries of an earlier page; the controller did not page by "
    "pageNumber, so the window cannot be located"
)


def _live_console(calls: list[dict[str, Any]], *, ignore: bool, echo: bool = False) -> Any:
    """Records ``synthetic-N`` with a counter that changes on every call.

    ``ignore`` answers every page number with records 0-1; otherwise the console pages
    correctly at its clamp. ``echo`` reports the requested ``page_number``.
    """

    async def fetch(controls: dict[str, Any]) -> Any:
        calls.append(dict(controls))
        number = 0 if ignore else controls["pageNumber"]
        size = min(controls["pageSize"], LIVE_CLAMP)
        first = number * size
        rows = [
            {"id": f"synthetic-{i}", "client_count": len(calls)}
            for i in range(first, min(first + size, LIVE_TOTAL))
        ]
        body: dict[str, Any] = {
            "data": rows,
            "total_element_count": LIVE_TOTAL,
            "total_page_count": -(-LIVE_TOTAL // size),
        }
        if echo:
            body["page_number"] = controls["pageNumber"]
        return body

    return fetch


@pytest.mark.parametrize("echo", [False, True], ids=["omits-page-number", "echoes-request"])
async def test_changing_fields_cannot_hide_a_repeated_page_in_a_nonzero_window(echo):
    calls: list[dict[str, Any]] = []
    window = await collect_number_window(
        _live_console(calls, ignore=True, echo=echo), page=1, page_size=4, max_pages=None
    )
    assert window["incomplete"] is True
    assert window["incompleteReason"] == LIVE_REASON
    assert window["nextPage"] is None
    assert window["items"] == []  # no duplicated identity is counted toward the window
    assert [c["pageNumber"] for c in calls] == [1, 2]


@pytest.mark.parametrize("echo", [False, True], ids=["omits-page-number", "echoes-request"])
async def test_distinct_identities_with_changing_fields_still_complete_the_window(echo):
    """Control: a console that pages correctly may change any non-identity field."""
    calls: list[dict[str, Any]] = []
    window = await collect_number_window(
        _live_console(calls, ignore=False, echo=echo), page=1, page_size=4, max_pages=None
    )
    assert window["incomplete"] is False
    assert [row["id"] for row in window["items"]] == [f"synthetic-{i}" for i in range(4, 8)]
    assert window["nextPage"] == 2


def _beta_registry() -> AsyncMock:
    registry = _registry()
    registry.resolve_key_for_host.return_value = "beta-key"
    return registry


def _keyed_client(calls: list[dict[str, Any]], keys: list[Any], *, ignore: bool) -> SimpleNamespace:
    fetch = _live_console(calls, ignore=ignore)

    async def post(path, *, key=None, json=None):
        keys.append(key)
        return await fetch({"pageNumber": json["pageNumber"], "pageSize": json["pageSize"]})

    return SimpleNamespace(post=post, paginate_max_pages=None)


async def _window_tool(tool: str, client: Any, registry: Any) -> Any:
    if tool == "overview":
        return await network_controller_insights.get_sites_overview(
            client, registry, "console", page=1, page_size=4
        )
    if tool == "teleport":
        return await network_vpn_dns.query_teleport_invitations(
            client, registry, "console", "default", page_number=1, page_size=4
        )
    return await system_log._read_system_log(
        client, registry, "console", "default", "all", None, page=1, page_size=4
    )


@pytest.mark.parametrize("tool", ["overview", "teleport", "system_log"])
async def test_tools_report_a_changing_field_repeat_incomplete_with_beta_key_routing(tool):
    calls: list[dict[str, Any]] = []
    keys: list[Any] = []
    result = await _window_tool(tool, _keyed_client(calls, keys, ignore=True), _beta_registry())
    mark = "_incomplete" if tool == "overview" else "incomplete"
    assert result[mark] is True
    assert result[f"{mark}Reason"] == LIVE_REASON
    assert result.get("_nextPage") is None
    assert result["data"] == []
    assert keys == ["beta-key"] * len(calls) and len(calls) == 2


@pytest.mark.parametrize("tool", ["overview", "teleport", "system_log"])
async def test_tools_return_the_window_of_a_console_that_pages_with_changing_fields(tool):
    calls: list[dict[str, Any]] = []
    keys: list[Any] = []
    result = await _window_tool(tool, _keyed_client(calls, keys, ignore=False), _beta_registry())
    mark = "_incomplete" if tool == "overview" else "incomplete"
    assert result.get(mark) is not True
    assert [row["id"] for row in result["data"]] == [f"synthetic-{i}" for i in range(4, 8)]
    assert result["_nextPage"] == 2
    assert keys == ["beta-key"] * len(calls)
