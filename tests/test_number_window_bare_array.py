"""page_size alone on a bare-array console is window 0, never a silent cut; synthetic only.

A console that answers every page number with one bare array (``critical`` system-log
class, an unpaged console) is read by ``page_size`` alone exactly as by ``page=0`` with the
same ``page_size``: the first N records, trimmed and reported in ``_pageSize``, with
``_nextPage`` counted in N-record windows, and resuming with ``page=_nextPage`` and the same
``page_size`` returns the next records. No record is dropped without a continuation.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from unifi_fabric.families.network import network_controller_insights
from unifi_fabric.families.statistics import system_log
from unifi_fabric.families.vpn import network_vpn_dns

TOOLS = ["system_log", "overview", "teleport"]


def _client(rows: list[Any], calls: list[dict[str, Any]], cap: int | None = None) -> Any:
    async def post(path, *, key=None, json=None, always_write=False):
        calls.append({k: v for k, v in json.items() if k in ("pageNumber", "pageSize")})
        return list(rows)

    return SimpleNamespace(post=post, paginate_max_pages=cap)


def _registry() -> AsyncMock:
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = None
    registry.resolve_host_id.return_value = "console"
    registry.resolve_site_slug.return_value = "default"
    return registry


async def _call(tool: str, client: Any, page: int | None, size: int) -> Any:
    if tool == "system_log":
        return await system_log._read_system_log(
            client, _registry(), "console", "default", "critical", None, page=page, page_size=size
        )
    if tool == "overview":
        return await network_controller_insights.get_sites_overview(
            client, _registry(), "console", page=page, page_size=size
        )
    return await network_vpn_dns.query_teleport_invitations(
        client, _registry(), "console", "default", page_number=page, page_size=size
    )


def _complete(result: dict[str, Any]) -> bool:
    return not result.get("incomplete") and not result.get("_incomplete")


@pytest.mark.parametrize("tool", TOOLS)
async def test_bare_list_of_five_page_size_two_resumes_without_a_gap(tool):
    rows = [{"id": i} for i in range(5)]
    calls: list[dict[str, Any]] = []
    client = _client(rows, calls)
    first = await _call(tool, client, None, 2)
    assert first["data"] == rows[0:2]
    assert first["_nextPage"] == 1
    assert first["_pageSize"] == {"requested": 2, "sent": [2], "effective": 5, "returned": 2}
    assert _complete(first)
    assert calls == [{"pageNumber": 0, "pageSize": 2}]

    second = await _call(tool, client, first["_nextPage"], 2)
    assert second["data"] == rows[2:4]
    assert second["_nextPage"] == 2
    assert _complete(second)

    third = await _call(tool, client, second["_nextPage"], 2)
    assert third["data"] == rows[4:5]
    assert third.get("_nextPage") is None
    assert _complete(third)
    assert first["data"] + second["data"] + third["data"] == rows


@pytest.mark.parametrize("tool", TOOLS)
async def test_bare_array_longer_than_page_size_alone_matches_page_zero(tool):
    rows = [{"id": i} for i in range(7)]
    results = []
    for page in (None, 0):
        calls: list[dict[str, Any]] = []
        result = await _call(tool, _client(rows, calls), page, 3)
        assert result["data"] == rows[0:3], page
        assert result["_nextPage"] == 1, page
        assert result["_pageSize"] == {
            "requested": 3,
            "sent": [3],
            "effective": 7,
            "returned": 3,
        }, page
        assert _complete(result), page
        assert calls == [{"pageNumber": 0, "pageSize": 3}], page
        results.append(result)
    assert results[0]["data"] == results[1]["data"]
    assert results[0]["_pageSize"] == results[1]["_pageSize"]


@pytest.mark.parametrize("tool", TOOLS)
async def test_bare_array_shorter_than_page_size_is_kept_and_reported_incomplete(tool):
    rows = [{"id": i} for i in range(3)]
    mark = "_incomplete" if tool == "overview" else "incomplete"
    for page in (None, 0):
        calls: list[dict[str, Any]] = []
        result = await _call(tool, _client(rows, calls), page, 10)
        # Page 1 repeats the short page 0 at the console size 3: a console that clamps at 3
        # and ignores pageNumber answers so for a longer collection, so the short array
        # is kept and reported incomplete, never complete (SHORTPAGE-EXPECTATIONS).
        assert result["data"] == rows, page
        assert result[mark] is True, page
        assert result[f"{mark}Reason"] == (
            "page 1 repeated the entries of an earlier page; the controller did not page by "
            "pageNumber, so the window cannot be located"
        ), page
        assert "_nextPage" not in result, page
        assert calls == [{"pageNumber": 0, "pageSize": 10}, {"pageNumber": 1, "pageSize": 3}]
