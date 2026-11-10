"""Explicit page plus page_size on the page-number family returns the logical window.

With ``page_size = N``, ``page`` is a zero-based window index: the result is the records
``source[page*N : page*N + N]`` whatever the console's own page size ``e``, resumable with
``_nextPage`` and the same ``page_size``. The three page-number tools (the system log, the
sites overview and the Teleport invitation history) are driven against synthetic consoles
that clamp ``pageSize`` (e < N), honour it (e == N), or ignore it with a fixed page that is
shorter, equal or longer than N. Every case also checks the request count against the
zero-based request oracle: the probe, a discovery request of page 0 only when the probe is
empty but the total lies past the window start, and every console page the window
intersects that was not already read.
"""

from __future__ import annotations

import math
from collections.abc import Awaitable, Callable
from typing import Any
from unittest.mock import AsyncMock

import pytest

from unifi_fabric.families.network import network_controller_insights as nci
from unifi_fabric.families.statistics import system_log
from unifi_fabric.families.vpn import network_vpn_dns as vd

#: (name, console page size for a request of pageSize s). "clamp-c" honours a size up to c;
#: "honour" serves exactly the size asked for; "ignore-e" serves e records per page always.
CONSOLES: dict[str, Callable[[int], int]] = {
    "clamp-3": lambda sent: min(3, sent),
    "honour": lambda sent: sent,
    "ignore-2": lambda _sent: 2,
    "ignore-5": lambda _sent: 5,
    "ignore-8": lambda _sent: 8,
}
TOTALS = (0, 1, 7, 12, 23)
SIZES = (1, 4, 5, 7)


def _client(total: int, console: Callable[[int], int]) -> AsyncMock:
    async def post(
        _path: str, *, key: Any = None, json: dict[str, Any], always_write: bool = False
    ) -> Any:
        number, size = json["pageNumber"], json["pageSize"]
        e = console(size)
        rows = [{"id": index} for index in range(number * e, min(number * e + e, total))]
        return {
            "data": rows,
            "page_number": number,
            "total_element_count": total,
            "total_page_count": math.ceil(total / e),
        }

    client = AsyncMock()
    client.paginate_max_pages = None
    client.post = AsyncMock(side_effect=post)
    return client


def _registry() -> AsyncMock:
    registry = AsyncMock()
    registry.resolve_key_for_host = AsyncMock(return_value=None)
    registry.resolve_host_id = AsyncMock(return_value="host-001")
    registry.resolve_site_slug = AsyncMock(return_value="default")
    return registry


def _system_log(client: AsyncMock, page: int, size: int) -> Awaitable[Any]:
    return system_log._read_system_log(
        client, _registry(), "h", "Default", "all", None, page=page, page_size=size
    )


def _sites(client: AsyncMock, page: int, size: int) -> Awaitable[Any]:
    return nci.get_sites_overview(client, _registry(), "h", page=page, page_size=size)


def _teleport(client: AsyncMock, page: int, size: int) -> Awaitable[Any]:
    return vd.query_teleport_invitations(client, _registry(), "h", "Default", page, size)


TOOLS = {"system_log": _system_log, "sites_overview": _sites, "teleport_invitations": _teleport}


def _oracle(total: int, page: int, size: int, console: Callable[[int], int]) -> int:
    """Requests a window needs: probe, page-0 discovery when needed, unread pages."""
    start, e = page * size, console(size)
    probe_rows = max(0, min(page * e + e, total) - page * e)
    discovery = 1 if page and not probe_rows and total > start else 0
    if total <= start:
        return 1 + discovery
    known = {page} | ({0} if discovery else set())
    pages = range(start // e, math.ceil(min(start + size, total) / e))
    return 1 + discovery + len([number for number in pages if number not in known])


def _a1_bound(total: int, page: int, size: int, console: Callable[[int], int]) -> int:
    """The request-count rule: probe, discovery, and every intersecting page but the probe."""
    start, e = page * size, console(size)
    if total <= start:
        return 2
    pages = range(start // e, math.ceil(min(start + size, total) / e))
    return 2 + len([number for number in pages if number != page])


@pytest.mark.parametrize("console", sorted(CONSOLES))
@pytest.mark.parametrize("tool", sorted(TOOLS))
async def test_windows_equal_the_source_slice_with_oracle_request_counts(tool, console):
    call, serve = TOOLS[tool], CONSOLES[console]
    for total in TOTALS:
        source = [{"id": index} for index in range(total)]
        for size in SIZES:
            for page in range(0, 7):
                client = _client(total, serve)
                result = await call(client, page, size)
                case = (tool, console, total, page, size)
                assert result["data"] == source[page * size : page * size + size], case
                assert "incomplete" not in result and "_incomplete" not in result, case
                assert result["_pageSize"]["requested"] == size, case
                assert result["_pageSize"]["returned"] == len(result["data"]), case
                expected_next = page + 1 if page * size + size < total else None
                assert result.get("_nextPage") == expected_next, case
                requests = client.post.await_count
                assert requests == _oracle(total, page, size, serve), case
                assert requests <= _a1_bound(total, page, size, serve), case
                assert len(result["_pageSize"]["sent"]) == requests, case


@pytest.mark.parametrize("console", sorted(CONSOLES))
@pytest.mark.parametrize("tool", sorted(TOOLS))
async def test_following_next_page_returns_every_record_exactly_once(tool, console):
    call, serve = TOOLS[tool], CONSOLES[console]
    for total in TOTALS:
        source = [{"id": index} for index in range(total)]
        for size in SIZES:
            gathered: list[Any] = []
            page: int | None = 0
            while page is not None:
                result = await call(_client(total, serve), page, size)
                assert len(result["data"]) <= size
                gathered += result["data"]
                page = result.get("_nextPage")
                assert page is None or page <= total
            assert gathered == source, (tool, console, total, size)


@pytest.mark.parametrize("console", sorted(CONSOLES))
@pytest.mark.parametrize("tool", sorted(TOOLS))
async def test_window_past_the_end_is_empty_without_next_page(tool, console):
    call, serve = TOOLS[tool], CONSOLES[console]
    for total in TOTALS:
        for size in SIZES:
            page = math.ceil(total / size) + 1
            result = await call(_client(total, serve), page, size)
            assert result["data"] == [], (tool, console, total, size)
            assert "_nextPage" not in result, (tool, console, total, size)


@pytest.mark.parametrize("tool", sorted(TOOLS))
async def test_page_budget_is_shared_and_a_short_window_is_incomplete(tool):
    # 20 records at console size 2; window page 1 of 5 needs the probe and three pages.
    client = _client(20, CONSOLES["ignore-2"])
    client.paginate_max_pages = 2
    result = await TOOLS[tool](client, 1, 5)
    flag, why = (
        ("_incomplete", "_incompleteReason")
        if tool == "sites_overview"
        else ("incomplete", "incompleteReason")
    )
    assert result[flag] is True
    assert "UNIFI_PAGINATE_MAX_PAGES page cap of 2 reached" in result[why]
    assert client.post.await_count == 2
    assert result["_pageSize"]["sent"] == [5, 2]
    assert result["data"] == [{"id": 5}]
    # A window that stopped short is resumed with the same page, never skipped past.
    assert "_nextPage" not in result
