"""Number-family windows, final review follow-up (N3, N4, N5 of the Opus final review).

- N3: ``page_size`` alone on the three page-number tools starts at record 0, so a result
  holding a whole number of windows reports ``_nextPage`` as the next window index; a
  caller that resumes with ``page=_nextPage`` and the same ``page_size`` (the documented
  rule) gets the next contiguous records under a console clamp.
- N4: a short page 0 without a total, page count or size echo is not final
  (SHORTPAGE-EXPECTATIONS canonical sentence): the window continues at the console size and
  an empty page proves the end, for bare arrays and object envelopes alike.
- N5: a declared total at or inside the window end suppresses ``nextPage`` even when a page
  count still declares a later (empty) page (NUMBER-EXPLICIT-PAGE rule 3).
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from unifi_fabric.families.network import network_controller_insights as nci
from unifi_fabric.families.statistics import system_log
from unifi_fabric.families.vpn import network_vpn_dns as vd
from unifi_fabric.shared_shapes._number_window import collect_number_window
from unifi_fabric.shared_shapes._pagination import collect_batch

settings.register_profile(
    "number-window-round3", max_examples=400, derandomize=True, database=None, deadline=None
)
PROFILE = settings.get_profile("number-window-round3")


def _console(
    total: int,
    width: Callable[[int], int],
    shape: str,
    calls: list[dict[str, Any]],
    order: list[int] | None = None,
) -> Callable[[dict[str, Any]], Any]:
    """A console whose page ``n`` at pageSize ``s`` holds ``[n*w, n*w + w)``, ``w = width(s)``.

    ``shape`` is ``bare`` (a JSON array), ``data`` (``{data}`` only), ``total``
    (``total_element_count``), ``pages`` (``total_page_count``) or ``both``. ``order`` maps a
    record position to its id (a reordered but stable collection).
    """
    ids = order if order is not None else list(range(total))

    async def fetch(controls: dict[str, Any]) -> Any:
        calls.append(dict(controls))
        number = controls.get("pageNumber", 0)
        w = width(controls.get("pageSize") or 200)
        rows = [{"id": ids[i]} for i in range(number * w, min(number * w + w, total))]
        if shape == "bare":
            return rows
        body: dict[str, Any] = {"data": rows}
        if shape in {"total", "both"}:
            body["total_element_count"] = total
        if shape in {"pages", "both"}:
            body["total_page_count"] = -(-total // w)
        return body

    return fetch


def _client(fetch: Callable[[dict[str, Any]], Any]) -> SimpleNamespace:
    async def post(
        _path: str, *, key: Any = None, json: dict[str, Any], always_write: bool = False
    ) -> Any:
        return await fetch(json)

    return SimpleNamespace(post=post, paginate_max_pages=None)


def _registry() -> AsyncMock:
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = None
    registry.resolve_host_id.return_value = "console"
    registry.resolve_site_slug.return_value = "default"
    return registry


async def _tool(name: str, client: Any, page: int | None, page_size: int) -> Any:
    registry = _registry()
    if name == "overview":
        return await nci.get_sites_overview(
            client, registry, "console", page=page, page_size=page_size
        )
    if name == "teleport":
        return await vd.query_teleport_invitations(
            client, registry, "console", "default", page, page_size
        )
    return await system_log._read_system_log(
        client, registry, "console", "default", "all", None, page=page, page_size=page_size
    )


def _ids(result: Any) -> list[Any]:
    rows = result if isinstance(result, list) else result["data"]
    return [row["id"] for row in rows]


# --------------------------------------------------------------------------- N3


@pytest.mark.parametrize("tool", ["overview", "teleport", "system_log"])
@pytest.mark.parametrize("shape", ["data", "both"])
async def test_n3_page_size_alone_resumes_with_the_same_page_size(tool, shape):
    # The review scenario: the console clamps pageSize to 2 and holds 269 records.
    # The system log drain proves completeness only from a page count and a total.
    shape = "both" if tool == "system_log" else shape
    calls: list[dict[str, Any]] = []
    client = _client(_console(269, lambda sent: min(sent, 2), shape, calls))
    first = await _tool(tool, client, None, 10)
    assert _ids(first) == list(range(10))
    assert first["_nextPage"] == 1
    resumed = await _tool(tool, client, first["_nextPage"], 10)
    assert _ids(resumed) == list(range(10, 20))
    assert resumed["_nextPage"] == 2


@pytest.mark.parametrize("tool", ["overview", "teleport", "system_log"])
@pytest.mark.parametrize(
    ("total", "clamp", "size"),
    [(269, 2, 10), (23, 1, 4), (50, 5, 5), (40, 3, 6), (31, 10, 5), (7, 3, 3)],
)
async def test_n3_following_next_page_from_page_size_alone_drains_contiguously(
    tool, total, clamp, size
):
    # Each window holds a whole number of console pages, or one console page holds a whole
    # number of windows (a console that serves 10 records for a request of 5).
    def width(sent: int) -> int:
        return clamp if clamp > size else min(sent, clamp)

    shape = "both" if tool == "system_log" else "data"
    client = _client(_console(total, width, shape, []))
    result = await _tool(tool, client, None, size)
    gathered = _ids(result)
    pages = 1
    while result.get("_nextPage") is not None:
        assert not result.get("incomplete") and not result.get("_incomplete")
        result = await _tool(tool, client, result["_nextPage"], size)
        gathered.extend(_ids(result))
        pages += 1
        assert pages <= total + 2
    assert not result.get("incomplete") and not result.get("_incomplete")
    assert gathered == list(range(total))


async def test_n3_page_size_over_a_clamp_is_window_zero_and_resumes_by_window():
    # N3-PAGESIZE-ALONE: page_size alone is collect_number_window(page=0). 215 requested
    # over a 200 clamp is exactly records [0, 215) (sent 215, then 200) with nextPage 1
    # counted in 215-record windows, and page=1 is [215, 430): no record is skipped or
    # repeated (PAGING-CONTINUITY).
    calls: list[dict[str, Any]] = []
    fetch = _console(450, lambda sent: min(sent, 200), "data", calls)
    first = await collect_number_window(fetch, page=0, page_size=215, max_pages=None)
    assert [row["id"] for row in first["items"]] == list(range(215))
    assert first["nextPage"] == 1
    assert not first["incomplete"]
    assert first["_pageSize"]["sent"] == [215, 200]
    second = await collect_number_window(fetch, page=1, page_size=215, max_pages=None)
    assert [row["id"] for row in second["items"]] == list(range(215, 430))
    assert second["nextPage"] == 2
    assert not second["incomplete"]


# --------------------------------------------------------------------------- N4


@pytest.mark.parametrize("shape", ["bare", "data"])
async def test_n4_short_page_zero_under_a_clamp_is_not_final(shape):
    calls: list[dict[str, Any]] = []
    fetch = _console(269, lambda sent: min(sent, 2), shape, calls)
    window = await collect_number_window(fetch, page=0, page_size=10, max_pages=None)
    assert [row["id"] for row in window["items"]] == list(range(10))
    assert window["nextPage"] == 1
    assert not window["incomplete"]
    assert calls == [{"pageNumber": 0, "pageSize": 10}] + [
        {"pageNumber": number, "pageSize": 2} for number in range(1, 5)
    ]
    batch = await collect_batch(fetch, requested=10, family="number", default_size=None)
    assert batch["items"] == window["items"]


@pytest.mark.parametrize("tool", ["overview", "teleport"])
async def test_n4_honoured_short_page_zero_is_complete_not_a_false_incomplete(tool):
    calls: list[dict[str, Any]] = []
    client = _client(_console(4, lambda sent: sent, "data", calls))
    result = await _tool(tool, client, 0, 25)
    assert _ids(result) == [0, 1, 2, 3]
    for marker in ("incomplete", "_incomplete", "_nextPage"):
        assert marker not in result
    assert calls[-1] == {"pageNumber": 1, "pageSize": 4}


async def test_n4_bare_short_page_zero_then_empty_page_is_returned_verbatim():
    calls: list[dict[str, Any]] = []
    fetch = _console(3, lambda sent: sent, "bare", calls)
    window = await collect_number_window(fetch, page=0, page_size=10, max_pages=None)
    assert window == {"raw": [{"id": 0}, {"id": 1}, {"id": 2}]}
    assert calls == [{"pageNumber": 0, "pageSize": 10}, {"pageNumber": 1, "pageSize": 3}]


async def test_n4_short_page_zero_repeated_without_evidence_is_an_abort():
    # SHORTPAGE-EXPECTATIONS canonical sentence: a repeated page is an abort unless it
    # exceeded the sent size. Page 1, sent at the console size 2, repeats the short page 0
    # with 2 records; a console that clamps at 2 and ignores pageNumber answers so for a
    # longer collection, so the short page is not evidence of the end.
    calls: list[dict[str, Any]] = []

    async def fetch(controls: dict[str, Any]) -> Any:
        calls.append(dict(controls))
        return {"data": [{"id": 0}, {"id": 1}]}

    window = await collect_number_window(fetch, page=0, page_size=10, max_pages=None)
    assert window["incomplete"] is True
    assert window["incompleteReason"] == (
        "page 1 repeated the entries of an earlier page; the controller did not page by "
        "pageNumber, so the window cannot be located"
    )
    assert window["items"] == [{"id": 0}, {"id": 1}]
    assert window["nextPage"] is None
    assert calls == [{"pageNumber": 0, "pageSize": 10}, {"pageNumber": 1, "pageSize": 2}]


# --------------------------------------------------------------------------- N5


@pytest.mark.parametrize("width", [1, 2])
async def test_n5_declared_total_reached_suppresses_next_page(width):
    # total_element_count 6 with total_page_count one page past it (an empty last page).
    async def fetch(controls: dict[str, Any]) -> Any:
        number = controls["pageNumber"]
        w = width if width == 2 else controls["pageSize"]
        rows = [{"id": i} for i in range(number * w, min(number * w + w, 6))]
        return {"data": rows, "total_element_count": 6, "total_page_count": 6 // w + 1}

    window = await collect_number_window(fetch, page=5, page_size=1, max_pages=None)
    assert [row["id"] for row in window["items"]] == [5]
    assert window["nextPage"] is None
    assert not window["incomplete"]


# --------------------------------------------------------------------------- properties


@st.composite
def _cases(draw: Any) -> tuple[int, str, int, str, int, list[int]]:
    total = draw(st.integers(0, 60))
    behaviour = draw(st.sampled_from(("honour", "clamp", "ignore")))
    native = draw(st.integers(1, 12))
    shape = draw(st.sampled_from(("bare", "data", "total", "pages", "both")))
    size = draw(st.integers(1, 15))
    order = draw(st.permutations(list(range(total)))) if draw(st.booleans()) else list(range(total))
    return total, behaviour, native, shape, size, order


def _width(behaviour: str, native: int) -> Callable[[int], int]:
    if behaviour == "honour":
        return lambda sent: sent
    if behaviour == "clamp":
        return lambda sent: min(sent, native)
    return lambda _sent: native


@PROFILE
@given(_cases(), st.integers(0, 8))
def test_property_every_window_is_exact_or_truthfully_incomplete(case, page):
    total, behaviour, native, shape, size, order = case
    calls: list[dict[str, Any]] = []
    fetch = _console(total, _width(behaviour, native), shape, calls, order)
    window = asyncio.run(collect_number_window(fetch, page=page, page_size=size, max_pages=None))
    expected = order[page * size : page * size + size]
    if "raw" in window:
        assert [row["id"] for row in window["raw"]] == expected
        return
    if window["incomplete"]:
        # Only a console that ignores pageSize and repeats a page can stop a window, and an
        # incomplete window never carries a continuation or a wrong record.
        assert behaviour == "ignore"
        assert window["nextPage"] is None
        assert [row["id"] for row in window["items"]] in ([], expected)
        return
    assert [row["id"] for row in window["items"]] == expected
    beyond = (page + 1) * size < total
    if beyond:
        assert window["nextPage"] == page + 1
    elif shape in {"total", "both"}:
        assert window["nextPage"] is None
    assert len(window["items"]) <= size


@PROFILE
@given(_cases())
def test_property_page_size_alone_then_same_size_windows_are_contiguous(case):
    # page_size alone is the shipped collect_number_window(page=0) (N3-PAGESIZE-ALONE);
    # following nextPage with the same page_size returns exact, contiguous, disjoint windows
    # until the collection ends, or stops truthfully incomplete with no continuation.
    total, behaviour, native, shape, size, order = case
    fetch = _console(total, _width(behaviour, native), shape, [], order)
    gathered: list[int] = []
    page: int | None = 0
    steps = 0
    while page is not None:
        window = asyncio.run(
            collect_number_window(fetch, page=page, page_size=size, max_pages=None)
        )
        if "raw" in window:
            rows, following = window["raw"], None
        else:
            if window["incomplete"]:
                assert behaviour == "ignore"
                assert window["nextPage"] is None
                return
            rows, following = window["items"], window["nextPage"]
        assert [row["id"] for row in rows] == order[page * size : page * size + size]
        gathered.extend(row["id"] for row in rows)
        page = following
        steps += 1
        assert steps <= total + 2
    assert gathered == order
