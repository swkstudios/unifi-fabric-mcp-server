"""Logical traffic-flow windows remain contiguous under console size behavior."""

from __future__ import annotations

from math import ceil
from types import SimpleNamespace
from typing import Any

import pytest

from unifi_fabric.families.network import network_nat_qos_traffic as flows


class FlowPages:
    """Stable fake console with optional size echoes and page-count metadata."""

    def __init__(
        self,
        total: int,
        native_size: int,
        *,
        ignores_size: bool = False,
        total_count: bool = True,
        size_echo: bool = False,
        page_count: bool = False,
    ) -> None:
        self.total = total
        self.native_size = native_size
        self.ignores_size = ignores_size
        self.total_count = total_count
        self.size_echo = size_echo
        self.page_count = page_count
        self.calls: list[dict[str, Any]] = []

    async def fetch(self, controls: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(dict(controls))
        size = (
            self.native_size
            if self.ignores_size
            else min(controls.get("pageSize", 200), self.native_size)
        )
        number = controls.get("pageNumber", 0)
        start = number * size
        stop = min(start + size, self.total)
        response: dict[str, Any] = {
            "data": [{"id": n, "unchanged": {"source": n}} for n in range(start, stop)],
            "page_number": number,
        }
        if self.total_count:
            response["total_element_count"] = self.total
        if self.size_echo:
            response["limit"] = size
        if self.page_count:
            response["total_page_count"] = ceil(self.total / size)
        else:
            response["has_next"] = stop < self.total
        return response


async def read_window(
    upstream: FlowPages, size: int | None, page: int | dict[str, int] = 0
) -> dict[str, Any]:
    body: dict[str, Any] = {"pageNumber": page}
    if size is not None:
        body["pageSize"] = size
    sent, batch = flows._flow_page_batch(body)
    assert sent is not None
    if batch is not None:
        batch["policy"].record_sent(sent.get("pageSize"))
    first = await upstream.fetch(sent)
    return await flows._nc_drain(
        SimpleNamespace(paginate_max_pages=None),
        "/synthetic/flows",
        sent,
        first,
        upstream.fetch,
        batch,
    )


def ids(result: dict[str, Any]) -> list[int]:
    return [row["id"] for row in result["data"]]


async def test_has_next_clamp_places_requested_flow_window() -> None:
    """F1: has_next overrides a total inferred with the wrong physical size."""
    upstream = FlowPages(51, 25)
    result = await read_window(upstream, 100, 1)
    assert ids(result) == []
    assert "incomplete" not in result
    assert "_nextPage" not in result
    assert result["total_element_count"] == 51


async def test_has_next_clamp_resume_keeps_record_offset() -> None:
    """F2: the additive offset resumes after the logical window exactly once."""
    upstream = FlowPages(101, 25)
    first = await read_window(upstream, 100)
    assert ids(first) == list(range(100))
    assert first["_nextPage"] == {"offset": 100, "pageSize": 100}
    second = await read_window(upstream, 100, first["_nextPage"])
    assert ids(second) == [100]
    assert ids(first) + ids(second) == list(range(101))
    assert "incomplete" not in second
    assert "_nextPage" not in second


async def test_terminal_page_zero_discovery_reuses_fixed_native_rows() -> None:
    """F3: a discovered terminal native page already contains the desired row."""
    upstream = FlowPages(2, 25, ignores_size=True, total_count=False)
    result = await read_window(upstream, 1, 1)
    assert ids(result) == [1]
    assert "incomplete" not in result
    assert "_nextPage" not in result
    assert upstream.calls == [
        {"pageNumber": 1, "pageSize": 1},
        {"pageNumber": 0, "pageSize": 1},
    ]
    assert result["data"] == [{"id": 1, "unchanged": {"source": 1}}]


async def test_fixed_native_resume_reuses_nonterminal_discovery() -> None:
    """F4: an effective page can exceed the requested size without shifting resume."""
    upstream = FlowPages(26, 25, ignores_size=True, total_count=False)
    first = await read_window(upstream, 1)
    assert ids(first) == [0]
    assert first["_nextPage"] == {"offset": 1, "pageSize": 1}
    second = await read_window(upstream, 1, first["_nextPage"])
    assert ids(second) == [1]
    assert second["_nextPage"] == {"offset": 2, "pageSize": 1}
    assert upstream.calls == [
        {"pageNumber": 0, "pageSize": 1},
        {"pageNumber": 1, "pageSize": 1},
        {"pageNumber": 0, "pageSize": 1},
    ]


@pytest.mark.parametrize("size", [1, 25, 100, 101, 250, 275])
@pytest.mark.parametrize("ignores_size", [False, True])
@pytest.mark.parametrize("page_count", [False, True])
async def test_flow_window_resume_and_drain_are_contiguous(
    size: int, ignores_size: bool, page_count: bool
) -> None:
    upstream = FlowPages(
        301, 25, ignores_size=ignores_size, total_count=True, page_count=page_count
    )
    collected: list[int] = []
    page: int | dict[str, int] = 0
    while True:
        result = await read_window(upstream, size, page)
        rows = ids(result)
        assert rows == list(range(len(collected), min(len(collected) + size, 301)))
        assert "incomplete" not in result
        collected.extend(rows)
        continuation = result.get("_nextPage")
        if continuation is None:
            break
        assert continuation == {"offset": len(collected), "pageSize": size}
        page = continuation
    assert collected == list(range(301))
    assert len(set(collected)) == len(collected)
    drain = FlowPages(301, 25, ignores_size=ignores_size, total_count=True, page_count=page_count)
    assert ids(await read_window(drain, None)) == list(range(301))
