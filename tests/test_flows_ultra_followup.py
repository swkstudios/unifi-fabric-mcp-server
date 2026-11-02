"""Flow page translation excludes probe rows when translation fails."""

from __future__ import annotations

from typing import Any
from unittest.mock import Mock

import pytest

from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.tools import network_nat_qos_traffic as nc


def _page(number: int, size: int, total: int) -> dict[str, Any]:
    return {
        "data": [{"id": row} for row in range(number * size, min((number + 1) * size, total))],
        "page_number": number,
        "total_page_count": -(-total // size),
        "has_next": (number + 1) * size < total,
    }


@pytest.mark.parametrize("number", ["2", 2.0, 2])
async def test_int_like_page_numbers_start_at_the_same_logical_record(number: Any) -> None:
    body = {"pageSize": 275, "pageNumber": number, "custom": "retained"}
    sent, batch = nc._flow_page_batch(body)
    assert sent is not None and batch is not None
    requests = [sent]

    async def fetch(request: dict[str, Any]) -> dict[str, Any]:
        requests.append(request)
        return _page(int(request["pageNumber"]), min(request["pageSize"], 100), 2000)

    first = _page(int(sent["pageNumber"]), min(sent["pageSize"], 100), 2000)
    result = await nc._nc_drain(Mock(), "/traffic-flows", sent, first, fetch, batch)
    assert [row["id"] for row in result["data"]] == list(range(550, 825))
    assert result["_nextPage"] == {"offset": 825, "pageSize": 275}
    assert requests[0]["pageNumber"] == number
    assert all(request["custom"] == "retained" for request in requests)
    assert "incomplete" not in result


async def test_unreadable_page_number_remains_upstream_and_uses_echo() -> None:
    body = {"pageSize": 100, "pageNumber": "console-specific"}
    sent, batch = nc._flow_page_batch(body)
    assert sent == body and batch is not None
    requests: list[dict[str, Any]] = []

    async def fetch(request: dict[str, Any]) -> dict[str, Any]:
        requests.append(request)
        return _page(request["pageNumber"], request["pageSize"], 1000)

    first = _page(2, 100, 1000)
    result = await nc._nc_drain(Mock(), "/traffic-flows", sent, first, fetch, batch)
    assert [row["id"] for row in result["data"]] == list(range(200, 300))
    assert result["_nextPage"] == {"offset": 300, "pageSize": 100}
    assert requests == []


@pytest.mark.parametrize(
    ("failure", "total", "failed_number"), [("probe", 250, 0), ("refetch", 2000, 5)]
)
async def test_failed_probe_or_translated_refetch_excludes_fetched_page(
    failure: str, total: int, failed_number: int
) -> None:
    sent, batch = nc._flow_page_batch({"pageSize": 275, "pageNumber": 2})
    assert sent is not None and batch is not None
    first = _page(2, 100, total)
    requests: list[dict[str, Any]] = []

    async def fetch(request: dict[str, Any]) -> dict[str, Any]:
        requests.append(request)
        raise UniFiConnectionError(f"{failure} returned HTTP 408", status=408)

    result = await nc._nc_drain(Mock(), "/traffic-flows", sent, first, fetch, batch)
    assert result["data"] == []
    assert result["page_number"] == first["page_number"]
    assert result["incomplete"] is True
    assert f"page {failed_number} failed (HTTP 408)" in result["incompleteReason"]
    assert [request["pageNumber"] for request in requests] == [failed_number]
    assert result["_pageSize"]["returned"] == 0
    assert "_nextPage" not in result
