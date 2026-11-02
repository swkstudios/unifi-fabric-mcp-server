"""Fake-upstream acceptance of requested totals and silent v2 page-size clamping."""

from __future__ import annotations

import math
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from unifi_fabric.tools import network_controller_insights, network_vpn_dns, system_log


@pytest.mark.parametrize("tool", ["overview", "teleport", "system_log"])
@pytest.mark.parametrize("requested,available", [(1000, 450), (10000, 215), (215, 450)])
async def test_v2_requested_total_is_gathered_in_effective_size_batches(tool, requested, available):
    maximum = 200
    records = [{"id": str(i)} for i in range(available)]
    requests: list[dict[str, Any]] = []

    async def post(path, *, key=None, json=None):
        body = dict(json)
        requests.append(body)
        size = min(body.get("pageSize", maximum), maximum)
        number = body["pageNumber"]
        return {
            "data": records[number * size : (number + 1) * size],
            "page_number": number,
            "total_page_count": math.ceil(available / size),
            "total_element_count": available,
            "traceId": "synthetic-batching",
        }

    client = SimpleNamespace(post=post, paginate_max_pages=None)
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = None
    registry.resolve_host_id.return_value = "console"
    registry.resolve_site_slug.return_value = "default"
    if tool == "overview":
        result = await network_controller_insights.get_sites_overview(
            client, registry, "console", page_size=requested
        )
    elif tool == "teleport":
        result = await network_vpn_dns.query_teleport_invitations(
            client, registry, "console", "default", page_size=requested
        )
    else:
        result = await system_log._read_system_log(
            client, registry, "console", "default", "all", None, page_size=requested
        )
    if requested == 215:
        # N3-PAGESIZE-ALONE: page_size alone is window 0, exactly
        # records [0, 215) gathered across clamped console pages and trimmed; _nextPage
        # counts 215-record windows.
        assert result["data"] == records[0:215]
        assert result["_pageSize"] == {
            "requested": 215,
            "sent": [215, 200],
            "effective": 200,
            "returned": 215,
        }
        assert result["traceId"] == "synthetic-batching"
        assert requests == [
            {"pageNumber": 0, "pageSize": 215},
            {"pageNumber": 1, "pageSize": 200},
        ]
        assert not result.get("incomplete") and not result.get("_incomplete")
        assert result.get("_nextPage") == 1
        return
    count = min(available, math.ceil(requested / maximum) * maximum)
    pages = math.ceil(count / maximum)
    assert result["data"] == records[:count]
    assert result["_pageSize"] == {
        "requested": requested,
        "sent": [requested, *([maximum] * (pages - 1))],
        "effective": maximum,
        "returned": count,
    }
    assert result["traceId"] == "synthetic-batching"
    assert requests == [
        {"pageNumber": number, "pageSize": requested if number == 0 else maximum}
        for number in range(pages)
    ]
    assert not result.get("incomplete") and not result.get("_incomplete")
    assert result.get("_nextPage") == (pages if count < available else None)


@pytest.mark.parametrize("tool", ["overview", "teleport", "system_log"])
async def test_v2_page_size_alone_next_page_resumes_with_the_same_page_size(tool):
    # N3-PAGESIZE-ALONE: a _nextPage from a page_size call resumes
    # with the same page_size, window after window, with no gap or overlap.
    maximum, available, size = 200, 450, 215
    records = [{"id": str(i)} for i in range(available)]
    requests: list[dict[str, Any]] = []

    async def post(path, *, key=None, json=None):
        body = dict(json)
        requests.append(body)
        width = min(body.get("pageSize", maximum), maximum)
        number = body["pageNumber"]
        return {
            "data": records[number * width : (number + 1) * width],
            "page_number": number,
            "total_page_count": math.ceil(available / width),
            "total_element_count": available,
        }

    client = SimpleNamespace(post=post, paginate_max_pages=None)
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = None
    registry.resolve_host_id.return_value = "console"
    registry.resolve_site_slug.return_value = "default"

    async def call(page: int | None) -> Any:
        if tool == "overview":
            return await network_controller_insights.get_sites_overview(
                client, registry, "console", page=page, page_size=size
            )
        if tool == "teleport":
            return await network_vpn_dns.query_teleport_invitations(
                client, registry, "console", "default", page_number=page, page_size=size
            )
        return await system_log._read_system_log(
            client, registry, "console", "default", "all", None, page=page, page_size=size
        )

    first = await call(None)
    assert first["data"] == records[0:215]
    assert first["_nextPage"] == 1

    before = len(requests)
    second = await call(first["_nextPage"])
    assert second["data"] == records[215:430]
    # Condition 2: the probe of window 1 is sent at the requested 215 (the console clamps
    # it to 200 and the window continues at 200), so the wire list is pinned as issued.
    assert requests[before:] == [
        {"pageNumber": 1, "pageSize": 215},
        {"pageNumber": 2, "pageSize": 200},
    ]
    assert second["_pageSize"]["sent"] == [215, 200]
    assert second["_pageSize"]["returned"] == 215
    assert not second.get("incomplete") and not second.get("_incomplete")
    assert second["_nextPage"] == 2

    third = await call(second["_nextPage"])
    assert third["data"] == records[430:450]
    assert third["_pageSize"]["returned"] == 20
    assert not third.get("incomplete") and not third.get("_incomplete")
    assert third.get("_nextPage") is None
    assert first["data"] + second["data"] + third["data"] == records


async def test_overview_without_total_reads_back_clamped_size_before_short_page_detection():
    records = [{"id": str(i)} for i in range(450)]
    requests: list[dict[str, Any]] = []

    async def post(path, *, key=None, json=None):
        requests.append(dict(json))
        size = min(json.get("pageSize", 200), 200)
        number = json["pageNumber"]
        return {"data": records[number * size : (number + 1) * size], "page_number": number}

    client = SimpleNamespace(post=post, paginate_max_pages=None)
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = None
    registry.resolve_host_id.return_value = "console"
    result = await network_controller_insights.get_sites_overview(
        client, registry, "console", page_size=1000
    )
    assert result["data"] == records
    # Old sent=200 hid the initial wire request of 1000; effective retains the clamp.
    assert result["_pageSize"] == {
        "requested": 1000,
        "sent": [1000, 200, 200, 200],
        "effective": 200,
        "returned": 450,
    }
    assert len(requests) == 4
    assert [body["pageSize"] for body in requests] == [1000, 200, 200, 200]

    assert "_incomplete" not in result
