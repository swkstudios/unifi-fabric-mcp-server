"""A caller pageSize above the console's largest page is fetched in pages of that size.

The fake upstream behaves as the measured console does: pageSize up to
``TRAFFIC_FLOWS_MAX_PAGE_SIZE`` is served (0-based pageNumber, ``has_next`` and
``total_page_count``), and a larger pageSize is answered with HTTP 400 and the console's
validation body. A real ``UniFiClient`` and ``Registry`` sit in front of it.
"""

from __future__ import annotations

import inspect
import json
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest

from tests import upstream_harness as uh
from unifi_fabric import server
from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.tools import network_nat_qos_traffic as nc

MAX = nc.TRAFFIC_FLOWS_MAX_PAGE_SIZE
REJECT_TEXT = '{"errorCode":400,"message":"Validation failed for argument [1]"}'


@dataclass
class FlowsUpstream(uh.FakeUpstream):
    """Traffic-flow POSTs served from ``total`` synthetic records; the rest as the harness."""

    total: int = 0
    clamp: int | None = None
    reject_sizes: frozenset[int] = frozenset()
    flow_requests: list[dict[str, Any]] = field(default_factory=list)

    def __call__(self, req: httpx.Request) -> httpx.Response:
        path = req.url.path
        if req.method != "POST" or not path.endswith(("/traffic-flows", "/traffic-flows/export")):
            return super().__call__(req)
        body = json.loads(req.content) if req.content else None
        self.flow_requests.append(body)
        size = (body or {}).get("pageSize", 1000)
        if size > MAX or size in self.reject_sizes:
            return httpx.Response(
                400, content=REJECT_TEXT.encode(), headers={"content-type": "application/json"}
            )
        if self.clamp is not None:
            size = min(size, self.clamp)
        number = (body or {}).get("pageNumber", 0)
        start = number * size
        data = [{"id": n} for n in range(start, min(start + size, self.total))]
        pages = -(-self.total // size)
        return httpx.Response(
            200,
            json={
                "data": data,
                "has_next": number + 1 < pages,
                "page_number": number,
                "total_element_count": self.total,
                "total_page_count": pages,
            },
        )


async def _query(monkeypatch: pytest.MonkeyPatch, up: FlowsUpstream, body: Any) -> Any:
    uh.install(monkeypatch, up)
    return await nc.query_traffic_flows(server._client, server._registry, uh.HOST, uh.SITE, body)


def _ids(result: dict[str, Any]) -> list[int]:
    return [row["id"] for row in result["data"]]


async def test_page_size_10000_is_two_requests_of_5000_and_returns_every_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    up = FlowsUpstream(total=10_000)
    result = await _query(monkeypatch, up, {"timestampFrom": 1, "pageSize": 10_000})
    assert up.flow_requests == [
        {"timestampFrom": 1, "pageSize": MAX},
        {"timestampFrom": 1, "pageSize": MAX, "pageNumber": 1},
    ]
    assert _ids(result) == list(range(10_000))
    assert result["_pages"] == 2
    # The former scalar sent assertion hid the requested wire size after a console clamp.
    assert result["_pageSize"] == {
        "requested": 10_000,
        "sent": [MAX, MAX],
        "effective": MAX,
        "returned": 10_000,
    }
    assert "incomplete" not in result


async def test_page_size_7000_is_5000_then_2000(monkeypatch: pytest.MonkeyPatch) -> None:
    up = FlowsUpstream(total=7000)
    result = await _query(monkeypatch, up, {"pageSize": 7000})
    assert [r["pageSize"] for r in up.flow_requests] == [MAX, MAX]
    assert [r.get("pageNumber", 0) for r in up.flow_requests] == [0, 1]
    assert _ids(result) == list(range(7000))
    assert result["_pages"] == 2
    # The former scalar sent assertion hid the requested wire size after a console clamp.
    assert result["_pageSize"] == {
        "requested": 7000,
        "sent": [MAX, MAX],
        "effective": MAX,
        "returned": 7000,
    }


async def test_absent_page_size_drains_every_page_with_the_body_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    up = FlowsUpstream(total=2500)
    result = await _query(monkeypatch, up, {"timestampFrom": 1})
    assert up.flow_requests == [
        {"timestampFrom": 1},
        {"timestampFrom": 1, "pageNumber": 1},
        {"timestampFrom": 1, "pageNumber": 2},
    ]
    assert _ids(result) == list(range(2500))
    assert result["_pages"] == 3
    assert "_pageSize" not in result


async def test_page_size_at_the_maximum_is_one_request_sent_as_given(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    up = FlowsUpstream(total=MAX)
    body = {"pageSize": MAX}
    result = await _query(monkeypatch, up, body)
    assert up.flow_requests == [body]
    assert len(result["data"]) == MAX
    # The former scalar sent assertion hid the requested wire size after a console clamp.
    assert result["_pageSize"] == {
        "requested": MAX,
        "sent": [MAX],
        "effective": MAX,
        "returned": MAX,
    }
    assert result["_pages"] == 1


async def test_a_400_at_or_below_the_maximum_passes_through_verbatim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    up = FlowsUpstream(total=10, reject_sizes=frozenset({MAX}))
    with pytest.raises(UniFiConnectionError) as caught:
        await _query(monkeypatch, up, {"pageSize": MAX})
    assert caught.value.status == 400
    assert REJECT_TEXT in str(caught.value)
    assert up.flow_requests == [{"pageSize": MAX}]


async def test_a_batched_page_number_keeps_the_callers_starting_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    up = FlowsUpstream(total=20_000)
    result = await _query(monkeypatch, up, {"pageSize": 7000, "pageNumber": 1})
    # record 7000 is page 1 at size 5000 with its first 2000 records before the start
    assert up.flow_requests[0] == {"pageSize": MAX, "pageNumber": 1}
    assert up.flow_requests == [
        {"pageSize": MAX, "pageNumber": 1},
        {"pageSize": MAX, "pageNumber": 2},
    ]
    assert _ids(result) == list(range(7000, 14_000))
    assert result["_pages"] == 2
    assert "incomplete" not in result
    # The former scalar sent assertion hid the requested wire size after a console clamp.
    assert result["_pageSize"] == {
        "requested": 7000,
        "sent": [MAX, MAX],
        "effective": MAX,
        "returned": 7000,
    }


async def test_export_batches_an_oversized_page_size_the_same_way(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    up = FlowsUpstream(total=6000)
    uh.install(monkeypatch, up)
    result = await nc.export_traffic_flows(
        server._client, server._registry, uh.HOST, uh.SITE, {"pageSize": 9000}
    )
    assert [r["pageSize"] for r in up.flow_requests] == [MAX, MAX]
    assert _ids(result) == list(range(6000))
    # The former scalar sent assertion hid the requested wire size after a console clamp.
    assert result["_pageSize"] == {
        "requested": 9000,
        "sent": [MAX, MAX],
        "effective": MAX,
        "returned": 6000,
    }


@pytest.mark.parametrize("size", ["10000", 10_000.0, True, None])
def test_non_integer_page_sizes_are_forwarded_unchanged(size: Any) -> None:
    body = {"pageSize": size}
    assert nc._flow_page_batch(body) == (body, None)


def test_the_documented_maximum_is_the_constant() -> None:
    source = inspect.getsource(nc.register)
    assert source.count(f"pageSize above {MAX}") == 2
    assert f"is sent as pageSize {MAX}" in source  # export_traffic_flows
    assert f"is sent as {MAX} per page" in source  # query_traffic_flows


@pytest.mark.parametrize("as_lists", [False, True])
async def test_typed_selectors_reach_console_in_observed_shape(
    monkeypatch: pytest.MonkeyPatch, as_lists: bool
) -> None:
    import time

    up = FlowsUpstream(total=3)
    uh.install(monkeypatch, up)
    values = {"direction": "sideways", "action": "quarantined", "risk": "unrated"}
    selectors = {k: [v] if as_lists else v for k, v in values.items()}
    before = int(time.time() * 1000)
    result = uh.result_payload(
        await server.mcp.call_tool(
            "query_traffic_flows", {"host": uh.HOST, "site": uh.SITE, "window": "5m", **selectors}
        )
    )
    after = int(time.time() * 1000)
    assert len(up.flow_requests) == 1
    body = up.flow_requests[0]
    assert {k: body[k] for k in values} == {k: [v] for k, v in values.items()}
    assert before <= body["timestampTo"] <= after
    assert body["timestampFrom"] == body["timestampTo"] - 300_000
    assert "window" not in body
    assert _ids(result) == [0, 1, 2]


async def test_typed_selectors_preserve_explicit_body_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    up = FlowsUpstream(total=3)
    uh.install(monkeypatch, up)
    await server.mcp.call_tool(
        "query_traffic_flows",
        {
            "host": uh.HOST,
            "site": uh.SITE,
            "window": "5m",
            "direction": "outgoing",
            "action": ["blocked"],
            "risk": "medium",
            "body": {
                "timestampFrom": 1,
                "timestampTo": 2,
                "direction": "custom",
                "action": ["custom"],
                "risk": None,
                "custom": 7,
            },
        },
    )
    assert up.flow_requests == [
        {
            "timestampFrom": 1,
            "timestampTo": 2,
            "direction": "custom",
            "action": ["custom"],
            "risk": None,
            "custom": 7,
        }
    ]


@pytest.mark.parametrize(
    ("requested", "available", "maximum", "expected_calls"),
    [
        (1000, 450, 200, 3),
        (10000, 215, MAX, 1),
        (1000, 2500, MAX, 1),
    ],
)
async def test_requested_total_reads_effective_page_size_and_stops_at_total_or_end(
    monkeypatch: pytest.MonkeyPatch,
    requested: int,
    available: int,
    maximum: int,
    expected_calls: int,
) -> None:
    up = FlowsUpstream(total=available, clamp=maximum)
    result = await _query(monkeypatch, up, {"pageSize": requested})
    assert len(up.flow_requests) == expected_calls
    assert _ids(result) == list(range(min(requested, available)))
    assert up.flow_requests[0]["pageSize"] == min(requested, MAX)
    assert [r["pageSize"] for r in up.flow_requests[1:]] == [min(requested, maximum)] * (
        expected_calls - 1
    )
    # The former scalar sent assertion hid the requested wire size after a console clamp.
    assert result["_pageSize"] == {
        "requested": requested,
        "sent": [min(requested, MAX)] + [min(requested, maximum)] * (expected_calls - 1),
        "effective": min(requested, maximum),
        "returned": min(requested, available),
    }
    assert result["_pages"] == expected_calls
    assert "incomplete" not in result


@pytest.mark.parametrize("export", [False, True])
@pytest.mark.parametrize("following_size", [275, 100])
async def test_logical_continuation_keeps_offset_when_page_size_changes(
    monkeypatch: pytest.MonkeyPatch, following_size: int, export: bool
) -> None:
    up = FlowsUpstream(total=1000, clamp=200)
    uh.install(monkeypatch, up)
    call = nc.export_traffic_flows if export else nc.query_traffic_flows
    first = await call(
        server._client,
        server._registry,
        uh.HOST,
        uh.SITE,
        {"timestampFrom": 1, "pageSize": 275},
    )
    assert _ids(first) == list(range(275))
    assert first["_nextPage"] == {"offset": 275, "pageSize": 275}
    assert up.flow_requests == [
        {"timestampFrom": 1, "pageSize": 275},
        {"timestampFrom": 1, "pageSize": 200, "pageNumber": 1},
    ]
    assert first["_pageSize"] == {
        "requested": 275,
        "sent": [275, 200],
        "effective": 200,
        "returned": 275,
    }
    up.flow_requests.clear()
    following = await call(
        server._client,
        server._registry,
        uh.HOST,
        uh.SITE,
        {"timestampFrom": 1, "pageSize": following_size, "pageNumber": first["_nextPage"]},
    )
    assert _ids(following) == list(range(275, 275 + following_size))
    assert _ids(first) + _ids(following) == list(range(275 + following_size))
    assert following["_nextPage"] == {"offset": 275 + following_size, "pageSize": following_size}
    expected = (
        [
            {"timestampFrom": 1, "pageSize": 275, "pageNumber": 1},
            {"timestampFrom": 1, "pageSize": 200, "pageNumber": 2},
        ]
        if following_size == 275
        else [
            {"timestampFrom": 1, "pageSize": 100, "pageNumber": 2},
            {"timestampFrom": 1, "pageSize": 100, "pageNumber": 3},
        ]
    )
    assert up.flow_requests == expected
    assert following["_pageSize"] == {
        "requested": following_size,
        "sent": [r["pageSize"] for r in expected],
        "effective": min(following_size, 200),
        "returned": following_size,
    }


async def test_logical_continuation_reuses_size_when_no_new_size_is_given(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    up = FlowsUpstream(total=450, clamp=200)
    result = await _query(
        monkeypatch,
        up,
        {"pageNumber": {"offset": 275, "pageSize": 100}},
    )
    assert _ids(result) == list(range(275, 375))
    assert result["_nextPage"] == {"offset": 375, "pageSize": 100}
    assert up.flow_requests == [
        {"pageNumber": 2, "pageSize": 100},
        {"pageNumber": 3, "pageSize": 100},
    ]


@pytest.mark.parametrize("export", [False, True])
@pytest.mark.parametrize(
    "body",
    [
        {"pageNumber": {"offset": -1, "pageSize": 100}},
        {"pageNumber": {"offset": True, "pageSize": 100}},
        {"pageNumber": {"offset": 100}},
        {"pageNumber": {"offset": 100, "pageSize": 0}},
        {"pageNumber": {"offset": 100, "pageSize": 100}, "pageSize": "100"},
    ],
)
async def test_invalid_logical_continuation_fails_before_any_request(
    monkeypatch: pytest.MonkeyPatch,
    export: bool,
    body: dict[str, Any],
) -> None:
    from unittest.mock import AsyncMock

    client, registry = AsyncMock(), AsyncMock()
    call = nc.export_traffic_flows if export else nc.query_traffic_flows
    with pytest.raises(ValueError, match="body.page(Number|Size)"):
        await call(client, registry, uh.HOST, uh.SITE, body)
    assert client.mock_calls == []
    assert registry.mock_calls == []
