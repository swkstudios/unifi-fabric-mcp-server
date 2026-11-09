"""Synthetic continuity checks across console clamps and public continuations."""

from __future__ import annotations

import json
from math import ceil
from unittest.mock import AsyncMock

import pytest

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_catalog import tools_by_name
from tests.conftest import MULTIKEY_HOSTS_BY_LABEL
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.registry import Registry
from unifi_fabric.tools import carrier_fabric
from unifi_fabric.tools import network_nat_qos_traffic as flows
from unifi_fabric.tools._continuation import decode_continuation
from unifi_fabric.tools._pagination import (
    PageSizeBatch,
    collect_batch,
    collect_links,
    collect_offset,
    offset_list_result,
)


@pytest.fixture(scope="module")
def tools():
    return tools_by_name()


REQUESTED = [199, 200, 201, 275, 450, 7000, 10000]
AVAILABLE = [0, 1, 215, 450]


class ClampedPages:
    """Stable records; cursors are opaque and cannot be arithmetically advanced."""

    def __init__(self, family, available, *, ignores_size=False):
        self.family = family
        self.available = available
        self.ignores_size = ignores_size
        self.calls = []

    async def fetch(self, controls):
        self.calls.append(dict(controls))
        size_key = "limit" if self.family in {"offset", "carrier"} else "pageSize"
        size = 200 if self.ignores_size else min(controls[size_key], 200)
        if self.family == "offset":
            start = controls.get("offset", 0)
        elif self.family in {"number", "links"}:
            first = 1 if self.family == "links" else 0
            key = "page" if self.family == "links" else "pageNumber"
            start = (controls.get(key, first) - first) * size
        else:
            key = "cursor" if self.family == "carrier" else "nextToken"
            start = int(controls.get(key, "opaque:0").split(":")[1])
        stop = min(start + size, self.available)
        token = f"opaque:{stop}" if stop < self.available else None
        response = {"data": list(range(start, stop)), "limit": size}
        if self.family == "offset":
            response.update(offset=start, totalCount=self.available)
        elif self.family == "number":
            response.update(
                page_number=controls.get("pageNumber", 0),
                total_page_count=ceil(self.available / size),
            )
        elif self.family == "links":
            response["links"] = {
                "next": f"?page={controls.get('page', 1) + 1}&pageSize={size}" if token else None
            }
        elif self.family == "carrier":
            response["meta"] = {"hasMore": token is not None, "nextCursor": token, "limit": size}
        else:
            response["nextToken"] = token
        return response


@pytest.mark.parametrize("family", ["offset", "number", "links", "cursor", "carrier"])
@pytest.mark.parametrize("requested", REQUESTED)
@pytest.mark.parametrize("available", AVAILABLE)
async def test_every_record_once_across_returned_continuations(family, requested, available):
    upstream = ClampedPages(family, available)
    records = []
    start, token = (1 if family == "links" else 0), None
    while True:
        call_start = len(upstream.calls)
        result = await collect_batch(
            upstream.fetch, requested=requested, family=family, start=start, token=token
        )
        assert not result["incomplete"]
        # The old scalar sent assertion confused observed clamp with actual wire sizes.
        size_key = "limit" if family in {"offset", "carrier"} else "pageSize"
        assert result["_pageSize"] == {
            "requested": requested,
            "sent": [c[size_key] for c in upstream.calls[call_start:]],
            "effective": min(requested, 200),
            "returned": len(result["items"]),
        }
        # The old exact cursor count encoded dropping the unreturned physical tail.
        expected = min(requested, available - len(records))
        if family != "offset":
            expected = min(
                ceil(requested / min(requested, 200)) * min(requested, 200),
                available - len(records),
            )
        assert len(result["items"]) == expected
        records.extend(result["items"])
        if family in {"cursor", "carrier"}:
            token = result["nextToken" if family == "cursor" else "nextCursor"]
            if token is None:
                break
        else:
            start = result["nextOffset" if family == "offset" else "nextPage"]
            if start is None:
                break
        assert len(records) < available
    assert records == list(range(available))


async def test_requested_275_cursor_does_not_skip_125_records_at_400():
    upstream = ClampedPages("cursor", 450)
    first = await collect_batch(upstream.fetch, requested=275, family="cursor")
    # Old 275-row trim plus native token 400 silently skipped 125 records.
    assert first["items"] == list(range(400))
    assert first["nextToken"] == "opaque:400"
    assert isinstance(first["_continuation"], str)
    assert decode_continuation(first["_continuation"]) == {
        "pageToken": "opaque:400",
        "pageSize": 275,
    }
    assert upstream.calls == [{"pageSize": 275}, {"pageSize": 275, "nextToken": "opaque:200"}]
    second = await collect_batch(
        upstream.fetch, requested=75, family="cursor", token=first["_continuation"]
    )
    assert second["items"] == list(range(400, 450))
    assert second["nextToken"] is None
    assert upstream.calls[-1] == {"pageSize": 275, "nextToken": "opaque:400"}


@pytest.mark.parametrize("family", ["cursor", "carrier"])
async def test_opaque_cursor_ignoring_tail_size_keeps_full_final_page(family):
    upstream = ClampedPages(family, 450, ignores_size=True)
    first = await collect_batch(upstream.fetch, requested=275, family=family)
    assert first["items"] == list(range(400))
    token = first["nextToken" if family == "cursor" else "nextCursor"]
    assert token == "opaque:400"
    second = await collect_batch(upstream.fetch, requested=275, family=family, token=token)
    assert first["items"] + second["items"] == list(range(450))


def flow_registry(client):
    registry = Registry(client)
    registry.resolve_key_for_host = AsyncMock(return_value=None)
    registry.resolve_host_id = AsyncMock(return_value="synthetic-host")
    registry.resolve_site_slug = AsyncMock(return_value="default")
    return registry


async def query_flow_page(upstream, requested, number):
    client = UniFiClient(Settings(api_key="synthetic-continuity-test"))

    async def post(path, *, key=None, json=None):
        return await upstream.fetch(json)

    client.post = post
    try:
        return await flows.query_traffic_flows(
            client,
            flow_registry(client),
            "synthetic-host",
            "default",
            body={"pageNumber": number, "pageSize": requested},
        )
    finally:
        await client.close()


async def test_requested_7000_flow_page_one_starts_at_7000_after_200_clamp():
    upstream = ClampedPages("number", 15000)
    result = await query_flow_page(upstream, 7000, 1)
    assert result["data"] == list(range(7000, 14000))
    assert result["_pageSize"] == {
        "requested": 7000,
        "sent": [5000] + [200] * 35,
        "effective": 200,
        "returned": 7000,
    }
    assert upstream.calls[0] == {"pageSize": 5000, "pageNumber": 1}
    assert upstream.calls[1] == {"pageSize": 200, "pageNumber": 35}
    assert not result.get("incomplete")


@pytest.mark.parametrize("requested", REQUESTED)
@pytest.mark.parametrize("available", AVAILABLE)
async def test_flow_logical_pages_are_contiguous_after_effective_size_readback(
    requested, available
):
    upstream = ClampedPages("number", available)
    records, number = [], 0
    while True:
        offset = number["offset"] if isinstance(number, dict) else number * requested
        call_start = len(upstream.calls)
        result = await query_flow_page(upstream, requested, number)
        assert result["data"] == list(range(offset, min(offset + requested, available)))
        assert result["_pageSize"] == {
            "requested": requested,
            "sent": [c["pageSize"] for c in upstream.calls[call_start:]],
            "effective": min(requested, 200),
            "returned": len(result["data"]),
        }
        assert not result.get("incomplete")
        records.extend(result["data"])
        if "_nextPage" not in result:
            break
        # Bare logical page numbers skipped records when the caller changed size.
        assert result["_nextPage"] == {
            "offset": offset + len(result["data"]),
            "pageSize": requested,
        }
        number = result["_nextPage"]
        assert len(records) < available
    assert records == list(range(available))


async def test_carrier_public_adapter_preserves_final_continuation():
    upstream = ClampedPages("carrier", 900)
    client = UniFiClient(Settings(api_key="synthetic-continuity-test"))

    async def get(path, *, key=None, params=None):
        return await upstream.fetch(params)

    client.get = get
    records, cursor = [], None
    try:
        while True:
            result = await carrier_fabric.list_carrier_subscribers(client, limit=275, cursor=cursor)
            records.extend(result["data"])
            cursor = result.get("_continuation")
            if not result["meta"]["hasMore"]:
                break
        assert records == list(range(900))
    finally:
        await client.close()


@pytest.mark.parametrize(
    ("name", "route"),
    [
        ("update_vpn_server", "/api/s/default/rest/networkconf/"),
        ("update_device_tag", "/v2/api/site/default/device-tags/"),
    ],
)
@pytest.mark.parametrize("multikey", [False, True])
async def test_classic_and_v2_writes_audit_canonical_site(
    monkeypatch, tmp_path, multikey_client, name, route, multikey, tools
):
    log = tmp_path / "audit.jsonl"
    args = tool_args.generated_args(tools[name])
    keys = (
        [multikey_client.get_key_by_label(label) for label in ("alpha", "beta")]
        if multikey
        else None
    )
    hosts = {key.key: MULTIKEY_HOSTS_BY_LABEL[key.label] for key in keys} if keys else None
    up = uh.FakeUpstream(hosts_by_key=hosts)
    if multikey:
        args["host"] = "beta-branch.example"
    await cti._call(
        monkeypatch,
        name,
        up,
        args=args,
        keys=keys,
        env={"UNIFI_AUDIT_LOG": str(log), "UNIFI_AUDIT_LOG_FORMAT": "json"},
    )
    records = [
        r
        for r in (json.loads(line) for line in log.read_text().splitlines())
        if r.get("event", "audit") == "audit"
    ]
    assert records
    expected_host = "console-beta-1" if multikey else uh.HOST_ID
    assert all(
        r["resolvedSite"] == uh.SITE_ID and r["resolvedHost"] == expected_host for r in records
    )
    assert any(route in r["path"] for r in records)
    if multikey:
        assert {s.api_key for s in up.served if s.method == "PUT"} == {
            multikey_client.get_key_by_label("beta").key
        }


@pytest.mark.parametrize("ignores_size", [False, True])
async def test_offset_without_total_retains_continuation_after_tail_request(ignores_size):
    upstream = ClampedPages("offset", 450, ignores_size=ignores_size)

    async def fetch(controls):
        response = await upstream.fetch(controls)
        response.pop("totalCount")
        return response

    first = await collect_batch(fetch, requested=275, family="offset")
    assert first["items"] == list(range(275))
    assert first["nextOffset"] == 275
    second = await collect_batch(fetch, requested=275, family="offset", start=275)
    assert first["items"] + second["items"] == list(range(450))


@pytest.mark.parametrize("malformed", [None, "invalid"])
async def test_carrier_malformed_later_page_keeps_last_valid_meta(malformed):
    meta = {"hasMore": True, "nextCursor": "opaque:1", "limit": 1}
    fetch = AsyncMock(side_effect=[{"data": [0], "meta": meta}, malformed])
    result = await collect_batch(fetch, requested=275, family="carrier")
    assert result["items"] == [0]
    assert result["meta"] == meta
    assert result["incomplete"]


async def test_carrier_bare_array_preserves_records():
    result = await collect_batch(AsyncMock(return_value=[0]), requested=275, family="carrier")
    assert result["items"] == [0]
    assert result["meta"] is None
    assert not result["incomplete"]


async def test_flow_returns_logical_continuation_for_trimmed_terminal_physical_page():
    upstream = ClampedPages("number", 400)
    first = await query_flow_page(upstream, 275, 0)
    assert first["data"] == list(range(275))
    assert first["_nextPage"] == {"offset": 275, "pageSize": 275}
    second = await query_flow_page(upstream, 275, first["_nextPage"])
    assert first["data"] + second["data"] == list(range(400))
    assert "_nextPage" not in second


async def test_flow_terminal_probe_does_not_mistake_short_tail_for_clamp():
    upstream = ClampedPages("number", 450)
    result = await query_flow_page(upstream, 275, 1)
    assert result["data"] == list(range(275, 450))
    assert result["_pageSize"] == {
        "requested": 275,
        "sent": [275, 200],
        "effective": 200,
        "returned": 175,
    }
    assert "_nextPage" not in result


async def test_number_continuation_does_not_reprobe_terminal_page_without_echo():
    upstream = ClampedPages("number", 450)

    async def fetch(controls):
        response = await upstream.fetch(controls)
        response.pop("limit")
        response["total_element_count"] = upstream.available
        return response

    first = await collect_batch(fetch, requested=275, family="number", strict_total=True)
    second = await collect_batch(
        fetch, requested=275, family="number", strict_total=True, start=first["nextPage"]
    )
    assert first["items"] + second["items"] == list(range(450))
    assert second["_pageSize"] == {
        "requested": 275,
        # Terminal count evidence proves width 200 while the sent size stays 275 (A4).
        "sent": [275],
        "effective": 200,
        "returned": 50,
    }
    assert upstream.calls[-1] == {"pageSize": 275, "pageNumber": 2}
    assert len(upstream.calls) == 3
    assert not second["incomplete"]
    assert second["nextPage"] is None


@pytest.mark.parametrize("answered", [None, "invalid", True])
def test_number_size_observation_tolerates_unusable_page_echo(answered):
    batch = PageSizeBatch(275)
    batch.observe({"page_number": answered, "total_page_count": 2}, [0, 1], "number", first=True)
    # The old assertion overwrote actual sent275 with observed2.
    assert batch.sent == 275
    assert batch.effective == 2


@pytest.mark.parametrize("family", ["cursor", "carrier"])
@pytest.mark.parametrize("clamp", [None, 200])
async def test_page_index_token_tail_and_changed_size_followup_are_contiguous(family, clamp):
    calls = []
    size_key = "limit" if family == "carrier" else "pageSize"
    token_key = "cursor" if family == "carrier" else "nextToken"
    result_key = "nextCursor" if family == "carrier" else "nextToken"

    async def fetch(controls):
        calls.append(dict(controls))
        size = min(controls[size_key], clamp) if clamp else controls[size_key]
        index = int(controls.get(token_key, "0"))
        start = index * size
        stop = min(start + size, 1000)
        native = str(index + 1) if stop < 1000 else None
        response = {"data": list(range(start, stop)), "limit": size}
        if family == "carrier":
            response["meta"] = {"limit": size, "hasMore": native is not None, "nextCursor": native}
        else:
            response["nextToken"] = native
        return response

    first = await collect_batch(fetch, requested=275, family=family)
    count = 400 if clamp else 275
    assert first["items"] == list(range(count))
    assert first[result_key] == ("2" if clamp else "1")
    expected_calls = [{size_key: 275}]
    if clamp:
        expected_calls.append({size_key: 275, token_key: "1"})
    assert calls == expected_calls  # No unsafe 75-record cursor tail.
    assert first["_pageSize"] == {
        "requested": 275,
        "sent": [275] * len(calls),
        "effective": clamp or 275,
        "returned": count,
    }
    continuation = first["_continuation"]
    assert isinstance(continuation, str)
    assert decode_continuation(continuation) == {
        "cursor" if family == "carrier" else "pageToken": first[result_key],
        size_key: 275,
    }
    second = await collect_batch(fetch, requested=75, family=family, token=continuation)
    physical = clamp or 275
    assert second["items"] == list(range(count, count + physical))
    assert first["items"] + second["items"] == list(range(count + physical))
    assert calls[-1] == {size_key: 275, token_key: first[result_key]}
    assert second["_pageSize"] == {
        "requested": 75,
        "sent": [275],
        "effective": physical,
        "returned": physical,
    }


@pytest.mark.parametrize("family", ["cursor", "carrier"])
async def test_short_page_with_fresh_token_keeps_gathering(family):
    calls = []
    token_key = "cursor" if family == "carrier" else "nextToken"
    size_key = "limit" if family == "carrier" else "pageSize"
    chunks = [list(range(2)), [2], list(range(3, 7))]

    async def fetch(controls):
        calls.append(dict(controls))
        index = int(controls.get(token_key, "0"))
        native = str(index + 1) if index < 2 else None
        response = {"data": chunks[index]}
        if family == "carrier":
            response["meta"] = {"hasMore": native is not None, "nextCursor": native}
        else:
            response["nextToken"] = native
        return response

    result = await collect_batch(fetch, requested=7, family=family)
    assert result["items"] == list(range(7))
    assert not result["incomplete"]
    assert calls == [{size_key: 7}, {size_key: 7, token_key: "1"}, {size_key: 7, token_key: "2"}]


async def test_native_offset_with_limit_is_one_verbatim_clamped_page():
    upstream = ClampedPages("offset", 1000)
    client = UniFiClient(Settings(api_key="synthetic-continuity-test"))

    async def get(path, *, key=None, params=None):
        return await upstream.fetch(params)

    client.get = get
    try:
        collected = await collect_offset(client, "/synthetic", offset=10, limit=275)
        assert offset_list_result(collected) == {
            "offset": 10,
            "limit": 200,
            "data": list(range(10, 210)),
            "totalCount": 1000,
            "_pageSize": {"requested": 275, "sent": [275], "effective": 200, "returned": 200},
        }
        assert upstream.calls == [{"offset": 10, "limit": 275}]
    finally:
        await client.close()


async def test_offset_envelope_without_total_or_limit_keeps_fetching():
    async def fetch(controls):
        offset = controls.get("offset", 0)
        return {"data": list(range(offset, min(offset + 100, 300)))}

    result = await collect_batch(fetch, requested=200, family="offset")
    assert result["items"] == list(range(200))
    assert not result["incomplete"]


async def test_linked_logical_page_starts_after_effective_clamp():
    async def get(path, *, key, params):
        size = min(params["pageSize"], 60)
        start = (params["page"] - 1) * size
        return {
            "data": list(range(start, min(start + size, 900))),
            "links": {"next": f"?page={params['page'] + 1}&pageSize={size}"},
        }

    client = type("Client", (), {"get": staticmethod(get), "paginate_max_pages": None})()
    result = await collect_links(client, "/test", "data", page=2, page_size=275)
    assert result["items"] == list(range(275, 550))
    assert len(result["items"]) <= 275
    assert not result["incomplete"]


async def test_linked_native_start_and_followup_are_contiguous_after_effective_clamp():
    calls = []

    async def get(path, *, key, params):
        calls.append(dict(params))
        size = min(params["pageSize"], 60)
        start = (params["page"] - 1) * size
        return {
            "data": list(range(start, min(start + size, 900))),
            "links": {"next": f"?page={params['page'] + 1}&pageSize={size}"},
        }

    client = type("Client", (), {"get": staticmethod(get), "paginate_max_pages": None})()
    result = await collect_links(client, "/test", "data", page=2, page_size=75)
    assert result["items"] == list(range(75, 150))
    assert len(result["items"]) <= 75
    assert result["nextPage"] == 3
    assert result["_pageSize"] == {
        "requested": 75,
        "sent": [75, 60],
        "effective": 60,
        "returned": 75,
    }
    assert calls == [{"page": page, "pageSize": 75 if page == 2 else 60} for page in range(2, 4)]
    assert not result["incomplete"]
    followup = await collect_links(
        client,
        "/test",
        "data",
        page=result["nextPage"],
        page_size=75,
    )
    assert result["items"] + followup["items"] == list(range(75, 225))
    assert len(followup["items"]) <= 75
    assert followup["nextPage"] == 4
    assert not followup["incomplete"]
