"""Synthetic regressions for the batching ultra-review findings."""

from __future__ import annotations

from math import ceil
from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import UniFiClient, UniFiConnectionError
from unifi_fabric.config import Settings
from unifi_fabric.families.carrier import carrier_fabric
from unifi_fabric.families.protect import protect, recognition
from unifi_fabric.families.protect.protect_events_cases import get_protect_case_activity
from unifi_fabric.registry import Registry
from unifi_fabric.shared_shapes._continuation import decode_continuation
from unifi_fabric.shared_shapes._pagination import collect_batch, collect_links, collect_offset


def _client(fetch):
    client = UniFiClient(Settings(api_key="synthetic-ultra-review"))
    client.get = fetch
    return client


def _registry(client):
    registry = Registry(client)
    registry.resolve_key_for_host = AsyncMock(return_value=None)
    registry.resolve_host_id = AsyncMock(return_value="synthetic-host")
    return registry


async def test_carrier_complete_requested_total_needs_no_further_cursor():
    calls = []

    async def fetch(controls):
        calls.append(dict(controls))
        start = 0 if len(calls) == 1 else 200
        return {
            "data": list(range(start, start + 200)),
            "meta": {"hasMore": True, "nextCursor": "200" if start == 0 else None},
        }

    result = await collect_batch(fetch, requested=400, known_max=200, family="carrier")
    assert result["items"] == list(range(400))
    assert not result["incomplete"]
    assert len(calls) == 2


@pytest.mark.parametrize("echo_number", [False, True])
async def test_number_terminal_page_uses_requested_position_without_probe(echo_number):
    calls = []

    async def fetch(controls):
        calls.append(dict(controls))
        number = controls["pageNumber"]
        size = controls["pageSize"]
        response = {
            "data": list(range(number * size, min((number + 1) * size, 215))),
            "total_page_count": ceil(215 / size),
            "total_element_count": 215,
        }
        if echo_number:
            response["page_number"] = number
        return response

    result = await collect_batch(fetch, requested=100, start=2, strict_total=True)
    assert result["items"] == list(range(200, 215))
    assert not result["incomplete"]
    assert calls == [{"pageSize": 100, "pageNumber": 2}]
    assert result["_pageSize"]["effective"] == 100


async def test_number_total_without_page_count_accounts_for_start():
    calls = []

    async def fetch(controls):
        calls.append(dict(controls))
        start = controls["pageNumber"] * controls["pageSize"]
        return {"data": list(range(start, min(start + 100, 250))), "total_element_count": 250}

    result = await collect_batch(fetch, requested=100, start=2)
    assert result["items"] == list(range(200, 250))
    assert not result["incomplete"]
    # A total alone cannot distinguish a terminal tail from an unreported clamp.
    # Discover page zero before claiming completion (N3).
    assert calls == [{"pageSize": 100, "pageNumber": 2}, {"pageSize": 100, "pageNumber": 0}]


async def test_offset_bare_arrays_without_size_echo_drain_past_short_pages():
    calls = []

    async def fetch(path, *, key=None, params=None):
        controls = dict(params or {})
        calls.append(controls)
        start = controls.get("offset", 0)
        return list(range(start, min(start + min(controls["limit"], 100), 450)))

    result = await collect_offset(_client(fetch), "/synthetic/events")
    assert result["items"] == list(range(450))
    assert not result["incomplete"]
    assert [call.get("offset", 0) for call in calls] == [0, 100, 200, 300, 400, 450]


async def test_links_follow_next_after_empty_middle_page():
    calls = []
    responses = [
        {"groups": [{"id": "first"}], "links": {"next": "?page=2&pageSize=100"}},
        {"groups": [], "links": {"next": "?page=3&pageSize=100"}},
        {"groups": [{"id": "last"}], "links": {"next": None}},
    ]

    async def fetch(path, *, key=None, params=None):
        calls.append(dict(params or {}))
        return responses[len(calls) - 1]

    result = await collect_links(_client(fetch), "/synthetic/groups", "groups")
    assert result["items"] == [{"id": "first"}, {"id": "last"}]
    assert not result["incomplete"]
    assert [call["page"] for call in calls] == [1, 2, 3]


async def test_carrier_requested_total_retains_last_meta_and_resumes():
    calls = []

    async def fetch(path, *, key=None, params=None):
        controls = dict(params or {})
        calls.append(controls)
        start = int(controls.get("cursor", "0"))
        stop = min(start + controls["limit"], 2000)
        return {
            "data": list(range(start, stop)),
            "meta": {"hasMore": stop < 2000, "nextCursor": str(stop), "limit": controls["limit"]},
        }

    client = _client(fetch)
    result = await carrier_fabric.list_carrier_subscribers(client, limit=600)
    assert result["data"] == list(range(1000))
    assert result["meta"] == {"hasMore": True, "nextCursor": "1000", "limit": 500}
    assert isinstance(result["_continuation"], str)
    assert decode_continuation(result["_continuation"]) == {"cursor": "1000", "limit": 500}
    assert result["_nextCursor"] == result["meta"]["nextCursor"]
    resumed = await carrier_fabric.list_carrier_subscribers(
        client, limit=600, cursor=result["_continuation"]
    )
    assert resumed["data"] == list(range(1000, 2000))
    assert not resumed["meta"]["hasMore"]
    assert calls == [
        {"limit": 500},
        {"limit": 500, "cursor": "500"},
        {"limit": 500, "cursor": "1000"},
        {"limit": 500, "cursor": "1500"},
    ]


@pytest.mark.parametrize("name", ["groups", "detections", "activity"])
async def test_links_logical_pages_at_large_size_do_not_overlap(name):
    field = {"groups": "groups", "detections": "detections", "activity": "activities"}[name]
    calls = []

    async def fetch(path, *, key=None, params=None):
        controls = dict(params or {})
        calls.append(controls)
        size = min(controls["pageSize"], 100)
        start = (controls["page"] - 1) * size
        stop = min(start + size, 1200)
        return {
            field: list(range(start, stop)),
            "links": {
                "next": f"?page={controls['page'] + 1}&pageSize={size}" if stop < 1200 else None
            },
        }

    client = _client(fetch)
    registry = _registry(client)

    async def page(number):
        kwargs = {"page": number, "page_size": 500}
        if name == "groups":
            return await recognition.list_recognition_groups(
                client, registry, "synthetic-host", "face", **kwargs
            )
        if name == "detections":
            return await recognition.list_recognition_detections(
                client, registry, "synthetic-host", "face", "group-1", **kwargs
            )
        return await get_protect_case_activity(
            client, registry, "synthetic-host", "case-1", **kwargs
        )

    first = await page(1)
    second = await page(2)
    assert first[field] == list(range(500))
    assert second[field] == list(range(500, 1000))
    assert not set(first[field]) & set(second[field])
    assert [call["page"] for call in calls] == list(range(1, 11))


@pytest.mark.parametrize("family", ["cursor", "carrier"])
@pytest.mark.parametrize("echo_size", [False, True])
async def test_short_cursor_page_preserves_wire_size_unless_explicit_echo(family, echo_size):
    calls = []

    async def fetch(controls):
        calls.append(dict(controls))
        token_key = "nextToken" if family == "cursor" else "cursor"
        start = int(controls.get(token_key, "0"))
        size_key = "pageSize" if family == "cursor" else "limit"
        size = 3 if len(calls) == 1 else controls[size_key]
        stop = min(start + size, 450)
        response = {"data": list(range(start, stop))}
        if family == "cursor":
            response["nextToken"] = str(stop) if stop < 450 else None
            if echo_size:
                response["limit"] = 100
        else:
            response["meta"] = {
                "hasMore": stop < 450,
                "nextCursor": str(stop) if stop < 450 else None,
            }
            if echo_size:
                response["meta"]["limit"] = 100
        return response

    result = await collect_batch(fetch, requested=600, known_max=200, family=family)
    assert result["items"] == list(range(450))
    assert not result["incomplete"]
    size_key = "pageSize" if family == "cursor" else "limit"
    assert calls[0][size_key] == 200
    assert {call[size_key] for call in calls[1:]} == {200}
    assert result["_pageSize"]["effective"] == (100 if echo_size else 3)
    assert len(calls) == 4


@pytest.mark.parametrize("configured_cap", [None, "2"])
async def test_operator_cap_applies_to_requested_offset_total(monkeypatch, configured_cap):
    if configured_cap is None:
        monkeypatch.delenv("UNIFI_PAGINATE_MAX_PAGES", raising=False)
    else:
        monkeypatch.setenv("UNIFI_PAGINATE_MAX_PAGES", configured_cap)
    calls = []

    async def fetch(path, *, key=None, params=None):
        controls = dict(params or {})
        calls.append(controls)
        start = controls.get("offset", 0)
        size = min(controls["limit"], 200)
        return {"data": list(range(start, start + size)), "totalCount": 1000, "limit": size}

    result = await collect_offset(
        _client(fetch),
        "/v1/connector/consoles/test/proxy/network/integration/v1/sites/test/clients",
        limit=1000,
    )
    expected = 400 if configured_cap else 1000
    assert result["items"] == list(range(expected))
    assert len(calls) == (2 if configured_cap else 5)
    assert result["incomplete"] is bool(configured_cap)
    if configured_cap:
        assert "UNIFI_PAGINATE_MAX_PAGES" in result["incompleteReason"]


@pytest.mark.parametrize("available", [450, 2000])
async def test_protect_private_events_large_limit_is_one_consistent_request(available):
    calls = []

    async def fetch(path, *, key=None, params=None):
        controls = dict(params or {})
        calls.append((path, controls))
        start = controls.get("offset", 0)
        return [{"id": str(i)} for i in range(start, min(start + controls["limit"], available))]

    client = _client(fetch)
    result = await protect.list_protect_events(
        client, _registry(client), "synthetic-host", start=1700000000, end=1700000100, limit=1000
    )
    rows = result if isinstance(result, list) else result.get("data", result.get("result"))
    assert rows == [{"id": str(i)} for i in range(min(1000, available))]
    assert len(calls) == 1
    assert calls[0][0].endswith("/proxy/protect/api/events")
    assert calls[0][1] == {"start": 1700000000000, "end": 1700000100000, "limit": 1000}


async def test_links_non_aligned_logical_page_discards_only_leading_overlap():
    calls = []

    async def fetch(path, *, key=None, params=None):
        controls = dict(params or {})
        calls.append(controls)
        size = controls["pageSize"]
        start = (controls["page"] - 1) * size
        return {
            "groups": list(range(start, start + size)),
            "links": {"next": f"?page={controls['page'] + 1}&pageSize={size}"},
        }

    result = await collect_links(
        _client(fetch), "/synthetic/groups", "groups", page=2, page_size=275
    )
    assert result["items"] == list(range(275, 550))
    assert len(result["items"]) <= 275
    assert [call["page"] for call in calls] == [3, 4, 5, 6]
    assert result["nextPage"] == 3
    assert result["_pageSize"] == {
        "requested": 275,
        "sent": [100, 100, 100, 100],
        "effective": 100,
        "returned": 275,
    }
    assert not result["incomplete"]


async def test_carrier_complete_window_still_rejects_malformed_cursor():
    async def fetch(controls):
        return {"data": [1], "meta": {"hasMore": True, "nextCursor": 42}}

    with pytest.raises(UniFiConnectionError, match="nextCursor"):
        await collect_batch(fetch, requested=1, family="carrier")
