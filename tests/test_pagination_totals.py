"""Drains trust the upstream totalCount, fan-out never deadlocks, errors keep their cause."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
import respx
from httpx import Request, Response

from unifi_fabric.client import UniFiClient, UniFiConnectionError
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.families.clients.clients import _list_clients
from unifi_fabric.families.devices.device_mgmt import _list_site_devices
from unifi_fabric.families.network.network_services_proxy import list_countries
from unifi_fabric.families.site_manager import aggregation, site_manager
from unifi_fabric.registry import Registry, incomplete_reason

BASE = "https://api.ui.com"
HOST = "AABBCCDDEEFF0000:1"
SITE_UUID = "aaaaaaaa-0000-4000-8000-000000000001"
PROXY = f"{BASE}/v1/connector/consoles/{HOST}/proxy/network/integration/v1"


def _registry() -> AsyncMock:
    reg = AsyncMock()
    reg.resolve_key_for_host = AsyncMock(return_value=None)
    reg.resolve_host_id = AsyncMock(return_value=HOST)
    reg.resolve_site_id = AsyncMock(return_value=SITE_UUID)
    reg.get_sites = AsyncMock(
        return_value=[{"id": SITE_UUID, "name": "Default", "internalReference": "default"}]
    )
    reg.get_hosts = AsyncMock(return_value=[])
    return reg


@pytest.fixture
def client() -> UniFiClient:
    return UniFiClient(Settings(api_key="sk-test"))


def _clamped(items: list[Any], max_limit: int):
    def handler(request: Request) -> Response:
        offset = int(request.url.params.get("offset", 0))
        limit = min(int(request.url.params.get("limit", 25)), max_limit)
        page = items[offset : offset + limit]
        return Response(200, json={"data": page, "totalCount": len(items)})

    return handler


# --- totalCount drives the drain ------------------------------------------------------


@respx.mock
async def test_server_clamping_limit_still_drains_everything(client):
    items = [{"code": f"C{i}"} for i in range(250)]
    route = respx.get(f"{PROXY}/countries").mock(side_effect=_clamped(items, 100))
    result = await list_countries(client, _registry(), "h")
    assert result["data"] == items
    assert result["totalCount"] == 250
    assert route.call_count == 3  # 100 + 100 + 50
    assert "incomplete" not in result


@respx.mock
async def test_server_ignoring_offset_with_total_is_flagged_not_silent(client):
    first = [{"code": f"C{i}"} for i in range(30)]
    respx.get(f"{PROXY}/countries").mock(
        return_value=Response(200, json={"data": first, "totalCount": 90})
    )
    result = await list_countries(client, _registry(), "h")
    assert result["incomplete"] is True
    assert "30 of 90" in result["incompleteReason"]
    assert result["data"] == first


@respx.mock
async def test_empty_page_before_total_is_flagged(client):
    pages = [
        Response(200, json={"data": [{"code": "A"}], "totalCount": 3}),
        Response(200, json={"data": [], "totalCount": 3}),
    ]
    respx.get(f"{PROXY}/countries").mock(side_effect=pages)
    result = await list_countries(client, _registry(), "h")
    assert result["incomplete"] is True
    assert "totalCount 3" in result["incompleteReason"]


@respx.mock
async def test_drain_reports_upstream_total(client):
    respx.get(f"{PROXY}/countries").mock(side_effect=_clamped([{"code": "A"}], 200))
    result = await list_countries(client, _registry(), "h")
    assert result["totalCount"] == 1


# --- manual paging returns the native envelope ----------------------------------------


@respx.mock
async def test_requested_total_returns_records_total_and_effective_size(client):
    page = {"offset": 0, "limit": 2, "count": 2, "totalCount": 9, "data": [{"id": 1}, {"id": 2}]}
    respx.get(f"{PROXY}/sites/{SITE_UUID}/clients").mock(return_value=Response(200, json=page))
    respx.get(f"{PROXY}/sites/{SITE_UUID}/devices").mock(return_value=Response(200, json=page))
    expected = {**page, "_pageSize": {"requested": 2, "sent": [2], "effective": 2, "returned": 2}}
    assert await _list_clients(client, _registry(), "h", "s", offset=0, limit=2) == expected
    assert await _list_site_devices(client, _registry(), "h", "s", offset=0, limit=2) == expected


# --- fan-out never deadlocks on the request semaphore ---------------------------------


@respx.mock
async def test_search_across_many_sites_does_not_deadlock():
    tight = UniFiClient(Settings(api_key="sk-test", max_concurrency=10))
    # 14 distinct console sites (each Site Manager site maps to its own console site by
    # internalReference), so the fan-out is genuinely 14 wide.
    sites = [{"hostId": HOST, "siteId": f"ea-{i}", "meta": {"name": f"s{i}"}} for i in range(14)]
    uuids = [f"aaaaaaaa-0000-4000-8000-{i + 1:012x}" for i in range(14)]
    reg = _registry()
    reg.get_ea_sites = AsyncMock(return_value=sites)
    reg.get_sites = AsyncMock(
        return_value=[
            {"id": u, "name": f"Site {i}", "internalReference": f"s{i}"}
            for i, u in enumerate(uuids)
        ]
    )

    overlapping = asyncio.Event()
    active = peak = 0
    completed: list[str] = []

    async def slow_empty(request: Request) -> Response:
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        if active == 2:
            overlapping.set()
        try:
            await overlapping.wait()
            completed.append(request.url.path)
            return Response(200, json={"data": [], "totalCount": 0})
        finally:
            active -= 1

    for u in uuids:
        respx.get(f"{PROXY}/sites/{u}/devices").mock(side_effect=slow_empty)
        respx.get(f"{PROXY}/sites/{u}/clients").mock(side_effect=slow_empty)
    result = await site_manager.search_across_sites(tight, reg, "x")
    assert result["_sitesSearched"] == 14
    assert 2 <= peak <= 10
    expected = [
        httpx.URL(f"{PROXY}/sites/{site}/{scope}").path
        for site in uuids
        for scope in ("devices", "clients")
    ]
    assert sorted(completed) == sorted(expected)
    assert active == 0
    await tight.close()


async def test_gather_tasks_can_make_requests_at_full_concurrency():
    tight = UniFiClient(Settings(api_key="sk-test", max_concurrency=2))

    overlapping = asyncio.Event()
    active = peak = completed = 0

    async def inner() -> int:
        nonlocal active, peak, completed
        async with tight._semaphore:  # what every HTTP request does
            active += 1
            peak = max(peak, active)
            if active == 2:
                overlapping.set()
            try:
                await overlapping.wait()
                completed += 1
            finally:
                active -= 1
        return 1

    async def outer() -> int:
        return await inner()

    assert await tight.gather([outer() for _ in range(6)]) == [1] * 6
    assert peak == 2
    assert active == 0 and completed == 6
    await tight.close()


# --- multi-key, registry cache, key labels, cursor stall, connect errors --------------


async def test_list_all_clients_raises_when_every_key_fails():
    mk = UniFiClient(
        Settings(
            api_keys=[
                APIKeyConfig(key="sk-a", label="alpha"),
                APIKeyConfig(key="sk-b", label="beta"),
            ]
        )
    )
    reg = _registry()
    reg.get_ea_sites = AsyncMock(side_effect=UniFiConnectionError("HTTP 401 bad key"))
    with pytest.raises(RuntimeError, match="All 2 API keys failed"):
        await aggregation._list_all_clients_fleet(mk, reg)


@respx.mock
async def test_capped_console_site_list_is_not_cached_and_flag_clears(client):
    capped = UniFiClient(Settings(api_key="sk-test", paginate_max_pages=1))
    reg = Registry(capped, ttl_seconds=900)
    url = f"{PROXY}/sites"
    route = respx.get(url).mock(
        return_value=Response(200, json={"data": [{"id": SITE_UUID, "name": "A"}], "totalCount": 5})
    )
    first = await reg.get_sites(HOST)
    assert first == [{"id": SITE_UUID, "name": "A"}]
    second = await reg.get_sites(HOST)
    assert route.call_count == 2  # not cached: fetched again
    # each fetched list carries its own reason, never a registry marker
    assert incomplete_reason(first) and incomplete_reason(second)


def test_unknown_key_label_lists_valid_labels():
    mk = UniFiClient(
        Settings(
            api_keys=[
                APIKeyConfig(key="sk-a", label="alpha"),
                APIKeyConfig(key="sk-b", label="beta"),
            ]
        )
    )
    with pytest.raises(ValueError, match="valid labels: alpha, beta"):
        mk.get_key_by_label("gamma")


@respx.mock
async def test_cursor_stall_does_not_duplicate_the_repeated_page(client):
    from unifi_fabric.client import PaginationAbortedError

    respx.get(f"{BASE}/v1/hosts").mock(
        side_effect=[
            Response(200, json={"data": [{"id": "h1"}], "nextToken": "T"}),
            Response(200, json={"data": [{"id": "h1"}], "nextToken": "T"}),
        ]
    )
    with pytest.raises(PaginationAbortedError) as exc:
        await client.paginate("/v1/hosts")
    assert exc.value.items == [{"id": "h1"}]


@respx.mock
async def test_connect_error_keeps_the_cause(client):
    respx.get(f"{BASE}/v1/hosts").mock(
        side_effect=httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] self-signed")
    )
    with pytest.raises(UniFiConnectionError) as exc:
        await client.get("/v1/hosts")
    msg = str(exc.value)
    assert "Connection failed: GET /v1/hosts" in msg
    assert "ConnectError: [SSL: CERTIFICATE_VERIFY_FAILED] self-signed" in msg
