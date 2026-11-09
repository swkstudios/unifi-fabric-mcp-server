"""Offset tools gather a requested total, or fetch a native page at an offset.

A limit alone gathers the requested total; an offset alone selects one native page.
With both, Integration fetches one page and Mobility gathers the requested window.
Omitting both drains the collection.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest
import respx
from httpx import Request, Response

from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.tools import mobility, network
from unifi_fabric.tools.clients import _list_clients

BASE = "https://api.ui.com"
HOST = "AABBCCDDEEFF0000:1"
SITE = "aaaaaaaa-0000-4000-8000-000000000001"
WID = "bbbbbbbb-0000-4000-8000-000000000002"
PROXY = f"{BASE}/v1/connector/consoles/{HOST}/proxy/network/integration/v1"
ITEMS = [{"id": f"r{i}"} for i in range(450)]  # more than two 200-row drain pages
NATIVE_PAGE = 25  # what the upstream serves when no limit is sent


def _registry() -> AsyncMock:
    reg = AsyncMock()
    reg.resolve_key_for_host = AsyncMock(return_value=None)
    reg.resolve_host_id = AsyncMock(return_value=HOST)
    reg.resolve_site_id = AsyncMock(return_value=SITE)
    return reg


def _paged(total_key: str, seen: list[dict[str, str]], total: int = len(ITEMS)):
    def handler(request: Request) -> Response:
        params = dict(request.url.params)
        seen.append(params)
        offset = int(params.get("offset", 0))
        limit = int(params.get("limit", NATIVE_PAGE))
        page = ITEMS[offset : min(offset + limit, total)]
        return Response(
            200, json={"offset": offset, "limit": limit, "data": page, total_key: total}
        )

    return handler


async def _clients(c: UniFiClient, **kw: Any) -> Any:
    return await _list_clients(c, _registry(), "h", "s", **kw)


async def _networks(c: UniFiClient, **kw: Any) -> Any:
    return await network.list_networks(c, _registry(), "h", "s", **kw)


async def _wifi(c: UniFiClient, **kw: Any) -> Any:
    return await network.list_wifi_broadcasts(c, _registry(), "h", "s", **kw)


async def _mobility(c: UniFiClient, **kw: Any) -> Any:
    return await mobility.list_mobility_devices(c, WID, **kw)


TOOLS = {
    "list_clients": (_clients, f"{PROXY}/sites/{SITE}/clients", "totalCount"),
    "list_networks": (_networks, f"{PROXY}/sites/{SITE}/networks", "totalCount"),
    "list_wifi_broadcasts": (_wifi, f"{PROXY}/sites/{SITE}/wifi/broadcasts", "totalCount"),
    "list_mobility_devices": (
        _mobility,
        f"{BASE}{mobility.MOBILITY_BASE}/workspaces/{WID}/devices",
        "total",
    ),
}


@pytest.mark.parametrize("tool", sorted(TOOLS))
@respx.mock
async def test_limit_alone_gathers_total_and_probes_continuation(tool):
    call, url, total_key = TOOLS[tool]
    seen: list[dict[str, str]] = []
    respx.get(url).mock(side_effect=_paged(total_key, seen))
    result = await call(UniFiClient(Settings(api_key="sk-test")), limit=5)
    assert seen == [{"limit": "5"}, {"offset": "5", "limit": "1"}]
    assert result == {
        "offset": 0,
        "limit": 5,
        total_key: len(ITEMS),
        "data": ITEMS[:5],
        "_pageSize": {"requested": 5, "sent": [5, 1], "effective": 5, "returned": 5},
        "_nextOffset": 5,
        **({"_count": 5} if tool == "list_mobility_devices" else {}),
    }


@pytest.mark.parametrize("tool", sorted(TOOLS))
@respx.mock
async def test_limit_alone_terminal_total_needs_no_probe(tool):
    call, url, total_key = TOOLS[tool]
    seen: list[dict[str, str]] = []
    respx.get(url).mock(side_effect=_paged(total_key, seen, total=5))
    result = await call(UniFiClient(Settings(api_key="sk-test")), limit=5)
    assert seen == [{"limit": "5"}]
    assert result["data"] == ITEMS[:5]
    assert result[total_key] == 5
    assert result["_pageSize"] == {"requested": 5, "sent": [5], "effective": 5, "returned": 5}
    assert "_nextOffset" not in result
    assert "incomplete" not in result


@pytest.mark.parametrize("tool", sorted(set(TOOLS) - {"list_mobility_devices"}))
@pytest.mark.parametrize("offset", [0, 10])
@respx.mock
async def test_explicit_offset_and_limit_return_one_native_page(tool, offset):
    call, url, total_key = TOOLS[tool]
    seen: list[dict[str, str]] = []
    respx.get(url).mock(side_effect=_paged(total_key, seen))
    result = await call(UniFiClient(Settings(api_key="sk-test")), offset=offset, limit=5)
    assert seen == [{"offset": str(offset), "limit": "5"}]
    expected = {
        "offset": offset,
        "limit": 5,
        "data": ITEMS[offset : offset + 5],
        total_key: len(ITEMS),
    }
    expected["_pageSize"] = {"requested": 5, "sent": [5], "effective": 5, "returned": 5}
    assert result == expected


@pytest.mark.parametrize("offset", [0, 10])
@pytest.mark.parametrize("bare", [False, True])
@respx.mock
async def test_mobility_offset_and_limit_gather_window(offset, bare):
    call, url, total_key = TOOLS["list_mobility_devices"]
    seen: list[dict[str, str]] = []

    def handler(request: Request) -> Response:
        params = dict(request.url.params)
        seen.append(params)
        position = int(params.get("offset", 0))
        limit = int(params["limit"])
        rows = ITEMS[position : position + limit]
        body = (
            rows
            if bare
            else {"offset": position, "limit": limit, "data": rows, total_key: len(ITEMS)}
        )
        return Response(200, json=body)

    respx.get(url).mock(side_effect=handler)
    result = await call(UniFiClient(Settings(api_key="sk-test")), offset=offset, limit=5)
    first = {"limit": "5"} if offset == 0 else {"offset": str(offset), "limit": "5"}
    assert seen == [first, {"offset": str(offset + 5), "limit": "1"}]
    assert result["data"] == ITEMS[offset : offset + 5]
    assert result["_pageSize"] == {"requested": 5, "sent": [5, 1], "effective": 5, "returned": 5}
    assert result["_nextOffset"] == offset + 5
    if not bare:
        assert result[total_key] == len(ITEMS)
        assert result["offset"] == offset
        assert result["limit"] == 5
    assert "incomplete" not in result


@pytest.mark.parametrize("tool", sorted(TOOLS))
@respx.mock
async def test_offset_alone_is_one_native_page(tool):
    call, url, total_key = TOOLS[tool]
    seen: list[dict[str, str]] = []
    respx.get(url).mock(side_effect=_paged(total_key, seen))
    result = await call(UniFiClient(Settings(api_key="sk-test")), offset=10)
    assert seen == [{"offset": "10"}]  # no limit sent: the upstream's own page size
    assert result["data"] == ITEMS[10 : 10 + NATIVE_PAGE]


@pytest.mark.parametrize("tool", sorted(TOOLS))
@respx.mock
async def test_neither_drains_every_page(tool):
    call, url, total_key = TOOLS[tool]
    seen: list[dict[str, str]] = []
    respx.get(url).mock(side_effect=_paged(total_key, seen))
    result = await call(UniFiClient(Settings(api_key="sk-test")))
    assert len(seen) > 1
    assert result["data"] == ITEMS
    assert "incomplete" not in result
