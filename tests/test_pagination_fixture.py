"""Fixture-driven pagination: exercise UniFiClient.paginate() past page one.

The committed fixtures used to be single-page (``proxy_sites_response.json``: two sites,
no ``nextToken``), so no fixture ever drove ``paginate()`` across a page boundary — at
200+ sites, silent truncation looks identical to success. These tests use a realistic
TWO-PAGE proxy-sites shape (``proxy_sites_page1.json`` carries a ``nextToken``;
``proxy_sites_page2.json`` terminates it) to cover:

* continuation-token handling (page 2 must be fetched with page 1's ``nextToken``),
* full aggregation across the boundary (no truncation),
* page-cap enforcement, and
* ``PaginationAbortedError`` stall detection.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import respx
from httpx import Response

from unifi_fabric.client import PaginationAbortedError, UniFiClient
from unifi_fabric.config import Settings

BASE = "https://api.ui.com"
_FIXTURES = Path(__file__).parent / "fixtures"

# A per-console proxy /sites endpoint — the realistic paginated shape.
_PROXY_SITES_PATH = "/v1/connector/consoles/console-1/proxy/network/integration/v1/sites"


def _load(name: str) -> dict:
    return json.loads((_FIXTURES / name).read_text())


@pytest.fixture
def client():
    return UniFiClient(Settings(api_key="sk-test"))


class TestFixtureDrivenPagination:
    @respx.mock
    @pytest.mark.asyncio
    async def test_crosses_page_boundary_and_aggregates_all_sites(self, client):
        page1 = _load("proxy_sites_page1.json")
        page2 = _load("proxy_sites_page2.json")
        route = respx.get(f"{BASE}{_PROXY_SITES_PATH}")
        route.side_effect = [Response(200, json=page1), Response(200, json=page2)]

        items = await client.paginate(_PROXY_SITES_PATH)

        # All four sites returned across both pages — nothing truncated at the boundary.
        assert route.call_count == 2
        assert len(items) == 4
        assert [i["description"] for i in items] == [
            "Default",
            "Branch Office",
            "Warehouse",
            "Remote Site",
        ]

    @respx.mock
    @pytest.mark.asyncio
    async def test_second_page_request_carries_continuation_token(self, client):
        page1 = _load("proxy_sites_page1.json")
        page2 = _load("proxy_sites_page2.json")
        route = respx.get(f"{BASE}{_PROXY_SITES_PATH}")
        route.side_effect = [Response(200, json=page1), Response(200, json=page2)]

        await client.paginate(_PROXY_SITES_PATH)

        # The cursor from page 1 must be sent as nextToken on the page-2 request.
        assert "nextToken" not in route.calls[0].request.url.params
        assert route.calls[1].request.url.params["nextToken"] == page1["nextToken"]

    @respx.mock
    @pytest.mark.asyncio
    async def test_page_cap_enforced_on_paginated_shape(self):
        capped = UniFiClient(Settings(api_key="sk-test", paginate_max_pages=1))
        page1 = _load("proxy_sites_page1.json")  # carries a nextToken → would fetch page 2
        respx.get(f"{BASE}{_PROXY_SITES_PATH}").mock(return_value=Response(200, json=page1))

        with pytest.raises(PaginationAbortedError, match="page cap of 1"):
            await capped.paginate(_PROXY_SITES_PATH)

    @respx.mock
    @pytest.mark.asyncio
    async def test_stall_detection_on_repeated_token(self, client):
        # Page 1 returned twice: the same nextToken repeats → stall, not silent loop.
        page1 = _load("proxy_sites_page1.json")
        respx.get(f"{BASE}{_PROXY_SITES_PATH}").mock(return_value=Response(200, json=page1))

        with pytest.raises(PaginationAbortedError, match="stall detected"):
            await client.paginate(_PROXY_SITES_PATH)

    @respx.mock
    @pytest.mark.asyncio
    async def test_abort_carries_pages_gathered_before_cap(self):
        # The cap abort must expose the pages already fetched so a caller can
        # return a partial-but-explicitly-incomplete result instead of nothing.
        capped = UniFiClient(Settings(api_key="sk-test", paginate_max_pages=1))
        page1 = _load("proxy_sites_page1.json")
        respx.get(f"{BASE}{_PROXY_SITES_PATH}").mock(return_value=Response(200, json=page1))

        with pytest.raises(PaginationAbortedError) as excinfo:
            await capped.paginate(_PROXY_SITES_PATH)

        # Two records were on page 1 — they are preserved on the exception.
        assert len(excinfo.value.items) == 2
        assert [i["description"] for i in excinfo.value.items] == ["Default", "Branch Office"]


# The offset/limit/totalCount family — the Network Integration proxy shape.
_PROXY_CLIENTS_PATH = (
    "/v1/connector/consoles/console-1/proxy/network/integration/v1/sites/s1/clients"
)


class TestOffsetDrivenPagination:
    @respx.mock
    @pytest.mark.asyncio
    async def test_crosses_offset_boundary_and_aggregates_all(self, client):
        page1 = _load("proxy_clients_page1.json")  # totalCount 4, 2 records
        page2 = _load("proxy_clients_page2.json")  # remaining 2 records
        route = respx.get(f"{BASE}{_PROXY_CLIENTS_PATH}")
        route.side_effect = [Response(200, json=page1), Response(200, json=page2)]

        items = await client.paginate_offset(_PROXY_CLIENTS_PATH, page_size=2)

        assert route.call_count == 2
        assert len(items) == 4
        assert [i["id"] for i in items] == [
            "client-0001",
            "client-0002",
            "client-0003",
            "client-0004",
        ]

    @respx.mock
    @pytest.mark.asyncio
    async def test_second_page_request_advances_offset(self, client):
        page1 = _load("proxy_clients_page1.json")
        page2 = _load("proxy_clients_page2.json")
        route = respx.get(f"{BASE}{_PROXY_CLIENTS_PATH}")
        route.side_effect = [Response(200, json=page1), Response(200, json=page2)]

        await client.paginate_offset(_PROXY_CLIENTS_PATH, page_size=2)

        assert route.calls[0].request.url.params["offset"] == "0"
        assert route.calls[1].request.url.params["offset"] == "2"

    @respx.mock
    @pytest.mark.asyncio
    async def test_short_page_terminates_without_extra_request(self, client):
        # A page shorter than the limit is unambiguously the last page.
        page1 = _load("proxy_clients_page1.json")
        route = respx.get(f"{BASE}{_PROXY_CLIENTS_PATH}").mock(
            return_value=Response(200, json=page1)
        )

        items = await client.paginate_offset(_PROXY_CLIENTS_PATH, page_size=50)

        assert route.call_count == 1
        assert len(items) == 2

    @respx.mock
    @pytest.mark.asyncio
    async def test_bare_list_response_is_drained(self, client):
        # Some private endpoints return a top-level JSON array (no totalCount).
        route = respx.get(f"{BASE}{_PROXY_CLIENTS_PATH}")
        route.side_effect = [
            Response(200, json=[{"id": "a"}, {"id": "b"}]),
            Response(200, json=[{"id": "c"}]),
        ]

        items = await client.paginate_offset(_PROXY_CLIENTS_PATH, page_size=2)

        assert route.call_count == 2
        assert [i["id"] for i in items] == ["a", "b", "c"]

    @respx.mock
    @pytest.mark.asyncio
    async def test_offset_page_cap_aborts_with_partial_items(self):
        capped = UniFiClient(Settings(api_key="sk-test", paginate_max_pages=1))
        page1 = _load("proxy_clients_page1.json")  # full page (== limit), totalCount 4
        respx.get(f"{BASE}{_PROXY_CLIENTS_PATH}").mock(return_value=Response(200, json=page1))

        with pytest.raises(PaginationAbortedError, match="page cap of 1") as excinfo:
            await capped.paginate_offset(_PROXY_CLIENTS_PATH, page_size=2)

        assert len(excinfo.value.items) == 2
