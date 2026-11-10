"""A drain keeps distinct records that share a ``mac``; a truly repeated page still stops.

Event, log, session and history rows carry the device's ``mac`` on every record, so a
``mac`` is not a record identity. Synthetic upstreams only.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import PaginationAbortedError, UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.families.network.network_controller_insights import get_sites_overview
from unifi_fabric.families.statistics.system_log import _read_system_log
from unifi_fabric.families.vpn.network_vpn_dns import query_teleport_invitations
from unifi_fabric.shared_shapes._pagination import collect_batch, collect_offset

MAC = "aa:bb:cc:00:11:22"


def _rows(n: int, *, key: str = "n", **extra: Any) -> list[dict[str, Any]]:
    return [{"mac": MAC, key: i, **extra} for i in range(n)]


def _client() -> UniFiClient:
    return UniFiClient(Settings(api_key="synthetic-shared-mac"))


def _registry() -> AsyncMock:
    reg = AsyncMock()
    reg.resolve_key_for_host = AsyncMock(return_value=None)
    reg.resolve_host_id = AsyncMock(return_value="HOST:1")
    reg.resolve_site_slug = AsyncMock(return_value="default")
    return reg


def _offset_get(rows: list[dict[str, Any]], *, envelope: bool):
    async def get(path, *, key=None, params=None, **_):
        offset = int((params or {}).get("offset", 0))
        limit = int((params or {}).get("limit", 25))
        page = rows[offset : offset + limit]
        return {"data": page} if envelope else page

    return get


@pytest.mark.parametrize("envelope", [True, False])
async def test_paginate_offset_keeps_rows_sharing_a_mac(envelope):
    rows = _rows(250)
    client = _client()
    client.get = _offset_get(rows, envelope=envelope)
    got = await client.paginate_offset("/events", page_size=100)
    assert list(got) == rows


@pytest.mark.parametrize("envelope", [True, False])
async def test_collect_offset_default_drain_keeps_rows_sharing_a_mac(envelope):
    rows = _rows(250)
    client = SimpleNamespaceGet(_offset_get(rows, envelope=envelope))
    result = await collect_offset(client, "/events")
    assert result["items"] == rows
    assert result["incomplete"] is False


@pytest.mark.parametrize("envelope", [True, False])
async def test_collect_offset_limit_gathers_requested_total_across_shared_mac(envelope):
    rows = _rows(250)
    client = SimpleNamespaceGet(_offset_get(rows, envelope=envelope))
    result = await collect_offset(client, "/events", limit=230)
    assert result["items"] == rows[:230]


class SimpleNamespaceGet:
    """A get-only adapter: the drain falls back to collect_batch."""

    paginate_max_pages = None

    def __init__(self, get):
        self.get = get


async def test_collect_batch_number_family_keeps_rows_sharing_a_mac():
    rows = _rows(250)

    async def fetch(paging):
        size = paging.get("pageSize", 100)
        number = paging.get("pageNumber", 0)
        return {"data": rows[number * size : (number + 1) * size]}

    result = await collect_batch(fetch, requested=None, family="number", default_size=100)
    assert result["items"] == rows
    assert not result.get("incomplete")


def _number_post(rows):
    async def post(path, *, key=None, json=None, **_):
        size = (json or {}).get("pageSize", 100)
        number = (json or {}).get("pageNumber", 0)
        return {
            "data": rows[number * size : (number + 1) * size],
            "page_number": number,
            "total_page_count": -(-len(rows) // size),
            "total_element_count": len(rows),
        }

    return post


async def test_get_system_log_drain_keeps_log_rows_sharing_a_mac():
    rows = _rows(250, key="seq")
    client = _client()
    client.post = _number_post(rows)
    result = await _read_system_log(client, _registry(), "h", "s", "device-alert", None)
    assert result["data"] == rows
    assert not result.get("incomplete")


async def test_get_system_log_window_keeps_log_rows_sharing_a_mac():
    rows = _rows(250, key="seq")
    client = _client()
    client.post = _number_post(rows)
    result = await _read_system_log(
        client, _registry(), "h", "s", "device-alert", None, page_size=230
    )
    assert result["data"] == rows[:230]


async def test_get_sites_overview_drain_keeps_rows_sharing_a_mac():
    rows = _rows(250)
    client = _client()
    client.post = _number_post(rows)
    result = await get_sites_overview(client, _registry(), "h")
    assert result["data"] == rows


async def test_teleport_invitation_history_drain_keeps_rows_sharing_a_mac():
    rows = _rows(250)
    client = _client()
    client.post = _number_post(rows)
    result = await query_teleport_invitations(client, _registry(), "h", "s")
    assert result["data"] == rows


# --- loop protection stays -------------------------------------------------------------


async def test_a_truly_repeated_page_of_shared_mac_rows_still_stops():
    rows = _rows(100)
    client = _client()

    async def get(path, *, key=None, params=None, **_):
        return {"data": rows}  # ignores offset: the same page forever

    client.get = get
    with pytest.raises(PaginationAbortedError) as error:
        await client.paginate_offset("/events", page_size=100)
    assert error.value.items == rows
    assert "same page again" in str(error.value)


async def test_a_repeated_page_of_identified_rows_still_stops_when_live_fields_change():
    client = _client()
    calls = 0

    async def get(path, *, key=None, params=None, **_):
        nonlocal calls
        calls += 1
        assert calls < 5
        return {"data": [{"id": i, "mac": MAC, "uptime": calls} for i in range(100)]}

    client.get = get
    with pytest.raises(PaginationAbortedError) as error:
        await client.paginate_offset("/events", page_size=100)
    assert len(error.value.items) == 100
