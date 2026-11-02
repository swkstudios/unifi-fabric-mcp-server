"""Every list path drains all pages by default; nothing is cut at the API's default page.

The Network Integration API pages at 25 items by default (verified live: a console with
46 clients returned 25 with ``totalCount: 46``; ``/v1/countries`` returned 25 of 248).
These tests drive the REAL client over respx with servers that page, so a single-GET
regression shows up as a short result.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest
import respx
from httpx import Request, Response

from unifi_fabric.client import UniFiClient, UniFiConnectionError
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.registry import Registry
from unifi_fabric.tools import aggregation, carrier_fabric, device_mgmt, mobility, site_manager
from unifi_fabric.tools.innerspace import list_innerspace_floor_plans
from unifi_fabric.tools.network_services_proxy import list_countries
from unifi_fabric.tools.protect import collect_protect_events

BASE = "https://api.ui.com"
HOST = "AABBCCDDEEFF0000:1"
SITE_UUID = "aaaaaaaa-0000-4000-8000-000000000001"
SITE2_UUID = "bbbbbbbb-0000-4000-8000-000000000002"
PROXY = f"{BASE}/v1/connector/consoles/{HOST}/proxy/network/integration/v1"


def _offset_pager(items: list[Any], *, total: bool = True):
    """respx side effect serving ``items`` honouring offset/limit (default limit 25)."""

    def handler(request: Request) -> Response:
        offset = int(request.url.params.get("offset", 0))
        limit = int(request.url.params.get("limit", 25))
        page = items[offset : offset + limit]
        body: dict[str, Any] = {"offset": offset, "limit": limit, "count": len(page), "data": page}
        if total:
            body["totalCount"] = len(items)
        return Response(200, json=body)

    return handler


@pytest.fixture
def client() -> UniFiClient:
    return UniFiClient(Settings(api_key="sk-test"))


def _registry() -> AsyncMock:
    reg = AsyncMock()
    reg.resolve_key_for_host = AsyncMock(return_value=None)
    reg.resolve_host_id = AsyncMock(return_value=HOST)
    reg.resolve_site_id = AsyncMock(return_value=SITE_UUID)
    reg.get_sites = AsyncMock(
        return_value=[{"id": SITE_UUID, "name": "Default", "internalReference": "default"}]
    )
    reg.get_hosts = AsyncMock(
        return_value=[{"id": HOST, "reportedState": {"hostname": "gw-main", "name": "Main"}}]
    )
    return reg


# --- core drainer guards --------------------------------------------------------------


@respx.mock
async def test_list_countries_drains_all_248(client):
    countries = [{"code": f"C{i:03d}"} for i in range(248)]
    route = respx.get(f"{PROXY}/countries").mock(side_effect=_offset_pager(countries))
    result = await list_countries(client, _registry(), "h")
    assert result["totalCount"] == 248
    assert result["data"] == countries
    assert route.call_count == 2  # 200 + 48


@respx.mock
async def test_server_ignoring_offset_stops_and_is_flagged(client):
    same = [{"code": f"C{i}"} for i in range(200)]
    respx.get(f"{PROXY}/countries").mock(return_value=Response(200, json={"data": same}))
    result = await list_countries(client, _registry(), "h")
    assert result["incomplete"] is True
    assert "same page again" in result["incompleteReason"]
    assert result["data"] == same


@respx.mock
async def test_server_ignoring_limit_and_offset_returns_everything_once(client):
    everything = [{"code": f"C{i}"} for i in range(300)]
    route = respx.get(f"{PROXY}/countries").mock(
        return_value=Response(200, json={"data": everything})
    )
    result = await list_countries(client, _registry(), "h")
    assert result["data"] == everything
    assert route.call_count == 2
    assert result.get("incomplete", False) is False


# --- per-site fan-out tools -----------------------------------------------------------


_EA_SITE = {"hostId": HOST, "siteId": "ea-1", "meta": {"name": "default", "desc": "Default"}}


@respx.mock
async def test_get_site_inventory_drains_devices_and_clients(client):
    clients = [{"mac": f"0a:00:00:00:{i // 256:02x}:{i % 256:02x}"} for i in range(250)]
    devices = [{"id": f"d{i}"} for i in range(30)]
    respx.get(f"{PROXY}/sites/{SITE_UUID}/clients").mock(side_effect=_offset_pager(clients))
    respx.get(f"{PROXY}/sites/{SITE_UUID}/devices").mock(side_effect=_offset_pager(devices))
    reg = _registry()
    reg.get_ea_sites = AsyncMock(return_value=[_EA_SITE])
    result = await site_manager.get_site_inventory(client, reg, "Default")
    assert result["_clientCount"] == 250
    assert result["_deviceCount"] == 30
    assert "incomplete" not in result


@respx.mock
async def test_search_across_sites_finds_a_client_beyond_the_first_page(client):
    clients = [{"name": f"c{i}", "mac": "", "ip": "", "hostname": ""} for i in range(240)]
    clients[230]["hostname"] = "needle-laptop"
    respx.get(f"{PROXY}/sites/{SITE_UUID}/clients").mock(side_effect=_offset_pager(clients))
    respx.get(f"{PROXY}/sites/{SITE_UUID}/devices").mock(side_effect=_offset_pager([]))
    reg = _registry()
    reg.get_ea_sites = AsyncMock(return_value=[_EA_SITE])
    result = await site_manager.search_across_sites(client, reg, "needle")
    assert result["_count"] == 1
    assert result["data"][0]["hostname"] == "needle-laptop"


@respx.mock
async def test_list_all_clients_drains_and_names_the_console(client):
    clients = [{"id": f"c{i}"} for i in range(210)]
    respx.get(f"{PROXY}/sites/{SITE_UUID}/clients").mock(side_effect=_offset_pager(clients))
    reg = _registry()
    reg.get_ea_sites = AsyncMock(return_value=[_EA_SITE])
    result = await aggregation._list_all_clients_fleet(client, reg)
    assert result["_count"] == 210
    assert result["data"][0]["_hostName"] == "gw-main"  # real console name, not the id


@respx.mock
async def test_mac_resolution_finds_device_on_page_two(client):
    device_mgmt._mac_uuid_cache.clear()
    devices = [{"id": f"id-{i}", "macAddress": f"0a:00:00:00:00:{i % 256:02x}"} for i in range(220)]
    devices[210]["macAddress"] = "de:ad:be:ef:00:01"
    respx.get(f"{PROXY}/sites/{SITE_UUID}/devices").mock(side_effect=_offset_pager(devices))
    uuid = await device_mgmt._resolve_device_id(client, HOST, SITE_UUID, "DEADBEEF0001", key=None)
    assert uuid == "id-210"


# --- Site Manager: siteId remedy path, cache rules ------------------------------------


async def test_ambiguous_site_name_then_site_id_works_end_to_end(client):
    reg = _registry()
    reg.get_ea_sites = AsyncMock(
        return_value=[
            {"hostId": HOST, "siteId": "ea-1", "meta": {"name": "default", "desc": "Default"}},
            {"hostId": HOST, "siteId": "ea-2", "meta": {"name": "branch", "desc": "Default"}},
        ]
    )
    reg.get_sites = AsyncMock(
        return_value=[
            {"id": SITE_UUID, "name": "Default", "internalReference": "default"},
            {"id": SITE2_UUID, "name": "Default", "internalReference": "branch"},
        ]
    )
    with pytest.raises(ValueError, match="Pass the siteId instead"):
        await site_manager.get_site_inventory(client, reg, "Default")
    with respx.mock:
        respx.get(f"{PROXY}/sites/{SITE2_UUID}/devices").mock(side_effect=_offset_pager([]))
        respx.get(f"{PROXY}/sites/{SITE2_UUID}/clients").mock(side_effect=_offset_pager([]))
        result = await site_manager.get_site_inventory(client, reg, "ea-2")
    assert result["_siteId"] == SITE2_UUID
    with respx.mock:
        health = respx.get(
            f"{BASE}/v1/connector/consoles/{HOST}/proxy/network/api/s/branch/stat/health"
        ).mock(return_value=Response(200, json={"data": []}))
        await site_manager.get_site_health_summary(client, reg, "ea-2")
        assert health.called


@respx.mock
async def test_capped_site_manager_drains_are_flagged_and_not_cached():
    capped = UniFiClient(Settings(api_key="sk-test", paginate_max_pages=1))
    reg = Registry(capped, ttl_seconds=900)
    respx.get(f"{BASE}/v1/sites").mock(
        return_value=Response(200, json={"data": [{"siteId": "s1"}], "nextToken": "t2"})
    )
    respx.get(f"{BASE}/v1/hosts").mock(
        return_value=Response(200, json={"data": [{"id": "h1"}], "nextToken": "t2"})
    )
    agg = await site_manager.list_all_sites_aggregated(capped, reg)
    assert agg["incomplete"] is True and agg["_count"] == 1
    hosts = await site_manager.list_hosts(capped, reg)
    assert hosts["incomplete"] is True
    assert reg._ea_sites == {} and reg._hosts == {}  # partial lists never cached


# --- multi-key coverage ---------------------------------------------------------------


def _multikey() -> UniFiClient:
    return UniFiClient(
        Settings(
            api_keys=[
                APIKeyConfig(key="sk-a", label="alpha"),
                APIKeyConfig(key="sk-b", label="beta"),
            ]
        )
    )


def _devices_by_key(request: Request) -> Response:
    if request.headers.get("X-API-KEY") == "sk-b":
        return Response(500, json={"error": "beta down"})
    return Response(
        200,
        json={"data": [{"hostId": "ha", "hostName": "gw-a", "devices": [{"id": "d1"}]}]},
    )


@respx.mock
async def test_multikey_fleet_tools_cover_every_key_and_report_failures():
    mk = _multikey()
    respx.get(f"{BASE}/v1/devices").mock(side_effect=_devices_by_key)
    devices = await aggregation._list_all_devices_fleet(mk)
    assert devices["_count"] == 1
    assert devices["data"][0]["_keyLabel"] == "alpha"
    # _key_labels: the keys whose results are included; the failed key is under errors.
    assert devices["_key_labels"] == ["alpha"]
    assert devices["errors"] and devices["errors"][0].startswith("beta:")
    search = await aggregation._search_device(mk, "d1")
    assert search["_count"] == 0 or search["matches"][0]["_keyLabel"] == "alpha"
    assert search["errors"]


@respx.mock
async def test_multikey_list_devices_aggregates_keys():
    mk = _multikey()
    respx.get(f"{BASE}/v1/devices").mock(side_effect=_devices_by_key)
    result = await site_manager.list_devices(mk, Registry(mk, ttl_seconds=900))
    assert result["_count"] == 1 and result["_consoleCount"] == 1
    assert result["data"][0]["_keyLabel"] == "alpha"
    assert result["errors"]


@respx.mock
async def test_list_devices_counts_devices_and_filters_by_host(client):
    route = respx.get(f"{BASE}/v1/devices").mock(
        return_value=Response(
            200,
            json={"data": [{"hostId": HOST, "devices": [{"id": "d1"}, {"id": "d2"}]}]},
        )
    )
    reg = _registry()
    result = await site_manager.list_devices(client, reg, host="gw-main")
    assert result["_count"] == 2
    assert result["_consoleCount"] == 1
    assert route.calls[0].request.url.params.get_list("hostIds[]") == [HOST]


async def test_multikey_search_reports_a_failing_key_and_searches_the_rest():
    mk = _multikey()
    reg = Registry(mk, ttl_seconds=900)

    async def ea_sites(*, key=None):
        site = {"hostId": HOST, "siteId": f"ea-{key.label}", "meta": {"name": "default"}}
        return [site]

    async def get_sites(host_id, *, key=None):
        if key is not None and key.label == "alpha":
            raise UniFiConnectionError("HTTP 403 alpha cannot reach console")
        return [{"id": SITE_UUID, "name": "Default", "internalReference": "default"}]

    reg.get_ea_sites = AsyncMock(side_effect=ea_sites)
    reg.get_sites = AsyncMock(side_effect=get_sites)
    with respx.mock:
        respx.get(f"{PROXY}/sites/{SITE_UUID}/devices").mock(side_effect=_offset_pager([]))
        respx.get(f"{PROXY}/sites/{SITE_UUID}/clients").mock(side_effect=_offset_pager([]))
        result = await site_manager.search_across_sites(mk, reg, "x")
    assert result["_sitesTotal"] == 2
    assert result["_sitesSearched"] == 1
    assert "alpha cannot reach console" in result["_skipped"][0]["reason"]


# --- other families -------------------------------------------------------------------


@respx.mock
async def test_mobility_capped_drain_keeps_pages_and_flags():
    capped = UniFiClient(Settings(api_key="sk-test", paginate_max_pages=1))
    respx.get(f"{BASE}/v1/mobility/workspaces/ws-1/devices").mock(
        return_value=Response(200, json={"data": [{"id": f"m{i}"} for i in range(200)]})
    )
    result = await mobility.list_mobility_devices(capped, "ws-1")
    assert result["incomplete"] is True and result["_count"] == 200


@respx.mock
async def test_unexpected_shapes_raise_with_the_shape(client):
    respx.get(f"{BASE}/v1/mobility/workspaces").mock(return_value=Response(200, json={"items": []}))
    with pytest.raises(UniFiConnectionError, match=r"object with keys \['items'\]"):
        await mobility.list_mobility_workspaces(client)
    respx.get(f"{BASE}/v1/carrier/service-plans").mock(
        return_value=Response(200, json={"plans": []})
    )
    with pytest.raises(UniFiConnectionError, match=r"keys \['plans'\]"):
        await carrier_fabric.list_carrier_service_plans(client)
    respx.get(
        f"{BASE}/v1/connector/consoles/{HOST}/proxy/innerspace/integration/v1/floor_plans"
    ).mock(return_value=Response(200, json={"unexpected": 1}))
    with pytest.raises(UniFiConnectionError, match="'floor_plans' array"):
        await list_innerspace_floor_plans(client, _registry(), "h")


@respx.mock
async def test_collect_protect_events_drains_each_poll(client, monkeypatch):
    from unifi_fabric.tools import protect

    monkeypatch.setattr(protect, "_sleep", AsyncMock())
    events = [{"id": f"e{i}"} for i in range(260)]

    def bare_pager(request: Request) -> Response:
        offset = int(request.url.params.get("offset", 0))
        limit = int(request.url.params.get("limit", 25))
        return Response(200, json=events[offset : offset + limit])

    respx.get(f"{BASE}/v1/connector/consoles/{HOST}/proxy/protect/api/events").mock(
        side_effect=bare_pager
    )
    result = await collect_protect_events(client, _registry(), "h", poll_count=2)
    assert len(result["result"]) == 260
    assert "incomplete" not in result
