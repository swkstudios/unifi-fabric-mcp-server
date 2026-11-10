"""Single-object pass-through, complete error reasons, and multi-key
console de-duplication for the fleet tools."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest
import respx
from httpx import Response

from tests import test_cross_tool_invariants as cti
from tests import upstream_harness as uh
from unifi_fabric.client import UniFiClient, UniFiConnectionError
from unifi_fabric.config import Settings
from unifi_fabric.families.carrier import carrier_fabric
from unifi_fabric.families.mobility import mobility
from unifi_fabric.families.site_manager import aggregation, site_manager
from unifi_fabric.registry import Registry

BASE = "https://api.ui.com"
_UUID = "3fa85f64-5717-4562-b3fc-2c963f66afa6"


@pytest.fixture
def client() -> UniFiClient:
    return UniFiClient(Settings(api_key="test-key"))


@pytest.fixture
def registry(client: UniFiClient) -> Registry:
    return Registry(client, ttl_seconds=900)


# --- single-object reads return the upstream object verbatim ---------------------


@respx.mock
async def test_get_host_returns_the_envelope_verbatim(client, registry):
    body = {
        "data": {"id": "h1", "reportedState": {"latitude": 1.5}},
        "httpStatusCode": 200,
        "traceId": "trace-host",
    }
    registry.resolve_host_id = AsyncMock(return_value="h1")
    respx.get(f"{BASE}/v1/hosts/h1").mock(return_value=Response(200, json=body))
    assert await site_manager.get_host(client, registry, "h1") == body


@respx.mock
@pytest.mark.parametrize(
    ("fn", "path"),
    [
        (site_manager.get_sdwan_config, f"/v1/sd-wan-configs/{_UUID}"),
        (site_manager.get_sdwan_config_status, f"/v1/sd-wan-configs/{_UUID}/status"),
    ],
)
async def test_sdwan_reads_return_the_envelope_verbatim(client, fn, path):
    body = {"data": {"id": _UUID, "status": "ok"}, "httpStatusCode": 200, "traceId": "t-1"}
    respx.get(f"{BASE}{path}").mock(return_value=Response(200, json=body))
    assert await fn(client, _UUID) == body


@pytest.mark.parametrize(
    "fn", [carrier_fabric.get_carrier_subscriber, carrier_fabric.get_carrier_service_plan]
)
async def test_carrier_reads_return_the_envelope_verbatim(client, fn):
    body = {"data": {"id": _UUID, "name": "x"}, "httpStatusCode": 200, "traceId": "t-2"}
    client.get = AsyncMock(return_value=body)
    assert await fn(client, _UUID) == body


async def test_carrier_read_still_rejects_a_non_object_data(client):
    client.get = AsyncMock(return_value={"data": [1, 2]})
    with pytest.raises(UniFiConnectionError, match="expected 'data' to be an object"):
        await carrier_fabric.get_carrier_subscriber(client, _UUID)


async def test_get_mobility_device_returns_the_envelope_verbatim(client):
    body = {"data": {"id": _UUID, "name": "umr"}, "traceId": "t-3"}
    client.get = AsyncMock(return_value=body)
    assert await mobility.get_mobility_device(client, _UUID, _UUID) == body


async def test_get_mobility_device_still_rejects_a_non_object_data(client):
    client.get = AsyncMock(return_value={"data": "nope"})
    with pytest.raises(UniFiConnectionError, match="expected 'data' to be a device object"):
        await mobility.get_mobility_device(client, _UUID, _UUID)


# --- LOW-3: raised errors carry every reason ------------------------------------------


async def test_list_all_clients_no_site_error_lists_every_skipped_host(client):
    hosts = [f"host-{i}" for i in range(9)]
    reg = AsyncMock()
    reg.get_hosts = AsyncMock(return_value=[])
    reg.get_ea_sites = AsyncMock(return_value=[{"hostId": h, "siteId": f"e-{h}"} for h in hosts])
    reg.get_sites = AsyncMock(side_effect=UniFiConnectionError("HTTP 403 nope"))
    with pytest.raises(RuntimeError) as exc:
        await aggregation._list_all_clients_fleet(client, reg)
    msg = str(exc.value)
    assert "(9 skipped)" in msg
    for h in hosts:
        assert h in msg, f"{h} reason missing from: {msg}"


async def test_search_across_sites_error_lists_every_failed_site(client):
    sites = [{"hostId": "h1", "siteId": f"e{i}", "meta": {"name": f"s{i}"}} for i in range(6)]
    reg = AsyncMock()
    reg.get_ea_sites = AsyncMock(return_value=sites)
    reg.resolve_key_for_host = AsyncMock(return_value=None)
    reg.get_sites = AsyncMock(side_effect=UniFiConnectionError("HTTP 500 down"))
    with pytest.raises(RuntimeError) as exc:
        await site_manager.search_across_sites(client, reg, "x")
    msg = str(exc.value)
    assert "No site could be searched (6 skipped" in msg
    for i in range(6):
        assert f"(e{i})" in msg, f"site e{i} missing from: {msg}"


# --- multi-key console de-duplication (as list_all_clients does) ----------------------


def _wrapper(host: str, *names: str) -> dict[str, Any]:
    return {"hostId": host, "hostName": host, "devices": [{"name": n} for n in names]}


def _paginate_by_key(per_key: dict[str, dict[str, list[Any]]]) -> AsyncMock:
    async def _paginate(path: str, *, key: Any = None) -> list[Any]:
        return per_key[key.label][path]

    return AsyncMock(side_effect=_paginate)


_SHARED = {
    "alpha": {
        "/v1/hosts": [{"id": "h1"}, {"id": "h2"}],
        "/v1/sites": [{"hostId": "h1", "siteId": "s1"}, {"hostId": "h2", "siteId": "s2"}],
        "/v1/devices": [_wrapper("h1", "a1"), _wrapper("h2", "b1", "b2")],
    },
    "beta": {
        "/v1/hosts": [{"id": "h2"}, {"id": "h3"}],
        "/v1/sites": [{"hostId": "h2", "siteId": "s2"}, {"hostId": "h3", "siteId": "s3"}],
        "/v1/devices": [_wrapper("h2", "b1", "b2"), _wrapper("h3", "c1")],
    },
}


async def test_list_all_devices_lists_a_shared_console_once(multikey_client):
    multikey_client.paginate = _paginate_by_key(_SHARED)
    result = await aggregation._list_all_devices_fleet(multikey_client)
    got = sorted((d["_hostId"], d["name"], d["_keyLabel"]) for d in result["data"])
    assert got == [
        ("h1", "a1", "alpha"),
        ("h2", "b1", "alpha"),
        ("h2", "b2", "alpha"),
        ("h3", "c1", "beta"),
    ]
    assert result["_count"] == 4


async def test_search_device_fleet_returns_a_shared_console_device_once(multikey_client):
    multikey_client.paginate = _paginate_by_key(_SHARED)
    result = await aggregation._search_device(multikey_client, "b1")
    assert [(m["_hostId"], m["_keyLabel"]) for m in result["data"]] == [("h2", "alpha")]


async def test_fleet_summary_counts_a_shared_console_once(multikey_client, multikey_registry):
    multikey_client.paginate = _paginate_by_key(_SHARED)
    result = await aggregation._fleet_summary(multikey_client, multikey_registry)
    assert result["hosts"] == 3
    assert result["sites"] == 3
    assert result["devices"]["total"] == 4


async def test_key_label_scope_is_not_deduplicated_against_other_keys(multikey_client):
    multikey_client.paginate = _paginate_by_key(_SHARED)
    result = await aggregation._list_all_devices_fleet(multikey_client, key_label="beta")
    assert sorted(d["name"] for d in result["data"]) == ["b1", "b2", "c1"]


# --- capped fleet drains: UNIFI_PAGINATE_MAX_PAGES=1, two keys, paged upstream ----------

_FLEET_TOOLS = ("get_fleet_summary", "list_all_devices", "list_devices", "search_device_fleet")


@pytest.mark.parametrize("name", _FLEET_TOOLS)
async def test_capped_fleet_drain_is_incomplete_for_every_key(monkeypatch, name):
    """With a one-page cap and two keys over a multi-page /v1/devices, every fleet tool
    returns what each key gathered with ``incomplete: true`` and a reason naming both
    keys' caps -- never an error, never a complete-looking result."""
    up = uh.FakeUpstream(mode="paged", hosts_by_key=cti._two_key_hosts(), tag_keys=True)
    args = {"query": "probe"} if name == "search_device_fleet" else None
    res = await cti._call(
        monkeypatch, name, up, args, keys=cti._KEYS, env={"UNIFI_PAGINATE_MAX_PAGES": "1"}
    )
    payload = uh.result_payload(res)
    assert payload["incomplete"] is True, payload
    reason = payload["incompleteReason"]
    assert "alpha" in reason and "beta" in reason and "page cap of 1" in reason, reason
    # /v1/devices was read once per key (the first page only) and never past the cap.
    device_reads = [s for s in up.served if s.path == "/v1/devices"]
    assert sorted(s.api_key for s in device_reads) == ["k-alpha", "k-beta"], device_reads
    assert all("nextToken" not in s.query for s in device_reads)
    # Each key still contributes what it gathered (shared consoles count once).
    dropped = [k for k in cti._KEY_IDS if not cti._key_contributed(name, k, payload, up)]
    assert dropped == [], dropped
