"""get_fleet_summary ``_keyTotals`` and the one ``errors`` list of the multi-key
fan-out tools (a failed key and a failed site in the same call)."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import UniFiClient, UniFiConnectionError
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.registry import Registry
from unifi_fabric.tools import aggregation, site_manager

_UUID_A1 = "3fa85f64-5717-4562-b3fc-2c963f66af01"
_UUID_G1 = "3fa85f64-5717-4562-b3fc-2c963f66af03"


def _device(name: str, status: str, line: str) -> dict[str, Any]:
    return {"name": name, "status": status, "productLine": line}


def _wrapper(host: str, *devices: dict[str, Any]) -> dict[str, Any]:
    return {"hostId": host, "hostName": host, "devices": list(devices)}


def _paginate_by_key(per_key: dict[str, Any]) -> AsyncMock:
    async def _paginate(path: str, *, key: Any = None) -> list[Any]:
        value = per_key[key.label if key is not None else None]
        if isinstance(value, Exception):
            raise value
        return value[path]

    return AsyncMock(side_effect=_paginate)


_ALPHA = {
    "/v1/hosts": [{"id": "h1"}, {"id": "h2"}],
    "/v1/sites": [{"hostId": "h1", "siteId": "s1"}, {"hostId": "h2", "siteId": "s2"}],
    "/v1/devices": [
        _wrapper("h1", _device("a1", "online", "network")),
        _wrapper("h2", _device("b1", "online", "network"), _device("b2", "offline", "protect")),
    ],
}
_BETA_DISJOINT = {
    "/v1/hosts": [{"id": "h3"}],
    "/v1/sites": [{"hostId": "h3", "siteId": "s3"}, {"hostId": "h3", "siteId": "s4"}],
    "/v1/devices": [
        _wrapper("h3", _device("c1", "offline", "network"), _device("c2", "online", "access"))
    ],
}
# beta also sees alpha's console h2 (same sites and devices): counted under alpha only.
_BETA_SHARED = {
    "/v1/hosts": [{"id": "h2"}, {"id": "h3"}],
    "/v1/sites": [{"hostId": "h2", "siteId": "s2"}, {"hostId": "h3", "siteId": "s3"}],
    "/v1/devices": [
        _wrapper("h2", _device("b1", "online", "network"), _device("b2", "offline", "protect")),
        _wrapper("h3", _device("c1", "offline", "network")),
    ],
}


def _sum_totals(per_key: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Add the per-key entries up into one {hosts, sites, devices} summary."""
    out: dict[str, Any] = {
        "hosts": 0,
        "sites": 0,
        "devices": {"total": 0, "byStatus": {}, "byType": {}},
    }
    for entry in per_key.values():
        out["hosts"] += entry["hosts"]
        out["sites"] += entry["sites"]
        out["devices"]["total"] += entry["devices"]["total"]
        for bucket in ("byStatus", "byType"):
            for name, count in entry["devices"][bucket].items():
                out["devices"][bucket][name] = out["devices"][bucket].get(name, 0) + count
    return out


def _top_level(summary: dict[str, Any]) -> dict[str, Any]:
    return {"hosts": summary["hosts"], "sites": summary["sites"], "devices": summary["devices"]}


async def test_key_totals_two_keys_sum_to_the_totals(multikey_client, multikey_registry):
    multikey_client.paginate = _paginate_by_key({"alpha": _ALPHA, "beta": _BETA_DISJOINT})
    result = await aggregation._fleet_summary(multikey_client, multikey_registry)
    totals = result["_keyTotals"]
    assert list(totals) == ["alpha", "beta"] == result["_key_labels"]
    assert totals["alpha"] == {
        "hosts": 2,
        "sites": 2,
        "devices": {
            "total": 3,
            "byStatus": {"online": 2, "offline": 1},
            "byType": {"network": 2, "protect": 1},
        },
    }
    assert totals["beta"] == {
        "hosts": 1,
        "sites": 2,
        "devices": {
            "total": 2,
            "byStatus": {"offline": 1, "online": 1},
            "byType": {"network": 1, "access": 1},
        },
    }
    assert _sum_totals(totals) == _top_level(result)
    assert "byKey" not in result
    assert "errors" not in result
    assert "_wrapperFields" not in result


async def test_key_totals_count_a_shared_console_once(multikey_client, multikey_registry):
    multikey_client.paginate = _paginate_by_key({"alpha": _ALPHA, "beta": _BETA_SHARED})
    result = await aggregation._fleet_summary(multikey_client, multikey_registry)
    totals = result["_keyTotals"]
    # h2 (its site and two devices) is counted under alpha, the first key, only.
    assert totals["alpha"]["hosts"] == 2
    assert totals["alpha"]["devices"]["total"] == 3
    assert totals["beta"] == {
        "hosts": 1,
        "sites": 1,
        "devices": {"total": 1, "byStatus": {"offline": 1}, "byType": {"network": 1}},
    }
    assert (result["hosts"], result["sites"], result["devices"]["total"]) == (3, 3, 4)
    assert _sum_totals(totals) == _top_level(result)


async def test_key_totals_leave_out_a_failing_key(multikey_client, multikey_registry):
    multikey_client.paginate = _paginate_by_key(
        {"alpha": _ALPHA, "beta": UniFiConnectionError("beta is down")}
    )
    result = await aggregation._fleet_summary(multikey_client, multikey_registry)
    assert list(result["_keyTotals"]) == ["alpha"]
    assert result["_key_labels"] == ["alpha"]
    assert len(result["errors"]) == 1
    assert result["errors"][0].startswith("beta: ")
    assert "beta is down" in result["errors"][0]
    assert _sum_totals(result["_keyTotals"]) == _top_level(result)
    assert "_wrapperFields" not in result


async def test_key_totals_absent_with_a_single_key():
    client = UniFiClient(Settings(api_key="test-key"))
    client.paginate = _paginate_by_key({None: _ALPHA})
    result = await aggregation._fleet_summary(client, Registry(client, ttl_seconds=900))
    assert result["devices"]["total"] == 3
    assert "_keyTotals" not in result
    assert "_key_labels" not in result
    assert "byKey" not in result


async def test_key_totals_absent_with_key_label(multikey_client, multikey_registry):
    multikey_client.paginate = _paginate_by_key({"alpha": _ALPHA, "beta": _BETA_SHARED})
    result = await aggregation._fleet_summary(multikey_client, multikey_registry, key_label="beta")
    assert (result["hosts"], result["sites"], result["devices"]["total"]) == (2, 2, 3)
    assert result["_key_label"] == "beta"
    assert "_keyTotals" not in result
    assert "byKey" not in result


# --- one errors list: a failed key and a failed site in the same call ------------------


@pytest.fixture
def three_key_client() -> UniFiClient:
    return UniFiClient(
        Settings(
            api_keys=[
                APIKeyConfig(key="k-alpha", label="alpha", is_org_key=False),
                APIKeyConfig(key="k-beta", label="beta", is_org_key=True),
                APIKeyConfig(key="k-gamma", label="gamma", is_org_key=True),
            ]
        )
    )


async def test_list_all_clients_reports_key_and_site_errors_together(monkeypatch, three_key_client):
    pairs = {
        "alpha": [
            {"hostId": "ha", "hostName": "ha", "siteId": "a1", "siteName": "a-site1"},
            {"hostId": "ha", "hostName": "ha", "siteId": "a2", "siteName": "a-site2"},
        ],
        "gamma": [{"hostId": "hg", "hostName": "hg", "siteId": "g1", "siteName": "g-site1"}],
    }

    async def _pairs(_registry: Any, *, key: Any = None, **_kw: Any) -> list[dict[str, str]]:
        if key.label == "beta":
            raise UniFiConnectionError("beta sites down")
        return pairs[key.label]

    async def _collect(_client: Any, path: str, *, key: Any = None, **_kw: Any) -> dict:
        if "/sites/a2/" in path:
            raise UniFiConnectionError("a2 clients down")
        return {"items": [{"mac": path}], "incomplete": False, "incompleteReason": None}

    monkeypatch.setattr(aggregation, "_get_all_host_site_pairs", _pairs)
    monkeypatch.setattr(aggregation, "collect_offset", _collect)
    result = await aggregation._list_all_clients_fleet(three_key_client, AsyncMock())

    assert result["errors"] == ["beta: beta sites down", "a-site2: a2 clients down"]
    assert result["_key_labels"] == ["alpha", "gamma"]
    assert result["_count"] == 2
    assert result["_sitesFailed"] == 1
    assert not any(field.startswith("_wrapperFields") for field in result)


async def test_search_across_sites_reports_key_and_site_errors_together(
    monkeypatch, three_key_client
):
    sites = {
        "alpha": [{"hostId": "ha", "siteId": "ea-a1", "meta": {"name": "a1"}}],
        "gamma": [{"hostId": "hg", "siteId": "ea-g1", "meta": {"name": "g1"}}],
    }
    proxy_ids = {"ea-a1": _UUID_A1, "ea-g1": _UUID_G1}

    async def _ea_sites(*, key: Any = None) -> list[dict[str, Any]]:
        if key.label == "beta":
            raise UniFiConnectionError("beta sites down")
        return sites[key.label]

    async def _proxy_site(_registry: Any, record: dict[str, Any], _key: Any) -> dict:
        return {"id": proxy_ids[record["siteId"]]}

    async def _collect(_client: Any, path: str, *, key: Any = None, **_kw: Any) -> dict:
        if f"/sites/{_UUID_A1}/clients" in path:
            raise UniFiConnectionError("a1 clients down")
        return {"items": [], "incomplete": False, "incompleteReason": None}

    registry = AsyncMock()
    registry.get_ea_sites = AsyncMock(side_effect=_ea_sites)
    monkeypatch.setattr(site_manager, "_proxy_site_for_ea", _proxy_site)
    monkeypatch.setattr(site_manager, "collect_offset", _collect)
    result = await site_manager.search_across_sites(three_key_client, registry, "x")

    assert result["errors"] == [
        {"key": "beta", "siteId": "", "scope": "sites", "reason": "beta sites down"},
        {"key": "alpha", "siteId": _UUID_A1, "scope": "clients", "reason": "a1 clients down"},
    ]
    assert result["_key_labels"] == ["alpha", "gamma"]
    assert result["_sitesFailed"] == 1
    assert not any(field.startswith("_wrapperFields") for field in result)
