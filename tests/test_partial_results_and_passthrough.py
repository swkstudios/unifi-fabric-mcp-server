"""Verbatim delete bodies, additive-key stripping on writes, per-key ISP metric
failures, capped multi-key drains, partial site lists, and strict read-before shapes.

Real UniFiClient over respx wherever the behavior lives in the client, so a regression
shows up as wrong data or a missing error, not as a mock mismatch.
"""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import respx
from httpx import Request, Response

from unifi_fabric import server
from unifi_fabric.client import UniFiClient, UniFiConnectionError, strip_additive_keys
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.registry import (
    FetchedRecords,
    PartialListingError,
    Registry,
    incomplete_reason,
)
from unifi_fabric.tools import network_services_proxy, protect, site_manager

BASE = "https://api.ui.com"
HOST_A = "AAAAAAAAAAAA0000:1"
HOST_B = "BBBBBBBBBBBB0000:2"


def _multikey() -> UniFiClient:
    return UniFiClient(
        Settings(
            api_keys=[
                APIKeyConfig(key="sk-a", label="alpha"),
                APIKeyConfig(key="sk-b", label="beta"),
            ]
        )
    )


@pytest.fixture
def client() -> UniFiClient:
    return UniFiClient(Settings(api_key="sk-test"))


# --- delete bodies -------------------------------------------------------------------


@respx.mock
async def test_delete_returns_non_json_body_verbatim(client):
    respx.delete(f"{BASE}/thing/1").mock(return_value=Response(200, text="removed 1 item"))
    assert await client.delete("/thing/1") == "removed 1 item"


@respx.mock
async def test_delete_returns_json_body_and_none_for_empty(client):
    respx.delete(f"{BASE}/thing/1").mock(return_value=Response(200, json={"count": 1}))
    respx.delete(f"{BASE}/thing/2").mock(return_value=Response(204))
    assert await client.delete("/thing/1") == {"count": 1}
    assert await client.delete("/thing/2") is None


# --- additive keys never written back --------------------------------------------------


def test_strip_additive_keys_keeps_real_id():
    body = {"_id": "x", "name": "n", "_warnings": [1], "_keyLabel": "a", "_profileNote": "p"}
    assert strip_additive_keys(body) == {"_id": "x", "name": "n"}
    assert body["_warnings"] == [1]  # input not mutated
    assert strip_additive_keys(["_x"]) == ["_x"]


@respx.mock
async def test_write_chokepoint_strips_additive_keys(client):
    route = respx.put(f"{BASE}/thing/1").mock(return_value=Response(200, json={}))
    await client.put(
        "/thing/1",
        json={"_id": "x", "name": "n", "_warnings": [{"code": "D12"}], "_wanHealthError": "e"},
    )
    assert json.loads(route.calls[0].request.content) == {"_id": "x", "name": "n"}


@respx.mock
async def test_raw_relay_body_is_sent_as_given(client):
    route = respx.post(f"{BASE}/thing").mock(return_value=Response(200, json={}))
    await client.request("POST", "/thing", json={"_custom": 1}, strip_additive=False)
    assert json.loads(route.calls[0].request.content) == {"_custom": 1}


async def test_d12_warning_is_additive_and_upstream_warnings_untouched():
    created = {"id": "net1", "vlanId": 30, "warnings": ["upstream-owned"]}
    reg = MagicMock()
    reg.resolve_key_for_host = AsyncMock(return_value=None)
    reg.resolve_host_id = AsyncMock(return_value=HOST_A)
    reg.resolve_site_slug = AsyncMock(return_value="default")
    api = MagicMock()
    api.get = AsyncMock(side_effect=RuntimeError("portconf 500"))
    out = await network_services_proxy.annotate_auto_exclusions(api, reg, "h", "s", created)
    assert out["warnings"] == ["upstream-owned"]
    assert out["_warnings"][0]["code"] == "D12_CHECK_FAILED"
    # The failed follow-up read is the create's read-after: reported additively.
    assert out["_readAfterError"] == "RuntimeError: portconf 500"
    assert strip_additive_keys(out) == created


# --- query_isp_metrics across owning keys ------------------------------------------------


_ISP_QUERY = json.loads(
    (
        Path(__file__).parent
        / "fixtures"
        / "recorded"
        / "site_manager"
        / "v1_isp_metrics_1h_query.json"
    ).read_text()
)["body"]


def _isp_body(site_id: str, host_id: str, *, trace: str, **data_extra: Any) -> dict[str, Any]:
    """The recorded POST /v1/isp-metrics/{type}/query body, re-targeted at one site."""
    body = copy.deepcopy(_ISP_QUERY)
    metric = body["data"]["metrics"][0]
    metric["siteId"], metric["hostId"] = site_id, host_id
    body["data"].update(data_extra)
    body["traceId"] = trace
    return body


def _isp_setup(monkeypatch, beta_status: int) -> Any:
    mk = _multikey()
    reg = Registry(mk, ttl_seconds=900)

    def hosts(request: Request) -> Response:
        if request.headers.get("X-API-KEY") == "sk-b":
            return Response(200, json={"data": [{"id": HOST_B}]})
        return Response(200, json={"data": [{"id": HOST_A}]})

    def query(request: Request) -> Response:
        if request.headers.get("X-API-KEY") == "sk-b":
            if beta_status == 200:
                return Response(200, json=_isp_body("sb", HOST_B, trace="t-beta"))
            return Response(beta_status, json={"code": "beta-broke", "message": "beta down"})
        return Response(200, json=_isp_body("sa", HOST_A, trace="t-alpha"))

    def sites(request: Request) -> Response:
        if request.headers.get("X-API-KEY") == "sk-b":
            return Response(200, json={"data": [{"siteId": "sb", "hostId": HOST_B}]})
        return Response(200, json={"data": [{"siteId": "sa", "hostId": HOST_A}]})

    respx.get(f"{BASE}/v1/hosts").mock(side_effect=hosts)
    respx.get(f"{BASE}/v1/sites").mock(side_effect=sites)
    respx.post(f"{BASE}/v1/isp-metrics/5m/query").mock(side_effect=query)
    monkeypatch.setattr(server, "_client", mk)
    monkeypatch.setattr(server, "_registry", reg)
    return [{"hostId": HOST_A, "siteId": "sa"}, {"hostId": HOST_B, "siteId": "sb"}]


@respx.mock
async def test_query_isp_metrics_one_owner_failing_keeps_the_other(monkeypatch):
    sites = _isp_setup(monkeypatch, beta_status=500)
    result = await server.query_isp_metrics("5m", sites=sites)
    alpha = _isp_body("sa", HOST_A, trace="t-alpha")
    assert result["data"]["metrics"] == [{**alpha["data"]["metrics"][0], "_keyLabel": "alpha"}]
    assert result["byKey"]["alpha"] == {"data": {}, "httpStatusCode": 200, "traceId": "t-alpha"}
    assert result["_key_labels"] == ["alpha"]
    assert len(result["errors"]) == 1 and "beta" in result["errors"][0]
    assert "beta down" in result["errors"][0]


@respx.mock
async def test_query_isp_metrics_two_owners_both_succeed(monkeypatch):
    sites = _isp_setup(monkeypatch, beta_status=200)
    result = await server.query_isp_metrics("5m", sites=sites)
    metrics = result["data"]["metrics"]
    assert sorted(m["_keyLabel"] for m in metrics) == ["alpha", "beta"]
    assert {m["siteId"] for m in metrics} == {"sa", "sb"}
    assert result["byKey"]["beta"]["traceId"] == "t-beta"
    assert "errors" not in result


@respx.mock
async def test_query_isp_metrics_multi_key_keeps_each_keys_partial_success(monkeypatch):
    """A key's data.status / data.message (partial success) is never dropped by the merge."""
    sites = _isp_setup(monkeypatch, beta_status=200)

    def query(request: Request) -> Response:
        if request.headers.get("X-API-KEY") == "sk-b":
            return Response(
                200,
                json=_isp_body(
                    "sb", HOST_B, trace="t-beta", status="partialSuccess", message="sb no data"
                ),
            )
        return Response(200, json=_isp_body("sa", HOST_A, trace="t-alpha"))

    respx.post(f"{BASE}/v1/isp-metrics/5m/query").mock(side_effect=query)
    result = await server.query_isp_metrics("5m", sites=sites)
    assert result["byKey"]["beta"]["data"] == {
        "status": "partialSuccess",
        "message": "sb no data",
    }
    assert result["byKey"]["alpha"]["data"] == {}


@respx.mock
async def test_query_isp_metrics_multi_key_other_shape_is_that_keys_error(monkeypatch):
    sites = _isp_setup(monkeypatch, beta_status=200)

    def query(request: Request) -> Response:
        if request.headers.get("X-API-KEY") == "sk-b":
            return Response(200, json={"data": [{"metricType": "5m"}]})  # not data.metrics
        return Response(200, json=_isp_body("sa", HOST_A, trace="t-alpha"))

    respx.post(f"{BASE}/v1/isp-metrics/5m/query").mock(side_effect=query)
    result = await server.query_isp_metrics("5m", sites=sites)
    assert result["_key_labels"] == ["alpha"]
    assert "beta" in result["errors"][0] and "data.metrics" in result["errors"][0]


@respx.mock
async def test_query_isp_metrics_every_owner_failing_raises_with_each_reason(monkeypatch):
    sites = _isp_setup(monkeypatch, beta_status=500)
    respx.post(f"{BASE}/v1/isp-metrics/5m/query").mock(
        return_value=Response(500, json={"message": "all down"})
    )
    with pytest.raises(RuntimeError) as exc:
        await server.query_isp_metrics("5m", sites=sites)
    assert "alpha" in str(exc.value) and "beta" in str(exc.value)


# --- capped multi-key drains ----------------------------------------------------------------


@respx.mock
async def test_multikey_list_sites_cap_keeps_items_and_never_caches(monkeypatch):
    monkeypatch.setenv("UNIFI_PAGINATE_MAX_PAGES", "1")
    mk = UniFiClient(
        Settings(
            api_keys=[
                APIKeyConfig(key="sk-a", label="alpha"),
                APIKeyConfig(key="sk-b", label="beta"),
            ]
        )
    )
    reg = Registry(mk, ttl_seconds=900)

    def sites(request: Request) -> Response:
        if request.headers.get("X-API-KEY") == "sk-b":
            return Response(200, json={"data": [{"siteId": "b1"}], "nextToken": "more"})
        return Response(200, json={"data": [{"siteId": "a1"}]})

    respx.get(f"{BASE}/v1/sites").mock(side_effect=sites)
    result = await site_manager.list_sites(mk, reg)
    assert sorted(s["siteId"] for s in result["data"]) == ["a1", "b1"]
    assert result["incomplete"] is True and "beta" in result["incompleteReason"]
    assert "beta" not in reg._ea_sites  # partial list never cached
    assert "alpha" in reg._ea_sites


# --- partial Site Manager site list ---------------------------------------------------------


@respx.mock
async def test_capped_site_list_flags_search_across_sites(monkeypatch):
    monkeypatch.setenv("UNIFI_PAGINATE_MAX_PAGES", "1")
    api = UniFiClient(Settings(api_key="sk-test"))
    reg = Registry(api, ttl_seconds=900)
    respx.get(f"{BASE}/v1/sites").mock(
        return_value=Response(200, json={"data": [], "nextToken": "more"})
    )
    result = await site_manager.search_across_sites(api, reg, "anything")
    assert result["incomplete"] is True
    assert "page cap" in result["incompleteReason"]


# --- registry incomplete state ------------------------------------------------------------


async def test_registry_incomplete_state_lives_with_the_fetched_list():
    """No separate (TTL-expiring) incomplete marker; a capped list carries its
    reason and is never cached, a complete list carries none."""
    reg = Registry(UniFiClient(Settings(api_key="sk-test")), ttl_seconds=900)
    for name in ("_sites_incomplete", "_hosts_incomplete", "_ea_sites_incomplete"):
        assert not hasattr(reg, name)
    capped = FetchedRecords([{"id": "x"}], "capped")
    assert incomplete_reason(capped) == "capped"
    assert incomplete_reason([{"id": "x"}]) is None
    await reg.set_hosts([])
    assert incomplete_reason(await reg.get_hosts()) is None


# --- compare_site_performance -------------------------------------------------------------


async def test_compare_site_performance_raises_when_every_site_fails(monkeypatch):
    monkeypatch.setattr(
        site_manager, "get_site_health_summary", AsyncMock(side_effect=ValueError("no site"))
    )
    with pytest.raises(RuntimeError, match="All 2 site"):
        await site_manager.compare_site_performance(MagicMock(), MagicMock(), ["a", "b"])


async def test_compare_site_performance_partial_failure_is_reported(monkeypatch):
    async def fake(_c, _r, site):
        if site == "bad":
            raise ValueError("no site bad")
        return {"health": [], "count": 0}

    monkeypatch.setattr(site_manager, "get_site_health_summary", fake)
    result = await site_manager.compare_site_performance(MagicMock(), MagicMock(), ["ok", "bad"])
    assert result["_count"] == 2
    assert {"_siteLabel": "bad", "error": "no site bad"} in result["_comparison"]


# --- Protect strict read-before and base64 ----------------------------------------------------


def _protect_registry() -> MagicMock:
    reg = MagicMock()
    reg.resolve_key_for_host = AsyncMock(return_value=None)
    reg.resolve_host_id = AsyncMock(return_value=HOST_A)
    return reg


@pytest.mark.parametrize("body", [["not", "an", "object"], "text", None])
async def test_update_item_verified_raises_on_non_object_read_before(body):
    api = MagicMock()
    api.get = AsyncMock(return_value=body)
    api.patch = AsyncMock()
    with pytest.raises(UniFiConnectionError, match="expected an object"):
        await protect._update_item_verified(
            api, _protect_registry(), "h", "lights", "a" * 24, "light_id", {"name": "x"}
        )
    api.patch.assert_not_called()


async def test_upload_protect_file_accepts_76_column_wrapped_base64():
    payload = bytes(range(256)) * 2
    flat = base64.b64encode(payload).decode()
    wrapped = "\n".join(flat[i : i + 76] for i in range(0, len(flat), 76)) + "\n"
    api = MagicMock()
    api.request = AsyncMock(return_value=httpx.Response(200, json={"ok": True}))
    await protect.upload_protect_file(api, _protect_registry(), "h", "sounds", "a.wav", wrapped)
    sent = api.request.call_args.kwargs["files"]["file"][1].getvalue()
    assert sent == payload


async def test_upload_protect_file_still_rejects_non_base64():
    api = MagicMock()
    api.request = AsyncMock()
    with pytest.raises(ValueError, match="not valid base64"):
        await protect.upload_protect_file(api, _protect_registry(), "h", "sounds", "a.wav", "@@@@")
    api.request.assert_not_called()


def _beta_sites_cycle(request: Request) -> Response:
    """Beta's /v1/sites drain cycles its cursor, so beta's site list is incomplete."""
    if request.headers.get("X-API-KEY") == "sk-b":
        return Response(
            200,
            json={
                "data": [{"siteId": "sb", "hostId": HOST_B, "meta": {"name": "Beta Site"}}],
                "nextToken": "cycle",
            },
        )
    return Response(200, json={"data": [{"siteId": "sa", "hostId": HOST_A}]})


@respx.mock
async def test_query_isp_metrics_partial_site_list_fails_only_that_key(monkeypatch):
    """A name matched on one key's incomplete site list is that key's listing problem: the
    other key's metrics are still returned and the beta key reports the reason."""
    _isp_setup(monkeypatch, beta_status=200)
    respx.get(f"{BASE}/v1/sites").mock(side_effect=_beta_sites_cycle)
    sites = [{"hostId": HOST_A, "siteId": "sa"}, {"hostId": HOST_B, "siteId": "Beta Site"}]
    result = await server.query_isp_metrics("5m", sites=sites)
    assert result["_key_labels"] == ["alpha"]
    assert [m["siteId"] for m in result["data"]["metrics"]] == ["sa"]
    assert len(result["errors"]) == 1
    assert "beta" in result["errors"][0] and "incomplete" in result["errors"][0]


@respx.mock
async def test_query_isp_metrics_unknown_site_on_a_complete_list_fails_the_call(monkeypatch):
    _isp_setup(monkeypatch, beta_status=200)
    sites = [{"hostId": HOST_A, "siteId": "sa"}, {"hostId": HOST_B, "siteId": "No Such Site"}]
    with pytest.raises(ValueError, match="'No Such Site' not found") as exc:
        await server.query_isp_metrics("5m", sites=sites)
    assert not isinstance(exc.value, PartialListingError)
    # The invalid selector fails before any metrics request for either key.
    assert not any(call.request.method == "POST" for call in respx.calls)
