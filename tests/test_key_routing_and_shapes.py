"""Org-scoped key routing, unexpected-shape errors, and related regression fixes.

Real UniFiClient over respx wherever the behavior lives in the client or drainer, so a
regression shows up as wrong data or a missing error, not as a mock mismatch.
"""

from __future__ import annotations

import base64
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
import respx
from httpx import Request, Response

from unifi_fabric import server
from unifi_fabric.client import PaginationAbortedError, UniFiClient, UniFiConnectionError
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.registry import FetchedRecords, Registry
from unifi_fabric.tools import (
    aggregation,
    carrier_fabric,
    device_mgmt,
    mobility,
    network,
    network_services_proxy,
    protect,
    site_manager,
)
from unifi_fabric.tools._pagination import collect_cursor, collect_links

BASE = "https://api.ui.com"
HOST_A = "AAAAAAAAAAAA0000:1"
HOST_B = "BBBBBBBBBBBB0000:2"
SITE_UUID = "aaaaaaaa-0000-4000-8000-000000000001"


def _multikey() -> UniFiClient:
    return UniFiClient(
        Settings(
            api_keys=[
                APIKeyConfig(key="sk-a", label="alpha"),
                APIKeyConfig(key="sk-b", label="beta"),
            ]
        )
    )


def _by_key(alpha: Any, beta: Any):
    def handler(request: Request) -> Response:
        body = beta if request.headers.get("X-API-KEY") == "sk-b" else alpha
        return body if isinstance(body, Response) else Response(200, json=body)

    return handler


@pytest.fixture
def client() -> UniFiClient:
    return UniFiClient(Settings(api_key="sk-test"))


# --- 1/2: org-scoped key routing --------------------------------------------------------


@respx.mock
async def test_query_isp_metrics_host_site_on_second_key(monkeypatch):
    mk = _multikey()
    reg = Registry(mk, ttl_seconds=900)
    respx.get(f"{BASE}/v1/hosts").mock(
        side_effect=_by_key(
            {"data": [{"id": HOST_A, "reportedState": {"hostname": "gw-a"}}]},
            {"data": [{"id": HOST_B, "reportedState": {"hostname": "gw-b"}}]},
        )
    )
    respx.get(f"{BASE}/v1/sites").mock(
        side_effect=_by_key(
            {"data": [{"hostId": HOST_A, "siteId": "sa", "meta": {"name": "default"}}]},
            {"data": [{"hostId": HOST_B, "siteId": "sb", "meta": {"name": "default"}}]},
        )
    )
    post = respx.post(f"{BASE}/v1/isp-metrics/5m/query").mock(
        return_value=Response(200, json={"data": {"metrics": []}, "httpStatusCode": 200})
    )
    monkeypatch.setattr(server, "_client", mk)
    monkeypatch.setattr(server, "_registry", reg)
    await server.query_isp_metrics("5m", host="gw-b", site="default")
    sent = post.calls[0].request
    assert sent.headers["X-API-KEY"] == "sk-b"
    assert b'"hostId":"' + HOST_B.encode() in sent.content.replace(b" ", b"")


@respx.mock
async def test_get_isp_metrics_merges_keys_and_reports_failures():
    mk = _multikey()
    respx.get(f"{BASE}/v1/isp-metrics/1h").mock(
        side_effect=_by_key(
            {"data": [{"metricType": "x"}], "httpStatusCode": 200, "traceId": "t-a"},
            Response(403, json={"e": 1}),
        )
    )
    result = await site_manager.get_isp_metrics(mk, "1h")
    # same access path as one key (data), each record tagged, the rest of the body kept
    assert result["data"] == [{"metricType": "x", "_keyLabel": "alpha"}]
    assert result["byKey"] == {"alpha": {"httpStatusCode": 200, "traceId": "t-a"}}
    assert result["errors"][0].startswith("beta:")


@respx.mock
async def test_sdwan_list_merges_and_get_uses_the_answering_key():
    mk = _multikey()
    respx.get(f"{BASE}/v1/sd-wan-configs").mock(
        side_effect=_by_key({"data": [{"id": "c1"}]}, {"data": [{"id": "c2"}]})
    )
    listed = await site_manager.list_sdwan_configs(mk)
    assert {(c["id"], c["_keyLabel"]) for c in listed["data"]} == {
        ("c1", "alpha"),
        ("c2", "beta"),
    }
    respx.get(f"{BASE}/v1/sd-wan-configs/c2").mock(
        side_effect=_by_key(Response(404, json={"e": "nf"}), {"data": {"id": "c2"}})
    )
    assert (await site_manager.get_sdwan_config(mk, "c2"))["data"]["id"] == "c2"


@respx.mock
async def test_mobility_and_carrier_route_across_keys(monkeypatch):
    mk = _multikey()
    respx.get(f"{BASE}/v1/mobility/workspaces").mock(
        side_effect=_by_key({"data": [{"workspace_id": "w1"}]}, {"data": [{"workspace_id": "w2"}]})
    )
    ws = await mobility.list_mobility_workspaces(mk)
    assert [w["_keyLabel"] for w in ws["data"]] == ["alpha", "beta"]
    respx.get(f"{BASE}/v1/carrier/subscribers/sub-b").mock(
        side_effect=_by_key(
            Response(404, json={"error": "subscriber_not_found"}),
            {"data": {"id": "sub-b", "suspended": False}},
        )
    )
    got = await carrier_fabric.get_carrier_subscriber(mk, "sub-b")
    assert got["data"]["id"] == "sub-b"
    put = respx.post(f"{BASE}/v1/carrier/subscribers/sub-b/suspend").mock(
        return_value=Response(200, json={"data": {"id": "sub-b", "suspended": True}})
    )
    await carrier_fabric.suspend_carrier_subscriber(mk, "sub-b", confirm=True)
    assert put.calls[0].request.headers["X-API-KEY"] == "sk-b"  # the owning org's key


# --- 3/4: partial site lists, nothing queryable -----------------------------------------


def _agg_registry() -> AsyncMock:
    reg = AsyncMock()
    reg.get_hosts = AsyncMock(return_value=[])
    reg.get_ea_sites = AsyncMock(return_value=[{"hostId": "h1", "siteId": "e1"}])
    return reg


async def test_partial_console_site_list_is_reported_as_skipped():
    reg = _agg_registry()
    reg.get_sites = AsyncMock(
        return_value=FetchedRecords(
            [{"id": SITE_UUID, "description": "A"}], "page cap of 1 reached"
        )
    )
    skipped: list = []
    pairs = await aggregation._get_all_host_site_pairs(reg, skipped=skipped)
    assert len(pairs) == 1  # gathered sites still queried
    assert skipped == [
        {"hostId": "h1", "hostName": "h1", "reason": "site list incomplete: page cap of 1 reached"}
    ]


async def test_list_all_clients_raises_when_no_console_site_list_can_be_read(client):
    reg = _agg_registry()
    reg.get_sites = AsyncMock(side_effect=UniFiConnectionError("HTTP 403 nope"))
    with pytest.raises(RuntimeError, match="No site could be queried"):
        await aggregation._list_all_clients_fleet(client, reg)


async def test_search_across_sites_raises_when_every_site_fails(client):
    reg = AsyncMock()
    reg.get_ea_sites = AsyncMock(
        return_value=[{"hostId": HOST_A, "siteId": "e1", "meta": {"name": "default"}}]
    )
    reg.resolve_key_for_host = AsyncMock(return_value=None)
    reg.get_sites = AsyncMock(side_effect=UniFiConnectionError("HTTP 500 down"))
    with pytest.raises(RuntimeError, match="No site could be searched"):
        await site_manager.search_across_sites(client, reg, "x")


# --- 5/6/10: drainers ----------------------------------------------------------------


@respx.mock
async def test_page_number_drain_stops_on_a_repeated_page(client):
    respx.get(f"{BASE}/x/groups").mock(
        return_value=Response(200, json={"groups": [{"id": 1}], "links": {"next": "?page=2"}})
    )
    collected = await collect_links(client, "/x/groups", "groups")
    assert collected["incomplete"] is True
    assert "same page again" in collected["incompleteReason"]
    assert collected["items"] == [{"id": 1}]


@respx.mock
async def test_client_links_drain_recognises_a_repeated_page_by_record_identity(client):
    """A console that ignores ``page`` can answer with the same records whose live fields
    changed; whole-page equality would miss it and the record would be gathered twice."""
    envelope = {"links": {"next": "?page=2"}}
    respx.get(f"{BASE}/x/groups").mock(
        side_effect=[
            Response(200, json={"groups": [{"id": 1, "clients": 3}], **envelope}),
            Response(200, json={"groups": [{"id": 1, "clients": 4}], **envelope}),
            Response(200, json={"groups": [{"id": 9, "clients": 5}]}),
        ]
    )
    with pytest.raises(PaginationAbortedError, match="same page again") as raised:
        await client.paginate_links("/x/groups", "groups")
    assert raised.value.items == [{"id": 1, "clients": 3}]


@respx.mock
async def test_drainers_raise_on_unexpected_shapes(client):
    respx.get(f"{BASE}/v1/hosts").mock(return_value=Response(200, json={"items": []}))
    with pytest.raises(UniFiConnectionError, match=r"keys \['items'\]"):
        await client.paginate("/v1/hosts")
    respx.get(f"{BASE}/off").mock(return_value=Response(200, json={"rows": []}))
    with pytest.raises(UniFiConnectionError, match=r"keys \['rows'\]"):
        await client.paginate_offset("/off")
    respx.get(f"{BASE}/links").mock(return_value=Response(200, json={"other": []}))
    with pytest.raises(UniFiConnectionError, match="'groups' array"):
        await client.paginate_links("/links", "groups")


@respx.mock
async def test_collect_cursor_explicit_page_accepts_a_bare_array(client):
    respx.get(f"{BASE}/v1/hosts").mock(return_value=Response(200, json=[{"id": "h1"}]))
    page = await collect_cursor(client, "/v1/hosts", page_token="t")
    assert page["items"] == [{"id": "h1"}]


@respx.mock
async def test_offset_drain_honours_total_alias_and_clamped_limit_without_total(client):
    items = [{"id": i} for i in range(120)]

    def mobility_pager(request: Request) -> Response:
        offset = int(request.url.params["offset"])
        return Response(200, json={"data": items[offset : offset + 50], "total": 120})

    respx.get(f"{BASE}/mob").mock(side_effect=mobility_pager)
    drained = await client.paginate_offset("/mob")
    assert len(drained) == 120 and drained.total_count == 120

    def bare_clamped(request: Request) -> Response:
        offset = int(request.url.params["offset"])
        return Response(200, json=items[offset : offset + 50])  # clamps limit, no total

    respx.get(f"{BASE}/bare").mock(side_effect=bare_clamped)
    assert len(await client.paginate_offset("/bare")) == 120


async def test_protect_lists_and_collector_raise_on_bad_shape(client, monkeypatch):
    reg = AsyncMock()
    reg.resolve_key_for_host = AsyncMock(return_value=None)
    reg.resolve_host_id = AsyncMock(return_value=HOST_A)
    client.get = AsyncMock(return_value={"unexpected": True})  # type: ignore[method-assign]
    with pytest.raises(UniFiConnectionError, match="Unexpected Protect response shape"):
        await protect.list_cameras(client, reg, "h")
    with pytest.raises(UniFiConnectionError, match="Unexpected Protect response shape"):
        await protect.collect_protect_device_changes(client, reg, "h", poll_count=1)


async def test_mobility_detail_and_carrier_pages_raise_on_bad_shape(client):
    client.get = AsyncMock(return_value=["not", "an", "object"])  # type: ignore[method-assign]
    with pytest.raises(UniFiConnectionError, match="expected a device object"):
        await mobility.get_mobility_device(client, "ws1", "dev1")
    client.get = AsyncMock(return_value={"meta": {}})  # type: ignore[method-assign]
    with pytest.raises(UniFiConnectionError, match="'data' array"):
        await carrier_fabric.list_carrier_subscribers(client)


# --- 9/12: transport errors and audit ---------------------------------------------------


@respx.mock
async def test_protocol_error_is_wrapped_and_failed_write_audited(tmp_path):
    log = tmp_path / "audit.log"
    c = UniFiClient(Settings(api_key="sk-test", audit_log=str(log)))
    respx.put(f"{BASE}/v1/x").mock(
        side_effect=httpx.RemoteProtocolError("Server disconnected without sending a response.")
    )
    with pytest.raises(UniFiConnectionError) as exc:
        await c.put("/v1/x", json={"a": 1})
    assert "Protocol error: PUT /v1/x" in str(exc.value)
    assert "RemoteProtocolError: Server disconnected" in str(exc.value)
    assert "PUT" in log.read_text() and "error" in log.read_text()


@respx.mock
async def test_empty_connect_error_names_the_class(client):
    respx.get(f"{BASE}/v1/hosts").mock(side_effect=httpx.ConnectError(""))
    with pytest.raises(UniFiConnectionError) as exc:
        await client.get("/v1/hosts")
    msg = str(exc.value)
    assert "ConnectError" in msg
    assert "ConnectError: )" not in msg  # never an empty "Class: " with nothing after it


@respx.mock
async def test_delete_returns_the_upstream_body(client):
    respx.delete(f"{BASE}/v1/x").mock(return_value=Response(200, json={"deleted": True}))
    assert await client.delete("/v1/x") == {"deleted": True}
    respx.delete(f"{BASE}/v1/y").mock(return_value=Response(204))
    assert await client.delete("/v1/y") is None


# --- 11: a write never fails after it was applied --------------------------------------


async def test_port_profile_write_survives_name_lookup_failure():
    c = AsyncMock()
    reg = AsyncMock()
    reg.resolve_key_for_host = AsyncMock(return_value=None)
    reg.resolve_host_id = AsyncMock(return_value=HOST_A)
    reg.resolve_site_slug = AsyncMock(return_value="default")
    c.put = AsyncMock(return_value={"data": [{"_id": "pp1", "native_networkconf_id": "n1"}]})

    async def get(path: str, **_kw: object) -> object:
        # The write target is resolved in /rest/portconf first; only the networkconf
        # name lookup fails.
        if path.endswith("/rest/portconf"):
            return {"data": [{"_id": "pp1", "native_networkconf_id": "n1"}]}
        raise UniFiConnectionError("HTTP 500 networkconf down")

    c.get = AsyncMock(side_effect=get)
    result = await network_services_proxy.update_port_profile(
        c, reg, "h", "s", "pp1", {"poe_mode": "auto"}
    )
    assert result["data"][0]["_id"] == "pp1"
    assert "networkconf down" in result["data"][0]["_resolvedNetworksError"]


# --- 13/14: invented values, caches, injected params ------------------------------------


async def test_snapshot_reports_upstream_content_type(client):
    reg = AsyncMock()
    reg.resolve_key_for_host = AsyncMock(return_value=None)
    reg.resolve_host_id = AsyncMock(return_value=HOST_A)
    client.get_binary = AsyncMock(return_value=(b"\x89PNG", "image/png"))  # type: ignore[method-assign]
    result = await protect.get_camera_snapshot(client, reg, "h", "cam1")
    assert result["content_type"] == "image/png"


async def test_upload_rejects_invalid_base64_before_sending(client):
    reg = AsyncMock()
    reg.resolve_key_for_host = AsyncMock(return_value=None)
    reg.resolve_host_id = AsyncMock(return_value=HOST_A)
    client.request = AsyncMock()  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="not valid base64"):
        await protect.upload_protect_file(client, reg, "h", "sounds", "a.mp3", "not base64!!")
    client.request.assert_not_called()
    ok = base64.b64encode(b"abc").decode()
    client.request.return_value = httpx.Response(200, json={"ok": True})
    assert await protect.upload_protect_file(client, reg, "h", "sounds", "a.mp3", ok) == {
        "status": "uploaded",
        "response": {"ok": True},
    }


async def test_site_slug_is_never_guessed(client):
    reg = Registry(client, ttl_seconds=900)
    reg.get_sites = AsyncMock(  # type: ignore[method-assign]
        return_value=[{"id": SITE_UUID, "name": "Office"}, {"id": "x"}]
    )
    with pytest.raises(ValueError, match="has no internalReference"):
        await reg.resolve_site_slug("Office", HOST_A)
    with pytest.raises(ValueError, match="must not be empty"):
        await reg.resolve_site_slug("", HOST_A)


async def test_mac_cache_is_per_client():
    a, b = AsyncMock(), AsyncMock()
    a.get = AsyncMock(
        return_value={
            "data": [{"id": "uuid-a", "macAddress": "de:ad:be:ef:00:01"}],
            "totalCount": 1,
        }
    )
    b.get = AsyncMock(
        return_value={
            "data": [{"id": "uuid-b", "macAddress": "de:ad:be:ef:00:01"}],
            "totalCount": 1,
        }
    )
    assert await device_mgmt._resolve_device_id(a, HOST_A, SITE_UUID, "DEADBEEF0001") == "uuid-a"
    assert await device_mgmt._resolve_device_id(b, HOST_A, SITE_UUID, "DEADBEEF0001") == "uuid-b"
    assert await device_mgmt._resolve_device_id(a, HOST_A, SITE_UUID, "DEADBEEF0001") == "uuid-a"
    assert await device_mgmt._resolve_device_id(b, HOST_A, SITE_UUID, "DEADBEEF0001") == "uuid-b"
    for client in (a, b):
        client.get.assert_awaited_once_with(
            f"/v1/connector/consoles/{HOST_A}/proxy/network/integration/v1/sites/{SITE_UUID}/devices",
            key=None,
            params={"limit": 200, "offset": 0},
        )


@respx.mock
async def test_explicit_offset_without_limit_sends_no_limit(client):
    reg = AsyncMock()
    reg.resolve_key_for_host = AsyncMock(return_value=None)
    reg.resolve_host_id = AsyncMock(return_value=HOST_A)
    reg.resolve_site_id = AsyncMock(return_value=SITE_UUID)
    route = respx.get(
        f"{BASE}/v1/connector/consoles/{HOST_A}/proxy/network/integration/v1/sites/{SITE_UUID}/networks"
    ).mock(return_value=Response(200, json={"offset": 5, "data": [], "totalCount": 0}))
    await network.list_networks(client, reg, "h", "s", offset=5)
    assert "limit" not in route.calls[0].request.url.params


def test_non_wrapper_device_item_raises():
    with pytest.raises(UniFiConnectionError, match="console wrapper object"):
        aggregation._unwrap_ea_devices([{"hostId": "h", "devices": []}, "junk"])


def test_transport_cause_without_any_detail():
    from unifi_fabric.client import _transport_cause

    assert _transport_cause(httpx.ConnectError("")) == (
        "ConnectError (no further detail from the network stack)"
    )
    assert issubclass(PaginationAbortedError, Exception)
