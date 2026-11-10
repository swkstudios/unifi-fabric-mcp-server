"""Upstream error signals: HTTP 408, Retry-After and the device-write note.

Every upstream body stays verbatim; only the classification and additive hints change.

C. HTTP 408 (the Fabric connector's request limit, an offline console or old firmware)
   carries a hint; a 408 on a write is outcome unknown and the write is sent once. The
   pinned Site Manager spec (tests/fixtures/openapi/site-manager-1.0.0.json) documents 408
   on every ``/v1/connector/consoles/{id}/*path`` verb.
K. A read via GET retries 429 after the upstream's ``Retry-After`` (seconds or HTTP date);
   writes stay single-shot. The same spec documents ``Retry-After`` on those 429 responses.
J. The device-settings write descriptions say a write can restart or reprovision the device.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
import respx

from unifi_fabric.client import (
    RateLimitError,
    UniFiClient,
    UniFiHTTPError,
    parse_retry_after,
    route_hint,
)
from unifi_fabric.config import Settings

BASE = "https://api.ui.com"
CONSOLE = "/v1/connector/consoles/h1/proxy"
V2 = f"{CONSOLE}/network/v2/api/site/default/nat"


@pytest.fixture(autouse=True)
def _quiet_logs():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


def _client(**kw: Any) -> UniFiClient:
    return UniFiClient(Settings(api_key="probe-key-1", api_base_url=BASE, **kw))


def _json(status: int, body: Any, **headers: str) -> httpx.Response:
    return httpx.Response(
        status,
        content=json.dumps(body, separators=(",", ":")).encode(),
        headers={"content-type": "application/json", **headers},
    )


# =========================================================================== C: HTTP 408
_408_BODY = {"code": "request_timeout", "httpStatusCode": 408, "message": "Request Timeout"}
_408_TEXT = json.dumps(_408_BODY, separators=(",", ":"))


@respx.mock
async def test_c_408_on_a_read_has_the_hint_and_no_outcome_clause():
    path = f"{CONSOLE}/network/api/s/default/stat/sta"
    route = respx.get(BASE + path).mock(return_value=_json(408, _408_BODY))
    with pytest.raises(UniFiHTTPError) as exc:
        await _client().get(path)
    msg = str(exc.value)
    assert exc.value.status == 408 and route.call_count == 1  # a 408 is not retried
    assert msg.startswith(f"HTTP 408 from GET {path}: {_408_TEXT}")  # body verbatim, first
    assert "Hint: HTTP 408 comes from the Fabric connector" in msg
    for part in ("request time limit", "offline", "firmware", "connector minimum", "list_hosts"):
        assert part in msg, part
    assert "outcome unknown" not in msg


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
@respx.mock
async def test_c_408_on_a_write_is_outcome_unknown_and_sent_once(method, tmp_path):
    audit = tmp_path / "audit.jsonl"
    client = _client(audit_log=str(audit), audit_log_format="json")
    route = respx.route(method=method, url=BASE + V2).mock(
        side_effect=[_json(408, _408_BODY), _json(200, {"ok": True})]
    )
    with pytest.raises(UniFiHTTPError) as exc:
        await client.request(method, V2, json={"a": 1})
    msg = str(exc.value)
    assert route.call_count == 1  # never retried
    assert exc.value.status == 408
    assert msg.startswith(f"HTTP 408 from {method} {V2}: {_408_TEXT}")
    assert "outcome unknown: the write may have been applied; it was not retried" in msg
    assert "fabric_connector_get on console h1" in msg  # read back before retrying
    assert "Hint: HTTP 408 comes from the Fabric connector" in msg
    assert json.loads(audit.read_text().strip())["outcome"] == "http_408"


@respx.mock
async def test_c_408_through_the_relay_reports_status_body_and_hint():
    respx.get(BASE + V2).mock(return_value=_json(408, _408_BODY))
    resp = await _client().request("GET", V2, raise_on_error=False)
    assert resp.status_code == 408 and resp.json() == _408_BODY
    assert "HTTP 408 comes from the Fabric connector" in resp.extensions["unifi_auth_hint"]


def test_c_gateway_statuses_keep_their_outcome_clause_and_get_no_408_hint():
    assert route_hint(504, V2, "") == "" and route_hint(401, V2, "") == ""
    assert "Hint: HTTP 408" in route_hint(408, V2, "")


# =========================================================================== K: Retry-After
async def _sleeps(monkeypatch) -> list[float]:
    slept: list[float] = []

    async def _sleep(delay: float) -> None:
        slept.append(delay)

    monkeypatch.setattr("unifi_fabric.client.asyncio.sleep", _sleep)
    return slept


def test_k_parse_retry_after_seconds_dates_and_garbage():
    assert parse_retry_after("7") == 7.0
    assert parse_retry_after(" 0 ") == 0.0
    assert parse_retry_after("2.5") == 2.5
    assert parse_retry_after("86400") == 86400.0  # no cap
    now = datetime(2026, 11, 8, 12, 0, 0, tzinfo=UTC).timestamp()
    assert parse_retry_after("Sun, 08 Nov 2026 12:00:30 GMT", now=now) == 30.0
    assert parse_retry_after("Sun, 08 Nov 2026 11:00:00 GMT", now=now) == 0.0  # past date
    for bad in (None, "", "  ", "-3", "nan", "inf", "soon", "5 seconds", "Sun, 99 Foo 2026", 7):
        assert parse_retry_after(bad, now=now) is None, bad


@respx.mock
async def test_k_a_read_waits_the_retry_after_seconds_instead_of_the_backoff(monkeypatch):
    slept = await _sleeps(monkeypatch)
    route = respx.get(BASE + "/v1/x").mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "7"}),
            httpx.Response(429, headers={"Retry-After": "3"}),
            _json(200, {"ok": True}),
        ]
    )
    assert (await _client().get("/v1/x")) == {"ok": True}
    assert route.call_count == 3
    assert slept == [7.0, 3.0]  # exactly what the upstream asked, no extra backoff


@respx.mock
async def test_k_a_read_waits_until_an_http_date(monkeypatch):
    slept = await _sleeps(monkeypatch)
    monkeypatch.setattr("unifi_fabric.client.time.time", lambda: 1_794_139_200.0)
    when = datetime.fromtimestamp(1_794_139_200.0 + 42, tz=UTC).strftime(
        "%a, %d %b %Y %H:%M:%S GMT"
    )
    respx.get(BASE + "/v1/x").mock(
        side_effect=[httpx.Response(429, headers={"Retry-After": when}), _json(200, {})]
    )
    await _client().get("/v1/x")
    assert slept == [42.0]


@pytest.mark.parametrize("header", [None, "", "garbage", "-5", "nan"])
@respx.mock
async def test_k_without_a_usable_retry_after_the_backoff_is_unchanged(monkeypatch, header):
    slept = await _sleeps(monkeypatch)
    headers = {} if header is None else {"Retry-After": header}
    respx.get(BASE + "/v1/x").mock(
        side_effect=[
            httpx.Response(429, headers=headers),
            httpx.Response(429, headers=headers),
            _json(200, {}),
        ]
    )
    await _client().get("/v1/x")
    assert len(slept) == 2
    assert 1 <= slept[0] <= 2 and 2 <= slept[1] <= 4  # 2**attempt plus up to the same jitter


@respx.mock
async def test_k_the_final_read_429_surfaces_the_retry_after_after_the_verbatim_body(monkeypatch):
    await _sleeps(monkeypatch)
    respx.get(BASE + "/v1/x").mock(
        return_value=httpx.Response(
            429, json={"message": "slow down"}, headers={"Retry-After": "120"}
        )
    )
    with pytest.raises(RateLimitError) as exc:
        await _client().request("GET", "/v1/x", max_retries=1)
    assert 'HTTP 429: {"message": "slow down"}' in str(exc.value) or "slow down" in str(exc.value)
    assert str(exc.value).endswith("\nRetry-After: 120")


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
@respx.mock
async def test_k_a_write_stays_single_shot_and_reports_the_wait(monkeypatch, method):
    slept = await _sleeps(monkeypatch)
    route = respx.route(method=method, url=BASE + V2).mock(
        side_effect=[httpx.Response(429, headers={"Retry-After": "7"}), _json(200, {})]
    )
    with pytest.raises(RateLimitError) as exc:
        await _client().request(method, V2, json={"a": 1}, max_retries=3)
    assert route.call_count == 1 and slept == []
    assert "Retry-After: 7" in str(exc.value)


# =========================================================================== J: descriptions
@pytest.mark.parametrize("name", ["fabric_connector_put", "update_device_radio"])
async def test_j_device_settings_writes_say_they_can_restart_or_reprovision(name):
    from unifi_fabric import server

    tool = await server.mcp.get_tool(name)
    text = " ".join(tool.description.split())
    assert "restart or reprovision" in text, name


@respx.mock
async def test_k_a_retry_after_at_the_ceiling_is_slept_above_it_is_raised(monkeypatch):
    slept = await _sleeps(monkeypatch)
    route = respx.get(BASE + "/v1/x").mock(
        side_effect=[httpx.Response(429, headers={"Retry-After": "64"}), _json(200, {})]
    )
    await _client().get("/v1/x")
    assert slept == [64.0] and route.call_count == 2

    slept.clear()
    route = respx.get(BASE + "/v1/y").mock(
        return_value=httpx.Response(429, headers={"Retry-After": "86400"})
    )
    with pytest.raises(RateLimitError) as exc:
        await _client().get("/v1/y")
    assert slept == [] and route.call_count == 1  # never sleeps a day
    assert "Retry-After: 86400" in str(exc.value)
