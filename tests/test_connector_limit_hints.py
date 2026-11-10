"""The Fabric connector's documented limits, as hints beside verbatim upstream errors.

The pinned Site Manager spec (tests/fixtures/openapi/site-manager-1.0.0.json, the five
``/v1/connector/consoles/{id}/*path`` verbs) documents four limits: each proxied request
must complete within 25 seconds (HTTP 408), each console is limited to 100 requests per
minute (HTTP 429), the upstream response body is limited to 10 MB, and the console firmware
must be 5.0.3 or later. A connector error that matches one gets an actionable hint; the
upstream status and body stay verbatim and nothing is retried or rewritten.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from unifi_fabric.client import (
    RateLimitError,
    UniFiClient,
    UniFiHTTPError,
    connector_rate_hint,
    is_connector_route,
    route_hint,
)
from unifi_fabric.config import Settings

BASE = "https://api.ui.com"
CONNECTOR = "/v1/connector/consoles/h1/proxy/network/integration/v1/sites"
SPEC = Path(__file__).parent / "fixtures" / "openapi" / "site-manager-1.0.0.json"
VERBS = ("get", "post", "put", "patch", "delete")


@pytest.fixture(autouse=True)
def _quiet_logs():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    async def _sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr("unifi_fabric.client.asyncio.sleep", _sleep)


def _client() -> UniFiClient:
    return UniFiClient(Settings(api_key="probe-key-1", api_base_url=BASE))


def _json(status: int, body: Any, **headers: str) -> httpx.Response:
    return httpx.Response(
        status,
        content=json.dumps(body, separators=(",", ":")).encode(),
        headers={"content-type": "application/json", **headers},
    )


# --- the spec is the source of every hint ------------------------------------------------
def test_the_pinned_spec_documents_each_limit_on_every_connector_verb():
    paths = json.loads(SPEC.read_text())["paths"]["/v1/connector/consoles/{id}/*path"]
    for verb in VERBS:
        op = paths[verb]
        text = op["description"]
        assert "within 25 seconds" in text, verb
        assert "100 requests per minute" in text, verb
        assert "limited to 10 MB" in text, verb
        assert "firmware version must >= 5.0.3" in text, verb
        assert {"408", "429", "502"} <= set(op["responses"]), verb
        assert "Retry-After" in op["responses"]["429"]["headers"], verb


def test_connector_routes_are_recognised_by_prefix_only():
    assert is_connector_route(CONNECTOR)
    for other in ("/v1/hosts", "/ea/hosts", "/v1/connector/consoles", None, 7):
        assert not is_connector_route(other), other


# --- 408: the 25 second limit, an offline console, firmware below 5.0.3 --------------------
@respx.mock
async def test_408_names_the_25_second_limit_and_the_firmware_minimum():
    body = {"code": "request_timeout", "httpStatusCode": 408, "message": "Request Timeout"}
    respx.get(BASE + CONNECTOR).mock(return_value=_json(408, body))
    with pytest.raises(UniFiHTTPError) as exc:
        await _client().get(CONNECTOR)
    msg = str(exc.value)
    assert msg.startswith(
        f"HTTP 408 from GET {CONNECTOR}: " + json.dumps(body, separators=(",", ":"))
    )
    assert "limit of 25 seconds" in msg and "minimum of 5.0.3" in msg
    assert "offline or restarting" in msg and "smaller window or page size" in msg


# --- 429: 100 requests per minute per console -------------------------------------------
@respx.mock
async def test_429_on_a_connector_read_names_the_per_console_limit_after_the_body():
    body = {"code": "rate_limited", "httpStatusCode": 429, "message": "Too Many Requests"}
    route = respx.get(BASE + CONNECTOR).mock(return_value=_json(429, body, **{"Retry-After": "3"}))
    with pytest.raises(RateLimitError) as exc:
        await _client().request("GET", CONNECTOR, max_retries=1)
    msg = str(exc.value)
    assert route.call_count == 2
    assert f"HTTP 429: {json.dumps(body, separators=(',', ':'))}\nHint: " in msg  # body first
    assert "100 requests per minute" in msg
    assert msg.endswith("\nRetry-After: 3")


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
@respx.mock
async def test_429_on_a_connector_write_names_the_limit_and_is_sent_once(method):
    route = respx.route(method=method, url=BASE + CONNECTOR).mock(
        side_effect=[_json(429, {"message": "slow"}), _json(200, {})]
    )
    with pytest.raises(RateLimitError) as exc:
        await _client().request(method, CONNECTOR, json={"a": 1})
    assert route.call_count == 1
    assert '{"message":"slow"}' in str(exc.value) and "100 requests per minute" in str(exc.value)


@respx.mock
async def test_429_off_the_connector_gets_no_limit_hint():
    respx.get(BASE + "/v1/hosts").mock(return_value=_json(429, {"message": "slow"}))
    with pytest.raises(RateLimitError) as exc:
        await _client().request("GET", "/v1/hosts", max_retries=0)
    assert "100 requests" not in str(exc.value) and "Hint" not in str(exc.value)
    assert connector_rate_hint("/v1/hosts") == ""


# --- 502: a console that cannot answer, or a response over the 10 MB limit ------------------
@respx.mock
async def test_502_on_a_connector_read_names_the_10_mb_limit_after_the_body():
    body = {"message": "Bad Gateway"}
    route = respx.get(BASE + CONNECTOR).mock(return_value=_json(502, body))
    with pytest.raises(UniFiHTTPError) as exc:
        await _client().get(CONNECTOR)
    msg = str(exc.value)
    assert route.call_count == 1 and exc.value.status == 502
    assert msg.startswith(
        f"HTTP 502 from GET {CONNECTOR}: " + json.dumps(body, separators=(",", ":"))
    )
    assert "10 MB" in msg and "smaller window or page size" in msg
    assert "outcome unknown" not in msg


@respx.mock
async def test_502_on_a_connector_write_keeps_the_outcome_clause_then_the_hint():
    route = respx.post(BASE + CONNECTOR).mock(return_value=_json(502, {"message": "Bad Gateway"}))
    with pytest.raises(UniFiHTTPError) as exc:
        await _client().post(CONNECTOR, json={"a": 1})
    msg = str(exc.value)
    assert route.call_count == 1  # never retried
    assert "outcome unknown: the write may have been applied; it was not retried" in msg
    assert msg.index("outcome unknown") < msg.index("10 MB")


@respx.mock
async def test_502_and_504_off_the_connector_or_other_statuses_get_no_10_mb_hint():
    respx.get(BASE + "/v1/hosts").mock(return_value=_json(502, {"message": "x"}))
    with pytest.raises(UniFiHTTPError) as exc:
        await _client().get("/v1/hosts")
    assert "10 MB" not in str(exc.value)
    assert route_hint(504, CONNECTOR, "") == "" and route_hint(500, CONNECTOR, "") == ""


@respx.mock
async def test_the_relay_gets_the_connector_hints_as_hint_beside_status_and_body():
    respx.get(BASE + CONNECTOR).mock(return_value=_json(502, {"message": "Bad Gateway"}))
    resp = await _client().request("GET", CONNECTOR, raise_on_error=False)
    assert resp.status_code == 502 and resp.json() == {"message": "Bad Gateway"}
    assert "10 MB" in resp.extensions["unifi_auth_hint"]


# --- the relay tool descriptions state the limits ------------------------------------------
@pytest.mark.parametrize("verb", ["get", "post", "delete"])
async def test_relay_descriptions_state_the_limits(verb):
    from unifi_fabric import server

    tool = await server.mcp.get_tool(f"fabric_connector_{verb}")
    text = " ".join(tool.description.split())
    for part in (
        "25 s/request",
        "100 requests/min/console",
        "10 MB response body",
        "5.0.3",
        "Site Manager spec",
    ):
        assert part in text, (verb, part)
    assert len(tool.description) < 2048


@pytest.mark.parametrize("verb", ["put", "patch"])
async def test_write_relay_descriptions_point_at_the_limits(verb):
    from unifi_fabric import server

    tool = await server.mcp.get_tool(f"fabric_connector_{verb}")
    assert "limits: see fabric_connector_get" in " ".join(tool.description.split())
    assert len(tool.description) < 2048


def test_route_hint_keeps_the_stats_hint_and_408_distinct():
    assert "25 seconds" in route_hint(408, CONNECTOR, "")
    assert route_hint(404, CONNECTOR, "<html>") == ""
