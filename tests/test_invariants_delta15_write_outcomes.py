"""Every catalog write keeps an uncertain outcome visible and is sent exactly once.

A write answered by a gateway status (502/503/504) or failing in transport after it was
sent may have been applied. The tool returns (or raises with) the upstream status and
body verbatim plus an appended warning: the outcome is unknown, the write was not
retried, and the read tool that verifies it. A failure before send (connect, pool,
local protocol) is not reported as unknown, and a read-POST query is not a write.
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx
import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import upstream_harness as uh
from tests._tool_classes import class_axis
from unifi_fabric.client import UniFiConnectionError, unknown_outcome_hint

REASON = json.dumps({"message": "gateway reason " + "unabridged " * 700, "traceId": "probe"})
FAILURES: list[int | type[httpx.HTTPError]] = [
    502,
    503,
    504,
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.ReadError,
    httpx.WriteError,
    httpx.RemoteProtocolError,
]
NOT_SENT: list[type[httpx.HTTPError]] = [
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.PoolTimeout,
    httpx.ProxyError,
    httpx.UnsupportedProtocol,
    httpx.LocalProtocolError,
]
WARNING = "outcome unknown: the write may have been applied; it was not retried"
TOOL_NAME = re.compile(r"\b(?:fabric_connector_get|(?:get|list)_[a-z0-9_]+[a-z0-9])\b")
RELAY = f"/v1/connector/consoles/{uh.HOST_ID}/proxy/network/api/s/default/rest/probe"


class UncertainUpstream(uh.FakeUpstream):
    """Fails the first non-GET or state-changing GET (a status or an exception); reads are
    served normally."""

    def __init__(self, failure: int | type[httpx.HTTPError]):
        super().__init__()
        self.failure = failure

    def __call__(self, req: httpx.Request) -> httpx.Response:
        if req.method != "GET" or uh.is_write_request(
            req.method, req.url.path, uh.request_json(req)
        ):
            self._record(req, self.failure if isinstance(self.failure, int) else 0, REASON, False)
            if isinstance(self.failure, int):
                return httpx.Response(
                    self.failure, content=REASON, headers={"content-type": "application/json"}
                )
            raise self.failure("probe failure", request=req)
        return super().__call__(req)


def _named_read_tools_exist(text: str) -> None:
    hint = text[text.index(WARNING) :]
    named = set(TOOL_NAME.findall(hint))
    assert named, hint
    assert named <= set(cti.TOOLS), sorted(named - set(cti.TOOLS))


@class_axis("name", lambda: sorted(cti.TOOLS), failure=lambda: FAILURES)
async def test_catalog_uncertain_write(monkeypatch: Any, name: str, failure: Any) -> None:
    up = UncertainUpstream(failure)
    try:
        result = await cti._call(monkeypatch, name, up)
        payload = uh.result_payload(result)
        text = uh.all_strings(payload)
    except ToolError as exc:
        payload = None
        text = str(exc)
    sent = [
        entry
        for entry in up.served
        if entry.method != "GET" or uh.is_write_request(entry.method, entry.path, entry.sent_json)
    ]
    if not sent:
        # Read tools have no non-GET route; every write tool must reach its write.
        assert name not in cti.WRITE_TOOLS, name
        return
    assert len(sent) == 1, (name, sent)
    if name not in cti.WRITE_TOOLS:
        # A read-POST query (Classic stat/*, ISP metrics) changes nothing upstream.
        assert WARNING not in text, (name, text)
        return
    assert WARNING in text, (name, text)
    _named_read_tools_exist(text)
    if isinstance(failure, int):
        assert REASON in text or uh.contains_record(payload, json.loads(REASON)), (name, text)
        assert str(failure) in text, (name, text)


@pytest.mark.parametrize("verb", ["POST", "PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize("failure", FAILURES)
@pytest.mark.parametrize("raise_on_error", [True, False])
async def test_client_uncertain_outcome_response_modes(
    monkeypatch: Any, verb: str, failure: Any, raise_on_error: bool
) -> None:
    up = UncertainUpstream(failure)
    client = uh.install(monkeypatch, up)
    try:
        if not raise_on_error and isinstance(failure, int):
            response = await client.request(verb, RELAY, raise_on_error=False, max_retries=5)
            assert response.status_code == failure
            assert response.text == REASON
            message = response.extensions["unifi_auth_hint"]
            assert message.startswith("outcome unknown"), message
        else:
            with pytest.raises(UniFiConnectionError) as error:
                await client.request(verb, RELAY, raise_on_error=raise_on_error, max_retries=5)
            message = str(error.value)
            if isinstance(failure, int):
                assert f"HTTP {failure}" in message and REASON in message
        assert WARNING in message
        assert f"fabric_connector_get on console {uh.HOST_ID}" in message
        assert "GET network/api/s/default/rest/probe" in message
        assert len(up.served) == 1
    finally:
        await client.close()


@pytest.mark.parametrize("failure", [*FAILURES, 500])
async def test_get_is_never_reported_unknown(monkeypatch: Any, failure: Any) -> None:
    class FailingReads(uh.FakeUpstream):
        def __call__(self, req: httpx.Request) -> httpx.Response:
            self._record(req, failure if isinstance(failure, int) else 0, REASON, False)
            if isinstance(failure, int):
                return httpx.Response(failure, content=REASON)
            raise failure("probe failure", request=req)

    client = uh.install(monkeypatch, FailingReads())
    try:
        with pytest.raises(UniFiConnectionError) as error:
            await client.request("GET", RELAY, max_retries=0)
        assert "outcome unknown" not in str(error.value)
    finally:
        await client.close()


@pytest.mark.parametrize("status", [400, 404, 409, 500])
async def test_definite_write_errors_are_not_reported_unknown(monkeypatch: Any, status: int):
    client = uh.install(monkeypatch, UncertainUpstream(status))
    try:
        with pytest.raises(UniFiConnectionError) as error:
            await client.request("POST", RELAY)
        assert "outcome unknown" not in str(error.value)
        assert REASON in str(error.value)
    finally:
        await client.close()


@pytest.mark.parametrize("failure", NOT_SENT)
async def test_before_send_transport_is_not_reported_unknown(
    monkeypatch: Any, failure: Any
) -> None:
    up = UncertainUpstream(failure)
    client = uh.install(monkeypatch, up)
    try:
        with pytest.raises(UniFiConnectionError) as error:
            await client.request("POST", RELAY)
        assert "outcome unknown" not in str(error.value)
        assert len(up.served) == 1
    finally:
        await client.close()


@pytest.mark.parametrize(
    ("path", "tools"),
    [
        ("/v1/carrier/subscribers/x", {"list_carrier_subscribers", "list_carrier_service_plans"}),
        ("/v1/mobility/devices/x", {"list_mobility_devices", "list_mobility_workspaces"}),
        (RELAY, {"fabric_connector_get"}),
        ("/ea/sites/site-id/rest/firewallrule", {"list_firewall_rules"}),
    ],
)
def test_every_named_verify_tool_is_in_the_catalog(path: str, tools: set[str]) -> None:
    hint = unknown_outcome_hint(path)
    assert set(TOOL_NAME.findall(hint)) == tools
    assert tools <= set(cti.TOOLS)
