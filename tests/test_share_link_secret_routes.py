"""Protect share links are a registered secret route (``route_secrets.ROUTE_SECRETS``).

The share link (``shareLink`` in a body, or a redirect ``Location``) of
``protect/api/cameras/{id}/sharedStream`` may leave the server only in the verbatim
successful upstream body. Error bodies and raised messages mask it only with the
UNIFI_REDACT_SECRETS opt-in; log lines always mask it while preserving the rest of the
upstream text verbatim.
Driven through the MCP layer with a real client on a mock transport, for the typed tools
and the generic relay alike.
"""

from __future__ import annotations

import json
import logging
import secrets
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
from fastmcp.exceptions import ToolError

from tests import upstream_harness as uh
from unifi_fabric import route_secrets, server
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings

CAM = "0000000000000000000000aa"
ROUTE = f"protect/api/cameras/{CAM}/sharedStream"
MARKER = secrets.token_hex(16)
LINK = f"https://share.example.invalid/live/{MARKER}?token={MARKER[::-1]}"
REASON = "upstream-kept-reason-7f3a"
TYPED = {
    "get_camera_share_link": "GET",
    "enable_camera_share_link": "POST",
    "disable_camera_share_link": "DELETE",
}


def _texts(obj: Any) -> str:
    return json.dumps(obj, default=str)


def _response(status: int) -> httpx.Response:
    if 300 <= status < 400:
        return httpx.Response(status, headers={"Location": LINK}, text=REASON)
    return httpx.Response(status, json={"error": REASON, "shareLink": LINK, "enabled": True})


class _Upstream:
    def __init__(self, status_for: dict[str, int]) -> None:
        self.status_for = status_for
        self.calls: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        status = self.status_for.get(request.method, 200)
        if status == 200:
            return httpx.Response(200, json={"enabled": True, "shareLink": LINK, "cameraId": CAM})
        return _response(status)


@pytest.fixture
def wire(monkeypatch):
    def install(status_for: dict[str, int], **settings: Any) -> _Upstream:
        upstream = _Upstream(status_for)
        s = Settings(
            api_key="synthetic-share-key",
            **{k: v for k, v in settings.items() if k != "write_policy"},
        )
        client = UniFiClient(s)
        http = httpx.AsyncClient(base_url=s.api_base_url, transport=httpx.MockTransport(upstream))
        client._get_client = AsyncMock(return_value=http)
        registry = AsyncMock()
        registry.resolve_key_for_host.return_value = None
        registry.resolve_host_id.return_value = "host-a"
        monkeypatch.setattr(server, "_settings", s)
        monkeypatch.setattr(server, "_client", client)
        monkeypatch.setattr(server, "_registry", registry)
        monkeypatch.setattr(uh.asyncio, "sleep", uh._no_sleep)
        monkeypatch.delenv("UNIFI_WRITE_POLICY", raising=False)
        monkeypatch.delenv("UNIFI_WRITE_EXCEPTIONS", raising=False)
        if settings.get("write_policy"):
            monkeypatch.setenv("UNIFI_WRITE_POLICY", settings["write_policy"])
        return upstream

    return install


@pytest.fixture
def logs():
    lines: list[str] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            lines.append(self.format(record))

    handler = _Capture(level=logging.DEBUG)
    root = logging.getLogger()
    previous = root.level
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    try:
        yield lines
    finally:
        root.removeHandler(handler)
        root.setLevel(previous)


def _assert_masked(text: str) -> None:
    assert MARKER not in text and MARKER[::-1] not in text, text
    assert "***" in text, text


def test_share_route_is_registered_for_every_method():
    for method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
        for path in (ROUTE, f"/v1/connector/consoles/host-a/proxy/{ROUTE}?x=1"):
            entries = route_secrets.matching(method, path)
            assert [e.name for e in entries] == ["protect-share-link"], (method, path)
    entry = route_secrets.matching("GET", ROUTE)[0]
    assert "shareLink" in entry.response_fields
    assert "location" in entry.response_headers


@pytest.mark.parametrize("redact", [False, True])
@pytest.mark.parametrize("status", [302, 400, 429])
@pytest.mark.parametrize("name", sorted(TYPED))
async def test_typed_error_follows_opt_in(wire, logs, redact, name, status):
    up = wire({TYPED[name]: status}, redact_secrets=redact)
    with pytest.raises(ToolError) as info:
        await server.mcp.call_tool(name, {"host": "console", "camera_id": CAM})
    text = str(info.value)
    if redact:
        _assert_masked(text)
    else:
        assert MARKER in text
    assert str(status) in text
    assert REASON in text, "the rest of the upstream reason stays verbatim"
    assert MARKER not in "\n".join(logs)
    assert MARKER[::-1] not in "\n".join(logs)
    assert up.calls, "the upstream was reached"


async def test_typed_success_body_stays_verbatim(wire):
    wire({})
    res = await server.mcp.call_tool("get_camera_share_link", {"host": "console", "camera_id": CAM})
    payload = uh.result_payload(res)
    assert LINK in _texts(payload), "a successful share-link body is returned verbatim"


async def test_link_from_a_success_is_scrubbed_from_that_calls_logs(wire, logs, monkeypatch):
    wire({})
    real = server._client.request

    async def request(*args: Any, **kwargs: Any) -> Any:
        resp = await real(*args, **kwargs)
        logging.getLogger("unifi_fabric.test").warning("upstream said %s", resp.text)
        return resp

    monkeypatch.setattr(server._client, "request", request)
    await server.mcp.call_tool("enable_camera_share_link", {"host": "console", "camera_id": CAM})
    joined = "\n".join(line for line in logs if "upstream said" in line)
    assert joined, logs
    _assert_masked(joined)


@pytest.mark.parametrize("redact", [False, True])
@pytest.mark.parametrize("status", [302, 400])
@pytest.mark.parametrize(
    "tool,method",
    [
        ("fabric_connector_post", "POST"),
        ("fabric_connector_delete", "DELETE"),
        ("fabric_connector_get", "GET"),
    ],
)
async def test_relay_non_2xx_follows_opt_in(wire, logs, redact, tool, method, status):
    wire({method: status}, redact_secrets=redact)
    res = await server.mcp.call_tool(tool, {"host": "console", "path": ROUTE})
    payload = uh.result_payload(res)
    text = _texts({"body": payload["body"], "headers": payload.get("headers")})
    if redact:
        _assert_masked(text)
    else:
        assert MARKER in text
    assert REASON in text
    assert MARKER not in "\n".join(logs)
    assert MARKER[::-1] not in "\n".join(logs)


async def test_relay_dry_run_read_before_masks_the_link(wire, logs):
    up = wire({}, write_policy="dry-run", redact_secrets=True)
    res = await server.mcp.call_tool("fabric_connector_delete", {"host": "console", "path": ROUTE})
    payload = uh.result_payload(res)
    assert payload["status"] == "dry_run"
    before = payload["readBefore"]
    assert before["status"] == 200
    assert before["body"]["shareLink"] == route_secrets.MASK
    assert before["body"]["enabled"] is True and before["body"]["cameraId"] == CAM
    assert MARKER not in _texts(payload)
    assert [c.method for c in up.calls] == ["GET"], "dry-run sends no DELETE"
    assert MARKER not in "\n".join(logs)
    assert MARKER[::-1] not in "\n".join(logs)


async def test_relay_real_delete_read_before_is_verbatim_success(wire):
    wire({})
    res = await server.mcp.call_tool("fabric_connector_delete", {"host": "console", "path": ROUTE})
    payload = uh.result_payload(res)
    assert payload["status"] == 200
    assert payload["body"]["shareLink"] == LINK, "the write's own 2xx body stays verbatim"
    for twin in ("readBefore", "readAfter"):
        assert payload[twin]["body"]["shareLink"] == LINK, twin
        assert payload[twin]["body"]["cameraId"] == CAM


async def test_relay_get_success_body_stays_verbatim(wire):
    wire({})
    res = await server.mcp.call_tool("fabric_connector_get", {"host": "console", "path": ROUTE})
    assert uh.result_payload(res)["body"]["shareLink"] == LINK


async def test_relay_dry_run_preview_masks_a_share_link_body(wire, logs):
    up = wire({}, write_policy="dry-run", redact_secrets=True)
    res = await server.mcp.call_tool(
        "fabric_connector_post", {"host": "console", "path": ROUTE, "body": {"shareLink": LINK}}
    )
    payload = uh.result_payload(res)
    assert payload["status"] == "dry_run"
    assert MARKER not in _texts(payload)
    assert up.calls == []
    assert MARKER not in "\n".join(logs)
    assert MARKER[::-1] not in "\n".join(logs)
