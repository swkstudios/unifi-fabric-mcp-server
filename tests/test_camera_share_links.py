"""Camera-share cloud routes: pass-through, fail-fast and exposure safety."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest

from unifi_fabric import server
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.tools import protect

CAM = "0000000000000000000000aa"
PATH = f"/v1/connector/consoles/host-a/proxy/protect/api/cameras/{CAM}/sharedStream"
NAMES = ["get_camera_share_link", "enable_camera_share_link", "disable_camera_share_link"]
FIXTURES = Path(__file__).parent / "fixtures/recorded/protect"


@pytest.fixture
def registry():
    reg = AsyncMock()
    reg.resolve_key_for_host.return_value = None
    reg.resolve_host_id.return_value = "host-a"
    return reg


@pytest.mark.parametrize(
    "name,fixture",
    [
        ("get_camera_share_link", "share_get_off"),
        ("get_camera_share_link", "share_get_on"),
        ("enable_camera_share_link", "share_post_enable"),
        ("disable_camera_share_link", "share_delete_disable"),
    ],
)
async def test_recorded_pass_through(name, fixture, registry):
    recording = json.loads((FIXTURES / f"{fixture}.json").read_text())
    body = recording["body"]
    client = AsyncMock()
    client.get.return_value = body
    client.delete.return_value = body
    client.request.return_value = httpx.Response(200, json=body)
    result = await getattr(protect, name)(client, registry, "console", CAM)
    assert result == body
    registry.resolve_host_id.assert_awaited_once_with("console", key=None)
    if name == "enable_camera_share_link":
        client.request.assert_awaited_once_with("POST", PATH, key=None)
    elif name == "disable_camera_share_link":
        client.delete.assert_awaited_once_with(PATH, key=None)
    else:
        client.get.assert_awaited_once_with(PATH, key=None)


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("bad", ["", "../camera", "%2e%2e/camera", "camera\n", None])
async def test_invalid_camera_precedes_resolution(name, bad, registry):
    client = AsyncMock()
    with pytest.raises(ValueError):
        await getattr(protect, name)(client, registry, "console", bad)
    registry.resolve_key_for_host.assert_not_awaited()
    client.request.assert_not_awaited()
    client.get.assert_not_awaited()
    client.delete.assert_not_awaited()


@pytest.mark.parametrize("name", NAMES[1:])
async def test_protect_opt_out_before_resolution(name, registry, monkeypatch):
    monkeypatch.setenv("UNIFI_WRITE_EXCEPTIONS", "family:protect=deny")
    with pytest.raises(ValueError, match="family:protect=deny"):
        await getattr(protect, name)(AsyncMock(), registry, "console", CAM)
    registry.resolve_key_for_host.assert_not_awaited()


@pytest.mark.parametrize("name", NAMES)
async def test_owning_key_is_threaded(name, registry):
    owner = APIKeyConfig(label="owner", key="synthetic-share-key")
    registry.resolve_key_for_host.return_value = owner
    client = AsyncMock()
    client.request.return_value = httpx.Response(200, json={"enabled": True})
    await getattr(protect, name)(client, registry, "console", CAM)
    registry.resolve_host_id.assert_awaited_once_with("console", key=owner)
    call = client.get if name == NAMES[0] else client.request if name == NAMES[1] else client.delete
    assert call.await_args.kwargs["key"] is owner


@pytest.mark.parametrize("name", NAMES[1:])
@pytest.mark.parametrize("mode", ["dry_run", "read_only", "429"])
async def test_real_client_safety(name, mode, registry, monkeypatch):
    monkeypatch.delenv("UNIFI_WRITE_POLICY", raising=False)
    monkeypatch.delenv("UNIFI_WRITE_EXCEPTIONS", raising=False)
    if mode == "dry_run":
        monkeypatch.setenv("UNIFI_WRITE_POLICY", "dry-run")
    if mode == "read_only":
        monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    calls = []

    def upstream(request):
        calls.append(request)
        return httpx.Response(429 if mode == "429" else 200, json={"enabled": True})

    client = UniFiClient(Settings(api_key="synthetic-share-key"))
    # Inject a mock transport through the client's normal key-client seam.
    http = httpx.AsyncClient(base_url="https://api.ui.com", transport=httpx.MockTransport(upstream))
    client._get_client = AsyncMock(return_value=http)
    try:
        if mode == "read_only":
            with pytest.raises(Exception, match="UNIFI_WRITE_POLICY"):
                await getattr(protect, name)(client, registry, "console", CAM)
            assert calls == []
        elif mode == "dry_run":
            result = await getattr(protect, name)(client, registry, "console", CAM)
            assert result["status"] == "dry_run"
            assert calls == []
        else:
            with pytest.raises(Exception, match="429"):
                await getattr(protect, name)(client, registry, "console", CAM)
            assert len(calls) == 1
            assert calls[0].content == b""
    finally:
        await http.aclose()
        await client.close()


@pytest.mark.parametrize("name", NAMES)
async def test_mcp_tool_delegates_verbatim(name, registry, monkeypatch):
    client = AsyncMock()
    monkeypatch.setattr(server, "_client", client)
    monkeypatch.setattr(server, "_registry", registry)
    body = {"enabled": True, "shareLink": "<redacted>", "extra": {"kept": True}}
    helper = AsyncMock(return_value=body)
    monkeypatch.setattr(protect, name, helper)
    tool = await server.mcp.get_tool(name)
    assert await tool.fn("console", CAM) is body
    helper.assert_awaited_once_with(client, registry, "console", CAM)
