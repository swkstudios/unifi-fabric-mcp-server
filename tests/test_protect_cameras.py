"""Unit tests for Protect camera operations — list, get, update, snapshot,
talkback, mic-disable, PTZ, and RTSPS stream GET."""

from __future__ import annotations

import base64
from unittest.mock import AsyncMock

import pytest

from unifi_fabric.tools.protect import (
    PROTECT_PROXY_BASE,
    disable_mic_permanently,
    get_camera,
    get_camera_snapshot,
    get_rtsps_stream,
    list_cameras,
    ptz_goto,
    ptz_patrol_start,
    ptz_patrol_stop,
    talkback_start,
    update_camera,
)

HOST_ID = "host-abc"
BASE = PROTECT_PROXY_BASE.format(host_id=HOST_ID)


@pytest.fixture()
def client():
    c = AsyncMock()
    c.get = AsyncMock()
    c.get_bytes = AsyncMock()
    c.post = AsyncMock()
    c.patch = AsyncMock()
    c.delete = AsyncMock()
    return c


@pytest.fixture()
def registry():
    r = AsyncMock()
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    return r


# --- list_cameras ---


class TestListCameras:
    async def test_list_returns_dict(self, client, registry):
        client.get.return_value = [{"id": "cam-1", "name": "Front Door"}]
        result = await list_cameras(client, registry, "myhost")
        client.get.assert_called_once_with(f"{BASE}/cameras")
        assert result == {"cameras": [{"id": "cam-1", "name": "Front Door"}], "count": 1}

    async def test_data_wrapper(self, client, registry):
        client.get.return_value = {"data": [{"id": "cam-2"}, {"id": "cam-3"}]}
        result = await list_cameras(client, registry, "myhost")
        assert result["count"] == 2
        assert len(result["cameras"]) == 2

    async def test_empty_list(self, client, registry):
        client.get.return_value = []
        result = await list_cameras(client, registry, "myhost")
        assert result == {"cameras": [], "count": 0}

    async def test_resolves_host(self, client, registry):
        client.get.return_value = []
        await list_cameras(client, registry, "MyHost")
        registry.resolve_host_id.assert_called_once_with("MyHost")


# --- get_camera ---


class TestGetCamera:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "cam-1", "state": "CONNECTED"}
        result = await get_camera(client, registry, "h", "cam-1")
        client.get.assert_called_once_with(f"{BASE}/cameras/cam-1")
        assert result["id"] == "cam-1"
        assert result["state"] == "CONNECTED"

    async def test_non_dict_wrapped(self, client, registry):
        client.get.return_value = ["raw"]
        result = await get_camera(client, registry, "h", "cam-1")
        assert result == {"data": ["raw"]}

    async def test_resolves_host(self, client, registry):
        client.get.return_value = {"id": "cam-1"}
        await get_camera(client, registry, "myhost", "cam-1")
        registry.resolve_host_id.assert_called_once_with("myhost")


# --- update_camera ---


class TestUpdateCamera:
    async def test_basic(self, client, registry):
        client.patch.return_value = {"id": "cam-1", "name": "Backyard"}
        result = await update_camera(client, registry, "h", "cam-1", name="Backyard")
        client.patch.assert_called_once_with(f"{BASE}/cameras/cam-1", json={"name": "Backyard"})
        assert result["name"] == "Backyard"

    async def test_multiple_fields(self, client, registry):
        client.patch.return_value = {"id": "cam-1", "name": "Gate", "recordingMode": "always"}
        result = await update_camera(
            client, registry, "h", "cam-1", name="Gate", recordingMode="always"
        )
        call_json = client.patch.call_args[1]["json"]
        assert call_json["name"] == "Gate"
        assert call_json["recordingMode"] == "always"
        assert result["recordingMode"] == "always"

    async def test_non_dict_wrapped(self, client, registry):
        client.patch.return_value = None
        result = await update_camera(client, registry, "h", "cam-1", name="X")
        assert result == {"data": None}


# --- get_camera_snapshot ---


class TestGetCameraSnapshot:
    async def test_basic(self, client, registry):
        jpeg_bytes = b"\xff\xd8\xff\xe0" + b"\x00" * 16
        client.get_bytes.return_value = jpeg_bytes
        result = await get_camera_snapshot(client, registry, "h", "cam-1")
        client.get_bytes.assert_called_once_with(f"{BASE}/cameras/cam-1/snapshot")
        assert result["image_base64"] == base64.b64encode(jpeg_bytes).decode()
        assert result["content_type"] == "image/jpeg"
        assert result["size_bytes"] == len(jpeg_bytes)

    async def test_resolves_host(self, client, registry):
        client.get_bytes.return_value = b"\xff\xd8\xff"
        await get_camera_snapshot(client, registry, "console-1", "cam-99")
        registry.resolve_host_id.assert_called_once_with("console-1")


# --- get_rtsps_stream ---


class TestGetRtspsStream:
    async def test_basic(self, client, registry):
        client.get.return_value = {"url": "rtsps://192.168.1.1/stream"}
        result = await get_rtsps_stream(client, registry, "h", "cam-1")
        client.get.assert_called_once_with(f"{BASE}/cameras/cam-1/rtsps-stream")
        assert result["url"].startswith("rtsps://")

    async def test_non_dict_wrapped(self, client, registry):
        client.get.return_value = None
        result = await get_rtsps_stream(client, registry, "h", "cam-1")
        assert result == {"data": None}


# --- talkback_start ---


class TestTalkbackStart:
    async def test_basic(self, client, registry):
        client.post.return_value = {"sessionId": "sess-1", "status": "started"}
        result = await talkback_start(client, registry, "h", "cam-1")
        client.post.assert_called_once_with(f"{BASE}/cameras/cam-1/talkback-session", json={})
        assert result["status"] == "started"

    async def test_non_dict_fallback(self, client, registry):
        client.post.return_value = None
        result = await talkback_start(client, registry, "h", "cam-1")
        assert result == {"status": "ok"}

    async def test_resolves_host(self, client, registry):
        client.post.return_value = {"status": "ok"}
        await talkback_start(client, registry, "console-x", "cam-5")
        registry.resolve_host_id.assert_called_once_with("console-x")


# --- disable_mic_permanently ---


class TestDisableMicPermanently:
    async def test_basic(self, client, registry):
        client.post.return_value = {"micDisabled": True}
        result = await disable_mic_permanently(client, registry, "h", "cam-1")
        client.post.assert_called_once_with(
            f"{BASE}/cameras/cam-1/disable-mic-permanently", json={}
        )
        assert result["micDisabled"] is True

    async def test_non_dict_fallback(self, client, registry):
        client.post.return_value = None
        result = await disable_mic_permanently(client, registry, "h", "cam-1")
        assert result == {"status": "ok"}

    async def test_resolves_host(self, client, registry):
        client.post.return_value = {"status": "ok"}
        await disable_mic_permanently(client, registry, "console-y", "cam-7")
        registry.resolve_host_id.assert_called_once_with("console-y")


# --- ptz_goto ---


class TestPtzGoto:
    async def test_basic(self, client, registry):
        client.post.return_value = {"status": "moving"}
        result = await ptz_goto(client, registry, "h", "cam-1", 2)
        client.post.assert_called_once_with(f"{BASE}/cameras/cam-1/ptz/goto/2", json={})
        assert result["status"] == "moving"

    async def test_slot_zero(self, client, registry):
        client.post.return_value = {"status": "ok"}
        result = await ptz_goto(client, registry, "h", "cam-1", 0)
        client.post.assert_called_once_with(f"{BASE}/cameras/cam-1/ptz/goto/0", json={})
        assert result == {"status": "ok"}

    async def test_non_dict_fallback(self, client, registry):
        client.post.return_value = None
        result = await ptz_goto(client, registry, "h", "cam-1", 1)
        assert result == {"status": "ok"}

    async def test_resolves_host(self, client, registry):
        client.post.return_value = {"status": "ok"}
        await ptz_goto(client, registry, "ptz-console", "cam-ptz", 3)
        registry.resolve_host_id.assert_called_once_with("ptz-console")


# --- ptz_patrol_start ---


class TestPtzPatrolStart:
    async def test_basic(self, client, registry):
        client.post.return_value = {"patrolling": True}
        result = await ptz_patrol_start(client, registry, "h", "cam-1", 1)
        client.post.assert_called_once_with(f"{BASE}/cameras/cam-1/ptz/patrol/start/1", json={})
        assert result["patrolling"] is True

    async def test_non_dict_fallback(self, client, registry):
        client.post.return_value = None
        result = await ptz_patrol_start(client, registry, "h", "cam-1", 0)
        assert result == {"status": "ok"}


# --- ptz_patrol_stop ---


class TestPtzPatrolStop:
    async def test_basic(self, client, registry):
        client.post.return_value = {"patrolling": False}
        result = await ptz_patrol_stop(client, registry, "h", "cam-1")
        client.post.assert_called_once_with(f"{BASE}/cameras/cam-1/ptz/patrol/stop", json={})
        assert result["patrolling"] is False

    async def test_non_dict_fallback(self, client, registry):
        client.post.return_value = None
        result = await ptz_patrol_stop(client, registry, "h", "cam-1")
        assert result == {"status": "ok"}

    async def test_resolves_host(self, client, registry):
        client.post.return_value = {"status": "ok"}
        await ptz_patrol_stop(client, registry, "console-z", "cam-ptz")
        registry.resolve_host_id.assert_called_once_with("console-z")
