"""Tests for non-camera Protect tools — sensors, lights, chimes, viewers, liveviews,
NVR, alarm webhook, and RTSPS stream management."""

from __future__ import annotations

import base64
from unittest.mock import AsyncMock

import pytest

from unifi_fabric.tools.protect import (
    PROTECT_PROXY_BASE,
    create_liveview,
    create_rtsps_stream,
    delete_rtsps_stream,
    get_chime,
    get_light,
    get_liveview,
    get_nvr,
    get_sensor,
    get_viewer,
    list_chimes,
    list_lights,
    list_liveviews,
    list_protect_files,
    list_sensors,
    list_viewers,
    trigger_alarm_webhook,
    update_chime,
    update_light,
    update_liveview,
    update_sensor,
    update_viewer,
    upload_protect_file,
)

HOST_ID = "host-001"
BASE = PROTECT_PROXY_BASE.format(host_id=HOST_ID)


@pytest.fixture()
def client():
    c = AsyncMock()
    c.get = AsyncMock()
    c.post = AsyncMock()
    c.post_multipart = AsyncMock()
    c.patch = AsyncMock()
    c.delete = AsyncMock()
    return c


@pytest.fixture()
def registry():
    r = AsyncMock()
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    return r


# --- Sensors ---


class TestListSensors:
    async def test_list_returns_dict(self, client, registry):
        client.get.return_value = [{"id": "sen-1", "type": "motion"}]
        result = await list_sensors(client, registry, "myhost")
        client.get.assert_called_once_with(f"{BASE}/sensors")
        assert result == {"sensors": [{"id": "sen-1", "type": "motion"}], "count": 1}

    async def test_data_wrapper(self, client, registry):
        client.get.return_value = {"data": [{"id": "sen-2"}]}
        result = await list_sensors(client, registry, "myhost")
        assert result["count"] == 1

    async def test_resolves_host(self, client, registry):
        client.get.return_value = []
        await list_sensors(client, registry, "MyHost")
        registry.resolve_host_id.assert_called_once_with("MyHost")


class TestGetSensor:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "sen-1", "state": "open"}
        result = await get_sensor(client, registry, "h", "sen-1")
        client.get.assert_called_once_with(f"{BASE}/sensors/sen-1")
        assert result["id"] == "sen-1"

    async def test_non_dict_wrapped(self, client, registry):
        client.get.return_value = ["raw"]
        result = await get_sensor(client, registry, "h", "sen-1")
        assert result == {"data": ["raw"]}


class TestUpdateSensor:
    async def test_basic(self, client, registry):
        client.patch.return_value = {"id": "sen-1", "name": "Door"}
        result = await update_sensor(client, registry, "h", "sen-1", name="Door")
        client.patch.assert_called_once_with(f"{BASE}/sensors/sen-1", json={"name": "Door"})
        assert result["name"] == "Door"


# --- Lights ---


class TestListLights:
    async def test_list_returns_dict(self, client, registry):
        client.get.return_value = [{"id": "lt-1"}]
        result = await list_lights(client, registry, "h")
        client.get.assert_called_once_with(f"{BASE}/lights")
        assert result == {"lights": [{"id": "lt-1"}], "count": 1}

    async def test_data_wrapper(self, client, registry):
        client.get.return_value = {"data": [{"id": "lt-2"}, {"id": "lt-3"}]}
        result = await list_lights(client, registry, "h")
        assert result["count"] == 2


class TestGetLight:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "lt-1", "on": True}
        result = await get_light(client, registry, "h", "lt-1")
        client.get.assert_called_once_with(f"{BASE}/lights/lt-1")
        assert result["id"] == "lt-1"


class TestUpdateLight:
    async def test_basic(self, client, registry):
        client.patch.return_value = {"id": "lt-1", "brightness": 80}
        result = await update_light(client, registry, "h", "lt-1", brightness=80)
        client.patch.assert_called_once_with(f"{BASE}/lights/lt-1", json={"brightness": 80})
        assert result["brightness"] == 80


# --- Chimes ---


class TestListChimes:
    async def test_basic(self, client, registry):
        client.get.return_value = [{"id": "ch-1"}]
        result = await list_chimes(client, registry, "h")
        client.get.assert_called_once_with(f"{BASE}/chimes")
        assert result == {"chimes": [{"id": "ch-1"}], "count": 1}

    async def test_data_wrapper(self, client, registry):
        client.get.return_value = {"data": [{"id": "ch-2"}]}
        result = await list_chimes(client, registry, "h")
        assert result["count"] == 1


class TestGetChime:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "ch-1", "volume": 70}
        result = await get_chime(client, registry, "h", "ch-1")
        client.get.assert_called_once_with(f"{BASE}/chimes/ch-1")
        assert result["id"] == "ch-1"


class TestUpdateChime:
    async def test_basic(self, client, registry):
        client.patch.return_value = {"id": "ch-1", "volume": 50}
        result = await update_chime(client, registry, "h", "ch-1", volume=50)
        client.patch.assert_called_once_with(f"{BASE}/chimes/ch-1", json={"volume": 50})
        assert result["volume"] == 50


# --- Viewers ---


class TestListViewers:
    async def test_basic(self, client, registry):
        client.get.return_value = [{"id": "vw-1"}]
        result = await list_viewers(client, registry, "h")
        client.get.assert_called_once_with(f"{BASE}/viewers")
        assert result == {"viewers": [{"id": "vw-1"}], "count": 1}

    async def test_data_wrapper(self, client, registry):
        client.get.return_value = {"data": [{"id": "vw-2"}, {"id": "vw-3"}]}
        result = await list_viewers(client, registry, "h")
        assert result["count"] == 2


class TestGetViewer:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "vw-1", "liveview": "lv-1"}
        result = await get_viewer(client, registry, "h", "vw-1")
        client.get.assert_called_once_with(f"{BASE}/viewers/vw-1")
        assert result["id"] == "vw-1"


class TestUpdateViewer:
    async def test_basic(self, client, registry):
        client.patch.return_value = {"id": "vw-1", "liveview": "lv-2"}
        result = await update_viewer(client, registry, "h", "vw-1", liveview="lv-2")
        client.patch.assert_called_once_with(f"{BASE}/viewers/vw-1", json={"liveview": "lv-2"})
        assert result["liveview"] == "lv-2"


# --- Liveviews ---


class TestListLiveviews:
    async def test_basic(self, client, registry):
        client.get.return_value = [{"id": "lv-1", "name": "Main View"}]
        result = await list_liveviews(client, registry, "h")
        client.get.assert_called_once_with(f"{BASE}/liveviews")
        assert result == {"liveviews": [{"id": "lv-1", "name": "Main View"}], "count": 1}

    async def test_data_wrapper(self, client, registry):
        client.get.return_value = {"data": [{"id": "lv-2"}]}
        result = await list_liveviews(client, registry, "h")
        assert result["count"] == 1


class TestGetLiveview:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "lv-1", "name": "Lobby"}
        result = await get_liveview(client, registry, "h", "lv-1")
        client.get.assert_called_once_with(f"{BASE}/liveviews/lv-1")
        assert result["id"] == "lv-1"


class TestCreateLiveview:
    async def test_basic(self, client, registry):
        client.post.return_value = {"id": "lv-2", "name": "New View"}
        result = await create_liveview(client, registry, "h", "New View")
        client.post.assert_called_once_with(f"{BASE}/liveviews", json={"name": "New View"})
        assert result["name"] == "New View"

    async def test_extra_fields(self, client, registry):
        client.post.return_value = {"id": "lv-3"}
        await create_liveview(client, registry, "h", "Cameras", slots=4)
        call_json = client.post.call_args[1]["json"]
        assert call_json["name"] == "Cameras"
        assert call_json["slots"] == 4


class TestUpdateLiveview:
    async def test_basic(self, client, registry):
        client.patch.return_value = {"id": "lv-1", "name": "Updated"}
        result = await update_liveview(client, registry, "h", "lv-1", name="Updated")
        client.patch.assert_called_once_with(f"{BASE}/liveviews/lv-1", json={"name": "Updated"})
        assert result["name"] == "Updated"


# --- NVR ---


class TestGetNvr:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "nvr-1", "version": "4.0.0"}
        result = await get_nvr(client, registry, "h")
        client.get.assert_called_once_with(f"{BASE}/nvrs")
        assert result["id"] == "nvr-1"

    async def test_non_dict_wrapped(self, client, registry):
        client.get.return_value = ["raw"]
        result = await get_nvr(client, registry, "h")
        assert result == {"data": ["raw"]}


# --- Alarm Webhook ---


class TestTriggerAlarmWebhook:
    async def test_basic(self, client, registry):
        client.post.return_value = {"status": "triggered"}
        result = await trigger_alarm_webhook(client, registry, "h", "wh-1")
        client.post.assert_called_once_with(f"{BASE}/alarm-manager/webhook/wh-1", json={})
        assert result["status"] == "triggered"

    async def test_non_dict_fallback(self, client, registry):
        client.post.return_value = None
        result = await trigger_alarm_webhook(client, registry, "h", "wh-1")
        assert result == {"status": "ok"}


# --- RTSPS Stream ---


class TestCreateRtspsStream:
    async def test_basic(self, client, registry):
        client.post.return_value = {"url": "rtsps://..."}
        result = await create_rtsps_stream(client, registry, "h", "cam-1", ["highest", "high"])
        client.post.assert_called_once_with(
            f"{BASE}/cameras/cam-1/rtsps-stream", json={"qualities": ["highest", "high"]}
        )
        assert result["url"] == "rtsps://..."

    async def test_qualities_normalized_to_lowercase(self, client, registry):
        client.post.return_value = {"url": "rtsps://..."}
        # Pass uppercase — API must receive lowercase
        await create_rtsps_stream(client, registry, "h", "cam-1", ["MEDIUM", "LOW"])
        call_json = client.post.call_args[1]["json"]
        assert call_json["qualities"] == ["medium", "low"]

    async def test_mixed_case_normalized(self, client, registry):
        client.post.return_value = {"url": "rtsps://..."}
        await create_rtsps_stream(client, registry, "h", "cam-1", ["HIGHEST", "High"])
        call_json = client.post.call_args[1]["json"]
        assert call_json["qualities"] == ["highest", "high"]

    async def test_non_dict_wrapped(self, client, registry):
        client.post.return_value = None
        result = await create_rtsps_stream(client, registry, "h", "cam-1", ["high"])
        assert result == {"data": None}


class TestDeleteRtspsStream:
    async def test_basic(self, client, registry):
        client.delete.return_value = None
        await delete_rtsps_stream(client, registry, "h", "cam-1", ["highest", "high"])
        client.delete.assert_called_once_with(
            f"{BASE}/cameras/cam-1/rtsps-stream", params={"qualities": ["highest", "high"]}
        )
        registry.resolve_host_id.assert_called_once_with("h")

    async def test_qualities_normalized_to_lowercase(self, client, registry):
        client.delete.return_value = None
        # Pass uppercase — API must receive lowercase
        await delete_rtsps_stream(client, registry, "h", "cam-1", ["MEDIUM"])
        call_params = client.delete.call_args[1]["params"]
        assert call_params["qualities"] == ["medium"]

    async def test_qualities_sent_in_body(self, client, registry):
        client.delete.return_value = None
        await delete_rtsps_stream(client, registry, "h", "cam-1", ["low"])
        call_params = client.delete.call_args[1]["params"]
        assert call_params["qualities"] == ["low"]


# --- Protect Files ---


class TestListProtectFiles:
    async def test_list_returns_dict(self, client, registry):
        client.get.return_value = [{"id": "file-1", "name": "alert.mp3"}]
        result = await list_protect_files(client, registry, "myhost", "sounds")
        client.get.assert_called_once_with(f"{BASE}/files/sounds")
        assert result == {
            "files": [{"id": "file-1", "name": "alert.mp3"}],
            "count": 1,
            "file_type": "sounds",
        }

    async def test_data_wrapper(self, client, registry):
        client.get.return_value = {"data": [{"id": "f-2"}, {"id": "f-3"}]}
        result = await list_protect_files(client, registry, "myhost", "images")
        assert result["count"] == 2
        assert result["file_type"] == "images"

    async def test_resolves_host(self, client, registry):
        client.get.return_value = []
        await list_protect_files(client, registry, "MyHost", "sounds")
        registry.resolve_host_id.assert_called_once_with("MyHost")

    async def test_empty_list(self, client, registry):
        client.get.return_value = []
        result = await list_protect_files(client, registry, "h", "sounds")
        assert result == {"files": [], "count": 0, "file_type": "sounds"}


class TestUploadProtectFile:
    async def test_basic_upload(self, client, registry):
        client.post_multipart.return_value = {"id": "file-new", "name": "chime.mp3"}
        raw = b"fake-audio-data"
        encoded = base64.b64encode(raw).decode()
        result = await upload_protect_file(
            client, registry, "myhost", "sounds", "chime.mp3", encoded
        )
        assert result == {"id": "file-new", "name": "chime.mp3"}
        call_args = client.post_multipart.call_args
        assert call_args[0][0] == f"{BASE}/files/sounds"
        files_arg = call_args[1]["files"]
        assert "file" in files_arg
        fname, fobj = files_arg["file"]
        assert fname == "chime.mp3"
        assert fobj.read() == raw

    async def test_non_dict_wrapped(self, client, registry):
        client.post_multipart.return_value = None
        encoded = base64.b64encode(b"data").decode()
        result = await upload_protect_file(client, registry, "h", "sounds", "a.mp3", encoded)
        assert result == {"data": None}

    async def test_resolves_host(self, client, registry):
        client.post_multipart.return_value = {}
        encoded = base64.b64encode(b"x").decode()
        await upload_protect_file(client, registry, "MyHost", "images", "img.png", encoded)
        registry.resolve_host_id.assert_called_once_with("MyHost")
