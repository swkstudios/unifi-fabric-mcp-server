"""Tests for non-camera Protect tools — sensors, lights, chimes, viewers, liveviews,
NVR, alarm webhook, and RTSPS stream management."""

from __future__ import annotations

import base64
from unittest.mock import AsyncMock

import pytest

from tests._protect_writes import assert_write, resp
from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.tools.protect import (
    PROTECT_PRIVATE_BASE,
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
    list_protect_events,
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
PRIVATE_BASE = PROTECT_PRIVATE_BASE.format(host_id=HOST_ID)


@pytest.fixture()
def client():
    c = AsyncMock()
    c.request = AsyncMock(return_value=resp({}))
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
    r.resolve_key_for_host = AsyncMock(return_value=None)
    return r


# --- Sensors ---


class TestListSensors:
    async def test_list_returns_dict(self, client, registry):
        client.get.return_value = [{"id": "sen-1", "type": "motion"}]
        result = await list_sensors(client, registry, "myhost")
        client.get.assert_called_once_with(f"{BASE}/sensors", key=None)
        assert result == {"result": [{"id": "sen-1", "type": "motion"}], "_count": 1}

    async def test_data_wrapper(self, client, registry):
        client.get.return_value = {"data": [{"id": "sen-2"}]}
        result = await list_sensors(client, registry, "myhost")
        assert result["_count"] == 1

    async def test_resolves_host(self, client, registry):
        client.get.return_value = []
        await list_sensors(client, registry, "MyHost")
        registry.resolve_host_id.assert_called_once_with("MyHost", key=None)


class TestGetSensor:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "sen-1", "state": "open"}
        result = await get_sensor(client, registry, "h", "sen-1")
        client.get.assert_called_once_with(f"{BASE}/sensors/sen-1", key=None)
        assert result["id"] == "sen-1"

    async def test_non_object_body_raises(self, client, registry):
        client.get.return_value = ["raw"]
        with pytest.raises(UniFiConnectionError, match="expected an object, got array"):
            await get_sensor(client, registry, "h", "sen-1")


class TestUpdateSensor:
    async def test_basic(self, client, registry):
        client.get.side_effect = [{"id": "sen-1", "name": "Old"}, {"id": "sen-1", "name": "Door"}]
        client.request.return_value = resp({"id": "sen-1", "name": "Door"})
        result = await update_sensor(client, registry, "h", "sen-1", name="Door")
        assert_write(client, "PATCH", f"{BASE}/sensors/sen-1", json={"name": "Door"}, key=None)
        assert result == {
            "status": "updated",
            "verified": True,
            "before": {"id": "sen-1", "name": "Old"},
            "after": {"id": "sen-1", "name": "Door"},
            "response": {"id": "sen-1", "name": "Door"},
        }

    async def test_noop_when_already_set(self, client, registry):
        client.get.return_value = {"id": "sen-1", "name": "Door"}
        result = await update_sensor(client, registry, "h", "sen-1", name="Door")
        client.request.assert_not_called()
        assert result["status"] == "noop"
        assert result["resource"] == {"id": "sen-1", "name": "Door"}


# --- Lights ---


class TestListLights:
    async def test_list_returns_dict(self, client, registry):
        client.get.return_value = [{"id": "lt-1"}]
        result = await list_lights(client, registry, "h")
        client.get.assert_called_once_with(f"{BASE}/lights", key=None)
        assert result == {"result": [{"id": "lt-1"}], "_count": 1}

    async def test_data_wrapper(self, client, registry):
        client.get.return_value = {"data": [{"id": "lt-2"}, {"id": "lt-3"}]}
        result = await list_lights(client, registry, "h")
        assert result["_count"] == 2


class TestGetLight:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "lt-1", "on": True}
        result = await get_light(client, registry, "h", "lt-1")
        client.get.assert_called_once_with(f"{BASE}/lights/lt-1", key=None)
        assert result["id"] == "lt-1"


class TestUpdateLight:
    async def test_basic(self, client, registry):
        client.get.side_effect = [{"id": "lt-1"}, {"id": "lt-1", "brightness": 80}]
        client.request.return_value = resp({"id": "lt-1", "brightness": 80})
        result = await update_light(client, registry, "h", "lt-1", brightness=80)
        assert_write(
            client,
            "PATCH",
            f"{BASE}/lights/lt-1",
            json={"brightness": 80},
            key=None,
        )
        assert result["response"]["brightness"] == 80
        assert result["verified"] is True
        assert result["after"]["brightness"] == 80


# --- Chimes ---


class TestListChimes:
    async def test_basic(self, client, registry):
        client.get.return_value = [{"id": "ch-1"}]
        result = await list_chimes(client, registry, "h")
        client.get.assert_called_once_with(f"{BASE}/chimes", key=None)
        assert result == {"result": [{"id": "ch-1"}], "_count": 1}

    async def test_data_wrapper(self, client, registry):
        client.get.return_value = {"data": [{"id": "ch-2"}]}
        result = await list_chimes(client, registry, "h")
        assert result["_count"] == 1


class TestGetChime:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "ch-1", "volume": 70}
        result = await get_chime(client, registry, "h", "ch-1")
        client.get.assert_called_once_with(f"{BASE}/chimes/ch-1", key=None)
        assert result["id"] == "ch-1"


class TestUpdateChime:
    async def test_basic(self, client, registry):
        client.get.side_effect = [{"id": "ch-1"}, {"id": "ch-1", "volume": 50}]
        client.request.return_value = resp({"id": "ch-1", "volume": 50})
        result = await update_chime(client, registry, "h", "ch-1", volume=50)
        assert_write(
            client,
            "PATCH",
            f"{BASE}/chimes/ch-1",
            json={"volume": 50},
            key=None,
        )
        assert result["response"]["volume"] == 50
        assert result["verified"] is True
        assert result["after"]["volume"] == 50


# --- Viewers ---


class TestListViewers:
    async def test_basic(self, client, registry):
        client.get.return_value = [{"id": "vw-1"}]
        result = await list_viewers(client, registry, "h")
        client.get.assert_called_once_with(f"{BASE}/viewers", key=None)
        assert result == {"result": [{"id": "vw-1"}], "_count": 1}

    async def test_data_wrapper(self, client, registry):
        client.get.return_value = {"data": [{"id": "vw-2"}, {"id": "vw-3"}]}
        result = await list_viewers(client, registry, "h")
        assert result["_count"] == 2


class TestGetViewer:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "vw-1", "liveview": "lv-1"}
        result = await get_viewer(client, registry, "h", "vw-1")
        client.get.assert_called_once_with(f"{BASE}/viewers/vw-1", key=None)
        assert result["id"] == "vw-1"


class TestUpdateViewer:
    async def test_basic(self, client, registry):
        client.get.side_effect = [{"id": "vw-1"}, {"id": "vw-1", "liveview": "lv-2"}]
        client.request.return_value = resp({"id": "vw-1", "liveview": "lv-2"})
        result = await update_viewer(client, registry, "h", "vw-1", liveview="lv-2")
        assert_write(
            client,
            "PATCH",
            f"{BASE}/viewers/vw-1",
            json={"liveview": "lv-2"},
            key=None,
        )
        assert result["response"]["liveview"] == "lv-2"
        assert result["verified"] is True
        assert result["after"]["liveview"] == "lv-2"


# --- Liveviews ---


class TestListLiveviews:
    async def test_basic(self, client, registry):
        client.get.return_value = [{"id": "lv-1", "name": "Main View"}]
        result = await list_liveviews(client, registry, "h")
        client.get.assert_called_once_with(f"{BASE}/liveviews", key=None)
        assert result == {"result": [{"id": "lv-1", "name": "Main View"}], "_count": 1}

    async def test_data_wrapper(self, client, registry):
        client.get.return_value = {"data": [{"id": "lv-2"}]}
        result = await list_liveviews(client, registry, "h")
        assert result["_count"] == 1


class TestGetLiveview:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "lv-1", "name": "Lobby"}
        result = await get_liveview(client, registry, "h", "lv-1")
        client.get.assert_called_once_with(f"{BASE}/liveviews/lv-1", key=None)
        assert result["id"] == "lv-1"


class TestCreateLiveview:
    async def test_basic(self, client, registry):
        client.request.return_value = resp({"id": "lv-2", "name": "New View"})
        result = await create_liveview(client, registry, "h", "New View")
        assert_write(client, "POST", f"{BASE}/liveviews", json={"name": "New View"}, key=None)
        assert result == {"status": "created", "response": {"id": "lv-2", "name": "New View"}}

    async def test_extra_fields(self, client, registry):
        client.request.return_value = resp({"id": "lv-3"})
        await create_liveview(client, registry, "h", "Cameras", slots=4)
        call_json = client.request.call_args[1]["json"]
        assert call_json["name"] == "Cameras"
        assert call_json["slots"] == 4


class TestUpdateLiveview:
    async def test_basic(self, client, registry):
        client.get.side_effect = [{"id": "lv-1"}, {"id": "lv-1", "name": "Updated"}]
        client.request.return_value = resp({"id": "lv-1", "name": "Updated"})
        result = await update_liveview(client, registry, "h", "lv-1", name="Updated")
        assert_write(
            client,
            "PATCH",
            f"{BASE}/liveviews/lv-1",
            json={"name": "Updated"},
            key=None,
        )
        assert result["response"]["name"] == "Updated"
        assert result["verified"] is True
        assert result["after"]["name"] == "Updated"


# --- NVR ---


class TestGetNvr:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "nvr-1", "version": "4.0.0"}
        result = await get_nvr(client, registry, "h")
        client.get.assert_called_once_with(f"{BASE}/nvrs", key=None)
        assert result["id"] == "nvr-1"

    async def test_non_object_body_raises(self, client, registry):
        client.get.return_value = ["raw"]
        with pytest.raises(UniFiConnectionError, match="expected an object, got array"):
            await get_nvr(client, registry, "h")


# --- Alarm Webhook ---


class TestTriggerAlarmWebhook:
    async def test_basic(self, client, registry):
        client.request.return_value = resp({"status": "triggered"})
        result = await trigger_alarm_webhook(client, registry, "h", "wh-1")
        assert_write(client, "POST", f"{BASE}/alarm-manager/webhook/wh-1", json=None, key=None)
        assert result == {"status": "sent", "response": {"status": "triggered"}}

    async def test_empty_body_is_reported_not_raised(self, client, registry):
        client.request.return_value = resp()
        result = await trigger_alarm_webhook(client, registry, "h", "wh-1")
        assert result == {"status": "sent", "response": None}

    async def test_text_body_is_returned_verbatim(self, client, registry):
        client.request.return_value = resp(text="OK")
        result = await trigger_alarm_webhook(client, registry, "h", "wh-1")
        assert result == {"status": "sent", "response": "OK"}


# --- RTSPS Stream ---


class TestCreateRtspsStream:
    async def test_basic(self, client, registry):
        client.request.return_value = resp({"url": "rtsps://..."})
        result = await create_rtsps_stream(client, registry, "h", "cam-1", ["highest", "high"])
        assert_write(
            client,
            "POST",
            f"{BASE}/cameras/cam-1/rtsps-stream",
            json={"qualities": ["highest", "high"]},
            key=None,
        )
        assert result == {"status": "created", "response": {"url": "rtsps://..."}}

    async def test_qualities_normalized_to_lowercase(self, client, registry):
        client.request.return_value = resp({"url": "rtsps://..."})
        # Pass uppercase — API must receive lowercase
        await create_rtsps_stream(client, registry, "h", "cam-1", ["MEDIUM", "LOW"])
        call_json = client.request.call_args[1]["json"]
        assert call_json["qualities"] == ["medium", "low"]

    async def test_mixed_case_normalized(self, client, registry):
        client.request.return_value = resp({"url": "rtsps://..."})
        await create_rtsps_stream(client, registry, "h", "cam-1", ["HIGHEST", "High"])
        call_json = client.request.call_args[1]["json"]
        assert call_json["qualities"] == ["highest", "high"]

    async def test_empty_body_is_reported_not_raised(self, client, registry):
        client.request.return_value = resp()
        result = await create_rtsps_stream(client, registry, "h", "cam-1", ["high"])
        assert result == {"status": "created", "response": None}


class TestDeleteRtspsStream:
    async def test_basic(self, client, registry):
        client.delete.return_value = None
        await delete_rtsps_stream(client, registry, "h", "cam-1", ["highest", "high"])
        client.delete.assert_called_once_with(
            f"{BASE}/cameras/cam-1/rtsps-stream",
            params={"qualities": ["highest", "high"]},
            key=None,
        )
        registry.resolve_host_id.assert_called_once_with("h", key=None)

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
        client.get.assert_called_once_with(f"{BASE}/files/sounds", key=None)
        assert result == {
            "result": [{"id": "file-1", "name": "alert.mp3"}],
            "_count": 1,
            "_file_type": "sounds",
        }

    async def test_data_wrapper(self, client, registry):
        client.get.return_value = {"data": [{"id": "f-2"}, {"id": "f-3"}]}
        result = await list_protect_files(client, registry, "myhost", "images")
        assert result["_count"] == 2
        assert result["_file_type"] == "images"

    async def test_resolves_host(self, client, registry):
        client.get.return_value = []
        await list_protect_files(client, registry, "MyHost", "sounds")
        registry.resolve_host_id.assert_called_once_with("MyHost", key=None)

    async def test_empty_list(self, client, registry):
        client.get.return_value = []
        result = await list_protect_files(client, registry, "h", "sounds")
        assert result == {"result": [], "_count": 0, "_file_type": "sounds"}


class TestUploadProtectFile:
    async def test_basic_upload(self, client, registry):
        client.request.return_value = resp({"id": "file-new", "name": "chime.mp3"})
        raw = b"fake-audio-data"
        encoded = base64.b64encode(raw).decode()
        result = await upload_protect_file(
            client, registry, "myhost", "sounds", "chime.mp3", encoded
        )
        assert result == {"status": "uploaded", "response": {"id": "file-new", "name": "chime.mp3"}}
        call_args = client.request.call_args
        assert call_args[0][:2] == ("POST", f"{BASE}/files/sounds")
        files_arg = call_args[1]["files"]
        assert "file" in files_arg
        fname, fobj, ctype = files_arg["file"]
        assert fname == "chime.mp3"
        assert ctype == "audio/mpeg"  # the type httpx would send, stated for the preview
        assert fobj.read() == raw

    async def test_text_body_is_returned_verbatim(self, client, registry):
        client.request.return_value = resp(text="stored")
        encoded = base64.b64encode(b"data").decode()
        result = await upload_protect_file(client, registry, "h", "sounds", "a.mp3", encoded)
        assert result == {"status": "uploaded", "response": "stored"}

    async def test_wrapped_base64_is_accepted(self, client, registry):
        raw = bytes(range(200))
        encoded = base64.encodebytes(raw).decode()  # MIME-wrapped at 76 columns
        assert "\n" in encoded.strip()
        await upload_protect_file(client, registry, "h", "sounds", "a.wav", encoded)
        assert client.request.call_args[1]["files"]["file"][1].read() == raw

    @pytest.mark.parametrize("file_type", ["../x", "a/b", "", "sounds?x=1"])
    async def test_file_type_is_validated_before_any_request(self, client, registry, file_type):
        encoded = base64.b64encode(b"x").decode()
        with pytest.raises(ValueError, match="file_type"):
            await upload_protect_file(client, registry, "h", file_type, "a.mp3", encoded)
        client.request.assert_not_called()
        registry.resolve_key_for_host.assert_not_called()

    async def test_resolves_host(self, client, registry):
        client.request.return_value = resp({})
        encoded = base64.b64encode(b"x").decode()
        await upload_protect_file(client, registry, "MyHost", "images", "img.png", encoded)
        registry.resolve_host_id.assert_called_once_with("MyHost", key=None)


# --- Historical Events (private /proxy/protect/api/events path) ---

# Synthetic timestamps (epoch seconds).
_EV_START_S = 1_735_000_000
_EV_END_S = 1_735_086_400


class TestListProtectEvents:
    @pytest.fixture(autouse=True)
    def uncapped_client(self, client):
        client.paginate_max_pages = None

    async def test_uses_private_events_path_not_integration(self, client, registry):
        # No offset/limit drains through the shared effective-size GET collector.
        client.get.return_value = []
        await list_protect_events(client, registry, "h", _EV_START_S, _EV_END_S)
        path = client.get.call_args.args[0]
        # Must use the private /proxy/protect/api path, NOT the integration path.
        assert path == f"{PRIVATE_BASE}/events"
        assert "/api/events" in path
        assert "/integration/" not in path

    async def test_drains_all_events_by_default(self, client, registry):
        # A wide window holds tens of thousands of events; the tool must drain
        # every page, not return only the first.
        records = [{"id": "e1"}, {"id": "e2"}]
        client.get.side_effect = [records, []]
        result = await list_protect_events(client, registry, "h", _EV_START_S, _EV_END_S)
        # A short bare page cannot prove completion without a total or size echo.
        assert client.get.call_count == 2
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == [0, 2]
        assert [call.kwargs["params"]["limit"] for call in client.get.call_args_list] == [200, 200]
        assert result["_count"] == 2
        assert result["result"] == records
        assert "incomplete" not in result

    async def test_cap_exceeded_marked_incomplete(self, client, registry):
        client.paginate_max_pages = 2
        pages = [[{"id": f"e{i}"} for i in range(start, start + 200)] for start in (0, 200)]
        client.get.side_effect = pages
        result = await list_protect_events(client, registry, "h", _EV_START_S, _EV_END_S)
        assert result["incomplete"] is True
        assert result["_count"] == 400
        assert result["result"] == pages[0] + pages[1]
        assert "page cap of 2 reached" in result["incompleteReason"]
        assert [call.kwargs["params"]["offset"] for call in client.get.await_args_list] == [0, 200]

    async def test_seconds_converted_to_milliseconds(self, client, registry):
        client.get.return_value = []
        await list_protect_events(client, registry, "h", _EV_START_S, _EV_END_S)
        params = client.get.call_args.kwargs["params"]
        # Protect events are epoch-millisecond; the tool accepts seconds and converts.
        assert params["start"] == _EV_START_S * 1000
        assert params["end"] == _EV_END_S * 1000

    async def test_types_single_and_list_passed_through(self, client, registry):
        client.get.return_value = []
        await list_protect_events(client, registry, "h", _EV_START_S, _EV_END_S, types="motion")
        assert client.get.call_args.kwargs["params"]["types"] == "motion"
        client.get.reset_mock()
        await list_protect_events(
            client, registry, "h", _EV_START_S, _EV_END_S, types=["motion", "sensorOpened"]
        )
        assert client.get.call_args.kwargs["params"]["types"] == [
            "motion",
            "sensorOpened",
        ]

    async def test_order_direction_and_pagination_params(self, client, registry):
        client.get.return_value = []
        await list_protect_events(
            client,
            registry,
            "h",
            _EV_START_S,
            _EV_END_S,
            limit=50,
            offset=100,
            order_direction="DESC",
        )
        params = client.get.call_args.kwargs["params"]
        assert params["limit"] == 50
        assert params["offset"] == 100
        assert params["orderDirection"] == "DESC"

    async def test_sensor_id_promoted_from_metadata(self, client, registry):
        # Sensor events set top-level `sensor` to null; the reference lives in
        # metadata.sensorId.text and must be surfaced there.
        client.get.return_value = [
            {
                "id": "evt-1",
                "type": "sensorOpened",
                "sensor": None,
                "metadata": {"sensorId": {"text": "sensor-abc-123"}},
            }
        ]
        result = await list_protect_events(client, registry, "h", _EV_START_S, _EV_END_S)
        assert result["_count"] == 1
        # The controller's null sensor field is left as sent; the id is added alongside.
        assert result["result"][0]["sensor"] is None
        assert result["result"][0]["_resolved_sensor"] == "sensor-abc-123"
        # Original metadata is preserved for callers that want to join on it.
        assert result["result"][0]["metadata"]["sensorId"]["text"] == "sensor-abc-123"

    async def test_non_sensor_event_sensor_field_untouched(self, client, registry):
        client.get.return_value = [
            {"id": "evt-2", "type": "smartDetectZone", "sensor": None, "camera": "cam-1"}
        ]
        result = await list_protect_events(client, registry, "h", _EV_START_S, _EV_END_S)
        # No metadata.sensorId, so nothing to add — event is verbatim.
        assert result["result"][0] == {
            "id": "evt-2",
            "type": "smartDetectZone",
            "sensor": None,
            "camera": "cam-1",
        }

    async def test_identifiers_survive_in_events(self, client, registry):
        # Data-survival: the metadata.name object carries camera / recognized-person /
        # license-plate text — the whole point of the events tool. It must survive the
        # full response path unchanged, along with mac and analytic fields.
        client.get.return_value = [
            {
                "id": "evt-3",
                "type": "smartDetectZone",
                "smartDetectTypes": ["animal"],
                "metadata": {
                    "name": {"text": "synthetic-cam-name"},
                    "mac": "0a:00:00:00:00:09",
                },
            }
        ]
        result = await list_protect_events(client, registry, "h", _EV_START_S, _EV_END_S)
        meta = result["result"][0]["metadata"]
        assert meta["name"] == {"text": "synthetic-cam-name"}
        assert meta["mac"] == "0a:00:00:00:00:09"
        assert result["result"][0]["smartDetectTypes"] == ["animal"]
        assert "synthetic-cam-name" in str(result)

    async def test_manual_page_preserves_data_envelope(self, client, registry):
        # A requested total may finish in one native data envelope when the
        # upstream total proves this is the complete collection.
        client.get.return_value = {
            "data": [{"id": "evt-4", "type": "motion"}],
            "totalCount": 1,
            "limit": 200,
        }
        result = await list_protect_events(client, registry, "h", _EV_START_S, _EV_END_S, limit=200)
        assert result["_count"] == 1
        assert result["data"] == [{"id": "evt-4", "type": "motion"}]
        client.get.assert_awaited_once()

    async def test_truncated_host_id_raises_host_error(self, client, registry):
        client.get.side_effect = UniFiConnectionError("HTTP 403 forbidden: host not found")
        with pytest.raises(UniFiConnectionError, match="host id"):
            await list_protect_events(client, registry, "h", _EV_START_S, _EV_END_S)

    # --- New filters: smart_detect_types, categories, without_descriptions ---

    async def test_smart_detect_types_passthrough_with_types(self, client, registry):
        client.get.return_value = []
        await list_protect_events(
            client,
            registry,
            "h",
            _EV_START_S,
            _EV_END_S,
            types="smartDetectZone",
            smart_detect_types="person",
        )
        params = client.get.call_args.kwargs["params"]
        assert params["types"] == "smartDetectZone"
        assert params["smartDetectTypes"] == "person"

    async def test_smart_detect_types_list_passthrough(self, client, registry):
        client.get.return_value = []
        await list_protect_events(
            client,
            registry,
            "h",
            _EV_START_S,
            _EV_END_S,
            types=["smartDetectZone", "smartAudioDetect"],
            smart_detect_types=["person", "alrmSpeak"],
        )
        params = client.get.call_args.kwargs["params"]
        assert params["smartDetectTypes"] == ["person", "alrmSpeak"]

    async def test_new_filters_omitted_when_none(self, client, registry):
        client.get.return_value = []
        await list_protect_events(client, registry, "h", _EV_START_S, _EV_END_S)
        params = client.get.call_args.kwargs["params"]
        assert "smartDetectTypes" not in params
        assert "categories" not in params
        assert "withoutDescriptions" not in params

    async def test_categories_single_and_list_passthrough(self, client, registry):
        client.get.return_value = []
        await list_protect_events(client, registry, "h", _EV_START_S, _EV_END_S, categories="smart")
        assert client.get.call_args.kwargs["params"]["categories"] == "smart"
        client.get.reset_mock()
        await list_protect_events(
            client, registry, "h", _EV_START_S, _EV_END_S, categories=["motion", "iot"]
        )
        assert client.get.call_args.kwargs["params"]["categories"] == ["motion", "iot"]

    async def test_without_descriptions_true_sets_param(self, client, registry):
        client.get.return_value = []
        await list_protect_events(
            client, registry, "h", _EV_START_S, _EV_END_S, without_descriptions=True
        )
        assert client.get.call_args.kwargs["params"]["withoutDescriptions"] == "true"

    async def test_without_descriptions_false_omits_param(self, client, registry):
        # Opt-in only: full fidelity is the default, so False/None must not send it.
        client.get.return_value = []
        await list_protect_events(
            client, registry, "h", _EV_START_S, _EV_END_S, without_descriptions=False
        )
        assert "withoutDescriptions" not in client.get.call_args.kwargs["params"]

    async def test_smart_detect_types_actually_narrows(self, client, registry):
        # End-to-end through the tool: a server that honours smartDetectTypes returns
        # only the matching subtype, and the tool surfaces exactly that narrowed set.
        dataset = [
            {"id": "z1", "type": "smartDetectZone", "smartDetectTypes": ["person"]},
            {"id": "z2", "type": "smartDetectZone", "smartDetectTypes": ["animal"]},
            {"id": "z3", "type": "smartDetectZone", "smartDetectTypes": ["person"]},
        ]

        async def fake_page(path, *, key=None, params=None):
            want = (params or {}).get("smartDetectTypes")
            if want is None:
                return dataset
            wants = {want} if isinstance(want, str) else set(want)
            return [e for e in dataset if wants & set(e["smartDetectTypes"])]

        client.get.side_effect = fake_page
        allz = await list_protect_events(
            client, registry, "h", _EV_START_S, _EV_END_S, types="smartDetectZone"
        )
        assert allz["_count"] == 3
        person = await list_protect_events(
            client,
            registry,
            "h",
            _EV_START_S,
            _EV_END_S,
            types="smartDetectZone",
            smart_detect_types="person",
        )
        assert person["_count"] == 2
        assert {e["id"] for e in person["result"]} == {"z1", "z3"}

    # --- cameras: name-or-ID resolution ---

    async def test_cameras_name_resolved_to_id(self, client, registry):
        client.get.return_value = [
            {"id": "aa" * 12, "name": "Camera A"},
            {"id": "bb" * 12, "name": "Camera B"},
        ]
        client.get.side_effect = lambda path, **kwargs: (
            client.get.return_value if path.endswith("/cameras") else []
        )
        await list_protect_events(client, registry, "h", _EV_START_S, _EV_END_S, cameras="camera a")
        assert [call.args[0] for call in client.get.await_args_list] == [
            f"{BASE}/cameras",
            f"{PRIVATE_BASE}/events",
        ]
        assert client.get.call_args.kwargs["params"]["cameras"] == ["aa" * 12]

    async def test_cameras_id_passes_through(self, client, registry):
        client.get.return_value = [{"id": "aa" * 12, "name": "Camera A"}]
        client.get.side_effect = lambda path, **kwargs: (
            client.get.return_value if path.endswith("/cameras") else []
        )
        await list_protect_events(client, registry, "h", _EV_START_S, _EV_END_S, cameras="cc" * 12)
        assert client.get.call_args.kwargs["params"]["cameras"] == ["cc" * 12]

    async def test_cameras_mixed_name_and_id(self, client, registry):
        client.get.return_value = [
            {"id": "aa" * 12, "name": "Camera A"},
            {"id": "bb" * 12, "name": "Camera B"},
        ]
        client.get.side_effect = lambda path, **kwargs: (
            client.get.return_value if path.endswith("/cameras") else []
        )
        await list_protect_events(
            client,
            registry,
            "h",
            _EV_START_S,
            _EV_END_S,
            cameras=["Camera B", "aa" * 12],
        )
        assert client.get.call_args.kwargs["params"]["cameras"] == [
            "bb" * 12,
            "aa" * 12,
        ]

    async def test_cameras_duplicate_name_is_ambiguous(self, client, registry):
        # No exact match; both names match case-insensitively -> ambiguous.
        client.get.return_value = [
            {"id": "aa" * 12, "name": "Driveway"},
            {"id": "bb" * 12, "name": "driveway"},
        ]
        with pytest.raises(ValueError) as exc:
            await list_protect_events(
                client, registry, "h", _EV_START_S, _EV_END_S, cameras="DRIVEWAY"
            )
        msg = str(exc.value)
        assert "ambiguous camera 'DRIVEWAY'" in msg
        assert "aa" * 12 in msg and "bb" * 12 in msg
        assert all(call.args[0] == f"{BASE}/cameras" for call in client.get.await_args_list)

    async def test_cameras_unknown_name_raises(self, client, registry):
        client.get.return_value = [{"id": "aa" * 12, "name": "Camera A"}]
        with pytest.raises(ValueError, match="not found"):
            await list_protect_events(
                client, registry, "h", _EV_START_S, _EV_END_S, cameras="Nonexistent Cam"
            )
        assert all(call.args[0] == f"{BASE}/cameras" for call in client.get.await_args_list)


@pytest.mark.parametrize("changed", [False, True])
async def test_official_update_addressing_body_id_case_noop_and_verification(
    client, registry, changed
):
    identity = "000000000000000000fa0101"
    requested = {"id": identity.upper(), "name": "changed" if changed else "same"}
    before = {"id": identity, "name": "same"}
    after = {"id": identity, "name": requested["name"]}
    client.get.side_effect = [before, after]
    client.request.return_value = resp({"accepted": True})
    result = await update_sensor(client, registry, "h", identity.upper(), **requested)
    if changed:
        assert result["verified"] is True
        assert_write(
            client,
            "PATCH",
            f"{BASE}/sensors/{identity}",
            json={**requested, "id": identity},
            key=None,
        )
    else:
        assert result["status"] == "noop"
        client.request.assert_not_called()
    assert requested["id"] == identity.upper()
    assert result.get("before", result.get("resource")) == before
