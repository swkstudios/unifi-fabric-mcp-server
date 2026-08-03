"""Tests for non-camera Protect tools — sensors, lights, chimes, viewers, liveviews,
NVR, alarm webhook, and RTSPS stream management."""

from __future__ import annotations

import base64
from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import PaginationAbortedError, UniFiConnectionError
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


# --- Historical Events (private /proxy/protect/api/events path) ---

# Synthetic timestamps (epoch seconds).
_EV_START_S = 1_735_000_000
_EV_END_S = 1_735_086_400


class TestListProtectEvents:
    async def test_uses_private_events_path_not_integration(self, client, registry):
        # No offset/limit -> drain mode, which drives the offset drainer.
        client.paginate_offset.return_value = []
        await list_protect_events(client, registry, "h", _EV_START_S, _EV_END_S)
        path = client.paginate_offset.call_args.args[0]
        # Must use the private /proxy/protect/api path, NOT the integration path.
        assert path == f"{PRIVATE_BASE}/events"
        assert "/api/events" in path
        assert "/integration/" not in path

    async def test_drains_all_events_by_default(self, client, registry):
        # A wide window holds tens of thousands of events; the tool must drain
        # every page, not return only the first.
        client.paginate_offset.return_value = [{"id": "e1"}, {"id": "e2"}]
        result = await list_protect_events(client, registry, "h", _EV_START_S, _EV_END_S)
        client.paginate_offset.assert_called_once()
        client.get.assert_not_called()
        assert result["count"] == 2

    async def test_cap_exceeded_marked_incomplete(self, client, registry):
        client.paginate_offset.side_effect = PaginationAbortedError(
            f"{PRIVATE_BASE}/events", 2, "page cap of 2 reached", items=[{"id": "e1"}]
        )
        result = await list_protect_events(client, registry, "h", _EV_START_S, _EV_END_S)
        assert result["incomplete"] is True
        assert result["count"] == 1

    async def test_seconds_converted_to_milliseconds(self, client, registry):
        client.paginate_offset.return_value = []
        await list_protect_events(client, registry, "h", _EV_START_S, _EV_END_S)
        params = client.paginate_offset.call_args.kwargs["params"]
        # Protect events are epoch-millisecond; the tool accepts seconds and converts.
        assert params["start"] == _EV_START_S * 1000
        assert params["end"] == _EV_END_S * 1000

    async def test_rejects_millisecond_magnitude(self, client, registry):
        with pytest.raises(ValueError, match="milliseconds"):
            await list_protect_events(client, registry, "h", _EV_START_S * 1000, _EV_END_S)
        client.get.assert_not_called()
        client.paginate_offset.assert_not_called()

    async def test_types_single_and_list_passed_through(self, client, registry):
        client.paginate_offset.return_value = []
        await list_protect_events(client, registry, "h", _EV_START_S, _EV_END_S, types="motion")
        assert client.paginate_offset.call_args.kwargs["params"]["types"] == "motion"
        client.paginate_offset.reset_mock()
        await list_protect_events(
            client, registry, "h", _EV_START_S, _EV_END_S, types=["motion", "sensorOpened"]
        )
        assert client.paginate_offset.call_args.kwargs["params"]["types"] == [
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
        client.paginate_offset.return_value = [
            {
                "id": "evt-1",
                "type": "sensorOpened",
                "sensor": None,
                "metadata": {"sensorId": {"text": "sensor-abc-123"}},
            }
        ]
        result = await list_protect_events(client, registry, "h", _EV_START_S, _EV_END_S)
        assert result["count"] == 1
        assert result["events"][0]["sensor"] == "sensor-abc-123"
        # Original metadata is preserved for callers that want to join on it.
        assert result["events"][0]["metadata"]["sensorId"]["text"] == "sensor-abc-123"

    async def test_non_sensor_event_sensor_field_untouched(self, client, registry):
        client.paginate_offset.return_value = [
            {"id": "evt-2", "type": "smartDetectZone", "sensor": None, "camera": "cam-1"}
        ]
        result = await list_protect_events(client, registry, "h", _EV_START_S, _EV_END_S)
        # No metadata.sensorId, so nothing to promote — stays null.
        assert result["events"][0]["sensor"] is None

    async def test_identifiers_survive_in_events(self, client, registry):
        # Data-survival: the metadata.name object carries camera / recognized-person /
        # license-plate text — the whole point of the events tool. It must survive the
        # full response path unchanged, along with mac and analytic fields.
        client.paginate_offset.return_value = [
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
        meta = result["events"][0]["metadata"]
        assert meta["name"] == {"text": "synthetic-cam-name"}
        assert meta["mac"] == "0a:00:00:00:00:09"
        assert result["events"][0]["smartDetectTypes"] == ["animal"]
        assert "synthetic-cam-name" in str(result)

    async def test_manual_page_unwraps_data_envelope(self, client, registry):
        # In manual-paging mode (offset/limit given) the endpoint's single-page
        # response may be a {"data": [...]} envelope; the drainer unwraps it.
        client.get.return_value = {"data": [{"id": "evt-4", "type": "motion"}]}
        result = await list_protect_events(client, registry, "h", _EV_START_S, _EV_END_S, limit=200)
        assert result["count"] == 1
        client.paginate_offset.assert_not_called()

    async def test_truncated_host_id_raises_host_error(self, client, registry):
        client.paginate_offset.side_effect = UniFiConnectionError(
            "HTTP 403 forbidden: host not found"
        )
        with pytest.raises(UniFiConnectionError, match="host id"):
            await list_protect_events(client, registry, "h", _EV_START_S, _EV_END_S)

    # --- New filters: smart_detect_types, categories, without_descriptions ---

    async def test_smart_detect_types_without_types_raises(self, client, registry):
        # Passing smart_detect_types alone is a silent no-op upstream (verified live);
        # the tool rejects it instead of returning the full, unfiltered set.
        with pytest.raises(ValueError, match="only honored"):
            await list_protect_events(
                client,
                registry,
                "h",
                _EV_START_S,
                _EV_END_S,
                smart_detect_types="person",
            )
        client.paginate_offset.assert_not_called()
        client.get.assert_not_called()

    async def test_smart_detect_types_passthrough_with_types(self, client, registry):
        client.paginate_offset.return_value = []
        await list_protect_events(
            client,
            registry,
            "h",
            _EV_START_S,
            _EV_END_S,
            types="smartDetectZone",
            smart_detect_types="person",
        )
        params = client.paginate_offset.call_args.kwargs["params"]
        assert params["types"] == "smartDetectZone"
        assert params["smartDetectTypes"] == "person"

    async def test_smart_detect_types_list_passthrough(self, client, registry):
        client.paginate_offset.return_value = []
        await list_protect_events(
            client,
            registry,
            "h",
            _EV_START_S,
            _EV_END_S,
            types=["smartDetectZone", "smartAudioDetect"],
            smart_detect_types=["person", "alrmSpeak"],
        )
        params = client.paginate_offset.call_args.kwargs["params"]
        assert params["smartDetectTypes"] == ["person", "alrmSpeak"]

    async def test_new_filters_omitted_when_none(self, client, registry):
        client.paginate_offset.return_value = []
        await list_protect_events(client, registry, "h", _EV_START_S, _EV_END_S)
        params = client.paginate_offset.call_args.kwargs["params"]
        assert "smartDetectTypes" not in params
        assert "categories" not in params
        assert "withoutDescriptions" not in params

    async def test_categories_single_and_list_passthrough(self, client, registry):
        client.paginate_offset.return_value = []
        await list_protect_events(client, registry, "h", _EV_START_S, _EV_END_S, categories="smart")
        assert client.paginate_offset.call_args.kwargs["params"]["categories"] == "smart"
        client.paginate_offset.reset_mock()
        await list_protect_events(
            client, registry, "h", _EV_START_S, _EV_END_S, categories=["motion", "iot"]
        )
        assert client.paginate_offset.call_args.kwargs["params"]["categories"] == ["motion", "iot"]

    async def test_without_descriptions_true_sets_param(self, client, registry):
        client.paginate_offset.return_value = []
        await list_protect_events(
            client, registry, "h", _EV_START_S, _EV_END_S, without_descriptions=True
        )
        assert client.paginate_offset.call_args.kwargs["params"]["withoutDescriptions"] == "true"

    async def test_without_descriptions_false_omits_param(self, client, registry):
        # Opt-in only: full fidelity is the default, so False/None must not send it.
        client.paginate_offset.return_value = []
        await list_protect_events(
            client, registry, "h", _EV_START_S, _EV_END_S, without_descriptions=False
        )
        assert "withoutDescriptions" not in client.paginate_offset.call_args.kwargs["params"]

    async def test_smart_detect_types_actually_narrows(self, client, registry):
        # End-to-end through the tool: a server that honours smartDetectTypes returns
        # only the matching subtype, and the tool surfaces exactly that narrowed set.
        dataset = [
            {"id": "z1", "type": "smartDetectZone", "smartDetectTypes": ["person"]},
            {"id": "z2", "type": "smartDetectZone", "smartDetectTypes": ["animal"]},
            {"id": "z3", "type": "smartDetectZone", "smartDetectTypes": ["person"]},
        ]

        async def fake_drain(path, *, key=None, params=None, page_size=200):
            want = (params or {}).get("smartDetectTypes")
            if want is None:
                return dataset
            wants = {want} if isinstance(want, str) else set(want)
            return [e for e in dataset if wants & set(e["smartDetectTypes"])]

        client.paginate_offset.side_effect = fake_drain
        allz = await list_protect_events(
            client, registry, "h", _EV_START_S, _EV_END_S, types="smartDetectZone"
        )
        assert allz["count"] == 3
        person = await list_protect_events(
            client,
            registry,
            "h",
            _EV_START_S,
            _EV_END_S,
            types="smartDetectZone",
            smart_detect_types="person",
        )
        assert person["count"] == 2
        assert {e["id"] for e in person["events"]} == {"z1", "z3"}

    # --- cameras: name-or-ID resolution ---

    async def test_cameras_name_resolved_to_id(self, client, registry):
        client.get.return_value = [
            {"id": "aa" * 12, "name": "Back Porch Cam"},
            {"id": "bb" * 12, "name": "Living Room Cam"},
        ]
        client.paginate_offset.return_value = []
        await list_protect_events(
            client, registry, "h", _EV_START_S, _EV_END_S, cameras="back porch cam"
        )
        assert client.get.call_args.args[0] == f"{BASE}/cameras"
        assert client.paginate_offset.call_args.kwargs["params"]["cameras"] == ["aa" * 12]

    async def test_cameras_id_passes_through(self, client, registry):
        client.get.return_value = [{"id": "aa" * 12, "name": "Back Porch Cam"}]
        client.paginate_offset.return_value = []
        await list_protect_events(client, registry, "h", _EV_START_S, _EV_END_S, cameras="cc" * 12)
        assert client.paginate_offset.call_args.kwargs["params"]["cameras"] == ["cc" * 12]

    async def test_cameras_mixed_name_and_id(self, client, registry):
        client.get.return_value = [
            {"id": "aa" * 12, "name": "Back Porch Cam"},
            {"id": "bb" * 12, "name": "Living Room Cam"},
        ]
        client.paginate_offset.return_value = []
        await list_protect_events(
            client,
            registry,
            "h",
            _EV_START_S,
            _EV_END_S,
            cameras=["Living Room Cam", "aa" * 12],
        )
        assert client.paginate_offset.call_args.kwargs["params"]["cameras"] == [
            "bb" * 12,
            "aa" * 12,
        ]

    async def test_cameras_unknown_name_raises(self, client, registry):
        client.get.return_value = [{"id": "aa" * 12, "name": "Back Porch Cam"}]
        with pytest.raises(ValueError, match="not found"):
            await list_protect_events(
                client, registry, "h", _EV_START_S, _EV_END_S, cameras="Nonexistent Cam"
            )
        client.paginate_offset.assert_not_called()
