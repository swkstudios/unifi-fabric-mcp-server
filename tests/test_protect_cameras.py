"""Unit tests for Protect camera operations — list, get, update, snapshot,
talkback, mic-disable, PTZ, and RTSPS stream GET."""

from __future__ import annotations

import base64
from unittest.mock import AsyncMock

import pytest

from tests._protect_writes import assert_write, resp
from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.tools.protect import (
    PROTECT_MUTATIONS_ENV,
    PROTECT_PRIVATE_BASE,
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
    c.request = AsyncMock(return_value=resp({}))
    c.get = AsyncMock()
    c.get_binary = AsyncMock()
    c.post = AsyncMock()
    c.patch = AsyncMock()
    c.delete = AsyncMock()
    return c


@pytest.fixture()
def registry():
    r = AsyncMock()
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    r.resolve_key_for_host = AsyncMock(return_value=None)
    return r


# --- list_cameras ---


class TestListCameras:
    async def test_list_returns_dict(self, client, registry):
        client.get.return_value = [{"id": "cam-1", "name": "Front Door"}]
        result = await list_cameras(client, registry, "myhost")
        client.get.assert_called_once_with(f"{BASE}/cameras", key=None)
        assert result == {"result": [{"id": "cam-1", "name": "Front Door"}], "_count": 1}

    async def test_data_wrapper(self, client, registry):
        client.get.return_value = {"data": [{"id": "cam-2"}, {"id": "cam-3"}]}
        result = await list_cameras(client, registry, "myhost")
        assert result["_count"] == 2
        assert len(result["data"]) == 2

    async def test_empty_list(self, client, registry):
        client.get.return_value = []
        result = await list_cameras(client, registry, "myhost")
        assert result == {"result": [], "_count": 0}

    async def test_resolves_host(self, client, registry):
        client.get.return_value = []
        await list_cameras(client, registry, "MyHost")
        registry.resolve_host_id.assert_called_once_with("MyHost", key=None)


# --- get_camera ---


class TestGetCamera:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "cam-1", "state": "CONNECTED"}
        result = await get_camera(client, registry, "h", "cam-1")
        client.get.assert_called_once_with(f"{BASE}/cameras/cam-1", key=None)
        assert result["id"] == "cam-1"
        assert result["state"] == "CONNECTED"

    async def test_non_object_body_raises(self, client, registry):
        client.get.return_value = ["raw"]
        with pytest.raises(UniFiConnectionError, match="expected an object, got array"):
            await get_camera(client, registry, "h", "cam-1")

    async def test_resolves_host(self, client, registry):
        client.get.return_value = {"id": "cam-1"}
        await get_camera(client, registry, "myhost", "cam-1")
        registry.resolve_host_id.assert_called_once_with("myhost", key=None)


# --- update_camera ---


class TestUpdateCamera:
    async def test_basic(self, client, registry):
        client.get.side_effect = [
            {"id": "cam-1", "name": "Old"},
            {"id": "cam-1", "name": "Backyard"},
        ]
        client.request.return_value = resp({"id": "cam-1", "name": "Backyard"})
        result = await update_camera(client, registry, "h", "cam-1", name="Backyard")
        assert_write(
            client,
            "PATCH",
            f"{BASE}/cameras/cam-1",
            json={"name": "Backyard"},
            key=None,
        )
        assert result["response"]["name"] == "Backyard"
        assert result["verified"] is True
        assert result["before"]["name"] == "Old"

    async def test_noop_when_already_set(self, client, registry):
        client.get.return_value = {"id": "cam-1", "name": "Backyard"}
        result = await update_camera(client, registry, "h", "cam-1", name="Backyard")
        client.request.assert_not_called()
        assert result["status"] == "noop"

    async def test_multiple_fields(self, client, registry):
        client.get.side_effect = [
            {"id": "cam-1"},
            {"id": "cam-1", "name": "Gate", "recordingMode": "always"},
        ]
        client.request.return_value = resp(
            {"id": "cam-1", "name": "Gate", "recordingMode": "always"}
        )
        result = await update_camera(
            client, registry, "h", "cam-1", name="Gate", recordingMode="always"
        )
        call_json = client.request.call_args[1]["json"]
        assert call_json["name"] == "Gate"
        assert call_json["recordingMode"] == "always"
        assert result["response"]["recordingMode"] == "always"

    async def test_empty_body_is_reported_not_raised(self, client, registry):
        client.get.side_effect = [{"id": "cam-1"}, {"id": "cam-1", "name": "X"}]
        client.request.return_value = resp()
        result = await update_camera(client, registry, "h", "cam-1", name="X")
        assert result == {
            "status": "updated",
            "verified": True,
            "before": {"id": "cam-1"},
            "after": {"id": "cam-1", "name": "X"},
            "response": None,
        }


# --- get_camera_snapshot ---


class TestGetCameraSnapshot:
    async def test_basic(self, client, registry):
        jpeg_bytes = b"\xff\xd8\xff\xe0" + b"\x00" * 16
        client.get_binary.return_value = (jpeg_bytes, "image/jpeg")
        result = await get_camera_snapshot(client, registry, "h", "cam-1")
        client.get_binary.assert_called_once_with(f"{BASE}/cameras/cam-1/snapshot", key=None)
        assert result["image_base64"] == base64.b64encode(jpeg_bytes).decode()
        assert result["content_type"] == "image/jpeg"
        assert result["size_bytes"] == len(jpeg_bytes)

    async def test_resolves_host(self, client, registry):
        client.get_binary.return_value = (b"\xff\xd8\xff", "image/jpeg")
        await get_camera_snapshot(client, registry, "console-1", "cam-99")
        registry.resolve_host_id.assert_called_once_with("console-1", key=None)

    @pytest.mark.parametrize(
        "kwargs,params",
        [
            ({"channel": "package"}, {"channel": "package"}),
            ({"channel": "main", "high_quality": True}, {"channel": "main", "highQuality": "true"}),
            ({"high_quality": False}, {"highQuality": "false"}),
        ],
    )
    async def test_channel_and_high_quality_passed_through(self, client, registry, kwargs, params):
        # The spec's optional channel / highQuality query parameters are sent only when
        # given, channel verbatim (package camera included).
        client.get_binary.return_value = (b"\xff\xd8\xff", "image/jpeg")
        await get_camera_snapshot(client, registry, "h", "cam-1", **kwargs)
        client.get_binary.assert_called_once_with(
            f"{BASE}/cameras/cam-1/snapshot", key=None, params=params
        )


# --- get_rtsps_stream ---


def _rtsps_body():
    return {
        "high": "rtsps://192.0.2.1:7441/synthetic-high",
        "medium": "rtsps://192.0.2.1:7441/synthetic-medium",
        "low": None,
        "package": None,
    }


class TestGetRtspsStream:
    async def test_basic(self, client, registry):
        # Live response: two stream strings and nullable low/package channels.
        body = _rtsps_body()
        client.get.return_value = body
        result = await get_rtsps_stream(client, registry, "h", "cam-1")
        client.get.assert_called_once_with(f"{BASE}/cameras/cam-1/rtsps-stream", key=None)
        assert set(result) == {"high", "medium", "low", "package"}
        assert result["high"].startswith("rtsps://")
        assert result == body
        assert result["low"] is None and result["package"] is None

    async def test_non_object_body_raises(self, client, registry):
        client.get.return_value = None
        with pytest.raises(UniFiConnectionError, match="expected an object, got NoneType"):
            await get_rtsps_stream(client, registry, "h", "cam-1")


# --- talkback_start ---


class TestTalkbackStart:
    async def test_basic(self, client, registry):
        client.request.return_value = resp({"sessionId": "sess-1", "status": "started"})
        result = await talkback_start(client, registry, "h", "cam-1", confirm=True)
        assert_write(
            client,
            "POST",
            f"{BASE}/cameras/cam-1/talkback-session",
            json=None,
            key=None,
        )
        assert result["response"]["status"] == "started"

    async def test_non_dict_fallback(self, client, registry):
        client.request.return_value = resp()
        result = await talkback_start(client, registry, "h", "cam-1", confirm=True)
        assert result == {"status": "sent", "response": None}  # empty body reported

    async def test_resolves_host(self, client, registry):
        client.request.return_value = resp({"status": "ok"})
        await talkback_start(client, registry, "console-x", "cam-5", confirm=True)
        registry.resolve_host_id.assert_called_once_with("console-x", key=None)


# --- disable_mic_permanently ---


class TestDisableMicPermanently:
    async def test_basic(self, client, registry):
        client.request.return_value = resp({"micDisabled": True})
        result = await disable_mic_permanently(client, registry, "h", "cam-1", confirm=True)
        assert_write(
            client,
            "POST",
            f"{BASE}/cameras/cam-1/disable-mic-permanently",
            json=None,
            key=None,
        )
        assert result["response"]["micDisabled"] is True

    async def test_non_dict_fallback(self, client, registry):
        client.request.return_value = resp()
        result = await disable_mic_permanently(client, registry, "h", "cam-1", confirm=True)
        assert result == {"status": "sent", "response": None}  # empty body reported

    async def test_resolves_host(self, client, registry):
        client.request.return_value = resp({"status": "ok"})
        await disable_mic_permanently(client, registry, "console-y", "cam-7", confirm=True)
        registry.resolve_host_id.assert_called_once_with("console-y", key=None)


# --- ptz_goto ---


class TestPtzGoto:
    async def test_basic(self, client, registry):
        client.request.return_value = resp({"status": "moving"})
        result = await ptz_goto(client, registry, "h", "cam-1", 2, confirm=True)
        assert_write(client, "POST", f"{BASE}/cameras/cam-1/ptz/goto/2", json=None, key=None)
        assert result["response"]["status"] == "moving"

    async def test_slot_zero(self, client, registry):
        client.request.return_value = resp({"status": "ok"})
        result = await ptz_goto(client, registry, "h", "cam-1", 0, confirm=True)
        assert_write(client, "POST", f"{BASE}/cameras/cam-1/ptz/goto/0", json=None, key=None)
        assert result == {"status": "sent", "response": {"status": "ok"}}

    async def test_non_dict_fallback(self, client, registry):
        client.request.return_value = resp()
        result = await ptz_goto(client, registry, "h", "cam-1", 1, confirm=True)
        assert result == {"status": "sent", "response": None}  # empty body reported

    async def test_resolves_host(self, client, registry):
        client.request.return_value = resp({"status": "ok"})
        await ptz_goto(client, registry, "ptz-console", "cam-ptz", 3, confirm=True)
        registry.resolve_host_id.assert_called_once_with("ptz-console", key=None)


# --- ptz_patrol_start ---


class TestPtzPatrolStart:
    async def test_basic(self, client, registry):
        client.request.return_value = resp({"patrolling": True})
        result = await ptz_patrol_start(client, registry, "h", "cam-1", 1, confirm=True)
        assert_write(
            client,
            "POST",
            f"{BASE}/cameras/cam-1/ptz/patrol/start/1",
            json=None,
            key=None,
        )
        assert result["response"]["patrolling"] is True

    async def test_non_dict_fallback(self, client, registry):
        client.request.return_value = resp()
        result = await ptz_patrol_start(client, registry, "h", "cam-1", 0, confirm=True)
        assert result == {"status": "sent", "response": None}  # empty body reported


# --- ptz_patrol_stop ---


class TestPtzPatrolStop:
    async def test_basic(self, client, registry):
        client.request.return_value = resp({"patrolling": False})
        result = await ptz_patrol_stop(client, registry, "h", "cam-1", confirm=True)
        assert_write(
            client,
            "POST",
            f"{BASE}/cameras/cam-1/ptz/patrol/stop",
            json=None,
            key=None,
        )
        assert result["response"]["patrolling"] is False

    async def test_non_dict_fallback(self, client, registry):
        client.request.return_value = resp()
        result = await ptz_patrol_stop(client, registry, "h", "cam-1", confirm=True)
        assert result == {"status": "sent", "response": None}  # empty body reported

    async def test_resolves_host(self, client, registry):
        client.request.return_value = resp({"status": "ok"})
        await ptz_patrol_stop(client, registry, "console-z", "cam-ptz", confirm=True)
        registry.resolve_host_id.assert_called_once_with("console-z", key=None)


# --- Confirm + mutation-gate guards for physical camera actions ---
# Each tuple: (callable, extra positional args, expected POST path suffix). The gate
# must refuse BEFORE any upstream HTTP call in both the no-confirm and the
# mutations-disabled cases.
_CAMERA_ACTIONS = [
    (talkback_start, ("cam-1",), "/cameras/cam-1/talkback-session"),
    (disable_mic_permanently, ("cam-1",), "/cameras/cam-1/disable-mic-permanently"),
    (ptz_goto, ("cam-1", 2), "/cameras/cam-1/ptz/goto/2"),
    (ptz_patrol_start, ("cam-1", 1), "/cameras/cam-1/ptz/patrol/start/1"),
    (ptz_patrol_stop, ("cam-1",), "/cameras/cam-1/ptz/patrol/stop"),
]


@pytest.mark.parametrize("fn,args,suffix", _CAMERA_ACTIONS)
async def test_camera_action_runs_without_confirm(client, registry, fn, args, suffix):
    # No gate: confirm is accepted but ignored; the action runs without it.
    client.request.return_value = resp({})
    result = await fn(client, registry, "h", *args)
    # physical actions are never auto-retried on 429 (a retry could repeat them)
    assert_write(client, "POST", f"{BASE}{suffix}", json=None, key=None)
    assert result == {"status": "sent", "response": {}}


@pytest.mark.parametrize("fn,args,suffix", _CAMERA_ACTIONS)
async def test_camera_action_executes_with_confirm(client, registry, fn, args, suffix):
    client.request.return_value = resp({})
    result = await fn(client, registry, "h", *args, confirm=True)
    # physical actions are never auto-retried on 429 (a retry could repeat them)
    assert_write(client, "POST", f"{BASE}{suffix}", json=None, key=None)
    assert result == {"status": "sent", "response": {}}


@pytest.mark.parametrize("fn,args,suffix", _CAMERA_ACTIONS)
async def test_camera_action_gate_disabled_beats_confirm(
    monkeypatch, client, registry, fn, args, suffix
):
    monkeypatch.setenv(PROTECT_MUTATIONS_ENV, "off")
    with pytest.raises(ValueError, match="(?i)writes|mutation|disabled|opted"):
        await fn(client, registry, "h", *args, confirm=True)
    client.request.assert_not_called()


# --- get_camera_snapshot ts (recording-snapshot) ---


class TestGetCameraSnapshotAtTime:
    """``ts`` reads a past moment from the private recording-snapshot route."""

    PRIVATE = PROTECT_PRIVATE_BASE.format(host_id=HOST_ID)

    async def test_ts_routes_to_the_private_recording_snapshot(self, client, registry):
        jpeg = b"\xff\xd8\xff\xe0" + b"\x00" * 16
        client.get_binary.return_value = (jpeg, "image/jpeg")
        result = await get_camera_snapshot(client, registry, "h", "cam-1", ts=1_760_140_800_000)
        client.get_binary.assert_called_once_with(
            f"{self.PRIVATE}/cameras/cam-1/recording-snapshot",
            key=None,
            params={"ts": 1_760_140_800_000},
        )
        assert result["image_base64"] == base64.b64encode(jpeg).decode()
        assert result["content_type"] == "image/jpeg"

    async def test_ts_is_sent_as_given_with_the_other_optional_params(self, client, registry):
        client.get_binary.return_value = (b"\xff\xd8\xff", "image/jpeg")
        await get_camera_snapshot(
            client, registry, "h", "cam-1", channel="main", high_quality=True, ts=0
        )
        # ts=0 is a value the caller gave, so it is sent (not dropped as falsy).
        client.get_binary.assert_called_once_with(
            f"{self.PRIVATE}/cameras/cam-1/recording-snapshot",
            key=None,
            params={"channel": "main", "highQuality": "true", "ts": 0},
        )

    async def test_without_ts_the_live_integration_route_is_unchanged(self, client, registry):
        client.get_binary.return_value = (b"\xff\xd8\xff", "image/jpeg")
        await get_camera_snapshot(client, registry, "h", "cam-1")
        client.get_binary.assert_called_once_with(f"{BASE}/cameras/cam-1/snapshot", key=None)

    async def test_upstream_404_reaches_the_caller_untouched(self, client, registry):
        # Probed 2026-10-17 (Protect 5.3.18): ts accepted, answer 404 "Recording not found".
        client.get_binary.side_effect = RuntimeError("HTTP 404: Recording not found")
        with pytest.raises(RuntimeError, match="Recording not found"):
            await get_camera_snapshot(client, registry, "h", "cam-1", ts=1)

    async def test_invalid_camera_id_sends_nothing(self, client, registry):
        with pytest.raises(ValueError):
            await get_camera_snapshot(client, registry, "h", "", ts=1)
        client.get_binary.assert_not_called()
        registry.resolve_host_id.assert_not_called()

    def test_ts_provenance_is_documented_on_the_tool(self):
        from unifi_fabric import server

        tool = server.get_camera_snapshot
        doc = (getattr(tool, "description", None) or "") + (tool.__doc__ or "")
        for needle in ("2026-10-17", "5.3.18", "400", "404", "Recording not found", "inferred"):
            assert needle in doc, needle
        assert "unverified" in doc
