"""Captured Protect query failures retain optional arguments and legacy wire shapes."""

import json
from unittest.mock import AsyncMock

import httpx
import pytest

from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.families.protect import protect_camera_recording as recording
from unifi_fabric.families.protect import protect_device_lifecycle as lifecycle
from unifi_fabric.families.protect import protect_recognition_search as recognition

DEVICE = "66d025b301ebc903e80003ec"


@pytest.mark.parametrize("kind", ["statistics", "sensor", "edge"])
@pytest.mark.parametrize("given", [False, True])
async def test_captured_query_error_preserves_optional_call_and_wire_shape(
    monkeypatch, kind, given
):
    client = AsyncMock()
    for module in (recording, lifecycle, recognition):
        monkeypatch.setattr(module, "_resolve", AsyncMock(return_value=(None, "synthetic-console")))
    supplied = {"start": 1760140800, "end": 1760140860} if given else {}
    if kind == "statistics":
        required = ["start", "end", "period"]
        if given:
            supplied["period"] = "minute"
        call = recognition._get_detection_statistics
        args = ()
        request = client.get
    elif kind == "sensor":
        required = ["start"]
        call = lifecycle.get_sensor_readings
        args = (DEVICE,)
        request = client.get
    else:
        required = ["filename", "start", "end"]
        if given:
            supplied["filename"] = "synthetic-export.mp4"
        call = recording.export_edge_recording
        args = (DEVICE, "prepare")
        request = client.request
    if given:
        request.return_value = (
            httpx.Response(200, json={"sentinel": "verbatim"})
            if kind == "edge"
            else {"sentinel": "verbatim"}
        )
        result = await call(client, None, "synthetic-console", *args, **supplied)
        assert result["sentinel"] == "verbatim"
    else:
        captured = {
            "error": "Failed to parse 'request-query'",
            "name": "AJV_PARSE_ERROR",
            "entity": "request-query",
            "issues": [
                {
                    "instancePath": "",
                    "message": f"must have required property '{field}'",
                    "keyword": "required",
                }
                for field in required
            ],
            "body": {},
            "isUserError": True,
        }
        upstream = json.dumps(captured, separators=(",", ":"))
        request.side_effect = UniFiConnectionError(upstream, status=400, request_sent=True)
        with pytest.raises(UniFiConnectionError) as caught:
            await call(client, None, "synthetic-console", *args)
        assert upstream in str(caught.value)
        assert "Hint:" in str(caught.value)
        assert all(field in str(caught.value).split("Hint:", 1)[1] for field in required)
        assert caught.value.status == 400
        assert caught.value.request_sent is True
    request.assert_awaited_once()
    expected = {
        key: value * 1000 if key in {"start", "end"} else value for key, value in supplied.items()
    } or None
    assert request.await_args.kwargs["params"] == expected
