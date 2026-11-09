"""Hermetic private Protect route, merge, identity and verification tests."""

from __future__ import annotations

import base64
import copy
import logging
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from unifi_fabric import secret_scrub
from unifi_fabric.client import DRY_RUN_MESSAGE, UniFiConnectionError
from unifi_fabric.tools import protect_private as pp

ID = "0000000000000000000000aa"
HOST_ID = "console-001"
BASE = f"/v1/connector/consoles/{HOST_ID}/proxy/protect/api"


@pytest.fixture
def rig():
    state = {
        "id": ID,
        "name": "Camera A",
        "recordingSettings": {"mode": "always", "prePaddingSecs": 8},
        "smartDetectSettings": {"objectTypes": ["person", "vehicle"], "audioTypes": ["smoke"]},
        "stats": {"rxBytes": 1},
        "ptzSettings": {
            "presets": [{"id": "preset-1", "name": "Door"}],
            "patrols": [{"id": "patrol-1", "name": "Loop"}],
        },
    }
    calls = []
    c = AsyncMock()
    c.settings = None
    r = AsyncMock()
    r.resolve_key_for_host.return_value = None
    r.resolve_host_id.return_value = HOST_ID

    async def request(method, path, **kwargs):
        calls.append((method, path, kwargs))
        if method == "GET":
            body = (
                [copy.deepcopy(state)]
                if path.endswith(("/cameras", "/sensors"))
                else copy.deepcopy(state)
            )
            return httpx.Response(200, json=body)
        state.update(copy.deepcopy(kwargs.get("json") or {}))
        state["stats"]["rxBytes"] += 1
        return httpx.Response(200, json={"saved": True, "upstreamExtra": [1, 2, 3]})

    c.request.side_effect = request
    return c, r, state, calls


@pytest.mark.parametrize(
    "fn,collection",
    [
        ("get_camera_private", "cameras"),
        ("get_sensor_private", "sensors"),
    ],
)
async def test_private_get_preserves_full_upstream_and_owning_key(rig, fn, collection):
    c, r, state, calls = rig
    result = await getattr(pp, fn)(c, r, "example", ID)
    assert result["body"] == state
    assert calls[-1][1] == f"{BASE}/{collection}/{ID}"
    r.resolve_key_for_host.assert_awaited()
    assert calls[-1][2]["key"] is None


@pytest.mark.parametrize("fn", ["update_camera_private", "update_sensor_private"])
async def test_nested_merge_preserves_siblings_and_replaces_supplied_arrays(rig, fn):
    c, r, state, calls = rig
    before = copy.deepcopy(state)
    requested = {
        "recordingSettings": {"mode": "detections"},
        "smartDetectSettings": {"objectTypes": []},
    }
    result = await getattr(pp, fn)(c, r, "example", ID, requested)
    writes = [entry for entry in calls if entry[0] == "PATCH"]
    assert len(writes) == 1
    body = writes[0][2]["json"]
    assert body == {
        "recordingSettings": {"mode": "detections", "prePaddingSecs": 8},
        "smartDetectSettings": {"objectTypes": [], "audioTypes": ["smoke"]},
    }
    assert before["smartDetectSettings"]["objectTypes"] == ["person", "vehicle"]
    assert requested["smartDetectSettings"] == {"objectTypes": []}
    assert result["_verified"] is True
    assert result["_noOp"] is False
    assert result["body"] == {"saved": True, "upstreamExtra": [1, 2, 3]}


async def test_same_fields_are_noop_despite_volatile_stats(rig):
    c, r, state, calls = rig
    result = await pp.update_camera_private(
        c, r, "example", ID, {"recordingSettings": {"mode": "always"}}
    )
    assert result["_noOp"] is True
    assert result["_verified"] is True


async def test_failed_readback_is_not_verified(rig):
    c, r, state, calls = rig
    original = c.request.side_effect

    async def discard(method, path, **kwargs):
        response = await original(method, path, **kwargs)
        if method == "PATCH":
            state["recordingSettings"]["mode"] = "always"
        return response

    c.request.side_effect = discard
    result = await pp.update_camera_private(
        c, r, "example", ID, {"recordingSettings": {"mode": "detections"}}
    )
    assert result["_verified"] is False


@pytest.mark.parametrize(
    "env,value",
    [
        ("UNIFI_WRITE_POLICY", "deny"),
        ("UNIFI_WRITE_EXCEPTIONS", "family:connector=deny"),
        ("UNIFI_WRITE_EXCEPTIONS", "family:protect=deny"),
    ],
)
async def test_optouts_precede_resolution(rig, monkeypatch, env, value):
    c, r, _, _ = rig
    monkeypatch.setenv(env, value)
    with pytest.raises(Exception, match=env):
        await pp.update_camera_private(c, r, "example", ID, {"name": "new"})
    r.resolve_key_for_host.assert_not_awaited()
    r.resolve_host_id.assert_not_awaited()
    c.request.assert_not_awaited()


async def test_dry_run_does_not_read_after(rig):
    c, r, _, calls = rig
    c.dry_run = True
    original = c.request.side_effect

    async def preview(method, path, **kwargs):
        if method == "PATCH":
            calls.append((method, path, kwargs))
            return httpx.Response(
                200,
                json={
                    "dryRun": True,
                    "message": DRY_RUN_MESSAGE,
                    "preview": {"method": method, "path": path},
                },
            )
        return await original(method, path, **kwargs)

    c.request.side_effect = preview
    result = await pp.update_camera_private(c, r, "example", ID, {"name": "new"})
    assert result["_verified"] is None
    assert calls[-1][0] == "PATCH"
    assert result["body"]["dryRun"] is True


async def test_name_selector_resolves_private_id(rig):
    c, r, _, calls = rig
    await pp.get_camera_private(c, r, "example", "Camera A")
    assert any(path == f"{BASE}/cameras" for _, path, _ in calls)
    assert calls[-1][1] == f"{BASE}/cameras/{ID}"


@pytest.mark.parametrize("fn", ["get_camera_private", "get_sensor_private"])
async def test_unknown_selector_lists_valid_choices(rig, fn):
    c, r, _, _ = rig
    with pytest.raises(Exception, match="Camera A"):
        await getattr(pp, fn)(c, r, "example", "missing")


async def test_nvr_private_route(rig):
    c, r, state, calls = rig
    result = await pp.get_nvr_private(c, r, "example")
    assert calls[-1][1] == f"{BASE}/nvr"
    assert result["body"] == state


@pytest.mark.parametrize("channel,lens", [(0, None), (3, 2)])
async def test_video_export_seconds_and_uncapped_binary(rig, channel, lens):
    c, r, _, calls = rig
    binary = bytes(range(256)) * 8192

    async def video(method, path, **kwargs):
        calls.append((method, path, kwargs))
        return httpx.Response(200, content=binary, headers={"content-type": "video/mp4"})

    c.request.side_effect = video
    result = await pp.export_camera_video(c, r, "example", ID, 1000, 1010, channel=channel, fps=15)
    assert calls[-1][1] == f"{BASE}/video/export"
    params = calls[-1][2]["params"]
    assert params["start"] == 1000000 and params["end"] == 1010000
    assert params["camera"] == ID and params["fps"] == 15
    if lens is not None:
        assert params["lens"] == lens
    assert base64.b64decode(result["bodyBase64"]) == binary
    assert result["sizeBytes"] == len(binary)


@pytest.mark.parametrize(
    ("start", "warning_code"),
    [
        (100_000_000_000, "EPOCH_SECONDS_LOOKS_LIKE_MILLISECONDS"),
        (-1, "EPOCH_SECONDS_NEGATIVE"),
    ],
)
async def test_video_export_epoch_unit_warnings_preserve_the_sent_value(rig, start, warning_code):
    c, r, _, calls = rig

    async def video(method, path, **kwargs):
        calls.append((method, path, kwargs))
        return httpx.Response(200, content=b"video", headers={"content-type": "video/mp4"})

    c.request.side_effect = video
    result = await pp.export_camera_video(c, r, "example", ID, start, 1010)

    assert calls[-1][2]["params"]["start"] == start * 1000
    assert result["_warnings"][0]["code"] == warning_code
    assert result["_warnings"][0]["value"] == start


@pytest.mark.parametrize("start,end", [(1010, 1000), (1000, 1000)])
async def test_video_export_end_not_after_start_reaches_upstream(rig, start, end):
    """No pinned spec orders the window: end <= start is sent as given, never refused."""
    c, r, _, calls = rig

    async def video(method, path, **kwargs):
        calls.append((method, path, kwargs))
        return httpx.Response(400, json={"error": "upstream judges the window"})

    c.request.side_effect = video
    result = await pp.export_camera_video(c, r, "example", ID, start, end)
    assert calls[-1][1] == f"{BASE}/video/export"
    params = calls[-1][2]["params"]
    assert params["start"] == start * 1000 and params["end"] == end * 1000
    assert result["status"] == 400
    assert result["body"] == {"error": "upstream judges the window"}


async def test_unadopt_read_after_404_confirms_the_delete(rig):
    c, r, state, calls = rig

    async def request(method, path, **kwargs):
        calls.append((method, path, kwargs))
        deleted = any(m == "DELETE" for m, _, _ in calls)
        if method == "GET" and deleted:
            return httpx.Response(404, json={"error": "not found"})
        if method == "GET":
            body = [copy.deepcopy(state)] if path.endswith("/cameras") else copy.deepcopy(state)
            return httpx.Response(200, json=body)
        return httpx.Response(200, json={"deleted": True})

    c.request.side_effect = request
    result = await pp.unadopt_protect_device(c, r, "example", "camera", ID)
    assert [m for m, _, _ in calls if m != "GET"] == ["DELETE"]
    assert result["readAfter"]["status"] == 404
    assert "readAfterError" not in result
    assert result["changed"] is True and result["noOp"] is False
    assert result["_verified"] is True and result["_noOp"] is False
    assert result["body"] == {"deleted": True}


@pytest.mark.parametrize(
    "fn", ["reboot_protect_device", "adopt_protect_device", "unadopt_protect_device"]
)
async def test_invalid_device_type_never_reaches_connector_logs(rig, caplog, monkeypatch, fn):
    """Invalid collection selectors never reach the connector or expose secrets."""
    c, r, _state, calls = rig
    secret = "synthetic-protect-device-type-secret"
    monkeypatch.setattr(secret_scrub, "_provider", lambda: (secret,))
    secret_scrub.install_log_scrubber()
    with caplog.at_level(logging.DEBUG, logger="unifi_fabric.tools.connector"):
        with pytest.raises(ValueError, match="device_type") as exc:
            await getattr(pp, fn)(c, r, "example", secret, ID)
    assert calls == []
    assert secret not in caplog.text and secret not in str(exc.value)


ABSENT_ID = "000000000000000000000000"


@pytest.mark.parametrize("native", [ABSENT_ID, ID.upper()])
async def test_adopt_native_id_is_sent_once_without_list(rig, native):
    c, r, _state, calls = rig
    result = await pp.adopt_protect_device(c, r, "example", "camera", native)
    assert [(m, p) for m, p, _ in calls] == [("POST", f"{BASE}/devices/adopt")]
    assert calls[0][2]["json"] == {"cameras": {native.lower(): {}}}
    assert result["status"] == 200


@pytest.mark.parametrize("registered", [False, True])
async def test_adopt_unknown_native_preserves_nested_error_without_listing(rig, registered):
    from fastmcp import FastMCP

    c, r, _state, calls = rig
    nested = {
        "cameras": {
            ABSENT_ID: {"adopted": False, "error": {"code": 404, "message": "Device Not Found"}}
        }
    }

    async def request(method, path, **kwargs):
        calls.append((method, path, kwargs))
        assert method == "POST"
        return httpx.Response(200, json=nested)

    c.request.side_effect = request
    if registered:
        mcp = FastMCP("adopt")
        pp.register(mcp, lambda: (c, r))
        tool = {t.name: t for t in await mcp.list_tools()}["adopt_protect_device"]
        result = await tool.fn(host="example", device_type="camera", device_id=ABSENT_ID)
    else:
        result = await pp.adopt_protect_device(c, r, "example", "camera", ABSENT_ID)
    assert [(m, p) for m, p, _ in calls] == [("POST", f"{BASE}/devices/adopt")]
    assert calls[0][2]["json"] == {"cameras": {ABSENT_ID: {}}}
    assert result["status"] == 200
    assert result["body"] == nested


@pytest.mark.parametrize(
    "fn,method,path",
    [
        ("reboot_protect_device", "POST", f"{BASE}/cameras/{ID}/reboot"),
        ("adopt_protect_device", "POST", f"{BASE}/devices/adopt"),
        ("unadopt_protect_device", "DELETE", f"{BASE}/cameras/{ID}"),
    ],
)
async def test_device_action_routes_and_verbatim_response(rig, fn, method, path):
    c, r, _, calls = rig
    result = await getattr(pp, fn)(c, r, "example", "camera", ID)
    writes = [call for call in calls if call[0] != "GET"]
    assert len(writes) == 1
    assert writes[0][:2] == (method, path)
    if fn == "adopt_protect_device":
        assert writes[0][2]["json"] == {"cameras": {ID: {}}}
    assert result["body"]["upstreamExtra"] == [1, 2, 3]


@pytest.mark.parametrize("fn", ["reboot_protect_device", "unadopt_protect_device"])
def test_direct_protect_write_audit_scrubs_secret_in_fresh_process(fn):
    """Direct tool use must install log scrubbing without server.py."""
    script = f"""
import asyncio
import io
import logging
import sys
from unittest.mock import AsyncMock

import httpx
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.tools import protect_private as pp

SECRET = "synthetic-direct-protect-audit-secret"
ID = "0000000000000000000000aa"

assert "unifi_fabric.server" not in sys.modules

async def main():
    client = UniFiClient(Settings(api_key=SECRET))
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = None
    registry.resolve_host_id.return_value = "console-001"
    responses = [httpx.Response(200, json={{"ok": True}})]
    if "{fn}" == "unadopt_protect_device":
        responses = [
            httpx.Response(200, json={{"id": ID}}),
            httpx.Response(200, json={{"deleted": True}}),
            httpx.Response(404, json={{"error": "not found"}}),
        ]
    client.request = AsyncMock(side_effect=responses)
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    logger = logging.getLogger("unifi_fabric.tools.connector")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        await getattr(pp, "{fn}")(client, registry, SECRET, "camera", ID)
    finally:
        logger.removeHandler(handler)
        await client.close()
    return SECRET not in stream.getvalue()

raise SystemExit(0 if asyncio.run(main()) else 1)
"""
    completed = subprocess.run([sys.executable, "-"], input=script, text=True, capture_output=True)
    assert completed.returncode == 0


async def test_reboot_nvr_route(rig):
    c, r, _, calls = rig
    await pp.reboot_nvr(c, r, "example")
    assert calls[-1][:2] == ("POST", f"{BASE}/nvr/reboot")


async def test_ambiguous_camera_name_lists_matches(rig):
    c, r, state, calls = rig
    original = c.request.side_effect

    async def duplicated(method, path, **kwargs):
        if method == "GET" and path.endswith("/cameras"):
            other = {**state, "id": "0000000000000000000000bb"}
            return httpx.Response(200, json=[state, other])
        return await original(method, path, **kwargs)

    c.request.side_effect = duplicated
    with pytest.raises(Exception, match="(?i)ambiguous"):
        await pp.get_camera_private(c, r, "example", "Camera A")


async def test_valid_hex_get_validates_upstream_existence(rig):
    c, r, _, calls = rig
    c.request.return_value = httpx.Response(404, json={"error": "not found"})
    c.request.side_effect = None
    result = await pp.get_camera_private(c, r, "example", ID)
    assert result["status"] == 404
    assert result["body"] == {"error": "not found"}
    c.request.assert_awaited()


async def test_nvr_update_verifies_requested_fields(rig):
    c, r, _, calls = rig
    result = await pp.update_nvr(c, r, "example", {"name": "Recorder B"})
    assert any(method == "PATCH" and path == f"{BASE}/nvr" for method, path, _ in calls)
    assert result["_verified"] is True


async def test_explicit_private_owner_key_is_used_for_every_request(rig):
    c, r, _, calls = rig
    owner = object()
    r.resolve_key_for_host.return_value = owner
    await pp.update_camera_private(c, r, "example", ID, {"name": "new"})
    assert calls
    assert all(kwargs["key"] is owner for _, _, kwargs in calls)


@pytest.mark.parametrize(
    "fn,args",
    [
        ("reboot_protect_device", ("camera", ID)),
        ("adopt_protect_device", ("camera", ID)),
        ("unadopt_protect_device", ("camera", ID)),
        ("reboot_nvr", ()),
        ("clear_sensor_tamper", (ID,)),
    ],
)
async def test_action_connector_optout_precedes_any_resolution(rig, monkeypatch, fn, args):
    c, r, _, _ = rig
    monkeypatch.setenv("UNIFI_WRITE_EXCEPTIONS", "family:connector=deny")
    with pytest.raises(Exception, match="family:connector=deny"):
        await getattr(pp, fn)(c, r, "example", *args)
    r.resolve_key_for_host.assert_not_awaited()
    c.request.assert_not_awaited()


@pytest.mark.parametrize(
    "fn,suffix",
    [
        ("list_ptz_presets", "preset"),
        ("list_ptz_patrols", "patrol"),
    ],
)
async def test_ptz_routes_are_direct_verbatim_reads(rig, fn, suffix):
    c, r, _, calls = rig
    upstream = [{"id": "ptz-001", "name": "Door", "unknown": {"keep": True}}]

    async def response(method, path, **kwargs):
        calls.append((method, path, kwargs))
        return httpx.Response(200, json=upstream)

    c.request.side_effect = response
    result = await getattr(pp, fn)(c, r, "example", ID)
    assert calls[-1][1] == f"{BASE}/cameras/{ID}/ptz/{suffix}"
    assert result["body"] == upstream


async def test_sensor_tamper_route_and_additive_readback(rig):
    c, r, state, calls = rig
    result = await pp.clear_sensor_tamper(c, r, "example", ID)
    assert any(call[:2] == ("POST", f"{BASE}/sensors/{ID}/clear-tamper-flag") for call in calls)
    assert calls[-1][:2] == ("GET", f"{BASE}/sensors/{ID}")
    assert result["body"]["saved"] is True
    assert result["_readAfter"]["body"] == state


@pytest.mark.parametrize(
    "kind,fn,requested",
    [
        ("camera", "update_camera_private", {"recordingSettings": {"mode": "detections"}}),
        ("nvr", "update_nvr", {"doorbellSettings": {"customMessages": []}}),
        ("sensor", "update_sensor_private", {"ledSettings": {"isEnabled": False}}),
    ],
)
async def test_recorded_nested_settings_preserve_full_real_siblings(rig, kind, fn, requested):
    import json
    from pathlib import Path

    c, r, state, calls = rig
    fixture = json.loads(
        (
            Path(__file__).parent
            / "fixtures"
            / "recorded"
            / "protect"
            / f"{kind}_private_settings.json"
        ).read_text()
    )
    recorded = copy.deepcopy(fixture["body"])
    # Keep the fixture synthetic identity and every recorded nested settings field.
    state.clear()
    state.update(recorded)
    state["stats"] = {"rxBytes": 1}
    args = (
        (c, r, "example", requested)
        if kind == "nvr"
        else (c, r, "example", recorded["id"], requested)
    )
    result = await getattr(pp, fn)(*args)
    writes = [kwargs["json"] for method, _, kwargs in calls if method == "PATCH"]
    assert len(writes) == 1
    body = writes[0]
    assert set(body) == set(requested)
    for parent, fields in requested.items():
        assert body[parent] == {**recorded[parent], **fields}
    assert result["_verified"] is True


@pytest.mark.parametrize(
    "fn,args",
    [
        ("update_camera_private", (ID, {"name": "new"})),
        ("update_sensor_private", (ID, {"name": "new"})),
        ("update_nvr", ({"name": "new"},)),
    ],
)
async def test_read_before_failure_preserves_error_body_and_sends_no_write(rig, fn, args):
    c, r, _, calls = rig
    error = {"code": "not_found", "nested": {"unknown": [1, False, None]}}

    async def rejected(method, path, **kwargs):
        calls.append((method, path, kwargs))
        return httpx.Response(404, json=error)

    c.request.side_effect = rejected
    result = await getattr(pp, fn)(c, r, "example", *args)
    assert result["body"] == error
    assert result["status"] == 404
    assert result["_writeNotSent"] is True
    assert result["_verified"] is False
    assert result["_noOp"] is None
    assert calls and all(method == "GET" for method, _, _ in calls)


@pytest.mark.parametrize("preview", [False, True])
@pytest.mark.parametrize(
    "fn,args,consequence",
    [
        ("reboot_protect_device", ("camera", ID), "interrupts recording"),
        ("reboot_nvr", (), "interrupts recording"),
        ("adopt_protect_device", ("camera", ID), "changes management"),
        ("unadopt_protect_device", ("camera", ID), "deletes its configuration"),
        ("clear_sensor_tamper", (ID,), "tamper alert"),
    ],
)
async def test_actions_report_consequence_for_result_and_preview(
    rig, fn, args, consequence, preview
):
    c, r, _, calls = rig
    c.dry_run = preview
    original = c.request.side_effect
    preview_body = {"dryRun": True, "message": DRY_RUN_MESSAGE, "preview": {"method": "POST"}}

    async def request(method, path, **kwargs):
        if preview and method != "GET":
            calls.append((method, path, kwargs))
            return httpx.Response(200, json=preview_body)
        return await original(method, path, **kwargs)

    c.request.side_effect = request
    result = await getattr(pp, fn)(c, r, "example", *args)
    if preview:
        assert "_warnings" not in result
        assert result["body"] == preview_body
    else:
        assert result["_warnings"][0]["code"] == "PHYSICAL_ACTION"
        assert consequence in result["_warnings"][0]["message"]


def test_nvr_settings_accept_live_integer_retention_duration():
    settings = pp.NvrSettings.model_validate({"recordingRetentionDurationMs": 518400000})
    assert settings.model_dump(exclude_unset=True) == {"recordingRetentionDurationMs": 518400000}


@pytest.mark.parametrize("value", [518400000, "518400000", None])
async def test_registered_nvr_retention_schema_and_patch_preserve_value(rig, value):
    import jsonschema
    from fastmcp import FastMCP

    c, r, state, calls = rig
    mcp = FastMCP("nvr-retention-contract")
    pp.register(mcp, lambda: (c, r))
    tool = next(t for t in await mcp.list_tools() if t.name == "update_nvr")
    field = tool.parameters["properties"]["settings"]["properties"]["recordingRetentionDurationMs"]
    jsonschema.Draft202012Validator(field).validate(value)
    model = pp.NvrSettings.model_validate({"recordingRetentionDurationMs": value})
    assert model.model_dump(exclude_unset=True) == {"recordingRetentionDurationMs": value}
    assert type(model.model_dump(exclude_unset=True)["recordingRetentionDurationMs"]) is type(value)

    await mcp.call_tool(
        "update_nvr",
        {
            "host": "example",
            "settings": {
                "recordingRetentionDurationMs": value,
            },
        },
    )
    writes = [call for call in calls if call[0] == "PATCH"]
    assert len(writes) == 1
    sent = writes[0][2]["json"]["recordingRetentionDurationMs"]
    assert sent == value and type(sent) is type(value)
    assert state["recordingRetentionDurationMs"] == value
    assert type(state["recordingRetentionDurationMs"]) is type(value)
    assert sum(method == "GET" for method, _, _ in calls) >= 2


@pytest.mark.parametrize("value", [True, False])
async def test_registered_nvr_retention_rejects_booleans_without_requests(rig, value):
    from fastmcp import FastMCP

    c, r, _, calls = rig
    mcp = FastMCP("nvr-retention-boolean")
    pp.register(mcp, lambda: (c, r))
    with pytest.raises(Exception):
        await mcp.call_tool(
            "update_nvr",
            {"host": "example", "settings": {"recordingRetentionDurationMs": value}},
        )
    assert calls == []


async def test_nvr_retention_preview_warns_of_footage_deletion(rig):
    c, r, _, calls = rig
    c.dry_run = True
    original = c.request.side_effect
    preview_body = {"dryRun": True, "message": DRY_RUN_MESSAGE, "preview": {"method": "PATCH"}}

    async def request(method, path, **kwargs):
        if method == "PATCH":
            calls.append((method, path, kwargs))
            return httpx.Response(200, json=preview_body)
        return await original(method, path, **kwargs)

    c.request.side_effect = request
    result = await pp.update_nvr(c, r, "example", {"recordingRetentionDurationMs": 3600000})
    assert result["_warnings"][0]["code"] == "RETENTION_DATA_LOSS"
    assert "permanently delete older footage" in result["_warnings"][0]["message"]
    assert result["_verified"] is None
    assert result["body"] == preview_body


@pytest.mark.parametrize(
    "readback_change,expected",
    [
        ("controller_extra", True),
        ("reordered", False),
        ("changed_field", False),
        ("changed_length", False),
    ],
)
async def test_privacy_zone_requested_leaves_allow_controller_extras_in_order(
    rig, readback_change, expected
):
    c, r, _, calls = rig
    zones = [
        {"id": 100, "name": "Door", "points": [[0, 0], [1, 1]]},
        {"id": 101, "name": "Window", "points": [[0.5, 0], [1, 0.5]]},
    ]
    original = c.request.side_effect

    async def request(method, path, **kwargs):
        response = await original(method, path, **kwargs)
        if method == "GET" and any(m == "PATCH" for m, _, _ in calls):
            body = response.json()
            body["privacyZones"] = [
                {**zone, "mergeId": None, "controllerExtra": True} for zone in body["privacyZones"]
            ]
            if readback_change == "reordered":
                body["privacyZones"].reverse()
            elif readback_change == "changed_field":
                body["privacyZones"][0]["name"] = "Wrong"
            elif readback_change == "changed_length":
                body["privacyZones"].pop()
            return httpx.Response(200, json=body)
        return response

    c.request.side_effect = request
    result = await pp.update_camera_private(c, r, "example", ID, {"privacyZones": zones})
    assert result["_verified"] is expected


@pytest.mark.parametrize("fn", ["update_camera_private", "update_nvr", "update_sensor_private"])
@pytest.mark.parametrize("failure", ["http", "transport", "shape"])
@pytest.mark.parametrize("same", [False, True])
async def test_read_after_failure_never_proves_saved_settings(rig, fn, failure, same):
    c, r, state, calls = rig
    original = c.request.side_effect
    written = False
    requested = {"name": state["name"] if same else "Changed"}
    reason = {"name": requested["name"], "reason": "full upstream reason " * 80}

    async def fail_after(method, path, **kwargs):
        nonlocal written
        if method == "GET" and written:
            if failure == "transport":
                raise httpx.ConnectError("read-after transport reason")
            return httpx.Response(
                403 if failure == "http" else 200, json=reason if failure == "http" else [requested]
            )
        response = await original(method, path, **kwargs)
        written |= method == "PATCH"
        return response

    c.request.side_effect = fail_after
    args = (c, r, "example", requested) if fn == "update_nvr" else (c, r, "example", ID, requested)
    result = await getattr(pp, fn)(*args)
    assert result["_verified"] is None
    assert result["_noOp"] is None
    assert result.get("noOp") is None
    assert "changed" not in result
    assert result["body"] == {"saved": True, "upstreamExtra": [1, 2, 3]}
    assert len([call for call in calls if call[0] == "PATCH"]) == 1
    if failure == "http":
        assert result["readAfter"]["body"] == reason
        assert reason["reason"] in result["readAfterError"]
    elif failure == "transport":
        assert "read-after transport reason" in result["readAfterError"]
    else:
        assert result["readAfter"]["body"] == [requested]


@pytest.mark.parametrize(
    "after", [None, [], {"body": {"name": "Changed"}}, {"status": 200, "body": None}]
)
async def test_malformed_read_after_cannot_verify(rig, monkeypatch, after):
    c, r, _, _ = rig
    monkeypatch.setattr(
        pp.connector,
        "connector_write",
        AsyncMock(return_value={"status": 200, "body": {"saved": True}, "readAfter": after}),
    )
    result = await pp.update_nvr(c, r, "example", {"name": "Changed"})
    assert result["_verified"] is None
    assert result["_noOp"] is None


def test_all_private_settings_hide_validation_input():
    import inspect

    from pydantic import ValidationError

    sentinel = "synthetic-validation-secret-sentinel"
    models = [
        model
        for _, model in inspect.getmembers(pp, inspect.isclass)
        if issubclass(model, pp.PrivateSettings)
    ]
    assert len(models) >= 11
    for model in models:
        assert model.model_config.get("hide_input_in_errors") is True, model
        with pytest.raises(ValidationError) as caught:
            model.model_validate(sentinel)
        assert sentinel not in str(caught.value), model


def _settings_call(fn, requested):
    """Call a private settings helper with its selector, whatever its signature."""
    selector = () if fn == "update_nvr" else (ID,)
    return lambda c, r: getattr(pp, fn)(c, r, "example", *selector, requested)


@pytest.mark.parametrize("fn", ["update_camera_private", "update_nvr", "update_sensor_private"])
async def test_unrequested_sibling_change_does_not_break_requested_leaf_noop(rig, fn):
    """No-op compares only the requested leaves, never their siblings."""
    c, r, state, calls = rig
    original = c.request.side_effect

    async def controller_moves_sibling(method, path, **kwargs):
        response = await original(method, path, **kwargs)
        if method == "PATCH":
            # The controller changes an unrequested nested sibling in the same object.
            state["recordingSettings"]["prePaddingSecs"] = 2
        return response

    c.request.side_effect = controller_moves_sibling
    result = await _settings_call(fn, {"recordingSettings": {"mode": "always"}})(c, r)
    assert result["_verified"] is True
    assert result["_noOp"] is True
    assert result["noOp"] is True
    assert result["changed"] is False


@pytest.mark.parametrize("fn", ["update_camera_private", "update_nvr", "update_sensor_private"])
async def test_changed_requested_leaf_is_not_noop_beside_unchanged_siblings(rig, fn):
    c, r, state, calls = rig
    result = await _settings_call(fn, {"recordingSettings": {"mode": "detections"}})(c, r)
    assert result["_verified"] is True
    assert result["_noOp"] is False
    assert result["noOp"] is False
    assert result["changed"] is True


@pytest.mark.parametrize("fn", ["update_camera_private", "update_nvr", "update_sensor_private"])
async def test_requested_leaf_noop_is_type_strict(rig, fn):
    """``True`` over a stored ``1`` is a change, and ``1`` never verifies ``True``."""
    c, r, state, calls = rig
    state["recordingSettings"]["enableMotionDetection"] = 1
    result = await _settings_call(fn, {"recordingSettings": {"enableMotionDetection": True}})(c, r)
    assert result["_verified"] is True
    assert result["_noOp"] is False
    assert result["changed"] is True

    original = c.request.side_effect

    async def controller_stores_int(method, path, **kwargs):
        response = await original(method, path, **kwargs)
        if method == "PATCH":
            state["recordingSettings"]["enableMotionDetection"] = 1
        return response

    c.request.side_effect = controller_stores_int
    result = await _settings_call(fn, {"recordingSettings": {"enableMotionDetection": True}})(c, r)
    assert result["_verified"] is False
    assert result["_noOp"] is None


@pytest.mark.parametrize("fn", ["update_camera_private", "update_nvr", "update_sensor_private"])
async def test_unverified_write_withdraws_relay_whole_record_noop(rig, fn):
    """A discarded write must not inherit the relay's whole-record "already applied"."""
    c, r, state, calls = rig
    original = c.request.side_effect

    async def controller_discards(method, path, **kwargs):
        saved = copy.deepcopy(state)
        response = await original(method, path, **kwargs)
        if method == "PATCH":
            # The controller acknowledges but keeps the whole record unchanged.
            state.clear()
            state.update(saved)
        return response

    c.request.side_effect = controller_discards
    result = await _settings_call(fn, {"recordingSettings": {"mode": "detections"}})(c, r)
    assert [entry[0] for entry in calls].count("PATCH") == 1
    assert result["readBefore"]["body"] == result["readAfter"]["body"]
    assert result["_verified"] is False
    assert result["_noOp"] is None
    assert result["noOp"] is None
    assert "changed" not in result
    assert result["_verificationWarning"]


@pytest.mark.parametrize("fn", ["update_camera_private", "update_nvr", "update_sensor_private"])
async def test_unverified_type_drift_withdraws_relay_changed(rig, fn):
    """A read-after that changed the record but not to the requested leaf has no verdict."""
    c, r, state, calls = rig
    original = c.request.side_effect

    async def controller_stores_int(method, path, **kwargs):
        response = await original(method, path, **kwargs)
        if method == "PATCH":
            state["recordingSettings"]["enableMotionDetection"] = 1
        return response

    c.request.side_effect = controller_stores_int
    result = await _settings_call(fn, {"recordingSettings": {"enableMotionDetection": True}})(c, r)
    assert result["_verified"] is False
    assert result["_noOp"] is None
    assert result["noOp"] is None
    assert "changed" not in result


async def test_ptz_presets_500_preserves_response_and_adds_hint(rig):
    c, r, _, _ = rig
    c.request.side_effect = lambda *args, **kwargs: httpx.Response(500, content=b"")
    result = await pp.list_ptz_presets(c, r, "example", ID)
    assert result["status"] == 500
    assert result["body"] is None
    assert result["_hint"] == "the camera may have no PTZ capability; check get_camera featureFlags"


@pytest.mark.parametrize(
    "fn", ["reboot_protect_device", "adopt_protect_device", "unadopt_protect_device"]
)
async def test_device_actions_reject_non_device_collections_before_request(rig, fn):
    client, registry, _, calls = rig
    with pytest.raises(ValueError, match="device_type"):
        await getattr(pp, fn)(client, registry, "example", "user", ID)
    assert calls == []


@pytest.mark.parametrize(
    "fn", ["reboot_protect_device", "adopt_protect_device", "unadopt_protect_device"]
)
async def test_device_actions_accept_sensor_and_advertise_both_types(rig, fn):
    from fastmcp import FastMCP

    client, registry, _, calls = rig
    mcp = FastMCP("device-types")
    pp.register(mcp, lambda: (client, registry))
    tool = {t.name: t for t in await mcp.list_tools()}[fn]
    assert set(tool.parameters["properties"]["device_type"]["enum"]) == {"camera", "sensor"}
    await getattr(pp, fn)(client, registry, "example", "sensor", ID)
    writes = [call for call in calls if call[0] != "GET"]
    assert len(writes) == 1
    if fn == "adopt_protect_device":
        assert writes[0][2]["json"] == {"sensors": {ID: {}}}
    else:
        assert f"/sensors/{ID}" in writes[0][1]


@pytest.mark.parametrize(
    "fn,args",
    [
        ("reboot_protect_device", ("camera", ID)),
        ("reboot_nvr", ()),
        ("adopt_protect_device", ("camera", ID)),
        ("unadopt_protect_device", ("camera", ID)),
        ("clear_sensor_tamper", (ID,)),
    ],
)
@pytest.mark.parametrize("status", [400, 500])
async def test_failed_action_does_not_claim_physical_consequence(rig, fn, args, status):
    c, r, _, calls = rig
    original = c.request.side_effect

    async def request(method, path, **kwargs):
        if method != "GET":
            calls.append((method, path, kwargs))
            return httpx.Response(status, json={"error": "synthetic"})
        return await original(method, path, **kwargs)

    c.request.side_effect = request
    result = await getattr(pp, fn)(c, r, "example", *args)
    assert result["_writeFailed"] is True
    assert "_warnings" not in result
    if fn == "clear_sensor_tamper":
        assert not any(
            path.endswith(f"/sensors/{ID}") for method, path, _ in calls if method == "GET"
        )


@pytest.mark.parametrize("status", [400, 403, 404, 500])
@pytest.mark.parametrize(
    "body",
    [
        '{"message":"upstream rejected adoption","detail":{"field":"deviceId"}}',
        '{ "message": "Synthetic café failure", "detail" : [1, 2] }',
        "upstream plain-text failure\nretain this line",
        "",
    ],
)
async def test_adopt_resolution_error_preserves_original_body(rig, status, body):
    c, r, _state, calls = rig
    c._settings = SimpleNamespace(redact_secrets=False)

    async def request(method, path, **kwargs):
        calls.append((method, path, kwargs))
        return httpx.Response(status, text=body)

    c.request.side_effect = request
    with pytest.raises(UniFiConnectionError) as exc:
        await pp.adopt_protect_device(c, r, "example", "camera", "Camera A")
    assert str(exc.value) == f"GET protect/api/cameras: HTTP {status}: {body}"
    assert [(method, path) for method, path, _ in calls] == [("GET", f"{BASE}/cameras")]


async def test_adopt_resolution_error_retains_opt_in_credential_masking(rig):
    c, r, _state, calls = rig
    c._settings = SimpleNamespace(redact_secrets=True)
    body = '{"message":"upstream rejected adoption","password":"synthetic-adoption-secret"}'

    async def request(method, path, **kwargs):
        calls.append((method, path, kwargs))
        return httpx.Response(403, text=body)

    c.request.side_effect = request
    with pytest.raises(UniFiConnectionError) as exc:
        await pp.adopt_protect_device(c, r, "example", "camera", "Camera A")
    assert "synthetic-adoption-secret" not in str(exc.value)
    assert "upstream rejected adoption" in str(exc.value)
    assert "***REDACTED***" in str(exc.value)
    assert [method for method, _path, _kwargs in calls] == ["GET"]
