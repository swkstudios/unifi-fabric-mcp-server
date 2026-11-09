"""Protect camera controls, camera WiFi and edge (on-camera) recording storage (GS3 P03).

Every tool is exercised against the real ``UniFiClient`` with only the HTTP transport
mocked: the route, method, query parameters and body sent, verbatim pass-through, binary
bodies as base64, dry-run previews, the Protect write opt-out and read-only mode (zero
requests), zero-request input validation, single-send writes (no 429 retry), multi-key
routing on the shared two-key fixtures, the state-changing GET classified as a write, the
secret registry entries and the registration contract.
"""

from __future__ import annotations

import ast
import asyncio
import base64
import inspect
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
from fastmcp import FastMCP
from pydantic import ValidationError

from tests.conftest import MULTIKEY_HOSTS_BY_LABEL
from unifi_fabric import read_only, route_secrets
from unifi_fabric._read_only_audit import (
    STATE_CHANGING_GET_ATTR,
    classify_tool_verbs,
    is_destructive,
)
from unifi_fabric.client import (
    DRY_RUN_MESSAGE,
    RateLimitError,
    UniFiClient,
    UniFiConnectionError,
    _key_fingerprint,
    is_dry_run_preview,
)
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.tools import protect_camera_recording as pcr

HOST = "console-p03"
BASE = f"/v1/connector/consoles/{HOST}/proxy/protect/api"
CAMERA = "000000000000000000fa0301"
START = 1_760_227_200
END = 1_760_230_800

READ_TOOLS = {
    "get_camera_adoption_qr",
    "get_camera_analytics",
    "get_camera_lux",
    "get_camera_playback_history",
    "get_camera_wifi_networks",
    "export_edge_recording",
}
WRITE_TOOLS = {
    "set_camera_control_enabled",
    "set_camera_door_lock",
    "reset_camera_image_settings",
    "set_camera_resolution_scale",
    "transfer_camera_management",
    "turn_on_camera_flashlight",
    "configure_camera_wifi",
    "set_camera_video_codec",
    "set_edge_storage_mount_state",
    "reformat_edge_storage",
    "update_edge_recording_settings",
    "delete_recordings",
}

#: tool -> (function, positional args after host, kwargs, method, path, params, body)
CALLS: dict[str, tuple[Any, tuple[Any, ...], dict[str, Any], str, str, dict[str, str], Any]] = {
    "get_camera_adoption_qr": (
        pcr.get_camera_adoption_qr,
        (),
        {"ssid": "synthetic-ssid", "wifi_password": "synthetic-wifi-pass"},
        "GET",
        f"{BASE}/cameras/qr",
        {"ssid": "synthetic-ssid", "password": "synthetic-wifi-pass"},
        None,
    ),
    "get_camera_analytics": (
        pcr.get_camera_analytics,
        (CAMERA, "detections", START, END),
        {"step": 3_600_000},
        "GET",
        f"{BASE}/cameras/{CAMERA}/analytics-detections",
        {"start": str(START * 1000), "end": str(END * 1000), "step": "3600000"},
        None,
    ),
    "get_camera_lux": (
        pcr.get_camera_lux,
        (CAMERA,),
        {},
        "GET",
        f"{BASE}/cameras/{CAMERA}/lux",
        {},
        None,
    ),
    "get_camera_playback_history": (
        pcr.get_camera_playback_history,
        (CAMERA, START, END),
        {"resolution": 2},
        "GET",
        f"{BASE}/cameras/{CAMERA}/playback-history",
        {"start": str(START * 1000), "end": str(END * 1000), "resolution": "2"},
        None,
    ),
    "get_camera_wifi_networks": (
        pcr.get_camera_wifi_networks,
        (CAMERA,),
        {},
        "GET",
        f"{BASE}/cameras/{CAMERA}/wifi-list",
        {},
        None,
    ),
    "export_edge_recording": (
        pcr.export_edge_recording,
        (CAMERA, "download"),
        {"filename": "edge-export.mp4"},
        "GET",
        f"{BASE}/edge-recording/{CAMERA}/download",
        {"filename": "edge-export.mp4"},
        None,
    ),
    "set_camera_control_enabled": (
        pcr.set_camera_control_enabled,
        (CAMERA, True),
        {},
        "GET",
        f"{BASE}/cameras/{CAMERA}/enable-control",
        {},
        None,
    ),
    "set_camera_door_lock": (
        pcr.set_camera_door_lock,
        (CAMERA, True),
        {},
        "POST",
        f"{BASE}/cameras/{CAMERA}/lock",
        {},
        None,
    ),
    "reset_camera_image_settings": (
        pcr.reset_camera_image_settings,
        (CAMERA,),
        {},
        "POST",
        f"{BASE}/cameras/{CAMERA}/reset-isp",
        {},
        None,
    ),
    "set_camera_resolution_scale": (
        pcr.set_camera_resolution_scale,
        (CAMERA, "2"),
        {},
        "POST",
        f"{BASE}/cameras/{CAMERA}/resolutionScale/2",
        {},
        None,
    ),
    "transfer_camera_management": (
        pcr.transfer_camera_management,
        (CAMERA, "02:00:5e:00:53:01"),
        {},
        "POST",
        f"{BASE}/cameras/{CAMERA}/transfer-mgmt",
        {},
        {"nvrMac": "02:00:5e:00:53:01"},
    ),
    "turn_on_camera_flashlight": (
        pcr.turn_on_camera_flashlight,
        (CAMERA,),
        {},
        "POST",
        f"{BASE}/cameras/{CAMERA}/turnon-flashlight",
        {},
        None,
    ),
    "configure_camera_wifi": (
        pcr.configure_camera_wifi,
        (CAMERA, {"ssid": "synthetic-ssid", "nested": {"keep": [1, None]}}),
        {},
        "POST",
        f"{BASE}/cameras/{CAMERA}/wifi-setup",
        {},
        {"ssid": "synthetic-ssid", "nested": {"keep": [1, None]}},
    ),
    "set_camera_video_codec": (
        pcr.set_camera_video_codec,
        (CAMERA, "h265"),
        {},
        "POST",
        f"{BASE}/cameras/{CAMERA}/videoCodec",
        {"name": "h265"},
        None,
    ),
    "set_edge_storage_mount_state": (
        pcr.set_edge_storage_mount_state,
        (CAMERA, "unmounted"),
        {},
        "POST",
        f"{BASE}/edge-recording/{CAMERA}/mount-state",
        {},
        {"mountState": "unmounted"},
    ),
    "reformat_edge_storage": (
        pcr.reformat_edge_storage,
        (CAMERA,),
        {},
        "POST",
        f"{BASE}/edge-recording/{CAMERA}/reformat",
        {},
        None,
    ),
    "update_edge_recording_settings": (
        pcr.update_edge_recording_settings,
        (CAMERA, {"enabled": True, "retention": {"days": 7}}),
        {},
        "PATCH",
        f"{BASE}/edge-recording/{CAMERA}/recording-settings",
        {},
        {"enabled": True, "retention": {"days": 7}},
    ),
    "delete_recordings": (
        pcr.delete_recordings,
        (CAMERA, START, END),
        {},
        "DELETE",
        f"{BASE}/video",
        {"camera": CAMERA, "start": str(START * 1000), "end": str(END * 1000)},
        None,
    ),
}


def registry(key: APIKeyConfig | None = None) -> AsyncMock:
    return AsyncMock(
        **{
            "resolve_key_for_host.return_value": key or APIKeyConfig(key="test-key", label="beta"),
            "resolve_host_id.return_value": HOST,
        }
    )


def client(handler, **settings: Any) -> UniFiClient:
    c = UniFiClient(Settings(api_key="test-key", **settings))
    c._clients[("beta", _key_fingerprint("test-key"))] = httpx.AsyncClient(
        base_url="https://api.ui.com", transport=httpx.MockTransport(handler)
    )
    return c


class Upstream:
    """Answers every request with ``response`` (a factory or a fixed value); records it."""

    def __init__(self, response: Any = None):
        self.response = response if response is not None else {"ok": True}
        self.seen: list[httpx.Request] = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.seen.append(req)
        entry = self.response(req) if callable(self.response) else self.response
        if isinstance(entry, httpx.Response):
            return entry
        return httpx.Response(200, json=entry)


def body_of(req: httpx.Request) -> Any:
    return json.loads(req.content) if req.content else None


async def run(handler, fn, *args, settings: dict[str, Any] | None = None, **kwargs):
    c = client(handler, **(settings or {}))
    try:
        return await fn(c, registry(), HOST, *args, **kwargs)
    finally:
        await c.close()


async def call(name: str, up: Upstream, settings: dict[str, Any] | None = None) -> Any:
    fn, args, kwargs, *_ = CALLS[name]
    return await run(up, fn, *args, settings=settings, **kwargs)


# --------------------------------------------------------------------- routes and bodies


def test_calls_cover_every_tool():
    assert set(CALLS) == READ_TOOLS | WRITE_TOOLS
    assert len(CALLS) == 18


@pytest.mark.parametrize("name", sorted(CALLS))
async def test_each_tool_sends_its_inventoried_route_params_and_body(name):
    _, _, _, method, path, params, body = CALLS[name]
    up = Upstream()
    await call(name, up)
    assert len(up.seen) == 1, name
    req = up.seen[0]
    assert (req.method, req.url.path) == (method, path)
    assert dict(req.url.params) == params
    assert body_of(req) == body


@pytest.mark.parametrize("name", sorted(CALLS))
async def test_write_tools_write_and_read_tools_only_read(name):
    up = Upstream()
    await call(name, up)
    methods = {r.method for r in up.seen}
    if name in WRITE_TOOLS and name != "set_camera_control_enabled":
        assert methods - {"GET"}, f"{name} sent no write"
    else:
        assert methods == {"GET"}, name


@pytest.mark.parametrize(
    ("enabled", "suffix", "status"),
    [(True, "enable-control", "enabled"), (False, "disable-control", "disabled")],
)
async def test_control_enabled_maps_to_its_get_route(enabled, suffix, status):
    up = Upstream({"id": CAMERA, "controlled": enabled})
    result = await run(up, pcr.set_camera_control_enabled, CAMERA, enabled)
    assert [(r.method, r.url.path) for r in up.seen] == [
        ("GET", f"{BASE}/cameras/{CAMERA}/{suffix}")
    ]
    assert result == {"status": status, "response": {"id": CAMERA, "controlled": enabled}}


@pytest.mark.parametrize(
    ("locked", "suffix", "status"), [(True, "lock", "locked"), (False, "unlock", "unlocked")]
)
async def test_door_lock_maps_to_lock_and_unlock(locked, suffix, status):
    up = Upstream({"success": True})
    result = await run(up, pcr.set_camera_door_lock, CAMERA, locked)
    assert up.seen[0].url.path == f"{BASE}/cameras/{CAMERA}/{suffix}"
    assert result == {"status": status, "response": {"success": True}}


async def test_analytics_heatmap_route_and_type_param():
    up = Upstream([{"x": 1}])
    result = await run(
        up, pcr.get_camera_analytics, CAMERA, "heatmap", START, END, heatmap_type="person"
    )
    assert up.seen[0].url.path == f"{BASE}/cameras/{CAMERA}/analytics-heatmap"
    assert dict(up.seen[0].url.params) == {
        "start": str(START * 1000),
        "end": str(END * 1000),
        "type": "person",
    }
    assert result == [{"x": 1}]  # verbatim: a plausible window adds no _warnings


async def test_export_prepare_sends_no_filename_and_returns_body_verbatim():
    job = {"id": "000000000000000000fa0399", "status": "preparing", "future": {"k": [1]}}
    up = Upstream(job)
    result = await run(up, pcr.export_edge_recording, CAMERA, "prepare")
    assert up.seen[0].url.path == f"{BASE}/edge-recording/{CAMERA}/prepare"
    assert not up.seen[0].url.query
    assert result == job


async def test_export_prepare_sends_filename_start_and_end_protect_7_3_requires():
    """Protect 7.3.74 (live 2026-10-28) answers prepare with 400 "must have required
    property 'filename', 'start', 'end'" (start and end in ms), and the console stores the
    export under that filename for download. All three are sent; start and end are epoch
    seconds converted to ms."""
    answer = {"filename": "edge-export.mp4", "expiresAfter": 1800000}
    up = Upstream(answer)
    result = await run(
        up,
        pcr.export_edge_recording,
        CAMERA,
        "prepare",
        filename="edge-export.mp4",
        start=START,
        end=START + 10,
    )
    assert up.seen[0].url.path == f"{BASE}/edge-recording/{CAMERA}/prepare"
    assert dict(up.seen[0].url.params) == {
        "filename": "edge-export.mp4",
        "start": str(START * 1000),
        "end": str((START + 10) * 1000),
    }
    assert result == answer


async def test_export_download_refuses_a_window_it_would_drop():
    up = Upstream({})
    with pytest.raises(ValueError, match="start and end only apply to action 'prepare'"):
        await run(up, pcr.export_edge_recording, CAMERA, "download", filename="a.mp4", start=START)
    assert up.seen == []


async def test_optional_query_parameters_are_sent_only_when_given():
    up = Upstream({"qr": "synthetic"})
    await run(up, pcr.get_camera_adoption_qr)
    assert not up.seen[0].url.query
    up = Upstream([])
    await run(up, pcr.get_camera_playback_history, CAMERA, START, END)
    assert dict(up.seen[0].url.params) == {"start": str(START * 1000), "end": str(END * 1000)}


# ------------------------------------------------------------------- verbatim responses


@pytest.mark.parametrize(
    "name", sorted(READ_TOOLS - {"get_camera_analytics", "get_camera_playback_history"})
)
async def test_read_bodies_are_returned_verbatim(name):
    body = {"data": [{"id": CAMERA, "unknownFuture": {"kept": [1, None, True]}}], "extra": 0}
    assert await call(name, Upstream(body)) == body


@pytest.mark.parametrize(
    "name", sorted(WRITE_TOOLS - {"delete_recordings", "update_edge_recording_settings"})
)
async def test_write_results_carry_the_upstream_body_verbatim(name):
    body = {"success": True, "unknownFuture": {"kept": [1, None]}}
    result = await call(name, Upstream(body))
    assert result["response"] == body
    assert set(result) == {"status", "response"}


async def test_delete_recordings_has_the_status_response_shape():
    body = {"success": True, "unknownFuture": {"kept": [1, None]}}
    result = await call("delete_recordings", Upstream(body))
    assert result["deleted"] is True
    assert result["response"] == body
    # A plausible window adds no _warnings (test_plausible_epoch_window_carries_no_warning).
    assert set(result) == {"deleted", "message", "response"}
    assert "status" not in result


async def test_edge_settings_update_has_the_protect_update_shape_unverified():
    body = {"enabled": True, "unknownFuture": [1]}
    up = Upstream(body)
    result = await call("update_edge_recording_settings", up)
    assert result == {
        "status": "updated",
        "verified": None,
        "before": None,
        "after": None,
        "response": body,
    }
    assert [r.method for r in up.seen] == ["PATCH"]  # nothing read before or after


async def test_write_empty_body_is_none_not_invented():
    result = await call("reformat_edge_storage", Upstream(lambda r: httpx.Response(204)))
    assert result == {"status": "sent", "response": None}


@pytest.mark.parametrize(
    ("name", "ctype"),
    [
        ("get_camera_adoption_qr", "image/png"),
        ("export_edge_recording", "video/mp4"),
        ("get_camera_analytics", "image/jpeg"),
    ],
)
async def test_binary_bodies_are_base64_with_upstream_content_type(name, ctype):
    raw = bytes(range(256)) * 2  # not UTF-8: must never be decoded as text
    up = Upstream(lambda r: httpx.Response(200, content=raw, headers={"content-type": ctype}))
    result = await call(name, up)
    assert result["content_base64"] == base64.b64encode(raw).decode()
    assert result["content_type"] == ctype
    assert result["size_bytes"] == len(raw)


async def test_binary_without_content_type_is_base64_and_type_not_invented():
    raw = b"\x89PNG\r\n\x1a\n\x00\xff"
    up = Upstream(lambda r: httpx.Response(200, content=raw))
    result = await call("get_camera_adoption_qr", up)
    assert result == {
        "content_base64": base64.b64encode(raw).decode(),
        "content_type": None,
        "size_bytes": len(raw),
    }


async def test_json_without_content_type_is_decoded():
    up = Upstream(lambda r: httpx.Response(200, content=b'{"a": [1]}'))
    assert await call("get_camera_adoption_qr", up) == {"a": [1]}


async def test_text_body_is_returned_verbatim():
    up = Upstream(
        lambda r: httpx.Response(200, content=b"plain text", headers={"content-type": "text/plain"})
    )
    assert await call("export_edge_recording", up) == "plain text"


@pytest.mark.parametrize("name", sorted(CALLS))
async def test_upstream_error_reason_is_kept_in_full(name):
    reason = "x" * 3000 + " Entity 'camera' not found NOT_FOUND"
    up = Upstream(lambda r: httpx.Response(404, json={"error": reason, "name": "NOT_FOUND"}))
    with pytest.raises(UniFiConnectionError) as exc:
        await call(name, up)
    assert reason in str(exc.value)
    assert "NOT_FOUND" in str(exc.value)


# ------------------------------------------------------------------------ epoch handling


EPOCH_TOOLS = ["get_camera_analytics", "get_camera_playback_history", "delete_recordings"]


def _with_epochs(name: str, start: int, end: int) -> tuple[Any, list[Any], dict[str, Any]]:
    """The inventoried call of an epoch tool with its start and end replaced."""
    fn, args, kwargs, *_ = CALLS[name]
    edited = [start if a == START else end if a == END else a for a in args]
    assert edited.count(start) == 1 and edited.count(end) == 1, (name, args)
    return fn, edited, kwargs


@pytest.mark.parametrize("name", EPOCH_TOOLS)
async def test_plausible_epoch_window_carries_no_warning(name):
    # The shared rule (_history_common.epoch_warnings): only a negative or
    # millisecond-looking epoch warns, so a plausible window adds no _warnings.
    body = {"items": []}
    result = await call(name, Upstream(body))
    assert "_warnings" not in result, result
    if name != "delete_recordings":
        assert result == body


@pytest.mark.parametrize("name", EPOCH_TOOLS)
@pytest.mark.parametrize(
    ("start", "end", "expected"),
    [
        (START * 1000, END, [("EPOCH_SECONDS_LOOKS_LIKE_MILLISECONDS", "start", START * 1000)]),
        (-1, END, [("EPOCH_SECONDS_NEGATIVE", "start", -1)]),
        (START, END * 1000, [("EPOCH_SECONDS_LOOKS_LIKE_MILLISECONDS", "end", END * 1000)]),
    ],
)
async def test_implausible_epoch_adds_exactly_the_shared_warning(name, start, end, expected):
    fn, args, kwargs = _with_epochs(name, start, end)
    result = await run(Upstream({"items": []}), fn, *args, **kwargs)
    assert [(w["code"], w["argument"], w["value"]) for w in result["_warnings"]] == expected


async def test_plausible_array_body_is_returned_verbatim():
    result = await call("get_camera_playback_history", Upstream([{"start": 1}]))
    assert result == [{"start": 1}]


async def test_array_body_with_warnings_is_returned_under_result():
    up = Upstream([{"start": 1}])
    result = await run(up, pcr.get_camera_playback_history, CAMERA, START * 1000, END)
    assert result["result"] == [{"start": 1}]
    assert result["_warnings"]


async def test_upstream_warnings_key_is_not_overwritten():
    body = {"_warnings": ["upstream"], "items": []}
    result = await run(Upstream(body), pcr.get_camera_playback_history, CAMERA, START * 1000, END)
    assert result["_warnings"] == ["upstream"]
    assert result["_wrapperFields"]["_warnings"]


@pytest.mark.parametrize(
    ("name", "position"),
    [
        ("get_camera_analytics", 2),
        ("get_camera_analytics", 3),
        ("get_camera_playback_history", 1),
        ("get_camera_playback_history", 2),
        ("delete_recordings", 1),
        ("delete_recordings", 2),
    ],
)
@pytest.mark.parametrize("bad", ["1760227200", 1.5, True, None])
async def test_non_integer_epoch_fails_before_any_request(name, position, bad):
    fn, args, kwargs, *_ = CALLS[name]
    broken = list(args)
    broken[position] = bad
    up = Upstream()
    with pytest.raises(ValueError, match="integer epoch-seconds"):
        await run(up, fn, *broken, **kwargs)
    assert up.seen == []


# ----------------------------------------------------------------- validation, no request


def _camera_positions(name: str) -> list[int]:
    _, args, *_ = CALLS[name]
    return [i for i, a in enumerate(args) if a == CAMERA]


@pytest.mark.parametrize("bad", ["", "../etc", "..", "a\nb"])
@pytest.mark.parametrize("name", sorted(n for n in CALLS if _camera_positions(n)))
async def test_unsafe_camera_ids_fail_before_any_request(name, bad):
    fn, args, kwargs, *_ = CALLS[name]
    for pos in _camera_positions(name):
        broken = list(args)
        broken[pos] = bad
        up = Upstream()
        with pytest.raises(ValueError):
            await run(up, fn, *broken, **kwargs)
        assert up.seen == [], (name, pos)


async def test_camera_id_is_encoded_as_one_segment():
    up = Upstream()
    await run(up, pcr.get_camera_lux, "cam/x?y")
    assert up.seen[0].url.raw_path.decode().endswith("/cameras/cam%2Fx%3Fy/lux")


@pytest.mark.parametrize("bad", ["", "../x", ".."])
async def test_unsafe_resolution_scale_fails_before_any_request(bad):
    up = Upstream()
    with pytest.raises(ValueError, match="scale"):
        await run(up, pcr.set_camera_resolution_scale, CAMERA, bad)
    assert up.seen == []


@pytest.mark.parametrize(
    ("fn", "args"),
    [
        (pcr.get_camera_analytics, (CAMERA, "heat", START, END)),
        (pcr.export_edge_recording, (CAMERA, "zip")),
        (pcr.set_camera_control_enabled, (CAMERA, "yes")),
        (pcr.set_camera_door_lock, (CAMERA, 1)),
    ],
)
async def test_closed_choices_fail_listing_valid_values_before_any_request(fn, args):
    up = Upstream()
    with pytest.raises(ValidationError, match="Input should be"):
        await run(up, fn, *args)
    assert up.seen == []


@pytest.mark.parametrize("name", ["configure_camera_wifi", "update_edge_recording_settings"])
@pytest.mark.parametrize("empty", [{}, {"_note": "additive only"}])
async def test_empty_free_form_body_is_refused_before_any_request(name, empty):
    fn, args, kwargs, *_ = CALLS[name]
    up = Upstream()
    with pytest.raises(ValueError, match="No fields provided"):
        await run(up, fn, args[0], empty, **kwargs)
    assert up.seen == []


# ---------------------------------------------------------- dry-run, opt-out, read-only


@pytest.mark.parametrize("name", sorted(WRITE_TOOLS))
async def test_dry_run_returns_the_preview_and_sends_no_write(name, monkeypatch):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "dry-run")
    _, _, _, method, path, params, body = CALLS[name]
    up = Upstream()
    result = await call(name, up)
    assert up.seen == [], name  # the control GET is not sent either
    if name == "delete_recordings":
        # A delete returns the deletion_result dry-run shape; a plausible window adds no
        # _warnings (test_implausible_epoch_adds_exactly_the_shared_warning covers them).
        assert result["status"] == "dry_run" and result["deleted"] is False, result
        assert result["message"] and "_warnings" not in result, result
        result = result["response"]
    assert is_dry_run_preview(result), result
    assert result["status"] == "dry_run" and result["dryRun"] is True
    assert result["message"] == DRY_RUN_MESSAGE
    preview = result["preview"]
    assert (preview["method"], preview["path"]) == (method, path)
    assert preview["body"] == body
    assert (preview["params"] or {}) == {k: _typed(v) for k, v in params.items()}
    assert "verified" not in result and result.get("deleted") in (None, False)


def _typed(value: str) -> Any:
    return int(value) if value.isdigit() else value


@pytest.mark.parametrize("name", sorted(WRITE_TOOLS))
async def test_protect_write_opt_out_refuses_with_zero_requests(name, monkeypatch):
    monkeypatch.setenv("UNIFI_WRITE_EXCEPTIONS", "family:protect=deny")
    up = Upstream()
    with pytest.raises(ValueError, match="family:protect=deny"):
        await call(name, up)
    assert up.seen == []


@pytest.mark.parametrize("name", sorted(WRITE_TOOLS))
async def test_read_only_mode_refuses_every_write_with_zero_requests(name, monkeypatch):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    up = Upstream()
    with pytest.raises(Exception, match="read-only mode"):
        await call(name, up)
    assert up.seen == []


@pytest.mark.parametrize("name", sorted(READ_TOOLS))
async def test_read_only_mode_and_opt_out_leave_reads_working(name, monkeypatch):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    monkeypatch.setenv("UNIFI_WRITE_EXCEPTIONS", "family:protect=deny")
    up = Upstream()
    await call(name, up)
    assert up.seen


@pytest.mark.parametrize("name", sorted(WRITE_TOOLS))
async def test_writes_are_sent_once_on_429_never_retried(name):
    up = Upstream(lambda r: httpx.Response(429, json={"error": "slow down"}))
    with pytest.raises(RateLimitError):
        await call(name, up)
    assert len(up.seen) == 1, name


async def test_reads_keep_the_get_429_retry(monkeypatch):
    monkeypatch.setattr(asyncio, "sleep", AsyncMock())
    replies = iter([httpx.Response(429, json={}), httpx.Response(200, json={"lux": 3})])
    up = Upstream(lambda r: next(replies))
    assert await call("get_camera_lux", up) == {"lux": 3}
    assert len(up.seen) == 2


@pytest.mark.parametrize("name", sorted(WRITE_TOOLS))
async def test_confirm_is_not_a_gate(name):
    fn, args, kwargs, *_ = CALLS[name]
    assert "confirm" not in inspect.signature(fn).parameters
    up = Upstream()
    await call(name, up)
    assert up.seen


# ------------------------------------------------------------------------- multi-key


def _keyed_client(multikey_client: UniFiClient, handler) -> None:
    for label in ("alpha", "beta"):
        key = multikey_client.get_key_by_label(label)
        multikey_client._clients[(label, _key_fingerprint(key.key))] = httpx.AsyncClient(
            base_url="https://api.ui.com",
            headers={"X-API-KEY": key.key},
            transport=httpx.MockTransport(handler),
        )


@pytest.mark.parametrize("name", sorted(CALLS))
async def test_multikey_requests_ride_the_key_that_owns_the_beta_host(
    name, multikey_client, multikey_registry
):
    for label, hosts in MULTIKEY_HOSTS_BY_LABEL.items():
        await multikey_registry.set_hosts(hosts, key=multikey_client.get_key_by_label(label))
    up = Upstream()
    _keyed_client(multikey_client, up)
    fn, args, kwargs, method, path, *_ = CALLS[name]
    try:
        await fn(multikey_client, multikey_registry, "Beta-Branch", *args, **kwargs)
    finally:
        await multikey_client.close()
    assert up.seen, name
    assert {r.headers["X-API-KEY"] for r in up.seen} == {"k-beta"}, name
    assert up.seen[-1].url.path == path.replace(HOST, "console-beta-1")
    assert up.seen[-1].method == method


async def test_multikey_alpha_host_rides_the_alpha_key(multikey_client, multikey_registry):
    for label, hosts in MULTIKEY_HOSTS_BY_LABEL.items():
        await multikey_registry.set_hosts(hosts, key=multikey_client.get_key_by_label(label))
    up = Upstream()
    _keyed_client(multikey_client, up)
    try:
        await pcr.reformat_edge_storage(multikey_client, multikey_registry, "Alpha-HQ", CAMERA)
    finally:
        await multikey_client.close()
    assert [r.headers["X-API-KEY"] for r in up.seen] == ["k-alpha"]


async def test_multikey_unknown_host_fails_without_a_data_request(
    multikey_client, multikey_registry
):
    for label, hosts in MULTIKEY_HOSTS_BY_LABEL.items():
        await multikey_registry.set_hosts(hosts, key=multikey_client.get_key_by_label(label))
    up = Upstream()
    _keyed_client(multikey_client, up)
    try:
        with pytest.raises(ValueError):
            await pcr.reformat_edge_storage(multikey_client, multikey_registry, "Gamma", CAMERA)
    finally:
        await multikey_client.close()
    assert [r for r in up.seen if "/proxy/" in r.url.path] == []


# ------------------------------------------------------------- state-changing GET class


def test_control_get_is_registered_as_a_state_changing_get():
    assert getattr(pcr._send_control_get, STATE_CHANGING_GET_ATTR) is True
    verbs = classify_tool_verbs(list(_registered().values()))
    assert verbs["set_camera_control_enabled"] == {"POST"}


@pytest.mark.parametrize(
    "path",
    [
        f"{BASE}/cameras/{CAMERA}/enable-control",
        f"{BASE}/cameras/{CAMERA}/disable-control",
        f"{BASE}/cameras/{CAMERA}/enable%2Dcontrol",
        f"protect/api/cameras/{CAMERA}/disable-control",
        f"{BASE}/cameras/{CAMERA}/enable-control?x=1",
    ],
)
def test_control_routes_are_writes_for_the_single_write_classifier(path):
    assert read_only.is_write_request("GET", path) is True
    assert read_only.is_write_request("HEAD", path) is False


@pytest.mark.parametrize(
    "path",
    [
        f"{BASE}/cameras/{CAMERA}",
        f"{BASE}/cameras/{CAMERA}/lux",
        f"{BASE}/cameras/{CAMERA}/enable-control/extra",
        f"{BASE}/cameras/enable-control",
        f"{BASE}/cameras/{CAMERA}/enable-controls",
    ],
)
def test_other_gets_stay_reads(path):
    assert read_only.is_write_request("GET", path) is False


async def test_control_get_is_audited_as_a_write(tmp_path):
    log = tmp_path / "audit.jsonl"
    up = Upstream()
    settings = {"audit_log": str(log), "audit_log_format": "json"}
    await run(up, pcr.set_camera_control_enabled, CAMERA, False, settings=settings)
    records = [
        r
        for r in (json.loads(line) for line in log.read_text().splitlines())
        if r.get("event", "audit") == "audit"
    ]
    assert [(r["method"], r["path"]) for r in records] == [
        ("GET", f"{BASE}/cameras/{CAMERA}/disable-control")
    ]


def test_destructive_tools_are_the_deletes():
    tools = _registered()
    destructive = {n for n, t in tools.items() if is_destructive(t.fn)}
    assert destructive == {"delete_recordings"}


# ------------------------------------------------------------------- secret registry


def test_adoption_qr_password_and_wifi_setup_are_registered_secrets():
    qr = route_secrets.matching("GET", f"{BASE}/cameras/qr")
    assert "protect-camera-adoption-qr-wifi-password" in [e.name for e in qr]
    assert route_secrets.tool_call_secrets(
        "get_camera_adoption_qr", {"wifi_password": "synthetic-wifi-pass"}
    ) == ("synthetic-wifi-pass",)
    setup = route_secrets.matching("POST", f"{BASE}/cameras/{CAMERA}/wifi-setup")
    assert [e.name for e in setup] == ["protect-camera-wifi-setup-password"]
    body = {"ssid": "synthetic-ssid", "password": "synthetic-wifi-pass"}
    assert route_secrets.request_secrets("POST", f"{BASE}/cameras/{CAMERA}/wifi-setup", body) == (
        "synthetic-wifi-pass",
    )


async def test_wifi_setup_body_is_sent_verbatim_by_default():
    up = Upstream()
    body = {"ssid": "synthetic-ssid", "password": "synthetic-wifi-pass"}
    await run(up, pcr.configure_camera_wifi, CAMERA, body)
    assert body_of(up.seen[0]) == body


async def test_wifi_setup_dry_run_masks_the_password_only_under_opt_in(monkeypatch):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "dry-run")
    body = {"ssid": "synthetic-ssid", "password": "synthetic-wifi-pass"}
    plain = await run(Upstream(), pcr.configure_camera_wifi, CAMERA, body)
    assert plain["preview"]["body"]["password"] == "synthetic-wifi-pass"
    masked = await run(
        Upstream(),
        pcr.configure_camera_wifi,
        CAMERA,
        body,
        settings={"redact_secrets": True},
    )
    assert "synthetic-wifi-pass" not in json.dumps(masked)


# --------------------------------------------------------------- registration contract


def _registered() -> dict[str, Any]:
    mcp = FastMCP("p03-test")
    pcr.register(mcp, lambda: (None, None))
    res = mcp.list_tools()
    tools = asyncio.run(res) if inspect.isawaitable(res) else res
    return {t.name: t for t in tools}


def test_register_adds_exactly_the_eighteen_tools():
    assert set(_registered()) == READ_TOOLS | WRITE_TOOLS


def test_server_registers_every_tool():
    from unifi_fabric import server

    names = {t.name for t in asyncio.run(server.mcp.list_tools())}
    assert READ_TOOLS | WRITE_TOOLS <= names
    assert "report_livestream_metrics" not in names


def test_annotations_match_the_source_derived_write_set():
    tools = _registered()
    verbs = classify_tool_verbs(list(tools.values()))
    assert {n for n, v in verbs.items() if v} == WRITE_TOOLS
    for name, tool in tools.items():
        writes = name in WRITE_TOOLS
        hints = tool.annotations.model_dump(by_alias=True)
        assert hints["readOnlyHint"] is (not writes), name
        assert hints["destructiveHint"] is writes, name


def test_descriptions_fit_and_every_property_is_described_with_an_example():
    tools = _registered()
    assert set(tools) == READ_TOOLS | WRITE_TOOLS
    for name, tool in tools.items():
        assert tool.description and len(tool.description) <= 2048, name
        assert "Returns" in tool.description, name
        props = (tool.parameters or {}).get("properties", {})
        assert "host" in tool.parameters.get("required", []), name
        for prop, schema in props.items():
            text = " ".join((schema.get("description") or "").split())
            assert "for example" in text, f"{name}.{prop}: {text!r}"
            assert schema.get("type") or schema.get("anyOf"), f"{name}.{prop}"


def test_write_descriptions_state_consequence_and_dry_run_preview():
    tools = _registered()
    for name in WRITE_TOOLS:
        desc = tools[name].description
        assert "Consequence:" in desc, name
        assert "returns a dry-run preview" in desc, name
        assert "simulat" not in desc.lower(), name
    for name in ("reformat_edge_storage", "delete_recordings", "transfer_camera_management"):
        assert "irreversible" in tools[name].description, name


def test_write_tools_accept_and_ignore_confirm():
    tools = _registered()
    for name in WRITE_TOOLS:
        assert "confirm" in tools[name].parameters["properties"], name
        assert "confirm" not in tools[name].parameters.get("required", []), name
    for name in READ_TOOLS:
        assert "confirm" not in tools[name].parameters["properties"], name


def test_free_form_bodies_are_documented_as_free_form():
    tools = _registered()
    for name in ("configure_camera_wifi", "update_edge_recording_settings"):
        settings = tools[name].parameters["properties"]["settings"]
        assert settings["type"] == "object"
        assert "free-form" in tools[name].description.lower()
        assert "Free-form" in settings["description"]


def test_module_raises_only_in_export_edge_recording():
    """Every pre-upstream refusal here comes from an already-registered helper
    (path_segment, require_epoch_seconds, the empty-update guard, the Protect opt-out,
    read-only mode, pydantic choice validation) except export_edge_recording's own
    argument grammar (start or end with download), registered in refusals.py.
    get_camera_adoption_qr only re-raises an upstream error (inventoried as a
    non-refusal raise)."""
    tree = ast.parse(Path(pcr.__file__).read_text())
    raising = {
        fn.name
        for fn in ast.walk(tree)
        if isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef)
        and any(isinstance(n, ast.Raise) for n in ast.walk(fn))
    }
    assert raising == {"export_edge_recording", "get_camera_adoption_qr"}


QR_404 = {"error": "Entity 'camera' not found", "name": "NOT_FOUND", "entity": "camera", "id": "qr"}


async def test_adoption_qr_404_on_protect_7_3_keeps_the_upstream_text_and_adds_a_hint():
    """Protect 7.3.74 (live 2026-10-28) has no QR route: GET cameras/qr is matched as
    camera id "qr" and answers this 404. The upstream text stays; a hint is appended."""
    up = Upstream(httpx.Response(404, json=QR_404))
    with pytest.raises(UniFiConnectionError) as info:
        await run(up, pcr.get_camera_adoption_qr)
    message = str(info.value)
    assert message.startswith(f"HTTP 404 from GET {BASE}/cameras/qr: ")
    assert json.dumps(QR_404, separators=(",", ":")) in message
    assert "-- Hint: " in message and "Protect 7.3" in message
    assert "UniFi Protect mobile app" in message


@pytest.mark.parametrize(
    "status,body",
    [(404, {"error": "Entity 'camera' not found", "id": "abc"}), (500, QR_404)],
)
async def test_adoption_qr_other_errors_pass_through_unhinted(status, body):
    up = Upstream(httpx.Response(status, json=body))
    with pytest.raises(UniFiConnectionError) as info:
        await run(up, pcr.get_camera_adoption_qr)
    assert "Hint" not in str(info.value)


@pytest.mark.parametrize("bad", ["", "02:00:5e:00:53:01\n", " 02:00:5e:00:53:01"])
async def test_nvr_mac_selector_grammar_fails_before_any_request(bad):
    up = Upstream()
    with pytest.raises(ValueError, match="nvr_mac"):
        await run(up, pcr.transfer_camera_management, CAMERA, bad)
    assert up.seen == []


async def test_edge_export_prepare_executes_in_read_only_and_dry_run(monkeypatch):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    up = Upstream()
    await run(up, pcr.export_edge_recording, CAMERA, "prepare")
    assert len(up.seen) == 1
    assert up.seen[0].method == "GET" and up.seen[0].url.path.endswith("/prepare")
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "dry-run")
    up = Upstream()
    await run(up, pcr.export_edge_recording, CAMERA, "prepare")
    assert len(up.seen) == 1
    assert up.seen[0].method == "GET" and up.seen[0].url.path.endswith("/prepare")


def test_edge_export_prepare_is_annotated_read_only():
    assert (
        _registered()["export_edge_recording"].annotations.model_dump(by_alias=True)["readOnlyHint"]
        is True
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "function,args,status,hint",
    [
        (pcr.export_edge_recording, (CAMERA, "prepare"), 400, "filename, start and end"),
        (pcr.get_camera_wifi_networks, (CAMERA,), 500, "WiFi"),
        (pcr.get_camera_adoption_qr, (), 404, "Protect 7.3"),
    ],
)
async def test_camera_read_failure_has_context_and_preserves_upstream(function, args, status, hint):
    client = AsyncMock()
    error = UniFiConnectionError('complete upstream failure {"id":"qr"}', status=status)
    client.get.side_effect = error
    client.request.side_effect = error
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = None
    registry.resolve_host_id.return_value = HOST
    with pytest.raises(UniFiConnectionError) as caught:
        await function(client, registry, HOST, *args)
    assert caught.value is error
    assert str(caught.value).startswith('complete upstream failure {"id":"qr"} -- Hint: ')
    assert hint in str(caught.value)
    assert caught.value.status == status


@pytest.mark.asyncio
async def test_edge_export_prepare_console_500_explains_edge_storage():
    client = AsyncMock()
    client.get.side_effect = UniFiConnectionError("console failed", status=500)
    client.request.side_effect = UniFiConnectionError("console failed", status=500)
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = None
    registry.resolve_host_id.return_value = HOST
    with pytest.raises(UniFiConnectionError) as caught:
        await pcr.export_edge_recording(
            client, registry, HOST, CAMERA, "prepare", filename="clip", start=1, end=2
        )
    assert "console failed" in str(caught.value)
    assert "edge" in str(caught.value) and "SD card" in str(caught.value)
    assert caught.value.status == 500
