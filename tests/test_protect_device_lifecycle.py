"""Protect device lifecycle tools (GS3 lane P01).

Every tool runs against the real ``UniFiClient`` with only the HTTP transport mocked:
the route, method, query and body sent; verbatim pass-through; dry-run previews; the
Protect write opt-out and read-only mode (zero requests); zero-request validation of ids,
device types and closed choices; read-before / no-op / read-after verification of the
settings update on official and private routes; epoch-second conversion; single-send of
physical actions; multi-key routing; the secret registry entries; and the registration
contract (annotations derived from source, described properties, consequence lines).
"""

from __future__ import annotations

import asyncio
import inspect
import json
from typing import Any, get_args
from unittest.mock import AsyncMock

import httpx
import pytest
from fastmcp import FastMCP
from pydantic import ValidationError

from tests.conftest import MULTIKEY_HOSTS_BY_LABEL
from unifi_fabric import route_secrets as rs
from unifi_fabric._read_only_audit import classify_tool_verbs
from unifi_fabric.client import RateLimitError, UniFiClient, UniFiConnectionError, _key_fingerprint
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.tools import protect_device_lifecycle as pdl
from unifi_fabric.tools._protect_device_types import device_types_with_action

HOST = "console-p01"
PRIV = f"/v1/connector/consoles/{HOST}/proxy/protect/api"
OFFI = f"/v1/connector/consoles/{HOST}/proxy/protect/integration/v1"
DEV = "000000000000000000fa0101"
CAM = "000000000000000000fa0201"
SENSOR = "000000000000000000fa0301"
BRIDGE = "000000000000000000fa0401"
SPEAKER = "000000000000000000fa0501"
CHIME = "000000000000000000fa0601"
LOCK = "000000000000000000fa0701"
AIPORT = "000000000000000000fa0801"
EVENT = "000000000000000000fa0901"
MAC = "00:00:5e:00:53:01"
LIST_ROUTES = ("/doorlocks", "/keyrings")
T0 = 1_760_000_000

READ_TOOLS = {
    "get_protect_device_metrics",
    "get_sensor_readings",
    "list_door_locks",
    "get_protect_bootstrap",
    "list_protect_keyrings",
}
WRITE_TOOLS = {
    "readopt_protect_device",
    "upgrade_protect_device_firmware",
    "locate_protect_device",
    "update_protect_device_settings",
    "set_ai_port_pairing",
    "control_retroactive_ai_processing",
    "analyze_footage_with_ai",
    "check_protect_firmware_updates",
    "upgrade_all_protect_devices",
    "assign_sensor_to_bridge",
    "stop_speaker_stream",
    "play_chime_sound",
    "set_door_lock_auto_close",
    "calibrate_door_lock",
    "set_door_lock_state",
    "adopt_third_party_camera",
    "set_nvr_stack_membership",
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
    """Route table: (method, path) -> response; records every request.

    An unlisted route answers a generic object, so the catalog-shaped calls below can run
    against one upstream."""

    def __init__(self, routes: dict[tuple[str, str], Any] | None = None):
        self.routes = routes or {}
        self.seen: list[httpx.Request] = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.seen.append(req)
        default: Any = [] if req.url.path.endswith(LIST_ROUTES) else {"ok": True}
        entry = self.routes.get((req.method, req.url.path), default)
        if callable(entry):
            entry = entry(req)
        if isinstance(entry, httpx.Response):
            return entry
        return httpx.Response(200, json=entry)

    def writes(self) -> list[httpx.Request]:
        return [r for r in self.seen if r.method != "GET"]


def body_of(req: httpx.Request) -> Any:
    return json.loads(req.content) if req.content else None


async def run(handler, coro_fn, *args, settings: dict[str, Any] | None = None, **kwargs):
    c = client(handler, **(settings or {}))
    try:
        return await coro_fn(c, registry(), HOST, *args, **kwargs)
    finally:
        await c.close()


#: tool -> (function, args, kwargs, method, path, json body or None, query params)
CALLS: dict[str, tuple[Any, tuple[Any, ...], dict[str, Any], str, str, Any, dict[str, str]]] = {
    "readopt_protect_device": (
        pdl.readopt_protect_device,
        ("camera", CAM),
        {"reset": True},
        "POST",
        f"{PRIV}/cameras/{CAM}/readopt",
        None,
        {"reset": "true"},
    ),
    "upgrade_protect_device_firmware": (
        pdl.upgrade_protect_device_firmware,
        ("sensor", SENSOR),
        {},
        "POST",
        f"{PRIV}/sensors/{SENSOR}/update",
        None,
        {},
    ),
    "locate_protect_device": (
        pdl.locate_protect_device,
        ("light", DEV),
        {},
        "POST",
        f"{PRIV}/lights/{DEV}/locate",
        None,
        {},
    ),
    "set_ai_port_pairing": (
        pdl.set_ai_port_pairing,
        (AIPORT, [CAM], True),
        {},
        "POST",
        f"{PRIV}/aiports/{AIPORT}/pair",
        {"cameraIds": [CAM]},
        {},
    ),
    "control_retroactive_ai_processing": (
        pdl.control_retroactive_ai_processing,
        ("start",),
        {"options": {"cameraIds": [CAM]}},
        "POST",
        f"{PRIV}/aiprocessors/retroactive-processing/start",
        {"cameraIds": [CAM]},
        {},
    ),
    "analyze_footage_with_ai": (
        pdl.analyze_footage_with_ai,
        (CAM,),
        {"timestamp": T0, "channel": 0, "event_id": EVENT},
        "POST",
        f"{PRIV}/aiprocessors/vlm/analyze",
        {"cameraId": CAM, "channel": 0, "eventId": EVENT, "timestamp": T0 * 1000},
        {},
    ),
    "check_protect_firmware_updates": (
        pdl.check_protect_firmware_updates,
        (),
        {},
        "POST",
        f"{PRIV}/devices/checkUpdates",
        None,
        {},
    ),
    "upgrade_all_protect_devices": (
        pdl.upgrade_all_protect_devices,
        (),
        {},
        "POST",
        f"{PRIV}/devices/updateAll",
        None,
        {},
    ),
    "get_protect_device_metrics": (
        pdl.get_protect_device_metrics,
        (DEV,),
        {},
        "GET",
        f"{PRIV}/devices/{DEV}/metrics",
        None,
        {"predefinedTimeRange": "1day"},
    ),
    "assign_sensor_to_bridge": (
        pdl.assign_sensor_to_bridge,
        (SENSOR, BRIDGE),
        {},
        "POST",
        f"{PRIV}/sensors/{SENSOR}/assign-bridge",
        {"assignedBridge": BRIDGE},
        {},
    ),
    "get_sensor_readings": (
        pdl.get_sensor_readings,
        (SENSOR,),
        {"start": T0, "end": T0 + 3600},
        "GET",
        f"{PRIV}/sensors/{SENSOR}/readings",
        None,
        {"start": str(T0 * 1000), "end": str((T0 + 3600) * 1000)},
    ),
    "stop_speaker_stream": (
        pdl.stop_speaker_stream,
        (SPEAKER,),
        {},
        "POST",
        f"{PRIV}/speakers/{SPEAKER}/stop-stream",
        None,
        {},
    ),
    "play_chime_sound": (
        pdl.play_chime_sound,
        (CHIME, "speaker"),
        {"options": {"volume": 60}},
        "POST",
        f"{PRIV}/chimes/{CHIME}/play-speaker",
        {"volume": 60},
        {},
    ),
    "list_door_locks": (
        pdl.list_door_locks,
        (),
        {},
        "GET",
        f"{PRIV}/doorlocks",
        None,
        {},
    ),
    "set_door_lock_auto_close": (
        pdl.set_door_lock_auto_close,
        (LOCK,),
        {"options": {"autoCloseTimeMs": 15000}},
        "POST",
        f"{PRIV}/doorlocks/{LOCK}/autoClose",
        {"autoCloseTimeMs": 15000},
        {},
    ),
    "calibrate_door_lock": (
        pdl.calibrate_door_lock,
        (LOCK,),
        {},
        "POST",
        f"{PRIV}/doorlocks/{LOCK}/calibrate",
        None,
        {},
    ),
    "set_door_lock_state": (
        pdl.set_door_lock_state,
        (LOCK, "close"),
        {},
        "POST",
        f"{PRIV}/doorlocks/{LOCK}/close",
        None,
        {},
    ),
    "adopt_third_party_camera": (
        pdl.adopt_third_party_camera,
        ({"host": "192.0.2.50", "username": "probe", "password": "probe-camera-pass"},),
        {},
        "POST",
        f"{PRIV}/third-party-cameras/adopt",
        {"host": "192.0.2.50", "username": "probe", "password": "probe-camera-pass"},
        {},
    ),
    "set_nvr_stack_membership": (
        pdl.set_nvr_stack_membership,
        (MAC, False),
        {"reset": False},
        "POST",
        f"{PRIV}/nvr-stacks/unadopt",
        {"mac": MAC, "reset": False},
        {},
    ),
    "get_protect_bootstrap": (
        pdl.get_protect_bootstrap,
        (),
        {},
        "GET",
        f"{PRIV}/bootstrap",
        None,
        {},
    ),
    "list_protect_keyrings": (
        pdl.list_protect_keyrings,
        (),
        {},
        "GET",
        f"{PRIV}/keyrings",
        None,
        {},
    ),
}
ACTIONS = sorted(n for n in CALLS if n in WRITE_TOOLS)


# ----------------------------------------------------------------- routes and pass-through


@pytest.mark.parametrize("name", sorted(CALLS))
async def test_each_tool_sends_its_sourced_route_body_and_query(name):
    fn, args, kwargs, method, path, body, params = CALLS[name]
    upstream: Any = {"echo": name, "futureField": {"kept": [1, None]}}
    if path.endswith(LIST_ROUTES):
        upstream = [upstream]
    up = Upstream({(method, path): upstream})
    result = await run(up, fn, *args, **kwargs)
    assert len(up.seen) == 1, [r.url.path for r in up.seen]
    req = up.seen[0]
    assert (req.method, req.url.path) == (method, path)
    assert body_of(req) == body
    assert dict(req.url.params) == params
    if name in WRITE_TOOLS:
        assert result["response"] == upstream
        assert result["status"] not in ("dry_run",)
    else:
        assert result == (
            {"result": upstream, "_count": 1} if isinstance(upstream, list) else upstream
        )


@pytest.mark.parametrize(
    "name,expected_status",
    [
        ("readopt_protect_device", "readopt_requested"),
        ("upgrade_protect_device_firmware", "upgrade_requested"),
        ("locate_protect_device", "locating"),
        ("set_ai_port_pairing", "paired"),
        ("control_retroactive_ai_processing", "start_requested"),
        ("analyze_footage_with_ai", "sent"),
        ("check_protect_firmware_updates", "check_requested"),
        ("upgrade_all_protect_devices", "upgrade_requested"),
        ("assign_sensor_to_bridge", "assigned"),
        ("stop_speaker_stream", "stopped"),
        ("play_chime_sound", "played"),
        ("set_door_lock_auto_close", "sent"),
        ("calibrate_door_lock", "calibrating"),
        ("set_door_lock_state", "closed"),
        ("adopt_third_party_camera", "adopt_requested"),
        ("set_nvr_stack_membership", "unadopt_requested"),
    ],
)
async def test_action_status_names_what_was_sent(name, expected_status):
    fn, args, kwargs, *_ = CALLS[name]
    result = await run(Upstream(), fn, *args, **kwargs)
    assert result["status"] == expected_status


async def test_list_reads_wrap_a_bare_array_with_count():
    locks = [{"id": LOCK, "lockStatus": "CLOSED", "unknown": 1}]
    up = Upstream({("GET", f"{PRIV}/doorlocks"): locks})
    assert await run(up, pdl.list_door_locks) == {"result": locks, "_count": 1}
    keyrings = [{"id": DEV, "registryType": "nfc", "registryId": "00000000000000aa"}]
    up = Upstream({("GET", f"{PRIV}/keyrings"): keyrings})
    # registryId is a registered credential: verbatim by default (pass-through).
    assert await run(up, pdl.list_protect_keyrings) == {"result": keyrings, "_count": 1}


async def test_bootstrap_is_returned_complete_and_never_truncated():
    cameras = [{"id": f"{i:024x}", "name": f"probe-{i}", "blob": "x" * 2000} for i in range(400)]
    bootstrap = {"nvr": {"id": DEV}, "cameras": cameras, "aiports": [], "future": {"a": 1}}
    up = Upstream({("GET", f"{PRIV}/bootstrap"): bootstrap})
    assert await run(up, pdl.get_protect_bootstrap) == bootstrap


async def test_bootstrap_bare_array_is_kept_under_result():
    up = Upstream({("GET", f"{PRIV}/bootstrap"): [1, 2]})
    assert await run(up, pdl.get_protect_bootstrap) == {"result": [1, 2], "_count": 2}


@pytest.mark.parametrize("body", [[{"t": 1}], {"readings": [{"t": 1}]}])
async def test_sensor_readings_verbatim_array_or_object(body):
    up = Upstream({("GET", f"{PRIV}/sensors/{SENSOR}/readings"): body})
    result = await run(up, pdl.get_sensor_readings, SENSOR, start=T0)
    assert result == (body if isinstance(body, dict) else {"result": body, "_count": 1})
    assert dict(up.seen[0].url.params) == {"start": str(T0 * 1000)}


async def test_metrics_sends_the_predefined_time_range_protect_7_3_requires():
    """Protect 7.3.70 (live 2026-10-28) answers 400 "must have required property
    'predefinedTimeRange'" without it; the web app opens on "1day" and sends
    aggregateFunc "MAX". The default is sent; a given range and aggregate are forwarded."""
    up = Upstream({("GET", f"{PRIV}/devices/{DEV}/metrics"): []})
    await run(up, pdl.get_protect_device_metrics, DEV)
    assert dict(up.seen[0].url.params) == {"predefinedTimeRange": "1day"}
    up = Upstream({("GET", f"{PRIV}/devices/{DEV}/metrics"): []})
    await run(up, pdl.get_protect_device_metrics, DEV, "1week", "MAX")
    assert dict(up.seen[0].url.params) == {"predefinedTimeRange": "1week", "aggregateFunc": "MAX"}
    tools = {t.name: t for t in await _registered_tools()}
    props = tools["get_protect_device_metrics"].parameters["properties"]
    assert props["predefined_time_range"]["default"] == "1day"
    assert "1week" in props["predefined_time_range"]["description"]
    assert "MAX" in props["aggregate_func"]["description"]


async def test_sensor_readings_requires_start_protect_7_3_requires():
    """Protect 7.3.70 (live 2026-10-28) answers 400 "must have required property 'start'"
    without it, so start is a required argument."""
    tools = {t.name: t for t in await _registered_tools()}
    schema = tools["get_sensor_readings"].parameters
    assert "start" not in schema["required"] and "end" not in schema["required"]
    up = Upstream({("GET", f"{PRIV}/sensors/{SENSOR}/readings"): {"readings": []}})
    await run(up, pdl.get_sensor_readings, SENSOR, T0)
    assert dict(up.seen[0].url.params) == {"start": str(T0 * 1000)}


async def _registered_tools() -> list[Any]:
    from unifi_fabric import server

    registered = server.mcp.list_tools()
    return await registered if inspect.isawaitable(registered) else registered


async def test_metrics_array_is_wrapped_with_count():
    up = Upstream({("GET", f"{PRIV}/devices/{DEV}/metrics"): [{"cpu": 1}]})
    assert await run(up, pdl.get_protect_device_metrics, DEV) == {
        "result": [{"cpu": 1}],
        "_count": 1,
    }


@pytest.mark.parametrize(
    "fn,args,path",
    [
        (pdl.set_ai_port_pairing, (AIPORT, [CAM], False), f"{PRIV}/aiports/{AIPORT}/unpair"),
        (pdl.play_chime_sound, (CHIME, "buzzer"), f"{PRIV}/chimes/{CHIME}/play-buzzer"),
        (pdl.set_door_lock_state, (LOCK, "open"), f"{PRIV}/doorlocks/{LOCK}/open"),
        (pdl.set_nvr_stack_membership, (MAC, True), f"{PRIV}/nvr-stacks/adopt"),
        (pdl.control_retroactive_ai_processing, ("cancel",), None),
    ],
)
async def test_alternate_branches_route_correctly(fn, args, path):
    up = Upstream()
    await run(up, fn, *args)
    expected = path or f"{PRIV}/aiprocessors/retroactive-processing/cancel"
    assert up.seen[0].url.path == expected
    if fn is pdl.set_nvr_stack_membership:
        assert body_of(up.seen[0]) == {"mac": MAC}  # reset is sent only when given
    if fn in (pdl.play_chime_sound, pdl.control_retroactive_ai_processing):
        assert up.seen[0].content == b""  # no body invented


@pytest.mark.parametrize(
    "device_type,collection",
    [
        ("aiport", "aiports"),
        ("aiprocessor", "aiprocessors"),
        ("camera", "cameras"),
        ("chime", "chimes"),
        ("doorlock", "doorlocks"),
        ("light", "lights"),
        ("linkstation", "linkstations"),
        ("sensor", "sensors"),
        ("speaker", "speakers"),
        ("viewer", "viewers"),
    ],
)
async def test_readopt_maps_every_type_to_its_collection(device_type, collection):
    up = Upstream()
    await run(up, pdl.readopt_protect_device, device_type, DEV)
    assert up.seen[0].url.path == f"{PRIV}/{collection}/{DEV}/readopt"
    assert not up.seen[0].url.params  # reset only when given


async def test_upstream_error_reason_is_kept_in_full():
    reason = {"error": "Device 'x' not found " + "detail " * 60, "name": "NOT_FOUND", "id": DEV}
    up = Upstream({("POST", f"{PRIV}/cameras/{DEV}/readopt"): httpx.Response(404, json=reason)})
    with pytest.raises(UniFiConnectionError) as exc:
        await run(up, pdl.readopt_protect_device, "camera", DEV)
    assert reason["error"] in str(exc.value) and DEV in str(exc.value)


async def test_physical_action_429_is_sent_once_never_retried():
    up = Upstream(
        {("POST", f"{PRIV}/doorlocks/{LOCK}/open"): httpx.Response(429, json={"error": "slow"})}
    )
    with pytest.raises(RateLimitError):
        await run(up, pdl.set_door_lock_state, LOCK, "open")
    assert len(up.seen) == 1


async def test_redirect_raises_with_status_and_location():
    up = Upstream(
        {
            ("POST", f"{PRIV}/devices/updateAll"): httpx.Response(
                302, headers={"location": "https://example.invalid/login"}
            )
        }
    )
    with pytest.raises(UniFiConnectionError) as exc:
        await run(up, pdl.upgrade_all_protect_devices)
    assert "302" in str(exc.value) and "example.invalid/login" in str(exc.value)


# ----------------------------------------------------------------------- epoch seconds


async def test_epoch_seconds_that_look_like_ms_are_sent_and_warned():
    up = Upstream({("GET", f"{PRIV}/sensors/{SENSOR}/readings"): {"readings": []}})
    result = await run(up, pdl.get_sensor_readings, SENSOR, start=T0 * 1000)
    assert up.seen[0].url.params["start"] == str(T0 * 1_000_000)
    assert result["_warnings"][0]["code"] == "EPOCH_SECONDS_LOOKS_LIKE_MILLISECONDS"
    up = Upstream()
    result = await run(up, pdl.analyze_footage_with_ai, CAM, timestamp=-5)
    assert result["_warnings"][0]["code"] == "EPOCH_SECONDS_NEGATIVE"


@pytest.mark.parametrize(
    "fn,args,kwargs",
    [
        (pdl.get_sensor_readings, (SENSOR,), {"start": 1.5}),
        (pdl.get_sensor_readings, (SENSOR,), {"start": T0, "end": True}),
        (pdl.analyze_footage_with_ai, (CAM,), {"timestamp": "1760000000"}),
    ],
)
async def test_non_integer_epoch_fails_before_any_request(fn, args, kwargs):
    up = Upstream()
    with pytest.raises(ValueError, match="integer epoch-seconds"):
        await run(up, fn, *args, **kwargs)
    assert up.seen == []


# ---------------------------------------------------------------- validation before I/O


@pytest.mark.parametrize("bad", ["", "../etc", "a/..", "\x00x"])
@pytest.mark.parametrize(
    "fn,make",
    [
        (pdl.readopt_protect_device, lambda b: ("camera", b)),
        (pdl.upgrade_protect_device_firmware, lambda b: ("camera", b)),
        (pdl.locate_protect_device, lambda b: ("light", b)),
        (pdl.set_ai_port_pairing, lambda b: (b, [CAM], True)),
        (pdl.get_protect_device_metrics, lambda b: (b,)),
        (pdl.assign_sensor_to_bridge, lambda b: (b, BRIDGE)),
        (pdl.get_sensor_readings, lambda b: (b, T0)),
        (pdl.stop_speaker_stream, lambda b: (b,)),
        (pdl.play_chime_sound, lambda b: (b, "buzzer")),
        (pdl.set_door_lock_auto_close, lambda b: (b,)),
        (pdl.calibrate_door_lock, lambda b: (b,)),
        (pdl.set_door_lock_state, lambda b: (b, "open")),
        (pdl.update_protect_device_settings, lambda b: ("camera", {"name": "n"}, b)),
        (pdl.update_protect_device_settings, lambda b: ("doorlock", {"name": "n"}, b)),
    ],
)
async def test_unsafe_ids_fail_before_any_request(fn, make, bad):
    up = Upstream()
    with pytest.raises(ValueError):
        await run(up, fn, *make(bad))
    assert up.seen == []


@pytest.mark.parametrize(
    "fn,args,match",
    [
        (pdl.readopt_protect_device, ("bridge", DEV), "Invalid action 'readopt'"),
        (pdl.readopt_protect_device, ("nvr", None), "Invalid action 'readopt'"),
        (pdl.upgrade_protect_device_firmware, ("doorlock", DEV), "Invalid action 'update'"),
        (pdl.locate_protect_device, ("camera", DEV), "Invalid action 'locate'"),
        (pdl.locate_protect_device, ("router", DEV), "Invalid device_type 'router'"),
        (pdl.update_protect_device_settings, ("router", {"a": 1}, DEV), "Invalid device_type"),
        (pdl.update_protect_device_settings, ("camera", {"a": 1}), "A device id is required"),
        (pdl.update_protect_device_settings, ("doorlock", {"a": 1}), "A device id is required"),
        (pdl.update_protect_device_settings, ("nvr", {"a": 1}, DEV), "singleton"),
        (pdl.update_protect_device_settings, ("camera", {}, CAM), "No fields provided"),
        (pdl.update_protect_device_settings, ("aiport", {}, AIPORT), "No fields provided"),
        (pdl.update_protect_device_settings, ("nvr", {"_note": 1}), "No fields provided"),
    ],
)
async def test_route_and_body_grammar_fail_before_any_request(fn, args, match):
    up = Upstream()
    with pytest.raises(ValueError, match=match):
        await run(up, fn, *args)
    assert up.seen == []


@pytest.mark.parametrize(
    "fn,args",
    [
        (pdl.control_retroactive_ai_processing, ("restart",)),
        (pdl.control_retroactive_ai_processing, ("../start",)),
        (pdl.play_chime_sound, (CHIME, "siren")),
        (pdl.set_door_lock_state, (LOCK, "unlock")),
        (pdl.set_ai_port_pairing, (AIPORT, [CAM], "yes")),
        (pdl.set_nvr_stack_membership, (MAC, 1)),
    ],
)
async def test_closed_choices_fail_listing_valid_values_before_any_request(fn, args):
    up = Upstream()
    with pytest.raises(ValidationError, match="Input should be"):
        await run(up, fn, *args)
    assert up.seen == []


def test_device_type_choices_are_the_sourced_action_sets():
    """Each per-action Literal is exactly the W0 mapper's types for that action."""
    assert set(get_args(pdl.ReadoptDeviceType)) == {
        t.value for t in device_types_with_action("readopt")
    }
    assert set(get_args(pdl.FirmwareDeviceType)) == {
        t.value for t in device_types_with_action("update")
    }
    assert set(get_args(pdl.LocateDeviceType)) == {
        t.value for t in device_types_with_action("locate")
    }
    from unifi_fabric.tools._protect_device_types import DEVICE_TYPES

    assert set(get_args(pdl.SettingsDeviceType)) == set(DEVICE_TYPES)


# ------------------------------------------------------------- write switches and dry-run


def _write_calls() -> list[tuple[str, Any, tuple[Any, ...], dict[str, Any]]]:
    calls = [(n, *CALLS[n][:3]) for n in ACTIONS]
    calls.append(
        (
            "update_protect_device_settings",
            pdl.update_protect_device_settings,
            ("camera", {"name": "n"}, CAM),
            {},
        )
    )
    calls.append(
        (
            "update_protect_device_settings[nvr]",
            pdl.update_protect_device_settings,
            ("nvr", {"name": "n"}),
            {},
        )
    )
    return calls


WRITE_CALLS = _write_calls()
WRITE_IDS = [c[0] for c in WRITE_CALLS]


@pytest.mark.parametrize("name,fn,args,kwargs", WRITE_CALLS, ids=WRITE_IDS)
async def test_dry_run_previews_every_write_and_sends_none(name, fn, args, kwargs):
    up = Upstream({("GET", f"{PRIV}/bootstrap"): {"nvr": {"name": "old"}}})
    result = await run(up, fn, *args, settings={"dry_run": True}, **kwargs)
    assert up.writes() == [], name
    assert result["status"] == "dry_run", result
    preview = result["response"]
    assert preview["dryRun"] is True and preview["status"] == "dry_run"
    assert "body" in preview["preview"] and "params" in preview["preview"]
    assert "verified" not in result


async def test_dry_run_preview_carries_the_query_and_body():
    result = await run(
        Upstream(),
        pdl.readopt_protect_device,
        "camera",
        CAM,
        reset=True,
        settings={"dry_run": True},
    )
    detail = result["response"]["preview"]
    assert detail["method"] == "POST" and detail["params"] == {"reset": True}
    result = await run(
        Upstream(), pdl.assign_sensor_to_bridge, SENSOR, BRIDGE, settings={"dry_run": True}
    )
    assert result["response"]["preview"]["body"] == {"assignedBridge": BRIDGE}


@pytest.mark.parametrize("name,fn,args,kwargs", WRITE_CALLS, ids=WRITE_IDS)
async def test_protect_write_opt_out_refuses_with_zero_requests(
    name, fn, args, kwargs, monkeypatch
):
    monkeypatch.setenv("UNIFI_PROTECT_MUTATIONS_ENABLED", "false")
    up = Upstream()
    with pytest.raises(ValueError, match="UNIFI_PROTECT_MUTATIONS_ENABLED"):
        await run(up, fn, *args, **kwargs)
    assert up.seen == []


@pytest.mark.parametrize("name,fn,args,kwargs", WRITE_CALLS, ids=WRITE_IDS)
async def test_read_only_mode_refuses_every_write_before_any_request(
    name, fn, args, kwargs, monkeypatch
):
    monkeypatch.setenv("UNIFI_READ_ONLY", "1")
    up = Upstream()
    with pytest.raises(Exception, match="read-only mode"):
        await run(up, fn, *args, **kwargs)
    assert up.seen == []  # not even the settings read-before


@pytest.mark.parametrize("name", sorted(READ_TOOLS))
async def test_read_only_mode_leaves_reads_working(name, monkeypatch):
    monkeypatch.setenv("UNIFI_READ_ONLY", "1")
    fn, args, kwargs, *_ = CALLS[name]
    up = Upstream()
    await run(up, fn, *args, **kwargs)
    assert up.seen


@pytest.mark.parametrize("name", ACTIONS)
async def test_confirm_is_not_a_gate(name):
    """Writes run by default: there is no confirm parameter on the module functions."""
    fn = CALLS[name][0]
    assert "confirm" not in inspect.signature(fn).parameters


# ------------------------------------------------------------------- settings update


async def test_official_settings_update_reads_patches_and_verifies():
    state = {"id": CAM, "name": "old", "ledSettings": {"isEnabled": False}}

    def patch(req: httpx.Request) -> dict[str, Any]:
        body = body_of(req)
        state["name"] = body["name"]
        return {"id": CAM, "patched": True}

    up = Upstream(
        {
            ("GET", f"{OFFI}/cameras/{CAM}"): lambda req: dict(state),
            ("PATCH", f"{OFFI}/cameras/{CAM}"): patch,
        }
    )
    result = await run(up, pdl.update_protect_device_settings, "camera", {"name": "new"}, CAM)
    assert [(r.method, r.url.path) for r in up.seen] == [
        ("GET", f"{OFFI}/cameras/{CAM}"),
        ("PATCH", f"{OFFI}/cameras/{CAM}"),
        ("GET", f"{OFFI}/cameras/{CAM}"),
    ]
    assert body_of(up.seen[1]) == {"name": "new"}
    assert result["status"] == "updated" and result["verified"] is True
    assert result["before"]["name"] == "old" and result["after"]["name"] == "new"
    assert result["response"] == {"id": CAM, "patched": True}
    assert result["_route"] == "official"


@pytest.mark.parametrize(
    "device_type,family",
    [
        ("bridge", "bridges"),
        ("chime", "chimes"),
        ("light", "lights"),
        ("linkstation", "link-stations"),
        ("sensor", "sensors"),
        ("speaker", "speakers"),
        ("viewer", "viewers"),
    ],
)
async def test_official_types_use_the_official_family(device_type, family):
    up = Upstream({("GET", f"{OFFI}/{family}/{DEV}"): {"id": DEV, "name": "old"}})
    await run(up, pdl.update_protect_device_settings, device_type, {"name": "new"}, DEV)
    assert {r.url.path for r in up.seen} == {f"{OFFI}/{family}/{DEV}"}
    assert up.writes()[0].method == "PATCH"


async def test_settings_noop_when_every_leaf_already_matches():
    up = Upstream({("GET", f"{PRIV}/doorlocks/{LOCK}"): {"id": LOCK, "name": "same"}})
    result = await run(up, pdl.update_protect_device_settings, "doorlock", {"name": "same"}, LOCK)
    assert result["status"] == "noop" and result["resource"]["name"] == "same"
    assert up.writes() == []


async def test_private_doorlock_update_verifies_type_strictly():
    up = Upstream({("GET", f"{PRIV}/doorlocks/{LOCK}"): {"id": LOCK, "enabled": 1}})
    result = await run(up, pdl.update_protect_device_settings, "doorlock", {"enabled": True}, LOCK)
    # 1 is not True: the write is sent and the read-after does not verify it.
    assert up.writes()[0].url.path == f"{PRIV}/doorlocks/{LOCK}"
    assert body_of(up.writes()[0]) == {"enabled": True}
    assert result["status"] == "updated" and result["verified"] is False
    assert result["_route"] == "private"


async def test_private_aiport_update_reads_the_bootstrap_collection():
    state = {"id": AIPORT, "name": "old", "nested": {"a": 1, "b": 2}}

    def patch(req: httpx.Request) -> dict[str, Any]:
        state["nested"].update(body_of(req)["nested"])
        return {}

    def bootstrap(req: httpx.Request) -> dict[str, Any]:
        return {"aiports": [{"id": "other"}, json.loads(json.dumps(state))], "nvr": {}}

    up = Upstream(
        {
            ("GET", f"{PRIV}/bootstrap"): bootstrap,
            ("PATCH", f"{PRIV}/aiports/{AIPORT}"): patch,
        }
    )
    result = await run(
        up, pdl.update_protect_device_settings, "aiport", {"nested": {"a": 5}}, AIPORT
    )
    assert body_of(up.writes()[0]) == {"nested": {"a": 5}}  # partial nested object as given
    assert result["verified"] is True
    assert result["before"]["nested"] == {"a": 1, "b": 2}
    assert result["after"]["nested"] == {"a": 5, "b": 2}


async def test_private_nvr_update_is_a_singleton_patch():
    up = Upstream({("GET", f"{PRIV}/bootstrap"): {"nvr": {"id": DEV, "name": "old"}}})
    result = await run(up, pdl.update_protect_device_settings, "nvr", {"name": "new"})
    assert up.writes()[0].url.path == f"{PRIV}/nvr"
    assert result["status"] == "updated" and result["verified"] is False  # fake never changes


async def test_unlisted_private_record_is_written_and_left_unverified():
    up = Upstream({("GET", f"{PRIV}/bootstrap"): {"cameras": []}})
    result = await run(up, pdl.update_protect_device_settings, "aiprocessor", {"x": 1}, DEV)
    assert up.writes()[0].url.path == f"{PRIV}/aiprocessors/{DEV}"
    assert result["verified"] is None and "could not be verified" in result["readAfterError"]
    assert result["before"] is None


async def test_failed_read_after_reports_null_verdict_with_reason():
    calls = {"n": 0}

    def read(req: httpx.Request) -> Any:
        calls["n"] += 1
        if calls["n"] == 1:
            return {"id": LOCK, "name": "old"}
        return httpx.Response(500, json={"error": "boom"})

    up = Upstream({("GET", f"{PRIV}/doorlocks/{LOCK}"): read})
    result = await run(up, pdl.update_protect_device_settings, "doorlock", {"name": "n"}, LOCK)
    assert result["status"] == "updated" and result["verified"] is None
    assert "boom" in result["readAfterError"]


async def test_settings_dry_run_keeps_before_and_skips_read_after():
    up = Upstream({("GET", f"{PRIV}/doorlocks/{LOCK}"): {"id": LOCK, "name": "same"}})
    result = await run(
        up,
        pdl.update_protect_device_settings,
        "doorlock",
        {"name": "same"},
        LOCK,
        settings={"dry_run": True},
    )
    # Under dry-run the no-op short-circuit never stands in for the preview.
    assert result["status"] == "dry_run" and result["before"]["name"] == "same"
    assert len(up.seen) == 1 and up.writes() == []


# ------------------------------------------------------------------------ multi-key


async def test_multikey_requests_ride_the_owning_key(multikey_client, multikey_registry):
    for label, hosts in MULTIKEY_HOSTS_BY_LABEL.items():
        await multikey_registry.set_hosts(hosts, key=multikey_client.get_key_by_label(label))
    multikey_registry.resolve_host_id = AsyncMock(return_value="console-beta-1")
    seen: list[str | None] = []

    async def capture(path, *a, key=None, **kw):
        seen.append(key.label if key else None)
        if path.endswith(("/doorlocks", "/keyrings")):
            return []
        return {}

    for method in ("get", "post", "patch"):
        setattr(multikey_client, method, AsyncMock(side_effect=capture))

    async def request(method, path, *a, key=None, **kw):
        seen.append(key.label if key else None)
        return httpx.Response(200, json={}, request=httpx.Request(method, "https://x" + path))

    multikey_client.request = AsyncMock(side_effect=request)
    assert "readopt_protect_device" in CALLS
    calls = [(n, *CALLS[n][:3]) for n in sorted(CALLS)] + WRITE_CALLS[-2:]
    for name, fn, args, kwargs in calls:
        seen.clear()
        await fn(multikey_client, multikey_registry, "Beta-Branch", *args, **kwargs)
        assert seen and set(seen) == {"beta"}, (name, seen)


# --------------------------------------------------------------------- secret registry


@pytest.mark.parametrize(
    "method,route,field,side",
    [
        ("POST", "protect/api/third-party-cameras/adopt", "password", "request"),
        ("GET", "protect/api/keyrings", "registryId", "response"),
        ("GET", "protect/api/bootstrap", "shareLink", "response"),
    ],
)
def test_lane_credentials_are_registered(method, route, field, side):
    path = f"/v1/connector/consoles/{HOST}/proxy/{route}"
    entries = rs.matching(method, path)
    assert entries
    fields = {
        f for e in entries for f in (e.request_fields if side == "request" else e.response_fields)
    }
    assert field in fields
    sentinel = "s3nt1nel-p01-0000"
    if side == "request":
        assert sentinel in rs.request_secrets(method, path, {"camera": {field: sentinel}})
    else:
        content = json.dumps([{field: sentinel}]).encode()
        assert sentinel in rs.response_secrets(method, path, content, [])
        payload = [{field: sentinel}]
        assert rs.mask_response_body(method, path, payload, redact_secrets=False) is payload


# --------------------------------------------------------------- registration contract


def _registered() -> dict[str, Any]:
    mcp = FastMCP("p01-test")
    pdl.register(mcp, lambda: (None, None))
    res = mcp.list_tools()
    tools = asyncio.run(res) if inspect.isawaitable(res) else res
    return {t.name: t for t in tools}


def test_register_adds_exactly_the_twenty_two_tools():
    tools = _registered()
    assert set(tools) == READ_TOOLS | WRITE_TOOLS
    assert len(tools) == 22
    assert "unadopt_protect_device" not in tools


def test_annotations_match_the_source_derived_write_set():
    tools = _registered()
    verbs = classify_tool_verbs(list(tools.values()))
    assert {name for name, v in verbs.items() if v} == WRITE_TOOLS
    for name, tool in tools.items():
        writes = name in WRITE_TOOLS
        hints = tool.annotations.model_dump(by_alias=True)
        assert hints["readOnlyHint"] is (not writes), name
        assert hints["destructiveHint"] is writes, name


def test_descriptions_fit_describe_every_property_and_give_examples():
    tools = _registered()
    assert set(tools) == READ_TOOLS | WRITE_TOOLS
    for name, tool in tools.items():
        text = tool.description or ""
        assert text and len(text) <= 2048, (name, len(text))
        assert "Args:" not in text, name
        props = (tool.parameters or {}).get("properties", {})
        assert "host" in (tool.parameters or {}).get("required", []), name
        for prop, schema in props.items():
            assert schema.get("description"), f"{name}.{prop} has no description"
            flat = " ".join(schema["description"].split())
            assert "for example" in flat, f"{name}.{prop} has no example"


def test_writes_accept_confirm_and_state_their_consequence():
    tools = _registered()
    for name in WRITE_TOOLS:
        assert "confirm" in tools[name].parameters["properties"], name
        if name != "update_protect_device_settings":
            assert "Consequence:" in tools[name].description, name
        assert "UNIFI_DRY_RUN" in tools[name].description, name
    for name in READ_TOOLS:
        assert "confirm" not in tools[name].parameters["properties"], name


def test_closed_choices_are_schema_enums():
    tools = _registered()
    props = tools["locate_protect_device"].parameters["properties"]
    assert props["device_type"]["enum"] == ["aiport", "doorlock", "light", "linkstation", "sensor"]
    props = tools["set_door_lock_state"].parameters["properties"]
    assert props["action"]["enum"] == ["open", "close"]


def test_module_raises_only_through_registered_helpers():
    """No ``raise`` in this module: every refusal comes from a registered helper."""
    source = inspect.getsource(pdl)
    assert "\n    raise " not in source and "\n        raise " not in source


@pytest.mark.parametrize("kind,identity", [("doorlock", LOCK), ("aiport", AIPORT), ("nvr", DEV)])
@pytest.mark.parametrize("changed", [False, True])
async def test_private_settings_addressing_body_id_case_noop_and_verification(
    kind, identity, changed
):
    before = {"id": identity, "name": "same"}
    requested = {"id": identity.upper(), "name": "changed" if changed else "same"}
    after = {**before, "name": requested["name"]}
    reads = iter([before, after])
    if kind == "doorlock":
        routes = {
            ("GET", f"{PRIV}/doorlocks/{identity.upper()}"): lambda req: next(reads),
            ("GET", f"{PRIV}/doorlocks/{identity}"): lambda req: next(reads),
            ("PATCH", f"{PRIV}/doorlocks/{identity}"): {},
        }
    else:

        def bootstrap(req):
            record = next(reads)
            return {"nvr": record} if kind == "nvr" else {"aiports": [record]}

        routes = {
            ("GET", f"{PRIV}/bootstrap"): bootstrap,
            ("PATCH", f"{PRIV}/{kind + 's' if kind != 'nvr' else kind}"): {},
        }
        if kind == "aiport":
            routes[("PATCH", f"{PRIV}/aiports/{identity}")] = {}
    up = Upstream(routes)
    result = await run(
        up,
        pdl.update_protect_device_settings,
        kind,
        requested,
        None if kind == "nvr" else identity.upper(),
    )
    if changed:
        assert result["verified"] is True
        assert body_of(up.writes()[0]) == {**requested, "id": identity}
    else:
        assert result["status"] == "noop" and up.writes() == []
    assert requested["id"] == identity.upper()
    assert result.get("before", result.get("resource")) == before


@pytest.mark.parametrize(
    "device_type,bucket", [("aiport", "aiports"), ("aiprocessor", "aiprocessors")]
)
async def test_private_settings_match_hex_id_case_and_send_upstream_spelling(device_type, bucket):
    before = {"id": DEV, "name": "before"}
    after = {**before, "id": DEV.upper(), "name": "after"}
    bodies = iter([{bucket: [before]}, {bucket: [after]}])
    path = f"{PRIV}/{bucket.lower()}/{DEV}"
    up = Upstream(
        {
            ("GET", f"{PRIV}/bootstrap"): lambda _req: httpx.Response(200, json=next(bodies)),
            ("PATCH", path): {"ack": "unchanged"},
        }
    )
    result = await run(
        up,
        pdl.update_protect_device_settings,
        device_type,
        {"name": "after"},
        device_id=DEV.upper(),
    )
    assert result["before"] == before
    assert result["after"] == after
    assert result["verified"] is True
    assert result["response"] == {"ack": "unchanged"}
    assert up.writes()[0].url.path == path
    assert body_of(up.writes()[0]) == {"name": "after"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "function,args,status,hint",
    [
        (pdl.get_sensor_readings, (SENSOR,), 400, "start"),
        (pdl.list_door_locks, (), 404, "Door lock"),
    ],
)
async def test_device_read_failure_has_context_and_preserves_upstream(function, args, status, hint):
    from unittest.mock import AsyncMock

    from unifi_fabric.client import UniFiConnectionError

    client = AsyncMock()
    client.get.side_effect = UniFiConnectionError("complete upstream failure", status=status)
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = None
    registry.resolve_host_id.return_value = HOST
    with pytest.raises(UniFiConnectionError) as caught:
        await function(client, registry, HOST, *args)
    assert "complete upstream failure" in str(caught.value)
    assert hint in str(caught.value)
    assert caught.value.status == status
