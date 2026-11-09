"""GS3 P02: Protect PTZ control, presets/patrols, camera shortcuts, calibration and doorbell.

Hermetic: a real ``UniFiClient`` over ``respx`` (every request is observable), a stubbed
host resolution, and synthetic records only (zero-padded ids, documentation names).
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
import respx
from fastmcp import FastMCP
from pydantic import ValidationError

from tests.conftest import MULTIKEY_HOSTS_BY_LABEL
from unifi_fabric import route_secrets, server
from unifi_fabric._read_only_audit import classify_tool_verbs, derive_write_tools, is_destructive
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.refusals import classify
from unifi_fabric.tools import protect_ptz_doorbell as p02

HOST_ID = "000000000000000000000000000000000000000000:1"
CAM = "0000000000000000000000c1"
SC1 = "0000000000000000000000d1"
SC2 = "0000000000000000000000d2"
API = "https://api.ui.com"
PRIVATE = f"{API}/v1/connector/consoles/{HOST_ID}/proxy/protect/api"
OFFICIAL = f"{API}/v1/connector/consoles/{HOST_ID}/proxy/protect/integration/v1"

TOOLS = {
    "move_ptz_camera": {"camera_id": CAM, "movement": {"type": "continuous"}},
    "ptz_home": {"camera_id": CAM},
    "set_ptz_event_control_window": {"camera_id": CAM, "open_window": True},
    "create_ptz_patrol": {"camera_id": CAM, "patrol": {"name": "probe", "slot": 0}},
    "update_ptz_patrol": {"camera_id": CAM, "slot": 0, "fields": {"name": "probe"}},
    "delete_ptz_patrol": {"camera_id": CAM, "slot": 0},
    "create_ptz_preset": {"camera_id": CAM, "preset": {"name": "probe", "slot": 1}},
    "update_ptz_preset": {"camera_id": CAM, "slot": 1, "fields": {"name": "probe"}},
    "delete_ptz_preset": {"camera_id": CAM, "slot": 1},
    "create_camera_shortcut": {"camera_id": CAM, "shortcut": {"name": "probe"}},
    "update_camera_shortcut": {"camera_id": CAM, "body": {"id": SC1, "name": "probe"}},
    "delete_camera_shortcut": {"camera_id": CAM, "shortcut_ids": [SC1]},
    "trigger_camera_shortcut": {"camera_id": CAM, "shortcut_id": SC1},
    "calibrate_camera": {"camera_id": CAM},
    "test_doorbell_ringtone": {"camera_id": CAM},
    "enroll_doorbell_credential": {"camera_id": CAM, "credential_type": "fingerprint"},
    "delete_doorbell_credential": {
        "camera_id": CAM,
        "credential_type": "nfc",
        "credential_id": "0000000000000000000000e1",
    },
}

#: (method, URL) of each tool's write.
WRITES = {
    "move_ptz_camera": ("POST", f"{PRIVATE}/cameras/{CAM}/move"),
    "ptz_home": ("POST", f"{OFFICIAL}/cameras/{CAM}/ptz/goto/-1"),
    "set_ptz_event_control_window": (
        "POST",
        f"{PRIVATE}/cameras/{CAM}/ptz/eventPtzControlWindow",
    ),
    "create_ptz_patrol": ("POST", f"{PRIVATE}/cameras/{CAM}/ptz/patrol"),
    "update_ptz_patrol": ("PATCH", f"{PRIVATE}/cameras/{CAM}/ptz/patrol/0"),
    "delete_ptz_patrol": ("DELETE", f"{PRIVATE}/cameras/{CAM}/ptz/patrol/0"),
    "create_ptz_preset": ("POST", f"{PRIVATE}/cameras/{CAM}/ptz/preset"),
    "update_ptz_preset": ("PATCH", f"{PRIVATE}/cameras/{CAM}/ptz/preset/1"),
    "delete_ptz_preset": ("DELETE", f"{PRIVATE}/cameras/{CAM}/ptz/preset/1"),
    "create_camera_shortcut": ("POST", f"{PRIVATE}/cameras/{CAM}/shortcuts"),
    "update_camera_shortcut": ("PATCH", f"{PRIVATE}/cameras/{CAM}/shortcuts"),
    "delete_camera_shortcut": ("DELETE", f"{PRIVATE}/cameras/{CAM}/shortcuts"),
    "trigger_camera_shortcut": ("POST", f"{PRIVATE}/cameras/{CAM}/shortcuts/{SC1}/click"),
    "calibrate_camera": ("POST", f"{PRIVATE}/cameras/{CAM}/calibrate"),
    "test_doorbell_ringtone": ("POST", f"{PRIVATE}/cameras/{CAM}/test-ringtone"),
    "enroll_doorbell_credential": ("POST", f"{PRIVATE}/cameras/{CAM}/fingerprint/enroll"),
    "delete_doorbell_credential": (
        "DELETE",
        f"{PRIVATE}/cameras/{CAM}/nfc/0000000000000000000000e1",
    ),
}

PATROLS = [
    {
        "id": "0000000000000000000000f0",
        "name": "probe-old",
        "slot": 0,
        "presets": [0, 1],
        "presetDurationSeconds": 10,
        "camera": CAM,
    }
]
PRESETS = [
    {
        "id": "0000000000000000000000f1",
        "name": "probe-old",
        "slot": 1,
        "ptz": {"pan": 1, "tilt": 2, "zoom": 0},
    },
    {
        "id": "0000000000000000000000f2",
        "name": "probe-home",
        "slot": -1,
        "ptz": {"pan": 0, "tilt": 0, "zoom": 0},
    },
]
CAMERA = {"id": CAM, "name": "probe-camera", "shortcuts": [{"id": SC1, "name": "probe-old"}]}


def _client(*, keys: list[APIKeyConfig] | None = None) -> UniFiClient:
    settings = Settings(api_keys=keys or [APIKeyConfig(key="k-test", label="test")])
    return UniFiClient(settings)


def _registry() -> AsyncMock:
    registry = AsyncMock()
    registry.resolve_key_for_host = AsyncMock(return_value=None)
    registry.resolve_host_id = AsyncMock(return_value=HOST_ID)
    return registry


def _reads(router: respx.Router) -> None:
    router.get(f"{PRIVATE}/cameras/{CAM}/ptz/patrol").respond(200, json=PATROLS)
    router.get(f"{PRIVATE}/cameras/{CAM}/ptz/preset").respond(200, json=PRESETS)
    router.get(f"{PRIVATE}/cameras/{CAM}").respond(200, json=CAMERA)


def _writes(router: respx.Router, body: Any = None) -> dict[str, respx.Route]:
    routes = {}
    for name, (method, url) in WRITES.items():
        match = {"url__startswith": url} if name == "delete_camera_shortcut" else {"url": url}
        routes[name] = router.route(method=method, **match).respond(
            200, json=body if body is not None else {"probe": name}
        )
    return routes


async def _call(
    name: str,
    client: UniFiClient,
    registry: Any = None,
    host: str = "probe-console",
    **args: Any,
) -> Any:
    fn = getattr(p02, name)
    merged = {**TOOLS[name], **args}
    return await fn(client, registry or _registry(), host, **merged)


def _sent(route: respx.Route) -> Any:
    content = route.calls.last.request.content
    return json.loads(content) if content else None


def _list_tools() -> dict[str, Any]:
    return {t.name: t for t in asyncio.run(server.mcp.list_tools())}


# --------------------------------------------------------------------------- registration


def test_every_tool_is_registered_with_derived_write_annotations():
    tools = _list_tools()
    assert set(TOOLS) <= set(tools)
    mine = [tools[n] for n in TOOLS]
    assert derive_write_tools(mine) == set(TOOLS)
    verbs = classify_tool_verbs(mine)
    for tool in mine:
        assert tool.annotations.read_only_hint is False
        assert tool.annotations.destructive_hint is True
        assert verbs[tool.name] == {WRITES[tool.name][0]}
    deletes = {n for n in TOOLS if n.startswith("delete_")}
    assert {t.name for t in mine if is_destructive(t.fn)} == deletes


def test_descriptions_document_every_argument_with_examples():
    assert "move_ptz_camera" in TOOLS and "calibrate_camera" in TOOLS
    tools = _list_tools()
    for name in TOOLS:
        tool = tools[name]
        assert len(tool.description) <= 2048, name
        assert "host" in tool.parameters["required"], name
        assert "camera_id" in tool.parameters["required"], name
        for param, spec in tool.parameters["properties"].items():
            assert "for example" in " ".join(spec.get("description", "").split()), (name, param)
        assert "dry-run policy" in tool.description, name
        if not name.startswith("create_"):
            assert "Consequence:" in tool.description, name


def test_register_on_a_fresh_server_uses_the_deps_function():
    mcp = FastMCP("p02")
    p02.register(mcp, lambda: (None, None))
    names = {t.name for t in asyncio.run(mcp.list_tools())}
    assert names == set(TOOLS)


# --------------------------------------------------------------------------- routes


@pytest.mark.parametrize("name", sorted(TOOLS))
async def test_each_tool_sends_its_route_and_returns_the_body_verbatim(name):
    client = _client()
    with respx.mock(assert_all_called=False) as router:
        _reads(router)
        routes = _writes(router)
        result = await _call(name, client)
    route = routes[name]
    assert route.call_count == 1
    if name.startswith("delete_"):
        assert result["deleted"] is True
        assert result["response"] == {"probe": name}
    elif name.startswith("update_"):
        assert result["status"] == "updated"
        assert result["response"] == {"probe": name}
    else:
        assert result["response"] == {"probe": name}
        assert result["status"] in {"sent", "created", "enrolling"}


async def test_free_form_bodies_are_sent_exactly_as_given():
    client = _client()
    movement = {"type": "relative", "payload": {"x": 1.5, "y": -2, "z": 0}, "host": "kept"}
    with respx.mock(assert_all_called=False) as router:
        routes = _writes(router)
        await _call("move_ptz_camera", client, movement=movement)
        await _call("create_ptz_preset", client, preset={"name": "probe", "camera": "kept"})
        await _call("create_camera_shortcut", client, shortcut={"site": "kept"})
    assert _sent(routes["move_ptz_camera"]) == movement
    assert _sent(routes["create_ptz_preset"]) == {"name": "probe", "camera": "kept"}
    assert _sent(routes["create_camera_shortcut"]) == [{"site": "kept"}]


async def test_event_control_window_sends_the_open_key():
    client = _client()
    with respx.mock(assert_all_called=False) as router:
        routes = _writes(router)
        await _call("set_ptz_event_control_window", client, open_window=False)
    assert _sent(routes["set_ptz_event_control_window"]) == {"open": False}


async def test_ptz_home_reuses_the_official_goto_helper_with_slot_minus_one(monkeypatch):
    seen: dict[str, Any] = {}

    async def fake_goto(client, registry, host, camera_id, slot, *, confirm=False):
        seen.update(host=host, camera_id=camera_id, slot=slot)
        return {"status": "sent", "response": None}

    monkeypatch.setattr(p02, "ptz_goto", fake_goto)
    result = await p02.ptz_home(_client(), _registry(), "probe-console", CAM)
    assert seen == {"host": "probe-console", "camera_id": CAM, "slot": -1}
    assert result == {"status": "sent", "response": None}


async def test_body_less_actions_send_no_body():
    client = _client()
    with respx.mock(assert_all_called=False) as router:
        _reads(router)
        routes = _writes(router)
        for name in ("calibrate_camera", "test_doorbell_ringtone", "trigger_camera_shortcut"):
            await _call(name, client)
    for name in ("calibrate_camera", "test_doorbell_ringtone", "trigger_camera_shortcut"):
        assert routes[name].calls.last.request.content == b""


@pytest.mark.parametrize(
    "kind,step,extra,url,body",
    [
        ("nfc", "enroll", {}, "nfc/enroll", None),
        ("fingerprint", "cancel", {}, "fingerprint/cancel", None),
        (
            "fingerprint",
            "assign",
            {"fingerprint_id": "3", "ulp_id": "probe-user"},
            "fingerprint/assign",
            {"fingerprintId": "3", "ulpId": "probe-user"},
        ),
        (
            "nfc",
            "assign",
            {"fields": {"probeKey": "kept"}, "ulp_id": "probe-user"},
            "nfc/assign",
            {"probeKey": "kept", "ulpId": "probe-user"},
        ),
    ],
)
async def test_enrollment_steps(kind, step, extra, url, body):
    client = _client()
    with respx.mock() as router:
        route = router.post(f"{PRIVATE}/cameras/{CAM}/{url}").respond(200, json={"ok": True})
        result = await _call(
            "enroll_doorbell_credential", client, credential_type=kind, step=step, **extra
        )
    assert _sent(route) == body
    assert result["response"] == {"ok": True}
    assert (
        result["status"]
        == {"enroll": "enrolling", "assign": "assigned", "cancel": "cancelled"}[step]
    )


async def test_delete_shortcuts_sends_every_id_as_shortcut_ids():
    client = _client()
    camera = {**CAMERA, "shortcuts": [{"id": SC1}, {"id": SC2}]}
    with respx.mock() as router:
        router.get(f"{PRIVATE}/cameras/{CAM}").respond(200, json=camera)
        route = router.delete(url__startswith=f"{PRIVATE}/cameras/{CAM}/shortcuts").respond(204)
        result = await _call("delete_camera_shortcut", client, shortcut_ids=[SC1, SC2])
    params = route.calls.last.request.url.params
    assert params.get_list("shortcutIds") == [SC1, SC2]
    assert result["deleted"] is True and result["response"] is None


async def test_empty_upstream_body_is_returned_as_none():
    client = _client()
    with respx.mock() as router:
        router.post(f"{PRIVATE}/cameras/{CAM}/calibrate").respond(204)
        result = await _call("calibrate_camera", client)
    assert result == {"status": "sent", "response": None}


# --------------------------------------------------------------------------- validation


@pytest.mark.parametrize(
    "name,args",
    [
        ("move_ptz_camera", {"camera_id": ""}),
        ("move_ptz_camera", {"camera_id": "../x"}),
        ("ptz_home", {"camera_id": "a\nb"}),
        ("set_ptz_event_control_window", {"open_window": "yes"}),
        ("update_ptz_patrol", {"fields": {}}),
        ("update_ptz_preset", {"fields": {"_note": "additive only"}}),
        ("update_camera_shortcut", {"body": {}}),
        ("trigger_camera_shortcut", {"shortcut_id": ""}),
        ("enroll_doorbell_credential", {"credential_type": "face"}),
        ("enroll_doorbell_credential", {"step": "start"}),
        ("delete_doorbell_credential", {"credential_type": "pin"}),
        ("delete_doorbell_credential", {"credential_id": ".."}),
        ("calibrate_camera", {"camera_id": ""}),
        ("enroll_doorbell_credential", {"step": "assign", "fingerprint_id": "3\n"}),
        ("enroll_doorbell_credential", {"step": "assign", "ulp_id": " probe-user"}),
        ("delete_camera_shortcut", {"shortcut_ids": [SC1, ""]}),
    ],
)
async def test_invalid_input_makes_zero_requests(name, args):
    client = _client()
    registry = _registry()
    with respx.mock(assert_all_called=False) as router:
        router.route().respond(200, json={})
        with pytest.raises((ValueError, ValidationError)) as exc:
            await _call(name, client, registry, **args)
        assert router.calls.call_count == 0
    registry.resolve_host_id.assert_not_awaited()
    if not isinstance(exc.value, ValidationError):
        assert classify(str(exc.value)) is not None, str(exc.value)


@pytest.mark.parametrize("name", sorted(TOOLS))
async def test_protect_write_opt_out_and_read_only_make_zero_requests(monkeypatch, name):
    for env, value in (
        ("UNIFI_WRITE_EXCEPTIONS", "family:protect=deny"),
        ("UNIFI_WRITE_POLICY", "deny"),
    ):
        with monkeypatch.context() as m:
            m.setenv(env, value)
            registry = _registry()
            with respx.mock(assert_all_called=False) as router:
                router.route().respond(200, json={})
                with pytest.raises(Exception) as exc:
                    await _call(name, _client(), registry)
                assert router.calls.call_count == 0
            assert env in str(exc.value) or "read-only" in str(exc.value)
            registry.resolve_host_id.assert_not_awaited()


# --------------------------------------------------------------------------- slot lookup


@pytest.mark.parametrize("name", ["update_ptz_patrol", "delete_ptz_patrol"])
async def test_unknown_patrol_slot_fails_listing_slots_without_a_write(name):
    client = _client()
    with respx.mock(assert_all_called=False) as router:
        _reads(router)
        routes = _writes(router)
        with pytest.raises(ValueError) as exc:
            await _call(name, client, slot=4)
    assert "not found" in str(exc.value) and "valid: [0]" in str(exc.value)
    assert routes[name].call_count == 0
    refusal = classify(str(exc.value))
    assert refusal is not None and refusal.id == "lookup-miss"


async def test_unknown_preset_slot_lists_every_slot():
    client = _client()
    with respx.mock(assert_all_called=False) as router:
        _reads(router)
        routes = _writes(router)
        with pytest.raises(ValueError, match=r"valid: \[1, -1\]"):
            await _call("delete_ptz_preset", client, slot=7)
    assert routes["delete_ptz_preset"].call_count == 0


async def test_bool_is_never_a_slot():
    assert p02._slot_record([{"slot": True}], 1) is None
    assert p02._slot_record([{"slot": 1}], 1) == {"slot": 1}


async def test_slot_list_without_slots_lets_the_upstream_judge():
    client = _client()
    with respx.mock() as router:
        router.get(f"{PRIVATE}/cameras/{CAM}/ptz/preset").respond(200, json=[{"id": "x"}])
        route = router.delete(f"{PRIVATE}/cameras/{CAM}/ptz/preset/3").respond(204)
        result = await _call("delete_ptz_preset", client, slot=3)
    assert route.call_count == 1 and result["deleted"] is True


async def test_slot_list_of_unexpected_shape_raises_naming_the_request():
    client = _client()
    with respx.mock() as router:
        router.get(f"{PRIVATE}/cameras/{CAM}/ptz/patrol").respond(200, json={"oops": 1})
        with pytest.raises(Exception, match="Unexpected Protect response shape"):
            await _call("delete_ptz_patrol", client)


# --------------------------------------------------------------------------- verified updates


async def test_update_preset_merges_nested_siblings_and_verifies():
    client = _client()
    after = [{**PRESETS[0], "ptz": {"pan": 50, "tilt": 2, "zoom": 0}}, PRESETS[1]]
    with respx.mock() as router:
        router.get(f"{PRIVATE}/cameras/{CAM}/ptz/preset").mock(
            side_effect=[httpx.Response(200, json=PRESETS), httpx.Response(200, json=after)]
        )
        route = router.patch(f"{PRIVATE}/cameras/{CAM}/ptz/preset/1").respond(200, json={"ok": 1})
        result = await _call("update_ptz_preset", client, fields={"ptz": {"pan": 50}})
    assert _sent(route) == {"ptz": {"pan": 50, "tilt": 2, "zoom": 0}}
    assert result["status"] == "updated" and result["verified"] is True
    assert result["before"] == PRESETS[0] and result["after"] == after[0]
    assert result["response"] == {"ok": 1}


async def test_update_patrol_is_a_noop_when_every_leaf_matches():
    client = _client()
    with respx.mock(assert_all_called=False) as router:
        _reads(router)
        routes = _writes(router)
        result = await _call(
            "update_ptz_patrol", client, fields={"name": "probe-old", "presets": [0, 1]}
        )
    assert result["status"] == "noop" and result["resource"] == PATROLS[0]
    assert routes["update_ptz_patrol"].call_count == 0


async def test_update_verification_is_type_strict():
    client = _client()
    before = [{"slot": 0, "settings": {"enabled": False}}]
    after = [{"slot": 0, "settings": {"enabled": 1}}]
    with respx.mock() as router:
        router.get(f"{PRIVATE}/cameras/{CAM}/ptz/patrol").mock(
            side_effect=[httpx.Response(200, json=before), httpx.Response(200, json=after)]
        )
        router.patch(f"{PRIVATE}/cameras/{CAM}/ptz/patrol/0").respond(200, json={})
        result = await _call("update_ptz_patrol", client, fields={"settings": {"enabled": True}})
    assert result["verified"] is False


async def test_update_read_after_miss_is_unknown_with_reason():
    client = _client()
    with respx.mock() as router:
        router.get(f"{PRIVATE}/cameras/{CAM}/ptz/patrol").mock(
            side_effect=[httpx.Response(200, json=PATROLS), httpx.Response(200, json=[])]
        )
        router.patch(f"{PRIVATE}/cameras/{CAM}/ptz/patrol/0").respond(200, json={"ok": 1})
        result = await _call("update_ptz_patrol", client)
    assert result["verified"] is None
    assert "not found in the read-after" in result["readAfterError"]
    assert result["response"] == {"ok": 1}


async def test_update_read_after_failure_keeps_the_write_response():
    client = _client()
    with respx.mock() as router:
        router.get(f"{PRIVATE}/cameras/{CAM}/ptz/preset").mock(
            side_effect=[httpx.Response(200, json=PRESETS), httpx.Response(500, json={"e": 1})]
        )
        router.patch(f"{PRIVATE}/cameras/{CAM}/ptz/preset/1").respond(200, json={"ok": 1})
        result = await _call("update_ptz_preset", client)
    assert result["verified"] is None and result["readAfterError"]
    assert result["response"] == {"ok": 1}


async def test_update_shortcut_locates_by_body_id_and_verifies():
    client = _client()
    before = {**CAMERA, "shortcuts": [{"id": SC1, "name": "probe-old", "readOnly": 7}]}
    after = {**CAMERA, "shortcuts": [{"id": SC1, "name": "probe"}]}
    with respx.mock() as router:
        router.get(f"{PRIVATE}/cameras/{CAM}").mock(
            side_effect=[httpx.Response(200, json=before), httpx.Response(200, json=after)]
        )
        route = router.patch(f"{PRIVATE}/cameras/{CAM}/shortcuts").respond(200, json={"ok": 1})
        result = await _call("update_camera_shortcut", client)
    assert _sent(route) == [{"id": SC1, "name": "probe"}]
    assert result["verified"] is True and result["before"] == before["shortcuts"][0]


async def test_update_shortcut_unknown_id_fails_listing_ids_without_a_write():
    client = _client()
    with respx.mock(assert_all_called=False) as router:
        _reads(router)
        routes = _writes(router)
        with pytest.raises(ValueError, match=rf"valid: \['{SC1}'\]"):
            await _call("update_camera_shortcut", client, body={"id": SC2, "name": "x"})
    assert routes["update_camera_shortcut"].call_count == 0


async def test_update_shortcut_without_an_id_is_sent_and_left_unverified():
    client = _client()
    with respx.mock() as router:
        router.get(f"{PRIVATE}/cameras/{CAM}").respond(200, json=CAMERA)
        route = router.patch(f"{PRIVATE}/cameras/{CAM}/shortcuts").respond(200, json={"ok": 1})
        result = await _call(
            "update_camera_shortcut", client, body={"shortcuts": [{"name": "probe"}]}
        )
    assert _sent(route) == [{"shortcuts": [{"name": "probe"}]}]
    assert result["verified"] is None
    assert "no string id" in result["readAfterError"]


@pytest.mark.parametrize("name", ["trigger_camera_shortcut", "delete_camera_shortcut"])
async def test_unknown_shortcut_fails_listing_ids_without_a_write(name):
    client = _client()
    args = {"shortcut_id": SC2} if name.startswith("trigger") else {"shortcut_ids": [SC2]}
    with respx.mock(assert_all_called=False) as router:
        _reads(router)
        routes = _writes(router)
        with pytest.raises(ValueError, match="not found on camera"):
            await _call(name, client, **args)
    assert routes[name].call_count == 0


async def test_camera_without_shortcuts_lets_the_upstream_judge():
    client = _client()
    with respx.mock() as router:
        router.get(f"{PRIVATE}/cameras/{CAM}").respond(200, json={"id": CAM})
        route = router.post(f"{PRIVATE}/cameras/{CAM}/shortcuts/{SC2}/click").respond(200)
        await _call("trigger_camera_shortcut", client, shortcut_id=SC2)
    assert route.call_count == 1


# --------------------------------------------------------------------------- dry-run


@pytest.mark.parametrize("name", sorted(TOOLS))
async def test_dry_run_sends_no_write_and_returns_the_preview(name, monkeypatch):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "dry-run")
    client = _client()
    with respx.mock(assert_all_called=False) as router:
        _reads(router)
        routes = _writes(router)
        result = await _call(name, client)
    assert routes[name].call_count == 0
    assert result["status"] == "dry_run"
    assert result.get("verified") is not True and result.get("deleted") is not True
    preview = result["response"]
    assert preview["dryRun"] is True and preview["status"] == "dry_run"
    method, url = WRITES[name]
    assert preview["preview"]["method"] == method
    assert url.endswith(preview["preview"]["path"])
    assert "body" in preview["preview"] and "params" in preview["preview"]


async def test_dry_run_preview_carries_query_and_body(monkeypatch):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "dry-run")
    client = _client()
    with respx.mock(assert_all_called=False) as router:
        _reads(router)
        deleted = await _call("delete_camera_shortcut", client)
        moved = await _call("move_ptz_camera", client)
    assert deleted["response"]["preview"]["params"] == {"shortcutIds": [SC1]}
    assert moved["response"]["preview"]["body"] == {"type": "continuous"}


# --------------------------------------------------------------------------- errors, retry


@pytest.mark.parametrize("status", [400, 404, 500])
async def test_upstream_error_body_is_reported_in_full(status):
    client = _client()
    body = {"error": "probe failure " + "x" * 600, "code": "PROBE"}
    with respx.mock() as router:
        router.post(f"{PRIVATE}/cameras/{CAM}/move").respond(status, json=body)
        with pytest.raises(Exception) as exc:
            await _call("move_ptz_camera", client)
    assert body["error"] in str(exc.value)
    assert f"/cameras/{CAM}/move" in str(exc.value)


@pytest.mark.parametrize(
    "name", ["move_ptz_camera", "calibrate_camera", "test_doorbell_ringtone", "ptz_home"]
)
async def test_physical_actions_are_never_auto_retried_on_429(name):
    client = _client()
    method, url = WRITES[name]
    with respx.mock() as router:
        route = router.route(method=method, url=url).respond(429, json={"error": "slow down"})
        with pytest.raises(Exception, match="429"):
            await _call(name, client)
    assert route.call_count == 1


# --------------------------------------------------------------------------- multi-key


async def _beta_registry(client: UniFiClient):
    from unifi_fabric.registry import Registry

    registry = Registry(client, ttl_seconds=900)
    for label, hosts in MULTIKEY_HOSTS_BY_LABEL.items():
        await registry.set_hosts(hosts, key=client.get_key_by_label(label))
    registry.resolve_host_id = AsyncMock(return_value=HOST_ID)  # type: ignore[method-assign]
    return registry


@pytest.mark.parametrize("name", sorted(TOOLS))
async def test_beta_owned_console_rides_the_beta_key(multikey_client, name):
    registry = await _beta_registry(multikey_client)
    with respx.mock(assert_all_called=False) as router:
        _reads(router)
        routes = _writes(router)
        await _call(name, multikey_client, registry, host="Beta-Branch")
    assert routes[name].calls.last.request.headers["X-API-KEY"] == "k-beta"
    for call in router.calls:
        assert call.request.headers["X-API-KEY"] == "k-beta"
    resolved = registry.resolve_host_id.await_args
    assert resolved.kwargs["key"].label == "beta"


async def test_beta_registry_is_resolved_by_console_name(multikey_client):
    registry = await _beta_registry(multikey_client)
    key = await registry.resolve_key_for_host("Beta-Branch")
    assert key is not None and key.label == "beta"


# --------------------------------------------------------------------------- secrets


def test_doorbell_credential_routes_are_registered_secrets():
    assign = f"/v1/connector/consoles/h/proxy/protect/api/cameras/{CAM}/fingerprint/assign"
    entries = route_secrets.matching("POST", assign)
    assert [e.name for e in entries] == ["protect-doorbell-credentials"]
    body = {"fingerprintId": "probe-secret-7", "ulpId": "u"}
    assert route_secrets.request_secrets("POST", assign, body) == ("probe-secret-7",)
    assert route_secrets.mask_request_body("POST", assign, body, redact_secrets=False) is body
    delete = f"protect/api/cameras/{CAM}/nfc/probe-card"
    assert route_secrets.matching("DELETE", delete)
    secrets = route_secrets.tool_call_secrets(
        "delete_doorbell_credential", {"credential_id": "probe-card-secret"}
    )
    assert secrets == ("probe-card-secret",)
    assert route_secrets.tool_call_secrets(
        "enroll_doorbell_credential", {"fingerprint_id": "probe-fp"}
    ) == ("probe-fp",)


async def test_credential_values_are_returned_verbatim_by_default():
    client = _client()
    with respx.mock() as router:
        router.post(f"{PRIVATE}/cameras/{CAM}/fingerprint/assign").respond(
            200, json={"fingerprintId": "probe-fp", "ulpId": "u"}
        )
        result = await _call(
            "enroll_doorbell_credential", client, step="assign", fingerprint_id="probe-fp"
        )
    assert result["response"] == {"fingerprintId": "probe-fp", "ulpId": "u"}


@pytest.mark.parametrize("redact", [False, True])
async def test_shortcut_webhook_credentials_obey_redaction(redact):
    client = UniFiClient(Settings(api_key="k-test", redact_secrets=redact))
    webhook = {
        "headers": {"Authorization": "synthetic-header"},
        "auth": {"password": "synthetic-auth"},
    }
    before = {**CAMERA, "shortcuts": [{"id": SC1, "shortcut": webhook, "name": "old"}]}
    after = {**CAMERA, "shortcuts": [{"id": SC1, "shortcut": webhook, "name": "new"}]}
    with respx.mock() as router:
        router.get(f"{PRIVATE}/cameras/{CAM}").mock(
            side_effect=[httpx.Response(200, json=before), httpx.Response(200, json=after)]
        )
        router.patch(f"{PRIVATE}/cameras/{CAM}/shortcuts").respond(200, json={"ok": 1})
        result = await _call("update_camera_shortcut", client, body={"id": SC1, "name": "new"})
    output = json.dumps(result)
    assert ("synthetic-header" in output) is not redact
    assert ("synthetic-auth" in output) is not redact
