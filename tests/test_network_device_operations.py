"""Network device operations (GS3 lane N03).

Every tool is exercised against the real ``UniFiClient`` with only the HTTP transport
mocked: routes, bodies and query parameters sent, verbatim pass-through, device
resolution (MAC, Classic ``_id``, name; unknown and ambiguous values fail listing every
device with no write), the affirmative Classic ``meta.rc`` rule, dry-run previews,
read-only mode (zero requests), zero-request input validation, single-send physical
actions (no retry on 429), multi-key routing, the registration contract (annotations
derived from source, described properties, Consequence lines) and the secret-registry
entry for the Classic bulk PUT.
"""

from __future__ import annotations

import asyncio
import inspect
import json
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
from fastmcp import FastMCP

from tests.conftest import MULTIKEY_HOSTS_BY_LABEL
from unifi_fabric import refusals, route_secrets, server
from unifi_fabric._read_only_audit import classify_tool_verbs
from unifi_fabric.client import ClassicApiError, RateLimitError, UniFiClient, _key_fingerprint
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.redaction import REDACTION_MASK
from unifi_fabric.tools import network_device_operations as ndo

HOST = "console-n03"
SITE = "Default"
SLUG = "default"
NET = f"/v1/connector/consoles/{HOST}/proxy/network"
CLASSIC_S = f"{NET}/api/s/{SLUG}"
DEVMGR = f"{CLASSIC_S}/cmd/devmgr"
STAT_DEVICE = f"{CLASSIC_S}/stat/device"
V2S = f"{NET}/v2/api/site/{SLUG}"

SWITCH_MAC = "02:00:5e:00:53:01"
SWITCH_ID = "0000000000000000000000a1"
AP_MAC = "02:00:5e:00:53:02"
AP_ID = "0000000000000000000000a2"
PDU_MAC = "02:00:5e:00:53:03"
PDU_ID = "0000000000000000000000a3"
TWIN_MAC = "02:00:5e:00:53:04"
OK = {"meta": {"rc": "ok"}, "data": [{"kept": True}]}
RC_ERROR = {"meta": {"rc": "error", "msg": "api.err.ProbeN03"}, "data": [{"detail": "x"}]}

DEVICES = {
    "meta": {"rc": "ok"},
    "data": [
        {"_id": SWITCH_ID, "mac": SWITCH_MAC, "name": "lab-switch", "model": "USW", "type": "usw"},
        {"_id": AP_ID, "mac": AP_MAC, "name": "lab-ap", "model": "U7", "type": "uap"},
        {"_id": PDU_ID, "mac": PDU_MAC, "name": "twin", "model": "USPPDU", "type": "usw"},
        {"_id": "0000000000000000000000a4", "mac": TWIN_MAC, "name": "twin", "type": "uap"},
    ],
}

WRITE_TOOLS = {
    "manage_device_ssh_session",
    "clear_switch_counters",
    "clone_device_config",
    "set_outlet_power",
    "recover_switch_port",
    "run_device_self_test",
    "set_device_alignment_mode",
    "set_priority_uplink",
    "set_device_rearrange_mode",
    "disconnect_remote_vpn_user",
    "locate_switch_port",
    "unpair_building_bridge",
    "reset_switch_port",
    "get_rolling_upgrade_plan",
    "replace_device",
    "control_device_battery",
    "update_device_battery_settings",
    "set_device_tag_assignments",
    "bulk_update_objects",
}
READ_TOOLS = {"get_device_adoption_info", "get_device_replacement_options"}
LIVE_ACCEPTANCE_PENDING = {
    "replace_device",
    "unpair_building_bridge",
    "clone_device_config",
    "reset_switch_port",
    "recover_switch_port",
    "set_outlet_power",
    "control_device_battery",
    "run_device_self_test",
}


def registry(key: APIKeyConfig | None = None) -> AsyncMock:
    return AsyncMock(
        **{
            "resolve_key_for_host.return_value": key or APIKeyConfig(key="test-key", label="beta"),
            "resolve_host_id.return_value": HOST,
            "resolve_site_slug.return_value": SLUG,
        }
    )


def client(handler, **settings: Any) -> UniFiClient:
    c = UniFiClient(Settings(api_key="test-key", **settings))
    c._clients[("beta", _key_fingerprint("test-key"))] = httpx.AsyncClient(
        base_url="https://api.ui.com", transport=httpx.MockTransport(handler)
    )
    return c


class Upstream:
    """Route table: (method, path) -> response; the device list is served by default."""

    def __init__(self, routes: dict[tuple[str, str], Any] | None = None, devices: Any = None):
        self.routes = {("GET", STAT_DEVICE): DEVICES if devices is None else devices}
        self.routes.update(routes or {})
        self.seen: list[httpx.Request] = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.seen.append(req)
        entry = self.routes.get((req.method, req.url.path))
        if entry is None:
            return httpx.Response(404, json={"errorCode": 404, "message": "no route in test"})
        if callable(entry):
            entry = entry(req)
        if isinstance(entry, httpx.Response):
            return entry
        return httpx.Response(200, json=entry)

    def writes(self) -> list[httpx.Request]:
        return [r for r in self.seen if r.method != "GET"]


def body_of(req: httpx.Request) -> Any:
    return json.loads(req.content) if req.content else None


async def run(handler, fn, *args, settings: dict[str, Any] | None = None, **kwargs):
    c = client(handler, **(settings or {}))
    try:
        return await fn(c, registry(), HOST, SITE, *args, **kwargs)
    finally:
        await c.close()


# ------------------------------------------------------------------ Classic commands

#: tool -> (args, kwargs, manager path, expected body)
CLASSIC_CASES: dict[str, tuple[tuple[Any, ...], dict[str, Any], str, dict[str, Any]]] = {
    "clear_switch_counters": (
        (SWITCH_MAC,),
        {},
        DEVMGR,
        {"cmd": "clear-switch-counters", "mac": SWITCH_MAC},
    ),
    "clear_switch_counters[port]": (
        ("lab-switch",),
        {"port_idx": 5, "unit_id": 1},
        DEVMGR,
        {"cmd": "clear-switch-port-counters", "mac": SWITCH_MAC, "port_idx": 5, "unit_id": 1},
    ),
    "clone_device_config": (
        (AP_ID, "lab-switch"),
        {"clone_dry_run": True},
        DEVMGR,
        {"cmd": "clone-config", "mac": AP_MAC, "origin": SWITCH_MAC, "dry_run": True},
    ),
    "set_outlet_power": (
        (PDU_MAC, 2),
        {"outlet_fields": {"relay_state": False}, "delay_time_to_off": 0},
        DEVMGR,
        {
            "cmd": "outlet-ctl",
            "mac": PDU_MAC,
            "outlet_table": [{"index": 2, "relay_state": False}],
            "delay_time_to_off": 0,
        },
    ),
    "recover_switch_port": (
        (SWITCH_MAC, 7),
        {"unit_id": 2},
        DEVMGR,
        {"cmd": "port-recovery", "mac": SWITCH_MAC, "port_idx": 7, "unit_id": 2},
    ),
    "recover_switch_port[rps]": (
        (SWITCH_MAC, 3),
        {"rps": True},
        DEVMGR,
        {"cmd": "rps-port-recovery", "mac": SWITCH_MAC, "port_idx": 3},
    ),
    "run_device_self_test": ((PDU_MAC,), {}, DEVMGR, {"cmd": "self-test", "mac": PDU_MAC}),
    "set_device_alignment_mode": (
        (AP_MAC, True),
        {},
        DEVMGR,
        {"cmd": "set-alignment", "mac": AP_MAC},
    ),
    "set_device_alignment_mode[off]": (
        (AP_MAC, False),
        {},
        DEVMGR,
        {"cmd": "unset-alignment", "mac": AP_MAC},
    ),
    "set_priority_uplink": (
        (AP_MAC, True),
        {"prefer1": "02:00:5e:00:53:0a", "prefer2": "02:00:5e:00:53:0b"},
        DEVMGR,
        {
            "cmd": "set-priority-uplink",
            "mac": AP_MAC,
            "prefer1": "02:00:5e:00:53:0a",
            "prefer2": "02:00:5e:00:53:0b",
        },
    ),
    "set_priority_uplink[off]": (
        (AP_MAC, False),
        {},
        DEVMGR,
        {"cmd": "unset-priority-uplink", "mac": AP_MAC},
    ),
    "set_device_rearrange_mode": (
        (SWITCH_MAC, True),
        {},
        DEVMGR,
        {"cmd": "set-rearrange", "mac": SWITCH_MAC},
    ),
    "set_device_rearrange_mode[off]": (
        (SWITCH_MAC, False),
        {},
        DEVMGR,
        {"cmd": "unset-rearrange", "mac": SWITCH_MAC},
    ),
    "locate_switch_port": (
        ("02-00-5E-00-53-01", 4, True),
        {"unit_id": 1},
        f"{DEVMGR}/port-locate",
        {"cmd": "set-port-locate", "mac": SWITCH_MAC, "port_idx_list": [4], "unit_id": 1},
    ),
    "locate_switch_port[off]": (
        (SWITCH_MAC, 4, False),
        {},
        f"{DEVMGR}/port-locate",
        {"cmd": "unset-port-locate", "mac": SWITCH_MAC, "port_idx_list": [4]},
    ),
    "unpair_building_bridge": (
        (AP_MAC,),
        {},
        f"{DEVMGR}/ubb-unpair",
        {"cmd": "ubb-unpair", "mac": AP_MAC},
    ),
}


@pytest.mark.parametrize("case", sorted(CLASSIC_CASES))
async def test_classic_command_resolves_device_and_sends_body(case):
    args, kwargs, path, body = CLASSIC_CASES[case]
    up = Upstream({("POST", path): OK})
    fn = getattr(ndo, case.split("[")[0])
    assert await run(up, fn, *args, **kwargs) == OK
    assert [(r.method, r.url.path) for r in up.seen] == [("GET", STAT_DEVICE), ("POST", path)]
    assert body_of(up.seen[1]) == body  # one device-list read, then the command


@pytest.mark.parametrize("case", sorted(CLASSIC_CASES))
async def test_classic_rc_error_raises_with_full_body(case):
    args, kwargs, path, _ = CLASSIC_CASES[case]
    up = Upstream({("POST", path): RC_ERROR})
    fn = getattr(ndo, case.split("[")[0])
    with pytest.raises(ClassicApiError) as err:
        await run(up, fn, *args, **kwargs)
    assert "api.err.ProbeN03" in str(err.value) and '"detail":"x"' in str(err.value)


@pytest.mark.parametrize("case", sorted(CLASSIC_CASES))
async def test_classic_dry_run_returns_preview_and_sends_no_write(case):
    args, kwargs, path, body = CLASSIC_CASES[case]
    up = Upstream({("POST", path): OK})
    fn = getattr(ndo, case.split("[")[0])
    result = await run(up, fn, *args, settings={"dry_run": True}, **kwargs)
    assert result["status"] == "dry_run" and result["dryRun"] is True
    assert result["preview"]["body"] == body and result["preview"]["method"] == "POST"
    assert up.writes() == []


async def test_ssh_session_actions_map_to_commands_with_free_form_body():
    assert ndo.SSH_COMMANDS == {
        "build": "build-ssh-session",
        "sdp_answer": "ssh-sdp-answer",
        "close": "close-ssh-session",
    }
    for action, cmd in ndo.SSH_COMMANDS.items():
        up = Upstream({("POST", DEVMGR): OK})
        params = {"mac": SWITCH_MAC, "sdp": "v=0"}
        assert await run(up, ndo.manage_device_ssh_session, action, params) == OK
        assert [r.method for r in up.seen] == ["POST"]  # no device lookup: body is free-form
        assert body_of(up.seen[0]) == {"cmd": cmd, **params}


async def test_ssh_session_other_action_is_sent_as_the_command():
    up = Upstream({("POST", DEVMGR): OK})
    await run(up, ndo.manage_device_ssh_session, "build-ssh-session")
    assert body_of(up.seen[0]) == {"cmd": "build-ssh-session"}


async def test_disconnect_remote_vpn_user_sends_params_as_given():
    up = Upstream({("POST", DEVMGR): OK})
    params = {"user_id": "0000000000000000000000b1"}
    assert await run(up, ndo.disconnect_remote_vpn_user, params) == OK
    assert body_of(up.seen[0]) == {"cmd": "terminate-remote-user-vpn", **params}


# --------------------------------------------------------------- device resolution


async def test_unknown_device_fails_listing_every_device_without_a_write():
    up = Upstream({("POST", DEVMGR): OK})
    with pytest.raises(ValueError, match="not found by MAC, _id or name") as err:
        await run(up, ndo.run_device_self_test, "02:00:5e:00:53:99")
    for mac in (SWITCH_MAC, AP_MAC, PDU_MAC, TWIN_MAC):
        assert mac in str(err.value)
    assert up.writes() == []
    assert refusals.classify(str(err.value)).id == "lookup-miss"


async def test_ambiguous_device_name_fails_asking_for_the_mac():
    up = Upstream({("POST", DEVMGR): OK})
    with pytest.raises(ValueError, match="is ambiguous: matches 2 devices; pass the MAC"):
        await run(up, ndo.run_device_self_test, "twin")
    assert up.writes() == []


async def test_device_list_rc_error_raises_before_any_write():
    up = Upstream({("POST", DEVMGR): OK}, devices=RC_ERROR)
    with pytest.raises(ClassicApiError, match="from GET .*stat/device.*api.err.ProbeN03"):
        await run(up, ndo.run_device_self_test, SWITCH_MAC)
    assert up.writes() == []


async def test_device_list_of_wrong_shape_raises_naming_the_request():
    up = Upstream({("POST", DEVMGR): OK}, devices={"meta": {"rc": "ok"}, "data": {}})
    with pytest.raises(Exception, match="Unexpected response shape from GET .*stat/device"):
        await run(up, ndo.run_device_self_test, SWITCH_MAC)
    assert up.writes() == []


async def test_device_without_mac_or_id_raises_shape_errors():
    devices = {"meta": {"rc": "ok"}, "data": [{"name": "nomac", "_id": SWITCH_ID}]}
    up = Upstream({("POST", DEVMGR): OK}, devices=devices)
    with pytest.raises(Exception, match="has no valid 'mac'"):
        await run(up, ndo.run_device_self_test, "nomac")
    devices = {"meta": {"rc": "ok"}, "data": [{"name": "noid", "mac": SWITCH_MAC}]}
    up = Upstream({}, devices=devices)
    with pytest.raises(Exception, match="has no '_id'"):
        await run(up, ndo.get_device_replacement_options, SWITCH_MAC)


# --------------------------------------------------------------------- v2 routes


async def test_reset_switch_port_posts_the_port_list_to_the_switch_mac():
    # Network 11.0.89 ports.js "Clear last seen": POST ports/${mac}/reset [{port_idx, unit_id}].
    up = Upstream({("POST", f"{V2S}/ports/{SWITCH_MAC}/reset"): {"unknownFuture": [1]}})
    ports = [{"port_idx": 5}, {"port_idx": 6, "unit_id": 2}]
    assert await run(up, ndo.reset_switch_port, SWITCH_MAC, ports) == {"unknownFuture": [1]}
    assert [r.method for r in up.seen] == ["GET", "POST"]
    assert body_of(up.writes()[0]) == ports


async def test_reset_switch_port_resolves_a_device_name_to_its_mac():
    up = Upstream({("POST", f"{V2S}/ports/{SWITCH_MAC}/reset"): {}})
    await run(up, ndo.reset_switch_port, "lab-switch", [{"port_idx": 1}])
    assert up.writes()[0].url.path == f"{V2S}/ports/{SWITCH_MAC}/reset"


async def test_adoption_info_reads_verbatim_without_device_lookup():
    up = Upstream({("GET", f"{V2S}/adopt-info/{SWITCH_MAC}"): {"state": "pending"}})
    assert await run(up, ndo.get_device_adoption_info, SWITCH_MAC) == {"state": "pending"}
    assert len(up.seen) == 1


async def test_rolling_upgrade_plan_eligible_and_estimate():
    route = f"{V2S}/device/upgrade/rollupgrade"
    up = Upstream(
        {
            ("GET", f"{route}/eligible-devices"): [{"mac": SWITCH_MAC}],
            ("POST", f"{route}/time-estimate"): {"seconds": 600},
        }
    )
    assert await run(up, ndo.get_rolling_upgrade_plan) == [{"mac": SWITCH_MAC}]
    body = {"macs": [SWITCH_MAC]}
    assert await run(up, ndo.get_rolling_upgrade_plan, time_estimate=True, estimate_body=body) == {
        "seconds": 600
    }
    assert body_of(up.seen[-1]) == body


async def test_replacement_options_use_the_resolved_classic_id():
    url = f"{V2S}/device/{SWITCH_ID}/replacement-candidates"
    up = Upstream({("GET", url): [{"mac": TWIN_MAC}]})
    assert await run(up, ndo.get_device_replacement_options, "lab-switch") == [{"mac": TWIN_MAC}]


async def test_replace_device_posts_query_and_cancel_deletes():
    url = f"{V2S}/device/{SWITCH_ID}/replace"
    up = Upstream({("POST", url): {"ok": 1}, ("DELETE", url): {"ok": 2}})
    assert await run(up, ndo.replace_device, SWITCH_MAC, replacement_mac=TWIN_MAC) == {"ok": 1}
    assert dict(up.seen[-1].url.params) == {"replacementDeviceMac": TWIN_MAC}
    assert up.seen[-1].content == b""
    assert await run(up, ndo.replace_device, SWITCH_MAC, cancel=True) == {"ok": 2}
    assert up.seen[-1].method == "DELETE" and not up.seen[-1].url.query


async def test_replace_device_dry_run_previews_query():
    up = Upstream()
    result = await run(
        up, ndo.replace_device, SWITCH_MAC, replacement_mac=TWIN_MAC, settings={"dry_run": True}
    )
    assert result["status"] == "dry_run"
    assert result["preview"]["params"] == {"replacementDeviceMac": TWIN_MAC}
    assert up.writes() == []


async def test_battery_action_and_update_bodies():
    action = f"{V2S}/device/{PDU_MAC}/battery/action"
    update = f"{V2S}/device/{PDU_MAC}/battery/update"
    up = Upstream({("POST", action): {"a": 1}, ("POST", update): {"u": 1}})
    battery = ["02:00:5e:00:53:21"]
    assert await run(up, ndo.control_device_battery, PDU_MAC, battery, "reboot") == {"a": 1}
    assert body_of(up.seen[-1]) == {"macs": battery, "action": "reboot"}
    assert await run(up, ndo.update_device_battery_settings, PDU_ID, battery) == {"u": 1}
    assert body_of(up.seen[-1]) == {"macs": battery, "action": "upgrade", "url": ""}
    url = "https://fw.example.com/battery.bin"
    await run(up, ndo.update_device_battery_settings, PDU_MAC, battery, url)
    assert body_of(up.seen[-1])["url"] == url


async def test_tag_assignment_posts_body_verbatim():
    url = f"{V2S}/device-tags/device-tag-assignment/t1"
    up = Upstream({("POST", url): {"assigned": True}})
    assert await run(up, ndo.set_device_tag_assignments, "t1", {"tag_ids": ["x"]}) == {
        "assigned": True
    }
    assert body_of(up.seen[0]) == {"tag_ids": ["x"]}


async def test_tag_assignment_posts_ui_shaped_device_mac_and_tag_deltas():
    url = f"{V2S}/device-tags/device-tag-assignment/{SWITCH_MAC}"
    body = {"device_tag_additions": ["0000000000000000000000b1"], "device_tag_removals": []}
    up = Upstream({("POST", url): {"assigned": True}})
    assert await run(up, ndo.set_device_tag_assignments, SWITCH_MAC, body) == {"assigned": True}
    assert body_of(up.seen[0]) == body


def test_tag_assignment_catalog_documents_device_mac_and_tag_deltas():
    tool = _registered()["set_device_tag_assignments"]
    props = tool.parameters["properties"]
    assert "managed device MAC" in props["assignment_id"]["description"]
    assert "device_tag_additions" in props["body"]["description"]
    assert "device_tag_removals" in props["body"]["description"]
    assert props["body"]["type"] == "object"
    assert "member_device_macs" in tool.description


@pytest.mark.parametrize(
    "object_type,payload",
    [
        ("device", [{"_id": SWITCH_ID, "led_override": "off"}]),
        ("user", {"data": {"usergroup_id": "0000000000000000000000d1"}, "id": ["e1"]}),
        ("setting", {"objects": [{"key": "mgmt", "x_ssh_password": "probe-secret"}]}),
    ],
)
async def test_bulk_update_puts_payload_verbatim_with_rc_check(object_type, payload):
    url = f"{CLASSIC_S}/group/{object_type}"
    up = Upstream({("PUT", url): OK})
    assert await run(up, ndo.bulk_update_objects, object_type, payload) == OK
    assert body_of(up.seen[0]) == payload
    bad = Upstream({("PUT", url): RC_ERROR})
    with pytest.raises(ClassicApiError, match="from PUT .*group.*ProbeN03"):
        await run(bad, ndo.bulk_update_objects, object_type, payload)


async def test_bulk_update_dry_run_preview():
    up = Upstream()
    result = await run(
        up, ndo.bulk_update_objects, "user", {"data": {"a": 1}}, settings={"dry_run": True}
    )
    assert result["status"] == "dry_run" and result["preview"]["method"] == "PUT"
    assert up.seen == []


# ------------------------------------------------------- validation: zero requests

INVALID_CALLS: list[tuple[str, tuple[Any, ...], dict[str, Any], str]] = [
    ("run_device_self_test", ("",), {}, "'device' must not be empty"),
    ("run_device_self_test", (" x",), {}, "surrounding whitespace"),
    ("clone_device_config", (SWITCH_MAC, ""), {}, "'source_device' must not be empty"),
    ("clear_switch_counters", (SWITCH_MAC,), {"unit_id": 1}, "needs port_idx"),
    ("clear_switch_counters", (SWITCH_MAC,), {"port_idx": True}, "must be an integer"),
    ("set_outlet_power", (PDU_MAC, 1), {"outlet_fields": {"index": 2}}, "must not contain"),
    ("set_outlet_power", (PDU_MAC, 1), {"outlet_fields": []}, "must be an object"),
    ("recover_switch_port", (SWITCH_MAC, 1), {"rps": 1}, "must be a boolean"),
    ("set_priority_uplink", (AP_MAC, False), {"prefer1": "x"}, "only when enabled is true"),
    ("set_priority_uplink", (AP_MAC, True), {"prefer2": ""}, "'prefer2' must not be empty"),
    ("set_device_alignment_mode", (AP_MAC, "yes"), {}, "must be a boolean"),
    ("manage_device_ssh_session", ("",), {}, "'action' must not be empty"),
    ("manage_device_ssh_session", ("Build",), {}, "Invalid Classic command name"),
    ("manage_device_ssh_session", ("build", {"cmd": "x"}), {}, "must not contain 'cmd'"),
    ("disconnect_remote_vpn_user", ({"v": float("nan")},), {}, "not JSON"),
    ("disconnect_remote_vpn_user", ([],), {}, "must be an object"),
    ("locate_switch_port", (SWITCH_MAC, "4", True), {}, "must be an integer"),
    ("reset_switch_port", ("", [{"port_idx": 1}]), {}, "'device' must not be empty"),
    ("reset_switch_port", (SWITCH_MAC, []), {}, "ports must be a non-empty list"),
    ("reset_switch_port", (SWITCH_MAC, {"port_idx": 1}), {}, "'ports' must be a JSON array"),
    ("reset_switch_port", (SWITCH_MAC, [{"port_idx": "1"}]), {}, "integer port_idx"),
    ("reset_switch_port", (SWITCH_MAC, [{"port_idx": True}]), {}, "integer port_idx"),
    (
        "reset_switch_port",
        (SWITCH_MAC, [{"port_idx": 1, "unit_id": "2"}]),
        {},
        "must be an integer",
    ),
    ("get_device_adoption_info", ("a/b\n",), {}, "surrounding whitespace|control character"),
    ("get_rolling_upgrade_plan", (), {"estimate_body": {"a": 1}}, "only with time_estimate"),
    ("replace_device", (SWITCH_MAC,), {"replacement_mac": " "}, "must not be empty"),
    ("replace_device", (SWITCH_MAC,), {"cancel": "no"}, "must be a boolean"),
    ("control_device_battery", (PDU_MAC, [""]), {}, "'battery_ids\\[0\\]' must not be empty"),
    ("control_device_battery", (PDU_MAC, "b1"), {}, "must be an array"),
    ("control_device_battery", (PDU_MAC, ["b1"], ""), {}, "'action' must not be empty"),
    ("update_device_battery_settings", (PDU_MAC, ["b1"], None), {}, "must be a string"),
    ("set_device_tag_assignments", ("t1", {}), {}, "^No fields provided"),
    ("set_device_tag_assignments", ("", {"a": 1}), {}, "'assignment_id' must not be empty"),
    ("bulk_update_objects", ("user", {}), {}, "^No fields provided"),
    ("bulk_update_objects", ("device", ["x"]), {}, "'payload\\[0\\]' must be an object"),
    ("bulk_update_objects", ("", {"a": 1}), {}, "'object_type' must not be empty"),
]


@pytest.mark.parametrize("name,args,kwargs,message", INVALID_CALLS)
async def test_invalid_input_makes_zero_requests_and_is_registered(name, args, kwargs, message):
    up = Upstream()
    reg = registry()
    c = client(up)
    try:
        with pytest.raises(ValueError, match=message) as err:
            await getattr(ndo, name)(c, reg, HOST, SITE, *args, **kwargs)
    finally:
        await c.close()
    assert up.seen == []
    reg.resolve_key_for_host.assert_not_called()
    refusal = refusals.classify(str(err.value))
    assert refusal is not None and refusal.category != refusals.UPSTREAM_JUDGED, err.value


async def test_blank_host_or_site_makes_no_request():
    up = Upstream()
    reg = registry()
    c = client(up)
    try:
        with pytest.raises(ValueError, match="'host' must not be empty"):
            await ndo.run_device_self_test(c, reg, "", SITE, SWITCH_MAC)
        with pytest.raises(ValueError, match="'site' must not be empty"):
            await ndo.unpair_building_bridge(c, reg, HOST, "", SWITCH_MAC)
    finally:
        await c.close()
    assert up.seen == []
    reg.resolve_key_for_host.assert_not_called()


@pytest.mark.parametrize(
    "fn,args",
    [
        (ndo.run_device_self_test, (SWITCH_MAC,)),
        (ndo.manage_device_ssh_session, ("close",)),
        (ndo.reset_switch_port, (SWITCH_MAC, [{"port_idx": 1}])),
        (ndo.replace_device, (SWITCH_MAC,)),
        (ndo.bulk_update_objects, ("user", {"data": {"a": 1}})),
        (ndo.set_device_tag_assignments, ("t1", {"a": 1})),
        (ndo.control_device_battery, (PDU_MAC, ["b1"])),
    ],
)
async def test_read_only_mode_refuses_writes_with_zero_requests(monkeypatch, fn, args):
    monkeypatch.setenv("UNIFI_READ_ONLY", "true")
    up = Upstream()
    with pytest.raises(Exception, match="UNIFI_READ_ONLY|read-only"):
        await run(up, fn, *args)
    assert up.seen == []


async def test_physical_action_is_sent_once_on_429():
    up = Upstream({("POST", DEVMGR): httpx.Response(429, json={"message": "slow down"})})
    with pytest.raises(RateLimitError):
        await run(up, ndo.set_outlet_power, PDU_MAC, 1)
    assert len(up.writes()) == 1


async def test_upstream_error_reason_is_complete():
    long_reason = "r" * 5000
    up = Upstream(
        {("POST", f"{V2S}/ports/{SWITCH_MAC}/reset"): httpx.Response(400, text=long_reason)}
    )
    with pytest.raises(Exception) as err:
        await run(up, ndo.reset_switch_port, SWITCH_MAC, [{"port_idx": 1}])
    assert long_reason in str(err.value)


# --------------------------------------------------------------------- multi-key


def _multikey_transport(multikey_client: UniFiClient, seen: list[tuple[str, str, str]]) -> None:
    for config in multikey_client._settings.get_key_configs():

        def handler(req: httpx.Request, label: str = config.label) -> httpx.Response:
            seen.append((label, req.method, req.url.path))
            if req.url.path.endswith("/stat/device"):
                return httpx.Response(200, json=DEVICES)
            if "/cmd/" in req.url.path or "/group/" in req.url.path:
                return httpx.Response(200, json=OK)
            return httpx.Response(200, json={"label": label})

        multikey_client._clients[(config.label, _key_fingerprint(config.key))] = httpx.AsyncClient(
            base_url="https://api.ui.com", transport=httpx.MockTransport(handler)
        )


MULTIKEY_CALLS: dict[str, tuple[Any, tuple[Any, ...]]] = {
    "run_device_self_test": (ndo.run_device_self_test, (SWITCH_MAC,)),
    "recover_switch_port": (ndo.recover_switch_port, (SWITCH_MAC, 24)),
    "manage_device_ssh_session": (ndo.manage_device_ssh_session, ("build",)),
    "replace_device": (ndo.replace_device, (SWITCH_MAC, TWIN_MAC)),
    "get_device_adoption_info": (ndo.get_device_adoption_info, (SWITCH_MAC,)),
    "control_device_battery": (ndo.control_device_battery, (PDU_MAC, ["b1"])),
    "bulk_update_objects": (ndo.bulk_update_objects, ("user", {"data": {"a": 1}})),
    "reset_switch_port": (ndo.reset_switch_port, (SWITCH_MAC, [{"port_idx": 1}])),
}


@pytest.mark.parametrize("name", sorted(MULTIKEY_CALLS))
async def test_multikey_beta_owned_host_rides_the_beta_key(
    name, multikey_client, multikey_registry
):
    for label, hosts in MULTIKEY_HOSTS_BY_LABEL.items():
        await multikey_registry.set_hosts(hosts, key=multikey_client.get_key_by_label(label))
    multikey_registry.resolve_site_slug = AsyncMock(return_value=SLUG)
    seen: list[tuple[str, str, str]] = []
    _multikey_transport(multikey_client, seen)
    fn, args = MULTIKEY_CALLS[name]
    try:
        await fn(multikey_client, multikey_registry, "Beta-Branch", SITE, *args)
    finally:
        await multikey_client.close()
    assert seen and {label for label, _, _ in seen} == {"beta"}, seen
    assert all("/consoles/console-beta-1/" in path for _, _, path in seen)


# ------------------------------------------------------------ registration contract


def _registered() -> dict[str, Any]:
    mcp = FastMCP("n03-test")
    ndo.register(mcp, lambda: (None, None))
    res = mcp.list_tools()
    tools = asyncio.run(res) if inspect.isawaitable(res) else res
    return {t.name: t for t in tools}


def test_register_adds_exactly_the_twenty_one_tools():
    assert set(_registered()) == WRITE_TOOLS | READ_TOOLS
    assert len(WRITE_TOOLS | READ_TOOLS) == 21
    assert set(ndo.ROUTE_CHOICES) == WRITE_TOOLS | READ_TOOLS
    assert LIVE_ACCEPTANCE_PENDING <= WRITE_TOOLS


def test_every_tool_appears_in_the_real_server_catalog():
    names = {tool.name for tool in asyncio.run(server.mcp.list_tools())}
    assert WRITE_TOOLS | READ_TOOLS <= names


def test_annotations_match_the_source_derived_write_set():
    tools = _registered()
    verbs = classify_tool_verbs(list(tools.values()))
    assert {name for name, v in verbs.items() if v} == WRITE_TOOLS
    for name, tool in tools.items():
        hints = tool.annotations.model_dump(by_alias=True)
        assert hints["readOnlyHint"] is (name not in WRITE_TOOLS), name
        assert hints["destructiveHint"] is (name in WRITE_TOOLS), name


def test_descriptions_fit_describe_every_property_and_state_consequences():
    tools = _registered()
    assert set(tools) == READ_TOOLS | WRITE_TOOLS
    for name, tool in tools.items():
        description = tool.description or ""
        assert description and len(description) <= 2048, name
        props = (tool.parameters or {}).get("properties", {})
        for prop, spec in props.items():
            assert spec.get("description"), (name, prop)
            assert spec != {}, (name, prop)
        assert {"host", "site"} <= set(tool.parameters.get("required", [])), name
        if name in WRITE_TOOLS:
            assert "Consequence:" in " ".join(description.split()), name
            assert "dry-run preview" in " ".join(description.split()), name
            assert "confirm" in props and "simulat" not in description, name


async def test_confirm_is_accepted_and_ignored():
    up = Upstream({("POST", DEVMGR): OK})
    c = client(up)
    mcp = FastMCP("n03-confirm")
    ndo.register(mcp, lambda: (c, registry()))
    try:
        for confirm in (True, False):
            await mcp.call_tool(
                "run_device_self_test",
                {"host": HOST, "site": SITE, "device": SWITCH_MAC, "confirm": confirm},
            )
    finally:
        await c.close()
    assert len(up.writes()) == 2


# ------------------------------------------------------------------ secret registry


def test_bulk_group_put_is_in_the_secret_registry():
    path = f"{CLASSIC_S}/group/setting"
    entries = route_secrets.matching("PUT", path)
    assert [e.name for e in entries] == ["classic-group-bulk-credentials"]
    body = {"objects": [{"key": "mgmt", "x_ssh_password": "probe-secret-n03"}]}
    assert "probe-secret-n03" in route_secrets.request_secrets("PUT", path, body)
    assert route_secrets.mask_request_body("PUT", path, body, redact_secrets=False) == body
    masked = route_secrets.mask_request_body("PUT", path, body, redact_secrets=True)
    assert masked["objects"][0]["x_ssh_password"] == REDACTION_MASK


async def test_bulk_secret_is_verbatim_by_default_in_the_dry_run_preview():
    body = {"objects": [{"key": "mgmt", "x_ssh_password": "probe-secret-n03"}]}
    result = await run(
        Upstream(), ndo.bulk_update_objects, "setting", body, settings={"dry_run": True}
    )
    assert result["preview"]["body"] == body
    masked = await run(
        Upstream(),
        ndo.bulk_update_objects,
        "setting",
        body,
        settings={"dry_run": True, "redact_secrets": True},
    )
    assert masked["preview"]["body"]["objects"][0]["x_ssh_password"] == REDACTION_MASK


async def test_classic_body_without_meta_envelope_is_not_success():
    up = Upstream({("POST", DEVMGR): OK}, devices={"data": DEVICES["data"]})
    with pytest.raises(ClassicApiError, match="Classic error from GET .*without the Classic meta"):
        await run(up, ndo.run_device_self_test, SWITCH_MAC)
    assert up.writes() == []
    bulk = Upstream({("PUT", f"{CLASSIC_S}/group/user"): {"data": []}})
    with pytest.raises(ClassicApiError, match="Classic error from PUT .*without the Classic meta"):
        await run(bulk, ndo.bulk_update_objects, "user", {"data": {"a": 1}})


@pytest.mark.parametrize("url", ["ftp://example.com/fw", "https:///fw", "relative.bin"])
async def test_battery_upgrade_rejects_invalid_url_before_requests(url):
    up = Upstream()
    with pytest.raises(ValueError, match="http"):
        await run(up, ndo.update_device_battery_settings, PDU_MAC, ["b1"], url)
    assert up.seen == []


@pytest.mark.parametrize(
    "kwargs",
    [
        {"port_id": SWITCH_MAC},
        {"port_id": SWITCH_MAC, "ports": [{"port_idx": 1}]},
        {"device": SWITCH_MAC, "body": {"port_idx": 1}, "ports": [{"port_idx": 2}]},
        {
            "device": "ignored-device",
            "port_id": SWITCH_MAC,
            "body": {"port_idx": 3, "future": "kept"},
            "ports": [{"port_idx": 2}],
        },
    ],
)
async def test_legacy_reset_preserves_precedence_and_optional_body(kwargs):
    response = {"unknownFuture": [1]}
    route = f"{V2S}/ports/{SWITCH_MAC}/reset"
    up = Upstream({("POST", route): response})
    c = client(up)
    mcp = FastMCP("legacy-reset")
    ndo.register(mcp, lambda: (c, registry()))
    tool = await mcp.get_tool("reset_switch_port")
    try:
        assert await tool.fn(HOST, SITE, **kwargs) == response
    finally:
        await c.close()
    assert len(up.seen) == 1
    assert up.seen[0].method == "POST" and up.seen[0].url.path == route
    assert body_of(up.seen[0]) == kwargs.get("body")


@pytest.mark.parametrize("selector", [{"port_id": SWITCH_MAC}, {"device": SWITCH_MAC}])
async def test_legacy_reset_preserves_object_body(selector):
    up = Upstream({("POST", f"{V2S}/ports/{SWITCH_MAC}/reset"): {}})
    c = client(up)
    mcp = FastMCP("legacy-reset")
    ndo.register(mcp, lambda: (c, registry()))
    tool = await mcp.get_tool("reset_switch_port")
    try:
        await tool.fn(HOST, SITE, body={"port_idx": 3}, **selector)
    finally:
        await c.close()
    assert body_of(up.writes()[0]) == {"port_idx": 3}


async def test_read_post_and_mixed_tools_hidden_by_both_write_policies(monkeypatch):
    from unifi_fabric.read_only_tools import (
        apply_area_opt_out_tool_filter,
        apply_read_only_tool_filter,
    )
    from unifi_fabric.tools import (
        client_records,
        network_proav_sandbox,
        network_switching_power,
        system_log,
    )

    names = {
        "get_system_log",
        "query_power_supervisor_logs",
        "query_switch_mac_tables",
        "query_port_system_logs",
        "get_rolling_upgrade_plan",
        "list_guests",
        "get_multicast_insights",
    }

    def app_with_tools():
        app = FastMCP("write-policy-test")
        for module in (
            system_log,
            network_switching_power,
            ndo,
            client_records,
            network_proav_sandbox,
        ):
            module.register(app, lambda: (None, None))
        return app

    app = app_with_tools()
    assert names <= await apply_read_only_tool_filter(app, True)
    monkeypatch.setenv("UNIFI_ENABLE_NETWORK_WRITE", "false")
    app = app_with_tools()
    hidden = await apply_area_opt_out_tool_filter(app, True)
    assert names <= hidden.keys()
    assert all(hidden[name] == "UNIFI_ENABLE_NETWORK_WRITE" for name in names)


@pytest.mark.parametrize(
    "module_name,tool_name",
    [
        ("system_log", "get_system_log"),
        ("system_log", "list_network_events"),
        ("system_log", "list_ips_events"),
        ("network_switching_power", "query_power_supervisor_logs"),
        ("network_switching_power", "query_switch_mac_tables"),
        ("network_switching_power", "query_port_system_logs"),
    ],
)
async def test_read_post_description_explains_area_opt_out(module_name, tool_name):
    from importlib import import_module

    module = import_module(f"unifi_fabric.tools.{module_name}")
    app = FastMCP("read-post-guidance")
    module.register(app, lambda: (None, None))
    tool = await app.get_tool(tool_name)
    assert "UNIFI_ENABLE_NETWORK_WRITE=false" in tool.description
    assert "UNIFI_READ_ONLY" in tool.description


@pytest.mark.parametrize(
    "module_name,tool_name",
    [
        ("network_device_operations", "get_rolling_upgrade_plan"),
        ("client_records", "list_guests"),
        ("network_proav_sandbox", "get_multicast_insights"),
    ],
)
async def test_mixed_action_description_explains_whole_tool_filter(module_name, tool_name):
    from importlib import import_module

    module = import_module(f"unifi_fabric.tools.{module_name}")
    app = FastMCP("mixed-action-guidance")
    module.register(app, lambda: (None, None))
    tool = await app.get_tool(tool_name)
    assert "whole tool" in tool.description
    assert "UNIFI_READ_ONLY" in tool.description


async def test_recover_invalid_target_port_preserves_body_and_explains_state():
    raw = '{"meta":{"rc":"error","port":24,"msg":"api.err.InvalidTargetPort"},"data":[]}'
    up = Upstream({("POST", DEVMGR): httpx.Response(400, text=raw)})
    with pytest.raises(Exception) as caught:
        await run(up, ndo.recover_switch_port, SWITCH_MAC, 24)
    assert raw in str(caught.value)
    assert "port may not be in a recoverable state" in str(caught.value)
    assert "blocked by loop detection or BPDU guard" in str(caught.value)
    assert len(up.writes()) == 1


async def test_adoption_404_preserves_error_and_explains_pending_state():
    route = f"{V2S}/adopt-info/{SWITCH_MAC}"
    up = Upstream({("GET", route): httpx.Response(404, text="pending device not found")})
    with pytest.raises(Exception) as caught:
        await run(up, ndo.get_device_adoption_info, SWITCH_MAC)
    assert "pending device not found" in str(caught.value)
    assert "pending adoption" in str(caught.value)
    assert len(up.seen) == 1
