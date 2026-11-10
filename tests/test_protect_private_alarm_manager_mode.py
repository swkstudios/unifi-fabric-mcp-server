"""Global Alarm Manager mode detection and refusal (hermetic).

The console reports its Alarm Manager mode in the private NVR object
(``featureFlags.useExternalAlarmManager``). In global mode the Protect Integration
arm-profile API answers HTTP 400, and the global Alarm Manager's own API
(``/api/v2/alarms``) lives at the console root, which the Fabric connector does not
relay. These tests drive synthetic local (legacy), global and unsupported/unknown
consoles through ``get_protect_alarm_manager_mode`` and the arm-profile refusal hint,
and check that a permission or transport failure is never reported as a mode.
"""

from __future__ import annotations

import copy
from unittest.mock import AsyncMock

import httpx
import pytest

from unifi_fabric.client import UniFiConnectionError, UniFiHTTPError
from unifi_fabric.families.protect import protect
from unifi_fabric.families.protect import protect_private as pp

HOST_ID = "console-001"
PRIVATE = f"/v1/connector/consoles/{HOST_ID}/proxy/protect/api"
INTEGRATION = protect.PROTECT_PROXY_BASE.format(host_id=HOST_ID)
GLOBAL_400 = (
    f"HTTP 400 from GET {INTEGRATION}/arm-profiles: "
    '{"error":"This operation is not available when global alarm manager is enabled",'
    '"name":"BAD_REQUEST"}'
)
FORBIDDEN_403 = (
    f"HTTP 403 from GET {INTEGRATION}/arm-profiles: "
    '{"code":"forbidden","message":"insufficient permissions for this endpoint"}'
)
ARM_MODE = {"mode": "home", "armProfileId": "00000000000000000000a001", "status": "disabled"}


def _nvr(**overrides):
    body = {"id": "nvr-1", "name": "Recorder", "armMode": copy.deepcopy(ARM_MODE)}
    body.update(overrides)
    return body


def _rig(status=200, body=None, *, raw=None):
    calls = []
    client = AsyncMock()
    client.settings = None
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = None
    registry.resolve_host_id.return_value = HOST_ID

    async def request(method, path, **kwargs):
        calls.append((method, path))
        if raw is not None:
            return raw
        return httpx.Response(status, json=body)

    client.request.side_effect = request
    return client, registry, calls


# --- Mode detection -------------------------------------------------------------------


async def _mode(body, status=200):
    client, registry, calls = _rig(status=status, body=body)
    result = await pp.get_protect_alarm_manager_mode(client, registry, "example")
    return result, calls


async def test_global_mode_detected_and_v2_marked_unsupported():
    nvr = _nvr(featureFlags={"useExternalAlarmManager": True})
    result, _ = await _mode(nvr)
    assert result["status"] == 200 and result["body"] == nvr  # relay result unchanged
    am = result["_alarmManager"]
    assert am["mode"] == "global"
    assert am["integrationArmProfiles"]["available"] is False
    assert "global alarm manager is enabled" in am["integrationArmProfiles"]["reason"]
    api = am["globalAlarmManagerApi"]
    assert api["supported"] is False
    assert "/api/v2/alarms/profiles" in " ".join(api["routes"])
    assert "Fabric connector" in api["reason"]


async def test_local_mode_when_flag_false():
    nvr = _nvr(featureFlags={"useExternalAlarmManager": False})
    result, _ = await _mode(nvr)
    assert result["body"] == nvr
    am = result["_alarmManager"]
    assert am["mode"] == "local"
    assert am["integrationArmProfiles"]["available"] is True
    assert am["integrationArmProfiles"]["reason"] is None
    assert "list_arm_profiles" in am["integrationArmProfiles"]["tools"]
    # The v2 API is a transport fact: unsupported through Fabric in every mode.
    assert am["globalAlarmManagerApi"]["supported"] is False


@pytest.mark.parametrize(
    "nvr",
    [
        _nvr(),  # a legacy console reports no featureFlags at all
        _nvr(featureFlags={"otherFlag": True}),  # featureFlags without the flag
    ],
    ids=["no-featureFlags", "flag-absent"],
)
async def test_legacy_console_without_flag_is_local(nvr):
    result, _ = await _mode(nvr)
    assert result["_alarmManager"]["mode"] == "local"
    assert "absent" in result["_alarmManager"]["reason"]


@pytest.mark.parametrize(
    "body,shape",
    [
        (_nvr(featureFlags=["useExternalAlarmManager"]), "featureFlags"),
        (_nvr(featureFlags={"useExternalAlarmManager": "true"}), "useExternalAlarmManager"),
        (_nvr(featureFlags={"useExternalAlarmManager": 1}), "useExternalAlarmManager"),
        (_nvr(featureFlags={"useExternalAlarmManager": None}), "useExternalAlarmManager"),
        ([_nvr()], "array"),
    ],
    ids=["flags-list", "flag-string", "flag-int", "flag-null", "nvr-array"],
)
async def test_unknown_mode_refuses_instead_of_guessing(body, shape):
    result, calls = await _mode(body)
    assert result["body"] == body  # the unexpected shape is returned, never dropped
    am = result["_alarmManager"]
    assert am["mode"] is None and am["integrationArmProfiles"] is None
    assert shape in am["reason"] and "mode was not determined" in am["reason"]
    assert calls == [("GET", f"{PRIVATE}/nvr")]


@pytest.mark.parametrize("status", [401, 403, 404, 500, 502])
async def test_permission_or_transport_error_is_not_a_mode(status):
    body = {"code": "forbidden", "message": "insufficient permissions for this endpoint"}
    result, _ = await _mode(body, status=status)
    assert result["status"] == status
    assert result["body"] == body  # upstream body verbatim
    am = result["_alarmManager"]
    assert am["mode"] is None and am["integrationArmProfiles"] is None
    assert f"HTTP {status}" in am["reason"] and "mode was not determined" in am["reason"]


async def test_network_failure_propagates_unchanged():
    client, registry, _ = _rig()
    client.request.side_effect = UniFiConnectionError("connection reset", request_sent=False)
    with pytest.raises(UniFiConnectionError, match="connection reset"):
        await pp.get_protect_alarm_manager_mode(client, registry, "example")


async def test_mode_read_sends_one_nvr_get_and_never_touches_v2_or_writes():
    _, calls = await _mode(_nvr(featureFlags={"useExternalAlarmManager": True}))
    assert calls == [("GET", f"{PRIVATE}/nvr")]
    assert not any("/api/v2/alarms" in path for _, path in calls)


async def test_mode_read_uses_owning_key():
    client, registry, _ = _rig(body=_nvr(featureFlags={"useExternalAlarmManager": False}))
    key = object()
    registry.resolve_key_for_host.return_value = key
    await pp.get_protect_alarm_manager_mode(client, registry, "example")
    registry.resolve_host_id.assert_awaited_with("example", key=key)
    assert client.request.await_args.kwargs["key"] is key


# --- Refusal hint on the Integration arm-profile tools ----------------------------------


def _integration_client(error):
    client = AsyncMock()
    client.settings = None
    client.get = AsyncMock(side_effect=error)
    client.post = AsyncMock(side_effect=error)
    client.patch = AsyncMock(side_effect=error)
    client.delete = AsyncMock(side_effect=error)
    client.request = AsyncMock(side_effect=error)
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = None
    registry.resolve_host_id.return_value = HOST_ID
    return client, registry


ARM_TOOLS = [
    ("list_arm_profiles", (), {}),
    ("get_arm_profile", ("00000000000000000000a001",), {}),
    ("create_arm_profile", ("Night",), {"automations": []}),
    ("update_arm_profile", ("00000000000000000000a001",), {"name": "Away"}),
    ("delete_arm_profile", ("00000000000000000000a001",), {}),
    ("update_arm_profile_settings", ("00000000000000000000a001",), {}),
    ("enable_arm", (), {}),
    ("disable_arm", (), {}),
]


@pytest.mark.parametrize("name,args,kwargs", ARM_TOOLS, ids=[t[0] for t in ARM_TOOLS])
async def test_global_mode_400_keeps_upstream_text_and_appends_hint(name, args, kwargs):
    client, registry = _integration_client(UniFiHTTPError(GLOBAL_400, status=400))
    with pytest.raises(UniFiHTTPError) as exc:
        await getattr(protect, name)(client, registry, "example", *args, **kwargs)
    text = str(exc.value)
    assert text.startswith(GLOBAL_400)  # the upstream answer is never rewritten
    assert "get_protect_alarm_manager_mode" in text
    assert "/api/v2/alarms" in text
    assert exc.value.status == 400


@pytest.mark.parametrize("name,args,kwargs", ARM_TOOLS, ids=[t[0] for t in ARM_TOOLS])
@pytest.mark.parametrize(
    "error",
    [
        UniFiHTTPError(FORBIDDEN_403, status=403),
        UniFiHTTPError(f"HTTP 400 from GET {INTEGRATION}/arm-profiles: bad body", status=400),
        UniFiConnectionError("connection reset"),
    ],
    ids=["403-permission", "400-other", "transport"],
)
async def test_other_failures_get_no_global_mode_hint(name, args, kwargs, error):
    original = str(error)
    client, registry = _integration_client(error)
    with pytest.raises(UniFiConnectionError) as exc:
        await getattr(protect, name)(client, registry, "example", *args, **kwargs)
    assert str(exc.value) == original
    assert "get_protect_alarm_manager_mode" not in str(exc.value)


# --- Registration ----------------------------------------------------------------------


async def test_registered_read_only_with_described_host():
    from unifi_fabric.server import mcp

    tool = next(t for t in await mcp.list_tools() if t.name == "get_protect_alarm_manager_mode")
    assert tool.annotations.readOnlyHint is True
    props = tool.parameters["properties"]
    assert set(props) == {"host"}
    assert all(p.get("description") for p in props.values())
    assert "global" in tool.description and "/api/v2/alarms" in tool.description


# --- Wording matches the evidence ---------------------------------------------------


def _says_three_things(text: str) -> None:
    flat = " ".join(text.split())
    assert "documents" in flat and "local Alarm Manager" in flat  # documented local-only
    assert "reads with HTTP 400" in flat  # the 400 was observed on the reads
    assert "not exercised" in flat  # the writes were not tried in global mode
    assert "not proof of the arm state" in flat
    for overclaim in ("answers them with HTTP 400", "to every Integration", "every Integration"):
        assert overclaim not in flat


async def test_global_mode_reason_states_only_what_was_observed():
    nvr = _nvr(featureFlags={"useExternalAlarmManager": True})
    result, _ = await _mode(nvr)
    _says_three_things(result["_alarmManager"]["integrationArmProfiles"]["reason"])


async def test_tool_description_states_only_what_was_observed():
    from unifi_fabric.server import mcp

    tool = next(t for t in await mcp.list_tools() if t.name == "get_protect_alarm_manager_mode")
    _says_three_things(tool.description)
    assert "body.armMode" in tool.description


ARM_PROFILE_TOOLS = (
    "list_arm_profiles",
    "get_arm_profile",
    "create_arm_profile",
    "update_arm_profile",
    "delete_arm_profile",
    "update_arm_profile_settings",
    "enable_arm",
    "disable_arm",
)
HAND_OFF = (
    "On a console in global Alarm Manager mode the arm-profile reads answer HTTP 400; "
    "check get_protect_alarm_manager_mode."
)


@pytest.mark.parametrize("name", ARM_PROFILE_TOOLS)
async def test_every_arm_profile_tool_description_hands_off_to_the_mode_tool(name):
    """A caller who reads only the tool list learns what a global-mode 400 means."""
    from unifi_fabric.server import mcp

    tool = next(t for t in await mcp.list_tools() if t.name == name)
    assert " ".join(HAND_OFF.split()) in " ".join(tool.description.split())


def _coverage_section() -> str:
    from pathlib import Path

    text = (Path(__file__).resolve().parents[1] / "docs" / "COVERAGE.md").read_text(
        encoding="utf-8"
    )
    start = text.index("### Protect global Alarm Manager")
    return " ".join(text[start : text.index("\n### ", start + 1)].split())


def test_coverage_labels_local_mode_detection_simulated():
    """Global mode was read live; local mode has only simulated evidence."""
    section = _coverage_section()
    assert "local mode" in section.lower()
    assert "simulated" in section
    assert "needs live testing" in section.lower()


def test_coverage_does_not_claim_adoption_forces_global_mode():
    """The evidence shows the flag on global-mode consoles, not why it is on."""
    section = _coverage_section()
    assert "forced on" not in section
    assert "adopting UniFi sensors, fobs, relays or an alarm hub" in section
    assert "can turn it on" in section
