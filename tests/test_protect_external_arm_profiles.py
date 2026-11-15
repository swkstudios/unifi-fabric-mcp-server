"""Protect 7.4.96: external arm profiles (7 routes) and stop_speaker_siren.

Each tool's request is checked against the route and body of the pinned Protect 7.4.96 spec
(``tests/fixtures/openapi/protect-7.4.96.json``); the arguments are refused before any
request when they cannot be sent.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from fastmcp import FastMCP

from tests._protect_writes import assert_write, resp
from unifi_fabric.families.protect import protect
from unifi_fabric.families.protect import registrar as protect_registrar
from unifi_fabric.families.protect.protect import PROTECT_PROXY_BASE

SPEC = json.loads(
    (Path(__file__).parent / "fixtures" / "openapi" / "protect-7.4.96.json").read_text()
)
HOST_ID = "host-ext-001"
BASE = PROTECT_PROXY_BASE.format(host_id=HOST_ID)
PROFILE_ID = "66d025b301ebc903e80003ea"
PROFILE = {
    "id": PROFILE_ID,
    "modelKey": "externalArmProfile",
    "title": "Night",
    "alarm_ids": [],
    "created_at": "2026-11-11T00:00:00Z",
    "state": "disarmed",
}


@pytest.fixture()
def client():
    c = AsyncMock()
    c.request = AsyncMock(return_value=resp({}))
    c.get = AsyncMock()
    c.delete = AsyncMock(return_value=None)
    c.dry_run = False
    return c


@pytest.fixture()
def registry():
    r = AsyncMock()
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    r.resolve_key_for_host = AsyncMock(return_value=None)
    return r


def test_the_routes_are_the_ones_the_pinned_spec_publishes() -> None:
    paths = SPEC["paths"]
    for path, methods in {
        "/v1/external/arm-profiles": {"get", "post"},
        "/v1/external/arm-profiles/{id}": {"get", "patch", "delete"},
        "/v1/external/arm-profiles/{id}/actions/arm": {"post"},
        "/v1/external/arm-profiles/{id}/actions/disarm": {"post"},
        "/v1/speakers/{id}/stop-siren": {"post"},
    }.items():
        assert methods <= set(paths[path]), path


async def test_list_and_get_read_the_external_routes(client, registry) -> None:
    client.get.side_effect = [[PROFILE], PROFILE]
    listed = await protect.list_external_arm_profiles(client, registry, "h")
    assert listed == {"result": [PROFILE], "_count": 1}
    got = await protect.get_external_arm_profile(client, registry, "h", PROFILE_ID)
    assert got == PROFILE
    assert [c.args[0] for c in client.get.call_args_list] == [
        f"{BASE}/external/arm-profiles",
        f"{BASE}/external/arm-profiles/{PROFILE_ID}",
    ]


async def test_create_posts_title_and_the_settings(client, registry) -> None:
    client.request.return_value = resp(PROFILE, status=201)
    result = await protect.create_external_arm_profile(
        client, registry, "h", "Night", activation_delay=30, title="Night"
    )
    assert_write(
        client,
        "POST",
        f"{BASE}/external/arm-profiles",
        json={"title": "Night", "activation_delay": 30},
    )
    assert result == {"status": "created", "response": PROFILE}


async def test_create_refuses_a_conflicting_or_empty_title_before_any_request(
    client, registry
) -> None:
    with pytest.raises(ValueError, match="twice"):
        await protect.create_external_arm_profile(client, registry, "h", "Night", title="Day")
    with pytest.raises(ValueError, match="empty"):
        await protect.create_external_arm_profile(client, registry, "h", "")
    client.request.assert_not_called()
    registry.resolve_host_id.assert_not_called()


async def test_update_patches_only_the_given_keys_reads_back_and_can_clear_a_delay(
    client, registry
) -> None:
    after = {**PROFILE, "title": "Day", "activation_delay": None}
    client.get.side_effect = [PROFILE, after]
    client.request.return_value = resp(after)
    result = await protect.update_external_arm_profile(
        client, registry, "h", PROFILE_ID, title="Day", activation_delay=None
    )
    path = f"{BASE}/external/arm-profiles/{PROFILE_ID}"
    assert_write(client, "PATCH", path, json={"title": "Day", "activation_delay": None})
    assert [c.args[0] for c in client.get.call_args_list] == [path, path]
    assert result["status"] == "updated" and result["verified"] is True
    assert result["before"] == PROFILE and result["after"] == after
    assert result["response"] == after


async def test_update_refuses_an_empty_body_and_a_bad_id_before_any_request(
    client, registry
) -> None:
    with pytest.raises(ValueError):
        await protect.update_external_arm_profile(client, registry, "h", PROFILE_ID)
    with pytest.raises(ValueError):
        await protect.update_external_arm_profile(client, registry, "h", "..", title="x")
    client.request.assert_not_called()
    registry.resolve_host_id.assert_not_called()


async def test_delete_arm_and_disarm_use_their_routes(client, registry) -> None:
    deleted = await protect.delete_external_arm_profile(client, registry, "h", PROFILE_ID)
    client.delete.assert_called_once_with(f"{BASE}/external/arm-profiles/{PROFILE_ID}", key=None)
    assert deleted["deleted"] is True

    client.request.return_value = resp(PROFILE)
    await protect.arm_external_arm_profile(client, registry, "h", PROFILE_ID)
    assert_write(client, "POST", f"{BASE}/external/arm-profiles/{PROFILE_ID}/actions/arm")
    client.request.reset_mock()
    await protect.disarm_external_arm_profile(client, registry, "h", PROFILE_ID)
    assert_write(client, "POST", f"{BASE}/external/arm-profiles/{PROFILE_ID}/actions/disarm")


async def test_stop_speaker_siren_posts_the_official_route_and_passes_204_through(
    client, registry
) -> None:
    client.request.return_value = resp()
    result = await protect.stop_speaker_siren(client, registry, "h", "00000000000000000000010f")
    assert_write(client, "POST", f"{BASE}/speakers/00000000000000000000010f/stop-siren")
    assert result == {"status": "sent", "response": None}
    with pytest.raises(ValueError):
        await protect.stop_speaker_siren(client, registry, "h", "..")


async def test_tools_carry_derived_hints_and_described_arguments() -> None:
    mcp = FastMCP("external-arm")
    protect_registrar.register_5(mcp, lambda: (AsyncMock(), AsyncMock()))
    tools = {t.name: t for t in await mcp.list_tools()}
    reads = {"list_external_arm_profiles", "get_external_arm_profile"}
    writes = {
        "create_external_arm_profile",
        "update_external_arm_profile",
        "delete_external_arm_profile",
        "arm_external_arm_profile",
        "disarm_external_arm_profile",
        "stop_speaker_siren",
    }
    for name in reads | writes:
        assert tools[name].annotations.readOnlyHint is (name in reads), name
        for prop, schema in tools[name].parameters["properties"].items():
            assert schema.get("description"), (name, prop)


def test_update_camera_accepts_the_antiflicker_video_mode_of_7_4_96() -> None:
    from unifi_fabric.spec_limits import argument_problems

    enum = SPEC["components"]["schemas"]["videoMode"]["enum"]
    assert "antiFlicker" in enum
    assert argument_problems("update_camera", {"settings": {"videoMode": "antiFlicker"}}) == []
    assert argument_problems("update_camera", {"settings": {"videoMode": "bogus"}}) != []


# ------------------------------------------------------------------ no-op skip (F6)


async def test_update_skips_the_write_when_every_requested_leaf_already_matches(
    client, registry
) -> None:
    client.get.side_effect = [PROFILE]
    result = await protect.update_external_arm_profile(
        client, registry, "h", PROFILE_ID, title=PROFILE["title"]
    )
    assert result["status"] == "noop" and result["resource"] == PROFILE
    client.request.assert_not_called()


async def test_a_pin_code_is_never_a_no_op_because_the_profile_reports_has_pin_only(
    client, registry
) -> None:
    client.get.side_effect = [PROFILE, PROFILE]
    client.request.return_value = resp(PROFILE)
    await protect.update_external_arm_profile(client, registry, "h", PROFILE_ID, pin_code="4821")
    assert_write(
        client,
        "PATCH",
        f"{BASE}/external/arm-profiles/{PROFILE_ID}",
        json={"pin_code": "4821"},
    )


# ------------------------------------------------------- the arm PIN is a secret (F1)

PIN = "482193"


async def test_a_pin_update_is_verified_by_has_pin_because_pin_code_never_reads_back(
    client, registry
) -> None:
    """The profile reports has_pin, never pin_code: a saved PIN must not read as unverified."""
    after = {**PROFILE, "has_pin": True}
    client.get.side_effect = [{**PROFILE, "has_pin": False}, after]
    client.request.return_value = resp(after)
    result = await protect.update_external_arm_profile(
        client, registry, "h", PROFILE_ID, pin_code=PIN
    )
    assert_write(
        client, "PATCH", f"{BASE}/external/arm-profiles/{PROFILE_ID}", json={"pin_code": PIN}
    )
    assert result["status"] == "updated" and result["verified"] is True
    assert PIN not in json.dumps(result["after"])


async def test_clearing_the_pin_is_verified_by_has_pin_reading_false(client, registry) -> None:
    """pin_code null clears the PIN; the working clear reads back has_pin false."""
    after = {**PROFILE, "has_pin": False}
    client.get.side_effect = [{**PROFILE, "has_pin": True}, after]
    client.request.return_value = resp(after)
    result = await protect.update_external_arm_profile(
        client, registry, "h", PROFILE_ID, pin_code=None
    )
    assert_write(
        client, "PATCH", f"{BASE}/external/arm-profiles/{PROFILE_ID}", json={"pin_code": None}
    )
    assert result["status"] == "updated" and result["verified"] is True


async def test_clearing_the_pin_is_not_verified_while_has_pin_still_reads_true(
    client, registry
) -> None:
    after = {**PROFILE, "has_pin": True}
    client.get.side_effect = [after, after]
    client.request.return_value = resp(after)
    result = await protect.update_external_arm_profile(
        client, registry, "h", PROFILE_ID, pin_code=None
    )
    assert result["status"] == "updated" and result["verified"] is False


async def test_a_pin_clear_next_to_other_keys_checks_each_of_them(client, registry) -> None:
    after = {**PROFILE, "title": "Day", "has_pin": False}
    client.get.side_effect = [{**PROFILE, "has_pin": True}, after]
    client.request.return_value = resp(after)
    result = await protect.update_external_arm_profile(
        client, registry, "h", PROFILE_ID, title="Day", pin_code=None
    )
    assert result["verified"] is True
    client.get.side_effect = [{**PROFILE, "has_pin": True}, {**PROFILE, "has_pin": False}]
    wrong_title = await protect.update_external_arm_profile(
        client, registry, "h", PROFILE_ID, title="Day", pin_code=None
    )
    assert wrong_title["verified"] is False


async def test_a_pin_update_next_to_other_keys_checks_each_of_them(client, registry) -> None:
    after = {**PROFILE, "title": "Day", "has_pin": True}
    client.get.side_effect = [PROFILE, after]
    client.request.return_value = resp(after)
    result = await protect.update_external_arm_profile(
        client, registry, "h", PROFILE_ID, title="Day", pin_code=PIN
    )
    assert result["verified"] is True
    client.get.side_effect = [PROFILE, {**PROFILE, "title": "Night", "has_pin": True}]
    wrong_title = await protect.update_external_arm_profile(
        client, registry, "h", PROFILE_ID, title="Day", pin_code=PIN
    )
    assert wrong_title["verified"] is False


@pytest.mark.parametrize("reported", [{"has_pin": False}, {}], ids=["has_pin false", "no has_pin"])
async def test_a_pin_update_is_not_verified_when_the_profile_does_not_report_a_pin(
    client, registry, reported
) -> None:
    after = {**PROFILE, **reported}
    client.get.side_effect = [PROFILE, after]
    client.request.return_value = resp(after)
    result = await protect.update_external_arm_profile(
        client, registry, "h", PROFILE_ID, pin_code=PIN
    )
    assert result["status"] == "updated" and result["verified"] is False


async def test_a_pin_update_with_a_failed_read_back_stays_unknown(client, registry) -> None:
    client.get.side_effect = [PROFILE, RuntimeError("boom")]
    client.request.return_value = resp(PROFILE)
    result = await protect.update_external_arm_profile(
        client, registry, "h", PROFILE_ID, pin_code=PIN
    )
    assert result["verified"] is None and "boom" in result["readAfterError"]


async def test_the_update_tool_description_says_what_a_pin_verification_proves() -> None:
    mcp = FastMCP("external-arm")
    protect_registrar.register_5(mcp, lambda: (AsyncMock(), AsyncMock()))
    tool = next(t for t in await mcp.list_tools() if t.name == "update_external_arm_profile")
    flat = " ".join(tool.description.split())
    assert "verified by has_pin reading true" in flat and "not its digits" in flat
    assert "pin_code null (clears the PIN) by has_pin reading false" in flat


def test_the_pin_is_a_registered_request_secret_on_both_writes() -> None:
    from unifi_fabric import route_secrets

    route = "protect/integration/v1/external/arm-profiles"
    assert route_secrets.request_secrets("POST", route, {"title": "n", "pin_code": PIN}) == (PIN,)
    assert route_secrets.request_secrets(
        "PATCH", f"{route}/{PROFILE_ID}", {"pin_code": PIN, "title": "n"}
    ) == (PIN,)
    for tool in ("create_external_arm_profile", "update_external_arm_profile"):
        assert route_secrets.tool_call_secrets(tool, {"settings": {"pin_code": PIN}}) == (PIN,)


def test_read_side_masks_the_pin_under_the_opt_in_and_leaves_has_pin_alone() -> None:
    from unifi_fabric.redaction import REDACTION_MASK, is_credential_field, redact_credentials

    assert is_credential_field("pin_code") and not is_credential_field("has_pin")
    masked = redact_credentials({"pin_code": PIN, "has_pin": True, "title": "n"})
    assert masked == {"pin_code": REDACTION_MASK, "has_pin": True, "title": "n"}


@pytest.mark.parametrize("name", ["create_external_arm_profile", "update_external_arm_profile"])
async def test_the_dry_run_preview_masks_the_pin_under_the_opt_in(monkeypatch, name) -> None:
    from tests import test_cross_tool_invariants as cti
    from tests import tool_args
    from tests import upstream_harness as uh
    from unifi_fabric.redaction import REDACTION_MASK

    monkeypatch.setenv("UNIFI_REDACT_SECRETS", "true")
    up = uh.FakeUpstream()
    args = tool_args.generated_args(cti.TOOLS[name])
    args["settings"] = {"title": "kept", "pin_code": PIN}
    if "title" in args:
        args["title"] = "kept"
    payload = uh.result_payload(
        await cti._call(monkeypatch, name, up, args, env={"UNIFI_WRITE_POLICY": "dry-run"})
    )
    text = json.dumps(payload)
    assert PIN not in text
    assert REDACTION_MASK in text and "kept" in text


@pytest.mark.parametrize("name", ["create_external_arm_profile", "update_external_arm_profile"])
async def test_a_redacted_pin_is_left_out_of_the_write_body(monkeypatch, name) -> None:
    """A read-side mask fed back into a write must never overwrite the stored PIN."""
    from tests import test_cross_tool_invariants as cti
    from tests import tool_args
    from tests import upstream_harness as uh
    from unifi_fabric.redaction import MASKED_FIELDS_KEY, REDACTION_MASK

    monkeypatch.setenv("UNIFI_REDACT_SECRETS", "true")
    up = uh.FakeUpstream()
    args = tool_args.generated_args(cti.TOOLS[name])
    args["settings"] = {"title": "kept", "pin_code": REDACTION_MASK}
    if "title" in args:
        args["title"] = "kept"
    payload = uh.result_payload(await cti._call(monkeypatch, name, up, args))
    sent = [w.sent_json for w in up.writes() if w.sent_json is not None]
    assert sent and all("pin_code" not in body for body in sent)
    assert any(body.get("title") == "kept" for body in sent)
    assert payload[MASKED_FIELDS_KEY] == ["pin_code"]


# --------------------------------------- global-mode guidance names the external tools (F2)


def test_global_mode_guidance_points_to_the_external_arm_profile_tools() -> None:
    from unittest.mock import MagicMock

    from unifi_fabric.families.protect import protect_private as pp

    summary = pp._alarm_manager_mode(
        200, {"featureFlags": {"useExternalAlarmManager": True}}, MagicMock()
    )
    external = summary["externalArmProfiles"]
    assert summary["mode"] == "global" and external["available"] is True
    assert set(external["tools"]) == set(pp.EXTERNAL_ARM_PROFILE_TOOLS)
    assert "7.4.96" in external["reason"]
    reason = summary["globalAlarmManagerApi"]["reason"]
    assert "list_external_arm_profiles" in reason and "arm/disarm them" not in reason
    local = pp._alarm_manager_mode(
        200, {"featureFlags": {"useExternalAlarmManager": False}}, MagicMock()
    )
    assert local["externalArmProfiles"]["available"] is False
    assert local["externalArmProfiles"]["reason"] is None


def test_the_global_mode_400_hint_names_the_external_tools() -> None:
    hint = protect.GLOBAL_ALARM_MANAGER_HINT
    assert "list_external_arm_profiles" in hint and "7.4.96" in hint
    assert "alarm profiles, alarm rules and arm/disarm cannot be managed" not in hint
