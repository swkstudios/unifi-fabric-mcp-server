"""Network controller administration tools: routes, bodies, validation, verification.

Hermetic: the real server, client and registry run against the synthetic fake upstream
(``tests.upstream_harness``); no controller is contacted.
"""

from __future__ import annotations

import base64
import copy
import json
from typing import Any

import httpx
import pytest
from fastmcp import FastMCP

from tests import upstream_harness as uh
from unifi_fabric import server
from unifi_fabric._read_only_audit import derive_write_tools
from unifi_fabric.client import DRY_RUN_MESSAGE
from unifi_fabric.tools import network_controller_admin as admin

HOST, SITE, MAC = uh.HOST, uh.SITE, uh.ARG_MAC
CLASSIC = "/proxy/network/api/s/"
V2 = "/proxy/network/v2/api/"

TOOL_NAMES = {
    "cancel_controller_backup",
    "delete_controller_backup",
    "restore_controller_backup",
    "import_site_configuration",
    "send_test_email",
    "get_remote_access_turn_credentials",
    "set_cloud_access_registration",
    "refresh_sso_session",
    "link_ubiquiti_sso_account",
    "update_my_admin_profile",
    "resend_mfa_code",
    "set_controller_system_parameter",
    "generate_support_file",
    "get_support_file",
    "check_controller_firmware_update",
    "manage_firmware_cache",
    "get_latest_firmware_versions",
}
READS = {"get_support_file", "get_latest_firmware_versions"}


async def _call(
    monkeypatch: pytest.MonkeyPatch, name: str, args: dict[str, Any], **settings: Any
) -> tuple[Any, uh.FakeUpstream]:
    up = uh.FakeUpstream()
    for field, value in settings.pop("upstream", {}).items():
        setattr(up, field, value)
    uh.install(monkeypatch, up, **settings)
    result = await server.mcp.call_tool(name, args)
    return uh.result_payload(result), up


def _main(up: uh.FakeUpstream) -> list[uh.Served]:
    return [s for s in up.served if not s.resolution]


# (tool, arguments, method, path suffix after /proxy/network, body sent)
CLASSIC_CASES: list[tuple[str, dict[str, Any], str, dict[str, Any]]] = [
    (
        "cancel_controller_backup",
        {"backup_id": "b-1"},
        "cmd/backup",
        {"cmd": "cancel-backup", "backup_id": "b-1"},
    ),
    (
        "delete_controller_backup",
        {"filename": "a.unf", "device_id": "d-1"},
        "cmd/backup",
        {"cmd": "delete-backup", "filename": "a.unf", "device_id": "d-1"},
    ),
    (
        "restore_controller_backup",
        {"body": {"probe": 1}},
        "cmd/backup",
        {"cmd": "restore", "probe": 1},
    ),
    (
        "import_site_configuration",
        {"backup_id": "b-2", "site_desc": "Branch"},
        "cmd/backup",
        {"cmd": "import-site", "backup_id": "b-2", "site_desc": "Branch"},
    ),
    (
        "send_test_email",
        {"email": "a@example.com", "smtp_host": "smtp.example.com", "port": 587},
        "cmd/cfgmgr",
        {"cmd": "test_mail", "email": "a@example.com", "host": "smtp.example.com", "port": 587},
    ),
    (
        "get_remote_access_turn_credentials",
        {},
        "cmd/cloudaccess",
        {"cmd": "get-turn-credentials"},
    ),
    (
        "set_cloud_access_registration",
        {"action": "register", "ubic_username": "u@example.com", "poll_login": True},
        "cmd/cloudaccess",
        {"cmd": "register", "ubic_username": "u@example.com", "poll_login": True},
    ),
    (
        "set_cloud_access_registration",
        {"action": "unregister"},
        "cmd/cloudaccess",
        {"cmd": "unregister"},
    ),
    (
        "refresh_sso_session",
        {"sso_username": "u@example.com", "sso_2fa_token": "123456"},
        "cmd/productinfo/refresh-sso",
        {"cmd": "refresh-sso", "sso_username": "u@example.com", "sso_2fa_token": "123456"},
    ),
    (
        "link_ubiquiti_sso_account",
        {"command": "probe-cmd", "ubic_username": "u@example.com"},
        "self/ubic_sso",
        {"cmd": "probe-cmd", "ubic_username": "u@example.com"},
    ),
    (
        "set_controller_system_parameter",
        {"key": "debug.mgmt", "value": "warn"},
        "cmd/system",
        {"cmd": "set-param", "key": "debug.mgmt", "value": "warn"},
    ),
    (
        "check_controller_firmware_update",
        {},
        "cmd/productinfo",
        {"cmd": "check-firmware-update"},
    ),
    (
        "manage_firmware_cache",
        {"action": "remove", "device": "U7PG2", "version": "6.6.77"},
        "cmd/firmware",
        {"cmd": "remove", "device": "U7PG2", "version": "6.6.77"},
    ),
]


@pytest.mark.parametrize(("name", "args", "route", "body"), CLASSIC_CASES)
async def test_classic_command_routes_and_bodies(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    args: dict[str, Any],
    route: str,
    body: dict[str, Any],
) -> None:
    result, up = await _call(monkeypatch, name, {"host": HOST, "site": SITE, **args})
    writes = up.writes()
    assert len(writes) == 1
    assert writes[0].method == "POST"
    assert writes[0].path.endswith(f"{CLASSIC}default/{route}")
    assert writes[0].sent_json == body
    # Delete uses the shared canonical deletion result while preserving the envelope.
    if name == "delete_controller_backup":
        assert result == {
            "deleted": True,
            "message": "Backup a.unf deleted.",
            "response": writes[0].body,
        }
    else:
        assert result == writes[0].body


async def test_restore_with_filename_chooses_then_restores(monkeypatch: pytest.MonkeyPatch) -> None:
    result, up = await _call(
        monkeypatch,
        "restore_controller_backup",
        {"host": HOST, "site": SITE, "filename": "a.unf"},
    )
    sent = [s.sent_json for s in up.writes()]
    assert sent == [{"cmd": "choose-backup", "filename": "a.unf"}, {"cmd": "restore"}]
    assert result["_chooseBackup"] == up.writes()[0].body


async def test_resend_mfa_code_route_and_body(monkeypatch: pytest.MonkeyPatch) -> None:
    _, up = await _call(
        monkeypatch,
        "resend_mfa_code",
        {"host": HOST, "mfa_type": "email", "mfa_id": "m-1", "body": {"mfa_cookie": "c"}},
    )
    (write,) = up.writes()
    assert write.path.endswith(f"{V2}mfa/email/m-1/send")
    assert write.sent_json == {"cmd": "resend-mfa-code", "mfa_cookie": "c"}


async def test_support_file_generation_status_and_download(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    upper = MAC.upper().replace(":", "-")
    _, up = await _call(
        monkeypatch,
        "generate_support_file",
        {"host": HOST, "site": SITE, "mac": upper, "body": {"probe": True}},
    )
    lookup, write = _main(up)
    assert lookup.path.endswith(f"{CLASSIC}default/stat/device-basic")
    assert write.path.endswith(f"{V2}site/default/support/{MAC}/generation")
    assert write.sent_json == {"probe": True}

    status, up = await _call(
        monkeypatch, "get_support_file", {"host": HOST, "site": SITE, "mac": MAC}
    )
    assert len(_main(up)) == 1  # a read: the upstream judges the MAC, no lookup
    assert _main(up)[-1].path.endswith(f"{V2}site/default/support/{MAC}")
    assert status == {"result": _main(up)[-1].body}  # a bare array, wrapped by the framework

    download, up = await _call(
        monkeypatch, "get_support_file", {"host": HOST, "site": SITE, "mac": MAC, "download": True}
    )
    served = _main(up)[-1]
    assert served.path.endswith(f"/support/{MAC}/download")
    raw = base64.b64decode(download["content_base64"])
    assert json.loads(raw) == served.body
    assert download["sizeBytes"] == len(raw)
    assert download["contentType"] == "application/json"


async def test_unknown_device_mac_fails_listing_choices_without_a_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(Exception, match=r"Unknown device MAC '02:00:5e:00:00:ff'.*valid: .*aa"):
        await _call(
            monkeypatch,
            "generate_support_file",
            {"host": HOST, "site": SITE, "mac": "02:00:5e:00:00:ff"},
        )


async def test_update_my_admin_profile_merges_nested_leaves_and_verifies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, up = await _call(
        monkeypatch,
        "update_my_admin_profile",
        {"host": HOST, "profile": {"nested": {"flag": True}, "name": "me"}},
    )
    (write,) = up.writes()
    assert write.method == "PUT"
    assert write.path.endswith("/proxy/network/api/self")
    assert write.sent_json == {
        "nested": {"list": [1, "two", {"three": None}], "flag": True, "ratio": 1.25},
        "name": "me",
    }
    # the fake reflects top-level scalars only: the nested leaf did not read back
    assert result["_verified"] is False


async def test_get_latest_firmware_versions_reads_both_official_sources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, up = await _call(
        monkeypatch,
        "get_latest_firmware_versions",
        {"host": HOST, "site": SITE, "filter": "probe-filter", "time": "2026-10-01T00:00:00Z"},
    )
    integration = [s for s in _main(up) if s.path.endswith(f"/sites/{uh.SITE_ID}/devices")]
    assert integration and "filter=probe-filter" in integration[0].query
    sm = [s for s in up.served if s.path == "/v1/devices"]
    assert sm and "hostIds" in sm[0].query and "time=" in sm[0].query
    assert result["data"] == integration[0].body["data"]
    assert result["totalCount"] == integration[0].body["totalCount"]
    assert result["_siteManagerDevices"]["data"]
    assert "incomplete" not in result


async def test_get_latest_firmware_versions_propagates_incomplete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def integration(*_: Any, **__: Any) -> dict[str, Any]:
        return {"data": [], "totalCount": 9}

    async def managed(*_: Any, **__: Any) -> dict[str, Any]:
        return {"data": [], "incomplete": True, "incompleteReason": "cap"}

    monkeypatch.setattr(admin.device_mgmt, "_list_site_devices", integration)
    monkeypatch.setattr(admin.site_manager, "list_devices", managed)
    result = await admin.get_latest_firmware_versions(None, None, HOST, SITE)  # type: ignore[arg-type]
    assert result["incomplete"] is True
    assert result["incompleteReason"] == "Site Manager: cap"
    assert result["totalCount"] == 9


INVALID_CALLS: list[tuple[str, dict[str, Any]]] = [
    ("cancel_controller_backup", {"host": " ", "site": SITE, "backup_id": "b"}),
    ("send_test_email", {"host": HOST, "site": "", "email": "a@example.com"}),
    ("set_cloud_access_registration", {"host": HOST, "site": SITE, "action": "nope"}),
    (
        "manage_firmware_cache",
        {"host": HOST, "site": SITE, "action": "x", "device": "d", "version": "v"},
    ),
    ("generate_support_file", {"host": HOST, "site": SITE, "mac": "not-a-mac"}),
    ("get_support_file", {"host": HOST, "site": SITE, "mac": "02:00:5e:00:00"}),
    ("resend_mfa_code", {"host": HOST, "mfa_type": "..", "mfa_id": "m"}),
    ("resend_mfa_code", {"host": HOST, "mfa_type": "a", "mfa_id": "m", "body": {"cmd": "x"}}),
    ("restore_controller_backup", {"host": HOST, "site": SITE, "body": {"cmd": "x"}}),
    ("link_ubiquiti_sso_account", {"host": HOST, "site": SITE, "command": "Bad Cmd"}),
    ("update_my_admin_profile", {"host": HOST, "profile": {}}),
    ("get_latest_firmware_versions", {"host": HOST, "site": " "}),
    (
        "set_controller_system_parameter",
        {"host": HOST, "site": SITE, "key": "k", "value": float("nan")},
    ),
]


@pytest.mark.parametrize(("name", "args"), INVALID_CALLS)
async def test_invalid_input_fails_before_any_request(
    monkeypatch: pytest.MonkeyPatch, name: str, args: dict[str, Any]
) -> None:
    up = uh.FakeUpstream()
    uh.install(monkeypatch, up)
    with pytest.raises(Exception):  # noqa: B017 - the refusal text is checked by the policy test
        await server.mcp.call_tool(name, args)
    assert up.served == []


async def test_classic_rejection_raises_with_the_full_upstream_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = {"meta": {"rc": "error", "msg": "api.err.SmtpFailed"}, "data": [{"why": "x" * 300}]}
    with pytest.raises(Exception) as caught:
        await _call(
            monkeypatch,
            "send_test_email",
            {"host": HOST, "site": SITE, "email": "a@example.com", "x_password": "probe-pw-77"},
            upstream={"classic_rc_body": body},
        )
    message = str(caught.value)
    assert "api.err.SmtpFailed" in message
    assert "x" * 300 in message  # never truncated
    assert "probe-pw-77" not in message  # the SMTP password is scrubbed


async def test_link_sso_rejection_raises_with_the_full_upstream_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = {"meta": {"rc": "error", "msg": "api.err.SsoFailed"}, "data": []}
    with pytest.raises(Exception, match="api.err.SsoFailed") as caught:
        await _call(
            monkeypatch,
            "link_ubiquiti_sso_account",
            {"host": HOST, "site": SITE, "command": "probe-cmd", "x_ubic_password": "probe-pw-78"},
            upstream={"classic_rc_body": body},
        )
    assert "probe-pw-78" not in str(caught.value)


@pytest.mark.parametrize(
    ("name", "args"),
    [
        ("cancel_controller_backup", {"backup_id": "b"}),
        ("link_ubiquiti_sso_account", {"command": "probe-cmd"}),
        ("generate_support_file", {"mac": MAC}),
        ("restore_controller_backup", {"filename": "a.unf"}),
    ],
)
async def test_dry_run_returns_the_preview_and_never_writes(
    monkeypatch: pytest.MonkeyPatch, name: str, args: dict[str, Any]
) -> None:
    result, up = await _call(monkeypatch, name, {"host": HOST, "site": SITE, **args}, dry_run=True)
    assert result["status"] == "dry_run"
    assert result["dryRun"] is True
    assert result["message"] == DRY_RUN_MESSAGE
    assert set(result["preview"]) >= {"method", "path", "body"}
    assert "_verified" not in result
    assert up.writes() == []


async def test_profile_dry_run_previews_the_merged_put(monkeypatch: pytest.MonkeyPatch) -> None:
    result, up = await _call(
        monkeypatch,
        "update_my_admin_profile",
        {"host": HOST, "profile": {"name": "me"}},
        dry_run=True,
    )
    assert result["status"] == "dry_run"
    assert result["preview"]["method"] == "PUT"
    assert result["preview"]["body"] == {"name": "me"}
    assert up.writes() == []


async def test_registration_is_typed_documented_and_derived() -> None:
    mcp = FastMCP("controller-admin")
    admin.register(mcp, lambda: (None, None))
    tools = {tool.name: tool for tool in await mcp.list_tools()}
    assert set(tools) == TOOL_NAMES
    writes = derive_write_tools(list(tools.values()))
    assert writes == TOOL_NAMES - READS
    for name, tool in tools.items():
        description = tool.description or ""
        assert len(description) <= 2048, name
        for field in tool.parameters["properties"].values():
            assert "e.g." in field.get("description", ""), (name, field)
            assert field.get("type") or field.get("anyOf"), (name, field)
        read_only = tool.annotations.read_only_hint if tool.annotations else None
        assert read_only is (name in READS), name
        if name not in READS:
            assert "dry-run preview" in description, name
            assert "Consequence:" in description, name
    assert TOOL_NAMES <= {tool.name for tool in await server.mcp.list_tools()}


async def test_non_first_key_owned_host_routes_to_that_key(
    monkeypatch: pytest.MonkeyPatch, multikey_client: Any, multikey_registry: Any
) -> None:
    up = uh.FakeUpstream(hosts_by_key={"k-alpha": [], "k-beta": [copy.deepcopy(uh.HOST_RECORD)]})

    async def http_session(key: Any) -> httpx.AsyncClient:
        if key.label not in multikey_client._clients:
            multikey_client._clients[key.label] = httpx.AsyncClient(
                base_url=multikey_client._settings.api_base_url,
                headers={"X-API-KEY": key.key},
                transport=httpx.MockTransport(up),
            )
        return multikey_client._clients[key.label]

    monkeypatch.setattr(multikey_client, "_get_client", http_session)
    await admin.cancel_controller_backup(multikey_client, multikey_registry, HOST, SITE, "b")
    await admin.cancel_controller_backup(multikey_client, multikey_registry, HOST, SITE, "b")
    served = [s for s in up.served if not s.resolution]
    assert len(served) == 2 and all(s.api_key == "k-beta" for s in served)
    assert any(s.path.endswith("/cmd/backup") for s in served)
    await multikey_client.close()
