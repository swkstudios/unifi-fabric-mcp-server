"""Hermetic coverage for the 22 P05 Protect automation, backup and cloud archive tools.

Synthetic fixtures under tests/fixtures/protect_automation_backup; no estate access.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
import respx
from httpx import Response

from tests.conftest import MULTIKEY_HOSTS_BY_LABEL
from unifi_fabric import route_secrets, server
from unifi_fabric.client import DRY_RUN_MESSAGE
from unifi_fabric.families.protect import protect_automation_backup as tools
from unifi_fabric.families.protect.protect import PROTECT_PRIVATE_BASE

FIXTURES = Path(__file__).parent / "fixtures" / "protect_automation_backup"
AUTOMATION_ID = "66f1a2b3c4d5e6f7a8b9c0d1"
BACKUP_ID = "backup-1718003600000"


def fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


class Registry:
    async def resolve_key_for_host(self, host):
        return None

    async def resolve_host_id(self, host, *, key):
        return "host-1"


CASES = [
    ("list_protect_automations", (), "GET", "/automations"),
    ("create_protect_automation", ({"name": "mcp-gs3-p05"},), "POST", "/automations"),
    (
        "update_protect_automation",
        (AUTOMATION_ID, {"name": "mcp-gs3-p05"}),
        "PATCH",
        f"/automations/{AUTOMATION_ID}",
    ),
    ("delete_protect_automation", (AUTOMATION_ID,), "DELETE", f"/automations/{AUTOMATION_ID}"),
    (
        "get_protect_automation_history",
        (AUTOMATION_ID,),
        "GET",
        f"/automations/{AUTOMATION_ID}/history",
    ),
    ("reset_protect_automations", (), "POST", "/automations/reset"),
    (
        "set_protect_notification_receivers",
        ({"userIds": []},),
        "PATCH",
        "/automations/system-notifications/receivers",
    ),
    ("list_protect_backups", (), "GET", "/backups"),
    ("create_protect_backup", (), "POST", "/backups"),
    ("delete_protect_backup", (BACKUP_ID,), "DELETE", f"/backup/{BACKUP_ID}"),
    ("import_protect_backup", ({"name": "mcp-gs3-p05"},), "POST", "/backups/import"),
    ("restore_protect_backup", (BACKUP_ID,), "POST", f"/backup/{BACKUP_ID}/restore"),
    ("restore_protect_database", (), "POST", "/nvr/restore-database-backup"),
    ("get_cloud_archive_status", ("google-drive",), "GET", "/cloud-provider/authenticate"),
    (
        "start_cloud_video_archive",
        ({"name": "mcp-gs3-p05"},),
        "POST",
        "/cloud-provider/video-archive",
    ),
    (
        "connect_cloud_archive_provider",
        ("synthetic-code",),
        "POST",
        "/cloud-provider/authenticate-device-code",
    ),
    ("cancel_cloud_archive_task", ("archive-1",), "POST", "/cloud-provider/cancel-archive-task"),
    ("disconnect_cloud_archive_provider", ("google-drive",), "POST", "/cloud-provider/revoke"),
    (
        "connect_unifi_video_server",
        ({"host": "192.0.2.10"},),
        "POST",
        "/cloud-provider/authenticate-nas",
    ),
    ("import_unifi_video_cameras", ("192.0.2.10",), "GET", "/cloud-provider/shared-drives"),
    (
        "accept_ironclad_terms",
        ("synthetic-cid", "synthetic-vid", "accepted", "synthetic"),
        "POST",
        "/ironclad/sendAcceptance",
    ),
]
IDS = [c[0] for c in CASES]
PREFIX = "/v1/connector/consoles/host-1/proxy/protect/api"
WRITES = [case for case in CASES if case[2] != "GET"]
WRITE_IDS = [c[0] for c in WRITES]
DELETE_MESSAGES = {
    "delete_protect_automation": f"Automation {AUTOMATION_ID} deleted.",
    "delete_protect_backup": f"Backup {BACKUP_ID} deleted.",
}


def impl(name: str) -> Any:
    return getattr(tools, f"_{name}")


def client_for(body: Any) -> AsyncMock:
    client = AsyncMock()

    async def get(path, **kwargs):
        if path.endswith("/automations"):
            return fixture("automations.json")
        if path.endswith("/backups"):
            # Like the console: a backup deleted with DELETE /backup/{id} is not listed again.
            gone = {call.args[0].rsplit("/", 1)[1] for call in client.delete.await_args_list}
            listed = fixture("backups.json")
            listed["data"] = [row for row in listed["data"] if row["id"] not in gone]
            return listed
        return body

    client.get.side_effect = get
    for method in ("post", "patch", "delete"):
        getattr(client, method).return_value = body
    return client


@pytest.mark.parametrize("name,args,method,route", CASES, ids=IDS)
@pytest.mark.parametrize("body", [{"native": True, "metadata": {"revision": 7}}, ["native"], None])
async def test_every_tool_preserves_upstream_body(name, args, method, route, body):
    client = client_for(body)
    result = await impl(name)(client, Registry(), "console", *args)
    if name == "list_protect_automations":
        assert result == fixture("automations.json")
    elif name == "list_protect_backups":
        assert result == fixture("backups.json")
    elif name == "update_protect_automation" and isinstance(body, dict):
        assert {k: v for k, v in result.items() if not k.startswith("_")} == body
        assert set(result) - set(body) == {"_before", "_after", "_verified"}
    elif name == "update_protect_automation":
        # A non-object write body is kept whole under ``response`` beside the verdict keys.
        assert result["response"] is body
        assert {"_before", "_after", "_verified"} <= set(result)
    elif name.startswith("delete_"):
        # A delete returns the deletion_result envelope: the upstream body is kept
        # whole, by identity, under ``response`` beside the exact confirmation keys.
        assert set(result) == {"deleted", "message", "response"}
        assert result["deleted"] is True
        assert result["message"] == DELETE_MESSAGES[name]
        assert result["response"] is body
    else:
        assert result is body
    assert any(
        call.args[0] == PREFIX + route for call in getattr(client, method.lower()).await_args_list
    )


@pytest.mark.parametrize("name,args,method,route", WRITES, ids=WRITE_IDS)
async def test_every_write_returns_standard_dry_run_preview(name, args, method, route):
    preview = {
        "status": "dry_run",
        "dryRun": True,
        "message": DRY_RUN_MESSAGE,
        "preview": {"method": method, "path": PREFIX + route, "body": None, "params": None},
    }
    result = await impl(name)(client_for(preview), Registry(), "console", *args)
    if name.startswith("delete_"):
        # A delete returns the deletion_result dry-run shape with the preview under response.
        assert set(result) == {"status", "deleted", "message", "response"}
        assert result["status"] == "dry_run" and result["deleted"] is False
        assert result["message"] == DRY_RUN_MESSAGE
        assert result["response"] is preview
    else:
        assert result is preview


@pytest.mark.parametrize("name,args,method,route", WRITES, ids=WRITE_IDS)
@pytest.mark.parametrize(
    "switch,value",
    [("UNIFI_WRITE_POLICY", "deny"), ("UNIFI_WRITE_EXCEPTIONS", "family:protect=deny")],
)
async def test_every_write_obeys_operator_opt_out_before_any_request(
    monkeypatch, name, args, method, route, switch, value
):
    from unifi_fabric.read_only import ReadOnlyModeError

    monkeypatch.setenv(switch, value)
    client = client_for({})
    refusal = (
        (ReadOnlyModeError, rf"^{method} refused: the server is in read-only mode")
        if switch == "UNIFI_WRITE_POLICY"
        else (
            ValueError,
            r"^Protect writes are denied: UNIFI_WRITE_EXCEPTIONS contains family:protect=deny\.",
        )
    )
    with pytest.raises(refusal[0], match=refusal[1]):
        await impl(name)(client, Registry(), "console", *args)
    assert not client.mock_calls


async def test_dry_run_is_honoured_end_to_end(monkeypatch):
    """A real client in dry-run policy previews the restore and sends nothing."""
    from unifi_fabric.client import UniFiClient
    from unifi_fabric.config import Settings

    monkeypatch.setenv("UNIFI_WRITE_POLICY", "dry-run")
    client = UniFiClient(Settings(api_key="synthetic-test-key"))
    try:
        with respx.mock(base_url="https://api.ui.com", assert_all_called=False) as mock:
            route = mock.post(url__regex=r".*").mock(return_value=Response(200, json={}))
            result = await tools._restore_protect_backup(client, Registry(), "console", BACKUP_ID)
        assert not route.called
        assert result["message"] == DRY_RUN_MESSAGE
        assert result["preview"]["path"] == PREFIX + f"/backup/{BACKUP_ID}/restore"
    finally:
        await client.close()


@pytest.mark.parametrize("name", ["delete_protect_backup", "delete_protect_automation"])
async def test_unknown_id_fails_listing_choices_before_any_write(name):
    client = client_for({"ok": True})
    with pytest.raises(ValueError, match="valid choices: .*(backup-1718000000000|66f1)"):
        await impl(name)(client, Registry(), "console", "unknown-id")
    client.delete.assert_not_awaited()


async def test_update_unknown_automation_sends_no_write():
    client = client_for({"ok": True})
    with pytest.raises(ValueError, match="valid choices"):
        await tools._update_protect_automation(
            client, Registry(), "console", "unknown-id", {"enabled": False}
        )
    client.patch.assert_not_awaited()


async def test_restore_is_never_refused_and_upstream_judges_the_id():
    """No-gates: restore of an id absent from the list is sent; the upstream decides."""
    response = fixture("restore_response.json")
    client = client_for(response)
    result = await tools._restore_protect_backup(client, Registry(), "console", "not-listed")
    assert result is response
    client.get.assert_not_awaited()
    client.post.assert_awaited_once_with(PREFIX + "/backup/not-listed/restore", key=None)


async def test_update_merges_into_listed_record_and_verifies():
    client = client_for({"ok": True})
    result = await tools._update_protect_automation(
        client, Registry(), "console", AUTOMATION_ID, {"settings": {"level": 3}}
    )
    sent = client.patch.await_args.kwargs["json"]
    listed = fixture("automations.json")[0]
    assert sent == {**listed, "settings": {"enabled": True, "level": 3}}
    assert result["_before"] == listed
    # The fixture list does not change, so the requested leaf is not re-read: False.
    assert result["_verified"] is False


@pytest.mark.parametrize("bad", [{"data": "x"}, "text", 7])
async def test_unexpected_list_shape_raises_naming_it(bad):
    client = client_for(None)
    client.get.side_effect = None
    client.get.return_value = bad
    with pytest.raises(ValueError, match="Unexpected response shape"):
        await tools._delete_protect_backup(client, Registry(), "console", BACKUP_ID)
    client.delete.assert_not_awaited()


async def test_incomplete_list_never_selects_write_target():
    client = client_for(None)
    client.get.side_effect = None
    client.get.return_value = {"data": [{"id": BACKUP_ID}], "incomplete": True}
    with pytest.raises(ValueError, match="Incomplete"):
        await tools._delete_protect_backup(client, Registry(), "console", BACKUP_ID)
    client.delete.assert_not_awaited()


async def test_list_is_one_request_with_no_invented_paging_params():
    client = client_for(None)
    await tools._list_protect_backups(client, Registry(), "console")
    client.get.assert_awaited_once_with(PREFIX + "/backups", key=None)


@pytest.mark.parametrize("limit", [None, -1, 0, 1000000])
async def test_history_limit_forwarded_unchanged_and_never_defaulted(limit):
    client = client_for(fixture("history.json"))
    result = await tools._get_protect_automation_history(
        client, Registry(), "console", AUTOMATION_ID, limit
    )
    assert result == fixture("history.json")
    expected = None if limit is None else {"limit": limit}
    assert client.get.await_args.kwargs["params"] == expected


@pytest.mark.parametrize(
    "name,args",
    [
        ("create_protect_automation", ({},)),
        ("import_protect_backup", ({},)),
        ("update_protect_automation", (AUTOMATION_ID, {})),
        ("set_protect_notification_receivers", ({},)),
        ("start_cloud_video_archive", ({},)),
        ("connect_unifi_video_server", ({},)),
        ("delete_protect_backup", ("../x",)),
        # archive_id is a body field (a free-form selector, not a path id).
        ("cancel_cloud_archive_task", ("a\n",)),
    ],
)
async def test_invalid_input_raises_before_any_request(name, args):
    client = client_for({})
    with pytest.raises(ValueError):
        await impl(name)(client, Registry(), "console", *args)
    assert not client.mock_calls


async def test_all_22_tools_have_typed_documented_schemas():
    registered = server.mcp.list_tools()
    registered = await registered if inspect.isawaitable(registered) else registered
    by_name = {tool.name: tool for tool in registered}
    for name, _args, method, _ in CASES:
        tool = by_name[name]
        assert "host" in tool.parameters["required"]
        if method == "GET":
            assert "confirm" not in tool.parameters["properties"], name
        else:
            confirm = tool.parameters["properties"]["confirm"]
            assert confirm["type"] == "boolean", name
            assert confirm.get("default") is False, name
            assert "confirm" not in tool.parameters.get("required", []), name
            assert confirm["description"].startswith("Accepted and ignored"), name
            assert "dry-run preview" in tool.description, name
        assert "Args:" in inspect.getdoc(tool.fn)
        assert len(tool.description) <= 2048
        for parameter, schema in tool.parameters["properties"].items():
            assert schema.get("description"), (name, parameter)
        hints = tool.annotations.model_dump(by_alias=True)
        assert hints["readOnlyHint"] is (method == "GET"), name
    private = {
        name[1:]
        for name, func in vars(tools).items()
        if inspect.iscoroutinefunction(func)
        and name.startswith("_")
        and not name.startswith("__")
        and func.__module__ == tools.__name__
        and name not in ("_list", "_known")
    }
    assert private == set(IDS)


@pytest.mark.parametrize("name,args,method,route", WRITES, ids=WRITE_IDS)
async def test_confirm_is_accepted_and_ignored(monkeypatch, name, args, method, route):
    """confirm never gates: omitted, False and True all forward the same call."""
    registered = server.mcp.list_tools()
    registered = await registered if inspect.isawaitable(registered) else registered
    tool = {tool.name: tool for tool in registered}[name]
    params = [p for p in inspect.signature(tool.fn).parameters if p not in ("host", "confirm")]
    kwargs = dict(zip(params, args, strict=True))
    sentinel = object()
    deps = (AsyncMock(), Registry())
    seen = []

    async def fake(*call_args):
        seen.append(call_args)
        return sentinel

    monkeypatch.setattr(tools, f"_{name}", fake)
    monkeypatch.setattr(server, "_client", deps[0])
    monkeypatch.setattr(server, "_registry", deps[1])
    for extra in ({}, {"confirm": False}, {"confirm": True}):
        assert await tool.fn(host="console", **kwargs, **extra) is sentinel
    assert seen == [(*deps, "console", *args)] * 3


async def test_multikey_routing_rides_owning_non_first_key(multikey_client, multikey_registry):
    for label, hosts in MULTIKEY_HOSTS_BY_LABEL.items():
        await multikey_registry.set_hosts(hosts, key=multikey_client.get_key_by_label(label))
    beta_host = "console-beta-1"
    multikey_registry.resolve_host_id = AsyncMock(return_value=beta_host)
    base = PROTECT_PRIVATE_BASE.format(host_id=beta_host)
    try:
        async with respx.mock(base_url="https://api.ui.com") as mock:
            listed = mock.get(f"{base}/backups").mock(
                return_value=Response(200, json=fixture("backups.json"))
            )
            result = await tools._list_protect_backups(
                multikey_client, multikey_registry, "Beta-Branch"
            )
        assert result == fixture("backups.json")
        assert listed.calls.last.request.headers["X-API-KEY"] == "k-beta"
    finally:
        await multikey_client.close()


@pytest.mark.parametrize(
    "route",
    ["backups/import", "backups/backup-1/download", "backups/backup-1/export", "backups"],
)
def test_backup_route_secrets_are_listed_and_masked_only_on_opt_in(route):
    sentinel = "synthetic-backup-credential-sentinel-0123456789"
    body = {
        "config": {
            "credentials": {"password": sentinel},
            "privateKey": sentinel,
            "tokens": [sentinel],
        },
        "native": 42,
    }
    path = PREFIX + "/" + route
    assert sentinel in route_secrets.request_secrets("POST", path, body)
    assert sentinel in route_secrets.response_secrets("GET", path, json.dumps(body).encode(), [])
    assert route_secrets.mask_response_body("GET", path, body, redact_secrets=False) is body
    masked = route_secrets.mask_response_body("GET", path, body, redact_secrets=True)
    assert sentinel not in json.dumps(masked)
    assert masked["native"] == 42


def test_cloud_archive_code_argument_is_a_registered_secret():
    entry = next(
        e for e in route_secrets.ROUTE_SECRETS if e.name == "protect-cloud-archive-credentials"
    )
    assert entry.tool_arguments["connect_cloud_archive_provider"] == ("code",)


# --------------------------------------------------------------- Protect 7.3.74 backup routes
# Observed live on Protect 7.3.74 (2026-10-28): the per-backup routes are registered as
# /backup{s}/:id and only the singular form reaches the handler. DELETE /backups/{id}
# answers 404 with an empty body for every backup; DELETE /backup/{id} answers 200
# {"success": true} and the backup is gone from GET /backups.

LIVE_BACKUP_ID = "000000000000000000000b02"
LIVE_BACKUPS = [
    {"type": "auto", "id": "000000000000000000000b01", "isAutoBackup": True},
    {"type": "manual", "id": LIVE_BACKUP_ID, "isAutoBackup": False},
]


def _live_backup_upstream(mock: Any, *, delete_takes_effect: bool = True) -> dict[str, Any]:
    state = {"listed": [dict(row) for row in LIVE_BACKUPS]}
    base = "/v1/connector/consoles/host-1/proxy/protect/api"

    def delete_singular(request):
        if delete_takes_effect:
            state["listed"] = [row for row in state["listed"] if row["id"] != LIVE_BACKUP_ID]
        return Response(200, json={"success": True})

    mock.get(base + "/backups").mock(
        side_effect=lambda request: Response(200, json=state["listed"])
    )
    mock.delete(base + f"/backups/{LIVE_BACKUP_ID}").mock(return_value=Response(404))
    mock.delete(base + f"/backup/{LIVE_BACKUP_ID}").mock(side_effect=delete_singular)
    return state


async def test_delete_backup_uses_the_singular_route_protect_7_3_serves():
    from unifi_fabric.client import UniFiClient
    from unifi_fabric.config import Settings

    client = UniFiClient(Settings(api_key="synthetic-test-key"))
    try:
        with respx.mock(base_url="https://api.ui.com", assert_all_called=False) as mock:
            state = _live_backup_upstream(mock)
            result = await tools._delete_protect_backup(
                client, Registry(), "console", LIVE_BACKUP_ID
            )
            deletes = [c.request.url.path for c in mock.calls if c.request.method == "DELETE"]
    finally:
        await client.close()
    assert deletes == [PREFIX + f"/backup/{LIVE_BACKUP_ID}"]
    assert result == {
        "deleted": True,
        "message": f"Backup {LIVE_BACKUP_ID} deleted.",
        "response": {"success": True},
    }
    assert [row["id"] for row in state["listed"]] == ["000000000000000000000b01"]


async def test_delete_backup_still_listed_after_the_delete_reports_not_deleted():
    from unifi_fabric.client import UniFiClient
    from unifi_fabric.config import Settings

    client = UniFiClient(Settings(api_key="synthetic-test-key"))
    try:
        with respx.mock(base_url="https://api.ui.com", assert_all_called=False) as mock:
            _live_backup_upstream(mock, delete_takes_effect=False)
            result = await tools._delete_protect_backup(
                client, Registry(), "console", LIVE_BACKUP_ID
            )
    finally:
        await client.close()
    assert result["deleted"] is False
    assert result["message"] == (
        f"Backup {LIVE_BACKUP_ID} is still listed by list_protect_backups after the DELETE; "
        "it was not deleted."
    )
    assert result["response"] == {"success": True}


async def test_delete_backup_failed_read_back_is_unconfirmed_not_success():
    client = client_for({"success": True})
    listed = fixture("backups.json")
    client.get.side_effect = [listed, RuntimeError("probe read-back failure")]
    result = await tools._delete_protect_backup(client, Registry(), "console", BACKUP_ID)
    assert result["deleted"] is None
    assert "unconfirmed" in result["message"]
    assert result["readAfterError"] == "RuntimeError: probe read-back failure"
    assert result["response"] == {"success": True}


async def test_restore_backup_uses_the_singular_route_protect_7_3_serves():
    from unifi_fabric.client import UniFiClient
    from unifi_fabric.config import Settings

    client = UniFiClient(Settings(api_key="synthetic-test-key"))
    base = "/v1/connector/consoles/host-1/proxy/protect/api"
    try:
        with respx.mock(base_url="https://api.ui.com", assert_all_called=False) as mock:
            plural = mock.post(base + f"/backups/{LIVE_BACKUP_ID}/restore").mock(
                return_value=Response(404)
            )
            singular = mock.post(base + f"/backup/{LIVE_BACKUP_ID}/restore").mock(
                return_value=Response(200, json={"success": True})
            )
            result = await tools._restore_protect_backup(
                client, Registry(), "console", LIVE_BACKUP_ID
            )
    finally:
        await client.close()
    assert not plural.called and singular.call_count == 1
    assert result == {"success": True}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "function,arg,hint",
    [
        (tools._get_cloud_archive_status, "google-drive", "provider"),
        (tools._import_unifi_video_cameras, "192.0.2.10", "shared drives"),
    ],
)
async def test_cloud_read_failure_has_context_and_preserves_upstream(function, arg, hint):
    from unifi_fabric.client import UniFiConnectionError

    client = AsyncMock()
    error = UniFiConnectionError("complete upstream failure", status=500)
    client.get.side_effect = error
    with pytest.raises(UniFiConnectionError) as caught:
        await function(client, Registry(), "host-1", arg)
    assert caught.value is error
    assert str(caught.value).startswith("complete upstream failure -- Hint: ")
    assert hint in str(caught.value)
    assert caught.value.status == 500


def test_cloud_archive_status_stays_a_read_with_an_honest_description():
    # The authorize GET is a read that stays usable in read-only mode; a live check
    # answered HTTP 500 with no write recorded.
    import asyncio

    from fastmcp import FastMCP

    from unifi_fabric.families.protect import protect_automation_backup as pab

    mcp = FastMCP("t")
    pab.register(mcp, lambda: (None, None))
    tool = asyncio.run(mcp.get_tool("get_cloud_archive_status"))
    assert tool.annotations.readOnlyHint is True
    assert "authorize endpoint" in tool.description
    assert "changes no" in tool.description


# Protect 7.x serves the staged foreign-dump restore at nvr/restore-database-backup; the
# 5.x nvr/restore-pg-dump route is gone (same server handler, moved).
RESTORE_DB_ROUTE = "/nvr/restore-database-backup"
OLD_RESTORE_DB_ROUTE = "/nvr/restore-pg-dump"
NO_DUMP_BODY = '{"name":"BAD_REQUEST","message":"Foreign Postgres dump file not detected."}'


async def test_restore_database_posts_the_7x_route_once_without_a_body():
    from unifi_fabric.client import UniFiClient
    from unifi_fabric.config import Settings

    client = UniFiClient(Settings(api_key="synthetic-test-key"))
    try:
        with respx.mock(base_url="https://api.ui.com", assert_all_called=False) as mock:
            old = mock.post(PREFIX + OLD_RESTORE_DB_ROUTE).mock(return_value=Response(404))
            new = mock.post(PREFIX + RESTORE_DB_ROUTE).mock(
                return_value=Response(200, json={"success": True})
            )
            result = await tools._restore_protect_database(client, Registry(), "console")
    finally:
        await client.close()
    assert not old.called and new.call_count == 1
    request = new.calls.last.request
    assert request.method == "POST"
    assert request.content == b""
    assert result == {"success": True}


async def test_restore_database_passes_the_no_dump_400_through_verbatim():
    # No foreign Postgres dump staged: Protect answers 400. The upstream body reaches the
    # caller whole and unrewritten, and the write is not retried.
    from unifi_fabric.client import UniFiClient, UniFiConnectionError
    from unifi_fabric.config import Settings

    client = UniFiClient(Settings(api_key="synthetic-test-key"))
    try:
        with respx.mock(base_url="https://api.ui.com", assert_all_called=False) as mock:
            new = mock.post(PREFIX + RESTORE_DB_ROUTE).mock(
                return_value=Response(400, text=NO_DUMP_BODY)
            )
            with pytest.raises(UniFiConnectionError) as caught:
                await tools._restore_protect_database(client, Registry(), "console")
    finally:
        await client.close()
    assert new.call_count == 1
    assert caught.value.status == 400
    assert NO_DUMP_BODY in str(caught.value)


async def test_restore_database_is_a_destructive_write_with_an_honest_description():
    from unifi_fabric._read_only_audit import derive_write_tools

    registered = server.mcp.list_tools()
    registered = await registered if inspect.isawaitable(registered) else registered
    by_name = {tool.name: tool for tool in registered}
    tool = by_name["restore_protect_database"]
    hints = tool.annotations.model_dump(by_alias=True)
    assert hints["readOnlyHint"] is False and hints["destructiveHint"] is True
    assert "restore_protect_database" in derive_write_tools(list(by_name.values()))
    text = " ".join(tool.description.split())
    assert "POST protect/api/nvr/restore-database-backup with no body" in text
    assert "foreign Postgres dump" in text and "restarts Protect" in text
    assert "HTTP 400" in text and "not run against a console" in text
    assert "Foreign Postgres dump file not detected" not in text
    assert "restore-pg-dump" not in text
