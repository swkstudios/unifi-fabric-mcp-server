"""Classic device commands preserve controller bodies and exact source payloads."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.config import APIKeyConfig
from unifi_fabric.tools import device_commands as commands

BASE = "/v1/connector/consoles/host/proxy/network/api/s/default/cmd/"
SECOND_KEY = APIKeyConfig(key="second-key")
MAC = "aa:bb:cc:dd:ee:ff"


@pytest.fixture
def deps():
    client, registry = AsyncMock(), AsyncMock()
    client.dry_run = False
    registry.resolve_key_for_host.return_value = SECOND_KEY
    registry.resolve_host_id.return_value = "host"
    registry.resolve_site_slug.return_value = "default"
    registry.resolve_site_id.return_value = "11111111-0000-0000-0000-000000000001"
    client.post.return_value = json.loads(
        (
            Path(__file__).parent / "fixtures/recorded/device_commands/force_provision.json"
        ).read_text()
    )["body"]
    return client, registry


COMMAND_CASES = [
    ("provision_device", (MAC,), "devmgr", {"cmd": "force-provision", "macs": [MAC]}),
    ("upgrade_all_devices", ("usw",), "devmgr/upgrade-all", {"type": "usw"}),
    ("start_rolling_upgrade", (["uap", "usw"],), "devmgr/set-rollupgrade", ["uap", "usw"]),
    ("cancel_rolling_upgrade", (), "devmgr", {"cmd": "unset-rollupgrade"}),
    ("list_device_firmware", (True,), "firmware", {"cmd": "list-cached"}),
    ("run_speedtest", (), "devmgr", {"cmd": "speedtest"}),
    ("get_speedtest_status", (), "devmgr", {"cmd": "speedtest-status"}),
    ("list_backups", (), "backup", {"cmd": "list-backups"}),
    ("create_backup", (7,), "backup", {"cmd": "backup", "days": 7}),
    ("export_site", (), "backup", {"cmd": "export-site"}),
    (
        "move_device_to_site",
        (MAC, "0123456789abcdef01234567"),
        "sitemgr",
        {"cmd": "move-device", "mac": MAC, "site": "0123456789abcdef01234567"},
    ),
    (
        "migrate_device",
        (MAC, "http://controller.example:8080/inform"),
        "devmgr",
        {
            "cmd": "migrate",
            "macs": [MAC],
            "inform_url": "http://controller.example:8080/inform",
        },
    ),
    (
        "advanced_adopt_device",
        (
            MAC,
            "192.0.2.10",
            "test-user",
            "synthetic-password",
            "http://controller.example:8080/inform",
        ),
        "devmgr",
        {
            "cmd": "adv-adopt",
            "mac": MAC,
            "ip": "192.0.2.10",
            "username": "test-user",
            "password": "synthetic-password",
            "url": "http://controller.example:8080/inform",
            "port": 22,
            "sshKeyVerify": True,
        },
    ),
    ("list_device_firmware", (False,), "firmware", {"cmd": "list-available"}),
]

#: The tools whose command is a listed read command (read_post_routes.READ_COMMANDS).
READ_TOOLS = frozenset({"list_device_firmware", "get_speedtest_status", "list_backups"})


def _recording_transport(received: list, body: object):
    import httpx

    async def upstream(request):
        received.append(request)
        return httpx.Response(200, json=body)

    return httpx.AsyncClient(
        base_url="https://example.invalid", transport=httpx.MockTransport(upstream)
    )


@pytest.mark.parametrize("name,args,route,body", COMMAND_CASES)
async def test_exact_command_body_and_verbatim_response(deps, name, args, route, body):
    client, registry = deps
    with patch.object(commands, "_device_mac", AsyncMock(return_value=MAC)):
        response = await getattr(commands, name)(client, registry, "host", "Default", *args)
    assert response is client.post.return_value
    client.post.assert_awaited_once_with(BASE + route, key=SECOND_KEY, json=body)
    registry.resolve_host_id.assert_awaited_once_with("host", key=SECOND_KEY)


async def test_timeout_appends_unknown_outcome_without_retry(deps):
    client, registry = deps
    client.post.side_effect = UniFiConnectionError(
        "Request timed out: POST route (ReadTimeout); outcome unknown; read back before retrying"
    )
    with pytest.raises(UniFiConnectionError, match="outcome unknown"):
        await commands.run_speedtest(client, registry, "host", "Default")
    assert client.post.await_count == 1


async def test_http_error_verbatim(deps):
    client, registry = deps
    error = UniFiConnectionError("HTTP 403 from route: permission denied")
    client.post.side_effect = error
    with pytest.raises(UniFiConnectionError) as raised:
        await commands.run_speedtest(client, registry, "host", "Default")
    assert raised.value is error


async def test_unknown_host_never_posts(deps):
    client, registry = deps
    registry.resolve_host_id.side_effect = ValueError("Unknown host; valid: console")
    with pytest.raises(ValueError, match="valid: console"):
        await commands.create_backup(client, registry, "missing", "Default")
    client.post.assert_not_called()


async def test_advanced_adopt_exact_body_without_adopted_lookup(deps):
    client, registry = deps
    with patch.object(commands, "_device_mac", AsyncMock()) as lookup:
        result = await commands.advanced_adopt_device(
            client,
            registry,
            "host",
            "Default",
            MAC,
            "192.0.2.10",
            "test-user",
            "synthetic-password",
            "http://controller.example:8080/inform",
        )
    assert result is client.post.return_value
    lookup.assert_not_called()
    client.post.assert_awaited_once_with(
        BASE + "devmgr",
        key=SECOND_KEY,
        json={
            "cmd": "adv-adopt",
            "mac": MAC,
            "ip": "192.0.2.10",
            "username": "test-user",
            "password": "synthetic-password",
            "url": "http://controller.example:8080/inform",
            "port": 22,
            "sshKeyVerify": True,
        },
    )


async def test_firmware_default_available(deps):
    client, registry = deps
    await commands.list_device_firmware(client, registry, "host", "Default")
    client.post.assert_awaited_once_with(
        BASE + "firmware", key=SECOND_KEY, json={"cmd": "list-available"}
    )


async def test_no_partial_rolling_array(deps):
    client, registry = deps
    await commands.start_rolling_upgrade(client, registry, "host", "Default")
    assert client.post.await_args.kwargs["json"] == ["uap", "usw", "ugw", "uxg"]


@pytest.mark.parametrize("destination", ["wrong/name", "../site", "site with spaces", "東京"])
async def test_body_only_destination_is_preserved(deps, destination):
    client, registry = deps
    with patch.object(commands, "_device_mac", AsyncMock(return_value=MAC)):
        await commands.move_device_to_site(client, registry, "host", "Default", MAC, destination)
    assert client.post.await_args.kwargs["json"]["site"] == destination


async def test_advanced_adopt_rejects_uuid_before_dependencies(deps):
    client, registry = deps
    with pytest.raises(ValueError, match="MAC"):
        await commands.advanced_adopt_device(
            client,
            registry,
            "host",
            "Default",
            "11111111-0000-0000-0000-000000000001",
            "192.0.2.10",
            "test-user",
            "synthetic-password",
            "http://controller.example:8080/inform",
        )
    registry.resolve_key_for_host.assert_not_called()
    client.post.assert_not_called()


async def test_transport_connection_error_unchanged(deps):
    client, registry = deps
    error = UniFiConnectionError("Connection failed: POST route (ConnectError)")
    client.post.side_effect = error
    with pytest.raises(UniFiConnectionError) as raised:
        await commands.create_backup(client, registry, "host", "Default")
    assert raised.value is error
    assert client.post.await_count == 1


async def test_registered_tools_are_write_classified(deps):
    from types import SimpleNamespace

    from unifi_fabric._read_only_audit import derive_write_tools

    tools = []

    class MCP:
        def tool(self, **kwargs):
            def decorator(fn):
                tools.append(SimpleNamespace(name=fn.__name__, fn=fn))
                return fn

            return decorator

    commands.register(MCP(), lambda: deps)
    assert len(tools) == 13
    names = {tool.name for tool in tools}
    assert READ_TOOLS < names
    assert derive_write_tools(tools) == names - READ_TOOLS


async def test_arbitrary_response_remains_verbatim(deps):
    client, registry = deps
    arbitrary = ["unwrapped", {"unusual": "body"}]
    client.post.return_value = arbitrary
    assert await commands.run_speedtest(client, registry, "host", "Default") is arbitrary


@pytest.mark.parametrize(
    "name,args,route,body",
    COMMAND_CASES,
)
async def test_real_client_dry_run_all_commands(deps, name, args, route, body):
    from unifi_fabric.client import UniFiClient
    from unifi_fabric.config import Settings

    _, registry = deps
    registry.resolve_key_for_host.return_value = None
    client = UniFiClient(Settings(api_key="synthetic-test-api-key", dry_run=True))
    if name in READ_TOOLS:
        # A read command is a read: dry-run sends it once and returns the body verbatim.
        received: list = []
        envelope = {"meta": {"rc": "ok"}, "data": [{"read": name}]}
        transport = _recording_transport(received, envelope)
        client._get_client = AsyncMock(return_value=transport)
        result = await getattr(commands, name)(client, registry, "host", "Default", *args)
        assert result == envelope
        assert [(r.method, r.url.path) for r in received] == [("POST", BASE + route)]
        assert json.loads(received[0].content) == body
        await transport.aclose()
        await client.close()
        return
    client._get_client = AsyncMock(side_effect=AssertionError("must not open transport"))
    with patch.object(commands, "_device_mac", AsyncMock(return_value=MAC)):
        result = await getattr(commands, name)(client, registry, "host", "Default", *args)
    assert result["dryRun"] is True
    assert result["preview"]["method"] == "POST"
    assert result["preview"]["path"] == BASE + route
    assert result["preview"]["body"] == body
    client._get_client.assert_not_awaited()
    await client.close()


@pytest.mark.parametrize(
    "name,args,route,body",
    COMMAND_CASES,
)
async def test_real_client_read_only_all_commands(deps, monkeypatch, name, args, route, body):
    from unifi_fabric.client import UniFiClient
    from unifi_fabric.config import Settings
    from unifi_fabric.read_only import ReadOnlyModeError

    monkeypatch.setenv("UNIFI_READ_ONLY", "1")
    _, registry = deps
    registry.resolve_key_for_host.return_value = None
    client = UniFiClient(Settings(api_key="synthetic-test-api-key", dry_run=True))
    if name in READ_TOOLS:
        # A read command is a read: read-only mode sends it once, body verbatim.
        received: list = []
        envelope = {"meta": {"rc": "ok"}, "data": [{"read": name}]}
        transport = _recording_transport(received, envelope)
        client._get_client = AsyncMock(return_value=transport)
        result = await getattr(commands, name)(client, registry, "host", "Default", *args)
        assert result == envelope
        assert [(r.method, r.url.path) for r in received] == [("POST", BASE + route)]
        assert json.loads(received[0].content) == body
        await transport.aclose()
        await client.close()
        return
    client._get_client = AsyncMock(side_effect=AssertionError("must not open transport"))
    with patch.object(commands, "_device_mac", AsyncMock(return_value=MAC)):
        with pytest.raises(ReadOnlyModeError):
            await getattr(commands, name)(client, registry, "host", "Default", *args)
    client._get_client.assert_not_awaited()
    await client.close()


@pytest.mark.parametrize("destination", ["site\n", " site", "site ", "si\x00te", ""])
async def test_body_only_destination_keeps_own_selector_syntax(deps, destination):
    """Body-only, but still the server's own syntax floor: no request for a padded value."""
    client, registry = deps
    with pytest.raises(ValueError, match="destination_site_id"):
        await commands.move_device_to_site(client, registry, "host", "Default", MAC, destination)
    client.post.assert_not_awaited()


# Live on Network 11.0.97 (a dev console, site Default, 2026-10-28): the backup command
# answers {"meta": {"rc": "ok"}, "data": [{"url": "/dl/backup/11.0.97.unf"}]}; list_backups
# never shows that file; export-site answers HTTP 400 api.err.BackupFailed for every body.
BACKUP_ANSWER = {"meta": {"rc": "ok"}, "data": [{"url": "/dl/backup/11.0.97.unf"}]}
EXPORT_FAILED = (
    "HTTP 400 from POST /v1/connector/consoles/host/proxy/network/api/s/default/cmd/backup: "
    '{"meta":{"rc":"error","msg":"api.err.BackupFailed"},"data":[]}'
)


def _registered_descriptions(deps):
    descriptions = {}

    class MCP:
        def tool(self, **kwargs):
            def decorator(fn):
                descriptions[fn.__name__] = fn.__doc__
                return fn

            return decorator

    commands.register(MCP(), lambda: deps)
    return descriptions


async def test_create_backup_returns_the_download_path_verbatim(deps):
    client, registry = deps
    client.post.return_value = BACKUP_ANSWER
    result = await commands.create_backup(client, registry, "host", "Default", 0)
    assert result is BACKUP_ANSWER
    assert client.post.await_args.kwargs["json"] == {"cmd": "backup", "days": 0}


def test_create_backup_says_where_the_file_is_and_what_cannot_see_it(deps):
    for text in (commands.create_backup.__doc__, _registered_descriptions(deps)["create_backup"]):
        assert "/dl/backup/" in text
        assert "transient" in text
        for tool in ("list_backups", "cancel_controller_backup", "delete_controller_backup"):
            assert tool in text


async def test_export_site_backup_failed_names_the_next_step(deps):
    client, registry = deps
    error = UniFiConnectionError(EXPORT_FAILED, request_sent=True, status=400)
    client.post.side_effect = error
    with pytest.raises(UniFiConnectionError) as raised:
        await commands.export_site(client, registry, "host", "Default")
    message = str(raised.value)
    assert message.startswith(EXPORT_FAILED)
    assert "Network application log" in message
    assert raised.value.status == 400
    assert raised.value.request_sent is True
    assert raised.value.__cause__ is error
    assert client.post.await_count == 1


async def test_export_site_other_errors_stay_verbatim(deps):
    client, registry = deps
    error = UniFiConnectionError("HTTP 403 from route: permission denied", status=403)
    client.post.side_effect = error
    with pytest.raises(UniFiConnectionError) as raised:
        await commands.export_site(client, registry, "host", "Default")
    assert raised.value is error


async def test_export_site_success_stays_verbatim(deps):
    client, registry = deps
    client.post.return_value = BACKUP_ANSWER
    assert await commands.export_site(client, registry, "host", "Default") is BACKUP_ANSWER
    assert client.post.await_args.kwargs["json"] == {"cmd": "export-site"}


def test_export_site_description_names_backup_failed(deps):
    assert "api.err.BackupFailed" in _registered_descriptions(deps)["export_site"]
