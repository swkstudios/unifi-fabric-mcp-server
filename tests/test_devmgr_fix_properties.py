"""Generated regression properties for device-manager command classes."""

import json
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import quote

import pytest

from unifi_fabric.client import UniFiClient, UniFiConnectionError
from unifi_fabric.config import Settings
from unifi_fabric.tools import device_commands as commands
from unifi_fabric.tools import device_mgmt, network_services_proxy, scheduled_tasks

MAC = "02:00:5e:00:00:01"
TASK_ID = "000000000000000000000001"


def dependencies():
    client, registry = AsyncMock(), AsyncMock()
    client.dry_run = False
    registry.resolve_key_for_host.return_value = None
    registry.resolve_host_id.return_value = "console"
    registry.resolve_site_slug.return_value = "default"
    registry.resolve_site_id.return_value = "11111111-0000-0000-0000-000000000001"
    client.get.return_value = {"macAddress": MAC}
    client.post.return_value = {"meta": {"rc": "ok"}, "data": []}
    return client, registry


COMMANDS = [
    ("provision_device", (MAC,)),
    ("upgrade_all_devices", ()),
    ("start_rolling_upgrade", ()),
    ("cancel_rolling_upgrade", ()),
    ("list_device_firmware", ()),
    ("run_speedtest", ()),
    ("get_speedtest_status", ()),
    ("list_backups", ()),
    ("create_backup", ()),
    ("export_site", ()),
    ("move_device_to_site", (MAC, "site/body value")),
    ("migrate_device", (MAC, "https://example.invalid/inform")),
    (
        "advanced_adopt_device",
        (MAC, "192.0.2.1", "test-user", "synthetic-secret", "https://example.invalid/inform"),
    ),
]


@pytest.mark.parametrize("name,args", COMMANDS)
@pytest.mark.parametrize("rc", ["error", "error.Invalid", "", None])
async def test_every_command_rejects_classic_failure_verbatim(name, args, rc):
    client, registry = dependencies()
    envelope = {"meta": {"rc": rc, "msg": "controller refusal"}, "data": [], "future": [1]}
    client.post.return_value = envelope
    with patch.object(commands, "_device_mac", AsyncMock(return_value=MAC)):
        with pytest.raises(UniFiConnectionError) as raised:
            await getattr(commands, name)(client, registry, "h", "s", *args)
    text = str(raised.value)
    assert "outcome is unknown" not in text
    assert json.loads(text[text.index("{") :]) == envelope


@pytest.mark.parametrize("operation", ["list", "get", "create", "update", "delete"])
@pytest.mark.parametrize("rc", ["error", "error.Invalid", "", None])
async def test_every_scheduled_path_rejects_classic_failure(operation, rc):
    client, registry = dependencies()
    ok = {"meta": {"rc": "ok"}, "data": [{"_id": TASK_ID, "name": "task"}]}
    envelope = {"meta": {"rc": rc, "msg": "controller refusal"}, "data": [], "future": [1]}
    transport = None
    if operation in {"list", "get"}:
        import httpx

        async def upstream(request):
            return httpx.Response(200, json=envelope)

        client = UniFiClient(Settings(api_key="synthetic-scheduled-path"))
        transport = httpx.AsyncClient(
            base_url="https://example.invalid", transport=httpx.MockTransport(upstream)
        )
        client._get_client = AsyncMock(return_value=transport)
        fn = getattr(
            network_services_proxy,
            f"{operation}_scheduled_task" + ("s" if operation == "list" else ""),
        )
    else:
        client.get.return_value = ok
        target = {"create": "post", "update": "put", "delete": "delete"}[operation]
        getattr(client, target).return_value = envelope
        fn = getattr(scheduled_tasks, f"_{operation}_scheduled_task")
    args = (
        ()
        if operation == "list"
        else (({"name": "task"},) if operation == "create" else (TASK_ID,))
    )
    if operation == "update":
        args += ({"name": "edited"},)
    try:
        with pytest.raises(UniFiConnectionError) as raised:
            await fn(client, registry, "h", "s", *args)
    finally:
        if transport is not None:
            await transport.aclose()
            await client.close()
    assert json.loads(str(raised.value)[str(raised.value).index("{") :]) == envelope


@pytest.mark.parametrize(
    "operation,kwargs",
    [
        ("_restart_device", {"reboot_type": "hard"}),
        ("_upgrade_device", {}),
        ("_upgrade_device", {"firmware_url": "https://example.invalid/fw.bin"}),
    ],
)
async def test_device_mgmt_classic_paths_reject_failure(operation, kwargs):
    client, registry = dependencies()
    envelope = {"meta": {"rc": "error"}, "data": [], "extension": {"kept": True}}
    client.post.return_value = envelope
    with pytest.raises(UniFiConnectionError) as raised:
        await getattr(device_mgmt, operation)(client, registry, "h", "s", "device", **kwargs)
    text = str(raised.value)
    assert "outcome unknown" not in text
    assert json.loads(text[text.index("{") :]) == envelope


@pytest.mark.parametrize("seed", range(4))
@pytest.mark.parametrize("representation", ["raw", "repr", "bytes-repr", "escaped", "percent"])
@pytest.mark.parametrize("redact", [False, True])
async def test_adoption_secret_error_follows_opt_in_but_log_always_masks(
    seed, representation, redact, caplog, monkeypatch
):
    from unifi_fabric import server
    from unifi_fabric.secret_scrub import install_log_scrubber

    secret = f"synthetic-{seed}-pass'\\word-☃"
    forms = {
        "raw": secret,
        "repr": repr(secret),
        "bytes-repr": repr(secret.encode()),
        "escaped": secret.encode("unicode_escape").decode(),
        "percent": quote(secret, safe=""),
    }
    echoed = forms[representation]
    client, registry = dependencies()

    async def upstream(*args, **kwargs):
        logging.getLogger("unifi_fabric.devmgr.regression").warning("upstream %s", echoed)
        raise UniFiConnectionError("HTTP 400 from upstream: " + echoed)

    client.post.side_effect = upstream
    install_log_scrubber()
    monkeypatch.setattr(
        server,
        "_settings",
        Settings(api_key="synthetic-server-setting", redact_secrets=redact),
    )
    context = SimpleNamespace(message=SimpleNamespace(arguments={"password": secret}))

    async def call_next(_):
        return await commands.advanced_adopt_device(
            client,
            registry,
            "h",
            "s",
            MAC,
            "192.0.2.1",
            "user",
            secret,
            "https://example.invalid/inform",
        )

    with caplog.at_level(logging.WARNING):
        with pytest.raises(Exception) as raised:
            await server.SecretScrubMiddleware().on_call_tool(context, call_next)
    error = str(raised.value)
    if redact:
        assert secret not in error
        assert echoed not in error
        assert "***" in error
    else:
        assert echoed in error
    assert secret not in caplog.text
    assert echoed not in caplog.text
    assert "***" in caplog.text


@pytest.mark.parametrize(
    "name,args",
    [
        item
        for item in COMMANDS
        if item[0]
        in {
            "provision_device",
            "upgrade_all_devices",
            "start_rolling_upgrade",
            "cancel_rolling_upgrade",
            "move_device_to_site",
            "migrate_device",
            "advanced_adopt_device",
            "run_speedtest",
        }
    ],
)
async def test_physical_preview_has_consequence_and_actual_shape(name, args, monkeypatch):
    _, registry = dependencies()
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "dry-run")
    client = UniFiClient(Settings())
    client._get_client = AsyncMock(side_effect=AssertionError("must not open transport"))
    with patch.object(commands, "_device_mac", AsyncMock(return_value=MAC)):
        result = await getattr(commands, name)(client, registry, "h", "s", *args)
    assert result["dryRun"] is True
    assert isinstance(result["message"], str)
    assert result["preview"]["method"] == "POST"
    assert "consequence" in json.dumps(result).lower()
    # The advertised description (the tool registered in device_commands.register since
    # 354b9fe4), not the implementation helper's docstring.
    from unifi_fabric import server

    doc = (await server.mcp.get_tool(name)).description or ""
    assert "Consequence:" in doc
    assert "dry-run policy" in doc
    assert "dryRun" in doc and "message" in doc
    await client.close()


@pytest.mark.parametrize("seed", range(3))
@pytest.mark.parametrize("representation", ["raw", "repr", "bytes-repr", "escaped"])
@pytest.mark.parametrize("redact", [False, True])
async def test_direct_adoption_client_error_follows_opt_in_but_log_always_masks(
    seed, representation, redact, caplog
):
    import httpx

    from unifi_fabric.secret_scrub import install_log_scrubber

    secret = f"synthetic-direct-{seed}-pass'\\word-☃"
    forms = {
        "raw": secret,
        "repr": repr(secret),
        "bytes-repr": repr(secret.encode()),
        "escaped": secret.encode("unicode_escape").decode(),
    }
    echoed = forms[representation]

    async def upstream(request):
        logging.getLogger("unifi_fabric.devmgr.regression").warning("upstream %s", echoed)
        return httpx.Response(400, text=echoed)

    _, registry = dependencies()
    client = UniFiClient(Settings(api_key="synthetic-test-api-key", redact_secrets=redact))
    transport = httpx.AsyncClient(
        base_url="https://example.invalid", transport=httpx.MockTransport(upstream)
    )
    client._get_client = AsyncMock(return_value=transport)
    install_log_scrubber()
    with caplog.at_level(logging.WARNING):
        with pytest.raises(UniFiConnectionError) as raised:
            await commands.advanced_adopt_device(
                client,
                registry,
                "h",
                "s",
                MAC,
                "192.0.2.1",
                "user",
                secret,
                "https://example.invalid/inform",
            )
    error = str(raised.value)
    if redact:
        assert secret not in error
        assert echoed not in error
        assert "***" in error
    else:
        assert echoed in error
    assert secret not in caplog.text
    assert echoed not in caplog.text
    assert "***" in caplog.text
    await transport.aclose()
    await client.close()


@pytest.mark.parametrize("seed", range(4))
async def test_call_secret_scope_isolated_nested_and_reset(seed):
    import asyncio

    from unifi_fabric.secret_scrub import configured_secrets, secret_scope

    first, second = f"synthetic-scope-{seed}-one", f"synthetic-scope-{seed}-two"
    ready = asyncio.Event()
    finish = asyncio.Event()

    async def scoped():
        with secret_scope([first]):
            assert first in configured_secrets()
            with secret_scope([second]):
                assert {first, second} <= set(configured_secrets())
            assert second not in configured_secrets()
            ready.set()
            await finish.wait()
        assert first not in configured_secrets()

    task = asyncio.create_task(scoped())
    await ready.wait()
    assert first not in configured_secrets()
    finish.set()
    await task
    with pytest.raises(RuntimeError):
        with secret_scope([second]):
            raise RuntimeError("synthetic scope failure")
    assert second not in configured_secrets()


async def test_scheduled_registered_docs_describe_actual_preview():
    from fastmcp import FastMCP

    mcp = FastMCP("scheduled-preview-docs")
    scheduled_tasks.register(mcp, dependencies)
    tools = await mcp.list_tools()
    assert {tool.name for tool in tools} == {
        "create_scheduled_task",
        "update_scheduled_task",
        "delete_scheduled_task",
    }
    for tool in tools:
        assert "Consequence:" in tool.description
        assert "dry-run policy" in tool.description
        assert "dryRun" in tool.description and "message" in tool.description


@pytest.mark.parametrize("operation", ["create", "update"])
@pytest.mark.parametrize("field", ["password", "api_key", "token", "key"])
async def test_scheduled_freeform_secrets_are_registered_per_call(operation, field):
    from unifi_fabric.secret_scrub import configured_secrets

    secret = f"synthetic-schedule-{operation}-{field}"
    client, registry = dependencies()
    client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": TASK_ID, "name": "task"}]}

    async def upstream(*args, **kwargs):
        assert secret in configured_secrets()
        return {"meta": {"rc": "ok"}, "data": []}

    method = "post" if operation == "create" else "put"
    getattr(client, method).side_effect = upstream
    body = {"name": "task", "future": [{field: secret}]}
    if operation == "create":
        await scheduled_tasks._create_scheduled_task(client, registry, "h", "s", body)
    else:
        await scheduled_tasks._update_scheduled_task(client, registry, "h", "s", TASK_ID, body)
    assert secret not in configured_secrets()


#: The read commands each metadata tool sends: route and exact body.
METADATA_READS = {
    "list_device_firmware": ("firmware", {"cmd": "list-available"}),
    "get_speedtest_status": ("devmgr", {"cmd": "speedtest-status"}),
    "list_backups": ("backup", {"cmd": "list-backups"}),
}


@pytest.mark.parametrize(
    "name,args",
    [
        item
        for item in COMMANDS
        if item[0]
        in {
            "list_backups",
            "list_device_firmware",
            "get_speedtest_status",
        }
    ],
)
@pytest.mark.parametrize("policy", ["dry-run", "deny"])
async def test_metadata_post_reads_execute_with_safety_modes(name, args, policy, monkeypatch):
    """A metadata command (list-available, speedtest-status, list-backups) is a read: its
    exact (route, command) pair is a listed read command (read_post_routes.READ_COMMANDS), so
    under dry-run policy and under UNIFI_WRITE_POLICY alike it is sent exactly once and the
    upstream envelope is returned verbatim."""
    import httpx

    from unifi_fabric import read_only

    monkeypatch.setenv(read_only.ENV_VAR, policy)
    received = []
    envelope = {"meta": {"rc": "ok"}, "data": [{"metadata": "kept"}]}

    async def upstream(request):
        received.append(request)
        return httpx.Response(200, json=envelope)

    _, registry = dependencies()
    client = UniFiClient(Settings(api_key="synthetic-test-api-key"))
    transport = httpx.AsyncClient(
        base_url="https://example.invalid", transport=httpx.MockTransport(upstream)
    )
    client._get_client = AsyncMock(return_value=transport)
    result = await getattr(commands, name)(client, registry, "h", "s", *args)
    assert result == envelope
    assert len(received) == 1 and received[0].method == "POST"
    route, body = METADATA_READS[name]
    assert received[0].url.path == (
        f"/v1/connector/consoles/console/proxy/network/api/s/default/cmd/{route}"
    )
    assert json.loads(received[0].content) == body
    await transport.aclose()
    await client.close()


@pytest.mark.parametrize("rows", [[], [{"_id": TASK_ID, "purpose": "wan"}]])
@pytest.mark.parametrize("rc", ["error", "error.Invalid", "", None])
async def test_classic_collection_helpers_reject_failure_verbatim(rows, rc):
    from unifi_fabric.tools._classic_objects import (
        _classic_data,
        networkconf_records,
    )

    envelope = {"meta": {"rc": rc, "msg": "refusal"}, "data": rows, "future": {"kept": True}}
    with pytest.raises(UniFiConnectionError) as raised:
        _classic_data(envelope, "/api/s/default/rest/networkconf")
    assert json.loads(str(raised.value)) == envelope
    client, _ = dependencies()
    client.get.return_value = envelope
    with pytest.raises(UniFiConnectionError) as raised:
        await networkconf_records(
            client,
            "console",
            "default",
            "wan",
            key=None,
        )
    assert json.loads(str(raised.value)) == envelope


@pytest.mark.parametrize("rows", [[], [{"_id": TASK_ID, "name": "task"}]])
@pytest.mark.parametrize("rc", ["error", "error.Invalid", "", None])
async def test_write_target_lookup_rejects_classic_failure_verbatim(rows, rc):
    from unifi_fabric.tools._classic_objects import require_listed_record

    envelope = {"meta": {"rc": rc, "msg": "refusal"}, "data": rows, "future": {"kept": True}}
    client, _ = dependencies()
    client.get.return_value = envelope
    with pytest.raises(UniFiConnectionError) as raised:
        await require_listed_record(
            client,
            "/api/s/default/rest/scheduletask",
            TASK_ID,
            key=None,
            kind="scheduled task",
            list_tool="list_scheduled_tasks",
        )
    assert json.loads(str(raised.value)) == envelope


@pytest.mark.parametrize(
    "name",
    [
        "adopt_device",
        "approve_pending_device",
        "execute_device_action",
        "execute_port_action",
    ],
)
async def test_integration_physical_preview_tool_warning(monkeypatch, name):
    from tests import tool_args
    from tests import upstream_harness as uh
    from unifi_fabric import server

    upstream = uh.FakeUpstream()
    client = uh.install(monkeypatch, upstream, dry_run=True)
    try:
        result = uh.result_payload(
            await server.mcp.call_tool(
                name,
                tool_args.generated_args(
                    next(tool for tool in await server.mcp.list_tools() if tool.name == name)
                ),
            )
        )
        assert result["dryRun"] is True
        assert isinstance(result["message"], str)
        assert result["preview"]["method"] == "POST"
        assert result["_consequence"]
    finally:
        await client.close()


@pytest.mark.parametrize("field", ["password", "api_key", "token", "key"])
@pytest.mark.parametrize("representation", ["raw", "repr", "bytes-repr", "escaped"])
@pytest.mark.parametrize("through_middleware", [False, True])
async def test_stored_schedule_secret_error_scrubbed_before_scope_closes(
    field, representation, through_middleware
):
    from unifi_fabric import server
    from unifi_fabric.secret_scrub import configured_secrets

    secret = f"synthetic-stored-{field}-pass'\\word-☃"
    echoed = {
        "raw": secret,
        "repr": repr(secret),
        "bytes-repr": repr(secret.encode()),
        "escaped": secret.encode("unicode_escape").decode(),
    }[representation]
    client, registry = dependencies()
    record = {
        "_id": TASK_ID,
        "name": "task",
        "execute_only_once": False,
        "future": {field: secret},
    }
    client.get.return_value = {"meta": {"rc": "ok"}, "data": [record]}
    client.put.return_value = {"meta": {"rc": "error", "msg": echoed}, "data": []}
    patch_body = {"execute_only_once": True}

    async def update(_=None):
        return await scheduled_tasks._update_scheduled_task(
            client, registry, "h", "s", TASK_ID, patch_body
        )

    async def framework_call(context):
        from fastmcp.exceptions import ToolError

        try:
            return await update(context)
        except UniFiConnectionError as exc:
            raise ToolError(str(exc)) from None

    with pytest.raises(Exception) as raised:
        if through_middleware:
            context = SimpleNamespace(
                message=SimpleNamespace(arguments={"task_id": TASK_ID, "task": patch_body})
            )
            await server.SecretScrubMiddleware().on_call_tool(context, framework_call)
        else:
            await update()
    if through_middleware:
        from fastmcp.exceptions import ToolError

        assert isinstance(raised.value, ToolError)
    else:
        assert isinstance(raised.value, UniFiConnectionError)
    text = str(raised.value)
    decoded = json.loads(text)
    assert secret not in text
    assert echoed not in text
    assert secret not in decoded["meta"]["msg"]
    assert echoed not in decoded["meta"]["msg"]
    assert "***" in decoded["meta"]["msg"]
    assert decoded["meta"]["rc"] == "error"
    assert decoded["data"] == []
    assert client.put.await_args.kwargs["json"]["future"][field] == secret
    assert secret not in configured_secrets()


@pytest.mark.parametrize("field", ["password", "api_key", "token", "key"])
async def test_stored_schedule_secret_success_envelope_stays_verbatim(field):
    secret = f"synthetic-stored-success-{field}"
    client, registry = dependencies()
    client.get.return_value = {
        "meta": {"rc": "ok"},
        "data": [{"_id": TASK_ID, "name": "task", "future": {field: secret}}],
    }
    envelope = {"meta": {"rc": "ok"}, "data": [{"future": {field: secret}}]}
    client.put.return_value = envelope
    result = await scheduled_tasks._update_scheduled_task(
        client, registry, "h", "s", TASK_ID, {"execute_only_once": True}
    )
    assert result is envelope
    assert result["data"][0]["future"][field] == secret


@pytest.mark.parametrize("configuration", ["api_key", "api_keys", "selected-key"])
@pytest.mark.parametrize("representation", ["raw", "repr", "bytes-repr", "escaped"])
@pytest.mark.parametrize(
    "path_class", ["command", "schedule-list", "schedule-update", "networkconf"]
)
async def test_sdk_settings_key_classic_error_scrubbed(configuration, representation, path_class):
    import httpx

    from unifi_fabric.config import APIKeyConfig
    from unifi_fabric.tools._classic_objects import networkconf_records

    secret = f"synthetic-sdk-{configuration}-pass'\\word"
    echoed = {
        "raw": secret,
        "repr": repr(secret),
        "bytes-repr": repr(secret.encode()),
        "escaped": secret.encode("unicode_escape").decode(),
    }[representation]
    envelope = {"meta": {"rc": "error", "msg": echoed}, "data": []}

    async def upstream(request):
        if path_class == "schedule-update" and request.method == "GET":
            return httpx.Response(
                200, json={"meta": {"rc": "ok"}, "data": [{"_id": TASK_ID, "name": "task"}]}
            )
        return httpx.Response(200, json=envelope)

    settings = (
        Settings(api_key="synthetic-sdk-base-key")
        if configuration == "selected-key"
        else Settings(api_key=secret)
        if configuration == "api_key"
        else Settings(api_keys=[APIKeyConfig(key=secret, label="sdk-test")])
    )
    client = UniFiClient(settings)
    _, registry = dependencies()
    if configuration == "selected-key":
        registry.resolve_key_for_host.return_value = APIKeyConfig(key=secret, label="selected")

    transport = httpx.AsyncClient(
        base_url="https://example.invalid", transport=httpx.MockTransport(upstream)
    )
    client._get_client = AsyncMock(return_value=transport)
    try:
        with pytest.raises(UniFiConnectionError) as raised:
            if path_class == "command":
                await commands.run_speedtest(client, registry, "h", "s")
            elif path_class == "schedule-list":
                await network_services_proxy.list_scheduled_tasks(client, registry, "h", "s")
            elif path_class == "schedule-update":
                await scheduled_tasks._update_scheduled_task(
                    client, registry, "h", "s", TASK_ID, {"execute_only_once": True}
                )
            else:
                await networkconf_records(
                    client,
                    "console",
                    "default",
                    "wan",
                    key=registry.resolve_key_for_host.return_value,
                )
        text = str(raised.value)
        # The client's Classic rc error carries the envelope after its prefix.
        decoded = json.loads(text[text.index("{") :])
        assert secret not in text
        assert echoed not in text
        assert secret not in decoded["meta"]["msg"]
        assert echoed not in decoded["meta"]["msg"]
        assert "***" in decoded["meta"]["msg"]
        assert decoded["meta"]["rc"] == "error"
        assert decoded["data"] == []
    finally:
        await transport.aclose()
        await client.close()


@pytest.mark.parametrize("configuration", ["api_key", "api_keys", "selected-key"])
@pytest.mark.parametrize("path_class", ["command", "schedule-list", "schedule-update"])
async def test_sdk_settings_key_classic_success_follows_own_secret_policy(
    configuration, path_class
):
    """A Classic success echoing the server's own (settings or selected) key is masked.

    Central policy (integration c468687): configured server secrets never leave in any
    response, 2xx included; every other field of the envelope stays verbatim.
    """
    import httpx

    from unifi_fabric.config import APIKeyConfig
    from unifi_fabric.secret_scrub import MASK

    secret = f"synthetic-sdk-success-{configuration}"
    envelope = {"meta": {"rc": "ok"}, "data": [{"_id": TASK_ID, "key": secret}]}

    async def upstream(request):
        return httpx.Response(200, json=envelope)

    settings = (
        Settings(api_key="synthetic-sdk-base-key")
        if configuration == "selected-key"
        else Settings(api_key=secret)
        if configuration == "api_key"
        else Settings(api_keys=[APIKeyConfig(key=secret, label="sdk-test")])
    )
    client = UniFiClient(settings)
    _, registry = dependencies()
    if configuration == "selected-key":
        registry.resolve_key_for_host.return_value = APIKeyConfig(key=secret, label="selected")

    transport = httpx.AsyncClient(
        base_url="https://example.invalid", transport=httpx.MockTransport(upstream)
    )
    client._get_client = AsyncMock(return_value=transport)
    try:
        if path_class == "command":
            result = await commands.run_speedtest(client, registry, "h", "s")
        elif path_class == "schedule-list":
            result = await network_services_proxy.list_scheduled_tasks(client, registry, "h", "s")
        else:
            result = await scheduled_tasks._update_scheduled_task(
                client, registry, "h", "s", TASK_ID, {"execute_only_once": True}
            )
        assert result == {**envelope, "data": [{"_id": TASK_ID, "key": MASK}]}
    finally:
        await transport.aclose()
        await client.close()


CALLER_SECRET = "synthetic-caller-passphrase-77"
SERVER_KEY = "synthetic-server-key-0001"


def _real_client(upstream, api_key=SERVER_KEY):
    import httpx

    client = UniFiClient(Settings(api_key=api_key))
    transport = httpx.AsyncClient(
        base_url="https://example.invalid", transport=httpx.MockTransport(upstream)
    )
    client._get_client = AsyncMock(return_value=transport)
    return client, transport


@pytest.mark.parametrize("path_class", ["adopt-tool", "generic-scope"])
async def test_call_scoped_secret_never_rewrites_a_successful_response(path_class):
    """Call-scoped secrets feed error/log scrubbing only; a 2xx echo stays verbatim.

    The server's own configured key is still masked in every response (central policy),
    so the boundary is: caller-supplied credential values are upstream data on success.
    """
    import httpx

    from unifi_fabric.secret_scrub import MASK, secret_scope

    envelope = {
        "meta": {"rc": "ok"},
        "data": [{"_id": TASK_ID, "x_password": CALLER_SECRET, "echo": SERVER_KEY}],
    }

    async def upstream(request):
        return httpx.Response(200, json=envelope)

    client, transport = _real_client(upstream)
    _, registry = dependencies()
    try:
        if path_class == "adopt-tool":
            with patch.object(commands, "_device_mac", AsyncMock(return_value=MAC)):
                result = await commands.advanced_adopt_device(
                    client,
                    registry,
                    "h",
                    "s",
                    MAC,
                    "192.0.2.1",
                    "u",
                    CALLER_SECRET,
                    "https://example.invalid/inform",
                )
        else:
            with secret_scope([CALLER_SECRET]):
                result = await client.get("/proxy/network/api/s/default/stat/x")
        row = result["data"][0]
        assert row["x_password"] == CALLER_SECRET
        assert row["echo"] == MASK
    finally:
        await transport.aclose()
        await client.close()


@pytest.mark.parametrize("redact", [False, True])
async def test_call_scoped_error_response_follows_opt_in(redact):
    import httpx

    from unifi_fabric.secret_scrub import secret_scope

    async def upstream(request):
        return httpx.Response(400, json={"error": f"bad password {CALLER_SECRET}"})

    client, transport = _real_client(upstream, api_key=SERVER_KEY)
    client._settings = Settings(api_key=SERVER_KEY, redact_secrets=redact)
    try:
        with secret_scope([CALLER_SECRET]):
            with pytest.raises(Exception) as raised:
                await client.get("/proxy/network/api/s/default/stat/x")
        for form in (str(raised.value), repr(raised.value)):
            assert (CALLER_SECRET not in form) is redact
            if redact:
                assert "***" in form
            else:
                assert CALLER_SECRET in form
    finally:
        await transport.aclose()
        await client.close()
