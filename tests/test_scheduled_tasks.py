"""Classic scheduled tasks: routing, whole-record updates and verbatim responses."""

from copy import deepcopy
from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.tools.scheduled_tasks import (
    _create_scheduled_task,
    _delete_scheduled_task,
    _update_scheduled_task,
)

BASE = "/v1/connector/consoles/host-001/proxy/network/api/s/default/rest/scheduletask"
ID = "000000000000000000000001"
RECORD = {
    "_id": ID,
    "name": "zz-mcp-test-schedule",
    "action": "upgrade",
    "cron_expr": "0 0 1 1 *",
    "execute_only_once": False,
    "upgrade_targets": [{"mac": "02:00:00:00:00:01"}, {"mac": "02:00:00:00:00:02"}],
    "timezone": "UTC",
    "future": {"preserve": True},
}


@pytest.fixture
def deps():
    client = AsyncMock()
    client.dry_run = False
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = "key-two"
    registry.resolve_host_id.return_value = "host-001"
    registry.resolve_site_slug.return_value = "default"
    client.get.return_value = {"meta": {"rc": "ok"}, "data": [deepcopy(RECORD)]}
    return client, registry


async def test_invalid_id_before_resolution(deps):
    client, registry = deps
    with pytest.raises(ValueError):
        await _delete_scheduled_task(client, registry, "console", "Default", "../task")
    registry.resolve_key_for_host.assert_not_awaited()
    client.get.assert_not_awaited()


async def test_update_invalid_id_before_resolution(deps):
    client, registry = deps
    with pytest.raises(ValueError):
        await _update_scheduled_task(client, registry, "console", "Default", "../task", {})
    registry.resolve_key_for_host.assert_not_awaited()


async def test_create_keeps_body_and_response(deps):
    client, registry = deps
    body = {"name": "zz-mcp-test", "action": "future-action", "extra": [""]}
    result = await _create_scheduled_task(client, registry, "console", "Default", body)
    client.post.assert_awaited_once_with(BASE, json=body, key="key-two")
    assert result is client.post.return_value


async def test_update_preserves_targets_and_unknown_fields(deps):
    client, registry = deps
    before = deepcopy(client.get.return_value)
    result = await _update_scheduled_task(
        client, registry, "console", "Default", ID, {"name": "edited"}
    )
    client.put.assert_awaited_once_with(
        BASE + "/" + ID, json={**RECORD, "name": "edited"}, key="key-two"
    )
    assert result is client.put.return_value
    assert client.get.return_value == before


async def test_explicit_targets_replacement_and_identity(deps):
    client, registry = deps
    await _update_scheduled_task(
        client,
        registry,
        "console",
        "Default",
        ID,
        {"upgrade_targets": [], "_id": "000000000000000000000002"},
    )
    assert client.put.await_args.kwargs["json"] == {**RECORD, "upgrade_targets": []}


async def test_unknown_lookup_lists_choices_without_write(deps):
    client, registry = deps
    with pytest.raises(ValueError, match="zz-mcp-test-schedule"):
        await _delete_scheduled_task(
            client, registry, "console", "Default", "000000000000000000000003"
        )
    client.delete.assert_not_awaited()


async def test_delete_response_verbatim(deps):
    client, registry = deps
    result = await _delete_scheduled_task(client, registry, "console", "Default", ID)
    client.delete.assert_awaited_once_with(BASE + "/" + ID, key="key-two")
    assert result == {
        "deleted": True,
        "message": f"Scheduled task {ID} deleted.",
        "response": client.delete.return_value,
    }


@pytest.mark.parametrize("body", [{"meta": {"rc": "ok"}}, {"data": [None]}])
async def test_malformed_lookup_never_writes(deps, body):
    client, registry = deps
    client.get.return_value = body
    with pytest.raises(UniFiConnectionError):
        await _update_scheduled_task(client, registry, "console", "Default", ID, {"name": "edited"})
    client.put.assert_not_awaited()


async def test_count_shortfall_never_silently_truncates(deps):
    client, registry = deps
    client.get.return_value["meta"]["count"] = 2
    with pytest.raises(UniFiConnectionError, match="incomplete"):
        await _delete_scheduled_task(client, registry, "console", "Default", ID)
    client.delete.assert_not_awaited()


@pytest.mark.parametrize("operation", ["create", "update", "delete"])
async def test_real_client_dry_run_suppresses_writes(deps, operation, monkeypatch):
    from unifi_fabric.client import UniFiClient
    from unifi_fabric.config import Settings

    _, registry = deps
    registry.resolve_key_for_host.return_value = None
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "dry-run")
    client = UniFiClient(Settings())
    client.get = AsyncMock(return_value={"meta": {"rc": "ok"}, "data": [deepcopy(RECORD)]})
    if operation == "create":
        result = await _create_scheduled_task(
            client, registry, "console", "Default", {"name": "test"}
        )
    elif operation == "update":
        result = await _update_scheduled_task(
            client, registry, "console", "Default", ID, {"name": "test"}
        )
        assert result["preview"]["body"]["upgrade_targets"] == RECORD["upgrade_targets"]
    else:
        result = await _delete_scheduled_task(client, registry, "console", "Default", ID)
        # A delete returns the deletion_result dry-run shape with the preview under response.
        assert result["status"] == "dry_run" and result["deleted"] is False and result["message"]
        result = result["response"]
    assert result["dryRun"] is True
    assert (
        result["preview"]["method"]
        == {"create": "POST", "update": "PUT", "delete": "DELETE"}[operation]
    )
    await client.close()


async def test_registration_annotations_match_verbs(deps):
    from fastmcp import FastMCP

    from unifi_fabric._read_only_audit import classify_tool_verbs
    from unifi_fabric.tools.scheduled_tasks import register

    mcp = FastMCP("scheduled-tests")
    register(mcp, lambda: deps)
    tools = await mcp.list_tools()
    assert len(tools) == 3
    assert {tool.name for tool in tools} == {
        "create_scheduled_task",
        "update_scheduled_task",
        "delete_scheduled_task",
    }
    verbs = classify_tool_verbs(tools)
    assert all(verbs.values())
    for tool in tools:
        hints = tool.annotations.model_dump(by_alias=True)
        assert hints["readOnlyHint"] is (not bool(verbs[tool.name]))
        assert hints["destructiveHint"] is bool(verbs[tool.name])
