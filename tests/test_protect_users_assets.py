"""P06 tools: registration, verb derivation, pass-through and verified writes."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastmcp import FastMCP

from unifi_fabric._read_only_audit import classify_tool_verbs, derive_write_tools
from unifi_fabric.client import DRY_RUN_MESSAGE
from unifi_fabric.families.protect import protect_users_assets as assets

ID = "65d4f1e2a1b2c3d4e5f60718"
READS = {
    "list_protect_device_tags",
    "get_protect_device_password",
    "get_protect_file",
    "get_ringtone",
}
ARGS = {
    "list_protect_device_tags": {},
    "create_protect_device_tag": {"tag": {"name": "mcp-gs3-p06-example"}},
    "update_protect_device_tag": {"tag_id": ID, "changes": {"settings": {"enabled": True}}},
    "delete_protect_device_tag": {"tag_id": ID},
    "create_protect_user_group": {"group": {"name": "mcp-gs3-p06-example"}},
    "update_protect_user_group": {"group_id": ID, "changes": {"settings": {"enabled": True}}},
    "delete_protect_user_group": {"group_id": ID},
    "update_protect_user": {"user_id": ID, "changes": {"settings": {"enabled": True}}},
    "set_protect_notifications_muted": {"user_id": ID, "muted": True, "valid_until": 1893456000000},
    "get_protect_device_password": {},
    "update_protect_device_password": {"device_password": "example-device-password"},
    "get_protect_file": {"file_id": ID, "asset_id": ID},
    "delete_protect_file": {"file_id": ID, "asset_id": ID},
    "upload_ringtone": {"filename": "chime.mp3", "content_base64": "SUQz"},
    "delete_ringtone": {"ringtone_id": ID},
    "get_ringtone": {"ringtone_id": ID},
    "delete_liveview": {"liveview_id": ID},
}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(
        assets, "_resolve", AsyncMock(return_value=("owning-key", "synthetic-host"))
    )
    monkeypatch.setattr(assets, "_require_mutations", lambda: None)
    record = {"id": ID, "settings": {"enabled": False, "sibling": 7}}
    return SimpleNamespace(
        dry_run=False,
        get=AsyncMock(
            return_value={
                "groups": [record],
                "users": [
                    {
                        **record,
                        "notifications": record,
                        "notificationSnoozeSettings": {"validUntil": None},
                    }
                ],
            }
        ),
        patch=AsyncMock(return_value={"upstream": "response"}),
        post=AsyncMock(return_value={"upstream": "response"}),
        delete=AsyncMock(return_value={"upstream": "response"}),
        post_multipart=AsyncMock(return_value={"upstream": "response"}),
        get_binary=AsyncMock(return_value=(b"ID3", "audio/mpeg")),
    )


async def tools_for(client):
    mcp = FastMCP("P06 test")
    assets.register(mcp, lambda: (client, None))
    return {tool.name: tool for tool in await mcp.list_tools()}


async def test_registration_and_all_parameter_descriptions(client):
    tools = await tools_for(client)
    assert set(tools) == set(ARGS)
    assert len(tools) == 17
    for name, tool in tools.items():
        schema = tool.parameters
        assert "host" in schema["required"]
        for param, spec in schema["properties"].items():
            assert spec.get("description"), (name, param)
            assert "example" in spec["description"], (name, param)
        for param in ARGS[name]:
            if param not in {"valid_until", "content_type"}:
                assert param in schema["required"], (name, param)


async def test_real_server_registers_every_tool():
    from unifi_fabric import server

    assert set(ARGS) <= {tool.name for tool in await server.mcp.list_tools()}


async def test_annotations_and_write_verbs_are_derived(client):
    tools = list((await tools_for(client)).values())
    assert derive_write_tools(tools) == set(ARGS) - READS
    verbs = classify_tool_verbs(tools)
    for tool in tools:
        assert tool.annotations.read_only_hint == (tool.name in READS)
        assert bool(verbs[tool.name]) == (tool.name not in READS)


@pytest.mark.parametrize("name", ARGS)
async def test_every_tool_calls_the_owning_key(client, name):
    if "device_tag" in name and name != "create_protect_device_tag":
        client.get.return_value = [{"id": ID, "settings": {"enabled": False}}]
    tools = await tools_for(client)
    result = await tools[name].fn(host="Home NVR", **ARGS[name])
    assert result is not None
    called = [
        mock
        for mock in (
            client.get,
            client.patch,
            client.post,
            client.delete,
            client.post_multipart,
            client.get_binary,
        )
        if mock.await_count
    ]
    assert called
    for mock in called:
        assert all(call.kwargs["key"] == "owning-key" for call in mock.await_args_list)


@pytest.mark.parametrize("name", sorted(READS - {"get_protect_file"}))
@pytest.mark.parametrize(
    "body",
    [
        [{"devicePassword": "example-value"}],
        {"data": [], "metadata": {"complete": True}},
        "text",
        None,
        3,
    ],
)
async def test_json_readers_accept_every_json_shape_verbatim(client, name, body):
    client.get.return_value = body
    assert await getattr(assets, name)(client, None, "Home NVR", **ARGS[name]) is body


@pytest.mark.parametrize(
    "name",
    [
        "update_protect_device_tag",
        "update_protect_user_group",
        "update_protect_user",
    ],
)
async def test_empty_updates_refuse_before_resolution(client, name):
    args = {**ARGS[name], "changes": {}}
    with pytest.raises(ValueError, match="No fields provided"):
        await getattr(assets, name)(client, None, "Home NVR", **args)
    assets._resolve.assert_not_awaited()
    client.get.assert_not_awaited()
    client.patch.assert_not_awaited()


@pytest.mark.parametrize(
    "name",
    [
        "update_protect_device_tag",
        "update_protect_user_group",
        "update_protect_user",
    ],
)
async def test_partial_writes_preserve_siblings_and_require_strict_readback(client, name):
    before = {"id": ID, "settings": {"enabled": False, "sibling": 7}, "upstreamOnly": 9}
    after = {**before, "settings": {"enabled": 1, "sibling": 7}}
    if name == "update_protect_device_tag":
        client.get.side_effect = [[before], [after]]
    else:
        family = "groups" if name == "update_protect_user_group" else "users"

        def wrap(record):
            return {family: [record]}

        client.get.side_effect = [wrap(before), wrap(after)]
    result = await getattr(assets, name)(client, None, "Home NVR", **ARGS[name])
    expected = (
        {"settings": {"enabled": True}}
        if name in {"update_protect_user_group", "update_protect_user"}
        else {**before, "settings": {"enabled": True, "sibling": 7}}
    )
    assert client.patch.await_args.kwargs["json"] == expected
    assert result["_verified"] is False
    assert result["upstream"] == "response"


@pytest.mark.parametrize(
    "name",
    [
        "update_protect_device_tag",
        "update_protect_user_group",
        "update_protect_user",
    ],
)
async def test_matched_id_and_body_id_are_sent_in_the_upstream_spelling(client, name):
    """A caller id matched case-insensitively (matching.same_id) addresses the write, URL
    and body ``id`` alike, by the listed upstream spelling (matching.with_upstream_id)."""
    record = {"id": ID, "settings": {"enabled": False}}
    if name == "update_protect_device_tag":
        client.get.return_value = [record]
    else:
        family = "groups" if name == "update_protect_user_group" else "users"
        client.get.return_value = {family: [record]}
    id_arg = next(arg for arg in ARGS[name] if arg.endswith("_id"))
    changes = {"id": ID.upper(), "settings": {"enabled": True}}
    await getattr(assets, name)(
        client, None, "Home NVR", **{id_arg: ID.upper(), "changes": changes}
    )
    sent = client.patch.await_args
    assert ID in sent.args[0] and ID.upper() not in sent.args[0]
    assert sent.kwargs["json"]["id"] == ID
    assert ID.upper() not in repr(sent)
    assert changes["id"] == ID.upper()  # the caller's body is never mutated


@pytest.mark.parametrize("name", sorted(set(ARGS) - READS))
async def test_every_write_returns_the_complete_preview(client, name):
    client.dry_run = True
    preview = {
        "status": "dry_run",
        "dryRun": True,
        "message": DRY_RUN_MESSAGE,
        "preview": {"method": "PATCH", "path": "/example", "body": {}},
    }
    for mock in (client.patch, client.post, client.delete, client.post_multipart):
        mock.return_value = preview
    if "device_tag" in name:
        client.get.return_value = [{"id": ID, "settings": {"enabled": False}}]
    result = await (await tools_for(client))[name].fn(host="Home NVR", **ARGS[name])
    if name.startswith("delete_"):
        # A delete returns the deletion_result dry-run shape with the preview under response.
        assert set(result) == {"status", "deleted", "message", "response"}
        assert result["status"] == "dry_run" and result["deleted"] is False
        assert result["message"] == DRY_RUN_MESSAGE
        assert result["response"] is preview
    else:
        assert result is preview


async def test_unknown_tag_is_a_registered_lookup_refusal(client):
    client.get.return_value = []
    with pytest.raises(ValueError, match="valid choices"):
        await assets.delete_protect_device_tag(client, None, "Home NVR", ID)
    client.delete.assert_not_awaited()


async def test_upload_encoding_is_validated_before_resolution(client):
    with pytest.raises(ValueError, match="valid base64"):
        await assets.upload_ringtone(client, None, "Home NVR", "example.mp3", "invalid-base64!")
    assets._resolve.assert_not_awaited()


async def test_group_patch_does_not_send_readonly_bootstrap_fields(client):
    before = {
        "id": ID,
        "modelKey": "group",
        "type": "custom",
        "isDefault": False,
        "name": "before",
        "permissions": ["nvr:read:*"],
    }
    after = {**before, "name": "after"}
    client.get.side_effect = [{"groups": [before]}, {"groups": [after]}]
    result = await assets.update_protect_user_group(client, None, "Home NVR", ID, {"name": "after"})
    assert client.patch.await_args.kwargs["json"] == {"name": "after"}
    assert result["_verified"] is True


async def test_user_patch_sends_requested_settings_without_bootstrap_fields(client):
    before = {
        "id": ID,
        "modelKey": "user",
        "isOwner": True,
        "settings": {"showFeaturesIntroduction": False, "other": True},
    }
    after = {**before, "settings": {**before["settings"], "showFeaturesIntroduction": True}}
    client.get.side_effect = [{"users": [before]}, {"users": [after]}]
    result = await assets.update_protect_user(
        client, None, "Home NVR", ID, {"settings": {"showFeaturesIntroduction": True}}
    )
    assert client.patch.await_args.kwargs["json"] == {
        "settings": {"showFeaturesIntroduction": True}
    }
    assert result["_verified"] is True


async def test_confirm_descriptions_include_complete_execution_notice(client):
    for name, tool in (await tools_for(client)).items():
        confirm = tool.parameters.get("properties", {}).get("confirm")
        if confirm is not None:
            description = confirm["description"]
            assert not description.rstrip().endswith("; the"), name
            assert "call executes immediately." in description, name
