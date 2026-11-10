"""Startup mode discovery, synthetic write status, and actionable refusals."""

import json
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest
from fastmcp import Client

from unifi_fabric import server
from unifi_fabric.client import UniFiClient, UniFiConnectionError
from unifi_fabric.config import Settings
from unifi_fabric.families.carrier import carrier_fabric
from unifi_fabric.families.connector import connector
from unifi_fabric.families.mobility import mobility
from unifi_fabric.families.protect import protect


@pytest.mark.parametrize(
    "read_only,dry_run", [(False, False), (True, False), (False, True), (True, True)]
)
async def test_initialize_instructions_report_actual_modes(monkeypatch, read_only, dry_run):
    expected = "deny" if read_only else "dry-run" if dry_run else "allow"
    if expected != "allow":
        monkeypatch.setenv("UNIFI_WRITE_POLICY", expected)
    settings = Settings(api_key="synthetic-unit-key")
    monkeypatch.setattr(server, "get_settings", lambda: settings)
    monkeypatch.setattr(server.policy, "apply_exposure", AsyncMock(return_value=[]))
    async with Client(server.mcp, mode="legacy") as client:
        result = await client.initialize()
        instructions = result.instructions
        assert f"UNIFI_WRITE_POLICY={expected}." in instructions
        assert "Current deployment:" in instructions
        assert len(instructions) <= 2048


async def test_suppressed_write_preview_has_top_level_status(monkeypatch):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "dry-run")
    client = UniFiClient(Settings(api_key="synthetic-unit-key"))
    try:
        preview = await client.post("/v1/unit", json={"name": "unit"})
        assert preview["status"] == "dry_run"
        assert preview["dryRun"] is True
    finally:
        await client.close()


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "GET"])
async def test_timeout_write_hint_and_no_transport_retry(monkeypatch, method):
    client = UniFiClient(Settings(api_key="synthetic-unit-key"))
    transport = AsyncMock()
    transport.request.side_effect = httpx.ReadTimeout("synthetic timeout")
    monkeypatch.setattr(client, "_get_client", AsyncMock(return_value=transport))
    try:
        with pytest.raises(UniFiConnectionError) as caught:
            await client.request(method, "/v1/unit")
        hint = "outcome unknown: the write may have been applied; it was not retried."
        assert (hint in str(caught.value)) is (method != "GET")
        assert transport.request.await_count == 1
    finally:
        await client.close()


@pytest.mark.parametrize(
    "message",
    [
        mobility.DISABLED_MSG,
        carrier_fabric.DISABLED_MSG,
        protect.MUTATIONS_DISABLED_REASON,
        connector.connector_write_refusal("PUT"),
    ],
)
def test_area_refusals_name_every_deployment_surface(message):
    manifest = Path(__file__).resolve().parents[1] / "plugins/claude/.claude-plugin/plugin.json"
    option = json.loads(manifest.read_text())["userConfig"]["write_policy"]["title"]
    assert option in message
    for phrase in [
        "client",
        "env",
        "plugin",
        "docker-compose",
        "Enabling / disabling connector writes",
        "docs/CONFIGURATION.md#enabling--disabling-connector-writes",
    ]:
        assert phrase in message


async def test_bad_host_and_empty_network_body_sends_no_request(monkeypatch):
    from fastmcp.exceptions import ToolError

    from tests import upstream_harness as uh

    upstream = uh.FakeUpstream()
    client = uh.install(monkeypatch, upstream)
    try:
        with pytest.raises(ToolError) as caught:
            await server.mcp.call_tool(
                "create_network", {"host": "unknown-host", "site": "default", "network_config": {}}
            )
        assert "No fields provided" in str(caught.value)
        assert "No request was sent" in str(caught.value)
        assert upstream.served == []
    finally:
        await client.close()


@pytest.mark.parametrize(
    "name", ["get_camera_snapshot", "get_thumbnail", "get_recognition_group_image"]
)
async def test_image_description_advertises_content_and_metadata(name):
    tool = await server.mcp.get_tool(name)
    assert "MCP ImageContent" in tool.description
    assert "metadata" in tool.description


@pytest.mark.parametrize("upstream", [[], {"data": [], "totalCount": 0}])
async def test_protect_event_wire_results_match_advertised_schema(monkeypatch, upstream):
    from jsonschema import validate

    monkeypatch.setattr(server, "_require", lambda: (object(), object()))
    monkeypatch.setattr(protect, "list_protect_events", AsyncMock(return_value=upstream))
    tool = await server.mcp.get_tool("list_protect_events")
    result = await server.mcp.call_tool(
        "list_protect_events",
        {
            "host": "my-console",
            "start": 1700000000,
            "end": 1700000060,
            "limit": 25,
        },
    )
    assert result.structured_content == ({"result": []} if upstream == [] else upstream)
    assert tool.output_schema is not None
    validate(result.structured_content, tool.output_schema)
