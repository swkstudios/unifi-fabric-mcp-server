"""A call naming a tool 0.7.2 removed gets a coded error that names the replacement."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from fastmcp import Client

from unifi_fabric import server
from unifi_fabric.removed_tools import REMOVED_TOOLS, TOOL_REMOVED

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def full(_reset_server_singletons, monkeypatch):
    monkeypatch.setattr(
        server, "_settings", server.Settings(api_key="u2-unit-test-key", tool_mode="full")
    )


async def _error(name: str) -> dict:
    async with Client(server.mcp) as client:
        result = await client.call_tool(name, {}, raise_on_error=False)
    assert result.is_error
    return json.loads(result.content[0].text)["error"]


@pytest.mark.parametrize("name", sorted(REMOVED_TOOLS))
async def test_a_removed_tool_call_is_a_coded_error_naming_the_way_forward(full, name):
    error = await _error(name)
    assert error["code"] == TOOL_REMOVED
    assert name in error["message"] and "No request was sent" in error["message"]
    assert REMOVED_TOOLS[name] in error["message"]


async def test_reboot_nvr_names_its_replacement(full):
    assert "reboot_unifi_os_console" in (await _error("reboot_nvr"))["message"]


async def test_an_unknown_name_keeps_the_plain_unknown_tool_error(full):
    async with Client(server.mcp) as client:
        result = await client.call_tool("no_such_tool_xyz", {}, raise_on_error=False)
    assert result.is_error and "Unknown tool" in result.content[0].text


def test_the_map_is_the_migration_guide_table():
    guide = (ROOT / "docs" / "MIGRATING-0.7.2.md").read_text()
    for name in REMOVED_TOOLS:
        assert re.search(rf"`{name}`", guide), name
