"""Relay refusals and hints, final review follow-up (R1 and R2 of the Opus final review)."""

from __future__ import annotations

import re

import pytest
from fastmcp import Client, FastMCP

from tests import test_cross_tool_invariants as cti
from unifi_fabric.client import unknown_outcome_hint
from unifi_fabric.read_only import read_only_message
from unifi_fabric.read_only_tools import ReadOnlyToolMiddleware, apply_read_only_tool_filter
from unifi_fabric.tool_annotations import WRITE

TOOL_NAME = re.compile(r"\b(?:fabric_connector_get|(?:get|list)_[a-z0-9_]+[a-z0-9])\b")
ACTION = "protect/api/cameras/camera/enable-control"


@pytest.mark.parametrize("read_only", [False, True])
async def test_r1_discovery_action_get_refusal_names_the_switch_that_applies(
    monkeypatch, read_only
):
    from unifi_fabric.discovery import apply_tool_mode

    monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny" if read_only else "allow")
    app = FastMCP("relay-round3")

    @app.tool(annotations=WRITE)
    async def fabric_connector_get(host: str, path: str) -> dict:
        return {"host": host, "path": path}

    app.add_middleware(ReadOnlyToolMiddleware(app))
    hidden = await apply_read_only_tool_filter(app, read_only)
    restore = await apply_tool_mode(
        app, "discovery", read_only=read_only, hidden_write_names=hidden
    )
    await apply_read_only_tool_filter(app, read_only)
    try:
        async with Client(app) as client:
            listed = {tool.name for tool in await client.list_tools()}
            assert ("call_write_tool" in listed) is not read_only
            with pytest.raises(Exception) as caught:
                await client.call_tool(
                    "call_read_tool",
                    {
                        "name": "fabric_connector_get",
                        "arguments": {"host": "synthetic-console", "path": ACTION},
                    },
                )
    finally:
        restore()
    message = str(caught.value)
    if read_only:
        # The dispatcher the old text pointed at is not listed in read-only mode.
        assert read_only_message("fabric_connector_get", tool=True) in message
        assert "Use call_write_tool" not in message
        assert message.endswith('call_write_tool is not listed while read-only mode is on."}}')
    else:
        assert "Use call_write_tool(name='fabric_connector_get', arguments=...) instead" in message
        assert "UNIFI_WRITE_POLICY" not in message.split("instead", 1)[0]


@pytest.mark.parametrize("action", ["enable-control", "disable-control"])
def test_r2_action_get_hint_names_the_camera_read_not_the_action(action):
    path = f"/v1/connector/consoles/console-1/proxy/protect/api/cameras/cam-1/{action}"
    hint = unknown_outcome_hint(path)
    assert set(TOOL_NAME.findall(hint)) == {"get_camera", "fabric_connector_get"}
    assert {"get_camera", "fabric_connector_get"} <= set(cti.TOOLS)
    assert "(GET protect/api/cameras/cam-1, not GET protect/api/cameras/cam-1/" in hint
    assert f"{action}, which repeats the action)" in hint
    assert f"(GET protect/api/cameras/cam-1/{action}," not in hint


def test_r2_other_console_routes_keep_the_read_back_hint():
    hint = unknown_outcome_hint("/v1/connector/consoles/console-1/proxy/protect/api/cameras/cam-1")
    assert "(GET protect/api/cameras/cam-1, or its collection" in hint
    assert "repeats the action" not in hint
