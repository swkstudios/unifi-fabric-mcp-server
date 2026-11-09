"""Site administration tools: create_site, rename_site, delete_site through the real server.

Hermetic: the in-process upstream serves synthetic Classic ``self/sites`` and records the
``cmd/sitemgr`` commands; nothing contacts a controller. Creating and deleting a site only
work on multi-site consoles (see the module docstring), so the live behaviour stays
unverified and these tests pin the request shapes and the id resolution before the write.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import upstream_harness as uh
from unifi_fabric import server

_call = cti._call
SITE_TOOLS = {"create_site", "rename_site", "delete_site"}
BASE = {"host": uh.HOST, "site": uh.SITE}


def _commands(up: uh.FakeUpstream) -> list[Any]:
    return [s for s in up.served if s.method == "POST" and s.path.endswith("/cmd/sitemgr")]


def _text(result: Any) -> str:
    return json.dumps(result.structured_content or result.content, default=str)


async def test_the_three_tools_are_registered_writes_naming_the_multi_site_limit() -> None:
    tools = {tool.name: tool for tool in await server.mcp.list_tools()}
    assert SITE_TOOLS <= set(tools)
    for name in sorted(SITE_TOOLS):
        tool = tools[name]
        assert tool.annotations is not None and tool.annotations.read_only_hint is False, name
        assert {"host", "site"} <= set(tool.parameters["required"]), name
        assert "dry-run policy" in (tool.description or ""), name
    assert "site_to_delete" in tools["delete_site"].parameters["required"]
    assert "Consequence" in (tools["delete_site"].description or "")


@pytest.mark.parametrize(
    ("name", "command"), [("create_site", "add-site"), ("rename_site", "update-site")]
)
async def test_create_and_rename_post_the_sitemgr_command_with_the_description(
    monkeypatch, name, command
) -> None:
    up = uh.FakeUpstream()
    await _call(monkeypatch, name, up, {**BASE, "description": "Branch office"})
    sent = _commands(up)
    assert len(sent) == 1, up.served
    assert sent[0].sent_json == {"cmd": command, "desc": "Branch office"}


async def test_delete_resolves_the_site_in_the_console_list_then_sends_its_id(
    monkeypatch,
) -> None:
    up = uh.FakeUpstream()
    result = await _call(monkeypatch, "delete_site", up, {**BASE, "site_to_delete": uh.ARG_HEX})
    sent = _commands(up)
    assert len(sent) == 1, up.served
    assert sent[0].sent_json == {"cmd": "delete-site", "site": uh.ARG_HEX}
    listing = [s for s in up.served if s.method == "GET" and s.path.endswith("/self/sites")]
    assert listing and up.served.index(listing[0]) < up.served.index(sent[0])
    assert "deleted" in _text(result)


async def test_delete_of_an_unknown_site_sends_no_command_and_lists_the_sites(monkeypatch) -> None:
    up = uh.FakeUpstream()
    with pytest.raises(ToolError) as exc:
        await _call(
            monkeypatch,
            "delete_site",
            up,
            {**BASE, "site_to_delete": "0000000000000000000000ff"},
        )
    assert _commands(up) == []
    assert "not found by _id, name or display name" in str(exc.value)


@pytest.mark.parametrize(
    ("name", "extra"),
    [
        ("create_site", {"description": "Branch office"}),
        ("rename_site", {"description": "Branch office"}),
        ("delete_site", {"site_to_delete": uh.ARG_HEX}),
    ],
)
async def test_dry_run_previews_without_sending_the_command(monkeypatch, name, extra) -> None:
    up = uh.FakeUpstream()
    result = await _call(
        monkeypatch, name, up, {**BASE, **extra}, env={"UNIFI_WRITE_POLICY": "dry-run"}
    )
    assert _commands(up) == []
    assert "dry_run" in _text(result)
