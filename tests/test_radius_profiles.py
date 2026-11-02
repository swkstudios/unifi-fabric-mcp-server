"""RADIUS profile update and delete: registration, id resolution before the write, dry run.

Hermetic: the in-process upstream serves synthetic Classic ``rest/radiusprofile`` records;
nothing contacts a controller. The shared record-CRUD core is covered in test_site_config*;
this file proves the two tools of ``tools/radius_profiles.py`` through the real server.
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
WRITE_TOOLS = {"update_radius_profile", "delete_radius_profile"}
BASE = {"host": uh.HOST, "site": uh.SITE, "profile_id": uh.ARG_HEX}
EXTRA = {
    "update_radius_profile": {"profile": {"name": "probe-renamed"}},
    "delete_radius_profile": {},
}


def _writes(up: uh.FakeUpstream) -> list[Any]:
    return [s for s in up.served if s.method != "GET" and not s.resolution]


def _args(name: str, **changes: Any) -> dict[str, Any]:
    return {**BASE, **EXTRA[name], **changes}


async def test_both_tools_are_registered_writes_with_documented_ids() -> None:
    tools = {tool.name: tool for tool in await server.mcp.list_tools()}
    assert WRITE_TOOLS <= set(tools)
    for name in sorted(WRITE_TOOLS):
        tool = tools[name]
        assert tool.annotations is not None and tool.annotations.read_only_hint is False, name
        assert {"host", "site", "profile_id"} <= set(tool.parameters["required"]), name
        description = tool.description or ""
        assert "list_radius_profiles" in description, name
        assert "UNIFI_DRY_RUN" in description, name
    assert "Consequence" in (tools["delete_radius_profile"].description or "")


async def test_update_resolves_the_id_in_the_list_then_puts_the_classic_record(monkeypatch) -> None:
    up = uh.FakeUpstream()
    await _call(monkeypatch, "update_radius_profile", up, _args("update_radius_profile"))
    writes = _writes(up)
    assert [w.method for w in writes] == ["PUT"], writes
    assert "/rest/radiusprofile/" in writes[0].path
    assert (writes[0].sent_json or {}).get("name") == "probe-renamed"
    # the list read that resolved the id came first
    assert any(s.method == "GET" and s.path.endswith("/rest/radiusprofile") for s in up.served)


async def test_delete_resolves_the_id_in_the_list_then_deletes_the_classic_record(
    monkeypatch,
) -> None:
    up = uh.FakeUpstream()
    result = await _call(monkeypatch, "delete_radius_profile", up, _args("delete_radius_profile"))
    writes = _writes(up)
    assert [w.method for w in writes] == ["DELETE"], writes
    assert "/rest/radiusprofile/" in writes[0].path
    assert json.dumps(result.structured_content or result.content, default=str)


@pytest.mark.parametrize("name", sorted(WRITE_TOOLS))
async def test_an_unknown_id_sends_no_write_and_lists_the_valid_ids(monkeypatch, name) -> None:
    up = uh.FakeUpstream()
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, name, up, _args(name, profile_id="0000000000000000000000ff"))
    assert _writes(up) == []
    message = str(exc.value)
    assert "0000000000000000000000ff" in message
    assert uh.ARG_HEX in message  # the valid ids are listed


@pytest.mark.parametrize("name", sorted(WRITE_TOOLS))
async def test_dry_run_previews_without_writing(monkeypatch, name) -> None:
    up = uh.FakeUpstream()
    result = await _call(monkeypatch, name, up, _args(name), env={"UNIFI_DRY_RUN": "true"})
    assert _writes(up) == []
    text = json.dumps(result.structured_content or result.content, default=str)
    assert "dry_run" in text
