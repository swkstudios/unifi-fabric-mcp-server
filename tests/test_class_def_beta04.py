"""P04: arguments a form ignores, and an empty event list, are refused before any request."""

from __future__ import annotations

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh


async def _refused(monkeypatch, tool, **override):
    up = uh.FakeUpstream()
    args = {**tool_args.generated_args(cti.TOOLS[tool]), **override}
    with pytest.raises(ToolError, match="Protect events and cases arguments"):
        await cti._call(monkeypatch, tool, up, args=args)
    assert up.served == [], [s.path for s in up.served]


async def test_favorite_refuses_an_empty_event_list(monkeypatch):
    await _refused(monkeypatch, "set_protect_event_favorite", event_ids=[])


async def test_favorite_refuses_objects_with_one_event_id(monkeypatch):
    await _refused(
        monkeypatch,
        "set_protect_event_favorite",
        event_ids=uh.ARG_ID,
        objects=[{"eventId": uh.ARG_ID, "objectId": uh.ARG_ID}],
    )


async def test_favorite_refuses_object_id_with_a_list(monkeypatch):
    await _refused(
        monkeypatch, "set_protect_event_favorite", event_ids=[uh.ARG_ID], object_id=uh.ARG_ID
    )


async def test_export_prepare_refuses_export_id(monkeypatch):
    await _refused(
        monkeypatch, "export_protect_case", action="prepare", case_id=uh.ARG_ID, export_id=uh.ARG_ID
    )


async def test_export_download_refuses_case_id(monkeypatch):
    await _refused(
        monkeypatch,
        "export_protect_case",
        action="download",
        case_id=uh.ARG_ID,
        export_id=uh.ARG_ID,
    )


@pytest.mark.parametrize(
    ("tool", "override"),
    [
        ("create_protect_case", {"summary": "typed", "fields": {"summary": "free"}}),
        ("update_protect_case", {"name": "typed", "fields": {"name": "free"}}),
        ("update_protect_case", {"active": True, "fields": {"active": False}}),
        ("add_protect_case_asset", {"fields": {"camera": uh.ARG_ID}}),
        ("add_protect_case_asset", {"fields": {"start": 1}}),
        ("add_protect_case_asset", {"note": "typed", "fields": {"note": "free"}}),
        ("update_protect_case_asset", {"note": "typed", "fields": {"note": "free"}}),
        ("update_protect_case_asset", {"asset_type": "clip", "fields": {"type": "snapshot"}}),
    ],
)
async def test_a_fields_key_a_typed_argument_sets_is_refused(monkeypatch, tool, override):
    await _refused(monkeypatch, tool, **override)
