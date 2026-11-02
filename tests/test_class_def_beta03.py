"""P03: an argument the chosen action ignores is refused before any request."""

from __future__ import annotations

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh


async def test_export_edge_recording_refuses_a_window_with_download(monkeypatch):
    up = uh.FakeUpstream()
    args = {
        **tool_args.generated_args(cti.TOOLS["export_edge_recording"]),
        "action": "download",
        "filename": "edge-export.mp4",
        "start": 1760227200,
    }
    with pytest.raises(ToolError, match="start and end"):
        await cti._call(monkeypatch, "export_edge_recording", up, args=args)
    assert up.served == [], [s.path for s in up.served]


async def test_export_edge_recording_prepare_sends_the_filename(monkeypatch):
    up = uh.FakeUpstream()
    args = {
        **tool_args.generated_args(cti.TOOLS["export_edge_recording"]),
        "action": "prepare",
        "filename": "edge-export.mp4",
        "start": 1760227200,
        "end": 1760227260,
    }
    await cti._call(monkeypatch, "export_edge_recording", up, args=args)
    assert any(
        "filename=edge-export.mp4" in s.query and "start=1760227200000" in s.query
        for s in up.served
    ), [s.query for s in up.served]


async def test_export_edge_recording_download_still_sends_the_filename(monkeypatch):
    up = uh.FakeUpstream()
    args = {
        **tool_args.generated_args(cti.TOOLS["export_edge_recording"]),
        "action": "download",
        "filename": "edge-export.mp4",
    }
    await cti._call(monkeypatch, "export_edge_recording", up, args=args)
    assert any("filename=edge-export.mp4" in s.query for s in up.served), [
        s.query for s in up.served
    ]
