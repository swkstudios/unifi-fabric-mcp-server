"""IS2: an empty list and a doubly named mode are refused before any request."""

from __future__ import annotations

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh


async def _refused(monkeypatch, tool, **override):
    up = uh.FakeUpstream()
    args = {**tool_args.generated_args(cti.TOOLS[tool]), **override}
    with pytest.raises(ToolError, match="InnerSpace arguments"):
        await cti._call(monkeypatch, tool, up, args=args)
    assert up.served == [], [s.path for s in up.served]


async def test_import_innerspace_captures_refuses_an_empty_list(monkeypatch):
    await _refused(monkeypatch, "import_innerspace_captures", captures=[])


async def test_reorder_innerspace_plans_refuses_an_empty_list(monkeypatch):
    await _refused(monkeypatch, "reorder_innerspace_plans", plans=[])


async def test_transform_innerspace_shapes_refuses_mode_given_twice(monkeypatch):
    await _refused(
        monkeypatch,
        "transform_innerspace_shapes",
        transform={"ids": ["shape-1"], "mode": "2D"},
        mode="3D",
    )
