"""P07: an empty thumbnail list is refused before any request."""

from __future__ import annotations

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh


async def test_report_ai_false_positive_refuses_an_empty_thumbnail_list(monkeypatch):
    up = uh.FakeUpstream()
    args = {
        **tool_args.generated_args(cti.TOOLS["report_ai_false_positive"]),
        "reported_thumbnails": [],
    }
    with pytest.raises(ToolError, match="reported_thumbnails"):
        await cti._call(monkeypatch, "report_ai_false_positive", up, args=args)
    assert up.served == [], [s.path for s in up.served]
