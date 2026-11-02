"""P01: an empty camera list is refused before any request."""

from __future__ import annotations

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh


async def test_set_ai_port_pairing_refuses_an_empty_camera_list(monkeypatch):
    up = uh.FakeUpstream()
    args = {**tool_args.generated_args(cti.TOOLS["set_ai_port_pairing"]), "camera_ids": []}
    with pytest.raises(ToolError, match="camera_ids"):
        await cti._call(monkeypatch, "set_ai_port_pairing", up, args=args)
    assert up.served == [], [s.path for s in up.served]
