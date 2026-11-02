"""N03: a required list that names nothing is refused before any request."""

from __future__ import annotations

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh


@pytest.mark.parametrize(
    ("name", "argument"),
    [
        ("control_device_battery", "battery_ids"),
        ("update_device_battery_settings", "battery_ids"),
        ("bulk_update_objects", "payload"),
    ],
)
async def test_an_empty_required_list_is_refused_before_any_request(monkeypatch, name, argument):
    up = uh.FakeUpstream()
    args = tool_args.generated_args(cti.TOOLS[name])
    args[argument] = []
    with pytest.raises(ToolError, match=argument):
        await cti._call(monkeypatch, name, up, args=args)
    assert up.served == [], [s.path for s in up.served]
