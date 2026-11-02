"""NC: an empty QoS batch list is refused before any request."""

from __future__ import annotations

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh


@pytest.mark.parametrize("name", ["delete_qos_rule", "reorder_qos_rules"])
async def test_an_empty_batch_list_is_refused_before_any_request(monkeypatch, name):
    up = uh.FakeUpstream()
    args = {**tool_args.generated_args(cti.TOOLS[name]), "body": []}
    with pytest.raises(ToolError, match="empty list"):
        await cti._call(monkeypatch, name, up, args=args)
    assert up.served == [], [s.path for s in up.served]
