"""N05: advertised text matches the code; no argument is silently dropped."""

from __future__ import annotations

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh


@pytest.mark.parametrize("name", ["update_dhcp_option", "update_hotspot_package"])
def test_verified_update_text_states_the_non_object_wrapping(name):
    assert "under response" in (cti.TOOLS[name].description or "")


@pytest.mark.parametrize(
    "override",
    [
        {"view": "topology", "timestamp": 1760003000, "start": 1760000000},
        {"view": "topology", "timestamp": 1760003000, "end": 1760003600},
        {"view": "logs-all", "timestamp": 1760003000},
        {"view": "timeline", "timestamp": 1760003000},
        {"view": "timestamps", "timestamp": 1760003000},
    ],
)
async def test_get_client_observability_refuses_an_argument_its_view_ignores(monkeypatch, override):
    up = uh.FakeUpstream()
    args = {**tool_args.generated_args(cti.TOOLS["get_client_observability"]), **override}
    with pytest.raises(ToolError, match="Client observability view"):
        await cti._call(monkeypatch, "get_client_observability", up, args=args)
    assert up.served == [], [s.path for s in up.served]


@pytest.mark.parametrize(
    "override",
    [
        # the generated baseline is a window view, so the snapshot view clears it
        {"view": "topology", "timestamp": 1760003000, "start": None, "end": None},
        {"view": "timeline", "start": 1760000000, "end": 1760003600},
    ],
)
async def test_get_client_observability_still_sends_the_arguments_its_view_uses(
    monkeypatch, override
):
    up = uh.FakeUpstream()
    args = {**tool_args.generated_args(cti.TOOLS["get_client_observability"]), **override}
    await cti._call(monkeypatch, "get_client_observability", up, args=args)
    assert any(not s.resolution for s in up.served)
