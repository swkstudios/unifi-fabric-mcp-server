"""N04: a required MAC list that names nothing is refused before any request."""

from __future__ import annotations

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh


async def test_get_lte_subscription_status_refuses_an_empty_macs_list(monkeypatch):
    up = uh.FakeUpstream()
    args = tool_args.generated_args(cti.TOOLS["get_lte_subscription_status"])
    args["macs"] = []
    with pytest.raises(ToolError, match="macs"):
        await cti._call(monkeypatch, "get_lte_subscription_status", up, args=args)
    assert up.served == [], [s.path for s in up.served]


@pytest.mark.parametrize(
    ("tool", "override"),
    [
        ("set_lte_apn_profile", {"profile": {"mac": "02:00:5e:00:53:99", "apn": "internet"}}),
        ("verify_sim_pin", {"params": {"pin": "9999"}}),
        ("verify_sim_pin", {"mac": "02:00:5e:00:53:01", "params": {"mac": "02:00:5e:00:53:99"}}),
    ],
)
async def test_a_free_form_key_a_typed_argument_sets_is_refused(monkeypatch, tool, override):
    up = uh.FakeUpstream()
    args = {**tool_args.generated_args(cti.TOOLS[tool]), **override}
    with pytest.raises(ToolError, match="must not contain"):
        await cti._call(monkeypatch, tool, up, args=args)
    assert up.served == [], [s.path for s in up.served]
