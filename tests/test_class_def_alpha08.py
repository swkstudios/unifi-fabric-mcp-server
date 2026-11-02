"""N08: advertised text matches the code; an empty reservations list is refused."""

from __future__ import annotations

import re

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh

VERIFIED_UPDATES = [
    "update_ospf_router",
    "update_bgp_config",
    "update_global_network_config",
    "update_switch_stack",
    "manage_mclag_group",
]


@pytest.mark.parametrize("name", VERIFIED_UPDATES)
def test_verified_update_text_states_the_non_object_wrapping(name):
    assert re.search(r"under\s+response", cti.TOOLS[name].description or "")


async def test_import_dhcp_reservations_refuses_an_empty_list(monkeypatch):
    up = uh.FakeUpstream()
    args = {**tool_args.generated_args(cti.TOOLS["import_dhcp_reservations"]), "reservations": []}
    with pytest.raises(ToolError, match="reservations"):
        await cti._call(monkeypatch, "import_dhcp_reservations", up, args=args)
    assert up.served == [], [s.path for s in up.served]
