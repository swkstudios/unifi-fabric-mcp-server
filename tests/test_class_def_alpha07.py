"""N07: advertised text matches the code; empty lists and doubly named keys are refused."""

from __future__ import annotations

import re

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh


@pytest.mark.parametrize(
    "name", ["update_ipsec_settings", "update_static_dns_record", "update_wireguard_users"]
)
def test_verified_update_text_states_the_non_object_wrapping(name):
    assert re.search(r"under\s+response", cti.TOOLS[name].description or "")


async def _refused(monkeypatch, tool, **override):
    up = uh.FakeUpstream()
    args = {**tool_args.generated_args(cti.TOOLS[tool]), **override}
    with pytest.raises(ToolError):
        await cti._call(monkeypatch, tool, up, args=args)
    assert up.served == [], [s.path for s in up.served]


@pytest.mark.parametrize(
    "name", ["create_wireguard_users", "update_wireguard_users", "delete_wireguard_users"]
)
async def test_an_empty_users_list_is_refused_before_any_request(monkeypatch, name):
    await _refused(monkeypatch, name, users=[])


@pytest.mark.parametrize(
    "override",
    [
        {"name": "a", "params": {"name": "b"}},
        {"vpn_site": "a", "params": {"site": "b"}},
    ],
)
async def test_control_site_vpn_refuses_a_key_named_twice(monkeypatch, override):
    await _refused(monkeypatch, "control_site_vpn", action="enable", **override)
