"""``tool_args.TOOL_ENV`` lists only environment a tool cannot be served without.

Every TOOL_ENV-driven sweep runs the listed tools under that environment only, so an
entry a tool does not need hides the shipped default from all of those sweeps. Each
entry must therefore be one the tool fails without, in the default environment.
"""

from __future__ import annotations

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh


async def _runs_in_default_env(name: str) -> tuple[bool, int]:
    """(served without error, writes sent) for ``name`` with no TOOL_ENV applied."""
    up = uh.FakeUpstream()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(tool_args, "TOOL_ENV", {})  # cti._call would apply the entry
        for variable in ("UNIFI_WRITE_POLICY", "UNIFI_WRITE_EXCEPTIONS", "UNIFI_FAMILY_ALLOW"):
            mp.delenv(variable, raising=False)
        try:
            await cti._call(mp, name, up, env={})
        except ToolError:
            return False, len(up.writes())
    return True, len(up.writes())


async def test_every_tool_env_entry_is_needed_to_serve_its_tool():
    needless = [
        name for name in sorted(tool_args.TOOL_ENV) if (await _runs_in_default_env(name))[0]
    ]
    assert needless == [], f"served in the default environment without their TOOL_ENV: {needless}"


async def test_placement_snapshot_is_served_in_the_default_environment():
    assert await _runs_in_default_env("get_unifi_placement_snapshot") == (True, 0)
