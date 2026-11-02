"""N09: advertised text matches the code."""

from __future__ import annotations

import re

import pytest

from tests import test_cross_tool_invariants as cti


@pytest.mark.parametrize(
    "name",
    ["update_energy_saving_policy", "update_power_supervisor", "update_power_supervisor_link"],
)
def test_verified_update_text_states_the_non_object_wrapping(name):
    assert re.search(r"under\s+response", cti.TOOLS[name].description or "")
