"""P05: advertised text matches the code."""

from __future__ import annotations

import re

from tests import test_cross_tool_invariants as cti


def test_update_protect_automation_text_states_the_non_object_wrapping():
    assert re.search(r"under\s+response", cti.TOOLS["update_protect_automation"].description or "")
