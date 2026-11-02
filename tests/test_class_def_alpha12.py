"""N12: advertised text matches the code."""

from __future__ import annotations

import re

from tests import test_cross_tool_invariants as cti


def test_update_digital_twin_layout_text_states_the_non_object_wrapping():
    assert re.search(r"under\s+response", cti.TOOLS["update_digital_twin_layout"].description or "")
