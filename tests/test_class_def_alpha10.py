"""N10: advertised text matches the code."""

from __future__ import annotations

import re

from tests import test_cross_tool_invariants as cti


def test_configure_wifi_wan_text_states_the_non_object_wrapping():
    assert re.search(r"under\s+response", cti.TOOLS["configure_wifi_wan"].description or "")
