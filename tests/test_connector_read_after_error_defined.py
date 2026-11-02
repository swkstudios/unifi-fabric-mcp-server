"""fabric_connector_put / fabric_connector_patch define readAfterError where they use it.

The descriptions refer to readAfterError ("noOpReason unless readAfterError explains"), so
each must also say what it is, and stay under the 2,048-character connector limit.
"""

from __future__ import annotations

import pytest

from tests._tool_catalog import tools as catalog_tools

DEFINITION = "readAfterError explains a failed or non-2xx read-after."


@pytest.mark.parametrize("name", ["fabric_connector_put", "fabric_connector_patch"])
def test_read_after_error_is_defined_where_it_is_referenced(name):
    tool = next(tool for tool in catalog_tools() if tool.name == name)
    text = " ".join((tool.description or "").split())
    assert "unless readAfterError explains" in text
    assert DEFINITION in text
    assert len(tool.description or "") < 2048
