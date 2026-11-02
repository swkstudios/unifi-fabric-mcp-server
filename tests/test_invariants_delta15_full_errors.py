"""Every catalog tool preserves complete invalid caller input before any request."""

from typing import Any

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_classes import tool_batches


@tool_batches("name", lambda: sorted(cti.TOOLS))
async def test_catalog_error_echo_is_complete(monkeypatch: Any, name: str) -> None:
    value = "invalid_unknown_parameter_" + "x" * 10_000
    args = {**tool_args.generated_args(cti.TOOLS[name]), value: 1}
    up = uh.FakeUpstream()
    with pytest.raises(ToolError) as caught:
        await cti._call(monkeypatch, name, up, args=args)
    assert value in str(caught.value), name
    assert up.served == [], name
