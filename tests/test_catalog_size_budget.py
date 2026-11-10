"""Proportional size budgets for the advertised tool catalog.

Three budgets keep catalog growth proportional to the tools and shapes advertised:

* PER_TOOL_AVERAGE_BUDGET_BYTES: the full catalog's UTF-8 JSON-RPC ``tools/list``
  response line over stdio must average at most 2,400 bytes per registered tool.
* PER_TOOL_BUDGET_BYTES: each tool's compact-JSON input schema stays within 10,000
  bytes, keeping any one schema from dominating the catalog.
* PER_SHAPE_BUDGET_BYTES and SHAPE_AVERAGE_BUDGET_BYTES: generated body shapes stay
  within 10,000 bytes each and average at most 2,000 bytes of compact JSON per shape.

The existing 2,048-character description cap is enforced by
``tests/test_client_surface_limits.py::
test_every_advertised_description_fits_claude_code_default_limit``.

The discovery-mode PR owns the separate merge condition
``DISCOVERY_BUDGET_BYTES = 8_000`` and its discovery catalog measurement test.
This module measures the full catalog; README count/size currency remains covered
by ``tests/test_readme_catalog_size.py``.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from tests.test_readme_catalog_size import _measure

PER_TOOL_AVERAGE_BUDGET_BYTES = 2_400
DISCOVERY_BUDGET_BYTES = 8_000
PER_TOOL_BUDGET_BYTES = 10_000
PER_SHAPE_BUDGET_BYTES = 10_000
SHAPE_AVERAGE_BUDGET_BYTES = 2_000


def _compact(value: Any) -> int:
    return len(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode())


def _input_schemas() -> dict[str, Any]:
    from fastmcp import Client

    from unifi_fabric import server

    async def listed() -> dict[str, Any]:
        async with Client(server.mcp) as client:
            return {tool.name: tool.input_schema for tool in await client.list_tools()}

    original = server._settings
    server._settings = server.Settings(api_key="size-budget-test-key", tool_mode="full")
    try:
        return asyncio.run(listed())
    finally:
        server._settings = original


def test_full_catalog_average_per_tool_is_within_budget() -> None:
    count, size = _measure(None)
    assert count > 0
    assert size <= count * PER_TOOL_AVERAGE_BUDGET_BYTES, (
        f"tools/list is {size} bytes for {count} tools; average is {size / count:.2f} "
        f"bytes/tool; ceiling is {PER_TOOL_AVERAGE_BUDGET_BYTES} bytes/tool"
    )


def test_discovery_catalog_is_within_budget() -> None:
    count, size = _measure(None, "discovery")
    from unifi_fabric.discovery import META_TOOLS

    assert count == len(META_TOOLS)
    assert size <= DISCOVERY_BUDGET_BYTES, (
        f"discovery tools/list is {size} bytes for {count} tools; "
        f"budget is {DISCOVERY_BUDGET_BYTES}"
    )


def test_generated_body_shapes_are_within_budget() -> None:
    from unifi_fabric.generated_api_facts._tool_shapes_table import TOOL_SHAPES

    shapes = [
        (f"{tool}.{arg}", _compact(shape))
        for tool, args in TOOL_SHAPES.items()
        for arg, shape in args.items()
    ]
    assert shapes
    over = {name: size for name, size in shapes if size > PER_SHAPE_BUDGET_BYTES}
    assert over == {}, f"body shapes over {PER_SHAPE_BUDGET_BYTES} bytes: {over}"
    size = sum(size for _, size in shapes)
    assert 0 < size <= len(shapes) * SHAPE_AVERAGE_BUDGET_BYTES, (
        f"body shapes total {size} bytes for {len(shapes)} shapes; "
        f"average is {size / len(shapes):.2f} bytes/shape; "
        f"ceiling is {SHAPE_AVERAGE_BUDGET_BYTES} bytes/shape"
    )


def test_no_single_input_schema_exceeds_budget() -> None:
    sizes = {name: _compact(schema) for name, schema in _input_schemas().items()}
    assert sizes
    over = {name: size for name, size in sizes.items() if size > PER_TOOL_BUDGET_BYTES}
    assert over == {}, f"input schemas over {PER_TOOL_BUDGET_BYTES} bytes: {over}"
