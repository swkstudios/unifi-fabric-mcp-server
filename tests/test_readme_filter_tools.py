"""docs/PAGINATION.md lists exactly the registered ``filter`` tools, as a generated block.

The count and the names come from the registry (``filter-tools`` in scripts/doc_blocks.py,
rendered by scripts/gen_reference_blocks.py); this test reads the block back and compares it
with the registry by a second route, so a renderer that stopped reading the registry fails.
"""

from __future__ import annotations

import asyncio
import inspect
import re
from pathlib import Path

from tests.test_reference_blocks import gen
from unifi_fabric import server

PAGINATION = Path(__file__).resolve().parents[1] / "docs" / "PAGINATION.md"


def _registered_filter_tools() -> set[str]:
    res = server.mcp.list_tools()
    if inspect.isawaitable(res):
        res = asyncio.run(res)
    return {t.name for t in res if "filter" in (t.parameters.get("properties") or {})}


def _block() -> str:
    match = gen.doc_blocks.BLOCK_RE.search(PAGINATION.read_text())
    while match and match["name"] != "filter-tools":
        match = gen.doc_blocks.BLOCK_RE.search(PAGINATION.read_text(), match.end())
    assert match, "docs/PAGINATION.md has no filter-tools block"
    return match["body"]


def test_filter_tools_block_equals_the_registry():
    body = _block()
    listed = set(re.findall(r"`((?:get|list)_[a-z0-9_]+)`", body))
    actual = _registered_filter_tools()
    assert listed == actual, (
        f"missing from docs/PAGINATION.md: {sorted(actual - listed)}; not registered with filter: "
        f"{sorted(listed - actual)}"
    )
    assert re.findall(r"These (\d+) ", body) == [str(len(actual))]


def test_a_stale_filter_tool_count_is_reported_as_a_stale_block():
    stale = PAGINATION.read_text().replace("These 27 Network tools", "These 26 Network tools", 1)
    assert gen.stale_blocks(PAGINATION, stale) == ["filter-tools"]
