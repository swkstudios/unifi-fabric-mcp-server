"""docs/PAGINATION.md "Server-side filtering" lists exactly the registered ``filter`` tools."""

from __future__ import annotations

import asyncio
import inspect
import re
from pathlib import Path

from unifi_fabric import server

README = Path(__file__).resolve().parents[1] / "docs" / "PAGINATION.md"


def _registered_filter_tools() -> set[str]:
    res = server.mcp.list_tools()
    if inspect.isawaitable(res):
        res = asyncio.run(res)
    return {t.name for t in res if "filter" in (t.parameters.get("properties") or {})}


def _readme_filter_paragraph() -> str:
    text = README.read_text()
    match = re.search(r"#{2,3} Server-side filtering\n\n(.*?)\n\n", text, re.S)
    assert match, "docs/PAGINATION.md has no 'Server-side filtering' paragraph"
    return match.group(1)


def test_readme_filter_list_equals_the_registry():
    paragraph = _readme_filter_paragraph()
    listed = set(re.findall(r"`((?:get|list)_[a-z0-9_]+)`", paragraph))
    actual = _registered_filter_tools()
    assert listed == actual, (
        f"missing from docs/PAGINATION.md: {sorted(actual - listed)}; not registered with filter: "
        f"{sorted(listed - actual)}"
    )
    stated = re.findall(r"These (\d+) ", paragraph)
    assert stated == [str(len(actual))], f"the doc states {stated}, registry has {len(actual)}"
