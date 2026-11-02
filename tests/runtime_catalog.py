"""The runtime catalog size: the one source every tool-count assertion compares to.

A literal count in a test goes stale whenever a lane adds or removes a tool; the
registered catalog (the same list ``scripts/gen_tools_doc.py`` documents) is the truth.
Call this at module import time, outside any running event loop.
"""

from __future__ import annotations

import asyncio


def runtime_tool_count() -> int:
    """The number of tools the FastMCP runtime registers."""
    from scripts.gen_tools_doc import _runtime_tools

    return len(asyncio.run(_runtime_tools()))
