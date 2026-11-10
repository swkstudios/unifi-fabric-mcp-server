"""Discovery search ordering as observed by an AI client."""

from __future__ import annotations

import pytest
from fastmcp import Client, FastMCP

from unifi_fabric.discovery import apply_tool_mode


async def _alpha_status() -> None:
    """Retrieve a synthetic resource."""


async def _bravo_status() -> None:
    """Retrieve a synthetic resource."""


async def _charlie_status() -> None:
    """Retrieve a synthetic resource."""


TOOLS = {
    "alpha_status": _alpha_status,
    "bravo_status": _bravo_status,
    "charlie_status": _charlie_status,
}


async def _search_order(catalog_order: tuple[str, ...]) -> list[str]:
    app = FastMCP("ranking-stability")
    for name in catalog_order:
        app.tool(name=name)(TOOLS[name])
    restore = await apply_tool_mode(app, "discovery")
    try:
        async with Client(app) as client:
            rows = (
                await client.call_tool("search_tools", {"query": "synthetic"})
            ).structured_content["result"]
        return [row["name"] for row in rows]
    finally:
        restore()


@pytest.mark.asyncio
async def test_search_ranking_is_stable_when_catalog_registration_order_changes() -> None:
    """Equal-score results must not reshuffle when a server registers tools differently."""
    forward = await _search_order(("alpha_status", "bravo_status", "charlie_status"))
    reversed_order = await _search_order(("charlie_status", "bravo_status", "alpha_status"))

    assert forward == reversed_order == ["alpha_status", "bravo_status", "charlie_status"]


@pytest.mark.parametrize("prefix", ["I need to", "Help me", "i NEED to", " HELP me "])
async def test_request_framing_does_not_introduce_unrelated_help_tools(prefix: str) -> None:
    app = FastMCP("request-framing")
    app.tool(name="alpha_status")(_alpha_status)

    @app.tool()
    async def assistance() -> None:
        """Help people who need assistance."""

    restore = await apply_tool_mode(app, "discovery")
    try:
        async with Client(app) as client:
            for query in ("synthetic", f"{prefix} synthetic"):
                rows = (
                    await client.call_tool("search_tools", {"query": query})
                ).structured_content["result"]
                assert [row["name"] for row in rows] == ["alpha_status"]
    finally:
        restore()
