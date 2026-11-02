"""Committed catalog-wide Recall@5 baseline; query creation is rank-independent."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

import pytest
from fastmcp import Client, FastMCP

from unifi_fabric import server
from unifi_fabric.discovery import apply_tool_mode
from unifi_fabric.families import build_family_index

FIXTURES = Path(__file__).with_name("fixtures")


def test_generated_queries_do_not_embed_expected_tool_names():
    fixture = json.loads((FIXTURES / "discovery_queries.json").read_text())
    leaks = [
        row
        for row in fixture["queries"]
        if " ".join(row["expected"].split("_")).casefold() in row["query"].casefold()
    ]
    assert not leaks, leaks[:12]


async def measure_accuracy():
    fixture = json.loads((FIXTURES / "discovery_queries.json").read_text())
    app = FastMCP("discovery-accuracy")
    for tool in await server.mcp.list_tools():
        app.add_tool(tool)
    assert {t.name for t in await app.list_tools()} == set(fixture["tools"])
    counts = Counter(row["expected"] for row in fixture["queries"] if row["kind"] != "confusable")
    assert counts == Counter({name: 2 for name in fixture["tools"]})
    assert sum(row["kind"] == "confusable" for row in fixture["queries"]) >= 8
    # Every family, including families added after the baseline, is measured on at least
    # one handwritten confusable intent as well as on its generated per-tool queries.
    family = build_family_index()
    confusable_families = {
        family.get(row["expected"], "other")
        for row in fixture["queries"]
        if row["kind"] == "confusable"
    }
    assert confusable_families == set(family.values()), set(family.values()) - confusable_families
    cleanup = await apply_tool_mode(app, "discovery")
    hits = 0
    misses = []
    try:
        async with Client(app) as client:
            for row in fixture["queries"]:
                result = await client.call_tool("search_tools", {"query": row["query"], "limit": 5})
                names = [item["name"] for item in result.data]
                if row["expected"] in names:
                    hits += 1
                else:
                    misses.append({**row, "top5": names})
    finally:
        cleanup()
    return {
        "hits": hits,
        "queries": len(fixture["queries"]),
        "recall_at_5": hits / len(fixture["queries"]),
        "misses": misses,
    }


async def test_search_recall_at_5_does_not_regress():
    baseline = json.loads((FIXTURES / "discovery_accuracy_baseline.json").read_text())
    assert (
        hashlib.sha256((FIXTURES / "discovery_queries.json").read_bytes()).hexdigest()
        == baseline["query_fixture_sha256"]
    )
    result = await measure_accuracy()
    assert result["queries"] == baseline["queries"], (
        "Regenerate/review the baseline when catalog changes"
    )
    assert result["recall_at_5"] >= baseline["recall_at_5"], (
        result["recall_at_5"],
        baseline["recall_at_5"],
        result["misses"][:12],
    )


@pytest.mark.parametrize("prefix", ["I need to", "Help me"])
async def test_poll_count_collector_retains_polling_window_discoverability(prefix):
    """A count-bounded collector remains discoverable using polling-window vocabulary."""
    from unifi_fabric.discovery import SearchIndex

    catalog = {tool.name: tool for tool in await server.mcp.list_tools()}
    collector = catalog["collect_protect_events"]
    assert "bounded by `poll_count` complete polls, never by elapsed time" in collector.description
    assert "poll_count" in collector.parameters["properties"]
    assert "window_seconds" not in collector.parameters["properties"]
    index = SearchIndex(catalog, build_family_index())
    results = index.search(
        f"{prefix} this task over a bounded polling window (live-feed stand-in)",
        family=None,
        writes=None,
        write_names=set(),
        limit=5,
    )
    assert "collect_protect_events" in [row["name"] for row in results]
