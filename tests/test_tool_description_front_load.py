"""Every tool description leads with its purpose: a first sentence, early, before details.

Clients truncate descriptions (Claude Code at 2,048 characters) and rank on the opening
words, so the first sentence must say what the tool does before any example, argument list
or return-shape text.
"""

from __future__ import annotations

import re

import pytest

FIRST_SENTENCE_LIMIT = 200
_SENTENCE = re.compile(r"^(.+?[.!?])(?=\s|$)", re.S)
_DETAIL_LEADS = (
    "Example",
    "Args:",
    "Arguments:",
    "Returns:",
    "Return type",
    "Note:",
    "Required arguments",
)


def front_load_problem(description: str) -> str | None:
    """Why ``description`` does not lead with its purpose, or None when it does."""
    text = description.strip()
    match = _SENTENCE.match(text)
    if not match:
        return "no first sentence"
    first = " ".join(match.group(1).split())
    if len(first) > FIRST_SENTENCE_LIMIT:
        return f"first sentence is {len(first)} characters (limit {FIRST_SENTENCE_LIMIT})"
    if first.startswith(_DETAIL_LEADS):
        return "opens with detail text instead of the tool's purpose"
    if not first[0].isupper():
        return "first sentence does not start with a capital letter"
    return None


def test_every_registered_tool_front_loads_its_first_sentence():
    from tests.test_tool_schema_contract import _tools

    problems = {
        tool.name: problem
        for tool in _tools()
        if (problem := front_load_problem(tool.description or ""))
    }
    assert not problems, problems


def test_every_discovery_meta_tool_front_loads_its_first_sentence():
    import asyncio

    from unifi_fabric.discovery import META_TOOLS
    from unifi_fabric.server import mcp

    tools = {tool.name: tool for tool in asyncio.run(mcp.list_tools())}
    present = META_TOOLS & set(tools)
    problems = {
        name: problem
        for name in present
        if (problem := front_load_problem(tools[name].description or ""))
    }
    assert not problems, problems


@pytest.mark.parametrize(
    "description",
    [
        "",
        'Example call: {"host": "my-console"}. Lists devices.',
        "Args: host. Lists devices.",
        "Returns: a list. Lists devices.",
        "lists devices for a site.",
        "List " + "very " * 60 + "many devices.",
    ],
)
def test_front_load_rule_rejects_detail_first_descriptions(description):
    assert front_load_problem(description)


def test_front_load_rule_accepts_a_purpose_first_description():
    assert front_load_problem("List adopted devices for a site. Example call: {}.") is None
    assert front_load_problem("Return the project geometry for a console.") is None
