"""The 13 user-facing tool families, their selection lists and the route-based firewall split."""

from __future__ import annotations

import ast
import inspect
import re
import textwrap
from collections import Counter
from pathlib import Path

import pytest
from fastmcp import Client, FastMCP
from pydantic import ValidationError

from tests.test_discovery import clone_app
from unifi_fabric import families, server
from unifi_fabric._read_only_audit import _called_package_functions
from unifi_fabric.api_sources import APPS as API_SOURCE_APPS
from unifi_fabric.config import Settings
from unifi_fabric.discovery import apply_tool_mode
from unifi_fabric.families import (
    ALL_FAMILIES,
    DISABLED_TOOL_FAMILIES_ENV,
    MODULE_FAMILY,
    TOOL_FAMILIES_ENV,
    apply_tool_family_filter,
    build_family_index,
    parse_families_env,
)

ROOT = Path(__file__).resolve().parents[1]
FAMILIES = (
    "site_manager",
    "network",
    "firewall",
    "devices",
    "clients",
    "hotspot",
    "vpn",
    "statistics",
    "protect",
    "innerspace",
    "mobility",
    "carrier",
    "connector",
)
#: Internal names that are not families: module names, with and without their ``_proxy``
#: suffix (never public family names).
NOT_FAMILIES = sorted(
    (set(MODULE_FAMILY) | {module.removesuffix("_proxy") for module in MODULE_FAMILY})
    - set(ALL_FAMILIES)
)


def test_the_thirteen_families():
    assert sorted(FAMILIES) == list(ALL_FAMILIES)
    index = build_family_index()
    assert set(index.values()) == set(ALL_FAMILIES)
    assert len(NOT_FAMILIES) > 10


async def test_every_registered_tool_has_one_family():
    names = {tool.name for tool in await server.mcp.list_tools()}
    assert set(build_family_index()) == names


async def test_family_counts_match_readme_table():
    tools = await server.mcp.list_tools()
    index = build_family_index()
    counts = Counter(index[tool.name] for tool in tools)
    writes = Counter(index[tool.name] for tool in tools if not tool.annotations.read_only_hint)
    text = (ROOT / "docs" / "CONFIGURATION.md").read_text()
    rows = re.findall(r"^\| `([a-z_]+)` \| (\d+) \| (\d+) \| [A-Z][^|]* \|$", text, re.M)
    assert [row[0] for row in rows] == list(ALL_FAMILIES)
    assert {fam: (int(n), int(w)) for fam, n, w in rows} == {
        fam: (counts[fam], writes[fam]) for fam in ALL_FAMILIES
    }


@pytest.mark.parametrize(
    "value",
    [
        "network,protect",
        "network protect",
        " Network ,\tPROTECT\n",
        "NETWORK,,protect,",
        "protect   network  network",
    ],
)
async def test_lists_accept_commas_whitespace_and_any_case(value):
    assert parse_families_env(value) == {"network", "protect"}
    assert Settings(api_key="k", tool_families=value).tool_families == value
    assert Settings(api_key="k", disabled_tool_families=value).disabled_tool_families == value
    index = build_family_index()
    for allow, deny, kept in (
        (value, None, {"network", "protect"}),
        (None, value, set(ALL_FAMILIES) - {"network", "protect"}),
    ):
        app = FastMCP("families")
        for tool in await server.mcp.list_tools():
            app.add_tool(tool)
        await apply_tool_family_filter(app, allow, deny)
        assert {index[t.name] for t in await app.list_tools()} == kept


@pytest.mark.parametrize("bad", [*NOT_FAMILIES, "not-a-family", "network,unknown"])
@pytest.mark.parametrize(
    ("field", "variable"),
    [("tool_families", TOOL_FAMILIES_ENV), ("disabled_tool_families", DISABLED_TOOL_FAMILIES_ENV)],
)
async def test_unknown_names_fail_listing_the_valid_families(bad, field, variable):
    with pytest.raises(ValidationError) as error:
        Settings(api_key="k", **{field: bad})
    message = str(error.value)
    assert variable in message
    assert f"valid families: {', '.join(ALL_FAMILIES)}" in message
    unknown = [part for part in re.split(r"[\s,]+", bad) if part and part not in ALL_FAMILIES]
    assert all(f"'{part}'" not in message for part in unknown)
    app = FastMCP("families")
    allow, deny = (bad, None) if field == "tool_families" else (None, bad)
    with pytest.raises(ValueError, match=variable):
        await apply_tool_family_filter(app, allow, deny)


async def test_opt_out_list_applies_after_allowlist():
    index = build_family_index()
    app = FastMCP("families")
    for tool in await server.mcp.list_tools():
        app.add_tool(tool)
    removed = await apply_tool_family_filter(app, "network firewall", "Firewall")
    assert {index[t.name] for t in await app.list_tools()} == {"network"}
    assert {index[name] for name in removed} == set(ALL_FAMILIES) - {"network"}


def _runtime_route_literals(fn) -> set[str]:
    """Route literals over the runtime call graph the annotations are derived from."""
    literals: set[str] = set()
    seen: set[object] = set()
    stack = [fn]
    while stack:
        current = stack.pop()
        key = getattr(current, "__code__", current)
        if key in seen:
            continue
        seen.add(key)
        try:
            source = textwrap.dedent(inspect.getsource(inspect.unwrap(current)))
        except (OSError, TypeError):
            continue
        literals |= families._route_literals(ast.parse(source))
        stack.extend(_called_package_functions(current))
    return literals


async def test_firewall_is_split_by_route():
    index = build_family_index()
    tools = {tool.name: tool for tool in await server.mcp.list_tools()}
    firewall = {name for name, family in index.items() if family == "firewall"}
    runtime = {
        name
        for name, tool in tools.items()
        if any(families.is_firewall_route(lit) for lit in _runtime_route_literals(tool.fn))
    }
    # The static source index and the runtime call graph agree on every tool.
    assert firewall == runtime
    named = {n for n in tools if re.search(r"(^|_)(firewall|acl)(_|$)", n)}
    assert named <= firewall
    assert {
        "list_firewall_policies",
        "set_acl_rule_ordering",
        "list_firewall_rules",
        "get_firewall_group",
        "batch_delete_firewall_zones",
    } <= firewall
    for literal in ("/sites/1/firewall/policies", "acl-rules", "/firewallrule", "firewall/zone"):
        assert families.is_firewall_route(literal)
    for literal in ("update_firewall_policy", "/traffic-rules", "/rest/portconf"):
        assert not families.is_firewall_route(literal)


async def test_connector_switch_scope_is_derived():
    tools = {tool.name: tool for tool in await server.mcp.list_tools()}
    derived = {
        n
        for n in families.tools_referencing("CONNECTOR_WRITE_ENV")
        if not tools[n].annotations.read_only_hint
    }
    text = (ROOT / "docs" / "CONFIGURATION.md").read_text()
    sentence = text[text.index("**Scope.** `UNIFI_ENABLE_CONNECTOR_WRITE` governs") :]
    sentence = sentence[: sentence.index("All are enabled by default")]
    documented = set(re.findall(r"`(fabric_connector_[a-z]+|[a-z_]+)`", sentence)) & set(tools)
    documented = {n for n in documented if not tools[n].annotations.read_only_hint}
    assert derived == documented


async def test_list_tool_families_reports_the_thirteen():
    from unifi_fabric.discovery import apply_tool_mode

    app = FastMCP("families")
    for tool in await server.mcp.list_tools():
        app.add_tool(tool)
    index = build_family_index()
    expected = Counter(index[tool.name] for tool in await app.list_tools())
    restore = await apply_tool_mode(app, "discovery")
    try:
        async with Client(app) as client:
            rows = (await client.call_tool("list_tool_families", {})).data
            assert [row["family"] for row in rows] == list(ALL_FAMILIES)
            assert {row["family"]: row["tools"] for row in rows} == dict(expected)
            for family in ALL_FAMILIES:
                found = (
                    await client.call_tool(
                        "search_tools", {"query": "", "family": family, "limit": None}
                    )
                ).data
                assert len(found) == expected[family]
            with pytest.raises(Exception, match="valid families"):
                await client.call_tool("search_tools", {"query": "", "family": NOT_FAMILIES[0]})
    finally:
        restore()


def test_public_surfaces_name_only_the_thirteen_families():
    tools_doc = (ROOT / "docs" / "TOOLS.md").read_text()
    assert set(re.findall(r"^\*\*Family:\*\* `([a-z_]+)`$", tools_doc, re.M)) == set(ALL_FAMILIES)
    assert set(re.findall(r"^- `([a-z_]+)` \(\d+\): ", tools_doc, re.M)) >= set(ALL_FAMILIES)
    readme = (ROOT / "README.md").read_text()
    catalog = (ROOT / "docs" / "CATALOG.md").read_text()
    allow_rows = re.findall(r"^\| `([a-z_, ]+)` \| \d+ \| ~\d+ KB \|$", catalog, re.M)
    assert allow_rows
    assert all(parse_families_env(row) <= set(ALL_FAMILIES) for row in allow_rows)
    for match in re.finditer(r"UNIFI_(?:DISABLED_)?TOOL_FAMILIES: \"([^\"]+)\"", readme):
        assert parse_families_env(match.group(1)) <= set(ALL_FAMILIES)
    surfaces = [
        ROOT / "README.md",
        *sorted((ROOT / "docs").glob("*.md")),
        *sorted((ROOT / "skills").rglob("*.md")),
        *sorted((ROOT / "plugins").rglob("*.md")),
        *sorted((ROOT / "plugins").rglob("*.json")),
    ]
    fragment = ROOT / "changelog.d" / "r3b-tool-families.added.md"
    if fragment.exists():  # before the release fold
        surfaces.append(fragment)
    folded = [
        line
        for line in (ROOT / "CHANGELOG.md").read_text().splitlines()
        if line.startswith("- Tool families are 13 product areas")
    ]
    assert fragment.exists() or len(folded) == 1, folded
    for line in folded:
        for name in NOT_FAMILIES:
            if name not in API_SOURCE_APPS:
                assert f"`{name}`" not in line, ("CHANGELOG.md", name)
    for path in surfaces:
        text = path.read_text()
        for name in NOT_FAMILIES:
            if name in API_SOURCE_APPS:
                continue  # an UNIFI_DISABLE_API_SOURCES app name, not a family
            assert f"`{name}`" not in text, (path, name)
    assert server.INSTRUCTIONS.count("FAMILIES") >= 2


async def _check_selection(mode, allowed, disabled):
    app = await clone_app()
    index = build_family_index()
    before = {tool.name for tool in await app.list_tools()}
    permitted = (set(allowed) if allowed else set(ALL_FAMILIES)) - set(disabled)
    expected = {name for name in before if index[name] in permitted}
    removed = await apply_tool_family_filter(app, ",".join(allowed), ",".join(disabled))
    assert set(removed) == before - expected
    assert {tool.name for tool in await app.list_tools()} == expected
    cleanup = await apply_tool_mode(app, mode)
    try:
        async with Client(app) as client:
            if mode == "full":
                assert {tool.name for tool in await client.list_tools()} == expected
            else:
                assert {tool.name for tool in await client.list_tools()} == {
                    "search_tools",
                    "describe_tool",
                    "call_read_tool",
                    "call_write_tool",
                    "list_tool_families",
                }
                found = (
                    await client.call_tool("search_tools", {"query": "", "limit": len(before)})
                ).data
                assert {row["name"] for row in found} == expected
                counts = (await client.call_tool("list_tool_families", {})).data
                assert counts == [
                    {"family": family, "tools": sum(index[name] == family for name in expected)}
                    for family in sorted(permitted)
                    if any(index[name] == family for name in expected)
                ]
    finally:
        cleanup()
    return expected


@pytest.mark.parametrize("mode", ["full", "discovery"])
@pytest.mark.parametrize("family", ALL_FAMILIES)
async def test_disabled_family_removed_from_every_catalog(mode, family):
    expected = await _check_selection(mode, (), (family,))
    index = build_family_index()
    assert expected
    assert {index[name] for name in expected} == set(ALL_FAMILIES) - {family}


@pytest.mark.parametrize("mode", ["full", "discovery"])
@pytest.mark.parametrize(
    ("allowed", "disabled"),
    [
        *(((family,), (family,)) for family in ALL_FAMILIES),
        (("network", "protect"), ("network", "protect", "firewall")),
        ((), ALL_FAMILIES),
    ],
)
async def test_overlapping_allow_and_deny_can_empty_catalog(mode, allowed, disabled):
    assert await _check_selection(mode, allowed, disabled) == set()
