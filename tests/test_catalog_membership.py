"""The explicit inventory (public #42 steps 6 and 7): catalog membership is authored.

Public #42: "Every ``ToolSpec`` resolves through the explicit loader map to exactly one
registered handler; missing, duplicate, or unknown entries fail clearly", and "Do not use
import-time scanning or AST inference as the source of truth for catalog membership."
"""

from __future__ import annotations

import inspect
import re

import pytest

from unifi_fabric import families
from unifi_fabric.catalog import META_FAMILY, load_catalog, membership
from unifi_fabric.catalog.loaders import LOADERS
from unifi_fabric.catalog.membership import MEMBERS, Member


def _registered() -> list[tuple[str, str]]:
    from unifi_fabric import server

    return membership.registered_steps(server.mcp)


def test_the_inventory_is_exactly_the_registration() -> None:
    assert membership.registration_problems(_registered()) == []
    assert [name for name, _step in _registered()] == [m.name for m in MEMBERS]


def test_the_inventory_has_no_static_problem() -> None:
    assert membership.problems() == []
    assert len(MEMBERS) == len(load_catalog().tools) - 5  # all but the discovery meta tools
    assert {membership.step_id(entry) for entry in LOADERS} == {m.step for m in MEMBERS}


def test_missing_duplicate_and_unknown_entries_fail_clearly() -> None:
    first, second = MEMBERS[0], MEMBERS[1]
    assert membership.problems((first, first, *MEMBERS[2:])) == [
        f"duplicate tool: {first.name} is listed 2 times",
    ]
    ghost = Member("ghost_tool", "vpn", "no_such_module:register")
    bad_family = second._replace(family="dns")
    assert membership.problems((first, bad_family, *MEMBERS[2:], ghost)) == [
        f"unknown family: {second.name} names 'dns'",
        "unknown step: ghost_tool names 'no_such_module:register', which is not in the loader map",
    ]
    registered = _registered()
    assert membership.registration_problems(registered, (first, *MEMBERS[2:], ghost)) == [
        f"unknown tool: {second.name} is registered by {registered[1][1]} but is not in the "
        "explicit inventory",
        "missing tool: ghost_tool is in the explicit inventory but no step registered it",
    ]
    moved = second._replace(step=first.step if first.step != second.step else MEMBERS[-1].step)
    assert membership.registration_problems(registered, (first, moved, *MEMBERS[2:])) == [
        f"wrong step: {second.name} is registered by {registered[1][1]}, the explicit "
        f"inventory says {moved.step}",
    ]
    assert membership.registration_problems([*registered, registered[0]]) == [
        f"duplicate tool: {first.name} is registered 2 times",
    ]


def test_the_server_refuses_to_start_on_a_stale_inventory(monkeypatch) -> None:
    from unifi_fabric import server

    monkeypatch.setattr(membership, "MEMBERS", MEMBERS[1:])
    with pytest.raises(RuntimeError, match=rf"explicit inventory: unknown tool: {MEMBERS[0].name}"):
        membership.verify(server.mcp)


def test_the_catalog_and_the_runtime_indexes_read_the_inventory() -> None:
    catalog = {row.name: row.family for row in load_catalog().tools}
    for member in MEMBERS:
        assert catalog[member.name] == member.family
    index = families.build_family_index()
    assert index == membership.family_index()
    assert index["list_configured_api_keys"] == "site_manager"
    assert {m.name for m in MEMBERS if m.family == META_FAMILY} == {"list_configured_api_keys"}
    assert families.build_module_index() == membership.module_index()


def test_membership_is_not_derived_from_source() -> None:
    """Step 7: the family index and module index come from the explicit inventory; the
    package no longer parses source to decide what a family contains. The read/write verb
    audit (``_read_only_audit``) stays."""
    source = inspect.getsource(families)
    for gone in ("import ast", "ast.parse", "derive_family_index", "derive_module_index"):
        assert gone not in source, gone
    assert not re.search(r"\bFAMILY_OVERRIDES\b", source)
    assert not hasattr(families, "derive_family_index")
    from unifi_fabric import _read_only_audit

    assert "ast.parse" in inspect.getsource(_read_only_audit)


def test_a_deferred_stub_names_its_step_by_index() -> None:
    """A tool registered without a function (a deferred stub, public #41) is checked by the
    loader-map index it carries."""
    from fastmcp import FastMCP
    from fastmcp.tools import Tool

    class Stub(Tool):
        deferred_step: int = -1

    app = FastMCP("stub-probe")
    member = MEMBERS[0]
    index = [membership.step_id(e) for e in LOADERS].index(member.step)
    app.add_tool(Stub(name=member.name, parameters={"type": "object"}, deferred_step=index))
    assert membership.registered_steps(app) == [(member.name, member.step)]


def _planted(name: str, module: str, qualname: str) -> object:
    def fn() -> None:
        """A planted tool function."""

    fn.__module__ = module
    fn.__qualname__ = qualname
    fn.__name__ = name
    return fn


def test_a_family_tool_named_like_a_meta_tool_is_an_unknown_tool() -> None:
    """A family step that registers a tool named like a discovery meta tool is
    refused at import, like any unknown tool; a real discovery meta tool is left out."""
    from fastmcp import FastMCP

    from unifi_fabric.catalog import loaders

    app = FastMCP("meta-name-plant")
    loaders.load(app, late=lambda: None, bound=lambda: None)
    planted = _planted(
        "list_tool_families",
        "unifi_fabric.families.site_manager.registrar",
        "register.<locals>.list_tool_families",
    )
    app.tool(name="list_tool_families")(planted)
    assert membership.registration_problems(membership.registered_steps(app)) == [
        "unknown tool: list_tool_families is registered by site_manager/registrar:register "
        "but is not in the explicit inventory"
    ]
    with pytest.raises(RuntimeError, match="unknown tool: list_tool_families"):
        membership.verify(app)

    real = FastMCP("meta-real")
    loaders.load(real, late=lambda: None, bound=lambda: None)
    meta = _planted(
        "search_tools", "unifi_fabric.discovery", "apply_tool_mode.<locals>.search_tools"
    )
    real.tool(name="search_tools")(meta)
    assert membership.registration_problems(membership.registered_steps(real)) == []
