"""Tool profiles (explicit family allowlists over the typed catalog)."""

from __future__ import annotations

import pytest

from unifi_fabric.catalog import META_FAMILY, load_catalog
from unifi_fabric.families import (
    ALL_FAMILIES,
    DISABLED_TOOL_FAMILIES_ENV,
    TOOL_FAMILIES_ENV,
    apply_tool_family_filter,
)
from unifi_fabric.profiles import (
    DEFAULT_PROFILE,
    PROFILES,
    Profile,
    default_profile,
    selection_profile,
)


def test_default_profile_is_the_complete_capability_set() -> None:
    assert DEFAULT_PROFILE == "complete"
    assert default_profile().families == frozenset(ALL_FAMILIES)
    assert set(PROFILES) == {"complete"}
    catalog_families = {s.family for s in load_catalog().tools} - {META_FAMILY}
    assert default_profile().families == catalog_families


def test_unknown_family_fails() -> None:
    with pytest.raises(ValueError, match="unknown families"):
        Profile("fork", frozenset({"protect", "nosuchfamily"}))
    with pytest.raises(ValueError, match=TOOL_FAMILIES_ENV):
        selection_profile({"nosuchfamily"}, allowed_value="nosuchfamily")


def test_meta_is_not_a_profile_family() -> None:
    with pytest.raises(ValueError):
        Profile("fork", frozenset({META_FAMILY}))


@pytest.mark.parametrize(
    "allowed,disabled,expected",
    [
        ((), (), frozenset(ALL_FAMILIES)),
        (("protect",), (), frozenset({"protect"})),
        ((), ("protect",), frozenset(ALL_FAMILIES) - {"protect"}),
        (("protect", "network"), ("network",), frozenset({"protect"})),
        (("protect",), ("protect",), frozenset()),
    ],
)
def test_selection_profile(allowed, disabled, expected) -> None:
    assert selection_profile(allowed, disabled).families == expected


async def test_fork_profile_registers_only_its_families_through_the_same_path() -> None:
    """A fork profile keeps exactly its families' domain tools (same registration path:
    the complete roster registers, then selection removes the rest)."""
    from fastmcp import FastMCP

    from unifi_fabric import server

    app = FastMCP("profile-test")
    for tool in await server.mcp.list_tools():
        app.add_tool(tool)
    removed = await apply_tool_family_filter(app, "protect,connector")
    kept = {t.name for t in await app.list_tools()}
    catalog = load_catalog()
    from unifi_fabric.families import build_family_index

    index = build_family_index()
    assert kept == {n for n, f in index.items() if f in {"protect", "connector"}}
    assert set(removed) | kept == {t.name for t in await server.mcp.list_tools()}
    # The relays stay with the connector family: typed selection is not a route boundary.
    assert {f"fabric_connector_{v}" for v in ("get", "post", "put", "patch", "delete")} <= kept
    assert all(catalog.by_name()[n].family in {"protect", "connector"} for n in kept)


def test_profile_includes_keeps_unclassified() -> None:
    profile = Profile("fork", frozenset({"protect"}))
    assert profile.includes("protect")
    assert not profile.includes("network")
    assert profile.includes(None)


async def _filtered(allowed, disabled=None):
    from fastmcp import FastMCP

    from unifi_fabric import server

    app = FastMCP("profile-filter-test")
    for tool in await server.mcp.list_tools():
        app.add_tool(tool)
    removed = await apply_tool_family_filter(app, allowed, disabled)
    return removed, {t.name for t in await app.list_tools()}


async def test_filter_no_op_when_both_lists_unset() -> None:
    removed, kept = await _filtered(None, "  ")
    assert removed == []
    assert len(kept) == len(load_catalog().tools) - 5  # the five discovery meta tools


async def test_filter_unknown_name_message_hides_the_value() -> None:
    with pytest.raises(ValueError) as err:
        await _filtered("protect,synthetic-secret")
    assert "synthetic-secret" not in str(err.value)
    assert TOOL_FAMILIES_ENV in str(err.value)
    with pytest.raises(ValueError, match=DISABLED_TOOL_FAMILIES_ENV):
        await _filtered(None, "nosuch")


async def test_filter_opt_out_applies_after_allowlist() -> None:
    from unifi_fabric.families import build_family_index

    _removed, kept = await _filtered("protect,network", "network")
    index = build_family_index()
    assert kept == {n for n, f in index.items() if f == "protect"}
