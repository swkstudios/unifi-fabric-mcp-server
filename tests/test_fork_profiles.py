"""Fork profiles over the explicit inventory (public #42 step 6).

Public #42: "Profile tests verify that the default includes the complete capability set and
that a selected fork profile includes only its declared families." The expected lists come
from the explicit inventory (:mod:`unifi_fabric.catalog.membership`), not from the server
under test, so a tool filed under the wrong family, or a profile that leaks one, fails.

Also the per-module switch: ``UNIFI_EXCLUDE=module:<module>`` removes exactly the tools of
one sub-area module, and an unknown module fails startup.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from unifi_fabric import policy
from unifi_fabric.catalog import META_FAMILY, load_catalog
from unifi_fabric.catalog.membership import MEMBERS, family_index, module_index
from unifi_fabric.families import ALL_FAMILIES
from unifi_fabric.policy import StartupRefusal

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import dump_tool_baseline as baseline  # noqa: E402

FORK = ("carrier", "vpn")


async def _listed(env: dict[str, str], mode: str = "full") -> list[str]:
    async with baseline._session(mode, env) as client:  # noqa: SLF001
        return [tool.name for tool in await client.list_tools()]


def _selection(name: str) -> str:
    """A member's selection family (the meta tool keeps its baseline family)."""
    return family_index().get(name, META_FAMILY)


async def test_the_default_profile_is_the_complete_inventory() -> None:
    listed = await _listed({})
    assert listed == [member.name for member in MEMBERS]
    assert {_selection(name) for name in listed} == set(ALL_FAMILIES)
    # Every catalog tool but the five discovery meta tools (listed in discovery mode only).
    assert len(listed) == len(load_catalog().tools) - 5


async def test_a_fork_profile_lists_only_its_declared_families() -> None:
    listed = await _listed({"UNIFI_FAMILY_ALLOW": ",".join(FORK)})
    declared = [m.name for m in MEMBERS if _selection(m.name) in FORK or m.family == META_FAMILY]
    assert listed == declared
    meta = {m.name for m in MEMBERS if m.family == META_FAMILY}
    assert {_selection(name) for name in listed if name not in meta} == {*FORK}
    # The meta tool stays (no token removes a meta tool); every other tool is declared.
    assert [m.name for m in MEMBERS if m.family == META_FAMILY] == ["list_configured_api_keys"]


async def test_a_fork_profile_in_discovery_mode_reaches_only_its_families() -> None:
    env = {"UNIFI_FAMILY_ALLOW": ",".join(FORK)}
    async with baseline._session("discovery", env) as client:  # noqa: SLF001
        result = await client.call_tool("list_tool_families", {})
        families = {row["family"]: row["tools"] for row in result.structured_content["result"]}
        found = await client.call_tool("search_tools", {"query": "dns record", "limit": None})
        names = [hit["name"] for hit in found.structured_content["result"]]
    counts = {
        f: sum(_selection(m.name) == f for m in MEMBERS if m.family != META_FAMILY) for f in FORK
    }
    # The declared families with their full tool counts, plus the one meta tool's baseline
    # selection family (list_configured_api_keys counts under site_manager, as before).
    assert families == {**counts, "site_manager": 1}
    assert names and all(_selection(name) in FORK for name in names)


async def test_a_module_exclusion_removes_exactly_that_module() -> None:
    listed = await _listed({"UNIFI_EXCLUDE": "module:network_vpn_dns"})
    modules = module_index()
    expected = [m.name for m in MEMBERS if modules.get(m.name) != "network_vpn_dns"]
    assert listed == expected
    assert len(MEMBERS) - len(listed) == 24


def test_an_unknown_module_fails_startup_without_echoing_it() -> None:
    with pytest.raises(StartupRefusal) as info:
        policy.operator_policy({"UNIFI_EXCLUDE": "family:vpn,module:no_such_module"}, None)
    assert info.value.token == "startup:UNIFI_EXCLUDE"
    assert "unknown module (position 1, counted from 0)" in info.value.message
    assert "no_such_module" not in info.value.message
    assert "network_vpn_dns" in info.value.message  # the valid modules are listed


def test_every_module_of_the_inventory_is_a_valid_exclusion() -> None:
    modules = sorted(set(module_index().values()))
    effective = policy.operator_policy(
        {"UNIFI_EXCLUDE": ",".join(f"module:{m}" for m in modules)}, None
    )
    assert effective.exposed_families == policy.FAMILIES
    assert len(effective.exclusions) == len(modules)
