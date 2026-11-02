"""Counts and lists in the 0.7.0 release text agree with the source they describe."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = (ROOT / "docs" / "MIGRATING-0.7.md").read_text()
CHANGELOG = (ROOT / "CHANGELOG.md").read_text()


def _section(anchor: str) -> str:
    return MIGRATION.split(f"### {anchor}\n", 1)[1].split("\n### ", 1)[0]


def test_runtime_lock_package_count_matches_the_migration_guide():
    lock = (ROOT / "requirements-runtime.lock").read_text()
    packages = {m.lower() for m in re.findall(r"(?m)^([A-Za-z0-9_.-]+)==", lock)}
    stated = re.findall(r"(\d+) hash-locked packages", MIGRATION)
    assert stated == [str(len(packages))]


def test_route_fix_write_count_matches_the_named_writes():
    entry = _section("change-043")
    (count,) = re.findall(r"all (\d+) writes always failed", entry)
    names = set(re.findall(r"`((?:create|update|delete)_[a-z_]+)`", entry.split("\n  - ", 1)[0]))
    # Every write the CHANGELOG bullet names for this change is counted; reads are not.
    (bullet,) = [line for line in CHANGELOG.splitlines() if "#change-043" in line]
    listed = re.findall(r"`([a-z_]+)`", bullet.split("affected:", 1)[1])
    writes = [name for name in listed if name.split("_", 1)[0] in {"create", "update", "delete"}]
    assert f"all {count} writes always failed" in bullet
    assert int(count) == len(writes) == len(set(writes))
    assert names <= set(listed)


def test_spec_limit_tools_are_listed_in_the_migration_guide():
    from unifi_fabric._spec_limits_table import SPEC_LIMITS

    entry = _section("change-085")
    match = re.search(r"The (\d+) tools: (.*?)\.\n", entry, re.S)
    assert match, "change-085 must list the tools whose limits are checked"
    listed = re.findall(r"`([a-z_0-9]+)`", match.group(2))
    assert int(match.group(1)) == len(listed) == len(SPEC_LIMITS)
    assert listed == sorted(SPEC_LIMITS)
    (bullet,) = [line for line in CHANGELOG.splitlines() if "#change-085" in line]
    assert f"{len(SPEC_LIMITS)} tools, listed in the migration guide" in bullet


def _description(name: str) -> str:
    from tests.test_tool_schema_contract import _tools

    return next(tool for tool in _tools() if tool.name == name).description or ""


def test_known_console_side_limits_are_in_the_tool_descriptions():
    assert "HTTP 500" in _description("list_ptz_presets")
    doors = _description("list_innerspace_doors")
    assert "HTTP 502" in doors and "UniFi Access app" in doors
    for name in (
        "list_traffic_rules",
        "create_traffic_rule",
        "update_traffic_rule",
        "delete_traffic_rule",
    ):
        assert "HTTP 501" in _description(name), name
