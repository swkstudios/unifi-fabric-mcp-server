"""Counts and lists in the 0.7.0 release text agree with the source they describe."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = (ROOT / "docs" / "MIGRATING-0.7.md").read_text()
CHANGELOG = (ROOT / "CHANGELOG.md").read_text()
FIXTURES = ROOT / "tests" / "fixtures"
RELEASED_LOCK = json.loads((FIXTURES / "v0_7_0_lock_pins.json").read_text())
OLD_PINS = json.loads((FIXTURES / "v0_6_2_lock_pins.json").read_text())["pins"]


def _section(anchor: str) -> str:
    return MIGRATION.split(f"### {anchor}\n", 1)[1].split("\n### ", 1)[0]


def test_runtime_lock_package_count_matches_the_migration_guide():
    # change-079 describes the runtime lock 0.7.0 shipped, read from the frozen v0.7.0 tag
    # fixture, never the lock at head: a later refresh must not rewrite released history.
    # The fixture keys every pin, including the four written with extras (for example
    # ``pydantic[email]==``), which a bare ``^name==`` count skips.
    runtime = RELEASED_LOCK["runtime_pins"]
    assert {"fastmcp-slim", "py-key-value-aio", "pydantic", "pyjwt"} <= runtime.keys()
    carried = runtime.keys() & OLD_PINS.keys()
    changed = sum(OLD_PINS[name] != runtime[name] for name in carried)
    entry = " ".join(_section("change-079").split())
    assert re.findall(r"(\d+) hash-locked packages", MIGRATION) == [str(len(runtime))]
    assert f"({changed} of the {len(carried)} carried over changed)" in entry


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
    from unifi_fabric.generated_api_facts._spec_limits_table import SPEC_LIMITS

    entry = _section("change-085")
    match = re.search(r"The (\d+) tools: (.*?)\.\n", entry, re.S)
    assert match, "change-085 must list the tools whose limits are checked"
    listed = re.findall(r"`([a-z_0-9]+)`", match.group(2))
    # change-085 and CHANGELOG describe shipped 0.7.0; later additions are listed
    # separately so current-table coverage cannot rewrite released history.
    assert int(match.group(1)) == len(listed)
    additions = re.search(r"Additional tools in 0[.]7[.]1: (.*?)\. ", entry, re.S)
    assert additions, "the migration guide must name the later spec-limit additions"
    added = re.findall(r"`([a-z_0-9]+)`", additions.group(1))
    assert listed == sorted(listed)
    assert not (set(listed) & set(added))
    assert len(listed) + len(added) == len(SPEC_LIMITS)
    assert sorted(listed + added) == sorted(SPEC_LIMITS)
    (bullet,) = [line for line in CHANGELOG.splitlines() if "#change-085" in line]
    assert f"{len(listed)} tools, listed in the migration guide" in bullet


def _description(name: str) -> str:
    from tests.test_tool_schema_contract import _tools

    return next(tool for tool in _tools() if tool.name == name).description or ""


def test_known_console_side_limits_are_in_the_tool_descriptions():
    assert "HTTP 500" in _description("list_ptz_presets")
    doors = _description("list_innerspace_doors")
    assert "HTTP 502" in doors and "UniFi Access app" in doors
    assert "HTTP 501" in _description("list_traffic_rules")
