"""Generated reference blocks in the docs match the code.

``scripts/gen_reference_blocks.py`` writes the environment-variable, write-switch, tool-mode
and family facts between ``<!-- BEGIN GENERATED: name -->`` markers. This test regenerates
every block and fails on any diff, naming the file, the block and the fix command.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _generator():
    spec = importlib.util.spec_from_file_location(
        "gen_reference_blocks", ROOT / "scripts" / "gen_reference_blocks.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(spec.name, module)
    spec.loader.exec_module(module)
    return sys.modules[spec.name]


gen = _generator()


def test_reference_blocks_are_current() -> None:
    findings = gen.check_all()
    assert not findings, "\n".join([*map(str, findings), f"fix: {gen.FIX_COMMAND}"])


def test_every_expected_block_is_present_once() -> None:
    for path, names in gen.BLOCKS.items():
        text = path.read_text()
        for name in names:
            assert text.count(f"<!-- BEGIN GENERATED: {name} -->") == 1, (path.name, name)


def test_a_stale_block_is_reported_with_its_name_and_the_fix_command() -> None:
    path = next(p for p, names in gen.BLOCKS.items() if "family-names" in names)
    stale = path.read_text().replace("The 13 families", "The 99 families", 1)
    assert gen.stale_blocks(path, stale) == ["family-names"]
    finding = gen.Finding(path, "family-names", f"block is stale; run {gen.FIX_COMMAND}")
    assert "family-names" in str(finding) and gen.FIX_COMMAND in str(finding)


def test_a_wrong_default_cell_is_reported() -> None:
    path = gen.CONFIGURATION
    text = path.read_text().replace(
        "| `UNIFI_CACHE_TTL_SECONDS` | No | `900` |",
        "| `UNIFI_CACHE_TTL_SECONDS` | No | `901` |",
        1,
    )
    assert [f.block for f in gen.default_findings(path, text)] == ["UNIFI_CACHE_TTL_SECONDS"]


def test_the_regeneration_fixes_a_wrong_default_cell_and_only_that_cell() -> None:
    """A changed code default is one regeneration away from agreeing: the Default cell of the
    hand-written table is rewritten; the Required and Description cells stay as written."""
    path = gen.CONFIGURATION
    current = path.read_text()
    row = "| `UNIFI_CACHE_MAX_HOSTS` | No | `512` | Max entries in the hosts TTLCache"
    assert row in current
    stale = current.replace(row, row.replace("`512`", "`999`"), 1)
    assert gen.default_findings(path, stale)
    fixed = gen.fix_default_cells(path, stale)
    assert fixed == current
    assert not gen.default_findings(path, fixed)
    assert gen.fix_default_cells(path, current) == current, "agreeing cells keep their wording"


def test_numeric_default_does_not_match_substring() -> None:
    field = gen.Settings.model_fields["cache_ttl_seconds"]
    assert gen._default_agrees(field, "`900`")
    assert not gen._default_agrees(field, "`1900`")


def _row(env: str) -> str:
    text = gen.CONFIGURATION.read_text()
    return next(line for line in text.splitlines() if line.startswith(f"| `{env}` |"))


def test_every_row_of_the_hand_written_table_is_compared_with_the_code() -> None:
    """No row is skipped: each variable of the table has a code default to compare with, the
    five that are not ``Settings`` fields included."""
    text = gen.CONFIGURATION.read_text()
    start, end, _column = gen._table_rows(gen.CONFIGURATION, text)
    rows = [m.group(1) for m in gen._ROW_RE.finditer(text[start:end])]
    targets = gen.default_targets()
    assert len(rows) >= 47 and not [r for r in rows if r not in targets], rows
    for env in (
        "UNIFI_KEY_MODE",
        "FASTMCP_HOST",
        "FASTMCP_PORT",
        "MCP_HEALTH_ROUTE",
        "UNIFI_MCP_CACHE_TTL",
    ):
        assert env in rows and env in targets, env
    assert gen.default_findings(gen.CONFIGURATION, text) == []


def test_a_row_with_no_code_default_is_a_finding() -> None:
    text = gen.CONFIGURATION.read_text()
    row = _row("UNIFI_CACHE_TTL_SECONDS")
    extra = row.replace("UNIFI_CACHE_TTL_SECONDS", "UNIFI_NOT_A_SETTING")
    findings = gen.default_findings(gen.CONFIGURATION, text.replace(row, row + "\n" + extra, 1))
    assert [f.block for f in findings] == ["UNIFI_NOT_A_SETTING"]


def test_a_changed_health_route_default_is_caught_and_fixed_in_the_tables_wording() -> None:
    """The documented ``off`` against a code default of on (and the other way round) was never
    compared: MCP_HEALTH_ROUTE is a transport setting, not a ``Settings`` field."""
    path, text = gen.CONFIGURATION, gen.CONFIGURATION.read_text()
    row = _row("MCP_HEALTH_ROUTE")
    assert "| `off` |" in row
    seeded_doc = text.replace(row, row.replace("| `off` |", "| `on` |", 1), 1)
    assert [f.block for f in gen.default_findings(path, seeded_doc)] == ["MCP_HEALTH_ROUTE"]
    assert gen.fix_default_cells(path, seeded_doc) == text, "a regeneration restores `off`"
    field = gen.config.MCPTransportSettings.model_fields["health_route"]
    original = field.default
    field.default = True  # the code default moves, the document still says off
    try:
        assert [f.block for f in gen.default_findings(path, text)] == ["MCP_HEALTH_ROUTE"]
        fixed = gen.fix_default_cells(path, text)
        assert _row_of(fixed, "MCP_HEALTH_ROUTE").count("| `on` |") == 1
        assert gen.default_findings(path, fixed) == []
    finally:
        field.default = original


def _row_of(text: str, env: str) -> str:
    return next(line for line in text.splitlines() if line.startswith(f"| `{env}` |"))


def test_the_other_rows_outside_settings_are_compared_too() -> None:
    path, text = gen.CONFIGURATION, gen.CONFIGURATION.read_text()
    for env, old, new in (
        ("UNIFI_KEY_MODE", "| `environment` |", "| `header` |"),
        ("UNIFI_MCP_CACHE_TTL", "| `300` |", "| `301` |"),
        ("FASTMCP_PORT", "`8000` from source", "`8001` from source"),
        ("FASTMCP_HOST", "`0.0.0.0` in the image", "`0.0.0.1` in the image"),
    ):
        row = _row(env)
        assert old in row, (env, row[:100])
        seeded = text.replace(row, row.replace(old, new, 1), 1)
        assert [f.block for f in gen.default_findings(path, seeded)] == [env], env
        assert gen.fix_default_cells(path, seeded) == text, env
