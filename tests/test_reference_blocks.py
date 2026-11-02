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


def test_numeric_default_does_not_match_substring() -> None:
    field = gen.Settings.model_fields["cache_ttl_seconds"]
    assert gen._default_agrees(field, "`900`")
    assert not gen._default_agrees(field, "`1900`")
