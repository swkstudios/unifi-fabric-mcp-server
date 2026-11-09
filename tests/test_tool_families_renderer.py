"""The ``tool-families`` renderer fails closed and keeps its accounting consistent.

``scripts/gen_reference_blocks.py`` builds the README catalog accounting and family table from
``families.build_family_index()``. A family with no table label must stop the run instead of
silently dropping tools from the table, and the registered, listed and remaining counts must
add up to the table rows.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

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


def _index(counts: dict[str, int]) -> dict[str, str]:
    return {f"{family}_tool_{i}": family for family, n in counts.items() for i in range(n)}


def test_unknown_family_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    index = _index({"network": 3, "brand_new_family": 2})
    monkeypatch.setattr(gen.families, "build_family_index", lambda: index)
    with pytest.raises(SystemExit) as exc:
        gen.tool_families()
    message = str(exc.value)
    assert "tool-families" in message
    assert "brand_new_family" in message


def test_accounting_and_table_sums(monkeypatch: pytest.MonkeyPatch) -> None:
    counts = {"network": 5, "protect": 3, "vpn": 2, "hotspot": 1, "carrier": 4, "mobility": 2}
    monkeypatch.setattr(gen.families, "build_family_index", lambda: _index(counts))
    out = gen.tool_families()

    assert "**17 registered tools**" in out
    assert "**11** are in the product" in out
    assert "The remaining 6 cover" in out

    # Each row holds two (family, count) pairs, so split cells rather than match pairs.
    table: dict[str, int] = {}
    for line in out.splitlines():
        if not line.startswith("| ") or line.startswith(("| Family", "|---")):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        for name, n in zip(cells[::2], cells[1::2], strict=True):
            if name:
                table[name] = int(n)
    assert table == {"Network": 5, "Protect": 3, "VPN": 2, "Hotspot": 1}
    assert sum(table.values()) == 11
    assert sum(table.values()) + 6 == 17
    assert "Carrier" not in " ".join(table) and "Mobility" not in " ".join(table)


def test_every_label_renders_and_odd_row_is_padded(monkeypatch: pytest.MonkeyPatch) -> None:
    counts = {family: 1 for family in gen.FAMILY_LABELS}
    monkeypatch.setattr(gen.families, "build_family_index", lambda: _index(counts))
    out = gen.tool_families()
    for label in gen.FAMILY_LABELS.values():
        assert f"| {label} | 1 |" in out or f"| {label} | 1 " in out
    assert "The remaining 0 cover" in out
    assert out.splitlines()[-1].endswith("|  |  |") == (len(counts) % 2 == 1)
