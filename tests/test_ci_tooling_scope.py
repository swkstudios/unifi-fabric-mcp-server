"""CI lint scope, ignore rules and the shapes budget stay as configured."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PYTHON_DIRS = ("src/", "tests/", "scripts/", ".github/scripts/", "tools/")


def test_ci_lint_and_format_cover_every_python_tree():
    lint = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]["lint"]
    runs = [step.get("run", "") for step in lint["steps"]]
    for command in ("ruff check", "ruff format --check"):
        (run,) = [r for r in runs if r.startswith(command + " ")]
        assert run.split()[len(command.split()) :] == list(PYTHON_DIRS), run


def test_every_tracked_python_file_outside_docs_is_linted():
    tracked = [p for p in ROOT.rglob("*.py") if ".git" not in p.parts and ".venv" not in p.parts]
    rel = [p.relative_to(ROOT).as_posix() for p in tracked]
    stray = [
        r
        for r in rel
        if not r.startswith(PYTHON_DIRS)
        and not r.startswith(("docs/", "build/", "dist/"))  # docs/: private helpers only
        and "site-packages" not in r
    ]
    assert stray == [], stray


def test_mcp_json_ignore_is_anchored_to_the_repo_root():
    lines = [line.strip() for line in (ROOT / ".gitignore").read_text().splitlines()]
    assert "/.mcp.json" in lines
    assert ".mcp.json" not in lines  # unanchored: would hide plugins/codex/.mcp.json
    assert (ROOT / "plugins" / "codex" / ".mcp.json").is_file()


def test_shapes_budgets_cover_the_measured_sizes():
    import json

    from tests.test_catalog_size_budget import (
        PER_SHAPE_BUDGET_BYTES,
        SHAPE_AVERAGE_BUDGET_BYTES,
    )
    from unifi_fabric._tool_shapes_table import TOOL_SHAPES

    sizes = [
        len(json.dumps(s, separators=(",", ":"), ensure_ascii=False).encode())
        for args in TOOL_SHAPES.values()
        for s in args.values()
    ]
    assert sizes
    assert max(sizes) <= PER_SHAPE_BUDGET_BYTES, (max(sizes), PER_SHAPE_BUDGET_BYTES)
    budget = len(sizes) * SHAPE_AVERAGE_BUDGET_BYTES
    assert sum(sizes) <= budget, (sum(sizes), budget)
