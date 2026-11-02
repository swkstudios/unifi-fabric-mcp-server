"""docs/site-stats.json follows the website contract and equals the generated figures."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from tests._tool_catalog import tools

ROOT = Path(__file__).resolve().parents[1]

_spec = importlib.util.spec_from_file_location("site_stats", ROOT / "scripts" / "site_stats.py")
assert _spec and _spec.loader
site_stats = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = site_stats
_spec.loader.exec_module(site_stats)

COVERAGE = "<!-- live-evidence: passed=2 writes=1 total=3 build=abc123 date=2026-01-02 -->\n"
TOOLS = "### `a_tool`\n\n### `b_tool`\n\n### `c_tool`\n"


def _tree(tmp_path: Path, stats: object | None = None) -> Path:
    (tmp_path / "docs").mkdir()
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "9.9.9"\n')
    (tmp_path / "docs" / "TOOLS.md").write_text(TOOLS)
    (tmp_path / "docs" / "COVERAGE.md").write_text(COVERAGE)
    if stats is not None:
        text = stats if isinstance(stats, str) else json.dumps(stats) + "\n"
        (tmp_path / "docs" / "site-stats.json").write_text(text)
    return tmp_path


def test_committed_file_is_current() -> None:
    assert site_stats.check(ROOT) == []


def test_committed_file_matches_the_registered_catalog() -> None:
    data = json.loads((ROOT / "docs" / "site-stats.json").read_text())
    assert data["tools"] == len(tools())
    assert data["live_verified"] + data["unit_tested"] == data["tools"]


def test_render_follows_the_contract() -> None:
    data = json.loads(site_stats.render("9.9.9", 3, COVERAGE))
    assert data == {
        "schema": 1,
        "version": "v9.9.9",
        "tools": 3,
        "live_verified": 2,
        "unit_tested": 1,
    }
    assert site_stats.validate(data, "9.9.9") == []


def test_write_then_check(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    assert site_stats.main(["--root", str(root)]) == 0
    assert site_stats.check(root) == []
    assert site_stats.main(["--check", "--root", str(root)]) == 0


@pytest.mark.parametrize(
    ("stats", "problem"),
    [
        (None, "missing"),
        ("{not json", "not valid JSON"),
        ([1], "not a JSON object"),
        (
            {"schema": 1, "version": "v9.9.8", "tools": 3, "live_verified": 2, "unit_tested": 1},
            "is not the release tag v9.9.9",
        ),
        (
            {"schema": 1, "version": "9.9.9", "tools": 3, "live_verified": 2, "unit_tested": 1},
            "is not a vX.Y.Z tag",
        ),
        (
            {"schema": 1, "version": "v9.9.9", "tools": 3, "live_verified": 2, "unit_tested": 2},
            "must equal tools",
        ),
        (
            {"schema": 1, "version": "v9.9.9", "tools": 3, "live_verified": "2", "unit_tested": 1},
            "non-negative integers",
        ),
        (
            {"schema": 1, "version": "v9.9.9", "tools": 3, "live_verified": True, "unit_tested": 2},
            "non-negative integers",
        ),
        (
            {"schema": 2, "version": "v9.9.9", "tools": 3, "live_verified": 2, "unit_tested": 1},
            "schema is 2",
        ),
        (
            {
                "schema": 1,
                "version": "v9.9.9",
                "tools": 3,
                "live_verified": 2,
                "unit_tested": 1,
                "extra": 0,
            },
            "keys are",
        ),
        (
            {"schema": 1, "version": "v9.9.9", "tools": 4, "live_verified": 3, "unit_tested": 1},
            "is stale",
        ),
    ],
    ids=[
        "missing",
        "invalid-json",
        "not-object",
        "version-not-tag",
        "version-format",
        "sum-rule",
        "string-count",
        "bool-count",
        "schema",
        "extra-key",
        "stale",
    ],
)
def test_check_failures(tmp_path: Path, stats: object | None, problem: str) -> None:
    problems = site_stats.check(_tree(tmp_path, stats))
    assert problems and problem in problems[0], problems


def test_missing_coverage_marker_is_an_error() -> None:
    with pytest.raises(ValueError, match="live-evidence marker"):
        site_stats.render("9.9.9", 3, "no marker\n")


def test_live_count_above_catalog_is_an_error() -> None:
    with pytest.raises(ValueError, match="outside"):
        site_stats.render("9.9.9", 1, COVERAGE)
