#!/usr/bin/env python3
"""Render and check docs/site-stats.json, the release figures the project website reads.

The website reads ``docs/site-stats.json`` from inside each release tag. Its contract::

    {"schema": 1, "version": "v0.7.0", "tools": 786, "live_verified": 380, "unit_tested": 406}

- ``version`` equals the release tag (``v`` plus ``pyproject.toml`` ``[project] version``);
- ``tools`` is the registered catalog count;
- ``live_verified`` is the ``passed`` count of the ``docs/COVERAGE.md`` live-evidence marker
  (the figure the README verification block shows);
- ``unit_tested`` is ``tools - live_verified``: the tools whose evidence is the CI run against
  a simulated upstream only. So ``live_verified + unit_tested == tools``; all are integers.

``scripts/gen_catalog_figures.py`` writes the file from the running server's catalog together
with the README figures, and its ``--check`` (run in CI's docs job) fails when the file is
stale. This script's own ``--check`` needs no running server: it validates the file against
the contract, the release version, the ``docs/TOOLS.md`` tool count and the coverage marker.

Usage:
    python3 scripts/site_stats.py           # rewrite docs/site-stats.json from docs/TOOLS.md
    python3 scripts/site_stats.py --check   # exit 1 when the file is wrong or stale
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SITE_STATS = Path("docs") / "site-stats.json"
SCHEMA = 1
KEYS = ("schema", "version", "tools", "live_verified", "unit_tested")
_LIVE_EVIDENCE_RE = re.compile(
    r"<!-- live-evidence: passed=(\d+) writes=(\d+) total=(\d+) "
    r"build=([0-9a-f]+) date=(\d{4}-\d{2}-\d{2}) -->"
)
_TOOL_HEADING_RE = re.compile(r"^### `([a-z][a-z0-9_]*)`\s*$", re.MULTILINE)


def live_verified(coverage_text: str) -> int:
    """The passed count of the docs/COVERAGE.md live-evidence marker."""
    match = _LIVE_EVIDENCE_RE.search(coverage_text)
    if match is None:
        raise ValueError("docs/COVERAGE.md has no live-evidence marker")
    return int(match.group(1))


def build(version: str, tools: int, coverage_text: str) -> dict[str, object]:
    live = live_verified(coverage_text)
    if not 0 <= live <= tools:
        raise ValueError(f"live-verified count {live} is outside 0..{tools} tools")
    return {
        "schema": SCHEMA,
        "version": f"v{version}",
        "tools": tools,
        "live_verified": live,
        "unit_tested": tools - live,
    }


def render(version: str, tools: int, coverage_text: str) -> str:
    return json.dumps(build(version, tools, coverage_text)) + "\n"


def validate(data: object, version: str | None = None) -> list[str]:
    """Contract violations in a parsed site-stats document (empty when it is valid)."""
    if not isinstance(data, dict):
        return ["site-stats.json is not a JSON object"]
    problems = []
    if sorted(data) != sorted(KEYS):
        problems.append(f"keys are {sorted(data)}, expected {sorted(KEYS)}")
    if data.get("schema") != SCHEMA:
        problems.append(f"schema is {data.get('schema')!r}, expected {SCHEMA}")
    counts = [data.get(k) for k in ("tools", "live_verified", "unit_tested")]
    if not all(isinstance(c, int) and not isinstance(c, bool) and c >= 0 for c in counts):
        problems.append(f"counts must be non-negative integers: {counts}")
    elif counts[1] + counts[2] != counts[0] or counts[0] <= 0:
        problems.append(
            f"live_verified + unit_tested must equal tools: {counts[1]} + {counts[2]} "
            f"!= {counts[0]}"
        )
    if not re.fullmatch(r"v\d+\.\d+\.\d+", str(data.get("version"))):
        problems.append(f"version {data.get('version')!r} is not a vX.Y.Z tag")
    elif version is not None and data.get("version") != f"v{version}":
        problems.append(f"version {data.get('version')!r} is not the release tag v{version}")
    return problems


def tools_doc_count(tools_doc: str) -> int:
    return len(set(_TOOL_HEADING_RE.findall(tools_doc)))


def check(root: Path) -> list[str]:
    """Problems with root/docs/site-stats.json, without starting the server."""
    path = root / SITE_STATS
    if not path.is_file():
        return [f"{SITE_STATS} is missing"]
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        return [f"{SITE_STATS} is not valid JSON: {exc}"]
    version = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    problems = validate(data, version)
    if problems:
        return problems
    try:
        expected = render(
            version,
            tools_doc_count((root / "docs" / "TOOLS.md").read_text()),
            (root / "docs" / "COVERAGE.md").read_text(),
        )
    except (OSError, ValueError) as exc:
        return [str(exc)]
    if path.read_text() != expected:
        return [f"{SITE_STATS} is stale: expected {expected.strip()}"]
    return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail when the file is stale")
    parser.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.check:
        problems = check(args.root)
        for problem in problems:
            print(f"site-stats: {problem}", file=sys.stderr)
        if not problems:
            print(f"site-stats: PASS {(args.root / SITE_STATS).read_text().strip()}")
        return 1 if problems else 0
    version = tomllib.loads((args.root / "pyproject.toml").read_text())["project"]["version"]
    text = render(
        version,
        tools_doc_count((args.root / "docs" / "TOOLS.md").read_text()),
        (args.root / "docs" / "COVERAGE.md").read_text(),
    )
    (args.root / SITE_STATS).write_text(text)
    print(f"wrote {SITE_STATS}: {text.strip()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
