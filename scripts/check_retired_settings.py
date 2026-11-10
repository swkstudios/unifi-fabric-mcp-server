#!/usr/bin/env python3
"""Fail when a retired setting name appears outside the changelog.

The migration table for retired settings lives in the changelog: in a pending fragment
under ``changelog.d/`` before the release fold, and in ``CHANGELOG.md`` after it. Each
retired name is one bullet that starts with ``- Retired setting `NAME```.
This script reads the names from those bullets, so it carries no retired name itself, then
searches every tracked file except the excluded paths with ``git grep -I -i -w`` (any
letter case). A dated capture that records the environment a past run used, and is never
edited after capture, is excluded by giving its exact path the ``retired-setting-capture``
attribute in a ``.gitattributes`` file in the capture's own directory tree, so this script
names no capture path; a mark that is a pattern or names no tracked file fails closed.
A line that is only an HTML anchor (``<a id="..."></a>``) is not counted: such an alias
keeps an old link target working, for example one cited by a released changelog section,
which is never edited, and it gives no guidance.

Output lists ``path: count`` per file and a total. It never prints a matched line, so a
value that sits next to a name (which could be a credential) is never echoed.

Exit status: 0 when the tree is clean, 1 when a retired name is found, 2 when the table
is missing or empty (fail closed), a capture mark is not one exact tracked path, or git
fails.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROW_RE = re.compile(r"^- Retired setting `([A-Z][A-Z0-9_]*)`", re.MULTILINE)

#: A line holding nothing but an HTML anchor alias; such lines are not counted.
ANCHOR_ONLY = r'^[[:space:]]*<a id="[^"]*"></a>[[:space:]]*$'

#: The attribute that marks a dated capture (see the module docstring). It is set per
#: exact path in a ``.gitattributes`` file, never by a directory or glob pattern.
CAPTURE_ATTRIBUTE = "retired-setting-capture"
_GLOB_CHARS = frozenset("*?[\\")

#: Paths that may name retired settings: the changelog (released sections stay
#: byte-identical), the docs-facts allowlist
#: (it keys the history and migration table entries by setting name) and the front-page
#: test (it asserts the published 0.7.0 lead, which is never edited), each by its exact
#: path, plus every file that carries the capture attribute.
EXCLUDED_PATHSPECS = (
    ":(exclude)CHANGELOG.md",
    ":(exclude)changelog.d",
    ":(exclude)tests/docs_facts_allowlist.toml",
    ":(exclude)tests/test_front_page_docs.py",
    f":(exclude,attr:{CAPTURE_ATTRIBUTE})",
)


def table_sources(root: Path) -> list[Path]:
    """The files that may hold the migration table: CHANGELOG.md and every fragment."""
    sources = [root / "CHANGELOG.md"]
    fragments = root / "changelog.d"
    if fragments.is_dir():
        sources.extend(sorted(fragments.glob("*.md")))
    return [path for path in sources if path.is_file()]


def retired_names(root: Path) -> list[str]:
    """Every retired setting name in the migration table, sorted and unique."""
    names: set[str] = set()
    for path in table_sources(root):
        names.update(ROW_RE.findall(path.read_text(encoding="utf-8")))
    return sorted(names)


def _tracked(root: Path, *pathspecs: str) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "--", *pathspecs],  # noqa: S607 - fixed git command
        cwd=root,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git ls-files failed with exit status {result.returncode}")
    return [rel for rel in result.stdout.decode("utf-8").split("\0") if rel]


def bad_capture_marks(root: Path) -> list[str]:
    """Each capture mark that is not one exact tracked path, and each file it reaches.

    A ``file:line`` entry is a mark that is a pattern or names no tracked file. A bare
    path entry is a file that carries the attribute although no mark names it exactly,
    for example through a mark without a slash (which matches at any depth) or a macro.
    """
    tracked = set(_tracked(root))
    exact: set[str] = set()
    bad: list[str] = []
    for rel in _tracked(root, ":(glob)**/.gitattributes"):
        base, path = Path(rel).parent, root / rel
        lines = path.read_text(encoding="utf-8").splitlines() if path.is_file() else []
        for number, line in enumerate(lines, start=1):
            # Only the set state exempts a file (``:(attr:NAME)``); -NAME, !NAME and
            # NAME=value never do, so they need no check.
            pattern, *attributes = line.split() or ["#"]
            if pattern.startswith("#") or CAPTURE_ATTRIBUTE not in attributes:
                continue
            target = (base / pattern.lstrip("/")).as_posix()
            if _GLOB_CHARS & set(pattern) or target not in tracked:
                bad.append(f"{rel}:{number}")
            else:
                exact.add(target)
    marked = set(_tracked(root, f":(attr:{CAPTURE_ATTRIBUTE})"))
    bad.extend(sorted(marked - exact))
    return bad


def find_occurrences(root: Path, names: list[str]) -> dict[str, int]:
    """``path -> match count`` for the retired names in tracked files outside the changelog."""
    if not names:
        return {}
    pattern = "|".join(re.escape(name) for name in names)
    cmd = [
        "git", "grep", "-I", "-i", "-w", "-c", "-E",
        "-e", pattern, "--and", "--not", "-e", ANCHOR_ONLY,
        "--", ".", *EXCLUDED_PATHSPECS,
    ]  # fmt: skip
    result = subprocess.run(cmd, cwd=root, capture_output=True, text=True, check=False)
    if result.returncode == 1:
        return {}
    if result.returncode != 0:
        raise RuntimeError(f"git grep failed with exit status {result.returncode}")
    counts: dict[str, int] = {}
    for line in result.stdout.splitlines():
        path, _, count = line.rpartition(":")
        counts[path] = int(count)
    return counts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail on any occurrence (the default; accepted for consistency with other checks)",
    )
    args = parser.parse_args(argv)
    root: Path = args.root
    names = retired_names(root)
    if not names:
        print(
            "check_retired_settings: no '- Retired setting `NAME`' rows found in CHANGELOG.md "
            "or changelog.d/; the migration table is missing",
            file=sys.stderr,
        )
        return 2
    try:
        bad_marks = bad_capture_marks(root)
        counts = find_occurrences(root, names)
    except RuntimeError as exc:
        print(f"check_retired_settings: {exc}", file=sys.stderr)
        return 2
    if bad_marks:
        print(
            f"check_retired_settings: a {CAPTURE_ATTRIBUTE} mark must name one tracked file "
            "by its exact path, not a pattern:",
            file=sys.stderr,
        )
        for mark in bad_marks:
            print(f"  {mark}", file=sys.stderr)
        return 2
    if not counts:
        print(
            f"check_retired_settings: OK ({len(names)} retired names, none outside the changelog)"
        )
        return 0
    total = sum(counts.values())
    print(
        f"check_retired_settings: {total} lines in {len(counts)} files name a retired setting "
        "outside the changelog; use the replacements in the CHANGELOG migration table:",
        file=sys.stderr,
    )
    for path, count in sorted(counts.items()):
        print(f"  {path}: {count}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
