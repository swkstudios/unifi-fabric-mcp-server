"""Name-based UUIDs in shipped files are synthetic.

A version-3 or version-5 UUID is derived from a name, the way a console derives its
site ids, so a literal that is not in the synthetic ``00000000-0000-`` range could be
a real console's identifier. The capture sanitizer maps recorded ids into that range
(the Default site is ``00000000-0000-3000-a000-000000000016``); hand-written tests use
the same range. Only the documentation locations that ship are scanned.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NAME_BASED = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[35][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", re.I
)
SYNTHETIC_PREFIX = "0" * 8 + "-" + "0" * 4 + "-"
#: Trees scanned recursively; ``docs`` itself is scanned one level deep (its own files).
SCANNED = ("src", "tests", "scripts", ".github", "tools", "docs/assets")
TEXT_SUFFIXES = {".py", ".md", ".json", ".yml", ".yaml", ".toml", ".txt", ".sh", ".cfg"}


def _shipped_text_files() -> list[Path]:
    files = [
        p
        for top in (ROOT, ROOT / "docs")
        for p in top.glob("*")
        if p.is_file() and p.suffix in TEXT_SUFFIXES
    ]
    for top in SCANNED:
        for path in (ROOT / top).rglob("*"):
            if path.suffix not in TEXT_SUFFIXES or not path.is_file():
                continue
            if "__pycache__" in path.parts:
                continue
            files.append(path)
    return files


def test_name_based_uuids_are_synthetic():
    found = {}
    for path in _shipped_text_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        real = sorted(
            {m.lower() for m in NAME_BASED.findall(text) if not m.startswith(SYNTHETIC_PREFIX)}
        )
        if real:
            found[path.relative_to(ROOT).as_posix()] = real
    assert found == {}, f"name-based UUIDs outside the synthetic range: {found}"
