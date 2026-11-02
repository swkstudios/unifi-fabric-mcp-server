"""Locate a released CHANGELOG section without assuming it is the first heading.

The CHANGELOG opens with ``## [Unreleased]`` (an empty placeholder between releases), so
"the in-flight section" is the first heading that is not ``Unreleased``. Tests that
inspect the current release take it from here instead of splitting on the first ``## [``.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_HEADING = re.compile(r"^## \[(?P<name>[^\]]+)\](?P<rest>.*)$", re.M)


def sections(text: str) -> list[tuple[str, str, str]]:
    """``(name, heading line, body)`` for every ``## [..]`` section, in file order."""
    found = list(_HEADING.finditer(text))
    out = []
    for i, m in enumerate(found):
        end = found[i + 1].start() if i + 1 < len(found) else len(text)
        out.append((m["name"], m.group(0), text[m.end() : end]))
    return out


def _in_flight(text: str) -> tuple[str, str]:
    for name, _heading, body in sections(text):
        if name.lower() != "unreleased":
            return name, body
    raise LookupError("CHANGELOG has no released or in-flight version section")


def folded_changelog() -> str:
    """CHANGELOG.md as published; the public tree has no pending-fragment fold."""
    return (ROOT / "CHANGELOG.md").read_text()


def current_release(text: str | None = None) -> tuple[str, str]:
    """``(version, section body)`` of the newest section that is not ``[Unreleased]``.

    Without ``text``, the section comes from :func:`folded_changelog`.
    """
    return _in_flight(folded_changelog() if text is None else text)
