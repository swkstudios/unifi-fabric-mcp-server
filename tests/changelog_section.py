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


_NUMBERED = re.compile(r"^## \[\d+\.\d+\.\d+\].*$", re.M)
_DATED = re.compile(r"^(## \[\d+\.\d+\.\d+\]) - \d{4}-\d{2}-\d{2}$")


def undated_in_flight(text: str) -> str:
    """``text`` with the first numbered heading's release date removed.

    Tests that exercise folding into the in-flight section call this so they run against an
    undated section whether or not the tree has been dated for release: the fragment fold
    refuses to fold into a dated section, so without it they pass only until the dating commit
    and then fail the release itself (CA-20261107-291, CA-20261107-293). On an undated tree the
    first numbered heading has no date, so this returns ``text`` unchanged: only that heading
    is ever looked at, never an older released one further down.
    """
    first = _NUMBERED.search(text)
    if first is None or not (dated := _DATED.match(first.group(0))):
        return text
    return text[: first.start()] + dated.group(1) + text[first.end() :]


def _in_flight(text: str) -> tuple[str, str]:
    for name, _heading, body in sections(text):
        if name.lower() != "unreleased":
            return name, body
    raise LookupError("CHANGELOG has no released or in-flight version section")


def folded_changelog() -> str:
    """CHANGELOG.md as published; the public tree has no pending-fragment fold."""
    return (ROOT / "CHANGELOG.md").read_text()


def section(name: str, text: str | None = None) -> str:
    """Body of the ``## [name]`` section, as published (released sections are never folded)."""
    text = (ROOT / "CHANGELOG.md").read_text() if text is None else text
    for found, _heading, body in sections(text):
        if found == name:
            return body
    raise LookupError(f"CHANGELOG has no [{name}] section")


def previous_release(text: str | None = None) -> str:
    """Version of the release before the in-flight section: the in-flight comparison baseline."""
    text = folded_changelog() if text is None else text
    names = [name for name, _heading, _body in sections(text) if name.lower() != "unreleased"]
    if len(names) < 2:
        raise LookupError("CHANGELOG has no release older than the in-flight section")
    return names[1]


def current_release(text: str | None = None) -> tuple[str, str]:
    """``(version, section body)`` of the newest section that is not ``[Unreleased]``.

    Without ``text``, the section comes from :func:`folded_changelog`.
    """
    return _in_flight(folded_changelog() if text is None else text)
