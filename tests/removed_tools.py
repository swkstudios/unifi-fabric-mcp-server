"""Tools the catalog has removed since a release, derived from the release records.

A public document or a dated test-issue file may name a tool that an earlier release shipped
and a later one removed. This module derives which names those are, so no test keeps a hand
list of them:

* every backticked tool-shaped name in a pending ``changelog.d/*.removed.md`` fragment,
* every backticked tool-shaped name in a ``### Removed`` section of ``CHANGELOG.md``,
* every tool of a frozen ``tests/fixtures/tool_input_schemas_v*.json`` release snapshot,

in each case only when the name is no longer registered. A name that no release record
removed (a misspelling, a tool that never existed) is not in the set and still fails.

Tool-shaped means ``<verb>_<rest>`` with a verb that begins a registered or snapshot tool
name: a Removed section also backticks routes (``trafficrules``) and modules
(``protect_camera_recording``), which are not tools. :func:`is_history_surface` says where a
removed name may still be written: a current document naming one as live is a defect.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
_NAME = re.compile(r"`([a-z][a-z0-9_]+)`")

#: Documents that record release history, where a removed tool is named on purpose.
_HISTORY = re.compile(
    r"^(?:CHANGELOG\.md|changelog\.d/.+|docs/MIGRATING-[\w.-]+\.md|docs/COVERAGE\.md"
    r"|docs/[^/]+/.+)$"
)


def is_history_surface(rel: str) -> bool:
    """Whether the repository-relative path ``rel`` records release history.

    The changelog and its fragments, the migration guides, the coverage notes and the private
    private notes under a ``docs/`` subfolder may name a removed tool; every other document is a
    current one.
    """
    return _HISTORY.match(rel.replace("\\", "/")) is not None


def _removed_sections(changelog: str) -> list[str]:
    sections = []
    for part in re.split(r"^### ", changelog, flags=re.MULTILINE)[1:]:
        heading, _, body = part.partition("\n")
        if heading.strip() == "Removed":
            sections.append(body.split("\n## ", 1)[0])
    return sections


def release_snapshot(version: str) -> set[str] | None:
    """The frozen tool names of ``version`` (``0.7.0`` or ``v0.7.0``), or None if none is kept."""
    path = FIXTURES / f"tool_input_schemas_v{version.lstrip('v').replace('.', '_')}.json"
    if not path.is_file():
        return None
    return set(json.loads(path.read_text(encoding="utf-8"))["schemas"])


def removed_since_release(live: set[str]) -> set[str]:
    """Names a release record shows as removed from the catalog, minus what is registered."""
    written: set[str] = set()
    for fragment in sorted((ROOT / "changelog.d").glob("*.removed.md")):
        written |= set(_NAME.findall(fragment.read_text(encoding="utf-8")))
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    for body in _removed_sections(changelog):
        written |= set(_NAME.findall(body))
    snapshots: set[str] = set()
    for path in sorted(FIXTURES.glob("tool_input_schemas_v*.json")):
        snapshots |= set(json.loads(path.read_text(encoding="utf-8"))["schemas"])
    verbs = {name.split("_", 1)[0] for name in live | snapshots}
    shaped = {n for n in written if "_" in n and n.split("_", 1)[0] in verbs}
    return (shaped | snapshots) - live


def tools_of_release(version: str, live: set[str]) -> set[str]:
    """The tool names ``version`` shipped: its frozen snapshot, else the registry plus removals.

    A release with no kept snapshot is judged against every tool registered now plus every
    tool removed since a release, which is a superset of what it shipped; the names it cannot
    have had (a tool added later) are only caught once its snapshot is frozen.
    """
    snapshot = release_snapshot(version)
    return snapshot if snapshot is not None else live | removed_since_release(live)
