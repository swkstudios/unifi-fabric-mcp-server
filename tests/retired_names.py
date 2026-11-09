"""Names a public document may mention without the code reading them (retired settings)."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_RETIRED_ROW = re.compile(r"^- Retired setting `([A-Z][A-Z0-9_]*)`", re.MULTILINE)
_MIGRATION_GUIDE = "docs/MIGRATING-0.7.1.md"
_MIGRATION_FRAGMENT = "changelog.d/s-071-upgrade-path.changed.md"
_MAPPING_ROW = re.compile(r"^\| `([A-Z][A-Z0-9_]*)` \|", re.MULTILINE)


def migration_table_names(path: Path, text: str) -> set[str]:
    """The retired settings that may be named without being read by the code.

    The server carries no list of old names, so these places name them: the rows
    ``- Retired setting `NAME``` of a pending changelog fragment, and, by exact path, the
    0.7.0 to 0.7.1 migration guide and its changelog fragment (both go with the guide in
    0.7.2). In those two only the names in the first column of the guide's mapping table are
    exempt; any other name, or the same name in any other file, is still checked.
    """
    relative = path.relative_to(ROOT).as_posix()
    if relative in {_MIGRATION_GUIDE, _MIGRATION_FRAGMENT}:
        guide = (ROOT / _MIGRATION_GUIDE).read_text(encoding="utf-8")
        names = set(_MAPPING_ROW.findall(guide))
        # Prose such as UNIFI_ENABLE_..._WRITE names the family stem; it is a docs-facts entry.
        return names | {"UNIFI_ENABLE_"}
    if relative.startswith("changelog.d/"):
        return set(_RETIRED_ROW.findall(text))
    return set()
