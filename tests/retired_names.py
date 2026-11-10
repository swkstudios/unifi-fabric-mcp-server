"""Names a public document may mention without the code reading them (retired settings)."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_RETIRED_ROW = re.compile(r"^- Retired setting `([A-Z][A-Z0-9_]*)`", re.MULTILINE)


def migration_table_names(path: Path, text: str) -> set[str]:
    """The retired settings that may be named without being read by the code.

    The server carries no list of old names, so the rows ``- Retired setting `NAME```
    of a pending changelog fragment name them. A name in any other file is still checked.
    """
    relative = path.relative_to(ROOT).as_posix()
    if relative.startswith("changelog.d/"):
        return set(_RETIRED_ROW.findall(text))
    return set()
