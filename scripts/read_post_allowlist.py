#!/usr/bin/env python3
"""Print the read-POST allowlist as extended regular expressions, for log scanners.

    python3 scripts/read_post_allowlist.py

One tab-separated line per entry, ``<kind>\\t<name>\\t<ERE>``, generated from
``unifi_fabric.read_post_routes`` so a log scanner follows the allowlist without keeping a
second copy:

* ``route``   - an exact :data:`READ_POST_ROUTES` path; a POST to it is a read.
* ``command`` - the route of a :data:`READ_COMMANDS` entry (``.../cmd/<route>``). A log line
  carries no request body, so a scanner can tell only that the POST went to a command route
  that has a listed read command, not which command it sent; report it separately and keep
  the body check where the body is visible.
* ``reject``  - a path shape no entry may match (a ``.`` or ``..`` segment).

Match against the request path alone: no scheme or host, and the query (everything from the
first raw ``?``) removed. A path that matches a ``reject`` line is never a read. Each ERE is
anchored. Placeholders are one segment holding none of ``/ \\ ? # %`` (stricter than
:mod:`unifi_fabric.read_post_routes`, which judges percent-encoded values by their decoded
form: an encoded path is reported as not a read here, never as a read), and ``interval`` /
``scope`` also hold no ``.``.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from unifi_fabric.read_post_routes import (  # noqa: E402
    _ENUM_PLACEHOLDERS,
    _PLACEHOLDER_RE,
    READ_COMMANDS,
    READ_POST_ROUTES,
)

_ID_SEGMENT = r"[^\\/?#%]+"
_ENUM_SEGMENT = r"[^\\/?#%.]+"
_ERE_SPECIAL = frozenset(".[]()*+?{}|^$\\")
DOT_SEGMENT = r"(^|/)\.\.?(/|$)"


def template_to_ere(template: str) -> str:
    """The anchored ERE of a request-path template (placeholders in braces)."""
    parts: list[str] = []
    pos = 0

    def literal(text: str) -> str:
        return "".join("\\" + c if c in _ERE_SPECIAL else c for c in text)

    for match in _PLACEHOLDER_RE.finditer(template):
        parts.append(literal(template[pos : match.start()]))
        parts.append(_ENUM_SEGMENT if match.group(1) in _ENUM_PLACEHOLDERS else _ID_SEGMENT)
        pos = match.end()
    parts.append(literal(template[pos:]))
    return "^" + "".join(parts) + "$"


def entries() -> list[tuple[str, str, str]]:
    rows = [("route", r.name, template_to_ere(r.template)) for r in READ_POST_ROUTES]
    seen: set[str] = set()
    for command in READ_COMMANDS:
        if command.template not in seen:
            seen.add(command.template)
            rows.append(("command", command.route, template_to_ere(command.template)))
    rows.append(("reject", "dot-segment", DOT_SEGMENT))
    return rows


if __name__ == "__main__":
    for kind, name, ere in entries():
        sys.stdout.write(f"{kind}\t{name}\t{ere}\n")
