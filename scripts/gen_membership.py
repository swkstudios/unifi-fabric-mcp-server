#!/usr/bin/env python3
"""Check (and, after a family move, refresh) the explicit tool inventory.

The explicit inventory, ``src/unifi_fabric/catalog/membership.py``, is the source of truth
for catalog membership (public #42 steps 6 and 7): each public tool, its family and the
loader-map step that registers it. Families are authored there and never inferred.

``--check`` (the default) fails, naming each difference, when:

* the inventory lists a tool twice, names an unknown family or a step that is not in the
  loader map (``catalog/loaders.py``), or a loader step registers none of its tools;
* the server's registration differs: a registered tool the inventory does not name
  (unknown), an inventory tool no step registers (missing), a tool registered twice or by
  another step, or a different order (the ``tools/list`` order);
* ``catalog.json`` (``scripts/gen_tool_catalog.py``) has another family or another tool set;
* the ``MEMBERS`` block is not exactly what this script renders from it.

``--generate`` rewrites the ``MEMBERS`` block from the registration, in registration order,
with each tool's current step and the family the inventory already gives it. A family move
changes steps only, so this is how a move updates the inventory. It refuses, naming them,
tools the inventory does not list: a new tool's family is written by hand.

Exit status: 0 clean, 1 a difference (each one printed), 2 a usage error.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

TARGET = ROOT / "src" / "unifi_fabric" / "catalog" / "membership.py"
BLOCK = re.compile(r"(# BEGIN MEMBERS\n)(.*?)(# END MEMBERS\n)", re.S)
LINE_LENGTH = 100


def _q(value: str) -> str:
    return '"' + value + '"'


def render(members: Sequence[Any]) -> str:
    """The ``MEMBERS`` block, one member per line (wrapped as ruff format wraps it)."""
    lines = ["MEMBERS: tuple[Member, ...] = ("]
    for m in members:
        one = f"    Member({_q(m.name)}, {_q(m.family)}, {_q(m.step)}),"
        if len(one) <= LINE_LENGTH:
            lines.append(one)
        else:
            lines += ["    Member(", *(f"        {_q(v)}," for v in m), "    ),"]
    return "\n".join([*lines, ")", ""])


def _block(text: str) -> str:
    match = BLOCK.search(text)
    if match is None:
        raise SystemExit("membership.py has no '# BEGIN MEMBERS' / '# END MEMBERS' block")
    return match.group(2)


def _registered() -> list[tuple[str, str]]:
    """The server's registration, read before the server checks it against the inventory."""
    from fastmcp import FastMCP

    from unifi_fabric.catalog import loaders, membership

    app = FastMCP("explicit-inventory-check")
    loaders.load(app, late=lambda: None, bound=lambda: None)
    return membership.registered_steps(app)


def check() -> list[str]:
    from unifi_fabric.catalog import load_catalog, membership

    out = list(membership.problems())
    out += membership.registration_problems(_registered())
    rows = {row.name: row.family for row in load_catalog().tools}
    members = {m.name: m.family for m in membership.MEMBERS}
    for name, family in members.items():
        if name not in rows:
            out.append(f"catalog.json: {name} is in the explicit inventory but not in the catalog")
        elif rows[name] != family:
            out.append(
                f"catalog.json: {name} is in family {rows[name]!r}, the explicit "
                f"inventory says {family!r}"
            )
    discovery = membership._DISCOVERY  # noqa: SLF001
    out += [
        f"catalog.json: {name} is in the catalog but not in the explicit inventory"
        for name in rows
        if name not in members and name not in discovery
    ]
    if _block(TARGET.read_text(encoding="utf-8")) != render(membership.MEMBERS):
        out.append(
            "membership.py: the MEMBERS block is not in the rendered form; run "
            "scripts/gen_membership.py --generate"
        )
    return out


def generate() -> list[str]:
    from unifi_fabric.catalog import membership

    family = {m.name: m.family for m in membership.MEMBERS}
    registered = _registered()
    new = [name for name, _step in registered if name not in family]
    if new:
        return [
            f"new tool: {name} (registered by {step or 'no loader step'}) is not in the "
            "explicit inventory; add its line with its family by hand"
            for name, step in registered
            if name in new
        ]
    members = [membership.Member(name, family[name], step) for name, step in registered]
    text = TARGET.read_text(encoding="utf-8")
    match = BLOCK.search(text)
    if match is None:
        raise SystemExit("membership.py has no MEMBERS block")
    TARGET.write_text(text[: match.start(2)] + render(members) + text[match.end(2) :])
    return []


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="compare (the default)")
    parser.add_argument("--generate", action="store_true", help="refresh steps and order")
    args = parser.parse_args(argv)
    if args.check and args.generate:
        parser.error("--check and --generate are exclusive")
    found = generate() if args.generate else check()
    for problem in found:
        print(problem)
    if found:
        return 1
    if not args.generate:
        from unifi_fabric.catalog import membership

        steps = {m.step for m in membership.MEMBERS}
        fams = {m.family for m in membership.MEMBERS} - {membership.META}
        print(
            f"explicit inventory: {len(membership.MEMBERS)} tools in {len(fams)} families + "
            f"meta, {len(steps)} loader steps; the registration, the loader map and "
            "catalog.json agree; none missing, duplicate or unknown"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
