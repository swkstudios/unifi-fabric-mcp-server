#!/usr/bin/env python3
"""The one list of generated documentation regions, and the marker code every generator uses.

A generated region sits between two marker lines and is never edited by hand:

    <!-- BEGIN GENERATED: name -->
    ...
    <!-- END GENERATED -->

A marker line may be indented with spaces, so a block can close inside a Markdown list item
without splitting the list. Everything outside the markers is free prose: no generator
rewrites it.

``BLOCKS`` below is the registry. Each entry names one block, the file it lives in and the
one generator that owns it (writes its content); entries of a file are listed in file order.
Both generators read this table:

* ``scripts/gen_catalog_figures.py`` owns the blocks that need the running server's catalog
  (tool counts) or the docs/COVERAGE.md live-evidence marker;
* ``scripts/gen_reference_blocks.py`` owns the blocks rendered from the code
  (``unifi_fabric.config``, ``families``, ``switches``, ``code_mode``, ``audit``).

Every registered block is required. A block that is missing, duplicated, unregistered, out of
order, or whose markers are unpaired or crossed fails both generators, in write and
``--check`` mode, naming the file and the marker; nothing is written. Adding a block means
adding its markers to the file and an entry here (plus its renderer in the owning
generator); removing one means removing both, a reviewable change.

``python3 scripts/regen_docs.py`` runs every documentation generator; ``--check`` is what CI
runs. Stdlib only: generators and release scripts load this module by path.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIX_COMMAND = "python3 scripts/regen_docs.py"
BEGIN = "<!-- BEGIN GENERATED: {name} -->"
END = "<!-- END GENERATED -->"


@dataclass(frozen=True)
class Block:
    """One generated region: ``name`` in ``file`` (repo-relative), written by ``owner``."""

    name: str
    file: str
    owner: str
    source: str


CATALOG = "gen_catalog_figures"
REFERENCE = "gen_reference_blocks"

#: Every generated region, per file in file order. One block, one owner.
BLOCKS: tuple[Block, ...] = (
    Block("catalog-headline", "README.md", CATALOG, "registered tool count (running server)"),
    Block("how-it-works-catalog", "README.md", CATALOG, "registered tool count (running server)"),
    Block("tool-families", "README.md", REFERENCE, "families.build_family_index()"),
    Block(
        "verification-status",
        "README.md",
        CATALOG,
        "registered tool count and the docs/COVERAGE.md live-evidence marker",
    ),
    Block("code-mode", "AGENTS.md", REFERENCE, "code_mode.CODE_MODE_TOOLS, EXPERIMENTAL_NOTICE"),
    Block("code-mode", "llms.txt", REFERENCE, "code_mode.CODE_MODE_TOOLS, EXPERIMENTAL_NOTICE"),
    Block("settings-reference", "docs/CONFIGURATION.md", REFERENCE, "config.Settings"),
    Block("write-switch-names", "docs/CONFIGURATION.md", REFERENCE, "switches"),
    Block("write-switches", "docs/CONFIGURATION.md", REFERENCE, "switches.AREA_WRITE_SWITCHES"),
    Block("audit-schema", "docs/CONFIGURATION.md", REFERENCE, "unifi_fabric.audit"),
    Block("write-switches", "docs/TOOL-USAGE.md", REFERENCE, "switches.AREA_WRITE_SWITCHES"),
    Block("tool-mode-defaults", "docs/TOOL-USAGE.md", REFERENCE, "config.Settings, discovery"),
    Block("tool-mode-choices", "docs/TOOL-USAGE.md", REFERENCE, "Settings.tool_mode"),
    Block("family-names", "docs/TOOL-USAGE.md", REFERENCE, "families.ALL_FAMILIES"),
    Block("search-tools-limit", "docs/TOOL-USAGE.md", REFERENCE, "search_tools limit default"),
)

#: A whole block: the BEGIN line, the generated body and the END line.
BLOCK_RE = re.compile(
    r"^(?P<begin>[ ]*<!-- BEGIN GENERATED: (?P<name>[a-z0-9-]+) -->)\n"
    r"(?P<body>.*?)"
    r"^(?P<end>[ ]*<!-- END GENERATED -->)$",
    re.M | re.S,
)
#: Line-start markers only: prose may quote the marker syntax inline (llms.txt does).
_MARKER_RE = re.compile(r"^[ ]*<!-- (BEGIN|END) GENERATED\b", re.M)


class MarkerError(RuntimeError):
    """A registered block is missing, duplicated, unregistered, out of order or crossed."""


def files() -> list[str]:
    """Every file that carries a generated block, in registry order."""
    return list(dict.fromkeys(block.file for block in BLOCKS))


def names(file: str, owner: str | None = None) -> tuple[str, ...]:
    """The registered block names of ``file`` in file order (only ``owner``'s, if given)."""
    return tuple(b.name for b in BLOCKS if b.file == file and owner in (None, b.owner))


def owned(owner: str, root: Path = ROOT) -> dict[Path, tuple[str, ...]]:
    """``{path: block names}`` for every file holding a block ``owner`` writes."""
    return {root / file: names(file, owner) for file in files() if names(file, owner)}


def problems(file: str, text: str) -> list[tuple[str, str]]:
    """``(block, message)`` for every structural problem of ``text`` against the registry.

    Checks every registered block of ``file``, whoever owns it: each must be present exactly
    once, in registry order, with paired, uncrossed markers; any other block name fails.
    """
    found: list[tuple[str, str]] = []
    seen = [m["name"] for m in BLOCK_RE.finditer(text)]
    expected = list(names(file))
    for name in sorted(set(expected) - set(seen)):
        found.append(
            (
                name,
                f"block is missing; add the marker lines `{BEGIN.format(name=name)}` and "
                f"`{END}`, or remove the block from BLOCKS in scripts/doc_blocks.py",
            )
        )
    for name in sorted({n for n in seen if n not in expected}):
        found.append((name, "unknown block name; register it in BLOCKS in scripts/doc_blocks.py"))
    for name in sorted({n for n in seen if seen.count(n) > 1}):
        found.append((name, "block appears more than once"))
    kinds = [(m[1], m.start()) for m in _MARKER_RE.finditer(text)]
    begins = sum(kind == "BEGIN" for kind, _ in kinds)
    ends = len(kinds) - begins
    if begins != len(seen) or ends != len(seen):
        found.append(("(markers)", "unpaired BEGIN or END GENERATED marker"))
    else:
        # Counts can agree while the markers are crossed (END before BEGIN, BEGIN twice).
        expect = "BEGIN"
        for kind, at in kinds:
            if kind != expect:
                line = text.count("\n", 0, at) + 1
                found.append(("(markers)", f"line {line}: {kind} where {expect} belongs"))
                break
            expect = "END" if expect == "BEGIN" else "BEGIN"
    present = [n for n in seen if n in expected]
    if sorted(present) == sorted(expected) and present != expected:
        found.append(
            (
                "(order)",
                f"blocks are out of order: found {', '.join(present)}; "
                f"expected {', '.join(expected)} (see BLOCKS in scripts/doc_blocks.py)",
            )
        )
    return found


def fill(
    file: str, text: str, owner: str, renderers: Mapping[str, Callable[[], str]]
) -> tuple[str, list[tuple[str, str]]]:
    """``text`` with ``owner``'s blocks of ``file`` regenerated, and the structural problems.

    The marker lines are kept as they are (with their indentation); only the body between
    them is replaced. ``renderers`` must cover exactly ``owner``'s blocks of ``file``.
    """
    mine = names(file, owner)
    if set(renderers) != set(mine):
        raise MarkerError(
            f"{file}: {owner} renders {sorted(renderers)} but BLOCKS in scripts/doc_blocks.py "
            f"assigns it {sorted(mine)}"
        )
    found = problems(file, text)

    def render(match: re.Match[str]) -> str:
        name = match["name"]
        if name not in mine:
            return match[0]
        return f"{match['begin']}\n{renderers[name]()}\n{match['end']}"

    return BLOCK_RE.sub(render, text), found


def fill_or_raise(
    file: str, text: str, owner: str, renderers: Mapping[str, Callable[[], str]]
) -> str:
    """``fill``, raising ``MarkerError`` (naming the file and every problem) on any problem."""
    new, found = fill(file, text, owner, renderers)
    if found:
        raise MarkerError("; ".join(f"{file}: {block}: {message}" for block, message in found))
    return new


def body(text: str, name: str) -> str | None:
    """The generated body of block ``name``, or None unless it appears exactly once."""
    bodies = [m["body"] for m in BLOCK_RE.finditer(text) if m["name"] == name]
    return bodies[0] if len(bodies) == 1 else None
