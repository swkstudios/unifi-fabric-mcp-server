"""Render the shared workflow header blocks from ``.github/workflow-headers.toml``.

The pull-request concurrency block is the same in every workflow that runs for a pull
request. Its one source is the ``[pr-concurrency]`` table; this script writes it as the
top-level ``concurrency:`` block of each listed workflow.

``--check`` (the default) exits 1 and names each workflow whose block differs from the
rendering, or that carries a pull-request concurrency block without being listed. A
workflow named in ``own-block`` keeps a pull-request block of its own that is not rendered
here; it must still carry one, so a stale entry fails too.
``--write`` rewrites the listed workflows in place. A listed workflow the tree does not
carry is skipped. Only the standard library is used, so CI runs it before any install.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / ".github" / "workflow-headers.toml"
WORKFLOWS = ROOT / ".github" / "workflows"
TABLE = "pr-concurrency"
#: The line written above each rendered block.
MARKER = "# Rendered by scripts/gen_workflow_headers.py from .github/workflow-headers.toml."
#: A top-level ``concurrency:`` block (with the marker line, if present) and its
#: indented body.
BLOCK = re.compile(
    r"^(?:" + re.escape(MARKER) + r"\n)?concurrency:[^\n]*\n(?:[ \t]+[^\n]*\n|\n(?=[ \t]))*",
    re.MULTILINE,
)
#: A concurrency block keyed by pull-request number is a pull-request block.
PR_KEY = "github.event.pull_request.number"


@dataclass(frozen=True)
class Header:
    group: str
    cancel_in_progress: str
    workflows: tuple[str, ...]
    own_block: tuple[str, ...] = ()

    def render(self) -> str:
        return (
            f"{MARKER}\n"
            "concurrency:\n"
            f"  group: {self.group}\n"
            f"  cancel-in-progress: {self.cancel_in_progress}\n"
        )


def load(config: Path = CONFIG) -> Header:
    data = tomllib.loads(config.read_text())
    table = data[TABLE]
    unknown = set(table) - {"group", "cancel-in-progress", "workflows", "own-block"}
    if unknown:
        raise ValueError(f"{config.name}: unknown keys in [{TABLE}]: {sorted(unknown)}")
    workflows = tuple(table["workflows"])
    own_block = tuple(table.get("own-block", ()))
    named = workflows + own_block
    if len(set(named)) != len(named):
        raise ValueError(f"{config.name}: [{TABLE}] lists a workflow twice")
    for value in (table["group"], table["cancel-in-progress"]):
        if not isinstance(value, str) or "\n" in value or not value.strip():
            raise ValueError(f"{config.name}: [{TABLE}] values must be one-line strings")
    return Header(table["group"], table["cancel-in-progress"], workflows, own_block)


def render(text: str, header: Header, name: str) -> str:
    """Return ``text`` with its one top-level concurrency block replaced by ``header``."""
    blocks = BLOCK.findall(text)
    if len(blocks) != 1:
        raise ValueError(f"{name}: expected one top-level concurrency block, found {len(blocks)}")
    return BLOCK.sub(lambda _: header.render(), text, count=1)


def problems(header: Header, workflows: Path = WORKFLOWS, write: bool = False) -> list[str]:
    found: list[str] = []
    for path in sorted([*workflows.glob("*.yml"), *workflows.glob("*.yaml")]):
        text = path.read_text()
        pr_block = any(PR_KEY in block for block in BLOCK.findall(text))
        if path.name in header.own_block:
            if not pr_block:
                found.append(
                    f"{path.name}: listed in {CONFIG.name} [{TABLE}] own-block but carries "
                    "no pull-request concurrency block"
                )
            elif MARKER in text:
                found.append(
                    f"{path.name}: keeps its own concurrency block, so it must not carry "
                    "the rendered marker"
                )
            continue
        if path.name not in header.workflows:
            if pr_block:
                found.append(
                    f"{path.name}: pull-request concurrency block not listed in "
                    f"{CONFIG.name} [{TABLE}] workflows"
                )
            continue
        try:
            rendered = render(text, header, path.name)
        except ValueError as error:
            found.append(str(error))
            continue
        if rendered == text:
            continue
        if write:
            path.write_text(rendered)
        else:
            found.append(f"{path.name}: concurrency block differs from {CONFIG.name} [{TABLE}]")
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="fail on drift (default)")
    mode.add_argument("--write", action="store_true", help="render into the workflows")
    parser.add_argument("--config", type=Path, default=CONFIG)
    parser.add_argument("--workflows", type=Path, default=WORKFLOWS)
    args = parser.parse_args(argv)
    found = problems(load(args.config), args.workflows, write=args.write)
    for line in found:
        print(f"::error::{line}", file=sys.stderr)
    if found:
        if not args.write:
            print("Run: python scripts/gen_workflow_headers.py --write", file=sys.stderr)
        return 1
    print("Workflow headers match .github/workflow-headers.toml.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
