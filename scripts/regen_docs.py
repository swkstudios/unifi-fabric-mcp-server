#!/usr/bin/env python3
"""Regenerate every generated part of the documentation, or check that all of it is current.

One command for editors and CI. It runs each documentation generator in order, the same
scripts with the same flags that were run one by one before:

1. ``scripts/gen_tools_doc.py``: docs/TOOLS.md and the release tool count in docs/COVERAGE.md;
2. ``scripts/gen_catalog_figures.py``: the catalog figures, the installation versions, the
   README blocks it owns and docs/site-stats.json;
3. ``scripts/gen_reference_blocks.py``: the reference blocks rendered from the code.

Every generated README region, and the one generator that owns it, is listed in ``BLOCKS`` in
scripts/doc_blocks.py. Text outside those blocks is free prose that no generator rewrites.

``--check`` writes nothing. The first generator that fails stops the run, as the separate
CI steps did; it prints what is stale (with a diff where it can) and the run exits 1 naming
the fix command. Running without ``--check`` regenerates everything at once.

Usage:
    python3 scripts/regen_docs.py          # rewrite every generated figure, pin and block
    python3 scripts/regen_docs.py --check  # exit 1 if anything generated is stale (CI)
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIX_COMMAND = "python3 scripts/regen_docs.py"
#: The documentation generators, in the order they run. Each takes ``--check``.
GENERATORS: tuple[str, ...] = (
    "scripts/gen_tools_doc.py",
    "scripts/gen_catalog_figures.py",
    "scripts/gen_reference_blocks.py",
)


def run(script: str, *, check: bool) -> int:
    """Run one generator with this interpreter from the repository root; its exit code."""
    command = [sys.executable, script, *(["--check"] if check else [])]
    print(f"regen_docs: {' '.join(command[1:])}", file=sys.stderr, flush=True)
    return subprocess.run(command, cwd=ROOT, check=False).returncode  # noqa: S603


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--check", action="store_true", help="write nothing; exit 1 if anything is stale"
    )
    args = parser.parse_args(argv)
    for script in GENERATORS:
        if run(script, check=args.check) != 0:
            then = (
                f"stale or broken generated docs; fix: {FIX_COMMAND}"
                if args.check
                else "failed; fix what the messages above name, then run it again"
            )
            print(f"regen_docs: {script} {then}", file=sys.stderr)
            return 1
    done = "generated documentation is current" if args.check else "documentation regenerated"
    print(f"regen_docs: {done} ({len(GENERATORS)} generators)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
