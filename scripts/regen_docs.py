#!/usr/bin/env python3
"""Regenerate every generated part of the repository, or check that all of it is current.

One command for editors and CI. It runs each generator in order:

0. ``scripts/gen_membership.py`` (``--check`` only): the explicit inventory, which is written
   by hand, before any generator imports the server, so a tool the inventory does not list,
   one it lists that no step registers, or a wrong step fails there with its own remedy;
1. ``scripts/gen_tools_doc.py``: docs/TOOLS.md and the release tool count in docs/COVERAGE.md;
2. ``scripts/gen_catalog_figures.py``: the catalog figures, the installation versions, the
   README blocks it owns and docs/site-stats.json;
3. ``scripts/gen_reference_blocks.py``: the reference blocks rendered from the code;
4. the committed baselines rendered from the registrations: the typed tool catalog, the tool
   index, the handler adapters and the tool input schemas;
5. the two lints over the documentation: retired settings and the claims ledger;
6. the baselines rendered from the hermetic tool capture, which is made once for all of them.

Every generated README region, and the one generator that owns it, is listed in ``BLOCKS`` in
scripts/doc_blocks.py. Text outside those blocks is free prose that no generator rewrites.

``--check`` writes nothing and runs every generator in this one interpreter. The server
registry is imported once and the hermetic tool capture is made once, where each generator run
as its own command imported and captured again. The first generator that fails stops the run;
it prints what is stale (with a diff where it can) and the run exits 1 naming the fix command.
Running without ``--check`` regenerates everything, each generator in its own process (they
write files the next one reads, so no in-process cache may outlive a write). A lint has no
write mode and is skipped there.

Usage:
    python3 scripts/regen_docs.py          # rewrite every generated figure, pin, block and baseline
    python3 scripts/regen_docs.py --check  # exit 1 if anything generated is stale (CI)
"""

from __future__ import annotations

import argparse
import contextlib
import os
import runpy
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIX_COMMAND = "python3 scripts/regen_docs.py"
#: The generators, in the order they run. Each takes ``--check``. The capture-based baseline
#: comes last: importing the hermetic capture harness is the one import the others avoid.
GENERATORS: tuple[str, ...] = (
    # First: it reads the registration from a scratch app, never the server. Every later
    # check imports the server or loads its deferred steps, which a stale inventory breaks
    # with no remedy of its own (the regeneration command below is wrong for an authored file).
    "scripts/gen_membership.py",
    "scripts/gen_tools_doc.py",
    "scripts/gen_catalog_figures.py",
    "scripts/gen_reference_blocks.py",
    "scripts/gen_tool_catalog.py",
    "scripts/gen_tool_index.py",
    "scripts/gen_loaders.py",
    "scripts/gen_handler_adapters.py",
    "scripts/gen_tool_input_schemas.py",
    "scripts/check_retired_settings.py",
    "scripts/docs_claim_ledger.py",
    "scripts/gen_route_manifest.py",
    "scripts/gen_deferred_catalog.py",
)
#: The flag that makes a generator write instead of check, where it is not "no flag".
WRITE_FLAGS: dict[str, str] = {
    "scripts/gen_tool_catalog.py": "--write",
    "scripts/gen_tool_index.py": "--write",
    "scripts/gen_deferred_catalog.py": "--generate",
    "scripts/gen_handler_adapters.py": "--write",
    "scripts/gen_tool_input_schemas.py": "--write",
}
#: Lints with no write mode: run by ``--check`` only.
CHECK_ONLY: frozenset[str] = frozenset(
    {
        "scripts/check_retired_settings.py",
        "scripts/docs_claim_ledger.py",
        "scripts/gen_loaders.py",  # the committed map is the source since it was generated once
        "scripts/gen_membership.py",  # the explicit inventory is authored, never generated
    }
)
#: What to do when a check-only script fails. Writing regenerates nothing for these, so the
#: command that fixes a generated file is the wrong advice; each script has printed its own
#: findings above the line this text ends.
REMEDIES: dict[str, str] = {
    "scripts/check_retired_settings.py": (
        "a retired setting name stands outside the changelog (printed above); "
        "remove or reword it in that file by hand"
    ),
    "scripts/docs_claim_ledger.py": (
        "a documented claim is false or stale (printed above); correct the document, or the "
        "code it describes, by hand: no generator writes claims"
    ),
    "scripts/gen_loaders.py": (
        "the committed loader map is the source, not a rendering: edit "
        "src/unifi_fabric/catalog/loaders.py as each difference above says"
    ),
    "scripts/gen_membership.py": (
        "the explicit inventory is the source of each tool's family: edit "
        "src/unifi_fabric/catalog/membership.py as each difference above says (after a family "
        "move, its --generate mode refreshes the steps only)"
    ),
}


@contextlib.contextmanager
def _as_command(path: Path, args: list[str]) -> Iterator[None]:
    """Run in this interpreter as ``python path args`` from the repository root would."""
    argv, cwd, search = sys.argv[:], Path.cwd(), sys.path[:]
    sys.argv = [str(path), *args]
    sys.path.insert(0, str(path.parent))
    os.chdir(ROOT)
    try:
        yield
    finally:
        os.chdir(cwd)
        sys.path[:] = search
        sys.argv = argv


def _run_in_process(script: str, args: list[str]) -> int:
    path = ROOT / script
    with _as_command(path, args):
        try:
            runpy.run_path(str(path), run_name="__main__")
        except SystemExit as stop:
            if stop.code is None:
                return 0
            if isinstance(stop.code, int):
                return stop.code
            print(stop.code, file=sys.stderr)  # what a command prints for SystemExit("text")
            return 1
    return 0


def run(script: str, *, check: bool) -> int:
    """Run one generator from the repository root; its exit code.

    A check runs in this interpreter, sharing the imported registry and the tool capture. A
    write runs in its own process, so it reads what the generators before it wrote.
    """
    args = ["--check"] if check else [WRITE_FLAGS[script]] if script in WRITE_FLAGS else []
    print(f"regen_docs: {script} {' '.join(args)}".rstrip(), file=sys.stderr, flush=True)
    if check:
        return _run_in_process(script, args)
    command = [sys.executable, script, *args]
    return subprocess.run(command, cwd=ROOT, check=False).returncode  # noqa: S603


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--check", action="store_true", help="write nothing; exit 1 if anything is stale"
    )
    args = parser.parse_args(argv)
    started = time.monotonic()
    ran = 0
    for script in GENERATORS:
        if script in CHECK_ONLY and not args.check:
            continue
        begin = time.monotonic()
        code = run(script, check=args.check)
        print(f"regen_docs: {script} {time.monotonic() - begin:.1f}s", file=sys.stderr, flush=True)
        if code != 0:
            then = (
                f"failed; {REMEDIES[script]}"
                if args.check and script in REMEDIES
                else f"stale or broken generated files; fix: {FIX_COMMAND}"
                if args.check
                else "failed; fix what the messages above name, then run it again"
            )
            print(f"regen_docs: {script} {then}", file=sys.stderr)
            return 1
        ran += 1
    done = "generated files are current" if args.check else "everything regenerated"
    print(
        f"regen_docs: {done} ({ran} generators, {time.monotonic() - started:.1f}s)", file=sys.stderr
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
