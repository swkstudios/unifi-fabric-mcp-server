#!/usr/bin/env python3
"""Generate or check ``src/unifi_fabric/catalog/deferred.json`` (public #41 lazy loading).

The snapshot is the listing data of every tool, per loader step, that the server's
fn-less stubs serve before a step loads. It is derived, never hand-edited:

* every step of ``catalog/loaders.py`` is registered on a private staging app, exactly as
  a deferred load does it, and the per-tool install passes run on it;
* each tool's listing fields (title, description, parameters, output schema, annotations,
  meta, tags, version) and its write verbs from the real verb audit
  (``_read_only_audit.write_verbs_for``) are recorded, in ``tools/list`` order;
* the Python minor version, ``sys.flags.optimize`` and the fastmcp and pydantic versions are
  recorded; a server running under others registers every step eagerly.

``--check`` regenerates in memory and fails on any difference; it runs on every PR that
touches ``src/`` (the verb audit follows the call graph into shared and core modules).
At runtime every loaded step is compared with the snapshot again and fails closed on a
difference, so a stale file can refuse a call but never let a write through as a read.

    python scripts/gen_deferred_catalog.py --generate
    python scripts/gen_deferred_catalog.py --check
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def build() -> str:
    """The snapshot text for the current source tree."""
    for name in [n for n in os.environ if n.startswith(("UNIFI_", "MCP_"))]:
        del os.environ[name]
    from unifi_fabric import server
    from unifi_fabric._read_only_audit import write_verbs_for
    from unifi_fabric.catalog import deferred, loaders
    from unifi_fabric.families import build_family_index

    steps: list[dict[str, object]] = []
    tools: list[dict[str, object]] = []
    seen: set[str] = set()
    for index, entry in enumerate(loaders.LOADERS):
        staged, returned = deferred.stage_step(
            entry,
            live=server.mcp,
            late=lambda: server._require(),  # noqa: SLF001 - the server's own deps
            bound=server._require,  # noqa: SLF001
            should_redact=lambda: False,
            prepare=server._prepare_tool_fn,  # noqa: SLF001
        )
        if not staged:
            raise SystemExit(f"gen_deferred_catalog: step {entry.ref} registers no tool")
        for name, tool in staged.items():
            if name in seen:
                raise SystemExit(f"gen_deferred_catalog: {name} is registered twice")
            seen.add(name)
            family = build_family_index().get(name)
            if family is None:
                raise SystemExit(
                    f"gen_deferred_catalog: {name} has no family in the explicit inventory"
                )
            verbs = write_verbs_for(tool.fn)  # type: ignore[attr-defined]
            tools.append(deferred.tool_record(tool, index, family, verbs))
        steps.append(
            {
                "ref": entry.ref,
                "deps": entry.deps,
                "origin": entry.origin,
                "family": entry.family,
                "tools": list(staged),
                "exports": sorted(returned),
            }
        )
    return deferred.render_snapshot(steps, tools)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--generate", action="store_true", help="write the snapshot")
    mode.add_argument("--check", action="store_true", help="fail when the snapshot is stale")
    args = parser.parse_args(argv)
    from unifi_fabric.catalog.deferred import SNAPSHOT_PATH

    text = build()
    if args.generate:
        SNAPSHOT_PATH.write_text(text, encoding="utf-8")
        print(f"gen_deferred_catalog: wrote {SNAPSHOT_PATH.relative_to(ROOT)}")
        return 0
    current = SNAPSHOT_PATH.read_text(encoding="utf-8") if SNAPSHOT_PATH.exists() else ""
    if current == text:
        print("gen_deferred_catalog: catalog/deferred.json is current")
        return 0
    old, new = current.splitlines(), text.splitlines()
    changed = [i for i, (a, b) in enumerate(zip(old, new, strict=False)) if a != b]
    where = f"first differing line {changed[0] + 1}" if changed else "length differs"
    print(
        "gen_deferred_catalog: catalog/deferred.json is stale "
        f"({where}); run python scripts/gen_deferred_catalog.py --generate",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
