#!/usr/bin/env python3
"""Generate the committed typed tool catalog (src/unifi_fabric/_generated/catalog.json).

Usage:
    python scripts/gen_tool_catalog.py --write
    python scripts/gen_tool_catalog.py --check
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def render() -> str:
    from unifi_fabric.catalog import render_catalog
    from unifi_fabric.catalog_build import build_catalog

    return render_catalog(build_catalog())


def main(argv: list[str] | None = None) -> int:
    from unifi_fabric.catalog import CATALOG_PATH

    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--write", action="store_true", help="Regenerate the committed catalog.")
    action.add_argument("--check", action="store_true", help="Fail if the catalog is stale.")
    args = parser.parse_args(argv)
    generated = render()
    if args.write:
        CATALOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        CATALOG_PATH.write_text(generated, encoding="utf-8")
        return 0
    current = CATALOG_PATH.read_text(encoding="utf-8") if CATALOG_PATH.exists() else ""
    if current != generated:
        print(
            "tool catalog is stale; run scripts/gen_tool_catalog.py --write",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
