#!/usr/bin/env python3
"""Write the catalog acceptance artifact handler-resolution.json.

Runs the committed typed catalog through the registrar (unifi_fabric.registration) with a
recording sink and records, for every spec, its id, emitted name and resolved adapter, plus
the counts the catalog acceptance compares: catalog specs, resolved handlers, registered keys and
emitted names (all equal, no duplicates).

Usage:
    python scripts/gen_handler_resolution.py --output <path>
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def _ref(fn) -> str:
    return f"{fn.__module__}:{fn.__qualname__}"


def build() -> dict:
    from unifi_fabric.catalog_registration import registration_specs, validate_registration

    specs = registration_specs()
    bound = validate_registration(specs)
    rows = [
        {
            "id": spec.id,
            "name": spec.name,
            "handler": spec.handler,
            "resolved": _ref(bound[spec.name].handler),
        }
        for spec in specs
    ]
    keys = {(s.family, s.name) for s in specs}
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=False
    ).stdout.strip()
    return {
        "head": head,
        "catalog_specs": len(specs),
        "resolved_handlers": len(bound),
        "registered_keys": len(keys),
        "emitted_names": len({s.name for s in specs}),
        "all_resolved_match_handler_ref": all(r["handler"] == r["resolved"] for r in rows),
        "handlers": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    data = build()
    args.output.write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
    counts = {
        data[k] for k in ("catalog_specs", "resolved_handlers", "registered_keys", "emitted_names")
    }
    ok = len(counts) == 1 and data["all_resolved_match_handler_ref"]
    print(
        f"specs={data['catalog_specs']} resolved={data['resolved_handlers']} "
        f"keys={data['registered_keys']} names={data['emitted_names']} ok={ok}"
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
