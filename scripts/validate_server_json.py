#!/usr/bin/env python3
"""Validate server.json against the vendored MCP registry server schema.

The schema at ``schemas/server.schema.json`` is a byte-for-byte copy of the
published MCP registry schema referenced by ``server.json``'s ``$schema`` field
(``https://static.modelcontextprotocol.io/schemas/.../server.schema.json``). It
is vendored so this check is hermetic and offline — no network fetch at release
or CI time. This catches, among other things, the ``description`` ``maxLength``
(100) the registry enforces.

Exit 0 = valid; exit 1 = schema violation; exit 2 = usage/environment error.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SERVER_JSON = REPO_ROOT / "server.json"
SCHEMA = REPO_ROOT / "schemas" / "server.schema.json"


def main() -> int:
    try:
        import jsonschema
    except ImportError:
        print("::error::jsonschema is not installed (pip install jsonschema)", file=sys.stderr)
        return 2

    if not SERVER_JSON.is_file():
        print(f"::error::{SERVER_JSON} not found", file=sys.stderr)
        return 2
    if not SCHEMA.is_file():
        print(f"::error::vendored schema {SCHEMA} not found", file=sys.stderr)
        return 2

    instance = json.loads(SERVER_JSON.read_text())
    schema = json.loads(SCHEMA.read_text())

    validator = jsonschema.Draft7Validator(schema)
    errors = sorted(validator.iter_errors(instance), key=lambda e: list(e.path))
    if errors:
        for err in errors:
            loc = "/".join(str(p) for p in err.path) or "<root>"
            print(f"::error::server.json schema violation at {loc}: {err.message}", file=sys.stderr)
        return 1

    desc_len = len(instance.get("description", ""))
    print(f"server.json valid against {SCHEMA.name} (description length {desc_len} <= 100).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
