#!/usr/bin/env python3
"""Generate the committed runtime tool-input-schema baseline.

Usage:
    python scripts/gen_tool_input_schemas.py --write
    python scripts/gen_tool_input_schemas.py --check
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "tests" / "fixtures" / "tool_input_schemas_baseline.json"


def render() -> str:
    sys.path.insert(0, str(ROOT))
    from scripts.gen_tools_doc import _runtime_tools

    tools = asyncio.run(_runtime_tools())
    payload: dict[str, Any] = {
        "schemas": {str(tool.name): tool.parameters for tool in tools},
        "tool_count": len(tools),
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--write", action="store_true", help="Regenerate the committed baseline.")
    action.add_argument("--check", action="store_true", help="Fail if the baseline is stale.")
    args = parser.parse_args(argv)
    generated = render()
    if args.write:
        BASELINE.write_text(generated, encoding="utf-8")
        return 0
    if BASELINE.read_text(encoding="utf-8") != generated:
        print(
            "tool input schema baseline is stale; run scripts/gen_tool_input_schemas.py --write",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
