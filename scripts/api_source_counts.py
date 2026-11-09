#!/usr/bin/env python3
"""Report how many tools each API-source level holds (app, app/source, read/write).

Reads the runtime catalog (every registered tool's ``unifi/apiSource`` metadata, derived
from the routes it calls; see ``src/unifi_fabric/api_sources.py``), so the counts are
what ``tools/list`` serves with every source enabled. Also reports, per selector, how many
tools ``UNIFI_EXCLUDE=source:<selector>`` would remove (a mixed tool is removed by
any private surface it calls).

    python3 scripts/api_source_counts.py            # markdown
    python3 scripts/api_source_counts.py --json     # machine-readable
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))


async def _report() -> dict:
    from gen_tools_doc import complete_catalog_env

    with complete_catalog_env():
        from unifi_fabric import api_sources
        from unifi_fabric.server import mcp

        tools = await mcp.list_tools()
    table = api_sources.table()
    classes: dict[str, str] = {}
    unclassified: list[str] = []
    for tool in tools:
        pairs = table.get(tool.name)
        if pairs is None:
            unclassified.append(tool.name)
            continue
        classes[tool.name] = api_sources.class_id(pairs, api_sources.selection_access(tool))
    removed: dict[str, int] = {}
    for selector in api_sources.valid_selectors():
        (parsed,) = api_sources.parse_disabled_sources(selector)
        removed[selector] = sum(
            1
            for tool in tools
            if tool.name in table
            and api_sources.is_disabled(
                table[tool.name], api_sources.selection_access(tool), (parsed,), tool_name=tool.name
            )
        )
    return {
        "total": len(tools),
        "counts": api_sources.counts(classes),
        "removed_by_selector": removed,
        "unclassified": sorted(unclassified),
    }


def _markdown(report: dict) -> str:
    lines = [f"# API-source counts ({report['total']} tools)", ""]
    for level in ("app", "app/source", "app/source/access", "app/access", "access"):
        lines += [f"## {level}", "", "| class | tools |", "| --- | ---: |"]
        lines += [f"| `{k}` | {v} |" for k, v in report["counts"][level].items()]
        lines.append("")
    lines += [
        "## Tools removed per UNIFI_EXCLUDE source: selector",
        "",
        "| selector | removed |",
        "| --- | ---: |",
    ]
    lines += [f"| `{k}` | {v} |" for k, v in report["removed_by_selector"].items()]
    if report["unclassified"]:
        lines += ["", "Unclassified (regenerate the table): " + ", ".join(report["unclassified"])]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    report = asyncio.run(_report())
    sys.stdout.write(json.dumps(report, indent=2) + "\n" if args.json else _markdown(report))
    return 1 if report["unclassified"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
