#!/usr/bin/env python3
"""Run every "Example call (tool):" block of docs/TOOL-USAGE.md against the local mock.

The server runs over MCP stdio with UNIFI_WRITE_POLICY=dry-run, the synthetic key `api-key-1` and
UNIFI_API_BASE_URL pointed at tests/support/tool_usage_mock/mock_api.py on 127.0.0.1 (ephemeral
port), so no real controller or account is contacted and nothing is written upstream. The set of
examples is read from the document, not hard-coded.

Usage: python3 scripts/run_tool_usage_examples.py [--report PATH]
Exit status is non-zero when any example is not "pass".
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import shutil
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "TOOL-USAGE.md"
sys.path.insert(0, str(ROOT / "tests" / "support" / "tool_usage_mock"))
import mock_api  # noqa: E402

HEADER = re.compile(r"^Example call \((?P<tool>[a-z0-9_]+)\):\s*$")
# The documentation uses a placeholder console; the mock serves these synthetic consoles.
PLACEHOLDER_HOST = "my-console"
MOCK_HOST = "main-office-gw"
TOOL_GAP = {404, 405}


def parse_examples(text: str) -> list[dict]:
    """Every `Example call (tool):` block: ordinal id, 1-based doc line, tool, arguments."""
    lines = text.splitlines()
    found = []
    for i, line in enumerate(lines):
        m = HEADER.match(line)
        if not m:
            continue
        body = []
        for nxt in lines[i + 1 :]:
            if not nxt.strip():
                break
            body.append(nxt)
        args = json.loads("\n".join(body))
        found.append(
            {"example_id": len(found) + 1, "doc_line": i + 1, "tool": m["tool"], "args": args}
        )
    return found


def start_mock() -> tuple[ThreadingHTTPServer, str]:
    mock_api.Handler.state = mock_api.build(json.loads(mock_api.FIXTURES.read_text()))
    mock_api.Handler.snapshot = mock_api.snapshot_image()
    mock_api.Handler.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), mock_api.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def with_mock_host(value):
    if isinstance(value, dict):
        return {k: with_mock_host(v) for k, v in value.items()}
    if isinstance(value, list):
        return [with_mock_host(v) for v in value]
    return MOCK_HOST if value == PLACEHOLDER_HOST else value


def classify(error: str | None, delta: list[dict]) -> str:
    if error is None and not any(r.get("status") in TOOL_GAP for r in delta):
        return "pass"
    if any(r.get("status") in TOOL_GAP for r in delta):
        return "mock-gap"
    return "fix-needed"


async def run(examples: list[dict], base_url: str) -> list[dict]:
    from fastmcp import Client
    from fastmcp.client.transports import StdioTransport

    server_cmd = (
        shutil.which("unifi-fabric-mcp", path=str(Path(sys.executable).parent))
        or "unifi-fabric-mcp"
    )
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
        "UNIFI_API_BASE_URL": base_url,
        "UNIFI_API_KEY": mock_api.API_KEY,
        "UNIFI_WRITE_POLICY": "dry-run",
        "UNIFI_TOOL_MODE": "full",
        "UNIFI_LOG_LEVEL": "ERROR",
    }
    records = []
    async with Client(
        StdioTransport(command=server_cmd, args=[], env=env, log_file=open(os.devnull, "w"))
    ) as client:
        for ex in examples:
            before = len(mock_api.Handler.requests)
            error = None
            try:
                result = await client.call_tool(
                    ex["tool"], with_mock_host(ex["args"]), raise_on_error=False
                )
                if result.is_error:
                    error = (
                        " ".join(getattr(c, "text", "") for c in result.content)[:300]
                        or "tool error"
                    )
            except Exception as exc:  # noqa: BLE001 - recorded, not hidden
                error = f"{type(exc).__name__}: {exc}"[:300]
            delta = [
                r for r in mock_api.Handler.requests[before:] if not r["path"].startswith("/_demo/")
            ]
            last = delta[-1] if delta else None
            result_name = classify(error, delta)
            records.append(
                {
                    "example_id": ex["example_id"],
                    "doc_line": ex["doc_line"],
                    "tool": ex["tool"],
                    "mode": "dry-run",
                    "mock_route": last["path"] if last else None,
                    "mock_method": last["method"] if last else None,
                    "result": result_name,
                    "upstream_mutations": sum(
                        1 for r in delta if r["method"] != "GET" and not r.get("read_post")
                    ),
                    "fix_slice": None
                    if result_name == "pass"
                    else ("U-2" if result_name == "mock-gap" else "U-doc"),
                    **({"error": error} if error else {}),
                }
            )
    return records


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--report", type=Path, help="write JSON records here")
    args = ap.parse_args(argv)
    examples = parse_examples(DOC.read_text())
    server, base_url = start_mock()
    try:
        records = asyncio.run(run(examples, base_url))
    finally:
        server.shutdown()
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(records, indent=2) + "\n")
    bad = [r for r in records if r["result"] != "pass"]
    mutations = sum(r["upstream_mutations"] for r in records)
    print(
        f"{len(records)} examples: {len(records) - len(bad)} pass, {len(bad)} not pass, "
        f"{mutations} upstream mutations"
    )
    for r in bad:
        print(
            f"  #{r['example_id']} line {r['doc_line']} {r['tool']}: {r['result']} "
            f"{r.get('error', '')}"
        )
    return 1 if bad or mutations else 0


if __name__ == "__main__":
    raise SystemExit(main())
