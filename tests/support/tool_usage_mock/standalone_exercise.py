#!/usr/bin/env python3
"""Standalone mock exercise: three read calls through the real server against the mock.

Needs a running mock (tests/support/tool_usage_mock/mock_api.py) and UNIFI_API_BASE_URL pointing
at it. Calls list_hosts, list_sites and list_devices over MCP stdio with the synthetic key
`api-key-1` and UNIFI_WRITE_POLICY=dry-run, prints what came back, then reads the mock's request
log and fails unless it holds only GET requests. Nothing leaves 127.0.0.1.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import urllib.request
from pathlib import Path

from fastmcp import Client
from fastmcp.client.transports import StdioTransport

BASE = os.environ.get("UNIFI_API_BASE_URL", "http://127.0.0.1:8765").rstrip("/")
KEY = "api-key-1"
READS = ("list_hosts", "list_sites", "list_devices")


async def main() -> int:
    server = shutil.which("unifi-fabric-mcp", path=str(Path(sys.executable).parent))
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
        "UNIFI_API_BASE_URL": BASE,
        "UNIFI_API_KEY": KEY,
        "UNIFI_WRITE_POLICY": "dry-run",
        "UNIFI_TOOL_MODE": "full",
        "UNIFI_LOG_LEVEL": "ERROR",
    }
    transport = StdioTransport(
        command=server or "unifi-fabric-mcp", args=[], env=env, log_file=open(os.devnull, "w")
    )
    async with Client(transport) as client:
        for name in READS:
            result = await client.call_tool(name, {})
            data = result.data if isinstance(result.data, dict) else {}
            print(f"{name}: {data.get('_count', '?')} results")
    request = urllib.request.Request(f"{BASE}/_demo/requests")  # noqa: S310 - loopback mock
    with urllib.request.urlopen(request) as response:  # noqa: S310 - loopback mock
        log = json.load(response)
    writes = [r for r in log if r["method"] != "GET"]
    print(f"mock requests: {len(log)}, writes: {len(writes)}")
    return 1 if writes or not log else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
