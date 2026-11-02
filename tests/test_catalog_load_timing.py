"""Cold catalog startup is functional; elapsed measurements are diagnostics only."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_cold_catalog_load_timing(record_property):
    code = """
import asyncio, json, time
start = time.monotonic()
from unifi_fabric import server
server._settings = server.Settings(api_key="catalog-load-test-key")
tools = asyncio.run(server.mcp.list_tools())
print(json.dumps({"seconds": time.monotonic() - start, "names": [t.name for t in tools]}))
"""
    result = subprocess.run(  # noqa: S603 - fixed interpreter and inline test code
        [sys.executable, "-c", code],
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "src")},
        capture_output=True,
        text=True,
        check=True,
    )
    measurement = json.loads(result.stdout.splitlines()[-1])
    names = measurement["names"]
    assert names
    assert len(names) == len(set(names))
    record_property("catalog_load_seconds", measurement["seconds"])
    record_property("catalog_tool_count", len(names))
