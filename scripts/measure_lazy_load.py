#!/usr/bin/env python3
"""Measure startup time, memory and cold/warm call cost (public #41 lazy loading).

Two measurements, each in fresh processes, ``--runs`` times (medians reported):

``startup``  spawn ``python -m unifi_fabric`` over stdio, then ``initialize`` and the first
             ``tools/list``: wall time to each, the child's CPU seconds (utime + stime),
             RSS and peak RSS (Linux ``/proc``), the tool count and the list size. No
             credential: ``UNIFI_API_KEY`` is a fixed placeholder and no tool is called.
``calls``    in-process MCP client, full mode, on the fake upstream of
             ``tests/upstream_harness.py`` (no console; harness key ``k-test``): the
             session's first call of each tool (cold) and the median of the next calls
             (warm), plus the deferred step load time when the server defers.

``--src`` points at another checkout's ``src`` (the base, for before/after); ``--preload``
sets ``UNIFI_PRELOAD`` (omit it for a base that has no such setting).

    python scripts/measure_lazy_load.py startup --runs 5 --preload none
    python scripts/measure_lazy_load.py calls --runs 5 --preload none
    python scripts/measure_lazy_load.py startup --runs 5 --src ../base/src

Prints one JSON line per run and a ``summary`` line of medians.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CALL_TOOLS = ("get_host", "list_networks", "list_cameras")


def _env(src: str | None, preload: str | None, mode: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("UNIFI_", "MCP_"))}
    env.update(UNIFI_API_KEY="placeholder-not-a-key", UNIFI_TOOL_MODE=mode)
    if preload is not None:
        env["UNIFI_PRELOAD"] = preload
    if src:
        env["PYTHONPATH"] = str(Path(src).resolve())
    return env


def _proc(pid: int) -> dict[str, float]:
    out: dict[str, float] = {}
    with open(f"/proc/{pid}/status", encoding="ascii") as fh:
        for line in fh:
            key, _, value = line.partition(":")
            if key in ("VmRSS", "VmHWM"):
                out[key] = int(value.split()[0]) / 1024
    with open(f"/proc/{pid}/stat", encoding="ascii") as fh:
        fields = fh.read().rsplit(")", 1)[1].split()
    out["cpu_s"] = (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")
    return out


def startup_once(src: str | None, preload: str | None, mode: str) -> dict[str, Any]:
    started = time.perf_counter()
    child = subprocess.Popen(  # noqa: S603 - this interpreter, fixed module
        [sys.executable, "-m", "unifi_fabric"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=_env(src, preload, mode),
        cwd="/tmp",  # noqa: S108 - no repository on the import path but --src
    )
    if child.stdin is None or child.stdout is None:
        raise SystemExit("measure_lazy_load: no pipes to the server")

    def send(message: dict[str, Any]) -> None:
        child.stdin.write((json.dumps(message) + "\n").encode())  # type: ignore[union-attr]
        child.stdin.flush()  # type: ignore[union-attr]

    def receive(want: int) -> dict[str, Any]:
        while True:
            line = child.stdout.readline()  # type: ignore[union-attr]
            if not line:
                raise SystemExit("measure_lazy_load: the server exited")
            message = json.loads(line)
            if message.get("id") == want:
                return message

    send(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "measure", "version": "0"},
            },
        }
    )
    receive(1)
    init_s = time.perf_counter() - started
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    listed = receive(2)
    list_s = time.perf_counter() - started
    proc = _proc(child.pid)
    child.stdin.close()
    child.terminate()
    child.wait()
    return {
        "measure": "startup",
        "mode": mode,
        "preload": preload,
        "init_s": round(init_s, 3),
        "list_s": round(list_s, 3),
        "cpu_s": round(proc["cpu_s"], 2),
        "rss_mib": round(proc["VmRSS"], 1),
        "hwm_mib": round(proc["VmHWM"], 1),
        "tools": len(listed["result"]["tools"]),
        "list_bytes": len(json.dumps(listed["result"])),
        "load1": round(os.getloadavg()[0], 1),
    }


CALLS_CHILD = r"""
import asyncio, json, os, statistics, sys, time
sys.path.insert(0, os.environ["MEASURE_ROOT"])
tools, warm_n = sys.argv[1].split(","), int(sys.argv[2])
async def main():
    import pytest
    from fastmcp import Client
    t = time.perf_counter()
    from unifi_fabric import server
    import_s = time.perf_counter() - t
    loads = {}
    try:
        from unifi_fabric.catalog import deferred
        controller = deferred.controller_for(server.mcp)
    except ImportError:
        controller = None
    if controller is not None:
        def emit(line):
            record = json.loads(line)
            loads[record["step"]] = record["duration_ms"]
        controller._emit = emit
    from tests import upstream_harness as uh, tool_args
    components = server.mcp._local_provider._components
    args = {n: dict(tool_args.generated_args(components[f"tool:{n}@"])) for n in tools}
    out = []
    with pytest.MonkeyPatch.context() as mp:
        uh.install(mp, uh.FakeUpstream(), tool_mode="full")
        async with Client(server.mcp) as client:
            for name in tools:
                before = dict(loads)
                t = time.perf_counter()
                first = await client.call_tool(name, args[name], raise_on_error=False)
                cold = time.perf_counter() - t
                step_ms = sum(v for k, v in loads.items() if k not in before)
                warm = []
                for _ in range(warm_n):
                    t = time.perf_counter()
                    res = await client.call_tool(name, args[name], raise_on_error=False)
                    warm.append(time.perf_counter() - t)
                out.append({
                    "tool": name,
                    "cold_ms": round(cold * 1000, 1),
                    "warm_ms": round(statistics.median(warm) * 1000, 2),
                    "step_load_ms": step_ms,
                    "is_error": bool(first.is_error or res.is_error),
                })
    print(json.dumps({"import_s": round(import_s, 3), "calls": out}))
asyncio.run(main())
"""


def calls_once(src: str | None, preload: str | None, warm_n: int) -> dict[str, Any]:
    env = _env(src, preload, "full")
    env.pop("UNIFI_API_KEY")
    env["MEASURE_ROOT"] = str(ROOT)
    done = subprocess.run(  # noqa: S603 - this interpreter, fixed child program
        [sys.executable, "-c", CALLS_CHILD, ",".join(CALL_TOOLS), str(warm_n)],
        env=env,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    result = json.loads(done.stdout.strip().splitlines()[-1])
    result.update(measure="calls", preload=preload, load1=round(os.getloadavg()[0], 1))
    return result


def _median(rows: list[dict[str, Any]], key: str) -> float:
    return round(statistics.median(float(r[key]) for r in rows), 3)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("measure", choices=("startup", "calls"))
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--preload", help="UNIFI_PRELOAD (omit for a base without it)")
    parser.add_argument("--mode", default="full", choices=("full", "discovery"))
    parser.add_argument("--src", help="another checkout's src directory (the base)")
    parser.add_argument("--warm", type=int, default=5, help="warm calls per tool")
    args = parser.parse_args(argv)
    rows: list[dict[str, Any]] = []
    for _ in range(args.runs):
        row = (
            startup_once(args.src, args.preload, args.mode)
            if args.measure == "startup"
            else calls_once(args.src, args.preload, args.warm)
        )
        rows.append(row)
        print(json.dumps(row), flush=True)
    if args.measure == "startup":
        summary = {
            key: _median(rows, key)
            for key in ("init_s", "list_s", "cpu_s", "rss_mib", "hwm_mib", "load1")
        }
        summary.update(tools=rows[0]["tools"], list_bytes=rows[0]["list_bytes"])
    else:
        summary = {"import_s": _median(rows, "import_s"), "load1": _median(rows, "load1")}
        for index, name in enumerate(CALL_TOOLS):
            per = [r["calls"][index] for r in rows]
            summary[name] = {
                "cold_ms": _median(per, "cold_ms"),
                "warm_ms": _median(per, "warm_ms"),
                "step_load_ms": _median(per, "step_load_ms"),
                "errors": sum(1 for p in per if p["is_error"]),
            }
    print(
        json.dumps(
            {
                "summary": args.measure,
                "src": args.src or "head",
                "preload": args.preload,
                "mode": args.mode,
                "runs": args.runs,
                **summary,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
