"""Run an allocation measurement in a fresh interpreter that no tracer observes.

tracemalloc stores a trace for every allocated memory block while it is tracing, and
coverage adds its own callback for every executed line of measured code. A peak-bound
test that runs the scrubber in the pytest worker pays both costs at once: in CI the
AT4 ``[mixed]`` case ran for 59.5 minutes, and in a full local run the one-megabyte
case took 2305 s in-process under coverage against 367 s in this child.

``run`` executes ``module:function(*args)`` in a new ``python -I`` process. The child
starts no coverage (pytest-cov 7 has no subprocess support and this repository does
not set coverage's ``patch = subprocess``), and before calling the function it checks
that no trace function, profile function or ``sys.monitoring`` tool is installed and
that tracemalloc is not already tracing. The function starts and stops tracemalloc
itself, so the measured peak means what it meant in-process: the peak size of the
blocks allocated after ``tracemalloc.start()``. Arguments and the return value travel
as JSON. A child failure fails the calling test with the child's output.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

_CHILD = """
import importlib, json, sys, tracemalloc
sys.path.insert(0, sys.argv[1])
observers = []
if sys.gettrace() is not None:
    observers.append("trace function")
if sys.getprofile() is not None:
    observers.append("profile function")
if any(sys.monitoring.get_tool(tool) is not None for tool in range(6)):
    observers.append("sys.monitoring tool")
if tracemalloc.is_tracing():
    observers.append("tracemalloc")
if "coverage" in sys.modules:
    observers.append("coverage imported")
if observers:
    raise SystemExit("measurement child is observed: " + ", ".join(observers))
module, name = sys.argv[2].split(":")
result = getattr(importlib.import_module(module), name)(*json.loads(sys.argv[3]))
with open(sys.argv[4], "w", encoding="utf-8") as fh:
    json.dump(result, fh)
"""

#: Environment that could start a tracer or change the child's interpreter.
_DROP_PREFIXES = ("COV_CORE_", "COVERAGE_", "PYTHON", "UNIFI_", "MCP_", "FASTMCP_")


def child_env() -> dict[str, str]:
    """The calling environment without tracer, interpreter or product configuration."""
    return {k: v for k, v in os.environ.items() if not k.startswith(_DROP_PREFIXES)}


def run(target: str, *args: Any) -> Any:
    """Return ``target(*args)`` computed in an untraced child interpreter."""
    with tempfile.TemporaryDirectory(prefix="untraced-") as tmp:
        out = Path(tmp) / "result.json"
        proc = subprocess.run(  # noqa: S603 -- fixed interpreter and in-repo target
            [sys.executable, "-I", "-c", _CHILD, str(ROOT), target, json.dumps(args), str(out)],
            cwd=ROOT,
            env=child_env(),
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0 or not out.exists():
            raise AssertionError(
                f"untraced child {target} exited {proc.returncode}\n"
                f"stdout:\n{proc.stdout[-4000:]}\nstderr:\n{proc.stderr[-8000:]}"
            )
        return json.loads(out.read_text(encoding="utf-8"))
