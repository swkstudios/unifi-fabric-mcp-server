"""Guard: importing a test module must not build the tool catalog.

Under pytest-xdist every worker imports (collects) every test module. A module-level
``TOOLS = _tools()`` - or any list derived from it - builds the full registered catalog (and
whatever is computed from it) in every worker before the first test runs. Build the catalog
lazily instead: ``tests._tool_catalog.tools()`` inside a function or fixture, and
``tests._tool_catalog.lazy_parametrize`` / a ``tool`` argument for per-tool parametrization.

This test runs ``pytest --collect-only`` over ``tests/`` in a subprocess with
``tests/_collect_guard_plugin.py`` loaded, which records catalog builds/reads that happen
while a module is being imported, and fails for any module outside the allowlist below.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

# Modules allowed to build the catalog at import: none. Every test module builds it lazily
# (``tools()`` / ``LazyCatalog`` / ``lazy_parametrize``); do not add entries.
ALLOWLIST: set[str] = set()

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_no_test_module_builds_the_tool_catalog_at_import(tmp_path):
    out = tmp_path / "guard.json"
    env = {**os.environ, "COLLECT_GUARD_OUT": str(out), "PYTHONDONTWRITEBYTECODE": "1"}
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests",
            "--collect-only",
            "-q",
            "-p",
            "tests._collect_guard_plugin",
            "-p",
            "no:cacheprovider",
            "-p",
            "no:xdist",
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert out.exists(), (proc.returncode, proc.stdout[-2000:], proc.stderr[-2000:])
    counts: dict[str, int] = json.loads(out.read_text())
    offenders = sorted(m for m, n in counts.items() if n and m not in ALLOWLIST)
    assert offenders == [], (
        "these test modules build the tool catalog while being imported (use "
        "tests._tool_catalog.tools() lazily / lazy_parametrize): " + ", ".join(offenders)
    )
    if proc.returncode == 0:  # a collection error hides modules, so only judge staleness when clean
        stale = sorted(ALLOWLIST - {m for m, n in counts.items() if n})
        assert stale == [], f"converted modules still allowlisted - remove them: {stale}"
