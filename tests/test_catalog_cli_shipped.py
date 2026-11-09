"""The catalog CLI must work using only the published Python files."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


def test_catalog_cli_from_shipped_tree(tmp_path):
    root = Path(__file__).resolve().parents[1]
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc")
    shutil.copytree(root / "src", tmp_path / "src", ignore=ignore)
    shutil.copytree(root / "scripts", tmp_path / "scripts", ignore=ignore)
    cli = tmp_path / "scripts" / "check_catalog_regression.py"
    result = subprocess.run(  # noqa: S603 - fixed repo-local CLI and Python executable
        [sys.executable, str(cli)],
        cwd=tmp_path,
        env={"UNIFI_TOOL_MODE": "discovery"},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    names = {line.strip().split("  ->  ")[0] for line in result.stdout.splitlines()[1:]}
    assert "list_hosts" in names
    assert "search_tools" not in names
