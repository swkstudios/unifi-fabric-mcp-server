"""Run reload/re-import tests in disposable interpreters, preserving pytest reports."""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import tempfile
from functools import cache
from pathlib import Path

import pytest
from _pytest.reports import TestReport

_CHILD_REPORTS = "_FABRIC_ISOLATED_REPORTS"


@cache
def needs_isolation(path: Path) -> bool:
    """Select whole modules automatically: reload helpers can serve many tests."""
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Call):
            name = getattr(node.func, "attr", getattr(node.func, "id", ""))
            if name == "reload":
                return True
            if name in {"import_module", "__import__"} and any(
                isinstance(arg, ast.Constant) and arg.value == "unifi_fabric.server"
                for arg in node.args
            ):
                return True
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and isinstance(node.slice, ast.Constant)
            and node.slice.value == "unifi_fabric.server"
        ):
            return True
    return False


def run_isolated_test(nodeid: str, root: Path) -> list[TestReport]:
    """Only reports cross back; logging, caches and registries die with the child."""
    with tempfile.TemporaryDirectory(prefix="fabric-import-test-") as directory:
        report_path = Path(directory) / "reports.jsonl"
        env = os.environ.copy()
        env[_CHILD_REPORTS] = str(report_path)
        # Do not inherit caller item selectors or an outer pytest basetemp.
        env.pop("PYTEST_ADDOPTS", None)
        result = subprocess.run(  # noqa: S603 -- pytest node id, no shell
            [
                sys.executable,
                "-m",
                "pytest",
                "-n",
                "0",
                "-c",
                str(root / "pyproject.toml"),
                "-o",
                "addopts=",
                "-p",
                "no:cacheprovider",
                "-p",
                "tests._server_import_isolation",
                nodeid,
            ],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
        )
        reports = (
            [
                TestReport._from_json(json.loads(line))
                for line in report_path.read_text().splitlines()
            ]
            if report_path.exists()
            else []
        )
        if not reports or (result.returncode != 0 and not any(r.failed for r in reports)):
            raise AssertionError(
                f"isolated pytest exited {result.returncode}:\n{result.stdout}\n{result.stderr}"
            )
        assert any(r.when == "teardown" for r in reports), "incomplete child protocol"
        return reports


def pytest_runtest_logreport(report: TestReport) -> None:
    path = os.environ.get(_CHILD_REPORTS)
    if path:
        with Path(path).open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(report._to_json()) + "\n")


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_protocol(item: pytest.Item, nextitem: pytest.Item | None) -> bool | None:
    if os.environ.get(_CHILD_REPORTS) or not needs_isolation(item.path):
        return None
    # Preserve scheduler order and the original setup/call/teardown outcomes.
    item.ihook.pytest_runtest_logstart(nodeid=item.nodeid, location=item.location)
    try:
        reports = run_isolated_test(item.nodeid, item.config.rootpath)
    except (AssertionError, OSError) as error:
        reports = [
            TestReport(
                item.nodeid, item.location, dict(item.keywords), "failed", str(error), "call"
            )
        ]
    for report in reports:
        item.ihook.pytest_runtest_logreport(report=report)
    item.ihook.pytest_runtest_logfinish(nodeid=item.nodeid, location=item.location)
    return True
