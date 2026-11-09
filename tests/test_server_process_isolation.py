"""The sanctioned server-import path must preserve every package binding."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from tests._server_import_isolation import run_isolated_test


@pytest.mark.parametrize(
    "nodeid",
    [
        "tests/test_test_isolation.py::test_reload_under_bearer_env",
        "tests/test_test_isolation.py::test_server_import_namespace_is_restored[reimport]",
    ],
    ids=["reload", "reimport"],
)
def test_all_package_bindings_survive_server_import(nodeid):
    # Keep actual objects alive so id reuse cannot hide a replacement.
    before = {
        name: (module, vars(module).copy())
        for name, module in tuple(sys.modules.items())
        if name == "unifi_fabric" or name.startswith("unifi_fabric.")
    }
    reports = run_isolated_test(nodeid, Path(__file__).resolve().parents[1])
    assert all(report.passed for report in reports), reports
    after = {
        name: module
        for name, module in tuple(sys.modules.items())
        if name == "unifi_fabric" or name.startswith("unifi_fabric.")
    }
    differences = []
    for module_name in before.keys() | after.keys():
        if module_name not in before or module_name not in after:
            differences.append(module_name)
            continue
        module, namespace = before[module_name]
        if after[module_name] is not module:
            differences.append(module_name)
        current = vars(after[module_name])
        for name in namespace.keys() | current.keys():
            if name not in namespace or name not in current or current[name] is not namespace[name]:
                differences.append(f"{module_name}.{name}")
    assert not differences, "server import leaked bindings: " + ", ".join(sorted(differences))


def test_child_assertion_failure_is_preserved(tmp_path):
    """A disposable test must still fail the outer run with its real assertion."""
    child = tmp_path / "test_child_failure.py"
    child.write_text(
        'def test_original_assertion():\n    assert False, "original child assertion"\n',
        encoding="utf-8",
    )
    reports = run_isolated_test(str(child), Path(__file__).resolve().parents[1])
    assert [report.when for report in reports] == ["setup", "call", "teardown"]
    assert reports[0].passed and reports[2].passed
    assert reports[1].failed
    assert "original child assertion" in str(reports[1].longrepr)
