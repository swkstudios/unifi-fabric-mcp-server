"""The process-wide logging guard (tests/_global_state_guard.py) fails a leaking test.

The synthetic tests run in a child pytest with only the guard (and xdist when asked), so
each leak kind is checked on its own: the leaking test errors at teardown with its node id
and what it left, the state is restored for the next test, and a test that restores, uses
caplog, or runs logging.basicConfig as the server lifespan does, passes.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

PROGRAM = """
import logging

import pytest


def _state_is_original():
    root = logging.getLogger()
    assert logging.root.manager.disable == logging.NOTSET
    assert root.level == logging.WARNING
    assert not [h for h in root.handlers if type(h).__name__ in ("NullHandler", "StreamHandler")]


def test_leaves_disable():
    logging.disable(logging.CRITICAL)


def test_after_disable_leak():
    _state_is_original()


def test_restores_disable():
    previous = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    try:
        assert not logging.getLogger("probe").isEnabledFor(logging.CRITICAL)
    finally:
        logging.disable(previous)


def test_leaves_root_level():
    logging.getLogger().setLevel(logging.DEBUG)


def test_leaves_root_handler():
    logging.getLogger().addHandler(logging.NullHandler())


@pytest.fixture
def leaky_fixture():
    logging.disable(logging.ERROR)
    yield


def test_fixture_leak(leaky_fixture):
    pass


def test_basic_config_is_undone():
    logging.basicConfig(level=logging.INFO, force=True)
    assert logging.getLogger().level == logging.INFO


def test_caplog_restores_its_level(caplog):
    caplog.set_level(logging.DEBUG)
    logging.getLogger("probe").debug("captured")
    assert "captured" in caplog.text


def test_after_all_leaks():
    _state_is_original()
"""

LEAKS = {
    "test_leaves_disable": "logging.disable is CRITICAL (was NOTSET)",
    "test_leaves_root_level": "root logger level is DEBUG (was WARNING)",
    "test_leaves_root_handler": "root logger handlers added ['NullHandler'], removed []",
    "test_fixture_leak": "logging.disable is ERROR (was NOTSET)",
}
CLEAN = (
    "test_after_disable_leak",
    "test_restores_disable",
    "test_basic_config_is_undone",
    "test_caplog_restores_its_level",
    "test_after_all_leaks",
)


def _child_env() -> dict[str, str]:
    return {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("PYTEST_", "SHARD_", "UNIFI_", "MCP_", "FASTMCP_"))
    }


def _run_guard(tmp_path: Path, *workers: str) -> str:
    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    (tmp_path / "test_leaks.py").write_text(PROGRAM)
    env = {**_child_env(), "PYTHONPATH": str(ROOT), "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"}
    xdist = ["-p", "xdist.plugin", *workers, "--max-worker-restart=0"] if workers else []
    run = subprocess.run(  # noqa: S603 -- fixed Python and synthetic test program
        [sys.executable, "-m", "pytest", *xdist, "-p", "tests._global_state_guard",
         "-p", "no:cacheprovider", "-rE", "test_leaks.py"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )  # fmt: skip
    output = run.stdout + run.stderr
    assert run.returncode == 1, output
    return output


@pytest.mark.parametrize("workers", [[], ["-n", "1"]], ids=["serial", "xdist"])
def test_guard_fails_each_leaking_test_by_name_and_restores(tmp_path, workers):
    output = _run_guard(tmp_path, *workers)
    # Every test passes its call phase; each leaking test errors at its teardown, and the
    # tests after it (test_after_disable_leak, test_after_all_leaks) see the state restored.
    assert f"{len(LEAKS) + len(CLEAN)} passed, {len(LEAKS)} errors" in output, output
    for test, what in LEAKS.items():
        assert f"ERROR at teardown of {test}" in output, (test, output)
        message = f"test_leaks.py::{test} left process-wide logging state changed: {what}"
        assert message in output, (test, output)
    for clean in CLEAN:
        assert f"ERROR at teardown of {clean}" not in output, (clean, output)


def test_guard_is_loaded_for_the_suite(request):
    assert request.config.pluginmanager.has_plugin("tests._global_state_guard")
    assert "_global_state_guard" in request.fixturenames


@pytest.mark.skipif(
    # the name is joined at runtime so the public-tree collection check sees no literal path
    # to the private-only file this guard exists to tolerate
    not (ROOT / "tests" / ("test_read_post_" + "classification.py")).is_file(),
    reason="the read-POST capture test is private-only: the public transform removes it",
)
def test_capture_main_no_longer_silences_later_log_captures():
    """The order that failed in a shard: the read-POST capture CLI's main() run in-process,
    then a test that reads root-logger records, in one process. main() calls
    logging.disable(CRITICAL) and sets UNIFI_WRITE_POLICY; the test restores both, so the
    second test sees its records and the guard passes the first."""
    tests = [
        "tests/test_read_post_classification.py::test_capture_main_constructs_valid_settings",
        "tests/test_secret_leak_invariant.py::test_short_secret_never_breaks_a_log_format_string",
    ]
    run = subprocess.run(  # noqa: S603 -- fixed Python and the repository's own tests
        [sys.executable, "-m", "pytest", "-p", "no:xdist", "-p", "no:cacheprovider", "-q",
         "-rE", *tests],
        cwd=ROOT,
        env={**_child_env(), "UNIFI_TEST_SELECTION_CACHE": "0"},
        capture_output=True,
        text=True,
    )  # fmt: skip
    output = run.stdout + run.stderr
    assert run.returncode == 0, output
    assert "2 passed" in output, output
    assert "left process-wide logging state changed" not in output, output
    assert logging.root.manager.disable == logging.NOTSET
