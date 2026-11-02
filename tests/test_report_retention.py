"""The controller releases passing tests' captured output, and nothing a summary prints."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BIG = 200_000

# Records, at session end in the controller, the captured-output bytes the terminal
# reporter still holds, per test name.
PROBE = """
import json, os
import pytest

@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session):
    if hasattr(session.config, "workerinput"):
        return
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    held = {}
    for reports in reporter.stats.values():
        for rep in reports:
            name = getattr(rep, "nodeid", "").split("::")[-1]
            for _section, content in getattr(rep, "sections", ()):
                held[name] = held.get(name, 0) + len(content)
    with open(os.environ["RETENTION_OUT"], "w") as fh:
        json.dump(held, fh)
"""

TESTS = f"""
import logging
import pytest

@pytest.fixture
def noisy_teardown():
    yield
    print("teardown-marker " + "t" * {BIG})

def test_pass(noisy_teardown):
    print("pass-marker " + "p" * {BIG})
    logging.getLogger("probe").warning("pass-log-marker " + "l" * {BIG})

def test_fail(noisy_teardown):
    print("fail-marker " + "f" * {BIG})
    assert False

@pytest.fixture
def broken_teardown():
    yield
    raise RuntimeError("teardown broke")

def test_teardown_error(broken_teardown):
    print("teardown-error-marker " + "e" * {BIG})

def test_skip():
    print("skip-marker " + "s" * {BIG})
    pytest.skip("skipped on purpose")

@pytest.mark.xfail(reason="expected", strict=False)
def test_xpass():
    print("xpass-marker " + "x" * {BIG})
"""


def _run(tmp_path, *args, retention=True):
    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    (tmp_path / "conftest.py").write_text(PROBE)
    (tmp_path / "test_noisy.py").write_text(TESTS)
    out = tmp_path / "held.json"
    env = {
        **os.environ,
        "PYTHONPATH": str(ROOT),
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "RETENTION_OUT": str(out),
    }
    plugins = ["-p", "xdist.plugin"] + (["-p", "tests._report_retention"] if retention else [])
    run = subprocess.run(  # noqa: S603 -- fixed Python and synthetic test program
        [sys.executable, "-m", "pytest", *plugins, *args, "test_noisy.py"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )
    output = run.stdout + run.stderr
    # test_fail fails and test_teardown_error errors in every configuration.
    assert run.returncode == 1, output
    assert "1 failed, 2 passed, 1 skipped, 1 xpassed, 1 error" in output, output
    return json.loads(out.read_text()), output


@pytest.mark.parametrize("workers", [[], ["-n", "1"], ["-n", "2"]], ids=["serial", "n1", "n2"])
def test_passing_output_is_released_and_failures_keep_theirs(tmp_path, workers):
    held, output = _run(tmp_path, *workers)
    assert "test_pass" not in held, held
    # Every test that is not an all-phases pass keeps its sections.
    for name in ("test_fail", "test_teardown_error", "test_skip", "test_xpass"):
        assert held.get(name, 0) > BIG, (name, held)
    # The failure and error summaries still print the captured output: the failed
    # test's call and teardown sections, and the teardown error's call output.
    assert "fail-marker" in output
    assert "teardown-marker" in output
    assert "teardown-error-marker" in output
    assert "pass-marker" not in output


@pytest.mark.parametrize("report", ["-rP", "-rA"])
def test_passes_summary_keeps_passing_output(tmp_path, report):
    held, output = _run(tmp_path, "-n", "1", report)
    assert held.get("test_pass", 0) > 3 * BIG, held
    assert "pass-marker" in output
    assert "pass-log-marker" in output


@pytest.mark.parametrize("workers", [[], ["-n", "2"]], ids=["serial", "n2"])
def test_live_report_consumers_still_receive_passing_output(tmp_path, workers):
    """junitxml reads each report as it is logged, before the plugin releases it."""
    xml = tmp_path / "junit.xml"
    held, _ = _run(tmp_path, *workers, "-o", "junit_logging=all", f"--junitxml={xml}")
    assert "test_pass" not in held, held
    text = xml.read_text()
    for marker in ("pass-marker", "pass-log-marker", "teardown-marker", "fail-marker"):
        assert marker in text, marker


def test_without_the_plugin_the_controller_holds_passing_output(tmp_path):
    """Control: the bytes the plugin releases are really held without it."""
    held, _ = _run(tmp_path, "-n", "1", retention=False)
    # The call and teardown reports repeat the earlier phases' sections.
    assert held.get("test_pass", 0) > 4 * BIG, held
