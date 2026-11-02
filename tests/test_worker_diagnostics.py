"""A crashed local worker reports its OS status and every worker its peak RSS, without
changing test execution."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "body,expected",
    [
        ("import os; os._exit(23)", r"returncode=23"),
        pytest.param(
            "import os, signal; os.kill(os.getpid(), signal.SIGTERM)",
            r"returncode=-15 signal=SIGTERM \(15\)",
            marks=pytest.mark.skipif(os.name != "posix", reason="POSIX signal exit status"),
        ),
        ("pass", None),
    ],
)
def test_worker_exit_evidence(tmp_path, body, expected):
    # Keep the deliberately crashing run outside the repository's conftest and
    # invoke just the diagnostic plugin. No project tools or upstream calls run.
    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    test = tmp_path / "test_worker.py"
    test.write_text(f"def test_worker():\n    {body}\n")
    env = {**os.environ, "PYTHONPATH": str(ROOT), "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"}
    run = subprocess.run(  # noqa: S603 -- fixed Python and synthetic test program
        [
            sys.executable,
            "-m",
            "pytest",
            "-p",
            "xdist.plugin",
            "-p",
            "tests._worker_diagnostics",
            "-n",
            "1",
            "--max-worker-restart=0",
            str(test),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )
    output = run.stdout + run.stderr
    if expected is None:
        assert run.returncode == 0, output
        assert "worker process exit:" not in output
    else:
        assert run.returncode == 1, output
        assert re.search(r"worker process exit: gw0 pid=\d+ " + expected, output), output


#: Holds the crashed child unreaped when xdist reports the node down: its first poll
#: returns None, as on a loaded host where the channel's EOF beats the child's exit.
_UNREAPED_AT_EOF = """
import pytest


@pytest.hookimpl(tryfirst=True, optionalhook=True)
def pytest_testnodedown(node, error):
    popen = node.gateway._io.popen
    reaped = popen.poll
    calls = []

    def poll():
        calls.append(None)
        return None if len(calls) == 1 else reaped()

    popen.poll = poll
"""


@pytest.mark.parametrize(
    "body,expected",
    [
        ("import os; os._exit(23)", r"returncode=23"),
        pytest.param(
            "import os, signal; os.kill(os.getpid(), signal.SIGTERM)",
            r"returncode=-15 signal=SIGTERM \(15\)",
            marks=pytest.mark.skipif(os.name != "posix", reason="POSIX signal exit status"),
        ),
    ],
)
def test_worker_exit_evidence_when_unreaped_at_node_down(tmp_path, body, expected):
    # The exit status is reported once xdist's teardown has reaped the child.
    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    (tmp_path / "unreaped_at_eof.py").write_text(_UNREAPED_AT_EOF)
    test = tmp_path / "test_worker.py"
    test.write_text(f"def test_worker():\n    {body}\n")
    env = {
        **os.environ,
        "PYTHONPATH": os.pathsep.join((str(ROOT), str(tmp_path))),
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    }
    run = subprocess.run(  # noqa: S603 -- fixed Python and synthetic test program
        [
            sys.executable,
            "-m",
            "pytest",
            "-p",
            "xdist.plugin",
            "-p",
            "tests._worker_diagnostics",
            "-p",
            "unreaped_at_eof",
            "-n",
            "1",
            "--max-worker-restart=0",
            str(test),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )
    output = run.stdout + run.stderr
    assert run.returncode == 1, output
    assert re.search(r"worker process exit: gw0 pid=\d+ " + expected, output), output
    assert "not observed" not in output, output


#: Holds a 64 MiB bytes object (every page written) while the test runs, then passes.
_ALLOCATE = (
    "def test_allocate():\n    blob = b'x' * (64 * 2**20)\n    assert len(blob) == 64 * 2**20\n"
)


def _run_peak_plugin(tmp_path: Path, tests: str, *workers: str) -> tuple[int, str]:
    # Only the diagnostic plugin (and xdist when ``workers`` is given): no project tools.
    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    test = tmp_path / "test_worker.py"
    test.write_text(tests)
    env = {**os.environ, "PYTHONPATH": str(ROOT), "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"}
    xdist = ["-p", "xdist.plugin", *workers, "--max-worker-restart=0"] if workers else []
    run = subprocess.run(  # noqa: S603 -- fixed Python and synthetic test program
        [sys.executable, "-m", "pytest", *xdist, "-p", "tests._worker_diagnostics", str(test)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )
    return run.returncode, run.stdout + run.stderr


def _mib(pattern: str, output: str) -> list[float]:
    return [float(value) for value in re.findall(pattern, output)]


def test_worker_peak_rss_on_exit_and_in_summary(tmp_path):
    returncode, output = _run_peak_plugin(tmp_path, _ALLOCATE, "-n", "1")
    assert returncode == 0, output
    # Once when the worker goes down, once in the terminal summary.
    peaks = _mib(r"worker peak RSS: gw0 ru_maxrss=(\d+\.\d) MiB\n", output)
    assert len(peaks) == 2, output
    assert all(peak >= 64 for peak in peaks), output
    assert "no final report" not in output, output
    assert re.search(r"pytest process peak RSS: ru_maxrss=\d+\.\d MiB", output), output


def test_killed_worker_reports_its_peak_as_of_its_last_report(tmp_path):
    # The kernel's out-of-memory kill sends no final report: the controller keeps the
    # peak each test report carried, and names the test that was running.
    tests = _ALLOCATE + "\n\ndef test_killed():\n    import os\n    os._exit(23)\n"
    returncode, output = _run_peak_plugin(tmp_path, tests, "-n", "1")
    assert returncode == 1, output
    assert re.search(r"worker process exit: gw0 pid=\d+ returncode=23", output), output
    peaks = _mib(
        r"worker peak RSS: gw0 ru_maxrss>=(\d+\.\d) MiB \(the worker sent no final report; "
        r"peak as of its last report, test_worker\.py::test_killed\)\n",
        output,
    )
    assert len(peaks) == 2, output
    assert all(peak >= 64 for peak in peaks), output


def test_run_without_workers_reports_its_own_peak(tmp_path):
    returncode, output = _run_peak_plugin(tmp_path, _ALLOCATE)
    assert returncode == 0, output
    assert "worker peak RSS" not in output, output
    peaks = _mib(r"pytest process peak RSS: ru_maxrss=(\d+\.\d) MiB", output)
    assert len(peaks) == 1, output
    assert peaks[0] >= 64, output


def test_rss_steps_rank_and_bound_fake_samples():
    from tests._worker_diagnostics import _RssSteps

    mib = 2**20
    tracker = _RssSteps(10 * mib)
    for i in range(20):
        tracker.record(f"test_{i:02}", (10 + i * (i + 1) // 2) * mib)
    lines = tracker.lines("gw0")
    assert len(lines) == 15
    assert lines[0] == "worker RSS step: gw0 test_19 181.0 MiB -> 200.0 MiB (+19.0 MiB)"
    assert lines[-1] == "worker RSS step: gw0 test_05 20.0 MiB -> 25.0 MiB (+5.0 MiB)"
