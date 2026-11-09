"""scripts/run_full_suite.sh owns the full-suite pytest command of CI's test and test-locked."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_full_suite.sh"
CI = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
BASH = shutil.which("bash") or "/bin/bash"
#: The command both jobs ran inline before the script owned it (ci.yml at dev 2e2651e).
FULL_SUITE = (
    "-m pytest tests/ -v -n 4 --dist loadgroup --max-worker-restart=0"
    " --cov=src/unifi_fabric --cov-report=term --cov-fail-under=97"
)
FULL_SUITE_STEPS = {"test": "Run full suite with coverage", "test-locked": "Run full locked suite"}


def _script(*args: str, cwd: Path = ROOT, env: dict[str, str] | None = None):
    return subprocess.run(  # noqa: S603 - fixed repository script, test-built arguments
        [BASH, str(SCRIPT), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def composed_command(*args: str) -> list[str]:
    """The command ``scripts/run_full_suite.sh <args>`` would run (``--print-command``)."""
    # The flag precedes any "--": everything after that goes to pytest verbatim.
    result = _script(args[0], "--print-command", *args[1:])
    assert result.returncode == 0, result.stderr
    return [word for line in result.stdout.splitlines() for word in shlex.split(line)]


def workflow_full_suite_command(run: str, python: str = "PYTHON") -> str:
    """The pytest command a workflow ``run`` step that calls the script composes.

    The step must be exactly ``bash scripts/run_full_suite.sh <python> [arguments]``; its
    interpreter argument is replaced by ``python`` so the result reads the same for every
    job."""
    words = shlex.split(run)
    assert words[:2] == ["bash", "scripts/run_full_suite.sh"], run
    assert len(words) >= 3, run
    return shlex.join(composed_command(python, *words[3:]))


def _step(job: str) -> dict:
    steps = [s for s in CI["jobs"][job]["steps"] if s.get("name") == FULL_SUITE_STEPS[job]]
    assert len(steps) == 1, job
    return steps[0]


def _extra_collection():
    return composed_command("python")[1 + len(FULL_SUITE.split()) :]


def test_default_command_is_the_full_suite_with_the_coverage_threshold():
    assert composed_command("python") == ["python", *FULL_SUITE.split(), *_extra_collection()]


def test_workers_change_only_the_xdist_count():
    for workers in ("1", "2", "4", "16"):
        expected = [
            "python",
            *FULL_SUITE.replace("-n 4", f"-n {workers}").split(),
            *_extra_collection(),
        ]
        assert composed_command("python", "--workers", workers) == expected
        assert composed_command("python", f"--workers={workers}") == expected


def test_extra_arguments_follow_the_command():
    assert composed_command("python", "-x", "--lf")[-2:] == ["-x", "--lf"]
    passed = composed_command("python", "--workers", "3", "--", "--workers", "9", "-k", "a b")
    assert passed[:7] == ["python", "-m", "pytest", "tests/", "-v", "-n", "3"]
    assert passed[-4:] == ["--workers", "9", "-k", "a b"]
    assert "--cov-fail-under=97" in passed


@pytest.mark.parametrize(
    "args",
    [
        (),
        ("--workers", "4"),
        ("", "--workers", "4"),
        ("python", "--workers"),
        ("python", "--workers", "0"),
        ("python", "--workers", "auto"),
        ("python", "--workers", "-1"),
    ],
)
def test_invalid_arguments_are_refused_before_anything_runs(args):
    result = _script(*args, "--print-command")
    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr


def test_runs_the_command_from_the_repository_root(tmp_path):
    """The script executes the composed command (no --print-command) from the root."""
    receipt = tmp_path / "receipt"
    fake = tmp_path / "bin" / "fake-python"
    fake.parent.mkdir()
    fake.write_text(f'#!/bin/sh\npwd > "{receipt}"\nprintf "%s\\n" "$@" >> "{receipt}"\nexit 7\n')
    fake.chmod(0o755)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    result = _script("bin/fake-python", "--workers", "2", "-q", cwd=tmp_path, env={**os.environ})
    # A relative interpreter path is resolved against the caller's directory, the pytest
    # exit status is the script's, and the suite runs from the repository root.
    assert result.returncode == 7, result.stderr
    cwd, *argv = receipt.read_text().splitlines()
    assert Path(cwd).resolve() == ROOT.resolve()
    assert argv == [*FULL_SUITE.replace("-n 4", "-n 2").split(), *_extra_collection(), "-q"]
    absolute = _script(str(fake), cwd=elsewhere)
    assert absolute.returncode == 7
    assert receipt.read_text().splitlines()[1:] == [*FULL_SUITE.split(), *_extra_collection()]


def test_both_ci_jobs_run_the_same_full_suite_through_the_script():
    commands = {}
    for job in FULL_SUITE_STEPS:
        run = str(_step(job)["run"]).strip()
        assert "\n" not in run, job
        assert "pytest" not in run, job  # the script owns the command
        words = shlex.split(run)
        assert words[3:] == ["--workers", "4"], job  # no shard: the threshold applies
        commands[job] = workflow_full_suite_command(run)
    assert shlex.split(_step("test")["run"])[2] == "$DEV_VENV/bin/python"
    assert shlex.split(_step("test-locked")["run"])[2] == "python"
    assert (
        commands["test"]
        == commands["test-locked"]
        == shlex.join(["PYTHON", *FULL_SUITE.split(), *_extra_collection()])
    )


def test_the_composed_command_keeps_the_suite_whole_and_fails_on_a_lost_worker():
    words = composed_command("python")
    options = words[words.index("pytest") + 1 :]
    assert options[0] == "tests/"  # the whole suite, no path narrowing
    assert "--max-worker-restart=0" in options
    for option in options:
        assert option not in {"-x", "--exitfirst", "--lf", "--last-failed", "-k", "-m"}, option
        assert not option.startswith(("--maxfail", "--deselect", "--timeout")), option


def test_script_has_no_wall_clock_limit():
    text = SCRIPT.read_text()
    assert "timeout" not in text
    assert os.access(SCRIPT, os.X_OK)
