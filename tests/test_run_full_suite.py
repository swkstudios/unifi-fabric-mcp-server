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
COLLECT = "-m pytest tests/ -n 4 --dist loadgroup --max-worker-restart=0"
#: The shard job of each suite and its one step that calls the script.
FULL_SUITE_STEPS = {
    "test-shard": "Run full suite with coverage",
    "test-locked-shard": "Run full locked suite",
}
SHARD_JOB_SUITES = {"test-shard": "test", "test-locked-shard": "test-locked"}


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
        ("python", "--workers", "auto5"),
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


def test_both_ci_jobs_run_the_same_full_suite_through_the_script(monkeypatch):
    # --workers auto resolves to the job CPU share; pin it so the composed command is the
    # documented -n 4 on any host (test_ci_tiers.py covers how auto sizes itself).
    monkeypatch.setenv("CI_JOB_CPUS", "4")
    commands = {}
    for job, suite in SHARD_JOB_SUITES.items():
        step = _step(job)
        run = str(step["run"]).strip()
        assert "\n" not in run, job
        assert "pytest" not in run, job  # the script owns the command
        words = shlex.split(run)
        assert words[3:5] == ["--workers", "auto"], job  # sized to the slot's CPU share
        assert words[5:] == [
            "--shard",
            "$SHARD_K/$SHARD_N",
            "--shard-suite",
            suite,
            "--shard-report",
            "$SHARD_OUT/report.json",
            "--junitxml=$SHARD_OUT/junit.xml",
        ], job
        assert step["env"]["SHARD_K"] == "${{ matrix.k }}", job
        assert step["env"]["SHARD_N"] == f"${{{{ needs.{suite}-prep.outputs.shards }}}}", job
        # Without its shard options the step is the whole suite with the coverage gate.
        commands[job] = workflow_full_suite_command(run.partition(" --shard ")[0])
    assert shlex.split(_step("test-shard")["run"])[2] == "$DEV_VENV/bin/python"
    assert shlex.split(_step("test-locked-shard")["run"])[2] == "python"
    assert (
        commands["test-shard"]
        == commands["test-locked-shard"]
        == shlex.join(["PYTHON", *FULL_SUITE.split(), *_extra_collection()])
    )
    # A shard runs the same command minus the threshold and the terminal report.
    shard = composed_command("python", "--workers", "4", "--shard", "3/20", "--shard-suite", "test")
    assert "--cov-fail-under=97" not in shard and "--cov-report=" in shard
    assert shard[shard.index("--shard") + 1] == "3/20"


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


# -- sharded runs and the coverage combine -------------------------------------------------

SHARD_SUITE = (
    "-m pytest tests/ -v -n 4 --dist loadgroup --max-worker-restart=0"
    " --cov=src/unifi_fabric --cov-report="
)


def test_shard_runs_the_same_options_without_a_threshold_or_terminal_report():
    words = composed_command("python", "--shard", "2/4", "--shard-suite", "test")
    assert words == [
        "python",
        *SHARD_SUITE.split(),
        *_extra_collection(),
        "--shard",
        "2/4",
        "--shard-suite",
        "test",
        "--shard-report",
        "shard-2-of-4.json",
    ]
    assert not [w for w in words if w.startswith("--cov-fail-under")]
    assert "--cov-report=term" not in words
    named = composed_command(
        "python",
        "--workers",
        "2",
        "--shard=1/3",
        "--shard-suite=test-locked",
        "--shard-report",
        "out/r.json",
        "-q",
    )
    assert named[named.index("-n") + 1] == "2"
    assert named[-7:] == [
        "--shard",
        "1/3",
        "--shard-suite",
        "test-locked",
        "--shard-report",
        "out/r.json",
        "-q",
    ]


def test_the_unsharded_default_is_unchanged_by_the_shard_options():
    assert composed_command("python") == ["python", *FULL_SUITE.split(), *_extra_collection()]


@pytest.mark.parametrize("shard", ["0/4", "5/4", "1/0", "x", "1", "1/2/3", "-1/4"])
def test_a_malformed_shard_is_refused(shard):
    result = _script("python", "--shard", shard, "--shard-suite", "test", "--print-command")
    assert result.returncode == 2
    assert result.stdout == ""
    assert shard in result.stderr


def test_shard_report_needs_a_shard_and_combine_refuses_other_modes(tmp_path):
    assert _script("python", "--shard-report", "r.json", "--print-command").returncode == 2
    assert _script("python", "--shard-suite", "test", "--print-command").returncode == 2
    # A shard without a suite name cannot write a run-bound report.
    assert _script("python", "--shard", "1/4", "--print-command").returncode == 2
    assert _script("python", "--combine", str(tmp_path), "--print-command").returncode == 2
    assert _script("python", "--shards", "4", "--print-command").returncode == 2
    assert (
        _script("python", "--combine", str(tmp_path), "--shards", "0", "--print-command").returncode
        == 2
    )
    both = _script(
        "python", "--combine", str(tmp_path), "--shards", "2", "--shard", "1/2", "--print-command"
    )
    assert both.returncode == 2


def _fake_python(tmp_path: Path) -> tuple[Path, Path]:
    log = tmp_path / "calls"
    fake = tmp_path / "fake-python"
    fake.write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" >> "{log}"\n')
    fake.chmod(0o755)
    return fake, log


def _coverage_files(root: Path, count: int) -> None:
    for k in range(1, count + 1):
        (root / f"test-shard-{k}").mkdir(parents=True)
        (root / f"test-shard-{k}" / ".coverage").write_text("data")


def test_combine_counts_exactly_n_files_then_combines_and_applies_the_one_threshold(tmp_path):
    fake, log = _fake_python(tmp_path)
    data = tmp_path / "data"
    _coverage_files(data, 4)
    result = _script(str(fake), "--combine", str(data), "--shards", "4")
    assert result.returncode == 0, result.stderr
    check, combine, to_json, summary, report = log.read_text().splitlines()
    assert check.startswith("scripts/shard_partition.py coverage-data ")
    assert check.count(".coverage") == 4
    assert combine.startswith("-m coverage combine --keep ")
    assert combine.count(".coverage") == 4
    assert to_json.startswith("-m coverage json --pretty-print -o ")
    assert summary.startswith("scripts/shard_partition.py coverage-summary ")
    assert summary.endswith("coverage-combined.json")
    assert report == "-m coverage report --fail-under=97"
    assert (
        "--fail-under=97"
        in _script("python", "--combine", str(data), "--shards", "4", "--print-command").stdout
    )
    # The threshold is written once: the same value drives the whole-suite default.
    code = [ln for ln in SCRIPT.read_text().splitlines() if not ln.lstrip().startswith("#")]
    assert [ln for ln in code if "97" in ln] == ["COVERAGE_FAIL_UNDER=97"]


def test_combine_refuses_a_data_file_without_measured_data(tmp_path):
    fake = tmp_path / "fake-python"
    log = tmp_path / "calls"
    fake.write_text(
        f'#!/bin/sh\nprintf "%s\\n" "$*" >> "{log}"\ncase "$*" in *coverage-data*) exit 1;; esac\n'
    )
    fake.chmod(0o755)
    data = tmp_path / "data"
    _coverage_files(data, 4)
    result = _script(str(fake), "--combine", str(data), "--shards", "4")
    assert result.returncode == 1
    assert "no measured data" in result.stderr
    assert log.read_text().count("\n") == 1  # the check ran; nothing was combined


def test_combine_writes_the_summary_where_asked(tmp_path):
    fake, log = _fake_python(tmp_path)
    data = tmp_path / "data"
    _coverage_files(data, 2)
    out = tmp_path / "out.json"
    result = _script(str(fake), "--combine", str(data), "--shards", "2", "--summary", str(out))
    assert result.returncode == 0, result.stderr
    assert log.read_text().splitlines()[3].endswith(str(out))


def test_collect_only_is_the_same_command_without_coverage_plus_the_collect_flags():
    words = composed_command("python", "--collect-only")
    assert words == ["python", *COLLECT.split(), *_extra_collection(), "--collect-only", "-q"]
    assert not [w for w in words if w.startswith("--cov")]
    # Apart from the coverage options and the shard / collect flags the arguments agree.
    sharded = composed_command("python", "--shard", "1/4", "--shard-suite", "test")
    drop = lambda ws: [w for w in ws if not w.startswith("--cov") and w != "-v"]  # noqa: E731
    assert drop(sharded)[: len(drop(words)) - 2] == drop(words)[:-2]
    passthrough = composed_command("python", "--collect-only", "--workers", "2", "-m", "not slow")
    assert passthrough[-4:] == ["--collect-only", "-q", "-m", "not slow"]
    assert passthrough[passthrough.index("-n") + 1] == "2"


@pytest.mark.parametrize(
    "extra",
    [
        ["--shard", "1/2", "--shard-suite", "test"],
        ["--shard-suite", "test"],
        ["--combine", "d", "--shards", "2"],
    ],
)
def test_collect_only_refuses_the_shard_and_combine_modes(extra):
    assert _script("python", "--collect-only", *extra, "--print-command").returncode == 2
    assert _script("python", "--identity-out", "id.json", "--print-command").returncode == 2


def test_collect_only_records_the_identity_before_collecting(tmp_path):
    fake, log = _fake_python(tmp_path)
    out = tmp_path / "id.json"
    result = _script(str(fake), "--collect-only", "--identity-out", str(out))
    assert result.returncode == 0, result.stderr
    identity, collect = log.read_text().splitlines()
    assert identity == f"scripts/env_identity.py record --out {out}"
    assert collect.startswith("-m pytest tests/ ") and collect.endswith("--collect-only -q")


@pytest.mark.parametrize("found", [0, 3, 5])
def test_combine_fails_when_the_coverage_file_count_is_not_n(tmp_path, found):
    fake, log = _fake_python(tmp_path)
    data = tmp_path / "data"
    data.mkdir()
    _coverage_files(data, found)
    result = _script(str(fake), "--combine", str(data), "--shards", "4")
    assert result.returncode == 1
    assert f"expected 4 coverage data files under {data}, found {found}" in result.stderr
    assert not log.exists()  # nothing was combined or reported


def test_combine_of_a_missing_directory_is_refused(tmp_path):
    fake, log = _fake_python(tmp_path)
    assert _script(str(fake), "--combine", str(tmp_path / "none"), "--shards", "4").returncode == 2
    assert not log.exists()
