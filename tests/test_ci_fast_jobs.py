"""scripts/prepush.sh runs CI's fast jobs from the workflows themselves, so they cannot drift."""

from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from tests.test_run_full_suite import workflow_full_suite_command

ROOT = Path(__file__).resolve().parents[1]
PREPUSH = ROOT / "scripts" / "prepush.sh"
HELPER = ROOT / "scripts" / "ci_fast_jobs.py"
CI = ROOT / ".github" / "workflows" / "ci.yml"

_spec = importlib.util.spec_from_file_location("ci_fast_jobs", HELPER)
assert _spec and _spec.loader
fast = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("ci_fast_jobs", fast)
_spec.loader.exec_module(fast)

WORKFLOWS = ROOT / ".github" / "workflows"
WORKFLOW = yaml.safe_load(CI.read_text())
CANONICAL = re.compile(r"^Pre-push: scripts/prepush\.sh pass \(head [0-9a-f]{7}\)$", re.M)
FULL = re.compile(
    r"^Pre-push: scripts/prepush\.sh --full pass \(head [0-9a-f]{7}, workers [1-9][0-9]*\)$",
    re.M,
)


def _expected_fast_steps(workflow):
    """Independent enumeration: every run step of every job CI does not keep to itself."""
    expected = []
    for name, job in workflow["jobs"].items():
        if name in fast.CI_ONLY_JOBS:
            continue
        for step in job.get("steps", []):
            if "run" in step and step.get("name") not in fast.SETUP_STEPS:
                expected.append((name, step["run"]))
    return expected


def test_every_ci_fast_job_step_is_in_the_prepush_step_list():
    listed = [(job, step["run"]) for job, step in fast.fast_job_steps(WORKFLOW)]
    assert sorted(listed) == sorted(_expected_fast_steps(WORKFLOW))
    jobs = {job for job, _ in listed}
    # The mandatory fast jobs (lint incl. the public-transform timeout scan, typecheck,
    # docs, version, fixtures, changelog) are all local.
    assert {
        "lint",
        "typecheck",
        "docs",
        "fixtures-sanitization",
        "version-consistency",
        "changelog-check",
    } <= jobs
    runs = "\n".join(run for _, run in listed)
    assert "ruff check src/ tests/ scripts/ .github/scripts/" in runs
    assert "ruff format --check src/ tests/ scripts/ .github/scripts/" in runs
    assert "scripts/check_no_timeouts.py" in runs
    assert "-m mypy src/unifi_fabric" in runs


def test_ci_only_jobs_are_the_reviewed_set():
    # Only the full suites, the image build, the secret scan and steps that need a
    # repository token, a secret or the public repository stay out of the local run.
    assert set(fast.CI_ONLY_JOBS) == {
        "classify",
        "test-selected",
        "ci-required",
        "test",
        "test-locked",
        "scrub-oracle",
        "gitleaks",
        "docker-build",
        "docker-build-arm64",
        "divergence-gate",
        "notify-matrix",
        "lint-public-language",
    }
    assert set(WORKFLOW["jobs"]) - set(fast.CI_ONLY_JOBS) == set(fast.fast_jobs(WORKFLOW))


def _setup_action_steps():
    for uses in sorted(fast.SETUP_ACTIONS):
        action = yaml.safe_load((ROOT / uses / "action.yml").read_text())
        assert action["runs"]["using"] == "composite", uses
        yield from action["runs"]["steps"]


def test_setup_steps_only_provision_the_environment():
    seen = set()
    action_steps = list(_setup_action_steps())
    for steps in (*(job.get("steps", []) for job in WORKFLOW["jobs"].values()), action_steps):
        for step in steps:
            if step.get("name") in fast.SETUP_STEPS:
                seen.add(step["name"])
                run = step["run"].replace("scripts/extract_ruff_requirements.py", "")
                assert re.search(r"pip install|python -m venv|mkdir|rm -rf", run), run
                for check in ("pytest", "mypy", "ruff check", "ruff format", "scripts/"):
                    assert check not in run, (step["name"], check)
    assert seen == fast.SETUP_STEPS


def test_setup_actions_hold_only_provisioning_steps():
    """The local run skips a SETUP_ACTIONS step whole, so every step inside it must be
    provisioning (a SETUP_STEPS run step or a SHA-pinned action), never a check."""
    steps = list(_setup_action_steps())
    assert steps
    for step in steps:
        if "run" in step:
            assert step.get("name") in fast.SETUP_STEPS, step.get("name")
        else:
            assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", step["uses"]), step
    # Only the jobs the local run executes (default and --full) reach the local-action
    # check; a CI_ONLY job (divergence-gate) may call its own local action.
    local_jobs = set(fast.fast_jobs(WORKFLOW)) | set(fast.fast_jobs(WORKFLOW, full=True))
    used = {
        str(step.get("uses"))
        for job_name in local_jobs
        for step in WORKFLOW["jobs"][job_name].get("steps", [])
        if str(step.get("uses", "")).startswith("./")
    }
    assert used == set(fast.SETUP_ACTIONS)


def test_a_local_action_outside_setup_actions_stops_the_run():
    workflow = {"jobs": {"fast": {"steps": [{"uses": "./.github/actions/other"}]}}}
    with pytest.raises(fast.WorkflowError, match="local action ./.github/actions/other"):
        list(fast.fast_job_steps(workflow))
    workflow["jobs"]["fast"]["steps"] = [{"uses": sorted(fast.SETUP_ACTIONS)[0]}]
    assert list(fast.fast_job_steps(workflow)) == []


def _pull_request_workflows():
    """Independent enumeration: every workflow file a pull request starts."""
    names = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        workflow = yaml.safe_load(path.read_text())
        on = workflow.get("on", workflow.get(True))
        events = {on} if isinstance(on, str) else set(on or ())
        if events & {"pull_request", "pull_request_target"}:
            names.append(path.name)
    return names


def test_dry_run_resolves_every_fast_job_expression(tmp_path):
    records = fast.run(
        base="0" * 40,
        base_ref="main",
        head="1" * 40,
        head_ref="topic",
        labels=[],
        venv=Path(sys.prefix),
        execute=False,
        out=lambda line: None,
    )
    labels = [(workflow, job, label) for workflow, job, label, _ in records]
    expected = [
        (name, job, fast.step_label(step))
        for name in fast.pull_request_workflows()
        for job, step in fast.fast_job_steps(yaml.safe_load((WORKFLOWS / name).read_text()), name)
    ]
    assert sorted(labels) == sorted(expected)
    assert {name for name, _, _ in labels} >= {"ci.yml"}


def test_run_removes_its_work_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(fast.tempfile, "tempdir", str(tmp_path))
    seen: list[Path] = []
    real = fast._run_workflow

    def spy(*args, **kwargs):
        seen.append(kwargs["event_path"])
        return real(*args, **kwargs)

    monkeypatch.setattr(fast, "_run_workflow", spy)
    fast.run(
        base="0" * 40,
        base_ref="main",
        head="1" * 40,
        head_ref="topic",
        labels=[],
        venv=Path(sys.prefix),
        execute=False,
        out=lambda line: None,
    )
    assert seen and all(path.parent.parent == tmp_path for path in seen)
    assert list(tmp_path.iterdir()) == []


def test_every_pull_request_workflow_is_classified():
    """A fast check in a workflow other than ci.yml must run in prepush, or be
    listed as CI-only with a reason; an unclassified workflow stops the run."""
    names = _pull_request_workflows()
    assert "ci.yml" in names
    assert fast.pull_request_workflows() == ["ci.yml", *(n for n in names if n != "ci.yml")]
    for name in names:
        assert name in fast.CI_ONLY, name
        jobs = yaml.safe_load((WORKFLOWS / name).read_text())["jobs"]
        for job, reason in fast.CI_ONLY[name].items():
            assert reason.strip(), (name, job)
            # ci.yml's CI-only set is pinned by test_ci_only_jobs_are_the_reviewed_set
            # (the public tree drops some of those jobs).
            assert name == "ci.yml" or job in jobs, (name, job)
    # Entries for a workflow this tree lacks are dormant (the public tree strips the
    # private-only ones); every listed workflow that exists runs for pull requests.
    for name in fast.CI_ONLY:
        assert name in names or not (WORKFLOWS / name).exists(), name
    for (name, job, step), reason in fast.CI_ONLY_STEPS.items():
        assert reason.strip()
        if (WORKFLOWS / name).exists():
            steps = yaml.safe_load((WORKFLOWS / name).read_text())["jobs"][job]["steps"]
            assert step in {s.get("name") for s in steps}, (name, job, step)


def test_fast_checks_of_every_pull_request_workflow_run_in_prepush():
    """Regression: a release pull request passed prepush, then failed the documentation
    check "Provenance and image-tag currency", which lived only in docs-checks.yml."""
    records = fast.run(
        base="0" * 40,
        base_ref="integration/0.7.0",
        head="1" * 40,
        head_ref="topic",
        labels=[],
        venv=Path(sys.prefix),
        execute=False,
        out=lambda line: None,
    )
    ran = {(workflow, job, label) for workflow, job, label, runs in records if runs}
    for name in fast.pull_request_workflows():
        if name == "ci.yml":
            continue
        workflow = yaml.safe_load((WORKFLOWS / name).read_text())
        for job, step in fast.fast_job_steps(workflow, name):
            # A lane pull request into an integration branch runs them too, though a
            # workflow's filter may name only dev and main: the release PR gates there.
            assert (name, job, fast.step_label(step)) in ran, (name, job, step)
    assert ("docs-checks.yml", "docs-checks", "Provenance and image-tag currency") in ran
    assert ("docs-checks.yml", "docs-checks", "Build artifacts") in ran


def test_an_unclassified_pull_request_workflow_stops_the_run(tmp_path):
    (tmp_path / "ci.yml").write_text(yaml.safe_dump({"on": "push", "jobs": {}}))
    (tmp_path / "new-check.yml").write_text(
        yaml.safe_dump({"on": {"pull_request": {}}, "jobs": {"x": {"steps": []}}})
    )
    (tmp_path / "nightly.yml").write_text(yaml.safe_dump({"on": "schedule", "jobs": {}}))
    with pytest.raises(fast.WorkflowError, match="new-check.yml runs for pull requests"):
        fast.pull_request_workflows(tmp_path)
    (tmp_path / "new-check.yml").unlink()
    assert fast.pull_request_workflows(tmp_path) == ["ci.yml"]


def test_prepush_guards_exist_and_cover_the_cross_file_artifacts():
    # The public tree's transform drops the entries whose files it removes.
    for guard in fast.PREPUSH_GUARDS:
        assert (ROOT / guard).is_file(), guard
    assert not re.search(
        r"(?<!\S)(-x|--lf|--maxfail\S*|-k|-m|--deselect\S*)(?!\S)", " ".join(fast.GUARD_PYTEST[2:])
    )


def test_lint_ruff_pin_is_the_locked_ruff():
    # The lint job installs the requirement generated from requirements.lock, the lock
    # the local development environment is built from (tests/test_ci_pins.py checks the
    # generated requirement against the lock).
    install = next(
        step["run"]
        for step in WORKFLOW["jobs"]["lint"]["steps"]
        if step.get("name") == "Install ruff (hash-pinned)"
    )
    generate = 'scripts/extract_ruff_requirements.py --lock requirements.lock --out "$RUFF_REQ"'
    assert generate in install
    assert "pip install --require-hashes --only-binary :all: --no-deps" in install
    assert install.index(generate) < install.index("pip install")
    assert "ruff==" not in install


def test_setup_python_version_reads_the_version_file(tmp_path):
    (tmp_path / ".python-version").write_text("3.12\n")
    step = {"uses": "actions/setup-python@x", "with": {"python-version-file": ".python-version"}}
    assert fast.setup_python_version(step, tmp_path) == "3.12"
    assert fast.setup_python_version({"with": {"python-version": "3.11"}}, tmp_path) == "3.11"
    (tmp_path / ".python-version").write_text("3.12\n3.13\n")
    with pytest.raises(fast.WorkflowError, match="exactly one"):
        fast.setup_python_version(step, tmp_path)
    # The tree's own file names the version every workflow job runs.
    assert fast.setup_python_version(step) == (ROOT / ".python-version").read_text().strip()


def _concurrency_groups(workflow, event, sha, run_id="1", pr=None):
    groups = []
    blocks = [workflow.get("concurrency")] + [
        job.get("concurrency") for job in workflow["jobs"].values()
    ]
    for block in blocks:
        if block is None:
            continue
        group = block["group"] if isinstance(block, dict) else block
        context = {
            "github": {
                "workflow": "CI",
                "event_name": event,
                "ref": "refs/heads/main",
                "sha": sha,
                "run_id": run_id,
                "event": {"pull_request": {"number": pr}} if pr is not None else {},
            }
        }
        groups.append(fast.substitute(str(group), context))
    return groups


def _no_pending_push_run_is_replaced(workflow):
    """Condition: two runs of different commits on a non-pull_request event never share
    a concurrency group (GitHub replaces a pending run in the same group even with
    cancel-in-progress false). No concurrency block means every run is its own group."""
    for event in ("push", "merge_group", "workflow_dispatch", "schedule", "release"):
        first = _concurrency_groups(workflow, event, "a" * 40, run_id="1")
        second = _concurrency_groups(workflow, event, "b" * 40, run_id="2")
        if set(first) & set(second):
            return False
    return True


# These workflow checks are private-only: the publication transform removes
# them, so they are exercised only where they exist (the private repository).
PR_CONCURRENCY_WORKFLOWS = tuple(
    name
    for name in (
        "ci",
        "changelog-size",
        "docs-checks",
        "install-smoke",
        "public-artifact-dry-run",
    )
    if (ROOT / ".github" / "workflows" / f"{name}.yml").exists()
)


@pytest.mark.parametrize("name", PR_CONCURRENCY_WORKFLOWS)
def test_pr_runs_share_a_group_and_other_runs_never_do(name):
    """runs of one PR share a group that is cancelled in progress; for ci.yml pushes to dev
    share one group too (the newest dev head supersedes the older run); every other event
    keeps a group unique per sha and run."""
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / f"{name}.yml").read_text())
    cancel = workflow["concurrency"]["cancel-in-progress"]
    expected = (
        "${{ github.event_name == 'pull_request' || "
        "(github.event_name == 'push' && github.ref == 'refs/heads/dev') }}"
        if name == "ci"
        else "${{ github.event_name == 'pull_request' }}"
    )
    assert cancel == expected
    pr_groups = [
        _concurrency_groups(workflow, "pull_request", sha, run_id=run, pr=7)
        for sha, run in (("a" * 40, "1"), ("b" * 40, "2"))
    ]
    assert pr_groups[0] == pr_groups[1] and len(pr_groups[0]) == 1
    other_pr = _concurrency_groups(workflow, "pull_request", "c" * 40, run_id="3", pr=8)
    assert set(other_pr).isdisjoint(pr_groups[0])
    assert _no_pending_push_run_is_replaced(workflow)
    for event in ("push", "workflow_dispatch"):
        groups = _concurrency_groups(workflow, event, "a" * 40, run_id="1")
        assert set(groups).isdisjoint(pr_groups[0])
        rerun = _concurrency_groups(workflow, event, "a" * 40, run_id="2")
        assert set(groups).isdisjoint(rerun)


def test_non_pull_request_runs_are_never_replaced_by_a_newer_commit():
    assert _no_pending_push_run_is_replaced(WORKFLOW)
    unique = {
        "concurrency": {"group": "${{ github.workflow }}-${{ github.ref }}-${{ github.sha }}"}
    }
    assert _no_pending_push_run_is_replaced({**unique, "jobs": {}})
    shared = {"concurrency": {"group": "${{ github.workflow }}-${{ github.ref }}"}}
    assert not _no_pending_push_run_is_replaced({**shared, "jobs": {}})


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("github.event_name == 'PULL_REQUEST'", True),
        ("github.base_ref != 'main' || 'fallback'", "fallback"),
        ("github.base_ref == 'main' && 'full' || 'targeted'", "full"),
        ("contains(github.event.pull_request.labels.*.name, 'ready')", True),
        ("contains(github.event.pull_request.labels.*.name, 'other')", False),
        ("!cancelled() && always() && success() && !failure()", True),
        ("format('{0}-{1}', github.base_ref, 3)", "main-3"),
        ("toJson(github.event.pull_request.labels.*.name)", '[\n  "ready"\n]'),
        ("needs.tier.outputs.tier == 'full'", True),
        ("needs.tier.outputs.missing == ''", True),
    ],
)
def test_expression_semantics(expression, expected):
    context = {
        "github": fast.strict(
            "github",
            {
                "event_name": "pull_request",
                "base_ref": "main",
                "event": {"pull_request": {"labels": [{"name": "ready"}]}},
            },
        ),
        "needs": {"tier": {"result": "success", "outputs": {"tier": "full"}}},
    }
    assert fast.evaluate(expression, context) == expected


@pytest.mark.parametrize(
    "expression",
    ["secrets.TOKEN", "github.event.pull_request.title", "hashFiles('x')", "a ="],
)
def test_unmodelled_expressions_fail_closed(expression):
    context = {"github": fast.strict("github", {"event": {"pull_request": {}}})}
    with pytest.raises(fast.WorkflowError):
        fast.evaluate(expression, context)


def test_prepush_script_contract():
    text = PREPUSH.read_text()
    assert text.startswith("#!/usr/bin/env bash\n")
    assert "set -euo pipefail" in text
    assert 'echo "Pre-push: scripts/prepush.sh pass (head ${head:0:7})"' in text
    assert "scripts/ci_fast_jobs.py" in text
    assert "git fetch" in text and "merge-base" in text
    for source in (text, HELPER.read_text()):
        assert not re.search(r"\btimeout\b|--deselect|\s-k\s|xfail|skipif|--lf\b|--maxfail", source)
    # The default base is derived (tests/test_lane_gate.py), never a pinned version.
    assert not re.search(r"integration/[0-9]", text)
    # Run by hand, never installed as a hook.
    assert "hooks" not in text
    assert not (ROOT / ".githooks").exists()
    assert os.access(PREPUSH, os.X_OK)


GIT = shutil.which("git") or "git"
BASH = shutil.which("bash") or "bash"
# The scratch origin is a local path; allow the file transport for these commands only.
# Host-level git hooks never apply to the scratch repositories.
LOCAL_ORIGIN = {
    "GIT_CONFIG_COUNT": "2",
    "GIT_CONFIG_KEY_0": "protocol.file.allow",
    "GIT_CONFIG_VALUE_0": "always",
    "GIT_CONFIG_KEY_1": "core.hooksPath",
    "GIT_CONFIG_VALUE_1": os.devnull,
}


def _git(*args):
    identity = ["-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    return subprocess.run(  # noqa: S603 - fixed git invocations on a scratch repository
        [GIT, *identity, *args],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, **LOCAL_ORIGIN},
    ).stdout


def _scratch_repository(
    tmp_path, steps, test_steps=None, guard="def test_guard():\n    pass\n", extra=None
):
    """A repository with its own origin, the real pre-push scripts and a small workflow.

    Each pre-push guard is a one-test file (``guard``); ``extra`` maps more workflow
    files to their content."""
    origin, work = tmp_path / "origin", tmp_path / "work"
    _git("init", "--quiet", "--initial-branch=main", str(origin))
    (origin / "scripts").mkdir()
    shutil.copy2(PREPUSH, origin / "scripts" / "prepush.sh")
    shutil.copy2(HELPER, origin / "scripts" / "ci_fast_jobs.py")
    (origin / ".github" / "workflows").mkdir(parents=True)
    for name in fast.PREPUSH_GUARDS:
        (origin / name).parent.mkdir(parents=True, exist_ok=True)
        (origin / name).write_text(guard)
    for name, content in (extra or {}).items():
        (origin / ".github" / "workflows" / name).write_text(yaml.safe_dump(content))
    workflow = {
        "on": {"pull_request": {"branches": ["main"]}},
        "jobs": {
            "tier": {
                "if": "${{ github.event_name == 'pull_request' }}",
                "outputs": {"tier": "${{ steps.pick.outputs.tier }}"},
                "steps": [{"id": "pick", "run": 'echo "tier=targeted" >> "$GITHUB_OUTPUT"'}],
            },
            "check": {
                "needs": ["tier"],
                "if": "${{ needs.tier.outputs.tier == 'targeted' }}",
                "steps": steps,
            },
            "never": {
                "if": "${{ github.base_ref == 'elsewhere' }}",
                "steps": [{"run": "exit 7"}],
            },
            "test": {
                "if": "${{ github.base_ref == 'elsewhere' }}",
                "steps": test_steps or [{"run": "exit 9"}],
            },
        },
    }
    (origin / ".github" / "workflows" / "ci.yml").write_text(yaml.safe_dump(workflow))
    _git("-C", str(origin), "add", "--all")
    _git("-C", str(origin), "commit", "--quiet", "-m", "base")
    _git("clone", "--quiet", str(origin), str(work))
    _git("-C", str(work), "checkout", "--quiet", "-b", "topic")
    (work / "change.txt").write_text("change\n")
    _git("-C", str(work), "add", "change.txt")
    _git("-C", str(work), "commit", "--quiet", "-m", "change")
    return work


def _prepush(work, *args, env=None):
    env = {
        **os.environ,
        **LOCAL_ORIGIN,
        "PREPUSH_PYTHON": sys.executable,
        "PREPUSH_BASE_BRANCH": "main",
        **(env or {}),
    }
    return subprocess.run(  # noqa: S603 - the checked-in pre-push script
        [BASH, "scripts/prepush.sh", *args], cwd=work, env=env, capture_output=True, text=True
    )


def test_prepush_runs_the_workflow_steps_and_prints_the_canonical_line(tmp_path):
    marker = tmp_path / "ran"
    work = _scratch_repository(
        tmp_path,
        [
            {"name": "Write marker", "env": {"OUT": str(marker)}, "run": 'echo "$OUT" > "$OUT"'},
            {"name": "Reads the base", "run": 'test "$GITHUB_BASE_REF" = main'},
        ],
    )
    result = _prepush(work)
    assert result.returncode == 0, result.stdout + result.stderr
    head = _git("-C", str(work), "rev-parse", "HEAD")
    assert result.stdout.rstrip().splitlines()[-1] == (
        f"Pre-push: scripts/prepush.sh pass (head {head[:7]})"
    )
    assert marker.exists()
    assert "== never: not run" in result.stdout
    assert "== test: CI only" in result.stdout


def test_prepush_fails_without_the_canonical_line(tmp_path):
    work = _scratch_repository(tmp_path, [{"name": "Lint", "run": "exit 3"}])
    result = _prepush(work)
    assert result.returncode != 0
    assert not CANONICAL.search(result.stdout)
    assert "job check, step 'Lint' exited 3" in result.stderr


def test_prepush_refuses_uncommitted_tracked_changes(tmp_path):
    work = _scratch_repository(tmp_path, [{"name": "Ok", "run": "true"}])
    (work / "change.txt").write_text("edited\n")
    result = _prepush(work)
    assert result.returncode != 0
    assert "commit or stash tracked changes" in result.stderr
    assert not CANONICAL.search(result.stdout)


def test_prepush_runs_other_pull_request_workflows_and_guards(tmp_path):
    marker = tmp_path / "docs-ran"
    work = _scratch_repository(
        tmp_path,
        [{"name": "Ok", "run": "true"}],
        extra={
            "docs-checks.yml": {
                "on": {"pull_request": {"branches": ["dev"]}},
                "jobs": {
                    "docs-checks": {
                        "steps": [
                            {"name": "Provenance and image-tag currency", "run": f"touch {marker}"},
                            {"name": "External reference links", "run": "exit 5"},
                        ]
                    },
                    "reference-report": {"steps": [{"run": "exit 6"}]},
                },
            },
            "nightly.yml": {"on": {"schedule": [{"cron": "0 0 * * *"}]}, "jobs": {}},
        },
    )
    result = _prepush(work)
    assert result.returncode == 0, result.stdout + result.stderr
    # The workflow's branch filter (dev) does not keep it out of a run against main.
    assert marker.exists()
    assert "External reference links: CI only" in result.stdout
    assert "== reference-report: CI only" in result.stdout
    if fast.PREPUSH_GUARDS:
        assert f"== guards: {' '.join(fast.PREPUSH_GUARDS)}" in result.stdout
        assert f"{len(fast.PREPUSH_GUARDS)} passed" in result.stdout
    assert CANONICAL.search(result.stdout)


def test_a_failing_guard_fails_prepush_whatever_the_change(tmp_path):
    """Regression (integration/0.7.0 cf9a531): the commit changed only a workflow and the
    transform, so the selector escalated to the full tier and prepush ran no test, while
    the base already carried a stale fingerprint fixture and an unstripped private test;
    CI's full suite failed. The guards run on every pre-push, so the stale artifact fails
    here. (The scratch change touches neither guard nor any input of it.)"""
    if not fast.PREPUSH_GUARDS:
        return  # public tree: no private cross-file artifact to guard
    work = _scratch_repository(
        tmp_path,
        [{"name": "Ok", "run": "true"}],
        guard="def test_fixture_is_current():\n    assert False, 'stale fixture'\n",
    )
    result = _prepush(work)
    assert result.returncode != 0
    assert "job guards" in result.stderr
    assert not CANONICAL.search(result.stdout) and not FULL.search(result.stdout)


def _full_suite_steps(out):
    return [
        {"name": "Cache key", "run": "mkdir -p never-run-setup"},
        {
            "name": "Run full suite with coverage",
            "env": {"OUT": str(out)},
            "run": (
                'python -c "import os, sys; '
                "open(os.environ['OUT'], 'w').write(' '.join(sys.argv[1:]) + '\\n' + "
                "'\\n'.join(sorted(os.environ)))\" -v -n 4 --dist loadgroup"
            ),
        },
    ]


def test_full_runs_the_workflow_full_suite_step_with_its_own_receipt(tmp_path):
    out = tmp_path / "suite"
    work = _scratch_repository(tmp_path, [{"name": "Ok", "run": "true"}], _full_suite_steps(out))
    secrets = {
        "UNIFI_API_KEY": "dummy-value",
        "UNIFI_API_KEYS": "dummy-value",
        "UNIFI_TEST_HOST": "dummy-value",
        "MCP_BEARER_TOKEN": "dummy-value",
        "SOME_SERVICE_TOKEN": "dummy-value",
        "CONSOLE_PASSWORD": "dummy-value",
    }
    result = _prepush(work, "--full", env=secrets)
    assert result.returncode == 0, result.stdout + result.stderr
    head = _git("-C", str(work), "rev-parse", "HEAD")[:7]
    lines = result.stdout.rstrip().splitlines()
    assert lines[-1] == f"Pre-push: scripts/prepush.sh --full pass (head {head}, workers 4)"
    # Exactly one receipt: the fast line is not printed, and each pattern matches only
    # its own line.
    assert len(FULL.findall(result.stdout)) == 1
    assert not CANONICAL.search(result.stdout)
    assert not FULL.search(f"Pre-push: scripts/prepush.sh pass (head {head})")
    argv, *names = out.read_text().splitlines()
    # The step ran as read from the workflow (its if never held in the scratch tree),
    # last, after the guards, and its setup step stayed provisioning.
    assert argv == "-v -n 4 --dist loadgroup"
    assert not (work / "never-run-setup").exists()
    if fast.PREPUSH_GUARDS:
        assert result.stdout.index("== guards") < result.stdout.index("== test\n")
    assert not set(secrets) & set(names)
    assert not any(name.startswith(("UNIFI_", "MCP_")) for name in names)
    # The runner may carry more credential-named variables than the six injected here
    # (prepush strips every inherited one), so check the injected names, not a fixed count.
    stripped = re.search(r"without (\d+) credential variable\(s\): (.*)", result.stdout)
    assert stripped, result.stdout
    removed = stripped.group(2).split()
    assert int(stripped.group(1)) == len(removed)
    assert set(secrets) <= set(removed)


def test_full_worker_override_is_printed_in_the_receipt(tmp_path):
    out = tmp_path / "suite"
    work = _scratch_repository(tmp_path, [{"name": "Ok", "run": "true"}], _full_suite_steps(out))
    result = _prepush(work, "--full", env={"PREPUSH_XDIST_WORKERS": "3"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert out.read_text().splitlines()[0] == "-v -n 3 --dist loadgroup"
    assert FULL.search(result.stdout).group(0).endswith(", workers 3)")
    bad = _prepush(work, "--full", env={"PREPUSH_XDIST_WORKERS": "auto"})
    assert bad.returncode != 0
    assert "not a positive integer" in bad.stderr
    assert not FULL.search(bad.stdout) and not CANONICAL.search(bad.stdout)


def test_default_prepush_is_unchanged_by_full_mode(tmp_path):
    out = tmp_path / "suite"
    work = _scratch_repository(tmp_path, [{"name": "Ok", "run": "true"}], _full_suite_steps(out))
    result = _prepush(work, env={"PREPUSH_XDIST_WORKERS": "3"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert not out.exists()
    assert "== test: CI only" in result.stdout
    assert "--full" not in result.stdout
    assert len(CANONICAL.findall(result.stdout)) == 1 and not FULL.search(result.stdout)
    assert _prepush(work, "--fast").returncode == 2


def test_full_fails_without_a_pass_line(tmp_path):
    steps = [{"name": "Run full suite with coverage", "run": "exit 4 # -n 4 workers"}]
    work = _scratch_repository(tmp_path, [{"name": "Ok", "run": "true"}], steps)
    result = _prepush(work, "--full")
    assert result.returncode != 0
    assert "step 'Run full suite with coverage (workers 4)' exited 4" in result.stderr
    assert not FULL.search(result.stdout) and not CANONICAL.search(result.stdout)


def test_full_refuses_a_suite_step_that_declares_a_credential(tmp_path):
    out = tmp_path / "suite"
    steps = _full_suite_steps(out)
    steps[1]["env"]["UNIFI_API_KEY"] = "${{ github.base_ref }}"
    work = _scratch_repository(tmp_path, [{"name": "Ok", "run": "true"}], steps)
    result = _prepush(work, "--full")
    assert result.returncode != 0
    assert "refusing to run the full suite" in result.stderr
    assert not out.exists()
    assert not FULL.search(result.stdout) and not CANONICAL.search(result.stdout)


def test_full_reads_the_ci_full_suite_step_unchanged():
    step = fast.full_suite_step(WORKFLOW)
    assert step["name"] == "Run full suite with coverage"
    run = str(step["run"])
    script, workers = fast.full_suite_workers(run, None)
    assert script == run and workers == "4"
    # The override changes only the script's --workers; the script turns it into -n.
    assert fast.full_suite_workers(run, "8")[0] == run.replace("--workers 4", "--workers 8")
    words = workflow_full_suite_command(run).split()
    assert words[words.index("-n") + 1] == "4"
    assert workflow_full_suite_command(fast.full_suite_workers(run, "8")[0]) == " ".join(
        words
    ).replace("-n 4", "-n 8")
    options = words[words.index("pytest") + 1 :]
    assert "tests/" in options  # the whole suite, no path narrowing
    for option in options:
        assert option not in {"-x", "--exitfirst", "--lf", "--last-failed", "-k", "-m"}, option
        assert not option.startswith(("--maxfail", "--deselect", "--timeout")), option
    assert fast.FULL_SUITE_JOB in fast.CI_ONLY_JOBS  # CI-only unless --full
    assert fast.FULL_SUITE_JOB not in fast.ci_only_jobs("ci.yml", full=True)


def test_full_suite_workers_reads_either_flag_and_keeps_it():
    script = 'bash scripts/run_full_suite.sh "$DEV_VENV/bin/python" --workers 4'
    assert fast.full_suite_workers(script, None) == (script, "4")
    assert fast.full_suite_workers(script, "3")[0].endswith(" --workers 3")
    assert fast.full_suite_workers("pytest -n 4 -v", "2") == ("pytest -n 2 -v", "2")
    with pytest.raises(fast.WorkflowError, match="2 worker counts"):
        fast.full_suite_workers("run --workers 4 -n 4", None)
    with pytest.raises(fast.WorkflowError, match="0 worker counts"):
        fast.full_suite_workers("bash scripts/run_full_suite.sh python", None)


def test_without_credentials_removes_every_credential_name_and_nothing_else():
    environ = {
        "PATH": "/bin",
        "HOME": "/home/x",
        "UNIFI_API_KEY": "v",
        "unifi_test_site": "v",
        "MCP_TLS_KEY_PASSWORD": "v",
        "GH_TOKEN": "v",
        "AWS_SECRET_ACCESS_KEY": "v",
        "SERVICE_APIKEY": "v",
        "DB_PASSWD": "v",
    }
    kept, removed = fast.without_credentials(environ)
    assert kept == {"PATH": "/bin", "HOME": "/home/x"}
    assert removed == sorted(set(environ) - {"PATH", "HOME"})
