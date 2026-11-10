"""The shared development environment has one definition: .github/actions/setup-dev.

Every CI job that uses the shared venv calls the action; none re-implements the cache
key, the restore or the locked install. The action never writes the cache: a job that
seeds it keeps its own default-branch save step and saves under the action's key output,
so the saved and restored keys cannot differ.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from tests._ci_actions import expanded_steps, local_action

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
ACTION_USES = "./.github/actions/setup-dev"
ACTION = local_action(ACTION_USES)
SHA_PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
LOCKED_INSTALL = '"$DEV_VENV/bin/python" -m pip install --require-hashes -r requirements.lock'
EDITABLE_INSTALL = '"$DEV_VENV/bin/python" -m pip install --no-deps -e .'
#: A step that builds the shared venv itself instead of calling the action. A job that
#: installs the locked requirements into its own separate venv (conformance.yml builds
#: the server into $RUNNER_TEMP) is not on the shared environment.
REIMPLEMENTS = re.compile(
    r"python -m venv \"?\$\{?DEV_VENV"
    r"|\$\{?DEV_VENV\}?/bin/python\"? -m pip install --require-hashes -r requirements\.lock"
    r"|date -u \+%G-W%V"
)


def _workflows():
    for path in sorted(WORKFLOWS.glob("*.y*ml")):
        yield path.name, yaml.safe_load(path.read_text()) or {}


def _ci_jobs():
    return yaml.safe_load((WORKFLOWS / "ci.yml").read_text())["jobs"]


def _uses_dev_venv(step):
    if "DEV_VENV" in str(step.get("run", "")):
        return True
    return "env.DEV_VENV" in str(step.get("with", {}))


def _callers():
    return {
        name: job
        for name, job in _ci_jobs().items()
        if any(step.get("uses") == ACTION_USES for step in job.get("steps", []))
    }


def test_every_job_on_the_shared_venv_calls_the_action_and_none_reimplements_it():
    callers = set()
    for workflow_name, workflow in _workflows():
        for job_name, job in (workflow.get("jobs") or {}).items():
            steps = job.get("steps") or []
            label = f"{workflow_name}:{job_name}"
            for step in steps:
                assert not REIMPLEMENTS.search(str(step.get("run", ""))), (
                    f"{label} re-implements the shared dev environment; call {ACTION_USES} instead"
                )
                restore = str(step.get("uses", "")).startswith("actions/cache/restore@")
                assert not (restore and _uses_dev_venv(step)), (
                    f"{label} restores the shared venv itself; call {ACTION_USES}"
                )
            if not any(_uses_dev_venv(step) for step in steps):
                continue
            calls = [i for i, step in enumerate(steps) if step.get("uses") == ACTION_USES]
            assert len(calls) == 1, f"{label} uses $DEV_VENV without calling {ACTION_USES} once"
            first_use = next(i for i, step in enumerate(steps) if _uses_dev_venv(step))
            assert calls[0] < first_use, f"{label} uses $DEV_VENV before setting it up"
            callers.add(label)
    # The jobs that shared the copied blocks before the action existed (lane-gate is
    # private-only: the public tree does not carry it).
    expected = {"typecheck", "docs", "test", "scrub-oracle", "lane-gate"} & set(_ci_jobs())
    assert {f"ci.yml:{name}" for name in expected} <= callers
    assert {"typecheck", "docs", "test", "scrub-oracle"} <= expected


def test_callers_pass_the_exact_interpreter_and_save_under_the_action_key():
    callers = _callers()
    assert callers
    for name, job in callers.items():
        steps = job["steps"]
        call_index, call = next(
            (i, step) for i, step in enumerate(steps) if step.get("uses") == ACTION_USES
        )
        setup_python = [
            i
            for i, step in enumerate(steps)
            if str(step.get("uses", "")).startswith("actions/setup-python@")
        ]
        assert setup_python and setup_python[0] < call_index, name
        py = steps[setup_python[0]].get("id")
        assert py, f"{name}: setup-python needs an id for its python-version output"
        assert call.get("id"), name
        assert call["with"] == {"python-version": f"${{{{ steps.{py}.outputs.python-version }}}}"}
        saves = [
            step
            for step in steps
            if str(step.get("uses", "")).startswith("actions/cache/save@")
            and step["with"]["path"] == "${{ env.DEV_VENV }}"
        ]
        for save in saves:
            assert save["with"]["key"] == f"${{{{ steps.{call['id']}.outputs.key }}}}", name
            assert f"steps.{call['id']}.outputs.cache-hit != 'true'" in save["if"], name
            assert "github.event.repository.default_branch" in save["if"], name
            assert "github.event_name == 'push'" in save["if"], name
    # typecheck, docs and test-prep (for the full suite) seed the cache on the default
    # branch; the others only read.
    assert {"typecheck", "docs", "test-prep"} <= {
        name
        for name, job in callers.items()
        if any(str(s.get("uses", "")).startswith("actions/cache/save@") for s in job["steps"])
    }


def test_the_action_owns_the_key_the_restore_and_the_locked_install():
    assert ACTION["runs"]["using"] == "composite"
    steps = ACTION["runs"]["steps"]
    key, restore, install = steps
    assert key["name"] == "Cache key" and key["id"] == "venv-key"
    assert install["name"] == "Install dev environment"
    # The key: OS, fixed venv path, exact interpreter, ISO week, project inputs.
    assert key["env"] == {
        "PYTHON_VERSION": "${{ inputs.python-version }}",
        "PROJECT_HASH": "${{ hashFiles('pyproject.toml', 'requirements.lock') }}",
    }
    assert 'week="$(date -u +%G-W%V)"' in key["run"]
    assert (
        'echo "key=venv-${RUNNER_OS}-${DEV_VENV}-py${PYTHON_VERSION}-${week}-${PROJECT_HASH}"'
        in key["run"]
    )
    assert 'rm -rf "${DEV_VENV:?}"' in key["run"]
    # Restore only: a PR run must never write the shared cache.
    assert restore["uses"].startswith("actions/cache/restore@")
    assert restore["id"] == "venv-cache"
    assert restore["with"] == {
        "path": "${{ env.DEV_VENV }}",
        "key": "${{ steps.venv-key.outputs.key }}",
    }
    for step in steps:
        uses = str(step.get("uses", ""))
        assert not uses.startswith(("actions/cache@", "actions/cache/save@")), uses
        if uses:
            assert SHA_PINNED.match(uses), uses
        if "run" in step:
            assert step["shell"] == "bash"
            assert "${{" not in step["run"], "expressions reach the shell through env only"
    # The hashed lock is installed before the project, then the venv goes on PATH.
    run = install["run"]
    assert install["env"] == {"CACHE_HIT": "${{ steps.venv-cache.outputs.cache-hit }}"}
    assert run.index(LOCKED_INSTALL) < run.index(EDITABLE_INSTALL)
    assert 'python -m venv "$DEV_VENV"' in run
    assert 'echo "$DEV_VENV/bin" >> "$GITHUB_PATH"' in run


def test_the_action_exposes_the_outputs_callers_need():
    outputs = ACTION["outputs"]
    assert {name: spec["value"] for name, spec in outputs.items()} == {
        "cache-hit": "${{ steps.venv-cache.outputs.cache-hit }}",
        "week": "${{ steps.venv-key.outputs.week }}",
        "python-version": "${{ steps.venv-key.outputs.python-version }}",
        "key": "${{ steps.venv-key.outputs.key }}",
    }
    assert ACTION["inputs"]["python-version"]["required"] is True


def test_expanded_caller_steps_install_the_hashed_lock_before_the_project():
    for name, job in _callers().items():
        expanded = list(expanded_steps(job["steps"]))
        runs = "\n".join(str(step.get("run", "")) for step in expanded)
        assert runs.index(LOCKED_INSTALL) < runs.index(EDITABLE_INSTALL), name
        assert not any(step.get("uses") == ACTION_USES for step in expanded), name
