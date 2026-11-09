"""The shared release-ref validator and its use by both publish.yml build jobs."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash") or "/bin/bash"
SCRIPT = ROOT / "scripts" / "validate_release_ref.sh"
PUBLISH = ROOT / ".github" / "workflows" / "publish.yml"
JOBS = ("build-amd64", "build-arm64")
# Where the build jobs check out the validator from the workflow's own commit.
VALIDATOR_DIR = "release-ref-validator"
# The only way the workflow may hand the three values to the script (never inline in run:).
EXPECTED_ENV = {
    "EVENT_NAME": "${{ github.event_name }}",
    "INPUT_TAG": "${{ github.event.inputs.tag || github.ref_name }}",
    "INPUT_CORRELATION_NONCE": "${{ github.event.inputs.correlation_nonce }}",
    "WORKFLOW_REF": "${{ github.ref }}",
}


def _steps(job: str) -> list[dict[str, Any]]:
    return yaml.safe_load(PUBLISH.read_text())["jobs"][job]["steps"]


def _validate(event: str, tag: str, ref: str) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        "EVENT_NAME": event,
        "INPUT_TAG": tag,
        "INPUT_CORRELATION_NONCE": "0" * 32 if event == "workflow_dispatch" else "",
        "WORKFLOW_REF": ref,
    }
    return subprocess.run(  # noqa: S603 - fixed shell and repository script
        [BASH, str(SCRIPT)], env=env, capture_output=True, text=True, check=False
    )


def _validate_step(job: str) -> dict[str, Any]:
    (step,) = [s for s in _steps(job) if "validate_release_ref.sh" in str(s.get("run", ""))]
    return step


def _checkouts(job: str) -> list[tuple[int, dict[str, Any]]]:
    return [
        (i, s)
        for i, s in enumerate(_steps(job))
        if str(s.get("uses", "")).startswith("actions/checkout@")
    ]


@pytest.mark.parametrize("job", JOBS)
def test_job_calls_the_shared_script_once_with_env_only(job: str) -> None:
    step = _validate_step(job)
    assert step["env"] == EXPECTED_ENV
    assert step.get("if") == "github.event_name != 'workflow_run'"
    assert step["run"].split() == [
        "bash",
        f"{VALIDATOR_DIR}/scripts/validate_release_ref.sh",
        "rm",
        "-rf",
        VALIDATOR_DIR,
    ]
    names = [s.get("name") for s in _steps(job)]
    assert "Validate tag format" not in names
    assert "Require the release tag as the workflow ref" not in names


@pytest.mark.parametrize("job", JOBS)
def test_validator_comes_from_the_workflow_commit_before_the_release_checkout(job: str) -> None:
    """The check is never loaded from the ref it judges (the tag input's tree).

    Every checkout before the validation step is the workflow's own commit, sparse to the
    validator, in its own directory; the release ref is checked out only afterwards.
    """
    steps = _steps(job)
    validate = steps.index(_validate_step(job))
    before = [(i, s) for i, s in _checkouts(job) if i < validate]
    after = [(i, s) for i, s in _checkouts(job) if i > validate]
    assert len(before) == 1, before
    _, trusted = before[0]
    assert trusted.get("if") == "github.event_name != 'workflow_run'"
    assert trusted["with"] == {
        "persist-credentials": False,
        "ref": "${{ github.workflow_sha }}",
        "path": VALIDATOR_DIR,
        "sparse-checkout": "scripts/validate_release_ref.sh",
        "sparse-checkout-cone-mode": False,
    }
    assert len(after) == 1, after
    _, release = after[0]
    assert "path" not in release["with"]
    assert release["with"]["ref"].startswith("${{ github.event.inputs.tag ||")
    # Nothing touches the release ref before it is validated.
    for step in steps[:validate]:
        assert "inputs.tag" not in str(step.get("with", {})), step


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


@pytest.mark.parametrize("job", JOBS)
def test_validate_step_ignores_a_validator_in_the_checked_out_tree(
    job: str, tmp_path: Path
) -> None:
    """Run the workflow's validation step in a workspace whose root holds a validator that
    accepts anything (as a hostile ref's tree would) and whose validator directory holds
    the trusted script. A dispatch naming a branch as its tag must still be refused."""
    _write(tmp_path / "scripts" / "validate_release_ref.sh", "exit 0\n")
    trusted = tmp_path / VALIDATOR_DIR / "scripts" / "validate_release_ref.sh"
    _write(trusted, SCRIPT.read_text())
    step = _validate_step(job)
    env = {
        **os.environ,
        "EVENT_NAME": "workflow_dispatch",
        "INPUT_TAG": "dev",
        "INPUT_CORRELATION_NONCE": "0" * 32,
        "WORKFLOW_REF": "refs/tags/v0.7.1",
    }
    refused = subprocess.run(  # noqa: S603 - fixed shell and the workflow's own step text
        [BASH, "-e", "-c", step["run"]],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert refused.returncode != 0, refused.stdout + refused.stderr
    assert "::error::" in refused.stdout
    env.update(INPUT_TAG="v0.7.1")
    accepted = subprocess.run(  # noqa: S603 - fixed shell and the workflow's own step text
        [BASH, "-e", "-c", step["run"]],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert accepted.returncode == 0, accepted.stdout + accepted.stderr
    # The validator directory is removed before the release checkout.
    assert not (tmp_path / VALIDATOR_DIR).exists()


def test_no_inline_tag_expression_reaches_a_shell() -> None:
    for job in JOBS:
        for step in _steps(job):
            assert "github.event.inputs.tag" not in str(step.get("run", ""))


@pytest.mark.parametrize("job", JOBS)
@pytest.mark.parametrize(
    ("event", "tag", "ref", "ok"),
    [
        # Clean release fixtures: created tag and dispatch on the tag.
        ("create", "v0.7.1", "refs/tags/v0.7.1", True),
        ("push", "v0.7.1", "refs/tags/v0.7.1", True),
        ("workflow_dispatch", "v0.7.1", "refs/tags/v0.7.1", True),
        # Pre-release fixtures: allowed on a created/pushed tag, never as a dispatched release.
        ("create", "v0.7.1-dev.3", "refs/tags/v0.7.1-dev.3", True),
        ("create", "v0.7.1-rc.1", "refs/tags/v0.7.1-rc.1", True),
        ("workflow_dispatch", "v0.7.1-dev.3", "refs/tags/v0.7.1-dev.3", False),
        # Dispatch must run on the tag itself.
        ("workflow_dispatch", "v0.7.1", "refs/heads/dev", False),
        ("workflow_dispatch", "v0.7.1", "refs/tags/v0.7.0", False),
        # A create event does not need the ref check but still needs a valid tag.
        ("create", "v0.7", "refs/tags/v0.7", False),
        ("create", "0.7.1", "refs/tags/0.7.1", False),
        ("create", "v0.7.1; touch pwned", "refs/tags/x", False),
        ("create", "v0.7.1-$(id)", "refs/tags/x", False),
        ("create", "", "refs/tags/", False),
    ],
)
def test_validator_fixtures(
    job: str, event: str, tag: str, ref: str, ok: bool, tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    # Both jobs use the same step, so the fixtures run against the env each job declares.
    step = _validate_step(job)
    assert set(step["env"]) == {
        "EVENT_NAME",
        "INPUT_TAG",
        "INPUT_CORRELATION_NONCE",
        "WORKFLOW_REF",
    }
    done = _validate(event, tag, ref)
    assert (done.returncode == 0) is ok, done.stdout + done.stderr
    if not ok:
        assert "::error::" in done.stdout
    assert not (tmp_path / "pwned").exists()


def test_missing_event_name_is_rejected() -> None:
    env = {k: v for k, v in os.environ.items() if k != "EVENT_NAME"}
    done = subprocess.run(  # noqa: S603 - fixed shell and repository script
        [BASH, str(SCRIPT)], env=env, capture_output=True, text=True, check=False
    )
    assert done.returncode != 0


@pytest.mark.parametrize("nonce", ["", "0" * 31, "0" * 33, "G" * 32, "$(id)"])
def test_dispatch_correlation_nonce_is_validated(nonce: str) -> None:
    env = {
        **os.environ,
        "EVENT_NAME": "workflow_dispatch",
        "INPUT_TAG": "v0.7.1",
        "INPUT_CORRELATION_NONCE": nonce,
        "WORKFLOW_REF": "refs/tags/v0.7.1",
    }
    done = subprocess.run(  # noqa: S603 - fixed shell and repository script
        [BASH, str(SCRIPT)], env=env, capture_output=True, text=True, check=False
    )
    assert done.returncode != 0
    assert "::error::" in done.stdout
