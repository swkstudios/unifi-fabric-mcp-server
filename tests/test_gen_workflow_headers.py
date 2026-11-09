"""The shared pull-request concurrency block has one source and CI checks every copy."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import gen_workflow_headers as gen  # noqa: E402

WORKFLOWS = ROOT / ".github" / "workflows"
#: The block every pull-request workflow carried before it had a single source.
LEGACY_BLOCK = (
    "concurrency:\n"
    "  group: ${{ github.event_name == 'pull_request' && format('{0}-pr-{1}', "
    "github.workflow, github.event.pull_request.number) || format('{0}-{1}-{2}-{3}', "
    "github.workflow, github.event_name, github.sha, github.run_id) }}\n"
    "  cancel-in-progress: ${{ github.event_name == 'pull_request' }}\n"
)
SERIAL_BLOCK = "concurrency:\n  group: release\n  cancel-in-progress: false\n"
WORKFLOW = """name: Example

on:
  pull_request:

{block}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
"""


def _tree(tmp_path: Path, **workflows: str) -> Path:
    directory = tmp_path / "workflows"
    directory.mkdir()
    for name, text in workflows.items():
        (directory / f"{name}.yml").write_text(text)
    return directory


def _header(*names: str) -> gen.Header:
    real = gen.load()
    return gen.Header(real.group, real.cancel_in_progress, names)


def test_committed_workflows_match_the_config():
    assert gen.problems(gen.load()) == []
    assert gen.main(["--check"]) == 0


def test_rendered_block_keeps_the_previous_concurrency_byte_for_byte():
    header = gen.load()
    assert header.render() == f"{gen.MARKER}\n{LEGACY_BLOCK}"
    for name in header.workflows:
        path = WORKFLOWS / name
        if not path.exists():
            continue
        text = path.read_text()
        assert text.count(header.render()) == 1, name
        # The parsed value every reader sees is the previous block's.
        assert yaml.safe_load(text)["concurrency"] == yaml.safe_load(LEGACY_BLOCK)["concurrency"]


def test_every_pull_request_concurrency_copy_is_listed():
    header = gen.load()
    for path in sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")]):
        block = yaml.safe_load(path.read_text()).get("concurrency")
        if isinstance(block, dict) and gen.PR_KEY in str(block.get("group")):
            assert path.name in header.workflows + header.own_block, path.name


def test_own_block_workflows_keep_their_own_concurrency(tmp_path):
    """ci.yml keeps its own block (dev pushes share one cancelling group); not rendered."""
    header = gen.load()
    assert "ci.yml" in header.own_block
    assert set(header.own_block).isdisjoint(header.workflows)
    ci = (WORKFLOWS / "ci.yml").read_text()
    assert gen.MARKER not in ci
    concurrency = yaml.safe_load(ci)["concurrency"]
    assert "format('{0}-push-dev', github.workflow)" in concurrency["group"]
    assert "refs/heads/dev" in concurrency["cancel-in-progress"]
    # --write leaves an own-block workflow byte-for-byte as it was.
    workflows = _tree(tmp_path, ci=ci)
    own = gen.Header(header.group, header.cancel_in_progress, (), ("ci.yml",))
    assert gen.problems(own, workflows, write=True) == []
    assert (workflows / "ci.yml").read_text() == ci


def test_stale_or_rendered_own_block_entry_fails(tmp_path):
    header = _header()
    workflows = _tree(
        tmp_path,
        bare=WORKFLOW.format(block=SERIAL_BLOCK),
        marked=WORKFLOW.format(block=header.render()),
    )
    own = gen.Header(header.group, header.cancel_in_progress, (), ("bare.yml", "marked.yml"))
    assert gen.problems(own, workflows) == [
        "bare.yml: listed in workflow-headers.toml [pr-concurrency] own-block but carries no "
        "pull-request concurrency block",
        "marked.yml: keeps its own concurrency block, so it must not carry the rendered marker",
    ]


def test_check_reports_drift_and_write_repairs_it(tmp_path):
    drifted = LEGACY_BLOCK.replace("cancel-in-progress: ${{", "cancel-in-progress: false #${{")
    workflows = _tree(tmp_path, a=WORKFLOW.format(block=drifted))
    header = _header("a.yml")
    assert gen.problems(header, workflows) == [
        "a.yml: concurrency block differs from workflow-headers.toml [pr-concurrency]"
    ]
    assert gen.problems(header, workflows, write=True) == []
    text = (workflows / "a.yml").read_text()
    assert text == WORKFLOW.format(block=header.render())
    assert gen.problems(header, workflows) == []
    # Rendering is idempotent: the marker line is part of the block it replaces.
    assert gen.render(text, header, "a.yml") == text


def test_unlisted_pull_request_block_and_missing_block_fail(tmp_path):
    workflows = _tree(
        tmp_path,
        copy=WORKFLOW.format(block=LEGACY_BLOCK),
        bare=WORKFLOW.format(block=""),
        serial=WORKFLOW.format(block=SERIAL_BLOCK),
    )
    found = gen.problems(_header("bare.yml"), workflows)
    assert found == [
        "bare.yml: expected one top-level concurrency block, found 0",
        "copy.yml: pull-request concurrency block not listed in workflow-headers.toml "
        "[pr-concurrency] workflows",
    ]


def test_listed_workflow_absent_from_the_tree_is_skipped(tmp_path):
    workflows = _tree(tmp_path, a=WORKFLOW.format(block=_header().render()))
    assert gen.problems(_header("a.yml", "private-only.yml"), workflows) == []


def test_job_level_concurrency_is_not_touched(tmp_path):
    job_level = WORKFLOW.format(block=LEGACY_BLOCK).replace(
        "    runs-on: ubuntu-latest\n",
        "    runs-on: ubuntu-latest\n    concurrency:\n      group: job\n",
    )
    workflows = _tree(tmp_path, a=job_level)
    header = _header("a.yml")
    gen.problems(header, workflows, write=True)
    text = (workflows / "a.yml").read_text()
    assert "    concurrency:\n      group: job\n" in text
    assert yaml.safe_load(text)["jobs"]["build"]["concurrency"] == {"group": "job"}


@pytest.mark.parametrize(
    "table",
    [
        'group = "g"\ncancel-in-progress = "c"\nworkflows = ["a.yml", "a.yml"]\n',
        'group = "g"\ncancel-in-progress = "c"\nworkflows = []\nextra = 1\n',
        'group = "g\\nh"\ncancel-in-progress = "c"\nworkflows = []\n',
        'group = "g"\ncancel-in-progress = "c"\nworkflows = ["a.yml"]\nown-block = ["a.yml"]\n',
    ],
)
def test_config_rejects_duplicates_unknown_keys_and_multiline_values(tmp_path, table):
    config = tmp_path / "workflow-headers.toml"
    config.write_text(f"[pr-concurrency]\n{table}")
    with pytest.raises(ValueError):
        gen.load(config)


def test_ci_lint_job_runs_the_drift_check():
    workflow = yaml.safe_load((WORKFLOWS / "ci.yml").read_text())
    runs = [step.get("run", "") for step in workflow["jobs"]["lint"]["steps"]]
    assert "python scripts/gen_workflow_headers.py --check" in runs


def test_cli_check_exit_codes(tmp_path):
    config = tmp_path / "headers.toml"
    real = (ROOT / ".github" / "workflow-headers.toml").read_text()
    start = real.index("workflows = [")
    config.write_text(real[:start] + 'workflows = ["a.yml"]\n')
    rendered = gen.render(WORKFLOW.format(block=LEGACY_BLOCK), gen.load(config), "a.yml")
    workflows = _tree(tmp_path, a=rendered)
    base = [sys.executable, str(ROOT / "scripts" / "gen_workflow_headers.py")]
    args = ["--config", str(config), "--workflows", str(workflows)]
    clean = subprocess.run([*base, "--check", *args], capture_output=True, text=True)  # noqa: S603
    assert clean.returncode == 0, clean.stderr
    (workflows / "a.yml").write_text(WORKFLOW.format(block=LEGACY_BLOCK.replace("pr-", "p-")))
    drift = subprocess.run([*base, *args], capture_output=True, text=True)  # noqa: S603
    assert drift.returncode == 1
    assert "::error::a.yml: concurrency block differs" in drift.stderr
    assert "--write" in drift.stderr


def test_yaml_extension_workflows_are_checked_too(tmp_path):
    """GitHub reads .yaml workflows as well as .yml; both drift and unlisted blocks are found."""
    directory = tmp_path / "workflows"
    directory.mkdir()
    drifted = LEGACY_BLOCK.replace("cancel-in-progress: ${{", "cancel-in-progress: false #${{")
    (directory / "listed.yaml").write_text(WORKFLOW.format(block=drifted))
    (directory / "copy.yaml").write_text(WORKFLOW.format(block=LEGACY_BLOCK))
    found = gen.problems(_header("listed.yaml"), directory)
    assert found == [
        "copy.yaml: pull-request concurrency block not listed in workflow-headers.toml "
        "[pr-concurrency] workflows",
        "listed.yaml: concurrency block differs from workflow-headers.toml [pr-concurrency]",
    ]
