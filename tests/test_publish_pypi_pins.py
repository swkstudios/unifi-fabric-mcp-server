"""The PyPI publish job installs its build/upload tooling by exact version and hash."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "publish-pypi.yml"
LOCK = ROOT / ".github" / "publish-pypi-requirements.txt"


def _runs() -> list[str]:
    jobs = yaml.safe_load(WORKFLOW.read_text())["jobs"]
    return [step.get("run", "") for job in jobs.values() for step in job["steps"]]


def test_tooling_installs_only_from_the_hashed_lock() -> None:
    installs = [r for r in _runs() if "pip install" in r]
    assert installs, "no pip install step"
    for run in installs:
        assert "--require-hashes" in run and "--only-binary :all:" in run, run
        assert "-r .github/publish-pypi-requirements.txt" in run, run


def test_build_uses_the_pinned_backend() -> None:
    builds = [r for r in _runs() if "python -m build" in r]
    assert builds and all("--no-isolation" in r for r in builds), builds


def test_lock_pins_every_requirement_with_a_hash() -> None:
    entries = re.split(r"\n(?=[a-z0-9])", LOCK.read_text().split("\n\n", 1)[-1].strip())
    reqs = [e for e in entries if not e.startswith("#")]
    names = set()
    for entry in reqs:
        head = entry.splitlines()[0]
        match = re.match(r"^([a-z0-9][a-z0-9._-]*)==([0-9][^ ;\\]*)", head)
        assert match, head
        names.add(match.group(1))
        assert "--hash=sha256:" in entry, head
    assert {"build", "twine", "hatchling"} <= names
