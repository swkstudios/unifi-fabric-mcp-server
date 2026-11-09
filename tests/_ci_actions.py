"""Workflow steps as the runner executes them: a step that calls a local composite
action (``uses: ./.github/actions/<name>``) is replaced by that action's own steps, so
a test that asserts what a job installs or runs reads the action's steps too."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
LOCAL_ACTION_PREFIX = "./.github/actions/"


def local_action(uses: str, root: Path = ROOT) -> dict[str, Any]:
    """The parsed ``action.yml`` of a local action reference such as
    ``./.github/actions/setup-dev``."""
    if not uses.startswith(LOCAL_ACTION_PREFIX):
        raise ValueError(f"not a local action: {uses}")
    return yaml.safe_load((root / uses[2:] / "action.yml").read_text())


def expanded_steps(steps: Iterable[dict[str, Any]], root: Path = ROOT) -> Iterator[dict[str, Any]]:
    """Every step, with each local composite action expanded in place."""
    for step in steps:
        uses = str(step.get("uses", ""))
        if uses.startswith(LOCAL_ACTION_PREFIX):
            action = local_action(uses, root)
            assert action["runs"]["using"] == "composite", uses
            yield from expanded_steps(action["runs"]["steps"], root)
        else:
            yield step
