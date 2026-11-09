"""Execute the CI changelog gate with representative changed-file sets."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    ("changed", "labels", "expected"),
    [
        ("src/tool.py\nCHANGELOG.md", "[]", 0),
        *[
            (f"src/tool.py\nchangelog.d/lane.{kind}.md", "[]", 0)
            for kind in ("added", "changed", "removed", "fixed", "security")
        ],
        ("src/tool.py\nchangelog.d/README.md", "[]", 1),
        ("src/tool.py\nchangelog.d/lane.invalid.md", "[]", 1),
        ("src/tool.py", '["skip-changelog"]', 0),
        ("tests/test_tool.py", "[]", 0),
        ("src/tool.py", "[]", 1),
    ],
)
def test_ci_changelog_gate_accepts_fragments_and_monolith(tmp_path, changed, labels, expected):
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    step = next(s for s in workflow["jobs"]["changelog-check"]["steps"] if "run" in s)
    # Feed the real shell gate a synthetic git diff without altering a repository.
    git = tmp_path / "git"
    git.write_text('#!/bin/sh\nprintf "%s\\n" "$CHANGED_FILES"\n')
    git.chmod(0o755)
    env = dict(
        os.environ,
        PATH=f"{tmp_path}:{os.environ['PATH']}",
        CHANGED_FILES=changed,
        BASE="base",
        HEAD="head",
        LABELS=labels,
    )
    result = subprocess.run(  # noqa: S603 - execute the checked-in CI gate
        ["/bin/bash", "-euo", "pipefail", "-c", step["run"]],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == expected, result.stdout + result.stderr
