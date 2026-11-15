"""Read a workflow job's ``runs-on`` the way both trees write it.

A Linux job reads its runner from a repository or organisation variable and falls back to a
default when the variable is missing::

    runs-on: ${{ fromJSON(vars.LINUX_RUNNER || '<json default>') }}

The source repository's default is its own runner pool and the published tree's default is a
GitHub-hosted label, so one assertion on ``runner_fallback`` serves tests that run in both.
A runner written as a plain label (macOS, Windows, a matrix value) is returned unchanged.
"""

from __future__ import annotations

import json
import re
from typing import Any

#: The one form of a Linux runner declaration: the variable name and its JSON fallback.
RUNNER_EXPRESSION = re.compile(
    r"^\$\{\{ fromJSON\(vars\.(LINUX_[A-Z0-9_]*RUNNER[A-Z0-9_]*) \|\| '([^']*)'\) \}\}$"
)


def runner_variable(runs_on: Any) -> str | None:
    """The variable a runs-on expression reads, or None for a plain runner."""
    match = RUNNER_EXPRESSION.match(runs_on) if isinstance(runs_on, str) else None
    return match.group(1) if match else None


def runner_fallback(runs_on: Any) -> Any:
    """The runner the job lands on when its variable is missing."""
    match = RUNNER_EXPRESSION.match(runs_on) if isinstance(runs_on, str) else None
    return json.loads(match.group(2)) if match else runs_on
