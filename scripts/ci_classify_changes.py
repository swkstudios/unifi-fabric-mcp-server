#!/usr/bin/env python3
"""Conservatively classify a CI change for the private development workflow.

The classifier never makes a source or shared-infrastructure change cheaper. A
single tools module with its matching test is the only targeted-test class;
everything else that is not documentation-only receives the complete test tier.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS_PREFIX = "src/unifi_fabric/tools/"
DOC_PREFIXES = ("docs/",)
DOC_FILES = {"README.md", "CHANGELOG.md", "CLAUDE.md", "AGENTS.md"}
COMMON_SELECTED_TESTS = (
    "tests/test_cross_tool_invariants.py",
    "tests/test_secret_leak_invariant.py",
)


class ClassificationError(RuntimeError):
    """The comparison is unavailable or ambiguous."""


@dataclass(frozen=True)
class Decision:
    tier: str
    reason: str
    test_file: str = ""


def _tool_module(path: str) -> str | None:
    if not path.startswith(TOOLS_PREFIX) or not path.endswith(".py"):
        return None
    stem = path.removeprefix(TOOLS_PREFIX).removesuffix(".py")
    if not stem or "/" in stem or stem.startswith("_"):
        return None
    return stem


def _is_documentation(path: str) -> bool:
    return path.startswith(DOC_PREFIXES) or path in DOC_FILES or path.startswith("changelog.d/")


def classify(paths: Iterable[str], *, root: Path = ROOT, force_full: bool = False) -> Decision:
    """Return fast, targeted, or full without trusting omitted/unknown paths."""
    changed = sorted({path for path in paths if path})
    if force_full:
        return Decision("full", "event requires the complete tier")
    if not changed:
        raise ClassificationError("empty change set is not safe to classify")
    if all(_is_documentation(path) for path in changed):
        return Decision("fast", "documentation-only change")

    modules = {_tool_module(path) for path in changed if _tool_module(path) is not None}
    if len(modules) != 1:
        return Decision("full", "shared, unknown, or multi-module change")
    module = next(iter(modules))
    test_file = f"tests/test_{module}.py"
    allowed = {
        f"{TOOLS_PREFIX}{module}.py",
        test_file,
        *COMMON_SELECTED_TESTS,
        "docs/TOOLS.md",
        "README.md",
        "CHANGELOG.md",
    }
    if any(path not in allowed and not path.startswith("changelog.d/") for path in changed):
        return Decision("full", "tool change also modifies shared or unknown paths")
    if not (root / test_file).is_file():
        return Decision("full", f"{test_file} is absent; targeted coverage is unproven")
    return Decision("targeted", f"isolated tools module {module}", test_file)


def changed_paths(base: str, head: str) -> list[str]:
    try:
        output = subprocess.check_output(
            ["git", "diff", "--name-only", f"{base}...{head}"], cwd=ROOT, text=True
        )
    except subprocess.CalledProcessError as exc:
        raise ClassificationError(f"cannot diff {base}...{head}") from exc
    return [line.strip() for line in output.splitlines() if line.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--force-full", action="store_true")
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args(argv)
    try:
        paths = [] if args.force_full else changed_paths(args.base, args.head)
        decision = classify(paths, force_full=args.force_full)
    except ClassificationError as exc:
        print(f"ci-classify: {exc}", file=sys.stderr)
        return 1
    payload = {
        "tier": decision.tier,
        "reason": decision.reason,
        "test_file": decision.test_file,
    }
    print(json.dumps(payload, sort_keys=True))
    if args.github_output:
        with args.github_output.open("a") as output:
            for key, value in payload.items():
                output.write(f"{key}={value}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
