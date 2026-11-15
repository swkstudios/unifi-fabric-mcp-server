#!/usr/bin/env python3
"""List the open issues that carry the ``release:<version>`` label.

    python3 scripts/release_open_issues.py                # the version in pyproject.toml
    python3 scripts/release_open_issues.py X.Y.Z --json   # machine-readable
    python3 scripts/release_open_issues.py --count        # only the number

This is automation for the release owner, not a gate: it reads the issue tracker through
``gh`` (nothing is written), prints what is still open for the release, and exits 0 whether
or not any issue is left. It exits 2 only when the lookup itself fails (no ``gh``, no access,
unreadable output), so a failed lookup is never mistaken for "nothing open".
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPO = "swkstudios/unifi-fabric-mcp-server"
VERSION = re.compile(r"\d+\.\d+\.\d+")
Runner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]


class LookupError_(RuntimeError):
    """The issue lookup failed; the caller reports it instead of an empty list."""


def project_version(root: Path = ROOT) -> str:
    data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def open_issues(version: str, repo: str = DEFAULT_REPO, run: Runner = _run) -> list[dict]:
    """Open issues labelled ``release:<version>``, lowest number first."""
    if not VERSION.fullmatch(version):
        raise ValueError(f"version {version!r} is not X.Y.Z")
    cmd = [
        "gh", "issue", "list", "-R", repo, "--state", "open",
        "--label", f"release:{version}", "--limit", "1000",
        "--json", "number,title,url,labels",
    ]  # fmt: skip
    try:
        done = run(cmd)
    except OSError as exc:
        raise LookupError_(f"cannot run gh: {exc}") from exc
    if done.returncode != 0:
        raise LookupError_(f"gh issue list failed: {done.stderr.strip()[:300]}")
    try:
        issues = json.loads(done.stdout)
    except json.JSONDecodeError as exc:
        raise LookupError_(f"gh issue list returned unreadable output: {exc}") from exc
    if not isinstance(issues, list):
        raise LookupError_("gh issue list did not return a list")
    return sorted(issues, key=lambda issue: issue["number"])


def render(issues: list[dict], version: str) -> str:
    if not issues:
        return f"No open issues carry release:{version}."
    lines = [f"{len(issues)} open issue(s) carry release:{version}:"]
    lines += [f"  #{issue['number']}  {issue['title']}" for issue in issues]
    return "\n".join(lines)


def main(argv: list[str] | None = None, run: Runner = _run) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("version", nargs="?", help="X.Y.Z (default: the pyproject.toml version)")
    parser.add_argument("--repo", default=DEFAULT_REPO, help="OWNER/REPO to read")
    parser.add_argument("--json", action="store_true", help="print the issues as JSON")
    parser.add_argument("--count", action="store_true", help="print only the number open")
    args = parser.parse_args(argv)
    version = args.version or project_version()
    try:
        issues = open_issues(version, args.repo, run)
    except (LookupError_, ValueError) as exc:
        print(f"release_open_issues: {exc}", file=sys.stderr)
        return 2
    if args.count:
        print(len(issues))
    elif args.json:
        print(json.dumps(issues, indent=2))
    else:
        print(render(issues, version))
    return 0


if __name__ == "__main__":
    sys.exit(main())
