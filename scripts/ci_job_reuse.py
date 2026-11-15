#!/usr/bin/env python3
"""Fingerprint a CI job's inputs so a pull request can reuse an unchanged job's result.

issue 919 item 4 (reuse results whose inputs did not change). A job is reusable when everything
it reads is a tracked file under the paths in ``INPUTS`` plus its own definition in
``ci.yml``. The fingerprint is a SHA-256 over

* the schema tag and the job name,
* the text of the job's block in ``ci.yml`` and of the workflow's top-level ``env`` (a
  changed step or action pin is a changed input),
* the git object id and path of every tracked file under the job's input paths at the
  checked-out revision (``git ls-tree -r``), so the same tree gives the same fingerprint
  and any change under an input path gives another one.

``ci.yml`` stores one marker per fingerprint in the Actions cache after a successful push run
on the default branch (a pull request never writes a cache) and looks it up only on a pull
request. Pushes, dispatches and the merge train never look up: they always run the job for
real, so every reusable result a pull request finds was produced by a full run of that job,
and a new base image or a drifting runner shows up on the next ``dev`` push. A missing
marker, an unreadable fingerprint or an error is a miss: the job runs. Nothing here reads,
caps or steers a runner.

    ci_job_reuse.py fingerprint JOB [--github-output FILE]
    ci_job_reuse.py record JOB --fingerprint FP --out FILE
    ci_job_reuse.py note JOB --marker FILE [--summary FILE]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = Path(".github/workflows/ci.yml")
SCHEMA = "ci-job-reuse-v1"

#: Everything the container image check reads. The Dockerfile's COPY sources are
#: ``requirements-runtime.lock``, ``requirements-build.lock``, ``pyproject.toml``,
#: ``README.md``, ``src/``, ``scripts/check_ca_bundle.py``, ``LICENSE`` and ``NOTICE``
#: (tests/test_ci_job_reuse.py reads the Dockerfile and fails if a COPY source is missing
#: here); the base image is pinned by digest in the Dockerfile itself. The boot and proxy
#: tests read ``scripts/`` and ``tests/proxy_container/``.
_IMAGE_INPUTS: tuple[str, ...] = (
    "Dockerfile",
    ".dockerignore",
    "pyproject.toml",
    "README.md",
    "LICENSE",
    "NOTICE",
    "requirements-runtime.lock",
    "requirements-build.lock",
    "requirements.lock",
    "src",
    "scripts",
    "tests/proxy_container",
    ".github/actions",
)

#: job name in ci.yml -> the tracked paths (files or directories) the job reads.
INPUTS: dict[str, tuple[str, ...]] = {
    "docker-build-amd64": _IMAGE_INPUTS,
    "docker-build-arm64": _IMAGE_INPUTS,
}


class ReuseError(Exception):
    """The fingerprint could not be computed; the caller treats it as a miss."""


def _git(root: Path, *args: str) -> bytes:
    try:
        return subprocess.run(  # noqa: S603 - fixed argv
            ["git", "-C", str(root), *args],  # noqa: S607
            capture_output=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ReuseError(f"git {' '.join(args)}: {exc}") from exc


def tracked_inputs(root: Path, job: str, rev: str = "HEAD") -> list[bytes]:
    """``mode type oid<TAB>path`` lines of every tracked input file of ``job`` at ``rev``."""
    if job not in INPUTS:
        raise ReuseError(f"{job!r} has no declared inputs")
    out = _git(root, "ls-tree", "-r", "-z", "--full-tree", rev, "--", *INPUTS[job])
    lines = sorted(entry for entry in out.split(b"\0") if entry)
    if not lines:
        raise ReuseError(f"no tracked input file for {job!r} at {rev}")
    return lines


def job_definition(root: Path, job: str) -> str:
    """The text of the job's block and of the top-level ``env`` block of ``ci.yml``.

    Plain text, not parsed YAML, so the script runs on a bare hosted runner (no PyYAML) and
    any edit of a step, an action pin or a comment-free line changes the fingerprint.
    """
    text = (root / WORKFLOW).read_text(encoding="utf-8")
    block = re.search(rf"^  {re.escape(job)}:\n(?:(?!  [A-Za-z0-9_-]+:\n)[^\n]*\n?)*", text, re.M)
    env = re.search(r"^env:\n(?:[ #][^\n]*\n|\n)*", text, re.M)
    if block is None or env is None:
        raise ReuseError(f"{job!r} or the top-level env is not in {WORKFLOW}")
    return env.group(0) + "\0" + block.group(0)


def fingerprint(root: Path, job: str, rev: str = "HEAD") -> str:
    digest = hashlib.sha256()
    digest.update(f"{SCHEMA}\0{job}\0".encode())
    digest.update(job_definition(root, job).encode())
    for line in tracked_inputs(root, job, rev):
        digest.update(b"\0" + line)
    return digest.hexdigest()


def cache_key(job: str, fp: str) -> str:
    return f"ci-reuse-v1-{job}-{fp}"


def _write_output(path: str, **values: str) -> None:
    with open(path, "a", encoding="utf-8") as handle:
        for name, value in values.items():
            handle.write(f"{name}={value}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    fp_cmd = sub.add_parser("fingerprint")
    fp_cmd.add_argument("job")
    fp_cmd.add_argument("--github-output", default="")
    rec = sub.add_parser("record")
    rec.add_argument("job")
    rec.add_argument("--fingerprint", required=True)
    rec.add_argument("--out", required=True)
    note = sub.add_parser("note")
    note.add_argument("job")
    note.add_argument("--marker", required=True)
    note.add_argument("--summary", default="")
    args = parser.parse_args(argv)
    if args.command == "fingerprint":
        try:
            fp = fingerprint(ROOT, args.job)
        except ReuseError as exc:
            # A miss, not a failure: the job runs. An empty fingerprint never matches a marker.
            print(f"ci_job_reuse: {exc}; the job will run", file=sys.stderr)
            fp = "unavailable-" + os.environ.get("GITHUB_RUN_ID", "local")
        print(fp)
        if args.github_output:
            _write_output(args.github_output, fingerprint=fp, key=cache_key(args.job, fp))
        return 0
    if args.command == "record":
        marker = {
            "job": args.job,
            "fingerprint": args.fingerprint,
            "run_id": os.environ.get("GITHUB_RUN_ID", ""),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
            "head_sha": os.environ.get("GITHUB_SHA", ""),
            "event": os.environ.get("GITHUB_EVENT_NAME", ""),
            "ref": os.environ.get("GITHUB_REF", ""),
        }
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(marker, sort_keys=True) + "\n", encoding="utf-8")
        return 0
    marker = json.loads(Path(args.marker).read_text(encoding="utf-8"))
    line = (
        f"{args.job}: reused the result of run {marker.get('run_id')} "
        f"({marker.get('event')} on {marker.get('ref')}, "
        f"commit {str(marker.get('head_sha'))[:8]}): "
        f"its inputs are unchanged (fingerprint {str(marker.get('fingerprint'))[:12]})"
    )
    print(line)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as handle:
            handle.write(f"### Result reuse\n\n{line}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
