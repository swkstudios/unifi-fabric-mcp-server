#!/usr/bin/env python3
"""Per-job wall clock and queue time of one workflow run, as a Markdown table.

issue 919 item 7. The data is the jobs API of a run (``created_at`` is when the job was queued,
``started_at`` when a runner took it, ``completed_at`` when it finished), so the report
needs no extra instrumentation and works on any past run:

    python3 scripts/ci_timing_report.py --run 42955534619 [--attempt N] [--repo OWNER/REPO]

``ci.yml`` runs it as the last step of ``ci-required`` and appends it to the run summary
(``--summary "$GITHUB_STEP_SUMMARY"``), so every run states where its time went. The report
only reads; it never fails a run (a missing token or an API error prints a note and exits 0
with ``--summary``, because a timing table must not turn a green run red).

Matrix jobs (``test-shard 1`` .. ``test-shard 20``) are folded into one row with the count,
the median and the maximum, because the slowest shard is the one that gates the aggregate.
Queue time is the runner wait: a job that waits long for a slot costs wall clock without
using a runner.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import Any

DEFAULT_REPO = "swkstudios/unifi-fabric-mcp-server"
_MATRIX_SUFFIX = re.compile(r"\s+(\d+|\$\{\{[^}]*\}\})$")


class ReportError(Exception):
    """The run or its jobs could not be read."""


def _parse(stamp: str | None) -> datetime | None:
    if not stamp:
        return None
    return datetime.fromisoformat(stamp.replace("Z", "+00:00")).astimezone(UTC)


def _seconds(start: datetime | None, end: datetime | None) -> float | None:
    if start is None or end is None:
        return None
    return max(0.0, (end - start).total_seconds())


def api(path: str) -> Any:
    """GET one API path. A token in the environment is used directly; otherwise ``gh api``."""
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        base = os.environ.get("GITHUB_API_URL", "https://api.github.com")
        request = urllib.request.Request(
            f"{base}{path}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(request) as response:  # noqa: S310 - fixed https API
                return json.load(response)
        except (urllib.error.URLError, json.JSONDecodeError) as exc:
            raise ReportError(f"cannot read {path}: {exc}") from exc
    try:
        out = subprocess.run(  # noqa: S603 - fixed argv, the path is an API path
            ["gh", "api", path],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(out.stdout)
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        raise ReportError(f"cannot read {path} (no GH_TOKEN and gh api failed): {exc}") from exc


def fetch(
    repo: str, run_id: int, attempt: int | None
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    run = api(f"/repos/{repo}/actions/runs/{run_id}")
    jobs: list[dict[str, Any]] = []
    page = 1
    while True:
        if attempt is None:
            path = f"/repos/{repo}/actions/runs/{run_id}/jobs?per_page=100&page={page}"
        else:
            path = (
                f"/repos/{repo}/actions/runs/{run_id}/attempts/{attempt}"
                f"/jobs?per_page=100&page={page}"
            )
        chunk = api(path).get("jobs", [])
        jobs.extend(chunk)
        if len(chunk) < 100:
            return run, jobs
        page += 1


def group_name(name: str) -> str:
    return _MATRIX_SUFFIX.sub("", name)


def rows(jobs: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """One row per job name; matrix members fold into one row (count, median, maximum)."""
    grouped: dict[str, list[Mapping[str, Any]]] = {}
    for job in jobs:
        grouped.setdefault(group_name(str(job["name"])), []).append(job)
    out = []
    for name, members in grouped.items():
        queues = []
        walls = []
        for job in members:
            created = _parse(job.get("created_at"))
            started = _parse(job.get("started_at"))
            completed = _parse(job.get("completed_at"))
            queue = _seconds(created, started)
            wall = _seconds(started, completed) if job.get("status") == "completed" else None
            if queue is not None:
                queues.append(queue)
            if wall is not None:
                walls.append(wall)
        results = sorted({str(m.get("conclusion") or m.get("status")) for m in members})
        ends = [_parse(m.get("completed_at")) for m in members if m.get("completed_at")]
        ran = [w for w in walls if w > 0]
        out.append(
            {
                "job": name,
                "n": len(members),
                "result": "/".join(results),
                "queue_med": statistics.median(queues) if queues else None,
                "queue_max": max(queues) if queues else None,
                "wall_med": statistics.median(ran) if ran else None,
                "wall_max": max(ran) if ran else None,
                "wall_sum": sum(ran),
                "ended": max(ends) if ends else None,
            }
        )
    return out


def _fmt(seconds: float | None) -> str:
    if seconds is None:
        return "-"
    seconds = int(round(seconds))
    if seconds >= 3600:
        return f"{seconds // 3600}h{seconds % 3600 // 60:02d}m{seconds % 60:02d}s"
    if seconds >= 60:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds}s"


def render(run: Mapping[str, Any], jobs: list[Mapping[str, Any]]) -> str:
    table = rows(jobs)
    created = _parse(run.get("created_at"))
    started = _parse(run.get("run_started_at")) or created
    ends = [r["ended"] for r in table if r["ended"] is not None]
    last = max(ends) if ends else None
    wall = _seconds(started, last)
    last_job = next((r for r in table if r["ended"] == last), None) if last else None
    cpu = sum(r["wall_sum"] for r in table)
    queue_total = sum((r["queue_med"] or 0) * r["n"] for r in table)
    lines = [
        f"### CI timing report: run {run.get('id')} (attempt {run.get('run_attempt', 1)})",
        "",
        f"- event `{run.get('event')}`, ref `{run.get('head_branch')}`, "
        f"head `{str(run.get('head_sha', ''))[:8]}`, "
        f"conclusion `{run.get('conclusion') or run.get('status')}`",
        f"- wall clock, first job queued to last job done: **{_fmt(wall)}**",
        f"- last job to finish: `{last_job['job'] if last_job else '-'}`",
        f"- job time on runners (sum of started to completed): {_fmt(cpu)}",
        f"- queue time (sum over jobs of created to started): {_fmt(queue_total)}",
        "",
        "| job | n | result | queue (median / max) | wall (median / max) | finished at |",
        "|---|---:|---|---|---|---|",
    ]
    for r in sorted(table, key=lambda row: -(row["wall_max"] or 0)):
        ended = r["ended"].strftime("%H:%M:%S") if r["ended"] else "running"
        lines.append(
            f"| {r['job']} | {r['n']} | {r['result']} | "
            f"{_fmt(r['queue_med'])} / {_fmt(r['queue_max'])} | "
            f"{_fmt(r['wall_med'])} / {_fmt(r['wall_max'])} | {ended} |"
        )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run", type=int, required=True, help="workflow run id")
    parser.add_argument("--attempt", type=int, default=None, help="run attempt (default: latest)")
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", DEFAULT_REPO))
    parser.add_argument("--summary", default="", help="append the report to this file")
    args = parser.parse_args(argv)
    try:
        run, jobs = fetch(args.repo, args.run, args.attempt)
        report = render(run, jobs)
    except ReportError as exc:
        note = f"CI timing report unavailable: {exc}"
        print(note, file=sys.stderr)
        if args.summary:
            with open(args.summary, "a", encoding="utf-8") as handle:
                handle.write(f"### CI timing report\n\n{note}\n")
            return 0
        return 1
    print(report)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as handle:
            handle.write(report + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
