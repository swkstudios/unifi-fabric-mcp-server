#!/usr/bin/env python3
"""Re-run the pull request's CI after a label that changes what CI does.

``ci.yml`` runs on ``opened``, ``synchronize`` and ``reopened`` only. A ``labeled`` or
``unlabeled`` trigger started a second run of the same commit within a second of the first
whenever a pull request was opened with a label: the older run was cancelled by the
concurrency group, and its always-on aggregate jobs (``docker-build``, ``ci-required``)
reported FAILURE on the commit, so a green pull request looked red. Only three labels change
what CI does (``scripts/ci_classify_changes.py`` reads ``full-ci`` and ``skip-heavy`` live;
``changelog-check`` reads ``skip-changelog`` live), so ``ci-relabel.yml`` calls this script
for those three and ignores every other label.

The script finds the newest ``ci.yml`` pull request run of the head commit and re-runs it
(the labels are read live, so the re-run sees the new set). A run still in progress is
force-cancelled first (force-cancel also stops its always-on aggregates, so the cancelled
attempt leaves no failing check behind) and the script waits for it to complete: there is
no deadline, the same unbounded-wait rule as the rest of the workflows. A run that does not
exist yet is left alone: it has not read the labels yet and will read them when it does.

    python3 scripts/ci_relabel.py --repo OWNER/REPO --head SHA --label NAME
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any

#: The labels CI reads. ci_classify_changes.LABEL_FULL / LABEL_SKIP_HEAVY and the
#: changelog-check job; a test pins this set to those readers.
CI_LABELS = frozenset({"full-ci", "skip-heavy", "skip-changelog"})
WORKFLOW = "ci.yml"
POLL_SECONDS = 5
#: Polls for a run that is not listed yet (the opened run is created with the label event).
LOOKUP_ATTEMPTS = 6


def call(method: str, path: str) -> Any:
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        raise SystemExit("ci_relabel: no GH_TOKEN")
    base = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    request = urllib.request.Request(
        f"{base}{path}",
        method=method,
        data=b"" if method == "POST" else None,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request) as response:  # noqa: S310 - fixed https API
            body = response.read()
    except urllib.error.HTTPError as exc:
        if method == "POST" and exc.code == 403:
            # A pull request from a fork gets a read-only token: nothing to re-run here.
            print(f"ci_relabel: {method} {path}: HTTP 403, this token cannot re-run: nothing done")
            raise SystemExit(0) from exc
        raise SystemExit(f"ci_relabel: {method} {path}: HTTP {exc.code}") from exc
    return json.loads(body) if body else {}


def current_head(repo: str, number: int) -> str:
    """The head commit of the pull request right now (the event payload is a snapshot)."""
    return str(call("GET", f"/repos/{repo}/pulls/{number}")["head"]["sha"])


def newest_run(repo: str, head: str) -> dict[str, Any] | None:
    listing = call(
        "GET",
        f"/repos/{repo}/actions/workflows/{WORKFLOW}/runs?head_sha={head}&event=pull_request&per_page=20",
    )
    runs = listing.get("workflow_runs", [])
    return max(runs, key=lambda run: run["created_at"]) if runs else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", required=True)
    parser.add_argument("--head", required=True, help="the pull request head commit")
    parser.add_argument("--label", required=True, help="the label that was added or removed")
    parser.add_argument("--pr", type=int, required=True, help="the pull request number")
    args = parser.parse_args(argv)
    if args.label not in CI_LABELS:
        print(f"label {args.label!r} does not change CI: nothing to re-run")
        return 0
    if current_head(args.repo, args.pr) != args.head:
        print(f"the pull request moved past {args.head[:8]}: the newer push has its own run")
        return 0
    run = None
    for _ in range(LOOKUP_ATTEMPTS):
        run = newest_run(args.repo, args.head)
        if run is not None:
            break
        time.sleep(POLL_SECONDS)
    if run is None:
        print(f"no {WORKFLOW} run for {args.head[:8]} yet: it reads the labels when it starts")
        return 0
    run_id = run["id"]
    if run["status"] != "completed":
        print(f"run {run_id} is {run['status']}: force-cancel, then re-run with the new labels")
        call("POST", f"/repos/{args.repo}/actions/runs/{run_id}/force-cancel")
        while call("GET", f"/repos/{args.repo}/actions/runs/{run_id}")["status"] != "completed":
            time.sleep(POLL_SECONDS)
    # A push during the cancel wait started a run of the newer commit; re-running the old
    # commit would be redundant and, in the shared group, would cancel that run.
    if current_head(args.repo, args.pr) != args.head:
        print(f"the pull request moved past {args.head[:8]} while waiting: not re-running it")
        return 0
    call("POST", f"/repos/{args.repo}/actions/runs/{run_id}/rerun")
    print(f"re-ran run {run_id} for label {args.label!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
