#!/usr/bin/env python3
"""Fail closed when an applicable CI job did not report success."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping

CORE_JOBS = frozenset(
    {
        "classify",
        "lint",
        "typecheck",
        "docs",
        "gitleaks",
        "fixtures-sanitization",
        "version-consistency",
        "docker-build",
    }
)
PR_ONLY_JOBS = frozenset({"lane-gate", "changelog-check", "divergence-gate"})
FULL_JOBS = frozenset({"test", "test-locked", "scrub-oracle"})
ALLOWED_EVENTS = frozenset({"pull_request", "push", "merge_group", "workflow_dispatch"})


def expected_jobs(event: str, tier: str) -> frozenset[str]:
    if event not in ALLOWED_EVENTS:
        raise ValueError(f"unknown event {event!r}")
    expected = set(CORE_JOBS)
    if event == "pull_request":
        expected.update(PR_ONLY_JOBS)
    if tier == "targeted":
        expected.add("test-selected")
    elif tier == "full":
        expected.update(FULL_JOBS)
    elif tier != "fast":
        raise ValueError(f"unknown tier {tier!r}")
    return frozenset(expected)


def validate(results: Mapping[str, Mapping[str, object]], event: str, tier: str) -> list[str]:
    expected = expected_jobs(event, tier)
    failures = [
        f"{job}={results.get(job, {}).get('result')!r}, expected success"
        for job in sorted(expected)
        if results.get(job, {}).get("result") != "success"
    ]
    failures.extend(
        f"{job}={detail.get('result')!r}, expected skipped"
        for job, detail in sorted(results.items())
        if job not in expected and detail.get("result") != "skipped"
    )
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event", required=True)
    parser.add_argument("--tier", required=True)
    args = parser.parse_args(argv)
    try:
        results = json.load(sys.stdin)
        failures = validate(results, args.event, args.tier)
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"ci-required: {exc}", file=sys.stderr)
        return 1
    if failures:
        print("ci-required: " + "; ".join(failures), file=sys.stderr)
        return 1
    print(f"ci-required: tier={args.tier}; all applicable jobs succeeded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
