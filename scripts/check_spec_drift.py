#!/usr/bin/env python3
"""Spec-drift watcher: published UniFi OpenAPI contracts vs. our recorded baseline (issue #199).

The target console rides the weekly-auto-update EA channel, so the per-app UniFi APIs move
constantly. Ubiquiti publishes machine-readable contracts at
``developer.ui.com/{service}/{version}/openapi.json`` behind a root index at
``developer.ui.com/llms.txt``. This watcher fetches the root index, discovers every
service that currently publishes a spec (catching a *new* family the day it appears),
fetches each spec, and diffs the result against a committed baseline — reporting version
drift, published-vs-console gaps, and NEW / CHANGED / REMOVED endpoints.

Modes (mirroring the ``check_catalog_regression.py`` precedent's ``--snapshot`` / ``--live``
split):

  * ``--snapshot FILE``    Hermetic. Diff a previously captured *current* snapshot bundle
                           (``snapshot_to_dict`` shape) against the committed baseline. No
                           network, CI-safe. This is what the pytest suite exercises.
  * ``--live``             Tier-2. Fetch the live root index + every published OpenAPI spec
                           from ``developer.ui.com`` and diff against the baseline.
  * ``--update-baseline``  Advance the committed baseline to the freshly fetched (``--live``)
                           or provided (``--snapshot FILE``) state, after a run is reviewed.
                           Console versions are normalised on write: a value equal to the
                           published version is kept, any distinct value is replaced by a
                           synthetic derived from the published version, so a real estate
                           build is never committed to the baseline (PR #253 review).
  * (default / ``--emit``) Print the baseline: known services, versions, and per-service
                           unimplemented published endpoints (coverage gaps). Exit 0.

Exit codes: 0 = clean (or emit / update), 1 = drift detected, 2 = usage / fetch error.

No credentials are used: the developer.ui.com specs are public. The watcher never touches
the estate; the published-vs-console gap is read from the committed console-version
observation in the baseline (refreshed estate-side, out of band).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from unifi_fabric._spec_drift import (  # noqa: E402  (path set above)
    ROOT_INDEX_URL,
    SpecSnapshot,
    build_snapshot,
    coverage_gaps,
    diff_snapshot,
    parse_root_index,
    snapshot_from_dict,
    snapshot_to_dict,
    synthesize_console_versions,
)

DEFAULT_BASELINE = ROOT / "tests" / "fixtures" / "spec_drift" / "baseline_snapshot.json"


def load_snapshot_file(path: str | Path) -> SpecSnapshot:
    """Load a snapshot bundle (baseline or captured current) from a JSON file."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return snapshot_from_dict(payload)


def write_snapshot_file(path: str | Path, snapshot: SpecSnapshot) -> None:
    """Write a snapshot bundle to a JSON file (pretty, stable key order, trailing newline).

    Console versions are NORMALISED at this single write boundary — common to every path
    that persists a baseline — so a real, distinct estate build can never be committed into
    the baseline fixture (which reaches the public repository). Each console version is
    passed through :func:`synthesize_console_versions`: a value equal to its service's
    published version is kept, any distinct value is re-derived deterministically from the
    published version, regardless of the magnitude the in-memory snapshot carried. See PR
    #253 review.
    """
    safe = SpecSnapshot(
        services=snapshot.services,
        console_versions=synthesize_console_versions(snapshot.console_versions, snapshot.services),
        captured_at=snapshot.captured_at,
    )
    text = json.dumps(snapshot_to_dict(safe), indent=2, ensure_ascii=False) + "\n"
    Path(path).write_text(text, encoding="utf-8")


def fetch_live_snapshot(
    *,
    root_index_url: str = ROOT_INDEX_URL,
    console_versions: dict[str, str] | None = None,
    captured_at: str | None = None,
    timeout: float = 30.0,
) -> SpecSnapshot:
    """Fetch the live root index and every published OpenAPI spec into a snapshot.

    A per-service spec that fails to fetch/parse is skipped (never recorded as empty), so a
    transient error on one family does not masquerade as "all its endpoints removed".
    """
    import httpx

    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        r_index = client.get(root_index_url)
        if r_index.status_code != 200:
            raise RuntimeError(f"root index fetch failed: HTTP {r_index.status_code}")
        root_index = parse_root_index(r_index.text)

        openapi_docs: dict[str, object] = {}
        for name, (_version, url) in sorted(root_index.items()):
            try:
                r_spec = client.get(url)
                if r_spec.status_code != 200:
                    print(
                        f"WARNING: {name} spec fetch failed: HTTP {r_spec.status_code} "
                        f"({url}) — skipping this service this run",
                        file=sys.stderr,
                    )
                    continue
                openapi_docs[name] = r_spec.json()
            except Exception as exc:  # noqa: BLE001  (surface, skip, continue)
                print(f"WARNING: {name} spec unreadable: {exc} — skipping", file=sys.stderr)

    return build_snapshot(
        root_index,
        openapi_docs,
        console_versions=console_versions,
        captured_at=captured_at,
    )


def _emit(baseline: SpecSnapshot) -> int:
    print(f"baseline captured_at: {baseline.captured_at}")
    print(f"known published services: {len(baseline.services)}")
    for name in sorted(baseline.services):
        spec = baseline.services[name]
        console = baseline.console_versions.get(name)
        gap = ""
        if console and console != spec.version:
            gap = f"  [CONSOLE_GAP: runs v{console}]"
        print(f"  {name}: v{spec.version} ({len(spec.endpoints)} endpoints){gap}")
    gaps = coverage_gaps(baseline)
    for name, missing in sorted(gaps.items()):
        if missing:
            print(f"  coverage gap [{name}]: {len(missing)} published endpoint(s) unimplemented")
            for ep in missing:
                print(f"      {ep}")
        else:
            count = len(baseline.services[name].endpoints)
            print(f"  coverage [{name}]: all {count} published endpoints implemented")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--baseline",
        default=str(DEFAULT_BASELINE),
        help=f"Committed baseline snapshot JSON (default: {DEFAULT_BASELINE}).",
    )
    src = parser.add_mutually_exclusive_group()
    src.add_argument("--snapshot", help="Diff a captured current snapshot bundle (hermetic).")
    src.add_argument("--live", action="store_true", help="Fetch live specs from developer.ui.com.")
    parser.add_argument(
        "--root-index-url",
        default=ROOT_INDEX_URL,
        help=f"Root index URL for --live (default: {ROOT_INDEX_URL}).",
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Write the fetched/provided current state to the baseline (console versions "
        "normalised to synthetic on write).",
    )
    parser.add_argument(
        "--emit",
        action="store_true",
        help="Print the baseline (services, versions, coverage gaps) and exit 0.",
    )
    args = parser.parse_args(argv)

    try:
        baseline = load_snapshot_file(args.baseline)
    except FileNotFoundError:
        print(f"ERROR: baseline not found: {args.baseline}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"ERROR: baseline is malformed: {exc}", file=sys.stderr)
        return 2

    if args.emit or (not args.snapshot and not args.live):
        return _emit(baseline)

    # Preserve the committed console-version observations across a live fetch (the public
    # spec fetch does not touch the estate).
    if args.snapshot:
        try:
            current = load_snapshot_file(args.snapshot)
        except (FileNotFoundError, ValueError) as exc:
            print(f"ERROR: could not load snapshot {args.snapshot}: {exc}", file=sys.stderr)
            return 2
    else:  # --live
        try:
            current = fetch_live_snapshot(
                root_index_url=args.root_index_url,
                console_versions=dict(baseline.console_versions),
            )
        except Exception as exc:  # noqa: BLE001  (surface a clean CLI error)
            print(f"ERROR: could not fetch live specs: {exc}", file=sys.stderr)
            return 2

    report = diff_snapshot(baseline, current)
    print(report.summary())

    if args.update_baseline:
        # Carry any console observations the current snapshot lacks forward from the
        # baseline. write_snapshot_file then NORMALISES every console version (keep if it
        # equals published, else replace with the synthetic), so no real, distinct estate
        # build is persisted regardless of what current/baseline carried (PR #253 review).
        merged_console = dict(baseline.console_versions)
        merged_console.update(current.console_versions)
        merged = SpecSnapshot(
            services=current.services,
            console_versions=merged_console,
            captured_at=current.captured_at,
        )
        write_snapshot_file(args.baseline, merged)
        print(f"baseline updated: {args.baseline}")
        return 0

    return 0 if report.is_clean else 1


if __name__ == "__main__":
    raise SystemExit(main())
