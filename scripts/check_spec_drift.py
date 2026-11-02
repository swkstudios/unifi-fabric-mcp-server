#!/usr/bin/env python3
"""Spec-drift watcher: published UniFi OpenAPI contracts vs. our recorded baseline.

The target console rides the weekly-auto-update EA channel, so the per-app UniFi APIs move
constantly. Ubiquiti publishes machine-readable contracts at
``developer.ui.com/{service}/{version}/openapi.json`` behind a root index at
``developer.ui.com/llms.txt``. This watcher fetches the root index, discovers every
service that currently publishes a spec (catching a *new* family the day it appears),
fetches each spec, and diffs the result against a committed baseline — reporting version
drift, published-vs-console gaps, and NEW / CHANGED / REMOVED endpoints.
CHANGED contracts include request, parameter, response-body and response-header
schemas. BREAKAGE means a request restriction or a widened response contract;
unproven pattern/format replacements and oneOf overlaps are potential breakage.
OpenAPI 3.1 schema reference siblings are conjunctive; 3.0 ignores them.

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
                           build is never committed to the baseline.
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
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from unifi_fabric._spec_drift import (  # noqa: E402  (path set above)
    ROOT_INDEX_URL,
    SUPPORTED_KEYWORDS,
    SpecSnapshot,
    _normalize_schema,
    _strip_examples,
    build_service_spec,
    build_snapshot,
    coverage_gaps,
    diff_snapshot,
    extract_service_endpoints,
    parse_root_index,
    snapshot_from_dict,
    snapshot_to_dict,
    spec_schema_keywords,
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
    published version, regardless of the magnitude the in-memory snapshot carried.
    """
    safe = SpecSnapshot(
        services={
            name: replace(spec, raw_document=None) for name, spec in snapshot.services.items()
        },
        console_versions=synthesize_console_versions(snapshot.console_versions, snapshot.services),
        captured_at=snapshot.captured_at,
    )
    text = json.dumps(snapshot_to_dict(safe), indent=2, ensure_ascii=False) + "\n"
    Path(path).write_text(text, encoding="utf-8")


def _complete_root_index(text: str) -> dict[str, tuple[str, str]]:
    """Validate the published index structure before interpreting missing services.

    The live index has an OpenAPI Specifications section followed by service sections.
    Requiring that boundary catches a truncated response even when some links parse.
    Every advertised spec link must parse, rather than silently losing malformed links.
    """
    lines = text.splitlines()
    try:
        start = lines.index("## OpenAPI Specifications") + 1
        end = next(i for i in range(start, len(lines)) if lines[i].startswith("## "))
    except (ValueError, StopIteration) as exc:
        raise RuntimeError(
            "incomplete root index: missing or unterminated OpenAPI section"
        ) from exc
    section = lines[start:end]
    try:
        root_index = parse_root_index("\n".join(section))
        for line in section:
            if "openapi.json" in line:
                parse_root_index(line)
    except ValueError as exc:
        raise RuntimeError("incomplete root index: malformed OpenAPI section") from exc
    return root_index


def fetch_live_snapshot(
    *,
    root_index_url: str = ROOT_INDEX_URL,
    console_versions: dict[str, str] | None = None,
    captured_at: str | None = None,
    expected_services: set[str] | None = None,
) -> SpecSnapshot:
    """Fetch the live root index and every published OpenAPI spec into a snapshot.

    Every indexed service must fetch and parse successfully. An incomplete observation
    raises before diffing or writing a baseline, so it never masquerades as removal.
    A complete index may omit an expected service: that is removal drift, not a fetch
    error. expected_services is retained for callers but never defines completeness.
    """
    import httpx

    with httpx.Client(timeout=None, follow_redirects=True) as client:  # noqa: S113 -- await HTTP completion
        r_index = client.get(root_index_url)
        if r_index.status_code != 200:
            raise RuntimeError(f"root index fetch failed: HTTP {r_index.status_code}")
        root_index = _complete_root_index(r_index.text)

        openapi_docs: dict[str, object] = {}
        for name, (_version, url) in sorted(root_index.items()):
            try:
                r_spec = client.get(url)
                if r_spec.status_code != 200:
                    raise RuntimeError(f"HTTP {r_spec.status_code}")
                doc = r_spec.json()
                # Validate here, before a malformed document can reach the diff.
                endpoints = extract_service_endpoints(doc)
                if not endpoints:
                    raise ValueError("published spec has no endpoints")
                openapi_docs[name] = _strip_examples(doc)
            except Exception as exc:  # noqa: BLE001  (fail closed on incomplete fetch)
                raise RuntimeError(f"incomplete spec fetch for {name}") from exc

    return build_snapshot(
        root_index,
        openapi_docs,
        console_versions=console_versions,
        captured_at=captured_at,
    )


def _canonical_saved_contracts(contracts: dict[str, object]) -> dict[str, object]:
    """Migrate projected legacy nullable/annotation representations, not semantics."""
    result = deepcopy(contracts)
    for contract in result.values():
        if not isinstance(contract, dict):
            continue

        def schemas(container: dict) -> None:
            for name, schema in container.items():
                container[name] = _normalize_schema(schema, {"openapi": "3.0.0"})

        def parameter(value: dict) -> None:
            if "schema" in value:
                value["schema"] = _normalize_schema(value["schema"], {"openapi": "3.0.0"})
            schemas(value.get("content", {}))

        for value in contract.get("parameters", {}).values():
            parameter(value)
        schemas(contract.get("requestBody", {}).get("schemas", {}))
        for response in contract.get("responses", {}).values():
            for media in list(response):
                if media != "headers":
                    response[media] = _normalize_schema(response[media], {"openapi": "3.0.0"})
            for header in response.get("headers", {}).values():
                parameter(header)
    return result


def hydrate_pinned_baseline(baseline: SpecSnapshot) -> SpecSnapshot:
    """Recover legacy raw evidence from committed, baseline-pinned fixtures.

    Never fetch an old raw document from upstream: a same-version unprojected
    change could otherwise be substituted for its own baseline and appear clean.
    Verify the saved semantic contracts before trusting the historical fixture.
    """
    directory = ROOT / "tests" / "fixtures" / "openapi"
    manifest = json.loads((directory / "manifest.json").read_text())
    services = dict(baseline.services)
    for name, saved in baseline.services.items():
        if saved.raw_document is not None or not saved.endpoint_contracts:
            continue
        pinned = manifest.get(name, {})
        if pinned.get("source_url") != saved.spec_url or pinned.get("version") != saved.version:
            raise ValueError(f"no committed raw baseline evidence for {name}")
        fixture = (directory / pinned["file"]).resolve()
        if not fixture.is_relative_to(directory.resolve()):
            raise ValueError(f"invalid pinned fixture path for {name}")
        hydrated = build_service_spec(
            name, saved.version, saved.spec_url, json.loads(fixture.read_text())
        )
        canonical_saved = _canonical_saved_contracts(saved.endpoint_contracts)
        canonical_fetched = _canonical_saved_contracts(hydrated.endpoint_contracts)
        if canonical_saved != canonical_fetched:
            raise ValueError(
                f"pinned baseline contract changed for {name}; raw evidence unavailable"
            )
        services[name] = hydrated
    return replace(baseline, services=services)


def fetch_pinned_schema_keywords(baseline: SpecSnapshot) -> set[str]:
    """Enumerate all schemas in every document pinned by the baseline."""
    import httpx

    keywords: set[str] = set()
    with httpx.Client(timeout=None, follow_redirects=True) as client:  # noqa: S113 -- await HTTP completion
        for service in baseline.services.values():
            response = client.get(service.spec_url)
            response.raise_for_status()
            document = response.json()
            if not extract_service_endpoints(document):
                raise ValueError(f"pinned spec has no endpoints: {service.name}")
            keywords.update(spec_schema_keywords(document))
    return keywords


def _emit(baseline: SpecSnapshot) -> int:
    print(f"baseline captured_at: {baseline.captured_at}")
    print(f"known published services: {len(baseline.services)}")
    for name in sorted(baseline.services):
        spec = baseline.services[name]
        console = baseline.console_versions.get(name)
        gap = ""
        if console and console != spec.version:
            gap = f"  [CONSOLE_GAP: runs v{console}]"
        print(
            f"  {name}: v{spec.version} (llms.txt {spec.version}; "
            f"info.version {spec.info_version}; "
            f"{len(spec.endpoints)} endpoints){gap}"
        )
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
    parser.add_argument(
        "--check-supported-keywords",
        action="store_true",
        help="Regenerate the schema keyword inventory from every baseline-pinned raw spec.",
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

    if args.check_supported_keywords:
        try:
            keywords = fetch_pinned_schema_keywords(baseline)
        except Exception as exc:  # noqa: BLE001 -- fail closed on incomplete inventory
            print(f"ERROR: pinned keyword inventory failed: {exc}", file=sys.stderr)
            return 2
        print("SUPPORTED_KEYWORDS: " + ", ".join(sorted(keywords)))
        if keywords != SUPPORTED_KEYWORDS:
            print(f"unsupported: {sorted(keywords - SUPPORTED_KEYWORDS)}")
            print(f"no longer pinned: {sorted(SUPPORTED_KEYWORDS - keywords)}")
            return 1
        return 0

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
                expected_services=set(baseline.services),
            )
        except Exception as exc:  # noqa: BLE001  (surface a clean CLI error)
            print(f"ERROR: could not fetch live specs: {exc}", file=sys.stderr)
            return 2

    if args.live:
        try:
            baseline = hydrate_pinned_baseline(baseline)
        except Exception as exc:  # noqa: BLE001 (fail closed when raw baseline cannot be verified)
            print(f"ERROR: could not recover pinned baseline evidence: {exc}", file=sys.stderr)
            return 2
    report = diff_snapshot(baseline, current)
    print(report.summary())

    if args.update_baseline:
        removed = set(baseline.services) - set(current.services)
        if removed:
            print(
                "ERROR: refusing baseline update after service removal: "
                + ", ".join(sorted(removed)),
                file=sys.stderr,
            )
            return 1
        # Carry any console observations the current snapshot lacks forward from the
        # baseline. write_snapshot_file then NORMALISES every console version (keep if it
        # equals published, else replace with the synthetic), so no real, distinct estate
        # build is persisted regardless of what current/baseline carried.
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
