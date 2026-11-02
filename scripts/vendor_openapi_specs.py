#!/usr/bin/env python3
"""Vendor the published UniFi OpenAPI specs that tests/test_spec_conformance.py validates against.

Every tool's outgoing requests are checked against the published contract, so the
contract has to live in the repository at a pinned version. This script fetches each
service's ``openapi.json`` at exactly the version pinned in the spec-drift baseline
(``tests/fixtures/spec_drift/baseline_snapshot.json``), so the vendored contract and the
drift watcher can never disagree about which version is current.

The ``example`` / ``examples`` annotation keywords are removed before writing. They carry
the publisher's sample values (public IP addresses, ASNs, IMEI-shaped numbers), which the
repository's fixture sanitizer rejects, and they play no part in validation. Nothing else
is changed. ``manifest.json`` records the source URL and the sha256 of the bytes as
published, so provenance stays checkable.

Usage (after advancing the baseline with ``scripts/check_spec_drift.py --live
--update-baseline``)::

    python scripts/vendor_openapi_specs.py           # re-vendor every service
    python scripts/vendor_openapi_specs.py --check   # verify files match the baseline pins

Exit codes: 0 = written / consistent, 1 = ``--check`` found a mismatch, 2 = fetch error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from unifi_fabric._spec_drift import (  # noqa: E402
    extract_service_endpoints,
    strip_example_annotations,
)

BASELINE = ROOT / "tests" / "fixtures" / "spec_drift" / "baseline_snapshot.json"
VENDOR_DIR = ROOT / "tests" / "fixtures" / "openapi"
MANIFEST = VENDOR_DIR / "manifest.json"


def vendored_name(service: str, version: str) -> str:
    return f"{service}-{version}.json"


def render(doc: Any) -> str:
    return json.dumps(strip_example_annotations(doc), indent=1, ensure_ascii=False) + "\n"


def pinned_services() -> dict[str, dict[str, Any]]:
    return json.loads(BASELINE.read_text(encoding="utf-8"))["services"]


def vendor() -> int:
    import httpx

    manifest: dict[str, Any] = {}
    VENDOR_DIR.mkdir(parents=True, exist_ok=True)
    with httpx.Client(timeout=None, follow_redirects=True) as client:  # noqa: S113 -- await HTTP completion
        for name, pin in sorted(pinned_services().items()):
            resp = client.get(pin["spec_url"])
            if resp.status_code != 200:
                print(
                    f"ERROR: {name}: HTTP {resp.status_code} for {pin['spec_url']}", file=sys.stderr
                )
                return 2
            doc = resp.json()
            if extract_service_endpoints(doc) != pin["endpoints"]:
                print(
                    f"ERROR: {name} v{pin['version']} as published no longer matches the "
                    "baseline endpoint signatures; run check_spec_drift.py --live first",
                    file=sys.stderr,
                )
                return 2
            text = render(doc)
            fname = vendored_name(name, pin["version"])
            (VENDOR_DIR / fname).write_text(text, encoding="utf-8")
            manifest[name] = {
                "version": pin["version"],
                "source_url": pin["spec_url"],
                "source_sha256": hashlib.sha256(resp.content).hexdigest(),
                "file": fname,
                "file_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                "transform": "example/examples annotation keywords removed",
            }
            print(f"vendored {name} v{pin['version']} -> {fname}")
    for stale in VENDOR_DIR.glob("*.json"):
        if stale.name != MANIFEST.name and stale.name not in {m["file"] for m in manifest.values()}:
            stale.unlink()
            print(f"removed stale {stale.name}")
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return 0


def check() -> list[str]:
    """Problems with the vendored set relative to the baseline pins (empty = consistent)."""
    problems: list[str] = []
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    pins = pinned_services()
    if set(manifest) != set(pins):
        problems.append(f"vendored services {sorted(manifest)} != pinned {sorted(pins)}")
    for name, pin in sorted(pins.items()):
        entry = manifest.get(name)
        if entry is None:
            continue
        if entry["version"] != pin["version"] or entry["source_url"] != pin["spec_url"]:
            problems.append(f"{name}: vendored v{entry['version']} != pinned v{pin['version']}")
            continue
        path = VENDOR_DIR / entry["file"]
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != entry["file_sha256"]:
            problems.append(f"{name}: {entry['file']} sha256 differs from the manifest")
        doc = json.loads(raw)
        if extract_service_endpoints(doc) != pin["endpoints"]:
            problems.append(f"{name}: {entry['file']} endpoints differ from the baseline")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="Verify, do not fetch.")
    args = parser.parse_args(argv)
    if args.check:
        problems = check()
        for p in problems:
            print(f"MISMATCH: {p}", file=sys.stderr)
        return 1 if problems else 0
    return vendor()


if __name__ == "__main__":
    raise SystemExit(main())
