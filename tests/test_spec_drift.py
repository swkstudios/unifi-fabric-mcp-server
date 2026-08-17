"""Spec-drift audit tests (issue #199).

Two layers, mirroring ``test_catalog_audit.py`` (PR #195):

1. **Hermetic (always in CI).** Unit tests for the pure logic in
   ``unifi_fabric._spec_drift`` — root-index parsing, endpoint signing, snapshot
   round-trip, and the NEW / CHANGED / REMOVED / VERSION_DRIFT / CONSOLE_GAP /
   NEW_SERVICE diff classes — plus guards against the committed baseline snapshot (the
   real published state captured 2026-08-15): it parses, round-trips, and diffs clean
   against itself, and a synthetically mutated copy is caught in every drift class.

2. **Live (Tier-2, ``@pytest.mark.integration``, skipped in CI).** Fetch the real
   developer.ui.com root index + specs and diff against the committed baseline. Gated on
   ``SPEC_DRIFT_LIVE`` so it never runs in CI. Reuses the CLI's single fetch
   implementation so the tool and the test exercise one code path.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from unifi_fabric._spec_drift import (
    ROOT_INDEX_URL,
    SPEC_COVERAGE,
    EndpointFinding,
    ServiceSpec,
    SpecDriftReport,
    SpecSnapshot,
    build_service_spec,
    build_snapshot,
    coverage_gaps,
    diff_service,
    diff_snapshot,
    endpoint_signature,
    extract_service_endpoints,
    known_service_slugs,
    parse_root_index,
    snapshot_from_dict,
    snapshot_to_dict,
    synthesize_console_versions,
    synthetic_console_version,
)

# Make scripts/ importable so the live test reuses the CLI's fetch implementation.
_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

_BASELINE_PATH = (
    Path(__file__).resolve().parents[1]
    / "tests"
    / "fixtures"
    / "spec_drift"
    / "baseline_snapshot.json"
)


def _load_baseline() -> SpecSnapshot:
    return snapshot_from_dict(json.loads(_BASELINE_PATH.read_text(encoding="utf-8")))


# ---------------------------------------------------------------------------
# parse_root_index
# ---------------------------------------------------------------------------

_SAMPLE_INDEX = """
# Ubiquiti Developer Documentation

## OpenAPI Specifications
- [Network OpenAPI Spec](https://developer.ui.com/network/v10.4.57/openapi.json): x
- [Protect OpenAPI Spec](https://developer.ui.com/protect/v7.2.105/openapi.json): x
- [InnerSpace OpenAPI Spec](https://developer.ui.com/innerspace/v1.3.23/openapi.json): x
- [Site Manager OpenAPI Spec](https://developer.ui.com/site-manager/v1.0.0/openapi.json): x
"""


def test_parse_root_index_extracts_service_version_url() -> None:
    idx = parse_root_index(_SAMPLE_INDEX)
    assert idx["network"] == ("10.4.57", "https://developer.ui.com/network/v10.4.57/openapi.json")
    assert idx["innerspace"][0] == "1.3.23"
    assert set(idx) == {"network", "protect", "innerspace", "site-manager"}


def test_parse_root_index_ignores_non_openapi_links() -> None:
    idx = parse_root_index(
        "- [Network API v10.4.57](https://developer.ui.com/network/v10.4.57/gettingstarted): x\n"
        "- [Network OpenAPI Spec](https://developer.ui.com/network/v10.4.57/openapi.json): x\n"
        "- [Network Postman](https://developer.ui.com/network/v10.4.57/postman.json): x\n"
    )
    assert set(idx) == {"network"}


def test_parse_root_index_rejects_indexless_text() -> None:
    with pytest.raises(ValueError, match="no OpenAPI spec links"):
        parse_root_index("just some prose with no links")


# ---------------------------------------------------------------------------
# endpoint_signature / extract_service_endpoints
# ---------------------------------------------------------------------------


def test_endpoint_signature_is_stable_and_ignores_prose() -> None:
    op_a = {"operationId": "getX", "summary": "Get X", "responses": {"200": {}}}
    op_b = {
        "operationId": "getX",
        "summary": "COMPLETELY different prose",
        "responses": {"200": {}},
    }
    assert endpoint_signature(op_a) == endpoint_signature(op_b)


def test_endpoint_signature_moves_on_semantic_change() -> None:
    base = {"operationId": "getX", "responses": {"200": {}}}
    add_param = {
        "operationId": "getX",
        "parameters": [{"name": "q", "in": "query", "required": True}],
        "responses": {"200": {}},
    }
    add_body = {"operationId": "getX", "requestBody": {"required": True}, "responses": {"200": {}}}
    add_code = {"operationId": "getX", "responses": {"200": {}, "404": {}}}
    sigs = {
        endpoint_signature(base),
        endpoint_signature(add_param),
        endpoint_signature(add_body),
        endpoint_signature(add_code),
    }
    assert len(sigs) == 4


def test_endpoint_signature_handles_non_dict_operation() -> None:
    # A malformed operation still signs deterministically rather than raising.
    assert endpoint_signature("weird") == endpoint_signature("weird")
    assert endpoint_signature("weird") != endpoint_signature("other")


def test_extract_service_endpoints_takes_only_http_methods() -> None:
    doc = {
        "paths": {
            "/v1/project": {
                "get": {"operationId": "getProject", "responses": {"200": {}}},
                "parameters": [{"name": "mode"}],  # path-level sibling, not an operation
                "x-extra": {"foo": 1},
            },
            "/v1/x": {"post": {"operationId": "postX", "responses": {"201": {}}}},
            "/v1/bogus": "not-an-operations-object",  # non-Mapping path value is skipped
        }
    }
    eps = extract_service_endpoints(doc)
    assert set(eps) == {"GET /v1/project", "POST /v1/x"}


def test_extract_service_endpoints_rejects_shapeless_doc() -> None:
    with pytest.raises(ValueError, match="no 'paths'"):
        extract_service_endpoints({"info": {}})
    with pytest.raises(ValueError, match="not an object"):
        extract_service_endpoints("nope")


# ---------------------------------------------------------------------------
# snapshot round-trip
# ---------------------------------------------------------------------------


def _spec(name: str, version: str, endpoints: dict[str, str]) -> ServiceSpec:
    return ServiceSpec(name=name, version=version, spec_url=f"http://x/{name}", endpoints=endpoints)


def test_snapshot_round_trips() -> None:
    snap = SpecSnapshot(
        services={"innerspace": _spec("innerspace", "1.3.23", {"GET /v1/project": "sig1"})},
        console_versions={"innerspace": "1.3.23"},
        captured_at="2026-08-15",
    )
    rebuilt = snapshot_from_dict(snapshot_to_dict(snap))
    assert rebuilt == snap


def test_snapshot_from_dict_rejects_bad_shapes() -> None:
    with pytest.raises(ValueError, match="unrecognised snapshot shape"):
        snapshot_from_dict({"nope": 1})
    with pytest.raises(ValueError, match="not an object"):
        snapshot_from_dict({"services": {"x": 5}})
    with pytest.raises(ValueError, match="non-object 'endpoints'"):
        snapshot_from_dict({"services": {"x": {"endpoints": 5}}})
    with pytest.raises(ValueError, match="console_versions"):
        snapshot_from_dict({"services": {}, "console_versions": 5})


# ---------------------------------------------------------------------------
# diff_service / diff_snapshot — the drift classes
# ---------------------------------------------------------------------------


def test_diff_service_flags_new_changed_removed() -> None:
    old = _spec("svc", "1.0.0", {"GET /a": "s1", "GET /b": "s2", "GET /c": "s3"})
    new = _spec("svc", "1.0.0", {"GET /a": "s1", "GET /b": "CHANGED", "GET /d": "s4"})
    diff = diff_service("svc", old, new)
    assert [f.endpoint for f in diff.new_endpoints] == ["GET /d"]
    assert [f.endpoint for f in diff.changed_endpoints] == ["GET /b"]
    assert [f.endpoint for f in diff.removed_endpoints] == ["GET /c"]
    assert diff.has_actionable_findings


def test_diff_service_version_drift() -> None:
    old = _spec("svc", "1.0.0", {"GET /a": "s1"})
    new = _spec("svc", "1.1.0", {"GET /a": "s1"})
    diff = diff_service("svc", old, new)
    assert diff.version_changed
    assert diff.has_actionable_findings
    assert not diff.new_endpoints


def test_diff_service_new_write_endpoint_is_a_write_capability() -> None:
    # The CEO case: a read-only family grows a write route.
    old = _spec("innerspace", "1.3.23", {"GET /v1/project": "s1"})
    new = _spec(
        "innerspace",
        "1.4.0",
        {"GET /v1/project": "s1", "POST /v1/floor_plans": "s2"},
    )
    diff = diff_service("innerspace", old, new)
    (finding,) = diff.new_endpoints
    assert finding.method == "POST"
    assert finding.write_capability is True
    assert finding.implemented is False
    # Boundary condition: a NEW write route on a covered family alone flips the run red.
    assert diff.has_actionable_findings is True


def test_diff_service_removed_implemented_endpoint_is_breakage() -> None:
    # An endpoint we implement (in SPEC_COVERAGE) vanishing from the spec = breakage.
    old = _spec("innerspace", "1.3.23", {"GET /v1/project": "s1", "GET /v1/switches": "s2"})
    new = _spec("innerspace", "1.3.23", {"GET /v1/project": "s1"})
    diff = diff_service("innerspace", old, new)
    (finding,) = diff.removed_endpoints
    assert finding.endpoint == "GET /v1/switches"
    assert finding.implemented is True
    assert finding.breakage is True


def test_diff_service_changed_implemented_endpoint_is_breakage() -> None:
    old = _spec("innerspace", "1.3.23", {"GET /v1/project": "s1"})
    new = _spec("innerspace", "1.3.23", {"GET /v1/project": "MOVED"})
    diff = diff_service("innerspace", old, new)
    (finding,) = diff.changed_endpoints
    assert finding.breakage is True


def test_diff_service_uses_injected_coverage_override() -> None:
    old = _spec("svc", "1.0.0", {"GET /a": "s1"})
    new = _spec("svc", "1.0.0", {})
    diff = diff_service("svc", old, new, coverage={"svc": frozenset({"GET /a"})})
    assert diff.removed_endpoints[0].breakage is True


def test_console_gap_is_informational_not_actionable() -> None:
    spec = _spec("network", "10.4.57", {"GET /a": "s1"})
    diff = diff_service("network", spec, spec, console_version="10.5.99")
    assert diff.console_gap is True
    # A pure console gap must NOT flip the run red.
    assert diff.has_actionable_findings is False


def test_diff_snapshot_new_and_removed_service() -> None:
    baseline = SpecSnapshot(services={"network": _spec("network", "10.4.57", {"GET /a": "s1"})})
    current = SpecSnapshot(
        services={
            "access": _spec("access", "1.0.0", {"GET /openings": "s9"}),  # newly published
        }
    )
    report = diff_snapshot(baseline, current)
    assert report.new_services == ["access"]
    removed = [d for d in report.service_diffs if d.service_removed]
    assert [d.name for d in removed] == ["network"]
    assert not report.is_clean
    assert "NEW SERVICE" in report.summary()
    assert "REMOVED from root index" in report.summary()


# ---------------------------------------------------------------------------
# Committed baseline: parse, round-trip, and synthetic drift detection.
# ---------------------------------------------------------------------------


def test_committed_baseline_parses_and_has_expected_services() -> None:
    baseline = _load_baseline()
    assert {
        "network",
        "protect",
        "innerspace",
        "mobility",
        "site-manager",
        "carrier-fabric",
    } <= set(baseline.services)
    # InnerSpace is the fully-covered, CEO-named family: exactly six GET endpoints.
    innerspace = baseline.services["innerspace"]
    assert len(innerspace.endpoints) == 6
    assert all(ep.startswith("GET ") for ep in innerspace.endpoints)


def test_committed_baseline_round_trips() -> None:
    baseline = _load_baseline()
    assert snapshot_from_dict(snapshot_to_dict(baseline)) == baseline


def test_committed_baseline_diffs_clean_against_itself() -> None:
    baseline = _load_baseline()
    report = diff_snapshot(baseline, baseline)
    assert report.is_clean, report.summary()


def test_committed_baseline_surfaces_network_console_gap() -> None:
    # Baseline records a SYNTHETIC console build for network (10.5.99, derived from published
    # 10.4.57 — never the real estate build) vs published 10.4.57 — surfaced, not failing.
    baseline = _load_baseline()
    report = diff_snapshot(baseline, baseline)
    assert report.is_clean
    gap_names = {d.name for d in report.console_gaps}
    assert "network" in gap_names
    assert "console runs v10.5.99" in report.summary()


def test_committed_baseline_console_versions_are_synthetic_not_real() -> None:
    # PR #253 review, item 2: the committed baseline must NEVER carry a real, distinct estate
    # console build. The single write-boundary normalisation (synthesize_console_versions) is
    # idempotent on a clean baseline, so the committed console_versions must be a FIXED POINT
    # of it — a field-equals-its-synthesis-rule invariant that catches any distinct real value
    # (including a future one) with no denylist and no enumeration of literals.
    baseline = _load_baseline()
    normalised = synthesize_console_versions(baseline.console_versions, baseline.services)
    assert baseline.console_versions == normalised
    # Every committed value is either the published version (discloses nothing beyond the
    # public spec) or the synthetic "ahead" build derived from it — never an arbitrary build.
    for name, ver in baseline.console_versions.items():
        published = baseline.services[name].version
        assert ver in (published, synthetic_console_version(published))
    # The demonstrated console gap (network) is specifically the synthetic ahead build.
    network_published = baseline.services["network"].version
    assert baseline.console_versions["network"] == synthetic_console_version(network_published)
    assert baseline.console_versions["network"] != network_published


def test_committed_baseline_innerspace_fully_covered() -> None:
    baseline = _load_baseline()
    gaps = coverage_gaps(baseline)
    assert gaps["innerspace"] == []  # every published InnerSpace endpoint is implemented


def test_synthetic_next_week_drift_is_caught_in_every_class() -> None:
    baseline = _load_baseline()
    payload = snapshot_to_dict(baseline)
    services = payload["services"]
    # Version bump on network (to a value distinct from BOTH the baseline 10.4.57 and the
    # recorded console 10.5.99, so this service shows version drift AND a console gap).
    services["network"]["version"] = "10.5.0"
    # InnerSpace grows a write route (the CEO case) and loses one implemented GET.
    services["innerspace"]["endpoints"]["POST /v1/project"] = "newsig"
    del services["innerspace"]["endpoints"]["GET /v1/switches"]
    # A protect endpoint's contract changes.
    first_protect_ep = sorted(services["protect"]["endpoints"])[0]
    services["protect"]["endpoints"][first_protect_ep] = "MUTATED"
    # A brand-new family publishes.
    services["access"] = {
        "version": "1.0.0",
        "spec_url": "https://developer.ui.com/access/v1.0.0/openapi.json",
        "endpoints": {"POST /v1/openings/unlock": "s"},
    }
    current = snapshot_from_dict(payload)
    report = diff_snapshot(baseline, current)

    assert not report.is_clean
    assert report.new_services == ["access"]
    # write-capability finding for the new InnerSpace POST route
    write_caps = {(name, f.endpoint) for name, f in report.write_capability_findings}
    assert ("innerspace", "POST /v1/project") in write_caps
    # breakage: the removed InnerSpace GET is one we implement
    breakages = {(name, f.endpoint, f.kind) for name, f in report.breakage_findings}
    assert ("innerspace", "GET /v1/switches", "REMOVED") in breakages
    # version drift + changed endpoint present
    network_diff = next(d for d in report.service_diffs if d.name == "network")
    assert network_diff.version_changed
    assert network_diff.console_gap  # 10.5.0 published vs 10.5.99 console
    protect_diff = next(d for d in report.service_diffs if d.name == "protect")
    assert protect_diff.changed_endpoints

    # Render the full drift summary and assert every class surfaces in the text.
    summary = report.summary()
    assert "SPEC DRIFT" in summary
    assert "VERSION_DRIFT 10.4.57 -> 10.5.0" in summary
    assert "CONSOLE_GAP: published v10.5.0, console runs v10.5.99" in summary
    assert "NEW      POST /v1/project (WRITE capability)" in summary
    assert "REMOVED  GET /v1/switches (BREAKAGE: implemented)" in summary
    assert "CHANGED" in summary
    assert "NEW SERVICE in root index" in summary


# ---------------------------------------------------------------------------
# build_snapshot / helpers
# ---------------------------------------------------------------------------


def test_build_snapshot_skips_unfetched_service() -> None:
    root = {
        "network": ("10.4.57", "http://x/network"),
        "protect": ("7.2.105", "http://x/protect"),
    }
    docs = {"network": {"paths": {"/v1/info": {"get": {"responses": {"200": {}}}}}}}
    snap = build_snapshot(root, docs, console_versions={"network": "10.5.99"})
    assert set(snap.services) == {"network"}  # protect skipped (not fetched)
    assert snap.console_versions == {"network": "10.5.99"}


def test_build_service_spec_lowercases_and_signs() -> None:
    spec = build_service_spec(
        "InnerSpace", "1.3.23", "http://x", {"paths": {"/v1/project": {"get": {"responses": {}}}}}
    )
    assert spec.name == "innerspace"
    assert "GET /v1/project" in spec.endpoints


def test_known_service_slugs_union() -> None:
    a = SpecSnapshot(services={"network": _spec("network", "1", {})})
    b = SpecSnapshot(services={"protect": _spec("protect", "1", {})})
    assert known_service_slugs(a, b) == ["network", "protect"]


# ---------------------------------------------------------------------------
# Synthetic console-version derivation + write-boundary normalisation (PR #253, item 2).
# ---------------------------------------------------------------------------


def test_synthetic_console_version_is_ahead_deterministic_and_public_input() -> None:
    # Derived from the PUBLISHED version alone: minor +1, patch pinned. Ahead of and always
    # distinct from the input, deterministic, and never a function of a real estate build.
    assert synthetic_console_version("10.4.57") == "10.5.99"
    assert synthetic_console_version("7.2.105") == "7.3.99"
    assert synthetic_console_version("1.3.23") == "1.4.99"
    assert synthetic_console_version("10.4.57") == synthetic_console_version("10.4.57")
    assert synthetic_console_version("10.4.57") != "10.4.57"
    # A non-numeric version shape falls back to a deterministic suffix, still != the input.
    assert synthetic_console_version("weird") == "weird+ahead"
    assert synthetic_console_version("weird") != "weird"


def test_synthesize_console_versions_keeps_published_scrubs_distinct_drops_orphans() -> None:
    services = {
        "network": _spec("network", "10.4.57", {}),
        "protect": _spec("protect", "7.2.105", {}),
    }
    got = synthesize_console_versions(
        {
            "network": "10.9.88",  # a distinct (real-magnitude) build -> synthesised away
            "protect": "7.2.105",  # equals published -> kept verbatim (public, not a leak)
            "orphan": "9.9.9",  # no matching service -> dropped (no published anchor)
        },
        services,
    )
    assert got == {"network": "10.5.99", "protect": "7.2.105"}
    assert "10.9.88" not in got.values()


def test_synthesize_console_versions_is_idempotent_on_the_committed_baseline() -> None:
    baseline = _load_baseline()
    once = synthesize_console_versions(baseline.console_versions, baseline.services)
    twice = synthesize_console_versions(once, baseline.services)
    assert once == baseline.console_versions == twice


def test_write_snapshot_file_never_persists_a_distinct_real_console_build(tmp_path) -> None:
    # The write boundary is common to every baseline-write path; a distinct build reaching it
    # (e.g. via an estate-capturing --snapshot bundle merged under --update-baseline) must be
    # normalised to the synthetic before it ever lands on disk.
    from check_spec_drift import write_snapshot_file

    snap = SpecSnapshot(
        services={"network": _spec("network", "10.4.57", {"GET /a": "s1"})},
        console_versions={"network": "10.9.88"},  # a fake build standing in for a real one
    )
    out = tmp_path / "baseline.json"
    write_snapshot_file(out, snap)
    text = out.read_text(encoding="utf-8")
    assert "10.9.88" not in text  # incoming distinct build scrubbed at the boundary
    assert "10.5.99" in text  # synthetic persisted instead
    reloaded = snapshot_from_dict(json.loads(text))
    assert reloaded.console_versions == {"network": "10.5.99"}


def test_spec_coverage_declares_innerspace() -> None:
    assert "innerspace" in SPEC_COVERAGE
    assert len(SPEC_COVERAGE["innerspace"]) == 6


def test_empty_report_is_clean_and_summarises() -> None:
    assert SpecDriftReport().is_clean
    assert "in sync" in SpecDriftReport().summary()


def test_endpoint_finding_method_property() -> None:
    f = EndpointFinding(
        kind="NEW", endpoint="POST /v1/x", implemented=False, breakage=False, write_capability=True
    )
    assert f.method == "POST"


# ---------------------------------------------------------------------------
# Live (Tier-2): fetch the real published specs and diff against the baseline.
# Skipped unless SPEC_DRIFT_LIVE is set, so it never runs in CI.
# ---------------------------------------------------------------------------

_LIVE = os.environ.get("SPEC_DRIFT_LIVE")


@pytest.mark.integration
@pytest.mark.skipif(
    not _LIVE,
    reason="SPEC_DRIFT_LIVE not set (live published-spec fetch is Tier-2 only)",
)
def test_live_published_specs_have_no_actionable_drift() -> None:
    from check_spec_drift import fetch_live_snapshot

    baseline = _load_baseline()
    current = fetch_live_snapshot(
        root_index_url=os.environ.get("SPEC_DRIFT_ROOT_INDEX_URL", ROOT_INDEX_URL),
        console_versions=dict(baseline.console_versions),
    )
    report = diff_snapshot(baseline, current)
    # Any actionable drift here means the published contract moved since the baseline was
    # cut — legitimate signal to review and advance the baseline, not a test bug.
    assert report.is_clean, report.summary()
