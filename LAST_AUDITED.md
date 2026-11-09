# API Audit Baseline — UniFi Fabric MCP Server

This document records manually reviewed audit results. The machine-readable baseline is
`tests/fixtures/spec_drift/baseline_snapshot.json`. After running
`scripts/check_spec_drift.py --live --update-baseline`, update this table's versions,
dates and notes manually from the reviewed results; the command updates only the JSON
baseline.

## Audited surfaces

| Surface | Audited version | Audit date | Notes |
|---------|-----------------|------------|-------|
| Network Integration API | 11.0.97 | 2026-11-03 | All implemented endpoints verified against spec |
| Protect | 7.3.74 | 2026-11-03 | All implemented endpoints verified against spec |
| InnerSpace | 1.3.23 | 2026-10-07 | GET surface fully covered; write surface absent from published spec |
| Carrier Fabric | 1.0.0 | 2026-10-07 | Spec-conformance only — not testable against live hardware |
| Site Manager | 1.0.0 | 2026-10-07 | Stable `/v1/` surface; EA (`/ea/`) endpoints listed below as unaudited |
| Mobility | 1.0.0 | 2026-10-07 | All implemented endpoints verified against spec |

## Known-unaudited surfaces

| Surface | Status | Reason |
|---------|--------|--------|
| Access | No spec available | Ubiquiti does not publish a machine-readable OpenAPI spec for Access; cloud connector returns 403 for all access proxy paths |
| Site Manager EA (`/ea/` endpoints) | Unaudited | EA namespace carries weaker contract guarantees and may change without notice; tracked separately from the stable `/v1/` surface |

## Audit procedure

Audit the live published specs by running:

```bash
python scripts/check_spec_drift.py --live
```

A clean run (exit 0) means all tracked services match the committed baseline in
`tests/fixtures/spec_drift/baseline_snapshot.json`. Exit 1 means VERSION_DRIFT or
endpoint changes were found and must be triaged before advancing the baseline.

To view the current baseline summary and coverage gaps without a live fetch:

```bash
python scripts/check_spec_drift.py --emit
```

To advance the baseline after a reviewed drift finding (this rewrites only the JSON
baseline; update the tables above by hand from the reviewed results):

```bash
python scripts/check_spec_drift.py --live --update-baseline
```

## Audit cadence and ownership

The spec-drift watcher is available for manual runs; no weekly schedule is shipped
in this repository. The audit owner for each release cycle is the release lead for
that cycle. A manual audit must be performed as part of every release gate
(a pre-publication step).

Newly published surfaces and deferred capabilities (such as Access and Protect
WebSocket streams) are tracked in the project's issue tracker.
