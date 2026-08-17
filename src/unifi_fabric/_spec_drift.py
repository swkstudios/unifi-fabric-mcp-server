"""Spec-drift audit: published UniFi OpenAPI contracts vs. what we last recorded (issue #199).

The target console rides the Early-Access / weekly-auto-update channel, so the per-app
UniFi APIs move constantly. Ubiquiti publishes machine-readable contracts at
``developer.ui.com/{service}/{version}/openapi.json`` behind a root index at
``developer.ui.com/llms.txt``. Today nothing detects when one of those contracts moves;
we only find out when a tool breaks or when someone manually re-reads the docs.

This module holds the **pure, hermetic** comparison logic so it can run in CI with no
network and no credentials — the same split the ``_catalog_audit`` precedent (PR #195)
uses: pure diff logic here, live I/O in ``scripts/check_spec_drift.py``.

The unit of comparison is a :class:`SpecSnapshot`: the set of published services, each
service's published *version* and its ``METHOD /path`` endpoint set (every endpoint
carrying a small content *signature* so a same-path contract change is detectable), plus
the versions those apps are actually running on the estate. A run diffs the freshly
fetched snapshot against the committed baseline and reports, per service:

* **VERSION_DRIFT** — published version differs from the recorded baseline.
* **CONSOLE_GAP** — the console runs a version other than the published contract (e.g.
  Network publishes ``10.4.57`` while the estate runs a higher build such as ``10.5.x`` — the
  estate is *ahead* of the documented contract).
* **NEW endpoint** — a ``METHOD /path`` present now but absent from the baseline: a
  capability we could add. Elevated when it is a write method or lands on a service whose
  coverage we track (e.g. the day InnerSpace grows a write route).
* **CHANGED endpoint** — same ``METHOD /path``, different signature: a contract change and
  a breakage risk. Elevated when we implement it.
* **REMOVED endpoint** — in the baseline, gone now: a breakage risk. Elevated when we
  implement it.
* **NEW_SERVICE / REMOVED_SERVICE** — a family appearing in (or vanishing from) the root
  index. A new trackable family (Access / Talk / Connect / Drive / Identity, or any other)
  triggers the CEO's build-from-spec rule.

Comparing the fetched snapshot against a *committed* baseline (rather than against our
live tool set on every run) is deliberate: it means drift is reported once, when it
happens, and not re-reported every run — the baseline is advanced with
``--update-baseline`` after a run is reviewed. The optional per-service *coverage* overlay
(:data:`SPEC_COVERAGE`) is what ties a changed/removed endpoint back to "…and we
implement it, so this is breakage, not just news".
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field

#: Root catalog that lists every published service, its current version, and its
#: ``openapi.json`` URL. Watching this (not just per-service versions) is what surfaces a
#: brand-new family the first day it publishes an API.
ROOT_INDEX_URL = "https://developer.ui.com/llms.txt"

#: HTTP methods that mutate state. A NEW endpoint using one of these is elevated: the CEO
#: specifically wants to hear the day a read-only family (e.g. InnerSpace) grows a write
#: route.
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

#: Per-service coverage overlay: the ``METHOD /path`` endpoints our tools actually
#: implement, keyed by the service slug used in the root index. Declared here so a
#: CHANGED / REMOVED endpoint we depend on is flagged as *breakage* (not merely news) and
#: a NEW endpoint on a covered service is flagged as an unimplemented capability.
#:
#: InnerSpace is declared in full — its published v1.3.23 surface is exactly six GET
#: endpoints, all read-only, and our five list/get tools plus ``get_innerspace_project``
#: cover every one. Services without an entry here are still fully drift-checked (version,
#: new/changed/removed endpoints, new-service); they simply are not yet annotated with an
#: implemented/unimplemented verdict. Extend this map as typed coverage is added.
SPEC_COVERAGE: dict[str, frozenset[str]] = {
    "innerspace": frozenset(
        {
            "GET /v1/project",
            "GET /v1/floor_plans",
            "GET /v1/access_points",
            "GET /v1/switches",
            "GET /v1/inventory",
            "GET /v1/assets/{planId}/{filename}",
        }
    ),
}

# A markdown link in llms.txt whose target ends in ``/openapi.json``. The URL carries the
# service slug and the ``vX.Y.Z`` version, e.g.
#   - [Network OpenAPI Spec](https://developer.ui.com/network/v10.4.57/openapi.json): ...
_OPENAPI_LINK_RE = re.compile(
    r"\]\((?P<url>https?://[^)]*?/(?P<service>[^/]+)/v(?P<version>[^/]+)/openapi\.json)\)"
)

_HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "trace"})


def parse_root_index(text: str) -> dict[str, tuple[str, str]]:
    """Parse ``llms.txt`` into ``{service_slug: (version, openapi_url)}``.

    Only lines advertising an ``openapi.json`` are taken, so the result is exactly the set
    of families that currently publish a machine-readable contract. A family that appears
    here but not in the baseline is a new trackable service; one that drops out is a
    removed service.

    Raises ``ValueError`` when no OpenAPI spec links are found at all, so a fetch that
    silently returned an error page (or a reshaped index) fails loud rather than looking
    like "every service disappeared".
    """
    found: dict[str, tuple[str, str]] = {}
    for match in _OPENAPI_LINK_RE.finditer(text):
        service = match.group("service").strip().lower()
        version = match.group("version").strip()
        url = match.group("url").strip()
        # First occurrence wins; the index lists each spec once under "OpenAPI
        # Specifications" but may also reference the URL elsewhere.
        found.setdefault(service, (version, url))
    if not found:
        raise ValueError(
            "no OpenAPI spec links found in root index — expected at least one "
            "'.../{service}/v{version}/openapi.json' link; the index may be an error page "
            "or its shape changed"
        )
    return found


def endpoint_signature(operation: object) -> str:
    """Return a short, stable content signature for one OpenAPI operation.

    The signature folds the pieces of an operation whose change would alter the contract a
    caller must satisfy: its ``operationId``, the sorted ``(name, in, required)`` of its
    parameters, whether a request body is present/required, and the sorted set of declared
    response status codes. Anything cosmetic (description prose, ordering, examples) is
    excluded so the signature only moves on a *semantic* change.

    A non-dict operation (a malformed spec) yields a signature over its raw JSON so it
    still round-trips deterministically rather than raising.
    """
    if not isinstance(operation, Mapping):
        canonical = json.dumps(operation, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]

    params = []
    raw_params = operation.get("parameters")
    if isinstance(raw_params, list):
        for param in raw_params:
            if isinstance(param, Mapping):
                params.append(
                    (
                        str(param.get("name", "")),
                        str(param.get("in", "")),
                        bool(param.get("required", False)),
                    )
                )
    params.sort()

    request_body = operation.get("requestBody")
    if isinstance(request_body, Mapping):
        body = [True, bool(request_body.get("required", False))]
    else:
        body = [False, False]

    responses = operation.get("responses")
    codes = sorted(str(c) for c in responses) if isinstance(responses, Mapping) else []

    canonical = json.dumps(
        {
            "operationId": operation.get("operationId"),
            "parameters": params,
            "requestBody": body,
            "responses": codes,
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def extract_service_endpoints(openapi_doc: object) -> dict[str, str]:
    """Extract ``{"METHOD /path": signature}`` from an OpenAPI document.

    Only true HTTP operations are taken; the ``paths``-level ``parameters``/``summary``
    siblings and any ``x-*`` extensions are ignored. Raises ``ValueError`` when the
    document has no ``paths`` mapping, so a truncated or wrong-shape spec fails loud.
    """
    if not isinstance(openapi_doc, Mapping):
        raise ValueError("OpenAPI document is not an object")
    paths = openapi_doc.get("paths")
    if not isinstance(paths, Mapping):
        raise ValueError("OpenAPI document has no 'paths' object")
    endpoints: dict[str, str] = {}
    for path, operations in paths.items():
        if not isinstance(operations, Mapping):
            continue
        for method, operation in operations.items():
            if method.lower() not in _HTTP_METHODS:
                continue
            endpoints[f"{method.upper()} {path}"] = endpoint_signature(operation)
    return endpoints


@dataclass(frozen=True)
class ServiceSpec:
    """One published service: its slug, version, spec URL, and signed endpoint set."""

    name: str
    version: str
    spec_url: str
    endpoints: dict[str, str] = field(default_factory=dict)


def build_service_spec(name: str, version: str, spec_url: str, openapi_doc: object) -> ServiceSpec:
    """Build a :class:`ServiceSpec` from a fetched OpenAPI document."""
    return ServiceSpec(
        name=name.lower(),
        version=version,
        spec_url=spec_url,
        endpoints=extract_service_endpoints(openapi_doc),
    )


@dataclass(frozen=True)
class SpecSnapshot:
    """A point-in-time view of every published service plus estate-running versions.

    ``services`` maps service slug -> :class:`ServiceSpec`. ``console_versions`` maps
    service slug -> the version that service is actually running on the estate (observed
    live; carried in the committed baseline). ``captured_at`` is informational provenance
    and never participates in the diff.
    """

    services: dict[str, ServiceSpec] = field(default_factory=dict)
    console_versions: dict[str, str] = field(default_factory=dict)
    captured_at: str | None = None


def snapshot_to_dict(snapshot: SpecSnapshot) -> dict:
    """Serialise a :class:`SpecSnapshot` to a JSON-safe dict (stable key order)."""
    return {
        "captured_at": snapshot.captured_at,
        "console_versions": dict(sorted(snapshot.console_versions.items())),
        "services": {
            name: {
                "version": spec.version,
                "spec_url": spec.spec_url,
                "endpoints": dict(sorted(spec.endpoints.items())),
            }
            for name, spec in sorted(snapshot.services.items())
        },
    }


def snapshot_from_dict(payload: object) -> SpecSnapshot:
    """Rebuild a :class:`SpecSnapshot` from :func:`snapshot_to_dict` output.

    Raises ``ValueError`` on an unrecognised shape so a corrupt baseline fails loud instead
    of diffing against an empty snapshot (which would flag everything as removed).
    """
    if not isinstance(payload, Mapping) or not isinstance(payload.get("services"), Mapping):
        raise ValueError("unrecognised snapshot shape: expected a {'services': {...}} object")
    services: dict[str, ServiceSpec] = {}
    for name, body in payload["services"].items():
        if not isinstance(body, Mapping):
            raise ValueError(f"service {name!r} entry is not an object")
        endpoints = body.get("endpoints", {})
        if not isinstance(endpoints, Mapping):
            raise ValueError(f"service {name!r} has a non-object 'endpoints'")
        services[str(name).lower()] = ServiceSpec(
            name=str(name).lower(),
            version=str(body.get("version", "")),
            spec_url=str(body.get("spec_url", "")),
            endpoints={str(k): str(v) for k, v in endpoints.items()},
        )
    console_versions = payload.get("console_versions", {})
    if not isinstance(console_versions, Mapping):
        raise ValueError("'console_versions' must be an object when present")
    return SpecSnapshot(
        services=services,
        console_versions={str(k).lower(): str(v) for k, v in console_versions.items()},
        captured_at=(str(payload["captured_at"]) if payload.get("captured_at") else None),
    )


@dataclass(frozen=True)
class EndpointFinding:
    """A single NEW / CHANGED / REMOVED endpoint on one service."""

    kind: str  # "NEW" | "CHANGED" | "REMOVED"
    endpoint: str  # "METHOD /path"
    implemented: bool
    breakage: bool  # CHANGED/REMOVED endpoint we implement, or...
    write_capability: bool  # NEW write-method endpoint we do not implement

    @property
    def method(self) -> str:
        return self.endpoint.split(" ", 1)[0]


@dataclass(frozen=True)
class ServiceDiff:
    """Drift for one service between the baseline and the current snapshot."""

    name: str
    old_version: str | None
    new_version: str | None
    console_version: str | None
    endpoint_findings: list[EndpointFinding] = field(default_factory=list)
    service_added: bool = False
    service_removed: bool = False

    @property
    def version_changed(self) -> bool:
        return (
            not self.service_added
            and not self.service_removed
            and self.old_version is not None
            and self.new_version is not None
            and self.old_version != self.new_version
        )

    @property
    def console_gap(self) -> bool:
        # Published-vs-running divergence, only meaningful while the service is published.
        # This is *informational*: on the EA channel the estate routinely runs ahead of the
        # documented contract, so it is a standing condition the watcher cannot resolve and
        # must NOT treat as actionable drift (that would make the weekly monitor permanently
        # red — the failure mode the monitor is designed to avoid). It is always
        # surfaced in the report body.
        return (
            self.new_version is not None
            and self.console_version is not None
            and self.console_version != self.new_version
        )

    @property
    def has_actionable_findings(self) -> bool:
        """Deltas vs. the baseline that flip the run RED until the baseline is advanced.

        Deliberately excludes :attr:`console_gap`, which is a standing informational
        condition rather than a run-to-run delta.
        """
        return bool(
            self.endpoint_findings
            or self.version_changed
            or self.service_added
            or self.service_removed
        )

    def _by_kind(self, kind: str) -> list[EndpointFinding]:
        return [f for f in self.endpoint_findings if f.kind == kind]

    @property
    def new_endpoints(self) -> list[EndpointFinding]:
        return self._by_kind("NEW")

    @property
    def changed_endpoints(self) -> list[EndpointFinding]:
        return self._by_kind("CHANGED")

    @property
    def removed_endpoints(self) -> list[EndpointFinding]:
        return self._by_kind("REMOVED")


def _endpoint_findings(
    old: ServiceSpec | None,
    new: ServiceSpec | None,
    implemented: frozenset[str],
) -> list[EndpointFinding]:
    old_eps = old.endpoints if old else {}
    new_eps = new.endpoints if new else {}
    findings: list[EndpointFinding] = []

    for ep in sorted(set(new_eps) - set(old_eps)):
        method = ep.split(" ", 1)[0]
        is_impl = ep in implemented
        findings.append(
            EndpointFinding(
                kind="NEW",
                endpoint=ep,
                implemented=is_impl,
                breakage=False,
                write_capability=(method in WRITE_METHODS and not is_impl),
            )
        )
    for ep in sorted(set(old_eps) & set(new_eps)):
        if old_eps[ep] != new_eps[ep]:
            is_impl = ep in implemented
            findings.append(
                EndpointFinding(
                    kind="CHANGED",
                    endpoint=ep,
                    implemented=is_impl,
                    breakage=is_impl,
                    write_capability=False,
                )
            )
    for ep in sorted(set(old_eps) - set(new_eps)):
        is_impl = ep in implemented
        findings.append(
            EndpointFinding(
                kind="REMOVED",
                endpoint=ep,
                implemented=is_impl,
                breakage=is_impl,
                write_capability=False,
            )
        )
    return findings


def diff_service(
    name: str,
    old: ServiceSpec | None,
    new: ServiceSpec | None,
    console_version: str | None = None,
    coverage: Mapping[str, frozenset[str]] | None = None,
) -> ServiceDiff:
    """Diff one service's baseline spec against its current spec."""
    implemented = (coverage or SPEC_COVERAGE).get(name, frozenset())
    return ServiceDiff(
        name=name,
        old_version=old.version if old else None,
        new_version=new.version if new else None,
        console_version=console_version,
        endpoint_findings=_endpoint_findings(old, new, implemented),
        service_added=old is None and new is not None,
        service_removed=old is not None and new is None,
    )


@dataclass(frozen=True)
class SpecDriftReport:
    """The full cross-service drift report between a baseline and current snapshot."""

    service_diffs: list[ServiceDiff] = field(default_factory=list)

    @property
    def drifted(self) -> list[ServiceDiff]:
        """Services with actionable drift (excludes informational console gaps)."""
        return [d for d in self.service_diffs if d.has_actionable_findings]

    @property
    def is_clean(self) -> bool:
        """True when no actionable drift exists. A standing console gap does not fail a run."""
        return not self.drifted

    @property
    def console_gaps(self) -> list[ServiceDiff]:
        """Services whose published version differs from the running console version."""
        return [d for d in self.service_diffs if d.console_gap]

    @property
    def new_services(self) -> list[str]:
        return sorted(d.name for d in self.service_diffs if d.service_added)

    @property
    def breakage_findings(self) -> list[tuple[str, EndpointFinding]]:
        out: list[tuple[str, EndpointFinding]] = []
        for d in self.service_diffs:
            for f in d.endpoint_findings:
                if f.breakage:
                    out.append((d.name, f))
        return out

    @property
    def write_capability_findings(self) -> list[tuple[str, EndpointFinding]]:
        out: list[tuple[str, EndpointFinding]] = []
        for d in self.service_diffs:
            for f in d.new_endpoints:
                if f.write_capability:
                    out.append((d.name, f))
        return out

    def _console_gap_lines(self) -> list[str]:
        gaps = self.console_gaps
        if not gaps:
            return []
        lines = ["Console/contract version gaps (informational — estate vs. published):"]
        for d in sorted(gaps, key=lambda x: x.name):
            lines.append(
                f"  [{d.name}] published v{d.new_version}, console runs v{d.console_version}"
            )
        return lines

    def summary(self) -> str:
        if self.is_clean:
            n = len(self.service_diffs)
            head = f"spec in sync: {n} published service(s) match the recorded baseline."
            gap_lines = self._console_gap_lines()
            return "\n".join([head, *gap_lines]) if gap_lines else head
        lines = [
            f"SPEC DRIFT: {len(self.drifted)} of {len(self.service_diffs)} service(s) drifted."
        ]
        for d in sorted(self.drifted, key=lambda x: x.name):
            if d.service_added:
                lines.append(
                    f"  [{d.name}] NEW SERVICE in root index (v{d.new_version}) — "
                    "build-from-spec rule applies."
                )
                continue
            if d.service_removed:
                lines.append(f"  [{d.name}] REMOVED from root index (was v{d.old_version}).")
                continue
            header = f"  [{d.name}]"
            if d.version_changed:
                header += f" VERSION_DRIFT {d.old_version} -> {d.new_version}"
            if d.console_gap:
                header += (
                    f" | CONSOLE_GAP: published v{d.new_version}, console runs v{d.console_version}"
                )
            lines.append(header)
            for f in d.new_endpoints:
                tag = " (WRITE capability)" if f.write_capability else ""
                lines.append(f"      NEW      {f.endpoint}{tag}")
            for f in d.changed_endpoints:
                tag = " (BREAKAGE: implemented)" if f.breakage else ""
                lines.append(f"      CHANGED  {f.endpoint}{tag}")
            for f in d.removed_endpoints:
                tag = " (BREAKAGE: implemented)" if f.breakage else ""
                lines.append(f"      REMOVED  {f.endpoint}{tag}")
        lines.extend(self._console_gap_lines())
        return "\n".join(lines)


def diff_snapshot(
    baseline: SpecSnapshot,
    current: SpecSnapshot,
    coverage: Mapping[str, frozenset[str]] | None = None,
) -> SpecDriftReport:
    """Diff a freshly fetched snapshot against the committed baseline.

    Console-version gaps are read from ``current.console_versions`` when present, else the
    baseline's (the checker's public-spec live mode does not touch the estate, so the
    committed console observation is used unless a caller supplies a fresher one).
    """
    names = sorted(set(baseline.services) | set(current.services))
    diffs: list[ServiceDiff] = []
    for name in names:
        console_version = current.console_versions.get(name) or baseline.console_versions.get(name)
        diffs.append(
            diff_service(
                name,
                baseline.services.get(name),
                current.services.get(name),
                console_version=console_version,
                coverage=coverage,
            )
        )
    return SpecDriftReport(service_diffs=diffs)


def build_snapshot(
    root_index: Mapping[str, tuple[str, str]],
    openapi_docs: Mapping[str, object],
    console_versions: Mapping[str, str] | None = None,
    captured_at: str | None = None,
) -> SpecSnapshot:
    """Assemble a :class:`SpecSnapshot` from a parsed root index and fetched specs.

    ``root_index`` is :func:`parse_root_index` output; ``openapi_docs`` maps service slug
    to its parsed OpenAPI document. A service present in the index but absent from
    ``openapi_docs`` is skipped (its spec could not be fetched) rather than recorded as
    empty, so a transient fetch failure never masquerades as "all endpoints removed".
    """
    services: dict[str, ServiceSpec] = {}
    for name, (version, url) in root_index.items():
        if name not in openapi_docs:
            continue
        services[name] = build_service_spec(name, version, url, openapi_docs[name])
    return SpecSnapshot(
        services=services,
        console_versions={str(k).lower(): str(v) for k, v in (console_versions or {}).items()},
        captured_at=captured_at,
    )


#: Synthetic "estate runs ahead of the published contract" derivation for the committed
#: baseline. On the EA channel the console genuinely runs a higher build than the published
#: spec, but the TRUE running build is a live estate observation that must never be
#: persisted into the committed baseline fixture — that file reaches the public repository,
#: so a real, distinct console build sitting in it is an unintended disclosure (PR #253
#: review). A committed console version is therefore only ever one of two safe values: the
#: published version itself (which discloses nothing beyond the public spec), or a value
#: DERIVED from the published version — bump the minor by :data:`_CONSOLE_AHEAD_MINOR` and
#: pin the patch to :data:`_CONSOLE_AHEAD_PATCH`. The derivation's input is the public spec
#: version, so it can never coincide with a real build, yet it is deterministically
#: reproducible (a CI check asserts the committed baseline is a fixed point of the write-
#: boundary rule) and differs from the published version, keeping the CONSOLE_GAP path
#: exercised.
_CONSOLE_AHEAD_MINOR = 1
_CONSOLE_AHEAD_PATCH = 99


def synthetic_console_version(published_version: str) -> str:
    """Derive a synthetic "estate is ahead" console build from a *published* spec version.

    Deterministic and public-input-only: for the usual ``major.minor.patch`` numeric dotted
    form, bump the minor by :data:`_CONSOLE_AHEAD_MINOR` and pin the patch to
    :data:`_CONSOLE_AHEAD_PATCH`, which guarantees a value ahead of — and always different
    from — ``published_version`` without ever reflecting a real console build. A version
    string that is not that numeric form falls back to a suffixed marker (still
    deterministic, still distinct from the input).
    """
    parts = published_version.split(".")
    try:
        major = int(parts[0])
        minor = int(parts[1])
    except (IndexError, ValueError):
        return f"{published_version}+ahead"
    return f"{major}.{minor + _CONSOLE_AHEAD_MINOR}.{_CONSOLE_AHEAD_PATCH}"


def synthesize_console_versions(
    console_versions: Mapping[str, str],
    services: Mapping[str, ServiceSpec],
) -> dict[str, str]:
    """Normalise console observations so no real, distinct estate build is ever persisted.

    This is the single normalisation applied at the baseline **write boundary** (see
    ``scripts/check_spec_drift.py``), common to every path that persists a baseline. For
    each service that carries a console observation AND is present in ``services``:

    * a value equal to that service's *published* version is kept verbatim — it discloses
      nothing beyond the public spec (no gap), and
    * any DISTINCT value is a potential live estate observation and is replaced by the
      deterministic :func:`synthetic_console_version` of the published version, regardless
      of the magnitude the incoming observation held.

    An observation for a service not present in ``services`` has no published version to
    anchor a synthetic and is dropped (it is undiffable anyway). The result is a fixed point
    of this function, so re-running it on a normalised baseline is a no-op. Returns a new
    dict in sorted key order.
    """
    out: dict[str, str] = {}
    for name, observed in console_versions.items():
        spec = services.get(name)
        if spec is None:
            continue
        published = spec.version
        out[name] = observed if observed == published else synthetic_console_version(published)
    return dict(sorted(out.items()))


def known_service_slugs(*snapshots: SpecSnapshot) -> list[str]:
    """Union of service slugs across the given snapshots (sorted)."""
    slugs: set[str] = set()
    for snap in snapshots:
        slugs.update(snap.services)
    return sorted(slugs)


def coverage_gaps(
    snapshot: SpecSnapshot, coverage: Mapping[str, frozenset[str]] | None = None
) -> dict[str, list[str]]:
    """For each covered service, the published endpoints we do not yet implement.

    A pure convenience for the ``--emit`` view: it answers "of the endpoints published
    today, which does our declared coverage not include" without any diff against a
    baseline. Services with no coverage declaration are omitted.
    """
    cov = coverage or SPEC_COVERAGE
    gaps: dict[str, list[str]] = {}
    for name, spec in snapshot.services.items():
        if name not in cov:
            continue
        missing = sorted(set(spec.endpoints) - cov[name])
        gaps[name] = missing
    return gaps
