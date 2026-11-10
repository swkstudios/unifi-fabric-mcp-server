"""The catalog side of the registration interface (``unifi_fabric.registration``).

The registrar owns ``ToolRegistrar.register_tool``/``register_catalog`` and the checks
it can run without the catalog (invalid_spec, missing_fixture, duplicate_key,
duplicate_emitted_name, missing_handler, invalid_signature). The catalog module supplies:

* :func:`registration_specs`: the committed typed catalog as ``ToolSpec`` records;
* :func:`catalog_checks`: the three catalog-dependent reasons as ``CatalogChecks``
  (unclassified_source against the baseline source table, annotation_mismatch against
  the annotation table and, when given, the source derivation, unbumped_version against
  the committed catalog);
* :func:`validate_registration`: validate the whole catalog through a registrar whose
  sink only records, which proves every spec resolves to exactly one adapter with the
  declared signature before any transport registration.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from .catalog import (
    HINT_KEYS,
    SEMVER_RE,
    Catalog,
    _annotation_problem,
    _semver,
    _thaw,
    api_status_for,
    load_catalog,
)
from .registration import BoundHandler, CatalogChecks, ToolRegistrar, ToolSpec


def registration_specs(catalog: Catalog | None = None) -> list[ToolSpec]:
    """The catalog's specs as ``ToolSpec`` records, in catalog (id) order."""
    out: list[ToolSpec] = []
    for spec in (catalog or load_catalog()).tools:
        data = spec.to_dict()
        data["fixtures"] = tuple(data["fixtures"])
        out.append(ToolSpec(**data))
    return out


def baseline_sources(names: Sequence[str]) -> dict[str, str]:
    """``name -> primary app/source`` from the baseline table (meta: server/local)."""
    from .api_sources import primary_pair
    from .catalog import DISCOVERY_META_TOOLS
    from .generated_api_facts._api_source_table import TOOL_API_SOURCES

    out: dict[str, str] = {}
    for name in names:
        pairs = TOOL_API_SOURCES.get(name)
        if pairs:
            out[name] = primary_pair(pairs)
        elif name in DISCOVERY_META_TOOLS:
            out[name] = "server/local"
    return out


def catalog_checks(
    *,
    sources: Mapping[str, str] | None = None,
    derivation: Mapping[str, Mapping[str, Any]] | None = None,
    baseline: Catalog | None = None,
) -> CatalogChecks:
    """The three catalog-dependent checks for the registration validator.

    Defaults: ``sources`` from the baseline source table, ``baseline`` the committed
    catalog; ``derivation`` (the live source audit) is optional because computing it
    needs the registered tool functions.
    """
    reference = baseline or load_catalog()
    by_id = {spec.id: spec for spec in reference.tools}

    def unclassified_source(specs: Sequence[ToolSpec]) -> str | None:
        table = sources if sources is not None else baseline_sources([s.name for s in specs])
        for spec in specs:
            expected = table.get(spec.name)
            if expected is None:
                return f"{spec.id}: no classified api source"
            if spec.api_source_id != expected:
                return f"{spec.id}: api_source_id is not the classified source"
            if spec.api_status != api_status_for(spec.api_source_id):
                return f"{spec.id}: api_status does not follow its source"
        return None

    def annotation_mismatch(specs: Sequence[ToolSpec]) -> str | None:
        for spec in specs:
            shape = spec.annotations
            if not isinstance(shape, Mapping) or set(shape) != {*HINT_KEYS, "api_class"}:
                return f"{spec.id}: annotations must be the four hints plus api_class"
            problem = _annotation_problem(spec, derivation)  # type: ignore[arg-type]
            if problem:
                return problem
        return None

    def unbumped_version(specs: Sequence[ToolSpec]) -> str | None:
        for spec in specs:
            old = by_id.get(spec.id)
            if old is None:
                continue
            changed = _thaw(old.input_schema) != _thaw(spec.input_schema) or _thaw(
                old.output_schema
            ) != _thaw(spec.output_schema)
            if changed and not SEMVER_RE.fullmatch(spec.version):
                return f"{spec.id}: schema changed and version is not SemVer"
            if changed and _semver(spec.version) <= _semver(old.version):
                return f"{spec.id}: schema changed without a version bump"
        return None

    return CatalogChecks(
        unclassified_source=unclassified_source,
        annotation_mismatch=annotation_mismatch,
        unbumped_version=unbumped_version,
    )


def validate_registration(
    specs: Sequence[ToolSpec] | None = None,
    *,
    checks: CatalogChecks | None = None,
    dependencies: Callable[[], Any] | None = None,
) -> dict[str, BoundHandler]:
    """Run the whole catalog through the registrar with a recording sink.

    Returns ``name -> BoundHandler`` for every spec; raises ``CatalogError`` with the
    first applicable reason, in which case nothing was recorded. This, not
    :func:`unifi_fabric.catalog.validate_catalog` (which imports no handler), is the gate
    for missing_handler and invalid_signature, including a HandlerRef symbol that is a
    valid name but not the spec's own adapter.
    """
    from pathlib import Path

    from .shared_shapes._shared import require_dependencies

    recorded: dict[str, BoundHandler] = {}

    def sink(spec: ToolSpec, bound: BoundHandler) -> None:
        recorded[spec.name] = bound

    registrar = ToolRegistrar(
        sink,
        checks=checks if checks is not None else catalog_checks(),
        fixture_root=Path(__file__).resolve().parents[2],
    )
    registrar.register_catalog(
        list(specs) if specs is not None else registration_specs(),
        dependencies=dependencies or require_dependencies,
    )
    return recorded
