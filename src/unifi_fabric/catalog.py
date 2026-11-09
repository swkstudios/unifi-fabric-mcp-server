"""The typed tool catalog: one metadata record (ToolSpec) per public tool.

The catalog is generated from the registered server by ``scripts/gen_tool_catalog.py``
and committed as ``src/unifi_fabric/_generated/catalog.json``. It is the single
inventory that registration, family selection, discovery, docs and audit read; a test
(``tests/test_catalog_contract.py``) regenerates it in memory and fails when the
committed file is stale.

Shape: an object with ``version`` (contract SemVer), ``tools`` (an
array of ToolSpec objects ordered by ``id``) and ``fixtures`` (catalog-wide fixture
paths). A ToolSpec carries:

* ``id``: ``<family>.<name>``; ``family``/``family_id``: one of the 13 frozen families,
  or the reserved family ``meta`` for the six meta tools;
* ``name``: the unchanged public tool name, which is also the emitted MCP name;
* ``api_source_id``: the tool's primary ``app/source`` pair; ``api_status``:
  ``official``, ``unofficial`` or ``local`` (``local`` exactly for ``server/local`` and
  ``relay/generic``);
* ``read_only``, ``annotations`` (the four MCP hints plus ``api_class``): one
  derivation, :func:`unifi_fabric.tool_annotations.for_tool` over the source-audited
  verb set and upstream reach; never hand-set;
* ``description``, ``input_schema``, ``output_schema`` (``null`` for pass-through),
  ``version`` (the SemVer of the schema pair, bumped on any schema change), ``fixtures``;
* ``handler``: the HandlerRef ``unifi_fabric._generated.adapters.<family>:<name>``.

:func:`validate_catalog` checks a spec list for the seven catalog-level startup reasons,
in contract order, before any handler is imported.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal

#: The contract version of the catalog shape (SemVer).
CATALOG_VERSION = "1.0.0"

#: The committed catalog file.
CATALOG_PATH = Path(__file__).parent / "_generated" / "catalog.json"

#: The reserved family of the six meta tools. It is not one of the 13 frozen families.
META_FAMILY = "meta"

#: The five discovery meta tools (src/unifi_fabric/discovery.py META_TOOLS) and the
#: local-only key listing: the tools of the reserved ``meta`` family.
DISCOVERY_META_TOOLS: frozenset[str] = frozenset(
    {"search_tools", "describe_tool", "call_read_tool", "call_write_tool", "list_tool_families"}
)
META_TOOL_NAMES: frozenset[str] = DISCOVERY_META_TOOLS | {"list_configured_api_keys"}

#: The package that holds the generated handler adapters.
ADAPTER_PACKAGE = "unifi_fabric._generated.adapters"

#: Initial per-tool schema version.
INITIAL_TOOL_VERSION = "1.0.0"

#: The two sources whose tools are of class ``local``.
LOCAL_SOURCES: frozenset[str] = frozenset({"server/local", "relay/generic"})

ApiStatus = Literal["official", "unofficial", "local"]
API_STATUSES: tuple[str, ...] = ("official", "unofficial", "local")

#: The catalog-level validation reasons, in the order they are checked.
CATALOG_REASONS: tuple[str, ...] = (
    "invalid_spec",
    "unclassified_source",
    "annotation_mismatch",
    "unbumped_version",
    "missing_fixture",
    "duplicate_key",
    "duplicate_emitted_name",
)
#: The handler-level reasons, checked after the catalog-level ones (registration).
HANDLER_REASONS: tuple[str, ...] = ("missing_handler", "invalid_signature")

ID_RE = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\Z")
NAME_RE = re.compile(r"^[a-z][a-z0-9_]*\Z")
SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)\Z")
HINT_KEYS: tuple[str, ...] = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")
SPEC_FIELDS: tuple[str, ...] = (
    "id",
    "family",
    "family_id",
    "name",
    "api_source_id",
    "api_status",
    "read_only",
    "annotations",
    "description",
    "input_schema",
    "output_schema",
    "version",
    "fixtures",
    "handler",
)


class CatalogError(ValueError):
    """A catalog failed validation; ``reason`` is one of the contract reasons."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"startup:catalog:{reason}: {detail}")
        self.reason = reason
        self.detail = detail

    @property
    def code(self) -> str:
        """The refusal code ``startup:catalog:<reason>``."""
        return f"startup:catalog:{self.reason}"


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, list | tuple):
        return tuple(_freeze(v) for v in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {k: _thaw(v) for k, v in value.items()}
    if isinstance(value, tuple):
        return [_thaw(v) for v in value]
    return value


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """One public tool's metadata record (immutable)."""

    id: str
    family: str
    family_id: str
    name: str
    api_source_id: str
    api_status: str
    read_only: bool
    annotations: Mapping[str, Any]
    description: str
    input_schema: Mapping[str, Any]
    output_schema: Mapping[str, Any] | None
    version: str
    fixtures: tuple[str, ...] = field(default_factory=tuple)
    handler: str = ""

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ToolSpec:
        """Build a spec from its JSON object (no validation; see :func:`validate_catalog`)."""
        return cls(
            id=data["id"],
            family=data["family"],
            family_id=data["family_id"],
            name=data["name"],
            api_source_id=data["api_source_id"],
            api_status=data["api_status"],
            read_only=data["read_only"],
            annotations=_freeze(data["annotations"]),
            description=data["description"],
            input_schema=_freeze(data["input_schema"]),
            output_schema=None if data["output_schema"] is None else _freeze(data["output_schema"]),
            version=data["version"],
            fixtures=tuple(data.get("fixtures") or ()),
            handler=data["handler"],
        )

    def to_dict(self) -> dict[str, Any]:
        """The spec as a JSON-ready object with the contract's field order."""
        return {name: _thaw(getattr(self, name)) for name in SPEC_FIELDS}

    @property
    def key(self) -> tuple[str, str]:
        """The registration key ``(family, name)``."""
        return (self.family, self.name)


@dataclass(frozen=True, slots=True)
class Catalog:
    """The checked-in catalog: contract version, specs ordered by id, catalog fixtures."""

    version: str
    tools: tuple[ToolSpec, ...]
    fixtures: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Catalog:
        """Parse the catalog JSON object."""
        if set(data) != {"version", "tools", "fixtures"}:
            raise CatalogError("invalid_spec", "catalog keys must be version, tools, fixtures")
        return cls(
            version=data["version"],
            tools=tuple(ToolSpec.from_dict(item) for item in data["tools"]),
            fixtures=tuple(data["fixtures"]),
        )

    def to_dict(self) -> dict[str, Any]:
        """The catalog as a JSON-ready object (tools ordered by id)."""
        return {
            "version": self.version,
            "tools": [spec.to_dict() for spec in sorted(self.tools, key=lambda s: s.id)],
            "fixtures": list(self.fixtures),
        }

    def by_name(self) -> dict[str, ToolSpec]:
        """Specs keyed by public tool name."""
        return {spec.name: spec for spec in self.tools}

    def family_index(self, *, include_meta: bool = False) -> dict[str, str]:
        """``tool name -> family``; meta tools only when ``include_meta``."""
        return {
            spec.name: spec.family
            for spec in self.tools
            if include_meta or spec.family != META_FAMILY
        }


def render_catalog(catalog: Catalog) -> str:
    """The deterministic committed text of a catalog."""
    return json.dumps(catalog.to_dict(), indent=1, sort_keys=False, ensure_ascii=False) + "\n"


@cache
def load_catalog(path: Path = CATALOG_PATH) -> Catalog:
    """Load and parse the committed catalog (cached; the file is immutable at runtime)."""
    return Catalog.from_dict(json.loads(path.read_text(encoding="utf-8")))


def handler_ref(family: str, name: str) -> str:
    """The HandlerRef a spec of ``family`` and ``name`` gets by rule."""
    return f"{ADAPTER_PACKAGE}.{family}:{name}"


def api_status_for(api_source_id: str) -> str:
    """``local`` for server/local and relay/generic; else official or unofficial."""
    if api_source_id in LOCAL_SOURCES:
        return "local"
    _app, _, source = api_source_id.partition("/")
    return "official" if source == "official" else "unofficial"


def derived_annotations(verbs: Iterable[str], open_world: bool, api_status: str) -> dict[str, Any]:
    """The four MCP hints and ``api_class`` from the single derivation (``for_tool``)."""
    from .tool_annotations import for_tool

    wire = for_tool(verbs=set(verbs), open_world=open_world).model_dump(by_alias=True)
    out: dict[str, Any] = {key: bool(wire[key]) for key in HINT_KEYS}
    out["api_class"] = api_status
    return out


def _schema_problem(spec: ToolSpec, families: frozenset[str]) -> str | None:
    """Why ``spec`` fails the catalog schema, or None."""
    if not isinstance(spec.id, str) or not ID_RE.fullmatch(spec.id):
        return f"id {spec.id!r} is off the <family>.<name> pattern"
    if spec.family != spec.family_id:
        return f"{spec.id}: family and family_id differ"
    if spec.family not in families and spec.family != META_FAMILY:
        return f"{spec.id}: unknown family {spec.family!r}"
    if (spec.family == META_FAMILY) != (spec.name in META_TOOL_NAMES):
        return f"{spec.id}: only the six meta tools use family meta"
    if not isinstance(spec.name, str) or not NAME_RE.fullmatch(spec.name):
        return f"{spec.id}: invalid name"
    if spec.id != f"{spec.family}.{spec.name}":
        return f"{spec.id}: id is not <family>.<name>"
    if spec.api_status not in API_STATUSES:
        return f"{spec.id}: invalid api_status {spec.api_status!r}"
    if not isinstance(spec.read_only, bool):
        return f"{spec.id}: read_only is not a boolean"
    if not isinstance(spec.description, str) or not spec.description.strip():
        return f"{spec.id}: empty description"
    if not isinstance(spec.input_schema, Mapping):
        return f"{spec.id}: input_schema is not an object"
    if spec.output_schema is not None and not isinstance(spec.output_schema, Mapping):
        return f"{spec.id}: output_schema is neither an object nor null"
    if not isinstance(spec.version, str) or not SEMVER_RE.fullmatch(spec.version):
        return f"{spec.id}: version is not SemVer"
    if not all(isinstance(p, str) and p for p in spec.fixtures):
        return f"{spec.id}: fixtures must be repository paths"
    annotations = spec.annotations
    if not isinstance(annotations, Mapping) or set(annotations) != {*HINT_KEYS, "api_class"}:
        return f"{spec.id}: annotations must be the four hints plus api_class"
    if not all(isinstance(annotations[k], bool) for k in HINT_KEYS):
        return f"{spec.id}: annotation hints must be booleans"
    if annotations["api_class"] not in API_STATUSES:
        return f"{spec.id}: invalid api_class"
    module, sep, symbol = (
        spec.handler.partition(":") if isinstance(spec.handler, str) else ("", "", "")
    )
    # The module must be the family adapter module; a symbol that module does not define
    # is missing_handler, found when the handler is imported (registration fixture contract).
    if not sep or module != f"{ADAPTER_PACKAGE}.{spec.family}" or not NAME_RE.fullmatch(symbol):
        return f"{spec.id}: HandlerRef {spec.handler!r} is outside its family's adapter module"
    return None


def _annotation_problem(
    spec: ToolSpec, derivation: Mapping[str, Mapping[str, Any]] | None
) -> str | None:
    """Why ``spec``'s classification disagrees with the derivation table, or None."""
    a = spec.annotations
    if a["api_class"] != spec.api_status:
        return f"{spec.id}: api_class differs from api_status"
    if a["readOnlyHint"] != spec.read_only:
        return f"{spec.id}: readOnlyHint differs from read_only"
    if spec.read_only and (a["destructiveHint"] or not a["idempotentHint"]):
        return f"{spec.id}: a read is non-destructive and idempotent"
    if not spec.read_only and not a["destructiveHint"]:
        return f"{spec.id}: every write is destructive"
    if derivation is not None:
        derived = derivation.get(spec.name)
        if derived is None:
            return f"{spec.id}: no derivation for this tool"
        if dict(a) != dict(derived):
            return f"{spec.id}: annotations differ from the source derivation"
    return None


def validate_catalog(
    specs: Sequence[ToolSpec],
    *,
    families: Iterable[str],
    sources: Mapping[str, str] | None = None,
    derivation: Mapping[str, Mapping[str, Any]] | None = None,
    baseline: Mapping[str, ToolSpec] | None = None,
    root: Path | None = None,
) -> None:
    """Raise :class:`CatalogError` with the first catalog-level reason that applies.

    Each reason is checked over the whole spec list before the next one:
    invalid_spec, unclassified_source, annotation_mismatch, unbumped_version,
    missing_fixture, duplicate_key, duplicate_emitted_name. No handler is imported here.

    ``sources`` maps a public name to its classified ``app/source`` pair (the baseline
    source table, meta tools ``server/local``); ``derivation`` maps a name to the
    annotations the source audit derives; ``baseline`` is the committed catalog by id
    (the unbumped-version reference); ``root`` resolves fixture paths.
    """
    frozen = frozenset(families)
    for spec in specs:
        problem = _schema_problem(spec, frozen)
        if problem:
            raise CatalogError("invalid_spec", problem)
    for spec in specs:
        expected_source = None if sources is None else sources.get(spec.name)
        if sources is not None and expected_source is None:
            raise CatalogError("unclassified_source", f"{spec.id}: no classified api source")
        if expected_source is not None and spec.api_source_id != expected_source:
            raise CatalogError(
                "unclassified_source", f"{spec.id}: api_source_id is not the classified source"
            )
        if spec.api_status != api_status_for(spec.api_source_id):
            raise CatalogError(
                "unclassified_source", f"{spec.id}: api_status does not follow its source"
            )
    for spec in specs:
        problem = _annotation_problem(spec, derivation)
        if problem:
            raise CatalogError("annotation_mismatch", problem)
    if baseline is not None:
        for spec in specs:
            old = baseline.get(spec.id)
            if old is None:
                continue
            changed = _thaw(old.input_schema) != _thaw(spec.input_schema) or _thaw(
                old.output_schema
            ) != _thaw(spec.output_schema)
            if changed and _semver(spec.version) <= _semver(old.version):
                raise CatalogError(
                    "unbumped_version", f"{spec.id}: schema changed without a version bump"
                )
    for spec in specs:
        if spec.output_schema is not None and not spec.fixtures:
            raise CatalogError("missing_fixture", f"{spec.id}: an output schema needs a fixture")
        if root is not None:
            for rel in spec.fixtures:
                if not (root / rel).is_file():
                    raise CatalogError(
                        "missing_fixture", f"{spec.id}: fixture {rel} does not exist"
                    )
    seen_keys: set[tuple[str, str]] = set()
    for spec in specs:
        if spec.key in seen_keys:
            raise CatalogError("duplicate_key", f"duplicate (family, name) key {spec.key}")
        seen_keys.add(spec.key)
    seen_names: set[str] = set()
    for spec in specs:
        if spec.name in seen_names:
            raise CatalogError(
                "duplicate_emitted_name", f"emitted name {spec.name!r} is registered twice"
            )
        seen_names.add(spec.name)


def _semver(text: str) -> tuple[int, int, int]:
    major, minor, patch = (int(p) for p in text.split("."))
    return major, minor, patch


def overlay(baseline: Sequence[ToolSpec], entries: Sequence[Mapping[str, Any]]) -> list[ToolSpec]:
    """Apply a catalog fixture's ``tool_specs`` overlay to the baseline specs.

    Each entry names a ``base`` public tool and replaces fields of that baseline spec; the
    baseline specs of every listed base are replaced by the entries (so one base listed
    twice yields two specs), unlisted baseline tools stay, and an entry that sets no
    ``handler`` gets the HandlerRef its family and name give.
    """
    by_name = {spec.name: spec for spec in baseline}
    listed = {entry["base"] for entry in entries}
    unknown = listed - by_name.keys()
    if unknown:
        raise CatalogError("invalid_spec", f"overlay names unknown base tools: {sorted(unknown)}")
    out = [spec for spec in baseline if spec.name not in listed]
    for entry in entries:
        data = by_name[entry["base"]].to_dict()
        fields = {k: v for k, v in entry.items() if k != "base"}
        data.update(fields)
        if "handler" not in fields:
            data["handler"] = handler_ref(data["family"], data["name"])
        out.append(ToolSpec.from_dict(data))
    return out
