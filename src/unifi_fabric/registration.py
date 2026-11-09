"""The registration interface: ToolSpec, HandlerRef and register_tool.

``register_tool(spec, *, dependencies)`` is the sole registration path. A spec's
HandlerRef names ``unifi_fabric._generated.adapters.<family>:<name>``,
the committed generated adapter for that tool (meta tools use ``adapters.meta``). The
adapter is the declared async handler::

    async def handler(request_context: RequestContext,
                      validated_arguments: Mapping[str, Any],
                      dependencies: Dependencies) -> Any

and the emitted MCP name is exactly ``spec.name``; ``spec.id`` is never a registration
key.

Catalog validation runs in a fixed order and returns the first reason that applies, as
``startup:catalog:<reason>``:

1. the whole catalog, before any handler import: ``invalid_spec``,
   ``unclassified_source``, ``annotation_mismatch``, ``unbumped_version``,
   ``missing_fixture``, ``duplicate_key``, ``duplicate_emitted_name``;
2. then each handler is imported: ``missing_handler``, ``invalid_signature``;
3. only then is anything registered.

The registrar implements ``invalid_spec``, ``missing_fixture``, ``duplicate_key``,
``duplicate_emitted_name``, ``missing_handler`` and ``invalid_signature``. The
``unclassified_source``, ``annotation_mismatch`` and ``unbumped_version`` checks need the
typed catalog, the source table and the staleness record, which the catalog supplies through
``CatalogChecks``; with none supplied those reasons do not apply.

How a bound handler becomes an MCP tool (the FastMCP wiring) is the server's: a
:class:`ToolRegistrar` receives the validated spec and its :class:`BoundHandler` through
its ``sink``.
"""

from __future__ import annotations

import importlib
import inspect
import re
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from .contracts import META_FAMILY_ID, Dependencies, RequestContext

__all__ = [
    "ADAPTER_PACKAGE",
    "API_STATUSES",
    "CATALOG_REASONS",
    "PRE_IMPORT_REASONS",
    "BoundHandler",
    "CatalogChecks",
    "CatalogError",
    "HandlerRef",
    "ToolRegistrar",
    "ToolSpec",
    "adapter_module_for",
    "validate_catalog",
]

ADAPTER_PACKAGE = "unifi_fabric._generated.adapters"
API_STATUSES = frozenset({"official", "unofficial", "local"})
ID_PATTERN = re.compile(r"[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*")
_NAME_PATTERN = re.compile(r"[a-z][a-z0-9_]*")
_HANDLER_PARAMS = ("request_context", "validated_arguments", "dependencies")

CatalogReason = Literal[
    "invalid_spec",
    "unclassified_source",
    "annotation_mismatch",
    "unbumped_version",
    "missing_fixture",
    "duplicate_key",
    "duplicate_emitted_name",
    "missing_handler",
    "invalid_signature",
]
#: Checked over the whole catalog, in this order, before any handler import.
PRE_IMPORT_REASONS: tuple[CatalogReason, ...] = (
    "invalid_spec",
    "unclassified_source",
    "annotation_mismatch",
    "unbumped_version",
    "missing_fixture",
    "duplicate_key",
    "duplicate_emitted_name",
)
#: Every catalog reason, in evaluation order.
CATALOG_REASONS: tuple[CatalogReason, ...] = (
    *PRE_IMPORT_REASONS,
    "missing_handler",
    "invalid_signature",
)

Handler = Callable[[RequestContext, Mapping[str, Any], Dependencies], Awaitable[Any]]


class CatalogError(RuntimeError):
    """A catalog failure; ``token`` is the ``startup:catalog:<reason>`` startup token."""

    def __init__(self, reason: CatalogReason, detail: str) -> None:
        self.reason: CatalogReason = reason
        self.token = f"startup:catalog:{reason}"
        super().__init__(f"{self.token}: {detail}")


def adapter_module_for(family_id: str) -> str:
    """The generated adapter module for ``family_id`` (``meta`` uses ``adapters.meta``)."""
    return f"{ADAPTER_PACKAGE}.{family_id}"


@dataclass(frozen=True, slots=True)
class HandlerRef:
    """A ``"<module>:<symbol>"`` reference to a generated adapter."""

    module: str
    symbol: str

    @classmethod
    def parse(cls, text: str) -> HandlerRef:
        module, sep, symbol = text.partition(":")
        if not sep or not module or not symbol or ":" in symbol:
            raise ValueError(f"HandlerRef must be '<module>:<symbol>', got {text!r}")
        return cls(module=module, symbol=symbol)

    def __str__(self) -> str:
        return f"{self.module}:{self.symbol}"


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """One catalog row. ``id`` is ``<family>.<name>``; ``name`` is the public name."""

    id: str
    name: str
    family: str
    family_id: str
    api_source_id: str
    api_status: str
    read_only: bool
    description: str
    input_schema: Mapping[str, Any]
    output_schema: Mapping[str, Any] | None
    version: str
    fixtures: tuple[str, ...]
    handler: str
    annotations: Mapping[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> tuple[str, str]:
        """The (family, name) catalog key."""
        return (self.family_id, self.name)

    @property
    def handler_ref(self) -> HandlerRef:
        return HandlerRef.parse(self.handler)


@dataclass(frozen=True, slots=True)
class CatalogChecks:
    """The catalog-level predicates. Each returns a detail string when it fails."""

    unclassified_source: Callable[[Sequence[ToolSpec]], str | None] | None = None
    annotation_mismatch: Callable[[Sequence[ToolSpec]], str | None] | None = None
    unbumped_version: Callable[[Sequence[ToolSpec]], str | None] | None = None


def _invalid_spec(spec: ToolSpec) -> str | None:
    if not isinstance(spec.id, str) or not ID_PATTERN.fullmatch(spec.id):
        return f"id {spec.id!r} is not <family>.<name>"
    if not isinstance(spec.name, str) or not _NAME_PATTERN.fullmatch(spec.name):
        return f"{spec.id}: name {spec.name!r} is invalid"
    if spec.family != spec.family_id:
        return f"{spec.id}: family {spec.family!r} differs from family_id {spec.family_id!r}"
    if spec.id != f"{spec.family_id}.{spec.name}":
        return f"{spec.id}: id is not {spec.family_id}.{spec.name}"
    if spec.api_status not in API_STATUSES:
        return f"{spec.id}: api_status {spec.api_status!r} is invalid"
    if not isinstance(spec.read_only, bool):
        return f"{spec.id}: read_only must be a boolean"
    if not isinstance(spec.description, str) or not spec.description.strip():
        return f"{spec.id}: description is empty"
    if not isinstance(spec.input_schema, Mapping):
        return f"{spec.id}: input_schema must be an object"
    if spec.output_schema is not None and not isinstance(spec.output_schema, Mapping):
        return f"{spec.id}: output_schema must be an object or null"
    if not isinstance(spec.version, str) or not spec.version:
        return f"{spec.id}: version is empty"
    if not isinstance(spec.fixtures, tuple) or not all(
        isinstance(p, str) and p for p in spec.fixtures
    ):
        return f"{spec.id}: fixtures must be a tuple of paths"
    try:
        ref = spec.handler_ref
    except (ValueError, AttributeError, TypeError):
        return f"{spec.id}: handler {spec.handler!r} is not a HandlerRef"
    if ref.module != adapter_module_for(spec.family_id):
        return f"{spec.id}: handler module {ref.module} is outside {spec.family_id}'s adapters"
    return None


def _missing_fixture(specs: Sequence[ToolSpec], root: Path | None) -> str | None:
    for spec in specs:
        if spec.output_schema is not None and not spec.fixtures:
            return f"{spec.id}: a tool with an output_schema lists no fixture"
        if root is not None:
            for rel in spec.fixtures:
                if not (root / rel).is_file():
                    return f"{spec.id}: fixture {rel} does not exist"
    return None


def _duplicate_key(specs: Sequence[ToolSpec]) -> str | None:
    seen: set[tuple[str, str]] = set()
    for spec in specs:
        if spec.key in seen:
            return f"duplicate (family, name) key {spec.key}"
        seen.add(spec.key)
    return None


def _duplicate_emitted_name(specs: Sequence[ToolSpec]) -> str | None:
    owner: dict[str, str] = {}
    for spec in specs:
        if spec.name in owner:
            return f"{spec.name} is emitted by {owner[spec.name]} and {spec.id}"
        owner[spec.name] = spec.id
    return None


def _resolve(spec: ToolSpec) -> object:
    ref = spec.handler_ref
    try:
        module = importlib.import_module(ref.module)
    except ImportError as exc:
        raise CatalogError("missing_handler", f"{spec.id}: cannot import {ref.module}") from exc
    if ref.symbol != spec.name:
        raise CatalogError("missing_handler", f"{spec.id}: {ref} does not name {spec.name}")
    handler = getattr(module, ref.symbol, None)
    if handler is None:
        raise CatalogError("missing_handler", f"{spec.id}: {ref} is not defined")
    return handler


def _check_signature(spec: ToolSpec, handler: object) -> Handler:
    if not inspect.iscoroutinefunction(handler):
        raise CatalogError("invalid_signature", f"{spec.id}: the handler is not async")
    try:
        params = list(inspect.signature(handler).parameters.values())
    except (TypeError, ValueError) as exc:
        raise CatalogError("invalid_signature", f"{spec.id}: no signature") from exc
    positional = (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    if (
        len(params) != len(_HANDLER_PARAMS)
        or tuple(p.name for p in params) != _HANDLER_PARAMS
        or any(p.kind not in positional or p.default is not p.empty for p in params)
    ):
        raise CatalogError(
            "invalid_signature",
            f"{spec.id}: the handler must be async handler(request_context, "
            "validated_arguments, dependencies)",
        )
    return handler  # type: ignore[return-value]


def validate_catalog(
    specs: Sequence[ToolSpec],
    *,
    checks: CatalogChecks | None = None,
    fixture_root: Path | None = None,
    existing: Sequence[ToolSpec] = (),
) -> dict[str, Handler]:
    """Validate ``specs`` in the fixed order; return each new name's handler.

    ``existing`` holds already-validated, registered specs: they count for the
    duplicate_key and duplicate_emitted_name checks only. Raises :class:`CatalogError`
    with the first reason that applies. Nothing is imported before the seven pre-import
    checks pass.
    """
    checks = checks or CatalogChecks()
    for spec in specs:
        detail = _invalid_spec(spec)
        if detail:
            raise CatalogError("invalid_spec", detail)
    ordered: Iterable[tuple[CatalogReason, Callable[[], str | None]]] = (
        (
            "unclassified_source",
            lambda: checks.unclassified_source and checks.unclassified_source(specs),
        ),
        (
            "annotation_mismatch",
            lambda: checks.annotation_mismatch and checks.annotation_mismatch(specs),
        ),
        ("unbumped_version", lambda: checks.unbumped_version and checks.unbumped_version(specs)),
        ("missing_fixture", lambda: _missing_fixture(specs, fixture_root)),
        ("duplicate_key", lambda: _duplicate_key([*existing, *specs])),
        ("duplicate_emitted_name", lambda: _duplicate_emitted_name([*existing, *specs])),
    )
    for reason, check in ordered:
        detail = check()
        if detail:
            raise CatalogError(reason, detail)
    resolved = {spec.name: _resolve(spec) for spec in specs}
    return {spec.name: _check_signature(spec, resolved[spec.name]) for spec in specs}


@dataclass(frozen=True, slots=True)
class BoundHandler:
    """A validated adapter bound to its spec and dependencies provider."""

    spec: ToolSpec
    handler: Handler
    dependencies: Callable[[], Dependencies]

    async def __call__(
        self, request_context: RequestContext, validated_arguments: Mapping[str, Any]
    ) -> Any:
        """Run the adapter; the provider raises ``_require``'s error when uninitialized."""
        return await self.handler(request_context, validated_arguments, self.dependencies())


class ToolRegistrar:
    """Owns the emitted-name space and hands each validated tool to ``sink``.

    ``sink(spec, bound)`` performs the transport registration under the name
    ``spec.name`` (the server supplies the FastMCP sink).
    """

    def __init__(
        self,
        sink: Callable[[ToolSpec, BoundHandler], None],
        *,
        checks: CatalogChecks | None = None,
        fixture_root: Path | None = None,
    ) -> None:
        self._sink = sink
        self._checks = checks
        self._fixture_root = fixture_root
        self._registered: dict[str, ToolSpec] = {}

    @property
    def registered_names(self) -> list[str]:
        return sorted(self._registered)

    def register_tool(
        self, spec: ToolSpec, *, dependencies: Callable[[], Dependencies]
    ) -> BoundHandler:
        """Register one tool: validate it against what is registered, then emit it."""
        handlers = self._validate([spec])
        return self._emit(spec, handlers[spec.name], dependencies)

    def register_catalog(
        self, specs: Sequence[ToolSpec], *, dependencies: Callable[[], Dependencies]
    ) -> list[str]:
        """Validate the whole catalog once, then register every spec in order.

        On any failure nothing is registered (``registered == 0``).
        """
        handlers = self._validate(specs)
        for spec in specs:
            self._emit(spec, handlers[spec.name], dependencies)
        return self.registered_names

    def _validate(self, specs: Sequence[ToolSpec]) -> dict[str, Handler]:
        return validate_catalog(
            specs,
            checks=self._checks,
            fixture_root=self._fixture_root,
            existing=tuple(self._registered.values()),
        )

    def _emit(
        self, spec: ToolSpec, handler: Handler, dependencies: Callable[[], Dependencies]
    ) -> BoundHandler:
        bound = BoundHandler(spec=spec, handler=handler, dependencies=dependencies)
        self._sink(spec, bound)
        self._registered[spec.name] = spec
        return bound


def is_meta(spec: ToolSpec) -> bool:
    """Whether ``spec`` is one of the reserved meta family's tools."""
    return spec.family_id == META_FAMILY_ID
