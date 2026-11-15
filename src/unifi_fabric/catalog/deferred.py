"""Deferred tool loading (public #41): a family's step loads on its first resolution.

At import the server registers one fn-less :class:`DeferredTool` stub per tool, built from
the committed generated snapshot ``catalog/deferred.json``
(``python scripts/gen_deferred_catalog.py --generate``; ``--check`` compares). A stub carries
every field ``tools/list`` serialises, so the listing, ``describe_tool``, exposure and
read-only hiding are the same as with every step registered, and no family module is
imported until a tool of it is resolved.

The first resolution of a stubbed tool (``FabricMCP.get_tool``, which every middleware and
the call core go through, or the :class:`DeferredTool` run backstop, or the sync
``server.<name>`` attribute) loads that tool's step:

1. import the step's module and run its ``register`` on a private staging app;
2. run the per-tool install passes on the staged tools, in the server's order: resolution
   state, response redaction, titles, annotations (the real verb audit), compact
   descriptions, shapes and API sources;
3. verify every staged tool against its stub: the same names, the same wire entry and the
   same write verbs; any difference fails the step closed (``inventory_mismatch``);
4. only then mark the step loaded and swap the real tools into the live provider in place
   (a dict keeps the position of an existing key, so the ``tools/list`` order is kept).

Build, verify and the ``loaded`` transition happen in one place, a per-step single-flight
future, for every caller; a step is loaded at most once per process. A deferred write tool
therefore never runs before write policy, redaction and the audit wrappers are installed:
a stub has no ``fn``, the only path from a stub to a run is through this load, and the load
installs those wrappers on staging before anything reaches the live provider.

A failed load refuses the call with a ``family_load_failed`` :class:`DeferredLoadError`
(never ``None`` and never a ``NotFoundError``, which the write guards read as "not a
write"); other steps are unaffected. One ``family.load`` JSON line per load attempt goes to
stderr with only the fields of :data:`EVENT_FIELDS`: never arguments, messages, paths, hosts
or key labels.

The snapshot records the Python minor version, ``sys.flags.optimize`` and the fastmcp and
pydantic versions it was generated under. When the running environment differs, the server
registers every step eagerly as before (one warning line): drift costs startup time, never
availability, and the load-time comparison still protects the matching case.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import importlib
import json
import sys
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, Final

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.tools import Tool, ToolResult
from pydantic import Field
from pydantic.json_schema import SkipJsonSchema

from . import loaders

#: The committed generated snapshot.
SNAPSHOT_PATH: Final = Path(__file__).with_name("deferred.json")
SNAPSHOT_SCHEMA: Final = 1

#: The refusal code of a call whose step failed to load.
FAMILY_LOAD_FAILED: Final = "family_load_failed"

#: The event name and the exact key set of a load record.
LOAD_EVENT: Final = "family.load"
EVENT_FIELDS: Final = frozenset(
    {"event", "family", "step", "trigger", "outcome", "tools", "duration_ms", "error_type"}
)
TRIGGERS: Final = ("call", "preload", "attribute", "adapter", "all")
OUTCOMES: Final = ("loaded", "failed", "inventory_mismatch")

#: ``UNIFI_PRELOAD`` values besides ``family:<id>[,...]``.
PRELOAD_ALL: Final = "all"
PRELOAD_NONE: Final = "none"

#: The FastMCP local-provider key of an unversioned tool.
_KEY: Final = "tool:{name}@"

#: The per-tool install passes, in the server's order (names for the test that pins it).
PASS_ORDER: Final = (
    "install_resolution_state",
    "install_response_redaction",
    "install_tool_titles",
    "install_tool_annotations",
    "install_compact_selector_descriptions",
    "install_tool_shapes",
    "install_api_sources",
)


class DeferredLoadError(ToolError):
    """A call refused because its tool's step could not be loaded (``family_load_failed``).

    A ``ToolError``, never a ``NotFoundError``: the write guards that resolve a target
    treat ``NotFoundError`` and ``None`` as "not a write", so a failed load must propagate.
    """

    def __init__(self, family: str, step: str) -> None:
        super().__init__(
            json.dumps(
                {
                    "error": {
                        "code": FAMILY_LOAD_FAILED,
                        "message": (
                            f"The {family} family's tools could not be loaded (step {step}); "
                            "the server log has a family.load record. Other families are "
                            "unaffected."
                        ),
                    }
                }
            )
        )
        self.family = family
        self.step = step


class InventoryMismatch(RuntimeError):
    """A staged tool differs from its stub (names, wire entry or write verbs)."""


class DeferredTool(Tool):
    """A registered tool whose step has not been loaded: listing fields only, no ``fn``."""

    deferred_step: Annotated[SkipJsonSchema[int], Field(exclude=True)] = -1
    write_verbs: Annotated[SkipJsonSchema[frozenset[str]], Field(exclude=True)] = frozenset()

    async def _run(self, arguments: dict[str, Any]) -> ToolResult:
        return await self._backstop(arguments)

    async def run(self, arguments: dict[str, Any]) -> ToolResult:
        return await self._backstop(arguments)

    async def _backstop(self, arguments: dict[str, Any]) -> ToolResult:
        """A path that reached the stub without ``get_tool`` (hashed-name dispatch): load
        the step, re-resolve through the server's ``get_tool`` (so its transforms apply),
        and run the real tool. Never runs anything on the stub itself."""
        controller = _controller_of_step_owner(self)
        if controller is None:
            raise ToolError(f"Tool {self.name!r} is not loaded")
        await controller.resolve(self.name, trigger="call")
        real = await controller.app.get_tool(self.name)
        if real is None or isinstance(real, DeferredTool):
            raise DeferredLoadError(controller.family_of(self.name), controller.step_ref(self))
        return await real._run(arguments)  # noqa: SLF001 - the server's own entry point


@dataclass
class _Step:
    """The load state of one loader step."""

    index: int
    entry: loaders.Loader
    names: tuple[str, ...]
    exports: tuple[str, ...]
    family: str
    state: str = "unloaded"  # unloaded | loaded | failed
    future: concurrent.futures.Future[None] | None = None
    staged: dict[str, Tool] = field(default_factory=dict)
    returned: dict[str, Any] = field(default_factory=dict)
    error_type: str | None = None
    outcome: str | None = None


# --------------------------------------------------------------------------- snapshot


def environment() -> dict[str, Any]:
    """The facts that fix the wire output of a snapshot (C10/S11)."""
    import fastmcp
    import pydantic

    return {
        "python": f"{sys.version_info.major}.{sys.version_info.minor}",
        "optimize": int(sys.flags.optimize),
        "fastmcp": str(fastmcp.__version__),
        "pydantic": str(pydantic.VERSION),
    }


def read_snapshot(path: Path = SNAPSHOT_PATH) -> dict[str, Any]:
    """The parsed snapshot."""
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != SNAPSHOT_SCHEMA:
        raise RuntimeError("catalog/deferred.json has an unknown schema; regenerate it")
    return data


def _annotations(value: Mapping[str, Any] | None) -> Any:
    from mcp.types import ToolAnnotations

    return None if value is None else ToolAnnotations.model_validate(dict(value))


def stub_from_record(record: Mapping[str, Any]) -> DeferredTool:
    """A :class:`DeferredTool` from one snapshot tool record (no validation pass)."""
    return DeferredTool.model_construct(
        name=record["name"],
        version=record.get("version"),
        title=record.get("title"),
        description=record.get("description"),
        tags=set(record.get("tags") or ()),
        meta=record.get("meta"),
        parameters=record["parameters"],
        output_schema=record.get("output_schema"),
        annotations=_annotations(record.get("annotations")),
        deferred_step=int(record["step"]),
        write_verbs=frozenset(record.get("write_verbs") or ()),
    )


def wire_entry(tool: Tool) -> dict[str, Any]:
    """The ``tools/list`` entry of ``tool`` as the server serialises it (before the
    server-level ``$ref`` dereference, which applies to stub and real tool alike)."""
    entry: dict[str, Any] = tool.to_mcp_tool().model_dump(by_alias=True, exclude_none=True)
    return entry


def _default_task_config() -> Any:
    """A tool's default ``task_config`` (task support forbidden), which a stub gets."""
    factory = Tool.model_fields["task_config"].default_factory
    assert factory is not None  # noqa: S101 - FastMCP declares a factory
    return factory()  # type: ignore[call-arg]


def tool_record(tool: Tool, step: int, family: str, write_verbs: Iterable[str]) -> dict[str, Any]:
    """The snapshot record of one registered (staged) tool."""
    if tool.icons is not None or tool.execution is not None:
        raise RuntimeError(f"{tool.name}: icons/execution are set; extend the snapshot fields")
    if tool.timeout is not None:
        raise RuntimeError(f"{tool.name}: a tool timeout is set; extend the snapshot fields")
    if tool.task_config != _default_task_config():
        raise RuntimeError(f"{tool.name}: task_config is set; extend the snapshot (S10)")
    annotations = tool.annotations
    return {
        "name": tool.name,
        "step": step,
        "family": family,
        "title": tool.title,
        "description": tool.description,
        "parameters": tool.parameters,
        "output_schema": tool.output_schema,
        "annotations": None
        if annotations is None
        else annotations.model_dump(mode="json", exclude_unset=True),
        "meta": tool.meta,
        "tags": sorted(tool.tags or ()),
        "version": tool.version,
        "write_verbs": sorted(write_verbs),
    }


def render_snapshot(steps: Sequence[Mapping[str, Any]], tools: Sequence[Mapping[str, Any]]) -> str:
    """The deterministic snapshot text: one step or tool per line, so a change diffs."""

    def line(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

    parts = [
        "{",
        f'"schema":{SNAPSHOT_SCHEMA},',
        f'"environment":{line(environment())},',
        '"steps":[',
        ",\n".join(line(step) for step in steps),
        "],",
        '"tools":[',
        ",\n".join(line(tool) for tool in tools),
        "]",
        "}",
    ]
    return "\n".join(parts) + "\n"


# --------------------------------------------------------------------------- staging


class StagingMCP(FastMCP):
    """The private app a step registers on: plain FastMCP plus only the server's
    registration-time docstring rule (``FabricMCP.tool``), which changes the advertised
    description and so must apply to staged tools as it does to eagerly registered ones.
    No ``get_tool``, ``call_tool`` or transport override."""

    def __init__(self, live: Any, prepare: Callable[[Any, dict[str, Any]], Any] | None) -> None:
        super().__init__("deferred-staging")
        self._deferred_live = live
        self._prepare = prepare

    def tool(self, name_or_fn: Any = None, **kwargs: Any) -> Any:
        prepare = self._prepare
        if prepare is None:
            return super().tool(name_or_fn, **kwargs)
        if callable(name_or_fn) and not isinstance(name_or_fn, str):
            return super().tool(prepare(name_or_fn, kwargs), **kwargs)
        decorator = super().tool(name_or_fn, **kwargs)

        def register(fn: Any) -> Any:
            return decorator(prepare(fn, kwargs))

        return register


def live_app(mcp: Any) -> Any:
    """The live server of ``mcp``: itself, or the server a staging app builds for. A step's
    closure that needs the server's own catalog (the diagnostic bundle's tool count) reads
    it through this, never through the app it was registered on (C6)."""
    return getattr(mcp, "_deferred_live", mcp)


def run_passes(app: Any, should_redact: Callable[[], bool]) -> None:
    """The per-tool install passes, in the server's order (:data:`PASS_ORDER`)."""
    from ..api_sources import install_api_sources
    from ..catalog_descriptions import install_compact_selector_descriptions
    from ..redaction import install_response_redaction
    from ..resolution_state import install_resolution_state
    from ..tool_annotations import install_tool_annotations
    from ..tool_shapes import install_tool_shapes
    from ..tool_titles import install_tool_titles

    install_resolution_state(app)
    install_response_redaction(app, should_redact)
    install_tool_titles(app)
    install_tool_annotations(app)
    install_compact_selector_descriptions(app)
    install_tool_shapes(app)
    install_api_sources(app)


def stage_step(
    entry: loaders.Loader,
    *,
    live: Any,
    late: Callable[[], Any],
    bound: Callable[[], Any],
    should_redact: Callable[[], bool],
    prepare: Callable[[Any, dict[str, Any]], Any] | None,
) -> tuple[dict[str, Tool], dict[str, Any]]:
    """Register one step on a fresh staging app and run the passes on it.

    Returns the staged tools in registration order and the step's returned wrappers.
    Nothing reaches the live server.
    """
    from ..local_components import tool_components

    staging = StagingMCP(live, prepare)
    module = importlib.import_module(entry.module_path)
    returned = getattr(module, entry.function)(staging, late if entry.deps == "late" else bound)
    run_passes(staging, should_redact)
    tools = {tool.name: tool for tool in tool_components(staging)}
    return tools, dict(returned or {})


# --------------------------------------------------------------------------- controller

_CONTROLLERS: dict[int, Controller] = {}


def controller_for(app: Any) -> Controller | None:
    """The deferred-loading controller of a live server, if it defers."""
    return _CONTROLLERS.get(id(app))


def _controller_of_step_owner(tool: DeferredTool) -> Controller | None:
    for controller in _CONTROLLERS.values():
        if controller.owns(tool):
            return controller
    return None


class Controller:
    """The load state machine of one live server's deferred steps."""

    def __init__(
        self,
        app: Any,
        snapshot: Mapping[str, Any],
        *,
        late: Callable[[], Any],
        bound: Callable[[], Any],
        should_redact: Callable[[], bool],
        prepare: Callable[[Any, dict[str, Any]], Any] | None,
        loader_map: Sequence[loaders.Loader] = loaders.LOADERS,
        emit: Callable[[str], None] | None = None,
    ) -> None:
        self.app = app
        self._late = late
        self._bound = bound
        self._should_redact = should_redact
        self._prepare = prepare
        self._emit = emit
        self._lock = threading.Lock()
        self._executor: concurrent.futures.ThreadPoolExecutor | None = None
        steps_data = list(snapshot["steps"])
        if [step["ref"] for step in steps_data] != [entry.ref for entry in loader_map]:
            raise RuntimeError("catalog/deferred.json steps differ from catalog/loaders.py")
        self.records: dict[str, Mapping[str, Any]] = {
            record["name"]: record for record in snapshot["tools"]
        }
        self.order: tuple[str, ...] = tuple(record["name"] for record in snapshot["tools"])
        self.steps: list[_Step] = []
        for index, (entry, data) in enumerate(zip(loader_map, steps_data, strict=True)):
            self.steps.append(
                _Step(
                    index=index,
                    entry=entry,
                    names=tuple(data["tools"]),
                    exports=tuple(data.get("exports") or ()),
                    family=str(data.get("family") or entry.family),
                )
            )
        self._stubs: dict[str, DeferredTool] = {}
        self._exports: dict[str, int] = {}
        for step in self.steps:
            for name in step.exports:
                self._exports.setdefault(name, step.index)
        self._modules: dict[str, str] = {
            entry.module: entry.module_path
            for entry in loader_map
            if entry.module not in loaders.LAYOUT_STEMS
        }
        # ``server.<origin>`` stays the origin module while that module exists (design review
        # R-L1B C2): after a family moves its last step to ``registrar``, the origin stem
        # still names its module. Resolved on use, so nothing is imported here.
        # A step can leave its origin directory entirely (firewall_proxy). Search
        # its own directory first, then every mapped family, as origin_module does.
        self._origins: dict[str, tuple[str, ...]] = {}
        for entry in loader_map:
            if entry.origin in loaders.LAYOUT_STEMS:
                continue
            families = dict.fromkeys((entry.family, *(e.family for e in loader_map)))
            self._origins.setdefault(
                entry.origin,
                tuple(f"{loaders.FAMILIES_PACKAGE}.{family}.{entry.origin}" for family in families),
            )

    # ---- registration

    def register_stubs(self) -> int:
        """Add one stub per snapshot tool to the live provider, in snapshot order."""
        components = self.app._local_provider._components  # noqa: SLF001 - the catalog
        for name in self.order:
            stub = stub_from_record(self.records[name])
            if stub.key in components:
                raise RuntimeError(f"deferred stub {name!r} collides with a registered tool")
            self._stubs[name] = stub
            # Direct insertion, as FastMCP's _add_component does after its checks: an
            # unversioned name that is new to the map needs neither.
            components[stub.key] = stub
        return len(self._stubs)

    def owns(self, tool: DeferredTool) -> bool:
        return self._stubs.get(tool.name) is tool

    def family_of(self, name: str) -> str:
        record = self.records.get(name)
        return str(record["family"]) if record else "unknown"

    def step_ref(self, tool: DeferredTool) -> str:
        return self.steps[tool.deferred_step].entry.ref

    def stub_step(self, name: str) -> int | None:
        """The step of ``name`` when a stub of it is registered now, else None."""
        component = self.app._local_provider._components.get(_KEY.format(name=name))  # noqa: SLF001
        if isinstance(component, DeferredTool):
            return component.deferred_step
        return None

    # ---- the single-flight load

    def _claim(self, index: int) -> tuple[concurrent.futures.Future[None], bool]:
        """The step's load future and whether this caller builds it."""
        step = self.steps[index]
        with self._lock:
            if step.future is not None:
                return step.future, False
            future: concurrent.futures.Future[None] = concurrent.futures.Future()
            step.future = future
            if step.state == "loaded":
                future.set_result(None)
                return future, False
            if step.state == "failed":
                future.set_exception(DeferredLoadError(step.family, step.entry.ref))
                return future, False
            # Running from the claim on: a running future cannot be cancelled, so no
            # waiter (async or sync) can cancel the shared load for the others.
            future.set_running_or_notify_cancel()
            return future, True

    def _build(self, index: int, trigger: str) -> None:
        """Build, verify and mark one step loaded; the one place that does so."""
        step = self.steps[index]
        started = time.perf_counter()
        outcome = "loaded"
        error: BaseException | None = None
        try:
            staged, returned = stage_step(
                step.entry,
                live=self.app,
                late=self._late,
                bound=self._bound,
                should_redact=self._should_redact,
                prepare=self._prepare,
            )
            self._verify(step, staged)
        except InventoryMismatch as exc:
            outcome, error = "inventory_mismatch", exc
        except BaseException as exc:  # noqa: BLE001 - any failure fails the step closed
            outcome, error = "failed", exc
        duration_ms = round((time.perf_counter() - started) * 1000, 1)
        with self._lock:
            if error is None:
                step.staged = staged
                step.returned = returned
                step.state = "loaded"
            else:
                step.state = "failed"
                step.error_type = type(error).__name__
            step.outcome = outcome
        self._record(step, trigger, outcome, duration_ms, error)
        future = step.future
        assert future is not None  # noqa: S101 - claimed by this caller
        if error is None:
            future.set_result(None)
        else:
            future.set_exception(DeferredLoadError(step.family, step.entry.ref))

    def _verify(self, step: _Step, staged: Mapping[str, Tool]) -> None:
        """Fail closed unless the staged tools are exactly the step's stubs."""
        from .._read_only_audit import write_verbs_for

        if tuple(staged) != step.names:
            raise InventoryMismatch("names")
        for name, tool in staged.items():
            record = self.records[name]
            if wire_entry(tool) != wire_entry(stub_from_record(record)):
                raise InventoryMismatch("wire entry")
            if frozenset(write_verbs_for(tool.fn)) != frozenset(record["write_verbs"]):  # type: ignore[attr-defined]
                raise InventoryMismatch("write verbs")
            if tool.timeout is not None:
                raise InventoryMismatch("timeout")
            if tool.task_config != _default_task_config():
                raise InventoryMismatch("task_config")

    def _record(
        self,
        step: _Step,
        trigger: str,
        outcome: str,
        duration_ms: float,
        error: BaseException | None,
    ) -> None:
        record: dict[str, Any] = {
            "event": LOAD_EVENT,
            "family": step.family,
            "step": step.entry.ref,
            "trigger": trigger if trigger in TRIGGERS else "call",
            "outcome": outcome,
            "tools": len(step.names),
            "duration_ms": duration_ms,
        }
        if error is not None:
            record["error_type"] = type(error).__name__
        line = json.dumps(record, sort_keys=True, separators=(",", ":"))
        if self._emit is not None:
            self._emit(line)
        else:
            from .. import policy

            policy.emit(line)
        _trace_load(record)

    def ensure(self, index: int, trigger: str = "attribute") -> None:
        """Load step ``index`` (any thread, blocking); raise :class:`DeferredLoadError`."""
        future, owner = self._claim(index)
        if owner:
            self._build(index, trigger)
        future.result()

    async def ensure_async(self, index: int, trigger: str = "call") -> None:
        """Load step ``index`` without blocking the event loop: the build runs in a worker
        thread, and a concurrent caller awaits the same future.

        The owner submits the build before its first suspension point, so a synchronous
        caller of the same step on the event-loop thread (an adapter, ``server.<name>``)
        waits for a build that is already running instead of one that can never start.
        """
        step = self.steps[index]
        if step.state == "loaded":
            return
        future, owner = self._claim(index)
        if owner:
            self._pool().submit(self._build, index, trigger)
        # Shielded: cancelling this caller (an MCP cancellation, a dropped HTTP request)
        # cancels only its own wait, never the step's shared load that other first calls
        # and later synchronous loads of the same step wait on.
        await asyncio.shield(asyncio.wrap_future(future))

    def _pool(self) -> concurrent.futures.ThreadPoolExecutor:
        """The worker threads deferred builds run on (created on first use)."""
        with self._lock:
            if self._executor is None:
                self._executor = concurrent.futures.ThreadPoolExecutor(
                    max_workers=4, thread_name_prefix="unifi-deferred-load"
                )
            return self._executor

    # ---- swap

    def swap(self, index: int) -> int:
        """Replace every registered stub of a loaded step with its real tool, in place.

        Only a stub currently registered is replaced, so an excluded or hidden tool stays
        unregistered; a hidden stub re-added later is swapped on its next resolution.
        Runs on the caller's thread (the event loop for calls and preload).
        """
        step = self.steps[index]
        if step.state != "loaded":
            raise DeferredLoadError(step.family, step.entry.ref)
        components = self.app._local_provider._components  # noqa: SLF001 - in-place swap
        swapped = 0
        for name, tool in step.staged.items():
            key = _KEY.format(name=name)
            current = components.get(key)
            if isinstance(current, DeferredTool) and current.deferred_step == index:
                components[key] = tool
                swapped += 1
        return swapped

    async def resolve(self, name: str, trigger: str = "call") -> None:
        """Load and swap the step of ``name`` when a stub of it is registered; else no-op
        (unknown, meta, excluded or hidden names keep today's refusals)."""
        index = self.stub_step(name)
        if index is None:
            return
        await self.ensure_async(index, trigger)
        self.swap(index)

    def resolve_sync(self, name: str, trigger: str = "adapter") -> None:
        """:meth:`resolve` for a synchronous caller (the generated adapters)."""
        index = self.stub_step(name)
        if index is None:
            return
        self.ensure(index, trigger)
        self.swap(index)

    # ---- server attributes

    def attribute(self, name: str) -> Any:
        """The ``server.<name>`` re-export: a step's returned wrapper (loading the step)
        or a family module of the map (importing only that module)."""
        index = self._exports.get(name)
        if index is not None:
            self.ensure(index, "attribute")
            self.swap(index)
            return self.steps[index].returned[name]
        module_path = self._modules.get(name)
        if module_path is not None:
            return importlib.import_module(module_path)
        for origin_path in self._origins.get(name, ()):
            try:
                return importlib.import_module(origin_path)
            except ModuleNotFoundError as exc:
                if exc.name != origin_path:
                    raise
        raise AttributeError(name)

    def export_names(self) -> frozenset[str]:
        return frozenset(self._exports) | frozenset(self._modules) | frozenset(self._origins)

    # ---- policy

    def exposed_steps(self) -> list[int]:
        """Every step with at least one stub registered now, in loader order."""
        components = self.app._local_provider._components  # noqa: SLF001
        found: set[int] = set()
        for component in components.values():
            if isinstance(component, DeferredTool):
                found.add(component.deferred_step)
        return sorted(found)

    async def preload(self, value: str) -> list[int]:
        """Apply ``UNIFI_PRELOAD`` after exposure: load the exposed steps it selects.

        A step that fails to load is isolated exactly as on a first call: its failure is
        recorded (``family.load``, outcome ``failed`` or ``inventory_mismatch``), its tools
        keep their stubs and refuse with ``family_load_failed``, and every other step
        still loads and the server starts. Returns the steps that loaded.
        """
        loaded: list[int] = []
        for index in preload_steps(value, self):
            try:
                await self.ensure_async(index, "preload")
            except DeferredLoadError:
                continue
            self.swap(index)
            loaded.append(index)
        return loaded

    def load_all(self, trigger: str = "all") -> None:
        """Load every step and swap every registered stub (tests and build tools)."""
        for step in self.steps:
            self.ensure(step.index, trigger)
            self.swap(step.index)

    def state(self) -> dict[str, str]:
        """``step ref -> state`` (health and tests)."""
        return {step.entry.ref: step.state for step in self.steps}


def parse_preload(value: str | None) -> tuple[str, tuple[str, ...]]:
    """``(kind, families)`` of an ``UNIFI_PRELOAD`` value; raise ``ValueError`` if invalid."""
    from ..families import ALL_FAMILIES

    text = (value or "").strip()
    if not text or text == PRELOAD_NONE:
        return PRELOAD_NONE, ()
    if text == PRELOAD_ALL:
        return PRELOAD_ALL, ()
    if text.startswith("family:"):
        families = tuple(part.strip() for part in text[len("family:") :].split(","))
        if families and all(part in ALL_FAMILIES for part in families):
            return "family", families
    raise ValueError(
        "UNIFI_PRELOAD must be all, none or family:<id>[,<id>...] with ids from "
        + ", ".join(sorted(ALL_FAMILIES))
    )


def preload_steps(value: str, controller: Controller) -> list[int]:
    """The exposed steps an ``UNIFI_PRELOAD`` value selects, in loader order."""
    kind, families = parse_preload(value)
    exposed = controller.exposed_steps()
    if kind == PRELOAD_NONE:
        return []
    if kind == PRELOAD_ALL:
        return exposed
    wanted = set(families)
    out = []
    for index in exposed:
        step = controller.steps[index]
        if any(controller.records[name]["family"] in wanted for name in step.names):
            out.append(index)
    return out


def _trace_load(record: Mapping[str, Any]) -> None:
    """The same fields on a ``family.load`` span when trace export is on (best effort)."""
    try:
        from opentelemetry import trace
    except ImportError:  # pragma: no cover - tracing is optional
        return
    try:
        tracer = trace.get_tracer("unifi_fabric.deferred")
        with tracer.start_as_current_span(LOAD_EVENT) as span:
            for key, value in record.items():
                if key != "event":
                    span.set_attribute(f"unifi.{key}", value)
    except Exception:  # noqa: BLE001, S110 - telemetry never breaks a load
        pass


# --------------------------------------------------------------------------- install


def install(
    app: Any,
    *,
    late: Callable[[], Any],
    bound: Callable[[], Any],
    should_redact: Callable[[], bool],
    prepare: Callable[[Any, dict[str, Any]], Any] | None,
    snapshot_path: Path = SNAPSHOT_PATH,
) -> dict[str, Any]:
    """Register the server's tools: stubs from the snapshot, or every step eagerly.

    Returns the module names the server binds now: empty when deferring (the server's
    ``__getattr__`` resolves re-exports on use), every step's re-exports when eager.
    Eager, with one warning, when the snapshot is missing, was generated under another
    environment (S11) or no longer matches the loader map: drift costs startup time, never
    availability.
    """
    try:
        snapshot = read_snapshot(snapshot_path)
    except (OSError, ValueError, RuntimeError):
        snapshot = None
    reason = None
    if snapshot is None:
        reason = "catalog/deferred.json is missing or unreadable"
    elif snapshot.get("environment") != environment():
        reason = (
            "catalog/deferred.json was generated for another Python, fastmcp or pydantic version"
        )
    elif [step.get("ref") for step in snapshot.get("steps", ())] != list(loaders.refs()):
        reason = "catalog/deferred.json does not match catalog/loaders.py (regenerate it)"
    if reason is None:
        assert snapshot is not None  # noqa: S101 - narrowed above
        controller = Controller(
            app, snapshot, late=late, bound=bound, should_redact=should_redact, prepare=prepare
        )
        _CONTROLLERS[id(app)] = controller
        controller.register_stubs()
        return {}
    print(
        f"unifi-fabric: {reason}; every tool family loads at startup", file=sys.stderr, flush=True
    )
    names = loaders.load(app, late=late, bound=bound)
    run_passes(app, should_redact)
    return names


def load_all(app: Any) -> None:
    """Load every deferred step of ``app`` (no-op when it registered eagerly)."""
    controller = controller_for(app)
    if controller is not None:
        controller.load_all()


def write_names(tools: Iterable[Any]) -> set[str]:
    """The write tools among ``tools``: a stub's snapshot write verbs (generated from the
    real audit and re-checked when its step loads), the real audit for a loaded tool."""
    from .._read_only_audit import derive_write_tools

    stubs = [tool for tool in tools if isinstance(tool, DeferredTool)]
    loaded = [tool for tool in tools if not isinstance(tool, DeferredTool)]
    names = {tool.name for tool in stubs if tool.write_verbs}
    names |= derive_write_tools(loaded)
    return names
