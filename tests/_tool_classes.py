"""Chokepoint classes and batched catalog runs.

The collected item count of a catalog-wide property is bounded without sampling it away:

* ``tool_batches(argnames, thunk)`` -- a per-tool property. ONE collected item per
  ``(area, read/write)`` batch (at most ``MAX_BATCH`` tools); the item runs the unchanged
  test body for EVERY tool (or case tuple) of the batch, with a fresh ``monkeypatch`` /
  ``tmp_path`` and fresh server singletons per tool, exactly as separate items would get,
  and fails listing every failing tool (``FAILED-TOOL <tool>: ...``).
* ``tool_batches(..., member=pred, eligible=pred)`` -- behaviour-derived membership
  and applicability are resolved against the fake upstream before batching. Only
  eligible members are collected, and every selected member reports its own outcome.
* ``class_axis(argname, thunk, axis=...)`` -- a per-tool property with harness axes
  (statuses, bodies, shapes, ttl, scenarios): every axis value for every tool, one item
  per axis value per batch of ``AXIS_BATCH`` tools.

The chokepoint class of a tool is ``(area, read/write, envelope kind)``: ``area`` is the
public tool family (``unifi_fabric.families``), the envelope kind the ``tools/``
sub-module whose client wrapper and result envelope the tool uses.
``assert_covers_every_tool`` is the membership proof that every tool of a set maps to
exactly one batch and one class with a representative (``representatives``).

Catalog sets are built on first use (``tests/_tool_catalog``), never at import.
"""

from __future__ import annotations

import ast
import asyncio
import functools
import inspect
import itertools
import os
import traceback
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

import pytest
from _pytest.outcomes import Failed, Skipped, XFailed

from tests import _selection_cache, _tool_catalog
from tests._tool_catalog import LazyIds, lazy_parametrize

# A batch (one collected item) carries at most this many tools, bounding the state
# retained by one item while preserving complete tool coverage.
MAX_BATCH = int(os.environ.get("UNIFI_TEST_MAX_BATCH", "48"))
# Candidates of a behaviour-derived set (most are not members, so cheap to run past).
DERIVED_BATCH = int(os.environ.get("UNIFI_TEST_DERIVED_BATCH", "200"))
# Tools per item of an axis test (every axis value runs for every tool).
AXIS_BATCH = int(os.environ.get("UNIFI_TEST_AXIS_BATCH", "100"))


@functools.cache
def tool_module_paths() -> list[Path]:
    """Every family handler and shared helper module (was ``tools/*.py``)."""
    pkg = Path(__file__).resolve().parents[1] / "src" / "unifi_fabric"
    found = [*(pkg / "families").rglob("*.py"), *(pkg / "shared_shapes").glob("*.py")]
    return sorted(p for p in found if p.name != "__init__.py")


def tool_module_names() -> list[str]:
    """Dotted names of :func:`tool_module_paths`."""
    root = Path(__file__).resolve().parents[1] / "src"
    parts = [p.relative_to(root).with_suffix("").parts for p in tool_module_paths()]
    return [".".join(part) for part in parts]


def tool_module_name(stem: str) -> str:
    """Dotted name of the moved module whose basename is ``stem``."""
    return next(n for n in tool_module_names() if n.rsplit(".", 1)[1] == stem)


def module_index() -> dict[str, str]:
    """``tool name -> tools/ sub-module``, statically from source (the reference the fast
    runtime classification is checked against in ``tests/test_tool_classes.py``)."""
    from unifi_fabric import families as fam

    pkg = Path(fam.__file__).parent.parent
    index: dict[str, str] = {}
    server_tree = ast.parse((pkg / "server.py").read_text())
    for node in server_tree.body:
        if isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef) and any(
            fam._is_tool_decorator(d) for d in node.decorator_list
        ):
            refs = fam._module_refs(node)
            index[fam._tool_name(node)] = refs[0] if refs else "server"
    for mod in fam._REGISTER_MODULES:
        tree = ast.parse((pkg / fam._module_rel(mod)).read_text())
        for reg in ast.walk(tree):
            if isinstance(reg, ast.FunctionDef) and fam._REGISTER_FUNCTION_RE.fullmatch(reg.name):
                for sub in ast.walk(reg):
                    if isinstance(sub, ast.AsyncFunctionDef | ast.FunctionDef) and any(
                        fam._is_tool_decorator(d) for d in sub.decorator_list
                    ):
                        index[fam._tool_name(sub)] = mod
    return index


@functools.cache
def runtime_module_index() -> dict[str, str]:
    """The same classification from the registered functions (no source parsing): the
    module defining the tool function, or, for a ``server.py`` inline wrapper, the first
    ``tools/`` sub-module its body references."""
    from unifi_fabric import families as fam

    out: dict[str, str] = {}
    for tool in _tool_catalog._build():
        fn = inspect.unwrap(tool.fn)
        mod = fn.__module__.rsplit(".", 1)[-1]
        if mod == "server":
            refs = [n for n in fn.__code__.co_names if n in fam.MODULE_FAMILY]
            mod = refs[0] if refs else "server"
        out[tool.name] = mod
    return out


def area(name: str) -> str:
    from unifi_fabric import families as fam

    return fam.build_family_index().get(name, "unclassified")


def rw(name: str) -> str:
    return "read" if _tool_catalog.is_read(_tool_catalog._by_name()[name]) else "write"


def envelope_kind(name: str) -> str:
    return runtime_module_index().get(name, "unclassified")


def class_of(name: str) -> tuple[str, str, str]:
    """The chokepoint class ``(area, read/write, envelope kind)`` of a tool."""
    return (area(name), rw(name), envelope_kind(name))


def batch_key(name: str) -> tuple[str, str]:
    return (area(name), rw(name))


class ToolBatch:
    """The tools one collected item runs (``names``), and its id."""

    __slots__ = ("id", "names")

    def __init__(self, id_: str, names: tuple[str, ...]) -> None:
        self.id = id_
        self.names = names

    def __repr__(self) -> str:
        return f"ToolBatch({self.id}, {len(self.names)} tools)"


def _chunks(key: tuple[str, ...], names: list[str], bound: int = 0) -> list[ToolBatch]:
    if not names:
        return []
    bound = bound or MAX_BATCH
    base = "-".join(key)
    if len(names) <= bound:
        return [ToolBatch(base, tuple(names))]
    n = -(-len(names) // bound)
    size = -(-len(names) // n)
    return [
        ToolBatch(f"{base}-{i + 1}of{n}", tuple(names[i * size : (i + 1) * size])) for i in range(n)
    ]


def tool_of(entry: Any) -> str:
    """The tool an entry names: the entry itself, or the first field of a case tuple."""
    return entry if isinstance(entry, str) else entry[0]


def _ordered(entries: Iterable[Any]) -> list[Any]:
    entries = list(entries)
    if all(isinstance(e, str) for e in entries):
        entries = list(dict.fromkeys(entries))
    return sorted(entries, key=tool_of)  # stable: case order within a tool is kept


def batches(names: Iterable[Any], bound: int = 0) -> list[ToolBatch]:
    """Every entry (a tool name, or a case tuple whose first field is the tool), grouped
    by ``(area, read/write)`` of its tool, in sorted order; nothing dropped."""
    groups: dict[tuple[str, str], list[Any]] = {}
    for entry in _ordered(names):
        groups.setdefault(batch_key(tool_of(entry)), []).append(entry)
    out: list[ToolBatch] = []
    for key in sorted(groups):
        out += _chunks(key, groups[key], bound)
    return out


def representatives(names: Iterable[str]) -> dict[tuple[str, str, str], str]:
    """One representative (the first by name) per chokepoint class present in ``names``."""
    reps: dict[tuple[str, str, str], str] = {}
    for name in sorted(set(names)):
        reps.setdefault(class_of(name), name)
    return reps


def representative_batches(names: Iterable[str]) -> list[ToolBatch]:
    """The class representatives of ``names``, one batch per read/write side."""
    groups: dict[str, list[str]] = {}
    for name in sorted(representatives(names).values()):
        groups.setdefault(rw(name), []).append(name)
    out: list[ToolBatch] = []
    for key in sorted(groups):
        out += _chunks(("classes", key), groups[key])
    return out


def assert_covers_every_tool(names: Iterable[str]) -> None:
    """Membership proof for a derived set: every tool is in exactly one batch, maps to a
    class, and that class has a representative that is itself in the set."""
    names = sorted(set(names))
    assert names, "derived tool set is empty"
    seen: list[str] = [n for b in batches(names) for n in b.names]
    assert sorted(seen) == names, "a tool is missing from, or repeated in, the batches"
    reps = representatives(names)
    for name in names:
        cls = class_of(name)
        assert cls in reps, f"{name}: class {cls} has no representative"
        assert class_of(reps[cls]) == cls and reps[cls] in names
    rep_seen = [n for b in representative_batches(names) for n in b.names]
    assert sorted(rep_seen) == sorted(reps.values())


# ------------------------------------------------------------------ batched execution
def _reset_server_state() -> dict[str, Any]:
    from unifi_fabric import server

    # Fixtures may already have installed a fake client and registry. Preserve
    # that baseline rather than discarding the fixture before the first tool.
    return {
        name: getattr(server, name)
        for name in ("mcp", "_mcp_transport", "_cache_ttl", "_settings", "_client", "_registry")
    }


def _restore_server_state(state: dict[str, Any]) -> None:
    from unifi_fabric import server

    for name, value in state.items():
        setattr(server, name, value)


def _isolated_kwargs(
    kwargs: dict[str, Any], argnames: tuple[str, ...], entry: Any, i: int, mp: Any
):
    out = dict(kwargs)
    if len(argnames) == 1:
        out[argnames[0]] = entry
    else:
        out.update(zip(argnames, entry, strict=True))
    if "monkeypatch" in out:
        out["monkeypatch"] = mp
    if "tmp_path" in out:
        sub = out["tmp_path"] / f"tool{i:03d}"
        sub.mkdir()
        out["tmp_path"] = sub
    if "caplog" in out:
        out["caplog"].clear()
    if "captured_logs" in out and isinstance(getattr(out["captured_logs"], "lines", None), list):
        out["captured_logs"].lines.clear()
    return out


def _summary(exc: BaseException) -> str:
    text = str(exc).strip().splitlines()
    head = text[0] if text else type(exc).__name__
    return f"{type(exc).__name__}: {head[:300]}"


def _report(
    test: str, names: tuple[str, ...], outcomes: list[tuple[str, str, Any]], request=None
) -> None:
    assert len(outcomes) == len(names), f"{test}: not every eligible member ran"
    lines = [f"{kind.upper()}-TOOL {name}: {detail[0]}" for name, kind, detail in outcomes]
    if request is not None:
        request.node.user_properties.extend(
            ("tool_outcome", f"{name}: {kind}") for name, kind, _ in outcomes
        )
    print("\n".join(lines))
    failed = [(n, *detail) for n, kind, detail in outcomes if kind != "passed"]
    if failed:
        lines.insert(0, f"{test}: {len(failed)} of {len(names)} tools failed")
        lines += ["", f"first failure ({failed[0][0]}):", failed[0][2]]
        pytest.fail("\n".join(lines), pytrace=False)


def _record(outcomes: list, name: str, exc: BaseException) -> None:
    # A selected member must exercise its property. Runtime skips/xfails are failures,
    # even when other members of the batch pass; applicability belongs in selection.
    tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)[-12:])
    outcomes.append((name, "failed", (_summary(exc), tb)))


def _argnames(argnames: str | tuple[str, ...] | list[str]) -> tuple[str, ...]:
    if isinstance(argnames, str):
        return tuple(a.strip() for a in argnames.split(","))
    return tuple(argnames)


def _select_entries(entries, member=None, eligible=None, argnames=("name",), axes=None):
    if member is None and eligible is None:
        return list(entries)
    entries = list(entries)
    # Collection-time selections are cached per code fingerprint (tests/_selection_cache).
    cache_key = (
        _selection_cache.key(entries, member, eligible, argnames, axes)
        if _tool_catalog.GENERATING
        else None
    )
    if cache_key is not None:
        hit = _selection_cache.get(cache_key, len(entries))
        if hit is not None:
            return [entries[i] for i in hit]

    async def select():
        selected = []
        for i, entry in enumerate(entries):
            state = _reset_server_state()
            mp = pytest.MonkeyPatch()
            try:
                if member is not None:
                    ok = member(tool_of(entry))
                    if inspect.isawaitable(ok):
                        ok = await ok
                    if not ok:
                        continue
                if eligible is not None:
                    values = (
                        {argnames[0]: entry}
                        if len(argnames) == 1
                        else dict(zip(argnames, entry, strict=True))
                    )
                    values.update(axes or {})
                    values["monkeypatch"] = mp
                    params = inspect.signature(eligible).parameters
                    ok = eligible(**{key: values[key] for key in params})
                    if inspect.isawaitable(ok):
                        ok = await ok
                    if not ok:
                        continue
                selected.append(i)
            except (Exception, Failed, Skipped, XFailed) as exc:
                raise AssertionError(
                    f"{tool_of(entry)}: applicability baseline failed: {_summary(exc)}"
                ) from exc
            finally:
                mp.undo()
                _restore_server_state(state)
        return selected

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        result = asyncio.run(select())
    else:
        # Tests also exercise the selector while an event loop is already running.
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(1) as pool:
            result = pool.submit(asyncio.run, select()).result()
    if cache_key is not None:
        _selection_cache.put(cache_key, len(entries), result)
    return [entries[i] for i in result]


def _run_each(
    fn: Callable[..., Any],
    argnames: str | tuple[str, ...],
    member: Callable[[str], Any] | None = None,
) -> Callable[..., Any]:
    """Wrap ``fn(argname=<tool name>, ...)`` to take a ``ToolBatch`` and run every tool.

    Decorators pass already-filtered batches. A selected member must produce a
    passing outcome; an unexpected skip or exclusion fails the batch.
    """

    names = _argnames(argnames)

    def _excluded(outcomes: list, name: Any, ok: Any) -> bool:
        if not ok:
            outcomes.append((name, "excluded", ("", "")))
            return True
        return False

    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def run(**kwargs: Any) -> None:
            request = kwargs.pop("request", None)
            batch: ToolBatch = kwargs[names[0]]
            outcomes: list[tuple[str, str, Any]] = []
            for i, name in enumerate(batch.names):
                state = _reset_server_state()
                mp = pytest.MonkeyPatch()
                try:
                    if member is not None:
                        ok = member(tool_of(name))
                        if inspect.isawaitable(ok):
                            ok = await ok
                        if _excluded(outcomes, name, ok):
                            continue
                    await fn(**_isolated_kwargs(kwargs, names, name, i, mp))
                    outcomes.append((name, "passed", ("", "")))
                except (Exception, Failed, Skipped, XFailed) as exc:
                    _record(outcomes, name, exc)
                finally:
                    mp.undo()
                    _restore_server_state(state)
            _report(fn.__name__, batch.names, outcomes, request)

    else:

        @functools.wraps(fn)
        def run(**kwargs: Any) -> None:
            request = kwargs.pop("request", None)
            batch: ToolBatch = kwargs[names[0]]
            outcomes: list[tuple[str, str, Any]] = []
            for i, name in enumerate(batch.names):
                state = _reset_server_state()
                mp = pytest.MonkeyPatch()
                try:
                    if member is not None and _excluded(outcomes, name, member(tool_of(name))):
                        continue
                    fn(**_isolated_kwargs(kwargs, names, name, i, mp))
                    outcomes.append((name, "passed", ("", "")))
                except (Exception, Failed, Skipped, XFailed) as exc:
                    _record(outcomes, name, exc)
                finally:
                    mp.undo()
                    _restore_server_state(state)
            _report(fn.__name__, batch.names, outcomes, request)

    signature = inspect.signature(fn)
    if "request" not in signature.parameters:
        run.__signature__ = signature.replace(
            parameters=[
                *signature.parameters.values(),
                inspect.Parameter("request", inspect.Parameter.KEYWORD_ONLY),
            ]
        )
    return run


def _ids(make: Callable[[], list[ToolBatch]]) -> LazyIds:
    return LazyIds(lambda: [b.id for b in make()])


def coarse_batches(names: Iterable[Any], bound: int = 0) -> list[ToolBatch]:
    """Candidates of a behaviour-derived set: one batch per read/write side (chunked)."""
    groups: dict[str, list[Any]] = {}
    for entry in _ordered(names):
        groups.setdefault(rw(tool_of(entry)), []).append(entry)
    out: list[ToolBatch] = []
    for key in sorted(groups):
        out += _chunks(("derived", key), groups[key], bound or DERIVED_BATCH)
    return out


def _batched(argnames: str | tuple[str, ...], make: Callable[[], list[ToolBatch]], fn, member):
    names = _argnames(argnames)
    run = _run_each(fn, names, member)
    if len(names) == 1:
        return lazy_parametrize(names[0], make, ids=_ids(make))(run)
    # Case tuples: the batch rides the first argname; the others are filled per case.
    rows = functools.cache(lambda: [(b, *([None] * (len(names) - 1))) for b in make()])
    return lazy_parametrize(list(names), rows, ids=_ids(make))(run)


def tool_batches(
    argnames: str | tuple[str, ...],
    thunk: Callable[[], Iterable[Any]],
    member: Callable[[str], Any] | None = None,
    max_batch: int = 0,
    *,
    eligible=None,
):
    """Per-tool property, every tool run: one collected item per ``(area, rw)`` batch.

    ``argnames`` is ``"name"`` (``thunk`` yields tool names) or a tuple such as
    ``("name", "arg")`` (``thunk`` yields case tuples whose first field is the tool).
    ``member(tool)`` selects a behaviour-derived set; ``eligible`` receives the case
    arguments and filters inapplicable properties. Both run in isolated fake-upstream
    state before batching. Every eligible member runs and reports its outcome.
    """

    def deco(fn):
        def selected():
            entries = _select_entries(thunk(), member, eligible, _argnames(argnames))
            return (batches if member is None else coarse_batches)(entries, max_batch)

        make = functools.cache(selected)
        return _batched(argnames, make, fn, None)

    return deco


def class_representatives(argname: str, thunk: Callable[[], Iterable[str]]):
    """Harness axis: one representative per ``(area, rw, envelope kind)`` class."""

    def deco(fn):
        make = functools.cache(lambda: representative_batches(thunk()))
        return _batched(argname, make, fn, None)

    return deco


def axis_batches(names: Iterable[Any], bound: int = 0) -> list[ToolBatch]:
    """Tools of an axis test: one batch per read/write side, chunked by ``AXIS_BATCH``."""
    groups: dict[str, list[Any]] = {}
    for entry in _ordered(names):
        groups.setdefault(rw(tool_of(entry)), []).append(entry)
    out: list[ToolBatch] = []
    for key in sorted(groups):
        out += _chunks(("axis", key), groups[key], bound or AXIS_BATCH)
    return out


def class_axis(
    argname: str | tuple[str, ...],
    thunk: Callable[[], Iterable[Any]],
    member: Callable[[str], Any] | None = None,
    *,
    max_batch: int = 0,
    eligible=None,
    **axes: Callable[[], Iterable[Any]],
):
    """A per-tool property with harness axes (status, body, shape, ttl, scenario ...).

    EVERY axis combination runs for EVERY tool: one collected item per combination per
    ``axis_batches`` batch (read/write side, ``AXIS_BATCH`` tools). Running the axes on
    one representative per chokepoint class only (R1's sampling) was measured to hide
    real per-tool failures that appear on a non-default axis value (L6 evidence), so the
    product is batched, not sampled. ``max_batch`` overrides only this test's
    batch size (zero retains the existing axis/derived default). Items:
    ``combinations x batches`` instead of ``combinations x tools``.
    The axes are given as ``axis=thunk`` (top decorator first).
    """

    if max_batch < 0:
        raise ValueError("max_batch must be nonnegative")

    def deco(fn):
        names = list(axes)
        tool_names = _argnames(argname)
        pad = [None] * (len(tool_names) - 1)

        @functools.cache
        def rows() -> list[tuple[Any, ...]]:
            combos = list(itertools.product(*(list(v()) for v in axes.values())))
            out = []
            for combo in combos:
                entries = _select_entries(
                    thunk(), member, eligible, tool_names, dict(zip(names, combo, strict=True))
                )
                groups = (axis_batches if member is None else coarse_batches)(entries, max_batch)
                out.extend((*combo, batch, *pad) for batch in groups)
            return out

        def _id(v: Any) -> str:
            return repr(v) if isinstance(v, str) else str(v)

        def ids() -> list[str]:
            n = len(names)
            return ["-".join([r[n].id, *(_id(v) for v in r[:n])]) for r in rows()]

        return lazy_parametrize([*names, *tool_names], rows, ids=LazyIds(ids))(
            _run_each(fn, tool_names)
        )

    return deco


__all__ = [
    "ToolBatch",
    "assert_covers_every_tool",
    "axis_batches",
    "batches",
    "class_axis",
    "class_of",
    "class_representatives",
    "coarse_batches",
    "representative_batches",
    "representatives",
    "tool_batches",
]
