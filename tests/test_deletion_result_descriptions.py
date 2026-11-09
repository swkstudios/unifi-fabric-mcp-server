"""Every tool that returns ``deletion_result`` describes that shape; no other tool claims it.

The tool set is derived from the code, never from tool names. A tool belongs to it when
a value it returns comes from :func:`unifi_fabric.tools._results.deletion_result`,
followed through the helpers it calls: module aliases, ``module.helper`` attributes and
closure variables are resolved at runtime, and a wrapper that adds keys to the result
passed as its first argument (``_with_epoch_unit(deletion_result(...))``) counts. A tool
all of whose returns come from it is *pure*; a tool with other return paths too (an
action or an omitted argument selects a PUT or a create) is *partial*.

A pure tool states :data:`DELETION_RESULT` and claims none of the shapes it does not
return: the bare upstream or native body, null as the whole result, additive ``_deleted``
/ ``_message`` / ``_route`` / ``_reason`` keys, or the unwrapped dry-run preview. A
partial tool states the same shape for its delete path. A tool outside the set never
claims the shape (the registration-time footer is chosen by tool name).

A behavioural cross-check runs every write tool under ``dry-run policy``: a tool that
answers with the deletion_result dry-run shape must be in the derived set, so a call
pattern the derivation does not follow fails here instead of passing unchecked.
"""

from __future__ import annotations

import ast
import functools
import inspect
import re
import textwrap
from typing import Any

from tests import test_cross_tool_invariants as cti
from tests import upstream_harness as uh
from tests._tool_catalog import lazy_parametrize, tools_by_name
from unifi_fabric.catalog_descriptions import DELETION_RESULT
from unifi_fabric.client import is_dry_run_preview
from unifi_fabric.tools import _results

PURE, PARTIAL, NONE = "pure", "partial", "none"
#: The shape itself, as a partial tool states it after "... returns".
SHAPE = DELETION_RESULT.removeprefix("Returns ").removesuffix(".")

#: Claims that contradict the deletion_result shape on every return path.
NEVER = {
    "additive key": re.compile(r"\b_(?:deleted|message|route|reason)\b"),
    "null as the whole result": re.compile(r"including null|null for an empty response", re.I),
    "unchanged bare body": re.compile(
        r"\b(?:bodies|arrays|scalars|results)\b[^.]*\bunchanged", re.I
    ),
    "unchanged preview": re.compile(r"\bpreview is unchanged", re.I),
    "success status": re.compile(r'returns \{status: "(?!dry_run")', re.I),
}
#: Claims that contradict it only where the tool has no other return path.
NEVER_PURE = {
    "bare upstream body": re.compile(
        r"\breturns:? (?:the )?(?:upstream|native)(?: \w+)? (?:body|response|envelope)", re.I
    ),
    "body returned unchanged": re.compile(
        r"\b(?:upstream|native) (?:body|response) (?:is )?returned\b", re.I
    ),
    "unwrapped dry-run preview": re.compile(
        r'dry-run returns \{status: "dry_run", dryRun|dry-run policy the preview \{', re.I
    ),
}


def _flat(text: str | None) -> str:
    return " ".join((text or "").split())


def _scope(fn: Any) -> dict[str, Any]:
    scope = dict(fn.__globals__)
    for name, cell in zip(fn.__code__.co_freevars, fn.__closure__ or (), strict=True):
        try:
            scope[name] = cell.cell_contents
        except ValueError:  # an unassigned cell
            continue
    return scope


def _resolve(expr: ast.expr, scope: dict[str, Any]) -> Any:
    if isinstance(expr, ast.Name):
        return scope.get(expr.id)
    if isinstance(expr, ast.Attribute):
        base = _resolve(expr.value, scope)
        return None if base is None else getattr(base, expr.attr, None)
    return None


def _own_nodes(node: ast.AST) -> list[ast.AST]:
    """Nodes of one function body, not descending into nested functions or lambdas."""
    out: list[ast.AST] = []
    stack = list(ast.iter_child_nodes(node))
    while stack:
        child = stack.pop()
        if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            continue
        out.append(child)
        stack.extend(ast.iter_child_nodes(child))
    return out


def _unawait(expr: ast.expr | None) -> ast.expr | None:
    return expr.value if isinstance(expr, ast.Await) else expr


def _returned_callees(fn: Any) -> list[list[Any]]:
    """Per return statement, the functions whose result it may return."""
    node = ast.parse(textwrap.dedent(inspect.getsource(fn))).body[0]
    scope = _scope(fn)
    nodes = _own_nodes(node)
    assigned: dict[str, list[ast.expr]] = {}
    for n in nodes:
        if isinstance(n, ast.Assign | ast.AnnAssign):
            target = n.targets[0] if isinstance(n, ast.Assign) else n.target
            value = _unawait(n.value)
            if isinstance(target, ast.Name) and isinstance(value, ast.Call):
                assigned.setdefault(target.id, []).append(value.func)
    paths: list[list[Any]] = []
    for n in nodes:
        if not isinstance(n, ast.Return):
            continue
        value = _unawait(n.value)
        funcs: list[ast.expr] = []
        if isinstance(value, ast.Call):
            funcs.append(value.func)
            first = _unawait(value.args[0]) if value.args else None
            if isinstance(first, ast.Call):
                funcs.append(first.func)
            elif isinstance(first, ast.Name):
                funcs.extend(assigned.get(first.id, []))
        elif isinstance(value, ast.Name):
            funcs.extend(assigned.get(value.id, []))
        paths.append([f for f in (_resolve(e, scope) for e in funcs) if f is not None])
    return paths


def _kind(fn: Any, _seen: frozenset = frozenset()) -> str:
    fn = inspect.unwrap(fn)
    fn = getattr(fn, "__func__", fn)
    if fn is _results.deletion_result:
        return PURE
    if not inspect.isfunction(fn) or fn.__code__ in _seen:
        return NONE
    try:
        paths = _returned_callees(fn)
    except (OSError, TypeError):  # no Python source (a builtin or C function)
        return NONE
    seen = _seen | {fn.__code__}
    kinds = []
    for callees in paths:
        found = {_kind(callee, seen) for callee in callees}
        kinds.append(PURE if PURE in found else PARTIAL if PARTIAL in found else NONE)
    if kinds and all(k == PURE for k in kinds):
        return PURE
    return PARTIAL if any(k != NONE for k in kinds) else NONE


@functools.cache
def deletion_tools() -> dict[str, str]:
    """Tool name -> PURE or PARTIAL, for every tool returning deletion_result."""
    kinds = {name: _kind(tool.fn) for name, tool in tools_by_name().items()}
    return {name: kind for name, kind in sorted(kinds.items()) if kind != NONE}


def _of_kind(kind: str) -> list[str]:
    return [name for name, k in deletion_tools().items() if k == kind]


def _violations(description: str, rules: dict[str, re.Pattern[str]]) -> list[str]:
    return [
        f"{label}: {m.group(0)!r}" for label, rx in rules.items() for m in rx.finditer(description)
    ]


def test_the_derivation_finds_pure_and_partial_deletion_tools():
    # remove_matter_node always returns the shape; set_client_icon returns it only
    # when icon is omitted. Both shapes must be derived, or the checks below check nothing.
    assert deletion_tools().get("remove_matter_node") == PURE
    assert deletion_tools().get("set_client_icon") == PARTIAL


@lazy_parametrize("name", lambda: _of_kind(PURE))
def test_pure_deletion_tool_describes_the_deletion_result_shape(name):
    description = _flat(tools_by_name()[name].description)
    assert DELETION_RESULT in description, (name, description)
    assert "deleted: false" in description, (name, "the dry-run shape is not described")
    problems = _violations(description, {**NEVER, **NEVER_PURE})
    assert not problems, (name, problems)


@lazy_parametrize("name", lambda: _of_kind(PARTIAL))
def test_partial_deletion_tool_describes_the_shape_of_its_delete_path(name):
    description = _flat(tools_by_name()[name].description)
    assert SHAPE in description, (name, description)
    assert "deleted: false" in description, (name, "the dry-run shape is not described")
    problems = _violations(description, NEVER)
    assert not problems, (name, problems)


def test_no_other_tool_claims_the_deletion_result_shape():
    claims = [
        name
        for name, tool in sorted(tools_by_name().items())
        if name not in deletion_tools()
        and any(
            claim in _flat(tool.description)
            for claim in ("{deleted, message, response}", "{deleted: true, message, response}")
        )
    ]
    assert claims == [], claims


@lazy_parametrize("name", lambda: cti._lz_WRITE_TOOLS())
async def test_every_tool_answering_with_the_delete_shape_is_derived(monkeypatch, name):
    upstream = uh.FakeUpstream()
    result = await cti._call(monkeypatch, name, upstream, env={"UNIFI_WRITE_POLICY": "dry-run"})
    payload = uh.result_payload(result)
    shaped = (
        isinstance(payload, dict)
        and payload.get("status") == "dry_run"
        and payload.get("deleted") is False
        and "message" in payload
        and is_dry_run_preview(payload.get("response"))
    )
    if shaped:
        assert name in deletion_tools(), (name, "returns deletion_result; derivation missed it")
