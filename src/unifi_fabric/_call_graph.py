"""The call-graph audit of the registered tools: route literals and referenced symbols.

The policy derivations that read a tool's code, not its membership, walk the package call
graph from each registered tool's function, from source: the tools whose call graph checks
the connector write switch (``CONNECTOR_WRITE_TOOLS`` of the generated tool index, by
:func:`tools_referencing`), and the firewall routes a tool reaches
(:func:`route_literals_of`, which the test-suite compares with the family the explicit
inventory gives each tool). Generation and test time only; the runtime never imports it.

Which tools exist, and which family each belongs to, is not derived here: that is the
explicit inventory (:mod:`unifi_fabric.catalog.membership`, public #42 steps 6 and 7). Each
tool's function node is found from the registered function itself (its file and first
line), never by scanning modules for tool decorators.
"""

from __future__ import annotations

import ast
import functools
import inspect
import re
import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

#: An upstream route of the firewall family, matched against each route literal (a string
#: constant with no whitespace, docstrings excluded) in a tool's call graph: a path segment
#: ``firewall...`` (Integration ``firewall/policies``, ``firewall/zones``; v2
#: ``firewall-policies``, ``firewall/zone``, ``firewall-groups``, ``firewall-app-blocks``),
#: ``acl-rules`` (Integration and v2 ACL rules) or the classic ``firewallrule`` /
#: ``firewallgroup`` collections (both start with ``firewall``).
FIREWALL_ROUTE_RE = re.compile(r"(?:^|/)(?:firewall|acl-rules?)[a-z/-]*(?:\Z|[/?])")

type _FunctionNode = ast.AsyncFunctionDef | ast.FunctionDef
type _Defs = dict[str, _FunctionNode]
type _Imports = dict[str, tuple[str, str | None]]

_PKG = Path(__file__).parent

type _Parsed = tuple[ast.Module, _Defs, _Imports]

# The parsed package (about a hundred megabytes of syntax trees) is shared within one
# source derivation, where the call-graph walk asks for the same modules tens of thousands
# of times, and released when the outermost derivation returns: a process that derived
# the index once (the generator, a test) must not keep every tree for its lifetime.
_parse_lock = threading.RLock()
_parsed: dict[str, _Parsed] | None = None


@contextmanager
def source_derivation() -> Iterator[None]:
    """Share parsed modules for the duration of the outermost derivation only.

    Each ``derive_*`` call opens one; a caller that runs several derivations in a row
    (the index generator) wraps them in one to parse the package once.
    """
    global _parsed
    with _parse_lock:
        if _parsed is not None:
            yield
            return
        _parsed = {}
        try:
            yield
        finally:
            _parsed = None


def _derivation[**P, R](fn: Callable[P, R]) -> Callable[P, R]:
    """Run ``fn`` inside one :func:`source_derivation` (nested derivations share it)."""

    @functools.wraps(fn)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        with source_derivation():
            return fn(*args, **kwargs)

    return wrapper


def _module_source(rel: str) -> _Parsed:
    """One package module's parse, shared within the current source derivation."""
    if _parsed is None:
        return _parse_module(rel)
    found = _parsed.get(rel)
    if found is None:
        found = _parsed[rel] = _parse_module(rel)
    return found


def _parse_module(rel: str) -> _Parsed:
    """Parse one package module: its tree, top-level functions and package imports.

    ``defs`` includes module-level aliases of a function (``_impl_x = x``). ``imports`` maps
    a local name to ``(module path, None)`` for an imported package module and to
    ``(module path, function name)`` for an imported package function.
    """
    tree = ast.parse((_PKG / rel).read_text())
    defs: _Defs = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef))
    }
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Name)
            and node.value.id in defs
        ):
            defs[node.targets[0].id] = defs[node.value.id]
    imports: _Imports = {}
    here = Path(rel).parent
    for node in tree.body:
        if not isinstance(node, ast.ImportFrom) or not node.level:
            continue
        base = here
        for _ in range(node.level - 1):
            base = base.parent
        parts = node.module.split(".") if node.module else []
        for alias in node.names:
            module = base.joinpath(*parts, alias.name).with_suffix(".py")
            if (_PKG / module).exists():
                imports[alias.asname or alias.name] = (module.as_posix(), None)
                continue
            module = base.joinpath(*parts).with_suffix(".py")
            if parts and (_PKG / module).exists():
                imports[alias.asname or alias.name] = (module.as_posix(), alias.name)
    return tree, defs, imports


def _route_literals(node: ast.AST) -> set[str]:
    """String constants without whitespace in ``node``, docstrings excluded."""
    docstrings: set[int] = set()
    for child in ast.walk(node):
        if isinstance(child, (ast.AsyncFunctionDef, ast.FunctionDef, ast.ClassDef)):
            first = child.body[0] if child.body else None
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                docstrings.add(id(first.value))
    return {
        child.value
        for child in ast.walk(node)
        if isinstance(child, ast.Constant)
        and isinstance(child.value, str)
        and id(child) not in docstrings
        and not any(c.isspace() for c in child.value)
    }


def _defined_in(module: str, name: str) -> tuple[str, _FunctionNode] | None:
    """The function ``module.name`` is, following re-exports to the defining module.

    A family module that imports a moved helper back (``from ...shared_shapes._x import
    _relay``) re-exports it: ``connector._relay`` is defined in the common module.
    """
    for _ in range(8):  # a re-export chain is short; a cycle must not hang the walk
        _, defs, imports = _module_source(module)
        if name in defs:
            return module, defs[name]
        target = imports.get(name)
        if target is None or target[1] is None:
            return None
        module, name = target[0], str(target[1])
    return None


def _referenced(rel: str, node: _FunctionNode, scope: _Defs) -> list[tuple[str, _FunctionNode]]:
    """Package functions ``node`` references: by name in its module or scope, or imported."""
    _, defs, imports = _module_source(rel)
    out: list[tuple[str, _FunctionNode]] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
            target = scope.get(child.id) or defs.get(child.id)
            if target is not None and target is not node:
                out.append((rel, target))
            elif child.id in imports and imports[child.id][1] is not None:
                module, name = imports[child.id]
                found = _defined_in(module, str(name))
                if found is not None:
                    out.append(found)
        elif (
            isinstance(child, ast.Attribute)
            and isinstance(child.value, ast.Name)
            and child.value.id in imports
            and imports[child.value.id][1] is None
        ):
            found = _defined_in(imports[child.value.id][0], child.attr)
            if found is not None:
                out.append(found)
    return out


def _call_graph(rel: str, node: _FunctionNode, scope: _Defs | None = None) -> list[_FunctionNode]:
    """Every package function reachable from a tool function, the tool itself first."""
    reached: list[_FunctionNode] = []
    seen: set[tuple[str, int]] = set()
    stack: list[tuple[str, _FunctionNode, _Defs]] = [(rel, node, scope or {})]
    while stack:
        module, fn, names = stack.pop()
        key = (module, fn.lineno)
        if key in seen:
            continue
        seen.add(key)
        reached.append(fn)
        stack.extend(
            (m, f, names if m == module else {}) for m, f in _referenced(module, fn, names)
        )
    return reached


@_derivation
def tool_route_literals(rel: str, node: _FunctionNode, scope: _Defs | None = None) -> set[str]:
    """Route literals reachable from a tool function through the package call graph."""
    return set().union(*(_route_literals(fn) for fn in _call_graph(rel, node, scope)))


def is_firewall_route(literal: str) -> bool:
    """Whether a route literal names a firewall-family route (:data:`FIREWALL_ROUTE_RE`)."""
    return FIREWALL_ROUTE_RE.search(literal) is not None


def _tool_node(fn: Any) -> tuple[str, _FunctionNode, _Defs] | None:
    """``(source module, node, enclosing scope)`` of a registered tool function.

    Found from the function itself (its unwrapped code object's file and first line), in
    the module's parse: the node whose first line (its first decorator) is that line, and
    the functions nested in the same top-level function (a ``register`` step) as its scope.
    """
    code = getattr(inspect.unwrap(fn), "__code__", None)
    if code is None:
        return None
    try:
        rel = Path(code.co_filename).resolve().relative_to(_PKG.resolve()).as_posix()
    except ValueError:
        return None
    tree = _module_source(rel)[0]
    for top in tree.body:
        if not isinstance(top, (ast.AsyncFunctionDef, ast.FunctionDef)):
            continue
        nested: _Defs = {
            sub.name: sub
            for sub in ast.walk(top)
            if isinstance(sub, (ast.AsyncFunctionDef, ast.FunctionDef)) and sub is not top
        }
        for node in (top, *nested.values()):
            first = min([node.lineno, *(d.lineno for d in node.decorator_list)])
            if first == code.co_firstlineno:
                return rel, node, (nested if node is not top else {})
    return None


def registered_tool_functions() -> dict[str, Any]:
    """Every tool the loader map registers, by name: its function (generation time)."""
    from fastmcp import FastMCP

    from .catalog import loaders

    app = FastMCP("call-graph-audit")
    loaders.load(app, late=lambda: None, bound=lambda: None)
    components = app.local_provider._components.values()  # noqa: SLF001
    found = {tool.name: getattr(tool, "fn", None) for tool in components}
    return {name: fn for name, fn in found.items() if fn is not None}


@_derivation
def tools_referencing(symbol: str, tools: Mapping[str, Any] | None = None) -> frozenset[str]:
    """Tools whose call graph names ``symbol`` (a variable or an attribute), from source.

    ``tools_referencing("CONNECTOR_WRITE_ENV")`` is every tool that checks the connector
    write switch: the relay tools and the typed tools that switch also governs. ``tools``
    maps tool names to their registered functions (default:
    :func:`registered_tool_functions`).
    """
    found: set[str] = set()
    for name, fn in (registered_tool_functions() if tools is None else tools).items():
        located = _tool_node(fn)
        if located is None:
            raise LookupError(
                f"call-graph audit: the function of tool {name!r} cannot be located in the "
                "package source (a wrapper without functools.wraps, or code outside the "
                "package); it would be left out of the derived set"
            )
        rel, node, scope = located
        for graph_fn in _call_graph(rel, node, scope):
            if any(
                (isinstance(child, ast.Name) and child.id == symbol)
                or (isinstance(child, ast.Attribute) and child.attr == symbol)
                for child in ast.walk(graph_fn)
            ):
                found.add(name)
                break
    return frozenset(found)


@_derivation
def route_literals_of(fn: Any) -> set[str]:
    """Route literals reachable from a registered tool function through the call graph."""
    located = _tool_node(fn)
    if located is None:
        raise LookupError(
            f"call-graph audit: the function {getattr(fn, '__qualname__', fn)!r} cannot be "
            "located in the package source"
        )
    return tool_route_literals(*located)
