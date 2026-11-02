"""Derive typed body arguments from registry callables by symbolic AST data flow.

Track argument dependencies through assignments, collections, mutations, local and
package helper calls into ``json=`` sinks. Tuple positions and constant dictionary
keys distinguish body data from route/query metadata. Bind positional/keyword calls
and starred dependency tuples without executing any implementation. Unknown transforms
conservatively retain dependencies; transport results do not. Scalar/scalar-list
schemas are typed; free-form JSON objects and Any are outside this inventory.
This branch-insensitive static approximation uses no grep or fixed tool allowlist.
"""

from __future__ import annotations

import ast
import inspect
import textwrap
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from functools import cache
from types import ModuleType
from typing import Any

from .request_shape import RequestShape


@dataclass(eq=False)
class Value:
    # Union nodes retain references to collection objects, rather than copying
    # their current fields. A later mutation must remain visible through aliases
    # and through any containing dictionary.
    direct_names: set[str]
    direct_fields: dict[str | int, Value] | None = None
    sources: tuple[Value, ...] = ()
    unknown_fields: tuple[Value, ...] = ()
    # Conservative lvalue roots for reads whose precise element is unknown.
    # These are write links, not additional data dependencies.
    write_roots: tuple[Value, ...] = ()
    # Observe caller mutations through returned data without writing back.
    read_sources: tuple[Value, ...] = ()

    def origins(self) -> list[Value]:
        pending = [self]
        result = []
        seen = set()
        while pending:
            value = pending.pop()
            if id(value) in seen:
                continue
            seen.add(id(value))
            if value.sources:
                pending.extend(value.sources)
            else:
                result.append(value)
        return result

    @property
    def names(self) -> set[str]:
        pending = [self]
        result: set[str] = set()
        seen = set()
        while pending:
            value = pending.pop()
            if id(value) in seen:
                continue
            seen.add(id(value))
            result.update(value.direct_names)
            pending.extend(value.sources)
            pending.extend(value.read_sources)
            pending.extend(value.unknown_fields)
            pending.extend((value.direct_fields or {}).values())
        return result

    @property
    def fields(self) -> dict[str | int, Value] | None:
        origins = self.origins()
        if any(v.direct_names or v.unknown_fields for v in origins):
            return None
        keys = set().union(*(set(v.direct_fields or {}) for v in origins))
        return {
            key: union(
                *((v.direct_fields or {})[key] for v in origins if key in (v.direct_fields or {}))
            )
            for key in keys
        }

    def at(self, key: str | int) -> Value:
        fields = self.fields
        if fields is not None:
            return fields.get(
                key, Value(set(), write_roots=(self,), read_sources=self.read_sources)
            )
        return self

    def mutate(
        self, added: Value, key: str | int | None = None, *, unknown_key: bool = False
    ) -> None:
        pending = self.origins()
        seen = set()
        while pending:
            origin = pending.pop()
            if id(origin) in seen:
                continue
            seen.add(id(origin))
            if origin.write_roots:
                pending.extend(root for value in origin.write_roots for root in value.origins())
                continue
            if unknown_key:
                origin.unknown_fields = (*origin.unknown_fields, added)
            elif key is not None and origin.direct_fields is not None:
                origin.direct_fields[key] = union(
                    origin.direct_fields.get(key, Value(set())), added
                )
            elif origin.direct_fields is not None and added.fields is not None:
                for field, value in added.fields.items():
                    origin.direct_fields[field] = union(
                        origin.direct_fields.get(field, Value(set())), value
                    )
            else:
                origin.unknown_fields = (*origin.unknown_fields, added)

    def detached(self) -> Value:
        # Snapshot the observable shape, not the full historical alias graph.
        # Read links retain later caller changes but are never mutation roots.
        copies: dict[tuple[int, ...], Value] = {}
        pending: list[tuple[Value, Value]] = []

        def clone(value: Value) -> Value:
            identity = tuple(sorted(id(origin) for origin in value.origins()))
            if identity not in copies:
                copied = Value(set(), read_sources=(value,))
                copies[identity] = copied
                pending.append((value, copied))
            return copies[identity]

        result = clone(self)
        while pending:
            value, copied = pending.pop()
            fields = value.fields
            if fields is None:
                copied.direct_names = value.names
            else:
                copied.direct_fields = {key: clone(child) for key, child in fields.items()}
        return result


def union(*values: Value) -> Value:
    origins = {
        id(origin): origin
        for value in values
        for origin in value.origins()
        if (
            origin.direct_fields is not None
            or origin.direct_names
            or origin.unknown_fields
            or origin.write_roots
            or origin.read_sources
        )
    }
    if len(origins) == 1:
        return next(iter(origins.values()))
    return Value(set(), {}, tuple(origins.values()))


def collection(fields: dict[str | int, Value]) -> Value:
    return Value(set(), fields)


@dataclass
class Function:
    node: ast.FunctionDef | ast.AsyncFunctionDef
    namespace: dict[str, Any]


@cache
def _function(fn: Callable) -> Function:
    fn = inspect.unwrap(fn)
    source = ast.parse(textwrap.dedent(inspect.getsource(fn.__code__)))
    node = next(
        (n for n in source.body if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)), None
    )
    if node is None:
        expression = next(n for n in ast.walk(source) if isinstance(n, ast.Lambda))
        node = ast.FunctionDef(
            name=fn.__name__,
            args=expression.args,
            body=[ast.Return(value=expression.body)],
            decorator_list=[],
            returns=None,
            type_params=[],
        )
    namespace = dict(fn.__globals__)
    namespace.update(inspect.getclosurevars(fn).nonlocals)
    return Function(node, namespace)


def _typed(schema: dict) -> bool:
    if "anyOf" in schema:
        return all(_typed(branch) for branch in schema["anyOf"])
    kind = schema.get("type")
    if kind == "array":
        return _typed(schema.get("items", {}))
    return kind in {"string", "integer", "number", "boolean", "null"}


class Derivation:
    def __init__(self) -> None:
        self.cache: dict[Callable, tuple[Value, set[str], dict[str, Value]]] = {}
        self.active: set[Callable] = set()

    def summary(self, fn: Callable) -> tuple[Value, set[str], dict[str, Value]]:
        fn = inspect.unwrap(fn)
        if fn in self.cache:
            return self.cache[fn]
        facts = _function(fn)
        if fn in self.active:
            return Value({a.arg for a in facts.node.args.args}), set(), {}
        self.active.add(fn)
        result = self.analyse(facts)
        self.active.remove(fn)
        self.cache[fn] = result
        return result

    def analyse(
        self, facts: Function, captured: dict[str, Value] | None = None
    ) -> tuple[Value, set[str], dict[str, Value]]:
        node, namespace = facts.node, dict(facts.namespace)
        formals = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        env = dict(captured or {})
        formals += [a for a in (node.args.vararg, node.args.kwarg) if a is not None]
        parameters = {a.arg: Value({a.arg}) for a in formals}
        env.update(parameters)
        sinks: set[str] = set()
        returns = Value(set())
        locals_ = {
            n.name: Function(n, namespace)
            for n in node.body
            if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
        }

        def resolve(expr: ast.AST) -> Any:
            if isinstance(expr, ast.Name):
                return locals_.get(expr.id, namespace.get(expr.id))
            if isinstance(expr, ast.Attribute):
                return getattr(resolve(expr.value), expr.attr, None)
            if isinstance(expr, ast.NamedExpr):
                return resolve(expr.value)
            if isinstance(expr, ast.Tuple | ast.List):
                return tuple(resolve(child) for child in expr.elts)
            if isinstance(expr, ast.Subscript) and isinstance(expr.slice, ast.Constant):
                values = resolve(expr.value)
                index = expr.slice.value
                if (
                    isinstance(values, tuple)
                    and isinstance(index, int)
                    and -len(values) <= index < len(values)
                ):
                    return values[index]
            return None

        def bind_callable(target: ast.AST, resolved: Any) -> None:
            if isinstance(target, ast.Name) and (
                isinstance(resolved, Function | tuple) or inspect.isfunction(resolved)
            ):
                namespace[target.id] = resolved
            elif isinstance(target, ast.Tuple | ast.List) and isinstance(resolved, tuple):
                starred = next(
                    (i for i, child in enumerate(target.elts) if isinstance(child, ast.Starred)),
                    None,
                )
                if starred is None:
                    for child, value in zip(target.elts, resolved, strict=False):
                        bind_callable(child, value)
                else:
                    tail = len(target.elts) - starred - 1
                    for child, value in zip(
                        target.elts[:starred], resolved[:starred], strict=False
                    ):
                        bind_callable(child, value)
                    star = target.elts[starred]
                    if isinstance(star, ast.Starred):
                        bind_callable(star.value, resolved[starred : len(resolved) - tail])
                    if tail:
                        for child, value in zip(
                            target.elts[-tail:], resolved[-tail:], strict=False
                        ):
                            bind_callable(child, value)

        def assign(target: ast.AST, value: Value) -> None:
            if isinstance(target, ast.Name):
                env[target.id] = union(env.get(target.id, Value(set())), value)
            elif isinstance(target, ast.Tuple | ast.List):
                for position, child in enumerate(target.elts):
                    assign(child, value.at(position))
            elif isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant):
                parent = expression(target.value)
                key = target.slice.value
                parent.mutate(value, key if isinstance(key, str | int) else None)
            elif isinstance(target, ast.Subscript):
                expression(target.value).mutate(
                    union(expression(target.slice), value), unknown_key=True
                )
            elif isinstance(target, ast.Attribute):
                expression(target.value).mutate(value)

        def assignment(targets: Iterable[ast.AST], source: ast.AST | None) -> Value:
            value = expression(source)
            resolved = resolve(source) if source is not None else None
            for target in targets:
                assign(target, value)
                bind_callable(target, resolved)
            return value

        def expression(expr: ast.AST | None) -> Value:
            if expr is None:
                return Value(set())
            if isinstance(expr, ast.NamedExpr):
                return assignment([expr.target], expr.value)
            if isinstance(expr, ast.Name):
                return env.get(expr.id, Value(set()))
            if isinstance(expr, ast.Constant):
                return Value(set())
            if isinstance(expr, ast.Dict):
                result = collection({})
                for field_key, val in zip(expr.keys, expr.values, strict=True):
                    value = expression(val)
                    if field_key is None:
                        result = union(result, value)
                    elif isinstance(field_key, ast.Constant) and isinstance(
                        field_key.value, str | int
                    ):
                        result = union(result, collection({field_key.value: value}))
                    else:
                        result = union(result, expression(field_key), value)
                return result
            if isinstance(expr, ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp):
                for generator in expr.generators:
                    iterable = expression(generator.iter)
                    assign(generator.target, Value(iterable.names, write_roots=(iterable,)))
                    for condition in generator.ifs:
                        expression(condition)  # discover sinks without treating predicates as data
                if isinstance(expr, ast.DictComp):
                    return Value(union(expression(expr.key), expression(expr.value)).names)
                return Value(expression(expr.elt).names)
            if isinstance(expr, ast.Tuple | ast.List):
                return collection({i: expression(v) for i, v in enumerate(expr.elts)})
            if isinstance(expr, ast.Subscript):
                value = expression(expr.value)
                if isinstance(expr.slice, ast.Constant) and isinstance(expr.slice.value, str | int):
                    return value.at(expr.slice.value)
                return Value(value.names | expression(expr.slice).names, write_roots=(value,))
            if isinstance(expr, ast.IfExp):
                expression(expr.test)
                return union(expression(expr.body), expression(expr.orelse))
            if isinstance(expr, ast.BoolOp):
                return union(*(expression(v) for v in expr.values))
            if isinstance(expr, ast.Await):
                return expression(expr.value)
            if isinstance(expr, ast.Call):
                # A callable expression can itself bind an alias, e.g. (build := helper)(x).
                expression(expr.func)
                values = [expression(a) for a in expr.args]
                keywords: dict[str | None, Value] = {}
                for keyword in expr.keywords:
                    value = expression(keyword.value)
                    if keyword.arg is None and value.fields is not None:
                        keywords.update({str(k): v for k, v in value.fields.items()})
                    else:
                        keywords[keyword.arg] = value
                receiver = (
                    expression(expr.func.value)
                    if isinstance(expr.func, ast.Attribute)
                    else Value(set())
                )
                name = expr.func.attr if isinstance(expr.func, ast.Attribute) else ""
                if "json" in keywords:
                    sinks.update(keywords["json"].names)
                if name in {"get", "post", "put", "patch", "delete", "request"} and any(
                    k.arg in {"json", "key", "params"} for k in expr.keywords
                ):
                    return Value(set())
                if name == "get" and expr.args and isinstance(expr.args[0], ast.Constant):
                    key = expr.args[0].value
                    if isinstance(key, str | int):
                        return union(receiver.at(key), *values[1:])
                if name in {"copy", "model_dump"}:
                    return receiver
                if name in {"update", "setdefault", "append", "extend", "insert", "add"}:
                    added = union(*values, *keywords.values())
                    if (
                        name == "setdefault"
                        and expr.args
                        and isinstance(expr.args[0], ast.Constant)
                    ):
                        key = expr.args[0].value
                        if isinstance(key, str | int):
                            added = collection({key: union(*values[1:])})
                    if isinstance(expr.func, ast.Attribute):
                        receiver.mutate(added)
                    return union(receiver, added)
                target = resolve(expr.func)
                # Collection helpers return upstream records, not their route selectors.
                if (
                    inspect.isfunction(target)
                    and target.__module__ == "unifi_fabric.tools._pagination"
                    and target.__name__
                    in {"collect_offset", "collect_links", "collect_cursor", "collect_batch"}
                ):
                    return Value(set())
                if isinstance(target, Function) or (
                    inspect.isfunction(target)
                    and (
                        target.__module__.startswith("unifi_fabric")
                        or target.__module__ == namespace.get("__name__")
                    )
                ):
                    child = target if isinstance(target, Function) else _function(target)
                    params = [*child.node.args.posonlyargs, *child.node.args.args]
                    positional: list[Value] = []
                    for arg, value in zip(expr.args, values, strict=True):
                        if isinstance(arg, ast.Starred):
                            getter = (
                                resolve(arg.value.func) if isinstance(arg.value, ast.Call) else None
                            )
                            annotation = (
                                _function(getter).node.returns
                                if inspect.isfunction(getter)
                                else None
                            )
                            width = (
                                len(annotation.slice.elts)
                                if isinstance(annotation, ast.Subscript)
                                and isinstance(annotation.slice, ast.Tuple)
                                else max(1, len(params) - len(expr.args) + 1)
                            )
                            positional.extend(value.at(i) for i in range(width))
                        else:
                            positional.append(value)
                    binding = {p.arg: v for p, v in zip(params, positional, strict=False)}
                    binding.update({k: v for k, v in keywords.items() if k is not None})
                    if child.node.args.kwarg:
                        named = {p.arg for p in [*params, *child.node.args.kwonlyargs]}
                        binding[child.node.args.kwarg.arg] = union(
                            collection(
                                {
                                    k: v
                                    for k, v in keywords.items()
                                    if k is not None and k not in named
                                }
                            ),
                            keywords.get(None, Value(set())),
                        )
                    if child.node.args.vararg:
                        binding[child.node.args.vararg.arg] = collection(
                            {i: v for i, v in enumerate(positional[len(params) :])}
                        )
                    out, body, mutations = (
                        self.analyse(child, env)
                        if isinstance(target, Function)
                        else self.summary(target)
                    )

                    substituted: dict[tuple[int, ...], Value] = {}

                    def substitute(value: Value) -> Value:
                        identity = tuple(sorted(id(v) for v in value.origins()))
                        if identity in substituted:
                            return substituted[identity]
                        fields = value.fields
                        if fields is not None:
                            result = collection({})
                            substituted[identity] = result
                            result.direct_fields = {k: substitute(v) for k, v in fields.items()}
                            # A detached returned parameter can have an empty snapshot
                            # but still observe later writes through its read links.
                            # Preserve those dependencies without exposing mutation roots.
                            result.read_sources = tuple(
                                substitute(source)
                                for origin in value.origins()
                                for source in origin.read_sources
                            )
                        else:
                            result = union(
                                *(binding.get(n, env.get(n, Value(set()))) for n in value.names)
                            )
                            substituted[identity] = result
                        return result

                    sinks.update(substitute(Value(body)).names)
                    for parameter, added in mutations.items():
                        if parameter in binding:
                            binding[parameter].mutate(substitute(added))
                    # Return dependencies without sharing caller argument nodes.
                    # Later result writes must not alter earlier transport bodies.
                    return substitute(out).detached()
                if isinstance(expr.func, ast.Name) and expr.func.id in {
                    "dict",
                    "list",
                    "tuple",
                    "cast",
                }:
                    return union(*values, *keywords.values())
                roots = union(receiver, *values, *keywords.values())
                return Value(roots.names, write_roots=(roots,))
            roots = union(*(expression(c) for c in ast.iter_child_nodes(expr)))
            return Value(roots.names, write_roots=(roots,))

        def statements(body: list[ast.stmt]) -> None:
            nonlocal returns
            for statement in body:
                if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef):
                    locals_[statement.name] = Function(statement, namespace)
                elif isinstance(statement, ast.Assign):
                    assignment(statement.targets, statement.value)
                elif isinstance(statement, ast.AugAssign):
                    receiver = expression(statement.target)
                    receiver.mutate(expression(statement.value))
                    assign(statement.target, receiver)
                elif isinstance(statement, ast.AnnAssign):
                    assignment([statement.target], statement.value)
                elif isinstance(statement, ast.Return):
                    returns = union(returns, expression(statement.value))
                elif isinstance(statement, ast.For | ast.AsyncFor):
                    iterable = expression(statement.iter)
                    assign(statement.target, Value(iterable.names, write_roots=(iterable,)))
                    statements(statement.body)
                    statements(statement.orelse)
                elif isinstance(statement, ast.If | ast.While):
                    expression(statement.test)
                    statements(statement.body)
                    statements(statement.orelse)
                elif isinstance(statement, ast.With | ast.AsyncWith):
                    for item in statement.items:
                        value = expression(item.context_expr)
                        if item.optional_vars is not None:
                            assign(item.optional_vars, value)
                    statements(statement.body)
                elif isinstance(statement, ast.Try):
                    statements(statement.body)
                    for handler in statement.handlers:
                        statements(handler.body)
                    statements(statement.orelse)
                    statements(statement.finalbody)
                else:
                    expression(statement)

        previous = None
        current = {k: frozenset(v.names) for k, v in env.items()}
        while previous != current:
            previous = current
            statements(node.body)
            current = {k: frozenset(v.names) for k, v in env.items()}
        mutations = {
            name: union(*value.unknown_fields)
            for name, value in parameters.items()
            if value.unknown_fields
        }
        return returns, sinks, mutations


def derive_body_arguments(tools: Iterable[Any]) -> set[tuple[str, str]]:
    audit = Derivation()
    result: set[tuple[str, str]] = set()
    for tool in tools:
        _, body, _ = audit.summary(tool.fn)
        result.update(
            (tool.name, name)
            for name, schema in tool.parameters["properties"].items()
            if name in body and _typed(schema)
        )
    return result


def collect_markers(modules: Iterable[ModuleType]) -> list[RequestShape]:
    return list(
        dict.fromkeys(
            marker
            for module in modules
            for obj in vars(module).values()
            if inspect.isfunction(obj)
            for marker in getattr(obj, "__request_shapes__", ())
        )
    )


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def assert_markers(markers: list[RequestShape], index: dict) -> None:
    for marker in markers:
        for argument in marker.args:
            key = marker.evidence.format(argument=argument)
            _require(key in index, f"missing evidence: {key}")
            record = index[key]
            _require(record["proven"] is True, f"unproven evidence: {key}")
            _require(key == f"{marker.tool}.{argument}", f"wrong evidence argument: {key}")


def assert_coverage(
    candidates: set[tuple[str, str]], markers: list[RequestShape], pending: list[dict]
) -> None:
    marked = {(m.tool, argument) for m in markers for argument in m.args}
    deferred = {(r["tool"], r["argument"]) for r in pending}
    _require(len(deferred) == len(pending), "duplicate pending arguments")
    _require(
        all(r["reason"] and r["tracking"] for r in pending), "pending needs reason and tracking"
    )
    _require(
        not (marked & deferred), f"proven arguments still pending: {sorted(marked & deferred)}"
    )
    missing = candidates - marked - deferred
    _require(not missing, f"typed body arguments lack evidence or pending entry: {sorted(missing)}")
    stale = (marked | deferred) - candidates
    _require(not stale, f"stale marker/pending entries: {sorted(stale)}")
