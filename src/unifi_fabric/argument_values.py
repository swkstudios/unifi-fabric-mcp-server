"""The argument-value rule every tool shares, checked before any request.

**Numbers are finite.** JSON has no NaN or Infinity; a Python caller (or a lax string
such as ``"nan"`` coerced into a number argument) could still pass one, and it would be
forwarded as an invalid JSON token or a meaningless query value. Every number anywhere
in the arguments (top level, inside a body object or a list) must be finite
(``refusals`` entry ``finite-number``, JSON validity).

**A blank string or an empty list is a value, not an error.** A filter or search the
server applies itself (``query``, ``status_filter``, ``client_type``, ``client_ids``)
given as ``""`` / whitespace or ``[]`` is not applied, and a value the server forwards
upstream (``types``, ``categories``, ``smart_detect_types``, ``attrs``, ``host_ids``,
``sites``) is sent as given for the upstream to judge: neither is a pre-upstream refusal
(the refusal policy, ``refusals``). :func:`is_blank` is the one test for "not applied".
The server's own selectors (host, site, key label, ids, camera names) keep their syntax
check (``selector_args``).

Tool code that is called directly (not through the MCP layer) uses
:func:`require_finite` for the same rule and message.
"""

from __future__ import annotations

import math
import re
from decimal import Decimal, InvalidOperation
from typing import Any

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext

from .argument_errors import echoed_input, input_path_component
from .spec_limits import argument_problems


def is_blank(value: Any) -> bool:
    """True for a filter value that applies no filter: an empty or whitespace-only
    string, or an empty list."""
    if isinstance(value, str):
        return not value.strip()
    return isinstance(value, (list, tuple)) and len(value) == 0


def _non_finite(value: Any) -> bool:
    return isinstance(value, float) and not math.isfinite(value)


def non_finite_problem(value: Any, where: str) -> str | None:
    """The first non-finite number or genuine cycle, without a JSON nesting limit."""
    active: set[int] = set()
    stack: list[tuple[Any, str, bool]] = [(value, where, False)]
    while stack:
        item, path, leaving = stack.pop()
        if leaving:
            active.remove(id(item))
            continue
        if _non_finite(item):
            return (
                f"{path} is {echoed_input(item)}: numbers must be finite (NaN and Infinity "
                "are not JSON numbers and are never sent upstream)"
            )
        if isinstance(item, (dict, list, tuple)):
            if id(item) in active:
                return f"{path} contains a circular reference; JSON values must be acyclic"
            active.add(id(item))
            stack.append((item, path, True))
            children = (
                [
                    (child, f"{path}.{input_path_component(key)}", False)
                    for key, child in item.items()
                ]
                if isinstance(item, dict)
                else [(child, f"{path}[{index}]", False) for index, child in enumerate(item)]
            )
            stack.extend(reversed(children))
    return None


def require_finite(value: Any, name: str) -> None:
    """Raise ``ValueError`` when ``value`` holds NaN or Infinity anywhere."""
    problem = non_finite_problem(value, repr(name))
    if problem is not None:
        raise ValueError(problem)


def _schema_types(schema: dict[str, Any]) -> set[Any]:
    return {schema.get("type")} | {s.get("type") for s in schema.get("anyOf") or []}


def _decimal(value: str) -> Decimal | None:
    """``value`` parsed exactly as a decimal number (no float rounding or overflow, no
    digit limit), or None when it is not a number."""
    try:
        return Decimal(value.strip())
    except InvalidOperation:
        return None


def _lax_non_finite_string(value: Any, integer: bool = False) -> bool:
    """A string the framework's lax number parsing would turn into NaN / Infinity.

    An integer argument is parsed as an exact decimal, never through float: a long
    integer string such as ``"1" + "0" * 309`` is a finite integer even though it is
    past the float range.
    """
    if not isinstance(value, str):
        return False
    if integer:
        number = _decimal(value)
        return number is not None and not number.is_finite()
    try:
        return not math.isfinite(float(value))
    except ValueError:
        return False


#: A string the framework's lax integer parsing accepts: optional whitespace and sign,
#: decimal digits (``_`` separators allowed) and an optional all-zero fraction.
_LAX_INTEGER = re.compile(r"\s*+([+-]?[0-9]+(?:_[0-9]+)*)(?:\.0*)?\s*+")


def _lax_integer(value: str) -> int | None:
    """The integer the framework's lax integer parsing reads from ``value`` (``"7"``,
    ``"1_000"``, ``"2.0"``), parsed as an integer, never through float; None when the
    framework would reject it (not an integer, or past the interpreter's digit limit,
    which the framework shares and reports itself)."""
    match = _LAX_INTEGER.fullmatch(value)
    if match is None:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


class ArgumentValueMiddleware(Middleware):
    """Refuse any non-finite number in the arguments (JSON validity) before the tool body
    runs."""

    def __init__(self, server: Any) -> None:
        self._server = server
        self._numbers: dict[str, frozenset[str]] = {}
        self._integers: dict[str, frozenset[str]] = {}

    async def _number_args(self, name: str) -> frozenset[str]:
        """The number-typed arguments of tool ``name``."""
        if name not in self._numbers:
            try:
                tool = await self._server.get_tool(name)
            except Exception:  # unknown tool: the framework reports it
                return frozenset()
            if tool is None:
                return frozenset()
            schema = getattr(tool, "parameters", None) or {}
            self._numbers[name] = frozenset(
                arg
                for arg, spec in (schema.get("properties") or {}).items()
                if {"number", "integer"} & _schema_types(spec)
            )
            self._integers[name] = frozenset(
                arg
                for arg, spec in (schema.get("properties") or {}).items()
                if "integer" in _schema_types(spec) and "boolean" not in _schema_types(spec)
            )
        return self._numbers[name]

    async def on_call_tool(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any, Any],
    ) -> Any:
        name = str(getattr(context.message, "name", ""))
        arguments = getattr(context.message, "arguments", None) or {}
        numbers = await self._number_args(name)
        problems: list[str] = []
        parsed = dict(arguments)
        for arg in sorted(arguments):
            value = arguments[arg]
            if arg in self._integers.get(name, ()) and isinstance(value, bool):
                problems.append(f"{arg!r} must be an integer, not a boolean")
            integer = arg in self._integers.get(name, ())
            problem = non_finite_problem(value, repr(arg))
            if problem is None and arg in numbers and _lax_non_finite_string(value, integer):
                problem = (
                    f"{arg!r} is {echoed_input(value)}: numbers must be finite (NaN and Infinity "
                    "are not JSON numbers and are never sent upstream)"
                )
            if problem is not None:
                problems.append(problem)
            elif arg in numbers and isinstance(value, str):
                # Match the framework's lax numeric parsing for bounds only. Keep the
                # original arguments unchanged for the framework and request body.
                # Integers are parsed as integers (exactly), never through float.
                if integer:
                    whole = _lax_integer(value)
                    if whole is not None:
                        parsed[arg] = whole
                else:
                    try:
                        parsed[arg] = float(value)
                    except ValueError:
                        pass  # the framework reports an invalid numeric type
        if problems:
            raise ToolError("; ".join(problems))
        problems = argument_problems(name, parsed)
        if problems:
            raise ToolError("; ".join(problems))
        return await call_next(context)
