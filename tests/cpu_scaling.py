"""Deterministic Python work counts for scrubber and parser scaling tests.

Counts cover module-local Python instructions expressed as line events, independent
of runner load. C-level regex work is covered by the structural ReDoS lint and full
adversarial-input completion tests; these counters make no timing claim about it.
"""

from __future__ import annotations

import sys
import types
from collections.abc import Callable
from typing import Any

SCALE = 4


def _code_objects(module: types.ModuleType) -> list[types.CodeType]:
    """Every code object defined in ``module``: functions (through ``functools``
    wrappers), methods, and the functions nested in them."""
    found: list[types.CodeType] = []

    def walk(code: types.CodeType) -> None:
        found.append(code)
        for const in code.co_consts:
            if isinstance(const, types.CodeType):
                walk(const)

    def visit(value: Any) -> None:
        function = getattr(value, "__wrapped__", value)
        if isinstance(function, types.FunctionType) and function.__module__ == module.__name__:
            walk(function.__code__)

    for value in vars(module).values():
        if isinstance(value, type) and value.__module__ == module.__name__:
            for attribute in vars(value).values():
                visit(attribute)
        else:
            visit(value)
    return found


def python_line_events(module: types.ModuleType, call: Callable[[], Any]) -> int:
    """How many lines of ``module``'s own code ``call()`` runs (``sys.monitoring`` LINE
    events, local to those code objects): the same input always gives the same count,
    whatever the runner's load. Work done inside C (``str.find``, a regex) is not
    counted; the structural ReDoS lint checks regex backtracking shapes."""
    monitoring = sys.monitoring
    tool = next(i for i in range(6) if monitoring.get_tool(i) is None)
    count = 0

    def on_line(code: types.CodeType, line: int) -> None:
        nonlocal count
        count += 1

    codes = _code_objects(module)
    monitoring.use_tool_id(tool, "python_line_events")
    try:
        monitoring.register_callback(tool, monitoring.events.LINE, on_line)
        for code in codes:
            monitoring.set_local_events(tool, code, monitoring.events.LINE)
        try:
            call()
        finally:
            for code in codes:
                monitoring.set_local_events(tool, code, 0)
            monitoring.register_callback(tool, monitoring.events.LINE, None)
    finally:
        monitoring.free_tool_id(tool)
    return count
