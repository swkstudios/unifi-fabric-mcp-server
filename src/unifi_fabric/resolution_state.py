"""Carry partial selector enumeration through every tool result without caching it."""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from contextvars import ContextVar
from typing import Any

_reasons: ContextVar[list[str] | None] = ContextVar("resolution_incomplete_reasons", default=None)
_WRAPPED = "_unifi_resolution_wrapped"


def note_incomplete_resolution(reason: str | None) -> None:
    """Record a partial resolution on this call; child fanouts share the call's sink."""
    sink = _reasons.get()
    if reason and sink is not None and reason not in sink:
        sink.append(reason)


def with_resolution_state(result: Any, reasons: list[str]) -> Any:
    """Add incomplete provenance beside the original result, retaining every field."""
    if not reasons:
        return result
    if isinstance(result, dict):
        # deferred: tools import this module
        from .tools._keys import context_value, update_context

        existing = context_value(result, "_incompleteReason") or context_value(
            result, "incompleteReason"
        )
        detail = list(reasons)
        if isinstance(existing, str) and existing and existing not in detail:
            detail.insert(0, existing)
        # Beside the result: a colliding upstream field keeps its value, while the
        # server's own earlier marker is superseded.
        return update_context(result, {"_incomplete": True, "_incompleteReason": "; ".join(detail)})
    return {"result": result, "incomplete": True, "incompleteReason": "; ".join(reasons)}


def wrap_resolution_result(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Capture per-call resolution provenance on synchronous and async handlers."""
    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def wrapped(*args: Any, **kwargs: Any) -> Any:
            reasons: list[str] = []
            token = _reasons.set(reasons)
            try:
                result = await fn(*args, **kwargs)
            finally:
                _reasons.reset(token)
            return with_resolution_state(result, reasons)
    else:

        @functools.wraps(fn)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            reasons: list[str] = []
            token = _reasons.set(reasons)
            try:
                result = fn(*args, **kwargs)
            finally:
                _reasons.reset(token)
            return with_resolution_state(result, reasons)

    setattr(wrapped, _WRAPPED, True)
    return wrapped


def install_resolution_state(mcp: Any) -> int:
    """Wrap every registered handler, before result-shape transforms are installed."""
    components = mcp._local_provider._components  # noqa: SLF001
    count = 0
    for component in components.values():
        fn = getattr(component, "fn", None)
        if callable(fn) and not getattr(fn, _WRAPPED, False):
            component.fn = wrap_resolution_result(fn)
            count += 1
    return count
