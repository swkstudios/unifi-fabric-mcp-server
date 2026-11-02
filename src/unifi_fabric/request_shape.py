"""Advisory links between typed body builders and captured request-shape evidence.

Markers leave the callable and accepted inputs unchanged. Evidence is checked by
repository tests, never by the request path.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class RequestShape:
    tool: str
    args: tuple[str, ...]
    evidence: str


def request_shape[F: Callable](
    *, tool: str, args: tuple[str, ...], evidence: str
) -> Callable[[F], F]:
    """Attach an evidence key (optionally formatted with ``{argument}``) unchanged."""

    def decorate(fn: F) -> F:
        markers = (*getattr(fn, "__request_shapes__", ()), RequestShape(tool, args, evidence))
        fn.__request_shapes__ = markers  # type: ignore[attr-defined]
        return fn

    return decorate
