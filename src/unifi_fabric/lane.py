"""Per-request lane attribution: ``X-UF-Lane: <run-id>/<unit-id>``.

Live acceptance runs count upstream writes over a time window, so two steps running at once
could not be told apart. A caller that sends ``X-UF-Lane: <run-id>/<unit-id>`` on an MCP call
tags every upstream request that call makes:

* the upstream request log line (``HTTP Request: ... lane=<run-id>/<unit-id>``), the
  source the live-test window accounting reads;
* the write audit record (``lane`` field), when the audit log is on;
* the connector pacing counters (:mod:`unifi_fabric.pacing`).

The tag is an opaque label for accounting. It grants nothing: it never changes policy,
credentials, routing or the write gate, and a call without it behaves exactly as before.
A present but malformed (or repeated) header is refused before any upstream call, so a
typo cannot silently move a write out of its lane.
"""

from __future__ import annotations

import contextvars
import re
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any, Final

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext

LANE_HEADER: Final = "x-uf-lane"
#: ``<run-id>/<unit-id>``: each part starts alphanumeric, then letters, digits, ``.``,
#: ``_``, ``:`` or ``-``, at most 64 characters (so a tag is at most 129 characters).
LANE_PATTERN: Final = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}/[A-Za-z0-9][A-Za-z0-9._:-]{0,63}"
)

_LANE: contextvars.ContextVar[str | None] = contextvars.ContextVar("uf_lane", default=None)

HeaderSource = Callable[[str], "list[str] | None"]


class InvalidLaneError(ValueError):
    """The ``X-UF-Lane`` header is malformed or repeated."""


def parse_lane(values: list[str] | None) -> str | None:
    """The lane tag in the header ``values``, ``None`` when absent, else ``InvalidLaneError``."""
    if not values:
        return None
    if len(values) != 1:
        raise InvalidLaneError("X-UF-Lane must be sent at most once per request")
    value = values[0]
    if not LANE_PATTERN.fullmatch(value):
        raise InvalidLaneError(
            "X-UF-Lane must be '<run-id>/<unit-id>': each part 1-64 characters of letters, "
            "digits, '.', '_', ':' or '-', starting with a letter or digit"
        )
    return value


def current_lane() -> str | None:
    """The lane tag of the call running now, else ``None``."""
    return _LANE.get()


@contextmanager
def lane_scope(value: str | None) -> Iterator[None]:
    """Run a block with ``value`` as the current lane (``None`` keeps the enclosing one)."""
    if value is None:
        yield
        return
    token = _LANE.set(value)
    try:
        yield
    finally:
        _LANE.reset(token)


def _raw_header_values(name: str) -> list[str] | None:
    from .header_credentials import _raw_header_values as raw

    return raw(name)


class LaneMiddleware(Middleware):
    """Bind the call's ``X-UF-Lane`` tag for everything the call sends upstream.

    Nested dispatch (``call_read_tool`` / ``call_write_tool``) re-enters the chain inside
    the same request, so the tag is read again from the same header and stays the same.
    """

    def __init__(self, headers: HeaderSource | None = None) -> None:
        self._headers = headers or _raw_header_values

    async def on_call_tool(
        self, context: MiddlewareContext[Any], call_next: CallNext[Any, Any]
    ) -> Any:
        try:
            lane = parse_lane(self._headers(LANE_HEADER))
        except InvalidLaneError as exc:
            raise ToolError(str(exc)) from None
        with lane_scope(lane):
            return await call_next(context)
