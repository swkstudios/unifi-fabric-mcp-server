"""Runtime support for the generated handler adapters (src/unifi_fabric/_generated/adapters).

A generated adapter ``async def <name>(request_context, validated_arguments, dependencies)``
calls the unchanged wrapper of public tool ``<name>`` with exactly
``**validated_arguments`` and returns its result unchanged. The wrapper is the function
registered for that public name, resolved here by name (never by module path), so moving a
wrapper between modules does not change any adapter.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

#: The FastMCP local-provider component key of a registered tool.
_KEY = "tool:{name}@"


def registered_wrapper(name: str) -> Callable[..., Awaitable[Any]]:
    """The wrapper function registered for public tool ``name``.

    Raises ``LookupError`` when no tool of that name is registered: a discovery meta tool
    outside discovery mode, or a tool that family selection, read-only mode, an area
    opt-out or the API-source filter de-registered. Until registration goes through
    ``register_tool``, adapters resolve against the live roster. A tool whose step is
    deferred (public #41) is loaded first, through the one load path, so its wrapper is
    the real one with every install pass applied; a failed load raises
    ``family_load_failed``.
    """
    from .catalog import deferred
    from .server import mcp

    controller = deferred.controller_for(mcp)
    if controller is not None:
        controller.resolve_sync(name)

    try:
        components = mcp._local_provider._components  # noqa: SLF001 - registered catalog
    except AttributeError as exc:  # pragma: no cover - FastMCP layout guard
        raise RuntimeError("cannot read the registered tool catalog") from exc
    component = components.get(_KEY.format(name=name))
    fn = getattr(component, "fn", None)
    if fn is None:
        raise LookupError(f"no registered tool {name!r}")
    return fn
