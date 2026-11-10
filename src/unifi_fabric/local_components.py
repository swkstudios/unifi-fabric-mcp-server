"""The registered tool components of the server, read from its local provider.

The local provider holds tools, resources, resource templates and prompts in one map.
Every catalog pass (titles, annotations, API sources, schema shapes, redaction and
resolution wrappers, the request-policy catalog) works on tools only, so it reads them
through :func:`tool_components`, never from the raw map: a resource template also has
``parameters`` and ``fn`` and must never be titled, annotated or classified as a tool.
"""

from __future__ import annotations

from typing import Any


def tool_components(mcp: Any) -> list[Any]:
    """Every registered component of ``mcp`` that is not a resource, template or prompt.

    Raises ``AttributeError`` when FastMCP's local-provider layout changes, so each
    caller keeps its own fail-closed or fail-open handling of that case.
    """
    from fastmcp.prompts import Prompt
    from fastmcp.resources import Resource, ResourceTemplate

    components = mcp._local_provider._components  # noqa: SLF001 - registered catalog
    return [
        c for c in components.values() if not isinstance(c, (Resource, ResourceTemplate, Prompt))
    ]
