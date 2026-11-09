"""Server-only helpers shared by tool wrappers and the generated adapters.

The helpers that wrapper code used to import from ``server.py`` live here, so a wrapper
or adapter module does not import the server module (P3 helper boundary):

* :func:`_image_result` and :func:`_nullable_default` -- moved verbatim from
  ``server.py``; ``server.py`` re-exports them under the same names.
* :func:`_validate_optional_site` -- moved verbatim from ``server.py``.
* :func:`get_settings` and :func:`require_dependencies` -- accessors for the server's
  lifespan state. They read ``server.py``'s state at call time, so the server stays the
  one owner of that state and ``server._require()``'s existing error is the error a
  caller sees when the server is not initialized.

``require_dependencies`` is the zero-argument ``Callable[[], Dependencies]`` provider
that ``register_tool`` takes.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from fastmcp.tools.base import ToolResult
from mcp.types import ImageContent, TextContent
from pydantic.fields import FieldInfo

from ..contracts import Dependencies

if TYPE_CHECKING:
    from ..config import Settings
    from ..registry import Registry

__all__ = [
    "_image_result",
    "_nullable_default",
    "_validate_optional_site",
    "get_settings",
    "require_dependencies",
]


def _image_result(metadata: dict[str, Any]) -> ToolResult:
    """Serve image content and preserve the upstream image metadata for callers.

    The image is sent three times on purpose: as MCP image content, in the JSON text
    block (the structured-content compatibility copy) and in ``structured_content``,
    which carries the documented ``{image_base64, content_type, size_bytes}`` result for
    clients that read only text or structured content. Dropping a copy changes that
    result shape.
    """
    mime = (metadata.get("content_type") or "image/jpeg").split(";", 1)[0].strip()
    return ToolResult(
        content=[
            ImageContent(type="image", data=metadata["image_base64"], mime_type=mime),
            TextContent(type="text", text=json.dumps(metadata)),
        ],
        structured_content=metadata,
    )


def _nullable_default(value: Any, unset: Any) -> Any:
    """Resolve optional Field defaults for direct Python calls as well as MCP calls."""
    return unset if isinstance(value, FieldInfo) else value


async def _validate_optional_site(registry: Registry, host: str, site: str | None) -> None:
    """Reject a site that does not exist on the console (fail fast, valid sites listed)."""
    if site is not None:
        key = await registry.resolve_key_for_host(host)
        host_id = await registry.resolve_host_id(host, key=key)
        await registry.resolve_site_id(site, host_id, key=key)


def get_settings() -> Settings:
    """The server's lazily built :class:`Settings` (``server.get_settings``)."""
    from .. import server

    return server.get_settings()


def require_dependencies() -> Dependencies:
    """Return the lifespan-built client and registry as :class:`Dependencies`.

    Raises ``server._require()``'s existing error when the server is not initialized.
    """
    from .. import server

    client, registry = server._require()
    return Dependencies(client=client, registry=registry)
