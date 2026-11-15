"""Names the protect family's ``protect`` shares with other families.

Used by innerspace, protect. Moved verbatim by ``scripts/move_family.py`` from
``families/protect/protect.py``, which import them back where they use them, so their own code and
import paths stay.
"""

from __future__ import annotations

from typing import Any

from ..client import UniFiClient, UniFiConnectionError, describe_shape
from ..registry import Registry
from ..shared_shapes._keys import with_context

PROTECT_PROXY_BASE = "/v1/connector/consoles/{host_id}/proxy/protect/integration/v1"


def _proxy(host_id: str, path: str) -> str:
    return PROTECT_PROXY_BASE.format(host_id=host_id) + path


def _as_list(data: Any, what: str = "Protect list") -> list[Any]:
    """Normalise a list-or-{'data': [...]} upstream body to a plain list.

    Any other shape raises with the shape received: reading it as an empty list would
    report "no items" (and, for the device-change collector, every device "removed").
    """
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        inner = data.get("data")
        if isinstance(inner, list):
            return inner
    raise UniFiConnectionError(
        f"Unexpected Protect response shape for {what}: expected an array or an object with "
        f"a 'data' array, got {describe_shape(data)}"
    )


def _list_body(data: Any, what: str) -> dict[str, Any]:
    """A Protect list response as the tool result, never under an invented key.

    A bare JSON array (what these endpoints answer) is returned under ``result``, the
    key FastMCP itself uses for a list result; an object carrying a ``data`` array is
    returned verbatim. Either way the additive ``_count`` is the number of items. Any
    other shape raises naming the shape received.
    """
    items = _as_list(data, what)
    out: dict[str, Any] = dict(data) if isinstance(data, dict) else {"result": items}
    return with_context(out, {"_count": len(items)})


async def list_cameras(
    client: UniFiClient,
    registry: Registry,
    host: str,
) -> dict[str, Any]:
    """List all cameras on a Protect console.

    This endpoint is not paginated: verified live it returns a bare JSON array with
    no offset/limit/count/totalCount envelope and no cursor, and offset/limit query
    params have no effect on the response. The array is the complete camera set, so
    the single fetch below returns everything and needs no drain.
    """
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.get(_proxy(host_id, "/cameras"), key=key)
    return _list_body(data, "cameras")


async def list_sensors(
    client: UniFiClient,
    registry: Registry,
    host: str,
) -> dict[str, Any]:
    """List all sensors on a Protect console."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.get(_proxy(host_id, "/sensors"), key=key)
    return _list_body(data, "sensors")
