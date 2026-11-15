"""Event-stream tools: stream compatibility, listener health and recent-event buffer reads.

Both tools read this server's own state (:mod:`unifi_fabric.stream_buffers`).
``get_event_stream_status`` makes no upstream request. ``read_recent_events`` resolves its host
(and Network site) first, so an unknown one fails with the valid choices; for a product whose
stream is not reachable over the Fabric connector (Network and Protect today) it then reports
the product as unsupported, with the recorded evidence and the history and polling tools to
use instead, and opens no stream. Neither tool subscribes the MCP client to
anything; this server sends no MCP push notifications for events.
"""

from __future__ import annotations

from typing import Any

from ... import stream_buffers
from ...registry import Registry
from ...stream_buffers import StreamKey
from .schemas import (
    _PUSH_NOTE,
)
from .schemas import (  # the family's shapes (family-owned layout)
    Product as Product,
)


def _unsupported(record: stream_buffers.StreamCompatibility, **echo: Any) -> dict[str, Any]:
    return {
        **echo,
        "product": record.product,
        "state": "unsupported",
        "supported": False,
        "attached": False,
        "reason": record.summary,
        "compatibility": record.as_dict(),
        "use_instead": list(record.fallback_tools),
        "note": _PUSH_NOTE,
    }


def _check_site_selector(product: str, site: str | None) -> None:
    """Protect events are per console; Network events are per site."""
    if product == "protect" and site is not None:
        raise ValueError(
            "site is a Network selector; Protect events are per console, so omit site "
            "for product 'protect'"
        )
    if product == "network" and site is None:
        raise ValueError(
            "site is required for product 'network': pass the Network site name or id "
            "from list_local_sites (e.g. 'Default')"
        )


def event_stream_status(
    product: str | None = None, manager: stream_buffers.StreamManager | None = None
) -> dict[str, Any]:
    """Per-product compatibility and every listener of this process (no upstream request)."""
    manager = manager or stream_buffers.MANAGER
    products = stream_buffers.PRODUCTS if product is None else (product,)
    out = []
    for name in products:
        record = manager.compatibility(name)
        listeners = [listener.status() for listener in manager.listeners(name)]
        if not record.supported:
            state = "unsupported"
        elif any(item["state"] == "connected" for item in listeners):
            state = "connected"
        else:
            state = "inactive" if not listeners else listeners[0]["state"]
        out.append({**record.as_dict(), "state": state, "listeners": listeners})
    return {"products": out, "note": _PUSH_NOTE}


async def read_recent_event_buffer(
    registry: Registry | None,
    client: Any,
    product: str,
    host: str,
    site: str | None = None,
    after_seq: int | None = None,
    limit: int | None = None,
    manager: stream_buffers.StreamManager | None = None,
) -> dict[str, Any]:
    """One key's buffered events and listener state; see ``read_recent_events``."""
    manager = manager or stream_buffers.MANAGER
    record = manager.compatibility(product)
    _check_site_selector(product, site)
    if registry is None:
        raise RuntimeError("the server registry is not available")
    api_key = await registry.resolve_key_for_host(host)
    console_id = await registry.resolve_host_id(host, key=api_key)
    site_key = (
        await registry.resolve_site_slug(site, console_id, key=api_key)
        if site is not None
        else None
    )
    if not record.supported:
        # Host and site are resolved (an unknown one has failed with the valid choices);
        # no listener can exist for an unsupported product, so no stream is opened.
        return _unsupported(record, host=host, site=site, console_id=console_id, site_key=site_key)
    key = StreamKey(product, console_id, site_key)
    listener = manager.get(key)
    started = False
    if listener is None or listener.state == "closed":
        # A listener in "error" was rejected by the upstream and is reported as it is:
        # the same request would be rejected again.
        listener = manager.attach(key, client, api_key)
        started = True
    page = listener.buffer.read(after_seq=after_seq, limit=limit)
    out: dict[str, Any] = {**listener.status(), **page, "note": _PUSH_NOTE}
    if started:
        out["listener_started"] = True
        out["hint"] = (
            "A server-side listener was started by this read; events are buffered from "
            "coverage_started_at onward. Read again with after_seq=next_after_seq. Earlier "
            f"events: {', '.join(record.fallback_tools)}."
        )
    return out
