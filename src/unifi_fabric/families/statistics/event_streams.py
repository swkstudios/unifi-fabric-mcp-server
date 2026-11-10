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

from collections.abc import Callable
from typing import Annotated, Any, Literal

from fastmcp import FastMCP
from pydantic import Field

from ... import stream_buffers
from ...registry import Registry
from ...stream_buffers import StreamKey
from ...tool_annotations import READ_ONLY

Product = Literal["network", "protect"]

_PUSH_NOTE = (
    "Reading a buffer never subscribes the MCP client to notifications; this server sends "
    "no MCP push notifications for events."
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


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the event-stream tools."""

    @mcp.tool(annotations=READ_ONLY)
    async def get_event_stream_status(
        product: Annotated[
            Product | None,
            Field(
                description=(
                    "Optional product: 'network' or 'protect'. Omit for both. Example: \"protect\"."
                )
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Report whether live Network and Protect event streams are available, and listener health.

        Reads this server's own state only; no console request is made. For each product it
        returns the recorded transport compatibility and the evidence behind it, and every
        listener this server process holds. Network and Protect publish live events only over
        WebSocket, and the UniFi Fabric connector this server uses is a request/response relay
        that does not carry WebSocket. Both products are therefore reported with state
        "unsupported" and supported false, and use_instead names the history and polling
        tools (list_network_events, get_system_log, list_ips_events; list_protect_events,
        collect_protect_events, collect_protect_device_changes). Nothing here subscribes the
        MCP client to notifications.

        Returns {products: [{product, supported, state, transport, stream, summary, checked,
        evidence: [{request, observed}], fallback_tools, listeners: [...]}], note}. state is
        "unsupported" (no reachable stream), "inactive" (supported, no listener), or the state
        of a listener: "connecting", "connected", "reconnecting", "error" or "closed". Each
        listener reports {product, console_id, site, state, attached, coverage_started_at,
        connects, disconnects, reconnect_attempts, last_error, gaps: [{after_seq, started_at,
        ended_at, reason}], buffered, capacity, evicted, oldest_seq, last_seq}; times are epoch
        seconds.

        Example call (get_event_stream_status):
            {"product": "protect"}

        Args:
            product: Optional product, "network" or "protect"; omit for both. Example: "protect".
        """
        return event_stream_status(product)

    @mcp.tool(annotations=READ_ONLY)
    async def read_recent_events(
        product: Annotated[
            Product,
            Field(description="Product whose event buffer to read: 'network' or 'protect'."),
        ],
        host: Annotated[
            str,
            Field(
                description=(
                    "Console name or id from list_hosts (reportedState.hostname or name, or "
                    'the long data[].id). Example: "my-console".'
                )
            ),
        ],
        site: Annotated[
            str | None,
            Field(
                description=(
                    'Network site name or id from list_local_sites (e.g. "Default"); '
                    "required for 'network', omit for 'protect'."
                )
            ),
        ] = None,
        after_seq: Annotated[
            int | None,
            Field(
                ge=0,
                description=(
                    "Cursor: return events with seq greater than this, oldest first. Pass the "
                    "next_after_seq of the previous read. Omit to get the newest events."
                ),
            ),
        ] = None,
        max_events: Annotated[
            int | None,
            Field(
                ge=1,
                description=(
                    "Optional maximum number of events to return. Omit to return every "
                    "matching buffered event. Example: 100."
                ),
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Read recent live events for one console; both products answer unsupported today.

        Network and Protect live event streams are not reachable through the UniFi Fabric
        connector this server uses (see get_event_stream_status). For both products this tool
        resolves host (and site; an unknown one fails listing the valid choices) and opens no
        stream. Returns {product, host, site, console_id, site_key, state: "unsupported",
        supported: false, attached: false, reason, compatibility, use_instead, note} with no
        events key, so an unsupported stream is never mistaken for a quiet one. Use the tools
        in use_instead for event history: list_network_events / get_system_log /
        list_ips_events for Network, list_protect_events / collect_protect_events /
        collect_protect_device_changes for Protect.

        A supported stream would be read from a bounded in-memory buffer by after_seq cursor;
        none is supported, so after_seq and max_events have no effect today. Reading never
        subscribes the MCP client to notifications.

        Example call (read_recent_events):
            {"product": "protect", "host": "my-console"}

        Args:
            product: "network" or "protect". Example: "protect".
            host: Console name or id from list_hosts. Example: "my-console".
            site: Network site name or id from list_local_sites (e.g. "Default"); required for
                "network", omit for "protect".
            after_seq: Cursor; events with a greater seq, oldest first. Pass next_after_seq from
                the previous read. Omit for the newest events. Example: 120.
            max_events: Optional maximum number of events returned; omit for all. Example: 100.
        """
        client, registry = deps_fn()
        return await read_recent_event_buffer(
            registry, client, product, host, site, after_seq, max_events
        )
