"""Recent-event stream buffers: product compatibility, bounded buffers and listener lifecycle.

Network and Protect publish live events only over WebSocket: Protect documents
``GET /v1/subscribe/events`` and ``GET /v1/subscribe/devices`` in its Integration API
("A WebSocket subscription that broadcasts Protect events"), and the Network
application serves its event socket at ``wss/s/{site}/events``. This server reaches
consoles only through the UniFi Fabric connector (``/v1/connector/consoles/{id}/*path``),
which the Site Manager API documents as forwarding "using RESTful HTTP methods" with a
25-second limit on each proxied request. Whether a product's stream is reachable is
therefore a recorded, evidence-backed fact (:data:`COMPATIBILITY`), not a setting. A
product whose record is unsupported refuses a listener before any socket or upstream
request, and the event-stream tools report that state and name the history and polling
tools that do work. No direct-LAN transport is assumed.

On a product whose transport is supported, :class:`StreamManager` keeps one
:class:`StreamListener` per (product, console id, site) key. Each listener owns one
bounded :class:`EventBuffer`. Events are stored verbatim with a monotonic sequence
number, and the oldest are evicted first once the buffer is full. Evictions, disconnects
and reconnects are reported as counts and gap records, so a read never implies
uninterrupted coverage. Nothing expires by age. Buffers live in this process only and
are lost on restart. Reading a buffer never subscribes an MCP client to notifications;
this server sends no MCP push notifications for events.

Design credit: the recent-event buffer and listener-state reporting follow the approach of
the unifi-mcp project by Chris Kirby and contributors
(https://github.com/sirkirby/unifi-mcp, MIT licence), including Tyler Mowbrey's Network
listener-state work. No code from that project is copied here.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, NamedTuple

from .client import upstream_error_value

#: The products with a live event stream upstream.
PRODUCTS: tuple[str, ...] = ("network", "protect")

#: Default number of events one buffer holds before it evicts the oldest.
DEFAULT_BUFFER_CAPACITY = 1000

#: Seconds to wait before reconnect attempts 1, 2, 3, ...; the last value repeats.
#: Reconnecting never gives up on a transient failure.
RECONNECT_DELAYS: tuple[float, ...] = (1.0, 2.0, 5.0, 10.0, 30.0)

#: Listener states. ``inactive`` (no listener for the key) and ``unsupported`` (the
#: product's stream is not reachable over this server's transport) are reported by the
#: tools; a listener itself moves through the remaining states.
STATES: tuple[str, ...] = (
    "unsupported",
    "inactive",
    "connecting",
    "connected",
    "reconnecting",
    "error",
    "closed",
)


class StreamKey(NamedTuple):
    """The isolation key of one listener and its buffer."""

    product: str
    console_id: str
    site: str | None

    def as_dict(self) -> dict[str, Any]:
        return {"product": self.product, "console_id": self.console_id, "site": self.site}


class StreamUnsupportedError(RuntimeError):
    """A listener was requested for a product whose stream transport is not supported."""


class StreamRejectedError(Exception):
    """The upstream refused the stream (an HTTP status other than 101 Switching Protocols).

    A rejection is final for the listener: it moves to ``error`` and does not retry,
    because the same request would be refused again.
    """

    def __init__(self, status: int, detail: str = "") -> None:
        super().__init__(f"stream rejected with HTTP {status}" + (f": {detail}" if detail else ""))
        self.status = status


#: Opens one stream connection. Awaiting it completes the handshake (the listener is
#: attached from then on, before any event arrives) and returns an iterator of the
#: connection's events (each a JSON object). The iterator ending means the upstream closed
#: the stream; raising, in the handshake or later, means it failed.
#: :class:`StreamRejectedError` is final; any other error is retried.
Connect = Callable[[], Awaitable[AsyncIterator[dict[str, Any]]]]

#: Builds the connect function of one key: ``(client, api_key, stream_key) -> Connect``.
TransportFactory = Callable[[Any, Any, StreamKey], Connect]


@dataclass(frozen=True)
class PathProbe:
    """One recorded transport probe."""

    request: str
    observed: str

    def as_dict(self) -> dict[str, str]:
        return {"request": self.request, "observed": self.observed}


@dataclass(frozen=True)
class StreamCompatibility:
    """Whether a product's event stream is reachable over this server's transport."""

    product: str
    supported: bool
    transport: str
    stream: str
    summary: str
    checked: str
    probes: tuple[PathProbe, ...]
    fallback_tools: tuple[str, ...]
    #: Present only when ``supported``: builds the connect function for one key.
    transport_factory: TransportFactory | None = field(default=None, compare=False)

    def as_dict(self) -> dict[str, Any]:
        return {
            "product": self.product,
            "supported": self.supported,
            "transport": self.transport,
            "stream": self.stream,
            "summary": self.summary,
            "checked": self.checked,
            "evidence": [probe.as_dict() for probe in self.probes],
            "fallback_tools": list(self.fallback_tools),
        }


_CONNECTOR = "UniFi Fabric connector (GET /v1/connector/consoles/{id}/*path)"
_CONNECTOR_IS_UNARY = PathProbe(
    "WebSocket handshake to a plain REST route (protect/integration/v1/meta/info)",
    "HTTP 200 with the REST body: the connector forwards the request as plain HTTP and "
    "does not carry the Upgrade",
)

#: Recorded compatibility per product. Only new evidence (a probe answering
#: 101 Switching Protocols over this server's transport, or a documented relay) changes a
#: record; there is deliberately no setting that enables an unproven stream.
COMPATIBILITY: dict[str, StreamCompatibility] = {
    "network": StreamCompatibility(
        product="network",
        supported=False,
        transport=_CONNECTOR,
        stream="Network application event socket wss/s/{site}/events",
        summary=(
            "Not reachable: the Fabric connector is a request/response relay and the "
            "Network event socket answers HTTP 404 through it. The published Network "
            "Integration API (v11.0.97) defines no event stream."
        ),
        checked="2026-11-08, UniFi OS 6.0.130 console, Network Integration API v11.0.97",
        probes=(
            PathProbe(
                "WebSocket handshake to proxy/network/wss/s/default/events",
                "HTTP 404 (Network application not-found page), never 101",
            ),
            _CONNECTOR_IS_UNARY,
            PathProbe(
                "WebSocket handshake to api/ws/system (console system socket)",
                "HTTP 403 forbidden (insufficient permissions for this endpoint)",
            ),
        ),
        fallback_tools=("list_network_events", "get_system_log", "list_ips_events"),
    ),
    "protect": StreamCompatibility(
        product="protect",
        supported=False,
        transport=_CONNECTOR,
        stream="Protect Integration API GET /v1/subscribe/events and /v1/subscribe/devices",
        summary=(
            "Not reachable: the Fabric connector is a request/response relay; both Protect "
            "subscription endpoints answer HTTP 404 through it."
        ),
        checked="2026-11-08, UniFi OS 6.0.130 console, Protect 7.3.74",
        probes=(
            PathProbe(
                "WebSocket handshake to proxy/protect/integration/v1/subscribe/events",
                "HTTP 404 Entity 'endpoint' not found, never 101",
            ),
            PathProbe(
                "WebSocket handshake to proxy/protect/integration/v1/subscribe/devices",
                "HTTP 404 Entity 'endpoint' not found, never 101",
            ),
            PathProbe(
                "WebSocket handshake to proxy/protect/ws/updates (private update socket)",
                "HTTP 302 redirect to the console login page, never 101",
            ),
            _CONNECTOR_IS_UNARY,
        ),
        fallback_tools=(
            "list_protect_events",
            "collect_protect_events",
            "collect_protect_device_changes",
        ),
    ),
}


def compatibility(product: str) -> StreamCompatibility:
    """The recorded compatibility of ``product`` (one of :data:`PRODUCTS`)."""
    try:
        return COMPATIBILITY[product]
    except KeyError:
        raise ValueError(
            f"Unknown event-stream product {product!r}; valid products: {', '.join(PRODUCTS)}"
        ) from None


def _now() -> float:
    return time.time()


class EventBuffer:
    """A bounded, in-memory buffer of one listener's events, oldest evicted first.

    Every event gets the next sequence number (1, 2, 3, ...) of this buffer. When the
    buffer is full, appending evicts exactly the oldest event, so eviction order is the
    arrival order and does not depend on content or time. Events are stored as received
    and never modified; a read returns each one under ``event`` next to its ``seq`` and
    ``received_at``.
    """

    def __init__(
        self, capacity: int = DEFAULT_BUFFER_CAPACITY, *, clock: Callable[[], float] = _now
    ) -> None:
        if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity < 1:
            raise ValueError(f"buffer capacity must be a positive integer, got {capacity!r}")
        self._items: deque[tuple[int, float, Any]] = deque(maxlen=capacity)
        self._clock = clock
        self.capacity = capacity
        self.last_seq = 0
        self.evicted = 0

    def __len__(self) -> int:
        return len(self._items)

    @property
    def oldest_seq(self) -> int | None:
        return self._items[0][0] if self._items else None

    def append(self, event: Any) -> int:
        """Store ``event`` and return its sequence number."""
        if len(self._items) == self.capacity:
            self.evicted += 1
        self.last_seq += 1
        self._items.append((self.last_seq, self._clock(), event))
        return self.last_seq

    def stats(self) -> dict[str, Any]:
        return {
            "buffered": len(self._items),
            "capacity": self.capacity,
            "evicted": self.evicted,
            "oldest_seq": self.oldest_seq,
            "last_seq": self.last_seq,
        }

    def read(self, after_seq: int | None = None, limit: int | None = None) -> dict[str, Any]:
        """Events after ``after_seq`` (oldest first), or the newest ``limit`` events.

        With ``after_seq``, returns the events whose ``seq`` is greater, oldest first,
        at most ``limit`` of them. ``next_after_seq`` is the cursor for the next read,
        and ``more`` is true while newer events remain. ``missed`` reports events evicted
        before this read could return them. Without ``after_seq``, returns the newest
        ``limit`` events (all buffered when ``limit`` is omitted), oldest first.
        """
        if after_seq is not None and after_seq > self.last_seq:
            raise ValueError(
                f"after_seq {after_seq} is beyond this buffer's newest seq {self.last_seq}; "
                "use a next_after_seq this listener returned (a restarted server starts again at 0)"
            )
        if after_seq is None:
            selected = list(self._items)
            if limit is not None:
                selected = selected[-limit:] if limit else []
        else:
            selected = [item for item in self._items if item[0] > after_seq]
            if limit is not None:
                selected = selected[:limit]
        out: dict[str, Any] = {
            "events": [
                {"seq": seq, "received_at": received, "event": event}
                for seq, received, event in selected
            ],
            **self.stats(),
        }
        oldest = self.oldest_seq
        first_wanted = (after_seq + 1) if after_seq is not None else None
        if first_wanted is not None and oldest is not None and first_wanted < oldest:
            out["missed"] = {"from_seq": first_wanted, "to_seq": oldest - 1, "reason": "evicted"}
        last_returned = selected[-1][0] if selected else (after_seq or 0)
        if after_seq is None and not selected:
            last_returned = self.last_seq
        out["next_after_seq"] = last_returned
        out["more"] = last_returned < self.last_seq
        return out


def describe_error(exc: BaseException) -> str:
    """A listener's last error: exception class and HTTP status only.

    The message text is left out because a transport error can echo request headers.
    """
    status = getattr(exc, "status", None)
    if status is None:
        status = getattr(getattr(exc, "response", None), "status_code", None)
    return f"{type(exc).__name__}" + (f" (HTTP {status})" if isinstance(status, int) else "")


class StreamListener:
    """One stream connection kept open for one key, with reconnect and gap tracking."""

    def __init__(
        self,
        key: StreamKey,
        connect: Connect,
        *,
        capacity: int = DEFAULT_BUFFER_CAPACITY,
        reconnect_delays: Sequence[float] = RECONNECT_DELAYS,
        sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
        clock: Callable[[], float] = _now,
    ) -> None:
        if not reconnect_delays:
            raise ValueError("reconnect_delays must name at least one delay")
        self.key = key
        self._connect = connect
        self._delays = tuple(reconnect_delays)
        self._sleep = sleep
        self._clock = clock
        self.buffer = EventBuffer(capacity, clock=clock)
        self.state = "connecting"
        self.created_at = clock()
        self.coverage_started_at: float | None = None
        self.connected_since: float | None = None
        self.last_error: str | None = None
        self.last_error_at: float | None = None
        self.connects = 0
        self.disconnects = 0
        self.reconnect_attempts = 0
        self.gaps: list[dict[str, Any]] = []
        self._task: asyncio.Task[None] | None = None

    @property
    def attached(self) -> bool:
        return self.state == "connected"

    def start(self) -> None:
        """Start the background connection task (idempotent)."""
        if self._task is None and self.state != "closed":
            self._task = asyncio.get_running_loop().create_task(self._run())

    def _open_gap(self, reason: str) -> None:
        self.gaps.append(
            {
                "after_seq": self.buffer.last_seq,
                "started_at": self._clock(),
                "ended_at": None,
                "reason": reason,
            }
        )

    async def _run(self) -> None:
        failures = 0
        while True:
            try:
                stream = await self._connect()
                self._on_connected()
                failures = 0
                async for event in stream:
                    self.buffer.append(event)
                self._on_disconnected("upstream closed the stream")
            except asyncio.CancelledError:
                raise
            except StreamRejectedError as exc:
                self._on_error(exc)
                self.state = "error"
                return
            except Exception as exc:  # noqa: BLE001 - any transport failure is retried
                self._on_error(exc)
            failures += 1
            self.state = "reconnecting"
            self.reconnect_attempts += 1
            await self._sleep(self._delays[min(failures, len(self._delays)) - 1])

    def _on_connected(self) -> None:
        now = self._clock()
        self.state = "connected"
        self.connects += 1
        self.connected_since = now
        if self.coverage_started_at is None:
            self.coverage_started_at = now
        if self.gaps and self.gaps[-1]["ended_at"] is None:
            self.gaps[-1]["ended_at"] = now

    def _on_disconnected(self, reason: str) -> None:
        if self.state == "connected":
            self.state = "reconnecting"
            self.disconnects += 1
            self.connected_since = None
            self._open_gap(reason)

    def _on_error(self, exc: BaseException) -> None:
        self.last_error = describe_error(exc)
        self.last_error_at = self._clock()
        if self.state == "connected":
            self._on_disconnected(f"error: {self.last_error}")

    async def close(self) -> None:
        """Stop the listener and drop its connection (idempotent). The buffer is kept."""
        task, self._task = self._task, None
        if self.state == "connected":
            self._on_disconnected("listener closed")
        self.state = "closed"
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    def status(self) -> dict[str, Any]:
        return {
            **self.key.as_dict(),
            "state": self.state,
            "attached": self.attached,
            "created_at": self.created_at,
            "coverage_started_at": self.coverage_started_at,
            "connected_since": self.connected_since,
            "connects": self.connects,
            "disconnects": self.disconnects,
            "reconnect_attempts": self.reconnect_attempts,
            "last_error": self.last_error,
            "last_error_at": self.last_error_at,
            "gaps": [dict(gap) for gap in self.gaps],
            **self.buffer.stats(),
        }


def _sort_key(item: tuple[StreamKey, Any]) -> tuple[str, ...]:
    return tuple(str(part) for part in item[0])


class StreamManager:
    """The listeners of this server process, one per key, created only on supported products."""

    def __init__(
        self,
        *,
        capacity: int = DEFAULT_BUFFER_CAPACITY,
        reconnect_delays: Sequence[float] = RECONNECT_DELAYS,
        sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
        clock: Callable[[], float] = _now,
        records: dict[str, StreamCompatibility] | None = None,
    ) -> None:
        self._listeners: dict[StreamKey, StreamListener] = {}
        self._capacity = capacity
        self._delays = tuple(reconnect_delays)
        self._sleep = sleep
        self._clock = clock
        self._records = records

    def compatibility(self, product: str) -> StreamCompatibility:
        if self._records is not None:
            if product not in self._records:
                raise ValueError(
                    f"Unknown event-stream product {product!r}; "
                    f"valid products: {', '.join(PRODUCTS)}"
                )
            return self._records[product]
        return compatibility(product)

    def get(self, key: StreamKey) -> StreamListener | None:
        return self._listeners.get(key)

    def listeners(self, product: str | None = None) -> list[StreamListener]:
        return [
            listener
            for key, listener in sorted(
                self._listeners.items(), key=lambda kv: tuple(map(str, kv[0]))
            )
            if product is None or key.product == product
        ]

    def attach(self, key: StreamKey, client: Any = None, api_key: Any = None) -> StreamListener:
        """The listener for ``key``, started now if none is running.

        Raises :class:`StreamUnsupportedError` before any connection attempt when the
        product's stream is not supported. A closed or rejected listener is replaced.
        """
        record = self.compatibility(key.product)
        if not record.supported or record.transport_factory is None:
            raise StreamUnsupportedError(
                f"{key.product} event stream is not supported over this server's transport: "
                f"{upstream_error_value(record.summary)} Use "
                f"{upstream_error_value(', '.join(record.fallback_tools))} instead."
            )
        existing = self._listeners.get(key)
        if existing is not None and existing.state not in ("closed", "error"):
            return existing
        listener = StreamListener(
            key,
            record.transport_factory(client, api_key, key),
            capacity=self._capacity,
            reconnect_delays=self._delays,
            sleep=self._sleep,
            clock=self._clock,
        )
        self._listeners[key] = listener
        listener.start()
        return listener

    async def close(self, key: StreamKey) -> bool:
        """Close and forget the listener of ``key``; False when there was none."""
        listener = self._listeners.pop(key, None)
        if listener is None:
            return False
        await listener.close()
        return True

    async def close_all(self) -> int:
        """Close and forget every listener (server shutdown); returns how many."""
        keys = list(self._listeners)
        for key in keys:
            await self.close(key)
        return len(keys)


#: The process-wide manager the tools use; the server lifespan closes it at shutdown.
MANAGER = StreamManager()
