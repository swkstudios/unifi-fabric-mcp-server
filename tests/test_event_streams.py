"""Event-stream compatibility, bounded buffers, listener lifecycle and the two read tools.

Network and Protect streams are recorded as unsupported over the Fabric connector, so the
tools must report that state, name the history/polling tools, and make no upstream request.
The buffer and listener engine is exercised against a simulated stream transport: bounded
deterministic eviction, per-key isolation, attach / disconnect / reconnect / error / gap /
cleanup state, and cursor reads.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from typing import Any

import httpx
import pytest
from fastmcp import Client, FastMCP

from unifi_fabric import server, stream_buffers
from unifi_fabric.config import Settings
from unifi_fabric.families import build_family_index
from unifi_fabric.families.statistics.event_streams import (
    event_stream_status,
    read_recent_event_buffer,
)
from unifi_fabric.stream_buffers import (
    COMPATIBILITY,
    EventBuffer,
    StreamKey,
    StreamListener,
    StreamManager,
    StreamRejectedError,
    StreamUnsupportedError,
    describe_error,
)

TOOLS = ("get_event_stream_status", "read_recent_events")
NET_A = StreamKey("network", "console-a", "default")
NET_A2 = StreamKey("network", "console-a", "branch")
NET_B = StreamKey("network", "console-b", "default")
PROTECT_A = StreamKey("protect", "console-a", None)


# --- simulated transport ---------------------------------------------------------------


class SimulatedStream:
    """A scripted upstream: each connect() plays the next session.

    A session is a list. An exception as its FIRST item fails the handshake; otherwise the
    handshake succeeds and the items are played in order: an event is delivered, an
    exception is raised mid-stream, and ``"hold"`` keeps the connection open until
    cancelled. A session without ``"hold"`` ends with the upstream closing the stream.
    """

    def __init__(self, *sessions: list[Any]) -> None:
        self.sessions = list(sessions)
        self.connects = 0
        self.held = asyncio.Event()

    async def __call__(self):
        self.connects += 1
        session = self.sessions.pop(0) if self.sessions else ["hold"]
        await asyncio.sleep(0)
        if session and isinstance(session[0], BaseException):
            raise session[0]
        return self._play(session)

    async def _play(self, session):
        for item in session:
            if isinstance(item, BaseException):
                raise item
            if item == "hold":
                self.held.set()
                await asyncio.Event().wait()
            yield item
            await asyncio.sleep(0)


class Sleeps:
    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)
        await asyncio.sleep(0)


class Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        self.now += 1.0
        return self.now


async def settle(predicate, rounds: int = 500) -> None:
    for _ in range(rounds):
        if predicate():
            return
        await asyncio.sleep(0)
    raise AssertionError("simulated stream did not reach the expected state")


def supported_records(factory) -> dict[str, stream_buffers.StreamCompatibility]:
    """Compatibility records with both products marked supported on a simulated transport."""
    return {
        name: replace(record, supported=True, transport_factory=factory)
        for name, record in COMPATIBILITY.items()
    }


# --- compatibility (evidence-gated) ------------------------------------------------------


def test_network_and_protect_are_recorded_separately_as_unsupported_with_evidence():
    assert set(COMPATIBILITY) == {"network", "protect"} == set(stream_buffers.PRODUCTS)
    for product, record in COMPATIBILITY.items():
        assert record.product == product
        assert record.supported is False
        assert record.transport_factory is None
        assert record.probes, f"{product}: no recorded probe"
        assert all(
            "101" not in probe.observed or "never 101" in probe.observed for probe in record.probes
        )
        assert record.checked.startswith("2026-")
    network, protect = COMPATIBILITY["network"], COMPATIBILITY["protect"]
    assert any("wss/s/default/events" in p.request for p in network.probes)
    assert any("subscribe/events" in p.request for p in protect.probes)
    assert any("subscribe/devices" in p.request for p in protect.probes)
    # The two products carry their own evidence, not a shared verdict.
    assert network.probes != protect.probes


def test_fallback_tools_are_registered():
    tools = {tool.name: tool for tool in asyncio.run(server.mcp.list_tools())}
    for record in COMPATIBILITY.values():
        for name in record.fallback_tools:
            assert name in tools, f"{record.product} fallback {name} is not registered"


def test_unknown_product_lists_valid_products():
    with pytest.raises(ValueError, match="valid products: network, protect"):
        stream_buffers.compatibility("access")


async def test_attach_on_unsupported_product_refuses_before_any_connection():
    calls = []

    def factory(*args):
        calls.append(args)
        raise AssertionError("an unsupported product must never open a connection")

    manager = StreamManager(
        records={k: replace(v, transport_factory=factory) for k, v in COMPATIBILITY.items()}
    )
    for key in (NET_A, PROTECT_A):
        with pytest.raises(StreamUnsupportedError, match="not supported") as info:
            manager.attach(key)
        for name in COMPATIBILITY[key.product].fallback_tools:
            assert name in str(info.value)
    assert calls == []
    assert manager.listeners() == []


# --- bounded buffer ---------------------------------------------------------------------


def test_buffer_evicts_oldest_first_deterministically():
    buffer = EventBuffer(3, clock=Clock())
    seqs = [buffer.append({"id": n}) for n in range(1, 8)]
    assert seqs == [1, 2, 3, 4, 5, 6, 7]
    assert len(buffer) == 3
    page = buffer.read()
    assert [e["event"] for e in page["events"]] == [{"id": 5}, {"id": 6}, {"id": 7}]
    assert [e["seq"] for e in page["events"]] == [5, 6, 7]
    assert (page["evicted"], page["oldest_seq"], page["last_seq"], page["capacity"]) == (4, 5, 7, 3)
    # Same input, same result: eviction does not depend on content or time.
    again = EventBuffer(3, clock=Clock())
    for n in range(1, 8):
        again.append({"id": n})
    assert again.read()["events"] == page["events"]


def test_buffer_never_grows_past_capacity():
    buffer = EventBuffer(5)
    for n in range(10_000):
        buffer.append(n)
        assert len(buffer) <= 5
    assert buffer.evicted == 10_000 - 5


@pytest.mark.parametrize("capacity", [0, -1, True, 2.5, "10", None])
def test_buffer_capacity_must_be_a_positive_integer(capacity):
    with pytest.raises(ValueError, match="positive integer"):
        EventBuffer(capacity)


def test_events_are_stored_verbatim():
    event = {"type": "motion", "nested": {"a": [1, 2]}, "_keep": None}
    buffer = EventBuffer(2)
    buffer.append(event)
    assert buffer.read()["events"][0]["event"] == {
        "type": "motion",
        "nested": {"a": [1, 2]},
        "_keep": None,
    }


def test_cursor_reads_report_evicted_gap_and_progress():
    buffer = EventBuffer(4)
    for n in range(1, 4):
        buffer.append(n)
    first = buffer.read(after_seq=0, limit=2)
    assert [e["event"] for e in first["events"]] == [1, 2]
    assert (first["next_after_seq"], first["more"], "missed" in first) == (2, True, False)
    for n in range(4, 11):  # 7 more: seq 7..10 remain
        buffer.append(n)
    second = buffer.read(after_seq=first["next_after_seq"])
    assert second["missed"] == {"from_seq": 3, "to_seq": 6, "reason": "evicted"}
    assert [e["seq"] for e in second["events"]] == [7, 8, 9, 10]
    assert (second["next_after_seq"], second["more"]) == (10, False)
    idle = buffer.read(after_seq=10)
    assert idle["events"] == [] and idle["next_after_seq"] == 10 and not idle["more"]


def test_newest_read_without_cursor_and_limit():
    buffer = EventBuffer(10)
    for n in range(1, 8):
        buffer.append(n)
    page = buffer.read(limit=3)
    assert [e["event"] for e in page["events"]] == [5, 6, 7]
    assert (page["next_after_seq"], page["more"]) == (7, False)
    assert EventBuffer(3).read()["next_after_seq"] == 0


def test_cursor_beyond_newest_seq_fails_with_guidance():
    buffer = EventBuffer(3)
    buffer.append(1)
    with pytest.raises(ValueError, match="beyond this buffer's newest seq 1"):
        buffer.read(after_seq=5)


# --- isolation ---------------------------------------------------------------------------


async def test_buffers_are_isolated_per_console_and_site():
    streams = {
        NET_A: SimulatedStream([{"k": "a-default"}, "hold"]),
        NET_A2: SimulatedStream([{"k": "a-branch"}, {"k": "a-branch-2"}, "hold"]),
        NET_B: SimulatedStream([{"k": "b-default"}, "hold"]),
        PROTECT_A: SimulatedStream([{"k": "protect-a"}, "hold"]),
    }
    manager = StreamManager(
        records=supported_records(lambda client, api_key, key: streams[key]), sleep=Sleeps()
    )
    listeners = {key: manager.attach(key) for key in streams}
    await settle(lambda: all(s.held.is_set() for s in streams.values()))
    seen = {
        key: [e["event"]["k"] for e in listener.buffer.read()["events"]]
        for key, listener in listeners.items()
    }
    assert seen == {
        NET_A: ["a-default"],
        NET_A2: ["a-branch", "a-branch-2"],
        NET_B: ["b-default"],
        PROTECT_A: ["protect-a"],
    }
    # attach is idempotent per key: the same listener, no second connection.
    assert manager.attach(NET_A) is listeners[NET_A]
    assert streams[NET_A].connects == 1
    assert [listener.key for listener in manager.listeners("network")] == sorted(
        [NET_A, NET_A2, NET_B], key=lambda k: tuple(map(str, k))
    )
    assert await manager.close_all() == 4


# --- lifecycle ---------------------------------------------------------------------------


async def test_attach_connect_disconnect_reconnect_records_a_gap():
    clock, sleeps = Clock(), Sleeps()
    stream = SimulatedStream([{"n": 1}, {"n": 2}], [{"n": 3}, "hold"])
    listener = StreamListener(NET_A, stream, capacity=10, sleep=sleeps, clock=clock)
    assert (listener.state, listener.attached) == ("connecting", False)
    listener.start()
    listener.start()  # idempotent
    await settle(lambda: stream.held.is_set())
    status = listener.status()
    assert (status["state"], status["attached"]) == ("connected", True)
    assert (status["connects"], status["disconnects"], status["reconnect_attempts"]) == (2, 1, 1)
    assert stream.connects == 2
    [gap] = status["gaps"]
    assert gap["after_seq"] == 2 and gap["reason"] == "upstream closed the stream"
    assert gap["ended_at"] is not None and gap["ended_at"] > gap["started_at"]
    assert status["coverage_started_at"] is not None
    assert [e["event"]["n"] for e in listener.buffer.read()["events"]] == [1, 2, 3]
    assert sleeps.delays == [stream_buffers.RECONNECT_DELAYS[0]]
    await listener.close()


async def test_an_open_quiet_stream_is_attached_before_any_event():
    stream = SimulatedStream(["hold"])
    listener = StreamListener(PROTECT_A, stream, sleep=Sleeps(), clock=Clock())
    listener.start()
    await settle(lambda: stream.held.is_set())
    status = listener.status()
    assert (status["state"], status["attached"], status["buffered"]) == ("connected", True, 0)
    assert status["coverage_started_at"] is not None and status["gaps"] == []
    await listener.close()


async def test_transport_error_is_reported_without_message_text_and_retried_with_backoff():
    secret = "sentinel-header-value-7f3a"
    sleeps = Sleeps()
    stream = SimulatedStream(
        [ConnectionError(f"reset while sending X-API-Key: {secret}")],
        [OSError(secret)],
        [{"n": 1}, TimeoutError(secret)],
        ["hold"],
    )
    listener = StreamListener(NET_A, stream, sleep=sleeps, clock=Clock())
    listener.start()
    await settle(lambda: stream.held.is_set())
    status = listener.status()
    assert status["state"] == "connected"
    assert status["last_error"] == "TimeoutError"
    assert secret not in repr(status)
    delays = stream_buffers.RECONNECT_DELAYS
    # Two failed connects back off 1st then 2nd delay; a connection that delivered an event
    # resets the backoff, so its later failure waits the first delay again.
    assert sleeps.delays == [delays[0], delays[1], delays[0]]
    [gap] = status["gaps"]
    assert gap["reason"] == "error: TimeoutError" and gap["after_seq"] == 1
    assert gap["ended_at"] is not None
    await listener.close()


async def test_reconnect_never_gives_up_and_backoff_repeats_the_last_delay():
    failures = [[ConnectionError("x")] for _ in range(len(stream_buffers.RECONNECT_DELAYS) + 3)]
    sleeps = Sleeps()
    stream = SimulatedStream(*failures, ["hold"])
    listener = StreamListener(NET_B, stream, sleep=sleeps, clock=Clock())
    listener.start()
    await settle(lambda: stream.held.is_set())
    last = stream_buffers.RECONNECT_DELAYS[-1]
    assert sleeps.delays == [*stream_buffers.RECONNECT_DELAYS, last, last, last]
    assert listener.state == "connected" and listener.reconnect_attempts == len(failures)
    await listener.close()


async def test_rejected_stream_is_a_final_error_state():
    sleeps = Sleeps()
    stream = SimulatedStream([StreamRejectedError(404, "Entity 'endpoint' not found")])
    listener = StreamListener(PROTECT_A, stream, sleep=sleeps, clock=Clock())
    listener.start()
    await settle(lambda: listener.state == "error")
    await asyncio.sleep(0)
    assert stream.connects == 1 and sleeps.delays == []
    assert listener.status()["last_error"] == "StreamRejectedError (HTTP 404)"
    assert listener.attached is False


async def test_manager_replaces_a_rejected_or_closed_listener_on_attach():
    sessions = {"n": 0}

    def factory(client, api_key, key):
        sessions["n"] += 1
        if sessions["n"] == 1:
            return SimulatedStream([StreamRejectedError(403)])
        return SimulatedStream(["hold"])

    manager = StreamManager(records=supported_records(factory), sleep=Sleeps())
    first = manager.attach(NET_A)
    await settle(lambda: first.state == "error")
    second = manager.attach(NET_A)
    assert second is not first and sessions["n"] == 2
    await manager.close_all()


async def test_close_is_idempotent_cleans_up_and_keeps_the_buffer():
    stream = SimulatedStream([{"n": 1}, "hold"])
    manager = StreamManager(
        records=supported_records(lambda c, a, k: stream), sleep=Sleeps(), clock=Clock()
    )
    listener = manager.attach(PROTECT_A)
    await settle(lambda: stream.held.is_set())
    assert await manager.close(PROTECT_A) is True
    assert await manager.close(PROTECT_A) is False
    await listener.close()
    status = listener.status()
    assert (status["state"], status["attached"], status["disconnects"]) == ("closed", False, 1)
    assert status["gaps"][-1]["reason"] == "listener closed"
    assert listener.buffer.read()["events"][0]["event"] == {"n": 1}
    assert manager.get(PROTECT_A) is None and manager.listeners() == []
    listener.start()  # a closed listener never restarts
    assert listener.state == "closed"


def test_describe_error_includes_status_only():
    response = httpx.Response(401, request=httpx.Request("GET", "https://example.invalid"))
    exc = httpx.HTTPStatusError("token sentinel-abc", request=response.request, response=response)
    assert describe_error(exc) == "HTTPStatusError (HTTP 401)"
    assert describe_error(StreamRejectedError(404, "detail")) == "StreamRejectedError (HTTP 404)"
    assert describe_error(ValueError("sentinel-abc")) == "ValueError"


# --- tools -------------------------------------------------------------------------------


@pytest.fixture
def no_upstream(monkeypatch):
    async def refuse(*args, **kwargs):
        raise AssertionError("event-stream tools must not contact the upstream")

    monkeypatch.setattr(httpx.AsyncClient, "send", refuse)


async def _app() -> FastMCP:
    app = FastMCP("event-streams")
    for tool in await server.mcp.list_tools():
        if tool.name in TOOLS:
            app.add_tool(tool)
    return app


def test_tools_are_registered_read_only_in_the_statistics_family():
    tools = {tool.name: tool for tool in asyncio.run(server.mcp.list_tools())}
    index = build_family_index()
    for name in TOOLS:
        assert tools[name].annotations.read_only_hint is True
        assert tools[name].annotations.destructive_hint is False
        assert index[name] == "statistics"
        schema = tools[name].parameters
        for prop, spec in schema.get("properties", {}).items():
            assert spec.get("description"), f"{name}.{prop} has no description"


async def test_status_tool_reports_both_products_unsupported(no_upstream, monkeypatch):
    monkeypatch.setattr(server, "_settings", Settings(api_key="synthetic-key", tool_mode="full"))
    app = await _app()
    async with server.lifespan(app), Client(app) as client:
        data = (await client.call_tool("get_event_stream_status", {})).structured_content
        one = (
            await client.call_tool("get_event_stream_status", {"product": "protect"})
        ).structured_content
    products = {row["product"]: row for row in data["products"]}
    assert set(products) == {"network", "protect"}
    for name, row in products.items():
        assert (row["state"], row["supported"], row["listeners"]) == ("unsupported", False, [])
        assert row["evidence"] == [p.as_dict() for p in COMPATIBILITY[name].probes]
        assert row["fallback_tools"] == list(COMPATIBILITY[name].fallback_tools)
    assert [row["product"] for row in one["products"]] == ["protect"]
    assert "never subscribes" in data["note"]


@pytest.mark.parametrize(("product", "site"), [("protect", None), ("network", "Default")])
async def test_read_tool_resolves_then_reports_unsupported_without_events_or_stream(product, site):
    registry = FakeRegistry()
    manager = StreamManager(records=dict(COMPATIBILITY))
    data = await read_recent_event_buffer(
        registry, None, product, "my-console", site, manager=manager
    )
    assert data["state"] == "unsupported" and data["supported"] is False
    assert data["attached"] is False
    assert "events" not in data, "an unsupported stream must not look like a quiet one"
    assert data["use_instead"] == list(COMPATIBILITY[product].fallback_tools)
    assert (data["host"], data["site"], data["console_id"]) == ("my-console", site, "console-a")
    assert data["site_key"] == ("default" if site else None)
    assert ("host", "my-console") in registry.calls
    assert manager.listeners() == [], "an unsupported product must never open a stream"


@pytest.mark.parametrize(
    ("product", "host", "site", "message"),
    [
        ("protect", "nope", None, "valid: my-console"),
        ("network", "nope", "Default", "valid: my-console"),
        ("network", "my-console", "Nowhere", "valid: Default"),
    ],
)
async def test_unsupported_product_still_fails_fast_on_unknown_host_or_site(
    product, host, site, message
):
    manager = StreamManager(records=dict(COMPATIBILITY))
    with pytest.raises(ValueError, match=message):
        await read_recent_event_buffer(FakeRegistry(), None, product, host, site, manager=manager)
    assert manager.listeners() == []


@pytest.mark.parametrize(
    ("product", "site", "message"),
    [
        ("protect", "Default", "omit site for product 'protect'"),
        ("network", None, "site is required for product 'network'"),
    ],
)
async def test_site_selector_is_validated_before_anything_else(product, site, message):
    with pytest.raises(ValueError, match=message):
        await read_recent_event_buffer(None, None, product, "my-console", site)


class FakeRegistry:
    """Resolves like Registry: an unknown host fails with the valid choices."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def resolve_key_for_host(self, host):
        self.calls.append(("key", host))
        return None

    async def resolve_host_id(self, host, *, key=None):
        self.calls.append(("host", host))
        if host != "my-console":
            raise ValueError(f"Host {host!r} not found; valid: my-console")
        return "console-a"

    async def resolve_site_slug(self, site, host_id, *, key=None):
        self.calls.append(("site", site))
        if site not in ("Default", "default"):
            raise ValueError(f"Site {site!r} not found on host {host_id!r}; valid: Default")
        return "default"


async def test_read_on_a_supported_transport_starts_a_listener_then_reads_by_cursor():
    stream = SimulatedStream([{"n": 1}, {"n": 2}, {"n": 3}, "hold"])
    manager = StreamManager(
        records=supported_records(lambda c, a, k: stream), sleep=Sleeps(), clock=Clock()
    )
    registry = FakeRegistry()
    first = await read_recent_event_buffer(
        registry, None, "network", "my-console", "Default", manager=manager
    )
    assert first["listener_started"] is True and "after_seq=next_after_seq" in first["hint"]
    assert (first["product"], first["console_id"], first["site"]) == (
        "network",
        "console-a",
        "default",
    )
    await settle(lambda: stream.held.is_set())
    page = await read_recent_event_buffer(
        registry, None, "network", "my-console", "Default", after_seq=1, limit=1, manager=manager
    )
    assert "listener_started" not in page
    assert [e["event"] for e in page["events"]] == [{"n": 2}]
    assert (page["state"], page["attached"], page["next_after_seq"], page["more"]) == (
        "connected",
        True,
        2,
        True,
    )
    status = event_stream_status("network", manager=manager)
    [row] = status["products"]
    assert row["state"] == "connected" and len(row["listeners"]) == 1
    assert stream.connects == 1
    await manager.close_all()


async def test_unknown_host_or_site_fails_fast_and_attaches_nothing():
    manager = StreamManager(
        records=supported_records(lambda c, a, k: SimulatedStream(["hold"])), sleep=Sleeps()
    )
    with pytest.raises(ValueError, match="valid: my-console"):
        await read_recent_event_buffer(FakeRegistry(), None, "protect", "nope", manager=manager)
    with pytest.raises(ValueError, match="valid: Default"):
        await read_recent_event_buffer(
            FakeRegistry(), None, "network", "my-console", "Nowhere", manager=manager
        )
    assert manager.listeners() == []


async def test_status_without_listeners_on_supported_transport_is_inactive():
    manager = StreamManager(records=supported_records(lambda c, a, k: SimulatedStream()))
    rows = {row["product"]: row for row in event_stream_status(manager=manager)["products"]}
    assert {name: row["state"] for name, row in rows.items()} == {
        "network": "inactive",
        "protect": "inactive",
    }


async def test_server_shutdown_closes_every_listener(monkeypatch):
    monkeypatch.setattr(server, "_settings", Settings(api_key="synthetic-key", tool_mode="full"))
    stream = SimulatedStream(["hold"])
    manager = StreamManager(records=supported_records(lambda c, a, k: stream), sleep=Sleeps())
    monkeypatch.setattr(stream_buffers, "MANAGER", manager)
    app = await _app()
    async with server.lifespan(app):
        listener = manager.attach(PROTECT_A)
        await settle(lambda: stream.held.is_set())
    assert listener.state == "closed" and manager.listeners() == []


async def test_read_recent_events_description_does_not_promise_events(no_upstream):
    """Both products are unsupported, so the advertised text must say so up front and
    must not describe an events list the tool never returns."""
    tools = {tool.name: tool for tool in await (await _app()).list_tools()}
    text = " ".join((tools["read_recent_events"].description or "").split())
    assert text.startswith(
        "Read recent live events for one console; both products answer unsupported"
    )
    assert "events: [{seq" not in text and "listener_started" not in text
    assert "Read buffered live events" not in text
