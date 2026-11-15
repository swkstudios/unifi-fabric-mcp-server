"""Review fixes for the connector pacer: the send is stamped when it goes out, a 429 is
never answered with an instant re-send, and a Retry-After is honoured exactly.

The first test simulates the real case the unit tests miss: 10 concurrency slots, mixed
upstream latencies up to 12 s, demand far above the cap. It runs on a virtual clock so the
upstream arrival stamps are exact. Before the fix the send was stamped before the slot,
so requests admitted in one window reached the connector inside the next window.
"""

from __future__ import annotations

import asyncio
import heapq
import json
import random

import httpx
import pytest
import respx

from unifi_fabric import pacing
from unifi_fabric.client import RateLimitError, UniFiClient
from unifi_fabric.config import Settings

BASE = "https://api.ui.com"
CONSOLE = "AAAA11112222333344445555666677778888:1234567890"
ROUTE = f"/v1/connector/consoles/{CONSOLE}/proxy/network/integration/v1/sites"

_REAL_SLEEP = asyncio.sleep


class VirtualTime:
    """A discrete-event clock: time moves only when every task is waiting on it."""

    def __init__(self, start: float = 10_000.0) -> None:
        self.now = start
        self._timers: list[tuple[float, int, asyncio.Future]] = []
        self._seq = 0

    def clock(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        future = asyncio.get_running_loop().create_future()
        self._seq += 1
        heapq.heappush(self._timers, (self.now + max(seconds, 0.0), self._seq, future))
        await future

    async def run(self, awaitable) -> object:
        task = asyncio.ensure_future(awaitable)
        while not task.done():
            for _ in range(60):  # let every runnable task settle
                await _REAL_SLEEP(0)
                if task.done():
                    break
            if task.done():
                break
            if not self._timers:
                raise AssertionError("deadlock: nothing is waiting on the clock")
            when, _, future = heapq.heappop(self._timers)
            self.now = max(self.now, when)
            if not future.done():
                future.set_result(None)
        return await task


@pytest.fixture
def vt():
    virtual = VirtualTime()
    pacing.set_time_source(virtual.clock, virtual.sleep)
    yield virtual
    pacing.set_time_source()


def _worst_in_window(stamps: list[float], width: float = 60.0) -> int:
    ordered = sorted(stamps)
    worst = low = 0
    for high, moment in enumerate(ordered):
        while ordered[low] <= moment - width:
            low += 1
        worst = max(worst, high - low + 1)
    return worst


def _client() -> UniFiClient:
    return UniFiClient(Settings(api_key="probe-key-1", api_base_url=BASE))


@pytest.mark.parametrize(
    "latencies",
    [(0.3, 1.2), (0.3, 6.0), (0.3, 12.0)],
    ids=["fast", "mixed", "slow-tail"],
)
@respx.mock
async def test_the_upstream_never_sees_more_than_95_in_any_60_seconds(vt, latencies):
    """PR-1: 10 slots, mixed latency, a slow tail; the connector's own arrival stamps."""
    rng = random.Random(1084)  # noqa: S311 - a seeded test generator
    arrivals: list[float] = []

    async def upstream(request: httpx.Request) -> httpx.Response:
        arrivals.append(vt.now)
        await vt.sleep(rng.uniform(*latencies))
        return httpx.Response(200, json={"ok": True})

    respx.get(BASE + ROUTE).mock(side_effect=upstream)
    client = _client()
    await vt.run(asyncio.gather(*(client.get(ROUTE) for _ in range(400))))
    assert len(arrivals) == 400
    assert _worst_in_window(arrivals) <= 95, _worst_in_window(arrivals)


@respx.mock
async def test_a_write_is_stamped_when_it_goes_out_too(vt):
    arrivals: list[float] = []

    async def upstream(request: httpx.Request) -> httpx.Response:
        arrivals.append(vt.now)
        await vt.sleep(5.0)
        return httpx.Response(200, json={})

    respx.route(method="PUT", url=BASE + ROUTE).mock(side_effect=upstream)
    client = _client()
    await vt.run(asyncio.gather(*(client.request("PUT", ROUTE, json={"a": i}) for i in range(150))))
    assert _worst_in_window(arrivals) <= 91  # a write starts at 90 or fewer: 91 after it


# --- PR-2 and PR-3: the wait after a 429 ----------------------------------------------------------
def _body(status: int, **headers: str) -> httpx.Response:
    return httpx.Response(
        status,
        content=json.dumps({"code": "rate_limited"}).encode(),
        headers={"Content-Type": "application/json", **headers},
    )


@pytest.fixture
def slept(monkeypatch):
    waits: list[float] = []

    async def _sleep(delay: float) -> None:
        waits.append(delay)

    monkeypatch.setattr("unifi_fabric.client.asyncio.sleep", _sleep)
    return waits


@respx.mock
async def test_a_429_with_no_retry_after_at_a_low_own_count_is_never_resent_at_once(slept):
    """PR-2: another sender filled the console; 20 of our own sends must not mean 'go now'."""
    pacing.limiter_for(CONSOLE)._sends.extend([pacing._clock()] * 20)
    route = respx.get(BASE + ROUTE).mock(return_value=_body(429))
    with pytest.raises(RateLimitError):
        await _client().request("GET", ROUTE)
    assert slept, "the client re-sent without waiting at all"
    assert all(wait >= 60.0 for wait in slept), slept
    assert route.call_count == len(slept) + 1 <= 3
    counters = pacing.limiter_for(CONSOLE).counters
    assert counters.outside_sender_429 == route.call_count


@respx.mock
async def test_a_429_while_our_own_count_is_high_is_not_an_outside_sender(slept):
    limiter = pacing.limiter_for(CONSOLE)
    limiter._sends.extend([pacing._clock()] * 92)
    respx.get(BASE + ROUTE).mock(side_effect=[_body(429), httpx.Response(200, json={})])
    await _client().request("GET", ROUTE)
    assert limiter.counters.throttled_429 == 1
    assert limiter.counters.outside_sender_429 == 0


@pytest.mark.parametrize("retry_after", ["3", "45", "100", "120"])
@respx.mock
async def test_retry_after_is_honoured_exactly(slept, retry_after):
    """PR-3: not capped at 64 s, not raised to 90, not shortened."""
    route = respx.get(BASE + ROUTE).mock(
        side_effect=[_body(429, **{"Retry-After": retry_after}), httpx.Response(200, json={})]
    )
    response = await _client().request("GET", ROUTE)
    assert response.status_code == 200 and route.call_count == 2
    assert slept == [float(retry_after)]


@pytest.mark.parametrize("retry_after", ["121", "300"])
@respx.mock
async def test_a_retry_after_beyond_the_budget_raises_without_resending(slept, retry_after):
    route = respx.get(BASE + ROUTE).mock(return_value=_body(429, **{"Retry-After": retry_after}))
    with pytest.raises(RateLimitError) as exc:
        await _client().request("GET", ROUTE)
    assert route.call_count == 1 and slept == []
    assert f"Retry-After: {retry_after}" in str(exc.value)


@respx.mock
async def test_the_second_retry_after_cannot_overrun_the_total_budget(slept):
    route = respx.get(BASE + ROUTE).mock(return_value=_body(429, **{"Retry-After": "70"}))
    with pytest.raises(RateLimitError):
        await _client().request("GET", ROUTE)
    assert slept == [70.0]  # a second 70 s would pass 120 s: stop, do not re-send early
    assert route.call_count == 2


def test_read_retry_wait_floors_and_budget():
    limiter = pacing.ConsoleLimiter()
    assert limiter.read_retry_wait(None, waited_total=0.0, attempt=0) >= 60.0
    assert limiter.read_retry_wait(7.0, waited_total=0.0, attempt=0) == 7.0
    assert limiter.read_retry_wait(7.0, waited_total=114.0, attempt=0) is None
    assert limiter.read_retry_wait(None, waited_total=61.0, attempt=0) is None


# --- F8: one limiter per console, however the id is spelled ---------------------------------------
def test_a_console_id_spelled_two_ways_shares_one_limiter():
    first = pacing.limiter_for("02005E0000AA:1000000001")
    assert pacing.limiter_for("02005e0000aa:1000000001") is first
    assert pacing.limiter_for("02005E0000AA%3A1000000001") is first
