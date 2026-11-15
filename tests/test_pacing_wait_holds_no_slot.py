"""A console's pacing wait never holds a global concurrency slot.

``UNIFI_MAX_CONCURRENCY`` slots are shared by every upstream call. A request that waits
for one console's send budget (up to a minute) must wait outside them, so a throttled
console cannot stall Site Manager routes or other consoles. The send is still counted
when it leaves, so the per-console cap holds.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any

import httpx
import pytest

from unifi_fabric import pacing
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings

CONSOLE_A = "/v1/connector/consoles/AABBCCDDEEFF:1/proxy/network/integration/v1/sites"
CONSOLE_B = "/v1/connector/consoles/001122334455:2/proxy/network/integration/v1/sites"


@pytest.fixture(autouse=True)
def _fresh_limiters() -> Any:
    pacing.reset_registry()
    yield
    pacing.reset_registry()


def _client(**settings: Any) -> UniFiClient:
    client = UniFiClient(Settings(api_key="k" * 24, **settings))
    http = httpx.AsyncClient(
        base_url=client._settings.api_base_url,
        transport=httpx.MockTransport(lambda _req: httpx.Response(200, json={"data": []})),
    )

    async def get_client(_key: Any) -> httpx.AsyncClient:
        return http

    client._get_client = get_client  # type: ignore[method-assign]
    return client


async def _settle(done: Any, rounds: int = 500) -> None:
    """Let runnable tasks run until ``done()`` (a bounded number of loop turns)."""
    for _ in range(rounds):
        if done():
            return
        await asyncio.sleep(0)


@pytest.fixture
def _frozen_clock() -> Any:
    """A pacing clock that stands still, so a budget wait really waits."""

    async def sleep(_seconds: float) -> None:
        await asyncio.sleep(3600)

    pacing.set_time_source(clock=lambda: 1000.0, sleep=sleep)
    yield
    pacing.set_time_source()


@pytest.mark.usefixtures("_frozen_clock")
@pytest.mark.parametrize("other", ["/v1/hosts", CONSOLE_B])
async def test_a_throttled_console_does_not_stall_other_calls(other: str) -> None:
    client = _client(max_concurrency=1, connector_max_rpm=1)
    await client.get(CONSOLE_A)  # spends console A's one send for the next 60 s
    waiting = asyncio.create_task(client.get(CONSOLE_A))  # waits ~60 s for budget
    await asyncio.sleep(0.2)
    assert not waiting.done()
    try:
        # The only slot must be free for an unpaced route and for another console.
        call = asyncio.create_task(client.get(other))
        await _settle(call.done)
        assert call.done() and call.exception() is None
    finally:
        waiting.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await waiting
        await client.close()


async def test_the_send_is_stamped_when_it_leaves() -> None:
    now = [1000.0]
    pacing.set_time_source(clock=lambda: now[0])
    try:
        limiter = pacing.limiter_for("AABBCCDDEEFF:1", 2)
        stamp = await limiter.reserve()
        now[0] += 30.0  # waited 30 s for a global slot
        assert limiter.restamp(stamp)
        # Counted from the moment it left: still in the window 59 s after leaving.
        assert limiter.count(now[0] + 59.0) == 1
        assert limiter.count(now[0] + 61.0) == 0
        # A reservation older than the window is gone; restamp reports it.
        late = await limiter.reserve()
        now[0] += 61.0
        assert not limiter.restamp(late)
    finally:
        pacing.set_time_source()


@pytest.mark.parametrize("method", ["GET", "POST"])
async def test_a_reservation_taken_again_counts_the_send_once(monkeypatch, method) -> None:
    # A reservation that aged out of the window while the request waited for a global
    # slot is admitted again; the pacing counters still count the one send once.
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "allow")
    monkeypatch.delenv("UNIFI_WRITE_EXCEPTIONS", raising=False)
    client = _client(max_concurrency=1, connector_max_rpm=95)
    limiter = pacing.limiter_for("AABBCCDDEEFF:1", 95)
    restamp = limiter.restamp
    refused: list[float] = []

    def aged_out_once(stamp: float, now: float | None = None, **kwargs: Any) -> bool:
        if not refused:  # the first reservation aged out while queued for the slot
            refused.append(stamp)
            return False
        return restamp(stamp, now, **kwargs)

    monkeypatch.setattr(limiter, "restamp", aged_out_once)
    try:
        if method == "GET":
            await client.get(CONSOLE_A)
        else:
            await client.post(CONSOLE_A, json={"name": "x"})
    finally:
        await client.close()
    assert limiter.counters.sends == 1
    assert limiter.counters.write_sends == (1 if method == "POST" else 0)


@pytest.mark.parametrize("method", ["POST", "GET"])
async def test_a_429_during_the_slot_wait_holds_the_queued_request(monkeypatch, method) -> None:
    # A 429 that another request receives while this one waits for a global slot (after
    # its console reservation) puts the console in backoff: a queued write must wait out
    # the 60 s hold like any write, never be sent inside it. A read below the lowered cap
    # is not delayed.
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "allow")
    monkeypatch.delenv("UNIFI_WRITE_EXCEPTIONS", raising=False)
    now = [5000.0]

    async def sleep(seconds: float) -> None:
        now[0] += max(seconds, 0.0)

    pacing.set_time_source(clock=lambda: now[0], sleep=sleep)
    sent_at: list[float] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        sent_at.append(now[0])
        return httpx.Response(200, json={"data": []})

    client = UniFiClient(Settings(api_key="k" * 24, max_concurrency=1, connector_max_rpm=95))
    http = httpx.AsyncClient(
        base_url=client._settings.api_base_url, transport=httpx.MockTransport(handler)
    )

    async def get_client(_key: Any) -> httpx.AsyncClient:
        return http

    client._get_client = get_client  # type: ignore[method-assign]
    limiter = pacing.limiter_for("AABBCCDDEEFF:1", 95)
    reserve = limiter.reserve

    noted: list[float] = []

    async def reserve_then_429(**kwargs: Any) -> float:
        stamp = await reserve(**kwargs)
        if not noted:  # another request's 429 lands while this one waits for a slot
            noted.append(stamp)
            limiter.note_429()
        return stamp

    monkeypatch.setattr(limiter, "reserve", reserve_then_429)
    held_from = now[0]
    try:
        if method == "POST":
            await client.post(CONSOLE_A, json={"name": "x"})
        else:
            await client.get(CONSOLE_A)
    finally:
        await client.close()
        pacing.set_time_source()
    assert len(sent_at) == 1
    if method == "POST":
        assert sent_at[0] >= held_from + pacing.WINDOW_SECONDS
    else:
        assert sent_at[0] == held_from
    assert limiter.counters.sends == 1


@pytest.mark.parametrize("other", ["/v1/hosts", CONSOLE_B])
async def test_an_expired_reservation_waits_without_the_global_slot(monkeypatch, other) -> None:
    # Two console-A requests reserve and queue for the only slot; their reservations
    # expire while queued and a fresh send (another client of the process-wide limiter)
    # takes console A's budget. The request that must wait again waits outside the slot,
    # so Site Manager routes and other consoles still progress.
    now = [1000.0]

    async def sleep(_seconds: float) -> None:
        await asyncio.Event().wait()  # a budget wait never ends during the test

    pacing.set_time_source(clock=lambda: now[0], sleep=sleep)
    client = _client(max_concurrency=1, connector_max_rpm=2)
    await client._semaphore.acquire()  # a slow request holds the only slot
    queued = [asyncio.create_task(client.get(CONSOLE_A)) for _ in range(2)]
    try:
        await _settle(lambda: False, rounds=50)  # both reserve, then queue for the slot
        assert not any(task.done() for task in queued)
        now[0] += 61.0  # the reservations expire while queued
        await pacing.limiter_for("AABBCCDDEEFF:1", 2).reserve()  # a fresh send elsewhere
        client._semaphore.release()
        await _settle(lambda: sum(task.done() for task in queued) == 1)
        assert sum(task.done() for task in queued) == 1  # one sent, one waits for budget
        call = asyncio.create_task(client.get(other))
        await _settle(call.done)
        assert call.done() and call.exception() is None
    finally:
        for task in queued:
            task.cancel()
        for task in queued:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await client.close()
        pacing.set_time_source()
