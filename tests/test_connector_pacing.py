"""Per-console connector pacing.

The connector answers HTTP 429 above 100 requests per minute per console. These tests run
the pacer on a fake clock (``set_time_source``), so a thousand sends take no real time,
and check the rules live acceptance runs depend on: the cap holds in every sliding 60 s
window, there is no burst credit, each console has its own budget, a write starts only
below the cap and is never retried, and a read waits out a 429 within its budget.
"""

from __future__ import annotations

import asyncio
import json
import random
from pathlib import Path

import httpx
import pytest
import respx
from pydantic import ValidationError

from unifi_fabric import pacing
from unifi_fabric.client import RateLimitError, UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.lane import lane_scope

BASE = "https://api.ui.com"
# A real connector route shape with a synthetic console id.
CONSOLE = "AAAA11112222333344445555666677778888:1234567890"
OTHER = "BBBB11112222333344445555666677778888:1234567890"


def _route(console: str = CONSOLE, tail: str = "proxy/network/integration/v1/sites") -> str:
    return f"/v1/connector/consoles/{console}/{tail}"


class FakeTime:
    """A clock whose sleep advances it, installed as the pacer's time source."""

    def __init__(self, start: float = 5000.0) -> None:
        self.now = start

    def clock(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.now += max(seconds, 0.0)

    def install(self) -> FakeTime:
        pacing.set_time_source(self.clock, self.sleep)
        return self


@pytest.fixture
def fake() -> FakeTime:
    return FakeTime().install()


def _max_in_window(times: list[float], width: float = 60.0) -> int:
    """The most sends in any trailing ``width`` seconds (a send at t counts for (t, t+width])."""
    worst, low = 0, 0
    for high, moment in enumerate(times):
        while times[low] <= moment - width:
            low += 1
        worst = max(worst, high - low + 1)
    return worst


# --- 1. the limiter on a fake clock ----------------------------------------------------------
async def test_a_thousand_sends_never_exceed_the_cap_in_any_60_second_window(fake):
    limiter = pacing.ConsoleLimiter()
    rng = random.Random(990)  # noqa: S311 - a seeded test generator, not a secret
    sent: list[float] = []
    for _ in range(1000):
        # Random timing: bursts of zero gap mixed with gaps up to 3 s (demand far above cap).
        fake.now += rng.choice([0.0, 0.0, 0.0, 0.01, 0.2, 3.0])
        await limiter.acquire()
        sent.append(fake.now)
    assert len(sent) == 1000
    assert _max_in_window(sent) <= 95
    assert _max_in_window(sent) == 95  # the cap is reached, so the test is not vacuous


async def test_concurrent_senders_share_one_budget(fake):
    limiter = pacing.ConsoleLimiter()
    sent: list[float] = []

    async def one() -> None:
        await limiter.acquire()
        sent.append(fake.now)

    await asyncio.gather(*(one() for _ in range(400)))
    assert len(sent) == 400 and _max_in_window(sorted(sent)) <= 95


async def test_there_is_no_burst_credit_after_an_idle_hour(fake):
    limiter = pacing.ConsoleLimiter()
    for _ in range(95):
        await limiter.acquire()
    fake.now += 3600.0  # idle: every earlier send has left the window
    started = fake.now
    stamps = []
    for _ in range(96):
        await limiter.acquire()
        stamps.append(fake.now)
    assert stamps[94] == started  # the first 95 go at once
    assert stamps[95] - started >= 60.0  # the 96th waits for the first of the burst to leave


async def test_a_cap_below_100_is_the_cap(fake):
    limiter = pacing.ConsoleLimiter(max_rpm=10)
    stamps = []
    for _ in range(30):
        await limiter.acquire()
        stamps.append(fake.now)
    assert _max_in_window(stamps) <= 10


def test_each_console_has_its_own_limiter_and_a_console_has_one(fake):
    first = pacing.limiter_for(CONSOLE, 95)
    assert pacing.limiter_for(CONSOLE, 95) is first
    assert pacing.limiter_for(OTHER, 95) is not first
    first._sends.extend([fake.now] * 95)
    assert first.count() == 95 and pacing.limiter_for(OTHER, 95).count() == 0


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (_route(), CONSOLE),
        (_route(tail="proxy/protect/api/cameras"), CONSOLE),
        ("/v1/hosts", None),
        ("/v1/connector/consoles", None),
        ("/ea/hosts", None),
        (None, None),
    ],
)
def test_only_connector_routes_have_a_console(path, expected):
    assert pacing.console_id(path) == expected


# --- 2. configuration -------------------------------------------------------------------------
def test_the_default_cap_is_95(monkeypatch):
    monkeypatch.delenv("UNIFI_CONNECTOR_MAX_RPM", raising=False)
    assert Settings(api_key="k").connector_max_rpm == pacing.DEFAULT_MAX_RPM == 95


@pytest.mark.parametrize("value", ["1", "100", " 60 "])
def test_a_cap_from_1_to_100_is_accepted(monkeypatch, value):
    monkeypatch.setenv("UNIFI_CONNECTOR_MAX_RPM", value)
    assert Settings(api_key="k").connector_max_rpm == int(value)


@pytest.mark.parametrize("value", ["0", "101", "-5", "lots", "9.5"])
def test_a_cap_outside_1_to_100_is_refused_at_startup_naming_the_variable(monkeypatch, value):
    monkeypatch.setenv("UNIFI_CONNECTOR_MAX_RPM", value)
    with pytest.raises(ValidationError, match="UNIFI_CONNECTOR_MAX_RPM"):
        Settings(api_key="k")


@pytest.mark.parametrize("value", [0, 101, "x", True])
def test_validate_max_rpm_refuses_what_the_setting_refuses(value):
    with pytest.raises(ValueError, match="UNIFI_CONNECTOR_MAX_RPM"):
        pacing.validate_max_rpm(value)


def test_the_documented_connector_limit_is_still_in_the_retry_doc():
    """The pre-flight kept from the ruling: the pacer's ceiling rests on this sentence."""
    text = (Path(__file__).parent.parent / "docs" / "RETRY.md").read_text(encoding="utf-8")
    assert "100 requests per minute" in text


# --- 3. writes: reserved budget, never retried ----------------------------------------------
def _fill(limiter: pacing.ConsoleLimiter, count: int, at: float) -> None:
    limiter._sends.clear()
    limiter._sends.extend(at + i * 0.001 for i in range(count))


def test_a_write_is_not_admitted_above_90_sends(fake):
    limiter = pacing.ConsoleLimiter()
    _fill(limiter, 91, fake.now)
    assert limiter._try_admit(write=True, lane=None, now=fake.now) > 0
    _fill(limiter, 90, fake.now)
    assert limiter._try_admit(write=True, lane=None, now=fake.now) == 0.0


def test_a_read_stops_at_90_while_a_write_waits_and_goes_to_95_otherwise(fake):
    limiter = pacing.ConsoleLimiter()
    _fill(limiter, 90, fake.now)
    assert limiter._try_admit(write=False, lane=None, now=fake.now) == 0.0  # 90 < 95
    limiter._writers_waiting = 1
    _fill(limiter, 90, fake.now)
    assert limiter._try_admit(write=False, lane=None, now=fake.now) > 0  # held at 90
    _fill(limiter, 89, fake.now)
    assert limiter._try_admit(write=False, lane=None, now=fake.now) == 0.0


async def test_a_waiting_write_is_registered_and_released(fake):
    limiter = pacing.ConsoleLimiter()
    _fill(limiter, 91, fake.now)
    await limiter.acquire(write=True)
    assert limiter._writers_waiting == 0
    assert fake.now > 5000.0  # it waited for room instead of sending at 91


async def test_no_write_starts_within_60_seconds_of_a_429(fake):
    limiter = pacing.ConsoleLimiter()
    limiter.note_429()
    started = fake.now
    await limiter.acquire(write=True)
    assert fake.now - started >= 60.0
    # A read is not held by that rule.
    limiter.note_429()
    marker = fake.now
    await limiter.acquire(write=False)
    assert fake.now == marker


# --- 4. back-off after a 429 ------------------------------------------------------------------
def test_a_429_drops_the_cap_and_it_climbs_5_a_minute_to_95(fake):
    limiter = pacing.ConsoleLimiter()
    _fill(limiter, 99, fake.now)  # another process pushed the console past our cap
    limiter.note_429()
    assert limiter._cap(fake.now) == 89  # count 99 - 10
    assert limiter._cap(fake.now + 59) == 89
    assert limiter._cap(fake.now + 60) == 94
    assert limiter._cap(fake.now + 120) == 95
    assert limiter._backoff_cap is None


def test_the_back_off_cap_never_falls_below_60(fake):
    limiter = pacing.ConsoleLimiter()
    _fill(limiter, 40, fake.now)
    limiter.note_429()
    assert limiter._cap(fake.now) == 60


async def test_a_backed_off_console_sends_under_the_lower_cap(fake):
    limiter = pacing.ConsoleLimiter()
    _fill(limiter, 99, fake.now)
    limiter.note_429()
    assert limiter._try_admit(write=False, lane=None, now=fake.now) > 0  # 99 >= 89
    assert limiter.counters.throttled_429 == 1


# --- 5. what a GET waits after a 429 ---------------------------------------------------------
def test_a_retry_after_of_3_is_one_wait_of_3_seconds(fake):
    limiter = pacing.ConsoleLimiter()
    assert limiter.read_retry_wait(3.0, waited_total=0.0) == 3.0


def test_a_retry_after_is_honoured_exactly_within_the_120_second_budget(fake):
    limiter = pacing.ConsoleLimiter()
    assert limiter.read_retry_wait(120.0, waited_total=0.0) == 120.0
    assert limiter.read_retry_wait(56.0, waited_total=64.0) == 56.0  # 120 s exactly
    assert limiter.read_retry_wait(57.0, waited_total=64.0) is None  # over: stop, no re-send
    assert limiter.read_retry_wait(30.0, waited_total=100.0) is None


def test_with_no_retry_after_a_read_waits_a_window_and_until_the_count_is_below_90(fake):
    limiter = pacing.ConsoleLimiter()
    _fill(limiter, 95, fake.now)
    wait = limiter.read_retry_wait(None, waited_total=0.0)
    assert wait is not None and 60.0 <= wait <= 64.0
    _fill(limiter, 10, fake.now)
    assert limiter.read_retry_wait(None, waited_total=0.0) == 60.0  # never zero


# --- 6. through the client --------------------------------------------------------------------
def _client(**extra) -> UniFiClient:
    return UniFiClient(Settings(api_key="probe-key-1", api_base_url=BASE, **extra))


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
async def test_the_client_never_sends_more_than_95_to_one_console_in_60_seconds(fake):
    route = respx.get(BASE + _route()).mock(return_value=httpx.Response(200, json={"ok": True}))
    stamps: list[float] = []
    route.side_effect = lambda request: (stamps.append(fake.now), httpx.Response(200, json={}))[1]
    client = _client()
    await asyncio.gather(*(client.get(_route()) for _ in range(300)))
    assert len(stamps) == 300 and _max_in_window(sorted(stamps)) <= 95


@respx.mock
async def test_two_consoles_each_get_their_own_95(fake):
    for console in (CONSOLE, OTHER):
        respx.get(BASE + _route(console)).mock(return_value=httpx.Response(200, json={}))
    client = _client()
    started = fake.now
    await asyncio.gather(
        *(client.get(_route(CONSOLE)) for _ in range(95)),
        *(client.get(_route(OTHER)) for _ in range(95)),
    )
    assert fake.now == started  # 190 sends, none waited
    assert pacing.limiter_for(CONSOLE).count() == 95 == pacing.limiter_for(OTHER).count()


@respx.mock
async def test_a_second_client_in_the_process_shares_the_console_log(fake):
    respx.get(BASE + _route()).mock(return_value=httpx.Response(200, json={}))
    first, second = _client(), _client()
    started = fake.now
    await asyncio.gather(*(first.get(_route()) for _ in range(60)))
    await asyncio.gather(*(second.get(_route()) for _ in range(60)))
    assert fake.now - started >= 0.0 and pacing.limiter_for(CONSOLE).count() <= 95
    assert pacing.limiter_for(CONSOLE).counters.sends == 120


@respx.mock
async def test_site_manager_routes_are_not_paced(fake):
    respx.get(BASE + "/v1/hosts").mock(return_value=httpx.Response(200, json={"data": []}))
    client = _client()
    started = fake.now
    await asyncio.gather(*(client.get("/v1/hosts") for _ in range(250)))
    assert fake.now == started
    assert pacing.limiter_for.__module__  # registry untouched by Site Manager routes
    assert not pacing._registry


@respx.mock
async def test_the_configured_cap_applies_to_the_client(fake):
    respx.get(BASE + _route()).mock(return_value=httpx.Response(200, json={}))
    client = _client(connector_max_rpm=10)
    started = fake.now
    await asyncio.gather(*(client.get(_route()) for _ in range(25)))
    assert fake.now - started >= 60.0  # 25 sends at 10 per minute need two waits


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
@respx.mock
async def test_a_429_on_a_write_is_sent_once_never_retried_and_starts_the_cooldown(
    fake, slept, method
):
    route = respx.route(method=method, url=BASE + _route()).mock(
        side_effect=[_body(429, **{"Retry-After": "2"}), httpx.Response(200, json={})]
    )
    with pytest.raises(RateLimitError):
        await _client().request(method, _route(), json={"a": 1})
    assert route.call_count == 1
    assert slept == []  # no wait, no second send
    limiter = pacing.limiter_for(CONSOLE)
    assert limiter.counters.throttled_429 == 1
    assert limiter._last_429 is not None  # the next write waits out 60 s


@respx.mock
async def test_a_read_429_with_retry_after_3_waits_3_seconds_and_retries(fake, slept):
    route = respx.get(BASE + _route()).mock(
        side_effect=[_body(429, **{"Retry-After": "3"}), httpx.Response(200, json={"ok": 1})]
    )
    response = await _client().request("GET", _route())
    assert response.status_code == 200 and route.call_count == 2
    assert slept == [3.0]


@respx.mock
async def test_a_read_429_with_retry_after_120_waits_exactly_120_then_stops(fake, slept):
    route = respx.get(BASE + _route()).mock(return_value=_body(429, **{"Retry-After": "120"}))
    with pytest.raises(RateLimitError) as exc:
        await _client().request("GET", _route())
    assert slept == [120.0]  # a second 120 s would pass the budget: stop, do not re-send
    assert route.call_count == 2
    assert "Retry-After: 120" in str(exc.value) and "HTTP 429" in str(exc.value)


@respx.mock
async def test_a_read_429_on_a_site_manager_route_keeps_the_documented_backoff(fake, slept):
    respx.get(BASE + "/v1/hosts").mock(
        side_effect=[_body(429), httpx.Response(200, json={"data": []})]
    )
    response = await _client().request("GET", "/v1/hosts")
    assert response.status_code == 200
    assert len(slept) == 1 and 1.0 <= slept[0] <= 2.0  # 2**0 + jitter 0..1 (RETRY.md)


@respx.mock
async def test_the_lane_of_the_call_is_counted_per_lane(fake):
    respx.get(BASE + _route()).mock(return_value=httpx.Response(200, json={}))
    client = _client()
    with lane_scope("run7/unit-a"):
        await client.get(_route())
        await client.get(_route())
    with lane_scope("run7/unit-b"):
        await client.get(_route())
    await client.get(_route())
    counters = pacing.limiter_for(CONSOLE).counters
    assert counters.by_lane == {"run7/unit-a": 2, "run7/unit-b": 1}
    assert counters.sends == 4
