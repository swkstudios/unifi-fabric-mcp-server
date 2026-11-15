"""A generator script that installs the hermetic upstream must not wait on the real pacer.

``tests/conftest.py`` puts the connector pacer on an instant clock for pytest. The generator
scripts (``scripts/private_api/tool_map.py``, ``scripts/dump_tool_baseline.py``,
``scripts/regen_docs.py`` and the rest that call ``tests.upstream_harness.install``) run
without conftest, on the real clock: the 96th stubbed request to one console would wait out a
real minute. ``install`` therefore installs the instant clock itself.
"""

from __future__ import annotations

import asyncio
import time

from tests import upstream_harness as uh
from unifi_fabric import pacing


def test_installing_the_harness_puts_the_pacer_on_an_instant_clock(monkeypatch):
    # What a script sees: the real clock (conftest's instant clock removed). The real sleeper
    # is stood in for by one that fails at once, so a pacer left on the real clock fails here
    # in milliseconds instead of waiting out a real minute (no timeout needed).
    async def real_sleep(seconds: float) -> None:
        raise AssertionError(f"the pacer slept {seconds:.1f}s on the real clock")

    monkeypatch.setattr(pacing, "_clock", time.monotonic)
    monkeypatch.setattr(pacing, "_sleep", real_sleep)
    pacing.reset_registry()
    uh.install(monkeypatch, uh.FakeUpstream())
    limiter = pacing.limiter_for("console-under-test")

    async def burst() -> None:
        for _ in range(3 * pacing.DEFAULT_MAX_RPM):
            await limiter.acquire(write=False, lane=None)

    asyncio.run(burst())
    assert limiter.counters.sends == 3 * pacing.DEFAULT_MAX_RPM
    assert limiter.counters.waited_seconds > 0, "the burst never reached the cap: test is vacuous"


def test_a_time_source_a_test_installed_is_not_replaced(monkeypatch):
    now = {"t": 5.0}

    def clock() -> float:
        return now["t"]

    monkeypatch.setattr(pacing, "_clock", clock)
    uh.install(monkeypatch, uh.FakeUpstream())
    assert pacing._clock is clock  # noqa: SLF001
