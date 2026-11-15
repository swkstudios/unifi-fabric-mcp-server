"""Per-console request pacing for the Fabric connector (100 requests/min per console).

The connector answers HTTP 429 above 100 requests per minute per console (Site Manager
spec, connector consoles routes; ``docs/RETRY.md``). This module keeps one sliding-window
send log per console id, process-wide, so every tool call to a console (typed tools, the
generic relay, parallel fan-out, a second client in the same process) draws on one budget.

Rules:

* A request is sent only while fewer than ``max_rpm`` sends sit in the trailing 60 s
  (default 95, ``UNIFI_CONNECTOR_MAX_RPM``, 1-100). There is no burst credit: an idle
  console starts every minute with the same cap.
* A **write** (POST/PUT/PATCH/DELETE that is not a read-POST) is admitted only at or
  below ``max_rpm - 5`` sends in the trailing 60 s (90 by default) and only when the
  console had no 429 in the last 60 s. While a write waits, reads stop at the same
  line, so the write cannot be starved and its read-back still fits under the cap.
* Any 429 backs the console off: the cap drops to ``max(count_at_429 - 10, 60)`` and
  climbs 5 per minute back to ``max_rpm``.
* Writes are never retried here (the caller's rule, :mod:`unifi_fabric.client`); this
  module only decides *when* a send may start and how long a GET waits after a 429.

Only connector routes (``/v1/connector/consoles/{id}/...``) are paced: the limit is the
connector's, per console. Site Manager routes are not.

The clock and sleep are injectable (:func:`set_time_source`) so the tests drive 1000
acquires on a fake clock. State is guarded by a thread lock, so one limiter is safe
across event loops and threads.
"""

from __future__ import annotations

import asyncio
import re
import threading
import time
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Final
from urllib.parse import unquote

#: The connector's documented limit and the width of its window.
CONNECTOR_LIMIT_RPM: Final = 100
WINDOW_SECONDS: Final = 60.0
#: Default send cap per console per trailing 60 s (``UNIFI_CONNECTOR_MAX_RPM``).
DEFAULT_MAX_RPM: Final = 95
#: A write starts only this far below the cap, and reads stop here while one waits.
WRITE_RESERVE: Final = 5
#: A read waiting out a 429 sleeps until the trailing count is below this line.
READ_RETRY_LINE: Final = 90
#: Back-off after a 429: cap = max(count - 10, floor), climbing 5 per minute.
BACKOFF_DROP: Final = 10
BACKOFF_FLOOR: Final = 60
BACKOFF_CLIMB_PER_MINUTE: Final = 5
#: A GET waits at most this long per 429 when the connector sent no Retry-After, and this
#: long in total across one call. A Retry-After is honoured exactly (never shortened).
MAX_WAIT_PER_RETRY_SECONDS: Final = 64.0
MAX_WAIT_TOTAL_SECONDS: Final = 120.0
#: With no Retry-After a 429 means the console's window is full: wait one window.
NO_RETRY_AFTER_WAIT_SECONDS: Final = 60.0

_CONSOLE_RE = re.compile(r"^/v1/connector/consoles/([^/]+)/")

Clock = Callable[[], float]
Sleeper = Callable[[float], Awaitable[None]]

_clock: Clock = time.monotonic
_sleep: Sleeper = asyncio.sleep


def set_time_source(clock: Clock | None = None, sleep: Sleeper | None = None) -> None:
    """Replace the clock and the sleeper (tests); call with no arguments to restore."""
    global _clock, _sleep
    _clock = clock or time.monotonic
    _sleep = sleep or asyncio.sleep


def console_id(path: object) -> str | None:
    """The console id of a connector route, else ``None`` (not paced)."""
    if not isinstance(path, str):
        return None
    match = _CONSOLE_RE.match(path)
    return match.group(1) if match else None


def validate_max_rpm(value: object) -> int:
    """``value`` as a cap in 1-100, else ``ValueError`` naming the setting."""
    if isinstance(value, bool):
        raise ValueError("UNIFI_CONNECTOR_MAX_RPM must be an integer from 1 to 100")
    try:
        number = int(str(value).strip())
    except ValueError:
        raise ValueError("UNIFI_CONNECTOR_MAX_RPM must be an integer from 1 to 100") from None
    if not 1 <= number <= CONNECTOR_LIMIT_RPM:
        raise ValueError(
            "UNIFI_CONNECTOR_MAX_RPM must be an integer from 1 to 100 "
            f"(the connector limit is {CONNECTOR_LIMIT_RPM} requests per minute per console)"
        )
    return number


@dataclass
class Counters:
    """What one console's limiter has done since it was created (window accounting)."""

    sends: int = 0
    write_sends: int = 0
    throttled_429: int = 0
    waited_seconds: float = 0.0
    #: 429s that arrived while this process had sent fewer than 90 in the trailing 60 s:
    #: some sender this process cannot see filled the console.
    outside_sender_429: int = 0
    by_lane: dict[str, int] = field(default_factory=dict)


class ConsoleLimiter:
    """One console's sliding-window send log and back-off state."""

    def __init__(self, max_rpm: int = DEFAULT_MAX_RPM) -> None:
        self.max_rpm = validate_max_rpm(max_rpm)
        self._sends: deque[float] = deque()
        self._lock = threading.Lock()
        self._writers_waiting = 0
        self._last_429: float | None = None
        self._backoff_cap: int | None = None
        self._backoff_start = 0.0
        self.counters = Counters()

    # -- state (call with the lock held, or from tests) ---------------------------------

    def _prune(self, now: float) -> None:
        horizon = now - WINDOW_SECONDS
        sends = self._sends
        while sends and sends[0] <= horizon:
            sends.popleft()

    def _cap(self, now: float) -> int:
        """The send cap right now: ``max_rpm``, or the climbing back-off cap after a 429."""
        if self._backoff_cap is None:
            return self.max_rpm
        climbed = self._backoff_cap + BACKOFF_CLIMB_PER_MINUTE * int(
            (now - self._backoff_start) // WINDOW_SECONDS
        )
        if climbed >= self.max_rpm:
            self._backoff_cap = None
            return self.max_rpm
        return min(climbed, self.max_rpm)

    def _read_line(self, now: float) -> int:
        """Reads may send while the count is below this (lower while a write waits)."""
        cap = self._cap(now)
        return max(cap - WRITE_RESERVE, 1) if self._writers_waiting else cap

    def _write_line(self, now: float) -> int:
        """A write may send while the count is below this (count <= max_rpm - 5)."""
        return max(self._cap(now) - WRITE_RESERVE, 0) + 1

    def count(self, now: float | None = None) -> int:
        """Sends in the trailing 60 s."""
        with self._lock:
            now = _clock() if now is None else now
            self._prune(now)
            return len(self._sends)

    def seconds_until_below(self, line: int, now: float | None = None) -> float:
        """Seconds until the trailing count is below ``line`` (0 when it already is)."""
        with self._lock:
            now = _clock() if now is None else now
            self._prune(now)
            return self._until_below(line, now)

    def _until_below(self, line: int, now: float) -> float:
        excess = len(self._sends) - line + 1
        if excess <= 0:
            return 0.0
        return max(self._sends[excess - 1] + WINDOW_SECONDS - now, 0.0)

    # -- admission -----------------------------------------------------------------------

    def _admission_wait(self, *, write: bool, now: float) -> float:
        """0.0 when a send may go now, else how long to wait (records nothing)."""
        self._prune(now)
        count = len(self._sends)
        if write:
            if self._last_429 is not None and now - self._last_429 < WINDOW_SECONDS:
                return max(self._last_429 + WINDOW_SECONDS - now, 0.001)
            line = self._write_line(now)
        else:
            line = self._read_line(now)
        if count >= line:
            return max(self._until_below(line, now), 0.001)
        return 0.0

    def _in_backoff(self, now: float) -> bool:
        """True while a 429 holds writes (60 s) or its lowered cap has not climbed back."""
        held = self._last_429 is not None and now - self._last_429 < WINDOW_SECONDS
        return held or self._cap(now) < self.max_rpm

    def _try_admit(self, *, write: bool, lane: str | None, now: float, tally: bool = True) -> float:
        """Admit and return 0.0, or return how long to wait before looking again.

        ``tally=False`` records the send in the window without counting it again in
        :attr:`counters` (a send whose reservation aged out is admitted a second time).
        """
        wait = self._admission_wait(write=write, now=now)
        if wait:
            return wait
        self._sends.append(now)
        if not tally:
            return 0.0
        self.counters.sends += 1
        if write:
            self.counters.write_sends += 1
        if lane is not None:
            self.counters.by_lane[lane] = self.counters.by_lane.get(lane, 0) + 1
        return 0.0

    async def acquire(
        self, *, write: bool = False, lane: str | None = None, tally: bool = True
    ) -> float:
        """Wait until a send is allowed, record it, and return the seconds waited.

        ``tally=False`` for a send already counted by a :meth:`reserve` that aged out of
        the window before the request left: it is recorded in the window again but
        counted once in :attr:`counters`.
        """
        waited, _stamp = await self._admit(write=write, lane=lane, tally=tally)
        return waited

    async def reserve(
        self, *, write: bool = False, lane: str | None = None, tally: bool = True
    ) -> float:
        """Wait until a send is allowed, record it, and return its stamp.

        The client reserves before it takes a global concurrency slot, so a pacing wait
        never holds one, then moves the stamp to the moment the request leaves with
        :meth:`restamp`.
        """
        _waited, stamp = await self._admit(write=write, lane=lane, tally=tally)
        return stamp

    def restamp(self, stamp: float, now: float | None = None, *, write: bool = False) -> bool:
        """Move one recorded send from ``stamp`` to ``now``; False when it already left
        the window, or when a 429 arrived since the reservation and the send would not
        be admitted now (the caller then admits it again, waiting out the backoff).

        A later stamp only keeps the send in the window longer, so the cap still holds
        for sends counted from the moment they leave. While the console is in 429 backoff
        the admission check runs again: a reservation never carries a write past the 60 s
        hold, or a read past the lowered cap. A refused reservation is removed.
        """
        with self._lock:
            now = _clock() if now is None else now
            self._prune(now)
            try:
                self._sends.remove(stamp)
            except ValueError:
                return False
            if self._in_backoff(now) and self._admission_wait(write=write, now=now):
                return False
            # Every recorded stamp was taken from the same clock before now: still sorted.
            self._sends.append(now)
            return True

    async def _admit(
        self, *, write: bool, lane: str | None, tally: bool = True
    ) -> tuple[float, float]:
        """``(seconds waited, stamp)`` of one admitted send."""
        waited = 0.0
        registered = False
        try:
            while True:
                with self._lock:
                    now = _clock()
                    if write and not registered:
                        self._writers_waiting += 1
                        registered = True
                    wait = self._try_admit(write=write, lane=lane, now=now, tally=tally)
                    if wait == 0.0:
                        self.counters.waited_seconds += waited
                        return waited, now
                await _sleep(wait)
                waited += wait
        finally:
            if registered:
                with self._lock:
                    self._writers_waiting -= 1

    def note_429(self, now: float | None = None) -> None:
        """A 429 arrived: start the back-off (cap = max(count - 10, 60), +5 per minute)."""
        with self._lock:
            now = _clock() if now is None else now
            self._prune(now)
            self._last_429 = now
            if len(self._sends) < READ_RETRY_LINE:
                self.counters.outside_sender_429 += 1
            self._backoff_cap = max(len(self._sends) - BACKOFF_DROP, BACKOFF_FLOOR)
            self._backoff_start = now
            self.counters.throttled_429 += 1

    def read_retry_wait(
        self, retry_after: float | None, *, waited_total: float, attempt: int = 0
    ) -> float | None:
        """How long a GET sleeps after a 429, or ``None`` when it must stop (and not re-send).

        * A ``Retry-After`` is honoured exactly: the wait is that long, or longer when the
          trailing count needs more time to fall below 90. It is never capped or shortened,
          and a request is never re-sent before it. When it does not fit in what is left of
          the 120 s budget, the answer is ``None``: raise, do not sleep, do not re-send.
        * With no ``Retry-After`` the wait is at least one window (60 s), at least the
          documented exponential backoff for ``attempt``, and until the count is below 90;
          at most 64 s per wait.
        """
        now = _clock()
        until_below = self.seconds_until_below(READ_RETRY_LINE, now)
        if retry_after is not None:
            wait = max(retry_after, until_below)
        else:
            backoff = min(2.0**attempt, 32.0) * 2
            wait = max(NO_RETRY_AFTER_WAIT_SECONDS, backoff, until_below)
            wait = min(wait, MAX_WAIT_PER_RETRY_SECONDS)
        if waited_total + wait > MAX_WAIT_TOTAL_SECONDS:
            return None
        return wait


def attempts_on_unannounced_429() -> int:
    """Sends a GET makes on a connector route that keeps answering 429 with no Retry-After.

    Each wait is one 60 s window and a call waits 120 s in total, so the first send and two
    retries: 3 sends, then ``RateLimitError``.
    """
    return 1 + int(MAX_WAIT_TOTAL_SECONDS // NO_RETRY_AFTER_WAIT_SECONDS)


def _key(console: str) -> str:
    """One key per console however its id is spelled (case, percent-encoding)."""
    return unquote(console).strip().upper()


_registry: dict[str, ConsoleLimiter] = {}
_registry_lock = threading.Lock()


def limiter_for(console: str, max_rpm: int = DEFAULT_MAX_RPM) -> ConsoleLimiter:
    """The process-wide limiter of ``console`` (created on first use at ``max_rpm``)."""
    with _registry_lock:
        key = _key(console)
        existing = _registry.get(key)
        if existing is None:
            existing = _registry[key] = ConsoleLimiter(max_rpm)
        return existing


def reset_registry() -> None:
    """Forget every limiter (tests)."""
    with _registry_lock:
        _registry.clear()
