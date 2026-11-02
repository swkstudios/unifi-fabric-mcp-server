"""Bounded-window collectors keep what they gathered, whatever ends the window.

Every collector tool (every registered tool taking ``poll_count``) is driven so its
first poll succeeds and every later upstream read fails, with each kind of failure the
client can raise: an HTTP error status, a 429 that stays 429 through the retries
(``RateLimitError``), a transport error and a response of the wrong shape. The result
is returned, never raised: ``incomplete: true``, an ``incompleteReason`` carrying the
failed poll's complete error, and the results gathered before it.

The device-change diff never reports a change for a device family that was unavailable
(404/501) in either of the two polls it compares: a family that stops answering is not
"removed", and one that starts answering is not "added".
"""

from __future__ import annotations

import functools
import logging
from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_catalog import lazy_parametrize
from unifi_fabric.tools import protect

TOOLS = cti.TOOLS


@functools.cache
def _lz_COLLECTORS():
    return sorted(
        n for n, t in TOOLS.items() if "poll_count" in (t.parameters or {}).get("properties", {})
    )


#: failure kind -> a fragment the complete upstream error carries
FAILURES = {
    "http_500": "probe-poll-failure",
    "rate_limited": "probe-rate-limited",
    "transport": "probe connect failure",
    "shape": "Unexpected",
}


@pytest.fixture(autouse=True)
def _quiet_logs():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


def test_collectors_are_found():
    assert {"collect_protect_events", "collect_protect_device_changes"} <= set(_lz_COLLECTORS())


@dataclass
class _FailAfter(uh.FakeUpstream):
    """Answers the first ``allow`` non-resolution GETs normally, then fails every one."""

    allow: int = 10**9
    kind: str = "http_500"
    reads: int = 0

    def __call__(self, req: httpx.Request) -> httpx.Response:
        if req.method != "GET" or uh.is_resolution(req.url.path):
            return super().__call__(req)
        self.reads += 1
        if self.reads <= self.allow:
            return super().__call__(req)
        if self.kind == "transport":
            self._record(req, 0, None, False)
            raise httpx.ConnectError(FAILURES["transport"], request=req)
        if self.kind == "shape":
            self._record(req, 200, "probe-scalar", False)
            return httpx.Response(200, json="probe-scalar")
        status = 429 if self.kind == "rate_limited" else 500
        body = {"code": FAILURES[self.kind]}
        self._record(req, status, body, False)
        return httpx.Response(status, json=body)


def _args(name: str, polls: int) -> dict[str, Any]:
    return {
        **tool_args.generated_args(TOOLS[name]),
        "poll_count": polls,
        "poll_interval_seconds": 0.01,
    }


def _payload(res: Any) -> Any:
    return uh.result_payload(res)


def _step_clock(monkeypatch) -> None:
    """Each run completes explicit polls; suppress only between-poll pacing."""
    monkeypatch.setattr(protect, "_sleep", AsyncMock())


async def _reads_per_poll(monkeypatch, name: str) -> int:
    """Non-resolution GETs one poll makes (a requested count of one polls exactly once)."""
    up = _FailAfter()
    await cti._call(monkeypatch, name, up, _args(name, 1))
    return up.reads


@lazy_parametrize("kind", lambda: sorted(FAILURES))
@lazy_parametrize("name", lambda: _lz_COLLECTORS())
async def test_a_failure_after_the_first_poll_keeps_the_gathered_results(monkeypatch, name, kind):
    allow = await _reads_per_poll(monkeypatch, name)
    assert allow >= 1, f"{name}: one poll made no upstream read"
    up = _FailAfter(allow=allow, kind=kind)
    res = await cti._call(monkeypatch, name, up, _args(name, 30))
    payload = _payload(res)
    assert payload.get("incomplete") is True, f"{name}/{kind}: {payload}"
    reason = str(payload.get("incompleteReason"))
    assert FAILURES[kind] in reason, f"{name}/{kind}: the full error is missing: {reason[:300]}"
    assert payload.get("_polls", 0) >= 1, payload
    if "result" in payload:  # the events gathered by the first poll are kept
        assert payload["result"], f"{name}/{kind}: gathered events were dropped"


@dataclass
class _FamilyFlip(uh.FakeUpstream):
    """Protect device families with one distinct device each; ``family`` answers 404 in
    the polls ``down`` names (poll numbers counted by the cameras list read)."""

    family: str = "lights"
    down: frozenset[int] = frozenset()
    poll: int = 0

    def __call__(self, req: httpx.Request) -> httpx.Response:
        path = req.url.path
        last = path.rsplit("/", 1)[-1]
        if req.method == "GET" and "/proxy/protect/" in path and last in protect.DEVICE_FAMILIES:
            if last == protect.DEVICE_FAMILIES[0]:
                self.poll += 1
            if last == self.family and self.poll in self.down:
                body = {"error": "probe not served"}
                self._record(req, 404, body, False)
                return httpx.Response(404, json=body)
            page = [{"id": f"probe-{last}", "name": last}]
            self._record(req, 200, page, False)
            return httpx.Response(200, json=page)
        return super().__call__(req)


@pytest.mark.parametrize(
    "down",
    [frozenset(range(2, 1000)), frozenset({1}), frozenset({2})],
    ids=["stops-answering", "starts-answering", "one-poll-gap"],
)
@pytest.mark.parametrize("family", list(protect.DEVICE_FAMILIES))
async def test_an_unavailable_family_is_never_diffed(monkeypatch, family, down):
    _step_clock(monkeypatch)
    name = "collect_protect_device_changes"
    up = _FamilyFlip(family=family, down=down)
    res = await cti._call(monkeypatch, name, up, _args(name, 6))
    payload = _payload(res)
    assert payload["_polls"] >= 3, payload  # the flip is inside the window
    flipped = [c for c in payload["changes"] if c["device"].get("id") == f"probe-{family}"]
    assert flipped == [], f"{family}: reported {[c['change'] for c in flipped]}"
    assert family in payload.get("unavailableFamilies", {}), payload
    others = [c for c in payload["changes"] if c["device"].get("id") != f"probe-{family}"]
    assert others == [], others  # the other families never changed


@dataclass
class _IdlessOnce(uh.FakeUpstream):
    """Every Protect device family answers ``[]``, except ``family``, whose FIRST poll
    answers one device object without an id."""

    family: str = "cameras"
    served_idless: bool = False

    def __call__(self, req: httpx.Request) -> httpx.Response:
        path = req.url.path
        last = path.rsplit("/", 1)[-1]
        if req.method == "GET" and "/proxy/protect/" in path and last in protect.DEVICE_FAMILIES:
            page: list[Any] = []
            if last == self.family and not self.served_idless:
                self.served_idless = True
                page = [{"name": "Idless device", "status": "offline"}]
            self._record(req, 200, page, False)
            return httpx.Response(200, json=page)
        return super().__call__(req)


@pytest.mark.parametrize("family", list(protect.DEVICE_FAMILIES))
async def test_an_id_less_device_seen_in_any_poll_stays_reported(monkeypatch, family):
    _step_clock(monkeypatch)
    """An id-less observation from ANY poll of the window is kept under ``unidentified``
    and the result stays incomplete, even when later polls no longer return it."""
    name = "collect_protect_device_changes"
    up = _IdlessOnce(family=family)
    payload = _payload(await cti._call(monkeypatch, name, up, _args(name, 6)))
    assert payload["_polls"] >= 2, payload
    assert payload.get("unidentified") == [
        {"family": family, "device": {"name": "Idless device", "status": "offline"}}
    ], payload
    assert payload.get("incomplete") is True and "no id" in payload["incompleteReason"], payload


@dataclass
class _IdlessHeartbeat(uh.FakeUpstream):
    """``family`` answers one id-less device whose ``uptime`` / ``lastSeen`` rise on every
    poll; every other family answers ``[]``."""

    family: str = "cameras"
    beats: int = 0

    def __call__(self, req: httpx.Request) -> httpx.Response:
        path = req.url.path
        last = path.rsplit("/", 1)[-1]
        if req.method == "GET" and "/proxy/protect/" in path and last in protect.DEVICE_FAMILIES:
            page: list[Any] = []
            if last == self.family:
                self.beats += 1
                page = [{"name": "Idless", "uptime": self.beats, "lastSeen": 1000 + self.beats}]
            self._record(req, 200, page, False)
            return httpx.Response(200, json=page)
        return super().__call__(req)


@pytest.mark.parametrize("family", list(protect.DEVICE_FAMILIES))
async def test_an_id_less_heartbeat_is_one_entry_in_its_latest_form(monkeypatch, family):
    """A heartbeat (rising uptime / lastSeen) never multiplies an id-less device: it is one
    ``unidentified`` entry, the latest verbatim object, however long the window."""
    _step_clock(monkeypatch)
    name = "collect_protect_device_changes"
    up = _IdlessHeartbeat(family=family)
    payload = _payload(await cti._call(monkeypatch, name, up, _args(name, 6)))
    assert payload["_polls"] >= 3, payload
    assert payload.get("unidentified") == [
        {
            "family": family,
            "device": {"name": "Idless", "uptime": up.beats, "lastSeen": 1000 + up.beats},
        }
    ], payload
