"""Hermetic tests for the Protect poll-count live-stream collectors.

Covers ``collect_protect_events`` and ``collect_protect_device_changes`` through the
REAL ``UniFiClient`` with the HTTP transport mocked by respx, so request paths, query
handling, and per-key routing are exercised for real. The explicit poll count and mocked
``protect._sleep`` complete each run deterministically
without real pacing delays.

Cases: window termination, max termination + ``truncated``, id-dedup keeping the LATEST
object, full-record dedup of id-less events (not re-counted toward ``max_events``),
``since`` validated before any resolution or upstream call, added/removed/modified device
diff, the volatile-field (lastSeen/uptime/upSince)
exclusion in the modified-equality basis, upstream-404 pass-through, and multi-key
routing (the data request rides the owning key).
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
import respx
from httpx import Response

from tests.conftest import MULTIKEY_HOSTS_BY_LABEL
from unifi_fabric.client import UniFiClient, UniFiConnectionError
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.families.protect import protect
from unifi_fabric.families.protect.protect import (
    PROTECT_PRIVATE_BASE,
    PROTECT_PROXY_BASE,
    collect_protect_device_changes,
    collect_protect_events,
)
from unifi_fabric.registry import Registry

BASE_URL = "https://api.ui.com"
HOST_ID = "host-001"
EVENTS_PATH = PROTECT_PRIVATE_BASE.format(host_id=HOST_ID) + "/events"
PROXY_BASE = PROTECT_PROXY_BASE.format(host_id=HOST_ID)


@pytest.fixture()
def _no_real_time(monkeypatch):
    """Never apply real pacing delays in hermetic collector tests."""
    monkeypatch.setattr(protect, "_sleep", AsyncMock(return_value=None))


@pytest.fixture()
async def client():
    settings = Settings(api_keys=[APIKeyConfig(key="k-solo", label="solo", is_org_key=False)])
    c = UniFiClient(settings)
    yield c
    await c.close()


@pytest.fixture()
def registry():
    r = AsyncMock()
    r.resolve_key_for_host = AsyncMock(return_value=None)
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    return r


def _family_routes(mock, bodies_by_family: dict[str, object]) -> None:
    """Mock every device family GET. Each value is either a list body (returned on
    every poll) or a list-of-Responses sequenced across polls."""
    for family in protect.DEVICE_FAMILIES:
        body = bodies_by_family.get(family, [])
        route = mock.get(f"{PROXY_BASE}/{family}")
        if isinstance(body, list) and body and isinstance(body[0], Response):
            route.side_effect = body
        else:
            route.return_value = Response(200, json=body)


# --- collect_protect_events ---------------------------------------------------


class TestCollectEvents:
    async def test_poll_count_termination_completes_exactly_requested_polls(
        self, client, registry, monkeypatch, _no_real_time
    ):
        async with respx.mock(base_url=BASE_URL) as mock:
            route = mock.get(EVENTS_PATH)
            route.side_effect = [
                Response(200, json=[{"id": "e1", "v": 1}]),
                Response(200, json=[]),
                Response(200, json=[{"id": "e2", "v": 1}]),
                Response(200, json=[]),
            ]
            result = await collect_protect_events(
                client, registry, "TestConsole", poll_count=2, poll_interval_seconds=1
            )
        assert result["_polls"] == 2
        assert result["_truncated"] is False
        assert result["_poll_count"] == 2
        assert {e["id"] for e in result["result"]} == {"e1", "e2"}

    async def test_max_events_termination_sets_truncated(
        self, client, registry, monkeypatch, _no_real_time
    ):
        # Window would allow many polls; max_events must stop it after poll 1.
        async with respx.mock(base_url=BASE_URL) as mock:
            mock.get(EVENTS_PATH).return_value = Response(
                200, json=[{"id": "e1"}, {"id": "e2"}, {"id": "e3"}]
            )
            result = await collect_protect_events(
                client, registry, "TestConsole", poll_count=5, max_events=2
            )
        assert result["_truncated"] is True
        assert result["_polls"] == 1
        assert len(result["result"]) == 3  # full fidelity: a poll is never split

    async def test_id_less_events_deduplicated_across_polls(
        self, client, registry, monkeypatch, _no_real_time
    ):
        # Every overlapping poll re-returns the same id-less event; it is kept once and
        # counted once toward max_events. An id-less event differing in any field is kept.
        anon = {"type": "motion", "start": 1, "metadata": {"a": [1, 2]}}
        reordered = {"metadata": {"a": [1, 2]}, "start": 1, "type": "motion"}
        other = {"type": "motion", "start": 2}
        async with respx.mock(base_url=BASE_URL) as mock:
            mock.get(EVENTS_PATH).side_effect = [
                Response(200, json=[anon]),
                Response(200, json=[]),
                Response(200, json=[reordered, other]),
                Response(200, json=[]),
                Response(200, json=[anon, other]),
                Response(200, json=[]),
            ]
            result = await collect_protect_events(
                client, registry, "TestConsole", poll_count=3, poll_interval_seconds=1
            )
        assert result["_polls"] == 3
        assert result["result"] == [anon, other]

    async def test_id_less_duplicates_do_not_count_toward_max_events(
        self, client, registry, monkeypatch, _no_real_time
    ):
        anon = {"type": "ring", "start": 5}
        async with respx.mock(base_url=BASE_URL) as mock:
            mock.get(EVENTS_PATH).return_value = Response(200, json=[anon])
            result = await collect_protect_events(
                client, registry, "TestConsole", poll_count=4, max_events=2
            )
        # the same id-less event on every poll never reaches max_events=2
        assert result["_truncated"] is False
        assert result["result"] == [anon]

    async def test_no_default_event_limit(self, client, registry, monkeypatch, _no_real_time):
        """max_events defaults to None: 1000 events in one window are all returned."""
        many = [{"id": f"e{i}"} for i in range(1000)]
        async with respx.mock(base_url=BASE_URL) as mock:
            mock.get(EVENTS_PATH).return_value = Response(200, json=many)
            result = await collect_protect_events(
                client, registry, "TestConsole", poll_count=2, poll_interval_seconds=1
            )
        assert result["_truncated"] is False
        assert result["_polls"] == 2
        assert len(result["result"]) == 1000

    async def test_dedup_keeps_latest_object_per_id(
        self, client, registry, monkeypatch, _no_real_time
    ):
        async with respx.mock(base_url=BASE_URL) as mock:
            mock.get(EVENTS_PATH).side_effect = [
                Response(200, json=[{"id": "e1", "score": 10}]),
                Response(200, json=[]),
                Response(200, json=[{"id": "e1", "score": 99}]),
                Response(200, json=[]),
            ]
            result = await collect_protect_events(
                client, registry, "TestConsole", poll_count=2, poll_interval_seconds=1
            )
        assert len(result["result"]) == 1
        assert result["result"][0]["score"] == 99  # latest object wins

    async def test_upstream_404_passes_through(self, client, registry, monkeypatch, _no_real_time):
        async with respx.mock(base_url=BASE_URL) as mock:
            mock.get(EVENTS_PATH).return_value = Response(
                404, json={"error": "Entity 'endpoint' not found"}
            )
            with pytest.raises(UniFiConnectionError):
                await collect_protect_events(client, registry, "TestConsole", poll_count=1)


# --- collect_protect_device_changes ------------------------------------------


class TestCollectDeviceChanges:
    async def test_added_removed_modified_diff(self, client, registry, monkeypatch, _no_real_time):
        poll1 = [{"id": "c1", "name": "Front"}, {"id": "c2", "name": "Back"}]
        poll2 = [{"id": "c1", "name": "Porch"}, {"id": "c3", "name": "Side"}]
        async with respx.mock(base_url=BASE_URL) as mock:
            _family_routes(
                mock,
                {"cameras": [Response(200, json=poll1), Response(200, json=poll2)]},
            )
            result = await collect_protect_device_changes(
                client, registry, "TestConsole", poll_count=2, poll_interval_seconds=1
            )
        assert result["_polls"] == 2
        changes = {(c["change"], c["device"]["id"]) for c in result["changes"]}
        assert ("modified", "c1") in changes  # c1 name changed
        assert ("added", "c3") in changes  # c3 appeared
        assert ("removed", "c2") in changes  # c2 disappeared

    async def test_volatile_only_change_is_not_modified(
        self, client, registry, monkeypatch, _no_real_time
    ):
        poll1 = [{"id": "c1", "name": "Front", "lastSeen": 100, "uptime": 5, "upSince": 1}]
        poll2 = [{"id": "c1", "name": "Front", "lastSeen": 900, "uptime": 9, "upSince": 1}]
        async with respx.mock(base_url=BASE_URL) as mock:
            _family_routes(
                mock,
                {"cameras": [Response(200, json=poll1), Response(200, json=poll2)]},
            )
            result = await collect_protect_device_changes(
                client, registry, "TestConsole", poll_count=2, poll_interval_seconds=1
            )
        assert result["changes"] == []  # only heartbeat fields moved

    async def test_real_change_alongside_volatile_is_modified(
        self, client, registry, monkeypatch, _no_real_time
    ):
        poll1 = [{"id": "c1", "name": "Front", "lastSeen": 100}]
        poll2 = [{"id": "c1", "name": "Porch", "lastSeen": 900}]
        async with respx.mock(base_url=BASE_URL) as mock:
            _family_routes(
                mock,
                {"cameras": [Response(200, json=poll1), Response(200, json=poll2)]},
            )
            result = await collect_protect_device_changes(
                client, registry, "TestConsole", poll_count=2, poll_interval_seconds=1
            )
        assert [(c["change"], c["device"]["id"]) for c in result["changes"]] == [("modified", "c1")]
        assert result["changes"][0]["device"]["lastSeen"] == 900  # verbatim object shipped

    async def test_no_default_change_limit(self, client, registry, monkeypatch, _no_real_time):
        """max_changes defaults to None: 800 added devices are all reported."""
        poll2 = [{"id": f"c{i}"} for i in range(800)]
        async with respx.mock(base_url=BASE_URL) as mock:
            _family_routes(mock, {"cameras": [Response(200, json=[]), Response(200, json=poll2)]})
            result = await collect_protect_device_changes(
                client, registry, "TestConsole", poll_count=2, poll_interval_seconds=1
            )
        assert result["_truncated"] is False
        assert len(result["changes"]) == 800

    async def test_max_changes_sets_truncated(self, client, registry, monkeypatch, _no_real_time):
        poll1: list = []
        poll2 = [{"id": f"c{i}"} for i in range(5)]
        async with respx.mock(base_url=BASE_URL) as mock:
            _family_routes(
                mock,
                {"cameras": [Response(200, json=poll1), Response(200, json=poll2)]},
            )
            result = await collect_protect_device_changes(
                client, registry, "TestConsole", poll_count=3, max_changes=2
            )
        assert result["_truncated"] is True
        assert len(result["changes"]) == 2

    async def test_upstream_404_passes_through(self, client, registry, monkeypatch, _no_real_time):
        # Protect absent: every family answers 501, so the upstream error passes through.
        async with respx.mock(base_url=BASE_URL) as mock:
            for family in protect.DEVICE_FAMILIES:
                mock.get(f"{PROXY_BASE}/{family}").return_value = Response(
                    501, json={"error": "not implemented"}
                )
            with pytest.raises(UniFiConnectionError, match="501"):
                await collect_protect_device_changes(client, registry, "TestConsole", poll_count=1)

    async def test_family_this_version_lacks_is_named_not_fatal(
        self, client, registry, monkeypatch, _no_real_time
    ):
        poll1 = [{"id": "s1"}]
        poll2 = [{"id": "s1"}, {"id": "s2"}]
        async with respx.mock(base_url=BASE_URL) as mock:
            _family_routes(
                mock,
                {
                    "sirens": [Response(200, json=poll1), Response(200, json=poll2)],
                    "alarm-hubs": [Response(404, json={"error": "nope"})] * 2,
                },
            )
            result = await collect_protect_device_changes(
                client, registry, "TestConsole", poll_count=2, poll_interval_seconds=1
            )
        assert result["changes"] == [{"change": "added", "device": {"id": "s2"}}]
        assert list(result["unavailableFamilies"]) == ["alarm-hubs"]
        assert "404" in result["unavailableFamilies"]["alarm-hubs"]
        assert result["incomplete"] is True and "alarm-hubs" in result["incompleteReason"]


# --- multi-key routing --------------------------------------------------------


_BETA_HOST_ID = "console-beta-1"


async def _seed_host_caches(client: UniFiClient, registry: Registry) -> None:
    for label, hosts in MULTIKEY_HOSTS_BY_LABEL.items():
        await registry.set_hosts(hosts, key=client.get_key_by_label(label))


class TestMultiKeyRouting:
    async def test_events_collector_rides_owning_key(
        self, multikey_client, multikey_registry, monkeypatch, _no_real_time
    ):
        await _seed_host_caches(multikey_client, multikey_registry)
        multikey_registry.resolve_host_id = AsyncMock(return_value=_BETA_HOST_ID)
        beta_events = PROTECT_PRIVATE_BASE.format(host_id=_BETA_HOST_ID) + "/events"
        async with respx.mock(base_url=BASE_URL) as mock:
            route = mock.get(beta_events).mock(return_value=Response(200, json=[]))
            await collect_protect_events(
                multikey_client, multikey_registry, "Beta-Branch", poll_count=1
            )
        assert route.called
        assert route.calls.last.request.headers["X-API-KEY"] == "k-beta"

    async def test_device_changes_collector_rides_owning_key(
        self, multikey_client, multikey_registry, monkeypatch, _no_real_time
    ):
        await _seed_host_caches(multikey_client, multikey_registry)
        multikey_registry.resolve_host_id = AsyncMock(return_value=_BETA_HOST_ID)
        beta_proxy = PROTECT_PROXY_BASE.format(host_id=_BETA_HOST_ID)
        async with respx.mock(base_url=BASE_URL) as mock:
            cameras = mock.get(f"{beta_proxy}/cameras").mock(return_value=Response(200, json=[]))
            for family in protect.DEVICE_FAMILIES:
                if family != "cameras":
                    mock.get(f"{beta_proxy}/{family}").mock(return_value=Response(200, json=[]))
            await collect_protect_device_changes(
                multikey_client, multikey_registry, "Beta-Branch", poll_count=1
            )
        assert cameras.called
        assert cameras.calls.last.request.headers["X-API-KEY"] == "k-beta"


# --- Id-less devices are reported, never silently skipped -------------------------


class TestDeviceChangesUnidentified:
    async def test_idless_device_is_listed_and_flags_incomplete(
        self, client, registry, monkeypatch, _no_real_time
    ):
        anon = {"name": "no-id-sensor", "type": "door"}
        poll = [{"id": "s1", "name": "A"}, anon]
        async with respx.mock(base_url=BASE_URL) as mock:
            _family_routes(mock, {"sensors": [Response(200, json=poll), Response(200, json=poll)]})
            result = await collect_protect_device_changes(
                client, registry, "TestConsole", poll_count=2, poll_interval_seconds=1
            )
        assert result["unidentified"] == [{"family": "sensors", "device": anon}]
        assert result["incomplete"] is True
        assert "1 device object" in result["incompleteReason"]
        assert result["changes"] == []

    async def test_all_identified_has_no_unidentified_key(
        self, client, registry, monkeypatch, _no_real_time
    ):
        async with respx.mock(base_url=BASE_URL) as mock:
            _family_routes(mock, {"cameras": [{"id": "c1"}]})
            result = await collect_protect_device_changes(
                client, registry, "TestConsole", poll_count=2, poll_interval_seconds=1
            )
        assert "unidentified" not in result
        assert "incomplete" not in result
