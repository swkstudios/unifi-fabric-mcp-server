"""Live, non-mutating integration tests for the Protect live-stream collectors.

Requires UNIFI_API_KEY and UNIFI_TEST_HOST. Tests skip when the key is absent and fail
when the key is present but the host is absent. The collectors poll GET endpoints over
a fixed number of complete polls, and the WebSocket canary issues a single upgrade
GET and only inspects the status code. No token is ever minted here — the configured
key is used as-is.

Run (with UNIFI_API_KEY already in the environment, loaded from a secret store; never
type the key on the command line, where shell history keeps it):
    UNIFI_TEST_HOST=<host> \
        pytest tests/test_protect_collectors_integration.py -v
"""

from __future__ import annotations

import base64
import os

import httpx
import pytest
import pytest_asyncio

from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.registry import Registry
from unifi_fabric.tools.protect import (
    collect_protect_device_changes,
    collect_protect_events,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not os.environ.get("UNIFI_API_KEY"),
        reason="UNIFI_API_KEY not set — skipping live integration tests",
    ),
    pytest.mark.asyncio(loop_scope="module"),
]

_TEST_HOST = os.environ.get("UNIFI_TEST_HOST", "")


@pytest.fixture(scope="module")
def settings():
    return Settings()


@pytest_asyncio.fixture(loop_scope="module", scope="module")
async def client(settings):
    c = UniFiClient(settings)
    yield c
    await c.close()


@pytest.fixture(scope="module")
def registry(client, settings):
    return Registry(client, ttl_seconds=settings.cache_ttl_seconds)


def _require_host():
    if not _TEST_HOST:
        pytest.fail("UNIFI_TEST_HOST must be set for Protect collector tests")


class TestCollectEventsIntegration:
    async def test_returns_poll_count_envelope(self, client, registry):
        _require_host()
        result = await collect_protect_events(
            client, registry, _TEST_HOST, poll_count=3, poll_interval_seconds=1
        )
        assert set(result) >= {"result", "_poll_count", "_polls", "_truncated"}
        assert result["_poll_count"] == 3
        assert result["_polls"] == 3 or result["_truncated"]
        assert 1 <= result["_polls"] <= 3
        assert isinstance(result["result"], list)  # empty on a quiet estate is a pass


class TestCollectDeviceChangesIntegration:
    async def test_returns_poll_count_envelope(self, client, registry):
        _require_host()
        result = await collect_protect_device_changes(
            client, registry, _TEST_HOST, poll_count=3, poll_interval_seconds=1
        )
        assert set(result) >= {"_poll_count", "_polls", "_truncated", "changes"}
        assert result["_poll_count"] == 3
        assert result["_polls"] == 3 or result["_truncated"]
        assert 1 <= result["_polls"] <= 3
        assert isinstance(result["changes"], list)
        for change in result["changes"]:
            assert change["change"] in {"added", "removed", "modified"}
            assert "device" in change


async def _check_websocket_canary(http, registry, settings, host):
    key_config = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key_config)
    key = key_config.key if key_config else settings.get_key_configs()[0].key
    base = f"{settings.api_base_url}/v1/connector/consoles/{host_id}/proxy/protect/integration/v1"
    auth = {"X-API-KEY": key}
    control = await http.get(f"{base}/cameras", headers=auth)
    assert control.status_code == 200, "inconclusive: authenticated control failed"
    response = await http.get(
        f"{base}/subscribe/events",
        headers={
            **auth,
            "Connection": "Upgrade",
            "Upgrade": "websocket",
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Key": base64.b64encode(os.urandom(16)).decode(),
        },
    )
    assert response.status_code != 101, "connector accepted the WebSocket upgrade"
    # The documented answer (protect.py exclusion note, acceptance-protect.md, `tf
    # collectors`) is the upstream HTTP 404 "Entity 'endpoint' not found". Any other status
    # may be authorization, routing or an upstream failure, or a changed connector: it is
    # inconclusive, never a pass, exactly as `tf collectors` treats it.
    message = response.text.lower()
    assert response.status_code == 404 and "not found" in message, (
        f"inconclusive: expected upstream HTTP 404 'not found', got {response.status_code}"
    )


class TestWebSocketCanary:
    async def test_subscribe_events_is_not_a_websocket_upgrade(self, client, registry, settings):
        """Check an authenticated control before accepting evidence of upgrade rejection."""
        _require_host()
        async with httpx.AsyncClient(timeout=None) as h:  # noqa: S113
            await _check_websocket_canary(h, registry, settings, _TEST_HOST)
