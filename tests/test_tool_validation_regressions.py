"""Regression coverage for collector and catalog input validation."""

import base64
from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.families.innerspace.innerspace import _fetch_project_document
from unifi_fabric.families.protect.protect import (
    collect_protect_device_changes,
    collect_protect_events,
)
from unifi_fabric.shared_shapes._continuation import decode_continuation


@pytest.mark.parametrize(
    "function,limit",
    [(collect_protect_events, "max_events"), (collect_protect_device_changes, "max_changes")],
)
@pytest.mark.parametrize("value", [0, -1, True, 1.5, "1"])
async def test_collector_rejects_invalid_limit_before_resolution(function, limit, value):
    registry = AsyncMock()
    with pytest.raises(ValueError, match=limit):
        await function(AsyncMock(), registry, "host", **{limit: value})
    registry.resolve_key_for_host.assert_not_awaited()


@pytest.mark.parametrize("value", [0, -1, True, 1.5, "1"])
async def test_collector_rejects_invalid_poll_count(value):
    registry = AsyncMock()
    with pytest.raises(ValueError, match="poll_count"):
        await collect_protect_events(AsyncMock(), registry, "host", poll_count=value)
    registry.resolve_key_for_host.assert_not_awaited()


def test_deep_continuation_is_invalid_token():
    payload = b"{" + b'"v":1,"state":' + b"[" * 20000 + b"0" + b"]" * 20000 + b"}"
    token = "ufpg1:" + base64.urlsafe_b64encode(payload).decode().rstrip("=")
    with pytest.raises(ValueError, match="Malformed _continuation"):
        decode_continuation(token)


async def test_permission_403_does_not_fallback():
    client = AsyncMock()
    client.get.side_effect = UniFiConnectionError("HTTP 403: Forbidden: insufficient permissions")
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = None
    registry.resolve_host_id.return_value = "host"
    with pytest.raises(UniFiConnectionError, match="insufficient permissions"):
        await _fetch_project_document(client, registry, "host", "3D")
    assert client.get.await_count == 1
