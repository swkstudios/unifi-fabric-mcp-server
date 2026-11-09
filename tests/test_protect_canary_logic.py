"""Offline verification of the Protect WebSocket canary decision."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest


@pytest.mark.asyncio
async def test_canary_uses_host_key_and_rejects_unrelated_error():
    path = Path(__file__).with_name("test_protect_collectors_integration.py")
    spec = importlib.util.spec_from_file_location("protect_canary", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    key = SimpleNamespace(key="host-key")
    registry = SimpleNamespace(
        resolve_key_for_host=AsyncMock(return_value=key),
        resolve_host_id=AsyncMock(return_value="synthetic-host"),
    )
    http = SimpleNamespace(
        get=AsyncMock(
            side_effect=[
                SimpleNamespace(status_code=200, text=""),
                SimpleNamespace(status_code=403, text="forbidden"),
            ]
        )
    )
    settings = SimpleNamespace(api_base_url="https://example.invalid", get_key_configs=MagicMock())
    with pytest.raises(AssertionError, match="inconclusive"):
        await module._check_websocket_canary(http, registry, settings, "synthetic-host")
    registry.resolve_host_id.assert_awaited_once_with("synthetic-host", key=key)
    assert all(
        call.kwargs["headers"]["X-API-KEY"] == "host-key" for call in http.get.await_args_list
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "control, status, body, expected",
    [
        (401, 404, "Entity 'endpoint' not found", "control"),
        (200, 101, "", "accepted"),
        (200, 404, '{"code":"not_found","message":"Entity \'endpoint\' not found"}', None),
        (200, 404, "", "inconclusive"),
        (200, 400, "bad request", "inconclusive"),
        (200, 400, "websocket not supported", "inconclusive"),
        (200, 501, "websocket unsupported", "inconclusive"),
    ],
)
async def test_canary_requires_control_and_explicit_rejection(control, status, body, expected):
    path = Path(__file__).with_name("test_protect_collectors_integration.py")
    spec = importlib.util.spec_from_file_location("protect_canary_cases", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    registry = SimpleNamespace(
        resolve_key_for_host=AsyncMock(return_value=None),
        resolve_host_id=AsyncMock(return_value="synthetic-host"),
    )
    settings = SimpleNamespace(
        api_base_url="https://example.invalid",
        get_key_configs=MagicMock(return_value=[SimpleNamespace(key="single-key")]),
    )
    http = SimpleNamespace(
        get=AsyncMock(
            side_effect=[
                SimpleNamespace(status_code=control, text=""),
                SimpleNamespace(status_code=status, text=body),
            ]
        )
    )
    if expected:
        with pytest.raises(AssertionError, match=expected):
            await module._check_websocket_canary(http, registry, settings, "synthetic-host")
    else:
        await module._check_websocket_canary(http, registry, settings, "synthetic-host")
