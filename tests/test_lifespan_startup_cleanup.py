"""A lifespan whose startup fails after the client exists still releases it."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from unifi_fabric import server


@pytest.mark.parametrize(
    "failing",
    [
        "policy.apply_exposure",
        "apply_read_only_tool_filter",
        "apply_area_opt_out_tool_filter",
        "apply_tool_mode",
    ],
)
async def test_failed_startup_closes_client_and_clears_globals(failing):
    app = MagicMock()
    app.list_tools = AsyncMock(return_value=[])
    client = AsyncMock()
    startup_error = ValueError(f"synthetic {failing} failure")
    with (
        patch("unifi_fabric.config.Settings.get_key_configs", return_value=[{"key": "test"}]),
        patch("unifi_fabric.server.UniFiClient", return_value=client),
        patch("unifi_fabric.server.Registry", return_value=MagicMock()),
        patch(f"unifi_fabric.server.{failing}", AsyncMock(side_effect=startup_error)),
    ):
        with pytest.raises(ValueError) as caught:
            async with server.lifespan(app):
                pytest.fail("startup must not reach the session body")
    assert caught.value is startup_error
    client.close.assert_awaited_once()
    assert server._client is None and server._registry is None
