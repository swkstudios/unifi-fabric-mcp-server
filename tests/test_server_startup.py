"""Tests for server startup validation."""

from __future__ import annotations

import pytest

from unifi_fabric.config import Settings
from unifi_fabric.server import lifespan


@pytest.mark.asyncio
async def test_lifespan_fails_without_api_key(monkeypatch):
    """Server should raise RuntimeError at startup if no API key is configured."""
    import unifi_fabric.server as server_module

    monkeypatch.delenv("UNIFI_API_KEY", raising=False)
    monkeypatch.delenv("UNIFI_API_KEYS", raising=False)
    monkeypatch.setattr(server_module, "settings", Settings())

    with pytest.raises(RuntimeError, match="No API key configured"):
        async with lifespan(None):
            pass  # pragma: no cover


@pytest.mark.asyncio
async def test_lifespan_succeeds_with_api_key(monkeypatch):
    """Server should start successfully when UNIFI_API_KEY is set."""
    import unifi_fabric.server as server_module

    monkeypatch.setattr(server_module, "settings", Settings(api_key="sk-test-key"))

    async with lifespan(None):
        assert server_module._client is not None
        assert server_module._registry is not None
