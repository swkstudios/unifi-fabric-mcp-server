"""Authentication guidance is additive even when relay errors return as data."""

from unittest.mock import AsyncMock

import httpx
import pytest
import respx

from unifi_fabric.client import UniFiClient
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.tools.connector import connector_get, connector_write


@pytest.mark.parametrize("status", [401, 403])
@pytest.mark.parametrize("multi", [False, True])
@pytest.mark.parametrize("method", ["GET", "POST", "PUT", "PATCH", "DELETE"])
@respx.mock
async def test_relay_auth_errors_keep_body_and_add_key_guidance(status, multi, method):
    keys = [
        APIKeyConfig(key="synthetic-key-one", label="first"),
        APIKeyConfig(key="synthetic-key-two", label="second"),
    ]
    settings = Settings(api_keys=keys) if multi else Settings(api_key="synthetic-only-key")
    client = UniFiClient(settings)
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = keys[1] if multi else None
    registry.resolve_host_id.return_value = "synthetic-host"
    path = "protect/api/events"
    url = "https://api.ui.com/v1/connector/consoles/synthetic-host/proxy/" + path
    body = {"error": "upstream reason", "detail": "α unchanged"}
    respx.get(url).mock(return_value=httpx.Response(status, json=body))
    if method != "GET":
        respx.route(method=method, url=url).mock(return_value=httpx.Response(status, json=body))
    try:
        result = (
            await connector_get(client, registry, "console", path)
            if method == "GET"
            else await connector_write(
                client, registry, "console", method, path, body={"name": "unchanged"}
            )
        )
        outcomes = [result]
        if method in {"PUT", "PATCH", "DELETE"}:
            outcomes += [result["readBefore"], result["readAfter"]]
        for outcome in outcomes:
            assert outcome["status"] == status
            assert outcome["body"] == body
            assert (
                "UNIFI_API_KEYS" in outcome["_hint"]
                if multi
                else "UNIFI_API_KEY" in outcome["_hint"]
            )
            if multi:
                assert "second" in outcome["_hint"]
            assert (
                "permission" in outcome["_hint"].lower()
                if status == 403
                else "key" in outcome["_hint"].lower()
            )
    finally:
        await client.close()
