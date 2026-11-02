"""Regression coverage for core review follow-ups, with hermetic upstream responses."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from unifi_fabric import server
from unifi_fabric.config import MCPTransportSettings
from unifi_fabric.redaction import RedactionScopeMiddleware, write_redaction_enabled


@respx.mock
@pytest.mark.parametrize("bad_listing", ["nextToken", "siteId"])
async def test_isp_upstream_site_shape_failure_is_scoped_to_key(
    multikey_client, multikey_registry, monkeypatch, bad_listing
):
    base = "https://api.ui.com"
    hosts = {"k-alpha": "AAAAAAAAAAAA0000:1", "k-beta": "BBBBBBBBBBBB0000:2"}
    respx.get(f"{base}/v1/hosts").mock(
        side_effect=lambda request: httpx.Response(
            200, json={"data": [{"id": hosts[request.headers["X-API-KEY"]]}]}
        )
    )

    def listing(request):
        host = hosts[request.headers["X-API-KEY"]]
        record = {"hostId": host, "siteId": "site-beta", "meta": {"name": "Office"}}
        body = {"data": [record]}
        if request.headers["X-API-KEY"] == "k-alpha":
            if bad_listing == "nextToken":
                body["nextToken"] = 5
            else:
                record["siteId"] = 5
        return httpx.Response(200, json=body)

    respx.get(f"{base}/v1/sites").mock(side_effect=listing)
    query = respx.post(f"{base}/v1/isp-metrics/5m/query").mock(
        return_value=httpx.Response(
            200, json={"data": {"metrics": [{"siteId": "site-beta", "latency": 17}]}}
        )
    )
    monkeypatch.setattr(server, "_client", multikey_client)
    monkeypatch.setattr(server, "_registry", multikey_registry)
    result = await server.query_isp_metrics(
        "5m", sites=[{"hostId": host, "siteId": "Office"} for host in hosts.values()]
    )
    assert result["data"]["metrics"] == [
        {"siteId": "site-beta", "latency": 17, "_keyLabel": "beta"}
    ]
    assert result["_key_labels"] == ["beta"]
    assert len(result["errors"]) == 1
    assert "alpha" in result["errors"][0] and bad_listing in result["errors"][0]
    assert query.call_count == 1
    assert query.calls[0].request.headers["X-API-KEY"] == "k-beta"


@pytest.mark.parametrize("enabled", [False, True])
async def test_redaction_scope_loads_lazy_settings_before_lifespan(monkeypatch, enabled):
    monkeypatch.setattr(server, "_settings", None)
    monkeypatch.setenv("UNIFI_REDACT_SECRETS", str(enabled).lower())
    middleware = next(
        item for item in server.mcp.middleware if isinstance(item, RedactionScopeMiddleware)
    )

    async def handler(_context):
        assert write_redaction_enabled() is enabled
        return "handled"

    assert await middleware.on_call_tool(SimpleNamespace(), handler) == "handled"
    assert server._settings.redact_secrets is enabled


def test_redaction_scope_defers_malformed_settings_to_startup(monkeypatch):
    monkeypatch.setattr(server, "_settings", None)
    monkeypatch.setenv("UNIFI_API_KEYS", "not-json")
    assert server._redaction_scope_enabled() is False
    assert server._settings is None


@pytest.mark.parametrize("primary_failure", [False, True])
async def test_jwks_cleanup_preserves_primary_close_failure(monkeypatch, primary_failure):
    monkeypatch.setenv("FASTMCP_TRANSPORT", "streamable-http")
    auth = server.build_auth(
        MCPTransportSettings(
            auth_mode="oauth",
            oauth_issuer="https://issuer.example/",
            oauth_jwks_uri="https://issuer.example/jwks",
            oauth_audience="https://resource.example/",
            oauth_base_url="https://resource.example/",
        )
    )
    real_jwks = auth.token_verifier._http_client
    await real_jwks.aclose()
    jwks = AsyncMock()
    jwks.aclose.side_effect = RuntimeError("synthetic JWKS close failure")
    auth.token_verifier._http_client = jwks
    app = MagicMock()
    app.list_tools = AsyncMock(return_value=[])
    app.auth = auth
    client = AsyncMock()
    primary = ValueError("synthetic UniFi close failure")
    if primary_failure:
        client.close.side_effect = primary
    with (
        patch("unifi_fabric.config.Settings.get_key_configs", return_value=[{"key": "test"}]),
        patch("unifi_fabric.server.UniFiClient", return_value=client),
        patch("unifi_fabric.server.Registry", return_value=MagicMock()),
    ):
        with pytest.raises(ValueError if primary_failure else RuntimeError) as caught:
            async with server.lifespan(app):
                pass
    if primary_failure:
        assert caught.value is primary
        assert "synthetic JWKS close failure" in " ".join(caught.value.__notes__)
    else:
        assert str(caught.value) == "synthetic JWKS close failure"
    jwks.aclose.assert_awaited_once()
    assert server._client is None and server._registry is None
