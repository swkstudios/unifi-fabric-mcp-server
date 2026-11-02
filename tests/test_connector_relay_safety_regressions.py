"""Offline regressions for relay previews and query log handling."""

import logging
from unittest.mock import AsyncMock

import pytest
import respx

from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.secret_scrub import secret_scope
from unifi_fabric.tools import connector, protect_private

KEY = "synthetic-w10-configured-api-key"
HOST = "synthetic-host"
PATH = "protect/api/cameras/0000000000000000000000aa"


@pytest.mark.parametrize("redact", [False, True])
@pytest.mark.parametrize("route", ["relay", "protect"])
async def test_configured_key_scrubbed_from_real_dry_run_preview(redact, route):
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = None
    registry.resolve_host_id.return_value = HOST
    client = UniFiClient(Settings(api_key=KEY, dry_run=True, redact_secrets=redact))
    url = f"https://api.ui.com/v1/connector/consoles/{HOST}/proxy/{PATH}"
    try:
        with respx.mock:
            respx.get(url).respond(200, json={"name": "old"})
            if route == "relay":
                result = await connector.connector_write(
                    client, registry, HOST, "PATCH", PATH, body={"name": KEY}
                )
            else:
                result = await protect_private._update(client, registry, HOST, PATH, {"name": KEY})
        assert result["status"] == "dry_run"
        assert KEY not in str(result)
        assert "***" in str(result)
    finally:
        await client.close()


@pytest.mark.parametrize("redact", [False, True])
@pytest.mark.parametrize("status", [200, 400])
async def test_voucher_filter_is_absent_from_httpx_logs(redact, status, caplog):
    code = "synthetic-w10-voucher-code"
    path = (
        "/v1/connector/consoles/synthetic-host/proxy/network/integration/v1/"
        "sites/site/hotspot/vouchers"
    )
    client = UniFiClient(Settings(api_key=KEY, redact_secrets=redact))
    try:
        with secret_scope(), respx.mock, caplog.at_level(logging.INFO):
            respx.get("https://api.ui.com" + path).respond(status, json={"data": []})
            response = await client.request(
                "GET", path, params={"filter": f"code.eq({code})"}, raise_on_error=False
            )
        assert response.status_code == status
        assert "HTTP Request: GET" in caplog.text
        assert code not in caplog.text
        assert "filter=" not in caplog.text
    finally:
        await client.close()
