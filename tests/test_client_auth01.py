"""Caller data follows the opt-in redaction setting; server credentials stay masked."""

import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from unifi_fabric import server
from unifi_fabric.client import UniFiClient, UniFiConnectionError
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.secret_scrub import secret_scope
from unifi_fabric.tools._classic_objects import checked_classic_response

PATH = "/v1/connector/consoles/console/proxy/network/v2/api/site/default/matter/nodes"
CALLER = "synthetic-caller-credential"
UPSTREAM = "synthetic-upstream-credential"
KEY = "synthetic-current-call-key"
BEARER = "synthetic-server-bearer"
TLS = "synthetic-tls-password"
CONFIGURED = "synthetic-other-configured-key"


@pytest.mark.parametrize("redact", [False, True])
@pytest.mark.parametrize("status", [200, 400])
@pytest.mark.parametrize("raise_on_error", [False, True])
async def test_auth01_response_and_error_scope(monkeypatch, caplog, redact, status, raise_on_error):
    monkeypatch.setenv("MCP_BEARER_TOKEN", BEARER)
    monkeypatch.setenv("MCP_TLS_KEY_PASSWORD", TLS)
    settings = Settings(api_key=CONFIGURED, redact_secrets=redact)
    client = UniFiClient(settings)
    payload = {
        "setup_code": UPSTREAM,
        "reason": (
            f"denied caller={CALLER}; route={UPSTREAM}; key={KEY}; "
            f"bearer={BEARER}; tls={TLS}; configured={CONFIGURED}"
        ),
    }

    def handler(request):
        return httpx.Response(status, json=payload, headers={"x-echo": f"{KEY} {BEARER} {TLS}"})

    transport = httpx.AsyncClient(
        base_url="https://api.ui.com", transport=httpx.MockTransport(handler)
    )
    monkeypatch.setattr(client, "_get_client", AsyncMock(return_value=transport))
    try:
        with secret_scope((CALLER,)), caplog.at_level(logging.WARNING):
            if status >= 300 and raise_on_error:
                with pytest.raises(UniFiConnectionError) as raised:
                    await client.request(
                        "POST",
                        PATH,
                        key=APIKeyConfig(key=KEY),
                        json={"setup_code": CALLER},
                        raise_on_error=True,
                    )
                output = str(raised.value)
            else:
                response = await client.request(
                    "POST",
                    PATH,
                    key=APIKeyConfig(key=KEY),
                    json={"setup_code": CALLER},
                    raise_on_error=raise_on_error,
                )
                output = response.text
                assert KEY not in str(response.headers)
                assert BEARER not in str(response.headers)
                assert TLS not in str(response.headers)
            logging.getLogger("unifi_fabric.auth01").warning("result %s", output)
        for value in (KEY, BEARER, TLS, CONFIGURED):
            assert value not in output
        assert "denied" in output
        assert (CALLER in output) is (not redact)
        assert (UPSTREAM in output) is (not redact)
        for value in (CALLER, UPSTREAM, KEY, BEARER, TLS, CONFIGURED):
            assert value not in caplog.text
        assert "***" in caplog.text
    finally:
        await transport.aclose()
        await client.close()


@pytest.mark.parametrize("redact", [False, True])
async def test_auth01_outer_tool_error_scope(monkeypatch, caplog, redact):
    monkeypatch.setattr(server, "_settings", Settings(api_key=CONFIGURED, redact_secrets=redact))
    monkeypatch.setenv("MCP_BEARER_TOKEN", BEARER)
    context = SimpleNamespace(
        message=SimpleNamespace(name="unknown_tool", arguments={"password": CALLER})
    )

    async def fail(_):
        logging.getLogger("unifi_fabric.auth01").warning(
            "denied %s %s %s", CALLER, CONFIGURED, BEARER
        )
        raise ValueError(f"denied {CALLER} {CONFIGURED} {BEARER}")

    with caplog.at_level(logging.WARNING), pytest.raises(Exception) as raised:
        await server.SecretScrubMiddleware().on_call_tool(context, fail)
    output = str(raised.value)
    assert (CALLER in output) is (not redact)
    assert CONFIGURED not in output and BEARER not in output
    assert "denied" in output
    assert CALLER not in caplog.text


@pytest.mark.parametrize("redact", [False, True])
def test_auth01_classic_error_scope(redact):
    client = UniFiClient(Settings(api_key=CONFIGURED, redact_secrets=redact))
    with secret_scope((CALLER,)), pytest.raises(UniFiConnectionError) as raised:
        checked_classic_response(
            {"meta": {"rc": "error", "msg": f"denied {CALLER} {KEY} {CONFIGURED}"}},
            "/classic",
            client=client,
            key=APIKeyConfig(key=KEY),
        )
    output = str(raised.value)
    assert (CALLER in output) is (not redact)
    assert KEY not in output and CONFIGURED not in output
    assert "denied" in output
