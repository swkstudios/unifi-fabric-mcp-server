"""HTTP errors retain their actionable status without server tracebacks."""

import logging

import httpx
import pytest
import respx
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError

from unifi_fabric.client import RateLimitError, UniFiClient, UniFiConnectionError
from unifi_fabric.config import Settings


@pytest.mark.parametrize("status", [401, 403, 404, 429, 500])
@respx.mock
async def test_http_errors_are_tool_errors_without_tracebacks(status, caplog):
    caplog.set_level(logging.ERROR)
    upstream = UniFiClient(Settings(api_key="synthetic-test"))
    respx.post("https://api.ui.com/test").mock(
        return_value=httpx.Response(status, text="synthetic upstream reason")
    )
    app = FastMCP("http-errors")

    @app.tool()
    async def example() -> str:
        expected = RateLimitError if status == 429 else UniFiConnectionError
        with pytest.raises(expected) as caught:
            await upstream.post("/test", json={})
        exc = caught.value
        assert isinstance(exc, ToolError)
        assert exc.status == status
        raise exc

    try:
        async with Client(app) as client:
            with pytest.raises(ToolError) as caught:
                await client.call_tool("example", {})
        assert str(status) in str(caught.value)
        assert "synthetic upstream reason" in str(caught.value)
        if status in (401, 403):
            assert "UNIFI_API_KEY" in str(caught.value)
        assert not any(record.exc_info for record in caplog.records)
    finally:
        await upstream.close()
