import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from unifi_fabric.client import PaginationAbortedError, UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.entrypoint import _unknown_command_message
from unifi_fabric.read_only import is_write_request
from unifi_fabric.secret_scrub import install_log_scrubber
from unifi_fabric.transport_security import WriteScopeMiddleware


def test_case_variant_state_changing_get():
    assert is_write_request("GET", "protect/api/cameras/abc/Enable-Control")


def test_unknown_command_hides_value():
    assert "sensitive-value" not in _unknown_command_message("sensitive-value")


@pytest.mark.asyncio
async def test_httpx_info_does_not_expose_query(caplog):
    install_log_scrubber()
    with caplog.at_level(logging.INFO):
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request: httpx.Response(200))
        ) as client:
            await client.get("https://example.test/path", params={"token": "query-value"})
    assert "HTTP Request: GET https://example.test/path" in caplog.text
    assert "query-value" not in caplog.text
    assert "?" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["scope", "read_only", "area", "empty_update"])
async def test_lookup_exception_does_not_forward_tool_call(kind, monkeypatch):
    server = SimpleNamespace(get_tool=AsyncMock(side_effect=RuntimeError("lookup failed")))
    next_call = AsyncMock()
    from unifi_fabric.read_only_tools import AreaOptOutMiddleware, ReadOnlyToolMiddleware
    from unifi_fabric.tools import connector
    from unifi_fabric.write_body import EmptyUpdateMiddleware

    monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    monkeypatch.setattr(connector, "area_write_refusal", lambda family: "area disabled")
    middleware = {
        "scope": lambda: WriteScopeMiddleware(server, lambda: "write"),
        "read_only": lambda: ReadOnlyToolMiddleware(server),
        "area": lambda: AreaOptOutMiddleware(server, lambda: True),
        "empty_update": lambda: EmptyUpdateMiddleware(server),
    }[kind]()
    context = SimpleNamespace(message=SimpleNamespace(name="write_tool", arguments={}))
    with pytest.raises(RuntimeError, match="lookup failed"):
        await middleware.on_call_tool(context, next_call)
    next_call.assert_not_awaited()


@pytest.mark.asyncio
async def test_pagination_error_hides_cursor():
    client = UniFiClient(Settings(api_key="sk-test"))
    client.get = AsyncMock(return_value={"data": [1], "nextToken": "private-cursor"})
    with pytest.raises(PaginationAbortedError) as exc:
        await client.paginate("/items")
    assert "private-cursor" not in str(exc.value)


@pytest.mark.asyncio
async def test_not_found_delegates_to_framework():
    from fastmcp.exceptions import NotFoundError

    server = SimpleNamespace(get_tool=AsyncMock(side_effect=NotFoundError("missing")))
    next_call = AsyncMock(return_value="framework result")
    middleware = WriteScopeMiddleware(server, lambda: "write")
    context = SimpleNamespace(message=SimpleNamespace(name="missing", arguments={}))
    assert await middleware.on_call_tool(context, next_call) == "framework result"
    next_call.assert_awaited_once()
