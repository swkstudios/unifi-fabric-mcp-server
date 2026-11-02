"""The InnerSpace project fetch never loses the documented path's rejection.

The project tools try the documented integration path first and fall back to the legacy
``/api/project`` only on a namespace-style rejection (403 / host not found). When that
fallback then fails differently (a console without the legacy route answers 404), the
raised error carries BOTH upstream errors, the integration path's reason intact.
"""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from unifi_fabric import server
from unifi_fabric.client import UniFiClient, UniFiConnectionError, UniFiHTTPError
from unifi_fabric.config import Settings
from unifi_fabric.registry import Registry
from unifi_fabric.tools import innerspace

H = "host-is-001"
IS = f"https://api.ui.com/v1/connector/consoles/{H}/proxy/innerspace"
FIRST = "API key lacks the InnerSpace scope 51c2"
SECOND = "legacy route absent 9d07"
PROJECT_TOOLS = ["get_innerspace_project", "get_innerspace_summary", "list_innerspace_devices"]


@pytest.fixture()
def tools(monkeypatch):
    settings = Settings(api_key="sk-innerspace-fallback")
    client = UniFiClient(settings)
    monkeypatch.setattr(server, "_settings", settings)
    monkeypatch.setattr(server, "_client", client)
    monkeypatch.setattr(server, "_registry", Registry(client, ttl_seconds=60))


def _hosts(router: respx.Router) -> None:
    router.get("https://api.ui.com/v1/hosts").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"id": H, "type": "console", "reportedState": {"hostname": "c1"}}]},
        )
    )


@pytest.mark.parametrize("tool", PROJECT_TOOLS)
@pytest.mark.parametrize("second_status", [404, 500])
async def test_fallback_failure_carries_both_upstream_errors(tools, tool, second_status):
    with respx.mock(assert_all_called=False) as router:
        _hosts(router)
        router.get(f"{IS}/integration/v1/project").mock(
            return_value=httpx.Response(
                403, json={"code": "forbidden", "message": "host not found: " + FIRST}
            )
        )
        router.get(f"{IS}/api/project").mock(
            return_value=httpx.Response(second_status, json={"message": SECOND})
        )
        with pytest.raises(ToolError) as info:
            await server.mcp.call_tool(tool, {"host": H})
    message = str(info.value)
    assert message.startswith(
        f"Error calling tool '{tool}': HTTP {second_status} from GET "
        f"/v1/connector/consoles/{H}/proxy/innerspace/api/project:"
    )
    assert SECOND in message and str(second_status) in message
    assert message.count(FIRST) == 1
    assert message.count("This was the legacy fallback.") == 1
    assert "/integration/v1/project" in message


@pytest.mark.parametrize("tool", PROJECT_TOOLS)
@pytest.mark.parametrize("status", [403, 404])
async def test_permission_or_route_error_is_raised_without_fallback(tools, tool, status):
    with respx.mock(assert_all_called=False) as router:
        _hosts(router)
        router.get(f"{IS}/integration/v1/project").mock(
            return_value=httpx.Response(status, json={"message": FIRST})
        )
        legacy = router.get(f"{IS}/api/project").mock(return_value=httpx.Response(200, json={}))
        with pytest.raises(ToolError, match=FIRST):
            await server.mcp.call_tool(tool, {"host": H})
    assert legacy.call_count == 0


@pytest.mark.parametrize("tool", PROJECT_TOOLS)
async def test_fallback_notes_are_rendered_and_scrubbed(tools, monkeypatch, tool):
    error = UniFiConnectionError("HTTP 500 from GET /synthetic-legacy: synthetic failure")
    error.add_note("First HTTP 403 rejection: sk-innerspace-fallback scope missing")

    async def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(innerspace, "_fetch_project_document", fail)
    with respx.mock(assert_all_called=False) as router:
        _hosts(router)
        with pytest.raises(ToolError) as info:
            await server.mcp.call_tool(tool, {"host": H})
    message = str(info.value)
    assert message.startswith(f"Error calling tool '{tool}': {error}")
    assert message.count("First HTTP 403 rejection:") == 1
    assert "scope missing" in message
    assert "sk-innerspace-fallback" not in message
    assert str(error) == "HTTP 500 from GET /synthetic-legacy: synthetic failure"


@pytest.mark.parametrize("tool", PROJECT_TOOLS)
async def test_http_error_notes_render_once_through_middleware(tools, monkeypatch, tool):
    error = UniFiHTTPError("HTTP 500 from GET /synthetic-legacy: synthetic failure", status=500)
    error.add_note("First HTTP 403 rejection: synthetic context 7e21")

    async def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(innerspace, "_fetch_project_document", fail)
    with respx.mock(assert_all_called=False) as router:
        _hosts(router)
        with pytest.raises(ToolError) as info:
            await server.mcp.call_tool(tool, {"host": H})
    message = str(info.value)
    assert message.startswith(f"Error calling tool '{tool}': {error}")
    assert message.count("First HTTP 403 rejection: synthetic context 7e21") == 1


async def test_scrubber_preserves_wrapper_and_deduplicates_cause_notes():
    cause = ValueError("underlying failure")
    cause.add_note("shared context")
    cause.add_note("inner context")
    wrapper = ToolError("outer wrapper context")
    wrapper.add_note("shared context")
    wrapper.add_note("outer context")
    wrapper.__cause__ = cause

    async def fail(context):
        raise wrapper

    with pytest.raises(ToolError) as caught:
        context = SimpleNamespace(message=SimpleNamespace(arguments={}, name=None))
        await server.SecretScrubMiddleware().on_call_tool(context, fail)
    message = str(caught.value)
    assert message.startswith("outer wrapper context")
    assert message.count("shared context") == 1
    assert "inner context" in message and "outer context" in message
    assert caught.value.__cause__ is None
