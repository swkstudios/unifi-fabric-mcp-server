"""Actionable argument errors (``unifi_fabric.argument_errors``).

Covers the three contracts of the middleware:

1. an argument-parsing failure (missing / unknown / wrongly-typed argument) becomes a
   ToolError naming the parameter, where its value comes from, the valid parameters and
   an example call — without echoing any input value;
2. a pydantic ValidationError raised *inside* a tool body passes through unmodified;
3. any other exception raised inside a tool (including an upstream error carrying the
   controller's response body) passes through unmodified.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

import pytest
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from pydantic import BaseModel

from unifi_fabric import server
from unifi_fabric.argument_errors import ArgumentErrorMiddleware, argument_validation_error
from unifi_fabric.client import UniFiConnectionError

SECRET = "s3cr3t-value-that-must-not-be-echoed"


class _Strict(BaseModel):
    count: int


def _scratch_server(with_middleware: bool) -> FastMCP:
    mcp = FastMCP("scratch")

    @mcp.tool()
    async def make_widget(host: str, widget_id: str, size: int = 1) -> dict[str, Any]:
        """Make a widget.

        Example call (make_widget):
            {"host": "my-console", "widget_id": "w-1"}

        Args:
            host: Console name. Get it from list_hosts (name or id).
            widget_id: Widget id. Get it from list_widgets (data[].id).
            size: Widget size.
        """
        return {"host": host, "widget_id": widget_id, "size": size}

    @mcp.tool()
    async def no_example(host: str, count: int, label: str | None = None) -> dict[str, Any]:
        """A tool whose description carries no worked example.

        Args:
            host: Console name.
            count: How many.
            label: Optional label.
        """
        return {}

    @mcp.tool()
    async def body_pydantic_error(value: str) -> dict[str, Any]:
        """Raise a pydantic ValidationError from inside the body.

        Args:
            value: Any string.
        """
        _Strict(count=value)  # type: ignore[arg-type]
        return {}

    @mcp.tool()
    async def body_upstream_error(value: str) -> dict[str, Any]:
        """Raise an upstream HTTP error carrying a controller response body.

        Args:
            value: Any string.
        """
        raise UniFiConnectionError(
            'HTTP 400 from PUT /v1/x: {"code":"api.request.invalid","message":"bad body"}'
        )

    @mcp.tool()
    async def body_value_error(value: str) -> dict[str, Any]:
        """Raise a ValueError from a local check inside the body.

        Args:
            value: Any string.
        """
        raise ValueError("create_x: missing required field(s): name")

    if with_middleware:
        mcp.add_middleware(ArgumentErrorMiddleware(mcp))
    return mcp


async def _call_text(mcp: FastMCP, name: str, args: dict[str, Any]) -> str:
    try:
        await mcp.call_tool(name, args)
    except Exception as exc:  # noqa: BLE001 - the error text is what is under test
        return f"{type(exc).__name__}: {exc}"
    return "OK"


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


class TestArgumentErrors:
    def test_missing_argument_names_param_source_and_example(self) -> None:
        text = _run(_call_text(_scratch_server(True), "make_widget", {"host": SECRET}))
        assert text.startswith("ToolError: Invalid arguments for tool 'make_widget':")
        assert "- widget_id: missing required argument." in text
        assert "Get it from list_widgets (data[].id)." in text
        assert "Valid parameters: host (required), widget_id (required), size." in text
        assert 'Example call: {"host": "my-console", "widget_id": "w-1"}' in text
        assert SECRET not in text
        assert "input_value" not in text

    def test_unknown_argument_is_named_with_valid_list(self) -> None:
        args = {"host": "h", "widget_id": "w", "colour": SECRET}
        text = _run(_call_text(_scratch_server(True), "make_widget", args))
        assert "- colour: not a parameter of this tool." in text
        assert "Valid parameters:" in text
        assert SECRET not in text

    def test_wrong_type_is_named_without_echoing_input(self) -> None:
        args = {"host": "h", "widget_id": "w", "size": SECRET}
        text = _run(_call_text(_scratch_server(True), "make_widget", args))
        assert "- size: invalid value" in text
        assert "(expected integer)" in text
        assert SECRET not in text

    def test_valid_call_unchanged(self) -> None:
        mcp = _scratch_server(True)
        result = _run(mcp.call_tool("make_widget", {"host": "h", "widget_id": "w"}))
        assert result.structured_content == {"host": "h", "widget_id": "w", "size": 1}

    def test_body_pydantic_error_passes_through_unmodified(self) -> None:
        with_mw = _run(_call_text(_scratch_server(True), "body_pydantic_error", {"value": "x"}))
        without = _run(_call_text(_scratch_server(False), "body_pydantic_error", {"value": "x"}))
        assert with_mw == without
        assert "Invalid arguments for tool" not in with_mw

    def test_body_upstream_error_passes_through_unmodified(self) -> None:
        with_mw = _run(_call_text(_scratch_server(True), "body_upstream_error", {"value": "x"}))
        without = _run(_call_text(_scratch_server(False), "body_upstream_error", {"value": "x"}))
        assert with_mw == without
        assert '{"code":"api.request.invalid","message":"bad body"}' in with_mw

    def test_body_value_error_passes_through_unmodified(self) -> None:
        with_mw = _run(_call_text(_scratch_server(True), "body_value_error", {"value": "x"}))
        without = _run(_call_text(_scratch_server(False), "body_value_error", {"value": "x"}))
        assert with_mw == without
        assert "missing required field(s): name" in with_mw

    def test_call_shape_has_no_angle_bracket_placeholders(self) -> None:
        text = _run(_call_text(_scratch_server(True), "no_example", {}))
        assert 'Call shape (required arguments): {"host": "STRING", "count": "INTEGER"}' in text
        assert _TAG_LIKE.search(text) is None

    def test_non_validation_exception_is_not_classified(self) -> None:
        assert argument_validation_error(ValueError("x")) is None
        assert argument_validation_error(ToolError("x")) is None

    def test_bare_pydantic_error_is_not_classified(self) -> None:
        # FastMCP wraps argument-parsing failures in its own ValidationError; a bare
        # pydantic error can only come from tool code and must pass through.
        try:
            _Strict(count="not-an-int")  # type: ignore[arg-type]
        except Exception as exc:  # noqa: BLE001 - the error object is under test
            assert argument_validation_error(exc) is None
        else:  # pragma: no cover
            raise AssertionError("expected a pydantic ValidationError")


# Same tag-like pattern the description contract test uses: ``<`` followed by a
# letter, ``/``, ``!`` or ``?``. Runtime error text must not contain it either.
_TAG_LIKE = re.compile(r"<\s*[A-Za-z/!?]")


class TestRegisteredOnServer:
    def test_server_has_the_middleware(self) -> None:
        assert any(isinstance(m, ArgumentErrorMiddleware) for m in server.mcp.middleware)

    @pytest.mark.parametrize(
        ("tool", "args", "expect"),
        [
            (
                "set_firewall_policy_ordering",
                {"host": "h", "site": "s", "ordering": {"orderedFirewallPolicyIds": {}}},
                "- source_zone_id: missing required argument.",
            ),
            (
                "get_firewall_policy",
                {"host": "h", "site": "s"},
                "Get it from list_firewall_policies",
            ),
        ],
    )
    def test_real_tool_missing_argument(self, tool: str, args: dict[str, Any], expect: str) -> None:
        text = _run(_call_text(server.mcp, tool, args))
        assert text.startswith(f"ToolError: Invalid arguments for tool '{tool}':")
        assert expect in text
        assert "Example call: {" in text

    def test_no_argument_error_contains_markup(self) -> None:
        """Every real tool's argument error (empty call) is free of angle-bracket markup."""

        async def _all() -> list[str]:
            bad: list[str] = []
            tools = await server.mcp.list_tools()
            assert len(tools) == len(server.mcp._local_provider._components)
            for tool in tools:
                text = await _call_text(server.mcp, tool.name, {"__not_a_param__": 1})
                assert text.startswith("ToolError: Invalid arguments"), (tool.name, text)
                if _TAG_LIKE.search(text):
                    bad.append(f"{tool.name}: {text}")
            return bad

        assert _run(_all()) == []
