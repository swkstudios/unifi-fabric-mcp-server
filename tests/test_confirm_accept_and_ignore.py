"""No-gates: the device and client action tools act immediately.

Covers the formerly confirm-gated tools plus forget_device, which accepts ``confirm`` the
same way.

All confirm gates have been removed. The ``confirm`` argument is accepted for backward
compatibility but ignored — the underlying handler is invoked whether ``confirm`` is
omitted, False, or True. These tests assert the action runs in both cases and that no
``not_executed`` refusal is ever returned.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from fastmcp import FastMCP
from pydantic import SecretStr

from tests import test_cross_tool_invariants as cti
from tests import tool_args, upstream_harness
from tests._tool_classes import tool_batches
from unifi_fabric import server
from unifi_fabric.tools import clients, device_mgmt, matter

_VERBS = ("get", "post", "put", "patch", "delete", "request")


def _mock_client() -> MagicMock:
    client = MagicMock()
    for verb in _VERBS:
        setattr(client, verb, AsyncMock())
    return client


# name, module, impl_attr, positional args
REGISTER_CASES = [
    (
        "commission_matter_node",
        matter,
        "_commission_matter_node",
        ("h", "s", SecretStr("34970112332")),
    ),
    (
        "rename_matter_node",
        matter,
        "_rename_matter_node",
        ("h", "s", "999999999999999999", "probe-name"),
    ),
    ("remove_matter_node", matter, "_remove_matter_node", ("h", "s", "999999999999999999")),
    ("adopt_device", device_mgmt, "_adopt_device", ("h", "s", {"mac": "aa:bb:cc:dd:ee:ff"})),
    ("unadopt_device", device_mgmt, "_unadopt_device", ("h", "s", "dev-uuid")),
    (
        "execute_device_action",
        device_mgmt,
        "_execute_device_action",
        ("h", "s", "dev-uuid", {"action": "restart"}),
    ),
    (
        "execute_port_action",
        device_mgmt,
        "_execute_port_action",
        ("h", "s", "dev-uuid", 1, {"action": "power-cycle"}),
    ),
    ("restart_device", device_mgmt, "_restart_device", ("h", "s", "dev-uuid")),
    ("locate_device", device_mgmt, "_locate_device", ("h", "s", "dev-uuid")),
    ("upgrade_device", device_mgmt, "_upgrade_device", ("h", "s", "dev-uuid")),
    (
        "approve_pending_device",
        device_mgmt,
        "_approve_pending_device",
        ("h", "s", "aa:bb:cc:dd:ee:ff", False),
    ),
    ("forget_device", device_mgmt, "_forget_device", ("h", "s", "aa:bb:cc:dd:ee:ff")),
    (
        "execute_client_action",
        clients,
        "_execute_client_action",
        ("h", "s", "cli-uuid", {"action": "block"}),
    ),
]


async def _register_tool(module, name, deps):
    mcp = FastMCP("test")
    module.register(mcp, deps)
    return await mcp.get_tool(name)


def _assert_ran(name, result, sentinel):
    if name == "unadopt_device":
        # wrapper returns a deletion result carrying the upstream response verbatim
        assert result == {
            "deleted": True,
            "message": "Device dev-uuid unadopted.",
            "response": sentinel,
        }
    else:
        assert result == sentinel
    assert not (isinstance(result, dict) and result.get("status") == "not_executed")


@pytest.mark.parametrize("name,module,impl,args", REGISTER_CASES)
async def test_action_runs_without_confirm(monkeypatch, name, module, impl, args):
    """confirm omitted (default) -> the underlying handler is invoked exactly once."""
    sentinel = {"handler": name}
    impl_mock = AsyncMock(return_value=sentinel)
    monkeypatch.setattr(module, impl, impl_mock)
    tool = await _register_tool(module, name, lambda: (_mock_client(), MagicMock()))

    result = await tool.fn(*args)

    impl_mock.assert_awaited_once()
    _assert_ran(name, result, sentinel)


@pytest.mark.parametrize("name,module,impl,args", REGISTER_CASES)
async def test_action_runs_with_confirm(monkeypatch, name, module, impl, args):
    """confirm=True (legacy caller) -> the handler is still invoked exactly once."""
    sentinel = {"handler": name}
    impl_mock = AsyncMock(return_value=sentinel)
    monkeypatch.setattr(module, impl, impl_mock)
    tool = await _register_tool(module, name, lambda: (_mock_client(), MagicMock()))

    result = await tool.fn(*args, confirm=True)

    impl_mock.assert_awaited_once()
    _assert_ran(name, result, sentinel)


async def test_bulk_delete_runs_without_confirm(monkeypatch):
    """bulk_delete_hotspot_vouchers runs with no confirm and returns the success summary."""
    impl_mock = AsyncMock()
    monkeypatch.setattr(server, "_client", MagicMock())
    monkeypatch.setattr(server, "_registry", MagicMock())
    monkeypatch.setattr(server.network_services_proxy, "bulk_delete_hotspot_vouchers", impl_mock)

    result = await server.bulk_delete_hotspot_vouchers("h", "s", {"k": "v"})

    impl_mock.assert_awaited_once()
    assert result == {
        "deleted": True,
        "message": "Hotspot vouchers deleted.",
        "response": impl_mock.return_value,
    }


async def test_bulk_delete_runs_with_confirm(monkeypatch):
    """bulk_delete_hotspot_vouchers runs identically when a legacy caller passes confirm."""
    impl_mock = AsyncMock()
    monkeypatch.setattr(server, "_client", MagicMock())
    monkeypatch.setattr(server, "_registry", MagicMock())
    monkeypatch.setattr(server.network_services_proxy, "bulk_delete_hotspot_vouchers", impl_mock)

    result = await server.bulk_delete_hotspot_vouchers("h", "s", {"k": "v"}, confirm=True)

    impl_mock.assert_awaited_once()
    assert result == {
        "deleted": True,
        "message": "Hotspot vouchers deleted.",
        "response": impl_mock.return_value,
    }


# Every write wrapper follows the compatibility contract, including wrappers whose
# advertised schema deliberately omits the ignored argument.


@tool_batches("name", lambda: cti._lz_WRITE_TOOLS())
async def test_every_write_accepts_and_ignores_confirm(monkeypatch, name):
    tool = cti._lz_TOOLS()[name]
    arguments = tool_args.generated_args(tool)
    arguments.pop("confirm", None)
    if name == "fabric_connector_get":
        # The write sweep must reach the mixed relay's mutating route.
        arguments["path"] = f"protect/api/cameras/{upstream_harness.ARG_ID}/enable-control"
    results = []
    requests = []
    for extra in ({}, {"confirm": True}, {"confirm": False}):
        upstream = upstream_harness.FakeUpstream()
        with monkeypatch.context() as scoped:
            result = await cti._call(scoped, name, upstream, args={**arguments, **extra})
            results.append(upstream_harness.result_payload(result))
            requests.append(upstream.served)
            assert upstream.writes(), f"{name}: no mocked write reached upstream"
    assert results[0] == results[1] == results[2], name
    assert requests[0] == requests[1] == requests[2], name


async def test_confirm_compat_preserves_caller_arguments_and_nested_body():
    from fastmcp.server.middleware import MiddlewareContext
    from mcp.types import CallToolRequestParams

    from unifi_fabric.confirm_compat import ConfirmIgnoredMiddleware

    arguments = {"confirm": False, "body": {"confirm": True}, "other": 7}
    message = CallToolRequestParams(name="write_example", arguments=arguments)
    context = MiddlewareContext(message=message)
    call_next = AsyncMock(return_value={"upstream": "verbatim"})

    result = await ConfirmIgnoredMiddleware().on_call_tool(context, call_next)

    assert result == {"upstream": "verbatim"}
    forwarded = call_next.call_args.args[0].message
    assert forwarded.arguments == {"body": {"confirm": True}, "other": 7}
    assert message.arguments == arguments
    assert "confirm" in message.arguments


async def test_confirm_compat_leaves_absent_arguments_unchanged():
    from fastmcp.server.middleware import MiddlewareContext
    from mcp.types import CallToolRequestParams

    from unifi_fabric.confirm_compat import ConfirmIgnoredMiddleware

    context = MiddlewareContext(message=CallToolRequestParams(name="write_example"))
    call_next = AsyncMock()
    await ConfirmIgnoredMiddleware().on_call_tool(context, call_next)
    assert call_next.call_args.args[0] is context
