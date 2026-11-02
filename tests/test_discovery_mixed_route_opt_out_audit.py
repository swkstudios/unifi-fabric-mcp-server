"""The mixed GET relay on a state-changing route under a write opt-out is audited.

With UNIFI_READ_ONLY off and a write opt-out set (the route's area switch, or
UNIFI_ENABLE_CONNECTOR_WRITE), ``call_read_tool(name="fabric_connector_get")`` on a
state-changing route is refused with the call_write_tool redirect. Before the fix that
refusal wrote no audit record, while the same call made directly is audited with the
opt-out that refuses it. Now each writes exactly one ``outcome=refused`` record naming the
same switch. A read route and a path that fails validation write none. No request reaches
the upstream.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastmcp import Client, FastMCP

from unifi_fabric import server
from unifi_fabric.config import Settings
from unifi_fabric.read_only_tools import AreaOptOutMiddleware, ReadOnlyToolMiddleware
from unifi_fabric.refusal_audit import RefusedWriteAuditMiddleware
from unifi_fabric.tools import connector

#: A state-changing route of the mixed GET relay in the Protect area.
WRITE_GET = "/proxy/protect/api/cameras/camera/enable-control"
REDIRECT = "Use call_write_tool(name='fabric_connector_get'"


async def _app() -> FastMCP:
    app = FastMCP("discovery-mixed-route-opt-out-audit")
    for tool in await server.mcp.list_tools():
        app.add_tool(tool)
    app.add_middleware(server.SecretScrubMiddleware())
    app.add_middleware(RefusedWriteAuditMiddleware(app, lambda: True, server._audit_refusal))
    app.add_middleware(ReadOnlyToolMiddleware(app, audit=server._audit_refusal))
    app.add_middleware(
        AreaOptOutMiddleware(
            app, lambda: server.get_settings().enable_connector_write, audit=server._audit_refusal
        )
    )
    return app


@pytest.fixture(
    params=[
        "UNIFI_PROTECT_MUTATIONS_ENABLED",
        "UNIFI_ENABLE_NETWORK_WRITE",
        "UNIFI_ENABLE_CONNECTOR_WRITE",
    ]
)
def opted_out(request, monkeypatch, tmp_path) -> tuple[str, Path]:
    env = request.param
    path = tmp_path / "audit.jsonl"
    monkeypatch.delenv("UNIFI_READ_ONLY", raising=False)
    monkeypatch.setenv(env, "0")
    monkeypatch.setattr(
        server,
        "_settings",
        Settings(
            api_key="synthetic-key",
            tool_mode="discovery",
            enable_connector_write=env != "UNIFI_ENABLE_CONNECTOR_WRITE",
            audit_log=str(path),
            audit_log_format="json",
        ),
    )

    async def no_upstream(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("an opt-out refusal must not contact upstream")

    monkeypatch.setattr(httpx.AsyncClient, "send", no_upstream)
    return env, path


def _records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


async def test_mixed_route_through_call_read_tool_and_direct_each_audit_once(opted_out):
    env, audit_file = opted_out
    args = {"host": "console", "path": WRITE_GET}
    app = await _app()
    async with server.lifespan(app), Client(app) as client:
        with pytest.raises(Exception, match="call_write_tool") as error:
            await client.call_tool(
                "call_read_tool", {"name": "fabric_connector_get", "arguments": args}
            )
        assert REDIRECT in str(error.value)
        discovery = _records(audit_file)
        assert len(discovery) == 1
        assert discovery[0]["outcome"] == "refused"
        assert discovery[0]["reason"] == env

        with pytest.raises(Exception, match=env):
            await client.call_tool("fabric_connector_get", args)
        direct = _records(audit_file)[1:]
        assert len(direct) == 1
        assert direct[0]["outcome"] == "refused"
        assert direct[0]["reason"] == env


@pytest.mark.parametrize("path", ["/proxy/protect/api/../cameras/camera/enable-control", ""])
async def test_mixed_route_that_fails_validation_writes_no_record(opted_out, path):
    _env, audit_file = opted_out
    app = await _app()
    async with server.lifespan(app), Client(app) as client:
        with pytest.raises(Exception):  # noqa: B017 - the refusal text is not under test
            await client.call_tool(
                "call_read_tool",
                {"name": "fabric_connector_get", "arguments": {"host": "console", "path": path}},
            )
    assert _records(audit_file) == []


@pytest.mark.parametrize(
    ("env", "path", "expected"),
    [
        (None, WRITE_GET, None),
        ("UNIFI_PROTECT_MUTATIONS_ENABLED", WRITE_GET, "UNIFI_PROTECT_MUTATIONS_ENABLED"),
        ("UNIFI_PROTECT_MUTATIONS_ENABLED", "/proxy/protect/api/cameras", None),
        # The route class is unclassified, which every active area opt-out refuses
        # (_check_unclassified_mutation) and the relay audits with that variable.
        ("UNIFI_ENABLE_NETWORK_WRITE", WRITE_GET, "UNIFI_ENABLE_NETWORK_WRITE"),
        ("UNIFI_ENABLE_CONNECTOR_WRITE", WRITE_GET, "UNIFI_ENABLE_CONNECTOR_WRITE"),
        ("UNIFI_ENABLE_CONNECTOR_WRITE", "/proxy/protect/api/../x/enable-control", None),
        ("UNIFI_ENABLE_CONNECTOR_WRITE", 5, None),
    ],
)
def test_relay_get_opt_out_env_follows_the_relay_order(monkeypatch, env, path, expected):
    for name in (
        "UNIFI_PROTECT_MUTATIONS_ENABLED",
        "UNIFI_ENABLE_NETWORK_WRITE",
        "UNIFI_ENABLE_CONNECTOR_WRITE",
    ):
        monkeypatch.delenv(name, raising=False)
    if env is not None:
        monkeypatch.setenv(env, "0")
    assert connector.relay_get_opt_out_env(path, None) == expected
