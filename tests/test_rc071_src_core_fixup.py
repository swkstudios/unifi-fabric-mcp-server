"""Regression coverage for source-core review corrections."""

import ast
from pathlib import Path

import pytest

from unifi_fabric import _spec_drift, families


def test_vpn_resource_lists_share_family():
    index = families.build_family_index()
    assert {index[name] for name in ("list_vpn_servers", "list_vpn_clients", "list_vpn_users")} == {
        "vpn"
    }


def test_spec_index_accepts_only_official_https_origin():
    legitimate = "[spec](https://developer.ui.com/network/v1.2.3/openapi.json)"
    assert _spec_drift.parse_root_index(legitimate)["network"][0] == "1.2.3"
    for url in (
        "http://developer.ui.com/network/v1.2.3/openapi.json",
        "https://developer.ui.com.evil.example/network/v1.2.3/openapi.json",
        "https://evil.example/network/v1.2.3/openapi.json",
    ):
        with pytest.raises(ValueError):
            _spec_drift.parse_root_index(f"[spec]({url})")


def test_registered_wrapper_only_imported_by_generated_adapters():
    root = Path(__file__).resolve().parents[1] / "src" / "unifi_fabric"
    for path in root.rglob("*.py"):
        if "_generated/adapters" in path.as_posix():
            continue
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ImportFrom)
                and node.module
                and node.module.endswith("_adapter_runtime")
            ):
                assert all(alias.name != "registered_wrapper" for alias in node.names), path


@pytest.mark.parametrize("dispatcher", ["call_read_tool", "call_write_tool", "execute"])
def test_nested_audit_records_dispatch_provenance(tmp_path, dispatcher):
    import json

    from unifi_fabric.audit import AuditStream, FileSink, audit_call

    path = tmp_path / "audit.jsonl"
    stream = AuditStream(sink=FileSink(str(path)), secrets=())
    with audit_call(dispatcher):
        with audit_call("update_network"):
            stream.record(method="PUT", path="/synthetic", outcome="ok", status=200)
    with audit_call("update_network"):
        stream.record(method="PUT", path="/synthetic", outcome="ok", status=200)
    nested, direct = [json.loads(line) for line in path.read_text().splitlines()]
    assert nested["tool"] == "update_network"
    assert nested["via"] == dispatcher
    assert "via" not in direct


async def test_codemode_filters_request_visibility_before_limit(monkeypatch):
    from fastmcp import Client, FastMCP

    from unifi_fabric.discovery import apply_tool_mode
    from unifi_fabric.tool_annotations import for_tool

    app = FastMCP("visibility-before-limit")

    @app.tool(annotations=for_tool(writes=False))
    def list_alpha():
        """List synthetic alpha resources."""
        return []

    @app.tool(annotations=for_tool(writes=False))
    def list_beta():
        """List synthetic beta resources."""
        return []

    monkeypatch.setattr(
        "unifi_fabric.request_policy.visible_to_request", lambda name: name != "list_alpha"
    )
    restore = await apply_tool_mode(app, "codemode", audit_hmac_key=bytes(range(32)))
    try:
        async with Client(app) as client:
            found = (await client.call_tool("search_tools", {"query": "", "limit": 1})).data
            assert [row["name"] for row in found] == ["list_beta"]
    finally:
        restore()


@pytest.mark.parametrize(
    "dispatcher,target",
    [
        ("call_read_tool", "list_hosts"),
        ("call_write_tool", "create_network"),
        ("execute", "list_hosts"),
    ],
)
async def test_production_middleware_dispatch_audit(tmp_path, monkeypatch, dispatcher, target):
    import json

    from fastmcp import Client, FastMCP

    from tests import upstream_harness as uh
    from unifi_fabric import server
    from unifi_fabric.discovery import DiscoveryMiddleware, apply_tool_mode
    from unifi_fabric.tool_annotations import for_tool

    path = tmp_path / "audit.jsonl"
    client = uh.install(monkeypatch, uh.FakeUpstream(), audit_sink="file", audit_log=str(path))
    app = FastMCP("production-audit")
    app.middleware = list(server.mcp.middleware)

    @app.tool(name=target, annotations=for_tool(writes=dispatcher == "call_write_tool"))
    async def record_target():
        client.audit_stream.record(method="PUT", path="/synthetic", outcome="success", status=200)
        return {"ok": True}

    mode = "codemode" if dispatcher == "execute" else "discovery"
    restore = await apply_tool_mode(
        app,
        mode,
        audit_hmac_key=bytes(range(32)) if mode == "codemode" else None,
    )
    try:
        order = [type(mw) for mw in app.middleware]
        assert order.index(DiscoveryMiddleware) < order.index(server.AuditContextMiddleware)
        async with Client(app) as transport:
            if dispatcher == "execute":
                await transport.call_tool(
                    "execute",
                    {"code": f'result = await call_tool("{target}", {{}})\nprint(result)'},
                )
            else:
                await transport.call_tool(dispatcher, {"name": target, "arguments": {}})
            if dispatcher != "execute":
                await transport.call_tool(target, {})
        records = [json.loads(line) for line in path.read_text().splitlines()]
        audits = [row for row in records if row["event"] == "audit"]
        assert audits[0]["tool"] == target
        assert audits[0]["via"] == dispatcher
        if dispatcher != "execute":
            assert audits[1]["tool"] == target
            assert "via" not in audits[1]
    finally:
        restore()
        await client.close()
