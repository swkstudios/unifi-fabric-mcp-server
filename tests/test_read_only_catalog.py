"""Startup catalog selection and hidden-name refusals use derived annotations."""

import json
from collections import Counter

import httpx
import pytest
from fastmcp import Client, FastMCP

from unifi_fabric import server
from unifi_fabric._read_only_audit import derive_write_tools
from unifi_fabric.api_sources import apply_api_source_filter
from unifi_fabric.config import Settings
from unifi_fabric.discovery import META_TOOLS
from unifi_fabric.families import apply_tool_family_filter, build_family_index
from unifi_fabric.read_only import read_only_message
from unifi_fabric.read_only_tools import ReadOnlyToolMiddleware, apply_read_only_tool_filter
from unifi_fabric.refusal_audit import RefusedWriteAuditMiddleware
from unifi_fabric.tool_annotations import READ_ONLY, WRITE


async def clone_app():
    app = FastMCP("read-only-catalog")
    for tool in await server.mcp.list_tools():
        app.add_tool(tool)
    app.add_middleware(server.SecretScrubMiddleware())
    app.add_middleware(RefusedWriteAuditMiddleware(app, lambda: True, server._audit_refusal))
    app.add_middleware(ReadOnlyToolMiddleware(app, audit=server._audit_refusal))
    return app


@pytest.mark.parametrize("mode", ["full", "discovery"])
@pytest.mark.parametrize("families,disabled", [("", ""), ("firewall", ""), ("", "network/private")])
async def test_startup_read_only_catalog_and_hidden_refusals(
    monkeypatch, tmp_path, mode, families, disabled
):
    audit_file = tmp_path / "audit.jsonl"
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    if families:
        monkeypatch.setenv("UNIFI_FAMILY_ALLOW", families)
    if disabled:
        monkeypatch.setenv("UNIFI_EXCLUDE", f"source:{disabled}")
    monkeypatch.setattr(
        server,
        "_settings",
        Settings(
            api_key="synthetic-key",
            tool_mode=mode,
            audit_log=str(audit_file),
            audit_log_format="json",
        ),
    )

    async def no_upstream(*args, **kwargs):
        raise AssertionError("Read-only catalog/refusal must not contact upstream")

    monkeypatch.setattr(httpx.AsyncClient, "send", no_upstream)
    expected_app = await clone_app()
    unfiltered = {tool.name: tool for tool in await expected_app.list_tools()}
    if families:
        await apply_tool_family_filter(expected_app, families)
    if disabled:
        await apply_api_source_filter(expected_app, disabled)
    selected = {tool.name: tool for tool in await expected_app.list_tools()}
    # list_configured_api_keys is a local tool: no exposure setting hides it.
    selected.setdefault("list_configured_api_keys", unfiltered["list_configured_api_keys"])
    writes = derive_write_tools(list(selected.values()))
    reads = set(selected) - writes
    assert writes and reads
    assert reads == {name for name, tool in selected.items() if tool.annotations.read_only_hint}
    mixed_reads = {"fabric_connector_get"} & selected.keys()
    callable_reads = reads | mixed_reads
    hidden_name = sorted(writes - mixed_reads)[0]
    app = await clone_app()
    async with server.lifespan(app), Client(app) as client:
        listed = await client.list_tools()
        assert {tool.name for tool in listed if not tool.annotations.read_only_hint} == (
            mixed_reads if mode == "full" else set()
        )
        if mode == "full":
            assert {tool.name for tool in listed} == callable_reads
        else:
            assert {tool.name for tool in listed} == META_TOOLS - {"call_write_tool"}
            rows = (await client.call_tool("search_tools", {"query": "", "limit": None})).data
            assert {row["name"] for row in rows} == callable_reads
            assert {row["name"] for row in rows if row["writes"]} == mixed_reads
            matches = (
                await client.call_tool("search_tools", {"query": "update configuration"})
            ).data
            assert matches
            assert {row["name"] for row in matches if row["writes"]} <= mixed_reads
            write_rows = (
                await client.call_tool("search_tools", {"query": "", "writes": True})
            ).data
            assert {row["name"] for row in write_rows} == mixed_reads
            for name in (hidden_name, "call_write_tool"):
                with pytest.raises(Exception, match="UNIFI_WRITE_POLICY") as error:
                    await client.call_tool("describe_tool", {"name": name})
                assert read_only_message(name, tool=True) in str(error.value)
            family_counts = (await client.call_tool("list_tool_families", {})).data
            family_index = build_family_index()
            assert {row["family"]: row["tools"] for row in family_counts} == dict(
                Counter(family_index[name] for name in callable_reads)
            )
            assert sum(row["tools"] for row in family_counts) == len(callable_reads)
            with pytest.raises(Exception, match="UNIFI_WRITE_POLICY"):
                await client.call_tool("call_write_tool", {"name": hidden_name, "arguments": {}})

        with pytest.raises(Exception, match="UNIFI_WRITE_POLICY") as error:
            await client.call_tool(hidden_name, {})
        assert read_only_message(hidden_name, tool=True) in str(error.value)
        assert await app.get_tool(hidden_name) is None
        records = [
            r
            for r in (json.loads(line) for line in audit_file.read_text().splitlines())
            if r.get("event", "audit") == "audit"
        ]
        # A refusal through the discovery dispatcher is audited under the tool it targets,
        # so the call_write_tool refusal and the direct refusal both name the hidden tool.
        assert [(row["tool"], row["outcome"], row["reason"]) for row in records] == (
            [(hidden_name, "refused", "UNIFI_WRITE_POLICY")] if mode == "discovery" else []
        ) + [(hidden_name, "refused", "UNIFI_WRITE_POLICY")]
        if not families and not disabled:
            assert "fabric_connector_get" in mixed_reads
            with pytest.raises(Exception, match="UNIFI_WRITE_POLICY"):
                await client.call_tool(
                    "fabric_connector_get",
                    {
                        "host": "console",
                        "path": "/proxy/protect/api/cameras/camera/enable-control",
                    },
                )


@pytest.mark.parametrize("mode", ["full", "discovery"])
async def test_default_startup_catalog_is_identical(monkeypatch, mode):
    from unifi_fabric.discovery import apply_tool_mode

    monkeypatch.delenv("UNIFI_WRITE_POLICY", raising=False)
    monkeypatch.setattr(server, "_settings", Settings(api_key="synthetic-key", tool_mode=mode))
    baseline = await clone_app()
    restore = await apply_tool_mode(baseline, mode)
    app = await clone_app()
    try:
        async with Client(baseline) as before, server.lifespan(app), Client(app) as after:
            assert [tool.model_dump_json() for tool in await after.list_tools()] == [
                tool.model_dump_json() for tool in await before.list_tools()
            ]
            if mode == "discovery":
                assert (await after.call_tool("search_tools", {"query": ""})).data == (
                    await before.call_tool("search_tools", {"query": ""})
                ).data
    finally:
        restore()


async def test_filter_uses_annotations_for_new_names():
    app = FastMCP("annotation-filter")

    @app.tool(annotations=READ_ONLY)
    def unfamiliar_read() -> str:
        return "read"

    @app.tool(annotations=WRITE)
    def unfamiliar_write() -> str:
        return "write"

    before = [tool.to_mcp_tool().model_dump_json() for tool in await app.list_tools()]
    assert await apply_read_only_tool_filter(app, False) == set()
    assert [tool.to_mcp_tool().model_dump_json() for tool in await app.list_tools()] == before
    assert await apply_read_only_tool_filter(app, True) == {"unfamiliar_write"}
    assert {tool.name for tool in await app.list_tools()} == {"unfamiliar_read"}


@pytest.mark.parametrize("mode", ["full", "discovery"])
@pytest.mark.parametrize("read_only", [False, True])
@pytest.mark.parametrize("connector_enabled", [False, True])
async def test_mixed_get_relay_keeps_reads_under_every_write_policy(
    monkeypatch, mode, read_only, connector_enabled
):
    from unifi_fabric.discovery import apply_tool_mode
    from unifi_fabric.read_only_tools import (
        AreaOptOutMiddleware,
        apply_area_opt_out_tool_filter,
    )

    monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny" if read_only else "allow")
    app = FastMCP("mixed-relay")

    @app.tool(annotations=WRITE)
    async def fabric_connector_get(host: str, path: str) -> dict:
        return {"host": host, "path": path}

    app.add_middleware(ReadOnlyToolMiddleware(app))
    app.add_middleware(AreaOptOutMiddleware(app, lambda: connector_enabled))
    hidden = await apply_read_only_tool_filter(app, read_only)
    area_hidden = await apply_area_opt_out_tool_filter(app, connector_enabled)
    assert "fabric_connector_get" not in hidden | area_hidden.keys()
    restore = await apply_tool_mode(
        app, mode, read_only=read_only, hidden_write_names=hidden, hidden_area_writes=area_hidden
    )
    # The real lifecycle also applies the read-only filter to discovery dispatchers.
    await apply_read_only_tool_filter(app, read_only)
    read_args = {"host": "synthetic-console", "path": "protect/api/bootstrap"}
    try:
        async with Client(app) as client:
            name, args = "fabric_connector_get", read_args
            if mode == "discovery":
                name, args = "call_read_tool", {"name": name, "arguments": args}
            assert (await client.call_tool(name, args)).data == read_args
            action_args = {**read_args, "path": "protect/api/cameras/camera/enable-control"}
            if mode == "discovery":
                with pytest.raises(Exception, match="call_write_tool"):
                    await client.call_tool(
                        "call_read_tool", {"name": "fabric_connector_get", "arguments": action_args}
                    )
            elif read_only or not connector_enabled:
                with pytest.raises(Exception, match="UNIFI_WRITE_POLICY|family:connector=deny"):
                    await client.call_tool("fabric_connector_get", action_args)
            else:
                assert (
                    await client.call_tool("fabric_connector_get", action_args)
                ).data == action_args
    finally:
        restore()
