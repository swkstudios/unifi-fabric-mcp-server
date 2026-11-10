"""Discovery catalog and registered-dispatch contract."""

import pytest
from fastmcp import Client, FastMCP
from pydantic import ValidationError

from unifi_fabric import server
from unifi_fabric.config import Settings


def test_tool_mode_config():
    assert Settings().tool_mode == "discovery"
    assert Settings(tool_mode="discovery").tool_mode == "discovery"
    assert Settings(tool_mode="full").tool_mode == "full"
    assert Settings(tool_mode="").tool_mode == "discovery"
    with pytest.raises(ValidationError, match="discovery.*full|full.*discovery"):
        Settings(tool_mode="typo")


async def clone_app():
    app = FastMCP("discovery-test")
    # The registered tools, before the list middleware: a clone of already dereferenced
    # tools would hide a describe_tool that skips the app's $ref dereferencing.
    for tool in await server.mcp.list_tools(run_middleware=False):
        app.add_tool(tool)
    app.middleware = list(server.mcp.middleware)
    return app


@pytest.mark.asyncio
async def test_describe_all_and_cleanup():
    from unifi_fabric.discovery import apply_tool_mode

    app = await clone_app()
    await apply_tool_mode(app, "full")
    async with Client(app) as client:
        full = {
            t.name: t.model_dump(by_alias=True, exclude_none=True)
            for t in await client.list_tools()
        }
    restore = await apply_tool_mode(app, "discovery")
    try:
        async with Client(app) as client:
            assert {t.name for t in await client.list_tools()} == {
                "search_tools",
                "describe_tool",
                "call_read_tool",
                "call_write_tool",
                "list_tool_families",
            }
            matches = (
                await client.call_tool("search_tools", {"query": "", "limit": len(full)})
            ).structured_content["result"]
            assert {row["name"] for row in matches} == set(full)
            assert len(matches) == len(full)
            for name, tool in full.items():
                result = await client.call_tool("describe_tool", {"name": name})
                assert result.structured_content == tool
    finally:
        restore()
    assert {t.name for t in await app.list_tools()} == set(full)


@pytest.mark.asyncio
async def test_cleanup_releases_index_even_when_framework_retains_tool(monkeypatch):
    import weakref

    from unifi_fabric import discovery

    references = []
    original_index = discovery.SearchIndex

    def tracked_index(*args, **kwargs):
        index = original_index(*args, **kwargs)
        references.append(weakref.ref(index))
        return index

    monkeypatch.setattr(discovery, "SearchIndex", tracked_index)
    app = FastMCP("discovery-lifetime")

    @app.tool()
    def list_items() -> list[str]:
        return ["item"]

    retained_tools = []
    for _ in range(3):
        cleanup = await discovery.apply_tool_mode(app, "discovery")
        tool = await app.get_tool("search_tools")
        assert tool is not None
        retained_tools.append(tool)
        await tool.run({"query": "", "limit": None})
        assert references[-1]() is not None
        cleanup()
        assert references[-1]() is None
        with pytest.raises(Exception, match="Discovery lifecycle has ended"):
            await tool.run({"query": ""})
        assert {tool.name for tool in await app.list_tools()} == {"list_items"}
    assert len(retained_tools) == 3


@pytest.mark.asyncio
async def test_search_no_cap_ranking_and_family_composition():
    from unifi_fabric.discovery import apply_tool_mode
    from unifi_fabric.families import apply_tool_family_filter, build_family_index

    app = await clone_app()
    await apply_tool_family_filter(app, "firewall")
    full = {t.name for t in await app.list_tools()}
    assert full == {n for n, family in build_family_index().items() if family == "firewall"}
    cleanup = await apply_tool_mode(app, "discovery")
    try:
        async with Client(app) as client:
            all_results = (
                await client.call_tool("search_tools", {"query": "", "limit": len(full)})
            ).structured_content["result"]
            assert {r["name"] for r in all_results} == full
            assert all(r["family"] == "firewall" and "\n" not in r["summary"] for r in all_results)
            results = (
                await client.call_tool(
                    "search_tools",
                    {
                        "query": "get_firewall_policy_ordering",
                        "writes": False,
                    },
                )
            ).structured_content["result"]
            assert results[0]["name"] == "get_firewall_policy_ordering"
            assert all(not r["writes"] for r in results)
            families = (await client.call_tool("list_tool_families", {})).structured_content[
                "result"
            ]
            assert families == [{"family": "firewall", "tools": len(full)}]
            for meta in ("describe_tool", "call_read_tool"):
                with pytest.raises(Exception, match="Unknown or unavailable tool"):
                    await client.call_tool(
                        meta,
                        {
                            "name": "list_hosts",
                            **({"arguments": {}} if meta == "call_read_tool" else {}),
                        },
                    )
            with pytest.raises(Exception, match="valid families"):
                await client.call_tool("search_tools", {"query": "", "family": "network"})
    finally:
        cleanup()


@pytest.mark.asyncio
async def test_registered_dispatch_and_result_equivalence(monkeypatch):
    from tests import tool_args
    from tests import upstream_harness as uh
    from unifi_fabric.discovery import apply_tool_mode

    app = await clone_app()
    tool = await app.get_tool("list_hosts")
    up = uh.FakeUpstream()
    uh.install(monkeypatch, up)
    async with Client(app) as client:
        direct = await client.call_tool("list_hosts", tool_args.generated_args(tool))
    cleanup = await apply_tool_mode(app, "discovery")
    try:
        assert await app.get_tool("list_hosts") is tool
        monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
        async with Client(app) as client:
            indirect = await client.call_tool(
                "call_read_tool",
                {"name": "list_hosts", "arguments": tool_args.generated_args(tool)},
            )
            assert indirect.content == direct.content
            assert indirect.structured_content == direct.structured_content
            annotations = {t.name: t.annotations for t in await client.list_tools()}
            assert annotations["call_write_tool"].destructive_hint
            assert annotations["call_read_tool"].read_only_hint
            assert annotations["describe_tool"].read_only_hint
    finally:
        cleanup()


@pytest.mark.asyncio
async def test_dispatch_envelope_errors_are_actionable_and_scrubbed(monkeypatch):
    from unifi_fabric import secret_scrub
    from unifi_fabric.discovery import apply_tool_mode

    original_provider = secret_scrub._provider
    app = await clone_app()
    cleanup = await apply_tool_mode(app, "discovery")
    try:
        async with Client(app) as client:
            for arguments in ({}, {"name": "list_hosts"}, {"name": 123, "arguments": {}}):
                with pytest.raises(Exception, match="Invalid arguments"):
                    await client.call_tool("call_write_tool", arguments)
            monkeypatch.setattr(
                server, "_settings", Settings(api_key="synthetic-configured-secret")
            )
            secret_scrub.set_secret_provider(lambda: ("synthetic-configured-secret",))
            with pytest.raises(Exception) as exc:
                await client.call_tool(
                    "call_read_tool", {"name": "synthetic-configured-secret", "arguments": {}}
                )
            assert "synthetic-configured-secret" not in str(exc.value)
    finally:
        secret_scrub.set_secret_provider(original_provider)
        cleanup()


@pytest.mark.asyncio
async def test_dispatch_preserves_oauth_scope_and_target_audit(monkeypatch):
    from types import SimpleNamespace

    from fastmcp.server import dependencies

    from tests import tool_args
    from tests import upstream_harness as uh
    from unifi_fabric.discovery import apply_tool_mode
    from unifi_fabric.transport_security import WriteScopeMiddleware

    app = await clone_app()
    audits = []
    app.middleware = [mw for mw in app.middleware if not isinstance(mw, WriteScopeMiddleware)]
    app.add_middleware(
        WriteScopeMiddleware(
            app, lambda: "write", audit=lambda name, reason: audits.append((name, reason))
        )
    )
    up = uh.FakeUpstream()
    uh.install(monkeypatch, up)
    token = SimpleNamespace(scopes=[], client_id=None, subject=None)
    monkeypatch.setattr(dependencies, "get_access_token", lambda: token)
    cleanup = await apply_tool_mode(app, "discovery")
    try:
        async with Client(app) as client:
            for name in ("list_hosts",):
                tool = await app.get_tool(name)
                await client.call_tool(
                    "call_read_tool", {"name": name, "arguments": tool_args.generated_args(tool)}
                )
            name = "create_network"
            tool = await app.get_tool(name)
            arguments = {"name": name, "arguments": tool_args.generated_args(tool)}
            with pytest.raises(Exception, match="OAuth scope"):
                await client.call_tool("call_write_tool", arguments)
            assert audits == [(name, "MCP_OAUTH_WRITE_SCOPE")]
            assert not up.writes()
            token.scopes.append("write")
            await client.call_tool("call_write_tool", arguments)
            assert up.writes()
    finally:
        cleanup()


@pytest.mark.asyncio
async def test_connections_share_catalog_and_description_budget():
    """Discovery never changes visibility in response to a connection's history."""
    import json

    from unifi_fabric.discovery import apply_tool_mode

    app = await clone_app()
    await apply_tool_mode(app, "full")
    async with Client(app) as client:
        full = await client.list_tools()
    cleanup = await apply_tool_mode(app, "discovery")
    try:
        async with Client(app) as first, Client(app) as second:
            before = await first.list_tools()
            await first.call_tool("describe_tool", {"name": "list_hosts"})
            after = await first.list_tools()
            other = await second.list_tools()
            assert before == after == other

            def serialize(tools):
                return json.dumps(
                    {"tools": [t.model_dump(by_alias=True, exclude_none=True) for t in tools]},
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode()

            assert len(serialize(before)) <= 16000
            assert len(serialize(before)) < len(serialize(full)) / 10
            for tool in [*full, *before]:
                assert tool.description and len(tool.description) <= 2048, (
                    tool.name,
                    len(tool.description or ""),
                )
                assert tool.description.splitlines()[0].strip(), tool.name
    finally:
        cleanup()


@pytest.mark.asyncio
async def test_read_dispatch_refuses_every_derived_write():
    from unifi_fabric._read_only_audit import derive_write_tools
    from unifi_fabric.discovery import apply_tool_mode

    app = await clone_app()
    writes = derive_write_tools(await app.list_tools())
    cleanup = await apply_tool_mode(app, "discovery")
    try:
        async with Client(app) as client:
            for name in writes:
                arguments = {}
                if name == "fabric_connector_get":
                    # Its conservative annotation covers mixed routes; test a real
                    # mutation rather than an absent (invalid) route argument.
                    from tests import tool_args

                    arguments = {
                        **tool_args.generated_args(await app.get_tool(name)),
                        "path": "protect/api/cameras/synthetic-camera/enable-control",
                    }
                with pytest.raises(Exception, match="call_write_tool"):
                    await client.call_tool("call_read_tool", {"name": name, "arguments": arguments})
    finally:
        cleanup()


@pytest.mark.asyncio
async def test_search_default_limit_and_all_matches_reachable():
    from unifi_fabric.discovery import apply_tool_mode

    app = await clone_app()
    count = len(await app.list_tools())
    cleanup = await apply_tool_mode(app, "discovery")
    try:
        async with Client(app) as client:
            assert (
                len(
                    (await client.call_tool("search_tools", {"query": ""})).structured_content[
                        "result"
                    ]
                )
                == 10
            )
            rows = (
                await client.call_tool("search_tools", {"query": "", "limit": count + 1000})
            ).structured_content["result"]
            assert len(rows) == count
            for limit in (0, -1):
                with pytest.raises(Exception):
                    await client.call_tool("search_tools", {"query": "", "limit": limit})
    finally:
        cleanup()


@pytest.mark.asyncio
async def test_search_parameter_descriptions_and_family_synonyms():
    from unifi_fabric.discovery import apply_tool_mode

    app = FastMCP("parameter-search")

    @app.tool
    async def inspect_alpha(radio: str):
        """Inspect the alpha resource.

        Args:
            radio: The quasar frequency selector for this inspection.
        """
        return radio

    @app.tool
    async def inspect_beta(nebula_id: str):
        """Inspect the beta resource.

        Args:
            nebula_id: Identifier of the resource.
        """
        return nebula_id

    cleanup = await apply_tool_mode(app, "discovery")
    try:
        async with Client(app) as client:
            by_description = (
                await client.call_tool("search_tools", {"query": "quasar"})
            ).structured_content["result"]
            by_parameter = (
                await client.call_tool("search_tools", {"query": "nebula"})
            ).structured_content["result"]
            assert by_description[0]["name"] == "inspect_alpha"
            assert by_parameter[0]["name"] == "inspect_beta"
    finally:
        cleanup()

    app = await clone_app()
    cleanup = await apply_tool_mode(app, "discovery")
    try:
        async with Client(app) as client:
            rows = (
                await client.call_tool(
                    "search_tools",
                    {"query": "surveillance cameras", "family": "protect", "limit": 1000},
                )
            ).structured_content["result"]
            assert "list_cameras" in {row["name"] for row in rows}
            assert all(row["family"] == "protect" for row in rows)
    finally:
        cleanup()


def test_tool_mode_environment(monkeypatch):
    monkeypatch.delenv("UNIFI_TOOL_MODE", raising=False)
    assert Settings().tool_mode == "discovery"
    monkeypatch.setenv("UNIFI_TOOL_MODE", "")
    assert Settings().tool_mode == "discovery"
    monkeypatch.setenv("UNIFI_TOOL_MODE", "full")
    assert Settings().tool_mode == "full"
    monkeypatch.setenv("UNIFI_TOOL_MODE", "invalid")
    with pytest.raises(ValidationError, match="discovery.*full|full.*discovery"):
        Settings()


@pytest.mark.asyncio
async def test_full_mode_never_adds_always_load_metadata():
    from unifi_fabric.discovery import apply_tool_mode

    app = await clone_app()
    cleanup_full = await apply_tool_mode(app, "full")
    try:
        async with Client(app) as client:
            tools = await client.list_tools()
            assert all(not (t.meta or {}).get("anthropic/alwaysLoad") for t in tools)
        cleanup_discovery = await apply_tool_mode(app, "discovery")
        try:
            async with Client(app) as client:
                assert all(
                    not (t.meta or {}).get("anthropic/alwaysLoad")
                    for t in await client.list_tools()
                )
        finally:
            cleanup_discovery()
    finally:
        cleanup_full()


@pytest.mark.asyncio
async def test_full_mode_is_byte_identical_and_discovery_does_not_mutate_tool_meta():
    import json

    from unifi_fabric.discovery import apply_tool_mode

    app = await clone_app()
    before = [tool.model_dump(by_alias=True, exclude_none=True) for tool in await app.list_tools()]
    cleanup = await apply_tool_mode(app, "full")
    try:
        full = [
            tool.model_dump(by_alias=True, exclude_none=True) for tool in await app.list_tools()
        ]
        assert json.dumps(
            full, default=str, separators=(",", ":"), ensure_ascii=False
        ) == json.dumps(before, default=str, separators=(",", ":"), ensure_ascii=False)
    finally:
        cleanup()
    cleanup = await apply_tool_mode(app, "discovery")
    try:
        async with Client(app) as client:
            await client.list_tools()
    finally:
        cleanup()
    after = [tool.model_dump(by_alias=True, exclude_none=True) for tool in await app.list_tools()]
    assert after == before


@pytest.mark.asyncio
async def test_meta_tool_descriptions_are_clean_across_python_docstring_rules():
    from unifi_fabric.discovery import apply_tool_mode

    app = await clone_app()
    cleanup = await apply_tool_mode(app, "discovery")
    try:
        async with Client(app) as client:
            tools = await client.list_tools()
            assert {tool.name for tool in tools} == {
                "search_tools",
                "describe_tool",
                "call_read_tool",
                "call_write_tool",
                "list_tool_families",
            }
            for tool in tools:
                assert not (tool.description or "").startswith((" ", "\t")), tool.name
    finally:
        cleanup()


@pytest.mark.asyncio
async def test_stopword_and_no_match_searches_are_actionable():
    from unifi_fabric.discovery import apply_tool_mode

    app = await clone_app()
    cleanup = await apply_tool_mode(app, "discovery")
    try:
        async with Client(app) as client:
            for query in ("the and to", "quasarflibbertigibbet"):
                with pytest.raises(Exception, match="Try a broader query|Try a tool name"):
                    await client.call_tool("search_tools", {"query": query})
    finally:
        cleanup()


async def test_discovery_write_accepts_and_ignores_outer_and_inner_confirm(monkeypatch):
    from tests import tool_args
    from tests import upstream_harness as uh
    from unifi_fabric.discovery import apply_tool_mode

    app = await clone_app()
    tool = await app.get_tool("restart_device")
    arguments = tool_args.generated_args(tool)
    arguments.pop("confirm", None)
    cleanup = await apply_tool_mode(app, "discovery")
    results = []
    requests = []
    try:
        async with Client(app) as client:
            for outer in ({}, {"confirm": True}, {"confirm": False}):
                for inner in ({}, {"confirm": True}, {"confirm": False}):
                    upstream = uh.FakeUpstream()
                    with monkeypatch.context() as scoped:
                        uh.install(scoped, upstream)
                        tool_args.prepare_upstream("restart_device", upstream)
                        target_args = tool_args.resolve_placeholders(
                            "restart_device", {**arguments, **inner}
                        )
                        result = await client.call_tool(
                            "call_write_tool",
                            {"name": "restart_device", "arguments": target_args, **outer},
                        )
                        results.append(result.data)
                        requests.append(upstream.served)
                        assert upstream.writes()
        assert all(value == results[0] for value in results)
        assert all(value == requests[0] for value in requests)
    finally:
        cleanup()
