"""Per-area write opt-outs hide their write tools from the catalog and discovery.

Each switch in ``switches.AREA_WRITE_SWITCHES`` and the connector relay's
``family:connector=deny`` removes its area's annotated write tools at startup, so
``tools/list`` (full mode) and discovery search, describe and family counts offer only tools
that can run. A hidden name called by a client is still refused with the area's reason and
audited (``AreaOptOutMiddleware``). The expected counts are the README opt-out table, which
``scripts/gen_catalog_figures.py`` writes; these tests start the server and count.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

import httpx
import pytest
from fastmcp import Client, FastMCP

from unifi_fabric import server, switches
from unifi_fabric.config import Settings
from unifi_fabric.discovery import META_TOOLS
from unifi_fabric.families import build_family_index
from unifi_fabric.families.connector.connector import CONNECTOR_WRITE_ENV
from unifi_fabric.read_only import read_only_message
from unifi_fabric.read_only_tools import AreaOptOutMiddleware, ReadOnlyToolMiddleware
from unifi_fabric.refusal_audit import RefusedWriteAuditMiddleware

ROOT = Path(__file__).resolve().parents[1]
AREA_ENVS = [s.env for s in switches.AREA_WRITE_SWITCHES]
ALL_ENVS = [*AREA_ENVS, CONNECTOR_WRITE_ENV]


def switch_table_counts() -> dict[str | None, tuple[int, int]]:
    """The docs/CONFIGURATION.md opt-out table: setting -> (write tools hidden, tools listed)."""
    text = (ROOT / "docs" / "CONFIGURATION.md").read_text()
    rows = re.findall(
        r"^\| (none \(default\)|`(UNIFI_WRITE_EXCEPTIONS|UNIFI_WRITE_POLICY)=([a-z:=-]+)`)"
        r" \| (\d+) \| (\d+) \|$",
        text,
        re.M,
    )
    # A write-exception row is keyed by its entry, the write-policy row by its setting.
    return {
        (value if setting == "UNIFI_WRITE_EXCEPTIONS" else setting) or None: (
            int(hidden),
            int(listed),
        )
        for _label, setting, value, hidden, listed in rows
    }


def connector_scope() -> set[str]:
    """The typed write tools docs/CONFIGURATION.md says the connector switch governs."""
    text = (ROOT / "docs" / "CONFIGURATION.md").read_text()
    sentence = text[text.index("**Scope of `family:connector=deny`.** It governs") :]
    sentence = sentence[: sentence.index("All are enabled by default")]
    sentence = sentence[sentence.index("these typed tools") :]
    return set(re.findall(r"`([a-z_]+)`", sentence))


def governed(env: str, name: str, family: str | None) -> bool:
    """Whether ``env`` governs tool ``name`` (independent of the selection code)."""
    if env == CONNECTOR_WRITE_ENV:
        return family == "connector" or name in connector_scope()
    switch = next(s for s in switches.AREA_WRITE_SWITCHES if s.env == env)
    return switch.governs(family)


async def clone_app() -> FastMCP:
    app = FastMCP("area-opt-out-catalog")
    for tool in await server.mcp.list_tools():
        app.add_tool(tool)
    app.add_middleware(server.SecretScrubMiddleware())
    app.add_middleware(RefusedWriteAuditMiddleware(app, lambda: True, server._audit_refusal))
    app.add_middleware(ReadOnlyToolMiddleware(app, audit=server._audit_refusal))
    app.add_middleware(
        AreaOptOutMiddleware(app, switches.connector_writes_enabled, server._audit_refusal)
    )
    return app


@pytest.fixture
def no_upstream(monkeypatch):
    async def refuse(*args, **kwargs):
        raise AssertionError("an opted-out catalog or refusal must not contact upstream")

    monkeypatch.setattr(httpx.AsyncClient, "send", refuse)


def configure(monkeypatch, tmp_path, mode, env=None, **settings):
    for var in (
        "UNIFI_WRITE_POLICY",
        "UNIFI_WRITE_EXCEPTIONS",
        "UNIFI_FAMILY_ALLOW",
        "UNIFI_EXCLUDE",
    ):
        monkeypatch.delenv(var, raising=False)
    if env is not None:
        monkeypatch.setenv("UNIFI_WRITE_EXCEPTIONS", env)
    audit_file = tmp_path / "audit.jsonl"
    monkeypatch.setattr(
        server,
        "_settings",
        Settings(
            api_key="synthetic-key",
            tool_mode=mode,
            audit_log=str(audit_file),
            audit_log_format="json",
            **settings,
        ),
    )
    return audit_file


def audit_rows(audit_file: Path) -> list[tuple[str, str, str]]:
    if not audit_file.exists():
        return []
    rows = [
        r
        for r in (json.loads(line) for line in audit_file.read_text().splitlines())
        if r.get("event", "audit") == "audit"
    ]
    return [(row["tool"], row["outcome"], row["reason"]) for row in rows]


def test_switch_table_has_every_switch():
    counts = switch_table_counts()
    assert list(counts) == [None, *ALL_ENVS, switches.READ_ONLY_ENV]
    assert counts[None][0] == 0
    total = counts[None][1]
    assert all(hidden + listed == total for hidden, listed in counts.values())


@pytest.mark.parametrize("mode", ["full", "discovery"])
@pytest.mark.parametrize("env", ALL_ENVS)
async def test_opt_out_hides_its_area_writes(monkeypatch, tmp_path, no_upstream, mode, env):
    audit_file = configure(monkeypatch, tmp_path, mode, env)
    before = {tool.name: tool for tool in await server.mcp.list_tools()}
    index = build_family_index()
    hidden = {
        name
        for name, tool in before.items()
        if not tool.annotations.read_only_hint
        and name != "fabric_connector_get"
        and governed(env, name, index.get(name))
    }
    expected = set(before) - hidden
    doc_hidden, doc_listed = switch_table_counts()[env]
    assert (len(before), len(hidden), len(expected)) == (
        switch_table_counts()[None][1],
        doc_hidden,
        doc_listed,
    )
    assert hidden, f"{env} governs no write tool"

    app = await clone_app()
    async with server.lifespan(app), Client(app) as client:
        listed = {tool.name for tool in await client.list_tools()}
        if mode == "full":
            assert listed == expected
            names = sorted(hidden)
        else:
            assert listed == META_TOOLS
            rows = (
                await client.call_tool("search_tools", {"query": "", "limit": None})
            ).structured_content["result"]
            assert {row["name"] for row in rows} == expected
            writes = (
                await client.call_tool("search_tools", {"query": "", "writes": True, "limit": None})
            ).structured_content["result"]
            assert not {row["name"] for row in writes} & hidden
            families = (await client.call_tool("list_tool_families", {})).structured_content[
                "result"
            ]
            assert {row["family"]: row["tools"] for row in families} == dict(
                Counter(index[name] for name in expected)
            )
            names = sorted(hidden)[:3]
            for name in names:
                with pytest.raises(Exception, match=env):
                    await client.call_tool("describe_tool", {"name": name})
                with pytest.raises(Exception, match=env):
                    await client.call_tool("call_write_tool", {"name": name, "arguments": {}})
        for name in names:
            with pytest.raises(Exception, match=env):
                await client.call_tool(name, {})
            assert await app.get_tool(name) is None
        refused = [row for row in audit_rows(audit_file) if row[0] in hidden]
        assert {row[0] for row in refused} == set(names)
        assert all(row[1:] == ("refused", env) for row in refused)


@pytest.mark.parametrize(
    ("env", "family", "module"),
    [
        (switches.NETWORK_WRITES.env, "firewall", None),
        (switches.NETWORK_WRITES.env, "devices", None),
        (switches.PROTECT_WRITES.env, "protect", "protect_recognition_search"),
        (switches.INNERSPACE_WRITES.env, "innerspace", None),
        (switches.CARRIER_WRITES.env, "carrier", None),
        (switches.MOBILITY_WRITES.env, "mobility", None),
        (CONNECTOR_WRITE_ENV, "connector", None),
        (CONNECTOR_WRITE_ENV, "devices", None),
    ],
)
async def test_hidden_name_refusal_names_the_switch(
    monkeypatch, tmp_path, no_upstream, env, family, module
):
    from unifi_fabric.families import build_module_index

    audit_file = configure(monkeypatch, tmp_path, "full", env)
    index, modules = build_family_index(), build_module_index()
    tools = {tool.name: tool for tool in await server.mcp.list_tools()}
    name = sorted(
        n
        for n, tool in tools.items()
        if index.get(n) == family
        and not tool.annotations.read_only_hint
        and n != "fabric_connector_get"
        and governed(env, n, family)
        and (module is None or modules.get(n) == module)
    )[0]
    app = await clone_app()
    async with server.lifespan(app), Client(app) as client:
        assert name not in {tool.name for tool in await client.list_tools()}
        with pytest.raises(Exception, match=env) as error:
            await client.call_tool(name, {})
        assert "unknown tool" not in str(error.value).lower()
    assert audit_rows(audit_file) == [(name, "refused", env)]


@pytest.mark.parametrize("mode", ["full", "discovery"])
@pytest.mark.parametrize("read_only", [False, True])
async def test_opt_outs_compose_with_read_only_and_family_lists(
    monkeypatch, tmp_path, no_upstream, mode, read_only
):
    configure(
        monkeypatch,
        tmp_path,
        mode,
        CONNECTOR_WRITE_ENV,
    )
    monkeypatch.setenv("UNIFI_FAMILY_ALLOW", "network,firewall,devices")
    monkeypatch.setenv("UNIFI_EXCLUDE", "family:devices")
    if read_only:
        monkeypatch.setenv(switches.READ_ONLY_ENV, "deny")
    index = build_family_index()
    tools = {tool.name: tool for tool in await server.mcp.list_tools()}
    selected = {n for n in tools if index.get(n) in {"network", "firewall"}}
    expected = {
        n
        for n in selected
        if tools[n].annotations.read_only_hint
        or (not read_only and not governed(CONNECTOR_WRITE_ENV, n, index.get(n)))
    }
    assert expected < selected
    # The local key list is a meta tool: listed whatever the selection.
    expected = expected | {"list_configured_api_keys"}
    hidden_by_connector = sorted(
        n
        for n in selected
        if not tools[n].annotations.read_only_hint
        and governed(CONNECTOR_WRITE_ENV, n, index.get(n))
    )
    assert hidden_by_connector
    app = await clone_app()
    async with server.lifespan(app), Client(app) as client:
        if mode == "full":
            assert {tool.name for tool in await client.list_tools()} == expected
        else:
            rows = (
                await client.call_tool("search_tools", {"query": "", "limit": None})
            ).structured_content["result"]
            assert {row["name"] for row in rows} == expected
            families = (await client.call_tool("list_tool_families", {})).structured_content[
                "result"
            ]
            assert {row["family"] for row in families} == {"network", "firewall", "site_manager"}
            assert sum(row["tools"] for row in families) == len(expected)
        name = hidden_by_connector[0]
        # Read-only mode is checked first, so its refusal wins when both apply.
        reason = switches.READ_ONLY_ENV if read_only else CONNECTOR_WRITE_ENV
        with pytest.raises(Exception, match=reason) as error:
            await client.call_tool(name, {})
        if read_only:
            assert read_only_message(name, tool=True) in str(error.value)


@pytest.mark.parametrize("mode", ["full", "discovery"])
async def test_switches_set_on_keep_the_default_catalog(monkeypatch, tmp_path, mode):
    """Every opt-out explicitly on (a true spelling) lists exactly the default catalog."""
    from unifi_fabric.discovery import apply_tool_mode

    configure(monkeypatch, tmp_path, mode)
    baseline = await clone_app()
    restore = await apply_tool_mode(baseline, mode)
    # No deny exception set (writes allowed): the default catalog.
    monkeypatch.setenv("UNIFI_WRITE_EXCEPTIONS", "family:network=dry-run")
    monkeypatch.setattr(server, "_settings", Settings(api_key="synthetic-key", tool_mode=mode))
    app = await clone_app()
    try:
        async with Client(baseline) as before, server.lifespan(app), Client(app) as after:
            assert [tool.model_dump_json() for tool in await after.list_tools()] == [
                tool.model_dump_json() for tool in await before.list_tools()
            ]
            if mode == "discovery":
                for meta in ("search_tools", "list_tool_families"):
                    args = {"query": "", "limit": None} if meta == "search_tools" else {}
                    assert (await after.call_tool(meta, args)).structured_content == (
                        await before.call_tool(meta, args)
                    ).structured_content
    finally:
        restore()
