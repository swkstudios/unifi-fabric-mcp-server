"""Advertised catalog must retain its instructions and hints in MCP clients."""

import asyncio

from unifi_fabric import server


def test_every_tool_advertises_explicit_directory_hints():
    tools = asyncio.run(server.mcp.list_tools())
    assert tools
    assert {"list_hosts", "create_wifi_broadcast"} <= {tool.name for tool in tools}
    assert len(tools) == len(server.mcp._local_provider._components)
    missing = []
    for tool in tools:
        hints = (
            tool.annotations.model_dump(exclude_unset=True, by_alias=True)
            if tool.annotations
            else {}
        )
        if (
            not tool.title
            or not tool.title.strip()
            or "readOnlyHint" not in hints
            or "destructiveHint" not in hints
        ):
            missing.append(tool.name)
        # Directory Policy 5E: both hints explicit and consistent. A read is never
        # destructive (Claude prompts before destructive tools); every write is.
        if "readOnlyHint" in hints and "destructiveHint" in hints:
            assert hints["destructiveHint"] is (not hints["readOnlyHint"]), tool.name
    assert not missing, missing


def test_instructions_fit_claude_code_default_limit():
    assert len(server.INSTRUCTIONS) <= 2048
    for essential in (
        "list_hosts",
        "host",
        "site",
        "UNIFI_WRITE_POLICY",
        "dry-run policy",
        "pagination",
        "error",
        "docs/TOOL-USAGE.md",
    ):
        assert essential in server.INSTRUCTIONS


def test_every_advertised_description_fits_claude_code_default_limit():
    tools = asyncio.run(server.mcp.list_tools())
    assert tools
    assert {"list_hosts", "create_wifi_broadcast"} <= {tool.name for tool in tools}
    over = {
        tool.name: len(tool.description or "")
        for tool in tools
        if len(tool.description or "") > 2048
    }
    assert not over, over


def test_short_descriptions_do_not_reference_moved_sections():
    tools = {tool.name: tool for tool in asyncio.run(server.mcp.list_tools())}
    assert "below" not in tools["create_wifi_broadcast"].description
    assert "nested keys above" not in tools["update_camera"].description
    schema = tools["update_camera"].parameters
    assert "nested keys above" not in str(schema)


def test_relay_read_twin_guidance_only_on_twin_methods():
    tools = {tool.name: tool for tool in asyncio.run(server.mcp.list_tools())}
    note = "readBefore/readAfter carry the same guidance"
    for method in ("get", "post"):
        assert note not in tools["fabric_connector_" + method].description
    for method in ("put", "patch", "delete"):
        assert note in tools["fabric_connector_" + method].description


def test_compact_host_guidance_retains_selector_semantics():
    from unifi_fabric.catalog_descriptions import HOST_DESCRIPTION

    tools = asyncio.run(server.mcp.list_tools())
    compact = [
        tool
        for tool in tools
        if tool.parameters.get("properties", {}).get("host", {}).get("description")
        == HOST_DESCRIPTION
    ]
    assert len(compact) >= 247
    for essential in (
        "case-insensitive",
        "reportedState.hostname/name",
        "my-console",
        "data[].id",
        "MAC:numericId",
        "list_hosts",
        "Network and Protect",
    ):
        assert essential in HOST_DESCRIPTION


def test_instructions_lines_end_at_a_sentence_or_clause_boundary():
    # Clients receive INSTRUCTIONS with its newlines, so a hard wrap inside a phrase
    # ("Full PUT replaces" / "fields: ...") reaches the agent as a broken sentence.
    for line in server.INSTRUCTIONS.splitlines():
        assert line.rstrip().endswith((".", ";", ":")), line
