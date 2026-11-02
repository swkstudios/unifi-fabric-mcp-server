"""A mixed relay read failure is not a refused write; action failures still are."""

from __future__ import annotations

import pytest
from fastmcp import FastMCP

from unifi_fabric.refusal_audit import RefusedWriteAuditMiddleware


@pytest.mark.parametrize(
    ("path", "action"),
    [
        ("protect/api/bootstrap", False),
        ("../x", False),
        (
            "protect/api/cameras/camera/enable-control",
            True,
        ),
    ],
)
async def test_mixed_get_relay_audits_only_action_failures(path, action):
    app = FastMCP("mixed-relay-refusal-audit")

    @app.tool(annotations={"readOnlyHint": False})
    async def fabric_connector_get(path: str) -> dict:
        raise ValueError("synthetic refusal")

    seen: list[tuple[str, str]] = []
    app.add_middleware(
        RefusedWriteAuditMiddleware(
            app, lambda: True, lambda tool, reason: seen.append((tool, reason))
        )
    )
    with pytest.raises(Exception, match="synthetic refusal") as exc:
        await app.call_tool("fabric_connector_get", {"path": path})
    assert seen == ([("fabric_connector_get", str(exc.value))] if action else [])


@pytest.mark.parametrize("selector", ["*/write", "relay/write", "relay/generic/write"])
async def test_write_source_filter_preserves_reads_and_per_call_action_refusal(
    monkeypatch, selector
):
    from unifi_fabric.api_sources import apply_api_source_filter
    from unifi_fabric.read_only_tools import ReadOnlyToolMiddleware

    app = FastMCP("mixed-relay-per-call-policy")

    @app.tool(annotations={"readOnlyHint": False})
    async def fabric_connector_get(path: str) -> dict:
        return {"path": path}

    monkeypatch.setenv("UNIFI_READ_ONLY", "1")
    app.add_middleware(ReadOnlyToolMiddleware(app))
    assert await apply_api_source_filter(app, selector) == []
    result = await app.call_tool("fabric_connector_get", {"path": "protect/api/bootstrap"})
    assert result.structured_content == {"path": "protect/api/bootstrap"}
    with pytest.raises(Exception, match="UNIFI_READ_ONLY"):
        await app.call_tool(
            "fabric_connector_get", {"path": "protect/api/cameras/camera/enable-control"}
        )
