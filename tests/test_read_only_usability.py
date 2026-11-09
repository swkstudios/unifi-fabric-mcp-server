"""Every registered read answers with read-only enabled on the fake upstream."""

from __future__ import annotations

import json
import time

import httpx
import pytest
from fastmcp import Client

from tests import tool_args
from tests import upstream_harness as uh
from unifi_fabric import server
from unifi_fabric._read_only_audit import derive_write_tools
from unifi_fabric.read_post_routes import READ_POST_ROUTES


async def test_every_read_answers_in_read_only_mode(monkeypatch):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    upstream = uh.FakeUpstream(replay_recordings=False)
    client = uh.install(monkeypatch, upstream)
    tools = list(await server.mcp.list_tools())
    writes = derive_write_tools(tools)
    failures = []
    answered = set()
    try:
        # In-process MCP transport starts the actual server lifespan; its client uses
        # the same fake HTTP transport installed above, never an upstream connection.
        async with Client(server.mcp) as session:
            for tool in tools:
                if tool.name in writes:
                    continue
                with pytest.MonkeyPatch.context() as mp:
                    for name, value in tool_args.TOOL_ENV.get(tool.name, {}).items():
                        mp.setenv(name, value)
                    try:
                        await session.call_tool(tool.name, tool_args.generated_args(tool))
                        answered.add(tool.name)
                    except Exception as exc:  # collect every refusal, never skip a tool
                        failures.append(f"{tool.name}: {exc}")
        assert not failures, "Read-only refusals/errors:\n" + "\n".join(failures)
        assert answered == {tool.name for tool in tools} - writes
        assert {name for route in READ_POST_ROUTES for name in route.tools} <= answered
    finally:
        await client.close()


@pytest.mark.parametrize("mode", ["deny", "dry-run"])
async def test_traffic_flows_read_sends_and_returns_data(monkeypatch, mode):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", mode)
    upstream = uh.FakeUpstream(replay_recordings=False)
    client = uh.install(monkeypatch, upstream, dry_run=mode == "dry-run")
    try:
        tool = next(t for t in await server.mcp.list_tools() if t.name == "query_traffic_flows")
        assert tool.annotations.read_only_hint is True
        result = await server.mcp.call_tool(tool.name, tool_args.generated_args(tool))
        assert "dry_run" not in str(result)
        assert any(
            row.method == "POST" and row.path.endswith("/traffic-flows") for row in upstream.served
        )
    finally:
        await client.close()


class FailedFlowPage(uh.FakeUpstream):
    def __call__(self, request):
        if request.url.path.endswith("/traffic-flows"):
            number = json.loads(request.content or b"{}").get("pageNumber", 0)
            if number == 2:
                return httpx.Response(
                    408, text="controller exhausted its query budget: detail kept"
                )
            return httpx.Response(
                200,
                json={
                    "data": [{"flow": number}],
                    "page_number": number,
                    "has_next": True,
                    "total_element_count": 10000,
                    "or_more": True,
                },
            )
        return super().__call__(request)


async def test_traffic_flows_mid_drain_408_returns_gathered_pages(monkeypatch):
    from unifi_fabric.tools.network_nat_qos_traffic import query_traffic_flows

    monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    upstream = FailedFlowPage(replay_recordings=False)
    client = uh.install(monkeypatch, upstream)
    body = {"pageSize": 5000, "timestampFrom": 1, "timestampTo": 2, "extra": {"kept": True}}
    original = json.loads(json.dumps(body))
    try:
        result = await query_traffic_flows(client, server._registry, uh.HOST, uh.SITE, body)
        assert result["data"] == [{"flow": 0}, {"flow": 1}]
        assert result["_pages"] == 2
        assert result["incomplete"] is True
        assert "page 2" in result["incompleteReason"]
        assert "HTTP 408" in result["incompleteReason"]
        assert "controller exhausted its query budget: detail kept" in result["incompleteReason"]
        assert result["or_more"] is True and result["total_element_count"] == 10000
        assert body == original
    finally:
        await client.close()


class SelectorFlowPages(uh.FakeUpstream):
    def __init__(self):
        super().__init__(replay_recordings=False)
        self.flow_bodies = []

    def __call__(self, request):
        if request.url.path.endswith("/traffic-flows"):
            body = json.loads(request.content)
            typed = {"direction": "outgoing", "action": "blocked", "risk": "high"}
            assert not any(body.get(key) == value for key, value in typed.items())
            assert "window" not in body
            self.flow_bodies.append(body)
            number = body.get("pageNumber", 0)
            return httpx.Response(
                200,
                json={
                    "data": [{"flow": number}],
                    "page_number": number,
                    "total_page_count": 3,
                    "total_element_count": 3,
                    "traceId": "synthetic-selector-drain",
                },
            )
        return super().__call__(request)


@pytest.mark.parametrize("mode", ["deny", "dry-run"])
@pytest.mark.parametrize("body_case", ["typed", "override", "partial"])
async def test_typed_flow_selectors_preserve_body_and_drain_in_read_modes(
    monkeypatch, mode, body_case
):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", mode)
    upstream = SelectorFlowPages()
    client = uh.install(monkeypatch, upstream, dry_run=mode == "dry-run")
    body = {"custom": {"kept": [1, 2]}}
    if body_case == "override":
        body.update(
            timestampFrom=1,
            timestampTo=2,
            direction="body-direction",
            action=["body-action"],
            risk=None,
        )
    elif body_case == "partial":
        body.update(timestampFrom=1, action=["body-action"])
    original = json.loads(json.dumps(body))
    selectors = {"direction": "outgoing", "action": "blocked", "risk": "high"}
    before = int(time.time() * 1000)
    try:
        result = uh.result_payload(
            await server.mcp.call_tool(
                "query_traffic_flows",
                {"host": uh.HOST, "site": uh.SITE, "body": body, "window": "5m", **selectors},
            )
        )
        after = int(time.time() * 1000)
        assert result["data"] == [{"flow": 0}, {"flow": 1}, {"flow": 2}]
        assert result["_pages"] == 3
        assert result["traceId"] == "synthetic-selector-drain"
        assert "incomplete" not in result
        assert "dry_run" not in result
        assert len(upstream.flow_bodies) == 3
        first = upstream.flow_bodies[0]
        expected = {
            **{key: [value] for key, value in selectors.items()},
            "timestampFrom": first["timestampFrom"],
            "timestampTo": first["timestampTo"],
            **original,
        }
        assert first == expected
        for key in ("timestampFrom", "timestampTo"):
            assert isinstance(first[key], int) and not isinstance(first[key], bool)
        if "timestampTo" not in original:
            assert before <= first["timestampTo"] <= after
        if "timestampFrom" not in original:
            assert first["timestampFrom"] == first["timestampTo"] - 300_000
        for key, value in selectors.items():
            if key not in original:
                assert first[key] == [value]
        assert all("window" not in page for page in upstream.flow_bodies)
        assert upstream.flow_bodies == [
            expected,
            {**expected, "pageNumber": 1},
            {**expected, "pageNumber": 2},
        ]
        assert body == original
    finally:
        await client.close()
