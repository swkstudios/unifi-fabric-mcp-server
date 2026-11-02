"""N06 review regressions exercised through the actual server catalog."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from fastmcp import Client

from tests.test_network_dpi_policy import CASES, real_client
from unifi_fabric import server
from unifi_fabric.redaction import REDACTION_MASK


@pytest.fixture(autouse=True)
def catalog_lifespan(_reset_server_singletons, monkeypatch):
    monkeypatch.setattr(server, "_settings", server.Settings(api_key="n06-unit-test-key"))


@pytest.fixture
def registry():
    return SimpleNamespace(
        resolve_key_for_host=AsyncMock(return_value=None),
        resolve_host_id=AsyncMock(return_value="test-host"),
        resolve_site_slug=AsyncMock(return_value="default"),
        resolve_site_id=AsyncMock(return_value="bbbbbbbb-0000-4000-8000-000000000001"),
    )


async def test_all_lane_tools_registered_in_real_server(monkeypatch):
    # tools/list advertises the domain tools in full mode; discovery (the default since
    # fe400517) advertises only the meta-tools.
    monkeypatch.setattr(
        server, "_settings", server.Settings(api_key="n06-unit-test-key", tool_mode="full")
    )
    async with Client(server.mcp) as mcp:
        tools = {tool.name: tool for tool in await mcp.list_tools()}
    assert "reset_dpi_counters" in {fn.__name__ for fn, *_ in CASES}
    for fn, *_ in CASES:
        assert fn.__name__ in tools
        tool = tools[fn.__name__]
        assert len(tool.description) <= 2048
        assert all(prop.get("description") for prop in tool.input_schema["properties"].values())


@pytest.mark.parametrize(
    "name,field",
    [
        ("create_policy_engine_rule", "rule"),
        ("preview_policy_engine_rule", "rule"),
        ("create_network_members_group", "group"),
        ("preview_firewall_group", "group"),
    ],
)
@pytest.mark.parametrize(
    "body", [{}, {"secret": REDACTION_MASK}, {"nested": {"secret": REDACTION_MASK}}]
)
async def test_create_and_preview_reject_effectively_empty_before_resolution(
    name, field, body, registry, monkeypatch
):
    monkeypatch.setenv("UNIFI_REDACT_SECRETS", "true")
    monkeypatch.setattr(
        server, "_settings", server.Settings(api_key="n06-unit-test-key", redact_secrets=True)
    )
    client = AsyncMock()
    monkeypatch.setattr(server, "_require", lambda: (client, registry))
    async with Client(server.mcp) as mcp:
        result = await mcp.call_tool(
            name, {"host": "my-console", "site": "Default", field: body}, raise_on_error=False
        )
    assert result.is_error
    assert "No fields provided" in result.content[0].text
    assert not client.mock_calls
    for resolver in vars(registry).values():
        resolver.assert_not_awaited()


PUT_CASES = [(fn.__name__, args) for fn, method, _, args in CASES if method == "PUT"]


@pytest.mark.parametrize("name,args", PUT_CASES)
@pytest.mark.parametrize("actual", [False, 0, None])
async def test_put_merges_then_verifies_type_strict_leaves(
    name, args, actual, registry, monkeypatch
):
    field = next(k for k, v in args.items() if isinstance(v, dict))
    identifier = next(v for k, v in args.items() if k.endswith("_id"))
    before = {"id": identifier, "name": "Original", "nested": {"keep": "retained", "flag": True}}
    after = {**before, "nested": {"keep": "retained", "flag": actual}}
    requests = []

    def handler(request):
        requests.append(request)
        if request.method == "PUT":
            return httpx.Response(200, json={"data": {"id": identifier}, "traceId": "test-trace"})
        record = before if len(requests) == 1 else after
        if "integration" in request.url.path:
            return httpx.Response(200, json=record)
        return httpx.Response(200, json=[record])

    client, transport = real_client(handler)
    monkeypatch.setattr(server, "_require", lambda: (client, registry))
    async with transport, Client(server.mcp) as mcp:
        result = await mcp.call_tool(
            name,
            {"host": "my-console", "site": "Default", **args, field: {"nested": {"flag": False}}},
        )
    assert [r.method for r in requests] == ["GET", "PUT", "GET"]
    sent = json.loads(requests[1].content)
    assert sent["name"] == "Original"
    assert sent["nested"] == {"keep": "retained", "flag": False}
    assert result.data["_verified"] is (actual is False)
    assert result.data["data"] == {"id": identifier}
    assert result.data["traceId"] == "test-trace"


@pytest.mark.parametrize("name,args", PUT_CASES)
async def test_put_dry_run_preserves_preview_without_readback(name, args, registry, monkeypatch):
    field = next(k for k, v in args.items() if isinstance(v, dict))
    identifier = next(v for k, v in args.items() if k.endswith("_id"))
    requests = []

    def handler(request):
        requests.append(request)
        assert request.method == "GET"
        record = {"id": identifier, "name": "Original", "enabled": True}
        return httpx.Response(200, json=record if "integration" in request.url.path else [record])

    client, transport = real_client(handler, dry_run=True)
    monkeypatch.setattr(server, "_require", lambda: (client, registry))
    async with transport, Client(server.mcp) as mcp:
        result = await mcp.call_tool(
            name, {"host": "my-console", "site": "Default", **args, field: {"enabled": False}}
        )
    assert len(requests) == 1
    assert result.data["status"] == "dry_run"
    assert result.data["preview"]["body"]["name"] == "Original"
    assert result.data["preview"]["body"]["enabled"] is False
    assert "_verified" not in result.data


@pytest.mark.parametrize("name,args", PUT_CASES)
@pytest.mark.parametrize("variant", ["owning-key", "all-fail", "page-capped"])
async def test_real_catalog_put_resolution_guards(monkeypatch, name, args, variant):
    from fastmcp.exceptions import ToolError

    from tests import tool_args
    from tests import upstream_harness as uh
    from unifi_fabric.config import APIKeyConfig

    alpha = json.loads(json.dumps(uh.HOST_RECORD))
    alpha["id"] = "0" * 54 + "FA0077:0000000077"
    alpha["reportedState"].update(hostname="alpha-only", name="alpha-only")
    kwargs = {"hosts_by_key": {"k-alpha": [alpha], "k-beta": [uh.HOST_RECORD]}}
    keys = [
        APIKeyConfig(key="k-alpha", label="alpha"),
        APIKeyConfig(key="k-beta", label="beta", is_org_key=True),
    ]
    if variant == "all-fail":
        kwargs["failing_keys"] = frozenset({"k-alpha", "k-beta"})
    if variant == "page-capped":
        kwargs["mode"] = "paged"
        monkeypatch.setenv("UNIFI_PAGINATE_MAX_PAGES", "1")
    up = uh.FakeUpstream(**kwargs)
    uh.install(monkeypatch, up, keys=keys)
    tools = {t.name: t for t in await server.mcp.list_tools()}
    call = {**tool_args.generated_args(tools[name]), "host": uh.HOST}
    async with Client(server.mcp) as mcp:
        if variant == "owning-key":
            result = await mcp.call_tool(name, call)
            assert not result.is_error
            assert up.writes()
            assert all(w.api_key == "k-beta" for w in up.writes())
        else:
            with pytest.raises(ToolError) as raised:
                await mcp.call_tool(name, call)
            if variant == "page-capped":
                assert (
                    "cap" in str(raised.value).lower() or "incomplete" in str(raised.value).lower()
                )
            assert not up.writes()


@pytest.mark.parametrize("name,args", PUT_CASES)
@pytest.mark.parametrize(
    "actual,expected",
    [
        ({"nested": {"flag": False, "value": [0, {"enabled": False}]}}, True),
        ({"nested": {"flag": False, "value": [0, {"enabled": 0}]}}, False),
        ({"nested": {"flag": False, "value": [0.0, {"enabled": False}]}}, False),
        ({"nested": {"flag": False}}, False),
    ],
)
async def test_real_catalog_multiple_requested_leaves(
    monkeypatch, registry, name, args, actual, expected
):
    field = next(k for k, v in args.items() if isinstance(v, dict))
    identifier = next(v for k, v in args.items() if k.endswith("_id"))
    requested = {"nested": {"flag": False, "value": [0, {"enabled": False}]}}
    count = 0

    def handler(request):
        nonlocal count
        if request.method == "PUT":
            return httpx.Response(200, json={"id": identifier, "vendor": "retained"})
        count += 1
        record = {"id": identifier, "name": "Existing"} if count == 1 else actual
        return httpx.Response(
            200, json=record if "integration" in request.url.path else [dict(record, id=identifier)]
        )

    client, transport = real_client(handler)
    monkeypatch.setattr(server, "_require", lambda: (client, registry))
    async with transport, Client(server.mcp) as mcp:
        result = await mcp.call_tool(
            name, {"host": "my-console", "site": "Default", **args, field: requested}
        )
    assert result.data["_verified"] is expected
    assert result.data["vendor"] == "retained"


@pytest.mark.parametrize("name,args", PUT_CASES)
async def test_readback_failure_is_unknown_not_success(monkeypatch, registry, name, args):
    identifier = next(v for k, v in args.items() if k.endswith("_id"))
    reads = 0

    def handler(request):
        nonlocal reads
        if request.method == "PUT":
            return httpx.Response(200, json={"id": identifier})
        reads += 1
        if reads > 1:
            return httpx.Response(403, json={"error": "readback-denied"})
        record = {"id": identifier, "enabled": True}
        return httpx.Response(200, json=record if "integration" in request.url.path else [record])

    client, transport = real_client(handler)
    monkeypatch.setattr(server, "_require", lambda: (client, registry))
    async with transport, Client(server.mcp) as mcp:
        result = await mcp.call_tool(name, {"host": "my-console", "site": "Default", **args})
    assert result.data["_verified"] is None
    assert "403" in result.data["_readAfterError"]


@pytest.mark.parametrize(
    "name,path",
    [
        ("list_policy_engine_rules", "object-oriented-network-configs"),
        ("list_network_members_groups", "network-members-groups"),
        ("list_firewall_app_blocks", "firewall-app-blocks"),
        ("get_firewall_zone_matrix", "firewall/zone-matrix"),
    ],
)
async def test_captured_read_shapes_are_verbatim_in_real_catalog(name, path, registry, monkeypatch):
    from pathlib import Path

    expected = json.loads(
        (Path(__file__).parent / "fixtures/alpha06-live-read-shapes.json").read_text()
    )[path]
    client, transport = real_client(lambda request: httpx.Response(200, json=expected))
    monkeypatch.setattr(server, "_require", lambda: (client, registry))
    async with transport, Client(server.mcp) as mcp:
        result = await mcp.call_tool(name, {"host": "my-console", "site": "Default"})
    assert result.data == expected


@pytest.mark.parametrize("body", [{"index": 1}, {"metadata": {"configurable": True}}])
async def test_official_readonly_only_body_rejected_before_resolution(registry, monkeypatch, body):
    client = AsyncMock()
    monkeypatch.setattr(server, "_require", lambda: (client, registry))
    async with Client(server.mcp) as mcp:
        result = await mcp.call_tool(
            "update_predefined_firewall_policy",
            {
                "host": "my-console",
                "site": "Default",
                "policy_id": "bbbbbbbb-0000-4000-8000-000000000001",
                "policy": body,
            },
            raise_on_error=False,
        )
    assert result.is_error
    assert "No fields provided" in result.content[0].text
    assert not client.mock_calls
    for resolver in vars(registry).values():
        resolver.assert_not_awaited()


@pytest.mark.parametrize("name,args", PUT_CASES[:2])
async def test_private_put_preserves_nested_native_fields(name, args, registry, monkeypatch):
    field = next(k for k, value in args.items() if isinstance(value, dict))
    identifier = next(value for key, value in args.items() if key.endswith("_id"))
    before = {
        "_id": identifier,
        "_warnings": ["additive metadata"],
        "future_field": {
            "_native_private": "retain",
            "enabled": False,
            "deeper": {"_native_private": "retain deeply", "enabled": False},
        },
    }
    requests = []
    persisted = None

    def handler(request):
        nonlocal persisted
        requests.append(request)
        if request.method == "PUT":
            persisted = json.loads(request.content)
            return httpx.Response(200, json={"success": True})
        return httpx.Response(200, json=[before if persisted is None else persisted])

    client, transport = real_client(handler)
    monkeypatch.setattr(server, "_require", lambda: (client, registry))
    async with transport, Client(server.mcp) as mcp:
        result = await mcp.call_tool(
            name,
            {
                "host": "my-console",
                "site": "Default",
                **args,
                field: {"future_field": {"enabled": True, "deeper": {"enabled": True}}},
            },
        )
    assert [request.method for request in requests] == ["GET", "PUT", "GET"]
    assert persisted == {
        "_id": identifier,
        "future_field": {
            "_native_private": "retain",
            "enabled": True,
            "deeper": {"_native_private": "retain deeply", "enabled": True},
        },
    }
    assert result.data["_verified"] is True


@pytest.mark.parametrize("name,args", PUT_CASES)
@pytest.mark.parametrize("write_response", [[], ["unchanged"], "upstream", 0, False, None])
@pytest.mark.parametrize("actual", [False, 0, "read-error"])
async def test_nonobject_put_preserves_response_and_verification(
    name, args, write_response, actual, registry, monkeypatch
):
    field = next(k for k, value in args.items() if isinstance(value, dict))
    identifier = next(value for k, value in args.items() if k.endswith("_id"))
    requests = []

    def handler(request):
        requests.append(request)
        if request.method == "PUT":
            return httpx.Response(
                200,
                content=json.dumps(write_response),
                headers={"content-type": "application/json"},
            )
        if len(requests) > 1 and actual == "read-error":
            return httpx.Response(403, json={"error": "read-back forbidden"})
        record = {"id": identifier, "enabled": True if len(requests) == 1 else actual}
        return httpx.Response(200, json=record if "integration" in request.url.path else [record])

    client, transport = real_client(handler)
    monkeypatch.setattr(server, "_require", lambda: (client, registry))
    async with transport, Client(server.mcp) as mcp:
        result = await mcp.call_tool(
            name, {"host": "my-console", "site": "Default", **args, field: {"enabled": False}}
        )
    assert [r.method for r in requests] == ["GET", "PUT", "GET"]
    assert result.data["result"] == write_response
    assert type(result.data["result"]) is type(write_response)
    assert result.data["_verified"] is (None if actual == "read-error" else actual is False)
    if actual == "read-error":
        assert "read-back forbidden" in result.data["_readAfterError"]
