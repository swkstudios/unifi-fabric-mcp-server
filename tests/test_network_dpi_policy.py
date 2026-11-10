"""N06 behavioral properties over every lane tool, using a real HTTP client."""

from __future__ import annotations

import inspect
import json
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from fastmcp import Client

from unifi_fabric import server
from unifi_fabric._read_only_audit import derive_write_tools, write_verbs_for
from unifi_fabric.client import UniFiClient, UniFiHTTPError
from unifi_fabric.config import Settings
from unifi_fabric.families.network import network_dpi_policy as lane

CASES = [
    (lane.reset_dpi_counters, "DELETE", "/dpi", {}),
    (lane.list_policy_engine_rules, "GET", "/object-oriented-network-configs", {}),
    (
        lane.create_policy_engine_rule,
        "POST",
        "/object-oriented-network-config",
        {"rule": {"name": "Test", "enabled": False}},
    ),
    (
        lane.update_policy_engine_rule,
        "PUT",
        "/object-oriented-network-config/test-rule",
        {"rule_id": "test-rule", "rule": {"name": "Updated", "enabled": False}},
    ),
    (
        lane.delete_policy_engine_rule,
        "DELETE",
        "/object-oriented-network-config/test-rule",
        {"rule_id": "test-rule"},
    ),
    (
        lane.preview_policy_engine_rule,
        "POST",
        "/object-oriented-network-config/preview",
        {"rule": {"enabled": False}},
    ),
    (lane.list_network_members_groups, "GET", "/network-members-groups", {}),
    (
        lane.create_network_members_group,
        "POST",
        "/network-members-group",
        {"group": {"name": "Test", "members": ["192.0.2.0/24"], "type": "IPV4"}},
    ),
    (
        lane.update_network_members_group,
        "PUT",
        "/network-members-group/test-group",
        {"group_id": "test-group", "group": {"name": "Updated"}},
    ),
    (
        lane.delete_network_members_group,
        "DELETE",
        "/network-members-group/test-group",
        {"group_id": "test-group"},
    ),
    (lane.list_firewall_app_blocks, "GET", "/firewall-app-blocks", {}),
    (
        lane.set_firewall_app_blocks,
        "POST",
        "/firewall-app-blocks",
        {"blocks": [{"enabled": False, "app_ids": []}]},
    ),
    (
        lane.preview_firewall_group,
        "POST",
        "/firewall-groups/preview",
        {"group": {"url": "https://example.invalid/list.txt", "group_type": "address-group"}},
    ),
    (
        lane.update_predefined_firewall_policy,
        "PUT",
        "/firewall/policies/test-policy",
        {"policy_id": "test-policy", "policy": {"enabled": False}},
    ),
    (lane.get_firewall_zone_matrix, "GET", "/firewall/zone-matrix", {}),
]
#: Write cases: the dry-run, no-retry and read-only tests apply to writes only. The GET
#: cases run through every shared-case test (route and body, errors, secondary key).
WRITE_CASES = [case for case in CASES if case[1] != "GET"]
READ_CASES = [case for case in CASES if case[1] == "GET"]
BODY_CASES = [
    (fn, next(k for k, v in args.items() if isinstance(v, (dict, list))), args)
    for fn, method, _, args in CASES
    if method in {"POST", "PUT"}
]
ID_CASES = [
    (fn, next(k for k in args if k.endswith("_id")), args)
    for fn, _, _, args in CASES
    if any(k.endswith("_id") for k in args)
]


@pytest.fixture(autouse=True)
def catalog_lifespan(_reset_server_singletons, monkeypatch):
    monkeypatch.setattr(
        server,
        "_settings",
        server.Settings(api_key="n06-unit-test-key", tool_mode="full"),
    )


@pytest.fixture
def registry():
    return SimpleNamespace(
        resolve_key_for_host=AsyncMock(return_value=None),
        resolve_host_id=AsyncMock(return_value="test-host"),
        resolve_site_slug=AsyncMock(return_value="default"),
        resolve_site_id=AsyncMock(return_value="bbbbbbbb-0000-4000-8000-000000000001"),
    )


@pytest.fixture(autouse=True)
def _write_policy_env_reset(monkeypatch):
    """Start every test without a write policy; ``_modes`` sets one for a client's modes."""
    # setenv first so the teardown removes a value a helper set directly in os.environ
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "allow")
    monkeypatch.delenv("UNIFI_WRITE_POLICY")


def _modes(settings: dict) -> dict:
    """Express the retired ``dry_run`` / ``read_only`` client modes as the write policy."""
    settings = dict(settings)
    dry = settings.pop("dry_run", False)
    deny = settings.pop("read_only", False)
    if deny:
        os.environ["UNIFI_WRITE_POLICY"] = "deny"
    elif dry:
        os.environ["UNIFI_WRITE_POLICY"] = "dry-run"
    return settings


def real_client(handler, **overrides):
    overrides = _modes(overrides)
    c = UniFiClient(Settings(api_key="synthetic-test-key", **overrides))
    transport = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://api.ui.com"
    )
    c._get_client = AsyncMock(return_value=transport)
    return c, transport


async def test_preview_405_preserves_complete_error_and_adds_version_guidance(registry):
    body = "<!doctype html><html><body>HTTP Status 405 – Method Not Allowed</body></html>"
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(405, text=body)

    client, transport = real_client(handler)
    async with transport:
        with pytest.raises(UniFiHTTPError) as caught:
            await lane.preview_policy_engine_rule(
                client, registry, "my-console", "Default", {"enabled": False}
            )
    assert caught.value.status == 405
    assert body in str(caught.value)
    assert lane.PREVIEW_RULE_405_VERSION in str(caught.value)
    assert lane.PREVIEW_RULE_MIN_VERSION in str(caught.value)
    assert "POST /object-oriented-network-config/preview" in str(caught.value)
    assert len(requests) == 1 and requests[0].method == "POST"
    assert json.loads(requests[0].content) == {"enabled": False}


SYSTEM_POLICY_REFUSAL = {
    "statusCode": 400,
    "statusName": "BAD_REQUEST",
    "code": "api.firewall.policy.operation.system-defined-firewall-policy-update-forbidden",
    "message": "Modifications of system-defined firewall policy is not allowed",
}


async def test_system_defined_policy_put_refusal_is_kept_whole_with_patch_hint(registry):
    """Live 2026-10-28 (Network 11.0.89): the Integration PUT on a SYSTEM_DEFINED policy
    answers HTTP 400 system-defined-firewall-policy-update-forbidden. The error keeps the
    complete upstream body and gains a hint to the loggingEnabled-only patch tool."""
    policy = {
        "id": "bbbbbbbb-0000-4000-8000-000000000002",
        "enabled": True,
        "name": "Block Invalid Traffic",
        "index": 30000,
        "action": {"type": "BLOCK"},
        "source": {"zoneId": "cccccccc-0000-4000-8000-000000000001"},
        "destination": {"zoneId": "cccccccc-0000-4000-8000-000000000002"},
        "ipProtocolScope": {"ipVersion": "IPV4_AND_IPV6"},
        "loggingEnabled": False,
        "metadata": {"origin": "SYSTEM_DEFINED", "configurable": True},
    }
    seen = []

    def handler(request):
        seen.append(request.method)
        if request.method == "GET":
            return httpx.Response(200, json=policy)
        return httpx.Response(400, json=SYSTEM_POLICY_REFUSAL)

    client, transport = real_client(handler)
    async with transport:
        with pytest.raises(UniFiHTTPError) as caught:
            await lane.update_predefined_firewall_policy(
                client, registry, "my-console", "Default", policy["id"], {"enabled": False}
            )
    text = str(caught.value)
    assert caught.value.status == 400
    assert "system-defined-firewall-policy-update-forbidden" in text
    assert "Modifications of system-defined firewall policy is not allowed" in text
    assert "patch_firewall_policy" in text and "loggingEnabled" in text
    assert seen.count("PUT") == 1  # sent once, never retried


async def test_other_policy_put_400_gets_no_system_defined_hint(registry):
    body = {"statusCode": 400, "code": "api.firewall.policy.validation.name", "message": "bad"}
    policy = {"id": "bbbbbbbb-0000-4000-8000-000000000002", "enabled": True, "name": "n"}

    def handler(request):
        if request.method == "GET":
            return httpx.Response(200, json=policy)
        return httpx.Response(400, json=body)

    client, transport = real_client(handler)
    async with transport:
        with pytest.raises(UniFiHTTPError) as caught:
            await lane.update_predefined_firewall_policy(
                client, registry, "my-console", "Default", policy["id"], {"enabled": False}
            )
    assert "api.firewall.policy.validation.name" in str(caught.value)
    assert "patch_firewall_policy" not in str(caught.value)


def stored_record(args):
    fields = next((v for v in args.values() if isinstance(v, dict)), {})
    identifier = next((v for k, v in args.items() if k.endswith("_id")), "test-object")
    return {"id": identifier, **fields}


def read_response(request, args):
    record = stored_record(args)
    return record if "integration" in request.url.path else [record]


#: Deletes that resolve the id in the collection list before the DELETE, like updates.
LIST_FIRST_DELETES = (lane.delete_policy_engine_rule, lane.delete_network_members_group)


def reads_first(fn, method):
    return method == "PUT" or fn in LIST_FIRST_DELETES


def stub_reads(client, args):
    client.get.return_value = stored_record(args) if "policy_id" in args else [stored_record(args)]


@pytest.mark.parametrize(
    "fn,method,path,args", CASES, ids=lambda v: v.__name__ if callable(v) else None
)
@pytest.mark.parametrize(
    "body",
    [
        {
            "data": {"id": "test-object", "enabled": False},
            "httpStatusCode": 200,
            "traceId": "test-trace",
        },
        [{"id": f"test-{i}"} for i in range(301)],
        None,
    ],
)
async def test_exact_route_and_verbatim_body(fn, method, path, args, body, registry):
    requests = []

    def handler(request):
        requests.append(request)
        if reads_first(fn, method) and request.method == "GET":
            return httpx.Response(200, json=read_response(request, args))
        return httpx.Response(200, json=body)

    c, transport = real_client(handler)
    async with transport:
        result = await fn(c, registry, "my-console", "Default", **args)
    if method == "PUT":
        expected = body if isinstance(body, dict) else {"result": body}
        assert {k: v for k, v in result.items() if k != "_verified"} == expected
        assert result["_verified"] is True
        if not isinstance(body, dict):
            assert type(result["result"]) is type(body)
    elif method == "DELETE" and fn is not lane.reset_dpi_counters:
        assert result["deleted"] is True
        assert result["response"] == body
        assert set(result) == {"deleted", "message", "response"}
    else:
        assert result == body
    expected_methods = (
        ["GET", "PUT", "GET"]
        if method == "PUT"
        else ["GET", method]
        if fn in LIST_FIRST_DELETES
        else [method]
    )
    assert [r.method for r in requests] == expected_methods
    sent_request = next(r for r in requests if r.method == method)
    if fn is lane.update_predefined_firewall_policy:
        prefix = "/v1/connector/consoles/test-host/proxy/network/integration/v1/sites/"
        assert sent_request.url.path == prefix + "bbbbbbbb-0000-4000-8000-000000000001" + path
        registry.resolve_site_id.assert_awaited_once_with("Default", "test-host", key=None)
    else:
        assert (
            sent_request.url.path
            == f"/v1/connector/consoles/test-host/proxy/network/v2/api/site/default{path}"
        )
        registry.resolve_site_slug.assert_awaited_once_with("Default", "test-host", key=None)
    expected = next((v for v in args.values() if isinstance(v, (dict, list))), None)
    if fn is lane.reset_dpi_counters:
        expected = {"cmd": "reset-dpi"}
    if expected is not None:
        sent = json.loads(sent_request.content)
        if method == "PUT":
            assert all(sent[k] == v for k, v in expected.items())
        else:
            assert sent == expected


@pytest.mark.parametrize("fn,method,path,args", WRITE_CASES)
async def test_dry_run_writes_make_no_http_request(fn, method, path, args, registry):

    def handler(request):
        assert reads_first(fn, method) and request.method == "GET"
        return httpx.Response(200, json=read_response(request, args))

    c, transport = real_client(handler, dry_run=True)
    async with transport:
        result = await fn(c, registry, "my-console", "Default", **args)
    if fn in (lane.delete_policy_engine_rule, lane.delete_network_members_group):
        # A delete returns the deletion_result dry-run shape with the preview under response.
        assert result["status"] == "dry_run" and result["deleted"] is False and result["message"]
        result = result["response"]
    assert result["status"] == "dry_run"
    assert result["preview"]["method"] == method
    assert result["preview"]["path"].endswith(path)
    for value in args.values():
        if isinstance(value, (dict, list)):
            assert (
                all(result["preview"]["body"][k] == v for k, v in value.items())
                if method == "PUT"
                else result["preview"]["body"] == value
            )
    assert not {"verified", "noOp", "deleted"} & result.keys()


@pytest.mark.parametrize("fn,method,path,args", CASES)
@pytest.mark.parametrize(
    "selector,bad", [("host", ""), ("host", " name "), ("site", ""), ("site", "Default\n")]
)
async def test_invalid_selectors_precede_resolution(
    fn, method, path, args, selector, bad, registry
):
    c = AsyncMock()
    selectors = {"host": "my-console", "site": "Default", selector: bad}
    with pytest.raises(ValueError):
        await fn(c, registry, **selectors, **args)
    assert not c.mock_calls
    assert not registry.resolve_key_for_host.mock_calls


@pytest.mark.parametrize("fn,field,args", BODY_CASES)
@pytest.mark.parametrize(
    "bad",
    [
        None,
        [],
        "string",
        {"nested": float("nan")},
        {"nested": [float("inf")]},
        {"nested": object()},
    ],
)
async def test_invalid_json_body_zero_requests(fn, field, args, bad, registry):
    c = AsyncMock()
    if fn is lane.set_firewall_app_blocks and isinstance(bad, dict):
        bad = [bad]
    elif fn is lane.set_firewall_app_blocks and bad == []:
        bad = {}
    with pytest.raises(ValueError):
        await fn(c, registry, "my-console", "Default", **{**args, field: bad})
    assert not c.mock_calls
    assert not registry.resolve_key_for_host.mock_calls


@pytest.mark.parametrize("fn,field,args", ID_CASES)
@pytest.mark.parametrize("bad", ["", "../test", "test/other", "test?x=1", "00:00:00:00:00:00"])
async def test_invalid_ids_zero_requests(fn, field, args, bad, registry):
    c = AsyncMock()
    with pytest.raises(ValueError):
        await fn(c, registry, "my-console", "Default", **{**args, field: bad})
    assert not c.mock_calls
    assert not registry.resolve_key_for_host.mock_calls


@pytest.mark.parametrize(
    "fn,field,args", [c for c in BODY_CASES if c[0].__name__.startswith("update_")]
)
@pytest.mark.parametrize("bad", [{}, {"_keyLabel": "test"}, {"id": "test"}, {"_id": "test"}])
async def test_empty_update_zero_requests(fn, field, args, bad, registry):
    c = AsyncMock()
    with pytest.raises(ValueError):
        await fn(c, registry, "my-console", "Default", **{**args, field: bad})
    assert not c.mock_calls
    assert not registry.resolve_key_for_host.mock_calls


@pytest.mark.parametrize("fn,field,args", BODY_CASES)
async def test_unknown_private_fields_forwarded_and_additive_stripped(fn, field, args, registry):
    c = AsyncMock()
    stub_reads(c, args)
    value = args[field][0] if isinstance(args[field], list) else args[field]
    original = {**value, "future_field": {"flag": False, "number": 1.5}, "_keyLabel": "test"}
    await fn(
        c,
        registry,
        "my-console",
        "Default",
        **{**args, field: [original] if fn is lane.set_firewall_app_blocks else original},
    )
    sent = next(call for call in c.mock_calls if call[0] in {"post", "put"}).kwargs["json"]
    if fn is lane.set_firewall_app_blocks:
        sent = sent[0]
    assert "_keyLabel" not in sent
    assert sent["future_field"] == {"flag": False, "number": 1.5}
    assert original["_keyLabel"] == "test"


@pytest.mark.parametrize("fn,method,path,args", CASES)
async def test_upstream_error_never_rewritten_or_truncated(fn, method, path, args, registry):
    reason = "upstream-reason-" * 600
    c, transport = real_client(lambda _: httpx.Response(400, json={"message": reason}))
    async with transport:
        with pytest.raises(Exception) as caught:
            await fn(c, registry, "my-console", "Default", **args)
    assert reason in str(caught.value)


@pytest.mark.parametrize("fn,method,path,args", WRITE_CASES)
async def test_no_mutating_retry(fn, method, path, args, registry):
    requests = []

    def handler(request):
        requests.append(request)
        if reads_first(fn, method) and request.method == "GET":
            return httpx.Response(200, json=read_response(request, args))
        return httpx.Response(503, json={"message": "unavailable"})

    c, transport = real_client(handler)
    async with transport:
        with pytest.raises(Exception):
            await fn(c, registry, "my-console", "Default", **args)
    assert sum(r.method == method for r in requests) == 1


@pytest.mark.parametrize(
    "fn,arg,list_tool",
    [
        (lane.delete_policy_engine_rule, "rule_id", "list_policy_engine_rules"),
        (lane.delete_network_members_group, "group_id", "list_network_members_groups"),
    ],
)
async def test_delete_unknown_id_lists_valid_ids_and_sends_no_write(fn, arg, list_tool, registry):
    requests = []

    def handler(request):
        requests.append(request)
        assert request.method == "GET"
        return httpx.Response(200, json=[{"_id": "listed-object", "name": "Listed"}])

    c, transport = real_client(handler)
    async with transport:
        with pytest.raises(ValueError) as caught:
            await fn(c, registry, "my-console", "Default", **{arg: "absent-object"})
    assert "absent-object" in str(caught.value) and "listed-object" in str(caught.value)
    assert list_tool in str(caught.value)
    assert [r.method for r in requests] == ["GET"]


@pytest.mark.parametrize(
    "fn,arg,path",
    [
        (lane.delete_policy_engine_rule, "rule_id", "/object-oriented-network-config"),
        (lane.delete_network_members_group, "group_id", "/network-members-group"),
    ],
)
async def test_delete_sends_the_listed_native_id_spelling(fn, arg, path, registry):
    native = "6512a0b1c2d3e4f5a6b7c8d9"
    requests = []

    def handler(request):
        requests.append(request)
        if request.method == "GET":
            return httpx.Response(200, json=[{"_id": native, "name": "Listed"}])
        return httpx.Response(200, json={})

    c, transport = real_client(handler)
    async with transport:
        await fn(c, registry, "my-console", "Default", **{arg: native.upper()})
    sent = next(r for r in requests if r.method == "DELETE")
    assert sent.url.path.endswith(f"{path}/{native}")


def test_derived_write_classification_includes_previews():
    tools = [SimpleNamespace(name=fn.__name__, fn=fn) for fn, *_ in CASES]
    expected = {fn.__name__ for fn, method, *_ in CASES if method != "GET"}
    assert derive_write_tools(tools) == expected
    for fn, method, *_ in CASES:
        assert write_verbs_for(fn) == ({method} if method != "GET" else set())


async def test_lane_runtime_schema_catalog():
    assert "reset_dpi_counters" in {fn.__name__ for fn, *_ in CASES}
    async with Client(server.mcp) as mcp:
        tools = {tool.name: tool for tool in await mcp.list_tools()}
    for fn, *_ in CASES:
        tool = tools[fn.__name__]
        assert len(tool.description) <= 2048
        assert tool.description
        for prop in tool.input_schema["properties"].values():
            assert prop.get("description")


def test_amended_exclusions():
    exported = {
        name
        for name, fn in vars(lane).items()
        if inspect.iscoroutinefunction(fn)
        and fn.__module__ == lane.__name__
        and not name.startswith("_")
    }
    assert exported == {fn.__name__ for fn, *_ in CASES}


async def test_empty_app_block_list_exact_restore(registry):
    c = AsyncMock()
    await lane.set_firewall_app_blocks(c, registry, "my-console", "Default", [])
    assert c.post.call_args.kwargs["json"] == []


@pytest.mark.parametrize("invalid", [{1: "x"}, {"x": (1, 2)}, {"x": {1, 2}}])
async def test_non_json_values_zero_requests(registry, invalid):
    c = AsyncMock()
    with pytest.raises(ValueError):
        await lane.create_policy_engine_rule(c, registry, "my-console", "Default", invalid)
    assert not c.mock_calls
    assert not registry.resolve_key_for_host.mock_calls


async def test_reset_carries_captured_command_body(registry):
    c = AsyncMock()
    await lane.reset_dpi_counters(c, registry, "my-console", "Default")
    assert c.delete.call_args.kwargs["json"] == {"cmd": "reset-dpi"}


@pytest.mark.parametrize("fn,method,path,args", CASES)
async def test_secondary_key_forwarded_without_default_fallback(fn, method, path, args, registry):
    selected = "synthetic-secondary-key"
    registry.resolve_key_for_host.return_value = selected
    c = AsyncMock()
    stub_reads(c, args)
    await fn(c, registry, "my-console", "Default", **args)
    registry.resolve_host_id.assert_awaited_once_with("my-console", key=selected)
    resolver = (
        registry.resolve_site_id
        if fn is lane.update_predefined_firewall_policy
        else registry.resolve_site_slug
    )
    resolver.assert_awaited_once_with("Default", "test-host", key=selected)
    assert c.mock_calls[-1].kwargs["key"] == selected


@pytest.mark.parametrize("fn,method,path,args", WRITE_CASES)
async def test_read_only_writes_refused_without_http(fn, method, path, args, registry, monkeypatch):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    c, transport = real_client(lambda _: pytest.fail("read-only sent HTTP"), read_only=True)
    async with transport:
        with pytest.raises(Exception, match="read.only|READ_ONLY"):
            await fn(c, registry, "my-console", "Default", **args)


def test_write_only_tests_take_every_write_case_and_reads_run_elsewhere():
    """WRITE_CASES and READ_CASES partition CASES; every read case runs in the shared tests."""
    assert WRITE_CASES and READ_CASES
    assert sorted(map(id, WRITE_CASES + READ_CASES)) == sorted(map(id, CASES))
    shared = (
        test_exact_route_and_verbatim_body,
        test_upstream_error_never_rewritten_or_truncated,
        test_secondary_key_forwarded_without_default_fallback,
    )
    for test in shared:
        (cases,) = [
            mark.args[1]
            for mark in test.pytestmark
            if mark.name == "parametrize" and mark.args[0] == "fn,method,path,args"
        ]
        assert all(case in cases for case in READ_CASES), test.__name__


def test_masked_field_drop_is_recorded_once():
    from unifi_fabric import redaction

    dropped = []
    token = redaction._dropped_masked_fields.set(dropped)
    try:
        with redaction.write_redaction_scope(True):
            assert lane._body({"name": "v", "password": redaction.REDACTION_MASK}) == {"name": "v"}
    finally:
        redaction._dropped_masked_fields.reset(token)
    assert dropped == ["password"]


def test_preview_policy_engine_rule_states_its_network_minimum():
    # Advertised label: the console version that serves the route, and what GA answers.
    import asyncio

    from unifi_fabric import server

    tools = {tool.name: tool for tool in asyncio.run(server.mcp.list_tools())}
    description = tools["preview_policy_engine_rule"].description or ""
    assert "Network 11.1.11 or later; 11.0.89 answered 405 and the 11.0.99" in description
    assert len(description) <= 2048


async def test_preview_description_and_405_error_name_the_same_versions(registry):
    """The tool description and the 405 error text read one version constant."""
    async with Client(server.mcp) as mcp_client:
        tools = {t.name: t for t in await mcp_client.list_tools()}
    description = tools["preview_policy_engine_rule"].description
    assert f"{lane.PREVIEW_RULE_405_VERSION} answered 405" in description
    assert f"Network {lane.PREVIEW_RULE_MIN_VERSION} or later" in description

    def handler(request):
        return httpx.Response(405, text="Method Not Allowed")

    client, transport = real_client(handler)
    async with transport:
        with pytest.raises(UniFiHTTPError) as caught:
            await lane.preview_policy_engine_rule(
                client, registry, "my-console", "Default", {"enabled": False}
            )
    message = str(caught.value)
    assert f"Network {lane.PREVIEW_RULE_405_VERSION} answered HTTP 405" in message
    assert f"Network {lane.PREVIEW_RULE_MIN_VERSION} frontend" in message
