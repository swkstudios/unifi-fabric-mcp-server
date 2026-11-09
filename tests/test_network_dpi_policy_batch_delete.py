"""Hermetic coverage for the three typed batch-delete tools (ACL rules, firewall policies,
firewall zones) of the network_dpi_policy module.

Provenance (live-verified on the dev console, Network 11.0.89, 2026-10-28): the v2
``{collection}/batch-delete`` routes key on the private ``_id``. With Integration ids the
``acl-rules`` route answers 404 ``api.err.AclRuleNotFound`` and the ``firewall-policies`` and
``firewall/zone`` routes answer 204 while nothing is removed. The Integration DELETE per id
does remove the record. The tools therefore delete per id and read the list back. The fake
console below reproduces exactly that behaviour with synthetic ids.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest

from tests.test_network_dpi_policy import real_client
from unifi_fabric import server
from unifi_fabric._read_only_audit import derive_write_tools
from unifi_fabric.client import RateLimitError, UniFiClient, UniFiConnectionError, UniFiHTTPError
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.tools import network_dpi_policy as lane


@pytest.fixture(autouse=True)
def _write_policy_env_reset(monkeypatch):
    """Start every test without a write policy (``real_client`` sets one for its modes)."""
    # setenv first so the teardown removes a value a helper set directly in os.environ
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "allow")
    monkeypatch.delenv("UNIFI_WRITE_POLICY")


V2 = "/v1/connector/consoles/test-host/proxy/network/v2/api/site/default"
IDS = ["0b6e1d8a-2f4c-4d7e-9a31-5c8f7e2b1a90", "0b6e1d8a-2f4c-4d7e-9a31-5c8f7e2b1a91"]
V2_IDS = ["65f1c0ffee0123456789abcd", "65f1c0ffee0123456789abce"]
#: (tool, v2 route collection, list tool named in the unknown-id error)
TOOLS = [
    ("batch_delete_acl_rules", "acl-rules", "list_acl_rules"),
    ("batch_delete_firewall_zones", "firewall/zone", "list_firewall_zones_proxy"),
]
POLICIES = "batch_delete_firewall_policies"
SITE_UUID = "00000000-0000-3000-a000-000000000016"
INTEGRATION = f"/v1/connector/consoles/test-host/proxy/network/integration/v1/sites/{SITE_UUID}"
IMPLS = {
    "batch_delete_acl_rules": lane._batch_delete_acl_rules,
    "batch_delete_firewall_policies": lane._batch_delete_firewall_policies,
    "batch_delete_firewall_zones": lane._batch_delete_firewall_zones,
}


@asynccontextmanager
async def real_key_client(handler, monkeypatch):
    """Keep real key selection and pool headers; replace only the HTTP transport."""
    constructor = httpx.AsyncClient

    def with_transport(**kwargs):
        return constructor(**kwargs, transport=httpx.MockTransport(handler))

    monkeypatch.setattr(httpx, "AsyncClient", with_transport)
    client = UniFiClient(Settings(api_key="synthetic-default-key"))
    try:
        yield client
    finally:
        await client.close()


@pytest.fixture(autouse=True)
def catalog_lifespan(_reset_server_singletons, monkeypatch):
    monkeypatch.setattr(server, "_settings", server.Settings(api_key="batch-delete-test-key"))


@pytest.fixture
def registry():
    return SimpleNamespace(
        resolve_key_for_host=AsyncMock(return_value=None),
        resolve_host_id=AsyncMock(return_value="test-host"),
        resolve_site_slug=AsyncMock(return_value="default"),
        resolve_site_id=AsyncMock(return_value=SITE_UUID),
    )


class FakeConsole:
    """The observed console. The v2 records carry the Integration id as ``external_id``; the
    batch route keys on ``_id``. An Integration id posted to it removes nothing: the ACL route
    answers 404 AclRuleNotFound, the policy and zone routes answer 204."""

    def __init__(self, collection: str, *, kind: str = "ok", extra: tuple[str, ...] = ()) -> None:
        self.collection = collection
        self.kind = kind  # "ok" removes; "stuck" answers 204 and removes nothing
        self.rows = [
            {"_id": v2, "external_id": ext, "name": f"synthetic-{n}"}
            for n, (v2, ext) in enumerate(zip(V2_IDS, IDS, strict=True))
        ] + [{"_id": e, "external_id": f"ext-{e}", "name": "keep"} for e in extra]
        self.requests: list[httpx.Request] = []
        self.accepted_body: Any = None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if request.method == "GET" and path == f"{V2}/{self.collection}":
            return httpx.Response(200, json=self.rows)
        if request.method == "POST" and path == f"{V2}/{self.collection}/batch-delete":
            body = json.loads(request.content)
            self.accepted_body = body
            known = {r["_id"] for r in self.rows}
            if not set(body) <= known:
                if self.collection == "acl-rules":
                    return httpx.Response(
                        404,
                        json={"code": "api.err.AclRuleNotFound", "message": "ACL rule not found"},
                    )
                return httpx.Response(204)  # accepted, nothing removed
            if self.kind == "ok":
                self.rows = [r for r in self.rows if r["_id"] not in body]
            return httpx.Response(204)
        raise AssertionError(f"unexpected {request.method} {path}")

    def posts(self) -> list[httpx.Request]:
        return [r for r in self.requests if r.method == "POST"]


@pytest.mark.parametrize("tool,collection,list_tool", TOOLS)
async def test_translates_integration_ids_to_v2_ids_and_reads_back(
    tool, collection, list_tool, registry
):
    console = FakeConsole(collection, extra=("keep-me",))
    c, transport = real_client(console)
    async with transport:
        result = await IMPLS[tool](c, registry, "my-console", "Default", IDS)
    assert [r["_id"] for r in console.rows] == ["keep-me"]  # the records are really gone
    assert console.accepted_body == V2_IDS  # a bare array of the private _id values
    assert result["deleted"] is True
    assert set(result) == {"deleted", "message", "response"}
    assert result["response"] is None  # the empty upstream body, verbatim
    assert [r.method for r in console.requests] == ["GET", "POST", "GET"]


@pytest.mark.parametrize("tool,collection,list_tool", TOOLS)
async def test_a_v2_id_is_accepted_as_given(tool, collection, list_tool, registry):
    console = FakeConsole(collection)
    c, transport = real_client(console)
    async with transport:
        result = await IMPLS[tool](c, registry, "my-console", "Default", [V2_IDS[0], IDS[1]])
    assert console.accepted_body == V2_IDS and result["deleted"] is True


@pytest.mark.parametrize("tool,collection,list_tool", TOOLS)
@pytest.mark.parametrize(
    "body",
    [
        {"data": {"deleted": 2}, "httpStatusCode": 200, "traceId": "synthetic-trace"},
        [{"id": f"x{i}"} for i in range(301)],
        "text",
    ],
)
async def test_the_upstream_body_is_returned_verbatim(tool, collection, list_tool, body, registry):
    console = FakeConsole(collection)

    def handler(request):
        if request.method == "POST":
            console(request)
            return httpx.Response(200, json=body)
        return console(request)

    c, transport = real_client(handler)
    async with transport:
        result = await IMPLS[tool](c, registry, "my-console", "Default", IDS)
    assert result["response"] == body and result["deleted"] is True


@pytest.mark.parametrize("tool,collection,list_tool", TOOLS)
async def test_an_accepted_batch_that_removes_nothing_is_not_reported_as_deleted(
    tool, collection, list_tool, registry
):
    # The live behaviour of the old code: a 2xx answer with the records still listed.
    console = FakeConsole(collection, kind="stuck")
    c, transport = real_client(console)
    async with transport:
        result = await IMPLS[tool](c, registry, "my-console", "Default", IDS)
    assert result["deleted"] is False
    assert all(i in result["message"] for i in IDS)
    assert result["response"] is None
    assert set(result) == {"deleted", "message", "response"}


@pytest.mark.parametrize("tool,collection,list_tool", TOOLS)
async def test_a_failed_read_back_is_reported_not_swallowed(tool, collection, list_tool, registry):
    console = FakeConsole(collection)
    reads = []

    def handler(request):
        if request.method == "GET":
            reads.append(request)
            if len(reads) > 1:
                return httpx.Response(500, json={"message": "synthetic read failure"})
        return console(request)

    c, transport = real_client(handler)
    async with transport:
        result = await IMPLS[tool](c, registry, "my-console", "Default", IDS)
    assert result["deleted"] is False
    assert "unverified" in result["message"]
    assert "synthetic read failure" in result["readAfterError"]


@pytest.mark.parametrize("tool,collection,list_tool", TOOLS)
async def test_an_unknown_id_fails_with_the_valid_ids_and_sends_no_write(
    tool, collection, list_tool, registry
):
    console = FakeConsole(collection)
    c, transport = real_client(console)
    async with transport:
        with pytest.raises(ValueError, match=f"not found; valid: .*{IDS[0]}.*{list_tool}"):
            await IMPLS[tool](c, registry, "my-console", "Default", [IDS[0], "absent-id"])
    assert console.posts() == []


@pytest.mark.parametrize("tool,collection,list_tool", TOOLS)
async def test_an_empty_list_sends_no_request(tool, collection, list_tool, registry):
    console = FakeConsole(collection)
    c, transport = real_client(console)
    async with transport:
        result = await IMPLS[tool](c, registry, "my-console", "Default", [])
    assert console.requests == []
    assert result["deleted"] is False


@pytest.mark.parametrize("tool,collection,list_tool", TOOLS)
async def test_dry_run_sends_no_write_and_previews_the_translated_array(
    tool, collection, list_tool, registry
):
    console = FakeConsole(collection)

    def handler(request):
        if request.method != "GET":
            raise AssertionError("dry-run sent a write")
        return console(request)

    c, transport = real_client(handler, dry_run=True)
    async with transport:
        result = await IMPLS[tool](c, registry, "my-console", "Default", IDS)
    assert result["status"] == "dry_run" and result["deleted"] is False and result["message"]
    preview = result["response"]
    assert not {"verified", "noOp"} & result.keys()
    assert preview["status"] == "dry_run"
    assert preview["preview"] == {
        "method": "POST",
        "path": f"{V2}/{collection}/batch-delete",
        "params": None,
        "body": V2_IDS,
        "keyLabel": "default",
    }
    assert preview["sent"] is False
    assert [r.method for r in console.requests] == ["GET"]  # no read-back either


@pytest.mark.parametrize("tool,collection,list_tool", TOOLS)
@pytest.mark.parametrize(
    "bad",
    [
        "not-a-list",
        None,
        {"ids": IDS},
        5,
        [""],
        ["  "],
        [" lead"],
        ["trail "],
        ["a\nb"],
        [1],
        [None],
    ],
)
async def test_invalid_ids_make_zero_requests(tool, collection, list_tool, bad, registry):
    c = AsyncMock()
    with pytest.raises(ValueError):
        await IMPLS[tool](c, registry, "my-console", "Default", bad)
    assert not c.mock_calls
    registry.resolve_key_for_host.assert_not_awaited()
    registry.resolve_site_slug.assert_not_awaited()


@pytest.mark.parametrize("tool,collection,list_tool", TOOLS)
@pytest.mark.parametrize(
    "selector,bad", [("host", ""), ("host", " name "), ("site", ""), ("site", "Default\n")]
)
async def test_invalid_selectors_precede_resolution(
    tool, collection, list_tool, selector, bad, registry
):
    c = AsyncMock()
    selectors = {"host": "my-console", "site": "Default", selector: bad}
    with pytest.raises(ValueError):
        await IMPLS[tool](c, registry, **selectors, ids=IDS)
    assert not c.mock_calls
    registry.resolve_key_for_host.assert_not_awaited()


@pytest.mark.parametrize("tool,collection,list_tool", TOOLS)
async def test_read_only_refuses_the_write_after_only_reading(
    tool, collection, list_tool, registry, monkeypatch
):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    console = FakeConsole(collection)
    c, transport = real_client(console, read_only=True)
    async with transport:
        with pytest.raises(Exception, match="read.only|READ_ONLY"):
            await IMPLS[tool](c, registry, "my-console", "Default", IDS)
    assert [r.method for r in console.requests] == ["GET"] and len(console.rows) == 2


@pytest.mark.parametrize("tool,collection,list_tool", TOOLS)
async def test_secondary_key_is_forwarded_without_default_fallback(
    tool, collection, list_tool, registry, monkeypatch
):
    selected = APIKeyConfig(key="synthetic-secondary-key", label="secondary")
    registry.resolve_key_for_host.return_value = selected
    console = FakeConsole(collection)
    async with real_key_client(console, monkeypatch) as c:
        await IMPLS[tool](c, registry, "my-console", "Default", IDS)
    assert [r.method for r in console.requests] == ["GET", "POST", "GET"]
    assert all(r.headers["X-API-KEY"] == selected.key for r in console.requests)
    registry.resolve_host_id.assert_awaited_with("my-console", key=selected)
    registry.resolve_site_slug.assert_awaited_with("Default", "test-host", key=selected)


class FakeIntegration:
    """The Integration policy routes: DELETE removes a record, GET lists them. A v2 policy
    record carries no Integration id, so only these routes can address the ids."""

    def __init__(self, *, stuck: tuple[str, ...] = (), body: Any = None) -> None:
        self.present = list(IDS) + ["keep-me"]
        self.stuck = stuck  # accepted (200) but not removed
        self.body = body
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        base = f"{INTEGRATION}/firewall/policies"
        if request.method == "GET" and path.startswith(base + "/"):
            target = path.rsplit("/", 1)[1]
            if target in self.present:
                return httpx.Response(200, json={"id": target, "name": "synthetic"})
            return httpx.Response(404, json={"code": "api.resource-not-found"})
        if request.method == "DELETE" and path.startswith(base + "/"):
            target = path.rsplit("/", 1)[1]
            if target not in self.present:
                return httpx.Response(404, json={"code": "api.resource-not-found"})
            if target not in self.stuck:
                self.present.remove(target)
            return (
                httpx.Response(200, json=self.body)
                if self.body is not None
                else httpx.Response(200)
            )
        raise AssertionError(
            f"the private v2 batch route must not be used: {request.method} {path}"
        )


async def test_policies_are_deleted_per_id_through_the_integration_api_and_read_back(registry):
    console = FakeIntegration()
    c, transport = real_client(console)
    async with transport:
        result = await lane._batch_delete_firewall_policies(
            c, registry, "my-console", "Default", IDS
        )
    assert console.present == ["keep-me"]  # really gone
    assert result["deleted"] is True and set(result) == {"deleted", "message", "response"}
    assert result["response"] is None  # identical empty bodies, verbatim
    deletes = [r for r in console.requests if r.method == "DELETE"]
    assert [r.url.path for r in deletes] == [f"{INTEGRATION}/firewall/policies/{i}" for i in IDS]
    assert [r.method for r in console.requests] == [
        "DELETE",
        "DELETE",
        "GET",
        "GET",
    ]  # then read back


async def test_policy_upstream_bodies_are_returned_verbatim(registry):
    console = FakeIntegration(body={"data": {"deleted": 1}})
    c, transport = real_client(console)
    async with transport:
        one = await lane._batch_delete_firewall_policies(
            c, registry, "my-console", "Default", IDS[:1]
        )
    assert one["response"] == {"data": {"deleted": 1}} and one["deleted"] is True


async def test_an_accepted_policy_delete_that_removes_nothing_is_not_reported_as_deleted(registry):
    console = FakeIntegration(stuck=(IDS[1],))
    c, transport = real_client(console)
    async with transport:
        result = await lane._batch_delete_firewall_policies(
            c, registry, "my-console", "Default", IDS
        )
    assert result["deleted"] is False
    assert IDS[1] in result["message"] and IDS[0] not in result["message"]


async def test_a_failing_policy_delete_raises_naming_what_was_and_was_not_done(registry):
    console = FakeIntegration()
    c, transport = real_client(console)
    async with transport:
        with pytest.raises(Exception, match="HTTP 404") as raised:
            await lane._batch_delete_firewall_policies(
                c, registry, "my-console", "Default", [IDS[0], "absent-id", IDS[1]]
            )
    assert f"Deleted before this failure: ['{IDS[0]}']" in str(raised.value)
    assert f"not attempted: ['{IDS[1]}']" in str(raised.value)
    assert console.present == [IDS[1], "keep-me"]


async def test_a_single_failing_policy_delete_raises_the_upstream_error_as_is(registry):
    c, transport = real_client(FakeIntegration())
    async with transport:
        with pytest.raises(Exception, match="HTTP 404") as raised:
            ids = ["absent"]
            await lane._batch_delete_firewall_policies(c, registry, "my-console", "Default", ids)
    assert "Deleted before" not in str(raised.value)


async def test_a_failed_policy_read_back_is_reported_not_swallowed(registry):
    console = FakeIntegration()

    def handler(request):
        if request.method == "GET":
            return httpx.Response(500, json={"message": "synthetic read failure"})
        return console(request)

    c, transport = real_client(handler)
    async with transport:
        result = await lane._batch_delete_firewall_policies(
            c, registry, "my-console", "Default", IDS
        )
    assert result["deleted"] is False and "unverified" in result["message"]
    assert "synthetic read failure" in result["readAfterError"]


async def test_policy_dry_run_sends_nothing(registry):
    def handler(request):
        raise AssertionError("dry-run sent HTTP")

    c, transport = real_client(handler, dry_run=True)
    async with transport:
        many = await lane._batch_delete_firewall_policies(c, registry, "my-console", "Default", IDS)
        one = await lane._batch_delete_firewall_policies(
            c, registry, "my-console", "Default", IDS[:1]
        )
    assert many["status"] == "dry_run" and many["deleted"] is False
    assert not {"verified", "noOp"} & many.keys()
    assert not {"verified", "noOp"} & one.keys()
    expected = [
        {
            "method": "DELETE",
            "path": f"{INTEGRATION}/firewall/policies/{identifier}",
            "params": None,
            "body": None,
            "keyLabel": "default",
        }
        for identifier in IDS
    ]
    assert [item["preview"] for item in many["response"]] == expected
    assert all(item["sent"] is False for item in many["response"])
    assert one["status"] == "dry_run" and one["deleted"] is False
    assert one["response"]["preview"] == expected[0]
    assert one["response"]["sent"] is False


@pytest.mark.parametrize(
    "bad", ["not-a-list", None, {"ids": IDS}, [""], [" lead"], ["a/b"], ["../x"], [1]]
)
async def test_invalid_policy_ids_make_zero_requests(bad, registry):
    c = AsyncMock()
    with pytest.raises(ValueError):
        await lane._batch_delete_firewall_policies(c, registry, "my-console", "Default", bad)
    assert not c.mock_calls
    registry.resolve_key_for_host.assert_not_awaited()


@pytest.mark.parametrize("selector,bad", [("host", ""), ("site", "Default\n")])
async def test_invalid_policy_selectors_precede_resolution(selector, bad, registry):
    c = AsyncMock()
    selectors = {"host": "my-console", "site": "Default", selector: bad}
    with pytest.raises(ValueError):
        await lane._batch_delete_firewall_policies(c, registry, **selectors, ids=IDS)
    assert not c.mock_calls


async def test_catalog_lists_the_tools_with_schema_and_derived_write_annotations():
    tools = {tool.name: tool for tool in await server.mcp.list_tools()}
    for name in IMPLS:
        tool = tools[name]
        assert tool.description and len(tool.description) <= 2048
        hints = tool.annotations.model_dump(by_alias=True)
        assert hints["readOnlyHint"] is False and hints["destructiveHint"] is True
        props = tool.parameters["properties"]
        assert set(props) == {"host", "site", "ids"} and tool.parameters["required"] == [
            "host",
            "site",
            "ids",
        ]
        assert props["ids"]["type"] == "array" and props["ids"]["items"]["type"] == "string"
        assert all(p.get("description") for p in props.values())
        flat = " ".join(tool.description.split())
        assert "read back" in flat


def test_the_three_tools_are_derived_writes():
    tools = [SimpleNamespace(name=n, fn=fn) for n, fn in IMPLS.items()]
    assert derive_write_tools(tools) == set(IMPLS)


#: Class check: every POST ``batch-delete`` / ``batch_delete`` route of the
#: pinned Network inventory is reached by a typed tool. A new inventory route fails here
#: until a tool is added (or it is listed with its reason).
INVENTORY_BATCH_DELETE_TOOLS = {
    "acl-rules/batch-delete": "batch_delete_acl_rules",
    "firewall-policies/batch-delete": "batch_delete_firewall_policies",
    "firewall/zone/batch-delete": "batch_delete_firewall_zones",
    "qos-rules/batch-delete": "delete_qos_rule",
    "radius/users/batch_delete": "delete_radius_account",
    "wireguard/{}/users/batch_delete": "delete_wireguard_users",
}


async def test_every_batch_delete_tool_of_the_class_is_registered():
    names = {tool.name for tool in await server.mcp.list_tools()}
    assert set(INVENTORY_BATCH_DELETE_TOOLS.values()) <= names


async def test_members_group_schema_remains_free_form_and_examples_are_valid():
    tools = {tool.name: tool for tool in await server.mcp.list_tools()}
    for name in ("create_network_members_group", "update_network_members_group"):
        group = tools[name].parameters["properties"]["group"]
        assert group["type"] == "object"
        assert group["additionalProperties"] is True
        assert not group.get("properties")
        assert "USERS" in group["description"] and "CLIENTS" in group["description"]
        assert "IPV4" not in group["description"].replace("including IPV4", "")
        assert "'type': 'CLIENTS'" in group["description"]


@pytest.mark.parametrize("name", ["create_network_members_group", "update_network_members_group"])
async def test_members_group_unusual_fields_reach_upstream_and_error_is_preserved(name):
    from fastmcp import FastMCP

    from unifi_fabric.client import UniFiHTTPError

    sent: list[httpx.Request] = []
    body = {
        "name": 7,
        "members": {"future": [1, None]},
        "type": "FUTURE",
        "extra": {"nested": [True, None]},
    }

    def handler(request):
        sent.append(request)
        if request.method == "GET":
            return httpx.Response(200, json=[{"id": "g1", "old": "preserved"}])
        return httpx.Response(400, json={"message": "upstream rejects synthetic group"})

    c, transport = real_client(handler)
    reg = SimpleNamespace(
        resolve_key_for_host=AsyncMock(return_value=None),
        resolve_host_id=AsyncMock(return_value="test-host"),
        resolve_site_slug=AsyncMock(return_value="default"),
    )
    mcp = FastMCP("members-group-contract")
    lane.register(mcp, lambda: (c, reg))
    args = {"host": "my-console", "site": "Default", "group": body}
    if name.startswith("update"):
        args["group_id"] = "g1"
    async with transport:
        with pytest.raises(UniFiHTTPError, match="upstream rejects synthetic group") as exc:
            await mcp.call_tool(name, args)
    assert exc.value.status == 400
    writes = [request for request in sent if request.method in ("POST", "PUT")]
    assert len(writes) == 1
    actual = json.loads(writes[0].content)
    for key, value in body.items():
        assert actual[key] == value
    if name.startswith("create"):
        assert actual == body
    else:
        assert actual == {"id": "g1", "old": "preserved", **body}


async def test_members_group_body_with_private_fields_is_sent_verbatim():
    sent: list[httpx.Request] = []

    def handler(request):
        sent.append(request)
        return httpx.Response(200, json={"id": "g1"})

    c, transport = real_client(handler)
    reg = SimpleNamespace(
        resolve_key_for_host=AsyncMock(return_value=None),
        resolve_host_id=AsyncMock(return_value="test-host"),
        resolve_site_slug=AsyncMock(return_value="default"),
    )
    body = {"name": "T", "members": ["aa:bb:cc:dd:ee:01"], "type": "CLIENTS", "extra": 1}
    async with transport:
        await lane.create_network_members_group(c, reg, "my-console", "Default", body)
    assert json.loads(sent[0].content) == body


# Restored wire-level controls from the bounded assertion adjudication.
@pytest.mark.parametrize("tool,collection,list_tool", TOOLS)
async def test_batch_upstream_failure_is_preserved_without_retry(
    tool, collection, list_tool, registry
):
    console = FakeConsole(collection)

    def handler(request):
        if request.method == "POST":
            console.requests.append(request)
            return httpx.Response(500, json={"message": "synthetic upstream failure"})
        return console(request)

    c, transport = real_client(handler)
    async with transport:
        with pytest.raises(UniFiHTTPError, match="synthetic upstream failure") as raised:
            await IMPLS[tool](c, registry, "my-console", "Default", IDS)
    assert raised.value.status == 500
    assert [r.method for r in console.requests] == ["GET", "POST"]
    assert len(console.rows) == 2


async def test_policy_secondary_key_reaches_every_delete_and_readback(registry, monkeypatch):
    selected = APIKeyConfig(key="synthetic-secondary-key", label="secondary")
    registry.resolve_key_for_host.return_value = selected
    console = FakeIntegration()
    async with real_key_client(console, monkeypatch) as c:
        result = await lane._batch_delete_firewall_policies(
            c, registry, "my-console", "Default", IDS
        )
    assert result["deleted"] is True
    assert [r.method for r in console.requests] == ["DELETE", "DELETE", "GET", "GET"]
    assert all(r.headers["X-API-KEY"] == selected.key for r in console.requests)
    assert console.present == ["keep-me"]


async def test_read_only_policy_batch_refuses_before_any_write(registry, monkeypatch):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    console = FakeIntegration()
    c, transport = real_client(console, read_only=True)
    async with transport:
        with pytest.raises(Exception, match="read.only|READ_ONLY"):
            await lane._batch_delete_firewall_policies(c, registry, "my-console", "Default", IDS)
    assert console.requests == []
    assert console.present == IDS + ["keep-me"]


@pytest.mark.parametrize("dry_run", [False, True])
async def test_empty_policy_batch_is_accepted_without_any_request(registry, dry_run):
    console = FakeIntegration()
    c, transport = real_client(console, dry_run=dry_run)
    async with transport:
        result = await lane._batch_delete_firewall_policies(
            c, registry, "my-console", "Default", []
        )
    assert result["deleted"] is (not dry_run)
    assert result["response"] == []
    assert "no writes" in result["message"].lower()
    assert not {"verified", "noOp"} & result.keys()
    if dry_run:
        assert result["status"] == "dry_run"
    assert console.requests == []
    assert console.present == IDS + ["keep-me"]


@pytest.mark.parametrize("tool", list(IMPLS))
async def test_empty_batch_never_addresses_or_removes_an_existing_record(tool, registry):
    collection = next((row[1] for row in TOOLS if row[0] == tool), None)
    console = FakeConsole(collection) if collection else FakeIntegration()
    c, transport = real_client(console)
    async with transport:
        result = await IMPLS[tool](c, registry, "my-console", "Default", [])
    assert result["deleted"] is (collection is None)
    if collection:
        assert console.requests == []
        assert len(console.rows) == 2
    else:
        assert console.requests == []
        assert console.present == IDS + ["keep-me"]


@pytest.mark.parametrize("stuck", [False, True])
@pytest.mark.parametrize("failure", ["http", "transport"])
async def test_policy_partial_failure_has_truthful_wire_accounting_without_retry(
    registry, stuck, failure
):
    console = FakeIntegration(stuck=(IDS[0],) if stuck else ())
    later = "not-attempted"

    def handler(request):
        if request.method == "DELETE" and request.url.path.endswith("/" + IDS[1]):
            console.requests.append(request)
            if failure == "transport":
                raise httpx.ConnectError("synthetic transport failure", request=request)
            return httpx.Response(500, json={"message": "synthetic upstream failure"})
        return console(request)

    c, transport = real_client(handler)
    async with transport:
        with pytest.raises(UniFiConnectionError) as raised:
            await lane._batch_delete_firewall_policies(
                c, registry, "my-console", "Default", [*IDS, later]
            )
    message = str(raised.value)
    assert f"Deleted before this failure: {'none' if stuck else [IDS[0]]}" in message
    assert f"still present: {[IDS[0]] if stuck else 'none'}" in message
    assert "unverified: none" in message
    assert f"failed/uncertain: {[IDS[1]]}" in message
    assert f"not attempted: {[later]}" in message
    assert [r.method for r in console.requests] == ["DELETE", "DELETE", "GET"]
    assert console.requests[-1].url.path.endswith("/" + IDS[0])
    assert raised.value.__cause__ is not None
    assert raised.value.status == (500 if failure == "http" else None)
    assert console.present == (IDS if stuck else IDS[1:]) + ["keep-me"]


async def test_registered_empty_policy_dry_run_never_claims_deletion(registry):
    from fastmcp import FastMCP

    console = FakeIntegration()
    client, transport = real_client(console, dry_run=True)
    mcp = FastMCP("empty-policy-dry-run")
    lane.register(mcp, lambda: (client, registry))
    tools = {tool.name: tool for tool in await mcp.list_tools()}
    async with transport:
        result = await tools[POLICIES].fn(host="my-console", site="Default", ids=[])
    assert result["status"] == "dry_run"
    assert result["deleted"] is False
    assert result["response"] == []
    assert "no writes" in result["message"].lower()
    assert not {"verified", "noOp"} & result.keys()
    assert console.requests == []
    assert console.present == IDS + ["keep-me"]


@pytest.mark.parametrize("fail_index", [0, 1])
@pytest.mark.parametrize("stuck", [False, True])
@pytest.mark.parametrize("registered", [False, True])
async def test_policy_batch_retains_rate_limit_class_status_and_truthful_progress(
    registry, fail_index, stuck, registered
):
    from fastmcp import FastMCP

    console = FakeIntegration(stuck=(IDS[0],) if stuck else ())

    def handler(request):
        if request.method == "DELETE" and request.url.path.endswith("/" + IDS[fail_index]):
            console.requests.append(request)
            return httpx.Response(429, json={"message": "synthetic-upstream-rate-limited"})
        return console(request)

    client, transport = real_client(handler)
    if registered:
        mcp = FastMCP("policy-batch-rate-limit")
        lane.register(mcp, lambda: (client, registry))
        tools = {tool.name: tool for tool in await mcp.list_tools()}
        invoke = tools[POLICIES].fn
    else:

        async def invoke(**kwargs):
            return await lane._batch_delete_firewall_policies(client, registry, **kwargs)

    async with transport:
        with pytest.raises(RateLimitError) as raised:
            await invoke(host="my-console", site="Default", ids=IDS)
    error = raised.value
    assert type(error) is RateLimitError
    assert error.status == 429
    assert type(error.__cause__) is RateLimitError
    assert error.__cause__.status == 429
    assert str(error.__cause__) in str(error)
    assert "synthetic-upstream-rate-limited" in str(error)
    removed = [IDS[0]] if fail_index == 1 and not stuck else "none"
    present = [IDS[0]] if fail_index == 1 and stuck else "none"
    assert f"Deleted before this failure: {removed}" in str(error)
    assert f"still present: {present}" in str(error)
    assert "unverified: none" in str(error)
    assert f"failed/uncertain: {[IDS[fail_index]]}" in str(error)
    assert f"not attempted: {IDS[fail_index + 1 :] or 'none'}" in str(error)
    assert [request.method for request in console.requests] == (
        ["DELETE"] * (fail_index + 1) + ["GET"] * fail_index
    )
    assert console.present == (IDS[1:] if fail_index == 1 and not stuck else IDS) + ["keep-me"]
