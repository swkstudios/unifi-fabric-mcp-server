"""Real catalog regression: the relay accepts every JSON value verbatim."""

import asyncio
import json

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh
from unifi_fabric import server

NAMES = ("fabric_connector_post", "fabric_connector_put", "fabric_connector_patch")
BODIES = ({}, [], [{"enabled": True}], "hello", 7, 1.25, True, False, None)


def args(name, body, path="network/api/s/{site}/rest/networkconf/test-id"):
    return {
        **tool_args.generated_args(cti.TOOLS[name]),
        "path": path,
        "body": body,
        "params": {"example": "query"},
    }


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("body", BODIES)
async def test_catalog_relay_forwards_every_json_value(monkeypatch, name, body):
    up = uh.FakeUpstream()
    await cti._call(monkeypatch, name, up, args(name, body))
    writes = [s for s in up.served if s.method == name.rsplit("_", 1)[-1].upper()]
    assert len(writes) == 1
    assert writes[0].sent_json == body
    assert type(writes[0].sent_json) is type(body)
    assert "example=query" in writes[0].query


@pytest.mark.parametrize("name", NAMES)
async def test_catalog_array_dry_run_preview(monkeypatch, name):
    up = uh.FakeUpstream()
    result = await cti._call(
        monkeypatch, name, up, args(name, []), env={"UNIFI_WRITE_POLICY": "dry-run"}
    )
    payload = json.loads(result.content[0].text)
    assert payload["status"] == "dry_run"
    assert payload["body"]["preview"]["body"] == []
    assert payload["body"]["preview"]["params"] == {"example": "query"}
    assert payload.get("noOp") is None
    assert "changed" not in payload
    assert not [s for s in up.served if s.method != "GET"]


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize(
    ("env", "path"),
    [
        ("UNIFI_WRITE_POLICY", "network/api/s/{site}/rest/networkconf/test-id"),
        ("family:connector=deny", "network/api/s/{site}/rest/networkconf/test-id"),
        ("family:protect=deny", "protect/api/cameras/test-id"),
        ("family:mobility=deny", "mobility/api/test-id"),
        ("family:carrier=deny", "carrier/api/test-id"),
        ("family:innerspace=deny", "innerspace/api/test-id"),
    ],
)
async def test_catalog_array_optouts_before_resolution(monkeypatch, name, env, path):
    up = uh.FakeUpstream()
    setting = (
        {"UNIFI_WRITE_POLICY": "deny"}
        if env == "UNIFI_WRITE_POLICY"
        else {"UNIFI_WRITE_EXCEPTIONS": env}
    )
    with pytest.raises(ToolError, match=env):
        await cti._call(monkeypatch, name, up, args(name, [], path), env=setting)
    assert up.served == []


@pytest.fixture(scope="module")
def catalog_schemas():
    """The tools/list input schemas, built once per module (not at import)."""
    return {t.name: t.parameters for t in asyncio.run(server.mcp.list_tools())}


@pytest.mark.parametrize("name", NAMES)
async def test_real_catalog_json_schema_and_description(name):
    tool = next(t for t in await server.mcp.list_tools() if t.name == name)
    body = tool.parameters["properties"]["body"]
    assert "$ref" not in body
    kinds = {branch.get("type") for branch in body["anyOf"]}
    assert kinds == {"object", "array", "string", "number", "boolean", "null"}
    assert "JSON" in body["description"]
    assert len(tool.description) <= 2048


def test_no_tool_schema_has_ref_or_defs(catalog_schemas):
    offenders = [
        name
        for name, schema in catalog_schemas.items()
        if "$ref" in json.dumps(schema) or "$defs" in json.dumps(schema)
    ]
    assert offenders == []


@pytest.mark.parametrize("name", NAMES)
async def test_catalog_array_error_scrubs_configured_secret(monkeypatch, name):
    up = uh.FakeUpstream(mode="error", error_body="operator key k-test")
    result = await cti._call(monkeypatch, name, up, args(name, [{"value": 7}]))
    assert "k-test" not in str(result)
    assert "operator key" in str(result)


@pytest.mark.parametrize("name", NAMES)
async def test_catalog_array_dry_run_opt_in_redaction(monkeypatch, name):
    up = uh.FakeUpstream()
    result = await cti._call(
        monkeypatch,
        name,
        up,
        args(name, [{"password": "synthetic-value"}]),
        env={"UNIFI_WRITE_POLICY": "dry-run", "UNIFI_REDACT_SECRETS": "1"},
    )
    assert "synthetic-value" not in str(result)
    assert not [s for s in up.served if s.method != "GET"]


@pytest.mark.parametrize("name", NAMES)
async def test_catalog_array_invalid_json_before_resolution(monkeypatch, name):
    up = uh.FakeUpstream()
    with pytest.raises(ToolError, match="finite"):
        await cti._call(monkeypatch, name, up, args(name, [float("nan")]))
    assert up.served == []


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("explicit", [True, False])
async def test_catalog_null_wire_body_differs_from_omitted(monkeypatch, name, explicit):
    class WireUpstream(uh.FakeUpstream):
        def __call__(self, req):
            if req.method != "GET":
                self.wire_body = req.content
                self.wire_content_type = req.headers.get("content-type")
            return super().__call__(req)

    up = WireUpstream()
    call_args = args(name, None)
    if not explicit:
        del call_args["body"]
    await cti._call(monkeypatch, name, up, call_args)
    assert up.wire_body == (b"null" if explicit else b"")
    assert up.wire_content_type == ("application/json" if explicit else None)


@pytest.mark.parametrize("name", NAMES)
def test_catalog_unrestricted_body_secret_probe_stays_nonvacuous(name):
    probe_args, injected = cti._secret_args(cti.TOOLS[name], "synthetic-secret-probe")
    assert "body" in injected
    assert probe_args["body"]["x_passphrase"] == "synthetic-secret-probe"
