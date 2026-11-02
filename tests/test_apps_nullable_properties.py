"""Pinned request schemas drive explicit-null/omission checks across the tool catalog."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_catalog import LazyCatalog
from unifi_fabric import server

# This maps operations, not fields: newly nullable properties enter the sweep automatically.
OPERATIONS = {
    ("carrier-fabric", "post", "/v1/carrier/subscribers"): "create_carrier_subscriber",
    ("carrier-fabric", "patch", "/v1/carrier/subscribers/{id}"): "update_carrier_subscriber",
    ("protect", "patch", "/v1/viewers/{id}"): "update_viewer",
    ("protect", "patch", "/v1/cameras/{id}"): "update_camera",
    ("protect", "patch", "/v1/sensors/{id}"): "update_sensor",
    (
        "mobility",
        "put",
        "/v1/mobility/workspaces/{workspaceID}/devices/{deviceID}/network",
    ): "update_mobility_device_network",
    ("site-manager", "post", "/v1/isp-metrics/{type}/query"): "query_isp_metrics",
}
ALIASES = {"serviceAddress": "service_address", "planId": "plan_id"}


def _nullable_paths(spec: dict, schema: Any, path: tuple = (), seen: tuple = ()):
    if not isinstance(schema, dict):
        return
    if "$ref" in schema:
        ref = schema["$ref"]
        if ref in seen:
            return
        node: Any = spec
        for part in ref[2:].split("/"):
            node = node[part]
        yield from _nullable_paths(spec, node, path, (*seen, ref))
        return
    if schema.get("nullable") or "null" in schema.get("type", []):
        yield path
    for field, child in schema.get("properties", {}).items():
        yield from _nullable_paths(spec, child, (*path, field), seen)
    if "items" in schema:
        yield from _nullable_paths(spec, schema["items"], (*path, 0), seen)
    for combination in ("allOf", "oneOf", "anyOf"):
        for child in schema.get(combination, []):
            yield from _nullable_paths(spec, child, path, seen)


def _cases():
    cases = []
    for spec_path in sorted((Path(__file__).parent / "fixtures/openapi").glob("*.json")):
        spec = json.loads(spec_path.read_text())
        family = spec_path.stem.rsplit("-", 1)[0]
        for route, verbs in spec.get("paths", {}).items():
            for method, operation in verbs.items():
                if method not in {"post", "put", "patch", "delete"}:
                    continue
                body = (
                    operation.get("requestBody", {})
                    .get("content", {})
                    .get("application/json", {})
                    .get("schema", {})
                )
                paths = sorted(set(_nullable_paths(spec, body)), key=str)
                if paths:
                    key = (family, method, route)
                    assert key in OPERATIONS, f"Uncovered nullable write operation: {key}"
                    cases.extend((OPERATIONS[key], path) for path in paths)
    assert cases, "Pinned specs yielded no nullable fields"
    return cases


CASES = _cases()
TOOLS = LazyCatalog()


def _set_path(body: dict, path: tuple, value: Any):
    node = body
    for field in path[:-1]:
        node = node.setdefault(field, {})
    node[path[-1]] = value


def _present(body: Any, path: tuple) -> bool:
    for field in path:
        if isinstance(field, int):
            if not isinstance(body, list) or len(body) <= field:
                return False
        elif not isinstance(body, dict) or field not in body:
            return False
        body = body[field]
    return True


@pytest.mark.parametrize(("name", "path"), CASES, ids=lambda value: str(value))
@pytest.mark.parametrize("transport", ["mcp", "direct"])
@pytest.mark.parametrize("explicit", [False, True], ids=["omitted", "explicit-null"])
async def test_spec_nullable_fields_preserve_omission_and_null(
    monkeypatch, name, path, explicit, transport
):
    upstream = uh.FakeUpstream()
    client = uh.install(monkeypatch, upstream)
    args = tool_args.generated_args(TOOLS[name])
    for env, value in tool_args.TOOL_ENV.get(name, {}).items():
        monkeypatch.setenv(env, value)
    if name in {"update_camera", "update_sensor", "update_viewer"}:
        args["settings"] = {"name": "nullable-probe-renamed"}
        if explicit:
            _set_path(args["settings"], path, None)
    elif name == "query_isp_metrics":
        args.pop("host", None)
        args.pop("site", None)
        args["sites"] = [{"hostId": uh.HOST, "siteId": uh.SITE}]
        if explicit:
            args["sites"].insert(0, None)
    else:
        field = ALIASES.get(path[0], path[0])
        if name == "update_mobility_device_network":
            args["host_address" if field != "host_address" else "dhcp_mode"] = (
                "192.0.2.20" if field != "host_address" else "none"
            )
        if name == "update_carrier_subscriber":
            args["subscriber_number"] = "nullable-probe-renamed"
        args.pop(field, None)
        if explicit:
            args[field] = None
    try:
        if transport == "mcp":
            await server.mcp.call_tool(name, args)
        else:
            await getattr(server, name)(**args)
        writes = [
            request for request in upstream.served if request.method in {"POST", "PUT", "PATCH"}
        ]
        assert writes, f"{name}: no request reached upstream"
        body = writes[-1].sent_json
        if name == "query_isp_metrics":
            assert (None in body["sites"]) is explicit
            if explicit:
                assert body["sites"][0] is None
        else:
            assert _present(body, path) is explicit, (name, path, explicit, body)
            if explicit:
                value = body
                for field in path:
                    value = value[field]
                assert value is None, (name, path, body)
    finally:
        await client.close()
