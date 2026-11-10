"""Network body documentation stays aligned with the pinned upstream schema."""

from __future__ import annotations

import inspect
import json
import re
from itertools import product
from pathlib import Path

import pytest

from unifi_fabric.families.network import network
from unifi_fabric.shared_shapes._payload import integration_update_body

SPEC = json.loads((Path(__file__).parent / "fixtures/openapi/network-11.0.97.json").read_text())


def _branches(schema, seen=frozenset()):
    """Walk composed/discriminated schemas without following inheritance cycles."""
    if "$ref" in schema:
        ref = schema["$ref"]
        if ref in seen:
            return
        target = SPEC
        for part in ref[2:].split("/"):
            target = target[part]
        yield from _branches(target, seen | {ref})
    else:
        yield schema
        for branch in schema.get("allOf", []):
            yield from _branches(branch, seen)
        for ref in schema.get("discriminator", {}).get("mapping", {}).values():
            yield from _branches({"$ref": ref}, seen)


def _path_schemas(schema, path):
    if not path:
        return [schema]
    result = []
    for branch in _branches(schema):
        child = branch.get("properties", {}).get(path[0])
        if child is not None:
            result.extend(_path_schemas(child, path[1:]))
    return result


@pytest.mark.parametrize(
    "tool,path,method",
    [
        (network.create_network, "/v1/sites/{siteId}/networks", "post"),
        (network.update_network, "/v1/sites/{siteId}/networks/{networkId}", "put"),
        (network.create_wifi_broadcast, "/v1/sites/{siteId}/wifi/broadcasts", "post"),
        (
            network.update_wifi_broadcast,
            "/v1/sites/{siteId}/wifi/broadcasts/{wifiBroadcastId}",
            "put",
        ),
    ],
)
def test_network_body_paths_match_spec(tool, path, method):
    operation = SPEC["paths"][path][method]
    body = operation["requestBody"]["content"]["application/json"]["schema"]
    # Read-only response keys and function references are explicitly distinguished
    # from writable body fields; every other documented identifier is schema-derived.
    response_keys = {"id", "default", "metadata", "index"}
    function_names = {"get_network", "get_wifi_broadcast"}
    doc = inspect.getdoc(tool)
    tokens = re.findall(r"``([a-z][A-Za-z0-9_.]*)``", doc)
    assert tokens, tool.__name__
    for token in tokens:
        if token not in response_keys | function_names:
            assert _path_schemas(body, token.split(".")), (tool.__name__, token)
    assert "dns_servers" not in doc


def test_nested_dns_example_matches_schema_and_round_trips():
    doc = inspect.getdoc(network.update_network)
    body = SPEC["paths"]["/v1/sites/{siteId}/networks/{networkId}"]["put"]["requestBody"][
        "content"
    ]["application/json"]["schema"]
    paths = re.findall(r"``([a-z][A-Za-z0-9_]*\.[A-Za-z0-9_.]+)``", doc)
    assert len(paths) == 1
    leaf = _path_schemas(body, paths[0].split("."))
    assert any(
        node.get("type") == "array" and node.get("items", {}).get("type") == "string"
        for node in leaf
    )
    payload = {"management": "GATEWAY"}
    target = payload
    parts = paths[0].split(".")
    for part in parts[:-1]:
        target = target.setdefault(part, {})
    target[parts[-1]] = ["192.168.1.1", "", ""]
    result = integration_update_body("update_network", payload)
    cleaned = result
    for part in parts:
        cleaned = cleaned[part]
    assert cleaned == ["192.168.1.1"]
    assert target[parts[-1]] == ["192.168.1.1", "", ""]


@pytest.mark.parametrize(
    "addresses",
    [
        list(values)
        for size in range(1, 5)
        for values in product(("192.168.1.1", "192.0.2.53", ""), repeat=size)
    ],
)
def test_l15_h2_doc_dns_sanitizer_preserves_values_and_order(addresses):
    """Every schema-sized DNS list keeps all non-placeholder entries in order."""
    path = re.findall(
        r"``([a-z][A-Za-z0-9_]*\.[A-Za-z0-9_.]+)``", inspect.getdoc(network.update_network)
    )[0]
    payload = {"management": "GATEWAY"}
    target = payload
    parts = path.split(".")
    for part in parts[:-1]:
        target = target.setdefault(part, {})
    target[parts[-1]] = addresses.copy()
    result = integration_update_body("update_network", payload)
    cleaned = result
    for part in parts:
        cleaned = cleaned[part]
    assert cleaned == [address for address in addresses if address != ""]
    assert target[parts[-1]] == addresses
