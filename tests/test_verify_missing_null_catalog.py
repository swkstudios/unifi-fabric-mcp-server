"""Missing/null comparison follows each pinned response schema."""

from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest

from unifi_fabric.tools import _results, carrier_fabric, mobility, network_services_proxy, protect
from unifi_fabric.tools._results import requested_leaves_match


def _protect_callers():
    tree = ast.parse(Path(protect.__file__).read_text())
    return sorted(
        node.name
        for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef)
        and not node.name.startswith("_")
        and any(
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id in {"_update_item_verified", "requested_leaves_match"}
            for call in ast.walk(node)
        )
    )


@pytest.mark.parametrize("depth", range(1, 17))
def test_shared_missing_null_at_every_depth(depth):
    wanted = None
    present = None
    absent = {}
    for _ in range(depth):
        wanted = {"field": wanted}
        present = {"field": present}
    for _ in range(depth - 1):
        absent = {"field": absent}
    assert requested_leaves_match(wanted, present)
    assert not requested_leaves_match(wanted, absent)


@pytest.mark.parametrize("tool_name", _protect_callers())
@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("after_present", [False, True])
@pytest.mark.asyncio
async def test_every_protect_verifying_caller(tool_name, nested, after_present, monkeypatch):
    monkeypatch.delenv("UNIFI_WRITE_EXCEPTIONS", raising=False)  # protect writes allowed
    monkeypatch.setattr(protect, "_resolve", AsyncMock(return_value=(None, "host-synthetic")))
    fields = {"futureField": {"leaf": None} if nested else None}
    before = {"id": "profile-synthetic", **({"futureField": {}} if nested else {})}
    after = {**before, **fields} if after_present else before
    client = AsyncMock()
    client.dry_run = False
    client.get.side_effect = [before, after]
    patch = AsyncMock(return_value={"applied": True})
    monkeypatch.setattr(protect, "_patch", patch)
    monkeypatch.setattr(
        protect, "_find_arm_profile", AsyncMock(side_effect=[(before, []), (after, [])])
    )
    tool = getattr(protect, tool_name)
    args = [client, object(), "host-synthetic"]
    args += ["profile-synthetic"] * (len(inspect.signature(tool).parameters) - 4)
    result = await tool(*args, **fields)
    patch.assert_awaited_once()
    assert result["verified"] is after_present
    json.dumps(result)


@pytest.mark.parametrize("nested", [False, True])
def test_setting_comparison_distinguishes_null(nested):
    wanted = {"leaf": None} if nested else None
    missing = {} if nested else network_services_proxy._value_at({}, ("leaf",))
    assert not network_services_proxy._satisfies(missing, wanted)
    assert network_services_proxy._satisfies(wanted, wanted)


@pytest.mark.parametrize("wire", ["serviceAddress", "suspendReason", "futureField"])
def test_carrier_comparison_distinguishes_null(wire):
    assert carrier_fabric._field_matches({}, wire, None) is (wire != "futureField")
    assert carrier_fabric._field_matches({wire: None}, wire, None)


def test_mobility_verification_distinguishes_null():
    checks = {"host_address": ("host_address", None)}
    assert mobility._updated({}, checks, {}, {}, {}, None)["verified"] == {"host_address": False}
    assert mobility._updated({}, checks, {}, {"host_address": None}, {}, None)["verified"] == {
        "host_address": True
    }


@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("after_present", [False, True])
@pytest.mark.asyncio
async def test_network_setting_missing_null_caller(nested, after_present):
    payload = {"futureField": {"leaf": None} if nested else None}
    before = {"key": "synthetic", **({"futureField": {}} if nested else {})}
    after = {**before, **payload} if after_present else before
    client = AsyncMock()
    client.dry_run = False
    client.get.side_effect = [{"data": [before]}, {"data": [after]}]
    client.put.return_value = {"data": [{"applied": True}]}
    registry = AsyncMock()
    registry.resolve_host_id.return_value = "host-synthetic"
    registry.resolve_site_slug.return_value = "default"
    registry.resolve_key_for_host.return_value = None
    result = await network_services_proxy.update_setting(
        client, registry, "host-synthetic", "default", "synthetic", payload
    )
    assert result["data"] == [{"applied": True}]
    assert result["_verified"] is after_present
    if not after_present:
        assert result["_unverifiedFields"] == ["futureField.leaf" if nested else "futureField"]
        assert "silent no-op" in result["_verificationNote"]
    client.put.assert_awaited_once()


@pytest.mark.asyncio
async def test_carrier_detach_missing_host_neither_noop_nor_verified(monkeypatch):
    monkeypatch.setattr(carrier_fabric, "_require_writes", lambda method: None)
    before = {"id": "subscriber-synthetic"}
    client = AsyncMock()
    client.dry_run = False
    client.list_key_labels = Mock(return_value=["synthetic"])
    client.get.return_value = {"data": before}
    client.delete.return_value = {"data": before}
    result = await carrier_fabric.detach_carrier_subscriber_host(client, "subscriber-synthetic")
    client.delete.assert_awaited_once()
    assert result["verified"] is False
    json.dumps(result)


@pytest.mark.parametrize("field", ["name", "email", "notes", "service_address", "plan_id"])
@pytest.mark.parametrize("after_present", [False, True])
@pytest.mark.asyncio
async def test_carrier_nullable_update_fields(field, after_present, monkeypatch):
    monkeypatch.setattr(carrier_fabric, "_require_writes", lambda method: None)
    wire = {"service_address": "serviceAddress", "plan_id": "planId"}.get(field, field)
    before = {"id": "subscriber-synthetic", wire: "old"}
    after = {"id": "subscriber-synthetic"}
    if after_present:
        after[wire] = None
    client = AsyncMock()
    client.dry_run = False
    client.list_key_labels = Mock(return_value=["synthetic"])
    client.get.return_value = {"data": before}
    client.patch.return_value = {"data": after}
    result = await carrier_fabric.update_carrier_subscriber(
        client, "subscriber-synthetic", **{field: None}
    )
    client.patch.assert_awaited_once()
    assert result["verified"] is (after_present or field == "service_address")
    json.dumps(result)


@pytest.mark.asyncio
async def test_carrier_omitted_service_address_is_already_cleared(monkeypatch):
    monkeypatch.setattr(carrier_fabric, "_require_writes", lambda method: None)
    client = AsyncMock()
    client.dry_run = False
    client.list_key_labels = Mock(return_value=["synthetic"])
    client.get.return_value = {"data": {"id": "subscriber-synthetic"}}
    result = await carrier_fabric.update_carrier_subscriber(
        client, "subscriber-synthetic", service_address=None
    )
    assert result["status"] == "no_op"
    client.patch.assert_not_awaited()


def _spec_nullable_omissions():
    """Recursively derive nullable omitted response paths across every pinned spec."""
    derived = {}
    fixtures = Path(__file__).parent / "fixtures" / "openapi"
    for fixture in sorted(fixtures.glob("*.json")):
        document = json.loads(fixture.read_text())
        schemas = document.get("components", {}).get("schemas", {})

        def nullable(node, seen=frozenset(), document=document):
            if not isinstance(node, dict):
                return False
            types = node.get("type", [])
            if (
                node.get("nullable")
                or types == "null"
                or (isinstance(types, list) and "null" in types)
            ):
                return True
            ref = node.get("$ref")
            if ref and ref not in seen:
                target = document
                for part in ref.removeprefix("#/").split("/"):
                    target = target.get(part.replace("~1", "/").replace("~0", "~"), {})
                if nullable(target, seen | {ref}):
                    return True
            return any(
                nullable(branch, seen)
                for key in ("allOf", "anyOf", "oneOf")
                for branch in node.get(key, [])
            )

        def fields(node, path=()):
            if isinstance(node, dict):
                for field, definition in node.get("properties", {}).items():
                    yield (*path, field), definition
                    yield from fields(definition, (*path, field))
                for key in ("allOf", "anyOf", "oneOf"):
                    for branch in node.get(key, []):
                        yield from fields(branch, path)
                if "items" in node:
                    yield from fields(node["items"], (*path, "[]"))

        def nodes(node, path=()):
            if isinstance(node, dict):
                yield path, node
                for key, value in node.items():
                    yield from nodes(value, (*path, key))
            elif isinstance(node, list):
                for index, value in enumerate(node):
                    yield from nodes(value, (*path, str(index)))

        # Scan inline responses and request schemas too: no omitted nullable node
        # may disappear just because it is outside components/schemas.
        for path, node in nodes(document):
            description = node.get("description", "")
            if (
                isinstance(description, str)
                and "omitted" in description.casefold()
                and nullable(node)
            ):
                assert path[:2] == ("components", "schemas"), (fixture.name, path)

        for schema, definition in schemas.items():
            omitted = set()
            peers = {
                path: field
                for suffix in ("Create", "Patch")
                for path, field in fields(schemas.get(schema + suffix, {}))
            }
            for path, response in fields(definition):
                description = response.get("description", "")
                if not isinstance(description, str) or "omitted" not in description.casefold():
                    continue
                if nullable(response) or nullable(peers.get(path, {})):
                    omitted.add(path)
            if omitted:
                derived[(fixture.name, schema)] = frozenset(omitted)
    return derived


def test_omitted_null_table_matches_all_pinned_nullable_specs():
    expected = _spec_nullable_omissions()
    # resume clears this action-managed field by omitting it; no PATCH schema.
    fixture = Path(__file__).parent / "fixtures/openapi/carrier-fabric-1.0.0.json"
    reason = json.loads(fixture.read_text())["components"]["schemas"]["Subscriber"]["properties"][
        "suspendReason"
    ]
    assert "omitted (not null)" in reason["description"]
    key = (fixture.name, "Subscriber")
    expected[key] = expected[key] | {("suspendReason",)}
    assert _results.OMITTED_NULL_FIELDS == expected


@pytest.mark.parametrize(
    "entry",
    [
        (spec, schema, path)
        for (spec, schema), paths in _results.OMITTED_NULL_FIELDS.items()
        for path in sorted(paths)
    ],
)
@pytest.mark.parametrize("present", [False, True])
def test_spec_omitted_null_property(entry, present):
    spec, schema, path = entry
    field = path[0]
    actual = {field: None} if present else {}
    assert _results.requested_leaves_match({field: None}, actual, spec=spec, schema=schema)
    assert not _results.requested_leaves_match({field: "set"}, actual, spec=spec, schema=schema)
    assert not _results.requested_leaves_match({"unknown": None}, {}, spec=spec, schema=schema)
    assert not _results.requested_leaves_match(
        {field: None}, {}, spec="protect-7.3.74.json", schema=schema
    )
    assert not _results.requested_leaves_match(
        {"nested": {field: None}}, {"nested": {}}, spec=spec, schema=schema
    )
