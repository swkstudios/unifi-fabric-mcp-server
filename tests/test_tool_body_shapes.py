"""Catalog-wide advisory shapes and non-tightening acceptance properties."""

from __future__ import annotations

import json
import os
import random
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from typing import Any

import jsonschema

from tests import test_spec_conformance as sc
from tests import tool_shapes_gen as gen

BASE = Path(__file__).parent / "fixtures/tool_input_schemas_pre_shapes.json"
ROOT = Path(__file__).resolve().parents[1]

#: Run outside pytest, as ``python -m tests.tool_shapes_gen --write`` runs: no conftest has
#: loaded the deferred steps (public #41), so the server starts with snapshot stubs.
_OUTSIDE_PYTEST = textwrap.dedent(
    """
    import asyncio, json, sys
    from unifi_fabric import server
    from unifi_fabric.catalog import deferred
    from tests import test_spec_conformance as sc, tool_shapes_gen as gen

    cold = asyncio.run(server.mcp.list_tools())
    tools = sc._tools()
    name, arg = sys.argv[1].split(".")
    model = gen.handler_model(tools[name], arg)
    print(json.dumps({
        "cold_stubs": sum(isinstance(t, deferred.DeferredTool) for t in cold),
        "stubs": sorted(n for n, t in tools.items() if isinstance(t, deferred.DeferredTool)),
        "model": f"{model.__module__}.{model.__qualname__}",
    }))
    """
)


def object_branch(schema: dict[str, Any]) -> dict[str, Any]:
    if schema.get("type") == "object":
        return schema
    return next(b for b in schema["anyOf"] if b.get("type") == "object")


def test_the_generator_reads_handlers_without_the_test_conftest() -> None:
    """``python -m tests.tool_shapes_gen --write`` failed with "'DeferredTool' object has no
    attribute 'fn'": the suite passed only because conftest loads every deferred step. The
    catalog the generator reads must be the loaded one in a fresh interpreter too."""
    from unifi_fabric.generated_api_facts._tool_shapes_table import SHAPE_SOURCES

    key = next(k for k, v in SHAPE_SOURCES.items() if v["classification"] == "handler-typed")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("UNIFI_", "MCP_", "FASTMCP_"))}
    done = subprocess.run(  # noqa: S603 - fixed interpreter and test-controlled code
        [sys.executable, "-c", _OUTSIDE_PYTEST, key],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr[-4000:]
    out = json.loads(done.stdout.strip().splitlines()[-1])
    assert out["cold_stubs"] > 0, "the server registered eagerly: nothing deferred was tested"
    assert out["stubs"] == []
    assert out["model"] == SHAPE_SOURCES[key]["model"]


def test_every_spec_backed_body_has_generated_properties() -> None:
    table, inventory = gen.derive()
    # 40 spec-backed bodies: the 39 of 505843cf plus update_predefined_firewall_policy
    # (7ac16050). The inventory is every object parameter of the registered catalog:
    # 231 since 0.7.2 (236 with the two port-automation bodies, the two Protect 7.4.96 external
    # arm profile bodies and diagnose_wifi.thresholds), down from 236 by the five
    # object parameters of removed tools
    # (calibrate_door_lock.options, set_door_lock_auto_close.options,
    # create_traffic_rule.payload, update_traffic_rule.payload and
    # update_protect_user_notifications.changes).
    assert len(table) == 42
    assert len(inventory) == 236
    tools = sc._tools()
    for name, args in table.items():
        for arg, shape in args.items():
            actual = object_branch(tools[name].parameters["properties"][arg])
            assert actual.get("properties") == shape["properties"], f"{name}.{arg}"
            assert actual["additionalProperties"] is True


def test_free_form_params_are_explicit_and_remain_unshaped() -> None:
    _, inventory = gen.derive()
    assert len(inventory) == 236  # see test_every_spec_backed_body_has_generated_properties
    assert any(source["classification"] == "free-form" for source in inventory.values())
    # Typed selectors coexist with retained native bodies in the merged caller contract.
    for key in (
        "create_recognition_group.group",
        "update_recognition_group.changes",
        "assign_detections_to_recognition_group.assignment",
        "merge_recognition_groups.merge",
    ):
        assert inventory[key]["classification"] == "free-form", key
    tools = sc._tools()
    for key, source in inventory.items():
        if source["classification"] != "free-form":
            continue
        name, arg = key.split(".")
        prop = tools[name].parameters["properties"][arg]
        assert "free-form" in prop["description"].lower(), key
        branch = object_branch(prop)
        assert not branch.get("properties"), key
        # Absent additionalProperties is JSON Schema's permissive default (true): the
        # relay bodies typed as any JSON value (9eaa2c6e) carry a bare {"type": "object"}.
        assert branch.get("additionalProperties", True) is True, key


def test_network_query_parameters_remain_optional_free_form_inventory() -> None:
    baseline = json.loads(BASE.read_text())["schemas"]
    _, inventory = gen.derive()
    tools = sc._tools()
    for name in ("get_poe_info", "get_traffic_stats"):
        assert "params" in baseline[name]["properties"]
        schema = tools[name].parameters
        assert set(schema["required"]) == {"host", "site"}
        prop = schema["properties"]["params"]
        assert prop["default"] is None
        assert any(branch.get("type") == "null" for branch in prop["anyOf"])
        assert object_branch(prop).get("additionalProperties", True) is True
        assert inventory[f"{name}.params"]["classification"] == "free-form"


def _assert_universal(schema: dict[str, Any]) -> None:
    # Structural proof: ONLY optional properties, permissive additionalProperties/items
    # and an anyOf containing {}. This accepts ALL JSON, beyond the samples below.
    assert set(schema) <= {"description", "anyOf", "properties", "items", "additionalProperties"}
    if "anyOf" in schema:
        assert schema["anyOf"][-1] == {}
        assert set(schema["anyOf"][0]) == {"type"}
    if "additionalProperties" in schema:
        assert schema["additionalProperties"] is True
    if "description" in schema:
        assert schema["description"].strip()
    for child in schema.get("properties", {}).values():
        assert child["anyOf"][0]["type"]
        _assert_universal(child)
    if "items" in schema:
        _assert_universal(schema["items"])


def test_generated_fragments_cannot_add_any_refusal() -> None:
    table, _ = gen.derive()
    for args in table.values():
        for shape in args.values():
            _assert_universal(shape)


def _property_depth(schema: dict[str, Any]) -> int:
    nested = [*schema.get("properties", {}).values()]
    if "items" in schema:
        return _property_depth(schema["items"])
    return 1 + max(map(_property_depth, nested)) if nested else 0


def test_shapes_are_bounded_and_deeper_fields_are_outlined() -> None:
    # Real properties stop at PROPERTY_DEPTH; a structured field at the boundary
    # carries its whole subtree as a compact outline instead (names stay visible).
    table, _ = gen.derive()
    for name, args in table.items():
        for arg, shape in args.items():
            assert _property_depth(shape) <= gen.PROPERTY_DEPTH, f"{name}.{arg}"
    policy = table["create_firewall_policy"]["policy"]["properties"]
    outline = policy["source"]["description"]
    for field in ("zoneId", "trafficFilter", "networkFilter", "networkIds", "'NETWORK'"):
        assert field in outline, field
    assert "{type:'ALLOW',allowReturnTraffic:boolean}" in policy["action"]["description"]
    network = table["create_network"]["network_config"]["description"]
    assert "Variants by management: GATEWAY (" in network


def test_shape_provenance_names_spec_route_and_pointer() -> None:
    from unifi_fabric.generated_api_facts._tool_shapes_table import SHAPE_SOURCES

    shaped = {k: v for k, v in SHAPE_SOURCES.items() if v["classification"] == "shaped"}
    assert len(shaped) == 42  # one per spec-backed body (test above)
    for key, source in shaped.items():
        assert {"file", "sha256", "source_url", "path", "method", "pointer", "schema"} <= set(
            source
        ), key
        assert source["pointer"].endswith("/content/application~1json/schema"), key
        target: Any = sc.specs()[source["service"]].doc
        for part in source["pointer"].lstrip("#/").split("/"):
            target = target[part.replace("~1", "/").replace("~0", "~")]
        assert target == source["schema"], key


def test_generator_output_is_current() -> None:
    from unifi_fabric.generated_api_facts._tool_shapes_table import SHAPE_SOURCES, TOOL_SHAPES

    table, inventory = gen.derive()
    assert TOOL_SHAPES == table
    assert SHAPE_SOURCES == inventory


def _json_value(rng: random.Random, depth: int = 0) -> Any:
    atoms = [None, True, False, -1, 0, 1, 1e100, "", "unexpected", " "]
    if depth >= 3 or rng.randrange(3) == 0:
        return rng.choice(atoms)
    if rng.randrange(2):
        return [_json_value(rng, depth + 1) for _ in range(rng.randrange(4))]
    return {f"key{i}": _json_value(rng, depth + 1) for i in range(rng.randrange(4))}


#: Spec-shaped bodies of tools added after the immutable pre-shape oracle (Protect 7.4.96).
SHAPED_AFTER_ORACLE = {
    "create_external_arm_profile.settings",
    "update_external_arm_profile.settings",
}


def test_every_previously_accepted_body_still_passes_input_validator() -> None:
    # Immutable pre-shape oracle, independent of the regenerated fixture.
    before = json.loads(BASE.read_text())["schemas"]
    tools = sc._tools()
    table, _ = gen.derive()
    rng = random.Random(17)  # noqa: S311 - reproducible non-security test data
    for name, shaped in table.items():
        for arg, shape in shaped.items():
            if f"{name}.{arg}" in SHAPED_AFTER_ORACLE:
                continue
            old = before[name]["properties"][arg]
            new = tools[name].parameters["properties"][arg]
            samples = [{}, sc.conformance_args(name)[arg], {"unknown": "passed-through"}]
            for prop in shape["properties"]:
                for value in [None, False, -1, 1e100, "", "unknown-enum", [], {}, [None]]:
                    samples.append({prop: value})
                samples.extend({prop: _json_value(rng)} for _ in range(20))
            accepted = 0
            for value in samples:
                if not jsonschema.Draft202012Validator(old).is_valid(value):
                    continue
                accepted += 1
                jsonschema.Draft202012Validator(new).validate(value)
            assert accepted > 0, name


def test_published_discriminator_subtypes_are_visible() -> None:
    from unifi_fabric.generated_api_facts._tool_shapes_table import TOOL_SHAPES

    props = TOOL_SHAPES["create_network"]["network_config"]["properties"]
    assert "ipv4Configuration" in props
    assert "internetAccessEnabled" in props
    assert "management" in props


def test_original_body_validation_contract_is_preserved_for_whole_catalog() -> None:
    from tests.test_tool_schema_contract import _strip_descriptions

    baseline = json.loads(BASE.read_text())["schemas"]
    table, inventory = gen.derive()
    tools = sc._tools()
    additions = {
        key
        for key in inventory
        if key not in SHAPED_AFTER_ORACLE
        and (
            key.split(".")[0] not in baseline
            or key.split(".")[1] not in baseline[key.split(".")[0]]["properties"]
        )
    }
    for key in SHAPED_AFTER_ORACLE:
        assert inventory[key]["classification"] == "shaped", key
    assert additions == {
        "get_multicast_insights.body",
        "create_firewall_rule.rule",
        "diagnose_wifi.thresholds",
        "create_port_automation.automation",
        "update_port_automation.automation",
    }
    # Scope the immutable oracle to all body/object parameters, including free-form
    # ones. Unrelated scalar parameters may evolve deliberately in other changes.
    for key in inventory:
        name, arg = key.split(".")
        current = json.loads(json.dumps(tools[name].parameters["properties"][arg]))
        if key in SHAPED_AFTER_ORACLE:
            continue
        if key == "create_firewall_rule.rule":
            # This tool postdates the immutable pre-shapes oracle. Its private EA
            # request has no fixed schema: require an object but permit every field.
            assert inventory[key]["classification"] == "free-form"
            assert arg in tools[name].parameters["required"]
            assert _strip_descriptions(current) == {"type": "object", "additionalProperties": True}
            continue
        if key in additions:
            assert inventory[key]["classification"] == "free-form"
            validator = jsonschema.Draft202012Validator(current)
            for value in (
                {},
                {"future": {"nested": [1, None, True]}, "x_passphrase": "***REDACTED***"},
            ):
                assert validator.is_valid(value), value
            optional = {"get_multicast_insights.body", "diagnose_wifi.thresholds"}
            assert validator.is_valid(None) == (key in optional)
            continue
        if inventory[key]["classification"] == "recorded-typed":
            assert key == "update_device_radio.radios"
            _assert_radio_validation_contract(tools[name])
            continue
        if arg in table.get(name, {}):
            object_branch(current).pop("properties")
        if key == "update_nvr.settings":
            field = "recordingRetentionDurationMs"
            old_field = _strip_descriptions(baseline[name]["properties"][arg]["properties"][field])
            new_field = _strip_descriptions(current["properties"][field])
            assert old_field == {"anyOf": [{"type": "string"}, {"type": "null"}], "default": None}
            assert new_field == {
                "anyOf": [{"type": "integer"}, {"type": "string"}, {"type": "null"}],
                "default": None,
            }
            current["properties"][field]["anyOf"].remove({"type": "integer"})
        assert _strip_descriptions(current) == _strip_descriptions(
            baseline[name]["properties"][arg]
        ), key


def test_shapes_are_advertised_on_the_wire() -> None:
    import asyncio

    from fastmcp import Client

    from unifi_fabric import server

    async def listed() -> dict[str, Any]:
        async with Client(server.mcp) as client:
            return {tool.name: tool.input_schema for tool in await client.list_tools()}

    original = server._settings
    server._settings = server.Settings(api_key="test-key-not-used", tool_mode="full")
    try:
        advertised = asyncio.run(listed())
    finally:
        server._settings = original
    table, _ = gen.derive()
    for name, args in table.items():
        for arg, shape in args.items():
            assert (
                object_branch(advertised[name]["properties"][arg])["properties"]
                == shape["properties"]
            )


def test_enum_notes_include_every_value_without_hidden_truncation() -> None:
    values = [f"protocol-{i}" for i in range(40)]
    for separator in ("|", ", "):
        assert gen.enum_text(values, separator) == separator.join(gen.lit(v) for v in values)
    spec = next(iter(sc.specs().values()))
    schema = {"type": "string", "enum": values}
    assert gen.outline(spec, schema, frozenset()) == "|".join(gen.lit(v) for v in values)
    description = gen.advisory(spec, schema, "protocol")["description"]
    for value in values:
        assert gen.lit(value) in description


def _spec_required(spec: Any, raw: Any, seen: frozenset[str] = frozenset()) -> set[str]:
    """A schema's ``required`` names, its allOf bases' included, read from the pinned spec."""
    node, seen = gen.resolve(spec, raw, seen)
    names = set(node.get("required") or [])
    for base in node.get("allOf") or []:
        names |= _spec_required(spec, base, seen)
    return names


def test_every_discriminated_variant_states_its_required_keys() -> None:
    # A shaped body whose top level is a discriminated union lists each variant; the
    # keys a variant requires beyond the common Required list come from the spec's own
    # ``required`` lists, so an AI client can build any variant without guessing.
    _, inventory = gen.derive()
    tools = sc._tools()
    specs = sc.specs()
    checked: dict[str, int] = {}
    for key, source in sorted(inventory.items()):
        if source["classification"] != "shaped":
            continue
        spec = specs[source["service"]]
        node, seen = gen.resolve(spec, source["schema"], frozenset())
        tag, alts = gen.variants(spec, node)
        if not (tag and alts):
            continue
        name, arg = key.split(".")
        text = tools[name].parameters["properties"][arg]["description"]
        base = _spec_required(spec, node)
        assert f"Required: {', '.join(sorted(base))}." in text, key
        for label, branch in alts:
            extra = sorted(_spec_required(spec, branch) - base - {tag})
            if extra:
                assert f"{label} (requires {', '.join(extra)}" in text, f"{key} {label}"
            else:
                assert f"{label} (requires" not in text, f"{key} {label}"
            checked[key] = checked.get(key, 0) + 1
    assert {"create_wifi_broadcast.broadcast", "update_wifi_broadcast.broadcast"} <= set(checked)
    assert {"create_network.network_config", "update_network.network_config"} <= set(checked)
    text = tools["create_wifi_broadcast"].parameters["properties"]["broadcast"]["description"]
    assert (
        "STANDARD (requires advertiseDeviceName, arpProxyEnabled, broadcastingFrequenciesGHz, "
        "bssTransitionEnabled" in text
    )


def _assert_radio_validation_contract(tool: Any) -> None:
    from typing import Literal

    from pydantic import TypeAdapter

    from tests.test_tool_schema_contract import _strip_descriptions
    from unifi_fabric.families.devices.device_radios import RadioChanges

    current = json.loads(json.dumps(tool.parameters["properties"]["radios"]))
    expected = TypeAdapter(dict[Literal["ng", "na", "6e"], RadioChanges]).json_schema()
    # FastMCP 4 inlines references and removes titles, which are annotations.
    # Compare every validator, including the complete referenced radio model.
    radio = expected.pop("$defs")["RadioChanges"]
    radio.pop("title")
    for prop in radio["properties"].values():
        prop.pop("title")
    expected["additionalProperties"] = radio
    assert _strip_descriptions(current) == _strip_descriptions(expected)


def test_recorded_radio_shape_has_provenance_and_preserves_typed_contract() -> None:
    import hashlib

    from unifi_fabric.families.devices.device_radios import RadioChanges

    table, inventory = gen.derive()
    typed = {
        key: source
        for key, source in inventory.items()
        if source["classification"] == "recorded-typed"
    }
    assert set(typed) == {"update_device_radio.radios"}
    source = typed["update_device_radio.radios"]
    captured = (gen.ROOT / source["file"]).read_bytes()
    assert hashlib.sha256(captured).hexdigest() == source["sha256"]
    record = json.loads(captured)
    assert source["method"] == record["request"]["method"] == "GET"
    assert source["path"] == record["request"]["path"]
    rows = record
    for part in source["pointer"].lstrip("#/").split("/"):
        rows = rows[int(part)] if isinstance(rows, list) else rows[part]
    assert source["bands"] == sorted(row["radio"] for row in rows) == ["6e", "na", "ng"]
    assert (
        source["fields"]
        == sorted(RadioChanges.model_fields)
        == sorted(["channel", "ht", "tx_power_mode", "tx_power", "min_rssi_enabled", "min_rssi"])
    )
    assert all(set(source["fields"]) <= set(row) for row in rows)
    assert "update_device_radio" not in table
    _assert_radio_validation_contract(sc._tools()["update_device_radio"])


def test_generator_rejects_ambient_settings(monkeypatch):
    import pytest

    monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    with pytest.raises(RuntimeError, match="ambient"):
        gen.require_clean_environment()


def test_note_preserves_abbreviations():
    from tests.tool_shapes_gen import note

    assert note("Currency, e.g. USD. Another sentence.") == "Currency, e.g. USD."
    assert note("Currency, i.e. USD. Another sentence.") == "Currency, i.e. USD."


def test_the_generator_cli_runs_on_an_instant_pacing_clock():
    # python -m tests.tool_shapes_gen sends hundreds of stubbed calls to one console; on the
    # real clock the connector pacer would wait out a minute after 95 sends (the move tool runs
    # the generator this way). The suite's conftest installs the same clock for pytest. The
    # command line starts on the real clock; here that clock's sleeper fails at once, so the
    # burst passes only if install_instant_pacing replaced it.
    import asyncio

    from tests import tool_shapes_gen
    from unifi_fabric import pacing

    async def real_sleep(seconds: float) -> None:
        raise AssertionError(f"the pacer slept {seconds:.1f}s on the real clock")

    try:
        pacing.set_time_source(time.monotonic, real_sleep)  # the command line starts here
        pacing.reset_registry()
        tool_shapes_gen.install_instant_pacing()
        limiter = pacing.limiter_for("console-a", 5)

        async def burst() -> None:
            for _ in range(12):
                await limiter.acquire()

        asyncio.run(burst())
    finally:
        pacing.set_time_source(None, None)
        pacing.reset_registry()
