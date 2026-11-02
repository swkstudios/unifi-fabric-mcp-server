"""L15-DRIFT regression tests for same-version schema changes."""

import json
from copy import deepcopy
from pathlib import Path

import pytest

from unifi_fabric._spec_drift import (
    _normalize_schema,
    _resolve_object,
    build_service_spec,
    build_snapshot,
    diff_service,
    diff_snapshot,
    snapshot_from_dict,
    snapshot_to_dict,
    strip_example_annotations,
)


def _doc(location="request"):
    schema = {"type": "object", "properties": {"mode": {"type": "string", "enum": ["OLD", "KEEP"]}}}
    op = {"operationId": "widgets", "responses": {"200": {}}}
    if location == "request":
        op["requestBody"] = {"content": {"application/json": {"schema": schema}}}
    elif location == "response":
        op["responses"]["200"] = {"content": {"application/json": {"schema": schema}}}
    else:
        op["parameters"] = [{"name": "filter", "in": "query", "schema": schema}]
    return {"info": {"version": "1"}, "paths": {"/v1/widgets": {"post": op}}}


def _schema(doc, location):
    op = doc["paths"]["/v1/widgets"]["post"]
    if location == "request":
        return op["requestBody"]["content"]["application/json"]["schema"]
    if location == "response":
        return op["responses"]["200"]["content"]["application/json"]["schema"]
    return op["parameters"][0]["schema"]


def _diff(old, new):
    return diff_service(
        "test",
        build_service_spec("test", "1", "http://test", old),
        build_service_spec("test", "1", "http://test", new),
    )


def _semantic_finding(diff):
    # Structural findings are independent; keep endpoint semantic polarity exact.
    (finding,) = [f for f in diff.changed_endpoints if not f.endpoint.startswith("DOCUMENT")]
    return finding


@pytest.mark.parametrize("location", ["request", "response", "parameter"])
@pytest.mark.parametrize(
    ("change", "path", "breaking"),
    [
        ("enum_add", ".properties.mode.enum", False),
        ("enum_remove", ".properties.mode.enum", True),
        ("required_add", ".required", True),
        ("type_change", ".properties.mode.type", True),
        ("field_remove", ".properties.mode", False),
        ("field_add", ".properties.extra", True),
    ],
)
def test_schema_change_without_version_bump(location, change, path, breaking):
    old = _doc(location)
    new = deepcopy(old)
    schema = _schema(new, location)
    if change == "enum_add":
        schema["properties"]["mode"]["enum"].append("NEW")
    elif change == "enum_remove":
        schema["properties"]["mode"]["enum"].remove("OLD")
    elif change == "required_add":
        schema["required"] = ["mode"]
    elif change == "type_change":
        schema["properties"]["mode"]["type"] = "integer"
    elif change == "field_remove":
        del schema["properties"]["mode"]
    else:
        schema["properties"]["extra"] = {"type": "string"}
    if location == "response" and change in {
        "enum_add",
        "enum_remove",
        "required_add",
        "field_remove",
        "field_add",
    }:
        breaking = change in {"enum_add", "field_remove"}
    diff = _diff(old, new)
    finding = _semantic_finding(diff)
    assert finding.breakage is breaking
    assert any(path in item for item in finding.changes)
    root = {"test": ("1", "http://test")}
    report = diff_snapshot(build_snapshot(root, {"test": old}), build_snapshot(root, {"test": new}))
    assert not report.is_clean
    assert "CHANGED" in report.summary()
    assert path in report.summary()
    assert ("BREAKAGE" in report.summary()) is breaking
    if change == "enum_add":
        assert '+["NEW"]' in report.summary()


def test_nested_ref_change_and_snapshot_round_trip():
    old = _doc()
    _schema(old, "request")["properties"]["mode"] = {"$ref": "#/components/schemas/Outer"}
    old["components"] = {
        "schemas": {
            "Outer": {
                "type": "object",
                "properties": {"nested": {"$ref": "#/components/schemas/Inner"}},
            },
            "Inner": {"type": "string", "enum": ["OLD"]},
        }
    }
    new = deepcopy(old)
    new["components"]["schemas"]["Inner"]["enum"].append("NEW")
    root = {"test": ("1", "http://test")}
    baseline = snapshot_from_dict(snapshot_to_dict(build_snapshot(root, {"test": old})))
    current = snapshot_from_dict(snapshot_to_dict(build_snapshot(root, {"test": new})))
    report = diff_snapshot(baseline, current)
    assert not report.is_clean
    assert ".properties.mode.properties.nested.enum" in report.summary()
    assert '+["NEW"]' in report.summary()


@pytest.mark.parametrize("location", ["request", "response", "parameter"])
def test_examples_and_descriptions_are_ignored(location):
    old = _doc(location)
    new = deepcopy(old)
    schema = _schema(new, location)
    schema.update(description="documentation", example={"mode": "NEW"}, examples=[{"mode": "NEW"}])
    schema["properties"]["mode"].update(description="prose", example="NEW", examples=["NEW"])
    new["paths"]["/v1/widgets"]["post"]["summary"] = "documentation"
    assert not _diff(old, new).changed_endpoints


def test_snapshot_projection_strips_only_example_annotations():
    document = _doc()
    schema = _schema(document, "request")
    schema["example"] = {"api_key": "sample-material"}
    schema["examples"] = [{"mac": "sample-material"}]
    schema["properties"]["example"] = {"type": "string", "example": "sample-material"}
    document["components"] = {"examples": {"Sample": {"value": "sample-material"}}}
    document["paths"]["/v1/widgets"]["post"]["requestBody"]["content"]["application/json"][
        "example"
    ] = {"token": "sample-material"}

    projected = strip_example_annotations(document)
    spec = build_service_spec("test", "1", "https://example.invalid", document)

    assert spec.raw_document == projected
    assert "example" not in projected["components"]
    projected_schema = _schema(projected, "request")
    assert "example" not in projected_schema and "examples" not in projected_schema
    assert projected_schema["properties"]["example"] == {"type": "string"}
    assert (
        "example"
        not in projected["paths"]["/v1/widgets"]["post"]["requestBody"]["content"][
            "application/json"
        ]
    )


@pytest.mark.parametrize("location", ["request", "response", "parameter"])
def test_raw_enum_reordering_requires_review(location):
    old = _doc(location)
    new = deepcopy(old)
    _schema(new, location)["properties"]["mode"]["enum"].reverse()
    findings = _diff(old, new).changed_endpoints
    assert findings
    assert all(f.breakage for f in findings)
    assert any("needs_review" in item for f in findings for item in f.changes)


def test_annotation_named_properties_are_semantic():
    old = _doc()
    new = deepcopy(old)
    _schema(new, "request")["properties"]["description"] = {"type": "string"}
    assert _diff(old, new).changed_endpoints


def test_path_level_and_referenced_parameters_are_signed():
    old = _doc()
    old["paths"]["/v1/widgets"]["parameters"] = [{"$ref": "#/components/parameters/Filter"}]
    old["components"] = {
        "parameters": {
            "Filter": {
                "name": "filter",
                "in": "query",
                "schema": {"type": "string", "enum": ["OLD"]},
            }
        }
    }
    new = deepcopy(old)
    new["components"]["parameters"]["Filter"]["schema"]["enum"].append("NEW")
    assert _diff(old, new).changed_endpoints


def test_unprojected_spec_info_version_change_requires_review(capsys, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    from check_spec_drift import _emit

    old = _doc()
    new = deepcopy(old)
    new["info"]["version"] = "0.0.0"
    root = {"protect": ("7.3.70", "http://test")}
    baseline = build_snapshot(root, {"protect": old})
    current = build_snapshot(root, {"protect": new})
    report = diff_snapshot(baseline, current)
    assert not report.is_clean
    assert "#/info/version needs_review" in report.summary()
    assert "BREAKAGE" in report.summary()
    assert "info.version 0.0.0" in report.summary()
    assert "llms.txt 7.3.70" in report.summary()
    assert snapshot_from_dict(snapshot_to_dict(current)) == current
    _emit(current)
    assert "info.version 0.0.0" in capsys.readouterr().out


def test_committed_full_specs_hydrate_baseline_and_review_reference_cycles():
    fixtures = Path(__file__).parent / "fixtures"
    manifest = json.loads((fixtures / "openapi/manifest.json").read_text())
    root = {name: (item["version"], item["source_url"]) for name, item in manifest.items()}
    docs = {
        name: json.loads((fixtures / "openapi" / item["file"]).read_text())
        for name, item in manifest.items()
    }
    baseline = snapshot_from_dict(
        json.loads((fixtures / "spec_drift/baseline_snapshot.json").read_text())
    )
    current = build_snapshot(root, docs)
    missing = diff_snapshot(baseline, current)
    assert not missing.is_clean
    assert "raw-document evidence missing on one side" in missing.summary()
    # Recover semantic contracts and raw evidence from the same pinned fixtures.
    hydrated = build_snapshot(root, docs, console_versions=baseline.console_versions)
    report = diff_snapshot(hydrated, current)
    assert report.is_clean
    changed_docs = deepcopy(docs)
    changed_docs["network"]["components"]["schemas"]["IntegrationIpAclRuleSubnetEndpointFilterDto"][
        "allOf"
    ][1]["properties"]["ipAddressesOrSubnets"]["items"]["minLength"] = 2
    report = diff_snapshot(hydrated, build_snapshot(root, changed_docs))
    assert not report.is_clean
    network = next(service for service in report.service_diffs if service.name == "network")
    assert any(f.kind == "CHANGED" and f.breakage for f in network.endpoint_findings)
    assert any(
        "IP ACL rule endpoint/discriminator/mapping/IP_ADDRESSES_OR_SUBNETS" in reason
        and "needs_review: reference" in reason
        for finding in network.endpoint_findings
        for reason in finding.breaking_changes
    )


@pytest.mark.parametrize("ring", [False, True])
def test_deep_reference_chains_do_not_crash(ring):
    old = _doc()
    schemas = {f"R{index}": {"$ref": f"#/components/schemas/R{index + 1}"} for index in range(249)}
    schemas["R249"] = {"$ref": "#/components/schemas/R0"} if ring else {"type": "string"}
    old["components"] = {"schemas": schemas}
    assert not _diff(old, deepcopy(old)).changed_endpoints
    if ring:
        new = deepcopy(old)
        new["components"]["schemas"]["R125"]["minLength"] = 2
        findings = _diff(old, new).changed_endpoints
        assert any(f.kind == "CHANGED" and f.breakage for f in findings)
        assert any("needs_review" in reason for f in findings for reason in f.breaking_changes)


def test_bare_name_discriminator_mapping_is_resolved():
    old = _doc()
    old["components"] = {
        "schemas": {
            "Base": {"discriminator": {"propertyName": "kind", "mapping": {"sub": "Sub"}}},
            "Sub": {"allOf": [{"$ref": "#/components/schemas/Base"}]},
            "Other": {"type": "string"},
        }
    }
    assert not _diff(old, deepcopy(old)).changed_endpoints
    for target in ("Missing", "Other", 7):
        new = deepcopy(old)
        new["components"]["schemas"]["Base"]["discriminator"]["mapping"]["sub"] = target
        findings = _diff(old, new).changed_endpoints
        assert any(f.kind == "CHANGED" and f.breakage for f in findings)
        assert any(
            "#/components/schemas/Base/discriminator/mapping/sub needs_review: reference" in reason
            for finding in findings
            for reason in finding.breaking_changes
        )
        if target in ("Missing", 7):
            assert _diff(new, deepcopy(new)).changed_endpoints


@pytest.mark.parametrize(
    "reference", ["#/components/schemas/Missing", "https://example.test/schema", 7]
)
def test_identical_unresolved_references_still_require_review(reference):
    old = _doc()
    _schema(old, "request")["properties"]["mode"] = {"$ref": reference}
    findings = _diff(old, deepcopy(old)).changed_endpoints
    assert findings and all(f.breakage for f in findings)
    assert any("needs_review" in reason for f in findings for reason in f.breaking_changes)


def _deep_reference_chain(links=250, terminal=None):
    document = _doc()
    schemas = {
        f"R{index}": {"$ref": f"#/components/schemas/R{index + 1}"} for index in range(links - 1)
    }
    schemas[f"R{links - 1}"] = terminal or {"type": "string", "enum": ["OLD", "KEEP"]}
    document["components"] = {"schemas": schemas}
    _schema(document, "request")["properties"]["mode"] = {"$ref": "#/components/schemas/R0"}
    return document


def _nested_properties(levels, leaf):
    schema = leaf
    for _ in range(levels):
        schema = {"type": "object", "properties": {"child": schema}}
    return schema


def _deep_properties_doc(levels, leaf):
    document = _doc()
    _schema(document, "request")["properties"]["mode"] = _nested_properties(levels, leaf)
    return document


def _breaking_reasons(diff):
    return [reason for f in diff.endpoint_findings for reason in f.breaking_changes]


def test_deep_referenced_schema_expansion_fails_safe():
    # Identical documents cannot drift, however long the used reference chain.
    old = _deep_reference_chain()
    assert not _diff(old, deepcopy(old)).endpoint_findings
    # A mutated deep region is still compared (alias links do not consume depth).
    new = _deep_reference_chain(terminal={"type": "integer"})
    diff = _diff(old, new)
    assert any(f.breakage for f in diff.endpoint_findings)
    assert _semantic_finding(diff).breaking_changes


def test_deep_reference_chain_compares_with_request_polarity():
    old = _deep_reference_chain()
    widened = _deep_reference_chain(terminal={"type": "string", "enum": ["OLD", "KEEP", "NEW"]})
    finding = _semantic_finding(_diff(old, widened))
    assert finding.changes and not finding.breaking_changes and not finding.breakage


def test_deep_reference_chain_with_dangling_link_still_requires_review():
    old = _deep_reference_chain()
    old["components"]["schemas"]["R100"] = {"$ref": "#/components/schemas/Missing"}
    findings = _diff(old, deepcopy(old)).endpoint_findings
    assert findings and all(f.breakage for f in findings)
    assert any("needs_review" in reason for f in findings for reason in f.breaking_changes)


def test_deep_reference_chain_cycle_is_compared_against_baseline():
    old = _deep_reference_chain(terminal={"$ref": "#/components/schemas/R0"})
    assert not _diff(old, deepcopy(old)).endpoint_findings
    changed = deepcopy(old)
    changed["components"]["schemas"]["R7"] = {"$ref": "#/components/schemas/R8", "minLength": 1}
    assert any(f.breakage for f in _diff(old, changed).endpoint_findings)


@pytest.mark.parametrize("levels", [32, 40, 63, 64, 70, 150])
def test_identical_deep_nested_properties_are_clean(levels):
    old = _deep_properties_doc(levels, {"type": "string"})
    assert not _diff(old, deepcopy(old)).endpoint_findings


@pytest.mark.parametrize("levels", [40, 63, 64, 70, 150])
def test_mutated_deep_nested_properties_are_breaking(levels):
    old = _deep_properties_doc(levels, {"type": "string"})
    new = _deep_properties_doc(levels, {"type": "integer"})
    assert any(f.breakage for f in _diff(old, new).endpoint_findings)


@pytest.mark.parametrize("levels", [70, 150])
def test_deep_region_beyond_bound_fails_safe_even_for_compatible_edits(levels):
    # A request enum widening is compatible when comparable. Beyond the expansion
    # bound the region cannot be compared, so any difference must fail safe.
    old = _deep_properties_doc(levels, {"type": "string", "enum": ["A"]})
    new = _deep_properties_doc(levels, {"type": "string", "enum": ["A", "B"]})
    diff = _diff(old, new)
    assert any(f.breakage for f in diff.endpoint_findings)
    assert any("needs_review" in reason for reason in _breaking_reasons(diff))


def test_deep_region_within_bound_keeps_semantic_polarity():
    old = _deep_properties_doc(40, {"type": "string", "enum": ["A"]})
    new = _deep_properties_doc(40, {"type": "string", "enum": ["A", "B"]})
    diff = _diff(old, new)
    assert diff.endpoint_findings
    assert not any(f.breakage for f in diff.endpoint_findings)


@pytest.mark.parametrize("container", ["example", "default", "const", "enum"])
def test_literal_discriminator_mapping_is_not_a_reference(container):
    payload = {"discriminator": {"propertyName": "kind", "mapping": {"a": "b"}}}
    old = _doc()
    mode = _schema(old, "request")["properties"]["mode"]
    mode[container] = [payload] if container == "enum" else payload
    assert not _diff(old, deepcopy(old)).endpoint_findings


def test_literal_discriminator_mapping_under_property_name_is_not_a_reference():
    old = _doc()
    properties = _schema(old, "request")["properties"]
    properties["discriminator"] = {"type": "object", "properties": {"mapping": {"type": "string"}}}
    assert not _diff(old, deepcopy(old)).endpoint_findings


def test_schema_discriminator_mapping_is_still_a_reference():
    old = _doc()
    old["components"] = {"schemas": {"Cat": {"type": "object"}}}
    schema = _schema(old, "request")
    schema["oneOf"] = [{"$ref": "#/components/schemas/Cat"}]
    schema["discriminator"] = {"propertyName": "kind", "mapping": {"cat": "Cat"}}
    assert not _diff(old, deepcopy(old)).endpoint_findings
    dangling = deepcopy(old)
    _schema(dangling, "request")["discriminator"]["mapping"]["dog"] = "Dog"
    for document in (dangling, deepcopy(dangling)):
        findings = _diff(dangling, document).endpoint_findings
        assert findings and all(f.breakage for f in findings)
        assert any("reference" in reason for f in findings for reason in f.breaking_changes)


def _nested_literal(levels, leaf="x"):
    value = leaf
    for _ in range(levels):
        value = {"a": value}
    return value


def _deep_document(position, levels, leaf="x"):
    document = _doc()
    if position == "default":
        _schema(document, "request")["properties"]["mode"]["default"] = _nested_literal(
            levels, leaf
        )
    elif position == "link":
        document["components"] = {"links": {"L": {"requestBody": _nested_literal(levels, leaf)}}}
    else:
        _schema(document, "request")["properties"]["mode"] = _nested_properties(
            levels, {"type": "string", "title": leaf}
        )
    return document


def _json_depth(value):
    depth, pending = 0, [(value, 1)]
    while pending:
        item, level = pending.pop()
        if isinstance(item, (dict, list)):
            depth = max(depth, level)
            children = item.values() if isinstance(item, dict) else item
            pending.extend((child, level + 1) for child in children)
    return depth


def test_copy_json_is_iterative_independent_and_preserves_aliases():
    from unifi_fabric._spec_drift import _copy_json

    deep = _nested_literal(5000)
    copied = _copy_json(deep)
    assert _json_depth(copied) == _json_depth(deep) == 5000
    cursor = copied
    for _ in range(4999):
        cursor = cursor["a"]
    cursor["a"] = "changed"
    cursor = deep
    for _ in range(4999):
        cursor = cursor["a"]
    assert cursor["a"] == "x"
    shared = {"k": [1, 2]}
    cyclic: dict = {"left": shared, "right": shared}
    cyclic["self"] = cyclic
    clone = _copy_json(cyclic)
    assert clone["left"] is clone["right"] and clone["left"] is not shared
    assert clone["self"] is clone and clone["left"] == {"k": [1, 2]}


@pytest.mark.parametrize("position", ["default", "link", "properties"])
def test_pathologically_deep_documents_never_crash(position):
    levels = 1200
    old = _deep_document(position, levels)
    old_spec = build_service_spec("test", "1", "http://test", old)
    restored = snapshot_from_dict({"services": {"test": {"version": "1", "raw_document": old}}})
    assert _json_depth(restored.services["test"].raw_document) == _json_depth(old)
    for new in (_deep_document(position, levels), _deep_document(position, levels, "y")):
        diff = diff_service("test", old_spec, build_service_spec("test", "1", "http://test", new))
        # Either clean or a fail-safe breaking review: never an exception.
        assert all(f.breakage for f in diff.endpoint_findings)
        if diff.endpoint_findings:
            assert any("needs_review" in reason for reason in _breaking_reasons(diff))
    changed = diff_service(
        "test",
        old_spec,
        build_service_spec("test", "1", "http://test", _deep_document(position, levels, "y")),
    )
    if position != "properties":  # titles are annotations; literal edits must surface
        assert any(f.breakage for f in changed.endpoint_findings)


def test_moderately_deep_literals_compare_cleanly():
    old = _deep_document("default", 200)
    assert not _diff(old, _deep_document("default", 200)).endpoint_findings
    assert _diff(old, _deep_document("default", 200, "y")).endpoint_findings


def test_deep_reference_object_chains_resolve_iteratively():
    bodies = {
        f"R{index}": {"$ref": f"#/components/requestBodies/R{index + 1}"} for index in range(249)
    }
    bodies["R249"] = {"description": "terminal", "required": True}
    document = {"openapi": "3.1.0", "components": {"requestBodies": bodies}}
    expanded = _resolve_object(
        {"$ref": "#/components/requestBodies/R0", "description": "outer"}, document
    )
    assert expanded == {"description": "outer", "required": True}


def test_deep_raw_ref_sibling_scan_is_iterative():
    sibling = {"unknownAssertion": True}
    for _ in range(1200):
        sibling = {"allOf": [sibling]}
    document = {"openapi": "3.0.0", "components": {"schemas": {"Base": {"type": "string"}}}}
    normalized = _normalize_schema(
        {"$ref": "#/components/schemas/Base", "allOf": [sibling]}, document
    )
    assert normalized["type"] == "string"
    assert any(
        "unsupported keyword unknownAssertion" == reason
        for reason in normalized["_spec_drift_raw_schema_review"].values()
    )


@pytest.mark.parametrize("change", ["parameter", "request_body", "type_add"])
def test_new_restrictions_are_breaking(change):
    old = _doc()
    new = deepcopy(old)
    op = new["paths"]["/v1/widgets"]["post"]
    if change == "parameter":
        op["parameters"] = [
            {"name": "filter", "in": "query", "required": True, "schema": {"type": "string"}}
        ]
    elif change == "request_body":
        op["requestBody"]["required"] = True
    else:
        del _schema(old, "request")["properties"]["mode"]["type"]
    finding = _semantic_finding(_diff(old, new))
    assert finding.breakage


@pytest.mark.parametrize("keyword", ["required", "enum"])
def test_removing_a_restriction_is_not_breaking(keyword):
    old = _doc()
    if keyword == "required":
        _schema(old, "request")["required"] = ["mode"]
    new = deepcopy(old)
    schema = _schema(new, "request")
    if keyword == "required":
        del schema["required"]
    else:
        del schema["properties"]["mode"]["enum"]
    finding = _semantic_finding(_diff(old, new))
    assert not finding.breakage


def test_ref_wrappers_cycles_escaped_pointer_and_override():
    old = _doc()
    op = old["paths"]["/v1/widgets"]["post"]
    op["requestBody"] = {"$ref": "#/components/requestBodies/Body"}
    op["responses"]["200"] = {"$ref": "#/components/responses/Result"}
    old["components"] = {
        "schemas": {
            "A/B~": {
                "type": "object",
                "properties": {
                    "child": {"$ref": "#/components/schemas/A~1B~0"},
                    "mode": {"type": "string", "enum": ["OLD"]},
                },
            }
        },
        "requestBodies": {
            "Body": {
                "content": {"application/json": {"schema": {"$ref": "#/components/schemas/A~1B~0"}}}
            }
        },
        "responses": {
            "Result": {
                "content": {"application/json": {"schema": {"$ref": "#/components/schemas/A~1B~0"}}}
            }
        },
    }
    new = deepcopy(old)
    new["components"]["schemas"]["A/B~"]["properties"]["mode"]["enum"].append("NEW")
    finding = _semantic_finding(_diff(old, new))
    assert any("requestBody" in change for change in finding.changes)
    assert any("responses.200" in change for change in finding.changes)
    assert finding.breakage  # Response enum widening breaks consumers of the old contract.


def test_parameter_override_and_enum_object_literals():
    old = _doc("parameter")
    old["paths"]["/v1/widgets"]["parameters"] = [
        {"name": "filter", "in": "query", "schema": {"type": "integer"}}
    ]
    schema = _schema(old, "parameter")
    schema["properties"]["mode"]["enum"] = [{"description": "OLD", "example": "OLD"}]
    new = deepcopy(old)
    new["paths"]["/v1/widgets"]["parameters"][0]["schema"]["type"] = "boolean"
    findings = _diff(old, new).changed_endpoints
    assert findings and all(f.breakage for f in findings)
    assert any("needs_review" in item for f in findings for item in f.changes)
    assert not [f for f in findings if not f.endpoint.startswith("DOCUMENT")]
    _schema(new, "parameter")["properties"]["mode"]["enum"][0]["description"] = "NEW"
    finding = _semantic_finding(_diff(old, new))
    assert finding.breakage


@pytest.mark.parametrize(
    "ref", ["#/components/schemas/Missing", "https://example.test/schema.json"]
)
def test_unresolved_ref_requires_breaking_review(ref):
    old = _doc()
    new = deepcopy(old)
    _schema(new, "request")["properties"]["mode"] = {"$ref": ref}
    finding = _semantic_finding(_diff(old, new))
    assert finding.breakage
    assert any(
        "needs_review" in reason and "reference" in reason for reason in finding.breaking_changes
    )


def test_enum_json_types_are_distinct():
    old = _doc()
    _schema(old, "request")["properties"]["mode"]["enum"] = [1]
    new = deepcopy(old)
    _schema(new, "request")["properties"]["mode"]["enum"] = [True]
    finding = _semantic_finding(_diff(old, new))
    assert finding.breakage
    assert any("-[1]" in item for item in finding.changes)
    assert any("+[true]" in item for item in finding.changes)


@pytest.mark.parametrize("name", ["enum", "required", "type", "example", "description"])
@pytest.mark.parametrize("remove", [False, True])
def test_schema_keyword_named_fields_are_classified_as_fields(name, remove):
    old = _doc()
    if remove:
        _schema(old, "request")["properties"][name] = {"type": "string"}
    new = deepcopy(old)
    if remove:
        del _schema(new, "request")["properties"][name]
    else:
        _schema(new, "request")["properties"][name] = {"type": "string"}
    finding = _semantic_finding(_diff(old, new))
    assert finding.breakage is not remove


@pytest.mark.parametrize("composition", ["allOf", "anyOf", "oneOf"])
def test_nested_composition_type_change_is_breaking(composition):
    old = _doc()
    _schema(old, "request")["properties"]["mode"] = {composition: [{"type": "string"}]}
    new = deepcopy(old)
    _schema(new, "request")["properties"]["mode"][composition][0]["type"] = "integer"
    finding = _semantic_finding(_diff(old, new))
    assert finding.breakage
    assert any(composition + "[0].type" in item for item in finding.changes)
