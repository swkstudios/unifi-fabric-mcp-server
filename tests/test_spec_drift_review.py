"""Behavioral acceptance regressions for schema compatibility and header drift."""

from copy import deepcopy

import pytest

from unifi_fabric._spec_drift import (
    SUPPORTED_KEYWORDS,
    build_service_spec,
    diff_service,
    schema_keywords,
)


def _document(schema, location="request", dialect="3.1.0"):
    operation = {"responses": {"200": {"description": "ok"}}}
    if location == "request":
        operation["requestBody"] = {"content": {"application/json": {"schema": schema}}}
    elif location == "parameter":
        operation["parameters"] = [{"name": "q", "in": "query", "schema": schema}]
    elif location == "response":
        operation["responses"]["200"]["content"] = {"application/json": {"schema": schema}}
    else:
        header = {"schema": schema}
        if location == "header_content":
            header = {"content": {"application/json": {"schema": schema}}}
        operation["responses"]["200"]["headers"] = {"X-Contract": header}
    return {
        "openapi": dialect,
        "info": {"version": "1"},
        "paths": {"/widgets": {"post": operation}},
    }


def _diff(old, new):
    return diff_service(
        "test",
        build_service_spec("test", "1", "https://example.invalid", old),
        build_service_spec("test", "1", "https://example.invalid", new),
    )


def _assert_delta(old, new, breaking):
    findings = _diff(old, new).changed_endpoints
    assert findings
    assert any(finding.changes for finding in findings)
    assert any(finding.breakage for finding in findings) is breaking
    assert any(bool(finding.breaking_changes) for finding in findings) is breaking
    # Reverting the contract must restore a clean fingerprint, in every class.
    assert not _diff(old, deepcopy(old)).changed_endpoints


# Every row denotes a strict subset of the former accepted instance set. Reverse
# each row as well: requests and responses have opposite compatibility polarity.
_TIGHTENINGS = [
    pytest.param({"minimum": 0}, {"minimum": 1}, id="minimum"),
    pytest.param({"maximum": 10}, {"maximum": 9}, id="maximum"),
    pytest.param({"exclusiveMinimum": 0}, {"exclusiveMinimum": 1}, id="exclusiveMinimum"),
    pytest.param({"exclusiveMaximum": 10}, {"exclusiveMaximum": 9}, id="exclusiveMaximum"),
    pytest.param({"minLength": 0}, {"minLength": 1}, id="minLength"),
    pytest.param({"maxLength": 10}, {"maxLength": 9}, id="maxLength"),
    pytest.param({"minItems": 0}, {"minItems": 1}, id="minItems"),
    pytest.param({"maxItems": 10}, {"maxItems": 9}, id="maxItems"),
    pytest.param({"minProperties": 0}, {"minProperties": 1}, id="minProperties"),
    pytest.param({"maxProperties": 10}, {"maxProperties": 9}, id="maxProperties"),
    pytest.param({"uniqueItems": False}, {"uniqueItems": True}, id="uniqueItems"),
    pytest.param({}, {"pattern": "^a"}, id="pattern-added"),
    pytest.param({"multipleOf": 2}, {"multipleOf": 4}, id="multipleOf"),
    pytest.param({}, {"not": {"type": "null"}}, id="not-added"),
    pytest.param(
        {"oneOf": [{"type": "string"}]},
        {"oneOf": [{"type": "string"}, {"type": "string", "minLength": 1}]},
        id="oneOf-overlap",
    ),
    pytest.param({"additionalProperties": True}, {"additionalProperties": False}, id="closed"),
    pytest.param(
        {"additionalProperties": {"type": "string"}},
        {"additionalProperties": {"type": "string", "minLength": 1}},
        id="additionalProperties-schema",
    ),
    pytest.param({}, {"dependentRequired": {"a": ["b"]}}, id="dependentRequired-added"),
    pytest.param(
        {"dependentRequired": {"a": ["b"]}},
        {"dependentRequired": {"a": ["b", "c"]}},
        id="dependentRequired-tightened",
    ),
    pytest.param({}, {"dependentSchemas": {"a": {"required": ["b"]}}}, id="dependentSchemas"),
    pytest.param({"enum": ["a", "b"]}, {"enum": ["a"]}, id="enum-removal"),
    pytest.param({"required": []}, {"required": ["a"]}, id="required-added"),
    pytest.param({"type": ["string", "null"]}, {"type": "string"}, id="type-narrowed"),
    pytest.param({"type": "string"}, {"type": "string", "format": "uuid"}, id="format-added"),
    pytest.param(
        {"allOf": [{"minimum": 0}]},
        {"allOf": [{"minimum": 0}, {"maximum": 10}]},
        id="conjunct-added",
    ),
    pytest.param(
        {"anyOf": [{"type": "string"}, {"type": "null"}]},
        {"anyOf": [{"type": "string"}]},
        id="anyOf-branch-removed",
    ),
]


@pytest.mark.parametrize(("wide", "narrow"), _TIGHTENINGS)
@pytest.mark.parametrize("location", ["request", "parameter", "response"])
@pytest.mark.parametrize("reverse", [False, True], ids=["tighten", "widen"])
def test_directional_restriction_classes(wide, narrow, location, reverse):
    old_schema, new_schema = (narrow, wide) if reverse else (wide, narrow)
    _assert_delta(
        _document(old_schema, location),
        _document(new_schema, location),
        breaking=True
        if (schema_keywords(wide) | schema_keywords(narrow)) - SUPPORTED_KEYWORDS
        else reverse
        if location == "response"
        else not reverse,
    )


@pytest.mark.parametrize(
    "keyword",
    [
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "minLength",
        "maxLength",
        "minItems",
        "maxItems",
        "minProperties",
        "maxProperties",
        "uniqueItems",
        "pattern",
        "multipleOf",
        "not",
        "additionalProperties",
        "dependentRequired",
        "dependentSchemas",
        "enum",
        "required",
        "type",
        "format",
        "allOf",
    ],
)
def test_removing_a_request_restriction_is_nonbreaking(keyword):
    values = {
        "minimum": 1,
        "maximum": 10,
        "exclusiveMinimum": 1,
        "exclusiveMaximum": 10,
        "minLength": 1,
        "maxLength": 10,
        "minItems": 1,
        "maxItems": 10,
        "minProperties": 1,
        "maxProperties": 10,
        "uniqueItems": True,
        "pattern": "^a",
        "multipleOf": 2,
        "not": {"type": "null"},
        "additionalProperties": False,
        "dependentRequired": {"a": ["b"]},
        "dependentSchemas": {"a": {"required": ["b"]}},
        "enum": ["a"],
        "required": ["a"],
        "type": "string",
        "format": "uuid",
        "allOf": [{"minimum": 0}, {"maximum": 10}],
    }
    _assert_delta(
        _document({keyword: values[keyword]}),
        _document({}),
        breaking=keyword not in SUPPORTED_KEYWORDS,
    )


@pytest.mark.parametrize("location", ["request", "response"])
def test_changed_pattern_is_potentially_breaking_in_both_directions(location):
    # These sets are incomparable: each accepts strings the other rejects.
    _assert_delta(
        _document({"pattern": "^a"}, location),
        _document({"pattern": "^b"}, location),
        breaking=True,
    )


@pytest.mark.parametrize(
    "keyword", ["minimum", "exclusiveMinimum", "minLength", "minItems", "minProperties"]
)
@pytest.mark.parametrize("low", range(4))
@pytest.mark.parametrize("step", [1, 3])
def test_lower_bound_monotonicity_property(keyword, low, step):
    wide, narrow = {keyword: low}, {keyword: low + step}
    for location in ("request", "response"):
        _assert_delta(
            _document(wide, location),
            _document(narrow, location),
            keyword not in SUPPORTED_KEYWORDS or location == "request",
        )
        _assert_delta(
            _document(narrow, location),
            _document(wide, location),
            keyword not in SUPPORTED_KEYWORDS or location == "response",
        )


@pytest.mark.parametrize(
    "keyword", ["maximum", "exclusiveMaximum", "maxLength", "maxItems", "maxProperties"]
)
@pytest.mark.parametrize("low", range(4))
@pytest.mark.parametrize("step", [1, 3])
def test_upper_bound_monotonicity_property(keyword, low, step):
    narrow, wide = {keyword: low}, {keyword: low + step}
    for location in ("request", "response"):
        _assert_delta(
            _document(wide, location),
            _document(narrow, location),
            keyword not in SUPPORTED_KEYWORDS or location == "request",
        )
        _assert_delta(
            _document(narrow, location),
            _document(wide, location),
            keyword not in SUPPORTED_KEYWORDS or location == "response",
        )


@pytest.mark.parametrize("dialect", ["3.0.3", "3.1.0"])
def test_ref_sibling_cannot_erase_the_referenced_constraint(dialect):
    old = _document({"$ref": "#/components/schemas/Base", "minLength": 1}, dialect=dialect)
    old["components"] = {"schemas": {"Base": {"type": "string", "minLength": 2}}}
    new = deepcopy(old)
    new["components"]["schemas"]["Base"]["minLength"] = 3
    _assert_delta(old, new, breaking=True)


@pytest.mark.parametrize("dialect", ["3.0.3", "3.1.0"])
def test_ref_sibling_constraints_follow_openapi_dialect(dialect):
    old = _document({"$ref": "#/components/schemas/Base", "maxLength": 10}, dialect=dialect)
    old["components"] = {"schemas": {"Base": {"type": "string", "minLength": 2}}}
    new = deepcopy(old)
    new["paths"]["/widgets"]["post"]["requestBody"]["content"]["application/json"]["schema"][
        "maxLength"
    ] = 5
    if dialect == "3.0.3":
        findings = _diff(old, new).changed_endpoints
        assert findings
        assert all(finding.endpoint == "DOCUMENT #" for finding in findings)
        assert all(finding.breakage for finding in findings)
        assert any(
            "needs_review" in reason and "/maxLength" in reason
            for finding in findings
            for reason in finding.breaking_changes
        )
    else:
        _assert_delta(old, new, breaking=True)


_ANNOTATION_NAMES = ["description", "summary", "example", "examples", "title"]


@pytest.mark.parametrize("name", _ANNOTATION_NAMES)
@pytest.mark.parametrize(
    "container", ["properties", "patternProperties", "dependentRequired", "discriminator"]
)
def test_annotation_spelling_is_literal_inside_mapping_containers(name, container):
    if container == "dependentRequired":
        old_schema = {container: {name: ["a"]}}
        new_schema = {container: {name: ["a", "b"]}}
    elif container == "discriminator":
        old_schema = {
            container: {"propertyName": "kind", "mapping": {name: "#/components/schemas/A"}}
        }
        new_schema = {
            container: {"propertyName": "kind", "mapping": {name: "#/components/schemas/B"}}
        }
    else:
        old_schema = {container: {name: {"type": "string", "minLength": 1}}}
        new_schema = {container: {name: {"type": "string", "minLength": 2}}}
    old, new = _document(old_schema), _document(new_schema)
    if container == "discriminator":
        for doc in (old, new):
            doc["components"] = {"schemas": {"A": {"type": "string"}, "B": {"type": "string"}}}
    finding = _diff(old, new).changed_endpoints
    assert finding
    assert any(name in change for item in finding for change in item.changes)
    assert not _diff(old, deepcopy(old)).changed_endpoints


@pytest.mark.parametrize("name", _ANNOTATION_NAMES)
def test_annotations_are_ignored_only_in_schema_keyword_positions(name):
    old = _document({"type": "string", name: "old annotation"})
    new = _document({"type": "string", name: "new annotation"})
    assert not _diff(old, new).changed_endpoints


@pytest.mark.parametrize("location", ["header", "header_content"])
@pytest.mark.parametrize("reference", [False, True], ids=["inline", "ref"])
def test_response_header_schema_and_content_are_fingerprinted(location, reference):
    old_schema = {"type": "string", "enum": ["a"]}
    old = _document(old_schema, location)
    new = _document({"type": "string", "enum": ["a", "b"]}, location)
    if reference:
        old = _document({"$ref": "#/components/schemas/HeaderValue"}, location)
        new = deepcopy(old)
        old["components"] = {"schemas": {"HeaderValue": old_schema}}
        new["components"] = {"schemas": {"HeaderValue": {"type": "string", "enum": ["a", "b"]}}}
    _assert_delta(old, new, breaking=True)
    _assert_delta(new, old, breaking=False)


@pytest.mark.parametrize("location", ["request", "response"])
def test_oneof_duplicate_branch_is_a_restriction(location):
    wide = _document({"oneOf": [{"type": "string"}]}, location)
    narrow = _document({"oneOf": [{"type": "string"}, {"type": "string"}]}, location)
    _assert_delta(wide, narrow, location == "request")
    _assert_delta(narrow, wide, location == "response")


@pytest.mark.parametrize("keyword", ["minimum", "maximum"])
def test_large_integer_bounds_keep_exact_polarity(keyword):
    lower, higher = {keyword: 2**60}, {keyword: 2**60 + 1}
    wide, narrow = (lower, higher) if keyword == "minimum" else (higher, lower)
    _assert_delta(_document(wide), _document(narrow), True)
    _assert_delta(_document(narrow), _document(wide), False)


def test_reference_chain_preserves_each_sibling_conjunction():
    old = _document({"$ref": "#/components/schemas/A", "minLength": 1})
    old["components"] = {
        "schemas": {
            "A": {"$ref": "#/components/schemas/B", "minLength": 1},
            "B": {"type": "string", "minLength": 2},
        }
    }
    new = deepcopy(old)
    new["components"]["schemas"]["B"]["minLength"] = 3
    _assert_delta(old, new, True)


@pytest.mark.parametrize("location", ["header", "header_content"])
def test_header_reference_objects_are_resolved(location):
    old = _document({"type": "string", "enum": ["a"]}, location)
    response = old["paths"]["/widgets"]["post"]["responses"]["200"]
    header = response["headers"]["X-Contract"]
    response["headers"]["X-Contract"] = {"$ref": "#/components/headers/Contract"}
    old["components"] = {"headers": {"Contract": header}}
    new = deepcopy(old)
    projected = new["components"]["headers"]["Contract"]
    schema = projected.get("schema") or projected["content"]["application/json"]["schema"]
    schema["enum"].append("b")
    _assert_delta(old, new, True)


def test_removing_response_header_schema_widens_the_contract():
    old = _document({"type": "string", "enum": ["a"]}, "header")
    new = deepcopy(old)
    del new["paths"]["/widgets"]["post"]["responses"]["200"]["headers"]["X-Contract"]["schema"]
    _assert_delta(old, new, True)


@pytest.mark.parametrize("closed", [False, True])
@pytest.mark.parametrize("location", ["request", "response"])
def test_optional_property_constraints_follow_additional_properties(closed, location):
    before = {"type": "object", "additionalProperties": not closed}
    after = {**before, "properties": {"foo": {"type": "string"}}}
    adding_breaks = closed if location == "response" else not closed
    _assert_delta(_document(before, location), _document(after, location), adding_breaks)
    _assert_delta(_document(after, location), _document(before, location), not adding_breaks)


@pytest.mark.parametrize("location", ["request", "response"])
def test_optional_property_equivalent_to_additional_schema_is_nonbreaking(location):
    before = {"additionalProperties": {"type": "string"}}
    after = {**before, "properties": {"foo": {"type": "string"}}}
    _assert_delta(_document(before, location), _document(after, location), False)
    _assert_delta(_document(after, location), _document(before, location), False)


@pytest.mark.parametrize("location", ["request", "response"])
def test_matching_pattern_property_constraints_are_preserved(location):
    before = {"patternProperties": {"^foo$": {"type": "string"}}}
    after = {**before, "properties": {"foo": {"type": "string"}}}
    _assert_delta(_document(before, location), _document(after, location), True)
    _assert_delta(_document(after, location), _document(before, location), True)


@pytest.mark.parametrize("location", ["request", "response"])
def test_oneof_branch_replacement_follows_direction(location):
    narrow = _document({"oneOf": [{"type": "string", "minLength": 2}]}, location)
    wide = _document({"oneOf": [{"type": "string"}]}, location)
    _assert_delta(narrow, wide, location == "response")
    _assert_delta(wide, narrow, location == "request")


@pytest.mark.parametrize("dialect", ["3.0.3", "3.1.0"])
def test_header_reference_siblings_cannot_shadow_target(dialect):
    old = _document({}, "header", dialect)
    response = old["paths"]["/widgets"]["post"]["responses"]["200"]
    response["headers"]["X-Contract"] = {
        "$ref": "#/components/headers/Contract",
        "schema": {"type": "string"},
    }
    old["components"] = {
        "headers": {
            "Contract": {
                "schema": {"type": "string", "enum": ["a"]},
            }
        }
    }
    new = deepcopy(old)
    new["components"]["headers"]["Contract"]["schema"]["enum"].append("b")
    _assert_delta(old, new, True)


def test_path_item_reference_keeps_its_own_operations():
    old = _document({"type": "string"})
    operation = old["paths"]["/widgets"]["post"]
    old["components"] = {"pathItems": {"Shared": {"get": {"responses": {"200": {}}}}}}
    old["paths"]["/widgets"] = {
        "$ref": "#/components/pathItems/Shared",
        "post": operation,
    }
    endpoints = build_service_spec("test", "1", "https://example.invalid", old).endpoints
    assert set(endpoints) == {"GET /widgets", "POST /widgets"}
