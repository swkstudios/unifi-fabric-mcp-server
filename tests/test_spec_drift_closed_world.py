"""Closed-world inventory and reviewer reproductions for directional schema drift."""

import json
import os
from copy import deepcopy
from pathlib import Path

import pytest

from tests import test_spec_drift_review as review
from unifi_fabric._spec_drift import SUPPORTED_KEYWORDS, schema_keywords, spec_schema_keywords

BASELINE = Path(__file__).parent / "fixtures/spec_drift/baseline_snapshot.json"


def test_projected_baseline_has_no_unsupported_keywords():
    # Hermetic CI checks every schema projected into the committed snapshot.
    baseline = json.loads(BASELINE.read_text())
    assert spec_schema_keywords(baseline) <= SUPPORTED_KEYWORDS


def test_regenerate_supported_keywords_from_all_raw_pinned_specs():
    # A live run supplies fetched documents, while CI remains network-free.
    # --check-supported-keywords exercises the same inventory against pinned URLs.
    directory = os.environ.get("SPEC_DRIFT_PINNED_DIRECTORY")
    if directory is None:
        pytest.skip("run live pinned-spec inventory with --check-supported-keywords")
    baseline = json.loads(BASELINE.read_text())
    regenerated = set()
    assert len(baseline["services"]) == 6
    for name in baseline["services"]:
        document = json.loads((Path(directory) / f"{name}.json").read_text())
        regenerated.update(spec_schema_keywords(document))
    assert regenerated == SUPPORTED_KEYWORDS


def test_inventory_visits_unused_components_and_ignores_literal_names():
    doc = {
        "components": {
            "schemas": {
                "Unused": {
                    "properties": {"contains": {"type": "string"}},
                    "default": {"unevaluatedProperties": False},
                    "enum": [{"dependentSchemas": {}}],
                    "discriminator": {"mapping": {"if": "literal"}},
                    "prefixItems": [{"type": "integer"}],
                }
            }
        }
    }
    assert spec_schema_keywords(doc) == {
        "properties",
        "type",
        "default",
        "enum",
        "discriminator",
        "prefixItems",
    }


# Request/response polarity or an explicit review requirement. Includes both
# rounds: reference context, tuple positions, contains cardinality, inapplicable
# restrictions, optional introductions, and pattern/conditional domains.
_REPROS = [
    ("numeric-on-string", {"type": "string"}, {"type": "string", "minimum": 1}, (False, False)),
    ("string-on-number", {"type": "number"}, {"type": "number", "minLength": 1}, (False, False)),
    ("array-on-string", {"type": "string"}, {"type": "string", "maxItems": 1}, (False, False)),
    ("required-on-array", {"type": "array"}, {"type": "array", "required": ["a"]}, (False, False)),
    (
        "minimum-on-union",
        {"type": ["string", "number"]},
        {"type": ["string", "number"], "minimum": 1},
        (True, False),
    ),
    (
        "tuple-removed",
        {"type": "array", "prefixItems": [{"type": "integer"}], "items": False},
        {"type": "array", "items": False},
        (True, False),
    ),
    (
        "tuple-second-removed",
        {"prefixItems": [{"type": "integer"}, {"type": "string"}], "items": False},
        {"prefixItems": [{"type": "integer"}], "items": False},
        (True, False),
    ),
    (
        "tuple-to-tail",
        {"prefixItems": [{"type": "integer"}], "items": {"type": "number"}},
        {"items": {"type": "number"}},
        (False, True),
    ),
    (
        "tuple-unreachable",
        {"prefixItems": [{"type": "integer"}], "maxItems": 0},
        {"prefixItems": [{"type": "string"}], "maxItems": 0},
        (False, False),
    ),
    (
        "tuple-tail-unreachable",
        {"prefixItems": [{"type": "integer"}], "maxItems": 1, "items": True},
        {"prefixItems": [{"type": "integer"}], "maxItems": 1, "items": False},
        (False, False),
    ),
    (
        "pattern-incomparable",
        {"type": "string", "pattern": "^a"},
        {"type": "string", "pattern": "^b"},
        (True, True),
    ),
    (
        "optional-open-property",
        {"type": "object"},
        {"type": "object", "properties": {"a": {"type": "string"}}},
        (True, False),
    ),
    (
        "optional-closed-property",
        {"type": "object", "additionalProperties": False},
        {"type": "object", "additionalProperties": False, "properties": {"a": {"type": "string"}}},
        (False, True),
    ),
    (
        "contains-max-widen",
        {"contains": {"type": "integer"}, "maxContains": 1},
        {"contains": {"type": "number"}, "maxContains": 1},
        "contains",
    ),
    ("contains-added-true", {}, {"contains": True}, "contains"),
    (
        "contains-min-zero",
        {"contains": {"type": "integer"}, "minContains": 0},
        {"contains": {"type": "integer"}},
        "minContains",
    ),
    (
        "contains-min-omitted",
        {"contains": {"type": "integer"}},
        {"contains": {"type": "integer"}, "minContains": 0},
        "minContains",
    ),
    ("unevaluated-items", {"unevaluatedItems": False}, {}, "unevaluatedItems"),
    ("dependent-schema", {}, {"dependentSchemas": {"a": {"required": ["b"]}}}, "dependentSchemas"),
    (
        "pattern-property-domain",
        {"patternProperties": {"^a": {"type": "integer"}}, "additionalProperties": False},
        {"patternProperties": {"^a": {"type": "number"}}, "additionalProperties": False},
        "patternProperties",
    ),
    (
        "conditional-tighten",
        {"if": {"type": "integer"}, "then": {"minimum": 0}},
        {"if": {"type": "integer"}, "then": {"minimum": 1}},
        "if",
    ),
    ("unknown-extension", {}, {"futureValidation": {"type": "string"}}, "futureValidation"),
]


@pytest.mark.parametrize(
    ("name", "old_schema", "new_schema", "expected"), _REPROS, ids=[row[0] for row in _REPROS]
)
@pytest.mark.parametrize("location", ["request", "response"])
@pytest.mark.parametrize("reverse", [False, True], ids=["change", "revert"])
def test_reviewer_repros(name, old_schema, new_schema, expected, location, reverse):
    before, after = (new_schema, old_schema) if reverse else (old_schema, new_schema)
    old, new = review._document(before, location), review._document(after, location)
    if isinstance(expected, str):
        breaks = True
    else:
        breaks = expected[(location == "response") ^ reverse]
    review._assert_delta(old, new, breaks)
    finding = review._diff(old, new).changed_endpoints[0]
    if isinstance(expected, str):
        assert f"needs_review: unsupported keyword {expected}" in "\n".join(
            finding.breaking_changes
        )
    else:
        assert not any("needs_review" in change for change in finding.changes)


@pytest.mark.parametrize("location", ["request", "response"])
def test_ref_unevaluated_context_is_never_reported_safe(location):
    old = review._document(
        {"$ref": "#/components/schemas/Base", "unevaluatedProperties": False}, location
    )
    old["components"] = {
        "schemas": {"Base": {"type": "object", "properties": {"a": {"type": "string"}}}}
    }
    new = deepcopy(old)
    new["components"]["schemas"]["Base"]["properties"]["b"] = {"type": "string"}
    review._assert_delta(old, new, True)
    assert any(
        "needs_review: unsupported keyword unevaluatedProperties" in reason
        for reason in review._diff(old, new).changed_endpoints[0].breaking_changes
    )


@pytest.mark.parametrize("required", [False, True])
@pytest.mark.parametrize("content", [False, True])
def test_new_parameter_is_an_introduction(required, content):
    old = review._document({})
    new = deepcopy(old)
    param = {"name": "q", "in": "query", "required": required}
    if content:
        param["content"] = {"application/json": {"schema": {"type": "string"}}}
    else:
        param["schema"] = {"type": "string"}
    new["paths"]["/widgets"]["post"]["parameters"] = [param]
    review._assert_delta(old, new, required)


def test_ref_conjunction_keeps_numeric_constraints_inapplicable_to_strings():
    old = review._document({"$ref": "#/components/schemas/Base", "minimum": 0})
    old["components"] = {"schemas": {"Base": {"type": "string"}}}
    new = deepcopy(old)
    new["paths"]["/widgets"]["post"]["requestBody"]["content"]["application/json"]["schema"][
        "minimum"
    ] = 1
    review._assert_delta(old, new, False)


@pytest.mark.parametrize(
    "location", ["request", "parameter", "response", "header", "header_content"]
)
def test_literal_unknown_keyword_names_are_not_schema_keywords(location):
    old = review._document({"properties": {"contains": {"enum": ["a"]}}}, location)
    new = review._document({"properties": {"contains": {"enum": ["a", "b"]}}}, location)
    review._assert_delta(old, new, location in {"response", "header", "header_content"})
    assert "contains" not in schema_keywords({"properties": {"contains": {"enum": ["a"]}}})


@pytest.mark.parametrize("mode", ["match", "new", "removed", "fetch-error"])
def test_cli_keyword_inventory_fails_closed(monkeypatch, capsys, mode):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    import check_spec_drift as script

    def fetch(baseline):
        assert len(baseline.services) == 6
        if mode == "fetch-error":
            raise RuntimeError("incomplete pinned documents")
        if mode == "new":
            return set(SUPPORTED_KEYWORDS) | {"futureValidation"}
        if mode == "removed":
            return set(SUPPORTED_KEYWORDS) - {"prefixItems"}
        return set(SUPPORTED_KEYWORDS)

    monkeypatch.setattr(script, "fetch_pinned_schema_keywords", fetch)
    result = script.main(["--baseline", str(BASELINE), "--check-supported-keywords"])
    assert result == {"match": 0, "new": 1, "removed": 1, "fetch-error": 2}[mode]
    output = capsys.readouterr()
    if mode == "new":
        assert "futureValidation" in output.out
    if mode == "removed":
        assert "no longer pinned: ['prefixItems']" in output.out
    if mode == "fetch-error":
        assert "ERROR: pinned keyword inventory failed" in output.err


def test_keyword_fetch_visits_every_pinned_service(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    import check_spec_drift as script
    import httpx

    baseline = script.load_snapshot_file(BASELINE)
    visited = []

    def fetch(request):
        visited.append(str(request.url))
        return httpx.Response(
            200,
            json={
                "paths": {"/x": {"get": {"responses": {"200": {}}}}},
                "components": {"schemas": {"Unused": {"type": "array", "prefixItems": []}}},
            },
        )

    transport = httpx.MockTransport(fetch)
    client_type = httpx.Client
    monkeypatch.setattr(
        httpx, "Client", lambda **kwargs: client_type(transport=transport, **kwargs)
    )
    assert script.fetch_pinned_schema_keywords(baseline) == {"type", "prefixItems"}
    assert sorted(visited) == sorted(service.spec_url for service in baseline.services.values())


@pytest.mark.parametrize("location", ["request", "response", "parameter", "header"])
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize(
    "failure", ["unresolved", "schema-cycle", "object-cycle", "unknown-dialect"]
)
def test_reference_and_dialect_failures_are_changed_breaking_review(location, reverse, failure):
    valid = review._document({"type": "string"}, location)
    invalid = review._document({"$ref": "#/components/schemas/Nope"}, location)
    expected = "Nope"
    if failure == "schema-cycle":
        invalid = review._document({"$ref": "#/components/schemas/Loop"}, location)
        invalid["components"] = {"schemas": {"Loop": {"$ref": "#/components/schemas/Loop"}}}
        expected = "cyclic schema $ref"
    elif failure == "object-cycle":
        invalid = deepcopy(valid)
        operation = invalid["paths"]["/widgets"]["post"]
        invalid["components"] = {
            "requestBodies": {"Loop": {"$ref": "#/components/requestBodies/Loop"}}
        }
        operation["requestBody"] = {"$ref": "#/components/requestBodies/Loop"}
        expected = "cyclic OpenAPI reference"
    elif failure == "unknown-dialect":
        invalid = review._document(
            {"type": "string", "$schema": "https://example.invalid/future-draft"}, location
        )
        expected = "$schema"
    old, new = (invalid, valid) if reverse else (valid, invalid)
    finding = review._diff(old, new).changed_endpoints[0]
    assert finding.kind == "CHANGED"
    assert finding.breakage
    assert any(
        "needs_review" in reason and expected in reason for reason in finding.breaking_changes
    )
    # Stable schema cycles are baseline evidence; unresolved contracts and
    # non-schema expansion failures still invoke unconditional review.
    unchanged = review._diff(invalid, deepcopy(invalid)).changed_endpoints
    if failure == "schema-cycle":
        assert not unchanged
    else:
        assert unchanged[0].breakage


@pytest.mark.parametrize("location", ["request", "response"])
@pytest.mark.parametrize(
    "dialect",
    [
        "http://json-schema.org/draft-04/schema#",
        "http://json-schema.org/draft-06/schema#",
        "http://json-schema.org/draft-07/schema#",
        "https://json-schema.org/draft/2019-09/schema",
        "https://json-schema.org/draft/2020-12/schema",
        "https://spec.openapis.org/oas/3.1/dialect/base",
    ],
)
def test_known_dialects_use_normal_directional_semantics(dialect, location):
    old = review._document({"$schema": dialect, "type": "string", "minLength": 1}, location)
    new = review._document({"$schema": dialect, "type": "string", "minLength": 2}, location)
    review._assert_delta(old, new, location == "request")
    assert not any(
        "needs_review" in reason for reason in review._diff(old, new).changed_endpoints[0].changes
    )
    # G1 requires review for every dialect occurrence-set change, including
    # an explicit declaration of a known dialect with unchanged semantics.
    plain = review._document({"type": "string", "minLength": 1}, location)
    findings = review._diff(plain, old).changed_endpoints
    assert any(
        finding.endpoint == "DOCUMENT #"
        and finding.breakage
        and any(
            "needs_review" in reason and "/$schema" in reason for reason in finding.breaking_changes
        )
        for finding in findings
    )


@pytest.mark.parametrize("keyword", ["$schema", "jsonSchemaDialect"])
def test_unknown_document_dialect_is_breaking_review(keyword):
    old = review._document({"type": "string"})
    new = deepcopy(old)
    new[keyword] = "https://example.invalid/future-draft"
    finding = review._diff(old, new).changed_endpoints[0]
    assert finding.breakage
    assert any(
        "needs_review" in reason and "future-draft" in reason for reason in finding.breaking_changes
    )


@pytest.mark.parametrize("reverse", [False, True])
def test_review_reason_has_nested_keyword_json_pointer(reverse):
    old = review._document({"type": "string"})
    new = review._document({"allOf": [{"not": {"if": {"type": "string"}}}]})
    before, after = (new, old) if reverse else (old, new)
    finding = review._diff(before, after).changed_endpoints[0]
    assert (
        "requestBody.schemas.application/json#/allOf/0/not/if needs_review: unsupported keyword if"
        in finding.breaking_changes
    )


def test_review_pointer_escapes_property_names_and_follows_refs():
    old = review._document({"type": "object"})
    new = review._document({"$ref": "#/components/schemas/Base"})
    new["components"] = {"schemas": {"Base": {"properties": {"a/b~c": {"futureValidation": True}}}}}
    finding = review._diff(old, new).changed_endpoints[0]
    assert (
        "requestBody.schemas.application/json#/properties/a~1b~0c/futureValidation "
        "needs_review: unsupported keyword futureValidation" in finding.breaking_changes
    )


# One behavioral row per supported keyword; every row runs requests and responses
# in both update directions. This exact-set assertion fails if coverage goes stale.
_DIRECTIONAL_KEYWORDS = {
    "$ref": (
        {"$ref": "#/components/schemas/Wide"},
        {"$ref": "#/components/schemas/Narrow"},
        (True, False),
    ),
    "additionalProperties": (
        {"additionalProperties": True},
        {"additionalProperties": False},
        (True, False),
    ),
    "allOf": ({"allOf": [{"minLength": 1}]}, {"allOf": [{"minLength": 2}]}, (True, False)),
    "anyOf": (
        {"anyOf": [{"type": "string"}, {"type": "null"}]},
        {"anyOf": [{"type": "string"}]},
        (True, False),
    ),
    "const": ({}, {"const": "a"}, (True, False)),
    "default": ({"default": "a"}, {"default": "b"}, (False, False)),
    "deprecated": ({"deprecated": False}, {"deprecated": True}, (False, False)),
    "discriminator": (
        {"discriminator": {"propertyName": "a"}},
        {"discriminator": {"propertyName": "b"}},
        (False, False),
    ),
    "enum": ({"enum": ["a", "b"]}, {"enum": ["a"]}, (True, False)),
    "exclusiveMinimum": ({"exclusiveMinimum": 1}, {"exclusiveMinimum": 2}, (True, False)),
    "format": ({"type": "string"}, {"type": "string", "format": "uuid"}, (True, False)),
    "items": (
        {"items": {"type": "string"}},
        {"items": {"type": "string", "minLength": 1}},
        (True, False),
    ),
    "maxItems": ({"maxItems": 2}, {"maxItems": 1}, (True, False)),
    "maxLength": ({"maxLength": 2}, {"maxLength": 1}, (True, False)),
    "maximum": ({"maximum": 2}, {"maximum": 1}, (True, False)),
    "minItems": ({"minItems": 1}, {"minItems": 2}, (True, False)),
    "minLength": ({"minLength": 1}, {"minLength": 2}, (True, False)),
    "minimum": ({"minimum": 1}, {"minimum": 2}, (True, False)),
    "nullable": (
        {"type": "string", "nullable": True},
        {"type": "string", "nullable": False},
        (True, False),
    ),
    "oneOf": (
        {"oneOf": [{"type": "string"}, {"type": "null"}]},
        {"oneOf": [{"type": "string"}]},
        (True, False),
    ),
    "pattern": ({"type": "string"}, {"type": "string", "pattern": "^a"}, (True, False)),
    "prefixItems": (
        {"prefixItems": [{"type": "string"}]},
        {"prefixItems": [{"type": "string", "minLength": 1}]},
        (True, False),
    ),
    "properties": (
        {"properties": {"a": {"type": "string"}}},
        {"properties": {"a": {"type": "string", "minLength": 1}}},
        (True, False),
    ),
    "required": ({"required": []}, {"required": ["a"]}, (True, False)),
    "type": ({"type": ["string", "null"]}, {"type": "string"}, (True, False)),
    "uniqueItems": ({"uniqueItems": False}, {"uniqueItems": True}, (True, False)),
}
for _keyword in (
    "description",
    "example",
    "examples",
    "title",
    "x-enum-descriptions",
    "x-enum-varnames",
    "x-properties-order",
    "x-tags",
):
    _DIRECTIONAL_KEYWORDS[_keyword] = ({_keyword: "a"}, {_keyword: "b"}, (False, False))


def test_every_supported_keyword_has_directional_cases():
    assert set(_DIRECTIONAL_KEYWORDS) == SUPPORTED_KEYWORDS
    for keyword, (old, new, _) in _DIRECTIONAL_KEYWORDS.items():
        assert keyword in schema_keywords(old) | schema_keywords(new)


@pytest.mark.parametrize("keyword", sorted(_DIRECTIONAL_KEYWORDS))
@pytest.mark.parametrize("location", ["request", "response"])
@pytest.mark.parametrize("reverse", [False, True])
def test_supported_keyword_directional_coverage(keyword, location, reverse):
    wide, narrow, expected = _DIRECTIONAL_KEYWORDS[keyword]
    before, after = (narrow, wide) if reverse else (wide, narrow)
    dialect = "3.0.3" if keyword == "nullable" else "3.1.0"
    old = review._document(before, location, dialect)
    new = review._document(after, location, dialect)
    for document in (old, new):
        document["components"] = {
            "schemas": {
                "Wide": {"type": "string", "minLength": 1},
                "Narrow": {"type": "string", "minLength": 2},
            }
        }
    findings = review._diff(old, new).changed_endpoints
    if keyword == "$ref":
        assert any(finding.breakage for finding in findings)
        assert any(
            finding.endpoint == "DOCUMENT #"
            and any(
                "needs_review" in reason and "/$ref" in reason
                for reason in finding.breaking_changes
            )
            for finding in findings
        )
    else:
        assert (
            any(finding.breakage for finding in findings)
            is expected[(location == "response") ^ reverse]
        )
        assert not any(
            "needs_review" in reason for finding in findings for reason in finding.changes
        )


@pytest.mark.parametrize("kind", ["parameter", "body", "response", "header", "path"])
@pytest.mark.parametrize("failure", ["cycle", "unresolved"])
def test_reference_object_errors_at_every_contract_position(kind, failure):
    old = review._document({"type": "string"})
    new = deepcopy(old)
    edge = {"$ref": "#/components/objects/Bad"}
    operation = new["paths"]["/widgets"]["post"]
    if kind == "parameter":
        operation["parameters"] = [edge]
        pointer = "parameters#/$ref"
    elif kind == "body":
        operation["requestBody"] = edge
        pointer = "requestBody#/$ref"
    elif kind == "response":
        operation["responses"]["200"] = edge
        pointer = "responses.200#/$ref"
    elif kind == "header":
        operation["responses"]["200"]["headers"] = {"X-Test": edge}
        pointer = "responses.200.headers.X-Test#/$ref"
    else:
        new["paths"]["/widgets"] = edge
        pointer = "#/$ref"
    if failure == "cycle":
        new["components"] = {"objects": {"Bad": edge}}
    finding = next(
        finding
        for finding in review._diff(old, new).changed_endpoints
        if finding.endpoint == "POST /widgets"
    )
    assert finding.breakage
    assert any(pointer in reason and "Bad" in reason for reason in finding.breaking_changes)


@pytest.mark.parametrize("openapi", ["3.0.3", "3.1.0"])
def test_unknown_schema_dialect_on_ref_sibling_is_not_discarded(openapi):
    old = review._document({"$ref": "#/components/schemas/Base"}, dialect=openapi)
    new = review._document(
        {"$ref": "#/components/schemas/Base", "$schema": "https://example.invalid/future"},
        dialect=openapi,
    )
    for doc in (old, new):
        doc["components"] = {"schemas": {"Base": {"type": "string"}}}
    finding = review._diff(old, new).changed_endpoints[0]
    assert finding.breakage
    assert any("#/$schema" in reason and "needs_review" in reason for reason in finding.changes)


@pytest.mark.parametrize("failure", ["unresolved", "unknown-dialect", "unsupported-keyword"])
def test_invalid_contract_on_new_endpoint_is_breaking_review(failure):
    old = review._document({"type": "string"})
    old["paths"] = {}
    schema = {
        "unresolved": {"$ref": "#/components/schemas/Nope"},
        "unknown-dialect": {"$schema": "https://example.invalid/future"},
        "unsupported-keyword": {"futureValidation": True},
    }[failure]
    new = review._document(schema)
    finding = review._diff(old, new).changed_endpoints[0]
    assert finding.kind == "CHANGED"
    assert finding.breakage
    assert finding.breaking_changes
    assert not finding.write_capability


@pytest.mark.parametrize("location", ["request", "response"])
@pytest.mark.parametrize("openapi", ["3.0.3", "3.1.0"])
@pytest.mark.parametrize("reverse", [False, True], ids=["change", "revert"])
@pytest.mark.parametrize("nested", [False, True], ids=["direct", "nested"])
@pytest.mark.parametrize("failure", ["unsupported-keyword", "unknown-dialect"])
def test_raw_ref_sibling_review_survives_normalization(location, openapi, reverse, nested, failure):
    schema = {"$ref": "#/components/schemas/Base"}
    invalid_schema = deepcopy(schema)
    keyword, value = (
        ("futureValidation", True)
        if failure == "unsupported-keyword"
        else ("$schema", "https://example.invalid/future")
    )
    if nested:
        invalid_schema["properties"] = {"a/b~c": {keyword: value}}
        pointer = f"#/properties/a~1b~0c/{keyword}"
    else:
        invalid_schema[keyword] = value
        pointer = f"#/{keyword}"
    valid = review._document(schema, location, openapi)
    invalid = review._document(invalid_schema, location, openapi)
    for doc in (valid, invalid):
        doc["components"] = {"schemas": {"Base": {"type": "object"}}}
    old, new = (invalid, valid) if reverse else (valid, invalid)
    findings = review._diff(old, new).changed_endpoints
    finding = next(item for item in findings if item.endpoint == "POST /widgets")
    assert any(
        item.endpoint == "DOCUMENT #"
        and item.breakage
        and any("needs_review" in reason for reason in item.breaking_changes)
        for item in findings
    )
    prefix = (
        "requestBody.schemas.application/json"
        if location == "request"
        else "responses.200.application/json"
    )
    assert finding.kind == "CHANGED"
    assert finding.breakage
    assert any(
        f"{prefix}{pointer} needs_review:" in reason and keyword in reason
        for reason in finding.breaking_changes
    )
    assert all(reason in finding.changes for reason in finding.breaking_changes)
    # Restoring the original valid document restores a clean contract fingerprint.
    assert not review._diff(valid, deepcopy(valid)).endpoint_findings


@pytest.mark.parametrize("location", ["request", "response"])
@pytest.mark.parametrize("openapi", ["3.0.3", "3.1.0"])
@pytest.mark.parametrize("removal", [False, True], ids=["addition", "removal"])
@pytest.mark.parametrize("whole_service", [False, True], ids=["endpoint", "service"])
@pytest.mark.parametrize("failure", ["unsupported-keyword", "unresolved", "unknown-dialect"])
def test_endpoint_lifecycle_reviews_uncertain_contracts(
    location, openapi, removal, whole_service, failure
):
    schema = {
        "unsupported-keyword": {"$ref": "#/components/schemas/Base", "futureValidation": True},
        "unresolved": {"$ref": "#/components/schemas/Nope"},
        "unknown-dialect": {
            "$ref": "#/components/schemas/Base",
            "$schema": "https://example.invalid/future",
        },
    }[failure]
    document = review._document(schema, location, openapi)
    document["components"] = {"schemas": {"Base": {"type": "string"}}}
    populated = review.build_service_spec("test", "1", "https://example.invalid", document)
    empty_doc = deepcopy(document)
    empty_doc["paths"] = {}
    empty = (
        None
        if whole_service
        else review.build_service_spec("test", "1", "https://example.invalid", empty_doc)
    )
    old, new = (populated, empty) if removal else (empty, populated)
    findings = review.diff_service("test", old, new).endpoint_findings
    finding = next(item for item in findings if item.endpoint == "POST /widgets")
    assert any(
        item.endpoint == "DOCUMENT #"
        and item.breakage
        and any("needs_review" in reason for reason in item.breaking_changes)
        for item in findings
    )
    expected = {
        "unsupported-keyword": "futureValidation",
        "unresolved": "Nope",
        "unknown-dialect": "$schema",
    }[failure]
    assert finding.kind == ("REMOVED" if removal else "CHANGED")
    assert finding.breakage
    assert not finding.implemented
    assert not finding.write_capability
    assert finding.changes == finding.breaking_changes
    assert any(
        "#" in reason and "needs_review" in reason and expected in reason
        for reason in finding.changes
    )
    assert not review.diff_service("test", empty, empty).endpoint_findings


@pytest.mark.parametrize("location", ["request", "response"])
@pytest.mark.parametrize("implemented", [False, True])
def test_plain_endpoint_removal_keeps_coverage_breakage_rule(location, implemented):
    document = review._document({"type": "string"}, location)
    old = review.build_service_spec("test", "1", "https://example.invalid", document)
    empty_doc = deepcopy(document)
    empty_doc["paths"] = {}
    new = review.build_service_spec("test", "1", "https://example.invalid", empty_doc)
    coverage = {"test": frozenset({"POST /widgets"}) if implemented else frozenset()}
    (finding,) = review.diff_service("test", old, new, coverage=coverage).removed_endpoints
    assert finding.breakage is implemented
    assert finding.implemented is implemented
    assert not finding.changes
    assert not finding.breaking_changes
    assert not review._diff(document, deepcopy(document)).endpoint_findings


@pytest.mark.parametrize("location", ["request", "response"])
def test_raw_ref_supported_siblings_and_literal_payload_changes_require_review(location):
    valid = review._document({"$ref": "#/components/schemas/Base"}, location, "3.0.3")
    changed = review._document(
        {
            "$ref": "#/components/schemas/Base",
            "minLength": 2,
            "default": {"futureValidation": True, "$schema": "literal"},
            "properties": {"futureValidation": {"type": "string"}},
        },
        location,
        "3.0.3",
    )
    for doc in (valid, changed):
        doc["components"] = {"schemas": {"Base": {"type": "object"}}}
    for old, new in ((valid, changed), (changed, valid)):
        findings = review._diff(old, new).endpoint_findings
        assert findings
        assert any(
            finding.endpoint == "DOCUMENT #"
            and finding.breakage
            and any("needs_review" in reason for reason in finding.breaking_changes)
            for finding in findings
        )


@pytest.mark.parametrize(
    "schemas",
    [
        {"Node": {"type": "object", "properties": {"next": {"$ref": "#/components/schemas/Node"}}}},
        {
            "A": {"items": {"$ref": "#/components/schemas/B"}},
            "B": {"allOf": [{"$ref": "#/components/schemas/A"}]},
        },
        {"Node": {"additionalProperties": {"$ref": "#/components/schemas/Node"}}},
        {"Node": {"discriminator": {"mapping": {"node": "#/components/schemas/Node"}}}},
        {"Node": {"not": {"$ref": "#/components/schemas/Node"}}},
        {"Node": {"patternProperties": {"^n": {"$ref": "#/components/schemas/Node"}}}},
        {"Node": {"prefixItems": [{"$ref": "#/components/schemas/Node"}]}},
        {"Node": {"$defs": {"next": {"$ref": "#/components/schemas/Node"}}}},
    ],
    ids=[
        "properties",
        "mutual-items-allOf",
        "additionalProperties",
        "discriminator",
        "not",
        "patternProperties",
        "prefixItems",
        "$defs",
    ],
)
@pytest.mark.parametrize("used", [False, True], ids=["unused", "used"])
def test_nested_reference_cycles_are_clean_until_changed(schemas, used):
    doc = review._document(
        {"$ref": "#/components/schemas/" + next(iter(schemas))} if used else {"type": "string"}
    )
    doc["components"] = {"schemas": schemas}
    assert not review._diff(doc, deepcopy(doc)).changed_endpoints
    changed = deepcopy(doc)
    # Even annotation edits inside a recursive region need breaking review.
    changed["components"]["schemas"][next(iter(schemas))]["description"] = "changed"
    findings = review._diff(doc, changed).changed_endpoints
    assert findings
    assert any(
        finding.kind == "CHANGED"
        and finding.breakage
        and finding.endpoint == "DOCUMENT #"
        and any("needs_review: reference" in reason for reason in finding.breaking_changes)
        for finding in findings
    )


@pytest.mark.parametrize("used", [False, True], ids=["unused", "used"])
def test_diamond_shared_reference_stays_clean(used):
    doc = review._document({"$ref": "#/components/schemas/Root"} if used else {"type": "string"})
    doc["components"] = {
        "schemas": {
            "Root": {
                "properties": {
                    "left": {"$ref": "#/components/schemas/Leaf"},
                    "right": {"$ref": "#/components/schemas/Leaf"},
                }
            },
            "Leaf": {"type": "string"},
        }
    }
    assert not review._diff(doc, deepcopy(doc)).changed_endpoints


@pytest.mark.parametrize("location", ["request", "response", "parameter"])
@pytest.mark.parametrize("keyword", ["enum", "const"])
@pytest.mark.parametrize(
    ("left", "right"),
    [(1, 1.0), ({"value": [1, True, "1"]}, {"value": [1.0, True, "1"]})],
)
@pytest.mark.parametrize("reverse", [False, True])
def test_numeric_literal_oneof_overlap_is_directional(location, keyword, left, right, reverse):
    def branch(value):
        return {keyword: [value] if keyword == "enum" else value}

    old = review._document({"oneOf": [branch(left)]}, location)
    new = review._document({"oneOf": [branch(left), branch(right)]}, location)
    if reverse:
        old, new = new, old
    findings = review._diff(old, new).changed_endpoints
    assert findings
    assert any(f.breakage for f in findings) is ((location != "response") != reverse)


@pytest.mark.parametrize("location", ["request", "response", "parameter"])
@pytest.mark.parametrize("keyword", ["enum", "const", "default"])
@pytest.mark.parametrize(
    ("left", "right"),
    [(1, 1.0), ({"schema": {"items": [1, False, "1"]}}, {"schema": {"items": [1.0, False, "1"]}})],
)
def test_numeric_literal_representations_are_equivalent(location, keyword, left, right):
    old = review._document({keyword: [left] if keyword == "enum" else left}, location)
    new = review._document({keyword: [right] if keyword == "enum" else right}, location)
    assert not review._diff(old, new).endpoint_findings
    assert not review._diff(new, old).endpoint_findings


@pytest.mark.parametrize("location", ["request", "response"])
@pytest.mark.parametrize("other", [True, "1", {"value": True}, {"value": "1"}])
@pytest.mark.parametrize("keyword", ["enum", "const", "default"])
def test_numeric_literals_remain_distinct_from_booleans_and_strings(location, keyword, other):
    number = {"value": 1} if isinstance(other, dict) else 1
    old = review._document({keyword: [number] if keyword == "enum" else number}, location)
    new = review._document({keyword: [other] if keyword == "enum" else other}, location)
    for before, after in ((old, new), (new, old)):
        findings = review._diff(before, after).changed_endpoints
        assert findings
        assert any(f.breakage for f in findings) is (keyword != "default")


@pytest.mark.parametrize("location", ["request", "response"])
@pytest.mark.parametrize("reverse", [False, True])
def test_numeric_enum_expansion_uses_value_equality(location, reverse):
    old = review._document({"enum": [1]}, location)
    new = review._document({"enum": [1.0, 2]}, location)
    if reverse:
        old, new = new, old
    findings = review._diff(old, new).changed_endpoints
    assert findings
    assert any(f.breakage for f in findings) is ((location == "response") != reverse)


@pytest.mark.parametrize("keyword", ["example", "examples", "default", "const", "enum"])
@pytest.mark.parametrize("placement", ["schema", "media", "parameter", "component"])
def test_schema_keyword_inventory_excludes_literal_payloads(keyword, placement):
    document = review._document({"type": "string"})
    operation = document["paths"]["/widgets"]["post"]
    media = operation["requestBody"]["content"]["application/json"]
    payload = {"schema": {"customer": "literal"}, "schemas": {"Literal": {"customer": "literal"}}}
    if keyword in {"examples", "enum"}:
        payload = [payload]
    if placement == "schema":
        media["schema"][keyword] = payload
    elif placement == "media":
        media[keyword] = payload
    elif placement == "parameter":
        operation["parameters"] = [
            {"name": "q", "in": "query", "schema": {"type": "string"}, keyword: payload}
        ]
    else:
        document["components"] = {"examples": {"Sample": {"value": payload}}}
    expected = {"type", keyword} if placement == "schema" else {"type"}
    assert spec_schema_keywords(document) == expected
    assert "customer" not in spec_schema_keywords(document)


def test_schema_keyword_inventory_only_visits_openapi_positions():
    document = review._document({"type": "string"})
    document["x-payload"] = {"schema": {"customer": "literal"}}
    document["components"] = {
        "schemas": {
            "Unused": {"properties": {"schema": {"type": "number"}}, "futureKeyword": True}
        },
        "links": {"Next": {"requestBody": {"schema": {"customer": "literal"}}}},
    }
    assert spec_schema_keywords(document) == {"type", "properties", "futureKeyword"}


@pytest.mark.parametrize("keyword", ["enum", "const"])
@pytest.mark.parametrize("other", [True, "1", {"value": True}, {"value": "1"}])
@pytest.mark.parametrize("location", ["request", "response"])
def test_literal_oneof_branches_keep_json_types_distinct(keyword, other, location):
    number = {"value": 1} if isinstance(other, dict) else 1

    def branch(value):
        return {keyword: [value] if keyword == "enum" else value}

    old = review._document({"oneOf": [branch(number)]}, location)
    new = review._document({"oneOf": [branch(number), branch(other)]}, location)
    findings = review._diff(old, new).changed_endpoints
    assert any(f.breakage for f in findings) is (location == "response")


@pytest.mark.parametrize("keyword", ["example", "examples"])
@pytest.mark.parametrize("location", ["request", "response", "parameter"])
def test_media_literal_schema_keys_do_not_create_raw_keyword_findings(keyword, location):
    old = review._document({"type": "string"}, location)
    new = deepcopy(old)
    operation = new["paths"]["/widgets"]["post"]
    if location == "request":
        target = operation["requestBody"]["content"]["application/json"]
    elif location == "response":
        target = operation["responses"]["200"]["content"]["application/json"]
    else:
        target = operation["parameters"][0]
    payload = {"schema": {"customer": "literal"}}
    target[keyword] = payload if keyword == "example" else {"Sample": {"value": payload}}
    assert not review._diff(old, new).endpoint_findings
    assert not review._diff(new, old).endpoint_findings
