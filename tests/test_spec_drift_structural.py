"""Whole-document fail-safe regressions and seeded raw-pointer mutations."""

import random
import sys
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from types import ModuleType

import pytest

from tests import test_spec_drift_review as review
from unifi_fabric._spec_drift import (
    SpecDriftReport,
    _canonical_raw,
    build_service_spec,
    diff_service,
    strip_example_annotations,
)


def _report(old, new):
    return SpecDriftReport(service_diffs=[review._diff(old, new)])


def _assert_review(old, new, pointer):
    report = _report(old, new)
    assert not report.is_clean
    findings = report.service_diffs[0].changed_endpoints
    assert findings
    reasons = "\n".join(reason for finding in findings for reason in finding.breaking_changes)
    assert any(finding.breakage for finding in findings)
    assert "needs_review" in reasons
    assert pointer in reasons


def _operation(doc):
    return doc["paths"]["/widgets"]["post"]


def _schema(doc):
    return _operation(doc)["requestBody"]["content"]["application/json"]["schema"]


def _insert_schema(doc, position, schema):
    if position == "callback":
        _operation(doc)["callbacks"] = {
            "onEvent": {
                "{$request.body#/url}": {
                    "post": {"requestBody": {"content": {"application/json": {"schema": schema}}}}
                }
            }
        }
        return (
            "/paths/~1widgets/post/callbacks/onEvent/{$request.body#~1url}"
            "/post/requestBody/content/application~1json/schema"
        )
    if position == "webhook":
        doc["webhooks"] = {
            "event": {
                "post": {"requestBody": {"content": {"application/json": {"schema": schema}}}}
            }
        }
        return "/webhooks/event/post/requestBody/content/application~1json/schema"
    if position == "unused":
        doc["components"] = {"schemas": {"Unused": schema}}
        return "/components/schemas/Unused"
    raise AssertionError(position)


@pytest.mark.parametrize("position", ["callback", "webhook", "unused"])
@pytest.mark.parametrize("reverse", [False, True], ids=["mutation", "revert"])
def test_unsupported_keyword_outside_endpoint_projection(position, reverse):
    old = review._document({"type": "string"})
    pointer = _insert_schema(old, position, {"type": "string"})
    new = deepcopy(old)
    _insert_schema(new, position, {"type": "string", "futureValidation": {"mode": 1}})
    before, after = (new, old) if reverse else (old, new)
    _assert_review(before, after, pointer + "/futureValidation")


_REF_POSITIONS = [
    ("root", ("futureObject",), "/futureObject/$ref"),
    ("parameter", ("components", "parameters", "Unused"), "/components/parameters/Unused/$ref"),
    ("response", ("components", "responses", "Unused"), "/components/responses/Unused/$ref"),
    ("callback", ("components", "callbacks", "Unused"), "/components/callbacks/Unused/$ref"),
    ("webhook", ("webhooks", "event"), "/webhooks/event/$ref"),
    ("link", ("components", "links", "Unused"), "/components/links/Unused/$ref"),
    ("path-item", ("components", "pathItems", "Unused"), "/components/pathItems/Unused/$ref"),
    (
        "response-link",
        ("paths", "/widgets", "post", "responses", "200", "links", "next"),
        "/paths/~1widgets/post/responses/200/links/next/$ref",
    ),
]


def _set_path(doc, path, value):
    node = doc
    for key in path[:-1]:
        node = node.setdefault(key, {})
    node[path[-1]] = value


@pytest.mark.parametrize(
    ("name", "path", "pointer"), _REF_POSITIONS, ids=[r[0] for r in _REF_POSITIONS]
)
@pytest.mark.parametrize("reverse", [False, True], ids=["mutation", "revert"])
@pytest.mark.parametrize("resolved", [False, True], ids=["unresolved", "resolved"])
def test_refs_anywhere_require_review_when_occurrence_set_changes(
    name, path, pointer, reverse, resolved
):
    old = review._document({"type": "string"})
    old["components"] = {"schemas": {"Valid": {"type": "string"}}}
    new = deepcopy(old)
    target = "#/components/schemas/Valid" if resolved else "#/components/schemas/Missing"
    _set_path(new, path, {"$ref": target})
    before, after = (new, old) if reverse else (old, new)
    _assert_review(before, after, pointer)


@pytest.mark.parametrize(
    ("name", "path", "pointer"), _REF_POSITIONS, ids=[r[0] for r in _REF_POSITIONS]
)
def test_unchanged_unresolved_ref_anywhere_is_not_clean(name, path, pointer):
    document = review._document({"type": "string"})
    _set_path(document, path, {"$ref": "#/components/schemas/Missing"})
    _assert_review(document, deepcopy(document), pointer)


def test_nested_unresolved_ref_beside_valid_ref_in_openapi_30():
    document = review._document(
        {
            "$ref": "#/components/schemas/Valid",
            "properties": {"hidden": {"$ref": "#/components/schemas/Missing"}},
        },
        dialect="3.0.3",
    )
    document["components"] = {"schemas": {"Valid": {"type": "string"}}}
    _assert_review(
        document,
        deepcopy(document),
        "/paths/~1widgets/post/requestBody/content/application~1json/schema/properties/hidden/$ref",
    )


@pytest.mark.parametrize("keyword", ["$schema", "jsonSchemaDialect"])
@pytest.mark.parametrize("reverse", [False, True], ids=["mutation", "revert"])
def test_unknown_dialect_anywhere_and_unchanged_is_review(keyword, reverse):
    old = review._document({"type": "string"})
    new = deepcopy(old)
    new["futureObject"] = {keyword: "https://example.invalid/future-dialect"}
    pointer = "/futureObject/" + keyword
    before, after = (new, old) if reverse else (old, new)
    _assert_review(before, after, pointer)
    _assert_review(new, deepcopy(new), pointer)


@pytest.mark.parametrize("keyword", ["$schema", "jsonSchemaDialect"])
@pytest.mark.parametrize("reverse", [False, True], ids=["mutation", "revert"])
def test_known_dialect_occurrence_change_anywhere_is_review(keyword, reverse):
    old = review._document({"type": "string"})
    new = deepcopy(old)
    new["futureObject"] = {keyword: "https://json-schema.org/draft/2020-12/schema"}
    before, after = (new, old) if reverse else (old, new)
    _assert_review(before, after, "/futureObject/" + keyword)


@pytest.mark.parametrize(
    ("path", "pointer"),
    [
        (("futureContract",), "/futureContract"),
        (("paths", "/widgets", "post", "futureContract"), "/paths/~1widgets/post/futureContract"),
        (("info", "futureContract"), "/info/futureContract"),
        (
            ("paths", "/widgets", "post", "responses", "200", "links", "next", "operationId"),
            "/paths/~1widgets/post/responses/200/links/next/operationId",
        ),
        (
            ("components", "schemas", "Unused", "properties", "description", "type"),
            "/components/schemas/Unused/properties/description/type",
        ),
    ],
)
@pytest.mark.parametrize("reverse", [False, True], ids=["mutation", "revert"])
def test_unexplained_raw_pointer_changes_fail_closed(path, pointer, reverse):
    old = review._document({"type": "string"})
    new = deepcopy(old)
    _set_path(new, path, "new-contract")
    before, after = (new, old) if reverse else (old, new)
    _assert_review(before, after, pointer)


@pytest.mark.parametrize("location", ["request", "response"])
@pytest.mark.parametrize("reverse", [False, True], ids=["upgrade", "downgrade"])
def test_nullable_30_and_null_union_31_are_equivalent(location, reverse):
    old = review._document({"type": "string", "nullable": True}, location, "3.0.3")
    new = review._document({"type": ["string", "null"]}, location, "3.1.0")
    before, after = (new, old) if reverse else (old, new)
    assert _report(before, after).is_clean


@pytest.mark.parametrize("location", ["request", "response"])
@pytest.mark.parametrize("dialect", ["3.0.3", "3.1.0"])
@pytest.mark.parametrize("reverse", [False, True], ids=["add-null", "remove-null"])
def test_null_acceptance_has_request_response_polarity(location, dialect, reverse):
    narrow = review._document({"type": "string"}, location, dialect)
    nullable = (
        {"type": "string", "nullable": True} if dialect == "3.0.3" else {"type": ["string", "null"]}
    )
    wide = review._document(nullable, location, dialect)
    old, new = (wide, narrow) if reverse else (narrow, wide)
    report = _report(old, new)
    assert not report.is_clean
    findings = report.service_diffs[0].changed_endpoints
    assert findings
    assert any(f.breakage for f in findings) is ((location == "response") != reverse)
    assert not any("needs_review" in reason for f in findings for reason in f.changes)


@pytest.mark.parametrize(
    "annotation",
    ["description", "summary", "example", "examples", "title", "externalDocs", "x-note"],
)
def test_pure_annotations_outside_literal_maps_are_clean(annotation):
    old = review._document({"type": "string"})
    new = deepcopy(old)
    _operation(new)[annotation] = {"free": "prose"}
    _schema(new)[annotation] = {"free": "prose"}
    assert _report(old, new).is_clean


def _object_paths(value, path=()):
    if isinstance(value, dict):
        yield path
        for key, child in value.items():
            yield from _object_paths(child, (*path, key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _object_paths(child, (*path, index))


def _at_path(doc, path):
    node = doc
    for key in path:
        node = node[key]
    return node


def test_seeded_random_raw_pointer_mutations_never_escape_detection():
    # Unknown semantics must fail safe at every object, including raw literal
    # objects; annotation exceptions are tested separately with named examples.
    rng = random.Random(20261011)  # noqa: S311 - deterministic test mutations
    old = review._document(
        {
            "type": "object",
            "properties": {
                "description": {"type": "string"},
                "payload": {"type": "object", "default": {"literal": {"value": 1}}},
            },
        }
    )
    old["components"] = {"schemas": {"Unused": {"type": "array", "items": {"type": "string"}}}}
    _insert_schema(old, "callback", {"type": "string"})
    # Preserve both callback and unused component branches.
    old["webhooks"] = {"event": {"post": {"responses": {"204": {"description": "ok"}}}}}
    paths = list(_object_paths(old))
    # Cover every raw object once, then choose random objects and nested values.
    selected = paths + [rng.choice(paths) for _ in range(100)]
    for index, path in enumerate(selected):
        new = deepcopy(old)
        node = _at_path(new, path)
        key = f"futureContract{index}"
        node[key] = rng.choice([False, index, f"contract-{index}", {"nested": [index, True]}])
        pointer = "/" + "/".join(
            str(part).replace("~", "~0").replace("/", "~1") for part in (*path, key)
        )
        assert not _report(old, new).is_clean, pointer
        assert not _report(new, old).is_clean, pointer
        assert _report(old, deepcopy(old)).is_clean, pointer


@pytest.mark.parametrize("location", ["request", "response"])
def test_json_schema_draft_nullable_does_not_add_null(location):
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "string",
        "nullable": False,
    }
    old = review._document(schema, location)
    new = deepcopy(old)
    operation = _operation(new)
    target = (operation["requestBody"] if location == "request" else operation["responses"]["200"])[
        "content"
    ]["application/json"]["schema"]
    target["nullable"] = True
    findings = _report(old, new).service_diffs[0].changed_endpoints
    # Nullable is an OpenAPI 3.0 modifier, never a draft-2020-12 null union.
    # Conservative review is allowed; a claimed directional widening is not.
    assert all(
        not finding.breakage or any("needs_review" in reason for reason in finding.breaking_changes)
        for finding in findings
    )


@pytest.mark.parametrize("index", ["-1", "01", "+0", "2", "nonnumeric"])
def test_ref_to_invalid_array_index_is_unresolved(index):
    document = review._document({"type": "string"})
    document["futureValues"] = [{"type": "string"}, {"type": "integer"}]
    document["futureObject"] = {"$ref": "#/futureValues/" + index}
    _assert_review(document, deepcopy(document), "/futureObject/$ref")


@pytest.mark.parametrize("literal", ["description", "x-auth"])
@pytest.mark.parametrize("reverse", [False, True], ids=["mutation", "revert"])
def test_security_requirement_names_are_literal_maps(literal, reverse):
    old = review._document({"type": "string"})
    old["security"] = [{literal: []}]
    new = deepcopy(old)
    new["security"][0][literal] = ["newscope"]
    before, after = (new, old) if reverse else (old, new)
    _assert_review(before, after, "/security/0/" + literal)


@pytest.mark.parametrize("reverse", [False, True], ids=["mutation", "revert"])
def test_server_variable_named_description_is_contract(reverse):
    old = review._document({"type": "string"})
    old["servers"] = [
        {
            "url": "https://{description}.example.invalid",
            "variables": {"description": {"default": "a"}},
        }
    ]
    new = deepcopy(old)
    new["servers"][0]["variables"]["description"]["default"] = "b"
    before, after = (new, old) if reverse else (old, new)
    _assert_review(before, after, "/servers/0/variables/description/default")


@pytest.mark.parametrize("reverse", [False, True], ids=["mutation", "revert"])
def test_security_scope_named_description_is_contract(reverse):
    old = review._document({"type": "string"})
    old["components"] = {
        "securitySchemes": {
            "auth": {
                "type": "oauth2",
                "flows": {
                    "clientCredentials": {
                        "tokenUrl": "https://example.invalid/token",
                        "scopes": {"description": "read"},
                    }
                },
            }
        }
    }
    new = deepcopy(old)
    new["components"]["securitySchemes"]["auth"]["flows"]["clientCredentials"]["scopes"][
        "description"
    ] = "write"
    before, after = (new, old) if reverse else (old, new)
    _assert_review(
        before,
        after,
        "/components/securitySchemes/auth/flows/clientCredentials/scopes/description",
    )


def test_identical_snapshots_without_raw_documents_fail_closed():
    document = review._document({"type": "string"})
    service = replace(
        build_service_spec("test", "1", "https://example.invalid", document),
        raw_document=None,
    )
    result = diff_service("test", service, deepcopy(service))
    report = SpecDriftReport(service_diffs=[result])
    assert not report.is_clean
    assert result.changed_endpoints
    assert any(
        finding.breakage and any("needs_review" in reason for reason in finding.breaking_changes)
        for finding in result.changed_endpoints
    )


@pytest.mark.parametrize("location", ["request", "response"])
def test_nested_explicit_draft_dialect_overrides_openapi30_nullable(location):
    old = review._document(
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {"value": {"type": "string", "nullable": False}},
        },
        location,
        "3.0.3",
    )
    new = deepcopy(old)
    operation = _operation(new)
    target = (operation["requestBody"] if location == "request" else operation["responses"]["200"])[
        "content"
    ]["application/json"]["schema"]["properties"]["value"]
    target["nullable"] = True
    findings = _report(old, new).service_diffs[0].changed_endpoints
    assert all(
        not finding.breakage or any("needs_review" in reason for reason in finding.breaking_changes)
        for finding in findings
    )


@pytest.mark.parametrize("guarantee", ["whole-document-inventory", "unexplained-raw-diff"])
def test_structural_guarantee_source_mutant_is_killed_and_reverted(guarantee, monkeypatch):
    source = Path(__file__).resolve().parents[1] / "src/unifi_fabric/_spec_drift.py"
    original = source.read_text()
    old = review._document({"type": "string"})
    if guarantee == "whole-document-inventory":
        old["futureObject"] = {"$ref": "#/components/schemas/Missing"}
        new = deepcopy(old)
        pointer = "/futureObject/$ref"
        anchors = [
            ("_document_inventory(old.raw_document)", "{}"),
            ("_document_inventory(new.raw_document)", "{}"),
        ]
    else:
        new = deepcopy(old)
        new["futureObject"] = {"newContract": True}
        pointer = "/futureObject"
        anchors = [
            ("for parts in _raw_changes(compared_before, compared_after):", "for parts in ():")
        ]
    mutated = original
    for anchor, replacement in anchors:
        assert mutated.count(anchor) == 1, "Update the source-mutant anchor after a refactor."
        mutated = mutated.replace(anchor, replacement, 1)
    _assert_review(old, new, pointer)
    module = ModuleType("unifi_fabric._spec_drift_structural_mutant")
    with monkeypatch.context() as patch:
        patch.setitem(sys.modules, module.__name__, module)
        exec(  # noqa: S102 - isolated repository-owned source mutant.
            compile(mutated, str(source), "exec"), module.__dict__
        )
        patch.setattr(review, "build_service_spec", module.build_service_spec)
        patch.setattr(review, "diff_service", module.diff_service)
        with pytest.raises(AssertionError):
            _assert_review(old, new, pointer)
    _assert_review(old, new, pointer)
    assert source.read_text() == original


def test_unused_self_reference_is_clean_until_changed():
    document = review._document({"type": "string"})
    document["components"] = {"schemas": {"A": {"$ref": "#/components/schemas/A"}}}
    assert _report(document, deepcopy(document)).is_clean
    changed = deepcopy(document)
    changed["components"]["schemas"]["A"]["minLength"] = 2
    _assert_review(document, changed, "/components/schemas/A/$ref")


@pytest.mark.parametrize("reverse", [False, True], ids=["mutation", "revert"])
def test_schema_reference_reaches_unsupported_custom_component_object(reverse):
    old = review._document({"$ref": "#/components/objects/A"})
    old["components"] = {"objects": {"A": {"type": "string"}}}
    new = deepcopy(old)
    new["components"]["objects"]["A"]["futureValidation"] = True
    before, after = (new, old) if reverse else (old, new)
    _assert_review(before, after, "/components/objects/A/futureValidation")


def _all_node_paths(value, path=()):
    yield path
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _all_node_paths(child, (*path, key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _all_node_paths(child, (*path, index))


def test_seeded_raw_scalar_deletion_and_list_mutations_never_escape():
    rng = random.Random(20261012)  # noqa: S311 - deterministic test mutations
    old = review._document(
        {
            "type": "object",
            "required": ["payload"],
            "properties": {
                "payload": {"type": "string", "enum": ["a", "b"]},
                "description": {"type": "string"},
                "batch": {"type": "array", "items": {"type": "string"}},
            },
        }
    )
    old["security"] = [{"x-auth": ["read", "write"]}]
    old["servers"] = [
        {"url": "https://example.invalid", "variables": {"description": {"default": "a"}}}
    ]
    old["components"] = {"schemas": {"Unused": {"type": "string", "enum": ["x", "y"]}}}
    _operation(old)["example"] = {"$ref": "#/components/schemas/Unused"}
    old["jsonSchemaDialect"] = "https://json-schema.org/draft/2020-12/schema"
    paths = list(_all_node_paths(old))
    scalar_paths = [path for path in paths if not isinstance(_at_path(old, path), (dict, list))]
    field_paths = [path for path in paths if path]
    list_paths = [path for path in paths if isinstance(_at_path(old, path), list)]
    cases = (
        [("replace-scalar", path) for path in scalar_paths]
        + [("delete", path) for path in field_paths]
        + [("append-list", path) for path in list_paths]
    )
    # Exhaust every candidate position and add genuinely random mutation choices.
    cases += [rng.choice(cases) for _ in range(100)]
    rng.shuffle(cases)
    for index, (kind, path) in enumerate(cases):
        new = deepcopy(old)
        if kind == "replace-scalar":
            parent = _at_path(new, path[:-1])
            prior = parent[path[-1]]
            parent[path[-1]] = not prior if isinstance(prior, bool) else f"mutated-contract-{index}"
        elif kind == "delete":
            parent = _at_path(new, path[:-1])
            del parent[path[-1]]
        else:
            _at_path(new, path).append(f"new-contract-{index}")
        pointer = "/" + "/".join(str(part).replace("~", "~0").replace("/", "~1") for part in path)

        def guard_occurrences(document):
            return [
                (node_path, key, repr(value[key]))
                for node_path in _all_node_paths(document)
                if isinstance(value := _at_path(document, node_path), dict)
                for key in ("$ref", "$schema", "jsonSchemaDialect")
                if key in value
            ]

        annotation_only = strip_example_annotations(old) == strip_example_annotations(new) or (
            _canonical_raw(old, old) == _canonical_raw(new, new)
            and guard_occurrences(old) == guard_occurrences(new)
        )
        for before, after in ((old, new), (new, old)):
            try:
                result = _report(before, after)
            except ValueError:
                # A malformed complete specification is rejected, never clean.
                continue
            assert not result.is_clean or annotation_only, (kind, pointer)
