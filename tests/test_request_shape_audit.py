"""Synthetic mutations prove typed-body evidence fails closed, offline."""

from __future__ import annotations

import ast
from types import SimpleNamespace

import pytest

from unifi_fabric._request_shape_audit import (
    Derivation,
    Function,
    Value,
    assert_coverage,
    assert_markers,
    collect_markers,
    derive_body_arguments,
)
from unifi_fabric.request_shape import RequestShape, request_shape


def _body(existing: str, novel: str | None = None) -> dict:
    result = {"existing": existing}
    result.update({"novel": novel})
    return result


async def _original(client, existing: str, query: str):
    return await client.post("/synthetic", json=_body(existing), params={"q": query})


async def _mutated(client, existing: str, novel: str, query: str):
    return await client.post("/synthetic", json=_body(existing, novel), params={"q": query})


def _tool(fn):
    return SimpleNamespace(
        name="synthetic",
        fn=fn,
        parameters={
            "properties": {name: {"type": "string"} for name in ("existing", "novel", "query")}
        },
    )


def test_new_typed_body_argument_requires_marker_or_pending():
    marker = RequestShape("synthetic", ("existing",), "synthetic.existing")
    original = derive_body_arguments([_tool(_original)])
    assert original == {("synthetic", "existing")}
    assert_coverage(original, [marker], [])
    mutated = derive_body_arguments([_tool(_mutated)])
    assert mutated == {("synthetic", "existing"), ("synthetic", "novel")}
    with pytest.raises(AssertionError, match="lack evidence or pending.*novel"):
        assert_coverage(mutated, [marker], [])
    assert_coverage(
        mutated,
        [marker],
        [
            {
                "tool": "synthetic",
                "argument": "novel",
                "reason": "awaiting capture",
                "tracking": "synthetic-tracker",
            }
        ],
    )


def test_marker_requires_proven_evidence_even_when_coverage_is_complete():
    marker = RequestShape("synthetic", ("novel",), "synthetic.novel")
    assert_coverage({("synthetic", "novel")}, [marker], [])
    with pytest.raises(AssertionError, match="missing evidence"):
        assert_markers([marker], {})
    with pytest.raises(AssertionError, match="unproven evidence"):
        assert_markers([marker], {"synthetic.novel": {"proven": False}})
    assert_markers([marker], {"synthetic.novel": {"proven": True}})


def test_marker_does_not_wrap_or_validate_the_builder():
    marked = request_shape(tool="synthetic", args=("novel",), evidence="synthetic.novel")(_body)
    assert marked is _body
    assert marked("anything", "not-an-enum") == {"existing": "anything", "novel": "not-an-enum"}
    module = SimpleNamespace(builder=marked)
    assert collect_markers([module]) == [RequestShape("synthetic", ("novel",), "synthetic.novel")]


async def _local_body(client, existing: str, novel: str, freeform: dict):
    def build(value):
        body = dict(freeform)
        body["field"] = value
        return body

    return await client.request("POST", "/synthetic", json=build(novel))


def test_local_builders_and_freeform_json():
    tool = _tool(_local_body)
    tool.parameters["properties"]["freeform"] = {"type": "object"}
    assert derive_body_arguments([tool]) == {("synthetic", "novel")}


def test_stale_and_duplicate_pending_are_errors():
    pending = {"tool": "synthetic", "argument": "novel", "reason": "capture", "tracking": "issue"}
    with pytest.raises(AssertionError, match="stale"):
        assert_coverage(set(), [], [pending])
    with pytest.raises(AssertionError, match="duplicate"):
        assert_coverage({("synthetic", "novel")}, [], [pending, pending])


def _kwargs_body(**fields):
    return fields


async def _aliased_and_normalized(client, novel: str):
    builder = _kwargs_body
    body = builder(**{"novel": novel.lower()})
    return await client.post("/synthetic", json=body)


def test_helper_alias_keyword_expansion_and_normalization_are_traced():
    assert derive_body_arguments([_tool(_aliased_and_normalized)]) == {("synthetic", "novel")}


def _dependency_tuple() -> tuple[object, object]:
    raise AssertionError("static derivation must not execute dependencies")


async def _starred_body(client, registry, value: str):
    return await client.post("/synthetic", json={"value": value})


async def _starred_tool(novel: str):
    return await _starred_body(*_dependency_tuple(), value=novel)


def test_starred_dependency_tuple_binding_does_not_execute_code():
    assert derive_body_arguments([_tool(_starred_tool)]) == {("synthetic", "novel")}


async def _response_with_route(client, path: str):
    result = await client.get(path, key=None)
    return path, result


async def _tuple_tool(client, query: str, novel: str):
    path, record = await _response_with_route(client, query)
    return await client.post(path, json={**record, "value": novel})


def test_tuple_positions_keep_route_metadata_out_of_body_dependencies():
    assert derive_body_arguments([_tool(_tuple_tool)]) == {("synthetic", "novel")}


async def _alias_subscript_body(client, novel: str):
    body = {}
    alias = body
    alias["novel"] = novel
    return await client.post("/synthetic", json=body)


async def _alias_update_body(client, novel: str):
    body = {}
    alias = body
    alias.update({"novel": novel})
    return await client.post("/synthetic", json=body)


async def _nested_alias_body(client, novel: str):
    body = {"nested": {}}
    alias = body["nested"]
    alias["novel"] = novel
    return await client.post("/synthetic", json=body)


async def _contained_alias_body(client, novel: str):
    nested = {}
    body = {"nested": nested}
    alias = nested
    alias.update({"novel": novel})
    return await client.post("/synthetic", json=body)


@pytest.mark.parametrize(
    "fn,expected",
    [
        (_alias_subscript_body, {"novel": "synthetic-value"}),
        (_alias_update_body, {"novel": "synthetic-value"}),
        (_nested_alias_body, {"nested": {"novel": "synthetic-value"}}),
        (_contained_alias_body, {"nested": {"novel": "synthetic-value"}}),
    ],
)
async def test_mutable_aliases_require_evidence_for_arguments_sent_to_transport(fn, expected):
    sent = []

    async def post(path, *, json):
        assert path == "/synthetic"
        sent.append(json)
        return json

    await fn(SimpleNamespace(post=post), "synthetic-value")
    assert sent == [expected]
    candidates = derive_body_arguments([_tool(fn)])
    assert candidates == {("synthetic", "novel")}
    with pytest.raises(AssertionError, match="lack evidence or pending.*novel"):
        assert_coverage(candidates, [], [])


async def _cyclic_alias_body(client, novel: str):
    body = {}
    alias = body
    alias["self"] = body
    alias["novel"] = novel
    return await client.post("/synthetic", json=body)


def test_cyclic_alias_dependency_walk_terminates_and_requires_evidence():
    candidates = derive_body_arguments([_tool(_cyclic_alias_body)])
    assert candidates == {("synthetic", "novel")}
    with pytest.raises(AssertionError, match="lack evidence or pending.*novel"):
        assert_coverage(candidates, [], [])


def _cyclic_alias_builder(novel):
    body = {}
    alias = body
    alias["self"] = body
    alias["novel"] = novel
    return body


async def _cyclic_helper_body(client, novel: str):
    return await client.post("/synthetic", json=_cyclic_alias_builder(novel))


def test_cyclic_helper_summary_substitution_preserves_dependencies():
    assert derive_body_arguments([_tool(_cyclic_helper_body)]) == {("synthetic", "novel")}


async def _dynamic_alias_extraction(client, novel: str, query: str):
    body = {}
    alias = body
    alias[query] = novel
    forwarded = body["field"]
    return await client.post("/synthetic", json={"field": forwarded})


async def _dynamic_direct_extraction(client, novel: str, query: str):
    body = {}
    body[query] = novel
    return await client.post("/synthetic", json={"field": body["field"]})


async def _dynamic_nested_alias_extraction(client, novel: str, query: str):
    body = {}
    nested = {}
    alias = body
    alias[query] = nested
    nested["novel"] = novel
    return await client.post("/synthetic", json=body["field"])


@pytest.mark.parametrize(
    "fn,expected",
    [
        (_dynamic_alias_extraction, {"field": "synthetic-value"}),
        (_dynamic_direct_extraction, {"field": "synthetic-value"}),
        (_dynamic_nested_alias_extraction, {"novel": "synthetic-value"}),
    ],
)
async def test_unknown_mutated_keys_preserve_dependencies_on_constant_extraction(fn, expected):
    sent = []

    async def post(path, *, json):
        sent.append(json)
        return json

    await fn(SimpleNamespace(post=post), "synthetic-value", "field")
    assert sent == [expected]
    candidates = derive_body_arguments([_tool(fn)])
    assert candidates == {("synthetic", "novel"), ("synthetic", "query")}
    with pytest.raises(AssertionError, match="lack evidence or pending.*novel"):
        assert_coverage(candidates, [], [])


async def _inplace_alias_body(client, novel: str):
    body = {}
    alias = body
    alias |= {"novel": novel}
    return await client.post("/synthetic", json=body)


async def _nested_inplace_alias_body(client, novel: str):
    body = {"nested": {}}
    alias = body["nested"]
    alias |= {"novel": novel}
    return await client.post("/synthetic", json=body)


@pytest.mark.parametrize(
    "fn,expected",
    [
        (_inplace_alias_body, {"novel": "synthetic-value"}),
        (_nested_inplace_alias_body, {"nested": {"novel": "synthetic-value"}}),
    ],
)
async def test_inplace_dictionary_union_mutates_every_alias(fn, expected):
    sent = []

    async def post(path, *, json):
        sent.append(json)
        return json

    await fn(SimpleNamespace(post=post), "synthetic-value")
    assert sent == [expected]
    candidates = derive_body_arguments([_tool(fn)])
    assert candidates == {("synthetic", "novel")}
    with pytest.raises(AssertionError, match="lack evidence or pending.*novel"):
        assert_coverage(candidates, [], [])


def _copied_payload(payload):
    return dict(payload)


async def _mutated_helper_result(client, existing: str, query: str):
    body = {"existing": existing}
    result = _copied_payload(body)
    result["readAfterError"] = query
    return await client.patch("/synthetic", json=body)


async def test_mutating_helper_return_does_not_pollute_caller_arguments():
    sent = []

    async def patch(path, *, json):
        sent.append(json)
        return {}

    await _mutated_helper_result(SimpleNamespace(patch=patch), "kept", "response-only")
    assert sent == [{"existing": "kept"}]
    assert derive_body_arguments([_tool(_mutated_helper_result)]) == {("synthetic", "existing")}


def _set_body_parameter(body, value):
    body["novel"] = value


async def _helper_parameter_mutation(client, novel: str):
    body = {}
    _set_body_parameter(body, novel)
    return await client.post("/synthetic", json=body)


async def _dynamic_nested_subscript_mutation(client, novel: str):
    body = {"items": [{}]}
    i = 0
    body["items"][i]["k"] = novel
    return await client.post("/synthetic", json=body)


async def _dynamic_subscript_update(client, novel: str):
    body = [{}]
    i = 0
    body[i].update({"novel": novel})
    return await client.post("/synthetic", json=body)


async def _loop_target_mutation(client, novel: str):
    body = {"items": [{}]}
    for item in body["items"]:
        item["k"] = novel
    return await client.post("/synthetic", json=body)


async def _comprehension_target_mutation(client, novel: str):
    body = {"items": [{}]}
    [item.update({"k": novel}) for item in body["items"]]
    return await client.post("/synthetic", json=body)


async def _list_inplace_add_mutation(client, novel: str):
    items = []
    body = {"items": items}
    items += [novel]
    return await client.post("/synthetic", json=body)


async def _list_append_mutation(client, novel: str):
    items = []
    body = {"items": items}
    items.append(novel)
    return await client.post("/synthetic", json=body)


async def _list_extend_mutation(client, novel: str):
    items = []
    body = {"items": items}
    items.extend([novel])
    return await client.post("/synthetic", json=body)


async def _list_insert_mutation(client, novel: str):
    items = []
    body = {"items": items}
    items.insert(0, novel)
    return await client.post("/synthetic", json=body)


async def _call_result_mutation(client, novel: str):
    body = {"items": [{}]}
    i = 0
    body.get("items")[i]["k"] = novel
    return await client.post("/synthetic", json=body)


async def _unknown_call_result_mutation(client, novel: str):
    body = {"item": {}}
    body.values().__iter__().__next__()["k"] = novel
    return await client.post("/synthetic", json=body)


async def _attribute_result_mutation(client, novel: str):
    body = {}
    holder = SimpleNamespace(body=body)
    holder.body["k"] = novel
    return await client.post("/synthetic", json=body)


@pytest.mark.parametrize(
    "fn,expected",
    [
        (_helper_parameter_mutation, {"novel": "synthetic-value"}),
        (_dynamic_nested_subscript_mutation, {"items": [{"k": "synthetic-value"}]}),
        (_dynamic_subscript_update, [{"novel": "synthetic-value"}]),
        (_loop_target_mutation, {"items": [{"k": "synthetic-value"}]}),
        (_comprehension_target_mutation, {"items": [{"k": "synthetic-value"}]}),
        (_list_inplace_add_mutation, {"items": ["synthetic-value"]}),
        (_list_append_mutation, {"items": ["synthetic-value"]}),
        (_list_extend_mutation, {"items": ["synthetic-value"]}),
        (_list_insert_mutation, {"items": ["synthetic-value"]}),
        (_call_result_mutation, {"items": [{"k": "synthetic-value"}]}),
        (_unknown_call_result_mutation, {"item": {"k": "synthetic-value"}}),
        (_attribute_result_mutation, {"k": "synthetic-value"}),
    ],
)
async def test_nested_and_inplace_mutations_reach_transport_and_require_evidence(fn, expected):
    sent = []

    async def post(path, *, json):
        assert path == "/synthetic"
        sent.append(json)
        return {}

    await fn(SimpleNamespace(post=post), "synthetic-value")
    assert sent == [expected]
    candidates = derive_body_arguments([_tool(fn)])
    assert candidates == {("synthetic", "novel")}
    with pytest.raises(AssertionError, match="lack evidence or pending.*novel"):
        assert_coverage(candidates, [], [])


async def _unknown_nested_key_mutation(client, novel: str):
    body = {}
    body["unknown"]["k"] = novel
    return await client.post("/synthetic", json=body)


def test_unknown_nested_constant_key_is_conservatively_a_body_dependency():
    # Static auditing must fail closed even when an unresolved receiver could
    # raise at runtime: absence of a known field is not evidence of safe shape.
    candidates = derive_body_arguments([_tool(_unknown_nested_key_mutation)])
    assert candidates == {("synthetic", "novel")}
    with pytest.raises(AssertionError, match="lack evidence or pending.*novel"):
        assert_coverage(candidates, [], [])


def _wrap_mutable_parameter(items):
    return {"items": items}


async def _returned_wrapper_tracks_later_argument_mutation(client, novel: str):
    items = []
    body = _wrap_mutable_parameter(items)
    items.append(novel)
    return await client.post("/synthetic", json=body)


async def test_fresh_helper_return_observes_later_mutations_to_contained_caller_arguments():
    sent = []

    async def post(path, *, json):
        assert path == "/synthetic"
        sent.append(json)
        return {}

    await _returned_wrapper_tracks_later_argument_mutation(
        SimpleNamespace(post=post), "synthetic-value"
    )
    assert sent == [{"items": ["synthetic-value"]}]
    candidates = derive_body_arguments([_tool(_returned_wrapper_tracks_later_argument_mutation)])
    assert candidates == {("synthetic", "novel")}
    with pytest.raises(AssertionError, match="lack evidence or pending.*novel"):
        assert_coverage(candidates, [], [])


async def _walrus_if_body(client, novel: str):
    if body := {"novel": novel}:
        return await client.post("/synthetic", json=body)


async def _walrus_while_body(client, novel: str):
    while body := {"novel": novel}:
        return await client.post("/synthetic", json=body)


async def _walrus_conditional_body(client, novel: str):
    body if (body := {"novel": novel}) else None
    return await client.post("/synthetic", json=body)


async def _walrus_comprehension_body(client, novel: str):
    [body for _ in [0] if (body := {"novel": novel})]
    return await client.post("/synthetic", json=body)


async def _walrus_helper_alias_body(client, novel: str):
    if builder := _body:
        body = builder(novel, novel)
        return await client.post("/synthetic", json=body)


@pytest.mark.parametrize(
    "fn",
    [
        _walrus_if_body,
        _walrus_while_body,
        _walrus_conditional_body,
        _walrus_comprehension_body,
        _walrus_helper_alias_body,
    ],
)
async def test_assignment_expressions_preserve_body_and_helper_dependencies(fn):
    sent = []

    async def post(path, *, json):
        assert path == "/synthetic"
        sent.append(json)
        return {}

    await fn(SimpleNamespace(post=post), "synthetic-value")
    assert sent[0].get("novel", sent[0].get("existing")) == "synthetic-value"
    candidates = derive_body_arguments([_tool(fn)])
    assert candidates == {("synthetic", "novel")}
    with pytest.raises(AssertionError, match="lack evidence or pending.*novel"):
        assert_coverage(candidates, [], [])


def _identity_payload(body):
    return body


def _returned_parameter_alias(novel):
    body = {}
    alias = _identity_payload(body)
    body["novel"] = novel
    return alias


async def _returned_parameter_alias_body(client, novel: str):
    return await client.post("/synthetic", json=_returned_parameter_alias(novel))


async def test_helper_return_parameter_alias_preserves_later_body_dependencies():
    sent = []

    async def post(path, *, json):
        assert path == "/synthetic"
        sent.append(json)
        return {}

    await _returned_parameter_alias_body(SimpleNamespace(post=post), "synthetic-value")
    assert sent == [{"novel": "synthetic-value"}]
    candidates = derive_body_arguments([_tool(_returned_parameter_alias_body)])
    assert candidates == {("synthetic", "novel")}
    with pytest.raises(AssertionError, match="lack evidence or pending.*novel"):
        assert_coverage(candidates, [], [])


def test_returned_parameter_read_links_survive_substitution_without_writeback():
    # Model the helper-return boundary directly: its collection snapshot predates
    # a caller mutation, while its read link observes the new typed dependency.
    caller_body = Value(set(), {})
    returned_alias = caller_body.detached()
    caller_body.mutate(Value({"novel"}), "novel")
    node = ast.parse(
        "async def tool(client, novel):\n"
        "    def identity():\n"
        "        return body\n"
        '    return await client.post("/synthetic", json=identity())\n'
    ).body[0]
    assert isinstance(node, ast.AsyncFunctionDef)
    _, body_arguments, _ = Derivation().analyse(Function(node, {}), {"body": returned_alias})
    assert body_arguments == {"novel"}
    with pytest.raises(AssertionError, match="lack evidence or pending.*novel"):
        assert_coverage({("synthetic", name) for name in body_arguments}, [], [])
    returned_alias.mutate(Value({"query"}), "response_only")
    assert caller_body.names == {"novel"}
    assert returned_alias.names == {"novel", "query"}


async def _walrus_callable_body(client, novel: str):
    body = (builder := _body)(novel, novel)
    body.update(builder(novel, novel))
    return await client.post("/synthetic", json=body)


async def _destructured_callable_body(client, novel: str):
    builder, other = _body, _identity_payload
    return await client.post("/synthetic", json=other(builder(novel, novel)))


async def _nested_destructured_callable_body(client, novel: str):
    builders = (_body, [_identity_payload])
    builder, [other] = builders
    return await client.post("/synthetic", json=other(builder(novel, novel)))


async def _list_destructured_callable_body(client, novel: str):
    [builder, other] = [_body, _identity_payload]
    return await client.post("/synthetic", json=other(builder(novel, novel)))


@pytest.mark.parametrize(
    "fn",
    [
        _walrus_callable_body,
        _destructured_callable_body,
        _nested_destructured_callable_body,
        _list_destructured_callable_body,
    ],
)
async def test_callable_expression_and_destructured_aliases_require_body_evidence(fn):
    sent = []

    async def post(path, *, json):
        assert path == "/synthetic"
        sent.append(json)
        return {}

    await fn(SimpleNamespace(post=post), "synthetic-value")
    assert sent == [{"existing": "synthetic-value", "novel": "synthetic-value"}]
    candidates = derive_body_arguments([_tool(fn)])
    assert candidates == {("synthetic", "novel")}
    with pytest.raises(AssertionError, match="lack evidence or pending.*novel"):
        assert_coverage(candidates, [], [])


async def _starred_destructured_callable_body(client, novel: str):
    *builders, other = _body, _body, _identity_payload
    return await client.post("/synthetic", json=other(builders[1](novel, novel)))


async def test_starred_destructured_callable_aliases_require_body_evidence():
    candidates = derive_body_arguments([_tool(_starred_destructured_callable_body)])
    assert candidates == {("synthetic", "novel")}
    with pytest.raises(AssertionError, match="lack evidence or pending.*novel"):
        assert_coverage(candidates, [], [])
