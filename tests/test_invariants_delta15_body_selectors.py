"""Catalog-wide: cyclic JSON and own-selector syntax are refused before every request.

A cyclic (self-referential) argument gets the actionable circular-reference error, never
a RecursionError from a recursive body helper, and sends nothing. Selector syntax (blank,
whitespace-padded or control-character host/site/key_label) is refused before any
resolution request, alone or combined with an invalid body.
"""

from __future__ import annotations

import functools
from typing import Any

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_classes import class_axis
from unifi_fabric.selector_args import NESTED_SELECTOR_ARGUMENTS, SELECTOR_ARGUMENTS
from unifi_fabric.write_body import body_argument, update_problem

TOOLS = cti.TOOLS


def _kinds(schema: Any) -> set[str]:
    """The JSON types a parameter schema admits (anyOf/oneOf branches included)."""
    if not isinstance(schema, dict):
        return set()
    raw = schema.get("type")
    kinds = set(raw) if isinstance(raw, list) else {raw} if isinstance(raw, str) else set()
    for branch in [*schema.get("anyOf", []), *schema.get("oneOf", [])]:
        kinds |= _kinds(branch)
    return kinds


@functools.cache
def _lz_GUARDED():
    return sorted((name, arg) for name, tool in TOOLS.items() if (arg := body_argument(tool)))


#: Every object- or array-typed argument in the catalog (bodies, params, metadata, lists).
@functools.cache
def _lz_STRUCTURED():
    return sorted(
        (name, arg, "object" if "object" in kinds else "array")
        for name, tool in TOOLS.items()
        for arg, schema in (tool.parameters.get("properties") or {}).items()
        if (kinds := _kinds(schema)) & {"object", "array"}
    )


@functools.cache
def _lz_SELECTORS():
    return sorted(
        (name, arg)
        for name, tool in TOOLS.items()
        for arg in SELECTOR_ARGUMENTS
        if arg in (tool.parameters.get("properties") or {})
    )


@functools.cache
def _lz_NESTED():
    return sorted(
        (name, arg)
        for name, tool in TOOLS.items()
        for arg in NESTED_SELECTOR_ARGUMENTS
        if arg in (tool.parameters.get("properties") or {})
    )


INVALID = ["", " \t ", " padded", "padded ", "control\nname"]


def _args(name: str) -> dict[str, Any]:
    return tool_args.generated_args(TOOLS[name])


def test_catalog_instances_are_derived_and_nontrivial():
    assert len(_lz_GUARDED()) >= 50
    assert {(n, a) for n, a, _ in _lz_STRUCTURED()} >= set(_lz_GUARDED())
    assert ("fabric_connector_post", "body", "object") in _lz_STRUCTURED()
    assert ("update_network", "host") in _lz_SELECTORS()
    assert ("update_network", "site") in _lz_SELECTORS()
    assert ("query_isp_metrics", "sites") in _lz_NESTED()


def _cyclic(base: Any, kind: str, shape: str) -> Any:
    if shape == "array":
        items: list[Any] = list(base) if isinstance(base, list) else []
        items.append(items if kind != "mutual" else {"back": items})
        return items
    body: dict[str, Any] = dict(base) if isinstance(base, dict) else {}
    if kind == "self":
        body["cycle"] = body
    elif kind == "mutual":
        body["cycle"] = {"back": body}
    else:
        items = []
        items.append(items)
        body["cycle"] = items
    return body


@class_axis(
    ("name", "arg", "shape"), lambda: _lz_STRUCTURED(), kind=lambda: ["self", "mutual", "list"]
)
async def test_cyclic_arguments_are_actionable_before_every_request(
    monkeypatch, name, arg, shape, kind
):
    args = _args(name)
    upstream = uh.FakeUpstream()
    with pytest.raises(ToolError) as error:
        await cti._call(
            monkeypatch, name, upstream, {**args, arg: _cyclic(args.get(arg), kind, shape)}
        )
    message = str(error.value)
    assert "RecursionError" not in message
    assert "maximum recursion depth" not in message
    if shape == "object":
        assert "circular reference" in message and "acyclic" in message, message
    else:
        # A list of scalars may first fail its item type, naming the argument; either
        # error is actionable and neither recurses.
        assert "circular reference" in message or arg in message, message
    assert upstream.served == []


def test_direct_body_processing_refuses_cycles_and_accepts_shared_acyclic_nodes():
    body: dict[str, Any] = {}
    body["self"] = body
    with pytest.raises(ValueError, match="circular reference.*acyclic"):
        update_problem(body, "body")
    shared = {"enabled": True}
    clean, _, reason = update_problem({"a": shared, "b": shared}, "body")
    assert reason is None
    assert clean == {"a": shared, "b": shared}


@class_axis(
    ("name", "arg"),
    lambda: _lz_SELECTORS(),
    value=lambda: INVALID,
    empty_body=lambda: [False, True],
)
async def test_invalid_selector_sends_no_request_even_with_an_invalid_body(
    monkeypatch, name, arg, value, empty_body
):
    args = {**_args(name), arg: value}
    body_arg = body_argument(TOOLS[name])
    if empty_body and body_arg:
        args[body_arg] = {}
    upstream = uh.FakeUpstream()
    with pytest.raises(ToolError, match="empty|whitespace|control character|No fields"):
        await cti._call(monkeypatch, name, upstream, args)
    assert upstream.served == [], f"{name}.{arg}: unexpected resolution requests"


@class_axis(("name", "arg"), lambda: _lz_NESTED(), value=lambda: ["", "control\nname"])
async def test_nested_selector_syntax_precedes_every_request(monkeypatch, name, arg, value):
    args = _args(name)
    args[arg] = [{"hostId": "host", "siteId": value}] if name == "query_isp_metrics" else [value]
    upstream = uh.FakeUpstream()
    with pytest.raises(ToolError, match="empty|control character"):
        await cti._call(monkeypatch, name, upstream, args)
    assert upstream.served == []


@class_axis(
    ("name", "arg"),
    lambda: _lz_GUARDED(),
    kind=lambda: ["empty", "nested_empty", "additive_only", "masked_only"],
)
async def test_invalid_body_precedes_semantic_unknown_host_resolution(monkeypatch, name, arg, kind):
    from unifi_fabric.redaction import REDACTION_MASK

    bodies = {
        "empty": {},
        "nested_empty": {"nested": {}},
        "additive_only": {"_callerNote": "not a writable field"},
        "masked_only": {"value": REDACTION_MASK},
    }
    upstream = uh.FakeUpstream()
    args = {**_args(name), "host": "unknown-but-syntactically-valid", arg: bodies[kind]}
    with pytest.raises(ToolError, match="No fields provided"):
        await cti._call(
            monkeypatch,
            name,
            upstream,
            args,
            env={"UNIFI_REDACT_SECRETS": "true"} if kind == "masked_only" else None,
        )
    assert upstream.served == []
