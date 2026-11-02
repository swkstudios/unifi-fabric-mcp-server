"""Spec value limits: enforced exactly, before any request.

* The committed table (``src/unifi_fabric/_spec_limits_table.py``) is exactly what
  ``tests/spec_limits_gen.py`` derives from the vendored specs, so a limit can neither be
  invented nor go missing; every name-alike argument left out is accounted for.
* Generated from the table: argument values just past each non-paging boundary fail
  before any request; boundary values reach the upstream. Paging maxima bound each
  upstream batch, while oversized requested totals are gathered without refusal.
"""

from __future__ import annotations

import asyncio
import copy
import logging
import math
import re
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
from fastmcp.exceptions import ToolError

from tests import spec_limits_gen as gen
from tests import test_spec_conformance as sc
from tests import tool_args
from tests import upstream_harness as uh
from unifi_fabric import refusals, server
from unifi_fabric._spec_limits_table import SPEC_LIMITS
from unifi_fabric.redaction import REDACTION_MASK
from unifi_fabric.spec_limits import check_arguments, limit_problems

#: Name-alike arguments the table leaves out because the tool converts the value's type
#: before sending, with why (asserted exactly).
EXPECTED_TYPE_CONVERTED = {
    # high_quality is a boolean argument the tool sends as the spec's "true" / "false"
    # string enum: no boolean can break that enum.
    "get_camera_snapshot": ["high_quality"],
}

#: A body field that duplicates a scalar argument of the same tool: the tool refuses two
#: different values, so the boundary case sets both (create_arm_profile takes the profile
#: name as its own argument and accepts settings['name'] only when it is the same).
COUPLED: dict[tuple[str, str, str], str] = {("create_arm_profile", "settings", "name"): "name"}

#: maxItems bounds too large to build a boundary list for; the keyword is still enforced
#: (see test_large_max_items_is_enforced).
_LARGE = 10_000


# --------------------------------------------------------------------------- the table
def test_table_is_exactly_what_the_specs_derive():
    table, report = gen.derive()
    assert SPEC_LIMITS == table, (
        "src/unifi_fabric/_spec_limits_table.py is stale: run "
        "`python -m tests.spec_limits_gen --write` and `ruff format` it"
    )
    assert report["untraced"] == {}
    assert report["type_converted"] == EXPECTED_TYPE_CONVERTED
    assert report["transformed"] == sorted(f"{t}.{a}" for t, a in gen.TRANSFORMED_ARGS)
    assert report["trimmed"] == sorted(f"{t}.{a}" for t, a in gen.TRIMMED_LENGTH_ARGS)


@pytest.mark.parametrize(("tool", "arg"), sorted(gen.DESCRIBED_LIMITS))
def test_described_limits_quote_the_spec(tool, arg):
    """A prose-only limit is backed by the exact sentence of the parameter's description."""
    limit, (service, template, param, sentence) = gen.DESCRIBED_LIMITS[(tool, arg)]
    spec = sc.specs()[service]
    item = spec.doc["paths"][template]
    params = [
        sc._resolve(spec, p)[0]
        for op in item.values()
        if isinstance(op, dict)
        for p in op.get("parameters", [])
    ]
    texts = [
        str(p.get("description", ""))
        + " "
        + str(sc._resolve(spec, p.get("schema", {}))[0].get("description", ""))
        for p in params
        if p.get("name") == param
    ]
    assert any(sentence in t for t in texts), (tool, arg, texts)
    for key, bound in limit.items():
        assert SPEC_LIMITS[tool][arg][key] == bound


def test_spec_patterns_are_end_anchored_only():
    """Only a trailing '$' is translated to ECMA-262 end anchoring; no other '$' exists."""

    def patterns(node: Any) -> list[str]:
        if isinstance(node, dict):
            own = [node["pattern"]] if isinstance(node.get("pattern"), str) else []
            return own + [p for v in node.values() for p in patterns(v)]
        if isinstance(node, list):
            return [p for v in node for p in patterns(v)]
        return []

    all_patterns = patterns(SPEC_LIMITS)
    assert "^[A-Z]{3}$" in all_patterns
    for pattern in all_patterns:
        assert "$" not in pattern[:-1], pattern


@pytest.mark.parametrize(("tool", "arg"), sorted(gen.LOGICAL_PAGINATION_COUNT_ARGS))
def test_logical_count_domain_preserves_upstream_zero_minimum(tool, arg):
    assert SPEC_LIMITS[tool][arg]["minimum"] == 0
    check_arguments(tool, {arg: 0})


# --------------------------------------------------------------------------- the checker
@pytest.mark.parametrize(
    ("value", "limits", "ok"),
    [
        (None, {"minimum": 1}, True),
        (0, {"minimum": 1}, False),
        (1, {"minimum": 1}, True),
        (1.5, {"exclusiveMaximum": 1.5}, False),
        (True, {"minimum": 5}, True),  # a boolean is not a number for the numeric bounds
        (True, {"enum": [1]}, False),  # type-strict enum
        (1.0, {"enum": [1]}, True),
        ("USD\n", {"pattern": "^[A-Z]{3}$"}, False),  # ECMA '$' is the very end
        ("USD", {"pattern": "^[A-Z]{3}$"}, True),
        (REDACTION_MASK, {"maxLength": 1}, False),  # a literal value unless opted in
        ("é" * 3, {"maxLength": 3}, True),  # characters, not bytes
        (
            {"_note": 99, "x": 2},
            {"properties": {"_note": {"maximum": 1}, "x": {"maximum": 2}}},
            True,
        ),
        ([1, 3], {"items": {"maximum": 2}}, False),
        (7, {"anyOf": [{"enum": [5]}, {"minimum": 6}]}, True),
        (4, {"anyOf": [{"enum": [5]}, {"minimum": 6}]}, False),
        ("7", {"minimum": 0, "integerString": True}, True),
        ("07x", {"minimum": 0, "integerString": True}, False),
        ("٣", {"minimum": 0, "integerString": True}, False),  # ASCII digits only
        ("x", {"minimum": 0}, True),  # another type: left to the argument's type check
    ],
)
def test_checker_semantics(value, limits, ok):
    assert (limit_problems(value, limits, "'v'") == []) is ok


def test_length_errors_never_echo_the_value():
    secret = "s3cr3t-wifi-pass-" + "x" * 60
    problems = limit_problems(secret, {"maxLength": 63}, "'password'")
    assert problems and all(secret not in p for p in problems)
    assert "77 characters" in problems[0]


def test_large_max_items_is_enforced():
    assert limit_problems([1, 2, 3], {"maxItems": 2}, "'v'")
    assert limit_problems([1, 2], {"maxItems": 2}, "'v'") == []


def test_direct_callers_get_the_same_rule():
    with pytest.raises(ValueError, match="spec maximum"):
        check_arguments("siren_test_sound", {"volume": 101})
    check_arguments("siren_test_sound", {"volume": 100})


# --------------------------------------------------------------------------- boundaries
Step = tuple[str, str]  # ("prop", key) or ("item", "")


def _reject_string(limits: dict[str, Any], length: int) -> str:
    for ch in ("a", "!", "0", "A"):
        value = ch * length
        if "pattern" not in limits or not re.search(limits["pattern"], value):
            return value
    raise AssertionError(f"cannot derive a value breaking {limits}")


def _accept_string(limits: dict[str, Any], length: int) -> str:
    for ch in ("a", "A", "0"):
        value = ch * length
        if "pattern" not in limits or not limit_problems(value, {"pattern": limits["pattern"]}, ""):
            return value
    raise AssertionError(f"cannot derive a value meeting {limits}")


def _cases(limits: dict[str, Any], path: tuple[Step, ...] = ()) -> list[tuple[Any, ...]]:
    """(path, keyword, rejected value, accepted value) for every limit in a fragment."""
    out: list[tuple[Any, ...]] = []
    if "minimum" in limits:
        out.append((path, "minimum", limits["minimum"] - 1, limits["minimum"]))
    if "maximum" in limits:
        out.append((path, "maximum", limits["maximum"] + 1, limits["maximum"]))
    if "exclusiveMinimum" in limits:
        b = limits["exclusiveMinimum"]
        out.append((path, "exclusiveMinimum", b, b + 1))
    if "exclusiveMaximum" in limits:
        b = limits["exclusiveMaximum"]
        out.append((path, "exclusiveMaximum", b, b - 1))
    if "minLength" in limits and limits["minLength"] >= 1:
        n = limits["minLength"]
        out.append((path, "minLength", _reject_string(limits, n - 1), _accept_string(limits, n)))
    if "maxLength" in limits:
        n = limits["maxLength"]
        low = limits.get("minLength", 0)
        out.append((path, "maxLength", "a" * (n + 1), _accept_string(limits, max(n, low))))
    if "pattern" in limits:
        n = max(limits.get("minLength", 1), 1)
        out.append((path, "pattern", _reject_string(limits, n), _accept_string(limits, n)))
    if "enum" in limits:
        values = limits["enum"]
        strings = all(isinstance(v, str) for v in values)
        bad: Any = "__not_a_spec_value__" if strings else max(values) + 1
        for value in values:
            out.append((path, "enum", bad, value))
    item = gen.accept_value(limits.get("items", {})) if "items" in limits else "probe-item"
    if "minItems" in limits and limits["minItems"] >= 1:
        k = limits["minItems"]
        out.append((path, "minItems", [item] * (k - 1), [item] * k))
    if "maxItems" in limits and limits["maxItems"] <= _LARGE:
        k = limits["maxItems"]
        out.append((path, "maxItems", [item] * (k + 1), [item] * k))
    if "items" in limits:
        out.extend(_cases(limits["items"], (*path, ("item", ""))))
    for key, sub in (limits.get("properties") or {}).items():
        out.extend(_cases(sub, (*path, ("prop", key))))
    return out


def _with(base: Any, path: tuple[Step, ...], value: Any) -> Any:
    if not path:
        return value
    (kind, key), rest = path[0], path[1:]
    if kind == "item":
        return [_with(None, rest, value)]
    node = copy.deepcopy(base) if isinstance(base, dict) else {}
    node[key] = _with(node.get(key), rest, value)
    return node


def _boundary_params() -> list[Any]:
    params = []
    for tool, args in sorted(SPEC_LIMITS.items()):
        for arg, limits in sorted(args.items()):
            for path, keyword, bad, good in _cases(limits):
                where = ".".join(k for _kind, k in path if k) or "-"
                boundaries = (("reject", bad), ("accept", good))
                if (
                    not path
                    and (tool, arg) in gen.LOGICAL_PAGINATION_COUNT_ARGS
                    and keyword == "minimum"
                    and good == 0
                ):
                    # A positive local count is stricter than the upstream minimum zero.
                    boundaries = (("logical-reject", -1), ("logical-reject", 0), ("accept", 1))
                for kind, value in boundaries:
                    if (
                        not path
                        and arg in {"limit", "page_size", "pageSize"}
                        and keyword == "maximum"
                    ):
                        kind = "batch" if kind == "reject" else kind
                    params.append(
                        pytest.param(
                            tool,
                            arg,
                            path,
                            value,
                            kind,
                            id=f"{tool}-{arg}-{where}-{keyword}-{kind}-{value!r:.24}",
                        )
                    )
    return params


def _call(tool: str, args: dict[str, Any]) -> tuple[BaseException | None, list[sc.Request]]:
    upstream = sc.CapturingUpstream()
    # Boundary values are deliberate query probes, outside the recorded captures.
    upstream.replay_recordings = False
    logging.disable(logging.CRITICAL)
    try:
        with pytest.MonkeyPatch.context() as mp:
            for k, v in tool_args.TOOL_ENV.get(tool, {}).items():
                mp.setenv(k, v)
            uh.install(mp, upstream)
            try:
                asyncio.run(server.mcp.call_tool(tool, args))
            except Exception as exc:
                return exc, upstream.requests
    finally:
        logging.disable(logging.NOTSET)
    return None, upstream.requests


def _tool_value(tool: str, arg: str, value: Any) -> Any:
    limits = SPEC_LIMITS[tool][arg]
    if limits.get("integerString") and isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    return value


@pytest.mark.parametrize(("tool", "arg", "path", "value", "kind"), _boundary_params())
def test_spec_limit_boundary(tool, arg, path, value, kind):
    args = sc.conformance_args(tool)
    args[arg] = _with(args.get(arg), path, _tool_value(tool, arg, value) if not path else value)
    if len(path) == 1 and (tool, arg, path[0][1]) in COUPLED:
        args[COUPLED[(tool, arg, path[0][1])]] = value
    error, requests = _call(tool, args)
    if kind == "logical-reject":
        assert isinstance(error, ToolError), (tool, arg, path, value, error)
        registered = refusals.classify(str(error))
        assert registered is not None, (tool, arg, value, error)
        expected = {"logical-pagination-integer"}
        if value == -1:
            expected.add("spec-limits")
        assert registered.id in expected, (tool, arg, value, registered)
        expected_category = (
            refusals.SPEC if registered.id == "spec-limits" else refusals.SELECTOR_SYNTAX
        )
        assert registered.category == expected_category
        assert requests == [], (
            f"{tool}: {len(requests)} request(s) sent for an invalid logical count"
        )
    elif kind == "reject":
        assert isinstance(error, ToolError), (tool, arg, path, value, error)
        assert "spec " in str(error), str(error)
        assert requests == [], f"{tool}: {len(requests)} request(s) sent for an invalid value"
    else:
        assert error is None, f"{tool} rejected the spec boundary {arg}{path}={value!r}: {error}"
        target = [r for r in requests if gen._is_target_request(tool, r)]
        assert target, f"{tool}: no request sent"
        if kind == "batch":
            maximum = SPEC_LIMITS[tool][arg]["maximum"]
            for request in target:
                query = parse_qs(request.query)
                if arg in query:
                    assert int(query[arg][0]) <= maximum, (tool, request)


@pytest.mark.parametrize("tool", ["relay_activate_output", "alarm_hub_trigger_output"])
@pytest.mark.parametrize("output_id", ["abc", "-1", "2", "1.0", " 1", "01x", ""])
def test_output_id_is_validated_before_any_request(tool, output_id):
    args = {**sc.conformance_args(tool), "output_id": output_id}
    error, requests = _call(tool, args)
    assert isinstance(error, (ToolError, ValueError)), (output_id, error)
    assert requests == []


def test_area_opt_out_and_read_only_answer_before_a_spec_limit():
    """The opt-out / read-only refusal comes first: an out-of-range value on a refused
    tool reports the refusal, not the limit (and sends nothing)."""
    args = {**sc.conformance_args("siren_test_sound"), "volume": 0}
    for env in ({"UNIFI_PROTECT_MUTATIONS_ENABLED": "0"}, {"UNIFI_READ_ONLY": "1"}):
        with pytest.MonkeyPatch.context() as mp:
            for k, v in env.items():
                mp.setenv(k, v)
            error, requests = _call("siren_test_sound", args)
        assert isinstance(error, ToolError) and "spec minimum" not in str(error), error
        assert requests == []


@pytest.mark.parametrize(
    "tool,maximum",
    [
        (name, limits["limit"]["maximum"])
        for name, limits in sorted(SPEC_LIMITS.items())
        if "maximum" in limits.get("limit", {})
    ],
)
@pytest.mark.parametrize("requested,available", [(1000, 450), (10000, 215)])
def test_spec_paging_maximum_batches_requested_totals_without_refusal(
    monkeypatch, tool, maximum, requested, available
):
    """Every spec-capped limit reaches the upstream and gathers all available rows."""
    targets = set()
    for request in sc.captured(tool):
        hit = gen._op_for(request)
        if (
            gen._is_target_request(tool, request)
            and hit is not None
            and any(
                parameter["name"] == "limit"
                for parameter in gen._params(hit[0], hit[2]["item"], hit[2]["op"])
            )
        ):
            targets.add((request.method, request.path))
    assert targets, tool
    records = [{"id": f"synthetic-{i}"} for i in range(available)]

    class ClampedUpstream(sc.CapturingUpstream):
        def __call__(self, request):
            response = super().__call__(request)
            if (request.method, request.url.path) not in targets:
                return response
            size = min(int(request.url.params.get("limit", maximum)), maximum)
            offset = int(request.url.params.get("offset", request.url.params.get("cursor", 0)))
            data = records[offset : offset + size]
            if tool == "list_carrier_subscribers":
                end = offset + len(data)
                return httpx.Response(
                    200,
                    json={
                        "data": data,
                        "meta": {
                            "hasMore": end < available,
                            "nextCursor": str(end) if end < available else None,
                        },
                    },
                )
            return httpx.Response(
                200,
                json={
                    "data": data,
                    "offset": offset,
                    "limit": size,
                    "count": len(data),
                    "totalCount": available,
                },
            )

    upstream = ClampedUpstream()
    upstream.replay_recordings = False
    for key, value in tool_args.TOOL_ENV.get(tool, {}).items():
        monkeypatch.setenv(key, value)
    uh.install(monkeypatch, upstream)
    result = asyncio.run(
        server.mcp.call_tool(tool, {**sc.conformance_args(tool), "limit": requested})
    )
    payload = uh.result_payload(result)
    assert payload["data"] == records
    assert payload["_pageSize"] == {
        "requested": requested,
        "sent": [maximum] * math.ceil(available / maximum),
        "effective": maximum,
        "returned": available,
    }
    sent = [request for request in upstream.requests if (request.method, request.path) in targets]
    assert len(sent) == math.ceil(available / maximum)
    assert all(int(parse_qs(request.query)["limit"][0]) <= maximum for request in sent)


@pytest.mark.parametrize("enabled", [False, True])
def test_mask_literal_obeys_limits_unless_redaction_enabled(monkeypatch, enabled):
    monkeypatch.setenv("UNIFI_REDACT_SECRETS", str(enabled))
    assert bool(limit_problems(REDACTION_MASK, {"maxLength": 1}, "body.note")) is not enabled
