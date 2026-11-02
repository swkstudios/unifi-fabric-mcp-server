"""Argument errors preserve data and follow published constraints."""

from types import SimpleNamespace

import pytest
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

from unifi_fabric.argument_values import ArgumentValueMiddleware
from unifi_fabric.selector_args import unknown_key_label_problem
from unifi_fabric.spec_limits import limit_problems
from unifi_fabric.write_body import EmptyUpdateMiddleware


def argument_server():
    mcp = FastMCP("argument-regression")

    @mcp.tool()
    async def list_networks(limit: int = 200, flag: bool = False):
        """Return the requested limit.

        Args:
            limit: Page size.
            flag: A boolean flag.
        """
        return {"limit": limit, "flag": flag}

    @mcp.tool()
    async def bounded_probe(amount: int = 200):
        return {"amount": amount}

    mcp.add_middleware(ArgumentValueMiddleware(mcp))
    return mcp


@pytest.mark.parametrize("value", [True, False])
async def test_booleans_are_not_integer_arguments(value):
    with pytest.raises(ToolError, match="limit.*integer.*boolean"):
        await argument_server().call_tool("list_networks", {"limit": value})


@pytest.mark.parametrize("value", ["-1"])
async def test_coerced_numeric_input_obeys_pinned_bounds(value):
    with pytest.raises(ToolError, match="limit.*spec (minimum|maximum)"):
        await argument_server().call_tool("list_networks", {"limit": value})


async def test_requested_count_above_wire_maximum_is_accepted():
    result = await argument_server().call_tool("list_networks", {"limit": "201"})
    assert result.structured_content["limit"] == 201


@pytest.mark.parametrize("value", [0, 200, "0", "200"])
async def test_spec_endpoints_and_boolean_flags_remain_accepted(value):
    result = await argument_server().call_tool("list_networks", {"limit": value, "flag": True})
    assert result.structured_content == {"limit": int(value), "flag": True}


def test_large_enum_input_echo_is_whole_without_mutating_value():
    """Echoed caller input is never truncated (Build rules 2 and 8)."""
    value = "x" * 10000
    message = "; ".join(limit_problems(value, {"enum": ["ok"]}, "interval"))
    assert message == f"interval is {value!r}: must be one of 'ok' (spec enum)"
    assert value == "x" * 10000


def test_large_unknown_key_label_echo_is_whole():
    label = "x" * 10000
    message = unknown_key_label_problem(label, ["primary"])
    assert message is not None and repr(label) in message
    assert "..." not in message
    assert "valid labels: primary" in message


@pytest.mark.parametrize(
    "name,body,reason",
    [
        ("create_network", {}, "empty_update"),
        ("set_acl_rule_ordering", {"wrongKey": []}, "required_body_fields"),
    ],
)
async def test_invalid_body_precedes_unknown_host(name, body, reason):
    visits = []
    middleware = EmptyUpdateMiddleware(SimpleNamespace(), audit=lambda t, r: visits.append((t, r)))
    middleware._body_args[name] = "body"
    middleware._required[name] = frozenset({"host", "body"})
    context = SimpleNamespace(
        message=SimpleNamespace(name=name, arguments={"host": "bad", "body": body})
    )

    async def next_call(context):
        raise AssertionError("must not execute tool body or resolve host")

    with pytest.raises(ToolError, match="No request was sent"):
        await middleware.on_call_tool(context, next_call)
    assert visits == [(name, reason)]


async def test_valid_body_does_not_add_host_resolution():
    middleware = EmptyUpdateMiddleware(SimpleNamespace())
    middleware._body_args["create_network"] = "body"
    middleware._required["create_network"] = frozenset({"host", "body"})
    context = SimpleNamespace(
        message=SimpleNamespace(
            name="create_network", arguments={"host": "primary", "body": {"name": "test"}}
        )
    )

    async def next_call(context):
        return "unchanged"

    assert await middleware.on_call_tool(context, next_call) == "unchanged"


def test_circular_json_is_reported_explicitly():
    from unifi_fabric.argument_values import non_finite_problem

    value = {}
    value["self"] = value
    assert "circular reference" in non_finite_problem(value, "body").lower()


def test_deep_acyclic_json_is_not_called_circular():
    from unifi_fabric.argument_values import non_finite_problem

    value = {}
    for _ in range(1500):
        value = {"child": value}
    assert non_finite_problem(value, "body") is None


def test_shared_json_subobjects_are_not_circular():
    from unifi_fabric.argument_values import non_finite_problem

    shared = {"finite": 1}
    assert non_finite_problem({"a": shared, "b": shared}, "body") is None


@pytest.mark.parametrize("value", [True, False])
async def test_real_output_id_rejects_boolean_before_resolution(value):
    from unifi_fabric import server

    with pytest.raises(ToolError, match="output_id.*integer.*boolean"):
        await server.mcp.call_tool(
            "alarm_hub_trigger_output",
            {"host": "bad-host", "alarm_hub_id": "hub", "output_id": value},
        )


async def test_unknown_argument_name_echo_is_whole():
    """No truncation of echoed caller input (Build rules 2 and 8): a cut echo leaves a
    long secret's prefix visible past the whole-token scrubber."""
    from unifi_fabric.argument_errors import ArgumentErrorMiddleware

    mcp = argument_server()
    mcp.add_middleware(ArgumentErrorMiddleware(mcp))
    name = "x" * 10000
    with pytest.raises(ToolError) as exc:
        await mcp.call_tool("list_networks", {name: 1})
    assert f"- {name}: not a parameter of this tool" in str(exc.value)
    assert "truncated" not in str(exc.value)


@pytest.mark.parametrize("host", [True, 123])
async def test_mistyped_host_precedes_empty_body_without_resolution(monkeypatch, host):
    from unifi_fabric import server

    def unexpected_runtime():
        raise AssertionError("a mistyped host must not resolve")

    monkeypatch.setattr(server, "_require", unexpected_runtime)
    with pytest.raises(ToolError) as exc:
        await server.mcp.call_tool(
            "create_network", {"host": host, "site": "default", "network_config": {}}
        )
    assert "host: invalid value" in str(exc.value)
    assert "No fields provided" not in str(exc.value)


@pytest.mark.parametrize("kind", ["finite", "spec"])
def test_nested_error_key_echo_is_whole(kind):
    from unifi_fabric.argument_values import non_finite_problem

    key = "x" * 10000
    if kind == "finite":
        message = non_finite_problem({key: float("nan")}, "body")
    else:
        message = "; ".join(
            limit_problems({key: -1}, {"properties": {key: {"minimum": 0}}}, "body")
        )
    assert message and f"body.{key} is " in message
    assert "truncated" not in message and "..." not in message


@pytest.mark.parametrize("digits", [309, 4299])
async def test_long_integer_string_is_an_integer_not_non_finite(monkeypatch, digits):
    """Integer arguments parse as integers, never through float: ``"1" + "0" * 309``
    is past the float range but a finite integer, so it reaches the spec bound check
    (and the framework's integer coercion) instead of a NaN/Infinity refusal."""
    from unifi_fabric.spec_limits import SPEC_LIMITS

    monkeypatch.setitem(SPEC_LIMITS, "bounded_probe", {"amount": {"maximum": 200}})
    value = "1" + "0" * digits
    with pytest.raises(ToolError) as exc:
        await argument_server().call_tool("bounded_probe", {"amount": value})
    message = str(exc.value)
    assert "must be finite" not in message
    assert f"'amount' is {value}: must be <= 200 (spec maximum 200)" in message


async def test_integer_string_within_bounds_parses_exactly(monkeypatch):
    from unifi_fabric.spec_limits import SPEC_LIMITS

    monkeypatch.setitem(
        SPEC_LIMITS, "list_networks", {"limit": {"minimum": 10**309, "maximum": 10**309}}
    )
    result = await argument_server().call_tool("list_networks", {"limit": "1" + "0" * 309})
    assert result.structured_content["limit"] == 10**309


@pytest.mark.parametrize("value", ["NaN", "-Infinity", " inf "])
async def test_integer_string_nan_and_infinity_still_refused(value):
    with pytest.raises(ToolError) as exc:
        await argument_server().call_tool("list_networks", {"limit": value})
    assert "numbers must be finite" in str(exc.value)


async def test_integer_string_past_digit_limit_left_to_framework(monkeypatch):
    """Past the interpreter's integer digit limit (shared with the framework) the value
    is not refused as non-finite; the framework reports its own integer error."""
    from unifi_fabric.spec_limits import SPEC_LIMITS

    monkeypatch.setitem(SPEC_LIMITS, "list_networks", {"limit": {"maximum": 200}})
    with pytest.raises(Exception) as exc:  # the framework's own validation error
        await argument_server().call_tool("list_networks", {"limit": "9" * 4301})
    assert "must be finite" not in str(exc.value)
    assert "spec maximum" not in str(exc.value)
    assert "exceeded maximum size" in str(exc.value)


@pytest.mark.parametrize("sign", ["", "-"])
def test_integer_string_spec_value_past_digit_limit_compares_by_sign(sign):
    value = sign + "9" * 5000
    problems = limit_problems(value, {"integerString": True, "minimum": 0, "maximum": 10}, "x")
    rule = ">= 0 (spec minimum 0)" if sign else "<= 10 (spec maximum 10)"
    assert problems == [f"x is {value!r}: must be {rule}"]


async def test_framework_integer_decimal_string_remains_accepted(monkeypatch):
    from unifi_fabric.spec_limits import SPEC_LIMITS

    monkeypatch.setitem(
        SPEC_LIMITS, "list_networks", {"limit": {"type": "integer", "minimum": 0, "maximum": 200}}
    )
    args = {"limit": "2.0", "flag": True}
    result = await argument_server().call_tool("list_networks", args)
    assert result.structured_content == {"limit": 2, "flag": True}
    assert args == {"limit": "2.0", "flag": True}


async def test_unknown_tool_names_do_not_grow_middleware_caches():
    from unittest.mock import AsyncMock

    missing = SimpleNamespace(get_tool=AsyncMock(return_value=None))
    values = ArgumentValueMiddleware(missing)
    bodies = EmptyUpdateMiddleware(missing)
    for index in range(1000):
        assert await values._number_args(f"unknown-{index}") == frozenset()
        assert await bodies._body_arg(f"unknown-{index}") is None
    assert not values._numbers and not values._integers
    assert not bodies._body_args and not bodies._required
