"""Malformed body and list selectors fail before tool dispatch, with useful paths."""

from types import SimpleNamespace

import pytest
from fastmcp.exceptions import ToolError

from unifi_fabric.selector_args import SelectorArgumentMiddleware


@pytest.mark.parametrize("argument", ["camera_id", "backup_id", "radio_activity_ap_mac"])
@pytest.mark.parametrize("value", ["", "probe\n", " probe"])
async def test_scalar_selectors_are_rejected_before_dispatch(argument, value):
    calls = []

    async def dispatch(context):
        calls.append(context)

    context = SimpleNamespace(message=SimpleNamespace(arguments={argument: value}))
    with pytest.raises(ToolError, match=argument):
        await SelectorArgumentMiddleware().on_call_tool(context, dispatch)
    assert calls == []


@pytest.mark.parametrize(
    "argument", ["battery_ids", "camera_ids", "ids", "event_ids", "object_ids", "macs"]
)
@pytest.mark.parametrize("value", ["probe\n", " probe", 5])
async def test_nested_ids_name_the_bad_element_before_dispatch(argument, value):
    calls = []

    async def dispatch(context):
        calls.append(context)

    context = SimpleNamespace(message=SimpleNamespace(arguments={argument: ["native-ID", value]}))
    with pytest.raises(ToolError, match=rf"{argument}\[1\]"):
        await SelectorArgumentMiddleware().on_call_tool(context, dispatch)
    assert calls == []


async def test_valid_selectors_are_forwarded_without_normalization():
    arguments = {"camera_id": "Native-ID", "ids": ["UPPER-ID", "opaque.id"]}
    context = SimpleNamespace(message=SimpleNamespace(arguments=arguments))
    marker = object()

    async def dispatch(received):
        assert received is context
        assert received.message.arguments is arguments
        return marker

    assert await SelectorArgumentMiddleware().on_call_tool(context, dispatch) is marker
