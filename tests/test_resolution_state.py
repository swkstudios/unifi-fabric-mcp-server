"""Partial resolution provenance remains visible at the tool boundary."""

from __future__ import annotations

import asyncio

import pytest

from unifi_fabric import server
from unifi_fabric.resolution_state import (
    note_incomplete_resolution,
    wrap_resolution_result,
)


@pytest.mark.parametrize("value", [{"data": [1]}, [1, 2], None, True, "id"])
async def test_partial_resolution_preserves_original_value(value):
    async def call():
        note_incomplete_resolution("page cap")
        return value

    result = await wrap_resolution_result(call)()
    assert (result.get("incomplete") or result.get("_incomplete")) is True and (
        result.get("_incompleteReason") or result.get("incompleteReason")
    ) == "page cap"
    if isinstance(value, dict):
        assert result["data"] == value["data"]
    else:
        assert result["result"] == value


async def test_parallel_calls_do_not_share_resolution_state():
    async def call(reason):
        note_incomplete_resolution(reason)
        await asyncio.sleep(0)
        return {}

    wrapped = wrap_resolution_result(call)
    results = await asyncio.gather(wrapped("one"), wrapped("two"))
    assert [r["_incompleteReason"] for r in results] == ["one", "two"]
    assert await wrapped(None) == {}


async def test_fanout_combines_all_partial_resolution_reasons():
    async def child(reason):
        note_incomplete_resolution(reason)

    async def call():
        await asyncio.gather(child("one"), child("two"))
        return {"incompleteReason": "upstream", "data": [1]}

    result = await wrap_resolution_result(call)()
    assert result["data"] == [1]
    assert set((result.get("_incompleteReason") or result.get("incompleteReason")).split("; ")) == {
        "upstream",
        "one",
        "two",
    }


async def test_error_resets_resolution_state():
    async def failing():
        note_incomplete_resolution("failed-call")
        raise ValueError("original")

    with pytest.raises(ValueError, match="original"):
        await wrap_resolution_result(failing)()

    async def complete():
        return {"ok": True}

    assert await wrap_resolution_result(complete)() == {"ok": True}


async def test_every_registered_handler_preserves_partial_resolution():
    components = server.mcp._local_provider._components
    handlers = [c.fn for c in components.values() if callable(getattr(c, "fn", None))]
    assert handlers
    assert all(getattr(fn, "_unifi_resolution_wrapped", False) for fn in handlers)
