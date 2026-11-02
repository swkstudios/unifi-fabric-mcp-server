"""Shared argument middlewares are never stricter than the pinned spec.

An upstream ``filter`` expression (spec ``type: string``, no ``minLength``) is forwarded
blank as given by every tool that takes one; ``update_carrier_subscriber``
``clear_fields=[]`` (an optional list of SubscriberPatch fields to null) clears nothing.
A blank local filter or search applies no filter (``tests/test_blank_filters_and_hints``).
"""

from __future__ import annotations

import functools
import logging
from typing import Any
from urllib.parse import parse_qsl

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_catalog import lazy_parametrize

#: Arguments forwarded verbatim as an upstream ``filter`` query parameter (the Network
#: Integration list operations' ``filter``; get_site_inventory's device / client filter).
UPSTREAM_FILTER_ARGUMENTS = frozenset({"filter", "device_filter", "client_filter"})

TOOLS = cti.TOOLS
_call = cti._call


@pytest.fixture(autouse=True)
def _quiet_logs():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


def _payload(res: Any) -> Any:
    """What a client receives, with FastMCP's ``{"result": ...}`` list wrapper undone."""
    body = uh.result_payload(res)
    if isinstance(body, dict) and set(body) == {"result"}:
        return body["result"]
    return body


# =========================================================================== spec strictness
@functools.cache
def _lz__UPSTREAM_FILTER_CASES():
    return sorted(
        (n, a)
        for n, t in TOOLS.items()
        for a in ((t.parameters or {}).get("properties") or {})
        if a in UPSTREAM_FILTER_ARGUMENTS
    )


def test_upstream_filter_sweep_is_non_trivial():
    names = {n for n, _a in _lz__UPSTREAM_FILTER_CASES()}
    assert {"list_networks", "list_clients", "list_all_clients", "get_site_inventory"} <= names
    assert ("get_site_inventory", "device_filter") in _lz__UPSTREAM_FILTER_CASES()
    assert ("get_site_inventory", "client_filter") in _lz__UPSTREAM_FILTER_CASES()


@lazy_parametrize("blank", lambda: (["", "   "]), ids=["empty", "whitespace"])
@lazy_parametrize(("name", "arg"), lambda: _lz__UPSTREAM_FILTER_CASES())
async def test_blank_upstream_filter_is_forwarded_as_given(monkeypatch, name, arg, blank):
    """The spec's ``filter`` is ``type: string`` with no ``minLength``: a blank value is
    the upstream's to judge, sent verbatim as the ``filter`` query parameter."""
    # Blank query values are deliberately outside the recorded captures. Exercise the
    # query construction against the generated transport so replay selectors cannot
    # reject a valid, previously uncaptured argument before the assertion runs.
    up = uh.FakeUpstream(replay_recordings=False)
    args = {**tool_args.generated_args(TOOLS[name]), arg: blank}
    await _call(monkeypatch, name, up, args=args)
    sent = [
        v for s in up.served for k, v in parse_qsl(s.query, keep_blank_values=True) if k == "filter"
    ]
    assert sent and all(v == blank for v in sent), f"{name}.{arg}: filter sent {sent!r}"


def _required_args(name: str) -> dict[str, Any]:
    required = set((TOOLS[name].parameters or {}).get("required") or [])
    return {k: v for k, v in tool_args.generated_args(TOOLS[name]).items() if k in required}


async def test_clear_fields_empty_list_clears_nothing(monkeypatch):
    name = "update_carrier_subscriber"
    base = _required_args(name)
    up = uh.FakeUpstream()
    await _call(monkeypatch, name, up, args={**base, "notes": "probe-note", "clear_fields": []})
    patches = [s for s in up.writes() if s.method == "PATCH"]
    assert len(patches) == 1, up.writes()
    assert patches[0].sent_json == {"notes": "probe-note"}


async def test_clear_fields_empty_list_alone_is_the_empty_update_refusal(monkeypatch):
    name = "update_carrier_subscriber"
    up = uh.FakeUpstream()
    args = {**_required_args(name), "clear_fields": []}
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, name, up, args=args)
    assert "selects nothing" not in str(exc.value), exc.value
    assert not up.writes()
