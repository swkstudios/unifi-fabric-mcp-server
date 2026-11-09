"""The empty-body refusal is worded by tool kind and names what the body needs.

Every write tool taking one object body refuses an empty body before any request,
except a literal empty firewall rule whose unpublished schema is upstream-judged
(``No fields provided``). An update asks for a field to change; a create or an action
says there is nothing to create / no action to send and names every key its published
request schema requires (``write_body.CREATE_ACTION_REQUIRED_KEYS``, pinned here to the
vendored spec operation the tool really calls), or points at its description when the
operation publishes no schema.
"""

from __future__ import annotations

import functools
import logging

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import test_spec_conformance as sc
from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_catalog import lazy_parametrize
from tests._tool_classes import tool_batches
from tests.test_refusal_policy import _deref, _required
from unifi_fabric.write_body import (
    CREATE_ACTION_REQUIRED_KEYS,
    NO_FIELDS,
    body_argument,
    body_kind,
)

TOOLS = cti.TOOLS


@functools.cache
def _lz_BODY_TOOLS():
    return sorted(n for n, t in TOOLS.items() if body_argument(t))


@functools.cache
def _lz_CREATE_ACTION():
    return [n for n in _lz_BODY_TOOLS() if body_kind(n) != "update"]


@pytest.fixture(autouse=True)
def _quiet_logs():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


def test_kinds_are_not_vacuous():
    kinds = {body_kind(n) for n in _lz_BODY_TOOLS()}
    assert kinds == {"update", "create", "action"}, kinds
    assert len(_lz_CREATE_ACTION()) >= 15


@tool_batches("name", lambda: _lz_BODY_TOOLS())
async def test_empty_body_message_by_kind(monkeypatch, name):
    arg = body_argument(TOOLS[name])
    args = {**tool_args.generated_args(TOOLS[name]), arg: {}}
    up = uh.FakeUpstream()
    if name == "create_firewall_rule":
        await cti._call(monkeypatch, name, up, args)
        assert len(up.writes()) == 1
        assert up.writes()[0].sent_json == {}
        return
    with pytest.raises(ToolError) as exc:
        await cti._call(monkeypatch, name, up, args)
    text = str(exc.value)
    assert text.startswith(NO_FIELDS), text
    assert up.served == []
    if body_kind(name) == "update":
        assert "field to change" in text, text
        return
    assert "to change" not in text, text
    gist = "nothing to create" if body_kind(name) == "create" else "no action to send"
    assert gist in text, text
    required = CREATE_ACTION_REQUIRED_KEYS.get(name)
    if required:
        assert all(key in text for key in required), (required, text)
    else:
        assert "tool description" in text, text


@pytest.mark.parametrize("rule", [{}, {"name": "synthetic"}])
async def test_unspecced_firewall_body_reaches_controller_unchanged(monkeypatch, rule):
    name = "create_firewall_rule"
    args = {**tool_args.generated_args(TOOLS[name]), "rule": rule}
    up = uh.FakeUpstream()
    await cti._call(monkeypatch, name, up, args)
    writes = up.writes()
    assert len(writes) == 1
    assert writes[0].method == "POST"
    assert writes[0].path.endswith("/rest/firewallrule")
    assert writes[0].sent_json == rule


def _spec_required(tool: str) -> set[str] | None:
    """The spec-required keys of the body (or required query parameters) of the write
    ``tool`` sends; None when its operation is unspecced."""
    writes = [r for r in sc.capture(tool) if r.method != "GET" and not r.resolution]
    assert writes, tool
    req = writes[-1]
    family, inner = sc.route(req.path)
    if family.startswith("unspecced:"):
        return None
    specs = [sc.specs()[s] for s in sc.DIRECT_SPECS] if family == "direct" else [sc.specs()[family]]
    for spec in specs:
        hit = sc._match(spec, inner)
        if hit is None:
            continue
        op = spec.doc["paths"][hit[0]][req.method.lower()]
        body = op.get("requestBody")
        if body:
            return _required(spec, _deref(spec, body)["content"]["application/json"]["schema"])
        return {
            _deref(spec, p)["name"]
            for p in op.get("parameters") or ()
            if _deref(spec, p).get("in") == "query" and _deref(spec, p).get("required")
        }
    if (
        tool == "create_firewall_rule"
        and req.method == "POST"
        and req.path.endswith("/rest/firewallrule")
    ):
        return None  # This EA operation has no published request schema.
    raise AssertionError(f"{tool}: {req.method} {req.path} matches no spec operation")


@lazy_parametrize("name", lambda: _lz_CREATE_ACTION())
def test_required_keys_are_the_vendored_specs(name):
    expected = _spec_required(name)
    if expected is None:
        assert name not in CREATE_ACTION_REQUIRED_KEYS
    else:
        assert set(CREATE_ACTION_REQUIRED_KEYS.get(name, ())) == expected, (name, expected)


def test_query_dict_is_not_a_request_body() -> None:
    assert body_argument(TOOLS["bulk_delete_hotspot_vouchers"]) is None


async def test_missing_provenance_preserves_empty_refusal(monkeypatch):
    from unifi_fabric.write_body import CREATE_ACTION_BODY_PROVENANCE

    monkeypatch.delitem(CREATE_ACTION_BODY_PROVENANCE, "create_firewall_rule")
    args = {**tool_args.generated_args(TOOLS["create_firewall_rule"]), "rule": {}}
    up = uh.FakeUpstream()
    with pytest.raises(ToolError, match=NO_FIELDS):
        await cti._call(monkeypatch, "create_firewall_rule", up, args)
    assert up.served == []
