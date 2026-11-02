"""Server-added ``_`` metadata never replaces an upstream key of the same name.

Rule: upstream bodies pass through verbatim, and a key the server adds (``_verified``,
``_before``, ``_count`` ...) that the upstream body already carries goes in the
``with_context`` collision bucket (``_wrapperFields``), never over the upstream value.

The generic property runs every registered tool twice through the shape-faithful fake
upstream. The first run records every ``_``-prefixed key the tool's result carries; the
second serves every 2xx JSON object body (and each object record of its record arrays)
with those keys already present, each holding a sentinel, plus a marker naming the keys
seeded into that object. Any result object carrying the marker is a pass-through of an
upstream body, so every key the marker names must still hold its sentinel.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import upstream_harness as uh
from tests._tool_classes import class_axis

SENTINEL = "upstream-sentinel"
#: Every seeded object carries this key, naming the keys seeded into it.
MARKER = "_upstreamSeeded"


def _sentinel(key: str) -> str:
    return f"{SENTINEL}:{key}"


#: Server metadata without the ``_`` prefix (the partial-result markers).
UNPREFIXED = frozenset({"incomplete", "incompleteReason"})


def _additive_keys(node: Any, out: set[str]) -> set[str]:
    """Every server metadata key at any depth (``_id`` is a real upstream field)."""
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(k, str) and (k.startswith("_") or k in UNPREFIXED) and k != "_id":
                out.add(k)
            _additive_keys(v, out)
    elif isinstance(node, list):
        for item in node:
            _additive_keys(item, out)
    return out


def _with_keys(record: dict[str, Any], keys: set[str]) -> dict[str, Any]:
    added = sorted(k for k in keys if k not in record)
    if not added:
        return record
    return {**{k: _sentinel(k) for k in added}, MARKER: added, **record}


def seed(body: Any, keys: set[str]) -> Any:
    """``body`` with every key present at the top level and in each object record."""
    if not isinstance(body, dict):
        return body
    seeded = _with_keys(body, keys)
    for field, value in list(seeded.items()):
        if isinstance(value, list) and value and all(isinstance(v, dict) for v in value):
            seeded[field] = [_with_keys(v, keys) for v in value]
    return seeded


class SeededUpstream(uh.FakeUpstream):
    """The fake upstream, serving every 2xx JSON object body seeded with ``seed_keys``."""

    seed_keys: frozenset[str] = frozenset()

    def __call__(self, req: httpx.Request) -> httpx.Response:
        resp = super().__call__(req)
        if not self.seed_keys or not 200 <= resp.status_code < 300:
            return resp
        if "json" not in resp.headers.get("content-type", ""):
            return resp
        try:
            body = json.loads(resp.content)
        except ValueError:
            return resp
        if not isinstance(body, dict):
            return resp
        return httpx.Response(
            resp.status_code,
            content=json.dumps(seed(body, set(self.seed_keys))).encode(),
            headers={"content-type": "application/json"},
        )


def clobbered(node: Any, path: str = "$") -> list[str]:
    """Every seeded key of a seeded (pass-through) object that no longer holds its value."""
    problems: list[str] = []
    if isinstance(node, dict):
        seeded = node.get(MARKER)
        for k in seeded if isinstance(seeded, list) else ():
            got = node.get(k, "<missing>")
            if got != _sentinel(k):
                problems.append(f"{path}.{k} = {json.dumps(got, default=str)[:80]}")
        for k, v in node.items():
            problems += clobbered(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, item in enumerate(node):
            problems += clobbered(item, f"{path}[{i}]")
    return problems


#: Harness scenarios: the plain fake upstream, a drain that stops short (the incomplete
#: markers), and two keys (the per-key merges and their envelopes).
SCENARIOS: dict[str, dict[str, Any]] = {
    "normal": {},
    "incomplete": {"mode": "paged", "repeat_pages": True},
    "two-keys": {"hosts_by_key": "two-keys"},
}


def _upstream(cls: type[uh.FakeUpstream], scenario: str) -> uh.FakeUpstream:
    kw = dict(SCENARIOS[scenario])
    if kw.get("hosts_by_key") == "two-keys":
        kw["hosts_by_key"] = cti._two_key_hosts()
    return cls(**kw)


async def _payload(monkeypatch, name: str, up: uh.FakeUpstream, scenario: str) -> Any:
    keys = cti._KEYS if scenario == "two-keys" else None
    return uh.result_payload(await cti._call(monkeypatch, name, up, keys=keys))


@class_axis("name", lambda: sorted(cti._lz_TOOLS()), scenario=lambda: sorted(SCENARIOS))
async def test_upstream_additive_keys_survive_server_metadata(monkeypatch, name, scenario):
    try:
        first = await _payload(monkeypatch, name, _upstream(uh.FakeUpstream, scenario), scenario)
    except ToolError:
        return  # this scenario ends in a tool error: no result object to compare
    keys = _additive_keys(first, set())
    up = _upstream(SeededUpstream, scenario)
    assert isinstance(up, SeededUpstream)
    up.seed_keys = frozenset(keys)
    problems = clobbered(await _payload(monkeypatch, name, up, scenario))
    assert problems == [], f"{name} [{scenario}]: " + "; ".join(problems[:6])


# ------------------------------------------------------------ one case per merge site
# (tool, scenario, the seeded key, where its object sits in the result, whether the
# server adds its own value there): each site that merged metadata into an upstream body.
SITES = [
    # protect_users_assets._result (update_protect_user and four sibling writes)
    ("update_protect_user", "normal", "_verified", (), True),
    ("update_protect_user", "normal", "_before", (), True),
    ("update_protect_user_group", "normal", "_after", (), True),
    ("update_protect_device_tag", "normal", "_readAfterError", (), True),
    ("update_protect_user_notifications", "normal", "_verified", (), True),
    ("set_protect_notifications_muted", "normal", "_warnings", (), True),
    # protect_automation_backup.update_protect_automation
    ("update_protect_automation", "normal", "_verified", (), True),
    ("update_protect_automation", "normal", "_before", (), True),
    # innerspace_internal.update_innerspace_plan
    ("update_innerspace_plan", "normal", "_verified", (), True),
    # device_radios.get_device_radios
    ("get_device_radios", "normal", "_device", (), True),
    ("get_device_radios", "normal", "_radios", (), True),
    # carrier_fabric.list_carrier_subscribers (one key: envelope beside the records)
    ("list_carrier_subscribers", "normal", "_count", (), True),
    ("list_carrier_subscribers", "incomplete", "incompleteReason", (), True),
    # carrier_fabric / mobility multi-key merges: each key's body under byKey
    ("list_carrier_service_plans", "two-keys", "_count", ("byKey", "alpha"), False),
    ("list_mobility_workspaces", "two-keys", "_count", ("byKey", "beta"), False),
    # aggregation.list_all_devices (one key: envelope beside the records)
    ("list_all_devices", "normal", "_count", (), True),
    ("list_all_devices", "normal", "_filter", (), True),
    ("list_all_devices", "incomplete", "incomplete", (), True),
    # system_log: the first page's fields beside the drained rows
    ("get_system_log", "normal", "incompleteReason", (), True),
    # network_controller_admin.get_latest_firmware_versions
    ("get_latest_firmware_versions", "incomplete", "incompleteReason", (), True),
]


@pytest.mark.parametrize(
    ("name", "scenario", "key", "where", "server_adds"),
    SITES,
    ids=[f"{n}-{k}-{s}" for n, s, k, _w, _a in SITES],
)
async def test_upstream_key_survives_at_merge_site(
    monkeypatch, name, scenario, key, where, server_adds
):
    cti._lz_TOOLS()
    up = _upstream(SeededUpstream, scenario)
    assert isinstance(up, SeededUpstream)
    up.seed_keys = frozenset({key})
    node = await _payload(monkeypatch, name, up, scenario)
    for step in where:
        node = node[step]
    assert node[key] == _sentinel(key), f"{name}: upstream {key} replaced by {node[key]!r}"
    if server_adds:
        buckets = [v for k, v in node.items() if k.startswith("_wrapperFields")]
        assert any(isinstance(b, dict) and key in b for b in buckets), (
            f"{name}: the server's {key} is not in a _wrapperFields bucket"
        )
