"""Cross-tool invariants (paging, ids, relays), enforced across EVERY registered tool they apply to.

The harness and helpers are those of ``tests/test_cross_tool_invariants``.

da. Explicit-page parity: every list tool with a manual paging mode (offset/limit,
    page_token, page/page_size, limit/cursor) rejects a non-list upstream body in that
    mode exactly as its default drain does: when the drain raises, the explicit page
    raises; neither returns the bad body as a successful list.
db. Body/query-only ids follow their spec, not path rules: an id argument that reaches the
    upstream only in a JSON body or a query string is never refused with the URL-path
    charset rule (alphanumerics, '-', '_'); a value the path rule rejects is either sent
    or refused naming its schema rule (format uuid, maxLength).
dc. Required array query parameters: for every published operation whose required query
    parameter is an array with minItems 1, the tool that serves it refuses an empty list
    before ANY upstream request, and its dry-run preview carries exactly the query it
    would send (the list given, as sent).
dd. Every write tool's description states its dry-run result: it names dry-run policy,
    and every top-level key of its dry-run policy result (``"dry_run"`` when the result
    carries ``status: "dry_run"``; ``dryRun`` / ``message`` / ``preview`` for a bare
    preview).
de. Relay placeholders: a connector path carrying any placeholder other than ``{site}``
    / ``{site_id}`` (or an unbalanced brace) is refused before ANY upstream request, on
    the read relay and on every write relay.
"""

from __future__ import annotations

import functools
import glob
import json
import logging
import re
from pathlib import Path
from typing import Any

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_catalog import lazy_parametrize
from tests._tool_classes import tool_batches
from unifi_fabric.client import is_dry_run_preview

TOOLS = cti.TOOLS
_call = cti._call

_OPENAPI = Path(__file__).parent / "fixtures" / "openapi"


@pytest.fixture(autouse=True)
def _quiet_logs():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


def _props(name: str) -> dict[str, Any]:
    return TOOLS[name].parameters.get("properties", {})


async def _raises(monkeypatch, name: str, up: uh.FakeUpstream, args: dict) -> bool:
    try:
        await _call(monkeypatch, name, up, args)
    except ToolError:
        return True
    return False


# =========================================================================== (da)
def _explicit_page_args(name: str) -> dict[str, Any] | None:
    props = _props(name)
    if {"offset", "limit"} <= set(props):
        return {"offset": 0}
    if "page_token" in props:
        return {"page_token": "probe-page-token"}
    if {"page", "page_size"} <= set(props):
        return {"page": 1}
    if "cursor" in props:
        return {"cursor": "probe-cursor"}
    return None


@functools.cache
def _lz_EXPLICIT_PAGE_TOOLS():
    return sorted(n for n in cti.READ_TOOLS if _explicit_page_args(n) is not None)


#: Non-list upstream bodies: an object without the records array, bare scalars, text, empty.
_NON_LIST = [("shape", None), ("get_body", "true"), ("get_body", "int"), ("get_body", "text")]


def test_da_explicit_page_tool_set_is_complete():
    assert len(_lz_EXPLICIT_PAGE_TOOLS()) >= 30, _lz_EXPLICIT_PAGE_TOOLS()
    for name in ("list_mobility_devices", "list_mobility_clients", "list_carrier_subscribers"):
        assert name in _lz_EXPLICIT_PAGE_TOOLS(), name


@tool_batches(
    ("name", "body"), lambda: ([(n, b) for n in _lz_EXPLICIT_PAGE_TOOLS() for b in _NON_LIST])
)
async def test_da_explicit_page_rejects_non_list_bodies_like_the_drain(monkeypatch, name, body):
    kind, value = body
    base = tool_args.generated_args(TOOLS[name])

    def upstream() -> uh.FakeUpstream:
        # Generated data for both calls: the explicit page's offset/limit is no captured
        # query, and an exact-capture replay would refuse it with a harness LookupError
        # that the drain (sent with the captured query) never meets.
        if kind == "shape":
            return uh.FakeUpstream(mode="shape", replay_recordings=False)
        return uh.FakeUpstream(get_body=value, replay_recordings=False)

    drain = await _raises(monkeypatch, name, upstream(), base)
    page_up = upstream()
    explicit = await _raises(
        monkeypatch, name, page_up, {**base, **(_explicit_page_args(name) or {})}
    )
    assert explicit == drain, (
        f"{name} ({kind}={value}): drain {'raises' if drain else 'passes'} but the explicit "
        f"page {'raises' if explicit else 'passes'}"
    )


# =========================================================================== (db)
_SPEC_SAFE_UUID = "3fa85f64-5717-4562-b3fc-00000000d1b7"
_PATH_UNSAFE = "probe.id:zz~9"
_PATH_RULE = re.compile(r"expected alphanumeric, hyphens, (and )?underscores")


def _id_params(name: str) -> list[str]:
    return [p for p in _props(name) if p.endswith(("_id", "_ids"))]


def _id_value(name: str, param: str, value: str) -> Any:
    return [value] if "array" in json.dumps(_props(name)[param]) else value


@functools.cache
def _lz_ID_CASES():
    return [(n, p) for n in sorted(TOOLS) for p in _id_params(n)]


async def _body_or_query_only(monkeypatch, name: str, param: str) -> bool:
    """True when ``param`` reaches the upstream only in a JSON body or a query string.

    Generated data: the probe id is in no captured query, and an exact-capture replay
    answers an unrecorded query with a harness LookupError (seen as a refusal)."""
    base = tool_args.generated_args(TOOLS[name])
    up = uh.FakeUpstream(replay_recordings=False)
    try:
        # Catalog-wide callers must not retain every prior upstream and client
        # until their outer test's monkeypatch fixture is torn down.
        with monkeypatch.context() as tool_patch:
            await _call(
                tool_patch, name, up, {**base, param: _id_value(name, param, _SPEC_SAFE_UUID)}
            )
    except ToolError:
        return False
    if any(_SPEC_SAFE_UUID in s.path for s in up.served):
        return False
    return any(
        _SPEC_SAFE_UUID in (s.query or "") or _SPEC_SAFE_UUID in json.dumps(s.sent_json)
        for s in up.served
    )


@tool_batches(("name", "param"), lambda: _lz_ID_CASES())
async def test_db_body_and_query_ids_are_never_held_to_path_rules(monkeypatch, name, param):
    if not await _body_or_query_only(monkeypatch, name, param):
        return
    base = tool_args.generated_args(TOOLS[name])
    try:
        await _call(
            monkeypatch,
            name,
            uh.FakeUpstream(replay_recordings=False),
            {**base, param: _id_value(name, param, _PATH_UNSAFE)},
        )
    except ToolError as exc:
        assert not _PATH_RULE.search(str(exc)), (
            f"{name}.{param} travels only in a body/query but is refused by the URL-path "
            f"rule: {exc}"
        )


async def test_db_body_and_query_id_set_is_non_trivial(monkeypatch):
    found = [f"{n}.{p}" for n, p in _lz_ID_CASES() if await _body_or_query_only(monkeypatch, n, p)]
    for case in (
        "attach_carrier_subscriber_host.host_id",
        "assign_carrier_subscriber_plan.plan_id",
        "create_carrier_subscriber.plan_id",
        "update_carrier_subscriber.plan_id",
        "list_carrier_subscribers.plan_id",
        "set_firewall_policy_ordering.source_zone_id",
        "get_firewall_policy_ordering.destination_zone_id",
        "list_all_devices.host_ids",
    ):
        assert case in found, (case, found)


@pytest.mark.parametrize(
    ("name", "param", "value", "rule"),
    [
        ("attach_carrier_subscriber_host", "host_id", "h" * 129, "at most 128"),
        ("attach_carrier_subscriber_host", "host_id", "", "non-empty"),
        ("assign_carrier_subscriber_plan", "plan_id", "not-a-uuid", "format: uuid"),
        ("create_carrier_subscriber", "plan_id", "not-a-uuid", "format: uuid"),
        ("update_carrier_subscriber", "plan_id", "not-a-uuid", "format: uuid"),
        ("list_carrier_subscribers", "plan_id", "not-a-uuid", "format: uuid"),
        ("set_firewall_policy_ordering", "source_zone_id", "not-a-uuid", "format: uuid"),
        ("get_firewall_policy_ordering", "destination_zone_id", "zone_1", "format: uuid"),
    ],
)
async def test_db_spec_rule_violations_fail_before_any_request(
    monkeypatch, name, param, value, rule
):
    up = uh.FakeUpstream()
    args = {**tool_args.generated_args(TOOLS[name]), param: value}
    with pytest.raises(ToolError, match=re.escape(rule)):
        await _call(monkeypatch, name, up, args)
    assert [s for s in up.served if not s.resolution] == [], up.served


async def test_db_a_128_char_host_id_with_any_characters_is_sent(monkeypatch):
    host_id = ("gw.host:1~" * 13)[:128]
    up = uh.FakeUpstream()
    args = {**tool_args.generated_args(TOOLS["attach_carrier_subscriber_host"]), "host_id": host_id}
    await _call(monkeypatch, "attach_carrier_subscriber_host", up, args)
    sent = [s.sent_json for s in up.writes()]
    assert {"hostId": host_id} in sent, sent


# =========================================================================== (dc)
def _resolve(spec: dict, node: Any) -> Any:
    while isinstance(node, dict) and "$ref" in node:
        target: Any = spec
        for part in node["$ref"].split("/")[1:]:
            target = target[part]
        node = target
    return node


def _required_array_query_params() -> set[tuple[str, str, str, str]]:
    out: set[tuple[str, str, str, str]] = set()
    for path in sorted(glob.glob(str(_OPENAPI / "*.json"))):
        if path.endswith("manifest.json"):
            continue
        spec = json.loads(Path(path).read_text())
        for route, ops in spec.get("paths", {}).items():
            for method, op in ops.items():
                if not isinstance(op, dict) or method == "parameters":
                    continue
                for prm in op.get("parameters", []):
                    prm = _resolve(spec, prm)
                    if prm.get("in") != "query" or not prm.get("required"):
                        continue
                    schema = _resolve(spec, prm.get("schema", {}))
                    variants = [_resolve(spec, v) for v in schema.get("anyOf", [schema])]
                    if any(
                        v.get("type") == "array" and v.get("minItems", 0) >= 1 for v in variants
                    ):
                        out.add((Path(path).name, method.upper(), route, prm["name"]))
    return out


#: Every published required array query parameter -> (tool, argument). A new one in a
#: vendored spec fails test_dc_every_required_array_query_param_is_mapped until it is mapped.
REQUIRED_ARRAY_QUERY: dict[tuple[str, str, str, str], tuple[str, str]] = {
    ("protect-7.3.74.json", "DELETE", "/v1/cameras/{id}/rtsps-stream", "qualities"): (
        "delete_rtsps_stream",
        "qualities",
    ),
}


def test_dc_every_required_array_query_param_is_mapped():
    assert _required_array_query_params() == set(REQUIRED_ARRAY_QUERY)


@pytest.mark.parametrize(("tool", "arg"), sorted(set(REQUIRED_ARRAY_QUERY.values())))
async def test_dc_empty_required_array_query_fails_before_any_request(monkeypatch, tool, arg):
    up = uh.FakeUpstream()
    args = {**tool_args.generated_args(TOOLS[tool]), arg: []}
    with pytest.raises(ToolError, match=re.escape(arg)):
        await _call(monkeypatch, tool, up, args)
    assert up.served == [], [f"{s.method} {s.path}" for s in up.served]


@pytest.mark.parametrize(("tool", "arg"), sorted(set(REQUIRED_ARRAY_QUERY.values())))
async def test_dc_dry_run_preview_shows_the_exact_query(monkeypatch, tool, arg):
    args = {**tool_args.generated_args(TOOLS[tool]), arg: ["high", "low"]}
    up = uh.FakeUpstream()
    payload = uh.result_payload(
        await _call(monkeypatch, tool, up, args, env={"UNIFI_WRITE_POLICY": "dry-run"})
    )
    previews = [n for n in cti._nested_objects(payload) if is_dry_run_preview(n)]
    assert [p["preview"]["params"] for p in previews] == [{arg: ["high", "low"]}], previews
    live = uh.FakeUpstream()
    await _call(monkeypatch, tool, live, args, env={"UNIFI_WRITE_POLICY": "allow"})
    assert [w.query for w in live.writes()] == [f"{arg}=high&{arg}=low"], live.writes()


async def test_dc_create_rtsps_stream_empty_qualities_fails_before_any_request(monkeypatch):
    up = uh.FakeUpstream()
    args = {**tool_args.generated_args(TOOLS["create_rtsps_stream"]), "qualities": []}
    with pytest.raises(ToolError, match="minItems 1"):
        await _call(monkeypatch, "create_rtsps_stream", up, args)
    assert up.served == []


# =========================================================================== (dd)
@tool_batches("name", lambda: cti.WRITE_TOOLS)
async def test_dd_every_write_description_states_its_dry_run_result(monkeypatch, name):
    desc = TOOLS[name].description or ""
    assert "dry-run policy" in desc, f"{name}: the description does not state its dry-run result"
    up = uh.FakeUpstream()
    payload = uh.result_payload(
        await _call(monkeypatch, name, up, env={"UNIFI_WRITE_POLICY": "dry-run"})
    )
    if not isinstance(payload, dict):
        return
    if payload.get("status") == "dry_run":
        assert '"dry_run"' in desc, f'{name}: the description does not say status "dry_run"'
    previews = [n for n in cti._nested_objects(payload) if is_dry_run_preview(n)]
    for preview in previews:
        assert preview["status"] == "dry_run", preview
        for key in ("body", "params"):
            assert key in preview["preview"], preview
            assert re.search(rf"(?<![A-Za-z0-9_]){key}\b", desc), (
                f"{name}: the description does not name dry-run preview {key}"
            )
    missing = [k for k in payload if not re.search(rf"(?<![A-Za-z0-9_]){re.escape(k)}\b", desc)]
    assert missing == [], f"{name}: the description does not name dry-run result key(s) {missing}"


@pytest.mark.parametrize("name", ["create_hotspot_operator", "update_hotspot_operator"])
async def test_dd_hotspot_operator_dry_run_is_the_uniform_shape(monkeypatch, name):
    up = uh.FakeUpstream()
    payload = uh.result_payload(
        await _call(monkeypatch, name, up, env={"UNIFI_WRITE_POLICY": "dry-run"})
    )
    assert payload["status"] == "dry_run" and set(payload) == {"status", "response"}, payload
    assert is_dry_run_preview(payload["response"]), payload


# =========================================================================== (de)
@functools.cache
def _lz_RELAY_TOOLS():
    return sorted(n for n in TOOLS if n.startswith("fabric_connector_"))


def test_de_relay_tool_set():
    assert _lz_RELAY_TOOLS() == [
        "fabric_connector_delete",
        "fabric_connector_get",
        "fabric_connector_patch",
        "fabric_connector_post",
        "fabric_connector_put",
    ]


@lazy_parametrize("name", lambda: _lz_RELAY_TOOLS())
@lazy_parametrize(
    "path",
    lambda: (
        [
            "network/integration/v1/sites/{siteId}/devices",
            "network/integration/v1/sites/{site_id}/devices/{deviceId}",
            "network/api/s/{site}/rest/{thing}",
            "network/api/s/{host}/stat/device",
            "network/integration/v1/sites/{}/devices",
            "network/api/s/{site/stat/device",
            "network/api/s/site}/stat/device",
        ]
    ),
)
async def test_de_unknown_placeholder_fails_before_any_request(monkeypatch, name, path):
    up = uh.FakeUpstream()
    args = {"host": uh.HOST, "site": "Default", "path": path}
    with pytest.raises(ToolError, match=r"placeholder|unbalanced"):
        await _call(monkeypatch, name, up, args)
    assert up.served == [], [f"{s.method} {s.path}" for s in up.served]
