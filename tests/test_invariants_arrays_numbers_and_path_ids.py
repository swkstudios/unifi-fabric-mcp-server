"""Cross-tool invariants (arrays, numbers, path ids), enforced across EVERY registered
tool they apply to.

The harness and helpers are those of ``tests/test_cross_tool_invariants``; (bd) manual
paging for every paging family lives there.

ea. An explicit empty list is a value: every tool argument whose schema admits an array,
    given ``[]``, reaches the upstream, or fails with a registered refusal
    (``unifi_fabric.refusals``: a spec ``minItems 1``, the server's own selector syntax)
    before any request. Accepted local empty computations are checked explicitly.
eb. Numbers are finite: NaN / Infinity (also as a lax string, and nested inside any body
    object) fail before ANY upstream request.
ec. collect_protect_device_changes watches every Protect device family: the family set
    equals the vendored Protect spec's device list endpoints.
db (path ids). A path id is held to its spec, never to a stricter charset: every string
    argument that lands in a spec path parameter accepts every value its schema allows
    (type/format/enum/maxLength) and sends it percent-encoded as exactly ONE segment; a
    ``.`` / ``..`` traversal segment is the one refusal.
"""

from __future__ import annotations

import base64
import functools
import json
import logging
import math
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import test_spec_conformance as sc
from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_catalog import lazy_parametrize
from tests._tool_classes import tool_batches
from unifi_fabric import refusals
from unifi_fabric.config import APIKeyConfig
from unifi_fabric.tools import protect

TOOLS = cti.TOOLS
_call = cti._call
_OPENAPI = Path(__file__).parent / "fixtures" / "openapi"


@pytest.fixture(autouse=True)
def _quiet_logs():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


def _props(name: str) -> dict[str, Any]:
    return (TOOLS[name].parameters or {}).get("properties") or {}


def _types(schema: dict[str, Any]) -> set[Any]:
    return {schema.get("type")} | {s.get("type") for s in schema.get("anyOf") or []}


def _args(name: str, **over: Any) -> dict[str, Any]:
    return {**tool_args.generated_args(TOOLS[name]), **over}


# =========================================================================== (ea)
@functools.cache
def _lz_ARRAY_ARGS():
    return sorted((n, a) for n in TOOLS for a, s in _props(n).items() if "array" in _types(s))


def test_ea_array_argument_set_is_complete():
    found = set(_lz_ARRAY_ARGS())
    for case in (
        ("list_protect_events", "types"),
        ("list_protect_events", "cameras"),
        ("list_protect_events", "categories"),
        ("list_protect_events", "smart_detect_types"),
        ("collect_protect_events", "types"),
        ("collect_protect_events", "cameras"),
        ("collect_protect_events", "smart_detect_types"),
        ("list_all_devices", "host_ids"),
        ("get_client_link_diagnostics", "client_ids"),
        ("get_historical_stats", "attrs"),
        ("query_isp_metrics", "sites"),
        ("compare_site_performance", "sites"),
        ("forget_device", "mac"),
        ("delete_rtsps_stream", "qualities"),
        ("update_carrier_subscriber", "clear_fields"),
    ):
        assert case in found, case


#: Array arguments whose ``[]`` is a value with no upstream request at all.
_EMPTY_IS_LOCAL = {
    ("compare_site_performance", "sites"): "compares no site",
    ("batch_delete_firewall_policies", "ids"): "accepted empty batch, zero DELETEs",
    ("batch_delete_acl_rules", "ids"): "accepted empty batch, zero POSTs",
    ("batch_delete_firewall_zones", "ids"): "accepted empty batch, zero POSTs",
}


@tool_batches(("name", "arg"), lambda: _lz_ARRAY_ARGS())
async def test_ea_explicit_empty_list_reaches_upstream_or_is_a_registered_refusal(
    monkeypatch, name, arg
):
    up = uh.FakeUpstream(replay_recordings=False)
    try:
        result = await _call(monkeypatch, name, up, _args(name, **{arg: []}))
    except ToolError as exc:
        refusal = refusals.classify(str(exc))
        assert refusal is not None and refusal.category in refusals.ARGUMENT_CATEGORIES, (
            f"{name}.{arg}=[]: unregistered refusal {exc}"
        )
        assert up.served == [], [f"{s.method} {s.path}" for s in up.served]
        return
    if (name, arg) in _EMPTY_IS_LOCAL:
        assert up.served == []
        if name == "batch_delete_firewall_policies":
            result = uh.result_payload(result)
            assert result["deleted"] is True
            assert result["response"] == []
            assert result["message"] == "No firewall policy ids supplied; no writes sent."
        elif name in ("batch_delete_acl_rules", "batch_delete_firewall_zones"):
            label = "ACL rule" if name == "batch_delete_acl_rules" else "firewall zone"
            assert uh.result_payload(result) == {
                "deleted": False,
                "message": f"Empty {label} batch; no write was sent.",
                "response": None,
            }
        return
    assert any(not s.resolution for s in up.served), f"{name}.{arg}=[]: no upstream request"


async def test_ea_empty_filter_lists_send_no_filter_parameter(monkeypatch):
    # An empty list of an upstream-forwarded filter adds no query parameter (no filter).
    for arg, param in (("types", "types"), ("cameras", "cameras"), ("categories", "categories")):
        up = uh.FakeUpstream(replay_recordings=False)
        await _call(
            monkeypatch, "list_protect_events", up, _args("list_protect_events", **{arg: []})
        )
        events = [s for s in up.served if s.path.endswith("/events")]
        assert events, arg
        assert all(f"{param}=" not in s.query for s in events), [s.query for s in events]


# =========================================================================== (eb)
@functools.cache
def _lz_NUMBER_ARGS():
    return sorted(
        (n, a)
        for n in TOOLS
        for a, s in _props(n).items()
        if "number" in _types(s)
        # RelayBody deliberately also accepts a literal JSON string.  A string
        # such as "nan" is valid pass-through input there, unlike a value for
        # a numeric tool parameter which FastMCP would coerce.
        and not _types(s) & {"string", "object", "array", "boolean"}
    )


@functools.cache
def _lz_OBJECT_ARGS():
    return sorted((n, a) for n in TOOLS for a, s in _props(n).items() if sc._is_object_param(s))


@functools.cache
def _lz_STRING_OR_NUMBER_ARGS():
    """Number arguments that also accept a string (a RelayBody, a system parameter
    value). A string such as "nan" is valid pass-through input there, so only the
    non-finite floats are asserted for them."""
    plain = set(_lz_NUMBER_ARGS())
    return sorted(
        (n, a)
        for n in TOOLS
        for a, s in _props(n).items()
        if "number" in _types(s) and (n, a) not in plain
    )


_NON_FINITE_FLOATS = [math.nan, math.inf, -math.inf]
_NON_FINITE = [*_NON_FINITE_FLOATS, "nan", "Infinity"]


def test_eb_numeric_and_object_argument_sets_are_non_trivial():
    assert ("collect_protect_events", "poll_interval_seconds") in _lz_NUMBER_ARGS()
    for relay in ("fabric_connector_patch", "fabric_connector_post", "fabric_connector_put"):
        assert (relay, "body") in _lz_STRING_OR_NUMBER_ARGS()
    assert ("pos_ingest_transaction", "transaction") in _lz_OBJECT_ARGS()
    assert len(_lz_OBJECT_ARGS()) >= 50


@tool_batches(("name", "arg"), lambda: _lz_NUMBER_ARGS())
@lazy_parametrize("value", lambda: _NON_FINITE, ids=repr)
async def test_eb_non_finite_number_fails_before_any_request(monkeypatch, name, arg, value):
    up = uh.FakeUpstream()
    with pytest.raises(ToolError):
        await _call(monkeypatch, name, up, _args(name, **{arg: value}))
    assert up.served == [], [f"{s.method} {s.path}" for s in up.served]


@tool_batches(("name", "arg"), lambda: _lz_STRING_OR_NUMBER_ARGS())
@lazy_parametrize("value", lambda: _NON_FINITE_FLOATS, ids=repr)
async def test_eb_non_finite_float_fails_before_any_request_where_strings_are_valid(
    monkeypatch, name, arg, value
):
    up = uh.FakeUpstream()
    with pytest.raises(ToolError):
        await _call(monkeypatch, name, up, _args(name, **{arg: value}))
    assert up.served == [], [f"{s.method} {s.path}" for s in up.served]


@tool_batches(("name", "arg"), lambda: _lz_OBJECT_ARGS())
async def test_eb_non_finite_number_in_a_body_fails_before_any_request(monkeypatch, name, arg):
    base = tool_args.generated_args(TOOLS[name])
    body = base.get(arg) if isinstance(base.get(arg), dict) else {}
    up = uh.FakeUpstream()
    with pytest.raises(ToolError, match="finite"):
        await _call(monkeypatch, name, up, {**base, arg: {**body, "probeNumber": math.nan}})
    assert up.served == [], [f"{s.method} {s.path}" for s in up.served]


@pytest.mark.parametrize("amount", [math.nan, math.inf, -math.inf])
async def test_eb_pos_amount_non_finite_is_refused_in_the_tool_too(amount):
    class _NoCalls:
        def __getattr__(self, name):
            raise AssertionError(f"upstream touched: {name}")

    txn = {"type": "sale", "externalId": "x", "amount": amount}
    with pytest.raises(ValueError, match="finite"):
        await protect.pos_ingest_transaction(
            _NoCalls(), _NoCalls(), "h", "0123456789abcdef01234567", txn
        )


# =========================================================================== (ec)
def _spec_device_families() -> set[str]:
    spec = json.loads((_OPENAPI / "protect-7.3.74.json").read_text())
    out: set[str] = set()
    for route, ops in spec["paths"].items():
        get = ops.get("get")
        parts = route.strip("/").split("/")
        if not get or len(parts) != 2 or "{" in route:
            continue
        schema = (
            get.get("responses", {}).get("200", {}).get("content", {}).get("application/json", {})
        ).get("schema", {})
        if schema.get("type") == "array" and any(
            t.endswith(" information & management") for t in get.get("tags", [])
        ):
            out.add(parts[1])
    return out


def test_ec_device_families_equal_the_spec_device_lists():
    spec = _spec_device_families()
    assert len(spec) == 12, spec
    assert set(protect.DEVICE_FAMILIES) == spec
    assert len(protect.DEVICE_FAMILIES) == len(set(protect.DEVICE_FAMILIES))


async def test_ec_every_family_is_polled_and_a_new_siren_is_a_change(monkeypatch):
    seen = {"n": 0}

    class Up(uh.FakeUpstream):
        def __call__(self, req: httpx.Request) -> httpx.Response:
            if req.url.path.endswith("/integration/v1/sirens"):
                seen["n"] += 1
                body = [{"id": f"s{k}"} for k in range(seen["n"])]
                self._record(req, 200, body, False)
                return httpx.Response(200, json=body)
            for family in protect.DEVICE_FAMILIES:
                if req.url.path.endswith(f"/integration/v1/{family}"):
                    self._record(req, 200, [], False)
                    return httpx.Response(200, json=[])
            return super().__call__(req)

    async def _no_sleep(_seconds):
        return None

    monkeypatch.setattr(protect, "_sleep", _no_sleep)
    up = Up()
    payload = uh.result_payload(
        await _call(
            monkeypatch,
            "collect_protect_device_changes",
            up,
            _args("collect_protect_device_changes", poll_count=2, poll_interval_seconds=0.1),
        )
    )
    polled = {s.path.rsplit("/", 1)[-1] for s in up.served if "/integration/v1/" in s.path}
    assert set(protect.DEVICE_FAMILIES) <= polled, polled
    assert {"change": "added", "device": {"id": "s1"}} in payload["changes"], payload


# =========================================================================== (db) path ids
_SELECTORS = {"host", "site", "key_label"}
#: Path parameters whose published schema is a plain string but whose spec DESCRIPTION
#: names the exact values; the tool validates those values (documented on the tool).
_DESCRIBED_VALUES = {
    ("get_isp_metrics", "interval"): "type: 'Specifies whether metrics are returned using "
    "`5m` or `1h` intervals'",
    ("query_isp_metrics", "interval"): "the same /v1/isp-metrics/{type} parameter",
}


def _path_param_schema(spec: Any, template: str, method: str, pname: str) -> dict[str, Any]:
    item = spec.doc["paths"][template]
    for raw in [*item.get("parameters", []), *item.get(method.lower(), {}).get("parameters", [])]:
        p, _ = sc._resolve(spec, raw)
        if p.get("in") == "path" and p.get("name") == pname:
            schema, _ = sc._resolve(spec, p.get("schema") or {})
            return schema
    return {}


def _camel(arg: str) -> str:
    return re.sub(r"_([a-z])", lambda m: m.group(1).upper(), arg)


async def _path_id_cases() -> list[tuple[str, str, dict[str, Any]]]:
    """Every (tool, argument, spec schema) whose generated value fills a path parameter of
    a published operation, observed by running every tool once in sequence. Runs at test
    EXECUTION, once per process (``_lz_PATH_ID_CASES``), never at collection."""
    out: list[tuple[str, str, dict[str, Any]]] = []
    mp = pytest.MonkeyPatch()
    try:
        for name in sorted(TOOLS):
            if name in cti.RAW_RELAY or name in cti.NO_UPSTREAM:
                continue
            args = tool_args.generated_args(TOOLS[name])
            up = uh.FakeUpstream()
            try:
                await _call(mp, name, up, dict(args))
                # Match the same recorded identifiers the installed harness used,
                # before releasing its per-tool patches. Generated placeholders
                # otherwise depend on whichever upstream preceded this tool.
                args = tool_args.resolve_placeholders(name, args)
            except ToolError:
                continue
            finally:
                # Each install retains the previous client/registry in the undo
                # stack. Release it per tool instead of after the whole catalog.
                mp.undo()
            strings = {
                a: v
                for a, v in args.items()
                if a not in _SELECTORS
                and isinstance(v, str)
                and "string" in _types(_props(name)[a])
            }
            for s in up.served:
                if s.resolution:
                    continue
                fam, inner = sc.route(s.path)
                if fam.startswith("unspecced:") or fam == "unknown":
                    continue
                candidates = (
                    [sc.specs()[k] for k in sc.DIRECT_SPECS]
                    if fam == "direct"
                    else [sc.specs()[fam]]
                )
                for spec in candidates:
                    hit = sc._match(spec, inner)
                    if not hit:
                        continue
                    template, values = hit
                    for pname, pvalue in values.items():
                        matched = [a for a, v in strings.items() if v == pvalue]
                        if len(matched) > 1:
                            # Two arguments share a generated value: the one named like the
                            # parameter, else the ones no other parameter is named after.
                            named = [a for a in matched if _camel(a) == pname]
                            matched = named or [a for a in matched if _camel(a) not in values]
                        for arg in matched:
                            schema = _path_param_schema(spec, template, s.method, pname)
                            if (name, arg, schema) not in out:
                                out.append((name, arg, schema))
                    break
    finally:
        mp.undo()
    return out


@functools.cache
def _lz_PATH_ID_CASES():
    previous = logging.root.manager.disable
    try:
        return cti._run_coroutine(_path_id_cases())
    finally:
        logging.disable(previous)


async def _path_id_cases_for(name: str) -> list[tuple[str, dict[str, Any]]]:
    """One tool's cases out of the whole derivation (built on first use, at execution)."""
    return [
        (a, s) for n, a, s in _lz_PATH_ID_CASES() if n == name and (n, a) not in _DESCRIBED_VALUES
    ]


def _path_id_candidates() -> list[str]:
    return sorted(n for n in TOOLS if n not in cti.RAW_RELAY and n not in cti.NO_UPSTREAM)


async def _each_case(name: str, cases: list[Any], check: Any) -> None:
    """Run ``check(mp, *case)`` for every case of one tool (fresh monkeypatch each), and
    fail listing every failing eligible case, including unexpected runtime skips."""
    failed: list[str] = []
    for case in cases:
        mp = pytest.MonkeyPatch()
        try:
            await check(mp, name, *case)
        except (Exception, pytest.fail.Exception, pytest.skip.Exception) as exc:  # noqa: BLE001
            extra = f"[{case[1]!r}]" if isinstance(case[1], str) else ""
            failed.append(f"{name}.{case[0]}{extra}: {exc!s:.300}")
        finally:
            mp.undo()
    if failed:
        pytest.fail("\n".join(failed), pytrace=False)


async def _has_path_ids(name: str) -> bool:
    return bool(await _path_id_cases_for(name))


_PLAIN_PROBES = ["front door", "Café", "a:b", "a+b", "a@b", "front.door", "a..b", "a/b", "x?y=1#z"]


def _probes(schema: dict[str, Any]) -> list[str]:
    if schema.get("enum"):
        return [str(v) for v in schema["enum"]]
    if schema.get("format") == "uuid":
        return ["3FA85F64-5717-4562-B3FC-2C963F66AFA6", "3fa85f64-5717-4562-b3fc-2c963f66afa6"]
    if schema.get("type") != "string" or schema.get("pattern"):
        return []
    probes = list(_PLAIN_PROBES)
    if schema.get("maxLength"):
        probes.append(("é x" * 200)[: schema["maxLength"]])
    return probes


def test_db_path_id_set_is_non_trivial():
    found = {(n, a) for n, a, _s in _lz_PATH_ID_CASES()}
    for case in (
        ("trigger_alarm_webhook", "webhook_id"),
        ("get_camera", "camera_id"),
        ("pos_ingest_transaction", "camera_id"),
        ("siren_play", "siren_id"),
        ("get_sdwan_config", "config_id"),
        ("get_innerspace_asset", "filename"),
        ("get_mobility_device", "device_id"),
    ):
        assert case in found, (case, sorted(found))


@tool_batches("name", _path_id_candidates, member=_has_path_ids)
async def test_db_path_ids_accept_their_spec_and_encode_it_as_one_segment(monkeypatch, name):
    """Every path-id case of the tool (each case as its own check)."""
    await _each_case(name, await _path_id_cases_for(name), _check_path_id_case)


async def _check_path_id_case(monkeypatch, name, arg, schema):
    assert (name, arg) not in _DESCRIBED_VALUES, "inapplicable path case reached execution"
    for probe in _probes(schema):
        up = uh.FakeUpstream()
        try:
            await _call(monkeypatch, name, up, _args(name, **{arg: probe}))
        except ToolError as exc:
            msg = str(exc)
            assert (
                any(not request.resolution for request in up.served)
                or refusals.classify(msg) is None
            ), f"{name}.{arg}={probe!r}: a spec-valid path id was refused: {msg}"
        encoded = quote(probe, safe="")
        primary = [s for s in up.served if not s.resolution]
        for s in primary:
            segments = s.raw_path.split("/")
            if any(probe in seg or encoded in seg for seg in segments if seg != encoded):
                pytest.fail(f"{name}.{arg}={probe!r}: not one encoded segment in {s.raw_path}")
        assert "x=1" not in "".join(s.query for s in primary)


_TRAVERSAL_PROBES = ["..", ".", "../x", "x/..", "%2e%2e"]


async def _traversal_cases(name: str) -> list[tuple[str, str]]:
    cases = await _path_id_cases_for(name)
    args = sorted(
        {a for a, s in cases if _probes(s) and not s.get("enum")}
        - {a for a, s in cases if s.get("format") == "uuid"}
    )
    return [(a, p) for a in args for p in _TRAVERSAL_PROBES]


async def _has_traversal_cases(name: str) -> bool:
    return bool(await _traversal_cases(name))


@tool_batches("name", _path_id_candidates, member=_has_traversal_cases)
async def test_db_path_traversal_segment_fails_before_any_request(monkeypatch, name):
    """Every (path-id argument, traversal probe) case of the tool."""
    await _each_case(name, await _traversal_cases(name), _check_traversal_case)


async def _check_traversal_case(monkeypatch, name, arg, probe):
    assert (name, arg) not in _DESCRIBED_VALUES, "inapplicable path case reached execution"
    up = uh.FakeUpstream()
    with pytest.raises(ToolError):
        await _call(monkeypatch, name, up, _args(name, **{arg: probe}))
    assert [s for s in up.served if not s.resolution] == [], [s.raw_path for s in up.served]


async def test_db_alarm_trigger_id_is_any_user_defined_string(monkeypatch):
    for webhook_id, segment in [
        ("front.door", "front.door"),
        ("front door", "front%20door"),
        ("Café", "Caf%C3%A9"),
        ("a:b", "a%3Ab"),
        ("a+b", "a%2Bb"),
        ("a@b", "a%40b"),
        ("a..b", "a%2E%2Eb"),
    ]:
        up = uh.FakeUpstream()
        await _call(
            monkeypatch,
            "trigger_alarm_webhook",
            up,
            _args("trigger_alarm_webhook", webhook_id=webhook_id),
        )
        assert [w.raw_path.rsplit("/", 1)[-1] for w in up.writes()] == [segment]


# =========================================================================== item 1: paging
async def test_list_devices_page_size_alone_returns_the_first_page_and_its_next_token(
    monkeypatch,
):
    class Up(uh.FakeUpstream):
        def __call__(self, req: httpx.Request) -> httpx.Response:
            if req.url.path == "/v1/devices":
                body = {
                    "data": [{"hostId": "h1", "devices": [{"id": "d1"}]}],
                    "nextToken": "n2",
                    "traceId": "t",
                    "httpStatusCode": 200,
                }
                self._record(req, 200, body, False)
                return httpx.Response(200, json=body)
            return super().__call__(req)

    up = Up()
    payload = uh.result_payload(await _call(monkeypatch, "list_devices", up, {"page_size": 1}))
    reads = [s for s in up.served if s.path == "/v1/devices"]
    assert [s.query for s in reads] == ["pageSize=1"]
    assert payload["nextToken"] == "n2" and payload["traceId"] == "t"
    assert payload["_count"] == 1 and payload["_consoleCount"] == 1


# =========================================================================== item 5: wrappers
_WRAPPERS = {
    "data": [
        {"hostId": "h1", "hostName": "A", "devices": [{"id": "d1"}, {"id": "d2"}]},
        {"hostId": "h2", "hostName": "Offline", "devices": None},
        {"hostId": "h3", "hostName": "NoKey"},
        {"hostId": "h4", "hostName": "Empty", "devices": []},
    ],
    "httpStatusCode": 200,
    "traceId": "t",
}


class _DevicesUp(uh.FakeUpstream):
    def __call__(self, req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/devices":
            self._record(req, 200, _WRAPPERS, False)
            return httpx.Response(200, json=_WRAPPERS)
        return super().__call__(req)


async def test_list_devices_counts_zero_for_an_empty_or_null_wrapper(monkeypatch):
    payload = uh.result_payload(await _call(monkeypatch, "list_devices", _DevicesUp(), {}))
    assert payload["_count"] == 2
    assert payload["_consoleCount"] == 4
    assert payload["data"] == _WRAPPERS["data"]


async def test_list_all_devices_never_returns_a_wrapper_as_a_device(monkeypatch):
    payload = uh.result_payload(await _call(monkeypatch, "list_all_devices", _DevicesUp(), {}))
    assert [d["id"] for d in payload["data"]] == ["d1", "d2"]
    assert payload["_count"] == 2
    assert all("hostName" not in d for d in payload["data"])


# =========================================================================== item 6: key_label
_TWO_KEYS = [
    APIKeyConfig(key="k-alpha", label="alpha"),
    APIKeyConfig(key="k-beta", label="beta", is_org_key=True),
]


@pytest.mark.parametrize("paging", [{"cursor": "c1"}, {"limit": 5}])
async def test_carrier_page_mode_with_several_keys_requires_key_label(monkeypatch, paging):
    up = uh.FakeUpstream(replay_recordings=False)
    with pytest.raises(ToolError, match="key_label") as exc:
        await _call(monkeypatch, "list_carrier_subscribers", up, paging, keys=_TWO_KEYS)
    assert "alpha" in str(exc.value) and "beta" in str(exc.value)
    assert up.served == []
    up = uh.FakeUpstream(replay_recordings=False)
    await _call(
        monkeypatch, "list_carrier_subscribers", up, {**paging, "key_label": "beta"}, keys=_TWO_KEYS
    )
    assert {s.api_key for s in up.served} == {"k-beta"}


@pytest.mark.parametrize(
    ("name", "paging"),
    [
        ("list_hosts", {"page_size": 5}),
        ("list_sites", {"page_size": 5}),
        ("list_devices", {"page_size": 5}),
        ("list_carrier_subscribers", {"limit": 5}),
    ],
)
async def test_every_multi_key_page_mode_names_the_labels(monkeypatch, name, paging):
    up = uh.FakeUpstream(hosts_by_key=cti._two_key_hosts())
    with pytest.raises(ToolError, match="alpha, beta"):
        await _call(monkeypatch, name, up, paging, keys=cti._KEYS)
    assert up.served == []


# =========================================================================== item 7: names
_CAMS = [
    {"id": "0123456789abcdef01234567", "name": "Café Ünï"},  # decomposed é
    {"id": "0123456789abcdef01234569", "name": "Garage"},
    {"id": "0123456789abcdef0123456a", "name": "garage"},
    {"id": "0123456789abcdef0123456b", "name": "Porch "},
]


class _CamsUp(uh.FakeUpstream):
    def __call__(self, req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/integration/v1/cameras"):
            self._record(req, 200, _CAMS, False)
            return httpx.Response(200, json=_CAMS)
        return super().__call__(req)


def _events_cameras(up: uh.FakeUpstream) -> list[str]:
    from urllib.parse import parse_qs

    return sorted(
        {
            v
            for s in up.served
            if s.path.endswith("/api/events")
            for v in parse_qs(s.query).get("cameras", [])
        }
    )


@pytest.mark.parametrize(
    ("ref", "camera_id"),
    [
        ("Garage", "0123456789abcdef01234569"),  # exact wins over the casefold twin
        ("garage", "0123456789abcdef0123456a"),
        ("Café Ünï", "0123456789abcdef01234567"),  # composed matches decomposed
        ("CAFÉ ÜNÏ", "0123456789abcdef01234567"),
        ("Porch", "0123456789abcdef0123456b"),  # stripped tier
        ("porch ", "0123456789abcdef0123456b"),
        ("  Garage", "0123456789abcdef01234569"),  # stripped, case kept, beats 'garage'
    ],
)
async def test_protect_camera_names_match_exact_then_nfc_casefold_then_stripped(
    monkeypatch, ref, camera_id
):
    up = _CamsUp(replay_recordings=False)
    await _call(
        monkeypatch,
        "list_protect_events",
        up,
        _args("list_protect_events", start=1700000000, end=1700003600, cameras=ref),
    )
    assert _events_cameras(up) == [camera_id]


async def test_protect_camera_casefold_twins_are_ambiguous_and_unknown_lists_exact_names(
    monkeypatch,
):
    up = _CamsUp()
    with pytest.raises(ToolError, match="ambiguous camera 'GARAGE'"):
        await _call(
            monkeypatch,
            "list_protect_events",
            up,
            _args("list_protect_events", start=1700000000, end=1700003600, cameras="GARAGE"),
        )
    with pytest.raises(ToolError) as exc:
        await _call(
            monkeypatch,
            "list_protect_events",
            _CamsUp(),
            _args("list_protect_events", start=1700000000, end=1700003600, cameras="Missing"),
        )
    # Error values use JSON; compare the decoded names without changing Unicode or spaces.
    names = str(exc.value).split("Pass a camera ID or one of these names: ", 1)[1]
    assert json.loads(names) == sorted(c["name"] for c in _CAMS)


# =========================================================================== item 8: charset
@pytest.mark.parametrize(
    ("content_type", "raw", "body"),
    [
        ("text/plain; charset=latin-1", "Café".encode("latin-1"), "Café"),
        ("application/json; charset=windows-1252", '{"n": "Café"}'.encode("cp1252"), {"n": "Café"}),
        ("text/plain; charset=utf-16", "Ünï".encode("utf-16"), "Ünï"),
        ("text/plain", "Café".encode(), "Café"),
    ],
)
async def test_relay_decodes_text_in_its_declared_charset(monkeypatch, content_type, raw, body):
    path = "network/api/s/{site}/rest/device/abc"

    class Up(uh.FakeUpstream):
        def __call__(self, req: httpx.Request) -> httpx.Response:
            if req.url.path.endswith("/rest/device/abc"):
                self._record(req, 200, None, False)
                return httpx.Response(200, content=raw, headers={"content-type": content_type})
            return super().__call__(req)

    payload = uh.result_payload(
        await _call(
            monkeypatch, "fabric_connector_get", Up(), _args("fabric_connector_get", path=path)
        )
    )
    assert payload["body"] == body and "bodyBase64" not in payload, payload


@pytest.mark.parametrize(
    "content_type", ["text/plain; charset=utf-8", "text/plain; charset=no-such-codec", "text/plain"]
)
async def test_relay_text_that_does_not_decode_is_base64(monkeypatch, content_type):
    raw = b"\xff\xfe\xfa bytes"
    path = "network/api/s/{site}/rest/device/abc"

    class Up(uh.FakeUpstream):
        def __call__(self, req: httpx.Request) -> httpx.Response:
            if req.url.path.endswith("/rest/device/abc"):
                self._record(req, 200, None, False)
                return httpx.Response(200, content=raw, headers={"content-type": content_type})
            return super().__call__(req)

    payload = uh.result_payload(
        await _call(
            monkeypatch, "fabric_connector_get", Up(), _args("fabric_connector_get", path=path)
        )
    )
    assert payload["body"] is None
    assert base64.b64decode(payload["bodyBase64"]) == raw


# =========================================================================== bounded doubt
async def test_subscriber_number_is_trimmed_only_on_update(monkeypatch):
    # SubscriberCreate: 1-32 characters as given; SubscriberPatch: 1-32 after trimming.
    up = uh.FakeUpstream()
    await _call(
        monkeypatch,
        "create_carrier_subscriber",
        up,
        _args("create_carrier_subscriber", subscriber_number="  "),
    )
    assert [w.sent_json.get("subscriberNumber") for w in up.writes()] == ["  "]
    padded = " " + "x" * 31 + " "  # 33 as given, 31 trimmed
    with pytest.raises(ToolError, match="1-32 characters"):
        await _call(
            monkeypatch,
            "create_carrier_subscriber",
            uh.FakeUpstream(),
            _args("create_carrier_subscriber", subscriber_number=padded),
        )
    with pytest.raises(ToolError, match="after trimming"):
        await _call(
            monkeypatch,
            "update_carrier_subscriber",
            uh.FakeUpstream(),
            _args("update_carrier_subscriber", subscriber_number="   "),
        )
