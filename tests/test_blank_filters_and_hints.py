"""Blank filters, empty lists and epoch values pass through; hints never replace a value.

* A filter or search the server applies itself, given a blank string (or an empty list),
  is not applied: the result equals the call without it (``status_filter``,
  ``client_type``, ``client_ids``), and a blank ``query`` returns every record.
* A value the server forwards upstream is sent as given: ``types`` / ``categories`` /
  ``smart_detect_types`` (a blank string as is; an empty list sends no parameter),
  ``attrs`` and ``sites`` (an empty list in the body), ``host_ids`` (no parameter).
* Every epoch-seconds argument of every tool takes a negative or millisecond-magnitude
  value: it is sent (converted to milliseconds where the endpoint needs them) and the
  existing history tools add a ``_warnings`` entry; speedtest passes the upstream
  result through unchanged. Derived from the tool schemas: a new epoch argument is
  covered on registration.
* ``smart_detect_types`` without ``types`` is sent, with a ``_warnings`` entry.
* An empty ``sites`` ISP query is sent as given; an upstream error gets a hint appended
  and keeps the upstream text.
"""

from __future__ import annotations

import functools
import json
import logging
from typing import Any
from urllib.parse import parse_qsl

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_catalog import lazy_parametrize
from tests._tool_classes import class_axis
from unifi_fabric.tools._history_common import MILLISECONDS_HINT_AT, with_warnings

TOOLS = cti.TOOLS
_call = cti._call


@pytest.fixture(autouse=True)
def _quiet_logs():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


def _payload(res: Any) -> Any:
    body = uh.result_payload(res)
    if isinstance(body, dict) and set(body) == {"result"}:
        return body["result"]
    return body


def _args(name: str, **over: Any) -> dict[str, Any]:
    if name == "get_client_observability" and "timestamp" in over:
        over = {
            "view": "topology",
            "start": None,
            "end": None,
            **over,
        }  # timestamp is the topology snapshot time only; the generated baseline is a window
    return {**tool_args.generated_args(TOOLS[name]), **over}


def _params(up: uh.FakeUpstream, suffix: str) -> list[list[tuple[str, str]]]:
    return [
        parse_qsl(s.query, keep_blank_values=True) for s in up.served if s.path.endswith(suffix)
    ]


# ------------------------------------------------------------------ local filters
_OPTIONAL_LOCAL_FILTERS = [
    ("list_all_devices", "status_filter", ""),
    ("list_all_devices", "status_filter", "   "),
    ("list_clients", "client_type", ""),
    ("list_clients", "client_type", "  "),
    ("get_client_link_diagnostics", "client_ids", []),
]
#: Keys a result echoes its own arguments under (not data).
_ECHO = {"_filter", "_query"}


@pytest.mark.parametrize(("name", "arg", "blank"), _OPTIONAL_LOCAL_FILTERS)
async def test_blank_local_filter_is_not_applied(monkeypatch, name, arg, blank):
    base = _args(name)
    if name == "get_client_link_diagnostics":
        base.pop("client_id", None)
        omitted_up = uh.FakeUpstream()
        omitted = None
    else:
        omitted_up = uh.FakeUpstream()
        omitted = _payload(await _call(monkeypatch, name, omitted_up, args=dict(base)))
    up = uh.FakeUpstream()
    got = _payload(await _call(monkeypatch, name, up, args={**base, arg: blank}))
    if omitted is None:
        # client_ids=[] (and no client_id): the whole /stat/sta envelope, verbatim.
        sta = [s for s in up.served if s.path.endswith("/stat/sta")]
        assert sta and got == sta[-1].body
        return
    strip = lambda p: {k: v for k, v in p.items() if k not in _ECHO} if isinstance(p, dict) else p  # noqa: E731
    assert strip(got) == strip(omitted)
    assert [(s.method, s.path, s.query) for s in up.served] == [
        (s.method, s.path, s.query) for s in omitted_up.served
    ]


@pytest.mark.parametrize("blank", ["", "   "])
async def test_blank_fleet_search_returns_every_device(monkeypatch, blank):
    up = uh.FakeUpstream()
    got = _payload(
        await _call(
            monkeypatch,
            "search_device_fleet",
            up,
            args=_args("search_device_fleet", query=blank),
        )
    )
    every = _payload(
        await _call(
            monkeypatch,
            "list_all_devices",
            uh.FakeUpstream(),
            args=_args("list_all_devices"),
        )
    )
    assert got["_count"] == every["_count"] > 0
    assert got["data"] == every["data"]


@pytest.mark.parametrize("blank", ["", "   "])
async def test_blank_site_search_returns_every_record(monkeypatch, blank):
    up = uh.FakeUpstream()
    got = _payload(await _call(monkeypatch, "search_across_sites", up, args={"query": blank}))
    served = sum(
        len(uh.upstream_records(s.body))
        for s in up.served
        if not s.resolution and 200 <= s.status < 300 and s.method == "GET"
    )
    assert got["_count"] == len(got["data"]) == served > 0


async def test_empty_compare_site_list_compares_nothing(monkeypatch):
    up = uh.FakeUpstream()
    got = _payload(await _call(monkeypatch, "compare_site_performance", up, args={"sites": []}))
    assert got == {"_comparison": [], "_count": 0}
    assert up.served == []


# ------------------------------------------------------------------ forwarded values
@pytest.mark.parametrize("arg", ["types", "categories", "smart_detect_types"])
@pytest.mark.parametrize("value", ["", "   "])
async def test_blank_protect_filter_is_sent_as_given(monkeypatch, arg, value):
    wire = {"smart_detect_types": "smartDetectTypes"}.get(arg, arg)
    up = uh.FakeUpstream()
    extra = {"types": "motion"} if arg == "smart_detect_types" else {}
    await _call(
        monkeypatch,
        "list_protect_events",
        up,
        args=_args("list_protect_events", **{arg: value}, **extra),
    )
    sent = [v for q in _params(up, "/events") for k, v in q if k == wire]
    assert sent and all(v == value for v in sent), sent


async def test_empty_attrs_and_host_ids_are_sent_as_given(monkeypatch):
    up = uh.FakeUpstream()
    await _call(
        monkeypatch,
        "get_historical_stats",
        up,
        args=_args("get_historical_stats", attrs=[]),
    )
    reports = [s for s in up.served if "/stat/report/" in s.path]
    assert reports and all(s.sent_json.get("attrs") == [] for s in reports)
    up = uh.FakeUpstream()
    await _call(monkeypatch, "list_all_devices", up, args=_args("list_all_devices", host_ids=[]))
    devices = [s for s in up.served if s.path.endswith("/v1/devices")]
    assert devices and all("hostIds" not in s.query for s in devices)


async def test_empty_isp_sites_is_sent_and_an_upstream_error_gets_a_hint(monkeypatch):
    args = {"interval": "1h", "sites": []}
    up = uh.FakeUpstream()
    await _call(monkeypatch, "query_isp_metrics", up, args=args)
    posts = [s for s in up.served if s.path.endswith("/query")]
    assert [s.sent_json for s in posts] == [{"sites": []}]

    body = json.dumps({"code": 400, "message": "error while parsing request"})
    up = uh.FakeUpstream(mode="error", error_status=400, error_body=body)
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, "query_isp_metrics", up, args=args)
    text = str(exc.value)
    assert "error while parsing request" in text and "Hint:" in text
    assert text.index("error while parsing request") < text.index("Hint:")


# ------------------------------------------------------------------ epoch values
def _epoch_args() -> list[tuple[str, str]]:
    """(tool, argument) for every integer epoch-seconds argument in the catalog."""
    out = []
    for name, tool in TOOLS.items():
        for arg, spec in ((tool.parameters or {}).get("properties") or {}).items():
            types = {spec.get("type")} | {s.get("type") for s in spec.get("anyOf") or []}
            text = (spec.get("description") or "").lower()
            if "integer" in types and "epoch seconds" in text.replace("-", " "):
                out.append((name, arg))
    return sorted(out)


@functools.cache
def _lz_EPOCH_ARGS():
    return _epoch_args()


def test_epoch_sweep_covers_every_history_tool():
    names = {n for n, _ in _lz_EPOCH_ARGS()}
    assert {
        "list_protect_events",
        "collect_protect_events",
        "list_client_sessions",
        "get_historical_stats",
        "list_recognition_detections",
    } <= names, _lz_EPOCH_ARGS()


@class_axis(
    ("name", "arg"),
    lambda: _lz_EPOCH_ARGS(),
    value=lambda: ([-1, MILLISECONDS_HINT_AT, 1_700_000_000_000]),
)
async def test_epoch_value_is_sent_with_a_warning(monkeypatch, name, arg, value):
    upstream_warning = [{"code": "UPSTREAM_WARNING", "message": "preserve me"}]
    body = {"data": [{"time": 123}], "_warnings": upstream_warning}
    up = uh.FakeUpstream(
        replay_recordings=False,
        classic_rc_body=body if name == "list_speedtest_results" else None,
    )
    got = _payload(await _call(monkeypatch, name, up, args=_args(name, **{arg: value})))
    assert any(not s.resolution for s in up.served), f"{name}: nothing sent"
    sent = [str(value), str(value * 1000)]
    on_wire = [
        str(v)
        for s in up.served
        for v in [
            *s.path.split("/"),
            *(dict(parse_qsl(s.query)).values()),
            *((s.sent_json or {}).values()),
        ]
        if not isinstance(v, (dict, list))
    ]
    assert any(wire in sent for wire in on_wire), f"{name}.{arg}={value} not sent: {on_wire}"
    if name == "list_speedtest_results":
        served = [s for s in up.served if s.path.endswith("/report/archive.speedtest")]
        assert len(served) == 1
        assert served[0].sent_json[arg] == value * 1000
        assert served[0].body["_warnings"] == upstream_warning
        assert got == served[0].body
    else:
        warnings = got.get("_warnings") if isinstance(got, dict) else None
        assert warnings and any(
            w.get("argument") == arg and w.get("value") == value for w in warnings
        ), got


@lazy_parametrize(("name", "arg"), lambda: _lz_EPOCH_ARGS())
async def test_plausible_epoch_value_has_no_warning(monkeypatch, name, arg):
    value = uh.NOW - 60
    args = _args(name, **{arg: value})
    up = uh.FakeUpstream(replay_recordings=False)
    got = _payload(
        await _call(
            monkeypatch,
            name,
            up,
            args=args,
        )
    )
    warnings = got.get("_warnings") if isinstance(got, dict) else []
    assert not warnings, got
    sent_values = [
        str(v)
        for s in up.served
        for v in [
            *s.path.split("/"),
            *(dict(parse_qsl(s.query)).values()),
            *((s.sent_json or {}).values()),
        ]
        if not isinstance(v, (dict, list))
    ]
    assert str(value) in sent_values or str(value * 1000) in sent_values, (
        f"{name}.{arg}={value} not sent: {sent_values}"
    )


def test_epoch_warnings_wrap_lists_and_leave_clean_results_untouched():
    records = [{"id": "record-1"}]
    warning = {"code": "EPOCH_SECONDS_NEGATIVE", "argument": "start", "value": -1}
    wrapped = with_warnings(records, [warning])
    assert wrapped == {"result": records, "_warnings": [warning]}
    assert wrapped["result"] is records
    assert with_warnings(records, []) is records


@pytest.mark.parametrize("name", ["list_protect_events", "collect_protect_events"])
async def test_smart_detect_types_without_types_is_sent_with_a_warning(monkeypatch, name):
    up = uh.FakeUpstream()
    got = _payload(
        await _call(monkeypatch, name, up, args=_args(name, smart_detect_types="person"))
    )
    sent = [v for q in _params(up, "/events") for k, v in q if k == "smartDetectTypes"]
    assert sent and set(sent) == {"person"}
    codes = [w.get("code") for w in got.get("_warnings") or []]
    assert "SMART_DETECT_TYPES_WITHOUT_TYPES" in codes, got


@pytest.mark.parametrize("name", ["list_protect_events", "collect_protect_events"])
async def test_smart_detect_types_without_types_upstream_error_gets_a_hint(monkeypatch, name):
    body = json.dumps({"error": "bad request"})
    up = uh.FakeUpstream(mode="error", error_status=400, error_body=body)
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, name, up, args=_args(name, smart_detect_types="person"))
    text = str(exc.value)
    assert "bad request" in text and "Hint:" in text and "types" in text[text.index("Hint:") :]
    assert any(s.path.endswith("/events") for s in up.served)
