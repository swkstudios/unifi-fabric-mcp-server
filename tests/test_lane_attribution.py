"""``X-UF-Lane`` per-request attribution.

A caller tags a call ``X-UF-Lane: <run-id>/<unit-id>``; every upstream request the call
makes then carries the tag in the request log line the live-test window accounting reads
and in the write audit record. The tag labels only: it grants nothing and changes no gate.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from unifi_fabric.audit import AuditStream, FileSink, audit_call
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.lane import (
    LANE_HEADER,
    InvalidLaneError,
    LaneMiddleware,
    current_lane,
    lane_scope,
    parse_lane,
)

BASE = "https://api.ui.com"
ROUTE = (
    "/v1/connector/consoles/AAAA11112222333344445555666677778888:1234567890"
    "/proxy/network/api/s/default/rest/account"
)
#: The pattern a live-acceptance window script uses on a log line.
RECORDED_LINE = re.compile(r'HTTP Request: (GET|POST|PUT|PATCH|DELETE) (\S+) "HTTP/\S+ (\d+)')


# --- the header ---------------------------------------------------------------------------
@pytest.mark.parametrize("value", ["run1/unit1", "sl073-n1/network-x", "a.b_c:d/e-f"])
def test_a_valid_tag_is_returned(value):
    assert parse_lane([value]) == value


@pytest.mark.parametrize("values", [None, []])
def test_no_header_is_no_lane(values):
    assert parse_lane(values) is None


@pytest.mark.parametrize(
    "value",
    [
        "",
        "run1",
        "run1/",
        "/unit1",
        "run1/unit1/extra",
        "-run/unit",
        "run/ unit",
        "run/unit\n",
        "run/un%it",
        "a" * 65 + "/b",
        "run/" + "b" * 65,
        "run;x/unit",
    ],
)
def test_a_malformed_tag_is_refused(value):
    with pytest.raises(InvalidLaneError):
        parse_lane([value])


def test_a_repeated_header_is_refused():
    with pytest.raises(InvalidLaneError, match="at most once"):
        parse_lane(["run1/unit1", "run1/unit2"])


# --- the middleware -----------------------------------------------------------------------
class _Ctx:
    message = object()


async def _through(headers: dict[str, list[str]]) -> str | None:
    seen: list[str | None] = []

    async def call_next(_context: Any) -> str:
        seen.append(current_lane())
        return "ok"

    middleware = LaneMiddleware(headers=lambda name: headers.get(name))
    await middleware.on_call_tool(_Ctx(), call_next)  # type: ignore[arg-type]
    return seen[0]


async def test_the_middleware_binds_the_tag_for_the_call_only():
    assert await _through({LANE_HEADER: ["run9/unit3"]}) == "run9/unit3"
    assert current_lane() is None


async def test_an_untagged_call_has_no_lane():
    assert await _through({}) is None


@pytest.mark.parametrize("values", [["bad"], ["a/b", "c/d"]])
async def test_a_bad_header_refuses_the_call_before_it_runs(values):
    ran: list[bool] = []

    async def call_next(_context: Any) -> str:
        ran.append(True)
        return "ok"

    middleware = LaneMiddleware(headers=lambda name: values)
    with pytest.raises(ToolError, match="X-UF-Lane"):
        await middleware.on_call_tool(_Ctx(), call_next)  # type: ignore[arg-type]
    assert not ran


async def test_concurrent_calls_keep_their_own_tags():
    async def call(tag: str) -> str | None:
        with lane_scope(tag):
            await asyncio.sleep(0)
            return current_lane()

    assert await asyncio.gather(call("r/a"), call("r/b"), call("r/c")) == ["r/a", "r/b", "r/c"]


# --- the upstream request log line --------------------------------------------------------
def _client() -> UniFiClient:
    return UniFiClient(Settings(api_key="probe-key-1", api_base_url=BASE))


def _request_lines(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.getMessage().startswith("HTTP Request:")]


@respx.mock
async def test_a_tagged_call_tags_every_upstream_request_line(caplog):
    respx.get(BASE + ROUTE).mock(return_value=httpx.Response(200, json={}))
    respx.post(BASE + ROUTE).mock(return_value=httpx.Response(200, json={}))
    client = _client()
    with caplog.at_level(logging.INFO, logger="httpx"), lane_scope("sl073-n1/unit-7"):
        await client.get(ROUTE)
        await client.request("POST", ROUTE, json={"name": "x"})
    lines = _request_lines(caplog)
    assert len(lines) == 2
    assert all(line.endswith(" lane=sl073-n1/unit-7") for line in lines), lines
    # The window script's own pattern still reads method, path and status from the line.
    assert [RECORDED_LINE.search(line).group(1) for line in lines] == ["GET", "POST"]
    assert RECORDED_LINE.search(lines[0]).group(3) == "200"


@respx.mock
async def test_an_untagged_call_logs_the_line_unchanged(caplog):
    respx.get(BASE + ROUTE).mock(return_value=httpx.Response(200, json={}))
    with caplog.at_level(logging.INFO, logger="httpx"):
        await _client().get(ROUTE)
    (line,) = _request_lines(caplog)
    assert "lane=" not in line and line.endswith('"HTTP/1.1 200 OK"')


@respx.mock
async def test_two_lanes_in_flight_together_are_told_apart(caplog):
    respx.get(BASE + ROUTE).mock(return_value=httpx.Response(200, json={}))
    client = _client()

    async def call(tag: str) -> None:
        with lane_scope(tag):
            await client.get(ROUTE)

    with caplog.at_level(logging.INFO, logger="httpx"):
        await asyncio.gather(call("r/read-a"), call("r/write-b"), call("r/read-a"))
    tags = sorted(line.rsplit(" lane=", 1)[1] for line in _request_lines(caplog))
    assert tags == ["r/read-a", "r/read-a", "r/write-b"]


@respx.mock
async def test_the_query_string_stays_out_of_a_tagged_line(caplog):
    respx.get(BASE + ROUTE).mock(return_value=httpx.Response(200, json={}))
    with caplog.at_level(logging.INFO, logger="httpx"), lane_scope("r/u"):
        await _client().get(ROUTE, params={"secretish": "value"})
    (line,) = _request_lines(caplog)
    assert "secretish" not in line and line.endswith(" lane=r/u")


# --- the write audit record --------------------------------------------------------------
def _audit(tmp_path) -> tuple[AuditStream, Any]:
    log = tmp_path / "audit.jsonl"
    return AuditStream(
        sink=FileSink(str(log)), secrets=(), fmt="json", level="normal", calls=False
    ), log


def test_the_audit_record_carries_the_lane_when_there_is_one(tmp_path):
    stream, log = _audit(tmp_path)
    with audit_call("create_network"), lane_scope("sl073-n1/u9"):
        stream.record(method="POST", path="/x", outcome="ok", status=200)
    stream.record(method="POST", path="/x", outcome="ok", status=200)
    first, second = (json.loads(line) for line in log.read_text().splitlines())
    assert first["lane"] == "sl073-n1/u9" and first["tool"] == "create_network"
    assert "lane" not in second
